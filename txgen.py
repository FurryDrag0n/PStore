#!/usr/bin/env python3
"""
PStore TxGen – создание цепочки транзакций для децентрализованного хранения.
Соответствует стандарту PStore.
RPC‑вызовы через HTTP, совместимы со старыми версиями ноды.
"""
import argparse
import struct
import hashlib
import os
import sys
import time
import json
import requests
from typing import List, Tuple

# ---------- Константы Novacoin ----------
NVC_P2PKH_VERSION = 0x08
NVC_P2SH_VERSION  = 0x14

MAX_BLOCK_SIZE = 1_000_000
MAX_SCRIPT_ELEMENT_SIZE = 10_000
CHUNK_SIZE = 10_000
MAX_TX_SIZE = 999_000          # 999 кБ
MAX_ZERO_OUTPUTS = 100          # кроме change

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
UNITS_PER_COIN = 1_000_000

# ---------- Base58Check ----------
def base58_decode_check(addr: str) -> Tuple[int, bytes]:
    n = 0
    for ch in addr:
        if ch not in BASE58_ALPHABET:
            raise ValueError(f"Invalid character '{ch}' in address")
        n = n * 58 + BASE58_ALPHABET.index(ch)
    data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    leading_ones = 0
    for ch in addr:
        if ch == '1':
            leading_ones += 1
        else:
            break
    if leading_ones:
        data = b'\x00' * leading_ones + data
    if len(data) != 25:
        raise ValueError(f"Invalid address length: {len(data)} (expected 25)")
    payload = data[:-4]
    checksum = data[-4:]
    hash1 = hashlib.sha256(payload).digest()
    hash2 = hashlib.sha256(hash1).digest()
    if checksum != hash2[:4]:
        raise ValueError("Invalid checksum")
    return payload[0], payload[1:]

def address_to_output_script(addr: str) -> bytes:
    version, h160 = base58_decode_check(addr)
    if version == NVC_P2PKH_VERSION:
        return b'\x76\xa9\x14' + h160 + b'\x88\xac'
    elif version == NVC_P2SH_VERSION:
        return b'\xa9\x14' + h160 + b'\x87'
    else:
        raise ValueError(f"Unsupported address version byte: 0x{version:02x}")

def build_opreturn_script(data: bytes) -> bytes:
    if len(data) > MAX_SCRIPT_ELEMENT_SIZE:
        raise ValueError(f"Data size {len(data)} exceeds {MAX_SCRIPT_ELEMENT_SIZE}")
    script = b'\x6a'
    if len(data) <= 75:
        script += struct.pack('<B', len(data))
    elif len(data) <= 0xFF:
        script += b'\x4c' + struct.pack('<B', len(data))
    elif len(data) <= 0xFFFF:
        script += b'\x4d' + struct.pack('<H', len(data))
    else:
        script += b'\x4e' + struct.pack('<I', len(data))
    script += data
    return script

# ---------- Сериализация ----------
def encode_varint(i: int) -> bytes:
    if i < 0xFD:
        return struct.pack('<B', i)
    elif i <= 0xFFFF:
        return b'\xFD' + struct.pack('<H', i)
    elif i <= 0xFFFFFFFF:
        return b'\xFE' + struct.pack('<I', i)
    else:
        return b'\xFF' + struct.pack('<Q', i)

def estimate_tx_size(change_script: bytes, zero_scripts: List[bytes]) -> int:
    size = 4 + 4
    size += 1 + 32 + 4 + 1 + 4
    size += 1
    size += 8 + len(change_script) + len(encode_varint(len(change_script)))
    for s in zero_scripts:
        size += 8 + len(s) + len(encode_varint(len(s)))
    size += 4
    num_outputs = 1 + len(zero_scripts)
    varint_len = 1 if num_outputs < 0xFD else (3 if num_outputs <= 0xFFFF else 5)
    return size + varint_len - 1

def make_tx(txid_in: str, vout_in: int, amount_units: int,
            change_script: bytes, zero_scripts: List[bytes],
            nTime: int) -> Tuple[str, int]:
    tx = struct.pack('<I', 1) + struct.pack('<I', nTime)
    tx += encode_varint(1)
    tx += bytes.fromhex(txid_in)[::-1]
    tx += struct.pack('<I', vout_in)
    tx += encode_varint(0)
    tx += struct.pack('<I', 0xFFFFFFFF)
    num_outputs = 1 + len(zero_scripts)
    tx += encode_varint(num_outputs)
    tx += struct.pack('<Q', amount_units)
    tx += encode_varint(len(change_script))
    tx += change_script
    for s in zero_scripts:
        tx += struct.pack('<Q', 0)
        tx += encode_varint(len(s))
        tx += s
    tx += struct.pack('<I', 0)
    return tx.hex(), len(tx)

# ---------- HTTP JSON-RPC ----------
def rpc_call(method: str, params: list, rpc_config: dict) -> dict:
    url = rpc_config.get('url', 'http://127.0.0.1:8344')
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "1.0",
        "id": "pstore",
        "method": method,
        "params": params
    }
    auth = (rpc_config.get('user'), rpc_config.get('password')) if rpc_config.get('user') else None
    try:
        response = requests.post(url, json=payload, headers=headers, auth=auth, timeout=30)
        response.raise_for_status()
        result = response.json()
        if result.get('error') is not None:
            raise RuntimeError(f"RPC error: {result['error']}")
        return result['result']
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"HTTP request to {url} failed: {e}") from e

def sign_transaction(hex_tx: str, rpc_config: dict) -> Tuple[str, bool]:
    result = rpc_call('signrawtransaction', [hex_tx], rpc_config)
    return result['hex'], result.get('complete', False)

def send_transaction(hex_tx: str, rpc_config: dict) -> str:
    return rpc_call('sendrawtransaction', [hex_tx], rpc_config)

def decode_txid(hex_tx: str, rpc_config: dict) -> str:
    result = rpc_call('decoderawtransaction', [hex_tx], rpc_config)
    return result['txid']

def micronvc_from_coin(amount: float) -> int:
    return int(round(amount * UNITS_PER_COIN))

# ---------- Основная логика ----------
def main():
    parser = argparse.ArgumentParser(description="PStore TxGen")
    parser.add_argument("--file", required=True, help="Файл для записи")
    parser.add_argument("--change-address", required=True,
                        help="Адрес для change (начинается с 4)")
    parser.add_argument("--utxo-txid", required=True, help="TXID начального UTXO")
    parser.add_argument("--utxo-vout", required=True, type=int, help="Vout начального UTXO")
    parser.add_argument("--utxo-amount", required=True, type=float,
                        help="Сумма UTXO в NVC")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE,
                        help=f"Макс. размер чанка (байт, по умолч. {CHUNK_SIZE})")
    parser.add_argument("--time", type=int, default=int(time.time()),
                        help="nTime транзакций (Unix timestamp)")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8344",
                        help="Полный URL RPC (например, http://127.0.0.1:8344/)")
    parser.add_argument("--rpc-user", default="user", help="RPC пользователь")
    parser.add_argument("--rpc-password", help="RPC пароль")
    parser.add_argument("--dry-run", action="store_true",
                        help="Только показать структуру графа, без RPC")
    parser.add_argument("--no-broadcast", action="store_true",
                        help="Подписать, но не отправлять (сохранить hex)")
    parser.add_argument("--output-dir", default=".",
                        help="Каталог для сохранения hex (при --no-broadcast)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Ошибка: файл '{args.file}' не найден", file=sys.stderr)
        sys.exit(1)

    with open(args.file, "rb") as f:
        file_data = f.read()
    print(f"Размер файла: {len(file_data)} байт")

    if args.chunk_size > MAX_SCRIPT_ELEMENT_SIZE:
        print(f"Ошибка: chunk-size {args.chunk_size} > {MAX_SCRIPT_ELEMENT_SIZE}", file=sys.stderr)
        sys.exit(1)

    chunks = [file_data[i:i+args.chunk_size] for i in range(0, len(file_data), args.chunk_size)]
    chunks_reversed = chunks[::-1]
    total_chunks = len(chunks_reversed)
    print(f"Всего чанков: {total_chunks}")

    if total_chunks == 0:
        print("Файл пуст, ничего не делаем.")
        return

    rpc_config = {
        'url': args.rpc_url,
        'user': args.rpc_user,
        'password': args.rpc_password,
    }
    if not args.dry_run:
        try:
            rpc_call('getinfo', [], rpc_config)
        except Exception as e:
            print(f"Ошибка подключения к RPC: {e}", file=sys.stderr)
            sys.exit(1)

    change_script = address_to_output_script(args.change_address)
    amount_units = micronvc_from_coin(args.utxo_amount)

    # ---------- Группировка чанков в транзакции ----------
    tx_groups = []
    current_group = []

    for idx, chunk in enumerate(chunks_reversed):
        test_group = current_group + [chunk]
        zero_scripts = [build_opreturn_script(c) for c in test_group]
        is_first_group = (idx == 0)
        is_last_group = (idx == total_chunks - 1)
        if is_last_group:
            zero_scripts.append(b'\x00')
        if is_first_group:
            zero_scripts.append(b'\x00')

        approx_size = estimate_tx_size(change_script, zero_scripts)
        new_count = len(test_group)
        if (approx_size <= MAX_TX_SIZE and new_count < MAX_ZERO_OUTPUTS):
            current_group.append(chunk)
        else:
            if current_group:
                tx_groups.append(current_group)
            current_group = [chunk]

    if current_group:
        tx_groups.append(current_group)

    total_txs = len(tx_groups)
    print(f"Будет создано транзакций: {total_txs}")

    if args.dry_run:
        print("\nСТРУКТУРА ГРАФА (dry-run):")
        for i, group in enumerate(tx_groups):
            markers = []
            if i == 0:
                markers.append("конец (OP_0 после данных)")
            if i == total_txs - 1:
                markers.append("начало (OP_0 перед данными)")
            data_size = sum(len(c) for c in group)
            print(f"Транзакция #{i+1}: {len(group)} чанков, {data_size} байт данных, маркеры: {', '.join(markers) if markers else 'нет'}")
        print(f"Идентификатор файла (точка входа): будет txid последней транзакции (№{total_txs})")
        return

    # ---------- Реальное создание ----------
    prev_txid = args.utxo_txid
    prev_vout = args.utxo_vout
    tx_chain = []

    print("\nСоздание цепочки транзакций:")
    for i, group in enumerate(tx_groups):
        zero_scripts = []
        is_first = (i == 0)
        is_last = (i == total_txs - 1)

        if is_last:
            zero_scripts.append(b'\x00')
        # Важно: чанки внутри транзакции идут в правильном порядке (от начала к концу)
        for chunk in reversed(group):
            zero_scripts.append(build_opreturn_script(chunk))
        if is_first:
            zero_scripts.append(b'\x00')

        if len(zero_scripts) > MAX_ZERO_OUTPUTS:
            print(f"Ошибка: в транзакции {i+1} слишком много нулевых выходов ({len(zero_scripts)} > {MAX_ZERO_OUTPUTS})", file=sys.stderr)
            sys.exit(1)

        hex_tx, tx_size = make_tx(prev_txid, prev_vout, amount_units,
                                  change_script, zero_scripts, args.time)
        if tx_size > MAX_TX_SIZE:
            print(f"Предупреждение: размер транзакции {tx_size} байт превышает лимит {MAX_TX_SIZE} для транзакции {i+1}", file=sys.stderr)

        print(f"Транзакция #{i+1}: размер {tx_size} байт, {len(group)} чанков данных")

        signed_hex, complete = sign_transaction(hex_tx, rpc_config)
        if not complete:
            print(f"  ⚠️  Подпись неполная (не хватает ключей). Продолжаем, но транзакция может быть недействительной.")
        txid = decode_txid(signed_hex, rpc_config)

        if not args.no_broadcast:
            print(f"  Трансляция {txid}...")
            send_transaction(signed_hex, rpc_config)
            print(f"  ✅ Отправлено: {txid}")
        else:
            outfile = os.path.join(args.output_dir, f"tx_{i+1}_{txid}.hex")
            with open(outfile, "w") as f:
                f.write(signed_hex)
            print(f"  Сохранено: {outfile}")

        tx_chain.append({'txid': txid, 'group': group})
        prev_txid = txid
        prev_vout = 0

    print("\n" + "="*70)
    print("СТАТУС:")
    last_txid = tx_chain[-1]['txid']
    print(f"✅ Все транзакции созданы и {'отправлены' if not args.no_broadcast else 'сохранены'}.")
    print(f"Идентификатор файла (точка входа): {last_txid}")
    print(f"Всего транзакций: {total_txs}")
    print("="*70)

if __name__ == "__main__":
    main()