#!/usr/bin/env python3
"""
PStore Pull Server – HTTP‑сервер для извлечения файлов из цепочки транзакций.
Эндпоинт: /pull/<txid>.<ext>
Возвращает файл с указанным расширением.
"""
import os
import sys
import json
import re
import requests
from flask import Flask, request, make_response, abort

app = Flask(__name__)

# ---------- Конфигурация RPC ----------
RPC_URL = "http://127.0.0.1:8344"
RPC_USER = "user"
RPC_PASS = "4tZUnIoxyrliNtO"

def rpc_call(method: str, params: list) -> dict:
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "1.0",
        "id": "pstore-pull",
        "method": method,
        "params": params
    }
    auth = (RPC_USER, RPC_PASS) if RPC_USER else None
    try:
        response = requests.post(RPC_URL, json=payload, headers=headers, auth=auth, timeout=30)
        response.raise_for_status()
        result = response.json()
        if result.get('error') is not None:
            raise RuntimeError(f"RPC error: {result['error']}")
        return result['result']
    except Exception as e:
        raise RuntimeError(f"RPC call failed: {e}") from e

def get_transaction(txid: str) -> dict:
    return rpc_call('getrawtransaction', [txid, 1])

def extract_opreturn_data(vout: dict) -> bytes:
    asm = vout['scriptPubKey'].get('asm', '')
    if asm.startswith('OP_RETURN'):
        parts = asm.split(' ', 1)
        if len(parts) > 1:
            hex_data = parts[1].replace(' ', '')
            try:
                return bytes.fromhex(hex_data)
            except ValueError:
                return b''
    return b''

@app.route('/pull/<path:txid_ext>')
def pull_file(txid_ext: str):
    if '.' in txid_ext:
        txid, ext = txid_ext.rsplit('.', 1)
    else:
        txid = txid_ext
        ext = 'bin'

    if not re.match(r'^[0-9a-fA-F]{64}$', txid):
        abort(400, description="Invalid txid format")

    data_parts = []
    current_txid = txid
    is_first = True

    try:
        while True:
            tx = get_transaction(current_txid)
            vouts = tx['vout']

            # Проверяем маркеры OP_0
            has_marker = any(vout['scriptPubKey'].get('asm') == '0' for vout in vouts)

            # Собираем OP_RETURN данные (игнорируем маркеры)
            for vout in vouts:
                if vout['scriptPubKey'].get('asm') == '0':
                    continue
                payload = extract_opreturn_data(vout)
                if payload:
                    data_parts.append(payload)

            # Если встретили маркер и это не первая транзакция, то это конец цепочки
            if has_marker and not is_first:
                break

            # Переход к предыдущей транзакции
            if len(tx['vin']) != 1:
                abort(400, description="Not a linear graph (multiple or zero inputs)")
            prev_txid = tx['vin'][0]['txid']
            if prev_txid == current_txid:
                break
            current_txid = prev_txid
            is_first = False

    except Exception as e:
        abort(404, description=f"Chain error: {e}")

    if not data_parts:
        abort(404, description="No data found")

    file_content = b''.join(data_parts)
    if len(file_content) == 0:
        abort(404, description="Empty file")

    response = make_response(file_content)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = f'attachment; filename="{txid}.{ext}"'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5080, debug=True)