#!/usr/bin/env python3
"""Write the stored band auth key as a Mi Fitness-style manifest.sqlite that Freeband can import."""

import argparse
import hashlib
import json
import os
import re
import sqlite3

from account_bind import STATE
from account_cloud import BindError, private_read, text_field


def write_manifest(out, key_hex, address, name='Xiaomi Smart Band 11', region='de'):
    """Freeband's KeyStore reads `select key, inline_data, filename from manifest where key like 'registerList%'`."""
    if not re.fullmatch(r'[0-9a-f]{32}', key_hex):
        raise BindError('Auth key must be 32 lowercase hex characters.')
    if not re.fullmatch(r'[a-z]{2,4}', region):
        raise BindError('Invalid region.')
    entry = json.dumps({'list': [{'encryptKey': key_hex, 'name': name, 'mac': address}]}).encode()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with sqlite3.connect(out) as db:
        db.execute('create table manifest (key text primary key, filename text, inline_data blob)')
        db.execute('insert into manifest values (?, null, ?)', ('registerList_' + region, entry))
    db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    parser.add_argument('--out', default='manifest.sqlite')
    parser.add_argument('--region', default='de', help='Xiaomi server region in the entry name')
    args = parser.parse_args()
    address = args.address.upper()
    if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', address):
        raise BindError('Invalid Bluetooth address.')
    record = private_read(STATE / ('band-' + hashlib.sha256(address.encode()).hexdigest()[:12] + '.json'))
    write_manifest(args.out, text_field(record, 'cloud_auth_key'), address, region=args.region)
    print(f'{args.out} written with mode 600. It contains the band key: move it to the phone, import, delete.')


if __name__ == '__main__':
    try:
        main()
    except BindError as error:
        raise SystemExit(f'error: {error}')
