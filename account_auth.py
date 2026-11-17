"""Verify reconnect authentication with this account's cloud encrypt_key, without rebinding.

Auth wire format follows Freeband (MIT) MiProtocol.swift MiAuth and Mi Fitness WearAuthV2.
The bind handshake's temporary device_key is never assumed to be the persistent auth key.
"""

import argparse
import hashlib
import hmac
import re
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import miproto
from account_bind import STATE, binary_field, command, message
from account_cloud import BindError, HealthClient, private_read, private_write, text_field
from band_link import BandLink, BleBandLink


def cloud_auth_key(result, did):
    devices = result.get('list')
    if not isinstance(devices, list):
        raise BindError('Invalid cloud device list.')
    matched = [item for item in devices if isinstance(item, dict) and str(item.get('sid')) == did]
    if len(matched) != 1 or not isinstance(matched[0].get('detail'), dict):
        raise BindError('Bound device was not uniquely found in cloud response.')
    value = matched[0]['detail'].get('encrypt_key')
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{32}', value):
        raise BindError('Cloud device encrypt_key is missing or invalid.')
    return bytes.fromhex(value)


def authenticate(link, auth_key):
    if len(auth_key) != 16:
        raise BindError('Auth key must contain 16 bytes.')
    phone = secrets.token_bytes(16)
    verified = message(link.exchange(command(26, 30, miproto.pb_bytes(1, phone)), 26), 31)
    watch = binary_field(verified, 1, 16)
    proof = binary_field(verified, 2, 32)
    block = HKDF(hashes.SHA256(), 64, phone + watch, b'miwear-auth').derive(auth_key)
    if not hmac.compare_digest(hmac.digest(block[:16], watch + phone, 'sha256'), proof):
        raise BindError('Reconnect device HMAC is invalid; auth confirmation was not sent.')
    companion = miproto.pb_varint(1, 0) + miproto.pb_bytes(3, b'Linux')
    encrypted = AESCCM(block[16:32], tag_length=4).encrypt(block[36:40] + bytes(8), companion, None)
    confirm = (miproto.pb_bytes(1, hmac.digest(block[16:32], phone + watch, 'sha256'))
               + miproto.pb_bytes(2, encrypted))
    result = message(link.exchange(command(27, 32, confirm), 27), 33)
    if type(result.get(1)) is not int or result[1] != 1:
        raise BindError('Band did not confirm reconnect authentication.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    parser.add_argument('--channel', type=int, default=5)
    parser.add_argument('--transport', choices=('spp', 'ble'), default='spp')
    args = parser.parse_args()
    address = args.address.upper()
    if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', address) or not 1 <= args.channel <= 30:
        raise BindError('Invalid Bluetooth address or RFCOMM channel.')
    path = STATE / ('band-' + hashlib.sha256(address.encode()).hexdigest()[:12] + '.json')
    record = private_read(path)
    if record.get('stage') != 'device_result_acknowledged' or record.get('address') != address:
        raise BindError('Binding completion checkpoint is missing or does not match the device.')
    if 'cloud_auth_key' not in record:
        session = private_read(STATE / 'session.json')
        cloud = HealthClient(session, text_field(session, 'region'))
        key = cloud_auth_key(cloud.post('devices', {'page_size': 100}), text_field(record, 'bind_did'))
        record['cloud_auth_key'] = key.hex()
        private_write(path, record)
    value = text_field(record, 'cloud_auth_key')
    if not re.fullmatch(r'[0-9a-fA-F]{32}', value):
        raise BindError('Stored auth key is invalid.')
    print('Trying auth on a fresh Bluetooth connection; no rebind.', flush=True)
    link_type = BleBandLink if args.transport == 'ble' else BandLink
    with link_type(address, args.channel) as link:
        authenticate(link, bytes.fromhex(value))
    record['auth_verified' if args.transport == 'spp' else 'ble_auth_verified'] = True
    private_write(path, record)
    print('Reconnect/auth succeeded. Band HMAC verified and 1/27 confirmation received.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BindError as exc:
        print('Stopped:', exc, file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print('Stopped: connection, local file or response format error. No keys were printed.', file=sys.stderr)
        sys.exit(1)
