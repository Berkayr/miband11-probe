"""Experimental Xiaomi-account SERVER_PSK bind client; never use with public logs.

Wire facts: Mi Fitness 3.59.2i PSKWearBinderV2 and protobuf nano field numbers.
Existing probe.py stays a first-step-only probe. This CLI explicitly performs binding.
"""

import argparse
import getpass
import hashlib
import hmac
import os
import pathlib
import re
import secrets
import sys
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

import miproto
from account_cloud import (BindError, HTTP, HealthClient, b64, browser_login, password_login,
                           private_read, private_write, text_field, unb64)
from band_link import BandLink

STATE = pathlib.Path(os.environ.get('XDG_STATE_HOME', pathlib.Path.home() / '.local/state')) / 'miband11-probe'


def command(cid, field, body):
    return (miproto.pb_varint(1, 1) + miproto.pb_varint(2, cid)
            + miproto.pb_bytes(3, miproto.pb_bytes(field, body)))


def message(account, field):
    raw = account.get(field)
    result = miproto.pb_parse(raw) if isinstance(raw, bytes) else None
    if not result:
        raise BindError(f'Missing protobuf message {field}.')
    return result


def binary_field(obj, field, length=None):
    value = obj.get(field)
    if not isinstance(value, bytes) or not value or (length is not None and len(value) != length):
        raise BindError(f'Missing or invalid binary field {field}.')
    return value


def server_bytes(obj, field):
    value = unb64(text_field(obj, field))
    if not value:
        raise BindError('Empty server proof field: ' + field)
    return value


def bind(link, cloud, session, save, support_find=False, notify=print):
    """Complete one bind attempt. Persist recovery material before mutating final steps."""
    info = message(link.exchange(miproto.bind_start_command(session['user_id']), 17), 12)
    if info.get(1) != 1 or info.get(5) != 3:
        raise BindError('This client requires SERVER_PSK + BUTTON_CONFIRM.')
    hello = {'mode': 1, 'mac': link.address, 'randomMac': link.address,
             'phone_id': session['phone_id'], 'node_id': '', 'is_support_find': support_find}
    for field, name in ((2, 'sn'), (4, 'model'), (7, 'did')):
        try:
            hello[name] = binary_field(info, field).decode('utf-8')
        except UnicodeError:
            raise BindError('Invalid device identity encoding.') from None
    hello['random_d'] = b64(binary_field(info, 6, 16)).replace('+', '-').replace('/', '_')
    applied = cloud.post('hello', hello)
    # bind_index/bind_did are strings in the APK's data models.
    context = {name: text_field(applied, name) for name in ('bind_index', 'bind_did')}
    server = b''.join(miproto.pb_bytes(i, server_bytes(applied, name))
                      for i, name in enumerate(('pub_s', 'sign_s', 'random_s'), 1))
    device = message(link.exchange(command(18, 13, server), 18), 14)
    verify = dict(context, pub_d=url_b64(binary_field(device, 1)),
                  sign_d=url_b64(binary_field(device, 2)))
    verified = cloud.post('ecdh', verify)
    key = server_bytes(verified, 'device_key')
    if len(key) not in (16, 24, 32):
        raise BindError('Invalid device AES key size.')
    code = verified.get('oob_code')
    if type(code) is not int or not 0 <= code <= 999999:
        raise BindError('Invalid six-digit OOB code.')
    oob = f'{code:06d}'.encode('ascii')
    bind_key = text_field(verified, 'bind_key')
    recovery = dict(context, address=link.address, user_id=session['user_id'],
                    phone_id=session['phone_id'], device_key=url_b64(key), bind_key=bind_key,
                    stage='before_device_confirm')
    save(recovery)
    random = secrets.token_bytes(16)
    proof = hmac.digest(key, random + oob, 'sha256')
    confirm = (miproto.pb_bytes(1, random) + miproto.pb_bytes(2, proof)
               + miproto.pb_bytes(3, bind_key.encode()))
    notify('If the band asks for confirmation, tap the button on its screen. Waiting 90 seconds.')
    confirmed = message(link.exchange(command(19, 15, confirm), 19, timeout=90), 16)
    peer_random = binary_field(confirmed, 1, 16)
    peer_sign = binary_field(confirmed, 2, 32)
    if not hmac.compare_digest(hmac.digest(key, peer_random + oob, 'sha256'), peer_sign):
        raise BindError('Band confirmation HMAC is invalid; server bind was not sent.')
    bind_sign = url_b64(binary_field(confirmed, 3))
    recovery.update(bind_sign=bind_sign, stage='before_server_bind')
    save(recovery)
    result = cloud.post('bind', dict(context, bind_sign=bind_sign))
    if type(result.get('ret')) is not int or result['ret'] != 1:
        raise BindError('Server did not confirm binding (ret != 1).')
    recovery['stage'] = 'server_bound_before_device_result'
    save(recovery)
    # Linux identity, no Android capability bits claimed. Field 2 is a float SDK version.
    companion = miproto.pb_varint(1, 0) + miproto.pb_bytes(3, b'Linux')
    plaintext = miproto.pb_bytes(1, session['user_id'].encode()) + miproto.pb_bytes(2, companion)
    sealed = AESCCM(key, tag_length=4).encrypt(bytes(range(0x10, 0x1c)), plaintext, b'bind-data')
    link.exchange(command(25, 29, miproto.pb_bytes(1, sealed)), 25)
    recovery['stage'] = 'device_result_acknowledged'
    save(recovery)
    notify('Band and server accepted the bind steps. Reconnect/auth not verified yet.')


def url_b64(value):
    return b64(value).replace('+', '-').replace('/', '_')


def login(args):
    if args.action == 'login' and not sys.stdin.isatty():
        raise BindError('Run login in your own interactive terminal; never pipe credentials.')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    identity_path = STATE / 'identity.json'
    identity = private_read(identity_path) if identity_path.exists() else {'phone_id': str(uuid.uuid4())}
    private_write(identity_path, identity)
    if args.action == 'login-browser':
        def present(url):
            print('XIAOMI_LOGIN_URL: ' + url, flush=True)
            print('Complete login and email verification on the Xiaomi page. Waiting 5 minutes.', flush=True)
        session = browser_login(HTTP(), identity['phone_id'], present)
    else:
        user = input('Xiaomi account (local terminal only): ').strip()
        if not user:
            raise BindError('Empty account name.')
        password = getpass.getpass('Xiaomi password (not saved): ')
        session = password_login(HTTP(), user, password, identity['phone_id'])
        del password
    session['region'] = args.region
    private_write(STATE / 'session.json', session)
    print('miothealth session saved to the local state directory with mode 600; band not contacted.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for name, description in (('login', 'interactive password login'),
                              ('login-browser', 'login and email verification on Xiaomi website')):
        auth = sub.add_parser(name, help=description)
        auth.add_argument('--region', choices=('cn', 'de', 'us', 'sg', 'in', 'ru'), required=True)
    pair = sub.add_parser('bind', help='bind your band using the saved Xiaomi session')
    pair.add_argument('--address', required=True)
    pair.add_argument('--channel', type=int, default=5)
    pair.add_argument('--support-find', action='store_true', help='experimental phone-finding capability')
    args = parser.parse_args()
    if args.action in ('login', 'login-browser'):
        login(args)
        return 0
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', args.address) or not 1 <= args.channel <= 30:
        raise BindError('Invalid Bluetooth address or RFCOMM channel.')
    session = private_read(STATE / 'session.json')
    recovery_path = STATE / ('band-' + hashlib.sha256(args.address.upper().encode()).hexdigest()[:12] + '.json')
    if recovery_path.exists():
        raise BindError('Recovery file already exists; inspect outcome before attempting another bind.')
    cloud = HealthClient(session, text_field(session, 'region'))
    print('Starting a real bind with the Xiaomi account; keep the band nearby.')
    with BandLink(args.address.upper(), args.channel) as link:
        bind(link, cloud, session, lambda data: private_write(recovery_path, data), args.support_find)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BindError as exc:
        print('Stopped:', exc, file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print('Stopped: connection, local file or response format error. No automatic retry.', file=sys.stderr)
        sys.exit(1)
