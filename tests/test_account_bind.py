import copy
import hashlib
import hmac
import json
import os
import pathlib
import tempfile
import unittest
import urllib.parse

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

import account_bind as ab
import account_cloud as ac
import miproto as pb
from band_link import BandLink

KEY = bytes(range(16))
SESSION = {'user_id': '12345', 'phone_id': 'test-phone', 'c_user_id': 'test-encrypted-id',
           'service_token': 'test-token', 'security': ac.b64(bytes(range(32))), 'region': 'de'}


def reference_rc4(key, data):
    cipher = Cipher(ARC4(key), mode=None).encryptor()
    cipher.update(bytes(1024))
    return cipher.update(data)


class CloudTests(unittest.TestCase):
    def test_rc4_rfc6229_offset1024(self):
        # RFC 6229, 40-bit key 01 02 03 04 05, stream offset 1024.
        self.assertEqual(ac.RC4(bytes(range(1, 6))).crypt(bytes(16)).hex(),
                         '30abbcc7c20b01609f23ee2d5f6bb7df')

    def test_form_matches_independent_cipher_and_digest(self):
        nonce = bytes(range(12))
        form, key = ac.encrypted_form('/bind/hello', {'mode': 1}, SESSION['security'], nonce)
        expected_key = hashlib.sha256(bytes(range(32)) + nonce).digest()
        self.assertEqual(key, expected_key)
        seed = 'POST&/bind/hello&data={"mode":1}&' + ac.b64(key)
        first_hash = ac.b64(hashlib.sha1(seed.encode()).digest())
        plaintext = b'{"mode":1}' + first_hash.encode()
        encrypted = reference_rc4(key, plaintext)
        self.assertEqual(ac.unb64(form['data']), encrypted[:10])
        self.assertEqual(ac.unb64(form['rc4_hash__']), encrypted[10:])
        signed = ('POST&/bind/hello&data=' + form['data']
                  + '&rc4_hash__=' + form['rc4_hash__'] + '&' + ac.b64(key))
        self.assertEqual(form['signature'], ac.b64(hashlib.sha1(signed.encode()).digest()))
        self.assertEqual(form['_nonce'], ac.b64(nonce))

    def test_http_result_envelope_and_fresh_response_cipher(self):
        class Server:
            def request(inner, url, data, headers):
                self.assertEqual(url, 'https://de.hlth.io.mi.com/healthapp/bind/hello')
                form = {k: v[0] for k, v in urllib.parse.parse_qs(data.decode()).items()}
                key = hashlib.sha256(bytes(range(32)) + ac.unb64(form['_nonce'])).digest()
                result = b'{"code":200,"result":{"bind_did":"test"}}'
                return ac.b64(reference_rc4(key, result)).encode()
        self.assertEqual(ac.HealthClient(SESSION, 'de', Server()).post('hello', {'mode': 1}),
                         {'bind_did': 'test'})

    def test_plaintext_success_is_rejected(self):
        class Server:
            def request(self, *args):
                return b'{"code":0,"result":{"ret":1}}'
        with self.assertRaises(ac.BindError):
            ac.HealthClient(SESSION, 'de', Server()).post('bind', {})

    def test_untrusted_urls_rejected(self):
        for url in ('http://account.xiaomi.com', 'https://xiaomi.com.attacker.test',
                    'https://attacker.test', 'https://user@account.xiaomi.com',
                    'https://account.xiaomi.com:444'):
            with self.subTest(url=url), self.assertRaises(ac.BindError):
                ac.allowed_url(url)

    def test_private_file_permissions_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            target = pathlib.Path(root) / 'private' / 'state.json'
            ac.private_write(target, {'fake': True})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(ac.private_read(target), {'fake': True})
            os.chmod(target, 0o644)
            with self.assertRaises(ac.BindError):
                ac.private_read(target)
            os.chmod(target, 0o600)
            link = target.with_name('link.json')
            link.symlink_to(target)
            with self.assertRaises(OSError):
                ac.private_read(link)
            ac.private_write(link, {'new': True})
            self.assertFalse(link.is_symlink())
            self.assertEqual(ac.private_read(target), {'fake': True})

    def test_password_login_and_sts_signature(self):
        class LoginServer:
            def __init__(self):
                from http.cookiejar import CookieJar
                self.cookies = CookieJar()
                self.calls = []

            def request(inner, url, data=None, headers=None):
                inner.calls.append(url)
                if 'serviceLogin?' in url:
                    return b'{"_sign":"test-sign","qs":"test-qs","callback":"test-callback"}'
                if 'serviceLoginAuth2' in url:
                    form = urllib.parse.parse_qs(data.decode())
                    self.assertEqual(form['hash'], [hashlib.md5(b'test-password').hexdigest().upper()])
                    self.assertEqual(form['sid'], ['miothealth'])
                    return json.dumps({'code': 0, 'ssecurity': SESSION['security'], 'nonce': 7,
                                       'location': 'https://hlth.io.mi.com/sts', 'userId': 12345,
                                       'cUserId': 'test-id'}).encode()
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                expected = ac.b64(hashlib.sha1(('nonce=7&' + SESSION['security']).encode()).digest())
                self.assertEqual(query['clientSign'], [expected])
                inner.cookies.set_cookie(ac.Cookie(0, 'serviceToken', 'test-token', None, False,
                    'hlth.io.mi.com', False, False, '/', True, True, None, True, None, None, {}, False))
                return b''
        http = LoginServer()
        session = ac.password_login(http, 'test-user', 'test-password', 'test-phone')
        self.assertEqual(session['service_token'], 'test-token')
        self.assertEqual(len(http.calls), 3)
        self.assertNotIn('test-password', json.dumps(session))


class FakeCloud:
    def __init__(self, ret=1):
        self.calls = []
        self.ret = ret

    def post(self, operation, data):
        self.calls.append((operation, data))
        if operation == 'hello':
            return {'bind_index': 'index', 'bind_did': 'did',
                    'pub_s': ac.b64(b'server-public'), 'sign_s': ac.b64(b'server-proof'),
                    'random_s': ac.b64(bytes(16))}
        if operation == 'ecdh':
            return {'device_key': ac.b64(KEY), 'bind_key': 'not-base64-bind-key', 'oob_code': 42}
        return {'ret': self.ret}


class FakeBand:
    address = '00:11:22:33:44:55'

    def __init__(self, bad_hmac=False, timeout_final=False):
        self.commands = []
        self.bad_hmac, self.timeout_final = bad_hmac, timeout_final

    def exchange(self, command, cid, timeout=30):
        self.commands.append(cid)
        msg = pb.pb_parse(command)
        self_account = pb.pb_parse(msg[3])
        if cid == 17:
            info = (pb.pb_varint(1, 1) + pb.pb_varint(5, 3) + pb.pb_bytes(2, b'TEST-SN')
                    + pb.pb_bytes(4, b'test.model') + pb.pb_bytes(6, bytes(16)) + pb.pb_bytes(7, b'TEST-DID'))
            return {12: info}
        if cid == 18:
            assert 13 in self_account
            return {14: pb.pb_bytes(1, b'public-device') + pb.pb_bytes(2, b'proof-device')}
        if cid == 19:
            confirm = pb.pb_parse(self_account[15])
            assert confirm[2] == hmac.digest(KEY, confirm[1] + b'000042', 'sha256')
            assert confirm[3] == b'not-base64-bind-key'
            random = bytes(range(16))
            proof = bytes(32) if self.bad_hmac else hmac.digest(KEY, random + b'000042', 'sha256')
            return {16: pb.pb_bytes(1, random) + pb.pb_bytes(2, proof) + pb.pb_bytes(3, b'bind-proof')}
        if self.timeout_final:
            raise ac.BindError('test final timeout')
        ciphertext = pb.pb_parse(self_account[29])[1]
        plaintext = AESCCM(KEY, tag_length=4).decrypt(bytes(range(0x10, 0x1c)), ciphertext, b'bind-data')
        assert pb.pb_parse(plaintext)[1] == SESSION['user_id'].encode()
        return {3: 0}


class BindTests(unittest.TestCase):
    def run_bind(self, band=None, cloud=None, save=None):
        self.band, self.cloud, self.saved = band or FakeBand(), cloud or FakeCloud(), []
        persist = save or (lambda record: self.saved.append(copy.deepcopy(record)))
        ab.bind(self.band, self.cloud, SESSION, persist, notify=lambda _: None)

    def test_whole_bind_wire_flow_and_checkpoint_order(self):
        self.run_bind()
        self.assertEqual(self.band.commands, [17, 18, 19, 25])
        self.assertEqual([call[0] for call in self.cloud.calls], ['hello', 'ecdh', 'bind'])
        self.assertEqual([x['stage'] for x in self.saved], ['before_device_confirm',
                         'before_server_bind', 'server_bound_before_device_result', 'device_result_acknowledged'])
        hello = self.cloud.calls[0][1]
        self.assertEqual(hello['mac'], hello['randomMac'])
        self.assertEqual(hello['mode'], 1)
        self.assertEqual(len(ac.unb64(hello['random_d'])), 16)

    def test_bad_hmac_stops_before_server_bind(self):
        with self.assertRaises(ac.BindError):
            self.run_bind(band=FakeBand(bad_hmac=True))
        self.assertEqual(self.band.commands, [17, 18, 19])
        self.assertEqual([x[0] for x in self.cloud.calls], ['hello', 'ecdh'])

    def test_server_rejection_stops_before_final_device_write(self):
        with self.assertRaises(ac.BindError):
            self.run_bind(cloud=FakeCloud(ret=0))
        self.assertEqual(self.band.commands, [17, 18, 19])
        self.assertEqual(self.saved[-1]['stage'], 'before_server_bind')

    def test_disk_failure_prevents_device_confirm(self):
        def broken_save(record):
            raise OSError('test disk full')
        with self.assertRaises(OSError):
            self.run_bind(save=broken_save)
        self.assertEqual(self.band.commands, [17, 18])

    def test_final_timeout_keeps_server_bound_checkpoint(self):
        with self.assertRaises(ac.BindError):
            self.run_bind(band=FakeBand(timeout_final=True))
        self.assertEqual(self.saved[-1]['stage'], 'server_bound_before_device_result')


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        pass

    def recv(self, count):
        return next(self.chunks, b'')


class LinkTests(unittest.TestCase):
    def test_fragmented_stream_and_duplicate_frames(self):
        frame = pb.encode_frame(pb.KIND_DATA, 3, b'\x01\x01test')
        second = pb.encode_frame(pb.KIND_DATA, 4, b'\x01\x01next')
        link = BandLink(FakeBand.address)
        link.sock = FakeSocket([frame[:5], frame[5:] + frame + second])
        self.assertEqual(link.receive(float('inf'))[1:], (3, b'\x01\x01test'))
        self.assertEqual(link.receive(float('inf'))[1:], (4, b'\x01\x01next'))
        self.assertEqual(len(link.sock.sent), 3)

    def test_unrelated_response_ignored_and_account_error_fails(self):
        unrelated = ab.command(26, 14, b'test')
        account = pb.pb_varint(3, 7)
        failed = pb.pb_varint(1, 1) + pb.pb_varint(2, 18) + pb.pb_bytes(3, account)
        chunks = [pb.encode_frame(pb.KIND_DATA, i, pb.data_payload(cmd))
                  for i, cmd in enumerate((unrelated, failed))]
        link = BandLink(FakeBand.address)
        link.sock = FakeSocket(chunks)
        with self.assertRaisesRegex(ac.BindError, 'VERIFY_ERROR'):
            link.exchange(ab.command(18, 13, b'test'), 18)

    def test_nack_stops_without_retransmit(self):
        link = BandLink(FakeBand.address)
        link.sock = FakeSocket([pb.encode_frame(pb.KIND_NACK, 0, b'')])
        with self.assertRaisesRegex(ac.BindError, 'NACK'):
            link.exchange(ab.command(18, 13, b'test'), 18)
        self.assertEqual(len(link.sock.sent), 1)

class AdditionalFailureTests(unittest.TestCase):
    def test_disk_failure_after_server_bind_prevents_final_write(self):
        band, cloud, saves = FakeBand(), FakeCloud(), []
        def save(record):
            if record['stage'] == 'server_bound_before_device_result':
                raise OSError('test disk failure')
            saves.append(copy.deepcopy(record))
        with self.assertRaises(OSError):
            ab.bind(band, cloud, SESSION, save, notify=lambda _: None)
        self.assertEqual(band.commands, [17, 18, 19])
        self.assertEqual(saves[-1]['stage'], 'before_server_bind')

    def test_invalid_oob_stops_before_device_confirm(self):
        class BadOOB(FakeCloud):
            def post(self, operation, data):
                result = super().post(operation, data)
                if operation == 'ecdh':
                    result['oob_code'] = -1
                return result
        band = FakeBand()
        with self.assertRaises(ac.BindError):
            ab.bind(band, BadOOB(), SESSION, lambda _: None, notify=lambda _: None)
        self.assertEqual(band.commands, [17, 18])

    def test_plaintext_different_error_does_not_expose_response(self):
        class Server:
            def request(self, *args):
                return b'{"code":401,"message":"secret-token-test"}'
        with self.assertRaises(ac.BindError) as ctx:
            ac.HealthClient(SESSION, 'de', Server()).post('hello', {})
        self.assertNotIn('secret-token-test', str(ctx.exception))
        self.assertIn('401', str(ctx.exception))

    def test_login_redirect_cookie_does_not_block_sts(self):
        request = ac.XiaomiRequest('https://account.xiaomi.com/pass/serviceLogin')
        request.add_unredirected_header('Cookie', 'deviceId=test')
        result = ac.XiaomiRedirect().redirect_request(request, None, 302, 'Found', {},
                                                      'https://account.xiaomi.com/next')
        self.assertIsNotNone(result)
        request._no_redirect = True
        with self.assertRaises(ac.BindError):
            ac.XiaomiRedirect().redirect_request(request, None, 302, 'Found', {},
                                                 'https://account.xiaomi.com/next')


class LoginSecurityTests(unittest.TestCase):
    def test_extension_pragma_session_fields(self):
        extension = json.dumps({'ssecurity': SESSION['security'], 'nonce': 7})
        self.assertEqual(ac.login_security({'code': 0}, extension), (SESSION['security'], 7))

    def test_body_fields_take_precedence(self):
        self.assertEqual(ac.login_security({'ssecurity': SESSION['security'], 'nonce': '7'}, 'bad-json'),
                         (SESSION['security'], 7))

    def test_account_verification_precedes_session_parsing(self):
        with self.assertRaisesRegex(ac.BindError, 'additional account verification') as ctx:
            ac.login_security({'code': 0, 'securityStatus': 16,
                               'notificationUrl': 'https://account.xiaomi.com/secret-test'})
        self.assertNotIn('secret-test', str(ctx.exception))

    def test_missing_fields_report_safe_structure(self):
        with self.assertRaisesRegex(ac.BindError, 'Extension-Pragma present=False') as ctx:
            ac.login_security({'code': 0, 'userId': 'private-test-id'})
        self.assertNotIn('private-test-id', str(ctx.exception))

    def test_invalid_status_or_nonce_rejected(self):
        for response in ({'securityStatus': '16'}, {'ssecurity': SESSION['security'], 'nonce': True}):
            with self.subTest(response=response), self.assertRaises(ac.BindError):
                ac.login_security(response)


class BrowserLoginTests(unittest.TestCase):
    def server(self, bad_url=False, expired=False):
        class BrowserServer:
            def __init__(inner):
                from http.cookiejar import CookieJar
                inner.cookies = CookieJar()
                inner.calls = []

            def request(inner, url, data=None, headers=None, timeout=30):
                inner.calls.append((url, timeout))
                if 'loginUrl?' in url:
                    return json.dumps({'code': 0, 'loginUrl': 'https://account.xiaomi.com/longPolling/login?ticket=test',
                        'lp': 'https://attacker.test/' if bad_url else 'https://eu.lp.account.xiaomi.com/lp/s?ticket=test'}).encode()
                if '/lp/s?' in url:
                    if expired:
                        return b'{"code":70016}'
                    return json.dumps({'code': 0, 'ssecurity': SESSION['security'], 'nonce': 7,
                                       'location': 'https://hlth.io.mi.com/sts', 'userId': '12345',
                                       'cUserId': 'browser-test-id'}).encode()
                inner.cookies.set_cookie(ac.Cookie(0, 'serviceToken', 'browser-test-token', None, False,
                    'hlth.io.mi.com', False, False, '/', True, True, None, True, None, None, {}, False))
                return b''
        return BrowserServer()

    def test_browser_login_waits_for_website_then_obtains_service_token(self):
        http, links = self.server(), []
        session = ac.browser_login(http, 'test-phone', links.append)
        self.assertEqual(session['service_token'], 'browser-test-token')
        self.assertEqual(session['c_user_id'], 'browser-test-id')
        self.assertEqual(len(links), 1)
        self.assertEqual(http.calls[1][1], 300)
        self.assertEqual(len(http.calls), 3)
        self.assertNotIn('password', json.dumps(session))

    def test_untrusted_poll_endpoint_rejected_before_opening_browser(self):
        links = []
        with self.assertRaises(ac.BindError):
            ac.browser_login(self.server(bad_url=True), 'test-phone', links.append)
        self.assertEqual(links, [])

    def test_expired_browser_login_never_contacts_sts(self):
        http = self.server(expired=True)
        with self.assertRaises(ac.BindError):
            ac.browser_login(http, 'test-phone', lambda _: None)
        self.assertEqual(len(http.calls), 2)


if __name__ == '__main__':
    unittest.main()
