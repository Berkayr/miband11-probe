import hashlib
import hmac
import json
import unittest
import urllib.parse

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

import account_auth as aa
import account_cloud as ac
import miproto as pb
from test_account_bind import KEY, SESSION, reference_rc4


class AuthBand:
    def __init__(self, bad_proof=False, success=1):
        self.commands = []
        self.bad_proof, self.success = bad_proof, success

    def exchange(self, command, cid):
        self.commands.append(cid)
        msg = pb.pb_parse(command)
        account = pb.pb_parse(msg[3])
        if cid == 26:
            self.phone = pb.pb_parse(account[30])[1]
            self.watch = bytes(range(16))
            # Independent HKDF extract/expand reference (RFC 5869).
            prk = hmac.digest(self.phone + self.watch, KEY, 'sha256')
            first = hmac.digest(prk, b'miwear-auth\x01', 'sha256')
            self.block = first + hmac.digest(prk, first + b'miwear-auth\x02', 'sha256')
            proof = bytes(32) if self.bad_proof else hmac.digest(self.block[:16], self.watch + self.phone, 'sha256')
            return {31: pb.pb_bytes(1, self.watch) + pb.pb_bytes(2, proof)}
        confirm = pb.pb_parse(account[32])
        assert confirm[1] == hmac.digest(self.block[16:32], self.phone + self.watch, 'sha256')
        companion = AESCCM(self.block[16:32], tag_length=4).decrypt(
            self.block[36:40] + bytes(8), confirm[2], None)
        assert pb.pb_parse(companion)[3] == b'Linux'
        return {33: pb.pb_varint(1, self.success)}


class AuthTests(unittest.TestCase):
    def test_auth_26_27_and_encrypted_companion(self):
        band = AuthBand()
        aa.authenticate(band, KEY)
        self.assertEqual(band.commands, [26, 27])

    def test_bad_hmac_stops_without_sending_confirm(self):
        band = AuthBand(bad_proof=True)
        with self.assertRaisesRegex(ac.BindError, 'HMAC'):
            aa.authenticate(band, KEY)
        self.assertEqual(band.commands, [26])

    def test_false_confirmation_is_failure(self):
        with self.assertRaisesRegex(ac.BindError, 'did not confirm'):
            aa.authenticate(AuthBand(success=0), KEY)

    def test_cloud_key_only_selected_for_bound_device(self):
        devices = {'list': [{'sid': 'other', 'detail': {'encrypt_key': '00' * 16}},
                            {'sid': 'wanted', 'detail': {'encrypt_key': KEY.hex()}}]}
        self.assertEqual(aa.cloud_auth_key(devices, 'wanted'), KEY)

    def test_missing_duplicate_or_invalid_cloud_device_key_rejected(self):
        entry = {'sid': 'wanted', 'detail': {'encrypt_key': KEY.hex()}}
        for devices in ({'list': []}, {'list': [entry, entry]},
                        {'list': [{'sid': 'wanted', 'detail': {'encrypt_key': 'bad'}}]}):
            with self.subTest(devices=devices), self.assertRaises(ac.BindError):
                aa.cloud_auth_key(devices, 'wanted')

    def test_cloud_list_path_is_signed_without_healthapp_prefix(self):
        class Server:
            def request(inner, url, data, headers):
                self.assertEqual(url, 'https://de.hlth.io.mi.com/app/v1/source/get_source_list')
                form = {k: v[0] for k,v in urllib.parse.parse_qs(data.decode()).items()}
                key = hashlib.sha256(bytes(range(32)) + ac.unb64(form['_nonce'])).digest()
                seed = ('POST&/app/v1/source/get_source_list&data=' + form['data']
                        + '&rc4_hash__=' + form['rc4_hash__'] + '&' + ac.b64(key))
                self.assertEqual(form['signature'], ac.b64(hashlib.sha1(seed.encode()).digest()))
                return ac.b64(reference_rc4(key, b'{"code":0,"result":{"list":[]}}')).encode()
        self.assertEqual(ac.HealthClient(SESSION, 'de', Server()).post('devices', {'page_size': 100}), {'list': []})


if __name__ == '__main__':
    unittest.main()
