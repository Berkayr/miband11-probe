import json
import os
import sqlite3
import tempfile
import unittest

import freeband_key as fk
from account_cloud import BindError


class FreebandKeyTest(unittest.TestCase):
    def test_manifest_matches_freeband_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'manifest.sqlite')
            fk.write_manifest(out, '00' * 16, 'AA:BB:CC:DD:EE:FF')
            self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
            rows = sqlite3.connect(out).execute(
                "select key, inline_data, filename from manifest where key like 'registerList%'").fetchall()
            self.assertEqual(rows[0][0], 'registerList_de')
            self.assertEqual(json.loads(rows[0][1])['list'][0]['encryptKey'], '00' * 16)
            self.assertIsNone(rows[0][2])

    def test_rejects_bad_key_and_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'manifest.sqlite')
            with self.assertRaises(BindError):
                fk.write_manifest(out, 'xyz', 'AA:BB:CC:DD:EE:FF')
            fk.write_manifest(out, '11' * 16, 'AA:BB:CC:DD:EE:FF')
            with self.assertRaises(FileExistsError):
                fk.write_manifest(out, '11' * 16, 'AA:BB:CC:DD:EE:FF')


if __name__ == '__main__':
    unittest.main()
