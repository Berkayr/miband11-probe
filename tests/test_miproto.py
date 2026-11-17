import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import miproto  # noqa: E402

VECTORS = json.loads((ROOT / "tests/freeband_vectors.json").read_text())


def vec(name: str) -> bytes:
    return bytes.fromhex(VECTORS[name])


class FreebandBytes(unittest.TestCase):
    """Our encoders against bytes produced by Freeband's Swift code (tests/freeband_vectors.py)."""

    def test_bind_start(self):
        self.assertEqual(miproto.bind_start_command("miband11-probe"), vec("start_probe"))
        self.assertEqual(miproto.bind_start_command("freeband-probe"), vec("start_freeband_probe"))
        self.assertEqual(miproto.bind_start_command("u", "Freeband"), vec("start_named"))

    def test_bind_start_frame(self):
        frame = miproto.encode_frame(miproto.KIND_DATA, 0,
                                     miproto.data_payload(miproto.bind_start_command("miband11-probe")))
        self.assertEqual(frame, vec("frame_start_probe_seq0"))

    def test_session_and_ack(self):
        self.assertEqual(miproto.encode_frame(miproto.KIND_SESSION_CONFIG, 0, miproto.START_SESSION_PAYLOAD),
                         vec("frame_session_config"))
        self.assertEqual(miproto.encode_frame(miproto.KIND_ACK, 5, b""), vec("frame_ack_seq5"))

    @unittest.skipUnless(os.environ.get("FREEBAND_DIR") and shutil.which("swiftc"), "needs FREEBAND_DIR and swiftc")
    def test_vectors_file_is_current(self):
        out = subprocess.run([sys.executable, str(ROOT / "tests/freeband_vectors.py")],
                             check=True, capture_output=True, text=True).stdout
        self.assertEqual(json.loads(out), VECTORS)


class BandReplies(unittest.TestCase):
    def reply(self, name: str) -> dict:
        buf = bytearray(b"\x00\x13" + vec(name) + b"\xa5\xa5\x03")
        packets = miproto.drain(buf)
        self.assertEqual(len(packets), 1)
        kind, _, payload = packets[0]
        self.assertEqual((kind, payload[:2]), (miproto.KIND_DATA, b"\x01\x01"))
        self.assertEqual(bytes(buf), b"\xa5\xa5\x03")  # partial frame kept
        return miproto.parse_bind_reply(payload[2:])

    def test_local_button(self):
        r = self.reply("frame_band_info_local_button")
        self.assertEqual((r["verify_mode_name"], r["oob_mode_name"], r["model"]), ("APP_LOCAL", "BUTTON_CONFIRM", "M0000"))
        self.assertEqual((r["serial_number"], r["mac"], r["did"]), ("SN0000", "AA:BB:CC:DD:5E:6F", "did0"))

    def test_server(self):
        self.assertEqual(self.reply("frame_band_info_server")["verify_mode"], 1)

    def test_already_bound(self):
        self.assertEqual(self.reply("frame_band_already_bound"), {"error_code": 1, "error": "HAVE_BOUND"})

    def test_bad_crc_dropped(self):
        frame = bytearray(vec("frame_band_info_server"))
        frame[-1] ^= 1
        self.assertEqual(miproto.drain(frame), [])

    def test_other_command_ignored(self):
        self.assertIsNone(miproto.parse_bind_reply(miproto.pb_varint(1, 2) + miproto.pb_varint(2, 1)))
        self.assertIsNone(miproto.parse_bind_reply(b"\xff"))

    def test_mask(self):
        self.assertEqual(miproto.mask("AA:BB:CC:DD:5E:6F"), "*************E:6F")
        self.assertEqual(miproto.mask(""), "")


if __name__ == "__main__":
    unittest.main()
