import asyncio
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import miproto  # noqa: E402
import probe  # noqa: E402
from test_miproto import vec  # noqa: E402


class FakeBand:
    """Answers the session config, then 1/17 with the given frame; records what the phone sent."""

    def __init__(self, reply_frame: bytes):
        self.reply_frame, self.sent, self.session = reply_frame, [], None

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)
        kind = frame[2]
        if kind == miproto.KIND_SESSION_CONFIG:
            asyncio.get_running_loop().call_soon(asyncio.ensure_future, self.session.feed(
                miproto.encode_frame(miproto.KIND_SESSION_CONFIG, 0, b"\x02\x01\x03\x00\x01\x00\x00")))
        elif kind == miproto.KIND_DATA:
            # Split in two chunks, as BLE notifications may be.
            half = len(self.reply_frame) // 2
            for chunk in (self.reply_frame[:half], self.reply_frame[half:]):
                asyncio.get_running_loop().call_soon(asyncio.ensure_future, self.session.feed(chunk))


def run(reply_frame: bytes):
    async def go():
        with tempfile.TemporaryDirectory() as tmp:
            band = FakeBand(reply_frame)
            session = probe.Session(probe.Log(pathlib.Path(tmp, "x.log")), band.send)
            band.session = session
            ok = await session.run(1)
            return ok, session.result, band.sent
    return asyncio.run(go())


class ProbeFlow(unittest.TestCase):
    def test_local_reply(self):
        ok, result, sent = run(vec("frame_band_info_local_button"))
        self.assertTrue(ok)
        self.assertEqual(result["verify_mode"], 2)
        # Exactly: session config, 1/17, ACK of the band's frame. Nothing after step 1.
        self.assertEqual(sent, [vec("frame_session_config"), vec("frame_start_probe_seq0"),
                                miproto.encode_frame(miproto.KIND_ACK, 0, b"")])

    def test_already_bound(self):
        ok, result, _ = run(vec("frame_band_already_bound"))
        self.assertTrue(ok)
        self.assertEqual(result["error"], "HAVE_BOUND")

    def test_no_reply_times_out(self):
        ok, result, sent = run(b"")
        self.assertFalse(ok)
        self.assertIsNone(result)
        self.assertEqual(len(sent), 2)

    def test_help(self):
        out = subprocess.run([sys.executable, str(ROOT / "probe.py"), "--help"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("--transport", out.stdout)


if __name__ == "__main__":
    unittest.main()
