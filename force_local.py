"""Experiment: run the APP_LOCAL bind on a band that reports SERVER_PSK, and record its answers.

Flow and field numbers ported from Freeband (MIT) ios/Freeband/Band/MiBind.swift (commit b98aa77):
1/17 BindStartV2 -> 1/18 AppVerify{1 id, 2 P-256 X||Y} -> band DeviceVerify (field 18)
-> 1/19 AppConfirm{random, HMAC} -> band confirm (field 20) -> 1/25 BindResult (AES-CCM).
Modes:
  verify   send 1/17, then 1/18 regardless of verify_mode (default)
  direct   skip 1/17, send 1/18 straight after the session config
Everything goes over BLE V2 (005e/005f) with an LE-only ATT socket (Python 3.14+).
The resulting key, if any, lands in logs/ (git-ignored), never on the console.
"""

import hashlib
import hmac
import json
import os
import pathlib
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import miproto

ATT_CID, RX, TX = 4, 0x0016, 0x0019  # handles from le_gatt.py discovery on this band
USER_ID, APP_DEVICE_ID, DEVICE_NAME = "miband11-probe", "miband11-probe-linux", "Linux"
LOG = pathlib.Path(__file__).parent / "logs" / f"force-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"


def log(event: str, **data) -> None:
    LOG.parent.mkdir(exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps({"t": time.strftime("%H:%M:%S"), "event": event, **data}) + "\n")


class Link:
    def __init__(self, addr: str):
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        self.sock.bind((socket.BDADDR_ANY, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
        self.sock.settimeout(20)
        self.sock.connect((addr, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
        self.buffer = bytearray()
        self.seq = 0
        self._att(struct.pack("<BH", 0x02, 247))
        self._att(struct.pack("<BHH", 0x12, RX + 1, 1))  # enable notifications on 005e

    def _att(self, pdu: bytes) -> bytes:
        self.sock.send(pdu)
        while True:
            reply = self.sock.recv(512)
            if reply[0] != 0x1B:
                return reply

    def send(self, kind: int, payload: bytes) -> None:
        frame = miproto.encode_frame(kind, self.seq if kind == miproto.KIND_DATA else 0, payload)
        if kind == miproto.KIND_DATA:
            self.seq = (self.seq + 1) & 0xFF
        log("tx", hex=frame.hex())
        for i in range(0, len(frame), 244):
            self.sock.send(struct.pack("<BH", 0x52, TX) + frame[i:i + 244])

    def command(self, cmd: bytes) -> None:
        self.send(miproto.KIND_DATA, miproto.data_payload(cmd))

    def wait(self, kind_wanted: int, timeout: float):
        """Next frame of `kind_wanted`; data frames come back as parsed protobuf commands."""
        end = time.time() + timeout
        while time.time() < end:
            self.sock.settimeout(max(0.5, end - time.time()))
            try:
                pdu = self.sock.recv(512)
            except TimeoutError:
                break
            if pdu[0] != 0x1B or struct.unpack("<H", pdu[1:3])[0] != RX:
                continue
            self.buffer += pdu[3:]
            for kind, seq, payload in miproto.drain(self.buffer):
                log("rx", kind=kind, hex=payload.hex())
                if kind == miproto.KIND_DATA:
                    ack = miproto.encode_frame(miproto.KIND_ACK, seq, b"")  # ack echoes the frame's seq
                    self.sock.send(struct.pack("<BH", 0x52, TX) + ack)
                if kind == kind_wanted:
                    return payload
        return None


def pb_cmd(cid: int, field: int, body: bytes) -> bytes:
    return (miproto.pb_varint(1, 1) + miproto.pb_varint(2, cid)
            + miproto.pb_bytes(3, miproto.pb_bytes(field, body)))


def describe(payload: bytes | None) -> tuple[dict, dict]:
    if payload is None:
        return {"reply": "none (timeout)"}, {}
    msg = miproto.pb_parse(payload[2:]) or {}
    account = miproto.pb_parse(msg.get(3, b"")) if isinstance(msg.get(3), bytes) else {}
    account = account or {}
    out = {"cmd": f"{msg.get(1)}/{msg.get(2)}", "account_fields": sorted(account)}
    if isinstance(account.get(3), int):
        out["error_code"] = account[3]
        out["error"] = miproto.ERROR_CODES.get(account[3], "?")
    return out, account


def main() -> int:
    addr, mode = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "verify")
    log("start", mode=mode)
    link = Link(addr)
    link.send(miproto.KIND_SESSION_CONFIG, miproto.START_SESSION_PAYLOAD)
    if link.wait(miproto.KIND_SESSION_CONFIG, 15) is None:
        print("No session config reply.")
        return 2
    print("Session open.")

    if mode == "verify":
        link.command(miproto.bind_start_command(USER_ID))
        info = miproto.parse_bind_reply((link.wait(miproto.KIND_DATA, 20) or b"\0\0")[2:])
        print("1/17 ->", {k: info[k] for k in ("verify_mode_name", "oob_mode_name")} if info and "verify_mode" in info else info)

    private = ec.generate_private_key(ec.SECP256R1())
    nums = private.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    link.command(pb_cmd(18, 17, miproto.pb_bytes(1, APP_DEVICE_ID.encode()) + miproto.pb_bytes(2, pub)))
    print("-> 1/18 AppVerify (if the band asks for a button press, press it)")
    summary, account = describe(link.wait(miproto.KIND_DATA, 40))
    print("1/18 ->", summary)
    log("verify_reply", **summary)
    verify = miproto.pb_parse(account.get(18, b"")) if isinstance(account.get(18), bytes) else None
    if not verify:
        return 0

    # The band accepted local verify: finish the bind (Freeband MiBind stage .verify/.confirm/.result).
    band_key, band_random, band_sign = verify.get(1), verify.get(2), verify.get(3)
    peer = ec.EllipticCurvePublicNumbers(int.from_bytes(band_key[:32], "big"), int.from_bytes(band_key[32:], "big"),
                                         ec.SECP256R1()).public_key()
    secret = private.exchange(ec.ECDH(), peer)
    ok = hmac.compare_digest(hmac.new(secret, band_random, hashlib.sha256).digest(), band_sign)
    print("Band proof valid:", ok)
    app_random = os.urandom(16)
    block = HKDF(hashes.SHA256(), 64, app_random + band_random, b"miwear-bind").derive(secret)
    app_sign = hmac.new(secret, app_random, hashlib.sha256).digest()
    link.command(pb_cmd(19, 19, miproto.pb_bytes(1, app_random) + miproto.pb_bytes(2, app_sign)))
    print("-> 1/19 AppConfirm (press the button on the band if asked)")
    summary, account = describe(link.wait(miproto.KIND_DATA, 60))
    print("1/19 ->", summary)
    confirm = miproto.pb_parse(account.get(20, b"")) if isinstance(account.get(20), bytes) else None
    if not confirm or not confirm.get(1):
        return 0
    companion = miproto.pb_varint(1, 1) + miproto.pb_bytes(3, DEVICE_NAME.encode()) + miproto.pb_varint(4, 0xFFFFFFFF)
    info_pb = miproto.pb_bytes(1, USER_ID.encode()) + miproto.pb_bytes(2, companion)
    sealed = AESCCM(block[16:32], tag_length=4).encrypt(bytes(range(0x10, 0x1C)), info_pb, b"bind-data")
    link.command(pb_cmd(25, 29, miproto.pb_bytes(1, sealed)))
    summary, _ = describe(link.wait(miproto.KIND_DATA, 20))
    print("1/25 ->", summary)
    log("BOUND_KEYS", auth_key=block[40:56].hex(), app_device_id=APP_DEVICE_ID, block=block.hex())
    print(f"Keys saved to {LOG} (private).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
