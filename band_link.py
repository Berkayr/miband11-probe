"""Framed Mi Wear commands over the Band 11's RFCOMM channel or its BLE V2 characteristics.

No raw frames are logged: account commands can contain pairing secrets.
"""

import collections
import ctypes
import ctypes.util
import os
import socket
import struct
import time

import miproto
from account_cloud import BindError


class BandLink:
    def __init__(self, address, channel=5):
        self.address, self.channel = address, channel
        self.sock = None
        self.buffer = bytearray()
        self.pending = collections.deque()
        self.seq = 0
        self.seen = collections.deque(maxlen=32)

    def __enter__(self):
        try:
            self.open()
            self.send(miproto.KIND_SESSION_CONFIG, miproto.START_SESSION_PAYLOAD)
            deadline = time.monotonic() + 20
            while True:
                kind, _, payload = self.receive(deadline)
                if kind == miproto.KIND_SESSION_CONFIG:
                    if not payload or payload[0] != 2:
                        raise BindError('Band rejected session configuration.')
                    return self
        except BaseException:
            if self.sock is not None:
                self.sock.close()
            raise

    def __exit__(self, *args):
        if self.sock is not None:
            self.sock.close()

    def open(self):
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        self.sock.settimeout(20)
        self.sock.connect((self.address, self.channel))

    def write(self, data):
        assert self.sock is not None
        self.sock.sendall(data)

    def read(self):
        assert self.sock is not None
        return self.sock.recv(4096)

    def send(self, kind, payload):
        if self.sock is None:
            raise BindError('Band link is not open.')
        seq = self.seq if kind == miproto.KIND_DATA else 0
        self.write(miproto.encode_frame(kind, seq, payload))
        if kind == miproto.KIND_DATA:
            self.seq = (self.seq + 1) & 255

    def receive(self, deadline):
        if self.sock is None:
            raise BindError('Band link is not open.')
        while not self.pending:
            left = deadline - time.monotonic()
            if left <= 0:
                raise BindError('Timed out waiting for band response.')
            self.sock.settimeout(left)
            chunk = self.read()
            if not chunk:
                raise BindError('Band disconnected; binding outcome may be incomplete.')
            self.buffer.extend(chunk)
            if len(self.buffer) > 65543:
                raise BindError('Band frame exceeded buffer limit.')
            for kind, seq, payload in miproto.drain(self.buffer):
                if kind == miproto.KIND_NACK:
                    raise BindError('Band rejected a frame (NACK); no automatic replay.')
                if kind == miproto.KIND_DATA:
                    self.write(miproto.encode_frame(miproto.KIND_ACK, seq, b''))
                    packet = (seq, payload)
                    if packet in self.seen:
                        continue
                    self.seen.append(packet)
                self.pending.append((kind, seq, payload))
        return self.pending.popleft()

    def exchange(self, command, cid, timeout=30):
        self.send(miproto.KIND_DATA, miproto.data_payload(command))
        deadline = time.monotonic() + timeout
        while True:
            kind, _, payload = self.receive(deadline)
            if kind != miproto.KIND_DATA or payload[:2] != b'\x01\x01':
                continue
            msg = miproto.pb_parse(payload[2:])
            if not msg:
                raise BindError('Malformed command from band.')
            if msg.get(1) != 1 or msg.get(2) != cid:
                continue
            raw = msg.get(3)
            account = miproto.pb_parse(raw) if isinstance(raw, bytes) else None
            if account is None:
                raise BindError('Missing Account response.')
            error = account.get(3, 0)
            if not isinstance(error, int) or error:
                safe = miproto.ERROR_CODES.get(error, 'UNKNOWN') if isinstance(error, int) else 'INVALID'
                raise BindError('Band account error: ' + safe)
            return account


ATT_CID = 4
BDADDR_LE_PUBLIC = 1
# shortcut: 005e/005f value handles as discovered by le_gatt.py on a Band 11; discover by UUID if they ever differ
RX_HANDLE, TX_HANDLE = 0x0016, 0x0019
ATT_MTU = 247
SOL_BLUETOOTH, BT_SECURITY, BT_SECURITY_MEDIUM = 274, 4, 2


class _SockaddrL2(ctypes.Structure):
    _fields_ = [('family', ctypes.c_ushort), ('psm', ctypes.c_ushort), ('bdaddr', ctypes.c_ubyte * 6),
                ('cid', ctypes.c_ushort), ('bdaddr_type', ctypes.c_ubyte)]


def _l2_address(address):
    raw = bytes.fromhex(address.replace(':', ''))[::-1]
    return _SockaddrL2(socket.AF_BLUETOOTH, 0, (ctypes.c_ubyte * 6)(*raw), ATT_CID, BDADDR_LE_PUBLIC)


def le_att_socket(address, secure=False):
    """LE-only ATT socket; BlueZ would otherwise pick BR/EDR for this dual-mode band."""
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    try:
        if secure:
            # Encrypt with the stored LE bond; without it the band shows "Pair with phone" on every auth.
            sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, struct.pack('BB', BT_SECURITY_MEDIUM, 0))
        if hasattr(socket, 'BDADDR_LE_PUBLIC'):
            sock.bind((socket.BDADDR_ANY, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
            sock.settimeout(20)
            sock.connect((address, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
            return sock
        # Python < 3.14 cannot express cid/address type in the tuple, so pass sockaddr_l2 directly.
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        local = _l2_address('00:00:00:00:00:00')
        if libc.bind(sock.fileno(), ctypes.byref(local), ctypes.sizeof(local)) != 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        remote = _l2_address(address)
        if libc.connect(sock.fileno(), ctypes.byref(remote), ctypes.sizeof(remote)) != 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return sock
    except BaseException:
        sock.close()
        raise


class BleBandLink(BandLink):
    """Same framed protocol over BLE V2: write commands to 005f, notifications from 005e."""

    secure = False

    def open(self):
        self.sock = le_att_socket(self.address, self.secure)
        self.sock.settimeout(20)
        self.request(struct.pack('<BH', 0x02, ATT_MTU), 0x03)
        self.request(struct.pack('<BHH', 0x12, RX_HANDLE + 1, 1), 0x13)

    def request(self, pdu, expected):
        assert self.sock is not None
        self.sock.send(pdu)
        while True:
            reply = self.sock.recv(512)
            if reply[:1] == bytes([expected]):
                return reply
            if reply[:1] == b'\x01':
                raise BindError('Band refused an ATT setup request.')

    def write(self, data):
        assert self.sock is not None
        for i in range(0, len(data), ATT_MTU - 3):
            self.sock.send(struct.pack('<BH', 0x52, TX_HANDLE) + data[i:i + ATT_MTU - 3])

    def read(self):
        assert self.sock is not None
        while True:
            pdu = self.sock.recv(512)
            if not pdu:
                return b''
            if pdu[0] == 0x1B and struct.unpack('<H', pdu[1:3])[0] == RX_HANDLE:
                return pdu[3:]


class SecureBleBandLink(BleBandLink):
    """BLE link encrypted with the host's LE bond; needs one pairing accepted on the band first."""
    secure = True
