"""Framed Mi Wear commands over the Band 11's measured RFCOMM channel.

No raw frames are logged: account commands can contain pairing secrets.
"""

import collections
import socket
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
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        self.sock.settimeout(20)
        try:
            self.sock.connect((self.address, self.channel))
            self.send(miproto.KIND_SESSION_CONFIG, miproto.START_SESSION_PAYLOAD)
            deadline = time.monotonic() + 20
            while True:
                kind, _, payload = self.receive(deadline)
                if kind == miproto.KIND_SESSION_CONFIG:
                    if not payload or payload[0] != 2:
                        raise BindError('Band rejected session configuration.')
                    return self
        except BaseException:
            self.sock.close()
            raise

    def __exit__(self, *args):
        if self.sock is not None:
            self.sock.close()

    def send(self, kind, payload):
        if self.sock is None:
            raise BindError('Band link is not open.')
        seq = self.seq if kind == miproto.KIND_DATA else 0
        self.sock.sendall(miproto.encode_frame(kind, seq, payload))
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
            chunk = self.sock.recv(4096)
            if not chunk:
                raise BindError('Band disconnected; binding outcome may be incomplete.')
            self.buffer.extend(chunk)
            if len(self.buffer) > 65543:
                raise BindError('Band frame exceeded buffer limit.')
            for kind, seq, payload in miproto.drain(self.buffer):
                if kind == miproto.KIND_NACK:
                    raise BindError('Band rejected a frame (NACK); no automatic replay.')
                if kind == miproto.KIND_DATA:
                    self.sock.sendall(miproto.encode_frame(miproto.KIND_ACK, seq, b''))
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
