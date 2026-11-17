import struct
import unittest

import band_link as bl
import miproto as pb


class FakeAtt:
    """ATT socket stand-in: records sent PDUs, replays queued ones."""

    def __init__(self, incoming):
        self.sent, self.incoming = [], list(incoming)

    def send(self, pdu):
        self.sent.append(pdu)

    def recv(self, _size):
        return self.incoming.pop(0) if self.incoming else b''

    def settimeout(self, _value):
        pass


def notify(handle, data):
    return struct.pack('<BH', 0x1B, handle) + data


class BleLink(unittest.TestCase):
    def link(self, incoming):
        link = bl.BleBandLink('AA:BB:CC:DD:EE:FF')
        link.sock = FakeAtt(incoming)  # type: ignore[assignment]
        return link

    def test_write_splits_into_write_commands(self):
        link = self.link([])
        link.write(bytes(600))
        sent = link.sock.sent  # type: ignore[union-attr]
        self.assertEqual([len(p) - 3 for p in sent], [244, 244, 112])
        self.assertTrue(all(p[:3] == struct.pack('<BH', 0x52, bl.TX_HANDLE) for p in sent))

    def test_read_skips_other_pdus(self):
        link = self.link([b'\x0a\x01\x00', notify(0x0099, b'x'), notify(bl.RX_HANDLE, b'frame')])
        self.assertEqual(link.read(), b'frame')

    def test_read_reports_disconnect(self):
        self.assertEqual(self.link([]).read(), b'')

    def test_exchange_acks_and_parses_split_frame(self):
        command = pb.pb_varint(1, 1) + pb.pb_varint(2, 26) + pb.pb_bytes(3, pb.pb_bytes(31, b'ok'))
        frame = pb.encode_frame(pb.KIND_DATA, 7, pb.data_payload(command))
        link = self.link([notify(bl.RX_HANDLE, frame[:5]), notify(bl.RX_HANDLE, frame[5:])])
        account = link.exchange(b'cmd', 26)
        self.assertEqual(account[31], b'ok')
        ack = pb.encode_frame(pb.KIND_ACK, 7, b'')
        self.assertEqual(link.sock.sent[-1][3:], ack)  # type: ignore[union-attr]

    def test_l2_address_is_little_endian(self):
        addr = bl._l2_address('11:22:33:44:55:66')
        self.assertEqual(bytes(addr.bdaddr), bytes.fromhex('665544332211'))
        self.assertEqual((addr.cid, addr.bdaddr_type), (4, 1))


if __name__ == '__main__':
    unittest.main()
