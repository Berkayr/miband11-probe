"""Lists GATT services and characteristics over an LE-only ATT link (no pairing, no writes).

BlueZ picks BR/EDR for this dual-mode band, so bleak saw no GATT table. This opens the ATT
fixed channel (CID 4) with an LE public address directly. Needs Python 3.14+ (L2CAP cid and
bdaddr_type in the address tuple). Read-only: only discovery requests are sent.
"""

import socket
import struct
import sys

ATT_CID = 4


def uuid_str(raw: bytes) -> str:
    if len(raw) == 2:
        return f"{struct.unpack('<H', raw)[0]:04x}"
    return raw[::-1].hex()


def request(sock, pdu: bytes) -> bytes:
    sock.send(pdu)
    while True:
        reply = sock.recv(512)
        if reply and reply[0] not in (0x1B, 0x1D):  # skip notifications/indications
            return reply


def discover(sock, opcode: int, start: int, end: int, type16: int):
    """Read By Group Type (0x10) or Read By Type (0x08) until ATTRIBUTE_NOT_FOUND."""
    items = []
    while start <= end:
        reply = request(sock, struct.pack("<BHHH", opcode, start, end, type16))
        if reply[0] == 0x01:  # error response
            break
        size, body = reply[1], reply[2:]
        last = start
        for i in range(0, len(body) - size + 1, size):
            items.append(body[i:i + size])
            last = struct.unpack("<H", body[i + (2 if opcode == 0x10 else 0):i + (4 if opcode == 0x10 else 2)])[0]
        if last >= 0xFFFF or last < start:
            break
        start = last + 1
    return items


def main() -> int:
    addr = sys.argv[-1]
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    sock.settimeout(20)
    sock.bind((socket.BDADDR_ANY, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
    sock.connect((addr, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
    print("LE ATT connected.")
    mtu = request(sock, struct.pack("<BH", 0x02, 247))
    print(f"MTU reply: {mtu.hex()}")
    services = []
    for item in discover(sock, 0x10, 1, 0xFFFF, 0x2800):
        start, end = struct.unpack("<HH", item[:4])
        services.append((start, end, uuid_str(item[4:])))
    for start, end, uuid in services:
        print(f"service {uuid}  [{start:#06x}-{end:#06x}]")
        for item in discover(sock, 0x08, start, end, 0x2803):
            props, value_handle = item[2], struct.unpack("<H", item[3:5])[0]
            print(f"    char {uuid_str(item[5:])}  props={props:#04x} handle={value_handle:#06x}")
    sock.close()
    return 0




def bind_probe(addr: str) -> int:
    """Step 1 only (session config + 1/17) over BLE V2, raw ATT. Same frames as probe.py."""
    import miproto

    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    sock.settimeout(15)
    sock.bind((socket.BDADDR_ANY, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
    sock.connect((addr, 0, ATT_CID, socket.BDADDR_LE_PUBLIC))
    request(sock, struct.pack("<BH", 0x02, 247))
    rx, tx = 0x0016, 0x0019  # 005e notify, 005f write (from discovery on this band)
    print("CCCD:", request(sock, struct.pack("<BHH", 0x12, rx + 1, 1)).hex())
    buffer = bytearray()

    def send(frame: bytes) -> None:
        for i in range(0, len(frame), 244):
            sock.send(struct.pack("<BH", 0x52, tx) + frame[i:i + 244])

    def wait_for(kind_wanted: int):
        while True:
            pdu = sock.recv(512)
            if pdu[0] != 0x1B or struct.unpack("<H", pdu[1:3])[0] != rx:
                continue
            print("RX", pdu[3:].hex())
            buffer.extend(pdu[3:])
            for kind, seq, payload in miproto.drain(buffer):
                if kind == miproto.KIND_DATA:
                    send(miproto.encode_frame(miproto.KIND_ACK, seq, b""))
                if kind == kind_wanted:
                    return payload

    send(miproto.encode_frame(miproto.KIND_SESSION_CONFIG, 0, miproto.START_SESSION_PAYLOAD))
    print("-> SessionConfig")
    wait_for(miproto.KIND_SESSION_CONFIG)
    print("<- SessionConfig reply")
    send(miproto.encode_frame(miproto.KIND_DATA, 0, miproto.data_payload(miproto.bind_start_command("miband11-probe"))))
    print("-> 1/17")
    while True:
        payload = wait_for(miproto.KIND_DATA)
        reply = miproto.parse_bind_reply(payload[2:]) if len(payload) > 2 else None
        if reply:
            print({k: v for k, v in reply.items() if k not in ("serial_number", "mac", "did")})
            return 0


if __name__ == "__main__":
    sys.exit(bind_probe(sys.argv[2]) if sys.argv[1] == "bind" else main())
