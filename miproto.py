"""Xiaomi wear protocol pieces needed for the bind probe (no I/O).

Ported from Freeband (MIT, https://github.com/cobanov/freeband, commit b98aa77):
  - frames, CRC, session config: ios/Freeband/Band/MiProtocol.swift (enum MiFrame)
  - protobuf writer/reader:      ios/Freeband/Band/MiProtocol.swift (PBWriter, PBMessage)
  - BindStartV2 (1/17), BindInfoV2: ios/Freeband/Band/MiBind.swift (startCommand, bandInfo)
  - data frame payload 01 01 + protobuf: ios/Freeband/Band/BandLink.swift:1039-1052 (sendCommand)
Field numbers are documented in Freeband docs/BIND.md section 2.
"""

import hashlib

KIND_NACK, KIND_ACK, KIND_SESSION_CONFIG, KIND_DATA = 0, 1, 2, 3

# START_SESSION_REQUEST: opcode 1, TLVs version 01.00.00, max frame 0xFC00, TX window 32, timeout 10000 ms.
START_SESSION_PAYLOAD = bytes([
    0x01,
    0x01, 0x03, 0x00, 0x01, 0x00, 0x00,
    0x02, 0x02, 0x00, 0x00, 0xFC,
    0x03, 0x02, 0x00, 0x20, 0x00,
    0x04, 0x02, 0x00, 0x10, 0x27,
])

CMD_TYPE_ACCOUNT = 1
ID_BIND_START = 17

VERIFY_MODES = {1: "SERVER_PSK", 2: "APP_LOCAL"}
OOB_MODES = {0: "NO_OOB", 1: "NUMERIC_COMPARISON", 2: "DYNAMIC_CODE", 3: "BUTTON_CONFIRM"}
ERROR_CODES = {
    0: "NO_ERROR", 1: "HAVE_BOUND", 2: "INFO_MISSING", 3: "INVALID_PARAM", 4: "NO_BOUND",
    5: "SERVER_ERROR", 6: "CANCEL", 7: "VERIFY_ERROR", 8: "STATE_NOT_MATCH", 9: "USER_CHANGED",
    10: "CONNECTION_REACH_LIMIT", 100: "UNKNOWN",
}


def crc16_arc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def encode_frame(kind: int, seq: int, payload: bytes) -> bytes:
    """a5 a5 | type | seq | len (u16 LE) | crc16 (u16 LE) | payload"""
    crc = crc16_arc(payload)
    return bytes([0xA5, 0xA5, kind & 0x0F, seq & 0xFF,
                  len(payload) & 0xFF, len(payload) >> 8, crc & 0xFF, crc >> 8]) + payload


def drain(buffer: bytearray) -> list[tuple[int, int, bytes]]:
    """Removes complete frames from the front of `buffer` as (kind, seq, payload).

    Junk before a preamble and frames with a bad CRC are dropped; a partial frame stays.
    """
    packets = []
    while len(buffer) >= 2:
        if buffer[0] != 0xA5 or buffer[1] != 0xA5:
            nxt = buffer.find(0xA5, 1)
            del buffer[:nxt if nxt > 0 else len(buffer)]
            continue
        if len(buffer) < 3:
            break
        if buffer[2] & 0x0F > KIND_DATA:
            del buffer[0]
            continue
        if len(buffer) < 8:
            break
        length = buffer[4] | buffer[5] << 8
        if len(buffer) < 8 + length:
            break
        crc = buffer[6] | buffer[7] << 8
        payload = bytes(buffer[8:8 + length])
        kind, seq = buffer[2] & 0x0F, buffer[3]
        del buffer[:8 + length]
        if crc16_arc(payload) == crc:
            packets.append((kind, seq, payload))
    return packets


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def pb_varint(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def pb_bytes(field: int, value: bytes) -> bytes:
    return _varint(field << 3 | 2) + _varint(len(value)) + value


def bind_start_command(user_id: str, device_name: str = "") -> bytes:
    """Command{1: 1, 2: 17, 3: Account{11: BindStartV2{1: false, 2: MD5(user_id), 3: name?}}}"""
    start = pb_varint(1, 0) + pb_bytes(2, hashlib.md5(user_id.encode()).digest())
    if device_name:
        start += pb_bytes(3, device_name.encode())
    account = pb_bytes(11, start)
    return pb_varint(1, CMD_TYPE_ACCOUNT) + pb_varint(2, ID_BIND_START) + pb_bytes(3, account)


def data_payload(command: bytes) -> bytes:
    """Channel 1 (protobuf), opcode 1 (plaintext), then the command."""
    return bytes([0x01, 0x01]) + command


def pb_parse(data: bytes) -> dict[int, int | bytes] | None:
    """Last varint or length-delimited value per field; None when malformed."""
    fields: dict[int, int | bytes] = {}
    i = 0

    def read_varint():
        nonlocal i
        result = shift = 0
        while i < len(data) and shift < 64:
            byte = data[i]
            i += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
        return None

    while i < len(data):
        key = read_varint()
        if key is None:
            return None
        field, wire = key >> 3, key & 7
        if wire == 0:
            value = read_varint()
            if value is None:
                return None
            fields[field] = value
        elif wire == 2:
            n = read_varint()
            if n is None or n > len(data) - i:
                return None
            fields[field] = data[i:i + n]
            i += n
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if len(data) - i < size:
                return None
            i += size
        else:
            return None
    return fields


def parse_bind_reply(command: bytes) -> dict | None:
    """Reads the band's 1/17 answer: BindInfoV2 or Account.error_code. None if it is not one."""
    msg = pb_parse(command)
    if not msg or msg.get(1) != CMD_TYPE_ACCOUNT or msg.get(2) != ID_BIND_START:
        return None
    raw_account = msg.get(3)
    account = pb_parse(raw_account) if isinstance(raw_account, bytes) else {}
    if account is None:
        return None
    raw_info = account.get(12)
    info = pb_parse(raw_info) if isinstance(raw_info, bytes) else None
    if info is None:
        code = account.get(3)
        return {"error_code": code, "error": ERROR_CODES.get(code, "?")} if isinstance(code, int) else {"raw": True}

    def text(field):
        value = info.get(field, b"")
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)

    verify, oob = info.get(1), info.get(5)
    verify = verify if isinstance(verify, int) else None
    oob = oob if isinstance(oob, int) else None
    return {
        "verify_mode": verify, "verify_mode_name": VERIFY_MODES.get(verify, "?") if verify is not None else "missing",
        "oob_mode": oob, "oob_mode_name": OOB_MODES.get(oob, "?") if oob is not None else "missing",
        "model": text(4), "serial_number": text(2), "mac": text(3), "did": text(7),
    }


def mask(value: str, keep: int = 4) -> str:
    """Identifiers (MAC, serial, did) stay out of shareable output."""
    return "*" * max(len(value) - keep, 0) + value[-keep:] if value else ""
