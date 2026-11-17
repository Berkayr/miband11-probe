"""Builds test vectors with Freeband's own Swift code and prints them as JSON.

Usage: FREEBAND_DIR=<freeband clone> python3 tests/freeband_vectors.py > tests/freeband_vectors.json

Freeband's files import CryptoKit/CommonCrypto, which Linux Swift lacks, so the needed
declarations (MiFrame, PBWriter, MiBind.command/envelope/startCommand) are cut out of the
sources verbatim and compiled next to a small MD5 shim. The shim is checked by the Python
side: a wrong MD5 makes the 1/17 vectors differ.
"""

import os
import pathlib
import subprocess
import sys
import tempfile

SHIM = r"""
import Foundation

// Stand-in for CryptoKit's Insecure.MD5 (RFC 1321).
enum Insecure {
    enum MD5 {
        static func hash(data: Data) -> [UInt8] {
            let s: [UInt32] = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                               4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21]
            let k: [UInt32] = (0..<64).map { UInt32(truncatingIfNeeded: Int64(abs(sin(Double($0 + 1))) * 4294967296.0)) }
            var m = [UInt8](data)
            let bitLen = UInt64(m.count) * 8
            m.append(0x80)
            while m.count % 64 != 56 { m.append(0) }
            for i in 0..<8 { m.append(UInt8((bitLen >> (8 * UInt64(i))) & 0xFF)) }
            var a0: UInt32 = 0x67452301, b0: UInt32 = 0xefcdab89, c0: UInt32 = 0x98badcfe, d0: UInt32 = 0x10325476
            for chunk in stride(from: 0, to: m.count, by: 64) {
                let w: [UInt32] = (0..<16).map { i in
                    (0..<4).reduce(UInt32(0)) { $0 | UInt32(m[chunk + i * 4 + $1]) << (8 * UInt32($1)) }
                }
                var a = a0, b = b0, c = c0, d = d0
                for i in 0..<64 {
                    var f: UInt32
                    var g: Int
                    switch i {
                    case 0..<16: f = (b & c) | (~b & d); g = i
                    case 16..<32: f = (d & b) | (~d & c); g = (5 * i + 1) % 16
                    case 32..<48: f = b ^ c ^ d; g = (3 * i + 5) % 16
                    default: f = c ^ (b | ~d); g = (7 * i) % 16
                    }
                    f = f &+ a &+ k[i] &+ w[g]
                    a = d; d = c; c = b
                    b = b &+ ((f << s[i]) | (f >> (32 - s[i])))
                }
                a0 = a0 &+ a; b0 = b0 &+ b; c0 = c0 &+ c; d0 = d0 &+ d
            }
            return [a0, b0, c0, d0].flatMap { v in (0..<4).map { UInt8((v >> (8 * UInt32($0))) & 0xFF) } }
        }
    }
}
"""

MAIN = r"""
func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

// BandLink.sendCommand (BandLink.swift:1039-1052), plaintext branch.
func dataFrame(_ protobuf: Data, seq: UInt8) -> Data {
    MiFrame.encode(kind: MiFrame.kindData, seq: seq, payload: Data([0x01, 0x01]) + protobuf)
}

// The band's BindInfoV2 / error replies as Freeband's tests build them (tests/protocol/main.swift:210-225).
func bandInfo(verify: UInt64, oob: UInt64) -> Data {
    var body = PBWriter()
    body.varint(1, verify); body.string(2, "SN0000"); body.string(3, "AA:BB:CC:DD:5E:6F"); body.string(4, "M0000")
    body.varint(5, oob); body.bytes(6, Data(0x70...0x7F)); body.string(7, "did0")
    var account = PBWriter(); account.message(12, body)
    var command = PBWriter(); command.varint(1, 1); command.varint(2, 17); command.message(3, account)
    return command.data
}
func bandError(_ id: UInt64, _ code: UInt64) -> Data {
    var account = PBWriter(); account.varint(3, code)
    var command = PBWriter(); command.varint(1, 1); command.varint(2, id); command.message(3, account)
    return command.data
}

let out: [String: String] = [
    "start_probe": hex(MiBind.startCommand(userID: "miband11-probe", deviceName: "")),
    "start_freeband_probe": hex(MiBind.startCommand(userID: "freeband-probe", deviceName: "")),
    "start_named": hex(MiBind.startCommand(userID: "u", deviceName: "Freeband")),
    "frame_start_probe_seq0": hex(dataFrame(MiBind.startCommand(userID: "miband11-probe", deviceName: ""), seq: 0)),
    "frame_session_config": hex(MiFrame.encode(kind: MiFrame.kindSessionConfig, seq: 0, payload: MiFrame.startSessionPayload)),
    "frame_ack_seq5": hex(MiFrame.encode(kind: MiFrame.kindAck, seq: 5, payload: Data())),
    "frame_band_info_local_button": hex(dataFrame(bandInfo(verify: 2, oob: 3), seq: 0)),
    "frame_band_info_server": hex(dataFrame(bandInfo(verify: 1, oob: 3), seq: 1)),
    "frame_band_already_bound": hex(dataFrame(bandError(17, 1), seq: 0)),
]
let json = try! JSONSerialization.data(withJSONObject: out, options: [.sortedKeys, .prettyPrinted])
print(String(decoding: json, as: UTF8.self))
"""


def cut(source: str, start: str) -> str:
    """The declaration beginning at the line containing `start`, up to its closing brace."""
    begin = source.index(start)
    begin = source.rindex("\n", 0, begin) + 1
    depth, i = 0, source.index("{", begin)
    while True:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[begin:i + 1] + "\n"
        i += 1


def main() -> None:
    root = pathlib.Path(os.environ["FREEBAND_DIR"]) / "ios/Freeband/Band"
    proto = (root / "MiProtocol.swift").read_text()
    bind = (root / "MiBind.swift").read_text()
    extracted = cut(proto, "enum MiFrame {") + cut(proto, "struct PBWriter {") + "enum MiBind {\n"
    for line in ("static let commandType", "static let idStart"):
        extracted += next(l for l in bind.splitlines() if line in l) + "\n"
    for fn in ("private static func command(", "private static func envelope(", "static func startCommand("):
        extracted += cut(bind, fn)
    extracted += "}\n"
    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp, "main.swift")
        src.write_text(SHIM + extracted + MAIN)
        exe = pathlib.Path(tmp, "vectors")
        subprocess.run(["swiftc", "-O", str(src), "-o", str(exe)], check=True)
        sys.stdout.write(subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout)


if __name__ == "__main__":
    main()
