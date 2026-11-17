"""Asks a factory-fresh Xiaomi band how it wants to be bound, and stops.

Sends only the session config and step 1 of the bind (1/17 BindStartV2), prints the band's
BindInfoV2 (verify_mode, oob_mode, model) and disconnects. No key is generated or written:
this file has no encoder for any later bind step. Flow follows Freeband's bind probe
(ios/Freeband/Band/BandLink.swift:541-590, MIT).

Raw hex of every frame goes to a local log file; it contains the band's MAC/serial/did,
so logs/ is git-ignored. Console output masks those.
"""

import argparse
import asyncio
import datetime
import json
import pathlib
import socket
import sys

import miproto

DEFAULT_NAME = "Xiaomi Smart Band 11"
FE95 = "0000fe95-0000-1000-8000-00805f9b34fb"
RX = "0000005e-0000-1000-8000-00805f9b34fb"  # band -> phone (notify)
TX = "0000005f-0000-1000-8000-00805f9b34fb"  # phone -> band (write)
V1_CHARS = {f"000000{c}-0000-1000-8000-00805f9b34fb" for c in ("51", "52", "53")}
DIS = {"2a24": "model_number", "2a26": "firmware_revision", "2a27": "hardware_revision", "2a28": "software_revision"}
USER_ID = "miband11-probe"


class Log:
    def __init__(self, path: pathlib.Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = path.open("a", encoding="utf-8")
        self.path = path

    def write(self, line: str, console: str | None = None) -> None:
        stamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.file.write(f"{stamp} {line}\n")
        self.file.flush()
        if console is not None:
            print(console)


class Session:
    """Frame handling shared by both transports: buffer, ACK, SessionConfig, 1/17 reply."""

    def __init__(self, log: Log, send):
        self.log, self.send = log, send
        self.buffer = bytearray()
        self.session_ok = asyncio.Event()
        self.answered = asyncio.Event()
        self.result: dict | None = None

    async def feed(self, chunk: bytes) -> None:
        self.log.write(f"RX {chunk.hex()}")
        self.buffer += chunk
        for kind, seq, payload in miproto.drain(self.buffer):
            if kind == miproto.KIND_SESSION_CONFIG:
                self.log.write(f"session config reply {payload.hex()}", "← SessionConfig reply")
                self.session_ok.set()
            elif kind == miproto.KIND_DATA:
                await self.send(miproto.encode_frame(miproto.KIND_ACK, seq, b""))
                self.on_data(payload)
            elif kind == miproto.KIND_NACK:
                self.log.write(f"NACK {seq}", f"← NACK {seq}")

    def on_data(self, payload: bytes) -> None:
        if len(payload) < 2:
            return
        channel, opcode, body = payload[0] & 0x0F, payload[1], payload[2:]
        if channel != 1 or opcode != 1:
            self.log.write(f"data ch={channel} op={opcode} {len(body)} bytes", f"← data ch={channel} op={opcode} ({len(body)} B)")
            return
        reply = miproto.parse_bind_reply(body)
        if reply is None:
            msg = miproto.pb_parse(body) or {}
            self.log.write(f"other command {msg.get(1)}/{msg.get(2)}", f"← command {msg.get(1)}/{msg.get(2)} (not 1/17)")
            return
        self.result = reply
        self.log.write("bind reply " + json.dumps(reply))
        self.answered.set()

    async def run(self, wait: float) -> bool:
        await self.send(miproto.encode_frame(miproto.KIND_SESSION_CONFIG, 0, miproto.START_SESSION_PAYLOAD))
        print("→ SessionConfig")
        try:
            await asyncio.wait_for(self.session_ok.wait(), wait)
        except TimeoutError:
            print("✗ No SessionConfig reply: the band did not open the V2 session on this transport.")
            return False
        command = miproto.bind_start_command(USER_ID)
        await self.send(miproto.encode_frame(miproto.KIND_DATA, 0, miproto.data_payload(command)))
        print(f"→ 1/17 BindStartV2 ({command.hex()})")
        try:
            await asyncio.wait_for(self.answered.wait(), wait)
        except TimeoutError:
            print("✗ No answer to 1/17.")
            return False
        return True


def report(result: dict, device: dict, log: Log) -> None:
    print("\n=== Result ===")
    if "error_code" in result:
        print(f"error_code = {result['error_code']} ({result['error']})")
        if result["error_code"] == 1:
            print("The band is already bound: reset it on the band and run again.")
    elif "verify_mode" in result:
        print(f"verify_mode = {result['verify_mode']} ({result['verify_mode_name']})")
        print(f"oob_mode    = {result['oob_mode']} ({result['oob_mode_name']})")
        print(f"model       = {result['model']}")
        print(f"serial/mac/did (masked) = {miproto.mask(result['serial_number'])} / "
              f"{miproto.mask(result['mac'])} / {miproto.mask(result['did'])}")
        verdict = {1: "SERVER_PSK: Xiaomi's server signature is required.",
                   2: "APP_LOCAL: local pairing without the server is possible."}
        print(verdict.get(result["verify_mode"], "Unknown verify mode."))
    else:
        print("1/17 reply without BindInfoV2 or error code (see log).")
    for key, value in device.items():
        print(f"{key:<17} = {value}")
    log.write("device " + json.dumps(device))
    print(f"\nRaw log (contains identifiers, keep private): {log.path}")


async def run_ble(args, log: Log) -> int:
    from bleak import BleakClient, BleakScanner

    if args.address:
        target = args.address
        print(f"Using address {miproto.mask(target, 5)}")
    else:
        print(f"Scanning {args.scan_time:.0f} s for '{args.name}'…")
        found = await BleakScanner.discover(timeout=args.scan_time, return_adv=True)
        candidates = []
        for dev, adv in found.values():
            name = adv.local_name or dev.name or ""
            xiaomi = FE95 in adv.service_uuids or FE95 in adv.service_data
            if args.name.lower() in name.lower() or (xiaomi and "band" in name.lower()):
                candidates.append((dev, name, adv.rssi))
                log.write(f"scan {dev.address} {name!r} rssi={adv.rssi} uuids={adv.service_uuids}",
                          f"  found {name!r} {miproto.mask(dev.address, 5)} rssi {adv.rssi}")
        if not candidates:
            print("✗ Band not found. Is it on, near the laptop and showing its pairing screen?")
            return 2
        target = max(candidates, key=lambda c: c[2])[0]

    async with BleakClient(target, pair=args.pair, timeout=30) as client:
        print("Connected.")
        services = client.services
        for service in services:
            for char in service.characteristics:
                log.write(f"gatt {service.uuid} {char.uuid} {','.join(char.properties)}")
        device: dict = {"transport": "BLE"}
        for char in services.characteristics.values():
            short = char.uuid[4:8]
            if short in DIS and "read" in char.properties:
                try:
                    value = bytes(await client.read_gatt_char(char))
                    device[DIS[short]] = value.decode("utf-8", "replace").strip("\x00")
                except Exception as exc:  # optional info, the probe goes on without it
                    log.write(f"DIS {short} read failed: {exc}")
        fe95 = services.get_service(FE95)
        chars = {c.uuid: c for c in fe95.characteristics} if fe95 else {}
        if RX not in chars or TX not in chars:
            if V1_CHARS <= chars.keys():
                print("✗ This band offers only the older V1 channel (0051-0053); the probe speaks V2.")
            else:
                print(f"✗ No FE95/005E/005F on BLE (FE95 chars: {sorted(c[4:8] for c in chars)}). "
                      "Try --transport spp.")
            return 3
        tx = chars[TX]
        with_response = "write-without-response" not in tx.properties
        size = max(20, client.mtu_size - 3)

        async def send(frame: bytes) -> None:
            log.write(f"TX {frame.hex()}")
            for i in range(0, len(frame), size):
                await client.write_gatt_char(tx, frame[i:i + size], response=with_response)

        session = Session(log, send)
        await client.start_notify(chars[RX], lambda _c, data: asyncio.ensure_future(session.feed(bytes(data))))
        ok = await session.run(args.wait)
        if ok and session.result is not None:
            report(session.result, device, log)
        return 0 if ok else 4


async def run_spp(args, log: Log) -> int:
    if not args.address:
        print("✗ --transport spp needs --address (the band's Bluetooth address).")
        return 2
    channels = [args.spp_channel] if args.spp_channel else range(1, 31)
    loop = asyncio.get_running_loop()
    sock = None
    for ch in channels:
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        s.settimeout(10)
        try:
            await loop.run_in_executor(None, s.connect, (args.address, ch))
        except OSError as exc:
            log.write(f"rfcomm ch {ch}: {exc}")
            s.close()
            continue
        sock = s
        print(f"RFCOMM channel {ch} connected.")
        break
    if sock is None:
        print("✗ No RFCOMM channel accepted the connection (pair the band first, or pass --spp-channel).")
        return 3
    sock.setblocking(False)

    async def send(frame: bytes) -> None:
        log.write(f"TX {frame.hex()}")
        await loop.sock_sendall(sock, frame)

    session = Session(log, send)

    async def reader() -> None:
        while chunk := await loop.sock_recv(sock, 4096):
            await session.feed(chunk)

    task = asyncio.ensure_future(reader())
    try:
        ok = await session.run(args.wait)
        if ok and session.result is not None:
            report(session.result, {"transport": "SPP"}, log)
        return 0 if ok else 4
    finally:
        task.cancel()
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--transport", choices=("ble", "spp"), default="ble")
    parser.add_argument("--address", help="band address; without it BLE scans by name")
    parser.add_argument("--name", default=DEFAULT_NAME, help=f"name to scan for (default: {DEFAULT_NAME!r})")
    parser.add_argument("--scan-time", type=float, default=15)
    parser.add_argument("--wait", type=float, default=15, help="seconds to wait for each reply (Mi Fitness: 15)")
    parser.add_argument("--pair", action="store_true", help="BLE: ask BlueZ to pair before the session")
    parser.add_argument("--spp-channel", type=int, help="SPP: RFCOMM channel (default: try 1-30)")
    parser.add_argument("--log", type=pathlib.Path,
                        default=pathlib.Path(__file__).parent / "logs" / f"probe-{datetime.datetime.now():%Y%m%d-%H%M%S}.log")
    args = parser.parse_args()
    log = Log(args.log)
    log.write(f"start {sys.argv[1:]}")
    runner = run_ble if args.transport == "ble" else run_spp
    try:
        return asyncio.run(runner(args, log))
    except Exception as exc:
        log.write(f"error {exc!r}", f"✗ {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
