"""Experiment: ask the band the old (V1) account commands and print what it answers.

Command ids/fields are protocol facts read from wear_account.proto (AstroBox-NG-Module-Pb):
1/0 BIND_STATUS, 1/1 BIND_START -> BindInfo{1 bind_key,2 did,3 model,4 mac,5 sign,6 serial},
1/2 BIND_RESULT{1 user_id, 2 token, 3 CompanionDevice}, 1/16 BOND_APPLY{1 hash_user_id}.
Usage: v1_probe.py <addr> <step...>   steps: status start bond result
Identifiers in replies are masked on the console; raw frames go to logs/.
"""
import hashlib
import os
import sys

import force_local as fl
import miproto

SHOW = {1: "bind_status", 3: "error_code", 4: "bind_info", 5: "bind_result", 10: "bond_reply", 12: "bind_info_v2"}


def run(link, cid: int, account_body: bytes, wait: float = 20) -> dict:
    cmd = miproto.pb_varint(1, 1) + miproto.pb_varint(2, cid) + miproto.pb_bytes(3, account_body)
    link.command(cmd)
    payload = link.wait(miproto.KIND_DATA, wait)
    if payload is None:
        return {"reply": "none"}
    msg = miproto.pb_parse(payload[2:]) or {}
    acc = miproto.pb_parse(msg.get(3, b"")) if isinstance(msg.get(3), bytes) else {}
    out = {"cmd": f"{msg.get(1)}/{msg.get(2)}"}
    for f, v in (acc or {}).items():
        name = SHOW.get(f, f"field{f}")
        if isinstance(v, bytes):
            sub = miproto.pb_parse(v)
            out[name] = {k: (miproto.mask(x.decode('utf-8', 'replace')) if isinstance(x, bytes) else x) for k, x in sub.items()} if sub else miproto.mask(v.hex())
        else:
            out[name] = v if f != 3 else f"{v} {miproto.ERROR_CODES.get(v, '?')}"
    return out


def main() -> int:
    addr, steps = sys.argv[1], sys.argv[2:]
    link = fl.Link(addr)
    link.send(miproto.KIND_SESSION_CONFIG, miproto.START_SESSION_PAYLOAD)
    if link.wait(miproto.KIND_SESSION_CONFIG, 15) is None:
        print("No session.")
        return 2
    for step in steps:
        if step == "status":
            r = run(link, 0, b"")
        elif step == "start":
            r = run(link, 1, b"")
        elif step == "bond":
            r = run(link, 16, miproto.pb_bytes(1, hashlib.md5(fl.USER_ID.encode()).digest()))
        elif step == "result":
            token = os.urandom(16).hex()
            fl.log("v1_token", token=token)
            companion = miproto.pb_varint(1, 1) + miproto.pb_bytes(3, b"Linux") + miproto.pb_varint(4, 0xFFFFFFFF)
            r = run(link, 2, miproto.pb_bytes(5, miproto.pb_bytes(1, fl.USER_ID.encode())
                                              + miproto.pb_bytes(2, token.encode()) + miproto.pb_bytes(3, companion)), 40)
        elif step == "start_dyn":  # BindStartV2 with check_dynamic_code=true, device name, pid
            body = (miproto.pb_varint(1, 1) + miproto.pb_bytes(2, hashlib.md5(fl.USER_ID.encode()).digest())
                    + miproto.pb_bytes(3, b"Linux") + miproto.pb_varint(4, 1))
            r = run(link, 17, miproto.pb_bytes(11, body))
        elif step == "auth":  # 1/26 AUTH_VERIFY with a phone nonce, as a bound app would log in
            r = run(link, 26, miproto.pb_bytes(30, miproto.pb_bytes(1, os.urandom(16))))
        else:
            continue
        print(step, "->", r)
        fl.log("v1_" + step, **{k: str(v) for k, v in r.items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
