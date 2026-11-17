# miband11-probe

Research tools for the Xiaomi Smart Band 11: measure how a factory-fresh band wants to be
bound, and bind it with a Xiaomi account **without installing Mi Fitness**.

> Experimental. Not affiliated with or endorsed by Xiaomi. Use only with your own band and
> your own account. Binding talks to Xiaomi's servers and changes the band's state.

## Findings (one Band 11, model `miwear.watch.q66gln`, 2026-11-17)

| Question | Result |
|---|---|
| Bind mode reported by `1/17 BindStartV2` | `verify_mode = 1` (SERVER_PSK) |
| Out-of-band confirmation | `oob_mode = 3` (tap a button on the band) |
| Local, serverless first bind (APP_LOCAL) | not possible: the band drops the link or ignores APP_LOCAL steps |
| Transports | BT Classic SPP on RFCOMM channel 5; BLE V2 (service `FE95`, characteristics `005E`/`005F`) |
| Xiaomi-account bind without Mi Fitness | **works** (`account_bind.py`) |
| Reconnect auth with the stored key | **works**, no server needed after the first bind (`account_auth.py`) |
| BLE after binding as an Android companion (`device_type = 0`) | band stops LE advertising; SPP keeps working. BLE auth is untested |

So the first bind of a Band 11 needs Xiaomi's server (the server signs the exchange; the band
checks it against a key in its firmware). After that, the 16-byte auth key is enough to
authenticate on every new connection, offline.

Only one band was tested. Other firmware versions, other bands and BLE auth are untested.

## Tools

| File | What it does |
|---|---|
| `probe.py` | Sends only the session config and `1/17`, prints `verify_mode` / `oob_mode` / model, disconnects. BLE or SPP. |
| `account_bind.py` | Xiaomi login (password or browser with email verification) and a full SERVER_PSK bind over RFCOMM. |
| `open_browser_login.py` | Runs the browser login on an SSH host and opens Xiaomi's login page on your desktop. |
| `account_auth.py` | Fetches the persistent auth key once, then authenticates a fresh connection with it. |
| `le_gatt.py` | Read-only GATT listing over an LE-only ATT socket (BlueZ picks BR/EDR for this dual-mode band). |
| `force_local.py`, `v1_probe.py` | Experiments that try the APP_LOCAL and older V1 account commands. Kept for the record. |

Usage, state files and safety notes for the bind client: [ACCOUNT-BIND.md](ACCOUNT-BIND.md).

## Requirements

- Linux with BlueZ, Python 3.10+ (`le_gatt.py` and `force_local.py` need 3.14+).
- `cryptography` 43+ for the bind and auth tools; `bleak` for BLE in `probe.py`.
- SPP needs a Python built with `AF_BLUETOOTH` (the distribution's `/usr/bin/python3` usually is).

## Tests

```sh
PYTHONPATH=.:tests python3 -m unittest discover -s tests
```

No band or account needed. Frame encoders are checked against bytes produced by Freeband's
Swift code (`tests/freeband_vectors.json`).

## Privacy

- Nothing in this repository comes from a real band or account: no logs, MACs, serials,
  device ids or keys. Examples use placeholders such as `AA:BB:CC:DD:EE:FF`.
- The tools write raw frames and secrets only under `logs/` (git-ignored) or
  `~/.local/state/miband11-probe/` (mode 600). Do not share those files.
- The bind client sends your band's identifiers and bind proofs to Xiaomi; that is how the
  first bind works and cannot be avoided.

## Credits

- Framing, protobuf helpers and the bind probe flow are ported from
  [Freeband](https://github.com/cobanov/freeband) (MIT, commit `b98aa77`).
- Account HTTP and bind steps were implemented from a local reading of Mi Fitness 3.59.2i.
- Field numbers for V1 commands are protocol facts from public `wear_account.proto` definitions;
  no code was copied from AGPL projects.

## License

MIT, see [LICENSE](LICENSE).
