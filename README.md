# miband11-probe

Pair a **Xiaomi Smart Band 11** without the Mi Fitness app and get its **auth key** on Linux.
Also measures how a factory-fresh band wants to be bound (`verify_mode`), and documents
every pairing route we tried, including the ones that fail.

Keywords: Mi Band 11, Xiaomi Smart Band 11, Mi Fitness alternative, auth key, pairing without
Mi Fitness, Gadgetbridge auth key, Freeband, SERVER_PSK, BindStartV2, Bluetooth reverse engineering.

> Experimental. Not affiliated with or endorsed by Xiaomi. Use only with your own band and
> your own account. Binding talks to Xiaomi's servers and changes the band's state.

## Findings (one Band 11, model `miwear.watch.q66gln`, 2026-11-17/18)

| Question | Result |
|---|---|
| Bind mode reported by `1/17 BindStartV2` | `verify_mode = 1` (SERVER_PSK) |
| Out-of-band confirmation | `oob_mode = 3` (tap a button on the band) |
| Local, serverless first bind (APP_LOCAL) | not possible: the band drops the link or ignores APP_LOCAL steps |
| Transports | BT Classic SPP on RFCOMM channel 5; BLE V2 (service `FE95`, characteristics `005E`/`005F`) |
| Xiaomi-account bind without Mi Fitness | **works** (`account_bind.py`) |
| Reconnect auth with the stored key | **works**, no server needed after the first bind (`account_auth.py`) |
| BLE after binding as an Android companion (`device_type = 0`) | band stops LE advertising; SPP keeps working |
| Bind as an iOS companion (`device_type = 1`, `--transport ble --companion ios`) | **works**; LE advertising stays on, SPP is no longer offered |
| BLE reconnect auth after an iOS bind | **works**, but only on an encrypted (LE-bonded) link. On a plain link the band shows "Pair with Phone" every time and reports `1/16` with account field 10 = `{1: 3}` (failed) or `{1: 2}` (ok) |
| Silent BLE reconnect | **works** once bonded: set `BT_SECURITY_MEDIUM` on the ATT socket so the kernel encrypts with the stored LTK; no prompt, ~1 s |
| Freeband (iPhone, TestFlight 0.5.3) with this key | **works**: battery, heart rate and steps came in. Band 11 is not on Freeband's supported list |

So the first bind of a Band 11 needs Xiaomi's server (the server signs the exchange; the band
checks it against a key in its firmware). After that, the 16-byte auth key is enough to
authenticate on every new connection, offline.

Only one band was tested. Other firmware versions and other bands are untested. HRV and sleep
files from the Band 11 were not checked.

## What did not work (save yourself the time)

All on the same factory-fresh Band 11, 2026-11-17, before the account bind succeeded.

| Attempt | What the band did |
|---|---|
| APP_LOCAL bind: `1/17` then `1/18 AppVerify` with a P-256 public key (Freeband / Band 8 style) | ACK, then dropped the connection |
| `1/18 AppVerify` without `1/17` first | ACK, then 40 s of silence |
| `1/17` with `check_dynamic_code = true`, name and pid | dropped the connection |
| Old V1 account commands `1/0 BIND_STATUS`, `1/1 BIND_START`, `1/16 BOND_APPLY` | ACK, no answer |
| `1/2 BIND_RESULT` with a random token | ACK, no answer |
| `1/26` auth before any bind | `NO_BOUND (4)`, as expected |
| `bleak` GATT discovery | empty service list: BlueZ connects this dual-mode band over BR/EDR. Use an LE-only ATT socket (`le_gatt.py`) |
| SPP on RFCOMM channels 1-4 | 1 timed out, 2-4 refused; channel 5 is the one |
| Direct password login when the account asks for email verification | stops (`ssecurity` missing); use `login-browser` |
| BLE after a bind that declared an Android companion | no LE advertising at all, BLE connection refused |
| Capturing the pairing with an iPhone `sysdiagnose` (Bluetooth logging profile) | only shows the iPhone's own links; it cannot see a Linux host pairing the band |

Conclusion: there is no serverless first bind on this band. The server-signed bind through a
Xiaomi account is the route that works.

## FAQ

**Can I pair a Mi Band 11 without Mi Fitness?** Yes, with a Xiaomi account: `account_bind.py`
does the account bind directly. You still need an account; the band only accepts a
server-signed first bind.

**Can I pair it with no Xiaomi account and no server at all?** Not on the band we tested
(`verify_mode = 1`). See the table above.

**How do I get the auth key for Gadgetbridge or Freeband?** After `account_bind.py`,
`account_auth.py` fetches the 16-byte key from your account once and stores it locally
(`cloud_auth_key` in the state file). For Freeband, `freeband_key.py` writes it as a
`manifest.sqlite` (the Mi Fitness format Freeband reads); pick that file in Freeband's
import screen. Tested with Freeband on iPhone. Gadgetbridge is untested.

**Does it work from an iPhone?** Yes, with Freeband. Bind with `--transport ble --companion ios`
from Linux, export the key with `freeband_key.py`, copy `manifest.sqlite` to the phone (Files),
import it in Freeband, then accept "Pair with Phone" on the band and the iOS pairing dialog once.

## Tools

| File | What it does |
|---|---|
| `probe.py` | Sends only the session config and `1/17`, prints `verify_mode` / `oob_mode` / model, disconnects. BLE or SPP. |
| `account_bind.py` | Xiaomi login (password or browser with email verification) and a full SERVER_PSK bind over RFCOMM. |
| `open_browser_login.py` | Runs the browser login on an SSH host and opens Xiaomi's login page on your desktop. |
| `account_auth.py` | Fetches the persistent auth key once, then authenticates a fresh connection with it. |
| `freeband_key.py` | Writes the stored key as a `manifest.sqlite` for Freeband's key import (mode 600; delete it after import). |
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
