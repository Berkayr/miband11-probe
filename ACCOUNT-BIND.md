# Experimental Xiaomi-account binding

`account_bind.py` implements one SERVER_PSK binding attempt using your Xiaomi account,
without running Mi Fitness. It sends device identifiers and proofs to Xiaomi's servers.
**Verified on one Band 11 (miwear.watch.q66gln), 2026-11-17:** Xiaomi-account binding
and fresh-connection authentication both succeeded from a Raspberry Pi 5 (BlueZ) over RFCOMM channel 5.
Other devices, firmware versions and transports remain untested.

The existing `probe.py` still performs only the initial mode probe.

Requires Python 3.10+, Linux Bluetooth RFCOMM support and `cryptography` 43 or newer.
The existing cryptography installation supplies AES-CCM and legacy RC4 protocol support;
no additional package is installed by this tool. Uses the Band 11's measured RFCOMM channel 5.
The server region must match your account/service region; no automatic region guesses are made.

For accounts requiring email verification, use browser login. Run this on the desktop
that has your browser (the session itself is created and stored on the SSH host):

```sh
python3 open_browser_login.py --ssh USER@HOST --remote-dir /path/to/miband11-probe --region de
```

The launcher opens Xiaomi's HTTPS login page. Enter your email, password and email
verification code **on Xiaomi's page**, then confirm login if asked. The remote client
waits up to five minutes using Xiaomi's long-polling login flow and receives the result.
No password, email verification code or browser cookie is copied into this client.
The temporary login URL is kept in memory and is not printed or saved by the launcher.

Alternatively, run `python3 account_bind.py login-browser --region de` on the SSH host
and open the URL displayed in your own terminal. That temporary link must remain private.

Direct password login remains available in your own terminal, using `getpass`:

```sh
python3 account_bind.py login --region de
python3 account_bind.py bind --address AA:BB:CC:DD:EE:FF
```

The address above is a placeholder. Region values: `cn`, `de`, `us`, `sg`, `in`, `ru`.
The `de` endpoint is the European service endpoint; the account's actual endpoint still
needs to be confirmed. Direct password login makes one attempt and stops at captcha/2FA. Browser login lets
you complete those steps on Xiaomi's website. Neither login command binds the band;
automatic token renewal is not implemented.
Never send your password, session file, keys or raw account-command dumps to a chat.

Binding uses fresh BindInfoV2 from the same open device connection, then:
`hello → 1/18 → ecdh → 1/19/button confirmation → bind → 1/25`.
Only SERVER_PSK with BUTTON_CONFIRM is supported. Press the band's on-screen button
when prompted. No firmware updates or automatic resets are performed.
`--support-find` advertises phone-finding support; the Band 11 capability default is
not confirmed, so this flag is experimental.

Local state goes to `$XDG_STATE_HOME/miband11-probe` (normally
`~/.local/state/miband11-probe`), outside the source tree, with directory mode 700 and file mode 600:

- `identity.json`: stable random client identifier.
- `session.json`: miothealth session secrets; no password is saved.
- `band-*.json`: device key and progress checkpoint, saved before confirmation/finalization.

State files are **plaintext protected by filesystem permissions**, not encrypted storage.
Keep them out of cloud sync and backups you do not control. Health requests only go to
Xiaomi HTTPS endpoints; redirects of requests containing explicit account tokens are refused.
The client does not log HTTP bodies, raw band frames or keys. Safe error messages omit
server messages, account identifiers, tokens and redirect URLs.

An existing device checkpoint blocks another bind attempt. A failed final response can mean
the server or band already changed state: do not delete the checkpoint or blindly retry.
No automatic resume, rollback or unbind is implemented. A successful final bind reply means the bind commands were accepted. The temporary
`device_key` is separate from the cloud `detail.encrypt_key` used for reconnect auth. Do not reset the band until the state and recovery material are reviewed.

To verify a fresh Bluetooth connection after binding:

```sh
python3 account_auth.py --address AA:BB:CC:DD:EE:FF
```

The first auth run reads the account's source list, selects only the bound device by its
server device ID, and stores its validated 16-byte `detail.encrypt_key` in the private
checkpoint as `cloud_auth_key`. It then verifies the band HMAC and requires the explicit
1/27 success flag. Later auth runs use this saved key without accessing Xiaomi's servers.
No rebinding or reset is performed. A wrong HMAC stops before auth confirmation is sent.
The command authenticates and disconnects; continuous data sync is outside its scope.

`--transport ble` runs the same auth over BLE V2 (write commands to `005f`, notifications
from `005e`, LE-only ATT socket; Python < 3.14 builds the `sockaddr_l2` with ctypes).
Observed on 2026-11-17: after a bind that declared an Android companion (`device_type = 0`,
which this client sends), the band no longer advertises over LE, so the BLE connection is
refused. Mi Fitness on iOS and Freeband declare `device_type = 1` (IOS); whether a bind with
that value keeps LE advertising is untested.

Offline verification (from the project directory):

```sh
PYTHONPATH=.:tests python3 -m unittest discover -s tests -v
pyright account_bind.py account_cloud.py band_link.py account_auth.py open_browser_login.py
```

Protocol facts were independently implemented from the locally inspected Mi Fitness 3.59.2i
`PSKWearBinderV2`, `CloudInterceptor`, `nl4`, `rk4`, `XMPassport`, and protobuf field layouts.
Existing framing helpers retain their Freeband MIT attribution in `miproto.py`.
The health response envelope uses `result`, not `data`; success codes are 0 or 200.
No claim is made that the APK's product catalog supports this particular Band 11 firmware.
