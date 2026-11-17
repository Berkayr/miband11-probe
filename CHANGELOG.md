# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-17

### Added
- `probe.py`: read `verify_mode` / `oob_mode` / model from a factory-fresh band (BLE or SPP).
- `account_bind.py`: Xiaomi account login (password or browser with email verification) and a full SERVER_PSK bind over RFCOMM, without Mi Fitness.
- `account_auth.py`: fetch the persistent auth key once and authenticate fresh connections offline; `--transport ble` option.
- `le_gatt.py`, `force_local.py`, `v1_probe.py`: GATT listing and the failed APP_LOCAL / V1 experiments.
- README with measured results, failed attempts and FAQ.

[0.1.0]: https://github.com/Berkayr/miband11-probe/releases/tag/v0.1.0
