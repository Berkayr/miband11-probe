# Security

This tool handles Xiaomi session tokens and band keys. They are stored only under
`~/.local/state/miband11-probe/` with mode 600 and are never printed or logged.

If you find a way these secrets could leak (logs, error messages, files in the repo),
please open a private report through GitHub's "Report a vulnerability" button instead of a
public issue. Do not attach session files, keys or raw frame logs to any report.
