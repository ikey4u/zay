# zay fork notes

This directory vendors `shadowsocks` 1.25.0 (MIT) from
`shadowsocks-rust`. The protocol, cipher and replay-protection implementation
is otherwise kept upstream-compatible.

The local delta adds a thread-safe `context::TimeProvider`. AEAD-2022 TCP and
UDP timestamp generation and validation read that provider instead of calling
`SystemTime::now()` directly. The default provider is still the system clock;
`crates/singbox` installs its shared `NtpClock` when NTP is enabled.

Keep this delta when updating the vendored release, or remove the fork once
upstream exposes an equivalent injectable clock API.
