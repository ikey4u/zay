# Zay - A simple network tool

See `zay --help` for usage.

## WebUI

`zay webui` starts the React control plane and all enabled components in the
foreground. It never daemonizes or installs a system service; use systemd,
launchd, or your preferred process manager when persistence is required.

By default the WebUI listens on `127.0.0.1:8787` and does not try to open a
desktop browser, so the same command works on headless Linux. Use `--open` on a
desktop. A non-loopback `--listen` requires a bearer `--token` (or
`ZAY_WEBUI_TOKEN`).

On macOS/Linux, if the enabled configuration needs TUN or a Mesh node,
`zay webui` requests sudo authorization in the launching terminal before the
HTTP server starts. Only the supervised core child is elevated. Passwords never
pass through the browser or HTTP API.

The former command-line interfaces are retained under the unstable `zay x`
namespace: `zay x run`, `zay x config`, and `zay x service`. They are internal
and may change without compatibility guarantees.

# PREBUILT FILES NOTICE

**sing-box** is implemented as the native Rust library in `crates/singbox` and linked into zay; no Go toolchain or sing-box executable is required at build or runtime. `inner/sing-box` remains only as the pinned upstream reference used for migration and differential tests.

**EasyTier** is a Cargo path dependency on `vendor/Easytier` (same submodule pin).

Windows packages additionally include runtime files extracted from the following official prebuilt archives. `build.rs` verifies each archive with the pinned SHA-256 hash before using it.

| File(s) used | Source archive | SHA-256 |
| --- | --- | --- |
| `Packet.lib`, `libpacket.a` | `https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip` | `ea799cf2f26e4afb1892938070fd2b1ca37ce5cf75fec4349247df12b784edbd` |
| `Packet.dll` | `https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe` | `fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de` |
| `wintun.dll` | `https://www.wintun.net/builds/wintun-0.14.1.zip` | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| `WinDivert64.sys` | `https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip` | `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15` |
