# Zay - A simple network tool

See `zay --help` for usage.

## Persistent runtime

`zay service start` starts components enabled in `zay.toml` after detaching
from the terminal. It writes logs to
`<data-dir>/logs/zay.log` and provides `zay service status`, `zay service logs --follow`, and
`zay service stop`.

The supervisor always runs as the invoking user. On macOS/Linux, if
`[proxy].tun` is enabled, `zay service start` requests administrator authorization
before detaching, then elevates only its sing-box TUN worker. User
configuration and service control files therefore stay editable without running
the whole service through `sudo`. Use `zay service start`, not `sudo zay service start`.

On Windows, the TUN worker opens the normal UAC prompt and is tracked through
its launcher process. It does not inherit the supervisor's stdout/stderr.

`zay run proxy`, `zay run ssh`, `zay run fwd`, and `zay run http` remain foreground,
one-off commands. They do not read or create `zay.toml`; `zay run proxy` stores
its generated runtime files in the system temporary directory. Configure
`[proxy]`, `[proxy.mesh]`, `[[ssh]]`, `[[fwd]]`, or `[[http]]` when an
equivalent component should persist.

# PREBUILT FILES NOTICE

Windows packages include runtime files extracted from the following official prebuilt archives. `build.rs` verifies each archive with the pinned SHA-256 hash before using it.

| File(s) used | Source archive | SHA-256 |
| --- | --- | --- |
| `Packet.lib`, `libpacket.a` | `https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip` | `ea799cf2f26e4afb1892938070fd2b1ca37ce5cf75fec4349247df12b784edbd` |
| `Packet.dll` | `https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe` | `fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de` |
| `wintun.dll` | `https://www.wintun.net/builds/wintun-0.14.1.zip` | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| `WinDivert64.sys` | `https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip` | `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15` |
