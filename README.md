# Zay - A simple network tool

See `zay --help` for usage.

## Standalone SOCKS5 server

`cargo run -p zay-server --bin s5 -- --listen 127.0.0.1:1080` starts the
standalone SOCKS5 server in `client/server/bin/s5.rs`, using the existing
singbox listener for TCP and UDP forwarding. See
[the server README](client/server/README.md) for authentication and build options.

## Native desktop (macOS)

`client/desktop` is a GPUI Kit + Ely desktop app linked directly to the Zay Rust
library. It provides native proxy and Mesh configuration, service controls, live
status, and a persistent macOS menu-bar menu. Closing the window keeps services
running; quitting stops the desktop-owned services.

```sh
cargo run --manifest-path client/desktop/Cargo.toml --locked
```

See [the desktop README](client/desktop/README.md) for packaging and authorization.

## WebUI

`zay webui` starts the React control plane and all enabled components in the
foreground. It never daemonizes or installs a system service; use systemd,
launchd, or your preferred process manager when persistence is required.

On Linux, put the executable in its permanent location, then generate a systemd
unit with the current executable and configuration paths:

```bash
zay x systemctl > zay.service                    # WebUI: 127.0.0.1:18888
zay x systemctl --port 3333 > zay.service        # custom port
```

The generated comments include installation, startup, logging, and shutdown
commands. `--config FILE` and `--data-dir DIR` select custom configuration paths.
The service runs as root for TUN access; stop any manually started Zay before
starting the system service.

By default the WebUI listens on `127.0.0.1:8787` and does not try to open a
desktop browser, so the same command works on headless Linux. Use `--open` on a
desktop. A non-loopback `--listen` requires a bearer `--token` (or
`ZAY_WEBUI_TOKEN`).

On macOS/Linux, `zay webui` requests administrator authorization once in the
launching terminal (including with `--no-start-core`). The supervised core host
keeps that authorization for the WebUI session, so stopping, starting, and
applying configuration from the browser do not depend on sudo's timestamp.
Exiting the WebUI also exits the host. System services running as root do not
prompt. Passwords are not retained or sent through the browser or HTTP API.

Saving configuration in the WebUI applies changes to affected components:
proxy changes replace the proxy runtime while Mesh stays connected; Mesh
identity changes replace Mesh only. Changes to Mesh addresses, peer/listener
routes, or enablement also update the proxy's dependent routes. Unchanged
configuration does not restart components. The UI reports application failures
and offers a retry; the explicit full restart action still restarts all components.

## Application traffic usage

The macOS desktop and WebUI **Overview** show per-application upload, download,
direct, and proxied usage. Recording starts with the proxy by default. Pause
keeps existing totals; **Reset usage** clears them and starts counting active
connections from zero. macOS app helpers are grouped under their parent `.app`;
unresolved processes appear under **Unattributed**.

Only traffic handled by Zay is counted. TUN includes direct and proxy routes,
except excluded routes; without TUN, only traffic sent to Zay's proxy listeners
is included. Counts measure forwarded payload, rather than physical interface
bytes or proxy protocol overhead.

Usage is stored in `singbox/application-traffic.json` in the selected data
directory, separately from the DNS cache. It survives proxy restarts and
configuration changes and remains visible while stopped. Desktop and CLI use
their respective data directories. Totals are checkpointed every five seconds
and on graceful shutdown; a crash can lose the latest uncheckpointed usage.

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
