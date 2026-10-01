# Zay Desktop

A native macOS client built with [GPUI Kit](https://gpui-kit.com/),
[Ely GPUI Components](https://github.com/ZacharyZhang-NY/Ely-GPUI-Components), and
the Zay Rust library. No browser, WebView, WebUI server, or HTTP control API is
used by the desktop interface.

## Features

- Native proxy configuration: enable/disable, HTTP/SOCKS5 port, subscription URLs,
  and system TUN. Advanced existing Zay routing settings are preserved.
- Native Mesh configuration: enable/disable, node/relay role, network name,
  masked network secret, peer URLs, and virtual IPv4 or DHCP.
- Start, stop, save, and selectively apply changes through `zay::desktop::Client`.
- Live proxy readiness and Mesh peer status from the networking library.
- Persistent **Zay** menu-bar item and native application menus.
- Closing the window keeps the networking services running. Reopen from the
  menu bar or Dock. **Quit Zay stops the services owned by this app.**
- Light/dark appearance, kept across window reopenings in the same session.

The desktop owns separate configuration in
`~/Library/Application Support/Zay Desktop/zay.toml`. Set `ZAY_DESKTOP_DATA_DIR`
to use a different directory. It does not modify the CLI's configuration.
Initially the proxy is configured for port 7890 with TUN off, and services are
stopped. Set a free port and click **Start services**. Empty subscriptions mean
direct routing; enter your subscription URLs to use remote proxy nodes.

TUN and Mesh node mode require administrator privileges. Enter your local
administrator password in the native Proxy or Mesh page before starting/applying
those modes. The library launches the same desktop binary as a supervised,
privileged worker, before any GUI initialization. The password is passed to sudo
stdin, never stored in the config or sent over HTTP. The authorized worker remains
available until the desktop exits. Non-TUN proxy and Mesh relay run in process.
No Network Extension or provisioning profile is needed for this architecture.

## Build and run

Requires macOS 13+, Rust 1.98+, Apple's developer tools, and `protoc` for the
networking library. From the repository root:

```sh
cargo run --manifest-path client/desktop/Cargo.toml --locked

# Locally signed app bundle; release by default.
client/desktop/scripts/bundle-macos.sh
# Faster development bundle:
client/desktop/scripts/bundle-macos.sh --debug
open "client/desktop/dist/Zay Desktop.app"
```

The script uses ad-hoc signing for local builds. Public distribution additionally
needs Developer ID signing and notarization. Builds target the host architecture.
Windows/Linux and launch-at-login are not implemented in this first release.

## Architecture

- `src/desktop.rs`: native GPUI views, inputs, menus, and application lifecycle.
- `src/backend.rs`: a serialized command worker on its own Tokio runtime. Slow
  network operations and service changes never block the GUI event loop.
- Repository `src/lib.rs` / `src/desktop.rs`: reusable Zay library and native-client
  API. The desktop disables Zay's default `webui` feature, so it neither builds
  nor embeds WebUI assets.
- Privileged operations reuse Zay's authenticated local worker channel and
  parent-process lifetime monitoring. There is no external CLI installation to
  locate or launch.

The independent Cargo workspace preserves the core's tested dependency versions
in its lockfile and adds GPUI Kit 0.7.0. Ely is pinned to commit
`cb45f5232f9fdf86453e18ea4991d5ac78a9cc6a`. Its GPUI Git package names are mapped
through two small `compat/` re-export crates to Kit's exact GPUI 0.3.7 snapshot.
Ely source is unmodified; both libraries share one App/Window/Element runtime.

Format owned code with `./scripts/fmt.sh`, or verify with `--check`.

## Manual smoke check

1. Build/launch and verify the native window and global Zay menu-bar item.
2. Set a free local proxy port, keep TUN off, and start services. Verify HTTP or
   SOCKS5 traffic passes through the configured port.
3. Save a new port while running; verify the proxy moves to the new port.
4. Configure a Mesh relay with a test network name/secret, save/apply, and verify
   the instance appears. Node/TUN testing requires explicit local authorization.
5. Close the window, switch apps, and reopen from the menu bar; services remain
   active and only one window opens. Check light/dark rendering.
6. Choose Quit Zay and verify the proxy port and Mesh listeners close.
