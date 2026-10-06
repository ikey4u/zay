# Zay Desktop

A native macOS client built with [GPUI Kit](https://gpui-kit.com/),
[Ely GPUI Components](https://github.com/ZacharyZhang-NY/Ely-GPUI-Components), and
the Zay Rust library. No browser, WebView, WebUI server, or HTTP control API is
used by the desktop interface.

## Features

- Native proxy configuration: Start/Pause/Stop, HTTP/SOCKS5 port, subscription URLs,
  and system TUN. Advanced existing Zay routing settings are preserved.
- Native Mesh configuration: Start/Pause/Stop, node/relay role, network name,
  masked network secret, peer URLs, and virtual IPv4 or DHCP.
- Toggles apply immediately; text fields apply on Enter. Enabled Proxy and Mesh
  configurations resume automatically when the app opens; there is no global
  Start/Stop control.
- Proxy and Mesh have independent controls. Pause suspends that service and
  keeps its configuration for Resume; Stop turns it off without deleting its
  settings. Paused states persist across app restarts. Enable Mesh to reveal
  its setup form and service controls; Start or Save starts the configuration.
  Mesh alone does not start the HTTP/SOCKS5 proxy. Node startup uses the native
  networking helper when needed; Pause and Stop never request authorization.
- Downloaded subscription nodes appear in Proxy settings with an immediate
  selection control, Automatic mode, and subscription refresh.
- Input help icons open a dismissible popup with field guidance.
- Rules include a URL/domain/IP routing preview showing the matched rule and
  Direct or selected proxy. It uses saved configuration and cached subscriptions
  without opening connections or starting services. DNS and process/source
  metadata may change the result for a real connection.
- Live proxy readiness and Mesh peer status from the networking library.
- Persistent **Zay** menu-bar item and native application menus.
- Closing the window keeps the networking services running. Reopen from the
  menu bar or Dock. **Quit Zay stops the services owned by this app.**
- Light/dark appearance, kept across window reopenings in the same session.

The desktop owns separate configuration in
`~/Library/Application Support/Zay Desktop/zay.toml`. Set `ZAY_DESKTOP_DATA_DIR`
to use a different directory. It does not modify the CLI's configuration.
Fresh installations have Proxy and Mesh disabled, with proxy port 7890 and TUN
enabled in Preferences. TUN takes effect when Proxy runs. Set a free port and enable Proxy. Existing enabled configurations start
automatically on launch. Empty subscriptions mean direct routing; enter your
subscription URLs and press Enter to fetch and display remote proxy nodes.
Choose a node or Automatic to apply the selection immediately.

TUN and Mesh node mode use a separate, signed networking helper. The first time
one of these modes needs it, native macOS Authorization Services asks permission
to install the helper through `SMJobBless`, following ClashX's helper model.
The native permission dialog explains that the helper creates virtual network
interfaces and manages routes for TUN and Mesh node mode. Later launches reuse
the installed helper through authenticated XPC. The GUI
stays under the current user and never restarts as root. There are no scripts,
password fields, or administrator notices in the settings UI. macOS chooses the
authentication methods; Touch ID is not guaranteed. Cancelling restores the
previous settings and reports the cancellation without silently retrying.

The helper's launchd metadata associates it with `dev.zay.desktop`, so macOS can
label the background item with the app name instead of the certificate owner.
The helper checks the application's signing requirement on every XPC message.
It launches only its own installed executable, never a caller-supplied program.
The networking worker belongs to the GUI's XPC connection, watches its PID, and
stops when the GUI quits or disconnects. The installed launchd helper remains
available for later sessions but does not start networking by itself. Non-TUN
proxy and Mesh relay continue to run in process.

## Build and run

Requires macOS 13+, Rust 1.98+, Apple's developer tools, and `protoc` for the
networking library. From the repository root:

```sh
# Build/sign on the host and launch inside a dedicated macOS VM:
# Set APPLE_SIGN_IDENTITY in your shell environment first.
mise run dev:desktop

# Build the complete release .app and a versioned, architecture-specific ZIP:
mise run pkg:desktop

# Explicit host launch (enabled connections affect the host):
mise run dev:desktop:host

# Unprivileged development only (no app bundle or privileged helper):
cargo run --manifest-path client/desktop/Cargo.toml --locked

# Locally signed app bundle; release by default.
client/desktop/scripts/bundle-macos.sh
# Faster development bundle:
client/desktop/scripts/bundle-macos.sh --debug
open "client/desktop/dist/Zay Desktop.app"
```

The package task writes `Zay Desktop.app` and
`zay-desktop-macos-<architecture>-v<version>.zip` under `client/desktop/dist/`.
It includes the full app and its networking worker in one bundle; it does not
launch the app or start services. The development task opens the app inside the
dedicated desktop VM and resumes its enabled configurations there.

The development task builds a debug app bundle, including the helper, and deploys
it to `/Applications` inside a dedicated Tart macOS VM. The VM uses NAT networking
and has its own configuration and helper installation. By default it keeps the
guest's inherited DNS settings. If the host VPN supplies synthetic DNS addresses,
you can opt into a guest-only loopback DNS fixture with
`ZAY_DESKTOP_VM_DNS=alidns mise dev:desktop`. This sends guest DNS queries to
AliDNS (`dns.alidns.com`) over HTTPS with IPv4 answers. It does not run Zay on the
host or copy your Keychain, signing keys, browser profiles, or host configuration.
It requires an Apple Silicon Mac and reuses the macOS base image cached by
`mise setup:macosvm`. The disposable guest account is `admin` with password `admin`.

```sh
mise run dev:desktop:open   # Reopen the existing VM without rebuilding
mise run dev:desktop:logs   # Collect guest helper diagnostics
mise run dev:desktop:stop   # Shut down only the desktop VM
```

The desktop VM (`zay-desktop-macos`) is separate from the existing CLI/WebUI lab
(`zay-devpane-macos`). `mise dev:desktop:host` is an explicit opt-in to running
configured connections on the host.

The bundle script uses ad-hoc signing by default for UI, ordinary proxy, and
Mesh relay development. TUN and Mesh node mode require an Apple signing identity
already in your keychain. Local development can use Apple Development; public distribution uses
Developer ID Application. Set `APPLE_SIGN_IDENTITY` in your shell environment;
the tasks pass it to the bundle script without storing your identity in source:

```sh
APPLE_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" mise run dev:desktop
APPLE_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" mise run pkg:desktop
```

The script derives the actual Team ID, embeds reciprocal app/helper signing
requirements, and signs both executables. It does not install the helper or
start networking. Ad-hoc bundles reject privileged mode before any authorization
prompt rather than falling back to scripts or trusting arbitrary local programs.
Public distribution additionally needs notarization; the ZIP task does not
notarize or publish the app. Builds target the host architecture.
Windows/Linux and launch-at-login are not implemented in this first release.

## Architecture

- `src/desktop.rs`: native GPUI views, inputs, menus, and application lifecycle.
- `src/backend.rs`: a serialized command worker on its own Tokio runtime. Slow
  network operations and service changes never block the GUI event loop.
- Repository `src/lib.rs` / `src/desktop.rs`: reusable Zay library and native-client
  API. The desktop disables Zay's default `webui` feature, so it neither builds
  nor embeds WebUI assets.
- `native/macos/helper.m`: native Authorization Services installation, signed
  XPC connections, and a fixed worker launcher. The separate helper binary is
  bundled under `Contents/Library/LaunchServices` with embedded Info and launchd
  plists. The installed helper lives at
  `/Library/PrivilegedHelperTools/dev.zay.desktop.helper`.
- Privileged workers reuse Zay's authenticated local control channel and
  parent-process lifetime monitoring. The CLI/WebUI elevation path is separate.
- Helper source/configuration changes produce a new build identity. The app
  compares that identity before use and requests installation when an update
  is needed.

The independent Cargo workspace preserves the core's tested dependency versions
in its lockfile and adds GPUI Kit 0.7.0. Ely is pinned to commit
`cb45f5232f9fdf86453e18ea4991d5ac78a9cc6a`. Its GPUI Git package names are mapped
through two small `compat/` re-export crates to Kit's exact GPUI 0.3.7 snapshot.
Ely source is unmodified; both libraries share one App/Window/Element runtime.

Format owned code with `./scripts/fmt.sh`, or verify with `--check`.

## Manual smoke check

1. Build/launch and verify the native window and global Zay menu-bar item.
2. Set a free local proxy port, keep TUN off, and enable Proxy. Verify HTTP or
   SOCKS5 traffic passes through the configured port.
3. Enter a new port and press Enter while running; verify the proxy moves to the new port.
4. Configure a Mesh relay with a test network name/secret, enable Mesh, and verify
   the instance appears. Node/TUN testing requires explicit local authorization.
5. Close the window, switch apps, and reopen from the menu bar; services remain
   active and only one window opens. Check light/dark rendering.
6. Choose Quit Zay and verify the proxy port and Mesh listeners close.
7. Disable Proxy and Mesh, then relaunch. Change the port and press Enter; verify the
   setting persists without starting services. Enable TUN and verify the system
   helper installation authorization dialog appears (use a signed bundle and
   an uninstalled helper). Cancel it and verify the toggle returns to its
   prior value with an error. This step requires explicit network-test approval.
8. With the proxy running, quit from the Dock and verify its listener closes.
   Native termination waits for the networking worker, with a 60-second limit
   if shutdown stalls.

## UI review (services stopped)

The sidebar contains icon-only navigation with tooltips and a separate Preferences
icon. Rules uses a filter icon. The window title-bar status icon opens diagnostic
details in a dismissible popover with a Copy details action. The status trigger
is a small borderless icon. The signed bundle includes
the Zay application icon and uses an icon-only macOS menu-bar item. The running
app also sets its Dock icon explicitly so development launches and cached bundle
updates display the logo.

Errors appear only in the status popover; the title-bar icon indicates attention
without adding banners to pages. Cancelling authorization rolls back the requested
settings and leaves a Retry action in that popover. Retry reapplies that specific attempted configuration,
including TUN or Mesh enablement, and requests authorization again when needed.
There are no automatic authorization retries. The Dock icon uses a rounded tile
with transparent padding.

The desktop opens with an Overview of the proxy pool, actual TUN state, Mesh
peers and live connections at the bottom. Pages omit introductory
title banners. Proxy nodes use checkboxes: one pins a node, several
form an automatic candidate pool, and Automatic includes every fetched node.
Desktop profiles default to Global routing; Rules retains the CLI's built-in
direct-first fallback policy, and Direct uses a direct fallback. Mesh transport
and interface safety routes retain priority. Custom rules precede these modes.

Connections reads the running core's live controller, including helper-owned
cores, refreshed every second. Pending TCP dials appear immediately; the last
100 completed attempts remain available so short and
failed requests are inspectable. Active and closed rows are labelled separately.
Search matches destinations, processes and routes; activity and TCP/UDP filters
work in Overview. There is no separate Connections page.
Right-click a connection or open its Route menu to route that destination
and process through a node, the selected pool, or direct. Default TUN route
removes the override created for that connection. Applying a rule reconnects
proxy traffic; established streams cannot migrate between remote endpoints.
Rules supports host patterns, process names/paths, source and destination IPs
or CIDRs, immediate enable/disable, editing, and removal. Press Enter in the
rule editor to apply. In-process proxy logs and helper-worker logs feed the same diagnostic view.
HTTP, CONNECT and SOCKS traffic include destination, process and routing
attribution; CONNECT destinations participate in rule matching.
Logs shows the last 300 redacted structured events with timestamps, concise
error text, process, destination domain and route. Historical errors remain
visible; the log reader does not suppress real connection failures.

The macOS authorization dialog appears when the signed networking helper needs
installation or update. An already installed current helper does not ask again
on every TUN toggle. Disabling the last privileged feature stops the root core
and resumes ordinary proxy service under the desktop user's account.

Use a temporary `ZAY_DESKTOP_DATA_DIR` when reviewing the interface. Keep services
stopped and do not enable Proxy, TUN, or Mesh during UI-only reviews.

- Check Overview, Proxy, Mesh, Rules, Logs, and Preferences in light
  and dark appearance.
- Scroll the settings pages: the header remains visible and there is no save bar.
- Switch between Node and Relay: only Node shows peer and virtual IP fields.
- Verify keyboard navigation and visible input focus. Enter an invalid port and
  press Enter to check the error banner without starting any service.
- Check text wrapping and controls at the 860 × 620 minimum window size.

Subscription cards show the source host and fetched proxy count. Click a card to
inspect and select its nodes; the last card adds a subscription. Subscription URL
credentials and query tokens are never displayed on cards. Proxy controls appear
alongside routing mode and the listening port. TUN is a persistent option in
Preferences; changing it does not enable a stopped or paused Proxy.

Logs supports text search and severity filters. Mesh appears immediately after
Proxy in navigation. Its Node/Relay tabs and compact fields appear only when
Mesh is enabled. Fields remain a draft until Save; disabling Mesh applies
immediately. Test connection uses an isolated EasyTier session with TUN disabled:
Node tests authenticate a remote peer, Relay tests verify listener startup. It
closes the temporary session and never saves the draft. Save uses the existing
macOS networking helper when Node mode needs its virtual interface.
