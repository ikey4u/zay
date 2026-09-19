# Zay iOS — Goal & Plan

## Goal

Ship an iOS app under `client/ios` that, after install, lets the user enter:

1. **Proxy URL** — Clash subscription `https://…`, or a direct proxy URI (`socks5://`, `http://`, `ss://`, …)
2. **Relay node URL** — EasyTier peer, e.g. `tcp://1.2.3.4:11010`
3. **Network name** + **Secret** — EasyTier `[network_identity]`

Tapping **Start** enables:

- **Global TUN proxy** via the embedded Rust `singbox` library / Network Extension
- **Mesh membership** via embedded EasyTier (same network as desktop `zay` nodes)

Detailed runtime logs are written to the App Group so the UI can tail / copy / export them.

## Why not copy desktop TUN 1:1

Desktop zay runs **two kernel TUNs** (EasyTier edge + sing-box) and lets the OS route table split mesh CIDRs vs the rest.

iOS allows **one** `NEPacketTunnelProvider` and one packet flow. The extension uses
the public `NEPacketTunnelFlow.readPackets` / `writePackets` API and bridges one
bare IP packet per datagram through a Unix `SOCK_DGRAM` socketpair. The Rust
runtime owns a duplicated engine-side descriptor; no private KVC access to the
underlying utun socket is required.

## Architecture (SOCKS bridge)

```
NEPacketTunnelFlow
       │ public readPackets/writePackets
       ▼
PacketDispatcher ── SOCK_DGRAM ──► Rust singbox library
                                         │
                                         ├─ default/public → proxy outbound
                                         └─ mesh CIDR      → socks://127.0.0.1:18080
                                                                  │
                                                                  ▼
                                                        EasyTier (no_tun + SOCKS portal)
```

| Component | Role |
| --- | --- |
| Rust singbox library | Owns Packet Tunnel; global proxy + **embedded Loyalsoldier clash-rules** (blacklist, same as desktop) |
| EasyTier | `no_tun=true` + local SOCKS5 portal |
| Mesh route | sing-box `ip_cidr` → `mesh-socks` (before clash `private` / `ip_is_private`) |

## Layout

```
client/ios/
  Rust/zay-ios/     # EasyTier lifecycle + config builders + logging
  Shared/           # App Group config, logger, C headers
  ZayApp/           # UI (Home + Settings tabs)
  ZayTunnel/        # NE + narrow Rust TUN callback
  Scripts/          # build-rust, build-zaycore, xcodegen
  Vendor/           # ZayCore.framework
```

## Build order

```bash
./Scripts/build-all.sh
open Zay.xcodeproj
```

Set Development Team; run on a **physical device**.

## Start / stop flow

1. App persists `ZayRuntimeConfig` → App Group
2. Extension: start EasyTier (SOCKS) → Rust singbox start
3. `openTun`: apply NE settings → start the public packet-flow bridge → transfer
   a `dup(2)` of the engine-side datagram descriptor to Rust
4. Stop: Rust singbox close → EasyTier stop
