# `zay stack`

`zay stack` runs Mihomo as the always-on network engine, with optional EasyTier mesh, LAN gateway mode, subscription proxy providers, and Mihomo TUN.

## Usage

```bash
zay stack [OPTIONS]
```

Common options:

| Option | Meaning |
|--------|---------|
| `-s, --proxy URL` | Add a Mihomo subscription provider. Repeatable. |
| `--mesh` | Start EasyTier in-process using `[mesh]` from `zay.toml`. |
| `--gateway` | Enable LAN mixed relay (`allow-lan`, direct gateway profile). |
| `--tun` | Enable Mihomo TUN. Requires root/admin privileges. |
| `--mixed-port PORT` | Mixed HTTP/SOCKS port. Default from `zay.toml`, usually `7890`. |
| `-d, --data-dir DIR` | Directory containing `zay.toml` and `mihomo/`. |
| `-c, --config FILE` | Explicit `zay.toml` path. |

## Process Model

Every `zay stack` starts Mihomo. Flags only change the profile:

| Command | Mihomo | EasyTier |
|---------|--------|----------|
| `zay stack` | base direct profile | off |
| `zay stack --gateway` | LAN mixed relay, direct egress | off |
| `zay stack --proxy URL` | subscription providers + rules | off |
| `zay stack --mesh` | base + direct mesh rules | EasyTier TUN |
| `zay stack --mesh --gateway` | LAN relay + direct mesh rules | EasyTier TUN |
| `zay stack --tun` | Mihomo TUN | off |
| `zay stack --mesh --tun` | Mihomo TUN excluding mesh routes | EasyTier TUN |

`fwd`, `ssh`, and `http` are separate foreground subcommands, not `stack` flags.

## EasyTier Mesh

EasyTier is linked as a Rust crate from GitHub and started in-process. It is not an embedded binary.

On Windows, Zay still uses the in-process EasyTier crate. The Windows package must carry packet/TUN runtime files next to `zay.exe`: `Packet.dll`, `wintun.dll`, and `WinDivert64.sys`. `build.rs` downloads checksum-pinned official upstream archives, uses the WinPcap Developer Pack `Packet.lib` to resolve `-lPacket`, extracts x64 `Packet.dll` from the official WinPcap installer, extracts `wintun.dll` from the official Wintun ZIP, and extracts `WinDivert64.sys` from the official WinDivert ZIP. Zay does not build or sign Windows drivers.

Run the shell as Administrator when TUN is required.

The Windows package is assembled from generated build outputs; no `assets/prebuilt` directory is required.

`zay stack --mesh` can create `[mesh]` automatically when it is missing:

```bash
sudo zay stack --mesh --tun \
  --mesh-network-name my-network \
  --mesh-network-secret change-me \
  --mesh-ipv4 10.126.126.10/24 \
  --mesh-peer tcp://public.easytier.top:11010
```

The `--mesh-ipv4` address should be different on each node. If `--mesh-route` is omitted, Zay derives it from `--mesh-ipv4`, for example `10.126.126.10/24` becomes `10.126.126.0/24`. Existing `[mesh]` config is left unchanged.

Equivalent manual config:

```toml
[mesh]
instance_name = "zay"
network_name = "my-network"
network_secret = "change-me"
dhcp = true
# For a stable EasyTier virtual IP, use ipv4 and leave dhcp omitted or false.
# ipv4 = "10.126.126.10/24"
listeners = ["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"]
peers = ["tcp://public.easytier.top:11010"]

# Zay-only: injected into Mihomo as IP-CIDR,...,DIRECT rules and TUN excludes
mesh_routes = ["10.126.126.0/24"]
```

Static EasyTier virtual IP:

```toml
[mesh]
instance_name = "zay"
network_name = "my-network"
network_secret = "change-me"
ipv4 = "10.126.126.10/24"
peers = ["tcp://public.easytier.top:11010"]
```

When `ipv4` is set, Zay writes `dhcp = false` to EasyTier. Do not set `dhcp = true` together with `ipv4`.

EasyTier owns the mesh CIDRs with its own TUN. Zay writes `[mesh].mesh_routes` into Mihomo `route-exclude-address` so mesh IP traffic stays on the EasyTier route when Mihomo TUN is enabled by `zay stack --tun` or by a `tun:` mixin. This keeps `ssh`, `mysql`, and `ping` to EasyTier virtual IPs on the EasyTier L3 path.

TUN ownership rule:

| Setup | Full-tunnel owner |
|-------|-------------------|
| `--mesh` | EasyTier for `mesh_routes` |
| `--tun` | Mihomo |
| `--mesh --tun` | Mihomo for normal traffic; EasyTier for excluded `mesh_routes` |

If `[mihomo].mixin` also writes `tun.route-exclude-address`, ensure it includes the mesh CIDRs because mixin values can override generated fields.

Corporate proxy gateways:

When `--tun` is enabled, Zay does not exclude local/private CIDRs from Mihomo TUN auto-route by default. It only writes `tun.route-exclude-address` for explicit `--tun-exclude` / `tun_exclude_routes` values and for `[mesh].mesh_routes`. This keeps VM traffic inside the Mihomo rule engine so rules can send corporate services, such as `10.x` addresses, through a host gateway. If a CIDR must bypass Mihomo TUN, add it explicitly:

```bash
sudo zay stack --gateway --tun --tun-exclude 11.155.134.0/24
```

```toml
tun_exclude_routes = ["11.155.134.0/24"]
```

## Tart Host/VM

Host direct relay:

```bash
sudo zay stack --gateway --mixed-port 7890
```

Host relay with subscription:

```bash
sudo zay stack --gateway --proxy "https://subscription.example"
```

VM TUN through host SOCKS:

```bash
sudo zay stack --tun -d ~/.config/zay --mixed-port 7890
```

VM `zay.toml`:

```toml
[mihomo]
mixin = '''
mode: rule

proxies:
  - name: Host
    type: socks5
    server: 192.168.64.1
    port: 7890
    udp: true

rules:
  # Corporate/internal domains that should use the host network/VPN.
  - DOMAIN-SUFFIX,example.com,Host
  - IP-CIDR,10.99.0.0/16,Host,no-resolve

  # Local/private ranges that should remain direct.
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR6,fc00::/7,DIRECT,no-resolve

  - MATCH,Host
'''
```

Avoid broad `IP-CIDR,10.0.0.0/8,DIRECT` if corporate services live in `10.x.x.x` and should route through the host.

## Notes

- ICMP/ping does not go through SOCKS. Test TCP/HTTPS with `curl`, not only `ping`.
- If MMDB is missing, Zay rewrites `GEOIP,PRIVATE,...` rules to private `IP-CIDR` rules so Mihomo can start offline.
- Generated Mihomo config is written to `<data-dir>/mihomo/config.yaml`.
