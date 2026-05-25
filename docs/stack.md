# `zay stack`

`zay stack` runs Mihomo as the always-on network engine, with optional EasyTier mesh, LAN gateway mode, subscription proxy providers, and Mihomo TUN.

## Usage

```bash
zay stack [OPTIONS]
```

Common options:

| Option | Meaning |
|--------|---------|
| `-s, --subscription URL` | Add a Mihomo subscription provider. Repeatable. |
| `--mesh` | Start EasyTier in-process using `[mesh]` from `zay.toml`. |
| `--gateway` | Enable LAN mixed relay (`allow-lan`, direct gateway profile). |
| `--tun` | Enable Mihomo TUN. Requires root/admin privileges. |
| `--mixed-port PORT` | Mixed HTTP/SOCKS port. Default from `zay.toml`, usually `7890`. |
| `-d, --data-dir DIR` | Directory containing `zay.toml`, `mixin.yaml`, and `mihomo/`. |
| `-c, --config FILE` | Explicit `zay.toml` path. |
| `--mixin FILE` | YAML mixin merged into generated Mihomo config. |

## Process Model

Every `zay stack` starts Mihomo. Flags only change the profile:

| Command | Mihomo | EasyTier |
|---------|--------|----------|
| `zay stack` | base direct profile | off |
| `zay stack --gateway` | LAN mixed relay, direct egress | off |
| `zay stack -s URL` | subscription providers + rules | off |
| `zay stack --mesh` | base + mesh route rules | on |
| `zay stack --mesh --gateway` | LAN relay + mesh route rules | on |
| `zay stack --tun` | Mihomo TUN | off |
| `zay stack --mesh --tun` | Mihomo TUN + mesh route rules | on, requires `[mesh].no_tun = true` |

`fwd`, `ssh`, and `http` are separate foreground subcommands, not `stack` flags.

## EasyTier Mesh

EasyTier is linked as a Rust crate from GitHub and started in-process. It is not an embedded binary.

The Windows package currently builds without the in-process EasyTier crate because EasyTier's Windows packet stack requires Npcap/Packet import libraries during cross-compilation. On Windows, `zay stack --mesh` returns a clear unsupported error; run EasyTier separately or use Zay mesh on macOS/Linux.

Configure mesh in `zay.toml`:

```toml
[mesh]
instance_name = "zay"
network_name = "my-network"
network_secret = "change-me"
dhcp = true
no_tun = true
listeners = ["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"]
peers = ["tcp://public.easytier.top:11010"]

# Zay-only: injected into Mihomo as IP-CIDR,...,DIRECT rules
mesh_routes = ["10.126.126.0/24"]
```

TUN ownership rule:

| Setup | Full-tunnel owner |
|-------|-------------------|
| `--mesh` + `no_tun = true` | none; EasyTier virtual IP only |
| `--mesh` without `no_tun` | EasyTier |
| `--tun` | Mihomo |
| `--mesh --tun` + `no_tun = true` | Mihomo |
| `--mesh --tun` without `no_tun` | rejected |

## Tart Host / VM

Host direct relay:

```bash
sudo zay stack --gateway --mixed-port 7890
```

Host relay with subscription:

```bash
sudo zay stack --gateway -s "https://subscription.example"
```

VM TUN through host SOCKS:

```bash
sudo zay stack --tun -d ~/.config/zay --mixed-port 7890
```

VM `mixin.yaml`:

```yaml
mode: rule

proxies:
  - name: Host
    type: socks5
    server: 192.168.64.1
    port: 7890
    udp: true

rules:
  # Corporate/internal domains that should use the host network/VPN.
  - DOMAIN-SUFFIX,woa.com,Host
  - IP-CIDR,10.99.0.0/16,Host,no-resolve

  # Local/private ranges that should remain direct.
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR6,fc00::/7,DIRECT,no-resolve

  - MATCH,Host
```

Avoid broad `IP-CIDR,10.0.0.0/8,DIRECT` if corporate services live in `10.x.x.x` and should route through the host.

## Notes

- ICMP/ping does not go through SOCKS. Test TCP/HTTPS with `curl`, not only `ping`.
- If MMDB is missing, Zay rewrites `GEOIP,PRIVATE,...` rules to private `IP-CIDR` rules so Mihomo can start offline.
- Generated Mihomo config is written to `<data-dir>/mihomo/config.yaml`.
