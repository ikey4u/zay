//! Mesh-related helpers for `zay stack`.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use anyhow::{Context, Result, bail};

use crate::settings::{MeshConfig, MeshRole, Settings};

/// Default relay listen sockets (`zay stack --mesh relay`).
pub const DEFAULT_RELAY_LISTENERS: &[&str] =
    &["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"];

/// Parsed `--mesh-auth` (shape depends on relay vs node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuth {
    /// EasyTier `network_name` (the `user` in `--mesh-auth`).
    pub network_name: String,
    /// EasyTier `network_secret` (the `password` in `--mesh-auth`).
    pub network_secret: String,
    /// Node peer URI (`user:password@tcp://host:port`). Empty on relay.
    pub endpoint: String,
}

pub fn default_relay_listeners() -> Vec<String> {
    DEFAULT_RELAY_LISTENERS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn parse_mesh_credentials(raw: &str) -> Result<(String, String)> {
    let raw = raw.trim();
    let credentials = raw
        .split_once('@')
        .map(|(left, _)| left.trim())
        .unwrap_or(raw);
    let (network_name, network_secret) = credentials.split_once(':').with_context(|| {
        format!(
            "--mesh-auth must be user:password or user:password@tcp://host:port, got {raw:?}"
        )
    })?;
    if network_name.trim().is_empty() || network_secret.is_empty() {
        bail!("--mesh-auth user and password must not be empty");
    }
    Ok((network_name.to_string(), network_secret.to_string()))
}

/// Relay: `user:password` only; any `@tcp://…` suffix is ignored. Listens on [`DEFAULT_RELAY_LISTENERS`].
pub fn parse_mesh_auth_relay(raw: &str) -> Result<MeshAuth> {
    if raw.contains('@') {
        eprintln!(
            "mesh relay: ignoring host in --mesh-auth (listen on {})",
            DEFAULT_RELAY_LISTENERS.join(", ")
        );
    }
    let (network_name, network_secret) = parse_mesh_credentials(raw)?;
    Ok(MeshAuth {
        network_name,
        network_secret,
        endpoint: String::new(),
    })
}

/// Node: `user:password@tcp://host:port` (UDP scheme also accepted).
pub fn parse_mesh_auth_node(raw: &str) -> Result<MeshAuth> {
    let raw = raw.trim();
    let (credentials, endpoint) = raw.split_once('@').with_context(|| {
        format!(
            "--mesh-auth must be user:password@tcp://host:port (example: my.home:secret@tcp://1.2.3.4:11010), got {raw:?}"
        )
    })?;
    let (network_name, network_secret) =
        credentials.split_once(':').with_context(|| {
            format!(
                "--mesh-auth must include user:password before @, got {raw:?}"
            )
        })?;
    if network_name.trim().is_empty() || network_secret.is_empty() {
        bail!("--mesh-auth user and password must not be empty");
    }
    let endpoint = endpoint.trim();
    if !endpoint.contains("://") {
        bail!(
            "--mesh-auth endpoint must be tcp://host:port or udp://host:port"
        );
    }
    let scheme = endpoint
        .split("://")
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if scheme != "tcp" && scheme != "udp" {
        bail!("--mesh-auth endpoint scheme must be tcp or udp (got {scheme})");
    }
    scheme_port_from_uri(endpoint).with_context(|| {
        format!("invalid --mesh-auth endpoint {endpoint:?}")
    })?;
    Ok(MeshAuth {
        network_name: network_name.to_string(),
        network_secret: network_secret.to_string(),
        endpoint: endpoint.to_string(),
    })
}

pub fn parse_mesh_auth(
    raw: &str,
    role: crate::settings::MeshRole,
) -> Result<MeshAuth> {
    match role {
        crate::settings::MeshRole::Relay => parse_mesh_auth_relay(raw),
        crate::settings::MeshRole::Node => parse_mesh_auth_node(raw),
    }
}

/// Peer/listener host `/32` entries for sing-box `route_exclude_address`.
///
/// EasyTier mesh control traffic must bypass the system TUN so hole-punching and
/// relay TCP/UDP are not re-injected through sing-box.
pub fn peer_exclude_cidrs(settings: &Settings) -> Vec<String> {
    if !settings.stack.mesh_enabled() {
        return Vec::new();
    }
    let Some(mesh) = settings.mesh.as_ref() else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    if let Some(peers) = &mesh.peers {
        for peer in peers {
            if let Some(host) = host_from_peer_uri(peer) {
                hosts.push(host);
            }
        }
    }
    if let Some(listeners) = &mesh.listeners {
        for listener in listeners {
            if let Some(host) = host_from_peer_uri(listener) {
                hosts.push(host);
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
        .into_iter()
        .filter_map(|host| resolve_ipv4_cidr(&host))
        .collect()
}

fn resolve_ipv4_cidr(host: &str) -> Option<String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(format!("{ip}/32"));
    }
    let addrs = format!("{host}:0").to_socket_addrs().ok()?;
    addrs
        .filter_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(format!("{v4}/32")),
            IpAddr::V6(_) => None,
        })
        .next()
}

/// EasyTier default STUN hostnames (plain `host`, not `txt:`) for TUN `route_exclude_address`.
/// Keep in sync with EasyTier `DEFAULT_UDP/TCP_STUN_SERVERS` (git rev 00957e5).
const EASYTIER_STUN_HOSTS: &[&str] = &[
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
    "stun.hot-chilli.net",
    "stun.fitauto.ru",
    "fwa.lifesizecloud.com",
    "global.turn.twilio.com",
    "turn.cloudflare.com",
    "stun.voip.blackberry.com",
    "stun.radiojar.com",
];

/// Resolve EasyTier STUN servers so UDP/TCP NAT probes stay on the physical NIC under full TUN.
pub fn easytier_stun_exclude_cidrs() -> Vec<String> {
    let mut out = Vec::new();
    for host in EASYTIER_STUN_HOSTS {
        if let Some(cidr) = resolve_ipv4_cidr(host) {
            out.push(cidr);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Per-node WG portal client host (`10.14.14.{base+1}/32`) for sing-box endpoint and mesh return routes.
pub fn portal_client_host_cidr(mesh: &MeshConfig) -> Option<String> {
    if let Some(addr) = mesh.wireguard_client_address.as_deref() {
        let addr = addr.trim();
        if !addr.is_empty() {
            return Some(if addr.contains('/') {
                addr.to_string()
            } else {
                format!("{addr}/32")
            });
        }
    }
    let n = mesh_ipv4_last_octet(mesh)? as u32;
    let base = (n.saturating_sub(1)) * 4;
    Some(format!("10.14.14.{}/32", base + 1))
}

/// sing-box TUN `address` prefix — system/mixed stack needs ≥2 addresses (/30); use a host
/// address inside the block (not the network address, e.g. `.9/30` not `.8/30` on macOS).
pub fn portal_tun_prefix_cidr(mesh: &MeshConfig) -> Option<String> {
    let n = mesh_ipv4_last_octet(mesh)? as u32;
    let base = (n.saturating_sub(1)) * 4;
    Some(format!("10.14.14.{}/30", base + 1))
}

pub fn mesh_ipv4_last_octet(mesh: &MeshConfig) -> Option<u8> {
    let host = mesh.ipv4.as_deref()?.split('/').next()?;
    let ip: Ipv4Addr = host.parse().ok()?;
    Some(ip.octets()[3])
}

/// EasyTier `vpn_portal_config.client_cidr` — use a /32 host route per node (not shared /24).
pub fn portal_client_network_cidr(mesh: &MeshConfig) -> String {
    mesh.wireguard_client_cidr
        .clone()
        .or_else(|| portal_client_host_cidr(mesh))
        .unwrap_or_else(|| "10.14.14.2/32".into())
}

/// `(scheme, port)` pairs from `[mesh].listeners`, e.g. `("tcp", 11010)`.
pub fn listener_ports(mesh: &MeshConfig) -> Vec<(&'static str, u16)> {
    let Some(listeners) = mesh.listeners.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for uri in listeners {
        let Some((scheme, port)) = scheme_port_from_uri(uri) else {
            continue;
        };
        out.push((scheme, port));
    }
    out.sort_by_key(|(scheme, port)| (*scheme, *port));
    out.dedup();
    out
}

/// Inbound mesh listeners configured (typical on VPS relay).
pub fn has_mesh_listeners(mesh: &MeshConfig) -> bool {
    mesh.listeners
        .as_ref()
        .is_some_and(|listeners| !listeners.is_empty())
}

/// Deprecated alias — use [`MeshConfig::is_relay`] or [`has_mesh_listeners`].
pub fn is_hub(mesh: &MeshConfig) -> bool {
    mesh.is_relay() && has_mesh_listeners(mesh)
}

/// Print role warnings so hub/client IPs are not swapped (common cause of curl/SSH failures).
pub fn warn_mesh_role(mesh: &MeshConfig) {
    let has_listeners = mesh
        .listeners
        .as_ref()
        .is_some_and(|listeners| !listeners.is_empty());
    let has_peers = mesh.peers.as_ref().is_some_and(|peers| !peers.is_empty());
    let ipv4 = mesh.ipv4.as_deref().unwrap_or("?");

    if mesh.role == MeshRole::Relay && has_peers {
        eprintln!("warn: [mesh].peers should be empty when role = \"relay\"");
    }
    if mesh.role == MeshRole::Node && has_listeners && has_peers {
        eprintln!(
            "warn: [mesh] has both listeners and peers — unusual for role = \"node\"; \
             typical: relay has listeners, nodes have peers"
        );
    }
    if mesh.is_relay() && has_listeners {
        eprintln!("mesh relay: listening on :11010 (no mesh virtual IP)");
    } else if mesh.is_node() && has_peers {
        eprintln!("mesh node: virtual IP {ipv4}; dial relay via [mesh].peers");
        if ipv4.contains("10.126.126.2") {
            eprintln!(
                "warn: hub is usually 10.126.126.1/24 — .2 is typically the weapon/client; \
                 if curl http://10.126.126.2:port fails, check which machine actually runs the service"
            );
        }
    } else if has_peers {
        eprintln!(
            "mesh role: client — virtual IP {ipv4}; services must listen on 0.0.0.0 or 127.0.0.1 \
             (not only the mesh IP); peers reach you via EasyTier tcp_proxy → 127.0.0.1:port"
        );
        if ipv4.contains("10.126.126.1") {
            eprintln!(
                "warn: client node has hub mesh IP 10.126.126.1/24 — weapon should be .2, hub/VPS should be .1 with listeners"
            );
        }
    }
}

fn scheme_port_from_uri(uri: &str) -> Option<(&'static str, u16)> {
    let uri = uri.trim();
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "tcp" => "tcp",
        "udp" => "udp",
        _ => return None,
    };
    let authority = rest.split('/').next()?.trim();
    let port_str = if authority.starts_with('[') {
        authority.rsplit_once(':').map(|(_, p)| p)?
    } else {
        authority
            .rsplit_once(':')
            .map(|(_, p)| p)
            .unwrap_or("11010")
    };
    let port: u16 = port_str.parse().ok()?;
    Some((scheme, port))
}

fn host_from_peer_uri(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let rest = uri.split("://").nth(1).unwrap_or(uri);
    let authority = rest.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[1..end]
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
    };
    let host = host.trim();
    if host.is_empty()
        || host == "0.0.0.0"
        || host == "::"
        || host == "localhost"
    {
        return None;
    }
    Some(host.to_string())
}

pub fn route_exclude_addresses(settings: &Settings) -> Option<Vec<String>> {
    if !settings.stack.mesh_enabled() {
        return None;
    }
    let routes = settings.mesh.as_ref()?.mesh_routes.as_ref()?;
    if routes.is_empty() {
        return None;
    }
    Some(routes.clone())
}

/// `IP-CIDR,...,DIRECT` lines from `[mesh].mesh_routes` when `--mesh` is set.
///
/// This protects explicit HTTP/SOCKS proxy traffic through Mihomo. TUN-mode
/// system traffic to these CIDRs is excluded from Mihomo and handled by
/// EasyTier's own TUN route.
pub fn route_lines(settings: &Settings) -> Vec<String> {
    if !settings.stack.mesh_enabled() {
        return Vec::new();
    }
    settings
        .mesh
        .as_ref()
        .and_then(|m| m.mesh_routes.as_ref())
        .map(|routes| {
            routes
                .iter()
                .map(|cidr| format!("IP-CIDR,{cidr},DIRECT,no-resolve"))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

    #[test]
    fn peer_uri_yields_exclude_cidr() {
        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "".into(),
            mihomo_mixin: None,
            singbox_mixin: None,
            bootstrap_proxy: None,
            mesh: Some(MeshConfig {
                role: MeshRole::Node,
                instance_name: None,
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: None,
                listeners: Some(vec!["tcp://0.0.0.0:11010".into()]),
                peers: Some(vec![
                    "tcp://43.138.178.37:11010".into(),
                    "tcp://192.168.31.10:11010".into(),
                ]),
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
                wireguard_endpoint: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Node),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        let excludes = peer_exclude_cidrs(&settings);
        assert!(excludes.contains(&"43.138.178.37/32".to_string()));
        assert!(excludes.contains(&"192.168.31.10/32".to_string()));
        assert!(!excludes.iter().any(|c| c.starts_with("0.0.0.0")));
    }

    #[test]
    fn parse_mesh_auth_node_splits_credentials_and_endpoint() {
        use crate::settings::MeshRole;
        let auth = parse_mesh_auth(
            "my.home:secret@tcp://43.138.178.37:11010",
            MeshRole::Node,
        )
        .unwrap();
        assert_eq!(auth.network_name, "my.home");
        assert_eq!(auth.network_secret, "secret");
        assert_eq!(auth.endpoint, "tcp://43.138.178.37:11010");
    }

    #[test]
    fn parse_mesh_auth_relay_ignores_endpoint_suffix() {
        use crate::settings::MeshRole;
        let auth = parse_mesh_auth(
            "my.home:secret@tcp://ignored:9999",
            MeshRole::Relay,
        )
        .unwrap();
        assert_eq!(auth.network_name, "my.home");
        assert_eq!(auth.network_secret, "secret");
        assert!(auth.endpoint.is_empty());
        assert_eq!(
            default_relay_listeners(),
            vec![
                "tcp://0.0.0.0:11010".to_string(),
                "udp://0.0.0.0:11010".to_string(),
            ]
        );
    }

    #[test]
    fn parse_mesh_auth_relay_user_password_only() {
        use crate::settings::MeshRole;
        let auth = parse_mesh_auth("my.home:secret", MeshRole::Relay).unwrap();
        assert_eq!(auth.network_name, "my.home");
        assert_eq!(auth.network_secret, "secret");
    }

    #[test]
    fn listener_ports_parsed() {
        let mesh = MeshConfig {
            role: MeshRole::Relay,
            instance_name: None,
            network_name: "n".into(),
            network_secret: "s".into(),
            dhcp: None,
            ipv4: None,
            listeners: Some(vec![
                "tcp://0.0.0.0:11010".into(),
                "udp://0.0.0.0:11010".into(),
            ]),
            peers: None,
            proxy_networks: None,
            mesh_routes: None,
            wireguard_listen: None,
            wireguard_client_cidr: None,
            wireguard_client_address: None,
            wireguard_endpoint: None,
        };
        assert_eq!(listener_ports(&mesh), vec![("tcp", 11010), ("udp", 11010)]);
    }

    #[test]
    fn portal_client_host_from_mesh_ipv4() {
        let mesh = MeshConfig {
            role: MeshRole::Node,
            instance_name: None,
            network_name: "n".into(),
            network_secret: "s".into(),
            dhcp: None,
            ipv4: Some("10.126.126.3/24".into()),
            listeners: None,
            peers: None,
            proxy_networks: None,
            mesh_routes: None,
            wireguard_listen: None,
            wireguard_client_cidr: None,
            wireguard_client_address: None,
            wireguard_endpoint: None,
        };
        assert_eq!(
            portal_client_host_cidr(&mesh).as_deref(),
            Some("10.14.14.9/32")
        );
        assert_eq!(
            portal_tun_prefix_cidr(&mesh).as_deref(),
            Some("10.14.14.9/30")
        );
        assert_eq!(portal_client_network_cidr(&mesh), "10.14.14.9/32");
    }
}
