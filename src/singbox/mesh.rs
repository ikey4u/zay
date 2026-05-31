//! EasyTier WireGuard portal → sing-box `endpoints` (kernel L3, supports ping).

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use easytier::tunnel::wireguard::WgConfig;
use serde_json::{Value, json};

use crate::settings::{MeshConfig, Settings};

pub const MESH_ENDPOINT_TAG: &str = "easytier-wg";

/// WireGuard endpoint JSON for sing-box 1.12+ (`endpoints`, not deprecated outbound WG).
pub fn wireguard_endpoint(settings: &Settings) -> Result<Option<Value>> {
    if !settings.stack.mesh {
        return Ok(None);
    }
    let mesh = settings
        .mesh
        .as_ref()
        .context("[mesh] missing in zay.toml")?;
    let (peer_host, peer_port) = resolve_wg_peer(mesh)?;
    let keys = portal_client_keys(mesh)?;
    let allowed_ips = mesh_allowed_ips(settings, mesh)?;

    Ok(Some(json!({
        "type": "wireguard",
        "tag": MESH_ENDPOINT_TAG,
        "system": false,
        "mtu": 1380,
        "address": [keys.client_address],
        "private_key": keys.private_key,
        "peers": [{
            "address": peer_host,
            "port": peer_port,
            "public_key": keys.peer_public_key,
            "allowed_ips": allowed_ips,
            "persistent_keepalive_interval": 25,
            "reserved": [0, 0, 0]
        }]
    })))
}

/// `[mesh].peers` host `/32` → direct (before mesh rules). Keeps SSH/TCP :11010 off the WG path.
pub fn peer_bypass_route_rules(settings: &Settings) -> Vec<Value> {
    if !settings.stack.mesh {
        return Vec::new();
    }
    let cidrs = crate::stack::mesh::peer_exclude_cidrs(settings);
    let mut rules = Vec::new();
    for cidr in cidrs {
        rules.push(json!({
            "action": "route",
            "network": "icmp",
            "ip_cidr": [cidr],
            "outbound": "direct"
        }));
        rules.push(json!({
            "action": "route",
            "network": ["tcp", "udp"],
            "ip_cidr": [cidr],
            "outbound": "direct"
        }));
        rules.push(json!({
            "action": "route",
            "ip_cidr": [cidr],
            "outbound": "direct"
        }));
    }
    rules
}

pub fn is_peer_bypass_route_rule(rule: &Value, settings: &Settings) -> bool {
    if rule.get("outbound").and_then(|v| v.as_str()) != Some("direct") {
        return false;
    }
    let Some(ip_cidr) = rule.get("ip_cidr").and_then(|v| v.as_array()) else {
        return false;
    };
    let peers: std::collections::HashSet<_> =
        crate::stack::mesh::peer_exclude_cidrs(settings)
            .into_iter()
            .collect();
    ip_cidr
        .iter()
        .any(|entry| entry.as_str().is_some_and(|cidr| peers.contains(cidr)))
}

pub fn mesh_route_rules(settings: &Settings) -> Vec<Value> {
    if !settings.stack.mesh {
        return Vec::new();
    }
    let Some(routes) =
        settings.mesh.as_ref().and_then(|m| m.mesh_routes.as_ref())
    else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for cidr in routes {
        // sing-box 1.13+ proxies ICMP from TUN to WireGuard endpoints; 1.12 cannot ping mesh IPs.
        rules.push(json!({
            "action": "route",
            "network": "icmp",
            "ip_cidr": [cidr],
            "outbound": MESH_ENDPOINT_TAG
        }));
        rules.push(json!({
            "action": "route",
            "network": ["tcp", "udp"],
            "ip_cidr": [cidr],
            "outbound": MESH_ENDPOINT_TAG
        }));
        rules.push(json!({
            "action": "route",
            "ip_cidr": [cidr],
            "outbound": MESH_ENDPOINT_TAG
        }));
    }
    rules
}

/// Whether a sing-box route rule targets the mesh WireGuard endpoint.
pub fn is_mesh_route_rule(rule: &Value) -> bool {
    rule.get("outbound").and_then(|v| v.as_str()) == Some(MESH_ENDPOINT_TAG)
        && rule.get("ip_cidr").is_some()
}

struct PortalKeys {
    private_key: String,
    peer_public_key: String,
    client_address: String,
}

fn portal_client_keys(mesh: &MeshConfig) -> Result<PortalKeys> {
    let seed = format!("{}{}", mesh.network_name, mesh.network_secret.as_str());
    let server = WgConfig::new_for_portal(&seed, &seed);
    let private_key = STANDARD.encode(server.peer_secret_key());
    let peer_public_key = STANDARD.encode(server.my_public_key());

    // sing-box WG endpoint address matches TUN / portal host (10.14.14.N/32 from mesh ipv4).
    let client_address = crate::stack::mesh::portal_client_host_cidr(mesh)
        .unwrap_or_else(|| "10.14.14.2/32".into());

    Ok(PortalKeys {
        private_key,
        peer_public_key,
        client_address,
    })
}

fn mesh_allowed_ips(
    _settings: &Settings,
    mesh: &MeshConfig,
) -> Result<Vec<String>> {
    let mut allowed = mesh.mesh_routes.clone().unwrap_or_default();
    let portal_cidr = crate::stack::mesh::portal_client_network_cidr(mesh);
    allowed.push(portal_cidr);
    if allowed.is_empty() {
        bail!("[mesh].mesh_routes required for WireGuard allowed_ips");
    }
    allowed.sort();
    allowed.dedup();
    Ok(allowed)
}

fn resolve_wg_peer(mesh: &MeshConfig) -> Result<(String, u16)> {
    if mesh.wireguard_endpoint.is_some() {
        bail!(
            "[mesh].wireguard_endpoint is not supported: mesh is managed by local EasyTier. \
Remove wireguard_endpoint and run `zay stack --mesh` with listeners/peers in [mesh]. \
Sing-box connects to [mesh].wireguard_listen (default 127.0.0.1:51820)."
        );
    }
    let listen = mesh
        .wireguard_listen
        .as_deref()
        .unwrap_or("127.0.0.1:51820");
    parse_host_port(listen)
}

fn parse_host_port(raw: &str) -> Result<(String, u16)> {
    let (host, port) = raw
        .rsplit_once(':')
        .with_context(|| format!("invalid host:port {raw:?}"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in {raw:?}"))?;
    Ok((host.to_string(), port))
}
