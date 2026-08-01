//! EasyTier mesh ↔ sing-box integration (native EasyTier TUN; no WG portal).

use serde_json::{Value, json};

use crate::{settings::Settings, singbox::tun_route};

/// Historical tag for the removed WireGuard portal endpoint (kept for rule detection).
pub const MESH_ENDPOINT_TAG: &str = "easytier-wg";

/// Full-capture TUN + subscription: EasyTier runs inside the `zay` process — keep all its sockets direct.
pub fn easytier_process_bypass_route_rules(settings: &Settings) -> Vec<Value> {
    if !tun_route::tun_full_capture_mesh_proxy(settings) {
        return Vec::new();
    }
    let mut names = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(stem) = exe.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
        if let Some(file) = exe.file_name().and_then(|s| s.to_str()) {
            names.push(file.to_string());
        }
    }
    names.sort();
    names.dedup();
    if names.is_empty() {
        names.push("zay".into());
    }
    vec![json!({
        "action": "route",
        "process_name": names,
        "outbound": "direct"
    })]
}

pub fn is_easytier_process_bypass_route_rule(rule: &Value) -> bool {
    rule.get("outbound").and_then(|v| v.as_str()) == Some("direct")
        && rule
            .get("process_name")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty())
        && rule.get("ip_cidr").is_none()
        && rule.get("ip_is_private").is_none()
}

/// Mesh nodes use EasyTier's own TUN — no sing-box WireGuard portal endpoint.
pub fn wireguard_endpoint(
    _settings: &Settings,
) -> anyhow::Result<Option<Value>> {
    Ok(None)
}

/// `[mesh].peers` host `/32` → direct. Keeps SSH/TCP :11010 off the proxy TUN path.
pub fn peer_bypass_route_rules(settings: &Settings) -> Vec<Value> {
    if !settings.mesh_is_node() {
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

/// Mesh CIDRs are owned by EasyTier TUN — no sing-box route rules to `easytier-wg`.
pub fn mesh_route_rules(_settings: &Settings) -> Vec<Value> {
    Vec::new()
}

/// Whether a sing-box route rule targets the (removed) mesh WireGuard endpoint.
pub fn is_mesh_route_rule(rule: &Value) -> bool {
    rule.get("outbound").and_then(|v| v.as_str()) == Some(MESH_ENDPOINT_TAG)
        && rule.get("ip_cidr").is_some()
}
