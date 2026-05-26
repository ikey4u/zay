//! Mesh-related helpers for `zay stack`.

use crate::settings::Settings;

pub fn route_exclude_addresses(settings: &Settings) -> Option<Vec<String>> {
    if !settings.stack.mesh {
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
    if !settings.stack.mesh {
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
