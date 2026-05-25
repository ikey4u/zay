//! Mesh-related helpers for `zay stack`.

use crate::settings::Settings;

/// `IP-CIDR,...,DIRECT` lines from `[mesh].mesh_routes` when `--mesh` is set.
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
