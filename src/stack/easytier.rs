//! EasyTier mesh leg for `zay stack --mesh <relay|node>`.

use std::{fmt::Write as _, path::Path};

use anyhow::{Context, Result, bail};

use crate::settings::{MeshConfig, MeshRole};

/// Serialize `[mesh]` to EasyTier TOML for `TomlConfigLoader`.
pub fn to_easytier_toml(mesh: &MeshConfig) -> Result<String> {
    match mesh.role {
        MeshRole::Relay => to_easytier_relay_toml(mesh),
        MeshRole::Node => to_easytier_node_toml(mesh),
    }
}

fn write_easytier_security_flags(out: &mut String) -> Result<()> {
    writeln!(out)?;
    writeln!(out, "[flags]")?;
    writeln!(out, "no_tun = true")?;
    Ok(())
}

fn write_ipv4_and_dhcp(out: &mut String, mesh: &MeshConfig) -> Result<()> {
    if let Some(ipv4) = mesh
        .ipv4
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if mesh.dhcp == Some(true) {
            bail!("[mesh].ipv4 requires dhcp = false or omitted");
        }
        writeln!(out, "ipv4 = {ipv4:?}")?;
        writeln!(out, "dhcp = false")?;
    } else if mesh.dhcp.unwrap_or(true) {
        writeln!(out, "dhcp = true")?;
    } else {
        writeln!(out, "dhcp = false")?;
    }
    Ok(())
}

fn write_vpn_portal(out: &mut String, mesh: &MeshConfig) -> Result<()> {
    if mesh
        .ipv4
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return Ok(());
    }
    let listen = mesh
        .wireguard_listen
        .as_deref()
        .unwrap_or("127.0.0.1:51820");
    let client_cidr = crate::stack::mesh::portal_client_network_cidr(mesh);
    writeln!(out)?;
    writeln!(out, "[vpn_portal_config]")?;
    writeln!(out, "wireguard_listen = {listen:?}")?;
    writeln!(out, "client_cidr = {client_cidr:?}")?;
    Ok(())
}

/// Relay-only: no `ipv4`, no WG portal.
fn to_easytier_relay_toml(mesh: &MeshConfig) -> Result<String> {
    if mesh.role != MeshRole::Relay {
        bail!("[mesh].role must be \"relay\"");
    }
    if mesh.dhcp == Some(true) {
        bail!("[mesh].dhcp must be false or omitted when role = \"relay\"");
    }
    if mesh.peers.as_ref().is_some_and(|peers| !peers.is_empty()) {
        bail!("[mesh].peers must be empty when role = \"relay\"");
    }
    if mesh
        .mesh_routes
        .as_ref()
        .is_some_and(|routes| !routes.is_empty())
    {
        bail!("[mesh].mesh_routes is only for role = \"node\"");
    }

    let instance_name = mesh.instance_name.as_deref().unwrap_or("zay").trim();
    if instance_name.is_empty() {
        bail!("[mesh].instance_name must not be empty");
    }

    let mut out = String::new();
    writeln!(out, "instance_name = {instance_name:?}")?;
    if mesh
        .ipv4
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some()
    {
        write_ipv4_and_dhcp(&mut out, mesh)?;
    } else {
        writeln!(out, "dhcp = false")?;
    }

    let listeners: Vec<String> = mesh
        .listeners
        .as_ref()
        .filter(|l| !l.is_empty())
        .cloned()
        .unwrap_or_else(|| {
            eprintln!(
                "easytier relay: [mesh].listeners unset — using {}",
                crate::stack::mesh::DEFAULT_RELAY_LISTENERS.join(", ")
            );
            crate::stack::mesh::default_relay_listeners()
        });
    writeln!(out)?;
    write!(out, "listeners = [")?;
    for (i, l) in listeners.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{l:?}")?;
    }
    writeln!(out, "]")?;

    writeln!(out)?;
    writeln!(out, "[network_identity]")?;
    writeln!(out, "network_name = {:?}", mesh.network_name)?;
    writeln!(out, "network_secret = {:?}", mesh.network_secret)?;

    write_easytier_security_flags(&mut out)?;
    write_vpn_portal(&mut out, mesh)?;

    Ok(out)
}

/// Mesh member with sing-box WireGuard portal (no system TUN).
fn to_easytier_node_toml(mesh: &MeshConfig) -> Result<String> {
    if mesh.role != MeshRole::Node {
        bail!("[mesh].role must be \"node\"");
    }

    let instance_name = mesh.instance_name.as_deref().unwrap_or("zay").trim();
    if instance_name.is_empty() {
        bail!("[mesh].instance_name must not be empty");
    }

    let mut out = String::new();
    writeln!(out, "instance_name = {instance_name:?}")?;
    write_ipv4_and_dhcp(&mut out, mesh)?;

    if let Some(listeners) = &mesh.listeners
        && !listeners.is_empty()
    {
        writeln!(out)?;
        write!(out, "listeners = [")?;
        for (i, l) in listeners.iter().enumerate() {
            if i > 0 {
                write!(out, ", ")?;
            }
            write!(out, "{l:?}")?;
        }
        writeln!(out, "]")?;
    }

    if let Some(peers) = &mesh.peers {
        for peer in peers {
            writeln!(out)?;
            writeln!(out, "[[peer]]")?;
            writeln!(out, "uri = {peer:?}")?;
        }
    }

    if let Some(proxy_networks) = &mesh.proxy_networks {
        for cidr in proxy_networks {
            writeln!(out)?;
            writeln!(out, "[[proxy_network]]")?;
            writeln!(out, "cidr = {cidr:?}")?;
            writeln!(out, "allow = [\"tcp\", \"udp\", \"icmp\"]")?;
        }
    }

    writeln!(out)?;
    writeln!(out, "[network_identity]")?;
    writeln!(out, "network_name = {:?}", mesh.network_name)?;
    writeln!(out, "network_secret = {:?}", mesh.network_secret)?;

    write_easytier_security_flags(&mut out)?;
    write_vpn_portal(&mut out, mesh)?;

    Ok(out)
}

fn warn_stale_easytier_iface() {
    #[cfg(not(target_os = "linux"))]
    return;
    #[cfg(target_os = "linux")]
    warn_stale_easytier_iface_linux();
}

#[cfg(target_os = "linux")]
fn warn_stale_easytier_iface_linux() {
    let Ok(out) = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", "edge0"])
        .output()
    else {
        return;
    };
    if !out.status.success() {
        return;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return;
    }
    eprintln!(
        "warn: stale Linux iface edge0 still present ({text}) — mesh uses sing-box TUN, not edge0. \
Run: sudo ip link del edge0"
    );
}

mod imp {
    use std::path::Path;

    use anyhow::{Context, Result};
    use easytier::{
        common::config::{ConfigFileControl, TomlConfigLoader},
        instance_manager::NetworkInstanceManager,
    };
    use once_cell::sync::Lazy;
    use uuid::Uuid;

    use super::to_easytier_toml;
    use crate::settings::{MeshConfig, MeshRole};

    static INSTANCE_MANAGER: Lazy<NetworkInstanceManager> =
        Lazy::new(NetworkInstanceManager::new);

    pub fn start(mesh: &MeshConfig, _data_dir: &Path) -> Result<Uuid> {
        match mesh.role {
            MeshRole::Relay => {
                if mesh.ipv4.as_deref().is_some_and(|s| !s.trim().is_empty()) {
                    eprintln!(
                        "easytier relay: hub-style (virtual ipv4 {}, listeners on :11010)",
                        mesh.ipv4.as_deref().unwrap_or("?")
                    );
                } else {
                    eprintln!(
                        "easytier relay: forward-only (no mesh IP — prefer --mesh-ip 10.x.1/24 on VPS)"
                    );
                }
            }
            MeshRole::Node => {
                #[cfg(target_os = "linux")]
                super::warn_stale_easytier_iface();
                eprintln!(
                    "easytier mesh node: no_tun (sing-box owns the only system TUN + WG portal)"
                );
            }
        }
        eprintln!(
            "easytier: network_name={:?} (secret {} chars) — must match on every mesh peer",
            mesh.network_name,
            mesh.network_secret.len()
        );
        match mesh.role {
            MeshRole::Relay => {
                if let Some(ipv4) =
                    mesh.ipv4.as_deref().filter(|s| !s.trim().is_empty())
                {
                    eprintln!(
                        "easytier relay: virtual ipv4 {ipv4} (hub-style; sing-box TUN stays off on VPS)"
                    );
                } else {
                    eprintln!(
                        "easytier relay: forward-only — no virtual ipv4 (nodes may not reach each other)"
                    );
                }
            }
            MeshRole::Node => {
                if let Some(ipv4) =
                    mesh.ipv4.as_deref().filter(|s| !s.trim().is_empty())
                {
                    eprintln!(
                        "easytier mesh node: virtual ipv4 {ipv4} (mesh routing, not edge0)"
                    );
                } else {
                    eprintln!(
                        "easytier mesh node: DHCP enabled (set [mesh].ipv4 for a fixed mesh address)"
                    );
                }
            }
        }
        let toml = to_easytier_toml(mesh)?;
        if let Some(listeners) =
            mesh.listeners.as_ref().filter(|l| !l.is_empty())
        {
            eprintln!("easytier: listeners → {}", listeners.join(", "));
        } else if mesh.role == MeshRole::Relay {
            eprintln!(
                "warn: [mesh].listeners empty — add listeners or rely on default :11010"
            );
        } else {
            eprintln!(
                "warn: [mesh].listeners empty — add listeners on the VPS relay, or peers on this node"
            );
        }
        let cfg = TomlConfigLoader::new_from_str(&toml)
            .context("parsing EasyTier mesh config")?;
        let id = INSTANCE_MANAGER
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .context("starting EasyTier mesh")?;
        eprintln!("mesh started (instance {id}, role={:?})", mesh.role);
        Ok(id)
    }

    pub fn stop_all() -> Result<()> {
        INSTANCE_MANAGER
            .retain_network_instance(Vec::new())
            .context("stopping EasyTier mesh")?;
        Ok(())
    }

    pub fn spawn_mesh_peer_watch(mesh: MeshConfig) {
        if std::env::var("ZAY_MESH_REQUIRE_PEERS").ok().as_deref() == Some("1")
        {
            return;
        }
        let role = mesh.role;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            log_mesh_status_now();
            let mut logged_no_peer = false;
            loop {
                match mesh_peer_count() {
                    Ok(n) if n > 0 => {
                        eprintln!("mesh: {n} remote peer(s) connected");
                        log_mesh_status_now();
                        return;
                    }
                    Ok(_) => {
                        if !logged_no_peer {
                            if role == MeshRole::Relay {
                                eprintln!(
                                    "mesh relay: waiting for clients on :11010 (no remote peers yet — normal)"
                                );
                            } else {
                                eprintln!(
                                    "mesh node: no remote peers yet — 10.x mesh routes inactive until peers connect"
                                );
                            }
                            logged_no_peer = true;
                        }
                    }
                    Err(e) => {
                        eprintln!("warn: mesh status query failed: {e:#}");
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        });
    }

    pub fn wait_for_mesh_peers(
        timeout: std::time::Duration,
        mesh: &MeshConfig,
    ) -> Result<()> {
        let is_relay = mesh.role == MeshRole::Relay;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if mesh_peer_count()? > 0 {
                log_mesh_status_now();
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                log_mesh_status_now();
                if is_relay {
                    eprintln!(
                        "easytier relay: no remote peers yet (normal until nodes run \
                         `zay stack --mesh node`; keep :11010 listening)"
                    );
                    return Ok(());
                }
                anyhow::bail!(
                    "EasyTier mesh has no remote peers after {}s — sing-box cannot reach \
                     10.x mesh IPs until EasyTier P2P is up.\n\
                     Checklist:\n\
                     1) Both sides run `zay stack --mesh node` with matching [mesh].role\n\
                     2) Same [mesh].network_name and network_secret on every node\n\
                     3) A relay (role = \"relay\") is listening on :11010\n\
                     4) Firewall allows TCP+UDP :11010",
                    timeout.as_secs()
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    fn mesh_peer_count() -> Result<usize> {
        let infos = INSTANCE_MANAGER
            .collect_network_infos_sync()
            .context("querying EasyTier mesh status")?;
        Ok(infos.values().map(|i| i.peers.len()).sum())
    }

    fn log_mesh_status_now() {
        let Ok(infos) = INSTANCE_MANAGER.collect_network_infos_sync() else {
            eprintln!("warn: could not query EasyTier mesh status");
            return;
        };
        for (id, info) in infos {
            let peers = info.peers.len();
            let routes = info.routes.len();
            let my_ip = info
                .my_node_info
                .as_ref()
                .and_then(|n| n.virtual_ipv4.as_ref())
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "(none — relay)".into());
            eprintln!(
                "easytier status ({id}): virtual ipv4 {my_ip}, {peers} remote peer(s), {routes} route(s)"
            );
            if let Some(node) = &info.my_node_info {
                let active: Vec<String> =
                    node.listeners.iter().map(|u| u.to_string()).collect();
                if active.is_empty() {
                    eprintln!(
                        "  active listeners: (none reported by EasyTier)"
                    );
                } else {
                    eprintln!("  active listeners: {}", active.join(", "));
                }
            }
            if peers == 0 {
                eprintln!(
                    "warn: EasyTier has no remote peers yet — check [mesh].role, network_name/secret, relay :11010"
                );
            } else {
                for pair in &info.peer_route_pairs {
                    let Some(route) = &pair.route else {
                        continue;
                    };
                    let host = if route.hostname.is_empty() {
                        format!("peer {}", route.peer_id)
                    } else {
                        route.hostname.clone()
                    };
                    let ip = route
                        .ipv4_addr
                        .as_ref()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "?".into());
                    eprintln!("  {host} mesh ipv4 {ip}");
                }
            }
            if info
                .my_node_info
                .as_ref()
                .and_then(|n| n.vpn_portal_cfg.as_ref())
                .is_some_and(|c| c.contains("ERROR"))
            {
                eprintln!(
                    "warn: EasyTier WireGuard portal not ready — sing-box easytier-wg will not work"
                );
            }
        }
    }
}

pub use imp::{spawn_mesh_peer_watch, start, stop_all, wait_for_mesh_peers};

pub fn start_for_singbox(
    mesh: &MeshConfig,
    data_dir: &Path,
) -> Result<uuid::Uuid> {
    start(mesh, data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::MeshConfig;

    fn mesh(role: MeshRole) -> MeshConfig {
        MeshConfig {
            role,
            instance_name: Some("zay".into()),
            network_name: "test-net".into(),
            network_secret: "secret".into(),
            dhcp: None,
            ipv4: None,
            listeners: None,
            peers: None,
            proxy_networks: None,
            mesh_routes: None,
            wireguard_listen: None,
            wireguard_client_cidr: None,
            wireguard_client_address: None,
            wireguard_endpoint: None,
        }
    }

    #[test]
    fn node_emits_dhcp_by_default() {
        let toml = to_easytier_toml(&mesh(MeshRole::Node)).unwrap();
        assert!(toml.contains("dhcp = true"));
        assert!(toml.contains("no_tun = true"));
        assert!(!toml.contains("private_mode"));
    }

    #[test]
    fn relay_forward_only_has_no_ipv4_or_portal() {
        let mut m = mesh(MeshRole::Relay);
        m.listeners = Some(vec![
            "tcp://0.0.0.0:11010".into(),
            "udp://0.0.0.0:11010".into(),
        ]);
        let toml = to_easytier_toml(&m).unwrap();
        assert!(!toml.contains("ipv4 = "));
        assert!(!toml.contains("[vpn_portal_config]"));
        assert!(toml.contains("no_tun = true"));
    }

    #[test]
    fn relay_hub_emits_ipv4_and_portal() {
        let mut m = mesh(MeshRole::Relay);
        m.ipv4 = Some("10.126.126.1/24".into());
        m.listeners = Some(vec!["tcp://0.0.0.0:11010".into()]);
        let toml = to_easytier_toml(&m).unwrap();
        assert!(toml.contains("ipv4 = \"10.126.126.1/24\""));
        assert!(toml.contains("[vpn_portal_config]"));
        assert!(!toml.contains("private_mode"));
    }

    #[test]
    fn node_has_portal_when_ipv4_set() {
        let mut m = mesh(MeshRole::Node);
        m.ipv4 = Some("10.126.126.10/24".into());
        let toml = to_easytier_toml(&m).unwrap();
        assert!(toml.contains("[vpn_portal_config]"));
        assert!(!toml.contains("private_mode"));
    }
}
