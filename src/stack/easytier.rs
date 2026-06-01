//! EasyTier mesh leg for `zay stack --mesh`.

use std::{fmt::Write as _, path::Path};

use anyhow::{Context, Result, bail};

use crate::settings::MeshConfig;

/// Serialize `[mesh]` to EasyTier TOML for `TomlConfigLoader`.
///
/// With sing-box, EasyTier runs `no_tun` and exposes a WireGuard VPN portal on
/// `127.0.0.1:51820`. The **only** system TUN is sing-box; mesh CIDRs route to the
/// `easytier-wg` endpoint. `[mesh].ipv4` is the virtual address on the mesh (not `edge0`).
pub fn to_easytier_toml(
    mesh: &MeshConfig,
    singbox_mesh: bool,
) -> Result<String> {
    let instance_name = mesh.instance_name.as_deref().unwrap_or("zay").trim();
    if instance_name.is_empty() {
        bail!("[mesh].instance_name must not be empty");
    }

    let mut out = String::new();
    writeln!(out, "instance_name = {instance_name:?}")?;
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

    // Must be root-level keys: TOML assigns keys after [network_identity] to that table.
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

    if singbox_mesh {
        writeln!(out)?;
        writeln!(out, "[flags]")?;
        writeln!(out, "no_tun = true")?;

        let listen = mesh
            .wireguard_listen
            .as_deref()
            .unwrap_or("127.0.0.1:51820");
        let client_cidr = crate::stack::mesh::portal_client_network_cidr(mesh);
        writeln!(out)?;
        writeln!(out, "[vpn_portal_config]")?;
        writeln!(out, "wireguard_listen = {listen:?}")?;
        writeln!(out, "client_cidr = {client_cidr:?}")?;
    }

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
    use crate::{settings::MeshConfig, stack::mesh};

    static INSTANCE_MANAGER: Lazy<NetworkInstanceManager> =
        Lazy::new(NetworkInstanceManager::new);

    pub fn start(
        mesh: &MeshConfig,
        _data_dir: &Path,
        singbox_mesh: bool,
    ) -> Result<Uuid> {
        if singbox_mesh {
            #[cfg(target_os = "linux")]
            super::warn_stale_easytier_iface();
            eprintln!(
                "easytier mesh: no_tun (sing-box owns the only system TUN + WG portal)"
            );
        }
        eprintln!(
            "easytier mesh: network_name={:?} (secret {} chars) — must be identical on Mac, Linux, and relay",
            mesh.network_name,
            mesh.network_secret.len()
        );
        if let Some(ipv4) =
            mesh.ipv4.as_deref().filter(|s| !s.trim().is_empty())
        {
            eprintln!(
                "easytier mesh: virtual ipv4 {ipv4} (mesh routing, not edge0)"
            );
        } else {
            eprintln!(
                "easytier mesh: DHCP enabled (set [mesh].ipv4 for a fixed mesh address)"
            );
        }
        let toml = to_easytier_toml(mesh, singbox_mesh)?;
        if let Some(listeners) =
            mesh.listeners.as_ref().filter(|l| !l.is_empty())
        {
            eprintln!("easytier mesh: listeners → {}", listeners.join(", "));
        } else {
            eprintln!(
                "warn: [mesh].listeners empty — this node will not accept inbound mesh on :11010; \
                 add listeners = [\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\"] on hub/VPS"
            );
        }
        let cfg = TomlConfigLoader::new_from_str(&toml)
            .context("parsing EasyTier mesh config")?;
        let id = INSTANCE_MANAGER
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .context("starting EasyTier mesh")?;
        eprintln!("mesh started (instance {id})");
        Ok(id)
    }

    pub fn stop_all() -> Result<()> {
        INSTANCE_MANAGER
            .retain_network_instance(Vec::new())
            .context("stopping EasyTier mesh")?;
        Ok(())
    }

    /// Log peer/routes after startup; warn when the EasyTier mesh has no remote peers yet.
    pub fn log_mesh_status(wait: std::time::Duration) {
        std::thread::sleep(wait);
        log_mesh_status_now();
    }

    /// Log mesh peer/routes in the background (default). Does not block stack startup.
    pub fn spawn_mesh_peer_watch(mesh: MeshConfig) {
        if std::env::var("ZAY_MESH_REQUIRE_PEERS").ok().as_deref() == Some("1")
        {
            return;
        }
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
                            if mesh::is_hub(&mesh) {
                                eprintln!(
                                    "mesh: hub waiting for clients on :11010 (no remote peers yet — normal)"
                                );
                            } else {
                                eprintln!(
                                    "mesh: no remote peers yet — 10.x mesh routes inactive until hub/clients connect; \
                                     proxy/TUN continues"
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

    /// Block until at least one remote peer appears (opt-in: `ZAY_MESH_REQUIRE_PEERS=1`).
    ///
    /// Hub nodes (with `[mesh].listeners`) skip the hard failure — they normally have
    /// zero peers until macOS/Linux clients connect.
    pub fn wait_for_mesh_peers(
        timeout: std::time::Duration,
        mesh: &MeshConfig,
    ) -> Result<()> {
        let is_hub = mesh::is_hub(mesh);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if mesh_peer_count()? > 0 {
                log_mesh_status_now();
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                log_mesh_status_now();
                if is_hub {
                    eprintln!(
                        "easytier hub: no remote peers yet (normal until other nodes run \
                         `zay stack --mesh`; keep this listener running on :11010)"
                    );
                    return Ok(());
                }
                anyhow::bail!(
                    "EasyTier mesh has no remote peers after {}s — sing-box cannot reach \
                     10.x mesh IPs until EasyTier P2P is up.\n\
                     Checklist:\n\
                     1) Both macOS and Linux run `zay stack --mesh` at the same time\n\
                     2) Same [mesh].network_name and network_secret on every node\n\
                     3) A hub node with listeners is running, or VPS runs EasyTier in the same network\n\
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
                .unwrap_or_else(|| "?".into());
            eprintln!(
                "easytier mesh status ({id}): virtual ipv4 {my_ip}, {peers} remote peer(s), {routes} route(s)"
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
                    "warn: EasyTier has no remote peers yet — ping to mesh IPs will fail until \
                     another node joins the same network_name/network_secret. \
                     Check: both nodes run `zay stack --mesh`, peers/listeners, VPS/firewall on :11010"
                );
            } else {
                let mut remote_ips = Vec::new();
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
                    if ip != "?" {
                        remote_ips.push(ip);
                    }
                }
                if peers == 1 && remote_ips.len() <= 1 {
                    eprintln!(
                        "warn: only one mesh node visible — if Mac should reach Linux (weapon), \
                         the relay hub must show 2+ peers and this node must list weapon's mesh IP above"
                    );
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

pub use imp::{
    log_mesh_status, spawn_mesh_peer_watch, start, stop_all,
    wait_for_mesh_peers,
};

pub fn start_for_singbox(
    mesh: &MeshConfig,
    data_dir: &Path,
) -> Result<uuid::Uuid> {
    start(mesh, data_dir, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::MeshConfig;

    fn mesh() -> MeshConfig {
        MeshConfig {
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
    fn emits_dhcp_by_default() {
        let toml = to_easytier_toml(&mesh(), false).unwrap();
        assert!(toml.contains("dhcp = true"));
        assert!(!toml.contains("no_tun"));
    }

    #[test]
    fn singbox_mesh_always_no_tun_and_vpn_portal() {
        let mut mesh = mesh();
        mesh.ipv4 = Some("10.126.126.10/24".into());
        mesh.listeners = Some(vec![
            "tcp://0.0.0.0:11010".into(),
            "udp://0.0.0.0:11010".into(),
        ]);
        let toml = to_easytier_toml(&mesh, true).unwrap();
        assert!(toml.contains("no_tun = true"));
        assert!(toml.contains("[vpn_portal_config]"));
        assert!(toml.contains("wireguard_listen = \"127.0.0.1:51820\""));
        // listeners must appear before [network_identity] (root-level EasyTier field)
        let ni = toml.find("[network_identity]").unwrap();
        let listeners = toml.find("listeners = ").unwrap();
        assert!(
            listeners < ni,
            "listeners must be root-level, before [network_identity]\n{toml}"
        );
        let cfg =
            easytier::common::config::TomlConfigLoader::new_from_str(&toml)
                .unwrap();
        use easytier::common::config::ConfigLoader as _;
        let uris = cfg.get_listener_uris();
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0].to_string(), "tcp://0.0.0.0:11010");
        assert_eq!(uris[1].to_string(), "udp://0.0.0.0:11010");
    }
}
