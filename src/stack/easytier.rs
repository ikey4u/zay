//! EasyTier mesh leg for `zay stack --mesh <relay|node>`.

use std::{fmt::Write as _, path::Path};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::settings::{MeshConfig, MeshRole};

/// A route-bearing mesh node reported by the local EasyTier instance.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshPeerStatus {
    pub peer_id: String,
    pub hostname: Option<String>,
    pub virtual_ipv4: Option<String>,
    /// `direct` when next hop is the peer itself; otherwise `via <relay-host>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Path latency in milliseconds when EasyTier reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Direct tunnel protocol(s) when connected, e.g. `udp` / `tcp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
}

/// Local EasyTier view of the currently connected mesh topology.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshInstanceStatus {
    pub instance_id: String,
    pub virtual_ipv4: Option<String>,
    pub connected_peers: usize,
    pub routes: usize,
    pub peers: Vec<MeshPeerStatus>,
}

/// Serialize `[mesh]` to EasyTier TOML for `TomlConfigLoader`.
pub fn to_easytier_toml(mesh: &MeshConfig) -> Result<String> {
    match mesh.role {
        MeshRole::Relay => to_easytier_relay_toml(mesh),
        MeshRole::Node => to_easytier_node_toml(mesh),
    }
}

/// Relay keeps `no_tun` (forward-only / optional hub). Nodes use EasyTier's kernel TUN
/// so mesh traffic is not hairpinned through sing-box userspace WireGuard.
fn write_easytier_flags(out: &mut String, role: MeshRole) -> Result<()> {
    writeln!(out)?;
    writeln!(out, "[flags]")?;
    match role {
        MeshRole::Relay => {
            writeln!(out, "no_tun = true")?;
        }
        MeshRole::Node => {
            writeln!(out, "no_tun = false")?;
            writeln!(out, "default_protocol = \"udp\"")?;
            writeln!(out, "latency_first = true")?;
            writeln!(out, "mtu = 1420")?;
            // Prefer LAN / hole-punched paths over the public relay when available.
            writeln!(out, "disable_udp_hole_punching = false")?;
        }
    }
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

/// Optional WG portal for hub-style relay (external clients). Nodes no longer use portal.
fn write_vpn_portal(out: &mut String, mesh: &MeshConfig) -> Result<()> {
    if mesh.role != MeshRole::Relay {
        return Ok(());
    }
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

    write_easytier_flags(&mut out, MeshRole::Relay)?;
    write_vpn_portal(&mut out, mesh)?;

    Ok(out)
}

/// Mesh member with EasyTier kernel TUN (sing-box excludes mesh CIDRs).
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

    // Nodes must listen so same-LAN peers can open a direct tunnel. Without
    // listeners, EasyTier only keeps the TCP session to the public relay and
    // bulk mesh transfers stay relay-bound (~1 MB/s).
    let listeners: Vec<String> = match mesh
        .listeners
        .as_ref()
        .filter(|l| !l.is_empty())
    {
        Some(l) => l.clone(),
        None => {
            eprintln!(
                "easytier node: [mesh].listeners unset — using {} (needed for LAN P2P)",
                crate::stack::mesh::DEFAULT_NODE_LISTENERS.join(", ")
            );
            crate::stack::mesh::default_node_listeners()
        }
    };
    writeln!(out)?;
    write!(out, "listeners = [")?;
    for (i, l) in listeners.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{l:?}")?;
    }
    writeln!(out, "]")?;

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

    write_easytier_flags(&mut out, MeshRole::Node)?;

    Ok(out)
}

fn clear_stale_easytier_iface() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    return Ok(());
    #[cfg(target_os = "linux")]
    clear_stale_easytier_iface_linux()
}

#[cfg(target_os = "linux")]
fn clear_stale_easytier_iface_linux() -> Result<()> {
    let Ok(out) = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", "edge0"])
        .output()
    else {
        return Ok(());
    };
    if !out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return Ok(());
    }
    eprintln!(
        "easytier: removing stale Linux iface edge0 before native TUN ({})",
        text.trim()
    );
    let del = std::process::Command::new("ip")
        .args(["link", "del", "edge0"])
        .output();
    let ok = matches!(&del, Ok(o) if o.status.success());
    if !ok {
        let del_sudo = std::process::Command::new("sudo")
            .args(["-n", "ip", "link", "del", "edge0"])
            .output();
        if !matches!(&del_sudo, Ok(o) if o.status.success()) {
            bail!(
                "stale Linux iface edge0 is still present and could not be deleted. \
                 Run: sudo ip link del edge0"
            );
        }
        eprintln!("easytier: deleted stale edge0 (via sudo -n)");
        return Ok(());
    }
    eprintln!("easytier: deleted stale edge0");
    Ok(())
}

mod imp {
    use std::{path::Path, sync::Arc};

    use anyhow::{Context, Result};
    use easytier::{
        common::config::{ConfigFileControl, TomlConfigLoader},
        instance::factory::{
            NativeInstanceManager, NativeProcessManagement,
            native_instance_manager_with_runtime, native_process_management,
        },
    };
    use once_cell::sync::Lazy;
    use tokio::runtime::{Builder, Runtime};
    use uuid::Uuid;

    use super::to_easytier_toml;
    use crate::settings::{MeshConfig, MeshRole};

    struct NoopHooks;

    #[async_trait::async_trait]
    impl easytier_core::management::InstanceMutationHooks for NoopHooks {
        async fn post_remove_network_instances(
            &self,
            _instance_ids: &[Uuid],
        ) -> Result<(), String> {
            Ok(())
        }
    }

    struct Ctx {
        runtime: Runtime,
        manager: Arc<NativeInstanceManager>,
        process_management: NativeProcessManagement,
    }

    impl Ctx {
        fn new() -> Self {
            let runtime = Builder::new_multi_thread()
                .enable_all()
                .thread_name("zay-et")
                .build()
                .expect("easytier tokio runtime");
            let manager = Arc::new(native_instance_manager_with_runtime(
                runtime.handle().clone(),
            ));
            let process_management =
                native_process_management(manager.clone(), Arc::new(NoopHooks));
            Self {
                runtime,
                manager,
                process_management,
            }
        }
    }

    static CTX: Lazy<Ctx> = Lazy::new(Ctx::new);

    /// EasyTier's `Runtime::block_on` / `Handle::block_on` panic if the current
    /// thread has entered any Tokio runtime (`spawn_blocking` on 1.52+ does).
    fn outside_tokio<T: Send>(f: impl FnOnce() -> T + Send) -> T {
        if tokio::runtime::Handle::try_current().is_ok() {
            match std::thread::scope(|scope| scope.spawn(f).join()) {
                Ok(value) => value,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        } else {
            f()
        }
    }

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
                super::clear_stale_easytier_iface()?;
                #[cfg(unix)]
                if !crate::privilege::is_root() {
                    anyhow::bail!(
                        "mesh node uses EasyTier kernel TUN and requires root \
                         (run `sudo zay run …`, or `zay service start` which elevates the daemon)"
                    );
                }
                eprintln!(
                    "easytier mesh node: native TUN (sing-box excludes mesh_routes; no WG portal)"
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
                        "easytier mesh node: virtual ipv4 {ipv4} on EasyTier edge TUN"
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
        let id = outside_tokio(|| {
            CTX.runtime.block_on(
                CTX.process_management.run_owned_network_instance(
                    cfg,
                    ConfigFileControl::STATIC_CONFIG,
                ),
            )
        })
        .context("starting EasyTier mesh")?;
        eprintln!("mesh started (instance {id}, role={:?})", mesh.role);
        Ok(id)
    }

    pub fn stop_all() -> Result<()> {
        outside_tokio(|| {
            CTX.runtime.block_on(
                CTX.process_management
                    .retain_owned_network_instances_by_name(Vec::new()),
            )
        })
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
                    "EasyTier mesh has no remote peers after {}s — mesh 10.x IPs are unreachable \
                     until EasyTier P2P is up.\n\
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

    /// Wait until EasyTier reports a virtual IPv4 (kernel TUN is up and addressed).
    pub fn wait_for_virtual_ip(timeout: std::time::Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if mesh_has_virtual_ip()? {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                log_mesh_status_now();
                anyhow::bail!(
                    "EasyTier virtual IPv4 not ready after {}s — kernel TUN may have failed to start",
                    timeout.as_secs()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    fn collect_infos() -> Result<
        std::collections::BTreeMap<
            Uuid,
            easytier::proto::api::manage::NetworkInstanceRunningInfo,
        >,
    > {
        outside_tokio(|| {
            CTX.manager
                .collect_network_infos_sync()
                .context("querying EasyTier mesh status")
        })
    }

    fn mesh_has_virtual_ip() -> Result<bool> {
        let infos = collect_infos()?;
        Ok(infos.values().any(|info| {
            info.my_node_info
                .as_ref()
                .and_then(|n| n.virtual_ipv4.as_ref())
                .is_some()
        }))
    }

    fn mesh_peer_count() -> Result<usize> {
        let infos = collect_infos()?;
        Ok(infos.values().map(|i| i.peers.len()).sum())
    }

    /// Query EasyTier's running snapshot (same data surface as `easytier-cli peer` / `route`).
    pub fn status() -> Result<Vec<super::MeshInstanceStatus>> {
        let infos = collect_infos()?;
        let mut instances = Vec::with_capacity(infos.len());
        for (id, info) in infos {
            let peer_host_by_id: std::collections::HashMap<u32, String> = info
                .routes
                .iter()
                .map(|r| {
                    let host = if r.hostname.is_empty() {
                        format!("peer-{}", r.peer_id)
                    } else {
                        r.hostname.clone()
                    };
                    (r.peer_id, host)
                })
                .collect();
            let peers = info
                .peer_route_pairs
                .iter()
                .filter_map(|pair| {
                    let route = pair.route.as_ref()?;
                    let next_hop = route
                        .next_hop_peer_id_latency_first
                        .unwrap_or(route.next_hop_peer_id);
                    let path = if next_hop == 0 || next_hop == route.peer_id {
                        Some("direct".to_string())
                    } else {
                        let via = peer_host_by_id
                            .get(&next_hop)
                            .cloned()
                            .unwrap_or_else(|| format!("peer-{next_hop}"));
                        Some(format!("via {via}"))
                    };
                    let latency_ms = {
                        let ms = route
                            .path_latency_latency_first
                            .unwrap_or(route.path_latency);
                        (ms > 0).then_some(ms as u64)
                    };
                    let tunnel = pair.get_conn_protos().map(|p| p.join("+"));
                    Some(super::MeshPeerStatus {
                        peer_id: route.peer_id.to_string(),
                        hostname: (!route.hostname.is_empty())
                            .then(|| route.hostname.clone()),
                        virtual_ipv4: route
                            .ipv4_addr
                            .as_ref()
                            .map(|ip| ip.to_string()),
                        path,
                        latency_ms,
                        tunnel,
                    })
                })
                .collect::<Vec<_>>();
            let virtual_ipv4 = info
                .my_node_info
                .as_ref()
                .and_then(|n| n.virtual_ipv4.as_ref())
                .map(|ip| ip.to_string());
            instances.push(super::MeshInstanceStatus {
                instance_id: id.to_string(),
                virtual_ipv4,
                connected_peers: info.peers.len(),
                routes: info.routes.len(),
                peers,
            });
        }
        Ok(instances)
    }

    fn log_mesh_status_now() {
        let Ok(infos) = collect_infos() else {
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
        }
    }
}

pub use imp::{
    spawn_mesh_peer_watch, start, status, stop_all, wait_for_mesh_peers,
    wait_for_virtual_ip,
};

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
            enabled: true,
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
        }
    }

    #[test]
    fn node_emits_native_tun_flags() {
        let mut m = mesh(MeshRole::Node);
        m.ipv4 = Some("10.126.126.10/24".into());
        let toml = to_easytier_toml(&m).unwrap();
        assert!(toml.contains("dhcp = false"));
        assert!(toml.contains("no_tun = false"));
        assert!(toml.contains("default_protocol = \"udp\""));
        assert!(toml.contains("latency_first = true"));
        assert!(toml.contains("mtu = 1420"));
        assert!(toml.contains("tcp://0.0.0.0:11010"));
        assert!(toml.contains("udp://0.0.0.0:11010"));
        assert!(!toml.contains("[vpn_portal_config]"));
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
        assert!(toml.contains("no_tun = true"));
        assert!(!toml.contains("private_mode"));
    }
}
