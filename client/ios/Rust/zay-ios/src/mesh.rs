//! EasyTier lifecycle for iOS (userspace mesh + SOCKS portal).

use std::sync::Arc;

use anyhow::{Context, Result};
use easytier::common::config::{ConfigFileControl, ConfigLoader as _, TomlConfigLoader};
use easytier::instance::factory::{
    NativeInstanceManager, NativeProcessManagement, native_instance_manager_with_runtime,
    native_process_management,
};
use once_cell::sync::Lazy;
use serde_json::json;
use tokio::runtime::{Builder, Runtime};

struct NoopHooks;

#[async_trait::async_trait]
impl easytier_core::management::InstanceMutationHooks for NoopHooks {
    async fn post_remove_network_instances(
        &self,
        _instance_ids: &[uuid::Uuid],
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
            .thread_name("zay-ios-et")
            .build()
            .expect("tokio runtime");
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

pub fn start_mesh(toml: &str) -> Result<()> {
    crate::logging::init_logging();
    tracing::info!("parsing EasyTier config ({} bytes)", toml.len());
    tracing::debug!("easytier toml:\n{toml}");

    let cfg = TomlConfigLoader::new_from_str(toml).context("parse EasyTier TOML")?;
    let name = cfg.get_inst_name();
    tracing::info!("starting EasyTier instance name={name}");

    outside_tokio(|| {
        CTX.runtime.block_on(
            CTX.process_management
                .run_owned_network_instance(cfg, ConfigFileControl::STATIC_CONFIG),
        )
    })
    .context("run EasyTier instance")?;

    tracing::info!("EasyTier instance started");
    Ok(())
}

pub fn stop_mesh() -> Result<()> {
    crate::logging::init_logging();
    tracing::info!("stopping all EasyTier instances");
    let stopped = outside_tokio(|| {
        let ids = CTX.manager.instance_ids();
        if ids.is_empty() {
            return Ok::<bool, anyhow::Error>(false);
        }
        CTX.runtime
            .block_on(CTX.process_management.delete_owned_network_instances(ids))
            .context("stop EasyTier")?;
        Ok(true)
    })?;
    if stopped {
        tracing::info!("EasyTier stopped");
    } else {
        tracing::info!("EasyTier already idle");
    }
    Ok(())
}

pub fn set_tun_fd(inst_name: &str, fd: i32) -> Result<()> {
    tracing::info!("set_tun_fd name={inst_name} fd={fd}");
    let id = easytier_core::management::resolve_optional_instance_by_name(
        CTX.manager.as_ref(),
        inst_name,
    )
    .map_err(|e| anyhow::anyhow!(e))?
    .map(|i| i.instance_id())
    .with_context(|| format!("instance not found: {inst_name}"))?;

    CTX.manager
        .attach_tun_fd(id, fd)
        .context("attach_tun_fd")?;
    Ok(())
}

pub fn mesh_status_json() -> Result<String> {
    let collected = outside_tokio(|| {
        CTX.manager
            .collect_network_infos_sync()
            .context("collect_network_infos_sync")
    })?;

    let mut arr = Vec::new();
    for (instance_id, value) in collected.iter() {
        let name = CTX
            .manager
            .instance(*instance_id)
            .map(|i| i.instance_name().to_owned())
            .unwrap_or_else(|| instance_id.to_string());
        arr.push(json!({
            "instance_id": instance_id.to_string(),
            "instance_name": name,
            "info": value,
        }));
    }

    // Convenience fields + UI-friendly overview/nodes for the Settings screen.
    for item in &mut arr {
        if let Some(cidr) = extract_vip_cidr(item) {
            item.as_object_mut()
                .unwrap()
                .insert("mesh_cidr".into(), json!(cidr));
        }
        if let Some(vip) = extract_vip_string(item) {
            item.as_object_mut()
                .unwrap()
                .insert("virtual_ipv4".into(), json!(vip));
        }
        let ui = build_ui_summary(item);
        item.as_object_mut()
            .unwrap()
            .insert("ui".into(), ui);
    }

    Ok(serde_json::to_string_pretty(&arr)?)
}

/// Flatten EasyTier network info into a stable shape for Swift UI.
fn build_ui_summary(item: &serde_json::Value) -> serde_json::Value {
    let info = item.get("info").cloned().unwrap_or(json!({}));
    let my = info
        .get("my_node_info")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let running = info
        .get("running")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let my_hostname = my
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let my_peer_id = json_u64(my.get("peer_id"));
    let my_vip = format_ipv4_prefix(my.get("virtual_ipv4"))
        .or_else(|| item.get("virtual_ipv4").and_then(|v| v.as_str()).map(str::to_string));
    let mesh_cidr = item
        .get("mesh_cidr")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| my_vip.as_ref().and_then(|v| guess_mesh_cidr_from_vip(v)));
    let version = my
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let stun_tcp = my
        .pointer("/stun_info/tcp_nat_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let stun_udp = my
        .pointer("/stun_info/udp_nat_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut network_name = String::new();
    let mut nodes = Vec::new();

    // Self node first.
    nodes.push(json!({
        "peer_id": my_peer_id.map(|v| v.to_string()).unwrap_or_default(),
        "hostname": if my_hostname.is_empty() { "(本机)".to_string() } else { my_hostname.clone() },
        "ipv4": my_vip.clone().unwrap_or_default(),
        "is_self": true,
        "cost": 0,
        "latency_ms": serde_json::Value::Null,
        "next_hop_peer_id": "",
        "version": version.clone(),
        "proxy_cidrs": [],
        "nat_tcp": stun_tcp,
        "nat_udp": stun_udp,
        "rx_bytes": 0,
        "tx_bytes": 0,
        "conn_count": 0,
        "tunnels": []
    }));

    // Peer connection stats keyed by peer_id (for rx/tx / tunnel urls).
    let mut peer_stats: std::collections::HashMap<u64, serde_json::Value> =
        std::collections::HashMap::new();
    if let Some(peers) = info.get("peers").and_then(|p| p.as_array()) {
        for peer in peers {
            let pid = json_u64(peer.get("peer_id")).or_else(|| {
                peer.pointer("/peer/peer_id")
                    .and_then(json_u64_value)
            });
            let Some(pid) = pid else { continue };
            let conns = peer
                .get("conns")
                .or_else(|| peer.pointer("/peer/conns"))
                .and_then(|c| c.as_array())
                .cloned()
                .unwrap_or_default();
            let mut rx = 0u64;
            let mut tx = 0u64;
            let mut tunnels = Vec::new();
            let mut best_lat_us: Option<u64> = None;
            for c in &conns {
                if let Some(nn) = c
                    .get("network_name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    if network_name.is_empty() {
                        network_name = nn.to_string();
                    }
                }
                if let Some(stats) = c.get("stats") {
                    rx += json_u64(stats.get("rx_bytes")).unwrap_or(0);
                    tx += json_u64(stats.get("tx_bytes")).unwrap_or(0);
                    if let Some(lat) = json_u64(stats.get("latency_us")) {
                        best_lat_us = Some(best_lat_us.map_or(lat, |b| b.min(lat)));
                    }
                }
                let local = c
                    .pointer("/tunnel/local_addr/url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let remote = c
                    .pointer("/tunnel/remote_addr/url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let tunnel_type = c
                    .pointer("/tunnel/tunnel_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !remote.is_empty() || !local.is_empty() {
                    tunnels.push(json!({
                        "type": tunnel_type,
                        "local": local,
                        "remote": remote
                    }));
                }
            }
            peer_stats.insert(
                pid,
                json!({
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                    "conn_count": conns.len(),
                    "latency_us": best_lat_us,
                    "tunnels": tunnels
                }),
            );
        }
    }

    if let Some(routes) = info.get("routes").and_then(|r| r.as_array()) {
        for route in routes {
            let peer_id = json_u64(route.get("peer_id"));
            let hostname = route
                .get("hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed)")
                .to_string();
            let ipv4 = format_ipv4_prefix(route.get("ipv4_addr")).unwrap_or_default();
            let cost = json_u64(route.get("cost")).unwrap_or(0);
            let latency_ms = json_u64(route.get("path_latency"))
                .or_else(|| json_u64(route.get("path_latency_latency_first")));
            let next_hop = json_u64(route.get("next_hop_peer_id"))
                .map(|v| v.to_string())
                .unwrap_or_default();
            let version = route
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let proxy_cidrs: Vec<String> = route
                .get("proxy_cidrs")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let nat_tcp = route
                .pointer("/stun_info/tcp_nat_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let nat_udp = route
                .pointer("/stun_info/udp_nat_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let is_self = peer_id.is_some() && peer_id == my_peer_id;
            if is_self {
                // Enrich self entry if route has better fields.
                if let Some(self_node) = nodes.first_mut() {
                    if self_node.get("ipv4").and_then(|v| v.as_str()).unwrap_or("").is_empty()
                        && !ipv4.is_empty()
                    {
                        self_node
                            .as_object_mut()
                            .unwrap()
                            .insert("ipv4".into(), json!(ipv4));
                    }
                }
                continue;
            }

            let mut node = json!({
                "peer_id": peer_id.map(|v| v.to_string()).unwrap_or_default(),
                "hostname": hostname,
                "ipv4": ipv4,
                "is_self": false,
                "cost": cost,
                "latency_ms": latency_ms,
                "next_hop_peer_id": next_hop,
                "version": version,
                "proxy_cidrs": proxy_cidrs,
                "nat_tcp": nat_tcp,
                "nat_udp": nat_udp,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "conn_count": 0,
                "tunnels": []
            });

            if let Some(pid) = peer_id {
                if let Some(stats) = peer_stats.get(&pid) {
                    if let Some(obj) = node.as_object_mut() {
                        obj.insert("rx_bytes".into(), stats["rx_bytes"].clone());
                        obj.insert("tx_bytes".into(), stats["tx_bytes"].clone());
                        obj.insert("conn_count".into(), stats["conn_count"].clone());
                        obj.insert("tunnels".into(), stats["tunnels"].clone());
                        if obj.get("latency_ms").and_then(|v| v.as_u64()).is_none() {
                            if let Some(us) = json_u64(stats.get("latency_us")) {
                                obj.insert("latency_ms".into(), json!(us / 1000));
                            }
                        }
                    }
                }
            }
            nodes.push(node);
        }
    }

    let peer_count = nodes.iter().filter(|n| n.get("is_self") != Some(&json!(true))).count();

    json!({
        "running": running,
        "instance_name": item.get("instance_name").cloned().unwrap_or(json!("")),
        "instance_id": item.get("instance_id").cloned().unwrap_or(json!("")),
        "hostname": my_hostname,
        "virtual_ipv4": my_vip.unwrap_or_default(),
        "mesh_cidr": mesh_cidr.unwrap_or_default(),
        "network_name": network_name,
        "peer_id": my_peer_id.map(|v| v.to_string()).unwrap_or_default(),
        "peer_count": peer_count,
        "node_count": nodes.len(),
        "version": version,
        "nodes": nodes
    })
}

fn format_ipv4_prefix(v: Option<&serde_json::Value>) -> Option<String> {
    let obj = v?;
    let addr = obj
        .pointer("/address/addr")
        .and_then(json_u64_value)
        .or_else(|| json_u64(obj.get("addr")))?;
    let len = json_u64(obj.get("network_length")).unwrap_or(24);
    let bytes = (addr as u32).to_be_bytes();
    Some(format!(
        "{}.{}.{}.{}/{len}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}

fn json_u64(v: Option<&serde_json::Value>) -> Option<u64> {
    v.and_then(json_u64_value)
}

fn json_u64_value(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().map(|i| i as u64))
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn extract_vip_string(item: &serde_json::Value) -> Option<String> {
    let info = item.get("info")?;
    if let Some(s) = format_ipv4_prefix(info.pointer("/my_node_info/virtual_ipv4")) {
        return Some(s);
    }
    // Best-effort walk of known shapes from EasyTier network infos.
    for key in ["ipv4", "virtual_ipv4", "my_ipv4", "addr"] {
        if let Some(s) = info.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    if let Some(s) = info
        .pointer("/node_info/ip_list/ipv4")
        .or_else(|| info.pointer("/node_info/ipv4"))
        .and_then(|v| v.as_str())
    {
        return Some(s.to_string());
    }
    let text = info.to_string();
    find_ipv4_cidr(&text)
}

fn extract_vip_cidr(item: &serde_json::Value) -> Option<String> {
    let vip = extract_vip_string(item)?;
    guess_mesh_cidr_from_vip(&vip).or(Some(vip))
}

fn find_ipv4_cidr(text: &str) -> Option<String> {
    // Very small scanner for N.N.N.N/N
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit() || bytes[i] == b'.' || bytes[i] == b'/')
            {
                if bytes[i] == b'.' {
                    dots += 1;
                }
                i += 1;
            }
            if dots == 3 {
                let cand = &text[start..i];
                if cand.contains('/') {
                    return Some(cand.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

pub fn guess_mesh_cidr_from_vip(vip: &str) -> Option<String> {
    let (addr, prefix) = vip.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    let octets: Vec<u8> = addr
        .split('.')
        .filter_map(|o| o.parse().ok())
        .collect();
    if octets.len() != 4 {
        return None;
    }
    let mask = if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let ip = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let net = ip & mask;
    let b = net.to_be_bytes();
    Some(format!("{}.{}.{}.{}/{}", b[0], b[1], b[2], b[3], prefix))
}

pub fn parse_relay_host(relay_url: &str) -> Option<String> {
    let raw = if relay_url.contains("://") {
        relay_url.to_string()
    } else {
        format!("tcp://{relay_url}")
    };
    let u = url::Url::parse(&raw).ok()?;
    u.host_str().map(|h| h.to_string())
}
