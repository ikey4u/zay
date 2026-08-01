//! TUN `route_exclude_address` helpers — keep LAN/SSH and mesh control traffic off the tunnel.

use std::{
    env,
    net::Ipv4Addr,
    process::Command,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::{settings::Settings, stack::mesh};

/// Fallback sing-box TUN when `[mesh].ipv4` is unset (/30 required for mixed stack).
pub const TUN_ADDRESS_FALLBACK: &str = "10.14.14.9/30";

pub fn tun_address(settings: &Settings) -> String {
    settings
        .mesh
        .as_ref()
        .and_then(|m| mesh::portal_tun_prefix_cidr(m))
        .unwrap_or_else(|| TUN_ADDRESS_FALLBACK.to_string())
}

/// TUN `address` list: IPv4 portal prefix + optional IPv6 /126 for full-capture stacks.
pub fn tun_addresses(settings: &Settings) -> Vec<String> {
    let mut addrs = vec![tun_address(settings)];
    if let Some(v6) = tun_inet6_prefix(settings) {
        addrs.push(v6);
    }
    addrs
}

/// ULA /126 on full-capture TUN so desktop browsers (Firefox IPv6/AAAA) enter sing-box instead of leaking.
///
/// Must be the **first** host in a /126 (e.g. `::1/126`), not the last (e.g. `::3/126`):
/// sing-box system/mixed stack needs `addr+1` inside the same prefix for TUN DNS.
pub fn tun_inet6_prefix(settings: &Settings) -> Option<String> {
    if !singbox_tun_enabled(settings) || tun_selective_mesh_routes(settings) {
        return None;
    }
    let _ = settings;
    Some("fdfe:dcba:9876::1/126".to_string())
}

/// RFC1918-style ranges that must not be captured by TUN (except mesh routes in 10.x).
const DEFAULT_EXCLUDES: &[&str] = &[
    "127.0.0.0/8",
    "169.254.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

pub fn tun_exclude_addresses(settings: &Settings) -> Result<Vec<String>> {
    let mut excludes: Vec<String> =
        DEFAULT_EXCLUDES.iter().map(|s| (*s).to_string()).collect();
    excludes.extend(settings.tun_exclude_routes.iter().cloned());
    let peer_excludes = mesh::peer_exclude_cidrs(settings);
    if !peer_excludes.is_empty() {
        eprintln!(
            "tun exclude: mesh peer/control plane → {}",
            peer_excludes.join(", ")
        );
    }
    excludes.extend(peer_excludes);
    // EasyTier owns mesh CIDRs on its edge TUN — derive from mesh_routes or ipv4.
    // Fail hard when sing-box full TUN would otherwise capture the same CIDRs.
    if let Some(mesh) = settings.mesh.as_ref() {
        let routes = crate::settings::mesh_tun_exclude_cidrs(mesh)?;
        if routes.is_empty() {
            if singbox_tun_enabled(settings) && settings.mesh_is_node() {
                bail!(
                    "mesh node with sing-box TUN requires [mesh].mesh_routes or \
                     [mesh].ipv4 so mesh CIDRs can be excluded from the proxy TUN"
                );
            }
        } else {
            eprintln!(
                "tun exclude: EasyTier mesh routes (from config) → {}",
                routes.join(", ")
            );
            excludes.extend(routes);
        }
    }
    if tun_full_capture_mesh_proxy(settings) {
        let stun = mesh::easytier_stun_exclude_cidrs();
        if !stun.is_empty() {
            eprintln!(
                "tun exclude: EasyTier STUN (NAT probes) → {}",
                stun.join(", ")
            );
        }
        excludes.extend(stun);
    }
    excludes.extend(detect_os_ipv4_cidrs());
    let ssh_servers = detect_ssh_server_cidrs();
    if !ssh_servers.is_empty() {
        eprintln!(
            "tun exclude: active SSH destination(s) → {}",
            ssh_servers.join(", ")
        );
    }
    excludes.extend(ssh_servers);
    let ssh_clients = detect_ssh_inbound_client_cidrs();
    if !ssh_clients.is_empty() {
        eprintln!(
            "tun exclude: inbound SSH client(s) → {}",
            ssh_clients.join(", ")
        );
    }
    excludes.extend(ssh_clients);
    excludes.sort();
    excludes.dedup();
    filter_fakeip_route_excludes(settings, &mut excludes);
    Ok(excludes)
}

/// FakeIP pool used with Loyalsoldier + sing-box TUN (must not appear in `route_exclude_address`).
const FAKEIP_V4_NET: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
const FAKEIP_V4_PREFIX: u8 = 15;

fn fakeip_excludes_active(settings: &Settings) -> bool {
    if !singbox_tun_enabled(settings) {
        return false;
    }
    if settings.stack.no_rules {
        return !settings.subscriptions.is_empty();
    }
    crate::singbox::rules::files_present(&settings.singbox_dir())
        || !settings.subscriptions.is_empty()
}

fn ipv4_in_fakeip_range(addr: Ipv4Addr) -> bool {
    let n = u32::from(addr);
    let base = u32::from(FAKEIP_V4_NET);
    let mask = if FAKEIP_V4_PREFIX == 0 {
        0
    } else {
        u32::MAX << (32 - FAKEIP_V4_PREFIX)
    };
    (n & mask) == (base & mask)
}

/// Drop `/32` (or any) excludes inside 198.18.0.0/15 — e.g. SSH/lsof can record a FakeIP peer and break curl.
fn filter_fakeip_route_excludes(
    settings: &Settings,
    excludes: &mut Vec<String>,
) {
    if !fakeip_excludes_active(settings) {
        return;
    }
    let mut dropped = Vec::new();
    excludes.retain(|cidr| {
        let host = cidr.split('/').next().unwrap_or(cidr).trim();
        let Ok(addr) = host.parse::<Ipv4Addr>() else {
            return true;
        };
        if ipv4_in_fakeip_range(addr) {
            dropped.push(cidr.clone());
            false
        } else {
            true
        }
    });
    if !dropped.is_empty() {
        eprintln!(
            "warn: removed route_exclude inside FakeIP 198.18.0.0/15 (fixes curl connection refused): {}",
            dropped.join(", ")
        );
    }
}

/// Whether sing-box should open a system TUN inbound.
///
/// Hub/relay nodes (`[mesh].listeners`) only forward EasyTier mesh traffic — they do not
/// need sing-box TUN (and enabling it breaks active SSH sessions on VPS).
pub fn singbox_tun_enabled(settings: &Settings) -> bool {
    if !(settings.tun || settings.stack.tun) {
        return false;
    }
    if settings.mesh_is_relay() {
        return false;
    }
    // Mesh-only (no proxy subscription): EasyTier owns the TUN; sing-box needs none.
    if mesh_only_no_proxy(settings) {
        return false;
    }
    true
}

/// Mesh node without proxy subscriptions — no sing-box TUN required.
pub fn mesh_only_no_proxy(settings: &Settings) -> bool {
    settings.mesh_is_node()
        && settings.subscriptions.is_empty()
        && !settings.stack.gateway
}

pub fn tun_auto_route(_settings: &Settings) -> bool {
    true
}

/// Full-capture TUN: `system` stack (Linux + macOS). `mixed` on macOS often breaks TCP (curl → :80 refused).
pub fn tun_stack(settings: &Settings) -> &'static str {
    if singbox_tun_enabled(settings) && !mesh_only_no_proxy(settings) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            return "system";
        }
    }
    "mixed"
}

/// Opt-in: nftables DNS redirect (`ZAY_TUN_AUTO_REDIRECT=1`). Fails if stale nft rules exist (`file exists`).
pub fn tun_auto_redirect(settings: &Settings) -> bool {
    #[cfg(target_os = "linux")]
    {
        if env::var("ZAY_TUN_AUTO_REDIRECT").ok().as_deref() != Some("1") {
            return false;
        }
        return singbox_tun_enabled(settings)
            && tun_auto_route(settings)
            && !mesh_only_no_proxy(settings);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = settings;
        false
    }
}

/// DNS addresses sing-box registers on the TUN link (next IP after each `address` entry).
pub fn tun_derived_dns_servers(settings: &Settings) -> Vec<String> {
    tun_addresses(settings)
        .iter()
        .filter_map(|cidr| next_address_host(cidr))
        .collect()
}

fn next_address_host(cidr: &str) -> Option<String> {
    let (host, _) = cidr.split_once('/')?;
    if host.contains(':') {
        return None;
    }
    let addr: Ipv4Addr = host.parse().ok()?;
    Some(Ipv4Addr::from(u32::from(addr).saturating_add(1)).to_string())
}

/// Mesh client without proxy: historically captured only `[mesh].mesh_routes` on sing-box TUN.
/// With native EasyTier TUN, sing-box does not capture mesh CIDRs (`mesh_only_no_proxy`).
///
/// With `--proxy` / `-s`, use full TUN for transparent proxy; EasyTier control plane is kept off TUN
/// via `route_exclude_address` (relay/STUN/mesh_routes) and a `process_name → direct` rule for `zay`.
pub fn tun_selective_mesh_routes(settings: &Settings) -> bool {
    mesh_only_no_proxy(settings)
}

/// `--mesh node` with subscription: full TUN for gfw/Proxy; mesh CIDRs excluded for EasyTier TUN.
pub fn tun_full_capture_mesh_proxy(settings: &Settings) -> bool {
    singbox_tun_enabled(settings)
        && settings.mesh_is_node()
        && !settings.subscriptions.is_empty()
        && !settings.stack.gateway
}

/// Mesh traffic no longer enters sing-box — EasyTier edge TUN owns `mesh_routes`.
pub fn tun_route_address(_settings: &Settings) -> Option<Vec<String>> {
    None
}

pub fn is_selective_mesh_tun(_settings: &Settings) -> bool {
    false
}

/// Log TUN routing knobs from the generated sing-box JSON (helps debug relay SSH drops).
pub fn log_tun_routing(config_json: &str) {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return;
    };
    let Some(inbounds) = doc.get("inbounds").and_then(|v| v.as_array()) else {
        return;
    };
    let Some(tun) = inbounds
        .iter()
        .find(|ib| ib.get("type").and_then(|t| t.as_str()) == Some("tun"))
    else {
        return;
    };
    let auto_route = tun
        .get("auto_route")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let route_address = tun
        .get("route_address")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let excludes = tun
        .get("route_exclude_address")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    if auto_route && !route_address.is_empty() {
        eprintln!(
            "tun routing: auto_route=true, route_address=[{route_address}] ({excludes} excludes; mesh-only capture, SSH-safe)"
        );
    } else if auto_route {
        let redirect = tun
            .get("auto_redirect")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if redirect {
            eprintln!(
                "tun routing: auto_route=true, auto_redirect=true, full capture ({excludes} excludes)"
            );
        } else {
            eprintln!(
                "tun routing: auto_route=true, full capture ({excludes} excludes)"
            );
        }
    } else {
        eprintln!("tun routing: auto_route=false ({excludes} excludes)");
    }
}

#[cfg(target_os = "linux")]
fn systemd_resolved_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// After sing-box brings up tun0: register TUN DNS on systemd-resolved when present (Mihomo does this in-core).
#[cfg(target_os = "linux")]
pub fn linux_register_tun_dns(settings: &Settings) {
    if env::var("ZAY_NO_RESOLVECTL_DNS").is_ok() {
        return;
    }
    if !singbox_tun_enabled(settings) || tun_selective_mesh_routes(settings) {
        return;
    }
    let servers = tun_derived_dns_servers(settings);
    if servers.is_empty() {
        return;
    }
    if !systemd_resolved_running() {
        log_glibc_dns_hint(&servers);
        return;
    }
    let ifname = tun_interface_name();
    let mut cmd = Command::new("resolvectl");
    cmd.arg("dns").arg(&ifname);
    for s in &servers {
        cmd.arg(s);
    }
    match cmd.status() {
        Ok(s) if s.success() => {
            eprintln!(
                "linux DNS: resolvectl dns {ifname} {} (systemd-resolved → sing-box FakeIP)",
                servers.join(" ")
            );
        }
        Ok(s) => {
            eprintln!(
                "warn: resolvectl dns {ifname} exited {}; check: resolvectl status {ifname}",
                s
            );
        }
        Err(e) => {
            eprintln!("warn: resolvectl failed ({e})");
            log_glibc_dns_hint(&servers);
        }
    }
}

#[cfg(target_os = "linux")]
fn log_glibc_dns_hint(tun_dns: &[String]) {
    eprintln!(
        "linux DNS: no systemd-resolved — glibc reads /etc/resolv.conf directly \
         (resolvectl does not apply on this host)"
    );
    eprintln!(
        "dns: FakeIP needs port-53 queries to reach sing-box (TUN hijack-dns). \
         Avoid stub 127.0.0.53 with no resolver behind it; use routable nameservers \
         (e.g. 223.5.5.5) or set ZAY_TUN_AUTO_REDIRECT=1 if nftables is clean. \
         TUN DNS gateway: {}",
        tun_dns.join(", ")
    );
    if let Ok(raw) = std::fs::read_to_string("/etc/resolv.conf") {
        let preview: String =
            raw.lines().take(4).collect::<Vec<_>>().join("; ");
        if !preview.is_empty() {
            eprintln!("dns: /etc/resolv.conf → {preview}");
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn linux_register_tun_dns(_settings: &Settings) {}

pub fn log_fakeip_dns_hint(settings: &Settings, clash_dns: bool) {
    if !clash_dns || !singbox_tun_enabled(settings) {
        return;
    }
    let servers = tun_derived_dns_servers(settings);
    if servers.is_empty() {
        return;
    }
    eprintln!(
        "dns: FakeIP active — with sing-box running, check: getent ahostsv4 google.com \
         (expect 198.18.x.x, not 173.x or 2607:…). TUN DNS: {}",
        servers.join(", ")
    );
    #[cfg(target_os = "linux")]
    if systemd_resolved_running() {
        eprintln!(
            "dns: systemd-resolved — after start: resolvectl status {}",
            tun_interface_name()
        );
    } else {
        eprintln!(
            "dns: no systemd-resolved — use getent ahostsv4; see /etc/resolv.conf"
        );
    }
}

fn tun_interface_name() -> String {
    env::var("ZAY_TUN_INTERFACE").unwrap_or_else(|_| "tun0".into())
}

/// `direct` outbound; bind to the physical NIC on full TUN (sing-box config only — avoids DNS loops).
pub fn direct_outbound_json(settings: &Settings, tun_enabled: bool) -> Value {
    let mut ob = json!({ "type": "direct", "tag": "direct" });
    if tun_enabled && !tun_selective_mesh_routes(settings) {
        if let Some(iface) = default_route_interface() {
            ob["bind_interface"] = json!(iface);
        }
    }
    ob
}

pub fn default_route_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        default_route_interface_linux()
    }
    #[cfg(target_os = "macos")]
    {
        default_route_interface_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn default_route_interface_linux() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    parse_ip_route_dev(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(target_os = "macos")]
fn default_route_interface_macos() -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("interface:") {
            let iface = rest.trim();
            if !iface.is_empty() {
                return Some(iface.to_string());
            }
        }
    }
    None
}

fn parse_ip_route_dev(text: &str) -> Option<String> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = parts.iter().position(|&p| p == "dev") {
            if let Some(dev) = parts.get(i + 1) {
                return Some((*dev).to_string());
            }
        }
    }
    None
}

/// `strict_route` breaks SSH/LAN when combined with mesh; keep it off for `--mesh`.
pub fn tun_strict_route(settings: &Settings) -> bool {
    !settings.stack.mesh_enabled()
}

/// Best-effort: add CIDRs of live global IPv4 interfaces (SSH client subnet, default route NIC).
fn detect_os_ipv4_cidrs() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        detect_linux_ipv4_cidrs().unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        detect_macos_ipv4_cidrs().unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_ipv4_cidrs() -> Option<Vec<String>> {
    let out = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_ip_addr_lines(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(target_os = "macos")]
fn detect_macos_ipv4_cidrs() -> Option<Vec<String>> {
    let out = Command::new("ifconfig").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_macos_ifconfig(&String::from_utf8_lossy(&out.stdout)))
}

/// Skip utun/lo/tunnel interfaces — only exclude the physical NIC (en*, bridge*, etc.).
fn parse_macos_ifconfig(text: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    let mut current_iface: Option<&str> = None;
    for line in text.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') {
            current_iface = line.split(':').next();
            continue;
        }
        let Some(iface) = current_iface else {
            continue;
        };
        if should_skip_macos_iface(iface) {
            continue;
        }
        if let Some(cidr) = parse_macos_inet_line(line) {
            cidrs.push(cidr);
        }
    }
    cidrs
}

fn should_skip_macos_iface(name: &str) -> bool {
    name.starts_with("utun")
        || name == "lo0"
        || name.starts_with("awdl")
        || name.starts_with("llw")
        || name.starts_with("gif")
        || name.starts_with("stf")
}

/// `inet 192.168.1.5 netmask 0xffffff00` or `inet 10.0.0.1/24`
fn parse_macos_inet_line(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix("inet ")?;
    let parts: Vec<_> = rest.split_whitespace().collect();
    let ip_token = parts.first()?;
    if let Some((ip, prefix)) = ip_token.split_once('/') {
        if ip.parse::<Ipv4Addr>().ok().is_some() {
            return Some(format!("{ip}/{prefix}"));
        }
        return None;
    }
    let ip: Ipv4Addr = ip_token.parse().ok()?;
    for (i, part) in parts.iter().enumerate() {
        if part == &"netmask" {
            let mask = parts.get(i + 1)?;
            let prefix = ipv4_netmask_prefix(mask)?;
            return Some(format!("{ip}/{prefix}"));
        }
    }
    None
}

fn ipv4_netmask_prefix(mask: &str) -> Option<u8> {
    if let Some(hex) =
        mask.strip_prefix("0x").or_else(|| mask.strip_prefix("0X"))
    {
        let bits = u32::from_str_radix(hex, 16).ok()?;
        return Some(mask_to_prefix(bits));
    }
    if mask.parse::<Ipv4Addr>().ok().is_some() {
        let bits = u32::from(mask.parse::<Ipv4Addr>().ok()?);
        return Some(mask_to_prefix(bits));
    }
    None
}

fn mask_to_prefix(bits: u32) -> u8 {
    bits.count_ones() as u8
}

/// Outbound SSH from this machine (dport :22) — Mac/Linux clients must reach relay/VPS directly.
fn detect_ssh_server_cidrs() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        for args in [
            &["-H", "-tn", "state", "established", "dport", "=", ":22"][..],
            &["-tn", "state", "established", "(", "dport", "=", ":22", ")"][..],
        ] {
            if let Ok(out) = Command::new("ss").args(args).output()
                && out.status.success()
            {
                let cidrs =
                    parse_ss_ssh_peers(&String::from_utf8_lossy(&out.stdout));
                if !cidrs.is_empty() {
                    return cidrs;
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
            .output()
            && out.status.success()
        {
            let cidrs =
                parse_lsof_ssh_servers(&String::from_utf8_lossy(&out.stdout));
            if !cidrs.is_empty() {
                return cidrs;
            }
        }
        if let Ok(out) =
            Command::new("netstat").args(["-anv", "-p", "tcp"]).output()
            && out.status.success()
        {
            let cidrs = parse_netstat_macos_ssh_servers(
                &String::from_utf8_lossy(&out.stdout),
            );
            if !cidrs.is_empty() {
                return cidrs;
            }
        }
    }
    Vec::new()
}

/// Inbound SSH on this machine (sport :22) — relay/VPS return traffic stays off TUN.
fn detect_ssh_inbound_client_cidrs() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        for args in [
            &["-H", "-tn", "state", "established", "sport", "=", ":22"][..],
            &["-tn", "state", "established", "(", "sport", "=", ":22", ")"][..],
        ] {
            if let Ok(out) = Command::new("ss").args(args).output()
                && out.status.success()
            {
                let cidrs =
                    parse_ss_ssh_peers(&String::from_utf8_lossy(&out.stdout));
                if !cidrs.is_empty() {
                    return cidrs;
                }
            }
        }
        if let Ok(out) = Command::new("netstat").args(["-tn"]).output()
            && out.status.success()
        {
            return parse_netstat_ssh_clients(&String::from_utf8_lossy(
                &out.stdout,
            ));
        }
    }
    Vec::new()
}

fn parse_netstat_ssh_clients(text: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in text.lines() {
        if !line.contains("ESTABLISHED") || !line.contains(":22 ") {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        // Foreign Address is typically the last column on Linux netstat -tn.
        if let Some(cidr) =
            peer_to_ipv4_cidr(parts.last().copied().unwrap_or(""))
        {
            cidrs.push(cidr);
        }
    }
    cidrs.sort();
    cidrs.dedup();
    cidrs
}

#[cfg(target_os = "macos")]
fn parse_lsof_ssh_servers(text: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in text.lines().skip(1) {
        if !line.contains("->") || !line.contains(":22") {
            continue;
        }
        let Some(remote) = line.split("->").nth(1) else {
            continue;
        };
        let remote = remote.split_whitespace().next().unwrap_or("");
        if let Some(cidr) =
            peer_to_ipv4_cidr(remote.trim_end_matches("(ESTABLISHED)"))
        {
            cidrs.push(cidr);
        }
    }
    cidrs.sort();
    cidrs.dedup();
    cidrs
}

#[cfg(target_os = "macos")]
fn parse_netstat_macos_ssh_servers(text: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in text.lines() {
        if !line.contains("ESTABLISHED") {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let foreign = parts[4];
        if foreign.ends_with(".22") || foreign.contains(":22") {
            if let Some(cidr) = peer_to_ipv4_cidr(foreign) {
                cidrs.push(cidr);
            }
        }
    }
    cidrs.sort();
    cidrs.dedup();
    cidrs
}

fn parse_ss_ssh_peers(text: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(peer) = line.split_whitespace().next_back() else {
            continue;
        };
        if let Some(cidr) = peer_to_ipv4_cidr(peer) {
            cidrs.push(cidr);
        }
    }
    cidrs.sort();
    cidrs.dedup();
    cidrs
}

fn peer_to_ipv4_cidr(peer: &str) -> Option<String> {
    let host = if peer.starts_with('[') {
        let end = peer.find(']')?;
        &peer[1..end]
    } else {
        peer.rsplit_once(':')?.0
    };
    if host.parse::<Ipv4Addr>().ok().is_some() {
        Some(format!("{host}/32"))
    } else {
        None
    }
}

fn parse_ip_addr_lines(text: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in text.lines() {
        // 2: enp5s0    inet 192.168.31.10/24 brd ...
        let Some(inet_idx) = line.split_whitespace().position(|t| t == "inet")
        else {
            continue;
        };
        let parts: Vec<_> = line.split_whitespace().collect();
        if let Some(addr) = parts.get(inet_idx + 1)
            && addr.contains('/')
            && addr
                .split('/')
                .next()
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .is_some()
        {
            cidrs.push(addr.to_string());
        }
    }
    cidrs
}

/// Wait until EasyTier mesh listener port(s) are open (hub / relay nodes).
pub fn wait_for_mesh_listeners(
    mesh: &crate::settings::MeshConfig,
    timeout: Duration,
) -> anyhow::Result<()> {
    use crate::stack::mesh;

    let ports = mesh::listener_ports(mesh);
    if ports.is_empty() {
        return Ok(());
    }

    let schemes: Vec<_> = ports
        .iter()
        .map(|(scheme, port)| format!("{scheme}://0.0.0.0:{port}"))
        .collect();
    eprintln!("easytier mesh listeners configured: {}", schemes.join(", "));

    let need_tcp = ports.iter().any(|(scheme, _)| *scheme == "tcp");
    let tcp_port = ports
        .iter()
        .find(|(scheme, _)| *scheme == "tcp")
        .map(|(_, port)| *port)
        .unwrap_or(11010);

    let deadline = Instant::now() + timeout;
    loop {
        let tcp_ok = !need_tcp || tcp_port_listening(tcp_port);
        if tcp_ok {
            eprintln!("easytier mesh: TCP :{tcp_port} is listening");
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "EasyTier mesh listener TCP :{tcp_port} not open after {}s.\n\
                 Check zay.toml [mesh].listeners, port conflicts (ss -tlnp | grep {tcp_port}), \
                 and cloud firewall for TCP+UDP {tcp_port}.\n\
                 Note: UDP :{tcp_port} does not always show in lsof; use: ss -ulnp | grep {tcp_port}",
                timeout.as_secs(),
                tcp_port = tcp_port,
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn tcp_port_listening(port: u16) -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("ss").args(["-tln"]).output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let needle = format!(":{port} ");
            return text.lines().any(|l| l.contains(&needle));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) =
            Command::new("netstat").args(["-an", "-p", "tcp"]).output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            return text.lines().any(|l| {
                l.contains("LISTEN")
                    && (l.contains(&format!(".{port} "))
                        || l.contains(&format!(":{port} ")))
            });
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = port;
    }
    false
}

/// Wait until EasyTier WireGuard portal UDP port is listening (Linux `ss`).
pub fn wait_for_wireguard_port(
    listen: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let (host, port) = parse_host_port(listen)?;
    if host != "127.0.0.1" && host != "::1" && host != "localhost" {
        std::thread::sleep(Duration::from_millis(500));
        return Ok(());
    }

    let deadline = Instant::now() + timeout;
    loop {
        if udp_port_listening(port) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "WireGuard portal {listen} not ready after {}s (EasyTier vpn_portal)",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn parse_host_port(raw: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = raw
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p))
        .ok_or_else(|| anyhow::anyhow!("invalid host:port {raw:?}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in {raw:?}"))?;
    Ok((host, port))
}

fn udp_port_listening(port: u16) -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("ss").args(["-lun"]).output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let needle = format!(":{port} ");
            return text.lines().any(|l| l.contains(&needle));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("netstat").args(["-an"]).output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let patterns = [format!(".{port} "), format!(":{port} ")];
            if text.lines().any(|l| {
                l.contains("udp")
                    && patterns.iter().any(|p| l.contains(p.as_str()))
            }) {
                return true;
            }
        }
        if let Ok(out) = Command::new("lsof")
            .args(["-nP", &format!("-iUDP:{port}")])
            .output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            return text.lines().skip(1).any(|l| !l.trim().is_empty());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = port;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_drops_fakeip_from_route_excludes() {
        use std::path::PathBuf;

        use crate::settings::{Settings, StackFlags};

        let mut excludes =
            vec!["192.168.0.0/16".into(), "198.18.0.15/32".into()];
        let settings = Settings {
            subscriptions: vec!["https://example.com/sub".into()],
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: None,
            stack: StackFlags {
                mesh: None,
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        filter_fakeip_route_excludes(&settings, &mut excludes);
        assert!(!excludes.iter().any(|c| c.starts_with("198.18.")));
        assert!(excludes.iter().any(|c| c.contains("192.168")));
    }

    #[test]
    fn parse_macos_ifconfig_skips_utun() {
        let text = "\
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>
\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>
\tinet 192.168.31.201 netmask 0xffffff00 broadcast 192.168.31.255
";
        let cidrs = parse_macos_ifconfig(text);
        assert_eq!(cidrs, vec!["192.168.31.201/24"]);
    }

    #[test]
    fn parse_macos_inet_netmask_line() {
        assert_eq!(
            parse_macos_inet_line(
                "inet 192.168.31.10 netmask 0xffffff00 broadcast 192.168.31.255"
            )
            .as_deref(),
            Some("192.168.31.10/24")
        );
    }

    #[test]
    fn parse_ip_addr_line() {
        let text = "2: enp5s0    inet 192.168.31.10/24 brd 192.168.31.255 scope global\n";
        let cidrs = parse_ip_addr_lines(text);
        assert_eq!(cidrs, vec!["192.168.31.10/24"]);
    }

    #[test]
    fn parse_ss_ssh_peers_inbound() {
        let text = "0 0 10.0.0.1:22 183.62.11.88:51234\n0 0 10.0.0.1:22 183.62.11.89:51235\n";
        let cidrs = parse_ss_ssh_peers(text);
        assert_eq!(
            cidrs,
            vec!["183.62.11.88/32".to_string(), "183.62.11.89/32".to_string()]
        );
    }

    #[test]
    fn mesh_hub_skips_singbox_tun() {
        use std::path::PathBuf;

        use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Relay,
                instance_name: Some("relay".into()),
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: None,
                listeners: Some(vec!["tcp://0.0.0.0:11010".into()]),
                peers: None,
                proxy_networks: None,
                mesh_routes: None,
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Relay),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        assert!(!singbox_tun_enabled(&settings));
        assert!(!is_selective_mesh_tun(&settings));
    }

    #[test]
    fn mesh_hub_route_address_defined_but_tun_disabled() {
        use std::path::PathBuf;

        use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Relay,
                instance_name: Some("relay".into()),
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: None,
                listeners: Some(vec!["tcp://0.0.0.0:11010".into()]),
                peers: None,
                proxy_networks: None,
                mesh_routes: None,
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Relay),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        assert!(tun_auto_route(&settings));
        assert!(!tun_selective_mesh_routes(&settings));
        assert_eq!(tun_route_address(&settings), None);
        assert!(!singbox_tun_enabled(&settings));
        assert!(!is_selective_mesh_tun(&settings));
    }

    #[test]
    fn mesh_disables_strict_route() {
        use std::path::PathBuf;

        use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Node,
                instance_name: None,
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: None,
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Node),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        assert!(!tun_strict_route(&settings));
        let ex = tun_exclude_addresses(&settings).unwrap();
        assert!(ex.iter().any(|c| c == "192.168.0.0/16"));
        assert!(ex.iter().any(|c| c == "10.126.126.0/24"));
        assert!(!singbox_tun_enabled(&settings));
        assert_eq!(tun_route_address(&settings), None);
    }

    #[test]
    fn mesh_exclude_derives_from_ipv4_when_routes_unset() {
        use std::path::PathBuf;

        use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

        let settings = Settings {
            subscriptions: vec!["https://example.com/sub".into()],
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Node,
                instance_name: None,
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: Some("10.55.1.9/16".into()),
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: None,
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Node),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        let ex = tun_exclude_addresses(&settings).unwrap();
        assert!(
            ex.iter().any(|c| c == "10.55.0.0/16"),
            "expected derived mesh exclude in {ex:?}"
        );
    }

    #[test]
    fn mesh_proxy_without_routes_fails_exclude() {
        use std::path::PathBuf;

        use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

        let settings = Settings {
            subscriptions: vec!["https://example.com/sub".into()],
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Node,
                instance_name: None,
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: None,
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: None,
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Node),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        assert!(singbox_tun_enabled(&settings));
        let err = tun_exclude_addresses(&settings).unwrap_err();
        assert!(
            err.to_string().contains("mesh_routes")
                || err.to_string().contains("ipv4"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn parse_ip_route_dev_extracts_interface() {
        let text =
            "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100\n";
        assert_eq!(super::parse_ip_route_dev(text).as_deref(), Some("eth0"));
    }

    #[test]
    fn derived_dns_is_next_host_after_tun_address() {
        assert_eq!(
            super::next_address_host("10.14.14.9/30").as_deref(),
            Some("10.14.14.10")
        );
        assert_eq!(
            super::next_address_host("172.18.0.1/30").as_deref(),
            Some("172.18.0.2")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_full_capture_uses_system_stack() {
        use std::path::PathBuf;

        use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

        let settings = Settings {
            subscriptions: vec!["https://example.com/sub".into()],
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://www.gstatic.com/generate_204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Node,
                instance_name: Some("zay".into()),
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: Some("10.126.126.2/24".into()),
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: None,
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
            }),
            stack: StackFlags {
                mesh: Some(MeshRole::Node),
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };
        assert_eq!(super::tun_stack(&settings), "system");
        assert_eq!(
            super::tun_derived_dns_servers(&settings)
                .first()
                .map(String::as_str),
            Some("10.14.14.10")
        );
    }
}
