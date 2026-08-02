//! Build sing-box JSON for iOS Packet Tunnel.
//!
//! sing-box owns the real utun FD (Libbox). Mesh CIDRs are routed to the
//! local EasyTier SOCKS5 portal (`127.0.0.1:socks_port`).
//!
//! Routing matches desktop Loyalsoldier **blacklist** when embedded rules are
//! present under `working_dir/ruleset-embedded/` (`final` → `direct`).

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;
use std::path::Path;

use crate::proxy_url::{OutboundSpec, resolve_proxy};
use crate::rules::{self, CustomRuleSet, RulesStage};

#[derive(Debug, Clone, Deserialize)]
pub struct SingboxInput {
    /// Clash subscription URL or direct proxy URI.
    pub proxy_url: String,
    /// Mesh IPv4 CIDR(s) routed to EasyTier SOCKS.
    pub mesh_cidrs: Vec<String>,
    /// Relay / peer public IPs that must bypass the TUN (direct).
    pub bypass_ips: Vec<String>,
    /// EasyTier local SOCKS portal port.
    pub socks_port: Option<u16>,
    pub log_level: Option<String>,
    /// Libbox working directory (contains `ruleset-embedded/`). Required for rules.
    pub working_dir: Option<String>,
    /// Preferred `Proxy` selector member: `Auto` or a node tag. Empty → Auto / sole node.
    #[serde(default)]
    pub selected_proxy_tag: Option<String>,
    /// Enabled custom rule-sets already written under `ruleset-custom/`.
    #[serde(default)]
    pub custom_rules: Vec<CustomRuleSet>,
    /// Progressive rules stage: `0`/`core`, `1`/`direct`, `2`/`full`.
    #[serde(default)]
    pub rules_profile: Option<String>,
    /// Prefer subscription cache over network (progressive reloads).
    #[serde(default)]
    pub prefer_cache: Option<bool>,
}

pub fn build_singbox_json(input: &SingboxInput) -> Result<String> {
    let log_level = input
        .log_level
        .as_deref()
        .unwrap_or("debug")
        .to_string();
    let socks_port = input.socks_port.unwrap_or(18080);

    let working_dir = input
        .working_dir
        .as_deref()
        .map(Path::new)
        .filter(|p| !p.as_os_str().is_empty());
    let stage = RulesStage::parse(input.rules_profile.as_deref());
    let has_rules = working_dir.is_some_and(rules::files_present);
    if let Some(dir) = working_dir {
        if has_rules {
            tracing::info!(
                "clash-rules: using embedded sets under {}/{} (stage={})",
                dir.display(),
                rules::EMBEDDED_RULESET_DIR,
                stage.0
            );
        } else {
            tracing::warn!(
                "clash-rules missing under {}/{} — fallback final=Proxy",
                dir.display(),
                rules::EMBEDDED_RULESET_DIR
            );
        }
    }

    let prefer_cache = input.prefer_cache.unwrap_or(false);
    let resolved = resolve_proxy(&input.proxy_url, working_dir, prefer_cache)
        .with_context(|| format!("resolving proxy_url {}", input.proxy_url))?;

    let mut outbounds = vec![
        json!({ "type": "direct", "tag": "direct" }),
        json!({
            "type": "socks",
            "tag": "mesh-socks",
            "server": "127.0.0.1",
            "server_port": socks_port,
            "version": "5"
        }),
    ];

    let selected = input
        .selected_proxy_tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let proxy_final = match resolved {
        OutboundSpec::Single(ob) => {
            let tag = ob
                .get("tag")
                .and_then(|t| t.as_str())
                .unwrap_or("proxy-node")
                .to_string();
            outbounds.push(ob);
            let default = selected
                .as_ref()
                .filter(|s| *s == "direct" || *s == &tag)
                .cloned()
                .unwrap_or_else(|| tag.clone());
            outbounds.push(json!({
                "type": "selector",
                "tag": "Proxy",
                "outbounds": [tag, "direct"],
                "default": default
            }));
            "Proxy".to_string()
        }
        OutboundSpec::Many(nodes) => {
            if nodes.is_empty() {
                bail!("subscription produced no proxy nodes");
            }
            let mut tags = Vec::new();
            for n in nodes {
                if let Some(tag) = n.get("tag").and_then(|t| t.as_str()) {
                    tags.push(tag.to_string());
                }
                outbounds.push(n);
            }
            outbounds.push(json!({
                "type": "urltest",
                "tag": "Auto",
                "outbounds": tags.clone(),
                "url": "https://www.gstatic.com/generate_204",
                "interval": "300s",
                "tolerance": 100
            }));
            let mut members = vec!["Auto".to_string()];
            members.extend(tags.clone());
            let default = selected
                .as_ref()
                .filter(|s| members.iter().any(|m| m == *s) || *s == "direct")
                .cloned()
                .unwrap_or_else(|| "Auto".to_string());
            if default == "direct" && !members.iter().any(|m| m == "direct") {
                members.push("direct".into());
            }
            outbounds.push(json!({
                "type": "selector",
                "tag": "Proxy",
                "outbounds": members,
                "default": default
            }));
            "Proxy".to_string()
        }
    };

    let mut route_rules = Vec::new();
    // L4 DNS hijack before sniff (same order as desktop).
    route_rules.push(json!({ "port": 53, "action": "hijack-dns" }));
    route_rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    route_rules.push(json!({
        "action": "sniff",
        "sniffer": ["http", "tls", "quic"],
        "timeout": "2s"
    }));

    // Mesh CIDRs → EasyTier SOCKS (MUST be before ip_is_private / clash private).
    let mesh: Vec<String> = input
        .mesh_cidrs
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !mesh.is_empty() {
        route_rules.push(json!({
            "ip_cidr": mesh,
            "outbound": "mesh-socks"
        }));
    }

    // Bypass relay / peer public IPs so EasyTier control plane is not hairpinned.
    for ip in &input.bypass_ips {
        let ip = ip.trim();
        if ip.is_empty() {
            continue;
        }
        let cidr = if ip.contains('/') {
            ip.to_string()
        } else {
            format!("{ip}/32")
        };
        route_rules.push(json!({
            "ip_cidr": [cidr],
            "outbound": "direct"
        }));
    }

    let custom = &input.custom_rules;
    let has_custom = working_dir.is_some_and(|dir| {
        !rules::custom_rule_set_definitions(dir, custom).is_empty()
    });

    if has_rules || has_custom {
        if has_custom {
            route_rules.extend(rules::custom_route_rules(custom, &proxy_final));
        }
        if has_rules {
            route_rules.extend(rules::proxy_fetch_rules(&proxy_final));
            route_rules.extend(rules::builtin_route_rules(&proxy_final, stage));
        } else {
            route_rules.push(json!({
                "ip_is_private": true,
                "outbound": "direct"
            }));
        }
    } else {
        route_rules.push(json!({
            "ip_is_private": true,
            "outbound": "direct"
        }));
        // VLESS Vision is TCP-oriented; reject QUIC when no rule-sets.
        route_rules.push(json!({
            "protocol": "quic",
            "action": "reject"
        }));
    }

    let mut exclude = vec![
        "127.0.0.0/8".to_string(),
        "169.254.0.0/16".to_string(),
        "224.0.0.0/4".to_string(),
        "255.255.255.255/32".to_string(),
        "223.5.5.5/32".to_string(),
        "8.8.8.8/32".to_string(),
        "114.114.114.114/32".to_string(),
    ];
    for ip in &input.bypass_ips {
        let ip = ip.trim();
        if ip.is_empty() {
            continue;
        }
        if ip.contains('/') {
            exclude.push(ip.to_string());
        } else {
            exclude.push(format!("{ip}/32"));
        }
    }

    // Blacklist: final → direct once rule-sets loaded (same as desktop).
    let route_final = if has_rules {
        "direct".to_string()
    } else {
        proxy_final.clone()
    };

    let mut route = json!({
        "auto_detect_interface": true,
        "default_network_strategy": "hybrid",
        "default_domain_resolver": "dns-direct",
        "rules": route_rules,
        "final": route_final
    });

    if let Some(dir) = working_dir {
        let mut rule_sets = Vec::new();
        if has_rules {
            rule_sets.extend(rules::rule_set_definitions(dir, stage));
        }
        rule_sets.extend(rules::custom_rule_set_definitions(dir, custom));
        if !rule_sets.is_empty() {
            route["rule_set"] = json!(rule_sets);
        }
    }

    let dns = if has_rules {
        json!({
            "servers": [
                { "type": "udp", "tag": "dns-direct", "server": "223.5.5.5" },
                { "type": "udp", "tag": "dns-direct-alt", "server": "114.114.114.114" },
                {
                    "type": "fakeip",
                    "tag": "fake-ip",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                }
            ],
            "rules": rules::clash_dns_rules(stage),
            "final": "dns-direct",
            "strategy": "ipv4_only",
            "reverse_mapping": true
        })
    } else {
        json!({
            "servers": [
                { "type": "udp", "tag": "dns-direct", "server": "223.5.5.5" },
                { "type": "udp", "tag": "dns-direct-alt", "server": "8.8.8.8" },
                {
                    "type": "fakeip",
                    "tag": "fake-ip",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                }
            ],
            "rules": [
                {
                    "domain_suffix": [".lan", ".local", ".internal"],
                    "action": "route",
                    "server": "dns-direct"
                },
                {
                    "query_type": ["A", "AAAA"],
                    "action": "route",
                    "server": "fake-ip"
                }
            ],
            "final": "dns-direct",
            "strategy": "ipv4_only",
            "reverse_mapping": true
        })
    };

    let doc = json!({
        "log": {
            "level": log_level,
            "timestamp": true
        },
        "dns": dns,
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "mtu": 4064,
                "auto_route": true,
                "strict_route": false,
                "stack": "system",
                "route_exclude_address": exclude
            }
        ],
        "outbounds": outbounds,
        "route": route,
        "experimental": {
            "cache_file": {
                "enabled": true,
                "path": "cache.db",
                "store_fakeip": true
            }
        }
    });

    serde_json::to_string_pretty(&doc).context("serialize sing-box json")
}
