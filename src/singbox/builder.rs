use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::{mesh, rules, subscription, tun_route};
use crate::settings::Settings;

pub fn build_config(settings: &Settings, has_rules: bool) -> Result<String> {
    let doc = build_value(settings, has_rules)?;
    serde_json::to_string_pretty(&doc).context("serializing sing-box config")
}

pub fn build_value(settings: &Settings, has_rules: bool) -> Result<Value> {
    let tun_enabled = tun_route::singbox_tun_enabled(settings);
    let clash_dns = clash_dns_enabled(settings, tun_enabled, has_rules);

    let mut outbounds: Vec<Value> =
        vec![tun_route::direct_outbound_json(settings, tun_enabled)];

    if let Some(bp) = &settings.bootstrap_proxy {
        if let Some(node) = super::clash::convert_proxy(&bp.proxy, None)? {
            outbounds.push(node);
        }
    }

    let mut member_tags: Vec<String> = Vec::new();
    if !settings.subscriptions.is_empty() {
        let nodes = subscription::fetch_and_convert(
            settings,
            settings.bootstrap_proxy.as_ref(),
        )
        .or_else(|_| subscription::load_cached_nodes(settings))?;
        for node in &nodes {
            if let Some(tag) = node.get("tag").and_then(|t| t.as_str()) {
                member_tags.push(tag.to_string());
            }
        }
        outbounds.extend(nodes);
    }

    let proxy_final = if member_tags.is_empty() {
        "direct".to_string()
    } else {
        outbounds.push(json!({
            "type": "urltest",
            "tag": "Auto",
            "outbounds": member_tags.clone(),
            "url": settings.health_check_url,
            "interval": "300s",
            "tolerance": 100
        }));
        let mut proxy_members = vec!["Auto".to_string()];
        proxy_members.extend(member_tags.clone());
        outbounds.push(json!({
            "type": "selector",
            "tag": "Proxy",
            "outbounds": proxy_members,
            "default": "Auto"
        }));
        "Proxy".to_string()
    };
    let (domain_outbounds, domain_routes) =
        build_domain_rule_groups(settings, &member_tags)?;
    outbounds.extend(domain_outbounds);

    let mut endpoints = Vec::new();
    if let Some(wg) = mesh::wireguard_endpoint(settings)? {
        endpoints.push(wg);
    }

    let include_applications =
        has_rules && rules::applications_present(&settings.singbox_dir());
    let find_process = include_applications
        || tun_route::tun_full_capture_mesh_proxy(&settings);

    let mut route_rules = Vec::new();
    // EasyTier (in-process) + relay/STUN bypass before mesh/proxy rules.
    route_rules.extend(mesh::easytier_process_bypass_route_rules(settings));
    // Relay/public peer IPs must bypass TUN path (SSH + EasyTier :11010) before mesh 10.x rules.
    route_rules.extend(mesh::peer_bypass_route_rules(settings));
    // Mesh CIDRs must win before sniff / clash private rules (10.x is ip_is_private).
    route_rules.extend(mesh::mesh_route_rules(settings));
    // Mihomo `dns-hijack: any:53` — L4 port match before sniff (sing-box 1.13+; see SagerNet/sing-box#3878).
    if tun_enabled {
        route_rules.push(json!({ "port": 53, "action": "hijack-dns" }));
    }
    route_rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    // Sniff after hijack-dns (TLS SNI / HTTP Host for connections that already have a destination).
    route_rules.extend(sniff_route_rules(settings, tun_enabled));
    route_rules.extend(domain_routes);

    if has_rules {
        route_rules.extend(rules::proxy_fetch_rules(&proxy_final));
        route_rules.extend(rules::builtin_route_rules(
            &proxy_final,
            include_applications,
        ));
    } else if !settings.subscriptions.is_empty() {
        // Interim routes while clash-rules download (before fake-ip + rule-sets apply).
        route_rules.push(json!({
            "action": "route",
            "ip_is_private": true,
            "outbound": "direct"
        }));
        route_rules.push(json!({
            "action": "route",
            "outbound": proxy_final
        }));
    } else if tun_enabled {
        // Mesh CIDR rules above already win for 10.x; keep RFC1918 on direct before final fallback.
        route_rules.push(json!({
            "action": "route",
            "ip_is_private": true,
            "outbound": "direct"
        }));
        route_rules.push(json!({
            "action": "route",
            "outbound": proxy_final
        }));
    }

    let mut inbounds = mixed_inbounds(settings);

    if tun_enabled {
        let auto_route = tun_route::tun_auto_route(settings);
        let mut tun = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": tun_route::tun_addresses(settings),
            "auto_route": auto_route,
            "strict_route": tun_route::tun_strict_route(settings),
            "stack": tun_route::tun_stack(settings),
            "route_exclude_address": tun_route::tun_exclude_addresses(settings)
        });
        if let Some(addrs) = tun_route::tun_route_address(settings) {
            tun["route_address"] = json!(addrs);
        }
        if tun_route::tun_auto_redirect(settings) {
            tun["auto_redirect"] = json!(true);
        }
        inbounds.push(tun);
    }

    // Loyalsoldier blacklist: final → direct once rule-sets are loaded.
    let route_final = if has_rules {
        "direct".to_string()
    } else {
        proxy_final.clone()
    };

    let dns_resolver_tag = if clash_dns { "dns-direct" } else { "local-dns" };

    let mut route = json!({
        "rules": route_rules,
        "final": route_final,
        "auto_detect_interface": true,
        "default_domain_resolver": dns_resolver_tag
    });

    if find_process {
        route["find_process"] = json!(true);
    }
    if has_rules {
        let rule_sets = rules::rule_set_definitions(settings);
        if rule_sets.is_empty() {
            eprintln!(
                "warn: clash-rules files missing under {}; routing without rule-sets",
                settings.singbox_dir().display()
            );
        } else {
            route["rule_set"] = json!(rule_sets);
        }
    }

    let mut cache_file = json!({
        "enabled": true,
        "path": "cache.db"
    });
    if clash_dns {
        cache_file["store_fakeip"] = json!(true);
        tun_route::log_fakeip_dns_hint(settings, true);
    }

    let mut root = json!({
        "log": {
            "level": settings.log_level,
            "timestamp": true
        },
        "dns": dns_config(settings, tun_enabled, has_rules, clash_dns),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
        "experimental": {
            "cache_file": cache_file
        }
    });

    if !endpoints.is_empty() {
        root["endpoints"] = json!(endpoints);
    }

    Ok(root)
}

fn build_domain_rule_groups(
    settings: &Settings,
    member_tags: &[String],
) -> Result<(Vec<Value>, Vec<Value>)> {
    let available: HashSet<&str> =
        member_tags.iter().map(String::as_str).collect();
    let mut names = HashSet::new();
    let mut outbounds = Vec::new();
    let mut routes = Vec::new();

    for policy in &settings.domain_rule {
        let name = policy.name.trim();
        if name.is_empty() {
            bail!("proxy.domain_rule.name must not be empty");
        }
        if !names.insert(name) {
            bail!("duplicate proxy.domain_rule name {name:?}");
        }
        if policy.by_suffix.is_empty() {
            bail!(
                "proxy.domain_rule {name:?} requires at least one domain_suffix"
            );
        }
        if policy.outbounds.is_empty() {
            bail!("proxy.domain_rule {name:?} requires at least one outbound");
        }
        let missing: Vec<&str> = policy
            .outbounds
            .iter()
            .map(String::as_str)
            .filter(|tag| !available.contains(tag))
            .collect();
        if !missing.is_empty() {
            bail!(
                "proxy.domain_rule {name:?} references unavailable subscription node(s): {}; run `zay service proxy list` to inspect current tags",
                missing.join(", ")
            );
        }

        let tag = format!("domain-proxy:{name}");
        outbounds.push(json!({
            "type": "urltest",
            "tag": tag,
            "outbounds": policy.outbounds,
            "url": policy.health_check_url.as_deref().unwrap_or(&settings.health_check_url),
            "interval": format!("{}s", policy.interval.unwrap_or(300)),
            "tolerance": policy.tolerance.unwrap_or(100)
        }));
        routes.push(json!({
            "action": "route",
            "domain_suffix": policy.by_suffix,
            "outbound": format!("domain-proxy:{name}")
        }));
    }

    Ok((outbounds, routes))
}

fn mixed_inbounds(settings: &Settings) -> Vec<Value> {
    let port = settings.mixed_port;
    if settings.allow_lan {
        return vec![json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "0.0.0.0",
            "listen_port": port
        })];
    }
    let mut inbounds = vec![json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "127.0.0.1",
        "listen_port": port
    })];
    // Firefox/GNOME often use "localhost" → ::1; listen there too (TUN apps should use No Proxy).
    inbounds.push(json!({
        "type": "mixed",
        "tag": "mixed-in-v6",
        "listen": "::1",
        "listen_port": port
    }));
    inbounds
}

fn sniff_inbound_tags(settings: &Settings, tun_enabled: bool) -> Vec<String> {
    let mut tags = if settings.allow_lan {
        vec!["mixed-in".to_string()]
    } else {
        vec!["mixed-in".to_string(), "mixed-in-v6".to_string()]
    };
    if tun_enabled {
        tags.push("tun-in".into());
    }
    tags
}

fn sniff_route_rules(settings: &Settings, tun_enabled: bool) -> Vec<Value> {
    if !tun_enabled {
        return Vec::new();
    }
    vec![json!({
        "action": "sniff",
        "sniffer": ["http", "tls", "quic"],
        "timeout": "2s"
    })]
}

fn clash_dns_enabled(
    settings: &Settings,
    tun_enabled: bool,
    has_rules: bool,
) -> bool {
    tun_enabled && (has_rules || !settings.subscriptions.is_empty())
}

fn dns_config(
    settings: &Settings,
    _tun_enabled: bool,
    has_rules: bool,
    clash_dns: bool,
) -> Value {
    if !clash_dns {
        return json!({
            "servers": [
                { "type": "local", "tag": "local-dns" }
            ],
            "final": "local-dns",
            "strategy": "prefer_ipv4"
        });
    }

    let dns_rules = rules::clash_dns_rules(has_rules);

    let _ = settings;
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
        "rules": dns_rules,
        "final": "dns-direct",
        "strategy": "prefer_ipv4",
        "reverse_mapping": true
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::settings::{
        DomainRuleFile, MeshConfig, MeshRole, Settings, StackFlags,
    };

    #[test]
    fn domain_rule_generates_restricted_urltest_and_route() {
        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "https://health.example/204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: vec![DomainRuleFile {
                name: "cursor".into(),
                by_suffix: vec!["cursor.com".into(), "cursor.sh".into()],
                outbounds: vec!["sg-1".into(), "sg-2".into()],
                health_check_url: None,
                interval: Some(60),
                tolerance: Some(50),
            }],
            mesh: None,
            stack: StackFlags::default(),
        };

        let (outbounds, routes) = build_domain_rule_groups(
            &settings,
            &["sg-1".into(), "sg-2".into()],
        )
        .unwrap();
        assert_eq!(outbounds[0]["tag"], "domain-proxy:cursor");
        assert_eq!(outbounds[0]["outbounds"], json!(["sg-1", "sg-2"]));
        assert_eq!(outbounds[0]["interval"], "60s");
        assert_eq!(routes[0]["outbound"], "domain-proxy:cursor");
        assert_eq!(
            routes[0]["domain_suffix"],
            json!(["cursor.com", "cursor.sh"])
        );
    }

    #[test]
    fn domain_rule_rejects_unavailable_node() {
        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
            allow_lan: false,
            tun: false,
            log_level: "info".into(),
            health_check_url: "https://health.example/204".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: None,
            bootstrap_proxy: None,
            domain_rule: vec![DomainRuleFile {
                name: "cursor".into(),
                by_suffix: vec!["cursor.com".into()],
                outbounds: vec!["missing".into()],
                health_check_url: None,
                interval: None,
                tolerance: None,
            }],
            mesh: None,
            stack: StackFlags::default(),
        };

        let error =
            build_domain_rule_groups(&settings, &["sg-1".into()]).unwrap_err();
        assert!(error.to_string().contains("unavailable subscription node"));
    }

    #[test]
    fn mesh_enables_wireguard_endpoint_and_tun() {
        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
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
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: Some("10.126.126.10/24".into()),
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
                wireguard_listen: Some("127.0.0.1:51820".into()),
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

        let json = build_config(&settings, false).unwrap();
        assert!(json.contains("\"easytier-wg\""));
        assert!(json.contains("\"type\": \"wireguard\""));
        assert!(json.contains("10.126.126.0/24"));
        assert!(json.contains("\"type\": \"tun\""));
        assert!(json.contains("\"auto_route\": true"));
        assert!(json.contains("\"route_address\""));
        assert!(json.contains("10.126.126.0/24"));
        assert!(json.contains("10.14.14.37/32"));
        assert!(json.contains("10.14.14.37/30"));
        assert!(json.contains(&tun_route::tun_address(&settings)));
        assert!(json.contains("\"port\": 53"));
        assert!(json.contains("\"action\": \"route\""));
        assert!(json.contains("\"network\": \"icmp\""));
        assert!(json.contains("\"tcp\""));
        assert!(json.contains("\"system\": false"));
        assert!(json.contains("127.0.0.1"));
    }

    #[test]
    fn mesh_hub_skips_singbox_tun() {
        let settings = Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
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
                role: MeshRole::Relay,
                instance_name: Some("relay".into()),
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: None,
                listeners: Some(vec![
                    "tcp://0.0.0.0:11010".into(),
                    "udp://0.0.0.0:11010".into(),
                ]),
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
                no_rules: true,
            },
        };

        let json = build_config(&settings, false).unwrap();
        assert!(!json.contains("\"type\": \"tun\""));
        assert!(!json.contains("\"easytier-wg\""));
        assert!(!json.contains("10.126.126.0/24"));
        assert!(!json.contains("\"port\": 53"));
        assert!(!json.contains("\"outbound\": \"any\""));
        assert!(json.contains("\"default_domain_resolver\": \"local-dns\""));
    }

    #[test]
    fn clash_rules_use_direct_final_blacklist() {
        let settings = Settings {
            subscriptions: vec!["https://example.com/sub".into()],
            data_dir: PathBuf::from("/tmp/zay-singbox-test"),
            mixed_port: 17890,
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
        let with_rules = build_config(&settings, true).unwrap();
        assert!(with_rules.contains("\"final\": \"direct\""));
        assert!(with_rules.contains("\"gfw\""));
        assert!(with_rules.contains("\"geoip-cn\""));
        assert!(with_rules.contains("\"geosite-cn\""));
        assert!(with_rules.contains("\"reverse_mapping\": true"));
        assert!(with_rules.contains("\"fake-ip\""));
        assert!(with_rules.contains("\"store_fakeip\": true"));
        assert!(with_rules.contains("\"type\": \"logical\""));

        let rules = serde_json::from_str::<Value>(&with_rules).unwrap();
        let route_rules = rules["route"]["rules"].as_array().unwrap();
        let reject_idx = route_rules
            .iter()
            .position(|r| {
                r.get("action").and_then(|a| a.as_str()) == Some("reject")
            })
            .unwrap();
        let icloud_idx = route_rules
            .iter()
            .position(|r| {
                r.get("rule_set")
                    .and_then(|s| s.as_array())
                    .is_some_and(|a| {
                        a.first().and_then(|v| v.as_str()) == Some("icloud")
                    })
            })
            .unwrap();
        assert!(
            reject_idx < icloud_idx,
            "reject must precede icloud (Mihomo order)"
        );
        let gfw_idx =
            route_rules
                .iter()
                .position(|r| {
                    r.get("rule_set").and_then(|s| s.as_array()).is_some_and(
                        |a| a.iter().any(|v| v.as_str() == Some("gfw")),
                    )
                })
                .unwrap();
        let cncidr_idx = route_rules
            .iter()
            .position(|r| {
                r.get("rule_set")
                    .and_then(|s| s.as_array())
                    .is_some_and(|a| {
                        a.first().and_then(|v| v.as_str()) == Some("cncidr")
                    })
            })
            .unwrap();
        assert!(
            gfw_idx < cncidr_idx,
            "gfw must precede cncidr (blocked domains → Proxy before CN IP → direct)"
        );
        let dns_rules = rules["dns"]["rules"].as_array().unwrap();
        let gfw_dns = dns_rules.iter().any(|r| {
            r.get("rule_set")
                .and_then(|s| s.as_array())
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("gfw")))
                && r.get("server").and_then(|v| v.as_str())
                    == Some("dns-direct")
        });
        assert!(gfw_dns, "gfw DNS queries must use dns-direct, not fake-ip");

        let without_rules = build_config(&settings, false).unwrap();
        assert!(without_rules.contains("\"reverse_mapping\": true"));
    }
}

pub fn config_has_tun(config_json: &str) -> bool {
    serde_json::from_str::<Value>(config_json)
        .ok()
        .and_then(|v| v.get("inbounds").cloned())
        .map(|inbounds| {
            inbounds.as_array().is_some_and(|arr| {
                arr.iter().any(|ib| {
                    ib.get("type").and_then(|t| t.as_str()) == Some("tun")
                })
            })
        })
        .unwrap_or(false)
}
