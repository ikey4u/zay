use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::{mesh, rules, subscription, tun_route};
use crate::settings::Settings;

pub fn build_config(settings: &Settings, has_rules: bool) -> Result<String> {
    let doc = build_value(settings, has_rules)?;
    serde_json::to_string_pretty(&doc).context("serializing sing-box config")
}

pub fn build_value(settings: &Settings, has_rules: bool) -> Result<Value> {
    let mut outbounds: Vec<Value> =
        vec![json!({ "type": "direct", "tag": "direct" })];

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
            "type": "selector",
            "tag": "Proxy",
            "outbounds": member_tags.clone(),
            "default": member_tags.first()
        }));
        outbounds.push(json!({
            "type": "urltest",
            "tag": "Auto",
            "outbounds": member_tags.clone(),
            "url": settings.health_check_url,
            "interval": "300s",
            "tolerance": 100
        }));
        "Proxy".to_string()
    };

    let mut endpoints = Vec::new();
    if let Some(wg) = mesh::wireguard_endpoint(settings)? {
        endpoints.push(wg);
    }

    let tun_enabled = tun_route::singbox_tun_enabled(settings);

    let mut route_rules = Vec::new();
    // Relay/public peer IPs must bypass TUN path (SSH + EasyTier :11010) before mesh 10.x rules.
    route_rules.extend(mesh::peer_bypass_route_rules(settings));
    // Mesh CIDRs must win before sniff / clash private rules (10.x is ip_is_private).
    route_rules.extend(mesh::mesh_route_rules(settings));
    if tun_enabled {
        // L4 match avoids DNS sniff timing issues (macOS/Linux TUN loops).
        route_rules.push(json!({ "port": 53, "action": "hijack-dns" }));
    }
    route_rules.extend(sniff_route_rules(tun_enabled));
    route_rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));

    if has_rules {
        route_rules.extend(rules::proxy_fetch_rules(&proxy_final));
        route_rules.extend(rules::builtin_route_rules(&proxy_final));
    } else if !settings.subscriptions.is_empty() {
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
        let mesh_routes_mesh_only = settings.stack.mesh
            && settings
                .mesh
                .as_ref()
                .and_then(|m| m.mesh_routes.as_ref())
                .is_some_and(|routes| !routes.is_empty());
        if !mesh_routes_mesh_only {
            route_rules.push(json!({
                "action": "route",
                "ip_is_private": true,
                "outbound": "direct"
            }));
        }
        route_rules.push(json!({
            "action": "route",
            "outbound": proxy_final
        }));
    }

    let listen_addr = if settings.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };

    let mut inbounds = vec![json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": listen_addr,
        "listen_port": settings.mixed_port
    })];

    if tun_enabled {
        let auto_route = tun_route::tun_auto_route(settings);
        let mut tun = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": [tun_route::tun_address(settings)],
            "auto_route": auto_route,
            "strict_route": tun_route::tun_strict_route(settings),
            "stack": "mixed",
            "route_exclude_address": tun_route::tun_exclude_addresses(settings)
        });
        if let Some(addrs) = tun_route::tun_route_address(settings) {
            tun["route_address"] = json!(addrs);
        }
        inbounds.push(tun);
    }

    let mut route = json!({
        "rules": route_rules,
        "final": proxy_final,
        "auto_detect_interface": true,
        "default_domain_resolver": "local-dns"
    });

    if has_rules {
        route["rule_set"] = json!(rules::rule_set_definitions());
    }

    let mut root = json!({
        "log": {
            "level": settings.log_level,
            "timestamp": true
        },
        "dns": dns_config(tun_enabled),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
        "experimental": {
            "clash_api": {
                "external_controller": settings.external_controller,
                "secret": settings.api_secret,
                "default_mode": "rule"
            },
            "cache_file": {
                "enabled": true,
                // Relative to sing-box `-D` / working directory (see singbox::spawn).
                "path": "cache.db"
            }
        }
    });

    if !endpoints.is_empty() {
        root["endpoints"] = json!(endpoints);
    }

    Ok(root)
}

fn sniff_route_rules(tun_enabled: bool) -> Vec<Value> {
    let inbounds: Vec<&str> = if tun_enabled {
        vec!["mixed-in", "tun-in"]
    } else {
        vec!["mixed-in"]
    };
    vec![json!({
        "inbound": inbounds,
        "action": "sniff"
    })]
}

fn dns_config(_tun_enabled: bool) -> Value {
    // sing-box 1.12+: no legacy dns.rules outbound items; use route.default_domain_resolver instead.
    json!({
        "servers": [
            { "type": "local", "tag": "local-dns" }
        ],
        "final": "local-dns"
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::settings::{MeshConfig, Settings, StackFlags};

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
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "secret".into(),
            mihomo_mixin: None,
            singbox_mixin: None,
            bootstrap_proxy: None,
            mesh: Some(MeshConfig {
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
                wireguard_endpoint: None,
            }),
            stack: StackFlags {
                mesh: true,
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
    fn mesh_peer_hosts_are_tun_excluded() {
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
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "secret".into(),
            mihomo_mixin: None,
            singbox_mixin: None,
            bootstrap_proxy: None,
            mesh: Some(MeshConfig {
                instance_name: Some("zay".into()),
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: Some("10.126.126.1/24".into()),
                listeners: None,
                peers: Some(vec!["tcp://43.138.178.37:11010".into()]),
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
                wireguard_listen: Some("127.0.0.1:51820".into()),
                wireguard_client_cidr: None,
                wireguard_client_address: None,
                wireguard_endpoint: None,
            }),
            stack: StackFlags {
                mesh: true,
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };

        let json = build_config(&settings, false).unwrap();
        assert!(json.contains("43.138.178.37/32"));
        assert!(json.contains("192.168.0.0/16"));
        assert!(!json.contains("\"strict_route\": true"));
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let rules = doc["route"]["rules"].as_array().unwrap();
        let peer_rule = rules
            .iter()
            .position(|rule| {
                rule.get("ip_cidr").and_then(|v| v.as_array()).is_some_and(
                    |cidrs| {
                        cidrs
                            .iter()
                            .any(|c| c.as_str() == Some("43.138.178.37/32"))
                    },
                )
            })
            .unwrap();
        let mesh_rule = rules
            .iter()
            .position(|rule| crate::singbox::mesh::is_mesh_route_rule(rule))
            .unwrap();
        assert!(peer_rule < mesh_rule);
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
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "secret".into(),
            mihomo_mixin: None,
            singbox_mixin: None,
            bootstrap_proxy: None,
            mesh: Some(MeshConfig {
                instance_name: Some("relay".into()),
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: Some("10.126.126.1/24".into()),
                listeners: Some(vec![
                    "tcp://0.0.0.0:11010".into(),
                    "udp://0.0.0.0:11010".into(),
                ]),
                peers: None,
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
                wireguard_listen: Some("127.0.0.1:51820".into()),
                wireguard_client_cidr: None,
                wireguard_client_address: None,
                wireguard_endpoint: None,
            }),
            stack: StackFlags {
                mesh: true,
                gateway: false,
                tun: true,
                no_rules: true,
            },
        };

        let json = build_config(&settings, false).unwrap();
        assert!(!json.contains("\"type\": \"tun\""));
        assert!(json.contains("\"easytier-wg\""));
        assert!(json.contains("10.126.126.0/24"));
        assert!(!json.contains("\"port\": 53"));
        assert!(!json.contains("\"outbound\": \"any\""));
        assert!(json.contains("\"default_domain_resolver\": \"local-dns\""));
    }

    #[test]
    fn wireguard_endpoint_rejected() {
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
            external_controller: "127.0.0.1:19090".into(),
            api_secret: "secret".into(),
            mihomo_mixin: None,
            singbox_mixin: None,
            bootstrap_proxy: None,
            mesh: Some(MeshConfig {
                instance_name: Some("zay".into()),
                network_name: "my-network".into(),
                network_secret: "change-me".into(),
                dhcp: None,
                ipv4: Some("10.126.126.10/24".into()),
                listeners: None,
                peers: None,
                proxy_networks: None,
                mesh_routes: Some(vec!["10.126.126.0/24".into()]),
                wireguard_listen: None,
                wireguard_client_cidr: None,
                wireguard_client_address: None,
                wireguard_endpoint: Some("nas.example.com:51820".into()),
            }),
            stack: StackFlags {
                mesh: true,
                gateway: false,
                tun: true,
                no_rules: false,
            },
        };

        let err = build_config(&settings, false).unwrap_err();
        assert!(err.to_string().contains("wireguard_endpoint"));
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
