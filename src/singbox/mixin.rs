use anyhow::{Context, Result};
use serde_json::Value;

use crate::settings::Settings;

/// Merge `[singbox].mixin` JSON fragment into the generated config.
pub fn merge_config(base_json: &str, settings: &Settings) -> Result<String> {
    let Some(raw) = settings.proxy_mixin.as_deref() else {
        return Ok(base_json.to_string());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return Ok(base_json.to_string());
    }

    let mut base: Value = serde_json::from_str(base_json)
        .context("parsing base sing-box config")?;
    let overlay: Value = serde_json::from_str(trimmed)
        .context("parsing [singbox].mixin JSON")?;
    merge_json(&mut base, overlay);
    prioritize_mesh_route_rules(&mut base, settings);
    serde_json::to_string_pretty(&base)
        .context("serializing merged sing-box config")
}

/// Keep EasyTier process bypass + peer bypass + mesh rules ahead of mixin / clash rules.
fn prioritize_mesh_route_rules(base: &mut Value, settings: &Settings) {
    let process_rules =
        crate::singbox::mesh::easytier_process_bypass_route_rules(settings);
    let peer_rules = crate::singbox::mesh::peer_bypass_route_rules(settings);
    let mesh_rules = crate::singbox::mesh::mesh_route_rules(settings);
    if process_rules.is_empty()
        && peer_rules.is_empty()
        && mesh_rules.is_empty()
    {
        return;
    }
    let Some(rules) = base
        .pointer_mut("/route/rules")
        .and_then(|value| value.as_array_mut())
    else {
        return;
    };
    rules.retain(|rule| {
        !crate::singbox::mesh::is_easytier_process_bypass_route_rule(rule)
            && !crate::singbox::mesh::is_mesh_route_rule(rule)
            && !crate::singbox::mesh::is_peer_bypass_route_rule(rule, settings)
    });
    let mut merged = process_rules;
    merged.extend(peer_rules);
    merged.extend(mesh_rules);
    merged.extend(rules.drain(..));
    if let Some(route) = base.get_mut("route")
        && let Some(rules_value) = route.get_mut("rules")
    {
        *rules_value = Value::Array(merged);
    }
}

fn merge_json(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                if k == "route" {
                    merge_route(b.entry(k).or_insert(Value::Null), v);
                } else if k == "outbounds"
                    || k == "inbounds"
                    || k == "endpoints"
                {
                    merge_array_append(b.entry(k).or_insert(Value::Null), v);
                } else {
                    merge_json(b.entry(k).or_insert(Value::Null), v);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn merge_route(base: &mut Value, overlay: Value) {
    let Value::Object(o) = overlay else {
        *base = overlay;
        return;
    };
    let Value::Object(b) = base else {
        *base = Value::Object(o);
        return;
    };
    for (k, v) in o {
        if k == "rules" {
            merge_rules_prepend(b.entry(k).or_insert(Value::Null), v);
        } else {
            merge_json(b.entry(k).or_insert(Value::Null), v);
        }
    }
}

fn merge_rules_prepend(base: &mut Value, overlay: Value) {
    match overlay {
        Value::Array(custom) => {
            let existing = base.as_array().cloned().unwrap_or_default();
            let mut merged = custom;
            merged.extend(existing);
            *base = Value::Array(merged);
        }
        other => *base = other,
    }
}

fn merge_array_append(base: &mut Value, overlay: Value) {
    match overlay {
        Value::Array(extra) => {
            let mut merged = base.as_array().cloned().unwrap_or_default();
            merged.extend(extra);
            *base = Value::Array(merged);
        }
        other => *base = other,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::settings::{MeshConfig, MeshRole, Settings, StackFlags};

    fn mesh_settings() -> Settings {
        Settings {
            subscriptions: Vec::new(),
            data_dir: PathBuf::from("/tmp"),
            mixed_port: 7890,
            allow_lan: false,
            tun: true,
            log_level: "info".into(),
            health_check_url: "https://example.com".into(),
            update_interval: 3600,
            tun_exclude_routes: Vec::new(),
            proxy_mixin: Some(
                r#"{"route":{"rules":[{"ip_is_private":true,"outbound":"direct"}]}}"#.into(),
            ),
            bootstrap_proxy: None,
            domain_rule: Vec::new(),
            mesh: Some(MeshConfig {
                enabled: true,
                role: MeshRole::Node,
                instance_name: None,
                network_name: "n".into(),
                network_secret: "s".into(),
                dhcp: None,
                ipv4: Some("10.126.126.1/24".into()),
                listeners: Some(vec!["tcp://0.0.0.0:11010".into()]),
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
                no_rules: true,
            },
        }
    }

    #[test]
    fn mixin_keeps_mesh_exclude_and_private_direct() {
        let settings = mesh_settings();
        let base =
            crate::singbox::builder::build_config(&settings, false).unwrap();
        let merged = merge_config(&base, &settings).unwrap();
        let doc: Value = serde_json::from_str(&merged).unwrap();
        // Mesh-only (no subscription): sing-box TUN is off — EasyTier owns mesh.
        assert!(
            doc["inbounds"]
                .as_array()
                .map(|a| !a
                    .iter()
                    .any(|i| i.get("type").and_then(|t| t.as_str())
                        == Some("tun")))
                .unwrap_or(true)
        );
        assert!(!merged.contains("easytier-wg"));
        let rules = doc["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|rule| {
            rule.get("outbound").and_then(|v| v.as_str()) == Some("direct")
                && rule.get("ip_is_private").and_then(|v| v.as_bool())
                    == Some(true)
        }));
    }
}
