pub mod config;
pub mod geo;
pub mod reload;
pub mod rules;

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result};
use config::Config;
use serde_yaml::Value;

use crate::{settings::Settings, yaml::key};

pub fn build_config(
    settings: &Settings,
    has_mmdb: bool,
    has_geosite: bool,
    has_builtin_rules: bool,
) -> Result<String> {
    let doc =
        build_config_value(settings, has_mmdb, has_geosite, has_builtin_rules);
    serde_yaml::to_string(&doc).context("serializing Mihomo config")
}

fn build_config_value(
    settings: &Settings,
    has_mmdb: bool,
    has_geosite: bool,
    has_builtin_rules: bool,
) -> Config {
    config::zay::build(settings, has_mmdb, has_geosite, has_builtin_rules)
}

fn merge_yaml(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Mapping(b), Value::Mapping(o)) => {
            for (k, v) in o {
                if k.as_str() == Some("rules") {
                    merge_rules_prepend(b.entry(k).or_insert(Value::Null), v);
                } else if k.as_str() == Some("proxy-groups") {
                    merge_proxy_groups(b.entry(k).or_insert(Value::Null), v);
                } else {
                    merge_yaml(b.entry(k).or_insert(Value::Null), v);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

/// Mixin `rules` are inserted before generated rules (first match wins).
fn merge_rules_prepend(base: &mut Value, overlay: Value) {
    match overlay {
        Value::Sequence(custom) => {
            let existing = base.as_sequence().cloned().unwrap_or_default();
            let mut merged = custom;
            merged.extend(existing);
            *base = Value::Sequence(merged);
        }
        other => *base = other,
    }
}

fn proxy_group_name(group: &Value) -> Option<String> {
    group
        .get("name")
        .and_then(|n| n.as_str())
        .map(str::to_string)
}

/// Merge mixin `proxy-groups` by `name`; unknown names are appended. `proxies` / `use` lists are unioned.
fn merge_proxy_groups(base: &mut Value, overlay: Value) {
    let Value::Sequence(overlay_seq) = overlay else {
        *base = overlay;
        return;
    };

    let base_seq = match base.as_sequence() {
        Some(s) => s.clone(),
        None => {
            *base = Value::Sequence(overlay_seq);
            return;
        }
    };

    let mut order: Vec<String> = Vec::new();
    let mut unnamed_base: Vec<Value> = Vec::new();
    let mut groups: HashMap<String, Value> = HashMap::new();

    for g in base_seq {
        if let Some(name) = proxy_group_name(&g) {
            if !groups.contains_key(&name) {
                order.push(name.clone());
            }
            groups.insert(name, g);
        } else {
            unnamed_base.push(g);
        }
    }

    let mut unnamed_overlay: Vec<Value> = Vec::new();
    for g in overlay_seq {
        if let Some(name) = proxy_group_name(&g) {
            if let Some(existing) = groups.get_mut(&name) {
                merge_proxy_group(existing, g);
            } else {
                order.push(name.clone());
                groups.insert(name, g);
            }
        } else {
            unnamed_overlay.push(g);
        }
    }

    let mut merged: Vec<Value> = order
        .into_iter()
        .filter_map(|name| groups.remove(&name))
        .collect();
    merged.extend(unnamed_base);
    merged.extend(unnamed_overlay);
    *base = Value::Sequence(merged);
}

fn merge_proxy_group(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Mapping(b), Value::Mapping(o)) => {
            for (k, v) in o {
                if matches!(k.as_str(), Some("proxies") | Some("use")) {
                    merge_sequences_unique(
                        b.entry(k).or_insert(Value::Null),
                        v,
                    );
                } else {
                    merge_yaml(b.entry(k).or_insert(Value::Null), v);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn merge_sequences_unique(base: &mut Value, overlay: Value) {
    match overlay {
        Value::Sequence(overlay_seq) => {
            let mut base_seq = base.as_sequence().cloned().unwrap_or_default();
            for item in overlay_seq {
                if !base_seq.iter().any(|b| b == &item) {
                    base_seq.push(item);
                }
            }
            *base = Value::Sequence(base_seq);
        }
        other => *base = other,
    }
}

fn mixin_is_comments_only(raw: &str) -> bool {
    raw.lines()
        .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
}

fn apply_mixin_overlay(config: &mut Value, overlay: Value) {
    merge_yaml(config, overlay);
}

fn proxy_names(proxies: &Value) -> Vec<String> {
    proxies
        .as_sequence()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            p.get("name")
                .and_then(|n| n.as_str())
                .map(ToString::to_string)
        })
        .collect()
}

fn load_cached_proxies(cache_path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(cache_path).ok()?;
    let doc: Value = serde_yaml::from_str(&raw).ok()?;
    doc.get("proxies").cloned()
}

fn provider_names_from_config(config: &Value) -> HashSet<String> {
    config
        .get("proxy-providers")
        .and_then(|p| p.as_mapping())
        .map(|m| {
            m.keys()
                .filter_map(|k| k.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn expand_proxy_groups(
    groups: &mut Value,
    proxy_names: &[String],
    provider_names: &HashSet<String>,
) {
    let Some(seq) = groups.as_sequence_mut() else {
        return;
    };
    for group in seq {
        let Some(map) = group.as_mapping_mut() else {
            continue;
        };
        let uses_providers = map
            .get(key("use"))
            .and_then(|u| u.as_sequence())
            .is_some_and(|uses| {
                uses.iter().any(|v| {
                    v.as_str().is_some_and(|name| provider_names.contains(name))
                })
            });
        if !uses_providers {
            continue;
        }
        map.remove(key("use"));

        let mut names: Vec<Value> = map
            .get(key("proxies"))
            .and_then(|p| p.as_sequence())
            .map(|s| s.to_vec())
            .unwrap_or_default();

        for name in proxy_names {
            let v = Value::from(name.as_str());
            if !names.iter().any(|n| n == &v) {
                names.push(v);
            }
        }
        map.insert(key("proxies"), Value::Sequence(names));
    }
}

fn merge_cached_subscription_proxies(settings: &Settings) -> Option<Value> {
    let mut merged = Vec::new();

    for i in 0..settings.subscriptions.len() {
        let path = settings.subscription_cache_path(i);
        let Some(seq) =
            load_cached_proxies(&path).and_then(|p| p.as_sequence().cloned())
        else {
            continue;
        };
        let prefix = Settings::subscription_name_prefix(i);
        for mut proxy in seq {
            let original = proxy
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let display_name = if original.starts_with(&prefix) {
                original
            } else {
                format!("{prefix}{original}")
            };
            if let Some(m) = proxy.as_mapping_mut() {
                m.insert(key("name"), Value::from(display_name.as_str()));
            }
            merged.push(proxy);
        }
    }

    if settings.subscriptions.len() == 1 && merged.is_empty() {
        let legacy = settings.mihomo_dir().join("providers/subscription.yaml");
        if let Some(seq) =
            load_cached_proxies(&legacy).and_then(|p| p.as_sequence().cloned())
        {
            merged.extend(seq);
        }
    }

    if merged.is_empty() {
        None
    } else {
        Some(Value::Sequence(merged))
    }
}

/// Inline cached subscription proxies into a full config (no proxy-providers).
pub fn expand_runtime_config(
    config_yaml: &str,
    settings: &Settings,
) -> Result<String> {
    let Some(proxies) = merge_cached_subscription_proxies(settings) else {
        return Ok(config_yaml.to_string());
    };

    let mut config: Value =
        serde_yaml::from_str(config_yaml).context("parsing config as YAML")?;
    let provider_names = provider_names_from_config(&config);
    let Some(mapping) = config.as_mapping_mut() else {
        return Ok(config_yaml.to_string());
    };

    let names = proxy_names(&proxies);
    mapping.insert(key("proxies"), proxies);
    mapping.remove(key("proxy-providers"));

    if let Some(groups) = mapping.get_mut(key("proxy-groups")) {
        expand_proxy_groups(groups, &names, &provider_names);
    }

    serde_yaml::to_string(&config).context("serializing expanded config")
}

pub fn config_has_tun(config_yaml: &str) -> bool {
    let doc: Value = match serde_yaml::from_str(config_yaml) {
        Ok(v) => v,
        Err(_) => return false,
    };
    doc.get("tun")
        .and_then(|t| t.get("enable"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub fn remove_geoip_rules_without_mmdb(config_yaml: &str) -> Result<String> {
    let mut config: Value =
        serde_yaml::from_str(config_yaml).context("parsing config as YAML")?;
    let Some(rules) = config.get_mut("rules").and_then(Value::as_sequence_mut)
    else {
        return Ok(config_yaml.to_string());
    };

    let mut normalized = Vec::with_capacity(rules.len());
    let mut changed = false;
    for rule in std::mem::take(rules) {
        let Some(raw) = rule.as_str() else {
            normalized.push(rule);
            continue;
        };
        if !raw.starts_with("GEOIP,") {
            normalized.push(rule);
            continue;
        }

        changed = true;
        let parts: Vec<&str> = raw.split(',').collect();
        if parts.get(1) == Some(&"PRIVATE") {
            let outbound = parts.get(2).copied().unwrap_or("DIRECT");
            for cidr in [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
            ] {
                normalized.push(Value::from(format!(
                    "IP-CIDR,{cidr},{outbound},no-resolve"
                )));
            }
            normalized.push(Value::from(format!(
                "IP-CIDR6,fc00::/7,{outbound},no-resolve"
            )));
        } else {
            eprintln!("removed GEOIP rule because MMDB is missing: {raw}");
        }
    }

    *rules = normalized;
    if changed {
        eprintln!("rewrote GEOIP rules because MMDB is missing");
    }
    serde_yaml::to_string(&config)
        .context("serializing config without GEOIP rules")
}

pub fn finalize_config(
    settings: &Settings,
    base_config: String,
) -> Result<String> {
    let mut config: Value = serde_yaml::from_str(&base_config)
        .context("parsing generated config as YAML")?;

    let mixin_path = settings.mixin_path();
    if mixin_path.is_file() {
        let mixin_raw = fs::read_to_string(&mixin_path).with_context(|| {
            format!("reading mixin {}", mixin_path.display())
        })?;
        if !mixin_is_comments_only(&mixin_raw) {
            eprintln!("merging mixin from {}", mixin_path.display());
            let overlay: Value = serde_yaml::from_str(&mixin_raw)
                .with_context(|| {
                    format!("parsing mixin {}", mixin_path.display())
                })?;
            apply_mixin_overlay(&mut config, overlay);
        }
    }

    serde_yaml::to_string(&config).context("serializing final config")
}

/// Write refreshed config to disk, reload Mihomo, and return the YAML text.
pub fn publish_config(
    settings: &Settings,
    base_config: String,
    should_reload: bool,
) -> Result<String> {
    let config_yaml = finalize_config(settings, base_config)?;
    let config_path = settings.config_path();
    fs::write(&config_path, &config_yaml).with_context(|| {
        format!("writing config to {}", config_path.display())
    })?;
    if should_reload {
        if let Err(e) = reload::reload_running_config(settings) {
            eprintln!("mihomo reload: {e:#}");
        }
    }
    Ok(config_yaml)
}

#[cfg(test)]
mod tests {
    use serde_yaml::Value as YamlValue;

    use super::*;

    #[test]
    fn merge_proxy_groups_unions_proxies_by_name() {
        let mut base: YamlValue = serde_yaml::from_str(
            r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies: [Auto]
    use: [sub0]
"#,
        )
        .unwrap();
        let overlay: YamlValue = serde_yaml::from_str(
            r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies: [DIRECT]
"#,
        )
        .unwrap();
        merge_proxy_groups(
            base.get_mut("proxy-groups").unwrap(),
            overlay.get("proxy-groups").unwrap().clone(),
        );
        let groups = base.get("proxy-groups").unwrap().as_sequence().unwrap();
        assert_eq!(groups.len(), 1);
        let proxies = groups[0].get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(proxies.len(), 2);
    }

    #[test]
    fn merge_rules_prepends_mixin() {
        let mut base: YamlValue =
            serde_yaml::from_str("rules:\n  - MATCH,Proxy\n").unwrap();
        let overlay: YamlValue =
            serde_yaml::from_str("rules:\n  - DOMAIN,example.com,DIRECT\n")
                .unwrap();
        merge_rules_prepend(
            base.get_mut("rules").unwrap(),
            overlay.get("rules").unwrap().clone(),
        );
        let rules = base.get("rules").unwrap().as_sequence().unwrap();
        assert_eq!(rules[0].as_str().unwrap(), "DOMAIN,example.com,DIRECT");
    }
}
