use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde_yaml::Value;

use crate::settings::Settings;

fn yaml_quote(value: &str) -> String {
    serde_yaml::to_string(value)
        .unwrap_or_else(|_| format!("\"{value}\""))
        .trim()
        .to_string()
}

pub fn build_config(
    settings: &Settings,
    has_mmdb: bool,
    has_geosite: bool,
) -> String {
    let subscription_url = yaml_quote(&settings.subscription);
    let sub_cache_rel = "providers/subscription.yaml";
    let mixed_port = settings.mixed_port;
    let log_level = &settings.log_level;
    let allow_lan = settings.allow_lan;
    let hc_url = &settings.health_check_url;

    let tun_block = if settings.tun {
        r#"
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
"#
        .to_string()
    } else {
        String::new()
    };

    let mmdb_line = if has_mmdb {
        "mmdb: \"Country.mmdb\"\n"
    } else {
        ""
    };
    let geosite_line = if has_geosite {
        "geosite: \"geosite.dat\"\n"
    } else {
        ""
    };

    let geoip_rules = if has_mmdb {
        "  - GEOIP,PRIVATE,DIRECT\n  - GEOIP,CN,DIRECT\n"
    } else {
        ""
    };

    let dns_block = if settings.tun {
        r#"
dns:
  enable: true
  listen: 0.0.0.0:53533
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "*.internal"
  default-nameserver:
    - 114.114.114.114
    - 223.5.5.5
  nameserver:
    - 114.114.114.114
    - 223.5.5.5
"#
        .to_string()
    } else {
        "\ndns:\n  enable: false\n".to_string()
    };

    format!(
        r#"mixed-port: {mixed_port}
allow-lan: {allow_lan}
ipv6: false
mode: rule
log-level: {log_level}
{mmdb_line}{geosite_line}{tun_block}{dns_block}
proxy-providers:
  subscription:
    type: http
    url: {subscription_url}
    interval: {update_interval}
    path: "./{sub_cache_rel}"
    health-check:
      enable: true
      url: "{hc_url}"
      interval: 300

proxy-groups:
  - name: "Auto"
    type: url-test
    lazy: true
    tolerance: 100
    proxies:
      - DIRECT
    use:
      - subscription
    url: "{hc_url}"
    interval: 300

  - name: "Proxy"
    type: select
    proxies:
      - Auto
      - DIRECT
    use:
      - subscription

rules:
{geoip_rules}  - MATCH,Proxy
"#,
        update_interval = settings.update_interval
    )
}

fn merge_yaml(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Mapping(b), Value::Mapping(o)) => {
            for (k, v) in o {
                merge_yaml(b.entry(k).or_insert(Value::Null), v);
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn apply_mixin(config_yaml: &str, mixin_path: &Path) -> Result<String> {
    let mixin_raw = fs::read_to_string(mixin_path)
        .with_context(|| format!("reading mixin {}", mixin_path.display()))?;

    let mut base: Value = serde_yaml::from_str(config_yaml)
        .context("parsing generated config as YAML")?;
    let overlay: Value = serde_yaml::from_str(&mixin_raw)
        .with_context(|| format!("parsing mixin {}", mixin_path.display()))?;

    merge_yaml(&mut base, overlay);

    serde_yaml::to_string(&base).context("serializing merged config")
}

fn proxy_names(proxies: &Value) -> Vec<String> {
    proxies
        .as_sequence()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            p.get("name").and_then(|n| n.as_str()).map(str::to_string)
        })
        .collect()
}

fn load_cached_proxies(cache_path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(cache_path).ok()?;
    let doc: Value = serde_yaml::from_str(&raw).ok()?;
    doc.get("proxies").cloned()
}

fn expand_proxy_groups(groups: &mut Value, proxy_names: &[String]) {
    let Some(seq) = groups.as_sequence_mut() else {
        return;
    };
    for group in seq {
        let Some(map) = group.as_mapping_mut() else {
            continue;
        };
        let uses_subscription = map
            .get(Value::from("use"))
            .and_then(|u| u.as_sequence())
            .is_some_and(|uses| {
                uses.iter().any(|v| v.as_str() == Some("subscription"))
            });
        if !uses_subscription {
            continue;
        }
        map.remove(Value::from("use"));

        let mut names: Vec<Value> = map
            .get(Value::from("proxies"))
            .and_then(|p| p.as_sequence())
            .map(|seq| seq.to_vec())
            .unwrap_or_default();

        for name in proxy_names {
            let v = Value::from(name.as_str());
            if !names.iter().any(|n| n == &v) {
                names.push(v);
            }
        }
        map.insert(Value::from("proxies"), Value::Sequence(names));
    }
}

/// Inline cached subscription proxies into a full config (no proxy-providers).
pub fn expand_runtime_config(
    config_yaml: &str,
    data_dir: &Path,
) -> Result<String> {
    let cache_path = data_dir.join("providers/subscription.yaml");
    let Some(proxies) = load_cached_proxies(&cache_path) else {
        return Ok(config_yaml.to_string());
    };

    let mut config: Value =
        serde_yaml::from_str(config_yaml).context("parsing config as YAML")?;
    let Some(mapping) = config.as_mapping_mut() else {
        return Ok(config_yaml.to_string());
    };

    let names = proxy_names(&proxies);
    mapping.insert(Value::from("proxies"), proxies);
    mapping.remove(Value::from("proxy-providers"));

    if let Some(groups) = mapping.get_mut(Value::from("proxy-groups")) {
        expand_proxy_groups(groups, &names);
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

pub fn finalize_config(
    settings: &Settings,
    mut config_yaml: String,
) -> Result<String> {
    let mixin_path = settings.mixin_path();
    if mixin_path.is_file() {
        let mixin_raw = fs::read_to_string(&mixin_path).with_context(|| {
            format!("reading mixin {}", mixin_path.display())
        })?;
        if !mixin_raw
            .lines()
            .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
        {
            eprintln!("merging mixin from {}", mixin_path.display());
            config_yaml = apply_mixin(&config_yaml, &mixin_path)?;
        }
    }
    Ok(config_yaml)
}
