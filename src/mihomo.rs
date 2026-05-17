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

    let controller_line = match &settings.controller {
        Some(addr) => format!("external-controller: \"{addr}\"\n"),
        None => String::new(),
    };
    let secret_line = match &settings.secret {
        Some(s) => format!("secret: \"{s}\"\n"),
        None => String::new(),
    };
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
{controller_line}{secret_line}{mmdb_line}{geosite_line}{tun_block}{dns_block}
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
            eprintln!("zay: applying mixin from {}", mixin_path.display());
            config_yaml = apply_mixin(&config_yaml, &mixin_path)?;
        }
    }
    Ok(config_yaml)
}
