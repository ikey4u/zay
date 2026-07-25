//! Optional bootstrap proxy: a single Mihomo `proxies` entry used to fetch stack proxy subscriptions.
//!
//! Maps to `proxy-providers.subscription.proxy` in the generated config (Mihomo dials this node directly).

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_yaml::Value;
use toml::Value as TomlValue;

use crate::settings::BootstrapProxy;

const DEFAULT_BOOTSTRAP_NAME: &str = "Bootstrap";

/// Load a proxy from a YAML file (`proxies: [one]` or a single proxy mapping with `name`).
pub fn load_from_yaml_file(path: &Path) -> Result<BootstrapProxy> {
    let raw = fs_read(path)?;
    let doc: Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;

    if let Some(seq) = doc.get("proxies").and_then(|p| p.as_sequence()) {
        let first = seq
            .first()
            .context("bootstrap proxy file: proxies list is empty")?;
        return proxy_value_to_bootstrap(first.clone());
    }

    proxy_value_to_bootstrap(doc)
}

fn fs_read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))
}

fn proxy_value_to_bootstrap(proxy: Value) -> Result<BootstrapProxy> {
    let Some(map) = proxy.as_mapping() else {
        bail!("bootstrap proxy must be a YAML mapping");
    };
    let name = map
        .get(Value::from("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_BOOTSTRAP_NAME)
        .to_string();
    Ok(BootstrapProxy { name, proxy })
}

/// Load from an inline `[proxy.bootstrap]` table in `zay.toml`.
pub fn load_from_toml_table(
    table: &toml::map::Map<String, TomlValue>,
) -> Result<BootstrapProxy> {
    let proxy = toml_table_to_yaml_value(table)?;
    proxy_value_to_bootstrap(proxy)
}

fn toml_table_to_yaml_value(
    table: &toml::map::Map<String, TomlValue>,
) -> Result<Value> {
    let mut map = serde_yaml::Mapping::new();
    for (k, v) in table {
        map.insert(Value::from(k.as_str()), toml_value_to_yaml(v)?);
    }
    Ok(Value::Mapping(map))
}

/// Build an HTTP proxy URL for fetching subscriptions through a sing-box outbound.
pub fn singbox_outbound_to_proxy_url(proxy: &Value) -> Result<String> {
    let map = proxy
        .as_mapping()
        .context("bootstrap proxy must be a mapping")?;
    let ty = yaml_string(map, "type")?.to_lowercase();
    let server = yaml_string(map, "server")?;
    let port = yaml_u16(map, "port")?;
    Ok(match ty.as_str() {
        "socks5" | "socks" => format!("socks5://{server}:{port}"),
        "http" | "https" => format!("http://{server}:{port}"),
        _ => anyhow::bail!(
            "bootstrap proxy type {ty} is not supported for HTTP fetch"
        ),
    })
}

fn yaml_string(map: &serde_yaml::Mapping, key: &str) -> Result<String> {
    map.get(Value::from(key))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .with_context(|| format!("missing `{key}` in bootstrap proxy"))
}

fn yaml_u16(map: &serde_yaml::Mapping, key: &str) -> Result<u16> {
    let v = map
        .get(Value::from(key))
        .context(format!("missing `{key}`"))?;
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).context(format!("`{key}` out of range"));
    }
    if let Some(s) = v.as_str() {
        return s.parse().context(format!("invalid `{key}`"));
    }
    anyhow::bail!("invalid `{key}`")
}

fn toml_value_to_yaml(v: &TomlValue) -> Result<Value> {
    Ok(match v {
        TomlValue::String(s) => Value::String(s.clone()),
        TomlValue::Integer(i) => Value::Number((*i).into()),
        TomlValue::Float(f) => Value::Number(serde_yaml::Number::from(*f)),
        TomlValue::Boolean(b) => Value::Bool(*b),
        TomlValue::Datetime(dt) => Value::String(dt.to_string()),
        TomlValue::Array(arr) => Value::Sequence(
            arr.iter().map(toml_value_to_yaml).collect::<Result<_>>()?,
        ),
        TomlValue::Table(t) => toml_table_to_yaml_value(t)?,
    })
}
