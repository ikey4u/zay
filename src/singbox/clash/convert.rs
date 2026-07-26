use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use serde_yaml::Value as YamlValue;

use super::parse::{ClashDoc, parse_clash_yaml};
use crate::settings::Settings;

pub fn convert_subscription(
    raw: &str,
    _settings: &Settings,
    sub_index: usize,
) -> Result<Vec<Value>> {
    let doc = parse_clash_yaml(raw)?;
    let prefix = Settings::subscription_name_prefix(sub_index);
    let mut outbounds = Vec::new();

    for proxy in &doc.proxies {
        if let Some(out) = convert_proxy(proxy, Some(&prefix))? {
            outbounds.push(out);
        }
    }

    if outbounds.is_empty() {
        bail!("subscription {sub_index} contains no supported proxies");
    }

    Ok(outbounds)
}

pub fn convert_proxy(
    proxy: &YamlValue,
    name_prefix: Option<&str>,
) -> Result<Option<Value>> {
    let map = proxy
        .as_mapping()
        .context("proxy entry must be a mapping")?;
    let proxy_type = yaml_str(map, "type")?.to_lowercase();
    let name = yaml_str(map, "name")?;
    let tag = match name_prefix {
        Some(p) => format!("{p}{name}"),
        None => name.to_string(),
    };

    let outbound = match proxy_type.as_str() {
        "ss" | "shadowsocks" => shadowsocks_outbound(map, &tag)?,
        "vmess" => vmess_outbound(map, &tag)?,
        "vless" => vless_outbound(map, &tag)?,
        "trojan" => trojan_outbound(map, &tag)?,
        "hysteria" => hysteria_outbound(map, &tag, false)?,
        "hysteria2" => hysteria_outbound(map, &tag, true)?,
        "tuic" => tuic_outbound(map, &tag)?,
        "anytls" => anytls_outbound(map, &tag)?,
        "socks5" | "socks" => socks_outbound(map, &tag, false)?,
        "http" | "https" => socks_outbound(map, &tag, true)?,
        "wireguard" => wireguard_outbound(map, &tag)?,
        "direct" => json!({ "type": "direct", "tag": tag }),
        "reject" => json!({ "type": "block", "tag": tag }),
        other => {
            eprintln!("skipping unsupported clash proxy type: {other} ({tag})");
            return Ok(None);
        }
    };

    Ok(Some(outbound))
}

pub fn build_selector_groups(
    doc: &ClashDoc,
    member_tags: &[String],
    settings: &Settings,
) -> Vec<Value> {
    let mut groups = Vec::new();
    let mut seen = IndexMap::new();

    for group in &doc.proxy_groups {
        let Some(map) = group.as_mapping() else {
            continue;
        };
        let Ok(name) = yaml_str(map, "name") else {
            continue;
        };
        let group_type =
            yaml_str(map, "type").unwrap_or("select").to_lowercase();
        let tag = name.to_string();
        if seen.contains_key(&tag) {
            continue;
        }

        let mut members: Vec<String> = Vec::new();
        if let Some(seq) = map
            .get(YamlValue::from("proxies"))
            .and_then(|v| v.as_sequence())
        {
            for item in seq {
                if let Some(s) = item.as_str() {
                    if s == "DIRECT" {
                        members.push("direct".into());
                    } else if member_tags
                        .iter()
                        .any(|t| t == s || t.ends_with(s))
                    {
                        members.push(s.to_string());
                    } else if member_tags.contains(&s.to_string()) {
                        members.push(s.to_string());
                    } else {
                        let prefixed = format!("sub0-{s}");
                        if member_tags.iter().any(|t| t == &prefixed) {
                            members.push(prefixed);
                        }
                    }
                }
            }
        }

        if members.is_empty() {
            members = member_tags.to_vec();
        }

        let outbound = match group_type.as_str() {
            "url-test" | "urltest" => json!({
                "type": "urltest",
                "tag": tag,
                "outbounds": members,
                "url": map.get(YamlValue::from("url")).and_then(|v| v.as_str()).unwrap_or(&settings.health_check_url),
                "interval": yaml_u64(map, "interval").unwrap_or(300).to_string() + "s",
                "tolerance": yaml_u64(map, "tolerance").unwrap_or(100)
            }),
            _ => json!({
                "type": "selector",
                "tag": tag,
                "outbounds": members,
                "default": members.first()
            }),
        };
        seen.insert(tag.clone(), ());
        groups.push(outbound);
    }

    if !seen.contains_key("Proxy") && !seen.contains_key("proxy") {
        groups.push(json!({
            "type": "selector",
            "tag": "Proxy",
            "outbounds": member_tags,
            "default": member_tags.first()
        }));
    }

    if !seen.contains_key("Auto") {
        groups.push(json!({
            "type": "urltest",
            "tag": "Auto",
            "outbounds": member_tags,
            "url": settings.health_check_url,
            "interval": "300s",
            "tolerance": 100
        }));
    }

    groups
}

fn shadowsocks_outbound(map: &serde_yaml::Mapping, tag: &str) -> Result<Value> {
    Ok(json!({
        "type": "shadowsocks",
        "tag": tag,
        "server": yaml_str(map, "server")?,
        "server_port": yaml_u16(map, "port")?,
        "method": yaml_str(map, "cipher")?,
        "password": yaml_str(map, "password")?,
        "udp_over_tcp": yaml_bool(map, "udp-over-tcp").unwrap_or(false)
    }))
}

fn vmess_outbound(map: &serde_yaml::Mapping, tag: &str) -> Result<Value> {
    let port = yaml_u16(map, "port")?;
    let mut out = json!({
        "type": "vmess",
        "tag": tag,
        "server": yaml_str(map, "server")?,
        "server_port": port,
        "uuid": yaml_str(map, "uuid")?,
        "security": yaml_str(map, "cipher").unwrap_or("auto"),
        "alter_id": yaml_u64(map, "alterId").unwrap_or(0)
    });
    apply_transport_and_tls(map, &mut out, "vmess", port)?;
    Ok(out)
}

fn vless_outbound(map: &serde_yaml::Mapping, tag: &str) -> Result<Value> {
    let port = yaml_u16(map, "port")?;
    let mut out = json!({
        "type": "vless",
        "tag": tag,
        "server": yaml_str(map, "server")?,
        "server_port": port,
        "uuid": yaml_str(map, "uuid")?,
        "flow": yaml_optional_str(map, "flow")
    });
    apply_transport_and_tls(map, &mut out, "vless", port)?;
    Ok(out)
}

fn trojan_outbound(map: &serde_yaml::Mapping, tag: &str) -> Result<Value> {
    let port = yaml_u16(map, "port")?;
    let mut out = json!({
        "type": "trojan",
        "tag": tag,
        "server": yaml_str(map, "server")?,
        "server_port": port,
        "password": yaml_str(map, "password")?
    });
    apply_transport_and_tls(map, &mut out, "trojan", port)?;
    Ok(out)
}

fn hysteria_outbound(
    map: &serde_yaml::Mapping,
    tag: &str,
    hysteria2: bool,
) -> Result<Value> {
    let ty = if hysteria2 { "hysteria2" } else { "hysteria" };
    let mut out = json!({
        "type": ty,
        "tag": tag,
        "server": yaml_str(map, "server")?,
        "server_port": yaml_u16(map, "port")?,
        "password": yaml_optional_str(map, "password").or_else(|| yaml_optional_str(map, "auth")),
        "up_mbps": yaml_u64(map, "up"),
        "down_mbps": yaml_u64(map, "down")
    });
    if let Some(obj) = out.as_object_mut() {
        if yaml_bool(map, "tls").unwrap_or(true) {
            obj.insert("tls".into(), build_outbound_tls(map, true)?);
        }
    }
    Ok(out)
}

fn tuic_outbound(map: &serde_yaml::Mapping, tag: &str) -> Result<Value> {
    Ok(json!({
        "type": "tuic",
        "tag": tag,
        "server": yaml_str(map, "server")?,
        "server_port": yaml_u16(map, "port")?,
        "uuid": yaml_str(map, "uuid")?,
        "password": yaml_str(map, "password")?,
        "congestion_control": yaml_optional_str(map, "congestion-controller").unwrap_or_else(|| "cubic".into()),
        "tls": build_outbound_tls(map, true)?
    }))
}

fn anytls_outbound(map: &serde_yaml::Mapping, tag: &str) -> Result<Value> {
    let mut out = json!({
        "type": "anytls",
        "tag": tag,
        "server": yaml_str(map, "server")?,
        "server_port": yaml_u16(map, "port")?,
        "password": yaml_str(map, "password")?
    });
    if let Some(obj) = out.as_object_mut() {
        if let Some(n) = yaml_u64(map, "idle-session-check-interval") {
            obj.insert(
                "idle_session_check_interval".into(),
                json!(format!("{n}s")),
            );
        }
        if let Some(n) = yaml_u64(map, "idle-session-timeout") {
            obj.insert("idle_session_timeout".into(), json!(format!("{n}s")));
        }
        if let Some(n) = yaml_u64(map, "min-idle-session") {
            obj.insert("min_idle_session".into(), json!(n));
        }
        obj.insert("tls".into(), build_outbound_tls(map, true)?);
    }
    Ok(out)
}

fn socks_outbound(
    map: &serde_yaml::Mapping,
    tag: &str,
    http: bool,
) -> Result<Value> {
    let ty = if http { "http" } else { "socks" };
    let mut obj = serde_json::Map::new();
    obj.insert("type".into(), json!(ty));
    obj.insert("tag".into(), json!(tag));
    obj.insert("server".into(), json!(yaml_str(map, "server")?));
    obj.insert("server_port".into(), json!(yaml_u16(map, "port")?));
    if let Some(u) = yaml_optional_str(map, "username") {
        obj.insert("username".into(), json!(u));
    }
    if let Some(p) = yaml_optional_str(map, "password") {
        obj.insert("password".into(), json!(p));
    }
    if !http {
        obj.insert("version".into(), json!("5"));
    }
    Ok(Value::Object(obj))
}

fn wireguard_outbound(map: &serde_yaml::Mapping, tag: &str) -> Result<Value> {
    let mut peers = Vec::new();
    let peer = json!({
        "address": yaml_str(map, "server")?,
        "port": yaml_u16(map, "port")?,
        "public_key": yaml_str(map, "public-key").or_else(|_| yaml_str(map, "public_key"))?,
        "pre_shared_key": yaml_optional_str(map, "pre-shared-key").or_else(|| yaml_optional_str(map, "pre_shared_key")),
        "allowed_ips": yaml_string_array(map, "allowed-ips").or_else(|_| yaml_string_array(map, "allowed_ips")).unwrap_or_else(|_| vec!["0.0.0.0/0".into()])
    });
    peers.push(peer);

    Ok(json!({
        "type": "wireguard",
        "tag": tag,
        "private_key": yaml_str(map, "private-key").or_else(|_| yaml_str(map, "private_key"))?,
        "address": yaml_string_array(map, "ip").or_else(|_| yaml_string_array(map, "address")).unwrap_or_else(|_| vec!["10.0.0.2/32".into()]),
        "peers": peers
    }))
}

fn apply_transport_and_tls(
    map: &serde_yaml::Mapping,
    out: &mut Value,
    proxy_type: &str,
    port: u16,
) -> Result<()> {
    apply_transport(map, out)?;
    if outbound_tls_enabled(map, proxy_type, port) {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("tls".into(), build_outbound_tls(map, false)?);
        }
    }
    Ok(())
}

fn apply_transport(map: &serde_yaml::Mapping, out: &mut Value) -> Result<()> {
    let network = yaml_optional_str(map, "network")
        .unwrap_or_else(|| "tcp".into())
        .to_lowercase();
    if network == "tcp" {
        return Ok(());
    }
    let Some(obj) = out.as_object_mut() else {
        return Ok(());
    };
    let transport = match network.as_str() {
        "ws" | "websocket" => {
            let mut headers = yaml_nested_map(map, "ws-opts", "headers")
                .or_else(|| yaml_optional_map(map, "ws-headers"));
            if headers.is_none() {
                if let Some(host) = yaml_optional_str(map, "host") {
                    let mut h = Map::new();
                    h.insert("Host".to_string(), json!(host));
                    headers = Some(h);
                }
            }
            json!({
                "type": "ws",
                "path": yaml_nested_str(map, "ws-opts", "path")
                    .or_else(|| yaml_optional_str(map, "ws-path"))
                    .or_else(|| yaml_optional_str(map, "path")),
                "headers": headers
            })
        }
        "grpc" => json!({
            "type": "grpc",
            "service_name": yaml_nested_str(map, "grpc-opts", "grpc-service-name")
                .or_else(|| yaml_optional_str(map, "grpc-service-name"))
        }),
        "h2" | "http" => json!({
            "type": "http",
            "path": yaml_optional_str(map, "path"),
            "host": yaml_string_array(map, "host").ok()
        }),
        other => {
            json!({ "type": other })
        }
    };
    obj.insert("transport".into(), transport);
    Ok(())
}

fn outbound_tls_enabled(
    map: &serde_yaml::Mapping,
    proxy_type: &str,
    port: u16,
) -> bool {
    if yaml_bool(map, "tls").unwrap_or(false) {
        return true;
    }
    if reality_opts(map).is_some() {
        return true;
    }
    if yaml_optional_str(map, "flow").is_some() {
        return true;
    }
    if yaml_optional_str(map, "sni").is_some()
        || yaml_optional_str(map, "servername").is_some()
    {
        return true;
    }
    matches!(proxy_type, "trojan" | "anytls")
        || (proxy_type == "vless" && port == 443)
}

/// Clash/Mihomo SNI: `sni`, `servername`, then `host`, then `server`.
fn tls_server_name(map: &serde_yaml::Mapping) -> Option<String> {
    yaml_optional_str(map, "sni")
        .or_else(|| yaml_optional_str(map, "servername"))
        .or_else(|| yaml_optional_str(map, "host"))
        .or_else(|| yaml_optional_str(map, "server"))
}

fn build_outbound_tls(
    map: &serde_yaml::Mapping,
    _required: bool,
) -> Result<Value> {
    let mut tls = json!({
        "enabled": true,
        "server_name": tls_server_name(map),
        "insecure": yaml_bool(map, "skip-cert-verify").unwrap_or(false)
    });
    if let Some(alpn) = yaml_string_array(map, "alpn")
        .ok()
        .filter(|a| !a.is_empty())
    {
        tls["alpn"] = json!(alpn);
    }
    if let Some(fp) = yaml_optional_str(map, "client-fingerprint")
        .or_else(|| yaml_optional_str(map, "fingerprint"))
    {
        tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
    }
    if let Some(reality) = reality_opts(map) {
        tls["reality"] = reality;
    }
    Ok(tls)
}

fn reality_opts(map: &serde_yaml::Mapping) -> Option<Value> {
    let nested = map.get(YamlValue::from("reality-opts"))?.as_mapping()?;
    let public_key = yaml_mapping_str(nested, "public-key")?;
    let mut reality = json!({
        "enabled": true,
        "public_key": public_key
    });
    if let Some(short_id) = yaml_mapping_str(nested, "short-id") {
        reality["short_id"] = json!(short_id);
    }
    Some(reality)
}

fn yaml_str<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Result<&'a str> {
    map.get(YamlValue::from(key))
        .and_then(|v| v.as_str())
        .with_context(|| format!("missing or invalid clash field `{key}`"))
}

fn yaml_optional_str(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    yaml_str(map, key).ok().map(str::to_string)
}

fn yaml_u16(map: &serde_yaml::Mapping, key: &str) -> Result<u16> {
    let v = map
        .get(YamlValue::from(key))
        .context(format!("missing `{key}`"))?;
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).context(format!("`{key}` out of range"));
    }
    if let Some(s) = v.as_str() {
        return s.parse().with_context(|| format!("invalid `{key}`"));
    }
    bail!("invalid `{key}`")
}

fn yaml_u64(map: &serde_yaml::Mapping, key: &str) -> Option<u64> {
    map.get(YamlValue::from(key)).and_then(|v| v.as_u64())
}

fn yaml_bool(map: &serde_yaml::Mapping, key: &str) -> Option<bool> {
    map.get(YamlValue::from(key)).and_then(|v| v.as_bool())
}

fn yaml_string_array(
    map: &serde_yaml::Mapping,
    key: &str,
) -> Result<Vec<String>> {
    let v = map
        .get(YamlValue::from(key))
        .context(format!("missing `{key}`"))?;
    if let Some(s) = v.as_str() {
        return Ok(vec![s.to_string()]);
    }
    if let Some(seq) = v.as_sequence() {
        return Ok(seq
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect());
    }
    bail!("invalid `{key}` array")
}

#[cfg(test)]
mod tests {
    use serde_yaml::Value;

    use super::convert_proxy;

    #[test]
    fn converts_shadowsocks_proxy() {
        let raw = r#"
name: test-ss
type: ss
server: 1.2.3.4
port: 8388
cipher: aes-256-gcm
password: secret
"#;
        let proxy: Value = serde_yaml::from_str(raw).unwrap();
        let out = convert_proxy(&proxy, None).unwrap().unwrap();
        assert_eq!(out["type"], "shadowsocks");
        assert_eq!(out["tag"], "test-ss");
    }

    #[test]
    fn converts_anytls_proxy() {
        let raw = r#"
name: jp-anytls
type: anytls
server: example.com
port: 443
password: secret
sni: example.com
client-fingerprint: chrome
idle-session-check-interval: 30
min-idle-session: 4
skip-cert-verify: true
"#;
        let proxy: Value = serde_yaml::from_str(raw).unwrap();
        let out = convert_proxy(&proxy, None).unwrap().unwrap();
        assert_eq!(out["type"], "anytls");
        assert_eq!(out["password"], "secret");
        assert_eq!(out["idle_session_check_interval"], "30s");
        assert_eq!(out["min_idle_session"], 4);
        assert_eq!(out["tls"]["server_name"], "example.com");
        assert_eq!(out["tls"]["utls"]["fingerprint"], "chrome");
        assert!(out["tls"]["insecure"].as_bool().unwrap());
    }

    #[test]
    fn vless_uses_servername_for_tls_sni() {
        let raw = r#"
name: sg-vless
type: vless
server: cm91.tiggert.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
network: tcp
tls: true
servername: dnpa5t1ieentty2kaux-sgweb-01.rarasafe.com
client-fingerprint: chrome
"#;
        let proxy: Value = serde_yaml::from_str(raw).unwrap();
        let out = convert_proxy(&proxy, None).unwrap().unwrap();
        assert_eq!(
            out["tls"]["server_name"],
            "dnpa5t1ieentty2kaux-sgweb-01.rarasafe.com"
        );
        assert_eq!(out["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn vless_reality_opts_mapped() {
        let raw = r#"
name: reality
type: vless
server: edge.example.net
port: 443
uuid: 11111111-2222-3333-4444-555555555555
flow: xtls-rprx-vision
tls: true
servername: www.microsoft.com
client-fingerprint: chrome
reality-opts:
  public-key: testpubkey==
  short-id: abcd
"#;
        let proxy: Value = serde_yaml::from_str(raw).unwrap();
        let out = convert_proxy(&proxy, None).unwrap().unwrap();
        assert_eq!(out["tls"]["reality"]["public_key"], "testpubkey==");
        assert_eq!(out["tls"]["reality"]["short_id"], "abcd");
    }
}

fn yaml_optional_map(
    map: &serde_yaml::Mapping,
    key: &str,
) -> Option<Map<String, Value>> {
    let v = map.get(YamlValue::from(key))?;
    yaml_value_to_map(v)
}

fn yaml_nested_str(
    map: &serde_yaml::Mapping,
    parent: &str,
    key: &str,
) -> Option<String> {
    map.get(YamlValue::from(parent))?
        .as_mapping()
        .and_then(|nested| yaml_mapping_str(nested, key))
}

fn yaml_nested_map(
    map: &serde_yaml::Mapping,
    parent: &str,
    key: &str,
) -> Option<Map<String, Value>> {
    map.get(YamlValue::from(parent))?
        .as_mapping()?
        .get(YamlValue::from(key))
        .and_then(yaml_value_to_map)
}

fn yaml_mapping_str(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(YamlValue::from(key))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn yaml_value_to_map(v: &YamlValue) -> Option<Map<String, Value>> {
    let mapping = v.as_mapping()?;
    let mut out = Map::new();
    for (k, val) in mapping {
        let key = k.as_str()?.to_string();
        if let Some(s) = val.as_str() {
            out.insert(key, Value::String(s.to_string()));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
