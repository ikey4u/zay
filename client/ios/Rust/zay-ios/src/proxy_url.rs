//! Resolve a user-facing proxy URL into sing-box outbound JSON.
//!
//! Supported:
//! - `socks5://[user:pass@]host:port`
//! - `http://[user:pass@]host:port` / `https://…` (HTTP outbound)
//! - `ss://…` (Shadowsocks SIP002 / legacy)
//! - Clash / Mihomo subscription (`http://` / `https://` returning YAML with `proxies:`)

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde_json::{Value, json};
use serde_yaml::Value as YamlValue;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub enum OutboundSpec {
    Single(Value),
    Many(Vec<Value>),
}

const SUB_CACHE_BODY: &str = "subscription-cache.yaml";
const SUB_CACHE_META: &str = "subscription-cache.url";

/// Resolve proxy URL into outbounds. When `cache_dir` is set, successful Clash
/// subscription fetches are saved and reused if a later fetch fails (common when
/// Packet Tunnel starts before the underlay network is ready).
///
/// When `prefer_cache` is true (progressive rule reloads), try the disk cache
/// first and skip the network round-trip if nodes are already present.
pub fn resolve_proxy(
    raw: &str,
    cache_dir: Option<&Path>,
    prefer_cache: bool,
) -> Result<OutboundSpec> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("proxy_url is empty");
    }

    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("socks5://") || lower.starts_with("socks://") {
        return Ok(OutboundSpec::Single(parse_socks_or_http(raw, false)?));
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        if prefer_cache {
            if let Some(dir) = cache_dir {
                if let Ok(nodes) = load_subscription_cache(dir, raw) {
                    if !nodes.is_empty() {
                        tracing::info!(
                            "subscription: prefer_cache hit ({} node(s))",
                            nodes.len()
                        );
                        return Ok(OutboundSpec::Many(nodes));
                    }
                }
            }
        }
        match fetch_clash_subscription(raw, cache_dir) {
            Ok(nodes) if !nodes.is_empty() => return Ok(OutboundSpec::Many(nodes)),
            Ok(_) => {
                if looks_like_subscription_url(raw) {
                    bail!("subscription URL returned no proxies (empty proxies list)");
                }
            }
            Err(e) => {
                if looks_like_subscription_url(raw) {
                    if let Some(dir) = cache_dir {
                        if let Ok(nodes) = load_subscription_cache(dir, raw) {
                            tracing::warn!(
                                "subscription fetch failed ({e:#}); using cached {} node(s)",
                                nodes.len()
                            );
                            return Ok(OutboundSpec::Many(nodes));
                        }
                    }
                    bail!("subscription fetch failed: {e:#}");
                }
                tracing::warn!("subscription fetch failed ({e:#}); treating as HTTP proxy URI");
            }
        }
        return Ok(OutboundSpec::Single(parse_socks_or_http(raw, true)?));
    }
    if lower.starts_with("ss://") {
        return Ok(OutboundSpec::Single(parse_shadowsocks(raw)?));
    }
    if lower.starts_with("vmess://") {
        return Ok(OutboundSpec::Single(parse_vmess(raw)?));
    }
    if lower.starts_with("vless://") {
        return Ok(OutboundSpec::Single(parse_vless(raw)?));
    }
    if lower.starts_with("trojan://") {
        return Ok(OutboundSpec::Single(parse_trojan(raw)?));
    }

    bail!(
        "unsupported proxy_url scheme (use socks5://, http(s):// subscription or proxy, ss://, vmess://, vless://, trojan://)"
    );
}

/// Fetch (or load cache) so Packet Tunnel cold-start can skip network.
pub fn prefetch_proxy(raw: &str, cache_dir: &Path) -> Result<usize> {
    match resolve_proxy(raw, Some(cache_dir), false)? {
        OutboundSpec::Single(_) => Ok(1),
        OutboundSpec::Many(v) => Ok(v.len()),
    }
}

fn looks_like_subscription_url(raw: &str) -> bool {
    let Ok(u) = url::Url::parse(raw) else {
        return false;
    };
    if u.query().is_some() {
        return true;
    }
    let path = u.path();
    path.len() > 1 && path != "/"
}

fn parse_socks_or_http(raw: &str, http: bool) -> Result<Value> {
    let u = url::Url::parse(raw).context("parse proxy URI")?;
    let host = u
        .host_str()
        .filter(|h| !h.is_empty())
        .context("proxy host missing")?
        .to_string();
    let port = u.port().unwrap_or(if http { 80 } else { 1080 });
    let mut ob = json!({
        "type": if http { "http" } else { "socks" },
        "tag": "proxy-node",
        "server": host,
        "server_port": port
    });
    if !http {
        ob.as_object_mut()
            .unwrap()
            .insert("version".into(), json!("5"));
    }
    if !u.username().is_empty() {
        ob.as_object_mut()
            .unwrap()
            .insert("username".into(), json!(u.username()));
    }
    if let Some(pass) = u.password() {
        ob.as_object_mut()
            .unwrap()
            .insert("password".into(), json!(pass));
    }
    Ok(ob)
}

fn fetch_clash_subscription(url: &str, cache_dir: Option<&Path>) -> Result<Vec<Value>> {
    const SUBSCRIPTION_UA: &str = concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

    tracing::info!("fetching Clash subscription: {url}");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(8))
        .timeout_read(Duration::from_secs(20))
        .build();
    let body = agent
        .get(url)
        .set("User-Agent", SUBSCRIPTION_UA)
        .set("Accept", "*/*")
        .call()
        .context("HTTP GET subscription")?
        .into_string()
        .context("read subscription body")?;
    if looks_like_invalid_subscription_body(&body) {
        bail!("subscription returned HTML or empty body");
    }
    let nodes = convert_clash_yaml(&body)?;
    if let Some(dir) = cache_dir {
        if let Err(e) = save_subscription_cache(dir, url, &body) {
            tracing::warn!("failed to write subscription cache: {e:#}");
        }
    }
    Ok(nodes)
}

fn cache_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join(SUB_CACHE_BODY), dir.join(SUB_CACHE_META))
}

fn save_subscription_cache(dir: &Path, url: &str, body: &str) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let (body_path, meta_path) = cache_paths(dir);
    fs::write(&body_path, body).with_context(|| format!("writing {}", body_path.display()))?;
    fs::write(&meta_path, url).with_context(|| format!("writing {}", meta_path.display()))?;
    tracing::info!(
        "subscription cache saved ({} bytes) under {}",
        body.len(),
        dir.display()
    );
    Ok(())
}

fn load_subscription_cache(dir: &Path, url: &str) -> Result<Vec<Value>> {
    let (body_path, meta_path) = cache_paths(dir);
    if !body_path.is_file() {
        bail!("no subscription cache at {}", body_path.display());
    }
    if meta_path.is_file() {
        let cached_url = fs::read_to_string(&meta_path).unwrap_or_default();
        if cached_url.trim() != url.trim() {
            bail!(
                "subscription cache URL mismatch (cached different proxy_url)"
            );
        }
    }
    let body = fs::read_to_string(&body_path)
        .with_context(|| format!("reading {}", body_path.display()))?;
    if looks_like_invalid_subscription_body(&body) {
        bail!("subscription cache body invalid");
    }
    let nodes = convert_clash_yaml(&body)?;
    tracing::info!(
        "loaded {} outbound(s) from subscription cache {}",
        nodes.len(),
        body_path.display()
    );
    Ok(nodes)
}

fn looks_like_invalid_subscription_body(raw: &str) -> bool {
    let t = raw.trim();
    t.is_empty()
        || t.starts_with("<!DOCTYPE")
        || t.starts_with("<html")
        || t.starts_with("<HTML")
}

fn convert_clash_yaml(raw: &str) -> Result<Vec<Value>> {
    let doc: YamlValue = serde_yaml::from_str(raw).context("parse Clash YAML")?;
    let proxies = doc
        .get("proxies")
        .and_then(|p| p.as_sequence())
        .context("Clash document missing proxies:")?;

    let mut out = Vec::new();
    for (idx, proxy) in proxies.iter().enumerate() {
        match convert_clash_proxy(proxy, idx) {
            Ok(Some(v)) => out.push(v),
            Ok(None) => {}
            Err(e) => tracing::warn!("skip proxy #{idx}: {e:#}"),
        }
    }
    if out.is_empty() {
        bail!("no supported proxies in subscription");
    }
    tracing::info!("subscription produced {} outbound(s)", out.len());
    Ok(out)
}

fn convert_clash_proxy(proxy: &YamlValue, idx: usize) -> Result<Option<Value>> {
    let map = proxy
        .as_mapping()
        .context("proxy entry must be a mapping")?;
    let get = |k: &str| -> Option<&str> {
        map.get(YamlValue::String(k.into()))
            .and_then(|v| v.as_str())
    };
    let get_i = |k: &str| -> Option<i64> {
        map.get(YamlValue::String(k.into())).and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_u64().map(|u| u as i64))
                .or_else(|| v.as_f64().map(|f| f as i64))
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    };
    let get_b = |k: &str| -> bool {
        map.get(YamlValue::String(k.into()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    let ty = get("type").unwrap_or("").to_ascii_lowercase();
    let name = get("name").unwrap_or("node").to_string();
    let tag = format!("sub0-{name}");
    let server = get("server").context("server")?.to_string();
    let port = get_i("port").context("port")? as u16;

    let outbound = match ty.as_str() {
        "ss" | "shadowsocks" => {
            let method = get("cipher").or_else(|| get("method")).unwrap_or("aes-128-gcm");
            let password = get("password").unwrap_or("");
            json!({
                "type": "shadowsocks",
                "tag": tag,
                "server": server,
                "server_port": port,
                "method": method,
                "password": password
            })
        }
        "socks5" | "socks" => json!({
            "type": "socks",
            "tag": tag,
            "server": server,
            "server_port": port,
            "version": "5",
            "username": get("username").unwrap_or(""),
            "password": get("password").unwrap_or("")
        }),
        "http" | "https" => json!({
            "type": "http",
            "tag": tag,
            "server": server,
            "server_port": port,
            "username": get("username").unwrap_or(""),
            "password": get("password").unwrap_or("")
        }),
        "vmess" => {
            let uuid = get("uuid").context("uuid")?;
            let mut ob = json!({
                "type": "vmess",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "security": get("cipher").unwrap_or("auto"),
                "alter_id": get_i("alterId").unwrap_or(0)
            });
            if let Some(net) = get("network").or_else(|| get("net")) {
                apply_transport(ob.as_object_mut().unwrap(), net, map);
            }
            if get_b("tls") || get("tls").map(|s| s == "true") == Some(true) {
                ob.as_object_mut()
                    .unwrap()
                    .insert("tls".into(), build_clash_tls(map, &server, false));
            }
            ob
        }
        "vless" => {
            let uuid = get("uuid").context("uuid")?;
            let mut ob = json!({
                "type": "vless",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": uuid
            });
            if let Some(flow) = get("flow") {
                ob.as_object_mut()
                    .unwrap()
                    .insert("flow".into(), json!(flow));
            }
            if let Some(net) = get("network").or_else(|| get("net")) {
                apply_transport(ob.as_object_mut().unwrap(), net, map);
            }
            let tls_mode = get("tls").unwrap_or("");
            if tls_mode == "tls" || tls_mode == "reality" || get_b("tls") {
                ob.as_object_mut()
                    .unwrap()
                    .insert("tls".into(), build_clash_tls(map, &server, tls_mode == "reality"));
            }
            ob
        }
        "trojan" => {
            let password = get("password").context("password")?;
            let mut ob = json!({
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": password,
                "tls": build_clash_tls(map, &server, false)
            });
            if let Some(net) = get("network").or_else(|| get("net")) {
                apply_transport(ob.as_object_mut().unwrap(), net, map);
            }
            ob
        }
        other => {
            tracing::debug!("unsupported clash type {other} at #{idx}");
            return Ok(None);
        }
    };
    Ok(Some(outbound))
}

fn apply_transport(
    ob: &mut serde_json::Map<String, Value>,
    net: &str,
    map: &serde_yaml::Mapping,
) {
    let net = net.to_ascii_lowercase();
    match net.as_str() {
        "ws" | "websocket" => {
            let path = map
                .get(YamlValue::String("ws-opts".into()))
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .or_else(|| {
                    map.get(YamlValue::String("ws-path".into()))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("/");
            ob.insert(
                "transport".into(),
                json!({
                    "type": "ws",
                    "path": path
                }),
            );
        }
        "grpc" => {
            let service = map
                .get(YamlValue::String("grpc-opts".into()))
                .and_then(|o| o.get("grpc-service-name"))
                .and_then(|v| v.as_str())
                .unwrap_or("GunService");
            ob.insert(
                "transport".into(),
                json!({
                    "type": "grpc",
                    "service_name": service
                }),
            );
        }
        _ => {}
    }
}

/// Align with desktop `src/singbox/clash/convert.rs` TLS mapping.
/// Reality + Vision almost always needs uTLS fingerprint; missing it yields
/// `unknown version: 72` (HTTP `H`) from the edge.
fn build_clash_tls(map: &serde_yaml::Mapping, server: &str, force_reality: bool) -> Value {
    let sni = map
        .get(YamlValue::String("sni".into()))
        .and_then(|v| v.as_str())
        .or_else(|| {
            map.get(YamlValue::String("servername".into()))
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            map.get(YamlValue::String("host".into()))
                .and_then(|v| v.as_str())
        })
        .unwrap_or(server);

    let mut tls = json!({
        "enabled": true,
        "server_name": sni,
        "insecure": map
            .get(YamlValue::String("skip-cert-verify".into()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });

    let fp = map
        .get(YamlValue::String("client-fingerprint".into()))
        .and_then(|v| v.as_str())
        .or_else(|| {
            map.get(YamlValue::String("fingerprint".into()))
                .and_then(|v| v.as_str())
        });

    let has_reality_opts = map
        .get(YamlValue::String("reality-opts".into()))
        .and_then(|v| v.as_mapping())
        .is_some();
    let use_reality = force_reality || has_reality_opts;

    if let Some(fp) = fp {
        tls.as_object_mut().unwrap().insert(
            "utls".into(),
            json!({ "enabled": true, "fingerprint": fp }),
        );
    } else if use_reality {
        // Subscriptions sometimes omit fingerprint; chrome is the safe default.
        tls.as_object_mut().unwrap().insert(
            "utls".into(),
            json!({ "enabled": true, "fingerprint": "chrome" }),
        );
    }

    if use_reality {
        if let Some(opts) = map
            .get(YamlValue::String("reality-opts".into()))
            .and_then(|v| v.as_mapping())
        {
            let pub_key = opts
                .get(YamlValue::String("public-key".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let short_id = opts
                .get(YamlValue::String("short-id".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut reality = json!({
                "enabled": true,
                "public_key": pub_key
            });
            if !short_id.is_empty() {
                reality
                    .as_object_mut()
                    .unwrap()
                    .insert("short_id".into(), json!(short_id));
            }
            tls.as_object_mut()
                .unwrap()
                .insert("reality".into(), reality);
        }
    }

    tls
}

fn parse_shadowsocks(raw: &str) -> Result<Value> {
    // ss://BASE64(method:password@host:port)#name  OR  ss://method:password@host:port
    let u = url::Url::parse(raw).context("parse ss://")?;
    let host = u.host_str().context("ss host")?.to_string();
    let port = u.port().context("ss port")?;
    let (method, password) = if !u.username().is_empty() {
        (
            urlencoding_decode(u.username()),
            u.password().unwrap_or("").to_string(),
        )
    } else {
        // Legacy: entire userinfo is base64(method:password@host:port) — already parsed by Url?
        // Fall back: decode opaque.
        let encoded = raw.trim_start_matches("ss://");
        let encoded = encoded.split('#').next().unwrap_or(encoded);
        let encoded = encoded.split('?').next().unwrap_or(encoded);
        if let Some((userinfo, _)) = encoded.split_once('@') {
            let decoded = decode_b64(userinfo)?;
            let (method, password) = decoded
                .split_once(':')
                .context("ss userinfo method:password")?;
            (method.to_string(), password.to_string())
        } else {
            let decoded = decode_b64(encoded)?;
            // method:password@host:port
            let (cred, _) = decoded.split_once('@').context("ss legacy format")?;
            let (method, password) = cred.split_once(':').context("ss method:password")?;
            return Ok(json!({
                "type": "shadowsocks",
                "tag": "proxy-node",
                "server": host,
                "server_port": port,
                "method": method,
                "password": password
            }));
        }
    };
    Ok(json!({
        "type": "shadowsocks",
        "tag": "proxy-node",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password
    }))
}

fn parse_vmess(raw: &str) -> Result<Value> {
    let encoded = raw.trim_start_matches("vmess://");
    let decoded = decode_b64(encoded)?;
    let v: Value = serde_json::from_str(&decoded).context("vmess json")?;
    let server = v
        .get("add")
        .or_else(|| v.get("host"))
        .and_then(|x| x.as_str())
        .context("vmess add")?;
    let port = v
        .get("port")
        .and_then(|p| {
            p.as_u64()
                .or_else(|| p.as_str().and_then(|s| s.parse().ok()))
        })
        .context("vmess port")? as u16;
    let uuid = v.get("id").and_then(|x| x.as_str()).context("vmess id")?;
    Ok(json!({
        "type": "vmess",
        "tag": "proxy-node",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": v.get("scy").and_then(|x| x.as_str()).unwrap_or("auto"),
        "alter_id": v.get("aid").and_then(|x| x.as_u64()).unwrap_or(0)
    }))
}

fn parse_vless(raw: &str) -> Result<Value> {
    let u = url::Url::parse(raw).context("parse vless://")?;
    let uuid = u.username();
    if uuid.is_empty() {
        bail!("vless uuid missing");
    }
    let host = u.host_str().context("vless host")?;
    let port = u.port().unwrap_or(443);
    let mut ob = json!({
        "type": "vless",
        "tag": "proxy-node",
        "server": host,
        "server_port": port,
        "uuid": uuid
    });
    let mut tls = json!({ "enabled": true, "server_name": host });
    for (k, v) in u.query_pairs() {
        match k.as_ref() {
            "security" if v == "reality" || v == "tls" => {
                tls.as_object_mut()
                    .unwrap()
                    .insert("enabled".into(), json!(true));
            }
            "sni" | "peer" => {
                tls.as_object_mut()
                    .unwrap()
                    .insert("server_name".into(), json!(v.to_string()));
            }
            "pbk" => {
                let reality = tls
                    .as_object_mut()
                    .unwrap()
                    .entry("reality".to_string())
                    .or_insert_with(|| json!({ "enabled": true }));
                reality
                    .as_object_mut()
                    .unwrap()
                    .insert("public_key".into(), json!(v.to_string()));
            }
            "sid" => {
                let reality = tls
                    .as_object_mut()
                    .unwrap()
                    .entry("reality".to_string())
                    .or_insert_with(|| json!({ "enabled": true }));
                reality
                    .as_object_mut()
                    .unwrap()
                    .insert("short_id".into(), json!(v.to_string()));
                reality
                    .as_object_mut()
                    .unwrap()
                    .insert("enabled".into(), json!(true));
            }
            "flow" => {
                ob.as_object_mut()
                    .unwrap()
                    .insert("flow".into(), json!(v.to_string()));
            }
            "fp" | "fingerprint" => {
                tls.as_object_mut().unwrap().insert(
                    "utls".into(),
                    json!({ "enabled": true, "fingerprint": v.to_string() }),
                );
            }
            "type" if v == "ws" => {
                let path = u
                    .query_pairs()
                    .find(|(k, _)| k == "path")
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_else(|| "/".into());
                ob.as_object_mut().unwrap().insert(
                    "transport".into(),
                    json!({ "type": "ws", "path": path }),
                );
            }
            _ => {}
        }
    }
    // Reality requires uTLS; default chrome when omitted (same as Clash path).
    if tls
        .get("reality")
        .and_then(|r| r.get("enabled"))
        .and_then(|e| e.as_bool())
        == Some(true)
        && tls.get("utls").is_none()
    {
        tls.as_object_mut().unwrap().insert(
            "utls".into(),
            json!({ "enabled": true, "fingerprint": "chrome" }),
        );
    }
    ob.as_object_mut().unwrap().insert("tls".into(), tls);
    Ok(ob)
}

fn parse_trojan(raw: &str) -> Result<Value> {
    let u = url::Url::parse(raw).context("parse trojan://")?;
    let password = u.username();
    if password.is_empty() {
        bail!("trojan password missing");
    }
    let host = u.host_str().context("trojan host")?;
    let port = u.port().unwrap_or(443);
    let sni = u
        .query_pairs()
        .find(|(k, _)| k == "sni" || k == "peer")
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| host.to_string());
    Ok(json!({
        "type": "trojan",
        "tag": "proxy-node",
        "server": host,
        "server_port": port,
        "password": password,
        "tls": { "enabled": true, "server_name": sni }
    }))
}

fn decode_b64(s: &str) -> Result<String> {
    let s = s.trim();
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let bytes = engine
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .context("base64 decode")?;
    String::from_utf8(bytes).context("utf8")
}

fn urlencoding_decode(s: &str) -> String {
    urlencoding::decode(s)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
}
