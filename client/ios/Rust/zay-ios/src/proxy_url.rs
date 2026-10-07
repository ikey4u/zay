//! Resolve a user-facing proxy URL into sing-box outbound JSON.
//!
//! Supported:
//! - `socks5://[user:pass@]host:port`
//! - `http://[user:pass@]host:port` / `https://…` (HTTP outbound)
//! - `ss://…` (Shadowsocks SIP002 / legacy)
//! - Clash / Mihomo subscription (`http://` / `https://` returning YAML with `proxies:`)

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde_json::{Value, json};
use serde_yaml::Value as YamlValue;

pub enum OutboundSpec {
    Single(Value),
    Many(Vec<Value>),
}

const SUB_CACHE_BODY: &str = "subscription-cache.yaml";
const SUB_CACHE_META: &str = "subscription-cache.url";

/// Render a proxy/subscription endpoint without credentials or token-bearing
/// path/query data. This value is safe to persist in user diagnostics.
pub(crate) fn redacted_proxy_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "(empty)".into();
    }
    let Ok(parsed) = url::Url::parse(trimmed) else {
        return format!("<redacted len={}>", trimmed.len());
    };
    let scheme = parsed.scheme();
    if matches!(scheme, "socks" | "socks5")
        && legacy_socks_node(trimmed).is_some()
    {
        return format!("{scheme}:<redacted>");
    }
    if !matches!(
        scheme,
        "http"
            | "https"
            | "socks"
            | "socks5"
            | "tcp"
            | "udp"
            | "vless"
            | "trojan"
    ) {
        return format!("{scheme}:<redacted>");
    }
    let Some(raw_host) = parsed.host_str().filter(|host| !host.is_empty())
    else {
        return format!("{scheme}:<redacted>");
    };
    let host = if raw_host.contains(':') {
        format!("[{raw_host}]")
    } else {
        raw_host.to_owned()
    };
    match parsed.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

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
    let normalized = normalize_share_link(raw)?;
    let raw = normalized.as_deref().unwrap_or(raw);

    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("socks5://") || lower.starts_with("socks://") {
        return Ok(OutboundSpec::Single(parse_socks_or_http(raw, false)?));
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        if prefer_cache
            && let Some(dir) = cache_dir
            && let Ok(nodes) = load_subscription_cache(dir, raw)
            && !nodes.is_empty()
        {
            tracing::info!(
                "subscription: prefer_cache hit ({} node(s))",
                nodes.len()
            );
            return Ok(OutboundSpec::Many(nodes));
        }
        match fetch_clash_subscription(raw, cache_dir) {
            Ok(nodes) if !nodes.is_empty() => {
                return Ok(OutboundSpec::Many(nodes));
            }
            Ok(_) => {
                if looks_like_subscription_url(raw) {
                    bail!(
                        "subscription URL returned no proxies (empty proxies list)"
                    );
                }
            }
            Err(e) => {
                if looks_like_subscription_url(raw) {
                    if let Some(dir) = cache_dir
                        && let Ok(nodes) = load_subscription_cache(dir, raw)
                    {
                        tracing::warn!(
                            "subscription fetch failed ({e:#}); using cached {} node(s)",
                            nodes.len()
                        );
                        return Ok(OutboundSpec::Many(nodes));
                    }
                    bail!("subscription fetch failed: {e:#}");
                }
                tracing::warn!(
                    "subscription fetch failed ({e:#}); treating as HTTP proxy URI"
                );
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

/// Unwrap app import links and Telegram proxy links before network access.
fn normalize_share_link(raw: &str) -> Result<Option<String>> {
    let Ok(url) = url::Url::parse(raw) else {
        return Ok(None);
    };
    let scheme = url.scheme();
    let quantumult = scheme == "quantumult-x"
        || scheme == "https"
            && url.host_str() == Some("quantumult.app")
            && url.path() == "/x/open-app/add-resource";
    if quantumult {
        if scheme == "quantumult-x"
            && (url.host_str().is_some() || url.path() != "/add-resource")
        {
            bail!("unsupported Quantumult X import action");
        }
        let resource = url
            .query_pairs()
            .find(|(key, _)| key == "remote-resource")
            .map(|(_, value)| value.into_owned())
            .context("Quantumult X resource missing")?;
        let resource: Value = serde_json::from_str(&resource)
            .context("parse Quantumult X resource")?;
        let servers = resource["server_remote"]
            .as_array()
            .context("Quantumult X server subscription missing")?;
        if servers.len() != 1 {
            bail!("import one Quantumult X server subscription at a time");
        }
        let target = servers[0]
            .as_str()
            .context("invalid Quantumult X server resource")?
            .split(',')
            .next()
            .unwrap()
            .trim();
        let endpoint = url::Url::parse(target)
            .context("parse Quantumult X subscription URL")?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
        {
            bail!(
                "Quantumult X imports require an HTTP or HTTPS subscription URL"
            );
        }
        return Ok(Some(target.to_owned()));
    }
    if matches!(scheme, "http" | "https") && url.path().ends_with('/') {
        let token = url.path().trim_matches('/');
        if (32..=64).contains(&token.len())
            && token.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
            })
        {
            // s5's browser page also serves a Clash profile beside the page.
            return Ok(Some(url.join("clash.yaml")?.into()));
        }
    }
    if matches!(scheme, "clash" | "clashmeta" | "cmfa" | "sing-box") {
        let action = if scheme == "sing-box" {
            "import-remote-profile"
        } else {
            "install-config"
        };
        if url.host_str() != Some(action) {
            bail!("unsupported app import action");
        }
        let target = url
            .query_pairs()
            .find(|(key, _)| key == "url")
            .map(|(_, value)| value.into_owned())
            .context("app import URL missing url parameter")?;
        let target_url = url::Url::parse(&target)
            .context("parse subscription import URL")?;
        if !matches!(target_url.scheme(), "http" | "https")
            || target_url.host_str().is_none()
        {
            bail!("app imports require an HTTP or HTTPS subscription URL");
        }
        return Ok(Some(target));
    }
    let telegram = scheme == "tg" && url.host_str() == Some("socks")
        || matches!(scheme, "http" | "https")
            && matches!(
                url.host_str(),
                Some("t.me" | "telegram.me" | "telegram.dog")
            )
            && url.path().trim_end_matches('/') == "/socks";
    if !telegram {
        return Ok(None);
    }
    let parameter = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    let host = parameter("server").context("Telegram proxy server missing")?;
    let port: u16 = parameter("port")
        .context("Telegram proxy port missing")?
        .parse()
        .context("invalid Telegram proxy port")?;
    if port == 0 {
        bail!("Telegram proxy port must be between 1 and 65535");
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let mut proxy = url::Url::parse("socks5://localhost:1080")?;
    proxy
        .set_host(Some(&host))
        .context("invalid Telegram proxy server")?;
    proxy
        .set_port(Some(port))
        .map_err(|_| anyhow!("invalid Telegram proxy port"))?;
    if let Some(username) = parameter("user") {
        proxy
            .set_username(&username)
            .map_err(|_| anyhow!("invalid Telegram proxy username"))?;
    }
    if let Some(password) = parameter("pass") {
        proxy
            .set_password(Some(&password))
            .map_err(|_| anyhow!("invalid Telegram proxy password"))?;
    }
    Ok(Some(proxy.into()))
}

fn parse_socks_or_http(raw: &str, http: bool) -> Result<Value> {
    if !http && let Some(node) = legacy_socks_node(raw) {
        return node;
    }
    let u = url::Url::parse(raw).context("parse proxy URI")?;
    let host = u
        .host_str()
        .filter(|h| !h.is_empty())
        .context("proxy host missing")?
        .trim_start_matches('[')
        .trim_end_matches(']')
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
    let username =
        urlencoding::decode(u.username()).context("decode proxy username")?;
    let password = u
        .password()
        .map(urlencoding::decode)
        .transpose()
        .context("decode proxy password")?;
    // v2ray clients encode user:password as one base64 userinfo component.
    if !http
        && password.is_none()
        && !username.is_empty()
        && let Ok(decoded) = decode_b64(&username)
        && let Some((username, password)) = decoded.split_once(':')
    {
        if !username.is_empty() {
            ob["username"] = json!(username);
            ob["password"] = json!(password);
        }
        return Ok(ob);
    }
    if !username.is_empty() {
        ob.as_object_mut()
            .unwrap()
            .insert("username".into(), json!(username));
    }
    if let Some(pass) = password {
        ob.as_object_mut()
            .unwrap()
            .insert("password".into(), json!(pass));
    }
    Ok(ob)
}

/// Shadowrocket wraps the entire SOCKS authority in base64, unlike v2rayNG's
/// base64 userinfo. Parse before URL normalization and preserve literal '%'.
fn legacy_socks_node(raw: &str) -> Option<Result<Value>> {
    let (_, payload) = raw.split_once("://")?;
    let payload = payload.split(['?', '#']).next()?;
    if payload.contains(['@', ':']) {
        return None;
    }
    let decoded = decode_b64(payload).ok()?;
    let (credentials, endpoint) = decoded
        .rsplit_once('@')
        .map_or((None, decoded.as_str()), |(credentials, endpoint)| {
            (Some(credentials), endpoint)
        });
    if !endpoint.contains(':') {
        return None;
    }
    Some((|| {
        let endpoint = url::Url::parse(&format!("socks5://{endpoint}"))?;
        let host = endpoint
            .host_str()
            .context("SOCKS host missing")?
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = endpoint
            .port()
            .filter(|port| *port != 0)
            .context("SOCKS port missing or invalid")?;
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            bail!("invalid encoded SOCKS endpoint");
        }
        let mut node = json!({"type":"socks", "tag":"proxy-node", "version":"5", "server":host, "server_port":port});
        if let Some(credentials) = credentials {
            let (user, pass) = credentials
                .split_once(':')
                .context("invalid encoded SOCKS credentials")?;
            if !user.is_empty() || !pass.is_empty() {
                node["username"] = json!(user);
                node["password"] = json!(pass);
            }
        }
        Ok(node)
    })())
}

fn fetch_clash_subscription(
    url: &str,
    cache_dir: Option<&Path>,
) -> Result<Vec<Value>> {
    const SUBSCRIPTION_UA: &str =
        concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

    let redacted_url = redacted_proxy_url(url);
    tracing::info!("fetching Clash subscription: {redacted_url}");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(8))
        .timeout_read(Duration::from_secs(20))
        .build();
    let body = agent
        .get(url)
        .set("User-Agent", SUBSCRIPTION_UA)
        .set("Accept", "*/*")
        .call()
        .map_err(|_| {
            anyhow!("HTTP GET subscription via {redacted_url} failed")
        })?
        .into_string()
        .context("read subscription body")?;
    if looks_like_invalid_subscription_body(&body) {
        bail!("subscription returned HTML or empty body");
    }
    let nodes = convert_subscription(&body)?;
    if let Some(dir) = cache_dir
        && let Err(error) = save_subscription_cache(dir, url, &body)
    {
        tracing::warn!("failed to write subscription cache: {error:#}");
    }
    Ok(nodes)
}

fn cache_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join(SUB_CACHE_BODY), dir.join(SUB_CACHE_META))
}

fn save_subscription_cache(dir: &Path, url: &str, body: &str) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let (body_path, meta_path) = cache_paths(dir);
    fs::write(&body_path, body)
        .with_context(|| format!("writing {}", body_path.display()))?;
    fs::write(&meta_path, url)
        .with_context(|| format!("writing {}", meta_path.display()))?;
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
    let nodes = convert_subscription(&body)?;
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
    let doc: YamlValue =
        serde_yaml::from_str(raw).context("parse Clash YAML")?;
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

fn convert_subscription(raw: &str) -> Result<Vec<Value>> {
    let raw = raw.trim();
    if raw.lines().any(|line| {
        line.split_once('=')
            .is_some_and(|(key, _)| key.trim() == "socks5")
    }) {
        return convert_quantumult_servers(raw);
    }
    if raw.starts_with('{') {
        let document: Value =
            serde_json::from_str(raw).context("parse JSON subscription")?;
        if document.get("proxies").is_some() {
            return convert_clash_yaml(raw);
        }
        let outbounds = document
            .get("outbounds")
            .and_then(Value::as_array)
            .context("JSON profile missing outbounds")?;
        let mut nodes = Vec::new();
        for outbound in outbounds {
            if outbound["type"].as_str().is_some()
                && outbound["server"].as_str().is_some()
            {
                // Import proxy nodes, leaving tunnel, DNS, routing, and groups
                // to Zay's own configuration builder.
                let mut node = outbound.clone();
                if node["tag"].as_str().is_none() {
                    node["tag"] = json!(format!("proxy-node-{}", nodes.len()));
                }
                nodes.push(node);
            } else if outbound["protocol"] == "socks"
                && let Some(servers) =
                    outbound["settings"]["servers"].as_array()
            {
                for server in servers {
                    let host = server["address"]
                        .as_str()
                        .context("Xray SOCKS server address missing")?;
                    let port = server["port"]
                        .as_u64()
                        .filter(|port| (1..=65535).contains(port))
                        .context("invalid Xray SOCKS server port")?;
                    let mut node = json!({ "type": "socks", "version": "5", "tag": format!("proxy-node-{}", nodes.len()), "server": host, "server_port": port });
                    if let Some(user) = server["users"]
                        .as_array()
                        .and_then(|users| users.first())
                    {
                        node["username"] = user["user"].clone();
                        node["password"] = user["pass"].clone();
                    }
                    nodes.push(node);
                }
            }
        }
        if nodes.is_empty() {
            bail!("JSON subscription contains no proxy nodes");
        }
        // Imported tags must not collide with Zay's Proxy/Auto/direct nodes.
        // Retain chains between imported proxies, while Zay supplies DNS.
        let mut tags = std::collections::HashMap::new();
        for (index, node) in nodes.iter().enumerate() {
            let tag = node["tag"].as_str().context("proxy tag missing")?;
            if tags
                .insert(tag.to_owned(), format!("sub0-json-{index}-{tag}"))
                .is_some()
            {
                bail!("JSON subscription contains duplicate proxy tags");
            }
        }
        for node in &mut nodes {
            let tag = node["tag"].as_str().unwrap();
            let tag = tags[tag].clone();
            node["tag"] = json!(tag);
            node.as_object_mut().unwrap().remove("domain_resolver");
            if let Some(detour) = node["detour"].as_str() {
                if let Some(imported) = tags.get(detour) {
                    node["detour"] = json!(imported);
                } else if detour != "direct" {
                    bail!(
                        "JSON proxy detour references a node outside the imported proxies"
                    );
                }
            }
        }
        return Ok(nodes);
    }
    let text = if raw.lines().any(|line| line.trim().contains("://")) {
        raw.to_owned()
    } else {
        decode_b64(raw).unwrap_or_else(|_| raw.to_owned())
    };
    let is_node_uri = |line: &str| {
        [
            "socks://",
            "socks5://",
            "ss://",
            "vmess://",
            "vless://",
            "trojan://",
        ]
        .iter()
        .any(|scheme| line.starts_with(scheme))
    };
    if text.lines().any(|line| is_node_uri(line.trim())) {
        let mut nodes = Vec::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            if !is_node_uri(line) {
                bail!("unsupported URI in proxy subscription");
            }
            let OutboundSpec::Single(mut node) =
                resolve_proxy(line, None, false)?
            else {
                bail!("expected a proxy node URI");
            };
            node["tag"] = json!(format!("proxy-node-{}", nodes.len()));
            nodes.push(node);
        }
        return Ok(nodes);
    }
    convert_clash_yaml(raw)
}

fn convert_quantumult_servers(raw: &str) -> Result<Vec<Value>> {
    let mut nodes = Vec::new();
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split(',').map(str::trim);
        let first = fields.next().unwrap();
        let (kind, endpoint) = first
            .split_once('=')
            .context("invalid Quantumult X server")?;
        if kind.trim() != "socks5" {
            bail!("unsupported Quantumult X server type");
        }
        let mut node = parse_socks_or_http(
            &format!("socks5://{}", endpoint.trim()),
            false,
        )?;
        let endpoint_url =
            url::Url::parse(&format!("socks5://{}", endpoint.trim()))?;
        if endpoint_url.port().filter(|port| *port != 0).is_none()
            || !endpoint_url.username().is_empty()
            || endpoint_url.password().is_some()
            || !matches!(endpoint_url.path(), "" | "/")
            || endpoint_url.query().is_some()
            || endpoint_url.fragment().is_some()
        {
            bail!("invalid Quantumult X SOCKS endpoint");
        }
        for field in fields {
            let (key, value) = field
                .split_once('=')
                .context("invalid Quantumult X server field")?;
            let value = value.trim();
            match key.trim() {
                "username" | "password" => {
                    node[key.trim()] = json!(value);
                }
                "over-tls" if value != "false" => {
                    bail!("SOCKS over TLS is unsupported")
                }
                "over-tls" | "udp-relay" | "fast-open" | "tag" => {}
                _ => bail!("unsupported Quantumult X server field"),
            }
        }
        if node.get("username").is_some() != node.get("password").is_some() {
            bail!(
                "Quantumult X SOCKS credentials require username and password"
            );
        }
        node["tag"] = json!(format!("sub0-quantumult-{}", nodes.len()));
        nodes.push(node);
    }
    if nodes.is_empty() {
        bail!("Quantumult X subscription contains no servers");
    }
    Ok(nodes)
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
            let method = get("cipher")
                .or_else(|| get("method"))
                .unwrap_or("aes-128-gcm");
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
                ob.as_object_mut().unwrap().insert(
                    "tls".into(),
                    build_clash_tls(map, &server, tls_mode == "reality"),
                );
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
fn build_clash_tls(
    map: &serde_yaml::Mapping,
    server: &str,
    force_reality: bool,
) -> Value {
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

    if use_reality
        && let Some(opts) = map
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
            let (cred, _) =
                decoded.split_once('@').context("ss legacy format")?;
            let (method, password) =
                cred.split_once(':').context("ss method:password")?;
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
    let compact = s.split_whitespace().collect::<String>();
    let s = compact.as_str();
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

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::{
        OutboundSpec, convert_clash_yaml, convert_subscription,
        normalize_share_link, redacted_proxy_url, resolve_proxy,
    };

    #[test]
    fn shadowrocket_nodes_preserve_literal_credentials_and_redact_them() {
        for payload in [
            "alice:p%20/λ@[2001:db8::5]:2345",
            ":@host:2345",
            "host:2345",
        ] {
            for scheme in ["socks", "socks5"] {
                let link = format!(
                    "{scheme}://{}?remarks=s5",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(payload)
                );
                let OutboundSpec::Single(proxy) =
                    resolve_proxy(&link, None, false).unwrap()
                else {
                    panic!("expected one proxy");
                };
                assert_eq!(proxy["server_port"], 2345);
                assert_eq!(
                    redacted_proxy_url(&link),
                    format!("{scheme}:<redacted>")
                );
                if payload.starts_with("alice") {
                    assert_eq!(proxy["server"], "2001:db8::5");
                    assert_eq!(proxy["username"], "alice");
                    assert_eq!(proxy["password"], "p%20/λ");
                } else {
                    assert!(proxy.get("username").is_none());
                }
            }
        }
        let invalid = format!(
            "socks://{}?remarks=s5",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode("alice:secret@host:0")
        );
        assert!(resolve_proxy(&invalid, None, false).is_err());
        assert_eq!(redacted_proxy_url(&invalid), "socks:<redacted>");
    }

    #[test]
    fn quantumult_import_links_and_server_snippets() {
        let resource = serde_json::json!({"server_remote":["http://host:1081/token/quantumult-x.txt, tag=s5, enabled=true"]}).to_string();
        for prefix in [
            "quantumult-x:///add-resource",
            "https://quantumult.app/x/open-app/add-resource",
        ] {
            let link = format!(
                "{prefix}?remote-resource={}",
                urlencoding::encode(&resource)
            );
            assert_eq!(
                normalize_share_link(&link).unwrap().unwrap(),
                "http://host:1081/token/quantumult-x.txt"
            );
        }
        assert!(
            normalize_share_link(
                "quantumult-x:///update-configuration?remote-resource=x"
            )
            .is_err()
        );
        let link = format!(
            "quantumult-x:///add-resource?remote-resource={}",
            urlencoding::encode(r#"{"server_remote":["file:///etc/passwd"]}"#)
        );
        assert!(normalize_share_link(&link).is_err());
        let nodes = convert_subscription("# s5\nsocks5=[2001:db8::5]:2345, username=a:b, password=p:@/%λ, over-tls=false, udp-relay=true, fast-open=false, tag=s5\nsocks5=host:1080, tag=anonymous\n").unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["server"], "2001:db8::5");
        assert_eq!(nodes[0]["username"], "a:b");
        assert_eq!(nodes[0]["password"], "p:@/%λ");
        assert!(nodes[1].get("username").is_none());
        assert_ne!(nodes[0]["tag"], nodes[1]["tag"]);
        for invalid in [
            "socks5=host:0",
            "socks5=host:1080, over-tls=true",
            "socks5=host:1080, password=only",
            "socks5=host:1080/path",
        ] {
            assert!(convert_subscription(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn app_import_links_unwrap_only_http_subscriptions() {
        let endpoint = "http://[2001:db8::5]:1081/token/clash.yaml";
        for scheme in ["clash", "clashmeta", "cmfa", "sing-box"] {
            let action = if scheme == "sing-box" {
                "import-remote-profile"
            } else {
                "install-config"
            };
            let link = format!(
                "{scheme}://{action}?url={}#s5",
                urlencoding::encode(endpoint)
            );
            assert_eq!(
                normalize_share_link(&link).unwrap().as_deref(),
                Some(endpoint)
            );
        }
        assert!(
            normalize_share_link(
                "clash://install-config?url=file%3A%2F%2F%2Fetc%2Fhosts"
            )
            .is_err()
        );
        assert!(
            normalize_share_link("sing-box://import-remote-profile").is_err()
        );
        assert_eq!(
            normalize_share_link(
                "http://host/0123456789abcdef0123456789abcdef/"
            )
            .unwrap()
            .unwrap(),
            "http://host/0123456789abcdef0123456789abcdef/clash.yaml"
        );
        assert!(normalize_share_link("http://host/").unwrap().is_none());
    }

    #[test]
    fn telegram_and_v2ray_links_preserve_authentication() {
        for prefix in [
            "tg://socks",
            "https://t.me/socks",
            "https://telegram.me/socks",
        ] {
            let link = format!(
                "{prefix}?server=2001%3Adb8%3A%3A5&port=2345&user=a%3Ab&pass=p%26%3F%23%2B"
            );
            let OutboundSpec::Single(proxy) =
                resolve_proxy(&link, None, false).unwrap()
            else {
                panic!("expected one proxy");
            };
            assert_eq!(proxy["server"], "2001:db8::5");
            assert_eq!(proxy["server_port"], 2345);
            assert_eq!(proxy["username"], "a:b");
            assert_eq!(proxy["password"], "p&?#+");
        }
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode("alice:p:@/λ");
        let link = format!(
            "socks://{}@[2001:db8::5]:2345#s5",
            urlencoding::encode(&encoded)
        );
        let OutboundSpec::Single(proxy) =
            resolve_proxy(&link, None, false).unwrap()
        else {
            panic!("expected one proxy");
        };
        assert_eq!(proxy["username"], "alice");
        assert_eq!(proxy["password"], "p:@/λ");
        assert!(
            resolve_proxy("tg://socks?server=host&port=0", None, false)
                .is_err()
        );
        assert!(resolve_proxy("tg://socks?port=1080", None, false).is_err());
    }

    #[test]
    fn json_and_base64_subscriptions_import_proxy_nodes() {
        let nodes = convert_subscription(r#"{"outbounds":[{"type":"selector","tag":"group","outbounds":["s5"]},{"type":"direct","tag":"direct"},{"type":"socks","tag":"s5","server":"::1","server_port":2345,"username":"a:b","password":"p&?"}]}"#).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["username"], "a:b");
        let nodes = convert_subscription(r#"{"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"::1","port":2345,"users":[{"user":"a:b","pass":"p&?"}]}]}}]}"#).unwrap();
        assert_eq!(nodes[0]["server"], "::1");
        assert_eq!(nodes[0]["username"], "a:b");
        assert_eq!(nodes[0]["password"], "p&?");
        let raw = "socks5://alice:p%3A%26@host:1080#one\nsocks://localhost:2345#two\n";
        for source in [
            raw.to_owned(),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
        ] {
            let nodes = convert_subscription(&source).unwrap();
            assert_eq!(nodes.len(), 2);
            assert_eq!(nodes[0]["username"], "alice");
            assert_eq!(nodes[0]["password"], "p:&");
            assert_ne!(nodes[0]["tag"], nodes[1]["tag"]);
        }
        assert!(
            convert_subscription(r#"{"outbounds":[{"type":"direct"}]}"#)
                .is_err()
        );
        let nodes = convert_subscription(r#"{"outbounds":[{"type":"socks","tag":"Proxy","server":"host","server_port":1080,"detour":"Auto","domain_resolver":"profile-dns"},{"type":"socks","tag":"Auto","server":"host","server_port":1081}]}"#).unwrap();
        assert_ne!(nodes[0]["tag"], "Proxy");
        assert_ne!(nodes[1]["tag"], "Auto");
        assert_eq!(nodes[0]["detour"], nodes[1]["tag"]);
        assert!(nodes[0].get("domain_resolver").is_none());
    }

    #[test]
    fn socks_share_link_decodes_credentials_and_ipv6() {
        let OutboundSpec::Single(proxy) = resolve_proxy(
            "socks5://a%3A%40%2F:p%25%20%3F%23@[2001:db8::5]:2345#s5",
            None,
            false,
        )
        .unwrap() else {
            panic!("expected a single SOCKS proxy");
        };
        assert_eq!(proxy["type"], "socks");
        assert_eq!(proxy["server"], "2001:db8::5");
        assert_eq!(proxy["server_port"], 2345);
        assert_eq!(proxy["username"], "a:@/");
        assert_eq!(proxy["password"], "p% ?#");
        let OutboundSpec::Single(anonymous) =
            resolve_proxy("socks5://proxy.example.com:1080#s5", None, false)
                .unwrap()
        else {
            panic!("expected a single SOCKS proxy");
        };
        assert!(anonymous.get("username").is_none());
        assert!(anonymous.get("password").is_none());
    }

    #[test]
    fn imports_s5_clash_profile() {
        let nodes = convert_clash_yaml(
            r#"proxies:
  - name: s5
    type: socks5
    server: '2001:db8::5'
    port: 2345
    udp: true
    username: 'a:@/'
    password: 'p% ?#'
proxy-groups:
  - name: PROXY
    type: select
    proxies: [s5]
rules:
  - MATCH,PROXY
"#,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["type"], "socks");
        assert_eq!(nodes[0]["server"], "2001:db8::5");
        assert_eq!(nodes[0]["server_port"], 2345);
        assert_eq!(nodes[0]["username"], "a:@/");
        assert_eq!(nodes[0]["password"], "p% ?#");
    }

    #[test]
    fn diagnostic_url_redaction_drops_all_credentials_and_resource_data() {
        assert_eq!(
            redacted_proxy_url(
                "https://user:pass@example.com:8443/sub/token?token=secret#node"
            ),
            "https://example.com:8443"
        );
        assert_eq!(
            redacted_proxy_url("vless://uuid@example.com:443?pbk=secret"),
            "vless://example.com:443"
        );
        assert_eq!(redacted_proxy_url("ss://opaque-secret"), "ss:<redacted>");
        assert_eq!(
            redacted_proxy_url("not a URL or credential"),
            "<redacted len=23>"
        );
    }
}
