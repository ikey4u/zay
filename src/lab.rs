//! Network probes for the WebUI lab page.
//!
//! Probes run as `curl` or `nc`, not inside the `zay` process. With EasyTier
//! and a subscription, Zay bypasses its own sockets; a child process follows TUN.

use std::{
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
pub struct ProbeRequest {
    pub url: Option<String>,
    pub tcp: Option<String>,
}

pub fn profile_json() -> Value {
    let name = std::env::var("ZAY_LAB")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut presets = Vec::new();
    if name.as_deref() == Some("devpane") {
        presets.push(preset(
            "proxy",
            "TUN path to the lab domain",
            Some(env_or("ZAY_LAB_PROXY_URL", "http://devpane.test/whoami")),
            None,
            Some("proxy"),
        ));
        presets.push(preset(
            "direct",
            "Control plane direct",
            Some(env_or(
                "ZAY_LAB_DIRECT_URL",
                "http://172.30.126.10:8090/whoami",
            )),
            None,
            Some("direct"),
        ));
        presets.push(preset(
            "external",
            "External connectivity",
            Some(env_or(
                "ZAY_LAB_EXTERNAL_URL",
                "https://www.gstatic.com/generate_204",
            )),
            None,
            None,
        ));
        presets.push(preset(
            "mesh",
            "Mesh Hub",
            None,
            Some(env_or("ZAY_LAB_MESH_TCP", "10.126.126.1:11010")),
            None,
        ));
    }
    json!({
        "active": name.is_some(),
        "name": name,
        "hint": "Probes run in the Zay process network, not in the browser that opened this page.",
        "presets": presets,
    })
}

pub fn run_probe(request: ProbeRequest) -> Result<Value> {
    match (request.url.as_deref(), request.tcp.as_deref()) {
        (Some(url), None) => probe_url(url),
        (None, Some(tcp)) => probe_tcp(tcp),
        _ => bail!("provide exactly one of url or tcp"),
    }
}

fn probe_url(raw: &str) -> Result<Value> {
    let url = validate_http_url(raw)?;
    if Command::new("curl").arg("--version").output().is_err() {
        bail!("curl is not installed on the host running Zay");
    }
    let stamp = nanos();
    let header_path = std::env::temp_dir()
        .join(format!("zay-lab-h-{}-{stamp}", std::process::id()));
    let body_path = std::env::temp_dir()
        .join(format!("zay-lab-b-{}-{stamp}", std::process::id()));
    let started = Instant::now();
    let output = Command::new("curl")
        .args([
            "--noproxy",
            "*",
            "--ipv4",
            "--proto",
            "=http,https",
            "--max-redirs",
            "0",
            "-sS",
            "--max-time",
            "12",
            "--connect-timeout",
            "5",
            "-D",
        ])
        .arg(&header_path)
        .arg("-o")
        .arg(&body_path)
        .arg("-w")
        .arg("%{http_code}")
        .arg(&url)
        .output()
        .context("running curl")?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|code| *code > 0);
    let headers = std::fs::read_to_string(&header_path).unwrap_or_default();
    let body = std::fs::read(&body_path).unwrap_or_default();
    let _ = std::fs::remove_file(&header_path);
    let _ = std::fs::remove_file(&body_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let error = if output.status.success() && status.is_some() {
        None
    } else {
        Some(stderr.trim().to_string()).filter(|text| !text.is_empty())
    };
    Ok(json!({
        "kind": "url",
        "target": url,
        "ok": error.is_none(),
        "status": status,
        "elapsed_ms": elapsed_ms,
        "via": header_value(&headers, "x-devpane-via"),
        "body": body_excerpt(&body),
        "error": error,
    }))
}

fn probe_tcp(raw: &str) -> Result<Value> {
    let (host, port) = parse_tcp_target(raw)?;
    if Command::new("nc").arg("-h").output().is_err() {
        bail!("nc is not installed on the host running Zay");
    }
    let started = Instant::now();
    let output = Command::new("nc")
        .args(["-z", "-w", "5", &host, &port.to_string()])
        .output()
        .context("running nc")?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let ok = output.status.success();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let error = if ok {
        None
    } else if stderr.trim().is_empty() {
        Some("connection failed".to_string())
    } else {
        Some(stderr.trim().to_string())
    };
    Ok(json!({
        "kind": "tcp",
        "target": format!("{host}:{port}"),
        "ok": ok,
        "status": Value::Null,
        "elapsed_ms": elapsed_ms,
        "via": Value::Null,
        "body": "",
        "error": error,
    }))
}

fn validate_http_url(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.len() > 2048 {
        bail!("url is too long");
    }
    let url = reqwest::Url::parse(raw).context("invalid url")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("url scheme must be http or https");
    }
    if url.host_str().is_none_or(|host| host.is_empty()) {
        bail!("url is missing a host");
    }
    Ok(url.to_string())
}

fn parse_tcp_target(raw: &str) -> Result<(String, u16)> {
    let raw = raw.trim();
    let (host, port) = raw
        .rsplit_once(':')
        .context("tcp target must be host:port")?;
    if host.is_empty()
        || !host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
        })
    {
        bail!("tcp host must be a hostname or IPv4 address");
    }
    let port: u16 = port.parse().context("invalid tcp port")?;
    if port == 0 {
        bail!("tcp port must be non-zero");
    }
    Ok((host.to_string(), port))
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        } else {
            None
        }
    })
}

fn body_excerpt(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut excerpt: String = text.chars().take(400).collect();
    if text.chars().count() > 400 {
        excerpt.push('…');
    }
    excerpt
}

fn preset(
    id: &str,
    label: &str,
    url: Option<String>,
    tcp: Option<String>,
    expect_via: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "label": label,
        "url": url,
        "tcp": tcp,
        "expect_via": expect_via,
    })
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::{header_value, parse_tcp_target, validate_http_url};

    #[test]
    fn accepts_http_urls() {
        assert!(validate_http_url("http://devpane.test/whoami").is_ok());
        assert!(validate_http_url("file:///etc/passwd").is_err());
        assert!(validate_http_url("not a url").is_err());
    }

    #[test]
    fn reads_devpane_via_header() {
        let headers = "HTTP/1.1 200 OK\r\nX-Devpane-Via: proxy\r\n\r\n";
        assert_eq!(
            header_value(headers, "x-devpane-via").as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn parses_tcp_target() {
        assert_eq!(
            parse_tcp_target("10.126.126.1:11010").unwrap(),
            ("10.126.126.1".into(), 11010)
        );
        assert!(parse_tcp_target("10.126.126.1").is_err());
    }
}
