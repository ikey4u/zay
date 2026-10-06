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

pub fn is_devpane() -> bool {
    (cfg!(target_os = "linux")
        && std::env::var("ZAY_LAB").as_deref() == Ok("devpane")
        && std::path::Path::new("/.dockerenv").exists())
        || (cfg!(target_os = "macos")
            && std::env::var("ZAY_LAB").as_deref() == Ok("devpane-macos")
            && std::path::Path::new("/etc/zay-devpane-macos").exists())
}

pub fn profile_json() -> Value {
    let name = std::env::var("ZAY_LAB")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut presets = Vec::new();
    if is_devpane() {
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
            "Mesh peer HTTP",
            Some(env_or(
                "ZAY_LAB_MESH_URL",
                "http://10.126.126.3:8090/whoami",
            )),
            None,
            None,
        ));
    }
    json!({
        "active": name.is_some(),
        "interactive": is_devpane(),
        "name": name,
        "platform": if cfg!(target_os = "macos") { "macOS VM" } else { "Linux container" },
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
            "--location",
            "--proto-redir",
            "=http,https",
            "--max-redirs",
            "5",
            "--max-filesize",
            "2097152",
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
        .arg("%{json}")
        .arg(&url)
        .output()
        .context("running curl")?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let timing: Value =
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    let status = timing["http_code"].as_u64().filter(|code| *code > 0);
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
        "remote_ip": timing["remote_ip"],
        "effective_url": timing["url_effective"],
        "dns_ms": timing["time_namelookup"].as_f64().map(|v| v * 1000.0),
        "connect_ms": timing["time_connect"].as_f64().map(|v| v * 1000.0),
        "headers": headers,
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
    fn browser_error_uses_navigation_failure_instead_of_dbus_noise() {
        assert_eq!(
            super::browser_failure(
                "ERROR:dbus: Failed to connect\nERROR Page load failed: net::ERR_CONNECTION_RESET\n"
            ),
            "Page could not load: net::ERR_CONNECTION_RESET"
        );
        assert!(
            !super::browser_failure(&"dbus error\n".repeat(500))
                .contains("dbus")
        );
    }

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

#[derive(Deserialize)]
pub struct BrowserRequest {
    pub url: String,
}

/// Render in a separate Chromium process so requests take the container's TUN.
pub async fn render_page(request: BrowserRequest) -> Result<Value> {
    use base64::Engine;
    static RENDERS: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(2);
    let _permit = RENDERS
        .try_acquire()
        .context("browser is busy; try again shortly")?;
    if !is_devpane() {
        bail!("browser rendering is only available inside devpane");
    }
    let url = validate_http_url(&request.url)?;
    let directory = (if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    })
    .join(format!("zay-browser-{}-{}", std::process::id(), nanos()));
    std::fs::create_dir(&directory)?;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let screenshot = directory.join("page.png");
    let mut command = tokio::process::Command::new("timeout");
    command
        .args([
            "--kill-after=2s",
            "30s",
            "chromium",
            "--headless",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-background-networking",
            "--no-proxy-server",
            // The lab subscription is an HTTP CONNECT proxy without UDP support.
            "--disable-quic",
            "--hide-scrollbars",
            "--window-size=1280,800",
            "--virtual-time-budget=3000",
        ])
        .arg(format!(
            "--user-data-dir={}",
            directory.join("profile").display()
        ))
        .arg(format!("--screenshot={}", screenshot.display()))
        .arg(&url)
        .kill_on_drop(true);
    let target = url.clone();
    let probe = tokio::task::spawn_blocking(move || probe_url(&target));
    let rendered = if cfg!(target_os = "macos") {
        render_macos(&directory, &url).await
    } else {
        command.output().await.context("starting the lab browser")
    };
    let connection = probe.await??;
    let diagnostics = rendered.as_ref().ok().map(|output| {
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(12000)
            .collect::<String>()
    });
    let (image, render_error) = match rendered {
        Ok(output) if output.status.success() && screenshot.is_file() => (
            Some(format!(
                "data:image/png;base64,{}",
                base64::engine::general_purpose::STANDARD
                    .encode(std::fs::read(screenshot)?)
            )),
            None,
        ),
        Ok(output) => (
            None,
            Some(
                if output.status.code() == Some(124)
                    || output.status.code() == Some(137)
                {
                    "The page did not finish rendering within 30 seconds"
                        .to_string()
                } else {
                    browser_failure(&String::from_utf8_lossy(&output.stderr))
                },
            ),
        ),
        Err(error) => (None, Some(error.to_string())),
    };
    Ok(
        json!({"url": url, "image": image, "error": render_error, "diagnostics": diagnostics, "connection": connection}),
    )
}

/// Chrome on macOS may remain alive after writing its screenshot.
/// Poll the complete PNG, then terminate only this render's process group.
async fn render_macos(
    directory: &std::path::Path,
    url: &str,
) -> Result<std::process::Output> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if !Command::new("chown")
            .arg("admin:staff")
            .arg(directory)
            .status()?
            .success()
        {
            bail!("could not prepare browser directory for the guest user");
        }
        let mut command = tokio::process::Command::new("/bin/bash");
        command.args(["-c", r#"
sudo -n -H -u admin '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
 --headless --disable-gpu --disable-quic --disable-background-networking \
 --no-first-run --no-proxy-server --window-size=1280,800 --virtual-time-budget=5000 \
 --user-data-dir="$1/profile" --screenshot="$1/page.png" "$2" > "$1/stdout" 2> "$1/stderr" &
for attempt in {1..30}; do
 if test -s "$1/page.png" && tail -c 8 "$1/page.png" | /usr/bin/xxd -p | /usr/bin/grep -q 49454e44ae426082; then
  exit 0
 fi
 sleep 1
done
cat "$1/stderr" >&2
exit 124
"#, "zay-render"]).arg(directory).arg(url);
        // The parent owns group cleanup; avoid the shell terminating itself.
        command.as_std_mut().process_group(0);
        command.kill_on_drop(true);
        let mut child = command.spawn()?;
        struct Group(u32);
        impl Drop for Group {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(-(self.0 as i32), libc::SIGKILL);
                }
            }
        }
        let _group = Group(child.id().context("browser process has no PID")?);
        let status = child.wait().await?;
        Ok(std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: std::fs::read(directory.join("stderr")).unwrap_or_default(),
        })
    }
    #[cfg(not(unix))]
    bail!("macOS browser requires Unix")
}

fn browser_failure(stderr: &str) -> String {
    stderr
        .lines()
        .find_map(|line| {
            line.split_once("Page load failed: ").map(|(_, reason)| {
                format!(
                    "Page could not load: {}",
                    reason.chars().take(160).collect::<String>()
                )
            })
        })
        .unwrap_or_else(|| {
            "Browser rendering failed. Expand browser diagnostics for details."
                .into()
        })
}

/// One PTY per WebSocket: shell state persists until the user disconnects.
pub async fn terminal(mut socket: axum::extract::ws::WebSocket) -> Result<()> {
    use std::io::{Read, Write};

    use axum::extract::ws::Message;
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    static TERMINALS: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(4);
    let _permit = TERMINALS
        .try_acquire()
        .context("all terminal sessions are in use")?;
    if !is_devpane() {
        bail!("terminal is only available inside devpane");
    }
    let pair = native_pty_system().openpty(PtySize {
        rows: 24,
        cols: 100,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    let mut command = CommandBuilder::new("/bin/bash");
    command.args(["--noprofile", "--norc", "-i"]);
    command.env("TERM", "xterm-256color");
    command.env("PS1", "\\u@devpane:\\w\\$ ");
    command.cwd(env_or("ZAY_LAB_WORKDIR", "/var/lib/zay"));
    if cfg!(target_os = "macos") {
        command.env("PS1", "\\u@devpane-macos:\\w\\$ ");
    }
    let mut child = pair.slave.spawn_command(command)?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<String>(16);
    let writer_task = tokio::task::spawn_blocking(move || {
        while let Some(data) = input_rx.blocking_recv() {
            if writer.write_all(data.as_bytes()).is_err() {
                break;
            }
        }
    });
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        let mut buffer = [0u8; 8192];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0
                || output_tx.blocking_send(buffer[..count].to_vec()).is_err()
            {
                break;
            }
        }
    });
    // Dropping the PTY closes the controlling terminal; kill and reap the shell
    // as well, so closing a browser tab cannot leave a shell session running.
    loop {
        tokio::select! {
            output = output_rx.recv() => match output {
                Some(bytes) => if socket.send(Message::Binary(bytes.into())).await.is_err() { break; },
                None => break,
            },
            input = socket.recv() => match input {
                Some(Ok(Message::Text(text))) => {
                    let Ok(value) = serde_json::from_str::<Value>(&text) else { continue; };
                    if value["type"] == "input" {
                        if let Some(data) = value["data"].as_str() {
                            if data.len() > 16384 || input_tx.try_send(data.to_string()).is_err() { break; }
                        }
                    } else if value["type"] == "resize" {
                        let cols = value["cols"].as_u64().unwrap_or(100).clamp(20, 300) as u16;
                        let rows = value["rows"].as_u64().unwrap_or(24).clamp(5, 100) as u16;
                        let _ = pair.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                    }
                },
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                _ => {},
            },
        }
    }
    if let Some(pid) = child.process_id() {
        let _ = tokio::process::Command::new("pkill")
            .args(["-KILL", "-s", &pid.to_string()])
            .status()
            .await;
    }
    let _ = child.kill();
    drop(input_tx);
    drop(pair.master);
    drop(output_rx);
    let _ = tokio::task::spawn_blocking(move || child.wait()).await;
    let _ = reader_task.await;
    let _ = writer_task.await;
    Ok(())
}
