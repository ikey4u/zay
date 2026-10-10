use std::{
    fmt::Write as _,
    io::{self, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::Arc,
};

use anyhow::{Context, Result};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use qrcode::{Color, QrCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Duration, sleep, timeout},
};

#[path = "formats.rs"]
mod formats;
pub use formats::QrFormat;
use formats::{Resource, ShareLink};

pub struct ImportServer {
    listener: TcpListener,
    resources: Vec<Resource>,
    links: Vec<ShareLink>,
}

impl ImportServer {
    pub async fn bind(
        listen: SocketAddr,
        host: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen).await?;
        let token = match token {
            Some(token) => import_token(token).map_err(anyhow::Error::msg)?,
            None => {
                let mut random = [0; 32];
                getrandom::fill(&mut random).map_err(|error| {
                    anyhow::anyhow!("generating QR import token: {error}")
                })?;
                random
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            }
        };
        let path = format!("/{token}");
        let url_host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let base = format!(
            "http://{url_host}:{}{path}",
            listener.local_addr()?.port()
        );
        let (links, resources) =
            formats::build(&base, &path, host, port, username, password)?;
        Ok(Self {
            listener,
            resources,
            links,
        })
    }

    #[cfg(test)]
    fn url(&self) -> &str {
        &self.links[0].url
    }

    pub fn print(&self, format: QrFormat) -> Result<()> {
        print_qr(&self.links, format)
    }

    pub async fn run(self) {
        let resources = Arc::new(self.resources);
        let mut requests = JoinSet::new();
        loop {
            tokio::select! {
                connection = self.listener.accept(), if requests.len() < 64 => {
                    // Accept failures such as descriptor exhaustion are
                    // transient; stopping here would take the proxy down.
                    let Ok((socket, _)) = connection else {
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    let resources = resources.clone();
                    requests.spawn(async move {
                        let _ = timeout(Duration::from_secs(5), serve_import(socket, &resources)).await;
                    });
                }
                Some(_) = requests.join_next(), if !requests.is_empty() => {}
            }
        }
    }
}

pub fn import_token(value: &str) -> Result<String, String> {
    if !(32..=64).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
        })
    {
        return Err("import token must contain 32–64 letters, digits, hyphens, or underscores".into());
    }
    Ok(value.to_owned())
}

pub fn clash_configuration(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<String> {
    let mut output = format!(
        "proxies:\n  - name: s5\n    type: socks5\n    server: {}\n    port: {port}\n    udp: true\n",
        serde_json::to_string(host)?
    );
    if let (Some(username), Some(password)) = (username, password) {
        writeln!(output, "    username: {}", serde_json::to_string(username)?)?;
        writeln!(output, "    password: {}", serde_json::to_string(password)?)?;
    }
    output.push_str("proxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - s5\nrules:\n  - MATCH,PROXY\n");
    Ok(output)
}

async fn serve_import(
    mut socket: TcpStream,
    resources: &[Resource],
) -> io::Result<()> {
    let mut header = [0; 8192];
    let mut size = 0;
    let request = loop {
        if size == header.len() {
            break None;
        }
        let read = socket.read(&mut header[size..]).await?;
        if read == 0 {
            return Ok(());
        }
        size += read;
        if header[..size].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            break std::str::from_utf8(&header[..size]).ok();
        }
    };
    let (status, body, head, content_type) =
        match request.and_then(|request| request.lines().next()) {
            Some(line) => {
                let mut parts = line.split_whitespace();
                let (method, target, version) =
                    (parts.next(), parts.next(), parts.next());
                let valid = matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
                    && parts.next().is_none();
                let head = method == Some("HEAD");
                let resource = target
                    .and_then(|target| target.split('?').next())
                    .and_then(|path| {
                        resources.iter().find(|resource| resource.path == path)
                    });
                if !valid {
                    ("400 Bad Request", "Bad request\n", head, "text/plain")
                } else if resource.is_none() {
                    ("404 Not Found", "Not found\n", head, "text/plain")
                } else if !matches!(method, Some("GET" | "HEAD")) {
                    (
                        "405 Method Not Allowed",
                        "Use GET or HEAD\n",
                        false,
                        "text/plain",
                    )
                } else {
                    let resource = resource.unwrap();
                    (
                        "200 OK",
                        resource.body.as_str(),
                        head,
                        resource.content_type,
                    )
                }
            }
            None => (
                "431 Request Header Fields Too Large",
                "Invalid request headers\n",
                false,
                "text/plain",
            ),
        };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(response.as_bytes()).await?;
    if !head {
        socket.write_all(body.as_bytes()).await?;
    }
    socket.shutdown().await
}

pub fn advertise_host(value: &str) -> Result<String, String> {
    let host = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(value);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified() {
            return Err("advertised address must identify this server; wildcard addresses are not reachable".into());
        }
        return Ok(ip.to_string());
    }
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(
            "expected a hostname or IP address without a scheme, port, or path"
                .into(),
        );
    }
    Ok(host.to_owned())
}

pub fn local_host(listen: SocketAddr) -> String {
    if !listen.ip().is_unspecified() {
        return listen.ip().to_string();
    }
    // UDP connect chooses the interface without sending a packet or making
    // an external request. An explicit --advertise takes precedence for NAT.
    let route = if listen.is_ipv4() {
        ("0.0.0.0:0", "192.0.2.1:80")
    } else {
        ("[::]:0", "[2001:db8::1]:80")
    };
    let address = UdpSocket::bind(route.0).and_then(|socket| {
        socket.connect(route.1)?;
        socket.local_addr()
    });
    match address {
        Ok(address) if !address.ip().is_unspecified() => {
            address.ip().to_string()
        }
        _ => {
            eprintln!(
                "Could not detect a reachable address. Set --advertise HOST for mobile access."
            );
            if listen.is_ipv4() { "127.0.0.1" } else { "::1" }.to_owned()
        }
    }
}

pub fn server_uri(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let credentials = match (username, password) {
        (Some(username), Some(password)) => format!(
            "{}:{}@",
            utf8_percent_encode(username, NON_ALPHANUMERIC),
            utf8_percent_encode(password, NON_ALPHANUMERIC)
        ),
        _ => String::new(),
    };
    format!("socks5://{credentials}{host}:{port}#s5")
}

pub fn terminal_qr(uri: &str) -> Result<String> {
    let code =
        QrCode::new(uri.as_bytes()).context("encoding server QR code")?;
    let width = code.width();
    let margin = 4;
    let size = width + margin * 2;
    let dark = |x: usize, y: usize| {
        x >= margin
            && y >= margin
            && x < width + margin
            && y < width + margin
            && code[(x - margin, y - margin)] == Color::Dark
    };
    let mut output = String::new();
    for y in (0..size).step_by(2) {
        // Fix foreground and background colors for scanning on both light
        // and dark terminals. Each character draws two square QR modules.
        output.push_str("\x1b[30;47m");
        for x in 0..size {
            output.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        output.push_str("\x1b[0m\n");
    }
    Ok(output)
}

fn print_qr(links: &[ShareLink], format: QrFormat) -> Result<()> {
    let mut output = String::new();
    writeln!(
        output,
        "\nServer import links (choose another QR with --qr FORMAT):"
    )?;
    if !matches!(format, QrFormat::All | QrFormat::None)
        && !links.iter().any(|link| link.format == format)
    {
        writeln!(
            output,
            "This QR format cannot represent the configured credentials. Use the SOCKS link or JSON profile instead."
        )?;
    }
    for link in links {
        if format == QrFormat::All || format == link.format {
            writeln!(output, "\nScan to import: {}", link.label)?;
            match terminal_qr(&link.url) {
                Ok(qr) => output.push_str(&qr),
                Err(error) => writeln!(
                    output,
                    "QR unavailable ({error}); copy the URL below instead."
                )?,
            }
        }
        writeln!(output, "{}: {}", link.label, link.url)?;
    }
    io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .context("printing server QR code")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_preserves_ipv6_and_escaped_credentials() {
        assert_eq!(
            server_uri("2001:db8::5", 1080, Some("a:@/"), Some("p% ?#")),
            "socks5://a%3A%40%2F:p%25%20%3F%23@[2001:db8::5]:1080#s5"
        );
        assert_eq!(
            server_uri("proxy.example.com", 1080, None, None),
            "socks5://proxy.example.com:1080#s5"
        );
        assert_eq!(advertise_host("[2001:db8::5]").unwrap(), "2001:db8::5");
        for host in [
            "0.0.0.0",
            "::",
            "http://server",
            "host:1080",
            "host/path",
            "user@host",
            "",
            "host\n",
        ] {
            assert!(
                advertise_host(host).is_err(),
                "accepted invalid advertised host: {host:?}"
            );
        }
    }

    async fn request(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn mobile_configuration_import_and_http_limits() {
        let token = "0123456789abcdef0123456789abcdef";
        let server = ImportServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "2001:db8::5",
            2345,
            Some("a:@/\"\n"),
            Some("p% ?#"),
            Some(token),
        )
        .await
        .unwrap();
        let address = server.listener.local_addr().unwrap();
        let path = server.resources[0].path.clone();
        assert_eq!(
            server.url(),
            format!("http://[2001:db8::5]:{}{path}", address.port())
        );
        let task = tokio::spawn(server.run());
        let response = request(
            address,
            &format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        let (header, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(
            header.contains(&format!("Content-Length: {}\r\n", body.len()))
        );
        let configuration: serde_yaml::Value =
            serde_yaml::from_str(body).unwrap();
        let proxy = &configuration["proxies"][0];
        assert_eq!(proxy["type"].as_str(), Some("socks5"));
        assert_eq!(proxy["server"].as_str(), Some("2001:db8::5"));
        assert_eq!(proxy["port"].as_u64(), Some(2345));
        assert_eq!(proxy["username"].as_str(), Some("a:@/\"\n"));
        assert_eq!(proxy["password"].as_str(), Some("p% ?#"));
        assert_eq!(proxy["udp"].as_bool(), Some(true));
        assert_eq!(
            configuration["proxy-groups"][0]["proxies"][0].as_str(),
            Some("s5")
        );
        assert_eq!(configuration["rules"][0].as_str(), Some("MATCH,PROXY"));
        let root = path.strip_suffix("clash.yaml").unwrap();
        for (file, content_type) in [
            ("sing-box.json", "application/json"),
            ("xray.json", "application/json"),
            ("links.txt", "text/plain"),
            ("", "text/html"),
        ] {
            let response =
                request(address, &format!("GET {root}{file} HTTP/1.1\r\n\r\n"))
                    .await;
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(
                response.contains(&format!("Content-Type: {content_type}"))
            );
            assert!(response.contains("Referrer-Policy: no-referrer\r\n"));
            let (_, body) = response.split_once("\r\n\r\n").unwrap();
            if file == "sing-box.json" {
                let profile: serde_json::Value =
                    serde_json::from_str(body).unwrap();
                assert_eq!(profile["outbounds"][0]["server"], "2001:db8::5");
                assert_eq!(profile["outbounds"][0]["username"], "a:@/\"\n");
                assert_eq!(profile["dns"]["servers"][1]["detour"], "s5");
                assert_eq!(profile["route"]["final"], "s5");
            } else if file == "xray.json" {
                let profile: serde_json::Value =
                    serde_json::from_str(body).unwrap();
                assert_eq!(
                    profile["outbounds"][0]["settings"]["servers"][0]["users"]
                        [0]["user"],
                    "a:@/\"\n"
                );
                assert_eq!(
                    profile["outbounds"][0]["settings"]["servers"][0]["users"]
                        [0]["pass"],
                    "p% ?#"
                );
            }
        }
        let head = request(
            address,
            &format!("HEAD {path}?refresh=1 HTTP/1.1\r\n\r\n"),
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));
        for (query, status) in [
            ("GET /clash.yaml HTTP/1.1\r\n\r\n".to_owned(), "404"),
            (format!("POST {path} HTTP/1.1\r\n\r\n"), "405"),
            (format!("GET {path} HTTP/2.0\r\n\r\n"), "400"),
            ("x".repeat(8192), "431"),
        ] {
            assert!(
                request(address, &query)
                    .await
                    .starts_with(&format!("HTTP/1.1 {status}"))
            );
        }
        task.abort();
        let _ = task.await;
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn anonymous_import_has_random_token_and_no_credentials() {
        let first = ImportServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "proxy.example.com",
            1080,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let second = ImportServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "proxy.example.com",
            1080,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_ne!(first.resources[0].path, second.resources[0].path);
        let configuration: serde_yaml::Value =
            serde_yaml::from_str(&first.resources[0].body).unwrap();
        assert!(configuration["proxies"][0]["username"].is_null());
        assert!(configuration["proxies"][0]["password"].is_null());
    }
}
