//! Lab edge for devpane.
//!
//! `edge` serves the Clash subscription, an HTTP proxy, and DNS.
//! `sink` serves the same HTTP paths with `X-Devpane-Via: direct`, so a bypassed
//! connection is visible. `devpane.test` resolves to a non-RFC1918 address because
//! Zay keeps `172.16.0.0/12` off TUN.

use std::{
    env, io,
    io::{Read, Write},
    net::{
        Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
        UdpSocket,
    },
    process::ExitCode,
    thread,
    time::Duration,
};

const LAB_NAME: &str = "devpane.test";

struct Config {
    role: String,
    advertise_host: String,
    proxy_port: u16,
    control_port: u16,
    sink_port: u16,
    lab_addr: Ipv4Addr,
    upstream_dns: SocketAddr,
}

fn main() -> ExitCode {
    let config = Config::from_env();
    if env::args().any(|arg| arg == "--healthcheck") {
        return if healthcheck(config.control_port) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    let mut handles = Vec::new();
    match config.role.as_str() {
        "edge" | "all" | "host" | "dns" => {
            let control = config.control_port;
            let proxy = config.proxy_port;
            let advertise = config.advertise_host.clone();
            let lab_addr = config.lab_addr;
            let upstream = config.upstream_dns;
            let proxy_port = config.proxy_port;
            let advertise_http = advertise.clone();
            let role = if config.role == "host" {
                "host"
            } else {
                "edge"
            };
            handles.push(thread::spawn(move || {
                serve_http(control, "direct", role, &advertise_http, proxy_port)
            }));
            if config.role != "dns" {
                handles.push(thread::spawn(move || {
                    serve_proxy(proxy, lab_addr, &advertise)
                }));
            }
            if config.role != "host" {
                handles
                    .push(thread::spawn(move || serve_dns(lab_addr, upstream)));
            }
        }
        "sink" => {}
        other => {
            eprintln!("unknown DEVPANE_ROLE={other}");
            return ExitCode::from(2);
        }
    }
    if config.role == "sink" || config.role == "all" {
        let sink = config.sink_port;
        let advertise = config.advertise_host.clone();
        let proxy_port = config.proxy_port;
        handles.push(thread::spawn(move || {
            serve_http(sink, "direct", "sink", &advertise, proxy_port)
        }));
    }
    if handles.is_empty() {
        eprintln!("unknown DEVPANE_ROLE={}", config.role);
        return ExitCode::from(2);
    }
    for handle in handles {
        let _ = handle.join();
    }
    ExitCode::SUCCESS
}

impl Config {
    fn from_env() -> Self {
        Self {
            role: env::var("DEVPANE_ROLE").unwrap_or_else(|_| "edge".into()),
            advertise_host: env::var("DEVPANE_ADVERTISE_HOST")
                .unwrap_or_else(|_| "172.30.126.10".into()),
            proxy_port: env_u16("DEVPANE_PROXY_PORT", 3128),
            control_port: env_u16("DEVPANE_CONTROL_PORT", 8090),
            sink_port: env_u16("DEVPANE_SINK_PORT", 80),
            lab_addr: env::var("DEVPANE_LAB_ADDRESS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(Ipv4Addr::new(192, 0, 2, 11)),
            upstream_dns: env::var("DEVPANE_UPSTREAM_DNS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| {
                    SocketAddr::from((Ipv4Addr::new(223, 5, 5, 5), 53))
                }),
        }
    }
}

fn env_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn healthcheck(port: u16) -> bool {
    let mut stream = match TcpStream::connect((
        env::var("DEVPANE_BIND")
            .unwrap_or_else(|_| "127.0.0.1".into())
            .as_str(),
        port,
    )) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("healthcheck connect: {error}");
            return false;
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = format!(
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0_u8; 128];
    match stream.read(&mut buf) {
        Ok(size) => std::str::from_utf8(&buf[..size])
            .map(|text| text.starts_with("HTTP/1.1 200"))
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn serve_http(
    port: u16,
    via: &'static str,
    role: &'static str,
    advertise: &str,
    proxy_port: u16,
) {
    let listener = TcpListener::bind((
        env::var("DEVPANE_BIND")
            .unwrap_or_else(|_| "0.0.0.0".into())
            .as_str(),
        port,
    ))
    .expect("bind http");
    eprintln!("devpane {role} listening on :{port} via={via}");
    let advertise = advertise.to_string();
    for conn in listener.incoming() {
        let Ok(mut stream) = conn else {
            continue;
        };
        let advertise = advertise.clone();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
        thread::spawn(move || {
            let peer = stream
                .peer_addr()
                .map(|addr| addr.ip().to_string())
                .unwrap_or_else(|_| "unknown".into());
            let mut pending = Vec::new();
            if let Some(head) = read_headers(&mut stream, &mut pending) {
                let path = request_path(&head);
                let (status, body, content_type) = local_result(
                    &path, via, role, &peer, &advertise, proxy_port,
                );
                let _ =
                    write_http(&mut stream, status, content_type, via, &body);
                eprintln!("[devpane:{role}] {peer} {path} {status}");
            }
        });
    }
}

fn serve_proxy(port: u16, lab_addr: Ipv4Addr, advertise: &str) {
    let listener = TcpListener::bind((
        env::var("DEVPANE_BIND")
            .unwrap_or_else(|_| "0.0.0.0".into())
            .as_str(),
        port,
    ))
    .expect("bind proxy");
    eprintln!("devpane proxy listening on :{port}");
    let advertise = advertise.to_string();
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            continue;
        };
        let advertise = advertise.clone();
        thread::spawn(move || handle_proxy(stream, lab_addr, &advertise, port));
    }
}

fn handle_proxy(
    mut client: TcpStream,
    lab_addr: Ipv4Addr,
    advertise: &str,
    proxy_port: u16,
) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(20)));
    let peer = client
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let mut pending = Vec::new();
    let Some(head) = read_headers(&mut client, &mut pending) else {
        return;
    };
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let Some(request) = lines.next() else {
        return;
    };
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();
    if let Err(error) = dispatch_proxy(
        &mut client,
        &mut pending,
        &method,
        &target,
        &head,
        &peer,
        lab_addr,
        advertise,
        proxy_port,
    ) {
        let _ = write_http(
            &mut client,
            502,
            "text/plain",
            "proxy",
            format!("{error}\n").as_bytes(),
        );
    }
}

fn connect_upstream(host: &str, port: u16) -> io::Result<TcpStream> {
    // Match the lab's IPv4 data plane. A host VPN may accept a synthetic IPv6
    // TCP connection but never carry its TLS traffic, preventing fallback.
    let ipv4_only = env::var("DEVPANE_IPV4_ONLY").as_deref() == Ok("1");
    let mut last_error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no usable upstream address",
    );
    for address in (host, port).to_socket_addrs()? {
        if ipv4_only && !address.is_ipv4() {
            continue;
        }
        match TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            Ok(stream) => {
                eprintln!(
                    "[devpane:proxy] upstream {host}:{port} via {address}"
                );
                return Ok(stream);
            }
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn dispatch_proxy(
    client: &mut TcpStream,
    pending: &mut Vec<u8>,
    method: &str,
    target: &str,
    head: &[u8],
    peer: &str,
    lab_addr: Ipv4Addr,
    advertise: &str,
    proxy_port: u16,
) -> io::Result<()> {
    if method == "CONNECT" {
        let (host, port) = split_host_port(target, 443);
        if is_lab_target(&host, lab_addr) {
            return answer_lab_tunnel(
                client, pending, peer, advertise, proxy_port,
            );
        }
        let upstream = connect_upstream(&host, port)?;
        upstream.set_read_timeout(Some(Duration::from_secs(20)))?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        relay(client.try_clone()?, upstream)?;
        return Ok(());
    }
    if method != "GET" && method != "HEAD" {
        return write_http(
            client,
            405,
            "text/plain",
            "proxy",
            b"method not allowed\n",
        );
    }
    let absolute = if target.starts_with('/') {
        let host = header_value(head, "host").unwrap_or_default();
        format!("http://{host}{target}")
    } else {
        target.to_string()
    };
    forward_http(
        client, method, &absolute, head, peer, lab_addr, advertise, proxy_port,
    )
}

fn answer_lab_tunnel(
    client: &mut TcpStream,
    pending: &mut Vec<u8>,
    peer: &str,
    advertise: &str,
    proxy_port: u16,
) -> io::Result<()> {
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    let path = read_headers(client, pending)
        .as_deref()
        .map(request_path)
        .unwrap_or_else(|| "/whoami".into());
    let (status, body, content_type) = local_result(
        &path,
        "proxy",
        &env::var("DEVPANE_ROLE").unwrap_or_else(|_| "edge".into()),
        peer,
        advertise,
        proxy_port,
    );
    write_http(client, status, content_type, "proxy", &body)
}

fn forward_http(
    client: &mut TcpStream,
    method: &str,
    target: &str,
    head: &[u8],
    peer: &str,
    lab_addr: Ipv4Addr,
    advertise: &str,
    proxy_port: u16,
) -> io::Result<()> {
    let (host, port, path) = split_http_target(target);
    let Some(host) = host else {
        return write_http(
            client,
            400,
            "text/plain",
            "proxy",
            b"missing host\n",
        );
    };
    if is_lab_target(&host, lab_addr) {
        let (status, body, content_type) = local_result(
            &path,
            "proxy",
            &env::var("DEVPANE_ROLE").unwrap_or_else(|_| "edge".into()),
            peer,
            advertise,
            proxy_port,
        );
        return write_http(client, status, content_type, "proxy", &body);
    }
    let mut upstream = connect_upstream(&host, port)?;
    upstream.set_read_timeout(Some(Duration::from_secs(12)))?;
    let mut request = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    for line in String::from_utf8_lossy(head).split("\r\n").skip(1) {
        if line.is_empty()
            || line.to_ascii_lowercase().starts_with("proxy-connection:")
        {
            continue;
        }
        request.extend_from_slice(line.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    upstream.write_all(&request)?;
    relay(client.try_clone()?, upstream)
}

fn relay(mut left: TcpStream, mut right: TcpStream) -> io::Result<()> {
    let mut left_read = left.try_clone()?;
    let mut right_write = right.try_clone()?;
    let worker = thread::spawn(move || {
        let _ = io::copy(&mut left_read, &mut right_write);
        let _ = right_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut right, &mut left);
    let _ = left.shutdown(Shutdown::Write);
    let _ = worker.join();
    Ok(())
}

fn serve_dns(lab_addr: Ipv4Addr, upstream: SocketAddr) {
    let bind = env::var("DEVPANE_BIND").unwrap_or_else(|_| "0.0.0.0".into());
    let socket = UdpSocket::bind((bind.as_str(), 53)).expect("bind dns");
    eprintln!("devpane dns listening on :53 ({LAB_NAME} -> {lab_addr})");
    let mut buf = [0_u8; 2048];
    loop {
        let Ok((size, peer)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let query = &buf[..size];
        let local_reply = lab_dns_response(query, lab_addr).or_else(|| {
            (env::var("DEVPANE_IPV4_ONLY").as_deref() == Ok("1"))
                .then(|| ipv4_only_dns_response(query))
                .flatten()
        });
        if let Some(reply) = local_reply {
            let _ = socket.send_to(&reply, peer);
            continue;
        }
        if env::var("DEVPANE_DOH").as_deref() == Ok("1") {
            let query = query.to_vec();
            let response_socket = socket.try_clone().expect("clone DNS socket");
            thread::spawn(move || match doh_query(&query) {
                Ok(reply) => {
                    let _ = response_socket.send_to(&reply, peer);
                }
                Err(error) => eprintln!("lab HTTPS DNS: {error}"),
            });
            continue;
        }
        let Ok(upstream_socket) = UdpSocket::bind(("0.0.0.0", 0)) else {
            continue;
        };
        let _ = upstream_socket.set_read_timeout(Some(Duration::from_secs(2)));
        if upstream_socket.send_to(query, upstream).is_err() {
            continue;
        }
        let mut reply = [0_u8; 2048];
        if let Ok((reply_size, _)) = upstream_socket.recv_from(&mut reply) {
            let _ = socket.send_to(&reply[..reply_size], peer);
        }
    }
}

// HTTPS to the existing AliDNS provider prevents host VPN FakeIP rewriting.
fn doh_query(query: &[u8]) -> io::Result<Vec<u8>> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--noproxy",
            "*",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
            "--resolve",
            "dns.alidns.com:443:223.5.5.5",
            "--header",
            "Content-Type: application/dns-message",
            "--header",
            "Accept: application/dns-message",
            "--data-binary",
            "@-",
            "https://dns.alidns.com/dns-query",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child.stdin.take().expect("DNS stdin").write_all(query)?;
    let output = child.wait_with_output()?;
    if !output.status.success() || output.stdout.len() < 12 {
        return Err(io::Error::other("upstream query failed"));
    }
    Ok(output.stdout)
}

fn local_result(
    path: &str,
    via: &str,
    role: &str,
    client: &str,
    advertise: &str,
    proxy_port: u16,
) -> (u16, Vec<u8>, &'static str) {
    if path == "/" {
        return (200, br#"<!doctype html><html><head><title>Devpane browser test</title><style>body{font:18px system-ui;background:#101827;color:#e2e8f0;padding:60px}main{max-width:780px;margin:auto;padding:40px;border:1px solid #334155;border-radius:24px}h1{font-size:44px}span{color:#6ee7b7}a{color:#93c5fd}</style></head><body><main><span>DEVPANE / NETWORK LAB</span><h1>The container browser is connected.</h1><p>This page was loaded inside the Zay network.</p><p id="js">JavaScript is loading...</p><script>document.getElementById('js').textContent='JavaScript rendering is working.';</script><p>Try a public URL in the address bar, or open the container terminal to inspect the network.</p></main></body></html>"#.to_vec(), "text/html; charset=utf-8");
    }
    if path.starts_with("/generate_204") {
        return (204, Vec::new(), "text/plain");
    }
    if path.starts_with("/health") || path.starts_with("/whoami") {
        let body = format!(
            "{{\"service\":\"devpane\",\"role\":\"{role}\",\"pid\":{},\"via\":\"{via}\",\"client\":\"{client}\",\"path\":\"{path}\"}}", std::process::id()
        );
        return (200, body.into_bytes(), "application/json");
    }
    if path.starts_with("/sub") {
        let body = format!(
            "proxies:\n  - name: devpane\n    type: http\n    server: {advertise}\n    port: {proxy_port}\n"
        );
        return (200, body.into_bytes(), "text/yaml; charset=utf-8");
    }
    (404, b"not found\n".to_vec(), "text/plain")
}

fn write_http(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    via: &str,
    body: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        502 => "Bad Gateway",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nX-Devpane-Via: {via}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn read_headers(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    let mut buf = [0_u8; 1024];
    loop {
        if let Some(end) =
            pending.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let rest = pending.split_off(end + 4);
            return Some(std::mem::replace(pending, rest));
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(size) => {
                pending.extend_from_slice(&buf[..size]);
                if pending.len() > 65536 {
                    return None;
                }
            }
        }
    }
}

fn request_path(head: &[u8]) -> String {
    let text = String::from_utf8_lossy(head);
    let line = text.split("\r\n").next().unwrap_or("");
    let target = line.split_whitespace().nth(1).unwrap_or("/");
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        rest.find('/')
            .map(|index| rest[index..].to_string())
            .unwrap_or_else(|| "/".into())
    } else {
        target.split('?').next().unwrap_or("/").to_string()
    }
}

fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    text.split("\r\n").find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case(name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn split_host_port(target: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port)) = target.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            if let Ok(port) = port.parse() {
                return (host.to_string(), port);
            }
        }
    }
    (target.to_string(), default_port)
}

fn split_http_target(target: &str) -> (Option<String>, u16, String) {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"));
    let Some(rest) = rest else {
        return (None, 80, target.to_string());
    };
    let default_port = if target.starts_with("https://") {
        443
    } else {
        80
    };
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let (host, port) = if let Some(host) = authority.strip_prefix('[') {
        let (host, port) = host
            .split_once("]:")
            .unwrap_or((host.trim_end_matches(']'), ""));
        (host.to_string(), port.parse().unwrap_or(default_port))
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_string(), port.parse().unwrap_or(default_port))
    } else {
        (authority.to_string(), default_port)
    };
    (Some(host), port, path)
}

fn is_lab_target(host: &str, lab_addr: Ipv4Addr) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    host == LAB_NAME || host == lab_addr.to_string()
}

fn lab_dns_response(query: &[u8], lab_addr: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let (name, offset) = decode_dns_name(query, 12)?;
    if offset + 4 > query.len()
        || !name.trim_end_matches('.').eq_ignore_ascii_case(LAB_NAME)
    {
        return None;
    }
    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let question = &query[12..offset + 4];
    let mut answer = Vec::new();
    let ancount: u16 = if qtype == 1 || qtype == 255 {
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        answer.extend_from_slice(&30_u32.to_be_bytes());
        answer.extend_from_slice(&4_u16.to_be_bytes());
        answer.extend_from_slice(&lab_addr.octets());
        1
    } else {
        0
    };
    let mut response = Vec::with_capacity(query.len() + answer.len());
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ancount.to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(question);
    response.extend_from_slice(&answer);
    Some(response)
}

// The lab bridge has no IPv6 egress. Advertising AAAA records would let the
// userspace TCP handshake succeed before the upstream IPv6 dial fails.
fn ipv4_only_dns_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let (_, offset) = decode_dns_name(query, 12)?;
    if query.get(offset..offset + 4)? != [0, 28, 0, 1] {
        return None;
    }
    let mut response = query[..offset + 4].to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    Some(response)
}

fn decode_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut jumped = false;
    for _ in 0..32 {
        if cursor >= data.len() {
            break;
        }
        let length = data[cursor] as usize;
        if length == 0 {
            cursor += 1;
            break;
        }
        if data[cursor] & 0xc0 == 0xc0 {
            if cursor + 1 >= data.len() {
                return None;
            }
            let pointer = (((data[cursor] & 0x3f) as usize) << 8)
                | data[cursor + 1] as usize;
            if !jumped {
                offset = cursor + 2;
            }
            cursor = pointer;
            jumped = true;
            continue;
        }
        cursor += 1;
        if cursor + length > data.len() {
            return None;
        }
        labels.push(
            String::from_utf8_lossy(&data[cursor..cursor + length])
                .into_owned(),
        );
        cursor += length;
    }
    Some((labels.join("."), if jumped { offset } else { cursor }))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{decode_dns_name, lab_dns_response};

    #[test]
    fn ipv4_lab_does_not_advertise_unreachable_ipv6() {
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05baidu\x03com\x00\x00\x1c\x00\x01";
        let response = super::ipv4_only_dns_response(query).unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(&response[6..12], &[0; 6]);
        assert_eq!(&response[12..], &query[12..]);
        let mut a_query = query.to_vec();
        let last = a_query.len() - 3;
        a_query[last] = 1;
        assert!(super::ipv4_only_dns_response(&a_query).is_none());
    }

    #[test]
    fn answers_lab_name() {
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07devpane\x04test\x00\x00\x01\x00\x01";
        let (name, offset) = decode_dns_name(query, 12).unwrap();
        assert_eq!(name, "devpane.test");
        assert_eq!(offset, 26);
        let response =
            lab_dns_response(query, Ipv4Addr::new(192, 0, 2, 11)).unwrap();
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 11]);
    }
}
