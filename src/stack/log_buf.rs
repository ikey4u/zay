use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const DEFAULT_CAPACITY: usize = 4096;
const MAX_DNS_MAP: usize = 4096;
const MIN_DNS_TTL_SECS: u64 = 60;
const MAX_DNS_TTL_SECS: u64 = 3600;
const MAX_DOMAINS_PER_IP: usize = 8;

#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<RwLock<VecDeque<String>>>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(VecDeque::new())),
            capacity: capacity.max(64),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    pub fn push(&self, line: impl Into<String>) {
        let mut guard = self.inner.write().expect("log buffer lock");
        guard.push_back(line.into());
        while guard.len() > self.capacity {
            guard.pop_front();
        }
    }
}

pub fn pipe_to_buffer(
    stream: impl std::io::Read + Send + 'static,
    buffer: LogBuffer,
) {
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        for line in BufReader::new(stream).lines() {
            match line {
                Ok(line) => {
                    eprintln!("{line}");
                    buffer.push(line);
                }
                Err(_) => break,
            }
        }
    });
}

#[derive(Clone)]
pub struct SingboxLogWriter {
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    domains_by_ip: Arc<RwLock<HashMap<String, IpDomains>>>,
    /// Per DNS connection-id: names seen in the CNAME/A chain for this lookup.
    /// First entry is the original query name.
    dns_chains: Arc<RwLock<HashMap<String, VecDeque<String>>>>,
}

#[derive(Clone)]
struct IpDomains {
    domains: VecDeque<String>,
    expires: Instant,
}

#[derive(Clone, Default)]
struct Connection {
    app: Option<String>,
    destination: Option<String>,
    domain: Option<String>,
}

impl SingboxLogWriter {
    pub fn new(_log_dir: std::path::PathBuf) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            domains_by_ip: Arc::new(RwLock::new(HashMap::new())),
            dns_chains: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn write(&self, line: &str, buffer: &LogBuffer) {
        let clean = strip_ansi(line);
        if !clean.starts_with('+') {
            crate::logging::emit_external("singbox", "info", &clean);
            buffer.push(clean);
            return;
        }
        crate::logging::emit_singbox_raw(&clean);
        let id = connection_id(&clean);
        let mut state = id
            .as_deref()
            .and_then(|id| self.connections.read().ok()?.get(id).cloned())
            .unwrap_or_default();
        if let Some((_, value)) =
            clean.split_once("router: found process path: ")
        {
            let path =
                value.split(", user:").next().unwrap_or(value).to_string();
            state.app = Some(path);
        }
        if let Some(destination) = extract_destination(&clean) {
            state.destination = Some(destination.to_string());
            if let Some(domain) = domain_from_destination(destination) {
                state.domain = Some(domain);
            } else if state.domain.is_none() {
                // DNS IP correlation is only a hint: CDN IPs are routinely
                // shared by unrelated hosts, so it cannot be authoritative.
                state.domain = None;
            }
        }
        if let Some(id) = id.as_deref() {
            if let Ok(mut map) = self.connections.write() {
                map.insert(id.to_string(), state.clone());
                while map.len() > DEFAULT_CAPACITY {
                    if let Some(key) = map.keys().next().cloned() {
                        map.remove(&key);
                    } else {
                        break;
                    }
                }
            }
        }
        let (mut kind, node) = if clean.contains(" ERROR ") {
            (
                "error",
                clean
                    .split("outbound/")
                    .nth(1)
                    .and_then(|s| s.split('[').nth(1))
                    .and_then(|s| s.split(']').next()),
            )
        } else if clean.contains(" dns: ") {
            ("dns", None)
        } else if clean.contains("outbound/") {
            let node = clean
                .split("outbound/")
                .nth(1)
                .and_then(|s| s.split('[').nth(1))
                .and_then(|s| s.split(']').next());
            ("connection", node)
        } else if clean.contains(" WARN ") {
            ("warning", None)
        } else {
            ("singbox", None)
        };
        let level = if clean.contains(" ERROR ") {
            "error"
        } else if clean.contains(" WARN ") {
            "warn"
        } else {
            "info"
        };
        let error = (kind == "error").then(|| error_message(&clean));
        if let Some(error) = error.as_deref() {
            kind = error_event(error);
        }
        let mut fields = BTreeMap::new();
        if let Some(id) = id.as_deref() {
            fields.insert("connection".into(), id.into());
        }
        if let Some(app) = state.app.as_deref() {
            fields.insert("app".into(), app.into());
        }
        if let Some(destination) = state.destination.as_deref() {
            fields.insert("destination".into(), destination.into());
        }
        if let Some(node) = node {
            fields.insert("node".into(), node.into());
        }
        if kind == "dns" {
            if let Some(parsed) = parse_dns_line(&clean) {
                fields.insert("domain".into(), parsed.domain.clone());
                fields.insert("domain_source".into(), "dns".into());
                if let Some(id) = id.as_deref() {
                    self.remember_dns_name(id, &parsed.domain);
                    if let Some(target) = parsed.cname_target.as_deref() {
                        self.remember_dns_name(id, target);
                    }
                }
                if let Some(answer) = parsed.answer.as_deref() {
                    let mut names = id
                        .as_deref()
                        .map(|id| self.dns_names_for(id))
                        .unwrap_or_default();
                    if names.is_empty() {
                        names.push(parsed.domain.clone());
                    }
                    for name in names {
                        self.remember_dns_answer(&name, answer, parsed.ttl);
                    }
                }
            }
        } else if let Some(domain) = state.domain.as_deref() {
            fields.insert("domain".into(), domain.into());
            fields.insert("domain_source".into(), "destination".into());
        } else if let Some(destination) = state.destination.as_deref() {
            if let Some(aliases) = self.domains_for_destination(destination) {
                // Preserve correlation for diagnostics, but filters must not
                // mistake it for direct evidence of this connection.
                fields.insert("dns_domains".into(), aliases.join(","));
            }
        }
        let human = format!(
            "proxy {kind} level={level} app={:?} dst={:?} domain={:?} node={:?}{}",
            state.app.as_deref().unwrap_or("-"),
            state.destination.as_deref().unwrap_or("-"),
            fields.get("domain").map(String::as_str).unwrap_or("-"),
            node.unwrap_or("-"),
            error
                .as_deref()
                .map(|value| format!(" error={value:?}"))
                .unwrap_or_default()
        );
        crate::logging::emit_with_source(
            "singbox",
            level,
            "proxy",
            kind,
            &clean,
            error.as_deref(),
            fields,
        );
        buffer.push(human);
    }

    fn remember_dns_name(&self, connection_id: &str, domain: &str) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return;
        }
        let Ok(mut chains) = self.dns_chains.write() else {
            return;
        };
        let entry = chains.entry(connection_id.to_string()).or_default();
        if !entry.iter().any(|name| name == &domain) {
            entry.push_back(domain);
        }
        while chains.len() > DEFAULT_CAPACITY {
            if let Some(key) = chains.keys().next().cloned() {
                chains.remove(&key);
            } else {
                break;
            }
        }
    }

    fn dns_names_for(&self, connection_id: &str) -> Vec<String> {
        self.dns_chains
            .read()
            .ok()
            .and_then(|chains| {
                chains
                    .get(connection_id)
                    .map(|names| names.iter().cloned().collect::<Vec<_>>())
            })
            .unwrap_or_default()
    }

    fn remember_dns_answer(&self, domain: &str, answer: &str, ttl: u64) {
        if answer.parse::<IpAddr>().is_err() {
            return;
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return;
        }
        let ttl = ttl.clamp(MIN_DNS_TTL_SECS, MAX_DNS_TTL_SECS);
        let now = Instant::now();
        let Ok(mut domains) = self.domains_by_ip.write() else {
            return;
        };
        domains.retain(|_, entry| entry.expires > now);
        while domains.len() >= MAX_DNS_MAP {
            if let Some(key) = domains.keys().next().cloned() {
                domains.remove(&key);
            } else {
                break;
            }
        }
        let entry =
            domains
                .entry(answer.to_string())
                .or_insert_with(|| IpDomains {
                    domains: VecDeque::new(),
                    expires: now + Duration::from_secs(ttl),
                });
        entry.expires = entry.expires.max(now + Duration::from_secs(ttl));
        if !entry.domains.iter().any(|name| name == &domain) {
            entry.domains.push_back(domain);
            while entry.domains.len() > MAX_DOMAINS_PER_IP {
                entry.domains.pop_front();
            }
        }
    }

    fn domain_for_destination(&self, destination: &str) -> Option<String> {
        self.domains_for_destination(destination)
            .and_then(|names| names.into_iter().next())
    }

    fn domains_for_destination(
        &self,
        destination: &str,
    ) -> Option<Vec<String>> {
        let host = destination_host(destination)?;
        let now = Instant::now();
        let mut domains = self.domains_by_ip.write().ok()?;
        domains.retain(|_, entry| entry.expires > now);
        domains
            .get(host)
            .map(|entry| entry.domains.iter().cloned().collect())
    }
}

pub fn pipe_singbox_to_buffer(
    stream: impl std::io::Read + Send + 'static,
    buffer: LogBuffer,
    writer: SingboxLogWriter,
) {
    std::thread::spawn(move || {
        frame_stream(stream, |line| writer.write(&line, &buffer));
    });
}

/// Drain a child pipe without relying on UTF-8 or newline-only framing.
/// A malformed or progress-style child output must never stop draining and
/// backpressure the networking process.
fn frame_stream(
    mut stream: impl std::io::Read,
    mut on_line: impl FnMut(String),
) {
    const MAX_FRAME: usize = 64 * 1024;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = match std::io::Read::read(&mut stream, &mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        for byte in &chunk[..count] {
            if *byte == b'\n' || *byte == b'\r' {
                if !bytes.is_empty() {
                    on_line(String::from_utf8_lossy(&bytes).into_owned());
                    bytes.clear();
                }
            } else {
                bytes.push(*byte);
                if bytes.len() >= MAX_FRAME {
                    on_line(format!(
                        "{} [truncated]",
                        String::from_utf8_lossy(&bytes)
                    ));
                    bytes.clear();
                }
            }
        }
    }
    if !bytes.is_empty() {
        on_line(String::from_utf8_lossy(&bytes).into_owned());
    }
}

fn connection_id(line: &str) -> Option<String> {
    let open = line.find('[')?;
    let close = line[open..].find(']')? + open;
    line[open + 1..close]
        .split_whitespace()
        .next()
        .filter(|id| id.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_owned)
}

fn extract_destination(line: &str) -> Option<&str> {
    for marker in [
        " inbound connection to ",
        " inbound packet connection to ",
        " outbound connection to ",
        " outbound packet connection to ",
        " open connection to ",
    ] {
        if let Some((_, rest)) = line.split_once(marker) {
            let text = rest
                .split(" using ")
                .next()
                .unwrap_or(rest)
                .trim_end_matches(|c: char| c == '.' || c.is_whitespace());
            let text = text.split_whitespace().next().unwrap_or(text);
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn domain_from_destination(destination: &str) -> Option<String> {
    let host = destination_host(destination)?;
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn destination_host(destination: &str) -> Option<&str> {
    let destination = destination.trim();
    if let Some(rest) = destination.strip_prefix('[') {
        return rest.split(']').next();
    }
    // host:port for IPv4/domain; leave bare IPv6 without brackets alone.
    if destination.matches(':').count() == 1 {
        return Some(
            destination
                .rsplit_once(':')
                .map_or(destination, |(host, _)| host),
        );
    }
    Some(destination)
}

struct DnsParsed {
    domain: String,
    cname_target: Option<String>,
    answer: Option<String>,
    ttl: u64,
}

fn parse_dns_line(line: &str) -> Option<DnsParsed> {
    let body = line
        .split(" dns: exchanged ")
        .nth(1)
        .or_else(|| line.split(" dns: cached ").nth(1))?;
    let mut parts = body.split_whitespace();
    let rr = parts.next()?.to_ascii_uppercase();
    let domain = parts.next()?.trim_end_matches('.').to_ascii_lowercase();
    let ttl = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300);
    let _class = parts.next();
    let _type = parts.next();
    let remainder: Vec<&str> = parts.collect();
    let last = remainder.last().copied();
    let answer = last
        .filter(|value| value.parse::<IpAddr>().is_ok())
        .map(|value| value.to_string());
    let cname_target = if rr == "CNAME" {
        last.map(|value| value.trim_end_matches('.').to_ascii_lowercase())
    } else {
        None
    };
    Some(DnsParsed {
        domain,
        cname_target,
        answer,
        ttl,
    })
}

fn error_message(line: &str) -> String {
    line.rsplit(": ").next().unwrap_or(line).to_string()
}

fn error_event(error: &str) -> &'static str {
    let error = error.to_ascii_lowercase();
    if error.contains("connection refused") {
        "connection_refused"
    } else if error.contains("timed out") || error.contains("timeout") {
        "connection_timeout"
    } else if error.contains("eof") {
        "connection_eof"
    } else if error.contains("network is unreachable") {
        "network_unreachable"
    } else if error.contains("no such host") || error.contains("dns") {
        "dns_failed"
    } else {
        "connection_failed"
    }
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            if !c.is_control() || c == '\t' {
                out.push(c);
            }
            continue;
        }
        match chars.next() {
            Some('[') => {
                // CSI ends at a byte in 0x40..=0x7e, not just `m`.
                while let Some(next) = chars.next() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                // OSC ends at BEL or ST (ESC \).
                let mut escape_seen = false;
                while let Some(next) = chars.next() {
                    if next == '\u{7}' || (escape_seen && next == '\\') {
                        break;
                    }
                    escape_seen = next == '\u{1b}';
                }
            }
            Some(_) | None => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Mutex};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn frames_invalid_utf8_cr_and_unterminated_output() {
        let mut frames = Vec::new();
        frame_stream(Cursor::new(b"one\r\xfftwo\nthree".to_vec()), |line| {
            frames.push(line)
        });
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], "one");
        assert!(frames[1].contains("two"));
        assert_eq!(frames[2], "three");
    }

    #[test]
    fn strips_csi_and_osc_sequences() {
        assert_eq!(
            strip_ansi("\u{1b}[31mERROR\u{1b}[0m \u{1b}]title\u{7}ok"),
            "ERROR ok"
        );
    }

    #[test]
    fn captures_connection_context() {
        let _guard =
            TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = std::env::temp_dir()
            .join(format!("zay-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::logging::init(&dir);
        let writer = SingboxLogWriter::new(dir.clone());
        let buffer = LogBuffer::with_default_capacity();
        writer.write("+0800 2026-07-26 00:01:56 INFO [12 0ms] inbound/tun[tun-in]: inbound connection to chatgpt.com:443", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [12 1ms] router: found process path: /Applications/Google Chrome.app/Chrome, user: user", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [12 170ms] outbound/vless[sg-1]: outbound connection to chatgpt.com:443", &buffer);
        crate::logging::flush();
        let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(
            events
                .contains("\"app\":\"/Applications/Google Chrome.app/Chrome\"")
        );
        assert!(events.contains("\"destination\":\"chatgpt.com:443\""));
        assert!(events.contains("\"domain\":\"chatgpt.com\""));
        assert!(events.contains("\"node\":\"sg-1\""));
    }

    #[test]
    fn dns_ip_correlation_is_diagnostic_not_connection_evidence() {
        let _guard =
            TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = std::env::temp_dir()
            .join(format!("zay-log-dns-map-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::logging::init(&dir);
        let writer = SingboxLogWriter::new(dir.clone());
        let buffer = LogBuffer::with_default_capacity();
        writer.write("+0800 2026-07-26 00:01:56 INFO [1 10ms] dns: exchanged A api2.cursor.sh. 30 IN A 54.174.13.26", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [2 0ms] inbound/tun[tun-in]: inbound connection to 54.174.13.26:443", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [2 1ms] router: found process path: /home/user/.local/share/cursor-agent/versions/x/node, user: user", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [2 2ms] outbound/vless[sg-1]: outbound connection to 54.174.13.26:443", &buffer);
        crate::logging::flush();
        let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(events.contains("\"event\":\"connection\""));
        assert!(events.contains("\"dns_domains\":\"api2.cursor.sh\""));
        assert!(events.contains("cursor-agent"));
    }

    #[test]
    fn cname_chain_keeps_original_query_name_on_ip() {
        let _guard =
            TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = std::env::temp_dir()
            .join(format!("zay-log-cname-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::logging::init(&dir);
        let writer = SingboxLogWriter::new(dir.clone());
        let buffer = LogBuffer::with_default_capacity();
        writer.write("+0800 2026-07-26 00:01:56 INFO [9 1ms] dns: exchanged CNAME api2.cursor.sh. 30 IN CNAME api2geo.cursor.sh.", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [9 1ms] dns: exchanged CNAME api2geo.cursor.sh. 30 IN CNAME api2direct.cursor.sh.", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [9 1ms] dns: exchanged A api2direct.cursor.sh. 30 IN A 54.174.13.26", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [10 0ms] inbound/tun[tun-in]: inbound connection to 54.174.13.26:443", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [10 1ms] outbound/vless[sg-1]: outbound connection to 54.174.13.26:443", &buffer);
        crate::logging::flush();
        let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        let connection_lines: Vec<_> = events
            .lines()
            .filter(|line| line.contains("\"event\":\"connection\""))
            .collect();
        assert!(!connection_lines.is_empty());
        assert!(
            connection_lines
                .iter()
                .any(|line| line.contains("\"dns_domains\""))
        );
        assert_eq!(
            writer.domain_for_destination("54.174.13.26:443").as_deref(),
            Some("api2.cursor.sh")
        );
        let mapped =
            writer.domains_for_destination("54.174.13.26:443").unwrap();
        assert!(mapped.contains(&"api2.cursor.sh".to_string()));
        assert!(mapped.contains(&"api2direct.cursor.sh".to_string()));
    }

    #[test]
    fn error_events_preserve_the_node_and_error_reason() {
        let _guard =
            TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = std::env::temp_dir()
            .join(format!("zay-log-error-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::logging::init(&dir);
        let writer = SingboxLogWriter::new(dir.clone());
        writer.write(
            "+0800 2026-07-26 00:13:08 ERROR [12 49ms] connection: open connection to 119.123.48.215:17957 using outbound/direct[direct]: dial tcp 119.123.48.215:17957: connect: connection refused",
            &LogBuffer::with_default_capacity(),
        );
        crate::logging::flush();
        let event = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(event.contains("\"event\":\"connection_refused\""));
        assert!(event.contains("\"node\":\"direct\""));
        assert!(event.contains("\"error\":\"connection refused\""));
    }
}
