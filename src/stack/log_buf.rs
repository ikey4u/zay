use std::{
    collections::{BTreeMap, VecDeque},
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::{Arc, RwLock},
};

const DEFAULT_CAPACITY: usize = 4096;

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
    raw: PathBuf,
    connections: Arc<RwLock<std::collections::HashMap<String, Connection>>>,
}

#[derive(Clone, Default)]
struct Connection {
    app: Option<String>,
    destination: Option<String>,
}

impl SingboxLogWriter {
    pub fn new(log_dir: PathBuf) -> Self {
        Self {
            raw: log_dir.join("singbox.raw.log"),
            connections: Arc::new(RwLock::new(Default::default())),
        }
    }

    fn write(&self, line: &str, buffer: &LogBuffer) {
        let clean = strip_ansi(line);
        if !clean.starts_with('+') {
            crate::logging::emit_external("singbox", "info", line);
            buffer.push(line);
            return;
        }
        append(&self.raw, &clean);
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
        if let Some(destination) = clean
            .split("inbound/")
            .nth(1)
            .and_then(|s| s.split(" connection to ").nth(1))
        {
            state.destination = Some(destination.to_string());
        }
        if let Some(id) = id.as_deref() {
            self.connections
                .write()
                .ok()
                .map(|mut m| m.insert(id.to_string(), state.clone()));
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
        } else if clean.contains("WARN") {
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
            if let Some(query) = clean
                .split(" dns: exchanged ")
                .nth(1)
                .and_then(|value| value.split_whitespace().nth(1))
            {
                fields.insert(
                    "domain".into(),
                    query.trim_end_matches('.').into(),
                );
            }
        }
        let mut human = format!(
            "proxy {kind} level={level} app={:?} dst={:?} node={:?}",
            state.app.as_deref().unwrap_or("-"),
            state.destination.as_deref().unwrap_or("-"),
            node.unwrap_or("-"),
        );
        if let Some(error) = error.as_deref() {
            human.push_str(&format!(" error={error:?}"));
        }
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
}

pub fn pipe_singbox_to_buffer(
    stream: impl std::io::Read + Send + 'static,
    buffer: LogBuffer,
    writer: SingboxLogWriter,
) {
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        for line in BufReader::new(stream).lines() {
            match line {
                Ok(line) => writer.write(&line, &buffer),
                Err(_) => break,
            }
        }
    });
}

fn append(path: &PathBuf, line: &str) {
    if let Ok(mut file) =
        OpenOptions::new().create(true).append(true).open(path)
    {
        let _ = writeln!(file, "{line}");
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
    let mut escape = false;
    for c in input.chars() {
        if escape {
            if c == 'm' {
                escape = false;
            }
            continue;
        }
        if c == '\u{1b}' {
            escape = true;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn captures_connection_context() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = std::env::temp_dir()
            .join(format!("zay-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::logging::init(&dir);
        let writer = SingboxLogWriter::new(dir.clone());
        let buffer = LogBuffer::with_default_capacity();
        writer.write("+0800 2026-07-26 00:01:56 INFO [12 0ms] inbound/tun[tun-in]: inbound connection to chatgpt.com:443", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [12 1ms] router: found process path: /Applications/Google Chrome.app/Chrome, user: m9", &buffer);
        writer.write("+0800 2026-07-26 00:01:56 INFO [12 170ms] outbound/vless[sg-1]: outbound connection to chatgpt.com:443", &buffer);
        let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(
            events
                .contains("\"app\":\"/Applications/Google Chrome.app/Chrome\"")
        );
        assert!(events.contains("\"destination\":\"chatgpt.com:443\""));
        assert!(events.contains("\"node\":\"sg-1\""));
    }

    #[test]
    fn error_events_preserve_the_node_and_error_reason() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = std::env::temp_dir()
            .join(format!("zay-log-error-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::logging::init(&dir);
        let writer = SingboxLogWriter::new(dir.clone());
        writer.write("+0800 2026-07-26 00:13:08 ERROR [12 49ms] connection: open connection to 119.123.48.215:17957 using outbound/direct[direct]: dial tcp 119.123.48.215:17957: connect: connection refused", &LogBuffer::with_default_capacity());
        let event = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(event.contains("\"event\":\"connection_refused\""));
        assert!(event.contains("\"node\":\"direct\""));
        assert!(event.contains("\"error\":\"connection refused\""));
    }
}
