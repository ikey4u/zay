//! Structured runtime logging shared by Zay and managed child processes.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread,
};

use chrono::Utc;
use once_cell::sync::Lazy;
use serde::Serialize;

const LOG_QUEUE_CAPACITY: usize = 16_384;
/// All files in the runtime log directory share this on-disk budget.
pub const MAX_LOG_DIR_BYTES: u64 = 200 * 1024 * 1024;
const LOG_ROLL_BYTES: u64 = 16 * 1024 * 1024;

static WRITER: Lazy<Mutex<Option<Writer>>> = Lazy::new(|| Mutex::new(None));

#[derive(Clone)]
struct Writer {
    sender: SyncSender<LogRecord>,
}

enum LogRecord {
    Event {
        event: String,
        human: String,
    },
    SingboxRaw(String),
    #[cfg(test)]
    Flush(std::sync::mpsc::Sender<()>),
}

#[derive(Serialize)]
pub struct Event<'a> {
    pub timestamp: String,
    pub source: &'a str,
    pub level: &'a str,
    pub component: &'a str,
    pub event: &'a str,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

pub fn init(log_dir: &Path) {
    if fs::create_dir_all(log_dir).is_err() {
        return;
    }
    enforce_log_budget(log_dir, MAX_LOG_DIR_BYTES);
    let (sender, receiver) = sync_channel(LOG_QUEUE_CAPACITY);
    let paths = (
        log_dir.join("zay.log"),
        log_dir.join("events.jsonl"),
        log_dir.join("singbox.raw.log"),
    );
    thread::spawn(move || write_records(receiver, paths));
    let writer = Writer { sender };
    *WRITER.lock().expect("logging lock") = Some(writer);
}

pub fn emit(
    level: &str,
    component: &str,
    event: &str,
    message: impl AsRef<str>,
) {
    emit_with(level, component, event, message, None, BTreeMap::new());
}

pub fn emit_error(component: &str, event: &str, error: impl std::fmt::Display) {
    let error = error.to_string();
    emit_with(
        "error",
        component,
        event,
        &error,
        Some(&error),
        BTreeMap::new(),
    );
}

pub fn emit_with(
    level: &str,
    component: &str,
    event: &str,
    message: impl AsRef<str>,
    error: Option<&str>,
    fields: BTreeMap<String, String>,
) {
    emit_with_source("zay", level, component, event, message, error, fields);
}

pub fn emit_with_source(
    source: &str,
    level: &str,
    component: &str,
    event: &str,
    message: impl AsRef<str>,
    error: Option<&str>,
    fields: BTreeMap<String, String>,
) {
    let message = message.as_ref();
    let record = Event {
        timestamp: Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        source,
        level,
        component,
        event,
        message,
        error,
        fields,
    };
    let mut human = format!(
        "zay level={level} component={component:?} event={event:?} message={message:?}{}",
        error
            .map(|value| format!(" error={value:?}"))
            .unwrap_or_default()
    );
    for (key, value) in &record.fields {
        human.push_str(&format!(" {key}={value:?}"));
    }
    let Some(writer) = WRITER.lock().expect("logging lock").clone() else {
        eprintln!("{human}");
        return;
    };
    let event =
        serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_string());
    enqueue(&writer, LogRecord::Event { event, human });
}

pub fn emit_external(component: &str, level: &str, message: &str) {
    let mut fields = BTreeMap::new();
    fields.insert("source_kind".to_string(), "external".to_string());
    emit_with(level, component, "external", message, None, fields);
}

pub fn emit_singbox_raw(line: &str) {
    let Some(writer) = WRITER.lock().expect("logging lock").clone() else {
        return;
    };
    enqueue(&writer, LogRecord::SingboxRaw(line.to_string()));
}

#[cfg(test)]
pub fn flush() {
    let Some(writer) = WRITER.lock().expect("logging lock").clone() else {
        return;
    };
    let (sender, receiver) = std::sync::mpsc::channel();
    if writer.sender.send(LogRecord::Flush(sender)).is_ok() {
        let _ = receiver.recv();
    }
}

fn enqueue(writer: &Writer, record: LogRecord) {
    match writer.sender.try_send(record) {
        Ok(())
        | Err(TrySendError::Full(_))
        | Err(TrySendError::Disconnected(_)) => {}
    }
}

fn write_records(
    receiver: std::sync::mpsc::Receiver<LogRecord>,
    (log_path, event_path, raw_path): (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ),
) {
    let Some(log_dir) = log_path.parent().map(Path::to_path_buf) else {
        return;
    };
    let Ok(mut log) = RollingFile::open(log_path, log_dir.clone()) else {
        return;
    };
    let Ok(mut events) = RollingFile::open(event_path, log_dir.clone()) else {
        return;
    };
    let Ok(mut raw) = RollingFile::open(raw_path, log_dir) else {
        return;
    };
    while let Ok(record) = receiver.recv() {
        match record {
            LogRecord::Event { event, human } => {
                let _ = events.write_line(&event);
                let _ = log.write_line(&human);
            }
            LogRecord::SingboxRaw(line) => {
                let _ = raw.write_line(&line);
            }
            #[cfg(test)]
            LogRecord::Flush(done) => {
                let _ = log.flush();
                let _ = events.flush();
                let _ = raw.flush();
                let _ = done.send(());
            }
        }
    }
}

fn append_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

struct RollingFile {
    path: PathBuf,
    log_dir: PathBuf,
    file: File,
    bytes: u64,
    sequence: u64,
}

impl RollingFile {
    fn open(path: PathBuf, log_dir: PathBuf) -> std::io::Result<Self> {
        let file = append_file(&path)?;
        let bytes = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        Ok(Self {
            path,
            log_dir,
            file,
            bytes,
            sequence: 0,
        })
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let incoming = line.len() as u64 + 1;
        if self.bytes > 0
            && self.bytes.saturating_add(incoming) > LOG_ROLL_BYTES
        {
            self.rotate()?;
        }
        writeln!(self.file, "{line}")?;
        self.bytes = self.bytes.saturating_add(incoming);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.file.flush()?;
        self.sequence = self.sequence.wrapping_add(1);
        let timestamp = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("zay.log");
        let archived = self
            .log_dir
            .join(format!("{file_name}.{timestamp}.{}", self.sequence));
        fs::rename(&self.path, archived)?;
        self.file = append_file(&self.path)?;
        self.bytes = 0;
        enforce_log_budget(&self.log_dir, MAX_LOG_DIR_BYTES);
        Ok(())
    }
}

fn enforce_log_budget(log_dir: &Path, budget: u64) {
    let Ok(entries) = fs::read_dir(log_dir) else {
        return;
    };
    let active = ["zay.log", "events.jsonl", "singbox.raw.log"];
    let mut total = 0u64;
    let mut archived = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !active
            .iter()
            .any(|base| name == *base || name.starts_with(&format!("{base}.")))
        {
            continue;
        }
        total = total.saturating_add(metadata.len());
        if !active.contains(&name.as_ref()) {
            archived.push((metadata.modified().ok(), path, metadata.len()));
        }
    }
    archived.sort_by_key(|(modified, _, _)| *modified);
    for (_, path, bytes) in archived {
        if total <= budget {
            break;
        }
        if fs::remove_file(path).is_ok() {
            total = total.saturating_sub(bytes);
        }
    }
}
