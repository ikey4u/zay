//! Structured runtime logging shared by Zay and managed child processes.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
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
    let human = format!(
        "zay level={level} component={component:?} event={event:?} message={message:?}{}",
        error
            .map(|value| format!(" error={value:?}"))
            .unwrap_or_default()
    );
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
    let Ok(mut log) = append_file(&log_path) else {
        return;
    };
    let Ok(mut events) = append_file(&event_path) else {
        return;
    };
    let Ok(mut raw) = append_file(&raw_path) else {
        return;
    };
    while let Ok(record) = receiver.recv() {
        match record {
            LogRecord::Event { event, human } => {
                let _ = writeln!(events, "{event}");
                let _ = writeln!(log, "{human}");
            }
            LogRecord::SingboxRaw(line) => {
                let _ = writeln!(raw, "{line}");
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
