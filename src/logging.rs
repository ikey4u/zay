//! Structured runtime logging shared by Zay and managed child processes.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::Mutex,
};

use chrono::Utc;
use once_cell::sync::Lazy;
use serde::Serialize;

static WRITER: Lazy<Mutex<Option<Writer>>> = Lazy::new(|| Mutex::new(None));

#[derive(Clone)]
struct Writer {
    log: std::path::PathBuf,
    events: std::path::PathBuf,
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
    let writer = Writer {
        log: log_dir.join("zay.log"),
        events: log_dir.join("events.jsonl"),
    };
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
    append(
        &writer.events,
        &serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_string()),
    );
    append(&writer.log, &human);
}

pub fn emit_external(component: &str, level: &str, message: &str) {
    let mut fields = BTreeMap::new();
    fields.insert("source_kind".to_string(), "external".to_string());
    emit_with(level, component, "external", message, None, fields);
}

fn append(path: &Path, text: &str) {
    if let Ok(mut file) =
        OpenOptions::new().create(true).append(true).open(path)
    {
        let _ = writeln!(file, "{text}");
    }
}
