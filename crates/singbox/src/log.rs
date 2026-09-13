//! Native logging factory matching sing-box's levels, formatting and tagged
//! logger model.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tokio::sync::mpsc;

use crate::option::LogOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Panic,
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    pub fn parse(value: &str) -> Result<Self, LogError> {
        match value {
            "panic" => Ok(Self::Panic),
            "fatal" => Ok(Self::Fatal),
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(LogError::UnknownLevel(value.to_owned())),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::Fatal => "fatal",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("unknown log level: {0}")]
    UnknownLevel(String),
    #[error("open log output {path:?}: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("write log output: {0}")]
    Write(#[from] io::Error),
    #[error("observable logging is disabled")]
    NotObservable,
}

#[derive(Debug, Clone, Copy)]
pub struct LogId {
    pub id: u32,
    pub created_at: Instant,
}

impl LogId {
    pub fn new() -> Self {
        let mut bytes = [0_u8; 4];
        let _ = getrandom::fill(&mut bytes);
        Self {
            id: u32::from_ne_bytes(bytes),
            created_at: Instant::now(),
        }
    }
}

impl Default for LogId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub level: Level,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Formatter {
    base_time: SystemTime,
    base_instant: Instant,
    pub disable_colors: bool,
    pub disable_timestamp: bool,
    pub full_timestamp: bool,
    pub disable_line_break: bool,
}

impl Default for Formatter {
    fn default() -> Self {
        Self {
            base_time: SystemTime::now(),
            base_instant: Instant::now(),
            disable_colors: false,
            disable_timestamp: false,
            full_timestamp: false,
            disable_line_break: false,
        }
    }
}

impl Formatter {
    pub fn format(
        &self,
        level: Level,
        tag: &str,
        message: &str,
        timestamp: SystemTime,
        id: Option<&LogId>,
    ) -> String {
        let mut output = String::with_capacity(tag.len() + message.len() + 64);
        self.write_prefix(&mut output, level, timestamp);
        if let Some(id) = id {
            self.write_id_prefix(&mut output, id);
        }
        if !tag.is_empty() {
            output.push_str(tag);
            output.push_str(": ");
        }
        if self.disable_line_break {
            output.push_str(message.strip_suffix('\n').unwrap_or(message));
        } else {
            output.push_str(message);
            if !message.ends_with('\n') {
                output.push('\n');
            }
        }
        output
    }

    pub fn format_simple(
        &self,
        tag: &str,
        message: &str,
        id: Option<&LogId>,
    ) -> String {
        if id.is_none() && tag.is_empty() {
            return message.to_owned();
        }
        let mut output = String::with_capacity(tag.len() + message.len() + 32);
        if let Some(id) = id {
            output.push('[');
            output.push_str(&id.id.to_string());
            output.push(' ');
            output.push_str(&format_duration(id.created_at.elapsed()));
            output.push_str("] ");
        }
        if !tag.is_empty() {
            output.push_str(tag);
            output.push_str(": ");
        }
        output.push_str(message);
        output
    }

    fn write_prefix(
        &self,
        output: &mut String,
        level: Level,
        timestamp: SystemTime,
    ) {
        let label = level.as_str().to_ascii_uppercase();
        let label = if self.disable_colors {
            label
        } else {
            let color = match level {
                Level::Trace | Level::Debug => 37,
                Level::Info => 36,
                Level::Warn => 33,
                Level::Error | Level::Fatal | Level::Panic => 31,
            };
            format!("\x1b[{color}m{label}\x1b[0m")
        };
        if self.disable_timestamp {
            output.push_str(&label);
            output.push(' ');
        } else if self.full_timestamp {
            output.push_str(&format_timestamp(timestamp));
            output.push(' ');
            output.push_str(&label);
            output.push(' ');
        } else {
            let elapsed = timestamp
                .duration_since(self.base_time)
                .unwrap_or_else(|_| self.base_instant.elapsed());
            output.push_str(&label);
            output.push('[');
            output.push_str(&format!("{:04}", elapsed.as_secs()));
            output.push_str("] ");
        }
    }

    fn write_id_prefix(&self, output: &mut String, id: &LogId) {
        output.push('[');
        if self.disable_colors {
            output.push_str(&id.id.to_string());
        } else {
            output.push_str("\x1b[38;5;");
            output.push_str(&color_for_id(id.id).to_string());
            output.push('m');
            output.push_str(&id.id.to_string());
            output.push_str("\x1b[0m");
        }
        output.push(' ');
        output.push_str(&format_duration(id.created_at.elapsed()));
        output.push_str("] ");
    }
}

fn format_timestamp(timestamp: SystemTime) -> String {
    const FORMAT: &[time::format_description::FormatItem<'static>] = format_description!(
        "[offset_hour sign:mandatory][offset_minute] [year]-[month]-[day] [hour]:[minute]:[second]"
    );
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    OffsetDateTime::from(timestamp)
        .to_offset(offset)
        .format(FORMAT)
        .unwrap_or_default()
}

pub fn format_duration(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        format!("{}ms", duration.as_millis())
    } else if duration < Duration::from_secs(60) {
        format!(
            "{}.{:02}s",
            duration.as_secs(),
            duration.subsec_millis() / 10
        )
    } else {
        format!("{}m{}s", duration.as_secs() / 60, duration.as_secs() % 60)
    }
}

fn color_for_id(value: u32) -> u8 {
    let mut color = (value % 215) as u8;
    let mut row = u32::from(color / 36);
    let mut column = u32::from(color % 36);
    let red = (row * 51) as f32;
    let green = (column / 6 * 51) as f32;
    let blue = (column % 6 * 51) as f32;
    if 0.2126 * red + 0.7152 * green + 0.0722 * blue < 60.0 {
        row = 5 - row;
        column = 35 - column;
        color = (row * 36 + column) as u8;
    }
    color + 16
}

pub trait PlatformWriter: Send + Sync {
    fn write_message(&self, level: Level, message: &str);
}

enum Destination {
    Stderr,
    Stdout,
    File(File),
    #[cfg(test)]
    Buffer(Arc<Mutex<Vec<u8>>>),
    Discard,
}

impl Destination {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Stderr => io::stderr().write_all(data),
            Self::Stdout => io::stdout().write_all(data),
            Self::File(file) => file.write_all(data),
            #[cfg(test)]
            Self::Buffer(buffer) => buffer
                .lock()
                .map_err(|_| io::Error::other("log buffer lock poisoned"))?
                .write_all(data),
            Self::Discard => Ok(()),
        }
    }
}

struct PendingEntry {
    level: Level,
    tag: String,
    message: String,
    timestamp: SystemTime,
    id: Option<LogId>,
}

struct FactoryState {
    destination: Destination,
    output_path: Option<PathBuf>,
    pending: Vec<PendingEntry>,
}

pub struct Factory {
    formatter: Formatter,
    platform_formatter: Formatter,
    state: Mutex<FactoryState>,
    level: AtomicU8,
    started: AtomicBool,
    disabled: bool,
    observable: bool,
    subscribers: Mutex<Vec<mpsc::Sender<Entry>>>,
    platform_writers: Mutex<Vec<Arc<dyn PlatformWriter>>>,
}

impl Factory {
    pub fn new(
        options: &LogOptions,
        observable: bool,
    ) -> Result<Arc<Self>, LogError> {
        let output_path = match options.output.as_str() {
            "" | "stderr" | "stdout" => None,
            path => Some(PathBuf::from(path)),
        };
        let destination = match options.output.as_str() {
            "" | "stderr" => Destination::Stderr,
            "stdout" => Destination::Stdout,
            _ => Destination::Discard,
        };
        let level = if options.level.is_empty() {
            Level::Trace
        } else {
            Level::parse(&options.level)?
        };
        let formatter = Formatter {
            disable_colors: output_path.is_some(),
            disable_timestamp: output_path.is_some() && !options.timestamp,
            full_timestamp: options.timestamp,
            ..Formatter::default()
        };
        Ok(Arc::new(Self {
            platform_formatter: Formatter {
                disable_line_break: true,
                ..Formatter::default()
            },
            formatter,
            state: Mutex::new(FactoryState {
                destination,
                output_path,
                pending: Vec::new(),
            }),
            level: AtomicU8::new(level as u8),
            started: AtomicBool::new(false),
            disabled: options.disabled,
            observable,
            subscribers: Mutex::new(Vec::new()),
            platform_writers: Mutex::new(Vec::new()),
        }))
    }

    #[cfg(test)]
    fn with_buffer(
        options: &LogOptions,
        observable: bool,
        buffer: Arc<Mutex<Vec<u8>>>,
    ) -> Result<Arc<Self>, LogError> {
        let factory = Self::new(options, observable)?;
        factory
            .state
            .lock()
            .expect("log state poisoned")
            .destination = Destination::Buffer(buffer);
        Ok(factory)
    }

    pub fn start(&self) -> Result<(), LogError> {
        let pending = {
            let mut state = self.state.lock().expect("log state poisoned");
            if let Some(path) = &state.output_path {
                state.destination = Destination::File(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .map_err(|source| LogError::Open {
                            path: path.clone(),
                            source,
                        })?,
                );
            }
            self.started.store(true, Ordering::Release);
            std::mem::take(&mut state.pending)
        };
        for entry in pending {
            self.output(entry)?;
        }
        Ok(())
    }

    pub fn close(&self) -> Result<(), LogError> {
        let mut state = self.state.lock().expect("log state poisoned");
        state.pending.clear();
        if let Destination::File(file) = &mut state.destination {
            file.flush()?;
        }
        self.started.store(false, Ordering::Release);
        Ok(())
    }

    pub fn level(&self) -> Level {
        match self.level.load(Ordering::Relaxed) {
            0 => Level::Panic,
            1 => Level::Fatal,
            2 => Level::Error,
            3 => Level::Warn,
            4 => Level::Info,
            5 => Level::Debug,
            _ => Level::Trace,
        }
    }

    pub fn set_level(&self, level: Level) {
        self.level.store(level as u8, Ordering::Relaxed);
    }

    pub fn logger(self: &Arc<Self>) -> Logger {
        self.new_logger("")
    }

    pub fn new_logger(self: &Arc<Self>, tag: impl Into<String>) -> Logger {
        Logger {
            factory: self.clone(),
            tag: tag.into(),
        }
    }

    pub fn subscribe(&self) -> Result<mpsc::Receiver<Entry>, LogError> {
        if self.disabled || !self.observable {
            return Err(LogError::NotObservable);
        }
        let (sender, receiver) = mpsc::channel(128);
        self.subscribers
            .lock()
            .expect("log subscribers poisoned")
            .push(sender);
        Ok(receiver)
    }

    pub fn attach_platform_writer(&self, writer: Arc<dyn PlatformWriter>) {
        self.platform_writers
            .lock()
            .expect("platform writers poisoned")
            .push(writer);
    }

    fn log(
        &self,
        level: Level,
        tag: &str,
        message: String,
        id: Option<LogId>,
    ) -> Result<(), LogError> {
        if self.disabled {
            return Ok(());
        }
        let entry = PendingEntry {
            level,
            tag: tag.to_owned(),
            message,
            timestamp: SystemTime::now(),
            id,
        };
        if !self.started.load(Ordering::Acquire)
            && !matches!(level, Level::Fatal | Level::Panic)
        {
            self.state
                .lock()
                .expect("log state poisoned")
                .pending
                .push(entry);
            return Ok(());
        }
        self.output(entry)
    }

    fn output(&self, entry: PendingEntry) -> Result<(), LogError> {
        if entry.level <= self.level() {
            let message = self.formatter.format(
                entry.level,
                &entry.tag,
                &entry.message,
                entry.timestamp,
                entry.id.as_ref(),
            );
            self.state
                .lock()
                .expect("log state poisoned")
                .destination
                .write_all(message.as_bytes())?;
        }
        if self.observable {
            let event = Entry {
                level: entry.level,
                message: self.formatter.format_simple(
                    &entry.tag,
                    &entry.message,
                    entry.id.as_ref(),
                ),
            };
            let mut subscribers =
                self.subscribers.lock().expect("log subscribers poisoned");
            subscribers.retain(|subscriber| {
                match subscriber.try_send(event.clone()) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                }
            });
        }
        let platform_message = self.platform_formatter.format(
            entry.level,
            &entry.tag,
            &entry.message,
            entry.timestamp,
            entry.id.as_ref(),
        );
        for writer in self
            .platform_writers
            .lock()
            .expect("platform writers poisoned")
            .iter()
        {
            writer.write_message(entry.level, &platform_message);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Logger {
    factory: Arc<Factory>,
    tag: String,
}

impl Logger {
    pub fn log(
        &self,
        level: Level,
        message: impl Into<String>,
    ) -> Result<(), LogError> {
        self.factory.log(level, &self.tag, message.into(), None)
    }

    pub fn log_with_id(
        &self,
        level: Level,
        id: LogId,
        message: impl Into<String>,
    ) -> Result<(), LogError> {
        self.factory.log(level, &self.tag, message.into(), Some(id))
    }

    pub fn trace(&self, message: impl Into<String>) -> Result<(), LogError> {
        self.log(Level::Trace, message)
    }

    pub fn debug(&self, message: impl Into<String>) -> Result<(), LogError> {
        self.log(Level::Debug, message)
    }

    pub fn info(&self, message: impl Into<String>) -> Result<(), LogError> {
        self.log(Level::Info, message)
    }

    pub fn warn(&self, message: impl Into<String>) -> Result<(), LogError> {
        self.log(Level::Warn, message)
    }

    pub fn error(&self, message: impl Into<String>) -> Result<(), LogError> {
        self.log(Level::Error, message)
    }

    pub fn fatal(&self, message: impl Into<String>) -> ! {
        let _ = self.log(Level::Fatal, message);
        std::process::exit(1)
    }

    pub fn panic(&self, message: impl Into<String>) -> ! {
        let message = message.into();
        let _ = self.log(Level::Panic, message.clone());
        panic!("{message}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_match_upstream_names_and_order() {
        assert_eq!(Level::parse("warning").unwrap(), Level::Warn);
        assert!(Level::Error < Level::Info);
        assert!(Level::parse("verbose").is_err());
    }

    #[test]
    fn duration_format_matches_upstream_boundaries() {
        assert_eq!(format_duration(Duration::from_millis(17)), "17ms");
        assert_eq!(format_duration(Duration::from_millis(1_234)), "1.23s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m5s");
    }

    #[tokio::test]
    async fn factory_buffers_before_start_filters_and_publishes() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let options = LogOptions {
            level: "info".into(),
            ..LogOptions::default()
        };
        let factory =
            Factory::with_buffer(&options, true, buffer.clone()).unwrap();
        let logger = factory.new_logger("route");
        let mut subscription = factory.subscribe().unwrap();
        logger.debug("hidden").unwrap();
        logger.info("ready").unwrap();
        assert!(buffer.lock().unwrap().is_empty());
        factory.start().unwrap();
        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("hidden"));
        assert!(output.contains("route: ready"));
        assert_eq!(subscription.recv().await.unwrap().message, "route: hidden");
        assert_eq!(subscription.recv().await.unwrap().message, "route: ready");
    }

    #[test]
    fn disabled_factory_is_a_nop() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let factory = Factory::with_buffer(
            &LogOptions {
                disabled: true,
                ..LogOptions::default()
            },
            false,
            buffer.clone(),
        )
        .unwrap();
        factory.start().unwrap();
        factory.logger().error("ignored").unwrap();
        assert!(buffer.lock().unwrap().is_empty());
    }
}
