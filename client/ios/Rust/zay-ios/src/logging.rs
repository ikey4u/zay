use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use once_cell::sync::OnceCell;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

static LOG_PATH: OnceCell<Mutex<Option<PathBuf>>> = OnceCell::new();

struct FileWriter;

impl<'a> MakeWriter<'a> for FileWriter {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter
    }
}

struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(guard) = LOG_PATH.get() {
            if let Some(path) = guard.lock().ok().as_ref().and_then(|p| p.as_ref()) {
                if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
                    let _ = f.write_all(buf);
                    let _ = f.flush();
                }
            }
        }
        // Also mirror to stderr for Xcode console / Console.app.
        let _ = std::io::stderr().write_all(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn init_logging() {
    static INIT: OnceCell<()> = OnceCell::new();
    INIT.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("warn,easytier=warn,zay_ios=info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(true)
            .with_writer(FileWriter)
            .try_init();
        // Forward `log` crate (used by EasyTier) into tracing.
        let _ = tracing_log::LogTracer::init();
    });
}

pub fn set_log_path(path: Option<PathBuf>) {
    init_logging();
    let slot = LOG_PATH.get_or_init(|| Mutex::new(None));
    if let Ok(mut g) = slot.lock() {
        *g = path;
    }
}

pub fn log_line(level: &str, message: &str) {
    init_logging();
    match level {
        "error" => tracing::error!(target: "zay_ios", "{message}"),
        "warn" => tracing::warn!(target: "zay_ios", "{message}"),
        "debug" => tracing::debug!(target: "zay_ios", "{message}"),
        "trace" => tracing::trace!(target: "zay_ios", "{message}"),
        _ => tracing::info!(target: "zay_ios", "{message}"),
    }
}
