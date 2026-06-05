//! `zay serve` — Web control plane (embedded WebUI + REST API).

mod app;
mod auth;
mod clash_proxy;
mod config_api;
mod error;
mod job_specs;
mod jobs;
mod jobs_api;
pub mod log_buf;
pub mod paths;
mod router;
mod stack_api;
mod ws;

use std::{net::SocketAddr, path::PathBuf, process::Command, sync::Arc};

use anyhow::{Context, Result, bail};
pub use app::ServeApp;
use clap::Args;
pub use error::ApiError;
pub use paths::ServePaths;

#[derive(Args, Debug)]
#[command(about = "Run the Zay Web control plane (embedded UI + /api/v1)")]
pub struct ServeCli {
    /// Zay config directory (zay.toml 所在)
    #[arg(short, long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// Path to zay.toml
    #[arg(short = 'c', long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Control plane listen address
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8787")]
    pub listen: SocketAddr,

    /// API Bearer token (overrides zay.toml [serve].token)
    #[arg(long, value_name = "SECRET")]
    pub token: Option<String>,

    /// Open the WebUI in the default browser after startup
    #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub open: bool,

    /// API only — do not serve embedded static WebUI
    #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pub no_ui: bool,
}

pub async fn run(cli: ServeCli) -> Result<()> {
    let paths = paths::ServePaths::resolve(
        cli.data_dir.as_deref(),
        cli.config.as_deref(),
    );
    paths.ensure_config()?;

    let token = resolve_token(&paths.toml_path, cli.token.as_deref())?;
    let app = Arc::new(ServeApp::new(paths, token));

    let listen = cli.listen;
    let cors = !listen.ip().is_loopback();

    if !listen.ip().is_loopback() {
        eprintln!(
            "warn: control plane listening on {} — use a strong --token or [serve].token",
            listen
        );
    }

    if !cli.no_ui && !crate::webui::EMBEDDED_UI {
        eprintln!(
            "warn: WebUI not embedded — build with `cd webui && pnpm build` then `cargo build`"
        );
    }

    if cli.open {
        let url = format!("http://{listen}/");
        let _ = open_browser(&url);
    }

    eprintln!("zay serve on http://{listen}");
    if cli.no_ui {
        eprintln!("  mode: API only (--no-ui)");
    } else if crate::webui::EMBEDDED_UI {
        eprintln!("  WebUI: http://{listen}/");
    }
    eprintln!("  API:   http://{listen}/api/v1/");

    router::run(app, listen, cli.no_ui, cors).await
}

fn resolve_token(
    toml_path: &std::path::Path,
    cli_token: Option<&str>,
) -> Result<String> {
    if let Some(t) = cli_token {
        if t.is_empty() {
            bail!("--token must not be empty");
        }
        return Ok(t.to_string());
    }
    if let Ok(raw) = std::fs::read_to_string(toml_path) {
        if let Ok(doc) = toml::from_str::<toml::Table>(&raw) {
            if let Some(serve) = doc.get("serve").and_then(|v| v.as_table()) {
                if let Some(t) = serve.get("token").and_then(|v| v.as_str()) {
                    if !t.is_empty() {
                        return Ok(t.to_string());
                    }
                }
            }
        }
    }
    let token = uuid::Uuid::new_v4().to_string();
    eprintln!(
        "serve: no token in zay.toml [serve] or --token — generated ephemeral token (not saved)"
    );
    Ok(token)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).status()?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        if Command::new("xdg-open").arg(url).status().is_ok() {
            return Ok(());
        }
    }
    #[cfg(windows)]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()?;
        return Ok(());
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = url;
    }
    Ok(())
}
