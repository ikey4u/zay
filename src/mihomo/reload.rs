//! Reload Mihomo via `external-controller` after `config.yaml` changes.

use std::{
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde_json::json;

use crate::settings::Settings;

const RELOAD_RETRIES: u32 = 8;
const RELOAD_RETRY_INTERVAL: Duration = Duration::from_millis(750);

pub fn reload_running_config(settings: &Settings) -> Result<()> {
    let config_path = settings
        .config_path()
        .canonicalize()
        .unwrap_or_else(|_| settings.config_path());
    let path = config_path
        .to_str()
        .context("config path must be valid UTF-8")?;

    let url =
        format!("http://{}/configs?force=true", settings.external_controller);
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("building reload HTTP client")?;

    let body = json!({ "path": path, "payload": "" }).to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_err: Option<String> = None;

    for attempt in 1..=RELOAD_RETRIES {
        if Instant::now() >= deadline {
            break;
        }
        match client
            .put(&url)
            .header("Authorization", format!("Bearer {}", settings.api_secret))
            .header("Content-Type", "application/json")
            .body(body.clone())
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                eprintln!("mihomo config reloaded");
                return Ok(());
            }
            Ok(resp) => {
                last_err = Some(format!("HTTP {}", resp.status()));
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
        if attempt < RELOAD_RETRIES {
            thread::sleep(RELOAD_RETRY_INTERVAL);
        }
    }

    bail!(
        "mihomo config reload failed ({}); is external-controller up?",
        last_err.unwrap_or_else(|| "timeout".into())
    )
}
