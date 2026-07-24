use anyhow::{Context, Result};
use reqwest::blocking::Client;

use crate::settings::Settings;

pub fn reload_config(settings: &Settings) -> Result<()> {
    let url =
        format!("http://{}/configs?force=true", settings.external_controller);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building reload HTTP client")?;

    let mut req = client.put(&url);
    if !settings.api_secret.is_empty() {
        req = req
            .header("Authorization", format!("Bearer {}", settings.api_secret));
    }

    let body = serde_json::json!({
        "path": settings.config_path().display().to_string()
    });
    let body = serde_json::to_string(&body).context("encoding reload body")?;

    req.header("Content-Type", "application/json")
        .body(body)
        .send()
        .context("sing-box config reload request")?
        .error_for_status()
        .context("sing-box config reload failed")?;

    eprintln!("sing-box config reloaded");
    Ok(())
}
