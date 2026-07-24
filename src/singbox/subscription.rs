use std::{fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde_json::Value;

use super::clash::convert_subscription;
use crate::{
    bootstrap::proxy,
    settings::{BootstrapProxy, Settings},
};

const SUBSCRIPTION_UA: &str =
    concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

pub fn fetch_and_convert(
    settings: &Settings,
    bootstrap: Option<&BootstrapProxy>,
) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    for (i, url) in settings.subscriptions.iter().enumerate() {
        let raw = fetch_subscription(url, settings, bootstrap)?;
        let cache = settings.subscription_cache_path(i);
        if let Some(parent) = cache.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&cache, &raw)
            .with_context(|| format!("writing {}", cache.display()))?;
        let mut nodes = convert_subscription(&raw, settings, i)?;
        all.append(&mut nodes);
    }
    Ok(all)
}

pub fn load_cached_nodes(settings: &Settings) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    for (i, _) in settings.subscriptions.iter().enumerate() {
        let cache = settings.subscription_cache_path(i);
        if !cache.is_file() {
            continue;
        }
        let raw = fs::read_to_string(&cache)
            .with_context(|| format!("reading {}", cache.display()))?;
        if is_invalid_body(&raw) {
            continue;
        }
        let mut nodes = convert_subscription(&raw, settings, i)?;
        all.append(&mut nodes);
    }
    Ok(all)
}

fn fetch_subscription(
    url: &str,
    settings: &Settings,
    bootstrap: Option<&BootstrapProxy>,
) -> Result<String> {
    let client = if let Some(bp) = bootstrap {
        client_via_bootstrap(bp)?
    } else {
        Client::builder()
            .user_agent(SUBSCRIPTION_UA)
            .timeout(Duration::from_secs(120))
            .build()
            .context("building HTTP client")?
    };

    let resp = client
        .get(url)
        .send()
        .with_context(|| format!("GET subscription {url}"))?
        .error_for_status()
        .with_context(|| format!("subscription {url}"))?;
    let body = resp.text().context("reading subscription body")?;
    if is_invalid_body(&body) {
        bail!("subscription returned HTML or empty body");
    }
    Ok(body)
}

pub fn client_via_bootstrap(bp: &BootstrapProxy) -> Result<Client> {
    let proxy = proxy::singbox_outbound_to_proxy_url(&bp.proxy)?;
    let proxy = reqwest::Proxy::all(&proxy)
        .with_context(|| format!("invalid bootstrap proxy URL {proxy}"))?;
    Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .proxy(proxy)
        .timeout(Duration::from_secs(120))
        .build()
        .context("building bootstrap HTTP client")
}

pub fn wait_for_mixed_proxy(
    settings: &Settings,
    timeout: Duration,
) -> Result<()> {
    crate::mihomo::geo::wait_for_proxy(settings.mixed_port, timeout)
}

fn is_invalid_body(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    trimmed.starts_with('<')
        || trimmed.starts_with("<!doctype")
        || trimmed.starts_with("<!DOCTYPE")
        || trimmed.is_empty()
}
