use std::{
    fs, thread,
    time::{Duration, Instant},
};

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
    _settings: &Settings,
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

pub fn client_via_mixed_proxy(mixed_port: u16) -> Result<Client> {
    let proxy_url = format!("http://127.0.0.1:{mixed_port}");
    let proxy = reqwest::Proxy::all(&proxy_url)
        .with_context(|| format!("invalid mixed proxy URL {proxy_url}"))?;
    Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .proxy(proxy)
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(30))
        .build()
        .context("building mixed proxy HTTP client")
}

pub fn clients_via_mixed_proxy(mixed_port: u16) -> Result<Vec<Client>> {
    let http = client_via_mixed_proxy(mixed_port)?;
    let socks_url = format!("socks5://127.0.0.1:{mixed_port}");
    let socks = reqwest::Proxy::all(&socks_url)
        .with_context(|| format!("invalid mixed proxy URL {socks_url}"))?;
    let socks = Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .proxy(socks)
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(30))
        .build()
        .context("building SOCKS proxy HTTP client")?;
    Ok(vec![http, socks])
}

pub fn wait_for_mixed_proxy(
    settings: &Settings,
    timeout: Duration,
) -> Result<()> {
    let clients = clients_via_mixed_proxy(settings.mixed_port)?;
    let deadline = Instant::now() + timeout;
    eprintln!(
        "waiting for sing-box mixed proxy on 127.0.0.1:{}…",
        settings.mixed_port
    );
    loop {
        if clients.iter().any(|client| {
            client
                .get("https://www.cloudflare.com/cdn-cgi/trace")
                .send()
                .map(|response| response.status().is_success())
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("proxy not ready after {}s", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn is_invalid_body(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    trimmed.starts_with('<')
        || trimmed.starts_with("<!doctype")
        || trimmed.starts_with("<!DOCTYPE")
        || trimmed.is_empty()
}
