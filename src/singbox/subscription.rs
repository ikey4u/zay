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

pub fn load_nodes(
    settings: &Settings,
    bootstrap: Option<&BootstrapProxy>,
) -> Result<Vec<Value>> {
    match fetch_and_convert(settings, bootstrap) {
        Ok(nodes) => Ok(nodes),
        Err(fetch_error) => match load_cached_nodes(settings) {
            Ok(nodes) if !nodes.is_empty() => {
                eprintln!(
                    "warning: proxy subscription refresh failed ({fetch_error:#}); using {} cached node(s)",
                    nodes.len()
                );
                Ok(nodes)
            }
            Ok(_) => Err(fetch_error).context(
                "proxy subscription unavailable and no cached proxy nodes exist",
            ),
            Err(cache_error) => Err(fetch_error).with_context(|| {
                format!(
                    "proxy subscription unavailable and cached proxy nodes are unusable: {cache_error:#}"
                )
            }),
        },
    }
}

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
        .map_err(reqwest::Error::without_url)
        .context("GET proxy subscription")?
        .error_for_status()
        .map_err(reqwest::Error::without_url)
        .context("proxy subscription returned an error status")?;
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

/// Complete a real request through the local mixed inbound.
///
/// This verifies more than a listening socket: route selection and the
/// selected `Proxy`/`Auto` outbound must both be able to carry traffic.
pub fn probe_mixed_proxy(
    mixed_port: u16,
    health_check_url: &str,
    timeout: Duration,
) -> Result<()> {
    let proxy_url = format!("http://127.0.0.1:{mixed_port}");
    let proxy = reqwest::Proxy::all(&proxy_url)
        .with_context(|| format!("invalid mixed proxy URL {proxy_url}"))?;
    let response = Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .proxy(proxy)
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .context("building proxy health-check client")?
        .get(health_check_url)
        .send()
        .with_context(|| {
            format!(
                "requesting {health_check_url} through local proxy {proxy_url}"
            )
        })?;
    response.error_for_status().with_context(|| {
        format!(
            "health check {health_check_url} through local proxy {proxy_url}"
        )
    })?;
    Ok(())
}

/// Complete a real request through the operating system route table.
///
/// In full-capture TUN mode this request is intercepted by sing-box, so it
/// validates the actual TUN path without requiring a loopback Mixed inbound.
/// Explicitly ignore environment proxy variables: otherwise an unrelated
/// desktop proxy could make the check pass while Zay's TUN is broken.
pub fn probe_tun_proxy(
    health_check_url: &str,
    timeout: Duration,
) -> Result<()> {
    let response = Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .no_proxy()
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .context("building TUN health-check client")?
        .get(health_check_url)
        .send()
        .with_context(|| {
            format!("requesting {health_check_url} through system TUN")
        })?;
    response.error_for_status().with_context(|| {
        format!("health check {health_check_url} through system TUN")
    })?;
    Ok(())
}

pub fn client_via_tun() -> Result<Client> {
    Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .no_proxy()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(30))
        .build()
        .context("building TUN HTTP client")
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
    let deadline = Instant::now() + timeout;
    eprintln!(
        "waiting for sing-box mixed proxy on 127.0.0.1:{}…",
        settings.mixed_port
    );
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt_timeout = remaining.min(Duration::from_secs(8));
        if probe_mixed_proxy(
            settings.mixed_port,
            &settings.health_check_url,
            attempt_timeout,
        )
        .is_ok()
        {
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
