use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;

use crate::{mihomo, settings::Settings};

const SUBSCRIPTION_UA: &str =
    concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

pub const MMDB_URL: &str = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb";
pub const GEOSITE_URL: &str = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat";

pub fn files_present(data_dir: &Path) -> (bool, bool) {
    (
        data_dir.join("Country.mmdb").is_file(),
        data_dir.join("geosite.dat").is_file(),
    )
}

fn http_client_via_proxy(mixed_port: u16) -> Result<Client> {
    let proxy = format!("http://127.0.0.1:{mixed_port}");
    let proxy = reqwest::Proxy::all(&proxy)
        .with_context(|| format!("invalid proxy URL {proxy}"))?;
    Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .proxy(proxy)
        .build()
        .context("building HTTP client")
}

fn wait_for_proxy(mixed_port: u16, timeout: Duration) -> Result<()> {
    let client = http_client_via_proxy(mixed_port)?;
    let deadline = Instant::now() + timeout;
    eprintln!("waiting for proxy on 127.0.0.1:{mixed_port}…");
    loop {
        if client
            .get("http://cp.cloudflare.com/generate_204")
            .send()
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

fn fetch_file(
    client: &Client,
    label: &str,
    url: &str,
    dest: &Path,
) -> Result<()> {
    if dest.exists() {
        eprintln!("reusing cached {label} at {}", dest.display());
        return Ok(());
    }
    eprintln!("downloading {label} via proxy from {url}");
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url} failed"))?;
    if !response.status().is_success() {
        bail!("{label} download returned HTTP {}", response.status());
    }
    let body = response
        .bytes()
        .with_context(|| format!("reading {label} body"))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(dest, &body)
        .with_context(|| format!("writing {label} to {}", dest.display()))?;
    eprintln!("{label} saved to {} ({} bytes)", dest.display(), body.len());
    Ok(())
}

fn refresh_config_on_disk(settings: &Settings) -> Result<()> {
    let (has_mmdb, has_geosite) = files_present(&settings.data_dir);
    let config_yaml = mihomo::finalize_config(
        settings,
        mihomo::build_config(settings, has_mmdb, has_geosite),
    )?;
    let config_path = settings.data_dir.join("config.yaml");
    std::fs::write(&config_path, &config_yaml).with_context(|| {
        format!("writing config to {}", config_path.display())
    })?;
    eprintln!(
        "config updated (mmdb={has_mmdb}, geosite={has_geosite}) → {}",
        config_path.display()
    );
    Ok(())
}

fn download_when_ready(settings: &Settings) -> Result<()> {
    let (has_mmdb, has_geosite) = files_present(&settings.data_dir);
    if has_mmdb && has_geosite {
        return Ok(());
    }

    wait_for_proxy(settings.mixed_port, Duration::from_secs(120))?;
    let client = http_client_via_proxy(settings.mixed_port)?;

    let mmdb_path = settings.data_dir.join("Country.mmdb");
    let geosite_path = settings.data_dir.join("geosite.dat");

    if !has_mmdb {
        fetch_file(&client, "Country.mmdb", MMDB_URL, &mmdb_path)?;
    }
    if !has_geosite {
        fetch_file(&client, "geosite.dat", GEOSITE_URL, &geosite_path)?;
    }

    refresh_config_on_disk(settings)?;
    Ok(())
}

pub fn spawn_background_download(settings: Settings) {
    thread::spawn(move || {
        if let Err(e) = download_when_ready(&settings) {
            eprintln!("geo rules download: {e:#}");
        }
    });
}
