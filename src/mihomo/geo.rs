use std::{
    fs,
    io::Read,
    path::Path,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;

use super::rules;
use crate::settings::Settings;

/// meta-rules-dat release label pinned for reproducible downloads (rolling `latest` URL + checksum).
pub const META_RULES_DAT_RELEASE: &str = "2026-05-19";

pub const MMDB_URL: &str = concat!(
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"
);
pub const GEOSITE_URL: &str = concat!(
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
);

const MMDB_SHA256_URL: &str = concat!(
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb.sha256sum"
);
const GEOSITE_SHA256_URL: &str = concat!(
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat.sha256sum"
);

const SUBSCRIPTION_UA: &str =
    concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

pub fn files_present(data_dir: &Path) -> (bool, bool) {
    (
        data_dir.join("Country.mmdb").is_file(),
        data_dir.join("geosite.dat").is_file(),
    )
}

fn build_proxy_client(proxy_url: &str) -> Result<Client> {
    let proxy = reqwest::Proxy::all(proxy_url)
        .with_context(|| format!("invalid proxy URL {proxy_url}"))?;
    Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .proxy(proxy)
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(30))
        .build()
        .with_context(|| format!("building HTTP client for {proxy_url}"))
}

pub(crate) fn http_client_via_proxy(mixed_port: u16) -> Result<Client> {
    build_proxy_client(&format!("http://127.0.0.1:{mixed_port}"))
}

/// HTTP + SOCKS5 mixed-port clients (retry HTTPS downloads through Mihomo).
pub(crate) fn http_clients_via_proxy(mixed_port: u16) -> Result<Vec<Client>> {
    let http = build_proxy_client(&format!("http://127.0.0.1:{mixed_port}"))?;
    let socks =
        build_proxy_client(&format!("socks5://127.0.0.1:{mixed_port}"))?;
    Ok(vec![http, socks])
}

pub(crate) fn wait_for_proxy(mixed_port: u16, timeout: Duration) -> Result<()> {
    let clients = http_clients_via_proxy(mixed_port)?;
    let deadline = Instant::now() + timeout;
    eprintln!("waiting for proxy on 127.0.0.1:{mixed_port}…");
    loop {
        let http_ok = clients.iter().any(|c| {
            c.get("http://cp.cloudflare.com/generate_204")
                .send()
                .is_ok()
        });
        let https_ok = clients.iter().any(|c| {
            c.get("https://www.cloudflare.com/cdn-cgi/trace")
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        });
        if http_ok && https_ok {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("proxy not ready after {}s", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn fetch_checksum(client: &Client, url: &str) -> Result<String> {
    let text = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url} failed"))?
        .error_for_status()
        .with_context(|| format!("checksum request {url}"))?
        .text()
        .with_context(|| format!("reading checksum from {url}"))?;
    let hex = text
        .split_whitespace()
        .next()
        .context("empty checksum file")?
        .to_ascii_lowercase();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid sha256 checksum format from {url}");
    }
    Ok(hex)
}

fn sha256_hex(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_hex(path)?;
    if actual != expected {
        bail!(
            "checksum mismatch for {} (expected {expected}, got {actual})",
            path.display()
        );
    }
    Ok(())
}

fn fetch_file(
    client: &Client,
    label: &str,
    url: &str,
    dest: &Path,
    checksum_url: Option<&str>,
) -> Result<()> {
    if dest.is_file() {
        if let Some(sum_url) = checksum_url {
            let expected = fetch_checksum(client, sum_url)?;
            if verify_sha256(dest, &expected).is_ok() {
                eprintln!("reusing cached {label} at {}", dest.display());
                return Ok(());
            }
            eprintln!("cached {label} failed checksum, re-downloading");
            let _ = fs::remove_file(dest);
        } else {
            eprintln!("reusing cached {label} at {}", dest.display());
            return Ok(());
        }
    }
    eprintln!(
        "downloading {label} via proxy from {url} (meta-rules-dat {META_RULES_DAT_RELEASE})"
    );
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
    if body.is_empty() {
        bail!("{label} download is empty");
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(dest, &body)
        .with_context(|| format!("writing {label} to {}", dest.display()))?;

    if let Some(sum_url) = checksum_url {
        let expected = fetch_checksum(client, sum_url)?;
        verify_sha256(dest, &expected)?;
    }

    eprintln!("{label} saved to {} ({} bytes)", dest.display(), body.len());
    Ok(())
}

pub fn refresh_config_on_disk(
    settings: &Settings,
    config_snapshot: Option<Arc<RwLock<String>>>,
) -> Result<String> {
    let (has_mmdb, has_geosite) = files_present(&settings.data_dir);
    let has_rules = rules::files_present(&settings.data_dir);
    let yaml = super::publish_config(
        settings,
        super::build_config(settings, has_mmdb, has_geosite, has_rules)?,
        true,
    )?;
    if let Some(snap) = config_snapshot {
        *snap.write().expect("config snapshot lock") = yaml.clone();
    }
    eprintln!(
        "config updated (mmdb={has_mmdb}, geosite={has_geosite}, rules={has_rules}) → {}",
        settings.data_dir.join("config.yaml").display()
    );
    Ok(yaml)
}

fn download_when_ready(
    settings: &Settings,
    config_snapshot: Option<Arc<RwLock<String>>>,
) -> Result<()> {
    let (has_mmdb, has_geosite) = files_present(&settings.data_dir);
    if has_mmdb && has_geosite {
        return Ok(());
    }

    wait_for_proxy(settings.mixed_port, Duration::from_secs(120))?;
    rules::wait_for_fetch_outbound(settings, Duration::from_secs(180))?;
    let clients = http_clients_via_proxy(settings.mixed_port)?;

    let mmdb_path = settings.data_dir.join("Country.mmdb");
    let geosite_path = settings.data_dir.join("geosite.dat");

    if !has_mmdb {
        fetch_file(
            &clients[0],
            "Country.mmdb",
            MMDB_URL,
            &mmdb_path,
            Some(MMDB_SHA256_URL),
        )?;
    }
    if !has_geosite {
        fetch_file(
            &clients[0],
            "geosite.dat",
            GEOSITE_URL,
            &geosite_path,
            Some(GEOSITE_SHA256_URL),
        )?;
    }

    refresh_config_on_disk(settings, config_snapshot)?;
    Ok(())
}

pub fn spawn_background_download(
    settings: Settings,
    config_snapshot: Option<Arc<RwLock<String>>>,
) {
    thread::spawn(move || {
        let snap = config_snapshot.clone();
        if let Err(e) = download_when_ready(&settings, snap.clone()) {
            eprintln!("geo rules download: {e:#}");
        }
        if let Err(e) = rules::download_when_ready(&settings, snap) {
            eprintln!("clash-rules download: {e:#}");
        }
    });
}
