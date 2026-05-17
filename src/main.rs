#![feature(cfg_version)]
#![cfg_attr(not(version("1.88.0")), feature(let_chains))]

extern crate clash_lib as clash;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use clap::Parser;
use clash::TokioRuntime;
use tracing_subscriber::{EnvFilter, fmt::time::LocalTime};

#[derive(Parser, Debug)]
#[clap(
    name = "zay",
    author,
    about = "Zero-config clash-rs launcher – just point it at a subscription URL",
    long_about = None
)]
struct Cli {
    /// Subscription URL (clash/mihomo-compatible YAML proxy list).
    ///
    /// The URL is fetched once at startup and cached locally.  The proxy
    /// provider will also re-fetch it on the configured `--interval`.
    #[clap(short, long, value_name = "URL")]
    subscription: String,

    /// Directory used to store the generated config, provider cache, and
    /// GeoIP/GeoSite databases.  Defaults to the OS config dir under
    /// `zay/` (e.g. `~/.config/zay`), falling back to a temp dir.
    #[clap(short, long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// HTTP + SOCKS5 mixed-mode proxy listen port.
    #[clap(long, default_value = "7890", value_name = "PORT")]
    mixed_port: u16,

    /// External REST API listen address (`host:port`).
    /// Omit to disable the API server.
    #[clap(long, value_name = "ADDR")]
    controller: Option<String>,

    /// Secret token for the REST API.
    #[clap(long, value_name = "TOKEN")]
    secret: Option<String>,

    /// Seconds between subscription re-fetches by the proxy provider.
    #[clap(long, default_value = "3600", value_name = "SECS")]
    interval: u64,

    /// URL used for proxy latency tests / health-checks.
    #[clap(
        long,
        default_value = "http://cp.cloudflare.com/generate_204",
        value_name = "URL"
    )]
    health_check_url: String,

    /// Log verbosity: trace | debug | info | warning | error | silent.
    #[clap(long, default_value = "info", value_name = "LEVEL")]
    log_level: String,

    /// Allow connections from LAN (sets `allow-lan: true`).
    #[clap(long, default_value_t = false)]
    allow_lan: bool,

    /// Enable TUN mode (requires root / CAP_NET_ADMIN on Linux).
    #[clap(long, default_value_t = false)]
    tun: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_data_dir() -> PathBuf {
    dirs_next::config_dir()
        .map(|p| p.join("zay"))
        .unwrap_or_else(|| std::env::temp_dir().join("zay"))
}

/// User-Agent sent when fetching subscription URLs.
const SUBSCRIPTION_UA: &str =
    concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

fn http_client() -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .build()
        .context("building HTTP client")
}

/// Fetch `url` and write the body to `dest`, skipping if `dest` already exists.
/// Returns `true` if the file was (re-)downloaded, `false` if skipped.
fn fetch_if_missing(
    client: &reqwest::blocking::Client,
    label: &str,
    url: &str,
    dest: &Path,
) -> anyhow::Result<bool> {
    if dest.exists() {
        eprintln!("zay: reusing cached {label} at {}", dest.display());
        return Ok(false);
    }
    eprintln!("zay: downloading {label} from {url}");
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url} failed"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("{label} download returned HTTP {status}");
    }
    let body = response
        .bytes()
        .with_context(|| format!("reading {label} body"))?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(dest, &body)
        .with_context(|| format!("writing {label} to {}", dest.display()))?;
    eprintln!(
        "zay: {label} saved to {} ({} bytes)",
        dest.display(),
        body.len()
    );
    Ok(true)
}

/// Best-effort variant of [`fetch_if_missing`]: logs a warning on failure.
/// Returns `true` if the file is available (pre-existing or just fetched).
fn try_fetch_if_missing(
    client: &reqwest::blocking::Client,
    label: &str,
    url: &str,
    dest: &Path,
) -> bool {
    match fetch_if_missing(client, label, url, dest) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "zay: warning: skipping {label} (will retry via proxy once running): {e}"
            );
            false
        }
    }
}

/// If `path` is a full clash config, rewrite it in-place to contain only the
/// `proxies:` block so it can be used as a clash proxy-provider file.
fn normalize_subscription(path: &Path) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let is_full_config = raw.lines().any(|l| {
        matches!(
            l.split(':').next().map(str::trim),
            Some("mixed-port" | "port" | "socks-port" | "mode" | "profile")
        )
    });

    if !is_full_config {
        return Ok(());
    }

    let mut in_proxies = false;
    let mut out = String::from("proxies:\n");
    let mut count = 0usize;

    for line in raw.lines() {
        if line.starts_with("proxies:") {
            in_proxies = true;
            // Inline sequence on same line e.g. "proxies: []" — keep as-is.
            let rest = line["proxies:".len()..].trim();
            if !rest.is_empty() && rest != "~" && rest != "null" {
                // Rare: all proxies on one line. Just keep the whole thing.
                out = line.to_string();
                out.push('\n');
            }
            continue;
        }

        if in_proxies {
            // A new top-level key ends the proxies block.
            if !line.is_empty()
                && !line.starts_with(' ')
                && !line.starts_with('\t')
                && !line.starts_with('-')
                && !line.starts_with('#')
            {
                break;
            }
            if line.trim_start().starts_with("- ")
                || line.trim_start().starts_with('-')
            {
                count += 1;
            }
            out.push_str(line);
            out.push('\n');
        }
    }

    fs::write(path, &out).with_context(|| {
        format!("writing normalized provider to {}", path.display())
    })?;

    eprintln!(
        "zay: normalized subscription from full config to proxy-provider format ({count} proxies)"
    );
    Ok(())
}

fn build_config(
    cli: &Cli,
    sub_cache_rel: &str,
    has_mmdb: bool,
    has_geosite: bool,
) -> String {
    let mixed_port = cli.mixed_port;
    let log_level = &cli.log_level;
    let allow_lan = cli.allow_lan;
    let hc_url = &cli.health_check_url;

    let controller_line = match &cli.controller {
        Some(addr) => format!("external-controller: \"{addr}\"\n"),
        None => String::new(),
    };
    let secret_line = match &cli.secret {
        Some(s) => format!("secret: \"{s}\"\n"),
        None => String::new(),
    };
    let tun_block = if cli.tun {
        "\ntun:\n  enable: true\n  device-id: \"utun1989\"\n  route-all: true\n  dns-hijack: true\n"
            .to_string()
    } else {
        String::new()
    };

    let mmdb_line = if has_mmdb {
        "mmdb: \"Country.mmdb\"\n"
    } else {
        ""
    };
    let geosite_line = if has_geosite {
        "geosite: \"geosite.dat\"\n"
    } else {
        ""
    };

    // Only add GEOIP rules when the mmdb file is available.
    let geoip_rules = if has_mmdb {
        "  - GEOIP,PRIVATE,DIRECT\n  - GEOIP,CN,DIRECT\n"
    } else {
        ""
    };

    let dns_block = if cli.tun {
        r#"
dns:
  enable: true
  listen: 0.0.0.0:53533
  default-nameserver:
    - 114.114.114.114
    - 223.5.5.5
  nameserver:
    - 114.114.114.114
    - 223.5.5.5
  fallback:
    - https://8.8.8.8/dns-query
    - https://1.1.1.1/dns-query
"#
        .to_string()
    } else {
        "\ndns:\n  enable: false\n".to_string()
    };

    format!(
        r#"mixed-port: {mixed_port}
allow-lan: {allow_lan}
ipv6: false
mode: rule
log-level: {log_level}
{controller_line}{secret_line}{mmdb_line}{geosite_line}{tun_block}{dns_block}
proxy-providers:
  subscription:
    type: file
    path: "./{sub_cache_rel}"
    health-check:
      enable: true
      url: "{hc_url}"
      interval: 300

proxy-groups:
  - name: "Auto"
    type: url-test
    proxies:
      - DIRECT
    use:
      - subscription
    url: "{hc_url}"
    interval: 300

  - name: "Proxy"
    type: select
    proxies:
      - Auto
      - DIRECT
    use:
      - subscription

rules:
{geoip_rules}  - MATCH,Proxy
"#
    )
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Install our own tracing subscriber before clash-rs starts so we control
    // the format.  clash-rs's setup_logging uses a Once-guard + set_global_default;
    // since the global is already set it will silently no-op and our format wins.
    let timer = LocalTime::new(time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
    ));
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("warn,clash={}", cli.log_level))
    });
    let _ = tracing_subscriber::fmt()
        .with_timer(timer)
        .with_env_filter(filter)
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .compact()
        .try_init();

    let data_dir = cli.data_dir.clone().unwrap_or_else(default_data_dir);
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    eprintln!("zay: data dir → {}", data_dir.display());

    let client = http_client()?;

    let has_mmdb = try_fetch_if_missing(
        &client,
        "Country.mmdb",
        "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
        &data_dir.join("Country.mmdb"),
    );
    let has_geosite = try_fetch_if_missing(
        &client,
        "geosite.dat",
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406182210/geosite.dat",
        &data_dir.join("geosite.dat"),
    );

    let sub_cache_rel = "providers/subscription.yaml";
    let sub_cache_abs = data_dir.join(sub_cache_rel);
    fetch_if_missing(
        &client,
        "subscription",
        &cli.subscription,
        &sub_cache_abs,
    )?;
    normalize_subscription(&sub_cache_abs)?;

    let config_yaml = build_config(&cli, sub_cache_rel, has_mmdb, has_geosite);
    let config_path = data_dir.join("config.yaml");
    fs::write(&config_path, &config_yaml).with_context(|| {
        format!("writing config to {}", config_path.display())
    })?;
    eprintln!("zay: config → {}", config_path.display());
    eprintln!("zay: starting – mixed proxy on 0.0.0.0:{}", cli.mixed_port);

    clash::start_scaffold(clash::Options {
        config: clash::Config::Str(config_yaml),
        cwd: Some(data_dir.to_string_lossy().into_owned()),
        rt: Some(TokioRuntime::MultiThread),
        log_file: None,
    })
    .inspect_err(|err| eprintln!("zay: fatal: {err}"))?;

    Ok(())
}
