#![feature(cfg_version)]
#![cfg_attr(not(version("1.88.0")), feature(let_chains))]

extern crate clash_lib as clash;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use clash::TokioRuntime;
use serde_yaml::Value;
use tracing_subscriber::{EnvFilter, fmt::time::LocalTime};

#[derive(Parser, Debug)]
#[clap(
    name = "zay",
    author,
    about = "Zero-config clash-rs launcher – just point it at a subscription URL",
    long_about = None
)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Serve(Args),
    Dump(Args),
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, value_name = "URL")]
    subscription: String,

    #[clap(short, long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[clap(long, default_value = "7890", value_name = "PORT")]
    mixed_port: u16,

    #[clap(long, value_name = "ADDR")]
    controller: Option<String>,

    #[clap(long, value_name = "TOKEN")]
    secret: Option<String>,

    #[clap(long, default_value = "3600", value_name = "SECS")]
    interval: u64,

    #[clap(
        long,
        default_value = "http://cp.cloudflare.com/generate_204",
        value_name = "URL"
    )]
    health_check_url: String,

    #[clap(long, default_value = "info", value_name = "LEVEL")]
    log_level: String,

    #[clap(long, default_value_t = false)]
    allow_lan: bool,

    #[clap(long, default_value_t = false)]
    tun: bool,

    #[clap(long, value_name = "FILE")]
    mixin: Option<PathBuf>,
}

fn default_data_dir() -> PathBuf {
    dirs_next::config_dir()
        .map(|p| p.join("zay"))
        .unwrap_or_else(|| std::env::temp_dir().join("zay"))
}

const SUBSCRIPTION_UA: &str =
    concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

fn http_client() -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(SUBSCRIPTION_UA)
        .build()
        .context("building HTTP client")
}

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
            let rest = line["proxies:".len()..].trim();
            if !rest.is_empty() && rest != "~" && rest != "null" {
                out = line.to_string();
                out.push('\n');
            }
            continue;
        }

        if in_proxies {
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

fn extract_proxy_servers(path: &Path) -> Vec<String> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let doc: Value = match serde_yaml::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let proxies = match doc.get("proxies").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return vec![],
    };
    let mut servers: Vec<String> = Vec::new();
    for proxy in proxies {
        if let Some(server) = proxy.get("server").and_then(|v| v.as_str()) {
            let s = server.to_string();
            if !servers.contains(&s) {
                servers.push(s);
            }
        }
    }
    servers
}

fn build_config(
    args: &Args,
    sub_cache_rel: &str,
    has_mmdb: bool,
    has_geosite: bool,
    proxy_servers: &[String],
) -> String {
    let mixed_port = args.mixed_port;
    let log_level = &args.log_level;
    let allow_lan = args.allow_lan;
    let hc_url = &args.health_check_url;

    let controller_line = match &args.controller {
        Some(addr) => format!("external-controller: \"{addr}\"\n"),
        None => String::new(),
    };
    let secret_line = match &args.secret {
        Some(s) => format!("secret: \"{s}\"\n"),
        None => String::new(),
    };
    let tun_block = if args.tun {
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

    let server_rules: String = proxy_servers
        .iter()
        .map(|s| {
            if s.parse::<std::net::IpAddr>().is_ok() {
                format!("  - IP-CIDR,{s}/32,DIRECT,no-resolve\n")
            } else {
                format!("  - DOMAIN-SUFFIX,{s},DIRECT\n")
            }
        })
        .collect();

    let geoip_rules = if has_mmdb {
        "  - GEOIP,PRIVATE,DIRECT\n  - GEOIP,CN,DIRECT\n"
    } else {
        ""
    };

    let dns_block = if args.tun {
        r#"
dns:
  enable: true
  listen: 0.0.0.0:53533
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "*.internal"
  default-nameserver:
    - 114.114.114.114
    - 223.5.5.5
  nameserver:
    - 114.114.114.114
    - 223.5.5.5
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
{server_rules}{geoip_rules}  - MATCH,Proxy
"#
    )
}

fn merge_yaml(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Mapping(b), Value::Mapping(o)) => {
            for (k, v) in o {
                merge_yaml(b.entry(k).or_insert(Value::Null), v);
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn apply_mixin(config_yaml: &str, mixin_path: &Path) -> anyhow::Result<String> {
    let mixin_raw = fs::read_to_string(mixin_path)
        .with_context(|| format!("reading mixin {}", mixin_path.display()))?;

    let mut base: Value = serde_yaml::from_str(config_yaml)
        .context("parsing generated config as YAML")?;
    let overlay: Value = serde_yaml::from_str(&mixin_raw)
        .with_context(|| format!("parsing mixin {}", mixin_path.display()))?;

    merge_yaml(&mut base, overlay);

    serde_yaml::to_string(&base).context("serializing merged config")
}

struct PreparedConfig {
    config_yaml: String,
    data_dir: PathBuf,
}

fn prepare(args: &Args) -> anyhow::Result<PreparedConfig> {
    let data_dir = args.data_dir.clone().unwrap_or_else(default_data_dir);
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

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
        &args.subscription,
        &sub_cache_abs,
    )?;
    normalize_subscription(&sub_cache_abs)?;

    let proxy_servers = extract_proxy_servers(&sub_cache_abs);
    let mut config_yaml = build_config(
        args,
        sub_cache_rel,
        has_mmdb,
        has_geosite,
        &proxy_servers,
    );

    let mixin_path = args
        .mixin
        .clone()
        .unwrap_or_else(|| data_dir.join("mixin.yaml"));
    if mixin_path.exists() {
        eprintln!("zay: applying mixin from {}", mixin_path.display());
        config_yaml = apply_mixin(&config_yaml, &mixin_path)?;
    }

    Ok(PreparedConfig {
        config_yaml,
        data_dir,
    })
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let args = match &cli.command {
        Command::Serve(a) | Command::Dump(a) => a,
    };

    let timer = LocalTime::new(time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
    ));
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("warn,clash={}", args.log_level))
    });
    let _ = tracing_subscriber::fmt()
        .with_timer(timer)
        .with_env_filter(filter)
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .compact()
        .try_init();

    match &cli.command {
        Command::Dump(args) => {
            let PreparedConfig { config_yaml, .. } = prepare(args)?;
            print!("{config_yaml}");
        }
        Command::Serve(args) => {
            let PreparedConfig {
                config_yaml,
                data_dir,
            } = prepare(args)?;

            let config_path = data_dir.join("config.yaml");
            fs::write(&config_path, &config_yaml).with_context(|| {
                format!("writing config to {}", config_path.display())
            })?;
            eprintln!("zay: config → {}", config_path.display());
            eprintln!(
                "zay: starting – mixed proxy on 0.0.0.0:{}",
                args.mixed_port
            );

            clash::start_scaffold(clash::Options {
                config: clash::Config::Str(config_yaml),
                cwd: Some(data_dir.to_string_lossy().into_owned()),
                rt: Some(TokioRuntime::MultiThread),
                log_file: None,
            })
            .inspect_err(|err| eprintln!("zay: fatal: {err}"))?;
        }
    }

    Ok(())
}
