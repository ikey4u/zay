mod mihomo;
mod settings;

use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use settings::Settings;

#[derive(Parser, Debug)]
#[clap(
    name = "zay",
    author,
    about = "A simple network proxy based on clash",
    long_about = None
)]
struct Cli {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    Serve(Args),
    Dump(Args),
}

/// CLI flags override values from zay.toml when provided.
#[derive(Parser, Debug)]
pub struct Args {
    /// Subscription URL (overrides zay.toml)
    #[clap(short, long, value_name = "URL")]
    pub subscription: Option<String>,

    /// Data directory (default: platform config dir / zay)
    #[clap(short, long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// Path to zay.toml (default: <data-dir>/zay.toml)
    #[clap(short = 'c', long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[clap(long, value_name = "PORT")]
    pub mixed_port: Option<u16>,

    #[clap(long, value_name = "ADDR")]
    pub controller: Option<String>,

    #[clap(long, value_name = "TOKEN")]
    pub secret: Option<String>,

    #[clap(long, value_name = "SECS")]
    pub update_interval: Option<u64>,

    #[clap(long, value_name = "URL")]
    pub health_check_url: Option<String>,

    #[clap(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    #[clap(long)]
    pub allow_lan: Option<bool>,

    #[clap(long)]
    pub tun: Option<bool>,

    /// Clash YAML mixin file (overrides zay.toml `mixin`)
    #[clap(long, value_name = "FILE")]
    pub mixin: Option<PathBuf>,
}

const SUBSCRIPTION_UA: &str =
    concat!("clash-verge/v", env!("CARGO_PKG_VERSION"));

const EMBEDDED_MIHOMO: &[u8] = include_bytes!(env!("MIHOMO_EMBED"));
const EMBEDDED_MIHOMO_VERSION: &str = env!("MIHOMO_VERSION");

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

struct PreparedConfig {
    config_yaml: String,
    data_dir: PathBuf,
    config_path: PathBuf,
    settings: Settings,
}

fn prepare(cli: &Args) -> anyhow::Result<PreparedConfig> {
    let settings = settings::resolve(cli)?;

    fs::create_dir_all(&settings.data_dir).with_context(|| {
        format!("creating data dir {}", settings.data_dir.display())
    })?;
    fs::create_dir_all(settings.data_dir.join("providers")).with_context(
        || {
            format!(
                "creating {}",
                settings.data_dir.join("providers").display()
            )
        },
    )?;

    settings::cleanup_stale_subscription_cache(&settings.data_dir);
    settings::ensure_default_mixin(&settings)?;

    let client = http_client()?;

    let has_mmdb = try_fetch_if_missing(
        &client,
        "Country.mmdb",
        "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb",
        &settings.data_dir.join("Country.mmdb"),
    );
    let has_geosite = try_fetch_if_missing(
        &client,
        "geosite.dat",
        "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        &settings.data_dir.join("geosite.dat"),
    );

    let config_yaml = mihomo::finalize_config(
        &settings,
        mihomo::build_config(&settings, has_mmdb, has_geosite),
    )?;

    let config_path = settings.data_dir.join("config.yaml");
    fs::write(&config_path, &config_yaml).with_context(|| {
        format!("writing clash config to {}", config_path.display())
    })?;
    eprintln!("zay: config → {}", config_path.display());

    Ok(PreparedConfig {
        config_yaml,
        data_dir: settings.data_dir.clone(),
        config_path,
        settings,
    })
}

fn mihomo_exe_name() -> &'static str {
    if cfg!(windows) {
        "mihomo.exe"
    } else {
        "mihomo"
    }
}

fn embedded_mihomo_cache_dir() -> PathBuf {
    dirs_next::cache_dir()
        .unwrap_or_else(|| std::env::temp_dir())
        .join("zay")
        .join("mihomo")
        .join(EMBEDDED_MIHOMO_VERSION)
}

fn materialize_embedded_mihomo() -> anyhow::Result<PathBuf> {
    let path = embedded_mihomo_cache_dir().join(mihomo_exe_name());
    if path.is_file() {
        return Ok(path);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    fs::write(&path, EMBEDDED_MIHOMO).with_context(|| {
        format!("writing embedded Mihomo to {}", path.display())
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .with_context(|| format!("metadata for {}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms)
            .with_context(|| format!("chmod {}", path.display()))?;
    }

    eprintln!(
        "zay: materialized embedded Mihomo {} → {}",
        EMBEDDED_MIHOMO_VERSION,
        path.display()
    );
    Ok(path)
}

fn resolve_mihomo_binary() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("ZAY_MIHOMO_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "ZAY_MIHOMO_BIN points to a missing file: {}",
            path.display()
        );
    }

    materialize_embedded_mihomo()
}

fn spawn_mihomo(
    binary: &Path,
    data_dir: &Path,
    config_path: &Path,
) -> anyhow::Result<Child> {
    let config_dir = config_path
        .parent()
        .context("config path has no parent directory")?;

    let mut cmd = Command::new(binary);
    cmd.arg("-d")
        .arg(config_dir)
        .arg("-f")
        .arg(config_path)
        .current_dir(data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd.spawn()
        .with_context(|| format!("spawning Mihomo at {}", binary.display()))
}

#[cfg(unix)]
fn terminate_process(pid: u32) {
    unsafe {
        let _ = libc::kill(pid as i32, libc::SIGTERM);
    }
}

#[cfg(windows)]
fn terminate_process(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn pipe_mihomo_logs(
    stream: impl std::io::Read + Send + 'static,
    label: &'static str,
) {
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            match line {
                Ok(line) => eprintln!("mihomo[{label}]: {line}"),
                Err(_) => break,
            }
        }
    });
}

fn run_mihomo(
    binary: &Path,
    data_dir: &Path,
    config_path: &Path,
) -> anyhow::Result<i32> {
    let mut child = spawn_mihomo(binary, data_dir, config_path)?;

    if let Some(stdout) = child.stdout.take() {
        pipe_mihomo_logs(stdout, "out");
    }
    if let Some(stderr) = child.stderr.take() {
        pipe_mihomo_logs(stderr, "err");
    }

    let pid = child.id();
    ctrlc::set_handler(move || {
        terminate_process(pid);
        eprintln!("zay: stopping Mihomo");
        std::process::exit(130);
    })
    .context("installing Ctrl-C handler")?;

    let status = child.wait().context("waiting for Mihomo")?;
    Ok(status.code().unwrap_or(1))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        SubCommand::Dump(args) => {
            let PreparedConfig { config_yaml, .. } = prepare(args)?;
            print!("{config_yaml}");
        }
        SubCommand::Serve(args) => {
            let PreparedConfig {
                data_dir,
                config_path,
                settings,
                ..
            } = prepare(args)?;

            let mihomo = resolve_mihomo_binary()?;
            eprintln!("zay: mihomo → {}", mihomo.display());
            eprintln!(
                "zay: starting – mixed proxy on 0.0.0.0:{}",
                settings.mixed_port
            );

            let code = run_mihomo(&mihomo, &data_dir, &config_path)?;
            if code != 0 {
                bail!("Mihomo exited with status {code}");
            }
        }
    }

    Ok(())
}
