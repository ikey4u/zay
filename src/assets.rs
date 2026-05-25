use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
};

use anyhow::{Context, bail};

use crate::settings;

const EMBEDDED_MIHOMO: &[u8] = include_bytes!(env!("MIHOMO_EMBED"));
const EMBEDDED_MIHOMO_VERSION: &str = env!("MIHOMO_VERSION");

/// Upstream Mihomo `docs/config.yaml` (v1.19.25), fetched at build time in `build.rs`.
const MIHOMO_CONFIG_TEMPLATE: &str =
    include_str!(concat!(env!("OUT_DIR"), "/mihomo-docs-config.yaml"));

pub const CONFIG_TEMPLATE_NAME: &str = "config.template.yaml";

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "mihomo.exe"
    } else {
        "mihomo"
    }
}

fn embedded_cache_dir() -> PathBuf {
    settings::default_cache_dir()
        .join("mihomo")
        .join(EMBEDDED_MIHOMO_VERSION)
}

fn materialize_embedded() -> anyhow::Result<PathBuf> {
    let path = embedded_cache_dir().join(exe_name());
    if path.is_file() {
        return Ok(path);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    fs::write(&path, EMBEDDED_MIHOMO).with_context(|| {
        format!("writing embedded proxy to {}", path.display())
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
        "materialized proxy {} → {}",
        EMBEDDED_MIHOMO_VERSION,
        path.display()
    );
    Ok(path)
}

/// Write the embedded Mihomo reference config into `<mihomo_dir>/config.template.yaml`.
pub fn ensure_config_template(mihomo_dir: &Path) -> anyhow::Result<()> {
    let path = mihomo_dir.join(CONFIG_TEMPLATE_NAME);
    if path.is_file() {
        return Ok(());
    }
    fs::write(&path, MIHOMO_CONFIG_TEMPLATE).with_context(|| {
        format!("writing Mihomo config reference to {}", path.display())
    })?;
    eprintln!(
        "created Mihomo config reference at {} (upstream docs/config.yaml)",
        path.display()
    );
    Ok(())
}

pub fn resolve_binary() -> anyhow::Result<PathBuf> {
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
    materialize_embedded()
}

#[cfg(unix)]
pub fn terminate_process(pid: u32) {
    unsafe {
        let _ = libc::kill(pid as i32, libc::SIGTERM);
    }
}

#[cfg(windows)]
pub fn terminate_process(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn spawn(
    binary: &Path,
    mihomo_dir: &Path,
    config_path: &Path,
    quiet: bool,
    privileged: bool,
) -> anyhow::Result<Child> {
    let config_path = config_path.canonicalize().with_context(|| {
        format!("canonicalizing config {}", config_path.display())
    })?;
    let config_dir = config_path
        .parent()
        .context("config path has no parent directory")?;
    let mihomo_dir = mihomo_dir.canonicalize().with_context(|| {
        format!("canonicalizing runtime dir {}", mihomo_dir.display())
    })?;

    #[cfg(unix)]
    if privileged && !crate::privilege::is_root() {
        crate::privilege::ensure_sudo_for_tun()?;
        return crate::privilege::spawn_via_sudo(
            binary,
            &[
                "-d",
                config_dir.to_str().context("non-UTF8 config dir")?,
                "-f",
                config_path.to_str().context("non-UTF8 config path")?,
            ],
            &mihomo_dir,
            quiet,
        );
    }

    #[cfg(not(unix))]
    if privileged {
        anyhow::bail!("TUN mode requires elevated privileges on this platform");
    }

    let mut cmd = Command::new(binary);
    cmd.arg("-d")
        .arg(config_dir)
        .arg("-f")
        .arg(&config_path)
        .current_dir(&mihomo_dir)
        .stdin(Stdio::null());

    if quiet {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    cmd.spawn()
        .with_context(|| format!("starting proxy at {}", binary.display()))
}

pub fn pipe_logs(stream: impl std::io::Read + Send + 'static) {
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            match line {
                Ok(line) => eprintln!("{line}"),
                Err(_) => break,
            }
        }
    });
}
