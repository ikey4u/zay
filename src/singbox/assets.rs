use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::{Context, bail};

use crate::settings;

const EMBEDDED_SINGBOX: &[u8] = include_bytes!(env!("SINGBOX_EMBED"));
const EMBEDDED_SINGBOX_VERSION: &str = env!("SINGBOX_VERSION");

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    }
}

fn embedded_cache_dir() -> PathBuf {
    settings::default_cache_dir()
        .join("sing-box")
        .join(EMBEDDED_SINGBOX_VERSION)
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

    fs::write(&path, EMBEDDED_SINGBOX).with_context(|| {
        format!("writing embedded sing-box to {}", path.display())
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
        "materialized sing-box {} → {}",
        EMBEDDED_SINGBOX_VERSION,
        path.display()
    );
    Ok(path)
}

pub fn resolve_binary() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("ZAY_SINGBOX_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "ZAY_SINGBOX_BIN points to a missing file: {}",
            path.display()
        );
    }
    materialize_embedded()
}

pub fn spawn(
    binary: &Path,
    runtime_dir: &Path,
    config_path: &Path,
    quiet: bool,
    privileged: bool,
    sudo_password: Option<&str>,
) -> anyhow::Result<Child> {
    let config_path = config_path.canonicalize().with_context(|| {
        format!("canonicalizing config {}", config_path.display())
    })?;
    let runtime_dir = runtime_dir.canonicalize().with_context(|| {
        format!("canonicalizing runtime dir {}", runtime_dir.display())
    })?;

    #[cfg(unix)]
    let needs_elevation = privileged && !crate::privilege::is_root();

    #[cfg(not(unix))]
    if privileged {
        anyhow::bail!("TUN mode requires elevated privileges on this platform");
    }

    #[cfg(unix)]
    let (mut cmd, write_password) =
        crate::privilege::command_for_program_with_password(
            binary,
            privileged,
            sudo_password,
        )?;

    #[cfg(not(unix))]
    let mut cmd = Command::new(binary);

    cmd.arg("run")
        .arg("-c")
        .arg(&config_path)
        .arg("-D")
        .arg(&runtime_dir)
        .current_dir(&runtime_dir);

    #[cfg(unix)]
    if needs_elevation {
        if write_password {
            // sudo -S: password written after spawn (WebUI / non-interactive).
        } else {
            // sudo/doas reads the password from the terminal (CLI).
            cmd.stdin(Stdio::inherit());
        }
    } else if !write_password {
        cmd.stdin(Stdio::null());
    }

    #[cfg(not(unix))]
    cmd.stdin(Stdio::null());

    if quiet {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    let mut child = cmd.spawn().with_context(|| {
        format!("starting sing-box at {}", binary.display())
    })?;

    #[cfg(unix)]
    if write_password {
        if let Some(password) = sudo_password {
            crate::privilege::write_password_stdin(&mut child, password)?;
        }
    }

    Ok(child)
}
