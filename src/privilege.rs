use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

const NO_ELEVATION_TOOL_MSG: &str = "\
TUN mode requires administrator privileges, but no elevation tool was found.

Install sudo (apt install sudo) or doas (apk add doas), or run as root:
  sudo zay stack …";

fn command_in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
        })
        .unwrap_or(false)
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Resolve `sudo` or `doas`, preferring well-known absolute paths (Linux PATH is often minimal).
pub fn resolve_privilege_wrapper() -> Result<PathBuf> {
    for candidate in ["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    if command_in_path("sudo") {
        return Ok(PathBuf::from("sudo"));
    }
    for candidate in ["/usr/bin/doas", "/bin/doas"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    if command_in_path("doas") {
        return Ok(PathBuf::from("doas"));
    }
    bail!(NO_ELEVATION_TOOL_MSG);
}

/// Build `sudo program …` when TUN needs root; otherwise `program …`.
pub fn command_for_program(
    program: &Path,
    privileged: bool,
) -> Result<Command> {
    let program = program
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", program.display()))?;

    if !privileged || is_root() {
        return Ok(Command::new(program));
    }

    let wrapper = resolve_privilege_wrapper()?;
    let mut cmd = Command::new(wrapper);
    cmd.arg(program);
    Ok(cmd)
}
