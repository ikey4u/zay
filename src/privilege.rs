use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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

fn wrapper_is_sudo(wrapper: &Path) -> bool {
    wrapper
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| name == "sudo" || name.ends_with("sudo"))
}

/// Build `sudo program …` when TUN needs root; otherwise `program …`.
pub fn command_for_program(
    program: &Path,
    privileged: bool,
) -> Result<Command> {
    Ok(command_for_program_with_password(program, privileged, None)?.0)
}

/// Like [`command_for_program`], but when `password` is set uses `sudo -S` with piped stdin.
///
/// Returns `(command, write_password_to_stdin)`; the caller must write the password after spawn
/// when the second value is `true`.
pub fn command_for_program_with_password(
    program: &Path,
    privileged: bool,
    password: Option<&str>,
) -> Result<(Command, bool)> {
    let program = program
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", program.display()))?;

    if !privileged || is_root() {
        return Ok((Command::new(program), false));
    }

    let wrapper = resolve_privilege_wrapper()?;

    if password.is_some() {
        if !wrapper_is_sudo(&wrapper) {
            bail!(
                "non-interactive admin password requires sudo; found {}",
                wrapper.display()
            );
        }
        let mut cmd = Command::new(wrapper);
        cmd.arg("-S").arg(&program).stdin(Stdio::piped());
        return Ok((cmd, true));
    }

    let mut cmd = Command::new(wrapper);
    cmd.arg(program);
    Ok((cmd, false))
}

/// Write `password` (+ newline) to a piped sudo stdin after spawn.
pub fn write_password_stdin(
    child: &mut std::process::Child,
    password: &str,
) -> Result<()> {
    let mut stdin = child.stdin.take().context("sudo stdin pipe missing")?;
    stdin
        .write_all(format!("{password}\n").as_bytes())
        .context("writing sudo password to stdin")?;
    Ok(())
}
