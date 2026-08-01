#[cfg(unix)]
use std::{io, process::Stdio};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

const NO_ELEVATION_TOOL_MSG: &str = "\
TUN mode requires administrator privileges, but no elevation tool was found.

Install sudo (apt install sudo) or doas (apk add doas), or run as root:
  zay run proxy …";

fn command_in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
        })
        .unwrap_or(false)
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Resolve `sudo` or `doas`, preferring well-known absolute paths (Linux PATH is often minimal).
#[cfg(unix)]
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

#[cfg(not(unix))]
pub fn resolve_privilege_wrapper() -> Result<PathBuf> {
    bail!("privilege elevation wrappers are only supported on Unix");
}

/// Authenticate before daemonizing so the detached supervisor never needs a
/// terminal. For mesh **node**, the daemon itself is elevated (EasyTier TUN).
/// Otherwise only the subsequently spawned sing-box TUN worker runs as root.
#[cfg(unix)]
pub fn preflight_tun_worker() -> Result<()> {
    if is_root() {
        return Ok(());
    }

    let wrapper = resolve_privilege_wrapper()?;
    let mut command = Command::new(&wrapper);
    if wrapper_is_sudo(&wrapper) {
        command.arg("-v");
    } else {
        // doas has no portable equivalent of `sudo -v`; verify that its
        // configured authorization can run a harmless command noninteractively.
        command.args(["-n", "true"]);
    }
    let status = command.status().with_context(|| {
        format!("requesting TUN elevation through {}", wrapper.display())
    })?;
    if !status.success() {
        bail!(
            "TUN elevation was not authorized; authenticate with `{}` and retry",
            wrapper.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn preflight_tun_worker() -> Result<()> {
    Ok(())
}

/// Prompt and validate a sudo password before daemonizing. The caller passes
/// the returned value through a private runtime channel to the TUN worker.
#[cfg(unix)]
pub fn daemon_tun_password() -> Result<Option<String>> {
    if is_root() {
        return Ok(None);
    }
    let wrapper = resolve_privilege_wrapper()?;
    if !wrapper_is_sudo(&wrapper) {
        preflight_tun_worker()?;
        return Ok(None);
    }

    let password = read_password("sudo password required: ")?;
    let mut command = Command::new(&wrapper);
    command.args(["-S", "-p", "", "-v"]).stdin(Stdio::piped());
    let mut child = command.spawn().with_context(|| {
        format!("requesting TUN elevation through {}", wrapper.display())
    })?;
    write_password_stdin(&mut child, &password)?;
    if !child
        .wait()
        .context("waiting for sudo authentication")?
        .success()
    {
        bail!("TUN elevation was not authorized");
    }
    Ok(Some(password))
}

#[cfg(not(unix))]
pub fn daemon_tun_password() -> Result<Option<String>> {
    Ok(None)
}

#[cfg(unix)]
fn read_password(prompt: &str) -> Result<String> {
    use std::os::fd::AsRawFd;

    print!("{prompt}");
    io::stdout().flush().context("flushing password prompt")?;
    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("reading terminal settings");
    }
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("hiding password input");
    }

    let mut password = String::new();
    let result = stdin
        .read_line(&mut password)
        .context("reading sudo password");
    let restore = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
    println!();
    if restore != 0 {
        return Err(std::io::Error::last_os_error())
            .context("restoring terminal settings");
    }
    result?;
    let password = password.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        bail!("sudo password cannot be empty");
    }
    Ok(password)
}

fn wrapper_is_sudo(wrapper: &Path) -> bool {
    wrapper
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| name == "sudo" || name.ends_with("sudo"))
}

/// Build `sudo -S program …` for elevating a daemon with a piped password.
///
/// Do **not** `setsid` before this sudo: macOS `tty_tickets` makes `sudo -n`
/// fail in a new session, and a detached `-S` child often cannot finish auth.
/// Call [`crate::daemon::become_session_leader`] inside `--run-daemon` instead.
pub fn command_for_elevated_daemon(
    program: &Path,
    password: Option<&str>,
) -> Result<(Command, bool)> {
    command_for_program_with_password(program, true, password)
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

    #[cfg(not(unix))]
    {
        let _ = password;
        bail!(
            "elevating a child process via sudo/doas is only supported on Unix; \
             on Windows use the elevated TUN worker path"
        );
    }

    #[cfg(unix)]
    {
        let wrapper = resolve_privilege_wrapper()?;

        if password.is_some() {
            if !wrapper_is_sudo(&wrapper) {
                bail!(
                    "non-interactive admin password requires sudo; found {}",
                    wrapper.display()
                );
            }
            let mut cmd = Command::new(wrapper);
            // -p "" suppresses the Password: prompt on the redirected stderr log.
            cmd.args(["-S", "-p", ""])
                .arg(&program)
                .stdin(Stdio::piped());
            return Ok((cmd, true));
        }

        let mut cmd = Command::new(wrapper);
        cmd.arg(program);
        Ok((cmd, false))
    }
}

/// When the daemon runs as root via `sudo`, return the invoking user's uid/gid.
#[cfg(unix)]
pub fn sudo_invoker_ids() -> Option<(u32, u32)> {
    if !is_root() {
        return None;
    }
    let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    if uid == 0 {
        return None;
    }
    Some((uid, gid))
}

/// Re-own a path created under an elevated daemon so the invoking user can
/// still `service stop` / read logs / read `config.json` without sudo.
#[cfg(unix)]
pub fn restore_invoker_ownership(path: &Path) {
    let Some((uid, gid)) = sudo_invoker_ids() else {
        return;
    };
    let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
}

#[cfg(not(unix))]
pub fn restore_invoker_ownership(_path: &Path) {}

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
