use std::{
    io::Write,
    path::Path,
    process::{Child, Command, Stdio},
};

use anyhow::{Context, Result, bail};

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn sudo_non_interactive_ok() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn read_sudo_password() -> Result<String> {
    eprint!("TUN requires administrator access. Password: ");
    std::io::stderr().flush()?;
    rpassword::read_password().context("reading password")
}

fn sudo_validate_password(password: &str) -> Result<()> {
    let mut child = Command::new("sudo")
        .args(["-S", "-p", "", "-v"])
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("starting sudo")?;
    writeln!(child.stdin.as_mut().unwrap(), "{password}")
        .context("sending password to sudo")?;
    let status = child.wait().context("waiting for sudo")?;
    if !status.success() {
        bail!("sudo authentication failed");
    }
    Ok(())
}

/// Ask for sudo password when needed; reuse cached sudo ticket when available.
pub fn ensure_sudo_for_tun() -> Result<()> {
    if is_root() {
        return Ok(());
    }
    if sudo_non_interactive_ok() {
        eprintln!("using cached sudo credentials");
        return Ok(());
    }
    let password = read_sudo_password()?;
    sudo_validate_password(&password)?;
    eprintln!("administrator access granted");
    Ok(())
}

pub fn spawn_via_sudo(
    program: &Path,
    args: &[&str],
    cwd: &Path,
    quiet: bool,
) -> Result<Child> {
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", "-E", "--"])
        .arg(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null());

    if quiet {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    cmd.spawn().with_context(|| {
        format!("starting proxy via sudo at {}", program.display())
    })
}
