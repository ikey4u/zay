use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

const NO_ELEVATION_TOOL_MSG: &str = "\
TUN mode requires administrator privileges, but no elevation tool was found in PATH.

Install sudo (apt install sudo) or doas (apk add doas), or run as root:
  su -c 'zay stack --tun …'";

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

fn elevation_wrapper() -> Result<&'static str> {
    if command_in_path("sudo") {
        Ok("sudo")
    } else if command_in_path("doas") {
        Ok("doas")
    } else {
        bail!(NO_ELEVATION_TOOL_MSG);
    }
}

/// Re-exec this process with raised privileges when TUN is enabled and we are not root.
/// Invokes the system `sudo` or `doas` binary (which may be sudo-rs on newer distros).
pub fn elevate_self_for_tun() -> Result<()> {
    if is_root() {
        return Ok(());
    }

    let wrapper = elevation_wrapper()?;
    let exe = std::env::current_exe().context("reading current executable")?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    let status = Command::new(wrapper)
        .arg(&exe)
        .args(&args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("re-executing via {wrapper} (TUN mode)"))?;

    std::process::exit(status.code().unwrap_or(1));
}
