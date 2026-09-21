#[cfg(windows)]
use std::path::PathBuf;
use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    path::Path,
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};

/// A zay-owned process that hosts the native Rust library with TUN privileges.
/// On Windows an unelevated Zay cannot directly own the UAC-launched worker,
/// so PowerShell remains as a small waiting proxy.
pub struct NativeTunWorker {
    #[cfg(unix)]
    child: Child,
    #[cfg(windows)]
    shell: Child,
    #[cfg(windows)]
    elevated_pid: PathBuf,
}

#[cfg(unix)]
pub fn terminate_worker_process(pid: u32) {
    unsafe {
        // Workers are spawned as their own process group so this also stops
        // the zay child behind sudo, rather than leaving it orphaned.
        let _ = libc::kill(-(pid as i32), libc::SIGTERM);
        let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

#[cfg(windows)]
pub fn terminate_worker_process(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Free `127.0.0.1:port` when a leftover `sing-box` still holds it after a
/// previous daemon panic/crash. Other occupants are reported, not killed.
pub fn ensure_mixed_port_free(port: u16) -> anyhow::Result<()> {
    if mixed_port_free(port) {
        return Ok(());
    }
    let occupants = mixed_port_occupants(port);
    let mut killed = Vec::new();
    for (pid, name) in &occupants {
        if is_singbox_name(name) {
            eprintln!("clearing leftover {name} pid {pid} on 127.0.0.1:{port}");
            kill_pid(*pid);
            killed.push(*pid);
        }
    }
    if !killed.is_empty() {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if mixed_port_free(port) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    if mixed_port_free(port) {
        return Ok(());
    }
    let detail = if occupants.is_empty() {
        "another process".to_string()
    } else {
        occupants
            .iter()
            .map(|(pid, name)| format!("{name} pid {pid}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    bail!(
        "proxy port 127.0.0.1:{port} is already in use ({detail}); \
         stop that process, or `zay x config set mixed_port <other-port>`"
    );
}

fn mixed_port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn is_singbox_name(name: &str) -> bool {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    base == "sing-box" || base == "sing-box.exe"
}

#[cfg(unix)]
fn kill_pid(pid: u32) {
    unsafe {
        let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        let _ = libc::kill(-(pid as i32), libc::SIGTERM);
    }
}

#[cfg(windows)]
fn kill_pid(pid: u32) {
    terminate_worker_process(pid);
}

fn mixed_port_occupants(port: u16) -> Vec<(u32, String)> {
    let mut found = Vec::new();
    #[cfg(unix)]
    {
        if let Some(rows) = parse_ss_listeners(port) {
            found.extend(rows);
        }
        if found.is_empty()
            && let Some(rows) = parse_lsof_listeners(port)
        {
            found.extend(rows);
        }
    }
    #[cfg(windows)]
    {
        found.extend(parse_netstat_listeners(port));
    }
    found.sort_by_key(|(pid, _)| *pid);
    found.dedup_by_key(|(pid, _)| *pid);
    found
}

#[cfg(unix)]
fn parse_ss_listeners(port: u16) -> Option<Vec<(u32, String)>> {
    let output = Command::new("ss")
        .args(["-lptn", &format!("sport = :{port}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();
    for chunk in text.split("pid=") {
        let Some(pid_end) = chunk.find(|c: char| !c.is_ascii_digit()) else {
            continue;
        };
        if pid_end == 0 {
            continue;
        }
        let Ok(pid) = chunk[..pid_end].parse::<u32>() else {
            continue;
        };
        let name = process_comm(pid).unwrap_or_else(|| "unknown".into());
        rows.push((pid, name));
    }
    Some(rows)
}

#[cfg(unix)]
fn parse_lsof_listeners(port: u16) -> Option<Vec<(u32, String)>> {
    let output = Command::new("lsof")
        .args(["-nP", "-i", &format!("TCP:{port}"), "-sTCP:LISTEN"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let Some(name) = cols.next() else { continue };
        let Some(pid) = cols.next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        rows.push((pid, name.to_string()));
    }
    Some(rows)
}

#[cfg(unix)]
fn process_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let output = Command::new("ps")
                .args(["-o", "comm=", "-p", &pid.to_string()])
                .output()
                .ok()?;
            let name =
                String::from_utf8_lossy(&output.stdout).trim().to_string();
            (!name.is_empty()).then_some(name)
        })
}

#[cfg(windows)]
fn parse_netstat_listeners(port: u16) -> Vec<(u32, String)> {
    let Ok(output) =
        Command::new("netstat").args(["-ano", "-p", "tcp"]).output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let needle = format!(":{port}");
    let mut rows = Vec::new();
    for line in text.lines() {
        if !line.contains("LISTENING") || !line.contains(&needle) {
            continue;
        }
        let Some(pid) = line
            .split_whitespace()
            .last()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        rows.push((pid, windows_image_name(pid)));
    }
    rows
}

#[cfg(windows)]
fn windows_image_name(pid: u32) -> String {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .ok()
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            text.split(',')
                .next()
                .map(|name| name.trim_matches('"').to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

pub fn pipe_worker_logs(stream: impl std::io::Read + Send + 'static) {
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

impl NativeTunWorker {
    #[cfg(unix)]
    fn direct(child: Child) -> Self {
        Self { child }
    }

    #[cfg(windows)]
    fn elevated(shell: Child, elevated_pid: PathBuf) -> Self {
        Self {
            shell,
            elevated_pid,
        }
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        #[cfg(unix)]
        {
            self.child.stdout.take()
        }
        #[cfg(windows)]
        {
            None
        }
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        #[cfg(unix)]
        {
            self.child.stderr.take()
        }
        #[cfg(windows)]
        {
            None
        }
    }

    pub fn id(&self) -> u32 {
        #[cfg(unix)]
        {
            self.child.id()
        }
        #[cfg(windows)]
        {
            fs::read_to_string(&self.elevated_pid)
                .ok()
                .and_then(|raw| {
                    serde_json::from_str::<serde_json::Value>(&raw).ok()
                })
                .and_then(|value| value["pid"].as_u64())
                .map(|pid| pid as u32)
                .unwrap_or_else(|| self.shell.id())
        }
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        #[cfg(unix)]
        {
            self.child.try_wait()
        }
        #[cfg(windows)]
        {
            self.shell.try_wait()
        }
    }

    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        #[cfg(unix)]
        {
            self.child.wait()
        }
        #[cfg(windows)]
        {
            self.shell.wait()
        }
    }

    pub fn kill(&mut self) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            let pid = self.child.id();
            if unsafe { libc::kill(-(pid as i32), libc::SIGTERM) } != 0 {
                self.child.kill().context("stopping native TUN worker")?;
            }
        }
        #[cfg(windows)]
        {
            if !stop_elevated_worker(&self.elevated_pid)? {
                let pid = self.id();
                let status = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T", "/F"])
                    .status()
                    .context(
                        "force-stopping unresponsive elevated TUN worker",
                    )?;
                if !status.success() {
                    bail!("taskkill exited with {status}");
                }
            }
        }
        Ok(())
    }
}

/// Start an elevated zay-owned worker that hosts the Rust singbox library.
///
/// This is the Unix privilege boundary for native TUN. The worker receives
/// only the generated configuration and runtime directory.
#[cfg(unix)]
pub fn spawn_native_tun_worker(
    runtime_dir: &Path,
    config_path: &Path,
    quiet: bool,
    sudo_password: Option<&str>,
) -> anyhow::Result<NativeTunWorker> {
    let config_path = config_path.canonicalize().with_context(|| {
        format!("canonicalizing config {}", config_path.display())
    })?;
    let runtime_dir = runtime_dir.canonicalize().with_context(|| {
        format!("canonicalizing runtime dir {}", runtime_dir.display())
    })?;
    let executable =
        std::env::current_exe().context("locating zay TUN worker")?;
    let needs_elevation = !crate::privilege::is_root();
    let (mut command, write_password) =
        crate::privilege::command_for_program_with_password(
            &executable,
            true,
            sudo_password,
        )?;
    command
        .arg("--run-tun-worker")
        .arg("--tun-worker-runtime-dir")
        .arg(&runtime_dir)
        .arg("--tun-worker-config")
        .arg(&config_path)
        .current_dir(&runtime_dir);

    if needs_elevation && !write_password {
        command.stdin(Stdio::inherit());
    } else if !write_password {
        command.stdin(Stdio::null());
    }

    use std::os::unix::process::CommandExt as _;
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }

    if quiet {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    } else if needs_elevation && !write_password {
        command.stdout(Stdio::piped()).stderr(Stdio::inherit());
    } else {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    let mut child = command
        .spawn()
        .context("starting elevated native TUN worker")?;
    if write_password && let Some(password) = sudo_password {
        crate::privilege::write_password_stdin(&mut child, password)?;
    }
    Ok(NativeTunWorker::direct(child))
}

#[cfg(windows)]
pub fn spawn_native_tun_worker(
    runtime_dir: &Path,
    config_path: &Path,
    _quiet: bool,
    _sudo_password: Option<&str>,
) -> anyhow::Result<NativeTunWorker> {
    let config_path = config_path.canonicalize().with_context(|| {
        format!("canonicalizing config {}", config_path.display())
    })?;
    let runtime_dir = runtime_dir.canonicalize().with_context(|| {
        format!("canonicalizing runtime dir {}", runtime_dir.display())
    })?;
    spawn_elevated_windows(&runtime_dir, &config_path)
}

#[cfg(windows)]
fn spawn_elevated_windows(
    runtime_dir: &Path,
    config_path: &Path,
) -> anyhow::Result<NativeTunWorker> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let worker_file = runtime_dir.join("sing-box-worker.json");
    let _ = fs::remove_file(&worker_file);
    let zay = std::env::current_exe().context("locating zay TUN worker")?;
    let pipe = format!("zay-tun-{}", uuid::Uuid::new_v4());
    let token = uuid::Uuid::new_v4().to_string();
    let quote = |path: &Path| {
        format!("'{}'", path.display().to_string().replace('\'', "''"))
    };
    let quote_text = |value: &str| format!("'{}'", value.replace('\'', "''"));
    let script = format!(
        "$p=Start-Process -FilePath {} -ArgumentList @('--run-tun-worker','--tun-worker-runtime-dir',{},'--tun-worker-config',{},'--tun-worker-pipe',{},'--tun-worker-token',{}) -WorkingDirectory {} -Verb RunAs -PassThru; Wait-Process -Id $p.Id; exit $p.ExitCode",
        quote(&zay),
        quote(runtime_dir),
        quote(config_path),
        quote_text(&pipe),
        quote_text(&token),
        quote(runtime_dir),
    );
    let encoded = STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let shell = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("requesting UAC elevation for native TUN worker")?;
    Ok(NativeTunWorker::elevated(shell, worker_file))
}

#[cfg(windows)]
pub fn stop_elevated_worker(metadata_path: &Path) -> anyhow::Result<bool> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ClientOptions,
        time::{Duration, timeout},
    };

    let Ok(raw) = fs::read_to_string(metadata_path) else {
        return Ok(false);
    };
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", metadata_path.display()))?;
    let (Some(pipe), Some(token)) =
        (value["pipe"].as_str(), value["token"].as_str())
    else {
        return Ok(false);
    };
    let pipe = format!(r"\\.\pipe\{pipe}");
    let token = token.to_owned();
    let stopped = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating TUN worker control runtime")?
        .block_on(async move {
            let client = timeout(Duration::from_secs(3), async {
                loop {
                    match ClientOptions::new().open(&pipe) {
                        Ok(client) => break Ok(client),
                        Err(error)
                            if error.kind() == std::io::ErrorKind::NotFound =>
                        {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        Err(error) => break Err(error),
                    }
                }
            })
            .await
            .ok()
            .and_then(Result::ok);
            let Some(mut client) = client else {
                return false;
            };
            if client
                .write_all(format!("{token} stop\n").as_bytes())
                .await
                .is_err()
            {
                return false;
            }
            let mut response = String::new();
            timeout(
                Duration::from_secs(5),
                client.read_to_string(&mut response),
            )
            .await
            .is_ok_and(|result| result.is_ok() && response.trim() == "stopped")
        });
    if stopped {
        let _ = fs::remove_file(metadata_path);
    }
    Ok(stopped)
}

#[cfg(test)]
mod tests {
    use super::{is_singbox_name, mixed_port_free};

    #[test]
    fn recognizes_singbox_process_names() {
        assert!(is_singbox_name("sing-box"));
        assert!(is_singbox_name("sing-box.exe"));
        assert!(is_singbox_name(
            "/home/m9/.cache/zay/sing-box/vendor-x/sing-box"
        ));
        assert!(!is_singbox_name("clash-meta"));
        assert!(!is_singbox_name("zay"));
    }

    #[test]
    fn ephemeral_bind_is_free() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(!mixed_port_free(port));
        drop(listener);
        assert!(mixed_port_free(port));
    }
}
