use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};

use crate::settings;

const EMBEDDED_SINGBOX: &[u8] = include_bytes!(env!("SINGBOX_EMBED"));
const EMBEDDED_SINGBOX_VERSION: &str = env!("SINGBOX_VERSION");

/// A sing-box process. On Windows an unelevated Zay cannot directly own the
/// UAC-launched child, so PowerShell remains as a small waiting proxy.
pub struct ManagedChild {
    #[cfg(unix)]
    child: Child,
    #[cfg(windows)]
    shell: Child,
    #[cfg(windows)]
    elevated_pid: PathBuf,
}

#[cfg(unix)]
pub fn terminate_process(pid: u32) {
    unsafe {
        // Workers are spawned as their own process group so this also stops
        // the sing-box child behind sudo, rather than leaving it orphaned.
        let _ = libc::kill(-(pid as i32), libc::SIGTERM);
        let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
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
         stop that process, or `zay config set mixed_port <other-port>`"
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
    terminate_process(pid);
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

impl ManagedChild {
    #[cfg(unix)]
    fn direct(child: Child) -> Self {
        Self { child }
    }

    #[cfg(windows)]
    fn direct(shell: Child) -> Self {
        Self {
            shell,
            elevated_pid: PathBuf::new(),
        }
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
                self.child.kill().context("stopping sing-box")?;
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
) -> anyhow::Result<ManagedChild> {
    let config_path = config_path.canonicalize().with_context(|| {
        format!("canonicalizing config {}", config_path.display())
    })?;
    let runtime_dir = runtime_dir.canonicalize().with_context(|| {
        format!("canonicalizing runtime dir {}", runtime_dir.display())
    })?;

    #[cfg(unix)]
    let needs_elevation = privileged && !crate::privilege::is_root();

    #[cfg(unix)]
    let (mut cmd, write_password) =
        crate::privilege::command_for_program_with_password(
            binary,
            privileged,
            sudo_password,
        )?;

    #[cfg(windows)]
    if privileged {
        return spawn_elevated_windows(binary, &runtime_dir, &config_path);
    }

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
            // sudo -S: password written after spawn for non-interactive startup.
        } else {
            // sudo/doas reads the password from the terminal (CLI).
            cmd.stdin(Stdio::inherit());
        }
    } else if !write_password {
        cmd.stdin(Stdio::null());
    }

    #[cfg(not(unix))]
    cmd.stdin(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }

    if quiet {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    } else {
        #[cfg(unix)]
        if needs_elevation && !write_password {
            // sudo's password prompt has no trailing newline. It must go directly
            // to the terminal instead of through the line-based sing-box log pipe.
            cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        #[cfg(not(unix))]
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

    Ok(ManagedChild::direct(child))
}

#[cfg(windows)]
fn spawn_elevated_windows(
    binary: &Path,
    runtime_dir: &Path,
    config_path: &Path,
) -> anyhow::Result<ManagedChild> {
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
        "$p=Start-Process -FilePath {} -ArgumentList @('--run-tun-worker','--tun-worker-binary',{},'--tun-worker-runtime-dir',{},'--tun-worker-config',{},'--tun-worker-pipe',{},'--tun-worker-token',{}) -WorkingDirectory {} -Verb RunAs -PassThru; Wait-Process -Id $p.Id; exit $p.ExitCode",
        quote(&zay),
        quote(binary),
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
        .context("requesting UAC elevation for sing-box TUN worker")?;
    Ok(ManagedChild::elevated(shell, worker_file))
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
