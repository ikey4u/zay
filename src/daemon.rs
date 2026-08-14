//! Cross-platform application-managed background runtime.
//!
//! This is intentionally not a system-service installer. `zay service start`
//! re-execs the current executable with detached process settings and leaves
//! lifecycle ownership with Zay's local runtime directory.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

use crate::{settings, stack::controller::StackController};

const READY_WAIT: Duration = Duration::from_secs(45);

#[derive(Clone, Debug)]
pub struct Paths {
    pub run_dir: PathBuf,
    pub log_dir: PathBuf,
    pub lock: PathBuf,
    pub pid: PathBuf,
    pub ready: PathBuf,
    pub control: PathBuf,
    pub log: PathBuf,
}

pub fn paths(data_dir: Option<&Path>, config: Option<&Path>) -> Paths {
    let (data_dir, _) = settings::stack_config_paths(data_dir, config);
    let run_dir = data_dir.join("run");
    let log_dir = data_dir.join("logs");
    Paths {
        lock: run_dir.join("zay.lock"),
        pid: run_dir.join("zay.pid"),
        ready: run_dir.join("zay.ready"),
        control: run_dir.join("control-port"),
        log: log_dir.join("zay.log"),
        run_dir,
        log_dir,
    }
}

/// Re-exec Zay in a new process/session and wait until it owns the runtime lock.
///
/// When `[proxy.mesh] role = "node"`, the daemon itself is elevated so in-process
/// EasyTier can create a kernel TUN (sing-box then runs as the same root user).
pub fn spawn(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    sudo_password: Option<String>,
) -> Result<()> {
    let paths = paths(data_dir.as_deref(), config.as_deref());
    fs::create_dir_all(&paths.run_dir)
        .with_context(|| format!("creating {}", paths.run_dir.display()))?;
    fs::create_dir_all(&paths.log_dir)
        .with_context(|| format!("creating {}", paths.log_dir.display()))?;
    reject_live_instance(&paths)?;
    let _ = fs::remove_file(&paths.ready);

    let exe =
        std::env::current_exe().context("locating current zay executable")?;
    let elevate_daemon = {
        #[cfg(unix)]
        {
            mesh_node_requires_daemon_elevation(
                data_dir.as_deref(),
                config.as_deref(),
            )?
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    if elevate_daemon {
        eprintln!(
            "mesh node: elevating daemon so EasyTier can create its kernel TUN"
        );
    }

    let log = open_log(&paths.log)?;
    let log_err = log.try_clone().context("cloning daemon log handle")?;

    // Resolve paths as the *invoking* user, then always pass them through so an
    // elevated child does not re-derive defaults under a different HOME.
    let (resolved_data_dir, resolved_config) =
        settings::stack_config_paths(data_dir.as_deref(), config.as_deref());

    // Mesh node: elevate with `sudo -S` + password pipe. Do NOT setsid first —
    // macOS tty_tickets makes `sudo -n` fail in a new session.
    // `--run-daemon` calls become_session_leader() after sudo has exec'd zay.
    let (mut command, write_password) = if elevate_daemon {
        crate::privilege::command_for_elevated_daemon(
            &exe,
            sudo_password.as_deref(),
        )?
    } else {
        (Command::new(&exe), false)
    };
    command
        .arg("--run-daemon")
        .arg("--data-dir")
        .arg(&resolved_data_dir)
        .arg("--config")
        .arg(&resolved_config)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    #[cfg(unix)]
    command.stdin(if write_password {
        Stdio::piped()
    } else if elevate_daemon {
        Stdio::null()
    } else {
        Stdio::inherit()
    });
    #[cfg(not(unix))]
    command.stdin(Stdio::null());
    // Only pass a sudo password file when the daemon stays unprivileged and
    // sing-box alone needs elevation.
    let password_file = if !elevate_daemon {
        if let Some(password) = sudo_password.as_ref() {
            let path = paths
                .run_dir
                .join(format!(".sudo-password-{}", std::process::id()));
            write_sudo_password(&path, password)?;
            command.env("ZAY_SUDO_PASSWORD_FILE", &path);
            Some(path)
        } else {
            None
        }
    } else {
        None
    };
    if !elevate_daemon {
        detach(&mut command)?;
    }
    let mut child = command.spawn().context("starting daemon process")?;
    if write_password {
        let password = sudo_password
            .as_deref()
            .context("sudo password missing for elevated daemon")?;
        crate::privilege::write_password_stdin(&mut child, password)?;
    }

    let deadline = Instant::now() + READY_WAIT;
    loop {
        if paths.ready.is_file() {
            println!(
                "zay service started (pid {}; log {})",
                child.id(),
                paths.log.display()
            );
            return Ok(());
        }
        if let Some(status) =
            child.try_wait().context("checking daemon startup")?
        {
            remove_sudo_password(password_file.as_deref());
            if elevate_daemon {
                bail!(
                    "elevated daemon exited during startup ({status}); see {}",
                    paths.log.display()
                );
            }
            bail!(
                "daemon exited during startup ({status}); see {}",
                paths.log.display()
            );
        }
        if Instant::now() >= deadline {
            remove_sudo_password(password_file.as_deref());
            bail!(
                "timed out waiting for daemon startup; see {}",
                paths.log.display()
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn mesh_node_requires_daemon_elevation(
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> Result<bool> {
    let cfg = settings::load_persistent_config(data_dir, config)?;
    Ok(cfg
        .mesh
        .as_ref()
        .is_some_and(|mesh| mesh.enabled && mesh.is_node()))
}

/// Fail fast before collecting credentials or starting a detached process.
pub fn ensure_not_running(
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> Result<()> {
    let paths = paths(data_dir, config);
    reject_live_instance(&paths)
}

pub fn take_sudo_password() -> Result<Option<String>> {
    let Some(path) =
        std::env::var_os("ZAY_SUDO_PASSWORD_FILE").map(PathBuf::from)
    else {
        return Ok(None);
    };
    let password = fs::read_to_string(&path).with_context(|| {
        format!("reading daemon sudo credential {}", path.display())
    })?;
    fs::remove_file(&path).with_context(|| {
        format!("removing daemon sudo credential {}", path.display())
    })?;
    Ok(Some(password))
}

fn remove_sudo_password(path: Option<&Path>) {
    if let Some(path) = path {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
fn write_sudo_password(path: &Path, password: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!("creating daemon sudo credential {}", path.display())
        })?;
    file.write_all(password.as_bytes())
        .context("writing daemon sudo credential")
}

#[cfg(not(unix))]
fn write_sudo_password(_path: &Path, _password: &str) -> Result<()> {
    Ok(())
}

pub struct Guard {
    paths: Paths,
}

impl Guard {
    pub fn mark_ready(&self) -> Result<()> {
        fs::write(&self.paths.ready, "ready\n").with_context(|| {
            format!("writing {}", self.paths.ready.display())
        })?;
        crate::privilege::restore_invoker_ownership(&self.paths.ready);
        Ok(())
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.paths.ready);
        let _ = fs::remove_file(&self.paths.pid);
        let _ = fs::remove_file(&self.paths.lock);
        let _ = fs::remove_file(&self.paths.control);
    }
}

/// EasyTier's `collect_network_infos_sync` uses `Handle::block_on`, which panics
/// if the current thread has entered a Tokio runtime. The control server runs
/// inside the daemon runtime, and `spawn_blocking` also enters it, so hop to a
/// plain OS thread — the same pattern as `StackController` mesh start.
async fn mesh_status_json() -> String {
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        let result = crate::stack::easytier::status().and_then(|status| {
            serde_json::to_string(&status)
                .context("serializing EasyTier mesh status")
        });
        let _ = tx.send(result);
    });
    match rx.await {
        Ok(Ok(json)) => json,
        Ok(Err(error)) => {
            serde_json::json!({ "error": format!("{error:#}") }).to_string()
        }
        Err(_) => serde_json::json!({ "error": "mesh status thread exited" })
            .to_string(),
    }
}

/// Start a loopback-only control listener shared by foreground and daemon runs.
/// The persisted port is intentionally private to the current user's data directory.
pub async fn start_control(
    paths: &Paths,
    shutdown: oneshot::Sender<()>,
    stack: Option<Arc<StackController>>,
) -> Result<JoinHandle<()>> {
    fs::create_dir_all(&paths.run_dir)
        .with_context(|| format!("creating {}", paths.run_dir.display()))?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding local control listener")?;
    let addr = listener.local_addr().context("reading control address")?;
    fs::write(&paths.control, format!("{}\n", addr.port()))
        .with_context(|| format!("writing {}", paths.control.display()))?;
    crate::privilege::restore_invoker_ownership(&paths.control);

    Ok(tokio::spawn(async move {
        let mut shutdown = Some(shutdown);
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut command = [0_u8; 32];
            let Ok(n) = stream.read(&mut command).await else {
                continue;
            };
            match std::str::from_utf8(&command[..n]).unwrap_or("").trim() {
                "status" => {
                    let _ = stream.write_all(b"running\n").await;
                }
                "stop" => {
                    let _ = stream.write_all(b"stopping\n").await;
                    if let Some(tx) = shutdown.take() {
                        let _ = tx.send(());
                    }
                    break;
                }
                "mesh-status" => {
                    let _ = stream
                        .write_all(mesh_status_json().await.as_bytes())
                        .await;
                }
                "stack-status" => {
                    let response = match &stack {
                        Some(controller) => serde_json::to_string(&controller.status())
                            .unwrap_or_else(|error| {
                                serde_json::json!({ "error": format!("{error:#}") })
                                    .to_string()
                            }),
                        None => serde_json::json!({ "error": "proxy stack is not enabled" })
                            .to_string(),
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                }
                _ => {
                    let _ = stream.write_all(b"unknown command\n").await;
                }
            }
            // `read_to_string` on the control client needs an EOF after the
            // response; do not retain its connection while waiting for the
            // next listener accept.
            drop(stream);
        }
    }))
}

pub async fn request(paths: &Paths, command: &str) -> Result<String> {
    let raw = fs::read_to_string(&paths.control)
        .with_context(|| format!("reading {}", paths.control.display()))?;
    let port: u16 = raw.trim().parse().context("parsing control port")?;
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .context("connecting to zay control runtime")?;
    stream
        .write_all(format!("{command}\n").as_bytes())
        .await
        .context("sending control command")?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .context("reading control response")?;
    Ok(response.trim().to_string())
}

pub fn remove_control(paths: &Paths) {
    let _ = fs::remove_file(&paths.control);
}

/// Claim the singleton runtime from the re-executed daemon process.
pub fn enter(data_dir: Option<&Path>, config: Option<&Path>) -> Result<Guard> {
    become_session_leader()?;
    let paths = paths(data_dir, config);
    fs::create_dir_all(&paths.run_dir)
        .with_context(|| format!("creating {}", paths.run_dir.display()))?;
    fs::create_dir_all(&paths.log_dir)
        .with_context(|| format!("creating {}", paths.log_dir.display()))?;
    reject_live_instance(&paths)?;
    let mut lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&paths.lock)
        .with_context(|| format!("creating {}", paths.lock.display()))?;
    writeln!(lock, "{}", std::process::id())?;
    crate::privilege::restore_invoker_ownership(&paths.lock);
    fs::write(&paths.pid, format!("{}\n", std::process::id()))
        .with_context(|| format!("writing {}", paths.pid.display()))?;
    crate::privilege::restore_invoker_ownership(&paths.pid);
    crate::privilege::restore_invoker_ownership(&paths.run_dir);
    crate::privilege::restore_invoker_ownership(&paths.log_dir);
    Ok(Guard { paths })
}

/// Detach from the controlling terminal after elevated `sudo` has already exec'd.
///
/// Parent skips `setsid` when spawning `sudo -S` (auth needs the pipe / TTY ticket);
/// the daemon itself becomes a session leader here instead.
#[cfg(unix)]
pub fn become_session_leader() -> Result<()> {
    let rc = unsafe { libc::setsid() };
    if rc == -1 {
        let err = std::io::Error::last_os_error();
        // Already a session leader (parent detached us) — fine.
        if err.raw_os_error() == Some(libc::EPERM) {
            return Ok(());
        }
        return Err(err).context("setsid for daemon session");
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn become_session_leader() -> Result<()> {
    Ok(())
}

pub fn status(
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> Result<Option<u32>> {
    let paths = paths(data_dir, config);
    let Ok(raw) = fs::read_to_string(&paths.pid) else {
        return Ok(None);
    };
    let Ok(pid) = raw.trim().parse::<u32>() else {
        return Ok(None);
    };
    if process_is_alive(pid) {
        Ok(Some(pid))
    } else {
        Ok(None)
    }
}

pub fn terminate(data_dir: Option<&Path>, config: Option<&Path>) -> Result<()> {
    let Some(pid) = status(data_dir, config)? else {
        bail!("zay service is not running");
    };
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .context("sending SIGTERM");
        }
    }
    #[cfg(windows)]
    {
        let (data_dir, _) = settings::stack_config_paths(data_dir, config);
        let worker_file = data_dir
            .join(settings::SINGBOX_DIR)
            .join("sing-box-worker.json");
        let worker_stopped =
            crate::singbox::assets::stop_elevated_worker(&worker_file)
                .unwrap_or(false);
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status()
            .context("stopping zay service")?;
        if !status.success() {
            bail!("taskkill exited with {status}");
        }
        if !worker_stopped
            && let Ok(raw) = fs::read_to_string(&worker_file)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw)
            && let Some(worker_pid) = value["pid"].as_u64()
        {
            let _ = Command::new("taskkill")
                .args(["/PID", &worker_pid.to_string(), "/T", "/F"])
                .status();
        }
        let _ = fs::remove_file(worker_file);
    }
    Ok(())
}

fn reject_live_instance(paths: &Paths) -> Result<()> {
    if let Some(pid) = status_from_paths(paths)? {
        bail!("zay service is already running (pid {pid})");
    }
    // A stale pid/lock can remain after a forced kill or reboot.
    let _ = fs::remove_file(&paths.lock);
    let _ = fs::remove_file(&paths.pid);
    Ok(())
}

fn status_from_paths(paths: &Paths) -> Result<Option<u32>> {
    let Ok(raw) = fs::read_to_string(&paths.pid) else {
        return Ok(None);
    };
    let Ok(pid) = raw.trim().parse::<u32>() else {
        return Ok(None);
    };
    Ok(process_is_alive(pid).then_some(pid))
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    // kill(pid, 0) does not send a signal; EPERM still proves a process exists.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    // `tasklist` is available on supported Windows editions and avoids adding a
    // Windows-only FFI dependency just for stale PID cleanup.
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .ok()
        .is_some_and(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines().any(|line| {
                line.split_whitespace()
                    .any(|field| field == pid.to_string())
            })
        })
}

fn open_log(path: &Path) -> Result<File> {
    rotate_log(path)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const LOG_ROTATIONS: usize = 5;

fn rotate_log(path: &Path) -> Result<()> {
    if fs::metadata(path).map(|meta| meta.len()).unwrap_or(0) < MAX_LOG_BYTES {
        return Ok(());
    }
    for index in (1..LOG_ROTATIONS).rev() {
        let from = path.with_extension(format!("log.{index}"));
        let to = path.with_extension(format!("log.{}", index + 1));
        if from.is_file() {
            let _ = fs::rename(from, to);
        }
    }
    fs::rename(path, path.with_extension("log.1"))
        .with_context(|| format!("rotating {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn detach(command: &mut Command) -> Result<()> {
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(windows)]
fn detach(command: &mut Command) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    Ok(())
}
