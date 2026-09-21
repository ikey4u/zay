//! Loopback control channel for foreground Zay runtimes.
//!
//! Process lifetime belongs to the caller or its system process manager. This
//! module does not detach, daemonize, or install an operating-system service.

#[cfg(windows)]
use std::process::Command;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

use crate::{settings, stack::controller::StackController};

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
        bail!("zay x service is not running");
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
            .context("stopping zay x service")?;
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
