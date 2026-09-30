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
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, oneshot},
    task::JoinHandle,
};

use crate::{runtime::CoreRuntime, settings};

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
#[derive(serde::Serialize, serde::Deserialize)]
struct ControlEndpoint {
    port: u16,
    token: String,
}

pub async fn start_control(
    paths: &Paths,
    shutdown: oneshot::Sender<()>,
    core: Arc<Mutex<CoreRuntime>>,
) -> Result<JoinHandle<()>> {
    use std::io::Write;
    fs::create_dir_all(&paths.run_dir)?;
    crate::privilege::restore_invoker_ownership(&paths.run_dir);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding local control listener")?;
    let token = uuid::Uuid::new_v4().to_string();
    let endpoint = ControlEndpoint {
        port: listener.local_addr()?.port(),
        token: token.clone(),
    };
    let temp = paths
        .run_dir
        .join(format!("control-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(&serde_json::to_vec(&endpoint)?)?;
    crate::privilege::restore_invoker_ownership(&temp);
    fs::rename(&temp, &paths.control)?;

    Ok(tokio::spawn(async move {
        let mut shutdown = Some(shutdown);
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut line = String::new();
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                async {
                    BufReader::new(&mut stream)
                        .take(4096)
                        .read_line(&mut line)
                        .await
                },
            )
            .await;
            if !matches!(read, Ok(Ok(_))) || !line.ends_with('\n') {
                continue;
            }
            let Some((provided, command)) = line.trim().split_once(' ') else {
                continue;
            };
            if provided != token {
                let _ = stream
                    .write_all(
                        b"{\"error\":\"unauthorized control request\"}\n",
                    )
                    .await;
                continue;
            }
            if command == "stop" {
                let _ = stream.write_all(b"stopping\n").await;
                if let Some(tx) = shutdown.take() {
                    let _ = tx.send(());
                }
                break;
            }
            let response = match command {
                "status" => "running".to_string(),
                "mesh-status" => mesh_status_json().await,
                _ => {
                    let mut core = core.lock().await;
                    let result: Result<serde_json::Value> = match command {
                        "core-status" => serde_json::to_value(core.status())
                            .context("serializing core status"),
                        "stack-status" => {
                            serde_json::to_value(core.status().stack)
                                .context("serializing stack status")
                        }
                        "components-start" => core
                            .start()
                            .await
                            .map(|_| serde_json::json!({"ok": true})),
                        "components-stop" => core
                            .stop()
                            .await
                            .map(|_| serde_json::json!({"ok": true})),
                        "components-restart" => core
                            .restart()
                            .await
                            .map(|_| serde_json::json!({"ok": true})),
                        "components-apply" | "proxy-apply" => core
                            .apply(command == "proxy-apply")
                            .await
                            .and_then(|result| {
                                serde_json::to_value(result)
                                    .context("serializing apply result")
                            }),
                        _ => Err(anyhow::anyhow!("unknown control command")),
                    };
                    result.unwrap_or_else(|error| serde_json::json!({"error": format!("{error:#}")})).to_string()
                }
            };
            let _ = stream.write_all(response.as_bytes()).await;
        }
    }))
}

pub async fn request(paths: &Paths, command: &str) -> Result<String> {
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let raw = fs::read_to_string(&paths.control)
            .context("reading core control endpoint")?;
        let endpoint: ControlEndpoint = serde_json::from_str(&raw)
            .context("decoding core control endpoint")?;
        let mut stream = TcpStream::connect(("127.0.0.1", endpoint.port))
            .await
            .context("connecting to core host")?;
        stream
            .write_all(format!("{} {command}\n", endpoint.token).as_bytes())
            .await?;
        let mut response = String::new();
        stream
            .take(1024 * 1024)
            .read_to_string(&mut response)
            .await?;
        Ok(response.trim().to_string())
    })
    .await
    .context("core control request timed out")?
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
pub(crate) fn process_is_alive(pid: u32) -> bool {
    // kill(pid, 0) does not send a signal; EPERM still proves a process exists.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
pub(crate) fn process_is_alive(pid: u32) -> bool {
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

#[cfg(test)]
mod control_tests {
    use super::*;

    #[tokio::test]
    async fn authenticated_host_survives_component_stop_and_rejects_other_clients()
     {
        let directory = std::env::temp_dir()
            .join(format!("zay-control-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let config = directory.join("zay.toml");
        fs::write(&config, "[proxy]\nenabled = false\n").unwrap();
        let paths = paths(Some(&directory), Some(&config));
        let core =
            Arc::new(Mutex::new(CoreRuntime::new(directory.clone(), config)));
        let (tx, rx) = oneshot::channel();
        let server = start_control(&paths, tx, core.clone()).await.unwrap();
        let endpoint: ControlEndpoint =
            serde_json::from_str(&fs::read_to_string(&paths.control).unwrap())
                .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&paths.control).unwrap().permissions().mode()
                    & 0o777,
                0o600
            );
        }
        let mut stranger = TcpStream::connect(("127.0.0.1", endpoint.port))
            .await
            .unwrap();
        stranger
            .write_all(b"wrong-token components-start\n")
            .await
            .unwrap();
        let mut response = String::new();
        stranger.read_to_string(&mut response).await.unwrap();
        assert!(response.contains("unauthorized"));
        assert!(!core.lock().await.status().running);
        for command in
            ["components-start", "components-stop", "components-start"]
        {
            assert!(request(&paths, command).await.unwrap().contains("true"));
            let current: ControlEndpoint = serde_json::from_str(
                &fs::read_to_string(&paths.control).unwrap(),
            )
            .unwrap();
            assert_eq!(current.port, endpoint.port);
            assert_eq!(current.token, endpoint.token);
        }
        assert!(core.lock().await.status().running);
        request(&paths, "stop").await.unwrap();
        rx.await.unwrap();
        server.await.unwrap();
        core.lock().await.stop().await.unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
