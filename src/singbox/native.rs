//! Zay-owned host for the embeddable Rust sing-box runtime.
//!
//! Signal handling and service lifecycle remain in zay. The `singbox` crate
//! only supplies the network engine and an explicit cancellation handle.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use singbox_core::{ConfigLoader, Runtime, RuntimeHandle, RuntimeHost};

/// A sing-box runtime running on a zay-owned Tokio executor thread.
pub struct NativeRuntime {
    handle: RuntimeHandle,
    join: Option<JoinHandle<Result<()>>>,
}

impl NativeRuntime {
    /// Load `config_path`, create the Rust engine relative to `base_path`, and
    /// wait until all runtime services have started.
    pub fn start(config_path: &Path, base_path: &Path) -> Result<Self> {
        let options = ConfigLoader::new()
            .path(config_path)
            .read_and_merge()
            .with_context(|| {
                format!(
                    "loading native sing-box config {}",
                    config_path.display()
                )
            })?;
        // TUN workers already forward stdout through the supervisor's log writer.
        // In-process engines need an explicit subscription instead.
        let capture_logs =
            !options.inbounds.iter().any(|inbound| inbound.kind == "tun");
        let cache_path = options
            .experimental
            .as_ref()
            .and_then(|experimental| experimental.cache_file.as_ref())
            .filter(|cache| cache.enabled)
            .map(|cache| {
                let configured = if cache.path.is_empty() {
                    Path::new("cache.db")
                } else {
                    Path::new(&cache.path)
                };
                if configured.is_absolute() {
                    configured.to_path_buf()
                } else {
                    base_path.join(configured)
                }
            });
        let runtime_host = || RuntimeHost {
            process_resolver: crate::platform::process_attribution::resolver(),
            ..RuntimeHost::default()
        };
        let mut runtime = match Runtime::from_options_in_with_host(
            options.clone(),
            base_path,
            runtime_host(),
        ) {
            Ok(runtime) => runtime,
            Err(error) if is_invalid_database(&error) => {
                let cache_path = cache_path.as_deref().context(
                        "native sing-box reported an invalid database without a configured cache file",
                    )?;
                let backup = quarantine_invalid_cache(cache_path)?;
                eprintln!(
                    "replaced incompatible DNS cache {}; backup preserved at {}",
                    cache_path.display(),
                    backup.display()
                );
                let runtime = Runtime::from_options_in_with_host(
                    options,
                    base_path,
                    runtime_host(),
                )
                .context(
                    "constructing native sing-box runtime after replacing incompatible DNS cache",
                )?;
                runtime
            }
            Err(error) => {
                return Err(error)
                    .context("constructing native sing-box runtime");
            }
        };
        if let Some(cache_path) = cache_path.as_deref() {
            restore_cache_ownership(cache_path);
        }
        let traffic_path = base_path.join("application-traffic.json");
        runtime
            .outbounds()
            .configure_process_traffic_storage(&traffic_path)
            .context("loading saved application traffic usage")?;
        crate::privilege::restore_invoker_ownership(&traffic_path);
        let handle = runtime.handle();
        let engine_logs = if capture_logs {
            runtime.subscribe_logs().ok()
        } else {
            None
        };
        let log_writer = crate::stack::log_buf::SingboxLogWriter::new(
            base_path.join("../logs"),
        );
        let runtime_handle = handle.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let clash_api_path = base_path.join("clash-api-port");
        let _ = fs::remove_file(&clash_api_path);
        let thread_name = format!(
            "zay-singbox-{}",
            config_path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("runtime")
        );

        let join = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let executor = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("creating native sing-box executor")?;
                executor.block_on(async move {
                    let log_task = engine_logs.map(|mut entries| {
                        tokio::spawn(async move {
                            let buffer =
                                crate::stack::log_buf::LogBuffer::new(100);
                            while let Some(entry) = entries.recv().await {
                                let line = format!(
                                    "+0000 {} {} {}",
                                    chrono::Utc::now()
                                        .format("%Y-%m-%d %H:%M:%S"),
                                    entry.level.as_str().to_ascii_uppercase(),
                                    entry.message
                                );
                                log_writer.write(&line, &buffer);
                            }
                        })
                    });
                    if let Err(error) = runtime.start().await {
                        let message = format!(
                            "starting native sing-box runtime: {error:#}"
                        );
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(anyhow!(message));
                    }
                    if let Some(address) = runtime.clash_api_addr() {
                        fs::write(
                            &clash_api_path,
                            format!("{}\n", address.port()),
                        )
                        .with_context(|| {
                            format!(
                                "writing Clash API port {}",
                                clash_api_path.display()
                            )
                        })?;
                        crate::privilege::restore_invoker_ownership(
                            &clash_api_path,
                        );
                    }
                    let _ = ready_tx.send(Ok(()));
                    let mut traffic_checkpoint = tokio::time::interval(std::time::Duration::from_secs(5));
                    loop {
                        tokio::select! {
                            _ = runtime_handle.cancelled() => break,
                            _ = traffic_checkpoint.tick() => {
                                if let Err(error) = runtime.outbounds().flush_process_traffic() {
                                    tracing::error!(%error, "saving application traffic usage");
                                }
                                crate::privilege::restore_invoker_ownership(&traffic_path);
                            }
                        }
                    }
                    let result = runtime
                        .close()
                        .await
                        .context("closing native sing-box runtime");
                    let usage_result = runtime.outbounds().flush_process_traffic()
                        .context("saving application traffic usage on shutdown");
                    crate::privilege::restore_invoker_ownership(&traffic_path);
                    if let Some(task) = log_task {
                        task.abort();
                    }
                    let _ = fs::remove_file(&clash_api_path);
                    result.and(usage_result)
                })
            })
            .context("spawning native sing-box runtime thread")?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                handle,
                join: Some(join),
            }),
            Ok(Err(message)) => {
                let _ = join.join();
                Err(anyhow!(message))
            }
            Err(_) => match join.join() {
                Ok(Ok(())) => Err(anyhow!(
                    "native sing-box runtime stopped before reporting readiness"
                )),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(anyhow!(
                    "native sing-box runtime panicked before reporting readiness"
                )),
            },
        }
    }

    /// Clone the control handle so zay can connect Ctrl-C, service stop, or UI
    /// actions to the engine without exposing process-level behavior in the
    /// library.
    pub fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    pub fn is_running(&self) -> bool {
        self.join.as_ref().is_some_and(|join| !join.is_finished())
    }

    /// Wait for the runtime thread to finish without requesting cancellation.
    pub fn wait(&mut self) -> Result<()> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        match join.join() {
            Ok(result) => result,
            Err(_) => Err(anyhow!("native sing-box runtime thread panicked")),
        }
    }

    /// Request graceful shutdown and wait for the engine to release sockets.
    pub fn stop(&mut self) -> Result<()> {
        self.handle.cancel();
        self.wait()
    }
}

fn is_invalid_database(error: &impl std::fmt::Display) -> bool {
    error.to_string().contains("file is not a database")
}

fn quarantine_invalid_cache(path: &Path) -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cache.db");
    let backup = path.with_file_name(format!(
        "{file_name}.incompatible-{timestamp}-{}",
        std::process::id()
    ));
    fs::rename(path, &backup).with_context(|| {
        format!(
            "preserving incompatible DNS cache {} as {}",
            path.display(),
            backup.display()
        )
    })?;
    crate::privilege::restore_invoker_ownership(&backup);
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        if sidecar.exists() {
            let sidecar_backup =
                PathBuf::from(format!("{}{suffix}", backup.display()));
            fs::rename(&sidecar, &sidecar_backup).with_context(|| {
                format!("preserving DNS cache sidecar {}", sidecar.display())
            })?;
            crate::privilege::restore_invoker_ownership(&sidecar_backup);
        }
    }
    Ok(backup)
}

fn restore_cache_ownership(path: &Path) {
    crate::privilege::restore_invoker_ownership(path);
    for suffix in ["-wal", "-shm"] {
        crate::privilege::restore_invoker_ownership(&PathBuf::from(format!(
            "{}{suffix}",
            path.display()
        )));
    }
}

impl Drop for NativeRuntime {
    fn drop(&mut self) {
        self.handle.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, net::TcpListener, path::PathBuf};

    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "zay-native-singbox-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn starts_and_gracefully_stops_library_runtime() {
        let directory = temporary_directory("lifecycle");
        let reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let config_path = directory.join("config.json");
        fs::write(
            &config_path,
            format!(
                r#"{{
                  "inbounds": [{{
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": {port}
                  }}],
                  "outbounds": [{{"type": "direct", "tag": "direct"}}],
                  "route": {{"final": "direct"}}
                }}"#
            ),
        )
        .unwrap();

        let mut host = NativeRuntime::start(&config_path, &directory).unwrap();
        assert!(host.is_running());
        assert!(!host.handle().is_cancelled());
        host.stop().unwrap();
        assert!(!host.is_running());
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn application_usage_is_saved_on_shutdown_and_served_after_restart() {
        use std::{
            io::{Read, Write},
            net::TcpStream,
        };

        let directory = temporary_directory("application-usage");
        let reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let target = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            let (mut socket, _) = target.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut data = [0u8; 64];
            socket.read_exact(&mut data).unwrap();
            assert_eq!(data, [7; 64]);
            socket.write_all(&[8; 128]).unwrap();
        });
        let config_path = directory.join("config.json");
        fs::write(&config_path, serde_json::to_vec(&serde_json::json!({
            "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "direct", "tag": "plain"}],
            "route": {"final": "plain"},
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}}
        })).unwrap()).unwrap();
        let mut host = NativeRuntime::start(&config_path, &directory).unwrap();
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        socket.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0u8; 2];
        socket.read_exact(&mut method).unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&target_port.to_be_bytes());
        socket.write_all(&request).unwrap();
        let mut reply = [0u8; 10];
        socket.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..2], &[5, 0]);
        socket.write_all(&[7; 64]).unwrap();
        let mut received = [0u8; 128];
        socket.read_exact(&mut received).unwrap();
        assert_eq!(received, [8; 128]);
        drop(socket);
        echo.join().unwrap();
        host.stop().unwrap();
        let path = directory.join("application-traffic.json");
        let saved =
            singbox_core::outbound::ProcessTrafficState::read_storage(&path)
                .unwrap()
                .unwrap();
        assert_eq!(
            saved.records.iter().map(|r| r.direct_upload).sum::<u64>(),
            64
        );
        assert_eq!(
            saved.records.iter().map(|r| r.direct_download).sum::<u64>(),
            128
        );
        assert_eq!(
            saved
                .records
                .iter()
                .map(|r| r.proxy_upload + r.proxy_download)
                .sum::<u64>(),
            0
        );

        // Use a new listener so this persistence test does not depend on the
        // kernel's TIME_WAIT policy for the completed proxy connection.
        let mut next: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        next["inbounds"][0]["listen_port"] = 0.into();
        fs::write(&config_path, serde_json::to_vec(&next).unwrap()).unwrap();
        let mut restarted =
            NativeRuntime::start(&config_path, &directory).unwrap();
        let api_port =
            fs::read_to_string(directory.join("clash-api-port")).unwrap();
        let url =
            format!("http://127.0.0.1:{}/zay/process-traffic", api_port.trim());
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let usage = client
            .get(&url)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .unwrap();
        let usage: serde_json::Value = serde_json::from_slice(&usage).unwrap();
        assert_eq!(
            usage["records"].as_array().unwrap().len(),
            saved.records.len()
        );
        let reset = client
            .post(format!("{url}/reset"))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .unwrap();
        let reset: serde_json::Value = serde_json::from_slice(&reset).unwrap();
        assert!(reset["records"].as_array().unwrap().is_empty());
        restarted.stop().unwrap();
        assert!(
            singbox_core::outbound::ProcessTrafficState::read_storage(&path)
                .unwrap()
                .unwrap()
                .records
                .is_empty()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reports_configuration_errors_before_returning_a_host() {
        let directory = temporary_directory("invalid");
        let config_path = directory.join("config.json");
        fs::write(&config_path, r#"{"outbounds":[{"type":"unknown"}]}"#)
            .unwrap();

        let error = match NativeRuntime::start(&config_path, &directory) {
            Ok(_) => panic!("invalid configuration started"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("loading native sing-box config"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn replaces_incompatible_persistent_dns_cache() {
        let directory = temporary_directory("legacy-cache");
        let reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let cache_path = directory.join("cache.db");
        fs::write(&cache_path, b"legacy non-sqlite cache").unwrap();
        let config_path = directory.join("config.json");
        fs::write(
            &config_path,
            format!(
                r#"{{
                  "inbounds": [{{
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": {port}
                  }}],
                  "outbounds": [{{"type": "direct", "tag": "direct"}}],
                  "route": {{"final": "direct"}},
                  "experimental": {{
                    "cache_file": {{"enabled": true, "path": "cache.db"}}
                  }}
                }}"#
            ),
        )
        .unwrap();

        let mut host = NativeRuntime::start(&config_path, &directory).unwrap();
        host.stop().unwrap();

        let header = fs::read(&cache_path).unwrap();
        assert!(header.starts_with(b"SQLite format 3\0"));
        let backup = fs::read_dir(&directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name().and_then(|name| name.to_str()).is_some_and(
                    |name| name.starts_with("cache.db.incompatible-"),
                )
            })
            .expect("incompatible cache backup");
        assert_eq!(fs::read(backup).unwrap(), b"legacy non-sqlite cache");

        fs::remove_dir_all(directory).unwrap();
    }
}
