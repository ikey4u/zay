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
        let handle = runtime.handle();
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
                    runtime_handle.cancelled().await;
                    let result = runtime
                        .close()
                        .await
                        .context("closing native sing-box runtime");
                    let _ = fs::remove_file(&clash_api_path);
                    result
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
