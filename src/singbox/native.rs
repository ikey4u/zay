//! Zay-owned host for the embeddable Rust sing-box runtime.
//!
//! Signal handling and service lifecycle remain in zay. The `singbox` crate
//! only supplies the network engine and an explicit cancellation handle.

use std::{
    path::Path,
    sync::mpsc,
    thread::{self, JoinHandle},
};

use anyhow::{Context, Result, anyhow};
use singbox_core::{ConfigLoader, Runtime, RuntimeHandle};

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
        let mut runtime = Runtime::from_options_in(options, base_path)
            .context("constructing native sing-box runtime")?;
        let handle = runtime.handle();
        let runtime_handle = handle.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
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
                    let _ = ready_tx.send(Ok(()));
                    runtime_handle.cancelled().await;
                    runtime
                        .close()
                        .await
                        .context("closing native sing-box runtime")
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
}
