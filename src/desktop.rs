//! Native-client API. No WebUI server or HTTP control plane is started here.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

pub use crate::runtime::{ApplyResult, CoreHealth, CoreStatus};
use crate::{
    runtime::{CoreRuntime, CoreSupervisor},
    settings::{self, PersistentProxyFile},
};

/// Owns proxy and Mesh lifetime for a desktop session. Closing a view must not
/// drop this owner. Call shutdown before exiting the application.
pub struct Client {
    data_dir: PathBuf,
    config_path: PathBuf,
    local: CoreRuntime,
    elevated: Option<CoreSupervisor>,
}

impl Client {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        let config_path = data_dir.join(settings::ZAY_TOML_FILE);
        if !config_path.exists() {
            std::fs::create_dir_all(&data_dir)?;
            // A desktop starts without changing system routes or asking for sudo.
            write_private(
                &config_path,
                "[proxy]\nenabled = true\nmixed_port = 7890\n[proxy.tun]\nenabled = false\n",
            )?;
        }
        settings::load_persistent_config(Some(&data_dir), Some(&config_path))?;
        crate::logging::init(&data_dir.join("logs"));
        Ok(Self {
            local: CoreRuntime::new(data_dir.clone(), config_path.clone()),
            data_dir,
            config_path,
            elevated: None,
        })
    }

    pub fn config(&self) -> Result<PersistentProxyFile> {
        Ok(settings::load_persistent_config(
            Some(&self.data_dir),
            Some(&self.config_path),
        )?
        .stack)
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn save(&self, proxy: &PersistentProxyFile) -> Result<()> {
        #[derive(Serialize)]
        struct Config<'a> {
            proxy: &'a PersistentProxyFile,
        }
        let new_proxy: toml_edit::DocumentMut =
            toml::to_string(&Config { proxy })?.parse()?;
        let mut doc: toml_edit::DocumentMut =
            std::fs::read_to_string(&self.config_path)?.parse()?;
        doc["proxy"] = new_proxy["proxy"].clone();
        let text = doc.to_string();
        settings::validate_persistent_toml(&text)?;
        write_private(&self.config_path, &text)
    }

    async fn authorize_if_needed(
        &mut self,
        password: Option<String>,
    ) -> Result<()> {
        let config = settings::load_persistent_config(
            Some(&self.data_dir),
            Some(&self.config_path),
        )?;
        if config.requires_root()
            && !crate::privilege::is_root()
            && self.elevated.is_none()
        {
            let supervisor = CoreSupervisor::new(
                self.data_dir.clone(),
                self.config_path.clone(),
            );
            // Authenticate before interrupting a running unprivileged proxy.
            supervisor.initialize(password).await?;
            self.local.stop().await?;
            self.elevated = Some(supervisor);
        }
        Ok(())
    }

    pub async fn start(&mut self, password: Option<String>) -> Result<()> {
        if let Some(core) = &self.elevated {
            // A host that exited may need fresh authorization on retry.
            return core.start(password).await;
        }
        self.authorize_if_needed(password).await?;
        if let Some(core) = &self.elevated {
            core.start(None).await
        } else {
            self.local.start().await
        }
    }

    pub async fn apply(
        &mut self,
        password: Option<String>,
    ) -> Result<ApplyResult> {
        let running = self.status().await.running;
        let was_elevated = self.elevated.is_some();
        if running {
            self.authorize_if_needed(password).await?;
        }
        if running && !was_elevated && self.elevated.is_some() {
            self.start(None).await?;
            return Ok(ApplyResult {
                applied: true,
                components: vec!["proxy".into(), "mesh".into()],
                error: None,
            });
        }
        if let Some(core) = &self.elevated {
            core.apply(false).await
        } else {
            self.local.apply(false).await
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(core) = &self.elevated {
            core.stop().await
        } else {
            self.local.stop().await
        }
    }

    pub async fn status(&self) -> CoreStatus {
        if let Some(core) = &self.elevated {
            core.status().await
        } else {
            self.local.status()
        }
    }

    pub async fn mesh_status(&self) -> Result<serde_json::Value> {
        if let Some(core) = &self.elevated {
            return core.mesh_status().await;
        }
        tokio::task::spawn_blocking(|| {
            crate::stack::easytier::status()
                .and_then(|s| serde_json::to_value(s).map_err(Into::into))
        })
        .await?
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(core) = self.elevated.take() {
            core.shutdown().await?;
        }
        self.local.stop().await
    }
}

fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.with_context(|| format!("saving {}", path.display()))
}

/// The desktop executable also hosts the library's authorized worker. These
/// internal arguments are handled before GPUI starts, with no GUI as root.
#[cfg(unix)]
pub fn run_helper_if_requested() -> Result<bool> {
    use clap::Parser;
    if !std::env::args().any(|a| a == "--run-core" || a == "--run-tun-worker") {
        return Ok(false);
    }
    #[derive(Parser)]
    struct Helper {
        #[arg(long)]
        run_core: bool,
        #[arg(long)]
        core_parent_pid: Option<u32>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        run_tun_worker: bool,
        #[arg(long)]
        tun_worker_runtime_dir: Option<PathBuf>,
        #[arg(long)]
        tun_worker_config: Option<PathBuf>,
    }
    let args = Helper::try_parse()?;
    if args.run_tun_worker {
        crate::native_tun_worker::run(crate::native_tun_worker::Args {
            runtime_dir: args
                .tun_worker_runtime_dir
                .context("missing worker runtime directory")?,
            config_path: args
                .tun_worker_config
                .context("missing worker configuration")?,
        })?;
    } else {
        tokio::runtime::Runtime::new()?.block_on(
            crate::runtime::run_supervised_core(
                args.data_dir,
                args.config,
                args.core_parent_pid.context("missing core owner PID")?,
            ),
        )?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_proxy_forwards_http_and_moves_ports_on_apply() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _guard = crate::runtime::TEST_RUNTIME_LOCK.lock().unwrap();
        let directory = std::env::temp_dir()
            .join(format!("zay-native-proxy-{}", uuid::Uuid::new_v4()));
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port1 = first.local_addr().unwrap().port();
        let port2 = second.local_addr().unwrap().port();
        drop((first, second));
        let origin =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = origin.accept().await.unwrap();
                let mut buffer = [0; 2048];
                let _ = socket.read(&mut buffer).await.unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnative-ok").await.unwrap();
            }
        });
        let mut client = Client::new(directory.clone()).unwrap();
        let mut config = client.config().unwrap();
        config.mixed_port = Some(port1);
        client.save(&config).unwrap();
        client.start(None).await.unwrap();
        for port in [port1, port2] {
            if port == port2 {
                config.mixed_port = Some(port2);
                client.save(&config).unwrap();
                assert_eq!(
                    client.apply(None).await.unwrap().components,
                    ["proxy"]
                );
                assert!(
                    std::net::TcpStream::connect(("127.0.0.1", port1)).is_err()
                );
            }
            let http = reqwest::Client::builder()
                .proxy(
                    reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
                        .unwrap(),
                )
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            assert_eq!(
                http.get(format!("http://{origin_address}/"))
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
                "native-ok"
            );
        }
        server.await.unwrap();
        client.shutdown().await.unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port2)).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_configuration_is_private_and_preserves_other_sections() {
        let dir = std::env::temp_dir()
            .join(format!("zay-desktop-test-{}", uuid::Uuid::new_v4()));
        let client = Client::new(dir.clone()).unwrap();
        let original = std::fs::read_to_string(client.config_path()).unwrap();
        std::fs::write(client.config_path(), format!("{original}\n[[http]]\nenabled = false\nlisten = '127.0.0.1:0'\n")).unwrap();
        let mut config = client.config().unwrap();
        assert!(!config.tun.enabled);
        config.mixed_port = Some(17990);
        client.save(&config).unwrap();
        assert!(
            std::fs::read_to_string(client.config_path())
                .unwrap()
                .contains("[[http]]")
        );
        assert_eq!(client.config().unwrap().mixed_port, Some(17990));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(client.config_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn native_client_runs_and_reconfigures_mesh_relay() {
        let _guard = crate::runtime::TEST_RUNTIME_LOCK.lock().unwrap();
        let dir = std::env::temp_dir()
            .join(format!("zay-native-mesh-{}", uuid::Uuid::new_v4()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut client = Client::new(dir.clone()).unwrap();
        let mut config = client.config().unwrap();
        config.enabled = false;
        config.mesh = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true, "role": "relay", "network_name": "native-test",
                "network_secret": "test-only", "dhcp": false,
                "listeners": [format!("tcp://127.0.0.1:{port}")]
            }))
            .unwrap(),
        );
        client.save(&config).unwrap();
        client.start(None).await.unwrap();
        assert!(client.status().await.running);
        // EasyTier publishes its first management snapshot asynchronously.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if client
                    .mesh_status()
                    .await
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len()
                    == 1
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        config.mesh.as_mut().unwrap().name = Some("renamed-native-test".into());
        client.save(&config).unwrap();
        assert_eq!(client.apply(None).await.unwrap().components, ["mesh"]);
        client.shutdown().await.unwrap();
        assert!(!client.status().await.running);
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
