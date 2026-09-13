//! Reusable SSH `direct-tcpip` outbound built on russh.

use std::{
    borrow::Cow,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use n0_watcher::Watcher as _;
use russh::{
    SshId,
    client::{self, Handler},
    keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey},
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{DialFuture, Dialer, Stream},
    common::network::SocksAddr,
    option::SshOutboundOptions,
};

#[derive(Clone)]
struct ClientHandler {
    accepted_keys: Arc<Vec<PublicKey>>,
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self.accepted_keys.is_empty()
            || self
                .accepted_keys
                .iter()
                .any(|key| key == server_public_key))
    }
}

pub struct SshOutbound<D> {
    upstream: D,
    server: SocksAddr,
    user: String,
    password: String,
    private_key: Option<Arc<PrivateKey>>,
    accepted_keys: Arc<Vec<PublicKey>>,
    config: Arc<client::Config>,
    session: Arc<Mutex<Option<Arc<client::Handle<ClientHandler>>>>>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

impl<D> SshOutbound<D> {
    pub fn new(
        upstream: D,
        mut options: SshOutboundOptions,
    ) -> io::Result<Self> {
        if options.server.server.is_empty() {
            return Err(invalid("SSH server is required"));
        }
        if options.server.server_port == 0 {
            options.server.server_port = 22;
        }
        if options.user.is_empty() {
            options.user = "root".into();
        }
        if !options.private_key.as_slice().is_empty()
            && !options.private_key_path.is_empty()
        {
            return Err(invalid(
                "SSH private_key conflicts with private_key_path",
            ));
        }
        let private_key = if !options.private_key.as_slice().is_empty() {
            let source = options.private_key.as_slice().join("\n");
            Some(parse_private_key(&source, &options.private_key_passphrase)?)
        } else if !options.private_key_path.is_empty() {
            let path = expand_environment(&options.private_key_path);
            let source = std::fs::read_to_string(&path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("read SSH private key {:?}: {error}", path),
                )
            })?;
            Some(parse_private_key(&source, &options.private_key_passphrase)?)
        } else {
            None
        };
        let accepted_keys = options
            .host_key
            .as_slice()
            .iter()
            .map(|line| parse_public_key(line))
            .collect::<io::Result<Vec<_>>>()?;
        let client_id =
            SshId::Standard(Cow::Owned(if options.client_version.is_empty() {
                random_client_version()?
            } else {
                validate_client_version(&options.client_version)?;
                options.client_version
            }));
        let mut config = client::Config {
            client_id,
            ..client::Config::default()
        };
        if !options.host_key_algorithms.as_slice().is_empty() {
            config.preferred.key = Cow::Owned(
                options
                    .host_key_algorithms
                    .as_slice()
                    .iter()
                    .map(|name| {
                        name.parse().map_err(|_| {
                            invalid(format!(
                                "unknown SSH host-key algorithm {name:?}"
                            ))
                        })
                    })
                    .collect::<io::Result<Vec<_>>>()?,
            );
        }
        if !options.cipher.as_slice().is_empty() {
            config.preferred.cipher =
                Cow::Owned(parse_names(options.cipher.as_slice(), "cipher")?);
        }
        if !options.mac.as_slice().is_empty() {
            config.preferred.mac =
                Cow::Owned(parse_names(options.mac.as_slice(), "MAC")?);
        }
        if !options.kex_algorithm.as_slice().is_empty() {
            config.preferred.kex = Cow::Owned(parse_names(
                options.kex_algorithm.as_slice(),
                "key-exchange",
            )?);
        }
        Ok(Self {
            upstream,
            server: SocksAddr::new(
                options.server.server,
                options.server.server_port,
            ),
            user: options.user,
            password: options.password,
            private_key: private_key.map(Arc::new),
            accepted_keys: Arc::new(accepted_keys),
            config: Arc::new(config),
            session: Arc::new(Mutex::new(None)),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        })
    }
}

impl<D: Dialer> SshOutbound<D> {
    fn ensure_network_monitor(&self) {
        if self
            .network_monitor_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let session = self.session.clone();
        let cancellation = self.cancellation.clone();
        let started = self.network_monitor_started.clone();
        tokio::spawn(async move {
            let Ok(monitor) =
                crate::common::network_monitor::NetworkMonitor::new().await
            else {
                started.store(false, Ordering::Release);
                return;
            };
            let mut watcher = monitor.interface_state();
            let mut previous = watcher.get();
            loop {
                let current = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    current = watcher.updated() => match current {
                        Ok(current) => current,
                        Err(_) => return,
                    },
                };
                let changed = current.is_major_change(&previous);
                previous = current;
                if changed {
                    disconnect_session(&session, "network changed").await;
                }
            }
        });
    }

    /// Close the cached physical SSH connection. A subsequent dial creates a
    /// fresh session, matching sing-box's interface-update reset behavior.
    pub async fn reset(&self) {
        disconnect_session(&self.session, "session reset").await;
    }

    async fn connect(&self) -> io::Result<Arc<client::Handle<ClientHandler>>> {
        self.ensure_network_monitor();
        let mut guard = self.session.lock().await;
        if let Some(handle) =
            guard.as_ref().filter(|handle| !handle.is_closed())
        {
            return Ok(handle.clone());
        }
        *guard = None;
        let stream = self.upstream.dial_tcp(&self.server).await?;
        let handler = ClientHandler {
            accepted_keys: self.accepted_keys.clone(),
        };
        let mut handle =
            client::connect_stream(self.config.clone(), stream, handler)
                .await
                .map_err(other)?;
        let mut authenticated = false;
        if !self.password.is_empty() {
            authenticated = handle
                .authenticate_password(&self.user, &self.password)
                .await
                .map_err(other)?
                .success();
        }
        if !authenticated && let Some(key) = &self.private_key {
            let hash = if key.algorithm().is_rsa() {
                handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(other)?
                    .flatten()
            } else {
                None
            };
            authenticated = handle
                .authenticate_publickey(
                    &self.user,
                    PrivateKeyWithHashAlg::new(key.clone(), hash),
                )
                .await
                .map_err(other)?
                .success();
        }
        if !authenticated
            && self.password.is_empty()
            && self.private_key.is_none()
        {
            authenticated = handle
                .authenticate_none(&self.user)
                .await
                .map_err(other)?
                .success();
        }
        if !authenticated {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSH authentication failed",
            ));
        }
        let handle = Arc::new(handle);
        *guard = Some(handle.clone());
        Ok(handle)
    }
}

async fn disconnect_session(
    session: &Mutex<Option<Arc<client::Handle<ClientHandler>>>>,
    message: &str,
) {
    let handle = session.lock().await.take();
    if let Some(handle) = handle {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, message, "")
            .await;
    }
}

impl<D> Drop for SshOutbound<D> {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut session) = self.session.try_lock()
            && let Some(handle) = session.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                let _ = handle
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        "outbound closed",
                        "",
                    )
                    .await;
            });
        }
    }
}

impl<D: Dialer> Dialer for SshOutbound<D> {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let handle = self.connect().await?;
            let channel = handle
                .channel_open_direct_tcpip(
                    destination.host(),
                    u32::from(destination.port()),
                    "0.0.0.0",
                    0,
                )
                .await
                .map_err(other)?;
            Ok(Box::new(channel.into_stream()) as Stream)
        })
    }
}

fn parse_private_key(source: &str, passphrase: &str) -> io::Result<PrivateKey> {
    russh::keys::decode_secret_key(
        source,
        (!passphrase.is_empty()).then_some(passphrase),
    )
    .map_err(other)
}

fn parse_public_key(source: &str) -> io::Result<PublicKey> {
    let encoded = source.split_whitespace().nth(1).unwrap_or(source.trim());
    russh::keys::parse_public_key_base64(encoded).map_err(other)
}

fn parse_names<T>(values: &[String], kind: &str) -> io::Result<Vec<T>>
where
    for<'a> T: TryFrom<&'a str>,
{
    values
        .iter()
        .map(|value| {
            T::try_from(value.as_str()).map_err(|_| {
                invalid(format!("unknown SSH {kind} algorithm {value:?}"))
            })
        })
        .collect()
}

fn random_client_version() -> io::Result<String> {
    let mut byte = [0_u8; 1];
    getrandom::fill(&mut byte)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let version = if byte[0] & 1 == 0 {
        format!("SSH-2.0-OpenSSH_7.{}", (byte[0] >> 1) % 10)
    } else {
        format!("SSH-2.0-OpenSSH_8.{}", (byte[0] >> 1) % 9)
    };
    Ok(version)
}

fn validate_client_version(version: &str) -> io::Result<()> {
    if !version.starts_with("SSH-2.0-")
        || version.bytes().any(|byte| byte == b'\r' || byte == b'\n')
    {
        return Err(invalid("invalid SSH client_version"));
    }
    Ok(())
}

fn expand_environment(path: &str) -> PathBuf {
    let mut output = String::new();
    let mut chars = path.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '$' {
            output.push(character);
            continue;
        }
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }
        let mut name = String::new();
        while let Some(next) = chars.peek().copied() {
            if (braced && next == '}')
                || (!braced && next != '_' && !next.is_ascii_alphanumeric())
            {
                break;
            }
            name.push(next);
            chars.next();
        }
        if braced && chars.peek() == Some(&'}') {
            chars.next();
        }
        if let Ok(value) = std::env::var(name) {
            output.push_str(&value);
        }
    }
    PathBuf::from(output)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use russh::{
        Channel, ChannelId,
        keys::{Algorithm, PrivateKey, PublicKey, ssh_key::LineEnding},
        server::{self, Auth, Msg, Session},
    };
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };

    use crate::{
        adapter::Dialer as _,
        common::network::SocksAddr,
        option::{DirectOutboundOptions, Options, SshOutboundOptions},
        outbound::OutboundManager,
        protocol::{direct::DirectOutbound, ssh::SshOutbound},
    };

    #[derive(Clone, Default)]
    struct TestServer {
        authorized_key: Option<PublicKey>,
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<Auth, Self::Error> {
            Ok(if user == "alice" && password == "secret" {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(
                if user == "alice" && self.authorized_key.as_ref() == Some(key)
                {
                    Auth::Accept
                } else {
                    Auth::reject()
                },
            )
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            let destination = format!("{host_to_connect}:{port_to_connect}");
            let mut remote = TcpStream::connect(destination).await?;
            let mut stream = channel.into_stream();
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote)
                    .await;
            });
            Ok(true)
        }

        async fn channel_close(
            &mut self,
            _channel: ChannelId,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn password_auth_host_pin_and_reused_session_forward_tcp() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = target.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut payload = [0_u8; 4];
                    stream.read_exact(&mut payload).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                });
            }
        });

        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let public_key = host_key.public_key().to_openssh().unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: std::time::Duration::ZERO,
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            keys: vec![host_key],
            ..server::Config::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ =
                server::run_stream(config, stream, TestServer::default()).await;
        });

        let options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{
                "type":"ssh", "tag":"ssh",
                "server":"127.0.0.1", "server_port":ssh_address.port(),
                "user":"alice", "password":"secret",
                "host_key":public_key,
                "client_version":"SSH-2.0-OpenSSH_8.9"
            }]
        }))
        .unwrap();
        let manager = OutboundManager::from_options(&options, "ssh").unwrap();
        for payload in [*b"ping", *b"pong"] {
            let mut stream = manager
                .default()
                .dial_tcp(&SocksAddr::from(destination))
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
            let mut response = [0_u8; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, payload);
        }
        echo.await.unwrap();
        server_task.abort();
    }

    #[tokio::test]
    async fn private_key_authentication_forwards_tcp() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let host_public_key = host_key.public_key().to_openssh().unwrap();
        let client_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let client_public_key = client_key.public_key().clone();
        let client_private_key =
            client_key.to_openssh(LineEnding::LF).unwrap().to_string();
        let config = Arc::new(server::Config {
            auth_rejection_time: std::time::Duration::ZERO,
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            keys: vec![host_key],
            ..server::Config::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server::run_stream(
                config,
                stream,
                TestServer {
                    authorized_key: Some(client_public_key),
                },
            )
            .await;
        });

        let options: SshOutboundOptions = serde_json::from_value(json!({
            "server":"127.0.0.1",
            "server_port":ssh_address.port(),
            "user":"alice",
            "private_key":client_private_key,
            "host_key":host_public_key,
            "client_version":"SSH-2.0-OpenSSH_8.9"
        }))
        .unwrap();
        let outbound = SshOutbound::new(
            DirectOutbound::new(DirectOutboundOptions::default()),
            options,
        )
        .unwrap();
        let mut stream = outbound
            .dial_tcp(&SocksAddr::from(destination))
            .await
            .unwrap();
        stream.write_all(b"key!").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"key!");

        echo.await.unwrap();
        server_task.abort();
    }

    #[tokio::test]
    async fn encrypted_private_key_passphrase_authentication_forwards_tcp() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let host_public_key = host_key.public_key().to_openssh().unwrap();
        let client_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let client_public_key = client_key.public_key().clone();
        let encrypted_client_key = client_key
            .encrypt(&mut russh::keys::key::safe_rng(), b"key password")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
            .to_string();
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory.path().join("client_key");
        fs::write(&key_path, encrypted_client_key).unwrap();
        let key_path = key_path.to_string_lossy().into_owned();
        let config = Arc::new(server::Config {
            auth_rejection_time: std::time::Duration::ZERO,
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            keys: vec![host_key],
            ..server::Config::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server::run_stream(
                config,
                stream,
                TestServer {
                    authorized_key: Some(client_public_key),
                },
            )
            .await;
        });

        let wrong_passphrase: SshOutboundOptions =
            serde_json::from_value(json!({
                "server":"127.0.0.1",
                "server_port":ssh_address.port(),
                "user":"alice",
                "private_key_path":key_path.clone(),
                "private_key_passphrase":"wrong password",
                "host_key":host_public_key.clone()
            }))
            .unwrap();
        let error = match SshOutbound::new(
            DirectOutbound::new(DirectOutboundOptions::default()),
            wrong_passphrase,
        ) {
            Ok(_) => panic!("encrypted SSH key accepted a wrong passphrase"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::Other);

        let options: SshOutboundOptions = serde_json::from_value(json!({
            "server":"127.0.0.1",
            "server_port":ssh_address.port(),
            "user":"alice",
            "private_key_path":key_path,
            "private_key_passphrase":"key password",
            "host_key":host_public_key,
            "client_version":"SSH-2.0-OpenSSH_8.9"
        }))
        .unwrap();
        let outbound = SshOutbound::new(
            DirectOutbound::new(DirectOutboundOptions::default()),
            options,
        )
        .unwrap();
        let mut stream = outbound
            .dial_tcp(&SocksAddr::from(destination))
            .await
            .unwrap();
        stream.write_all(b"lock").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"lock");

        echo.await.unwrap();
        server_task.abort();
    }

    #[tokio::test]
    async fn reset_disconnects_cached_session_and_reconnects() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = target.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut payload = [0_u8; 4];
                    stream.read_exact(&mut payload).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                });
            }
        });

        let host_key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let public_key = host_key.public_key().to_openssh().unwrap();
        let config = Arc::new(server::Config {
            auth_rejection_time: std::time::Duration::ZERO,
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            keys: vec![host_key],
            ..server::Config::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = server::run_stream(
                        config,
                        stream,
                        TestServer::default(),
                    )
                    .await;
                });
            }
        });

        let options: SshOutboundOptions = serde_json::from_value(json!({
            "server":"127.0.0.1", "server_port":ssh_address.port(),
            "user":"alice", "password":"secret",
            "host_key":public_key,
            "client_version":"SSH-2.0-OpenSSH_8.9"
        }))
        .unwrap();
        let outbound = SshOutbound::new(
            DirectOutbound::new(DirectOutboundOptions::default()),
            options,
        )
        .unwrap();
        for payload in [*b"one!", *b"two!"] {
            let mut stream = outbound
                .dial_tcp(&SocksAddr::from(destination))
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
            let mut response = [0_u8; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, payload);
            drop(stream);
            outbound.reset().await;
        }
        echo.await.unwrap();
        server_task.await.unwrap();
    }

    #[test]
    fn rejects_invalid_client_version_and_algorithm() {
        let invalid_version: crate::option::SshOutboundOptions =
            serde_json::from_value(json!({
                "server":"127.0.0.1", "server_port":22,
                "client_version":"bad\nversion"
            }))
            .unwrap();
        assert!(super::SshOutbound::new(
            crate::protocol::direct::DirectOutbound::new(Default::default()),
            invalid_version,
        )
        .is_err());

        let invalid_cipher: crate::option::SshOutboundOptions =
            serde_json::from_value(json!({
                "server":"127.0.0.1", "server_port":22,
                "cipher":"made-up-cipher"
            }))
            .unwrap();
        assert!(super::SshOutbound::new(
            crate::protocol::direct::DirectOutbound::new(Default::default()),
            invalid_cipher,
        )
        .is_err());
    }
}
