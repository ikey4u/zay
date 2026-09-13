//! ShadowTLS TCP inbound and Shadowsocks inbound-detour injection.

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    io::copy_bidirectional,
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Dialer, Stream, replay_stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::SocksAddr,
        sniff::tls_client_hello,
    },
    inbound::{TcpInboundContext, prepare_tcp_inbound_detour},
    option::{
        ShadowTlsHandshakeOptions, ShadowTlsInboundOptions,
        ShadowTlsWildcardSni,
    },
    outbound::OutboundManager,
    protocol::shadowtls::{
        V3User, authenticate_v3_client_hello, server_handshake_v1,
        server_handshake_v2, server_handshake_v3_authenticated,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ShadowTlsInboundError {
    #[error("invalid ShadowTLS inbound configuration: {0}")]
    Config(String),
}

pub struct ShadowTlsInbound {
    name: String,
    tag: String,
    options: ShadowTlsInboundOptions,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl ShadowTlsInbound {
    pub fn new(
        tag: impl Into<String>,
        options: ShadowTlsInboundOptions,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, ShadowTlsInboundError> {
        let version = if options.version == 0 {
            1
        } else {
            options.version
        };
        if !matches!(version, 1..=3) {
            return Err(ShadowTlsInboundError::Config(format!(
                "unsupported version {version}"
            )));
        }
        if version == 2 && options.password.is_empty() {
            return Err(ShadowTlsInboundError::Config(
                "v2 requires password".into(),
            ));
        }
        if version == 3
            && (options.users.is_empty()
                || options.users.iter().any(|user| user.password.is_empty()))
        {
            return Err(ShadowTlsInboundError::Config(
                "v3 requires non-empty users".into(),
            ));
        }
        if options.handshake.server.server.is_empty()
            && options.wildcard_sni == ShadowTlsWildcardSni::Off
        {
            return Err(ShadowTlsInboundError::Config(
                "missing default handshake server".into(),
            ));
        }
        let tag = tag.into();
        let mut options = options;
        options.version = version;
        Ok(Self {
            name: format!("inbound/shadowtls[{tag}]"),
            tag,
            options,
            outbounds,
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    async fn bind(&mut self) -> io::Result<()> {
        let ip = self
            .options
            .listen
            .listen
            .map(|address| address.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let listener = crate::common::socket::bind_tcp_listener(
            SocketAddr::new(ip, self.options.listen.listen_port),
            &self.options.listen,
        )
        .await?;
        self.local_addr = Some(listener.local_addr()?);
        let cancellation = self.cancellation.clone();
        let options = self.options.clone();
        let tag = self.tag.clone();
        let outbounds = self.outbounds.clone();
        self.task = Some(tokio::spawn(async move {
            accept_loop(listener, cancellation, tag, options, outbounds).await
        }));
        Ok(())
    }
}

impl Lifecycle for ShadowTlsInbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.bind().await.map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(task) = self.task.take() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: error.to_string(),
                        });
                    }
                }
            }
            Ok(())
        })
    }
}

async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    options: ShadowTlsInboundOptions,
    outbounds: Arc<OutboundManager>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let options = options.clone();
                let tag = tag.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let _ = handle_connection(
                        Box::new(stream), source, &tag, &options, &outbounds,
                    ).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection(
    mut client: Stream,
    source: SocketAddr,
    tag: &str,
    options: &ShadowTlsInboundOptions,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let tunnel = match options.version {
        1 => {
            let decoy = dial_handshake(&options.handshake, outbounds).await?;
            server_handshake_v1(client, decoy).await?
        }
        2 => {
            let hello =
                crate::protocol::shadowtls::read_first_tls_frame(&mut client)
                    .await?;
            let server_name = tls_client_hello(&hello)
                .map(|result| result.domain)
                .unwrap_or_default();
            let handshake = options
                .handshake_for_server_name
                .get(&server_name)
                .unwrap_or(&options.handshake);
            let decoy = dial_handshake(handshake, outbounds).await?;
            server_handshake_v2(
                replay_stream(client, hello),
                decoy,
                options.password.as_bytes(),
            )
            .await?
        }
        3 => {
            let hello =
                crate::protocol::shadowtls::read_first_tls_frame(&mut client)
                    .await?;
            let server_name = tls_client_hello(&hello)
                .map(|result| result.domain)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("extract ShadowTLS ClientHello SNI: {error}"),
                    )
                })?;
            let users: Vec<_> = options
                .users
                .iter()
                .map(|user| V3User {
                    name: user.name.clone(),
                    password: user.password.clone(),
                })
                .collect();
            let authenticated = authenticate_v3_client_hello(&hello, &users);
            if authenticated.is_err() {
                let handshake =
                    selected_v3_handshake(options, &server_name, false);
                let decoy = dial_handshake(&handshake, outbounds).await?;
                let mut client = replay_stream(client, hello);
                let mut decoy = decoy;
                copy_bidirectional(&mut client, &mut decoy).await?;
                return Ok(());
            }
            let user = authenticated.expect("checked above").clone();
            let handshake = selected_v3_handshake(options, &server_name, true);
            let decoy = dial_handshake(&handshake, outbounds).await?;
            server_handshake_v3_authenticated(
                client,
                decoy,
                hello,
                user,
                options.strict_mode,
            )
            .await?
            .0
        }
        _ => unreachable!("validated ShadowTLS version"),
    };
    let mut context = TcpInboundContext::accepted(source, tag);
    let injector =
        prepare_tcp_inbound_detour(&mut context.metadata, outbounds)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "ShadowTLS inbound requires an inbound detour",
                )
            })?;
    injector.inject(tunnel, context).await
}

fn selected_v3_handshake(
    options: &ShadowTlsInboundOptions,
    server_name: &str,
    authenticated: bool,
) -> ShadowTlsHandshakeOptions {
    if let Some(custom) = options.handshake_for_server_name.get(server_name) {
        return custom.clone();
    }
    if !server_name.is_empty()
        && (authenticated && options.wildcard_sni != ShadowTlsWildcardSni::Off
            || options.wildcard_sni == ShadowTlsWildcardSni::All)
    {
        return ShadowTlsHandshakeOptions {
            server: crate::option::ServerOptions {
                server: server_name.to_owned(),
                server_port: 443,
            },
            dialer: options.handshake.dialer.clone(),
        };
    }
    options.handshake.clone()
}

async fn dial_handshake(
    options: &ShadowTlsHandshakeOptions,
    outbounds: &OutboundManager,
) -> io::Result<Stream> {
    if options.server.server.is_empty() || options.server.server_port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing ShadowTLS handshake destination",
        ));
    }
    let destination = SocksAddr::new(
        options.server.server.clone(),
        options.server.server_port,
    );
    let dialer: Arc<dyn Dialer> = outbounds
        .endpoint_dialer("ShadowTLS handshake", &options.dialer)
        .map_err(io::Error::other)?;
    dialer.dial_tcp(&destination).await
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::{
        common::{keygen::generate_tls_keypair, lifecycle::Lifecycle, tls},
        inbound::shadowsocks::ShadowsocksTcpInjector,
        option::{
            Addr, DirectOutboundOptions, InboundTlsOptions, Listable,
            ListenOptions, NetworkList, OutboundTlsOptions, ServerOptions,
            ShadowsocksInboundOptions,
        },
        protocol::{
            direct::DirectOutbound, shadowsocks::ShadowsocksOutbound,
            shadowtls::ShadowTlsV1Outbound,
        },
        route::Router,
    };

    #[tokio::test]
    async fn all_versions_inject_authenticated_stream_into_shadowsocks() {
        for version in 1..=3 {
            run_listener_chain(version).await;
        }
    }

    async fn run_listener_chain(version: i32) {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let pair = generate_tls_keypair("decoy.example", 1).unwrap();
        let tls_version = if version == 3 { "1.3" } else { "1.2" };
        let server_tls = tls::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![pair.certificate_pem.clone()]),
            key: Listable(vec![pair.private_key_pem]),
            min_version: tls_version.into(),
            max_version: tls_version.into(),
            ..Default::default()
        })
        .unwrap();
        let client_tls = tls::build_client_config(
            "decoy.example",
            &OutboundTlsOptions {
                enabled: true,
                server_name: "decoy.example".into(),
                certificate: Listable(vec![pair.certificate_pem]),
                min_version: tls_version.into(),
                max_version: tls_version.into(),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_address = decoy.local_addr().unwrap();
        let decoy_task = tokio::spawn(async move {
            let (stream, _) = decoy.accept().await.unwrap();
            let _stream = TlsAcceptor::from(server_tls.config)
                .accept(stream)
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });

        let outbounds = Arc::new(
            OutboundManager::from_options(
                &crate::option::Options::default(),
                "",
            )
            .unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let shadowsocks_options = ShadowsocksInboundOptions {
            listen: ListenOptions::default(),
            network: NetworkList::default(),
            method: "aes-128-gcm".into(),
            password: "shadowsocks password".into(),
            ..Default::default()
        };
        let injector = Arc::new(
            ShadowsocksTcpInjector::new(
                "ss-in",
                shadowsocks_options,
                router,
                outbounds.clone(),
            )
            .unwrap(),
        );
        outbounds.register_inbound_tcp_detour(
            "shadow-in",
            "ss-in",
            true,
            Some(injector),
        );
        let mut inbound = ShadowTlsInbound::new(
            "shadow-in",
            ShadowTlsInboundOptions {
                listen: ListenOptions {
                    listen: Some(Addr("127.0.0.1".parse().unwrap())),
                    listen_port: 0,
                    detour: "ss-in".into(),
                    ..Default::default()
                },
                version,
                password: "shadow password".into(),
                users: vec![crate::option::ShadowTlsUser {
                    name: "alice".into(),
                    password: "shadow password".into(),
                }],
                handshake: ShadowTlsHandshakeOptions {
                    server: ServerOptions {
                        server: decoy_address.ip().to_string(),
                        server_port: decoy_address.port(),
                    },
                    ..Default::default()
                },
                strict_mode: version == 3,
                ..Default::default()
            },
            outbounds,
        )
        .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let shadow_address = inbound.local_addr().unwrap();

        let direct =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let shadow = Arc::new(match version {
            1 => ShadowTlsV1Outbound::new(
                direct,
                shadow_address.into(),
                client_tls,
            ),
            2 => ShadowTlsV1Outbound::new_v2(
                direct,
                shadow_address.into(),
                b"shadow password".to_vec(),
                client_tls,
            ),
            3 => ShadowTlsV1Outbound::new_v3(
                direct,
                shadow_address.into(),
                b"shadow password".to_vec(),
                client_tls,
            ),
            _ => unreachable!(),
        });
        let shadowsocks = ShadowsocksOutbound::new(
            shadow,
            shadow_address.into(),
            "aes-128-gcm",
            "shadowsocks password",
        )
        .unwrap();
        let mut stream =
            shadowsocks.dial_tcp(&target_address.into()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");

        inbound.close().await.unwrap();
        echo.await.unwrap();
        decoy_task.abort();
    }

    #[test]
    fn v3_wildcard_sni_applies_only_at_the_configured_auth_boundary() {
        let mut options = ShadowTlsInboundOptions {
            handshake: ShadowTlsHandshakeOptions {
                server: ServerOptions {
                    server: "default.example".into(),
                    server_port: 8443,
                },
                ..Default::default()
            },
            wildcard_sni: ShadowTlsWildcardSni::Authed,
            ..Default::default()
        };
        assert_eq!(
            selected_v3_handshake(&options, "client.example", false)
                .server
                .server,
            "default.example"
        );
        assert_eq!(
            selected_v3_handshake(&options, "client.example", true)
                .server
                .server,
            "client.example"
        );
        options.wildcard_sni = ShadowTlsWildcardSni::All;
        assert_eq!(
            selected_v3_handshake(&options, "client.example", false)
                .server
                .server,
            "client.example"
        );
        options.handshake_for_server_name.insert(
            "client.example".into(),
            ShadowTlsHandshakeOptions {
                server: ServerOptions {
                    server: "custom.example".into(),
                    server_port: 9443,
                },
                ..Default::default()
            },
        );
        assert_eq!(
            selected_v3_handshake(&options, "client.example", false)
                .server
                .server,
            "custom.example"
        );
    }

    #[tokio::test]
    async fn handshake_direct_dialer_options_are_not_ignored() {
        let manager_options: crate::option::Options =
            serde_json::from_value(serde_json::json!({
                "certificate": {"store": "none"},
                "dns": {
                    "servers": [{"type": "hosts", "tag": "hosts"}],
                    "final": "hosts"
                }
            }))
            .unwrap();
        let outbounds =
            OutboundManager::from_options(&manager_options, "").unwrap();
        let options: ShadowTlsHandshakeOptions =
            serde_json::from_value(serde_json::json!({
                "server": "example.com",
                "server_port": 443,
                "domain_resolver": "missing"
            }))
            .unwrap();
        let error = dial_handshake(&options, &outbounds)
            .await
            .err()
            .expect("missing handshake resolver was ignored");
        assert!(
            error
                .to_string()
                .contains("DNS resolver \"missing\" not found"),
            "{error}"
        );
    }
}
