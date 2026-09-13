//! AnyTLS inbound with optional TLS and native TCP/UoT routing.

use std::{
    collections::HashMap,
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
    adapter::{PacketStream, Stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::Network,
        tls::{
            ServerTlsConfig, TlsError,
            build_server_config_with_default_alpn_and_reality_dialer,
        },
    },
    inbound::{
        TcpInboundContext, TcpInboundInjector, TcpInjectFuture,
        inherited_tcp_metadata, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream,
        socks::{proxy_packet_connection, restore_fake_ip},
        with_tcp_inbound_context,
    },
    option::AnyTlsInboundOptions,
    outbound::OutboundManager,
    protocol::{
        anytls::{
            ServerHandshake, ServerStreamHandler, default_padding_scheme,
            password_hash, serve_connection, validate_padding_scheme,
        },
        uot,
    },
    route::{Action, Metadata, Router},
};

#[derive(Debug, thiserror::Error)]
pub enum AnyTlsInboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("invalid AnyTLS inbound configuration: {0}")]
    Invalid(String),
}

pub struct AnyTlsInbound {
    name: String,
    tag: String,
    options: AnyTlsInboundOptions,
    users: Arc<HashMap<[u8; 32], String>>,
    padding_scheme: Arc<Vec<u8>>,
    tls: Option<ServerTlsConfig>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

/// Injects an already accepted TCP stream at the AnyTLS protocol boundary.
///
/// This is used by wrapper inbounds such as ShadowTLS. Listener-level TLS is
/// deliberately not applied here because the wrapper has already established
/// the outer transport.
#[derive(Clone)]
pub struct AnyTlsTcpInjector {
    tag: String,
    users: Arc<HashMap<[u8; 32], String>>,
    padding_scheme: Arc<Vec<u8>>,
    tls: Option<ServerTlsConfig>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
}

impl AnyTlsTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: AnyTlsInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, AnyTlsInboundError> {
        let inbound = AnyTlsInbound::new(tag, options, router, outbounds)?;
        Ok(Self {
            tag: inbound.tag,
            users: inbound.users,
            padding_scheme: inbound.padding_scheme,
            tls: inbound.tls,
            router: inbound.router,
            outbounds: inbound.outbounds,
            udp_timeout: inbound
                .options
                .listen
                .udp_timeout
                .0
                .as_std()
                .filter(|duration| !duration.is_zero())
                .unwrap_or(crate::constant::UDP_TIMEOUT),
        })
    }
}

impl TcpInboundInjector for AnyTlsTcpInjector {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a> {
        let source = context.source;
        let handler_context = context.clone();
        Box::pin(with_tcp_inbound_context(context, async move {
            let stream = match self.tls.clone() {
                Some(tls) => Box::new(tls.accept_stream(stream).await?),
                None => stream,
            };
            let tag = self.tag.clone();
            let router = self.router.clone();
            let outbounds = self.outbounds.clone();
            let udp_timeout = self.udp_timeout;
            let handler: ServerStreamHandler =
                Arc::new(move |stream, destination, user, handshake| {
                    let tag = tag.clone();
                    let router = router.clone();
                    let outbounds = outbounds.clone();
                    let context = handler_context.clone();
                    Box::pin(with_tcp_inbound_context(context, async move {
                        handle_stream(
                            stream,
                            source,
                            &tag,
                            destination,
                            user,
                            handshake,
                            &router,
                            &outbounds,
                            udp_timeout,
                        )
                        .await
                    }))
                });
            serve_connection(
                stream,
                self.users.clone(),
                self.padding_scheme.clone(),
                handler,
            )
            .await
        }))
    }
}

impl AnyTlsInbound {
    pub fn new(
        tag: impl Into<String>,
        options: AnyTlsInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, AnyTlsInboundError> {
        if options.users.is_empty() {
            return Err(AnyTlsInboundError::Invalid("missing users".into()));
        }
        let users = options
            .users
            .iter()
            .map(|user| (password_hash(&user.password), user.name.clone()))
            .collect();
        let padding_scheme = if options.padding_scheme.0.is_empty() {
            default_padding_scheme()
        } else {
            options.padding_scheme.0.join("\n").into_bytes()
        };
        validate_padding_scheme(&padding_scheme)
            .map_err(|error| AnyTlsInboundError::Invalid(error.to_string()))?;
        let reality_dialer = options
            .tls
            .as_ref()
            .and_then(|tls| tls.reality.as_ref())
            .filter(|reality| reality.enabled)
            .map(|reality| {
                outbounds.endpoint_dialer(
                    "inbound/anytls/reality",
                    &reality.handshake.dialer,
                )
            })
            .transpose()
            .map_err(|error| {
                AnyTlsInboundError::Tls(TlsError::Unsupported(
                    error.to_string(),
                ))
            })?;
        let tls = options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .map(|tls| {
                build_server_config_with_default_alpn_and_reality_dialer(
                    tls,
                    &[],
                    reality_dialer.clone(),
                )
            })
            .transpose()?;
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/anytls[{tag}]"),
            tag,
            options,
            users: Arc::new(users),
            padding_scheme: Arc::new(padding_scheme),
            tls,
            router,
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
        let tag = self.tag.clone();
        let users = self.users.clone();
        let padding_scheme = self.padding_scheme.clone();
        let tls = self.tls.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        self.task = Some(tokio::spawn(async move {
            accept_loop(
                listener,
                cancellation,
                tag,
                users,
                padding_scheme,
                tls,
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }));
        Ok(())
    }
}

impl Lifecycle for AnyTlsInbound {
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

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    users: Arc<HashMap<[u8; 32], String>>,
    padding_scheme: Arc<Vec<u8>>,
    tls: Option<ServerTlsConfig>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let tag = tag.clone();
                let users = users.clone();
                let padding_scheme = padding_scheme.clone();
                let tls = tls.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let stream: Stream = if let Some(tls) = tls {
                        let stream = tls.accept_stream(Box::new(stream)).await?;
                        Box::new(stream)
                    } else {
                        Box::new(stream)
                    };
                    let handler: ServerStreamHandler = Arc::new(move |stream, destination, user, handshake| {
                        let tag = tag.clone();
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        Box::pin(async move {
                            handle_stream(
                                stream,
                                source,
                                &tag,
                                destination,
                                user,
                                handshake,
                                &router,
                                &outbounds,
                                udp_timeout,
                            )
                            .await
                        })
                    });
                    serve_connection(stream, users, padding_scheme, handler).await
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    stream: Stream,
    source: SocketAddr,
    tag: &str,
    destination: crate::common::network::SocksAddr,
    user: String,
    handshake: ServerHandshake,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    if let Some(version) = uot::destination_version(&destination) {
        let packets: PacketStream = match uot::accept(stream, version).await {
            Ok(packets) => Box::new(packets),
            Err(error) => {
                let _ = handshake.failure(&error).await;
                return Err(error);
            }
        };
        handshake.success().await?;
        return proxy_packet_connection(
            packets,
            source,
            tag,
            Some(user),
            router,
            outbounds,
            udp_timeout,
        )
        .await;
    }
    proxy_tcp(
        stream,
        source,
        tag,
        destination,
        user,
        handshake,
        router,
        outbounds,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn proxy_tcp(
    client: Stream,
    source: SocketAddr,
    tag: &str,
    destination: crate::common::network::SocksAddr,
    user: String,
    handshake: ServerHandshake,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let (destination, origin_destination) =
        match restore_fake_ip(destination, outbounds) {
            Ok(destination) => destination,
            Err(error) => {
                let _ = handshake.failure(&error).await;
                return Err(error);
            }
        };
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Tcp),
        user,
        ..inherited_tcp_metadata(source, tag)
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        handshake.success().await?;
        return injector
            .inject(client, TcpInboundContext { source, metadata })
            .await;
    }
    let (mut client, decision) =
        match sniff_and_route_stream(client, &mut metadata, router, outbounds)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                let _ = handshake.failure(&error).await;
                return Err(error);
            }
        };
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        let error = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        );
        let _ = handshake.failure(&error).await;
        return Err(error);
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        handshake.success().await?;
        return serve_hijacked_dns_stream_with_context(
            client, outbounds, &metadata,
        )
        .await;
    }
    let destination = decision.destination(&destination);
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        Ok(outbounds.direct())
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })
    };
    let dialer = match dialer {
        Ok(dialer) => dialer,
        Err(error) => {
            let _ = handshake.failure(&error).await;
            return Err(error);
        }
    };
    let mut remote = match dialer
        .dial_tcp_with_options(&destination, &connection_options.network)
        .await
    {
        Ok(remote) => remote,
        Err(error) => {
            let _ = handshake.failure(&error).await;
            return Err(error);
        }
    };
    remote = match super::apply_routed_tcp_options(remote, &connection_options)
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = handshake.failure(&error).await;
            return Err(error);
        }
    };
    handshake.success().await?;
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    use super::AnyTlsInbound;
    use crate::{
        adapter::Dialer,
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
        },
        option::{AnyTlsInboundOptions, Options},
        outbound::OutboundManager,
        route::Router,
    };

    #[tokio::test]
    async fn proxies_tls_tcp_and_uot_udp_end_to_end() {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut data = [0_u8; 16];
            let (length, source) =
                udp_target.recv_from(&mut data).await.unwrap();
            udp_target.send_to(&data[..length], source).await.unwrap();
        });
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.pem();
        let inbound_options: AnyTlsInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "udp_timeout":"5s",
                "users":[{"name":"alice","password":"secret"}],
                "tls":{
                    "enabled":true,
                    "certificate":certificate,
                    "key":key_pair.serialize_pem()
                }
            }))
            .unwrap();
        let direct_options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let direct = Arc::new(
            OutboundManager::from_options(&direct_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            AnyTlsInbound::new("anytls-in", inbound_options, router, direct)
                .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let server = inbound.local_addr().unwrap();
        let client_options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{
                "type":"anytls",
                "tag":"anytls-out",
                "server":"127.0.0.1",
                "server_port":server.port(),
                "password":"secret",
                "client_metadata":"rust-test",
                "tls":{
                    "enabled":true,
                    "server_name":"localhost",
                    "certificate":certificate
                }
            }]
        }))
        .unwrap();
        let manager =
            OutboundManager::from_options(&client_options, "").unwrap();
        let outbound = manager.default();

        let mut tcp = outbound
            .dial_tcp(&SocksAddr::from(tcp_destination))
            .await
            .unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        tcp.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        let udp_destination = SocksAddr::from(udp_destination);
        let udp = outbound.listen_udp(&udp_destination).await.unwrap();
        udp.send_to(b"pong", &udp_destination).await.unwrap();
        let mut response = [0_u8; 16];
        let (length, source) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..length], b"pong");
        assert_eq!(source, udp_destination);

        inbound.close().await.unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
    }
}
