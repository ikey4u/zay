//! VLESS version 0 TCP inbound with optional TLS and legacy UDP routing.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    adapter::{PacketStream, Stream, VisionDirectSwitch},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::Network,
        tls::{
            ServerTlsConfig, TlsError, accept_switchable_server_tls,
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
    option::{V2RayTransportOptions, VlessInboundOptions},
    outbound::OutboundManager,
    protocol::vless::{
        Command, FLOW_VISION, VlessServerPacketConnection, parse_user_id,
        read_request, write_response,
    },
    route::{Action, Metadata, Router},
    transport::{
        quic::{
            StreamHandler as QuicStreamHandler,
            accept_loop as quic_accept_loop, server_endpoint,
        },
        v2ray::{
            accept_transport_streams, tls_alpn, validate_server_transport,
        },
    },
};

#[derive(Debug, thiserror::Error)]
pub enum VlessInboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("unsupported VLESS inbound functionality: {0}")]
    Unsupported(String),
    #[error("duplicate VLESS UUID for users {first} and {second}")]
    DuplicateUser { first: usize, second: usize },
}

pub struct VlessInbound {
    name: String,
    tag: String,
    options: VlessInboundOptions,
    users: HashMap<Uuid, usize>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct VlessTcpInjector {
    tag: String,
    users: HashMap<Uuid, usize>,
    names: Vec<crate::option::VlessUser>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
}

impl VlessTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: VlessInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, VlessInboundError> {
        let inbound = VlessInbound::new(tag, options, router, outbounds)?;
        let multiplex_brutal = crate::protocol::mux::server_brutal_options(
            inbound
                .options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )
        .map_err(|error| VlessInboundError::Unsupported(error.to_string()))?;
        Ok(Self {
            tag: inbound.tag,
            users: inbound.users,
            names: inbound.options.users,
            tls: inbound.tls,
            transport: inbound.transport,
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
            multiplex_enabled: inbound
                .options
                .multiplex
                .as_ref()
                .is_some_and(|multiplex| multiplex.enabled),
            multiplex_padding: inbound.options.multiplex.as_ref().is_some_and(
                |multiplex| multiplex.enabled && multiplex.padding,
            ),
            multiplex_brutal,
        })
    }
}

impl TcpInboundInjector for VlessTcpInjector {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a> {
        let source = context.source;
        Box::pin(with_tcp_inbound_context(context, async move {
            let vision_enabled =
                self.names.iter().any(|user| user.flow == FLOW_VISION);
            let vision_switchable = vision_enabled && self.transport.is_none();
            let (stream, vision_switch): (
                Stream,
                Option<Arc<dyn VisionDirectSwitch>>,
            ) = match self.tls.clone() {
                Some(tls) if self.transport.is_none() && vision_switchable => {
                    let transport =
                        accept_switchable_server_tls(stream, tls).await?;
                    (transport.stream, Some(transport.direct_switch))
                }
                Some(tls) if self.transport.is_none() => {
                    (Box::new(tls.accept_stream(stream).await?), None)
                }
                _ => (stream, None),
            };
            handle_connection(
                stream,
                source,
                &self.tag,
                &self.users,
                &self.names,
                &self.router,
                &self.outbounds,
                self.udp_timeout,
                self.multiplex_enabled,
                self.multiplex_padding,
                self.multiplex_brutal,
                vision_switch,
            )
            .await
        }))
    }
}

impl VlessInbound {
    pub fn new(
        tag: impl Into<String>,
        options: VlessInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, VlessInboundError> {
        let transport = options.transport.clone();
        if let Some(transport) = transport.as_ref() {
            validate_server_transport(transport).map_err(|error| {
                VlessInboundError::Unsupported(error.to_string())
            })?;
        }
        if matches!(transport, Some(V2RayTransportOptions::Quic))
            && !options.tls.as_ref().is_some_and(|tls| tls.enabled)
        {
            return Err(VlessInboundError::Unsupported(
                "V2Ray QUIC transport requires TLS".into(),
            ));
        }
        crate::protocol::mux::server_brutal_options(
            options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )
        .map_err(|error| VlessInboundError::Unsupported(error.to_string()))?;
        if let Some(user) = options
            .users
            .iter()
            .find(|user| !matches!(user.flow.as_str(), "" | FLOW_VISION))
        {
            return Err(VlessInboundError::Unsupported(format!(
                "unknown VLESS flow {:?}",
                user.flow
            )));
        }
        let mut users = HashMap::new();
        for (index, user) in options.users.iter().enumerate() {
            let id = parse_user_id(&user.uuid);
            if let Some(first) = users.insert(id, index) {
                return Err(VlessInboundError::DuplicateUser {
                    first,
                    second: index,
                });
            }
        }
        let reality_dialer = options
            .tls
            .as_ref()
            .and_then(|tls| tls.reality.as_ref())
            .filter(|reality| reality.enabled)
            .map(|reality| {
                outbounds.endpoint_dialer(
                    "inbound/vless/reality",
                    &reality.handshake.dialer,
                )
            })
            .transpose()
            .map_err(|error| {
                VlessInboundError::Tls(TlsError::Unsupported(error.to_string()))
            })?;
        let tls = options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .map(|tls| {
                build_server_config_with_default_alpn_and_reality_dialer(
                    tls,
                    tls_alpn(options.transport.as_ref()),
                    reality_dialer.clone(),
                )
            })
            .transpose()?;
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/vless[{tag}]"),
            tag,
            options,
            users,
            tls,
            transport,
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
            .map(|value| value.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let bind_address = SocketAddr::new(ip, self.options.listen.listen_port);
        let cancellation = self.cancellation.clone();
        let tag = self.tag.clone();
        let users = self.users.clone();
        let names = self.options.users.clone();
        let tls = self.tls.clone();
        let transport = self.transport.clone();
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let multiplex_enabled = self
            .options
            .multiplex
            .as_ref()
            .is_some_and(|multiplex| multiplex.enabled);
        let multiplex_padding =
            self.options.multiplex.as_ref().is_some_and(|multiplex| {
                multiplex.enabled && multiplex.padding
            });
        let multiplex_brutal = crate::protocol::mux::server_brutal_options(
            self.options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )?;
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|value| !value.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        if matches!(transport, Some(V2RayTransportOptions::Quic)) {
            let endpoint = server_endpoint(
                tls.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "QUIC requires TLS",
                    )
                })?,
                bind_address,
            )?;
            self.local_addr = Some(endpoint.local_addr()?);
            let handler: QuicStreamHandler = Arc::new(move |stream, source| {
                let tag = tag.clone();
                let users = users.clone();
                let names = names.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                Box::pin(async move {
                    let _ = handle_connection(
                        stream,
                        source,
                        &tag,
                        &users,
                        &names,
                        &router,
                        &outbounds,
                        udp_timeout,
                        multiplex_enabled,
                        multiplex_padding,
                        multiplex_brutal,
                        None,
                    )
                    .await;
                })
            });
            self.task = Some(tokio::spawn(quic_accept_loop(
                endpoint,
                cancellation,
                handler,
            )));
        } else {
            let listener = crate::common::socket::bind_tcp_listener(
                bind_address,
                &self.options.listen,
            )
            .await?;
            self.local_addr = Some(listener.local_addr()?);
            self.task = Some(tokio::spawn(async move {
                accept_loop(
                    listener,
                    cancellation,
                    tag,
                    users,
                    names,
                    tls,
                    transport,
                    router,
                    outbounds,
                    udp_timeout,
                    multiplex_enabled,
                    multiplex_padding,
                    multiplex_brutal,
                )
                .await
            }));
        }
        Ok(())
    }
}

impl Lifecycle for VlessInbound {
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
    users: HashMap<Uuid, usize>,
    names: Vec<crate::option::VlessUser>,
    tls: Option<ServerTlsConfig>,
    transport: Option<V2RayTransportOptions>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let tag = tag.clone(); let users = users.clone(); let names = names.clone();
                let tls = tls.clone(); let transport = transport.clone(); let router = router.clone(); let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let socket = crate::adapter::tcp_stream_socket(&stream);
                    let tls_enabled = tls.is_some();
                    let vision_enabled = names.iter().any(|user| user.flow == FLOW_VISION);
                    // Go sing-vmess locates *tls.Conn through only
                    // replaceable stream wrappers. V2Ray transports are not
                    // replaceable at VLESS setup time, so upstream accepts
                    // the configuration but rejects a Vision connection.
                    let vision_switchable = vision_enabled && transport.is_none();
                    let stream: Stream = Box::new(stream);
                    let stream: io::Result<(Stream, Option<Arc<dyn VisionDirectSwitch>>)> = if let Some(tls) = tls {
                        if vision_switchable {
                            let transport = accept_switchable_server_tls(stream, tls).await?;
                            Ok((transport.stream, Some(transport.direct_switch)))
                        } else {
                            let stream = tls.accept_stream(stream).await?;
                            Ok((Box::new(stream), None))
                        }
                    } else { Ok((stream, None)) };
                    if let Ok((stream, vision_switch)) = stream {
                        let mut accepted = accept_transport_streams(
                            stream,
                            transport.as_ref(),
                            tls_enabled,
                        ).await?;
                        let mut logical_streams = JoinSet::new();
                        while let Some(stream) = accepted.recv().await {
                            let stream = crate::adapter::preserve_stream_socket(stream?, socket);
                            let tag = tag.clone(); let users = users.clone(); let names = names.clone();
                            let router = router.clone(); let outbounds = outbounds.clone();
                            let vision_switch = vision_switch.clone();
                            logical_streams.spawn(async move {
                                let _ = handle_connection(stream, source, &tag, &users, &names, &router, &outbounds, udp_timeout, multiplex_enabled, multiplex_padding, multiplex_brutal, vision_switch).await;
                            });
                        }
                        while logical_streams.join_next().await.is_some() {}
                    }
                    Ok::<_, io::Error>(())
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
async fn handle_connection(
    mut client: Stream,
    source: SocketAddr,
    tag: &str,
    users: &HashMap<Uuid, usize>,
    names: &[crate::option::VlessUser],
    router: &Arc<Router>,
    outbounds: &Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
    vision_switch: Option<Arc<dyn VisionDirectSwitch>>,
) -> io::Result<()> {
    let socket = crate::adapter::stream_socket(&client);
    let request = read_request(&mut client).await?;
    let user_index = users.get(&request.uuid).copied().ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "unknown VLESS UUID")
    })?;
    let configured_flow = names
        .get(user_index)
        .map(|user| user.flow.as_str())
        .unwrap_or_default();
    if request.flow != configured_flow {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VLESS flow mismatch",
        ));
    }
    let vision = request.flow == FLOW_VISION;
    let mut client = if vision {
        let direct_switch = vision_switch.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "VLESS Vision requires a switchable outer TLS stream",
            )
        })?;
        crate::adapter::preserve_stream_socket(
            Box::new(crate::protocol::vless_vision::VisionStream::server(
                client,
                direct_switch,
                *request.uuid.as_bytes(),
            )),
            socket,
        )
    } else {
        client
    };
    let user = names
        .get(user_index)
        .map(|value| value.name.clone())
        .unwrap_or_default();
    match request.command {
        Command::Tcp => {
            let destination = request.destination.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS TCP request has no destination",
                )
            })?;
            if multiplex_enabled
                && crate::protocol::mux::is_destination(&destination)
            {
                write_connection_response(&mut client, vision).await?;
                let client =
                    crate::adapter::preserve_stream_socket(client, socket);
                return crate::protocol::mux::serve_routed_h2mux(
                    client,
                    source,
                    tag.to_owned(),
                    user,
                    router.clone(),
                    outbounds.clone(),
                    udp_timeout,
                    multiplex_padding,
                    multiplex_brutal,
                )
                .await;
            }
            proxy_tcp(
                client,
                source,
                tag,
                destination,
                user,
                router,
                outbounds,
                vision,
            )
            .await
        }
        Command::Udp => {
            if vision {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "xtls-rprx-vision flow does not support UDP",
                ));
            }
            let destination = request.destination.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS UDP request has no destination",
                )
            })?;
            let packet: PacketStream = Box::new(
                VlessServerPacketConnection::new(client, destination.clone()),
            );
            let packet = if crate::protocol::packetaddr::is_magic(&destination)
            {
                Box::new(
                    crate::protocol::packetaddr::PacketAddrConnection::new(
                        packet,
                    ),
                ) as PacketStream
            } else {
                packet
            };
            proxy_packet_connection(
                packet,
                source,
                tag,
                Some(user),
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }
        Command::Mux => {
            if vision {
                write_connection_response(&mut client, true).await?;
            }
            crate::protocol::vmess_mux::serve_routed(
                client,
                if vision {
                    None
                } else {
                    Some(vec![crate::protocol::vless::VERSION, 0])
                },
                source,
                tag.to_owned(),
                user,
                router.clone(),
                outbounds.clone(),
                udp_timeout,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn proxy_tcp(
    mut client: Stream,
    source: SocketAddr,
    tag: &str,
    destination: crate::common::network::SocksAddr,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
    vision: bool,
) -> io::Result<()> {
    let (destination, origin_destination) =
        restore_fake_ip(destination, outbounds)?;
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
        write_connection_response(&mut client, vision).await?;
        return injector
            .inject(client, TcpInboundContext { source, metadata })
            .await;
    }
    let (mut client, decision) =
        sniff_and_route_stream(client, &mut metadata, router, outbounds)
            .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by route rule",
        ));
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        write_connection_response(&mut client, vision).await?;
        return serve_hijacked_dns_stream_with_context(
            client, outbounds, &metadata,
        )
        .await;
    }
    let destination = decision.destination(&destination);
    let connection_options = decision.connection_options();
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let mut remote = dialer
        .dial_tcp_with_options(&destination, &connection_options.network)
        .await?;
    remote = super::apply_routed_tcp_options(remote, &connection_options)?;
    write_connection_response(&mut client, vision).await?;
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn write_connection_response(
    client: &mut Stream,
    vision: bool,
) -> io::Result<()> {
    if vision {
        client.flush().await
    } else {
        write_response(client).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        time::{Duration, timeout},
    };
    use tokio_rustls::TlsAcceptor;
    use x25519_dalek::x25519;

    use super::VlessInbound;
    use crate::{
        adapter::{
            DialFuture, Dialer, VisionDialFuture, VisionDirectSwitch,
            VisionTransport,
        },
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            reality_tls::spawn_reality_cover_stub,
            tls::{ClientTlsDialer, build_client_config, build_server_config},
        },
        option::{
            InboundTlsOptions, Options, OutboundMultiplexOptions,
            OutboundTlsOptions, VlessInboundOptions,
        },
        outbound::OutboundManager,
        protocol::{
            direct::DirectOutbound,
            mux::MuxClient,
            vless::{Command, FLOW_VISION, VlessOutbound, write_request},
        },
        route::Router,
        transport::{quic::QuicDialer, v2ray::WebsocketDialer},
    };

    struct VisionProbe<D> {
        inner: D,
        switch: Arc<Mutex<Option<Arc<dyn VisionDirectSwitch>>>>,
    }

    impl<D: Dialer> Dialer for VisionProbe<D> {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            self.inner.dial_tcp(destination)
        }

        fn dial_vision_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> VisionDialFuture<'a> {
            Box::pin(async move {
                let transport = self.inner.dial_vision_tcp(destination).await?;
                *self.switch.lock().unwrap() =
                    Some(transport.direct_switch.clone());
                Ok(VisionTransport {
                    stream: transport.stream,
                    direct_switch: transport.direct_switch,
                })
            })
        }
    }

    #[tokio::test]
    async fn proxies_tcp_legacy_udp_and_xudp_end_to_end() {
        proxies_tcp_udp_end_to_end(None).await;
    }

    #[tokio::test]
    async fn proxies_websocket_tcp_udp_end_to_end() {
        proxies_tcp_udp_end_to_end(Some("ws")).await;
    }

    #[tokio::test]
    async fn proxies_quic_tcp_udp_end_to_end() {
        proxies_tcp_udp_end_to_end(Some("quic")).await;
    }

    #[tokio::test]
    async fn proxies_tcp_through_reality_inbound_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let (cover_address, cover_task) = spawn_reality_cover_stub().await;
        let private_key = [0x31; 32];
        let public_key =
            x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let user = "00112233-4455-6677-8899-aabbccddeeff";
        let options: VlessInboundOptions = serde_json::from_value(json!({
            "listen": "127.0.0.1",
            "listen_port": 0,
            "users": [{"name": "alice", "uuid": user}],
            "tls": {
                "enabled": true,
                "server_name": "reality.example",
                "reality": {
                    "enabled": true,
                    "private_key": URL_SAFE_NO_PAD.encode(private_key),
                    "short_id": ["01020304"],
                    "handshake": {
                        "server": cover_address.ip().to_string(),
                        "server_port": cover_address.port()
                    }
                }
            }
        }))
        .unwrap();
        let runtime_options: Options = serde_json::from_value(json!({
            "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "direct").unwrap());
        let mut inbound =
            VlessInbound::new("vless", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();

        let tls = build_client_config(
            "reality.example",
            &OutboundTlsOptions {
                utls: Some(crate::option::OutboundUtlsOptions {
                    enabled: true,
                    fingerprint: "randomized".into(),
                }),
                reality: Some(crate::option::OutboundRealityOptions {
                    enabled: true,
                    public_key: URL_SAFE_NO_PAD.encode(public_key),
                    short_id: "01020304".into(),
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let direct: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(Default::default()));
        let tls_dialer: Arc<dyn Dialer> =
            Arc::new(ClientTlsDialer::new(direct, tls));
        let client = VlessOutbound::new(
            tls_dialer,
            inbound.local_addr().unwrap().into(),
            user,
            true,
            false,
        );
        let mut stream = client.dial_tcp(&destination.into()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        drop(stream);
        inbound.close().await.unwrap();
        echo.await.unwrap();
        cover_task.await.unwrap();
    }

    #[tokio::test]
    async fn proxies_tls13_through_vision_direct_end_to_end() {
        timeout(Duration::from_secs(15), async {
            let CertifiedKey {
                cert: target_cert,
                key_pair: target_key,
            } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let target_tls: InboundTlsOptions = serde_json::from_value(json!({
                "enabled": true,
                "certificate": target_cert.pem(),
                "key": target_key.serialize_pem(),
                "min_version": "1.3",
                "max_version": "1.3"
            }))
            .unwrap();
            let target_tls = build_server_config(&target_tls).unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = target.local_addr().unwrap();
            let payload = vec![0x5a_u8; 20_000];
            let expected = payload.clone();
            let target_task = tokio::spawn(async move {
                let (stream, _) = target.accept().await.unwrap();
                let mut stream = TlsAcceptor::from(target_tls.config)
                    .accept(stream)
                    .await
                    .unwrap();
                let mut received = vec![0_u8; expected.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected);
                stream.write_all(&received).await.unwrap();
                stream.flush().await.unwrap();
            });

            let CertifiedKey {
                cert: outer_cert,
                key_pair: outer_key,
            } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let user = "00112233-4455-6677-8899-aabbccddeeff";
            let inbound_options: VlessInboundOptions =
                serde_json::from_value(json!({
                    "listen":"127.0.0.1",
                    "listen_port":0,
                    "users":[{
                        "name":"vision",
                        "uuid":user,
                        "flow":"xtls-rprx-vision"
                    }],
                    "tls":{
                        "enabled":true,
                        "certificate":outer_cert.pem(),
                        "key":outer_key.serialize_pem(),
                        "min_version":"1.3",
                        "max_version":"1.3"
                    }
                }))
                .unwrap();
            let runtime_options: Options = serde_json::from_value(json!({
                "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
                "outbounds":[{"type":"direct","tag":"direct"}]
            }))
            .unwrap();
            let outbounds = Arc::new(
                OutboundManager::from_options(&runtime_options, "").unwrap(),
            );
            let router = Arc::new(Router::from_json(&[], "").unwrap());
            let mut inbound =
                VlessInbound::new("vision", inbound_options, router, outbounds)
                    .unwrap();
            inbound.start(StartStage::Start).await.unwrap();

            let direct: Arc<dyn Dialer> =
                Arc::new(DirectOutbound::new(Default::default()));
            let outer_client_tls = build_client_config(
                "localhost",
                &OutboundTlsOptions {
                    enabled: true,
                    insecure: true,
                    min_version: "1.3".into(),
                    max_version: "1.3".into(),
                    ..Default::default()
                },
                &[],
            )
            .unwrap();
            let switch_probe = Arc::new(Mutex::new(None));
            let outer: Arc<dyn Dialer> = Arc::new(VisionProbe {
                inner: ClientTlsDialer::new(direct, outer_client_tls),
                switch: switch_probe.clone(),
            });
            let vless: Arc<dyn Dialer> = Arc::new(
                VlessOutbound::new_with_flow(
                    outer,
                    inbound.local_addr().unwrap().into(),
                    user,
                    false,
                    false,
                    "xtls-rprx-vision",
                )
                .unwrap(),
            );
            let target_client_tls = build_client_config(
                "localhost",
                &OutboundTlsOptions {
                    enabled: true,
                    insecure: true,
                    min_version: "1.3".into(),
                    max_version: "1.3".into(),
                    ..Default::default()
                },
                &[],
            )
            .unwrap();
            let client = ClientTlsDialer::new(vless, target_client_tls);
            let mut stream =
                client.dial_tcp(&destination.into()).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = vec![0_u8; payload.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, payload);
            let switch = switch_probe.lock().unwrap().clone().unwrap();
            assert!(switch.read_direct_active());
            assert!(switch.write_direct_active());

            inbound.close().await.unwrap();
            target_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn vision_without_tls_matches_upstream_connection_time_rejection() {
        let user = "00112233-4455-6677-8899-aabbccddeeff";
        let inbound_options: VlessInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "users":[{
                    "name":"",
                    "uuid":user,
                    "flow":"xtls-rprx-vision"
                }]
            }))
            .unwrap();
        let runtime_options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            VlessInbound::new("vision", inbound_options, router, outbounds)
                .expect("upstream accepts Vision without TLS at config time");
        inbound.start(StartStage::Start).await.unwrap();

        let mut stream = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        write_request(
            &mut stream,
            uuid::Uuid::parse_str(user).unwrap(),
            Command::Tcp,
            Some(&SocksAddr::new("target.test", 443)),
            FLOW_VISION,
        )
        .await
        .unwrap();
        let mut byte = [0_u8; 1];
        let size = timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(size, 0);

        inbound.close().await.unwrap();
    }

    #[tokio::test]
    async fn proxies_tcp_and_udp_through_h2mux() {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut data = [0; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut data = [0; 16];
            let (size, source) = udp_target.recv_from(&mut data).await.unwrap();
            udp_target.send_to(&data[..size], source).await.unwrap();
        });
        let user = "00112233-4455-6677-8899-aabbccddeeff";
        let options: VlessInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "udp_timeout":"5s",
            "users":[{"name":"alice","uuid":user}],
                "multiplex":{"enabled":true,"padding":true}
        }))
        .unwrap();
        let runtime_options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{"type":"direct","tag":"direct"}]
        }))
        .unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            VlessInbound::new("vless", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let direct: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(Default::default()));
        let base: Arc<dyn Dialer> = Arc::new(VlessOutbound::new(
            direct,
            inbound.local_addr().unwrap().into(),
            user,
            true,
            false,
        ));
        let client = MuxClient::new(
            base,
            OutboundMultiplexOptions {
                enabled: true,
                max_connections: 1,
                padding: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut tcp = client.dial_tcp(&tcp_destination.into()).await.unwrap();
        tcp.write_all(b"mux!").await.unwrap();
        let mut response = [0; 16];
        tcp.read_exact(&mut response[..4]).await.unwrap();
        assert_eq!(&response[..4], b"mux!");
        let packets = client.listen_udp(&udp_destination.into()).await.unwrap();
        packets
            .send_to(b"packet", &udp_destination.into())
            .await
            .unwrap();
        let (size, source) = packets.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"packet");
        assert_eq!(source, udp_destination.into());
        inbound.close().await.unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
    }

    async fn proxies_tcp_udp_end_to_end(transport: Option<&str>) {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut data = [0; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            for _ in 0..3 {
                let mut data = [0; 16];
                let (size, source) =
                    udp_target.recv_from(&mut data).await.unwrap();
                udp_target.send_to(&data[..size], source).await.unwrap();
            }
        });
        let user = "00112233-4455-6677-8899-aabbccddeeff";
        let tls = if transport == Some("quic") {
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            Some(json!({
                "enabled":true,
                "certificate":cert.pem(),
                "key":key_pair.serialize_pem(),
                "alpn":["h3"]
            }))
        } else {
            None
        };
        let options: VlessInboundOptions = serde_json::from_value(json!({
            "listen":"127.0.0.1",
            "listen_port":0,
            "udp_timeout":"5s",
            "users":[{"name":"alice","uuid":user}],
            "tls":tls,
            "transport":transport.map(|transport| match transport {
                "ws" => json!({"type":"ws","path":"/vless"}),
                "quic" => json!({"type":"quic"}),
                transport => panic!("unsupported test transport: {transport}"),
            })
        }))
        .unwrap();
        let runtime_options: Options = serde_json::from_value(json!({"dns":{"servers":[{"type":"hosts","tag":"hosts"}]},"outbounds":[{"type":"direct","tag":"direct"}]})).unwrap();
        let outbounds = Arc::new(
            OutboundManager::from_options(&runtime_options, "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound =
            VlessInbound::new("vless", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let direct: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(Default::default()));
        let upstream: Arc<dyn Dialer> = match transport {
            Some("ws") => Arc::new(
                WebsocketDialer::new(
                    direct,
                    inbound.local_addr().unwrap().into(),
                    serde_json::from_value(json!({"path":"/vless"})).unwrap(),
                )
                .unwrap(),
            ),
            Some("quic") => Arc::new(
                QuicDialer::new(
                    inbound.local_addr().unwrap().into(),
                    "localhost",
                    build_client_config(
                        "localhost",
                        &OutboundTlsOptions {
                            enabled: true,
                            insecure: true,
                            ..Default::default()
                        },
                        &["h3"],
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            None => direct,
            Some(transport) => {
                panic!("unsupported test transport: {transport}")
            }
        };
        let client = VlessOutbound::new(
            upstream.clone(),
            inbound.local_addr().unwrap().into(),
            user,
            true,
            false,
        );
        let mut tcp = client.dial_tcp(&tcp_destination.into()).await.unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        let packet = client.listen_udp(&udp_destination.into()).await.unwrap();
        packet
            .send_to(b"datagram", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let mut response = [0; 16];
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"datagram");
        assert_eq!(source, SocksAddr::from(udp_destination));

        let xudp_client = VlessOutbound::new(
            upstream.clone(),
            inbound.local_addr().unwrap().into(),
            user,
            false,
            false,
        );
        let xudp = xudp_client
            .listen_udp(&udp_destination.into())
            .await
            .unwrap();
        xudp.send_to(b"xudp", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let (size, source) = xudp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"xudp");
        assert_eq!(source, SocksAddr::from(udp_destination));

        let packetaddr_client = VlessOutbound::new(
            upstream,
            inbound.local_addr().unwrap().into(),
            user,
            true,
            true,
        );
        let packetaddr = packetaddr_client
            .listen_udp(&udp_destination.into())
            .await
            .unwrap();
        packetaddr
            .send_to(b"packetaddr", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let (size, source) = packetaddr.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"packetaddr");
        assert_eq!(source, SocksAddr::from(udp_destination));
        inbound.close().await.unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
    }
}
