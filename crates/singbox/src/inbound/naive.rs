//! NaiveProxy HTTP/1.1 CONNECT inbound with the protocol padding layer.

use std::{
    convert::Infallible,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use hyper::{
    Response, StatusCode, body::Incoming, server::conn::http2 as server_http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::{Endpoint, VarInt, crypto::rustls::QuicServerConfig};
use tokio::{
    io::{AsyncReadExt as _, copy_bidirectional},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{PacketStream, Stream, replay_stream},
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::Network,
        tls::{
            ServerTlsConfig, TlsError,
            build_server_config_with_default_alpn_and_reality_dialer,
        },
    },
    inbound::{
        TcpInboundContext, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream,
        socks::{proxy_packet_connection, restore_fake_ip},
    },
    option::{NaiveInboundOptions, Network as OptionNetwork},
    outbound::OutboundManager,
    protocol::{naive, uot},
    route::{Action, Metadata, Router},
};

#[derive(Debug, thiserror::Error)]
pub enum NaiveInboundError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("invalid NaiveProxy inbound configuration: {0}")]
    Invalid(String),
}

pub struct NaiveInbound {
    name: String,
    tag: String,
    options: NaiveInboundOptions,
    tls: Option<ServerTlsConfig>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl NaiveInbound {
    pub fn new(
        tag: impl Into<String>,
        options: NaiveInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, NaiveInboundError> {
        if options.users.is_empty() {
            return Err(NaiveInboundError::Invalid("missing users".into()));
        }
        let networks = options.network.build();
        let tcp = networks.contains(&OptionNetwork::Tcp);
        let udp = networks.contains(&OptionNetwork::Udp);
        if !tcp && !udp {
            return Err(NaiveInboundError::Invalid(
                "network must include tcp or udp".into(),
            ));
        }
        if !matches!(
            options.quic_congestion_control.as_str(),
            "" | "bbr" | "cubic" | "reno"
        ) {
            return Err(NaiveInboundError::Invalid(format!(
                "unknown QUIC congestion control {:?}",
                options.quic_congestion_control
            )));
        }
        let tls = if let Some(tls_options) =
            options.tls.as_ref().filter(|tls| tls.enabled)
        {
            if tls_options.alpn.as_slice().iter().any(|value| {
                value != "http/1.1" && value != "h2" && value != "h3"
            }) {
                return Err(NaiveInboundError::Invalid(
                    "only h3, h2 and http/1.1 ALPN are supported for NaiveProxy"
                        .into(),
                ));
            }
            if udp
                && tls_options
                    .reality
                    .as_ref()
                    .is_some_and(|reality| reality.enabled)
            {
                return Err(NaiveInboundError::Invalid(
                    "REALITY is unavailable for HTTP/3".into(),
                ));
            }
            let reality_dialer = tls_options
                .reality
                .as_ref()
                .filter(|reality| reality.enabled)
                .map(|reality| {
                    outbounds.endpoint_dialer(
                        "inbound/naive/reality",
                        &reality.handshake.dialer,
                    )
                })
                .transpose()
                .map_err(|error| {
                    NaiveInboundError::Tls(TlsError::Unsupported(
                        error.to_string(),
                    ))
                })?;
            Some(build_server_config_with_default_alpn_and_reality_dialer(
                tls_options,
                &["h2", "http/1.1"],
                reality_dialer,
            )?)
        } else {
            None
        };
        if udp && tls.is_none() && !tcp {
            return Err(NaiveInboundError::Invalid(
                "TLS is required for HTTP/3-only NaiveProxy inbound".into(),
            ));
        }
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/naive[{tag}]"),
            tag,
            options,
            tls,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            tasks: Vec::new(),
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
        let address = SocketAddr::new(ip, self.options.listen.listen_port);
        let networks = self.options.network.build();
        let tcp = networks.contains(&OptionNetwork::Tcp);
        let udp = networks.contains(&OptionNetwork::Udp);
        let users = Arc::new(self.options.users.clone());
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        if tcp {
            let listener = crate::common::socket::bind_tcp_listener(
                address,
                &self.options.listen,
            )
            .await?;
            self.local_addr = Some(listener.local_addr()?);
            self.tasks.push(tokio::spawn(accept_loop(
                listener,
                self.cancellation.clone(),
                self.tag.clone(),
                users.clone(),
                self.tls.clone(),
                self.router.clone(),
                self.outbounds.clone(),
                udp_timeout,
            )));
        }
        if udp && self.tls.is_some() {
            let quic_address = self.local_addr.unwrap_or(address);
            let endpoint = http3_endpoint(
                quic_address,
                self.tls.clone().expect("HTTP/3 TLS exists"),
                &self.options.quic_congestion_control,
            )?;
            if self.local_addr.is_none() {
                self.local_addr = Some(endpoint.local_addr()?);
            }
            self.tasks.push(tokio::spawn(http3_accept_loop(
                endpoint,
                self.cancellation.clone(),
                self.tag.clone(),
                users,
                self.router.clone(),
                self.outbounds.clone(),
                udp_timeout,
            )));
        }
        Ok(())
    }
}

impl Lifecycle for NaiveInbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage == StartStage::Start {
                self.bind().await.map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })?;
            }
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            for task in self.tasks.drain(..) {
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

fn http3_endpoint(
    address: SocketAddr,
    tls: ServerTlsConfig,
    congestion_control: &str,
) -> io::Result<Endpoint> {
    let mut rustls = (*tls.config).clone();
    if !rustls.alpn_protocols.iter().any(|value| value == b"h3") {
        rustls.alpn_protocols.push(b"h3".to_vec());
    }
    let crypto =
        QuicServerConfig::try_from(rustls).map_err(io::Error::other)?;
    let mut transport = quinn::TransportConfig::default();
    // A very large value near QUIC's protocol limit causes Quinn peers to
    // reject the transport parameter. One million remains effectively
    // unbounded while interoperating with standard HTTP/3 implementations.
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1 << 20));
    match congestion_control {
        "" | "bbr" => {
            transport.congestion_controller_factory(Arc::new(
                crate::protocol::quic_bbr::BbrConfig::new(
                    crate::protocol::quic_bbr::BbrProfile::Standard,
                ),
            ));
        }
        "cubic" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::CubicConfig::default(),
            ));
        }
        "reno" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        value => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown QUIC congestion control {value:?}"),
            ));
        }
    }
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport));
    Endpoint::server(server, address)
}

#[allow(clippy::too_many_arguments)]
async fn http3_accept_loop(
    endpoint: Endpoint,
    cancellation: CancellationToken,
    tag: String,
    users: Arc<Vec<crate::option::User>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let tag = tag.clone();
                let users = users.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let connection = incoming.await.map_err(io::Error::other)?;
                    let source = connection.remote_address();
                    let mut http3 = h3::server::Connection::new(
                        h3_quinn::Connection::new(connection),
                    )
                    .await
                    .map_err(io::Error::other)?;
                    let mut requests = JoinSet::new();
                    loop {
                        let Some(resolver) = http3
                            .accept()
                            .await
                            .map_err(io::Error::other)?
                        else {
                            break;
                        };
                        let tag = tag.clone();
                        let users = users.clone();
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        requests.spawn(async move {
                            let (request, mut stream) = resolver
                                .resolve_request()
                                .await
                                .map_err(io::Error::other)?;
                            let (destination, user) = match naive::validate_http3_request(
                                &request,
                                &users,
                            ) {
                                Ok(result) => result,
                                Err(error) => {
                                    let status = if error.kind()
                                        == io::ErrorKind::PermissionDenied
                                    {
                                        StatusCode::PROXY_AUTHENTICATION_REQUIRED
                                    } else {
                                        StatusCode::BAD_REQUEST
                                    };
                                    stream
                                        .send_response(
                                            Response::builder()
                                                .status(status)
                                                .body(())
                                                .map_err(io::Error::other)?,
                                        )
                                        .await
                                        .map_err(io::Error::other)?;
                                    stream.finish().await.map_err(io::Error::other)?;
                                    return Ok::<_, io::Error>(());
                                }
                            };
                            stream
                                .send_response(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(
                                            "padding",
                                            naive::generate_padding_header()?,
                                        )
                                        .body(())
                                        .map_err(io::Error::other)?,
                                )
                                .await
                                .map_err(io::Error::other)?;
                            let client = Box::new(naive::PaddingStream::new(
                                naive::bridge_http3_server(stream),
                            )) as Stream;
                            route_connection(
                                client,
                                source,
                                &tag,
                                destination,
                                user,
                                &router,
                                &outbounds,
                                udp_timeout,
                            )
                            .await
                        });
                    }
                    requests.abort_all();
                    while requests.join_next().await.is_some() {}
                    Ok::<_, io::Error>(())
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    endpoint.close(0_u32.into(), b"");
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    users: Arc<Vec<crate::option::User>>,
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
                let tls = tls.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let (stream, http2): (Stream, bool) = if let Some(tls) = tls {
                        let stream = tls.accept_stream(Box::new(stream)).await?;
                        let http2 = stream.alpn_protocol()
                            == Some(b"h2".as_slice());
                        (Box::new(stream), http2)
                    } else {
                        detect_cleartext_http2(Box::new(stream)).await?
                    };
                    if http2 {
                        serve_http2_connection(
                            stream, source, tag, users, router, outbounds,
                            udp_timeout,
                        ).await
                    } else {
                        serve_connection(
                            stream, source, &tag, &users, &router, &outbounds,
                            udp_timeout,
                        ).await
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn detect_cleartext_http2(
    mut stream: Stream,
) -> io::Result<(Stream, bool)> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut prefix = vec![0_u8; PREFACE.len()];
    stream.read_exact(&mut prefix).await?;
    let http2 = prefix == PREFACE;
    Ok((replay_stream(stream, prefix), http2))
}

#[allow(clippy::too_many_arguments)]
async fn serve_http2_connection(
    stream: Stream,
    source: SocketAddr,
    tag: String,
    users: Arc<Vec<crate::option::User>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
        let users = users.clone();
        let tag = tag.clone();
        let router = router.clone();
        let outbounds = outbounds.clone();
        async move {
            let (destination, user) =
                match naive::validate_http2_request(&request, &users) {
                    Ok(result) => result,
                    Err(error) => {
                        let status = if error.kind()
                            == io::ErrorKind::PermissionDenied
                        {
                            StatusCode::PROXY_AUTHENTICATION_REQUIRED
                        } else {
                            StatusCode::BAD_REQUEST
                        };
                        return Ok::<_, Infallible>(empty_http2_response(
                            status,
                        ));
                    }
                };
            let upgraded = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let Ok(upgraded) = upgraded.await else {
                    return;
                };
                let client = Box::new(naive::PaddingStream::new(Box::new(
                    TokioIo::new(upgraded),
                ))) as Stream;
                let _ = route_connection(
                    client,
                    source,
                    &tag,
                    destination,
                    user,
                    &router,
                    &outbounds,
                    udp_timeout,
                )
                .await;
            });
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            drop(sender);
            let mut response = Response::new(naive::streaming_body(receiver));
            response.headers_mut().insert(
                "padding",
                naive::generate_padding_header()
                    .and_then(|value| value.parse().map_err(io::Error::other))
                    .expect("generated padding is a valid HTTP header"),
            );
            Ok::<_, Infallible>(response)
        }
    });
    server_http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
        .map_err(io::Error::other)
}

fn empty_http2_response(
    status: StatusCode,
) -> Response<http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    drop(sender);
    let mut response = Response::new(naive::streaming_body(receiver));
    *response.status_mut() = status;
    response
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    mut stream: Stream,
    source: SocketAddr,
    tag: &str,
    users: &[crate::option::User],
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let (destination, user) =
        naive::server_handshake(&mut stream, users).await?;
    let stream = Box::new(naive::PaddingStream::new(stream)) as Stream;
    route_connection(
        stream,
        source,
        tag,
        destination,
        user,
        router,
        outbounds,
        udp_timeout,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn route_connection(
    stream: Stream,
    source: SocketAddr,
    tag: &str,
    destination: crate::common::network::SocksAddr,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    if let Some(version) = uot::destination_version(&destination) {
        let packets: PacketStream =
            Box::new(uot::accept(stream, version).await?);
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
    proxy_tcp(stream, source, tag, destination, user, router, outbounds).await
}

#[allow(clippy::too_many_arguments)]
async fn proxy_tcp(
    client: Stream,
    source: SocketAddr,
    tag: &str,
    destination: crate::common::network::SocksAddr,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
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
        ..Metadata::default()
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
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
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedKey,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        generate_simple_self_signed,
    };
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, UdpSocket},
    };

    use super::NaiveInbound;
    use crate::{
        adapter::Dialer as _,
        common::{
            lifecycle::{Lifecycle as _, StartStage},
            network::SocksAddr,
        },
        option::{NaiveInboundOptions, Options},
        outbound::OutboundManager,
        route::Router,
    };

    async fn spawn_udp_impairment_proxy(
        server: SocketAddr,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut sequence = 0_u64;
            let mut held = None::<(Vec<u8>, SocketAddr)>;
            let mut buffer = vec![0_u8; 65_535];
            loop {
                let Ok((length, source)) = socket.recv_from(&mut buffer).await
                else {
                    return;
                };
                let destination = if source == server {
                    let Some(client) = client else {
                        continue;
                    };
                    client
                } else {
                    client = Some(source);
                    server
                };
                sequence += 1;

                // Leave the handshake undisturbed, then introduce deterministic
                // bidirectional loss, reordering, and a temporary low-bandwidth
                // interval. This is deliberately based on relay sequence rather
                // than encrypted QUIC contents.
                if sequence > 64 && sequence.is_multiple_of(31) {
                    continue;
                }
                let datagram = buffer[..length].to_vec();
                if sequence > 64
                    && sequence.is_multiple_of(13)
                    && held.is_none()
                {
                    held = Some((datagram, destination));
                    continue;
                }
                if (300..900).contains(&sequence) {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                if socket.send_to(&datagram, destination).await.is_err() {
                    return;
                }
                if let Some((datagram, destination)) = held.take() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    if socket.send_to(&datagram, destination).await.is_err() {
                        return;
                    }
                }
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn proxies_tls_tcp_and_uot_udp_end_to_end() {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            for _ in 0..6 {
                let (mut stream, _) = tcp_target.accept().await.unwrap();
                let mut data = [0_u8; 4];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
            }
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
        let inbound_options: NaiveInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "network":"tcp",
                "udp_timeout":"5s",
                "users":[{"username":"alice","password":"secret"}],
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
            NaiveInbound::new("naive-in", inbound_options, router, direct)
                .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let server = inbound.local_addr().unwrap();

        let client_options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[{
                "type":"naive",
                "tag":"naive-out",
                "server":"127.0.0.1",
                "server_port":server.port(),
                "username":"alice",
                "password":"secret",
                "insecure_concurrency":3,
                "extra_headers":{"X-Naive-Test":"yes"},
                "stream_receive_window":"8MB",
                "udp_over_tcp":{"enabled":true,"version":2},
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

        for _ in 0..6 {
            let mut tcp = outbound
                .dial_tcp(&SocksAddr::from(tcp_destination))
                .await
                .unwrap();
            tcp.write_all(b"ping").await.unwrap();
            let mut echoed = [0_u8; 4];
            tcp.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"ping");
        }

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

    #[tokio::test]
    async fn proxies_http3_tcp_and_uot_udp_end_to_end() {
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
        let inbound_options: NaiveInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "network":"udp",
                "udp_timeout":"5s",
                "users":[{"username":"alice","password":"secret"}],
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
            NaiveInbound::new("naive-h3-in", inbound_options, router, direct)
                .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let server = inbound.local_addr().unwrap();

        let client_options: Options = serde_json::from_value(json!({
            "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
            "outbounds":[
                {"type":"direct","tag":"quic-underlay","connect_timeout":"5s"},
                {
                    "type":"naive",
                    "tag":"naive-h3-out",
                    "server":"127.0.0.1",
                    "server_port":server.port(),
                    "username":"alice",
                    "password":"secret",
                    "extra_headers":{"X-Naive-Test":"h3"},
                    "stream_receive_window":"2MB",
                    "quic_session_receive_window":"8MB",
                    "quic":true,
                    "quic_congestion_control":"bbr2",
                    "udp_over_tcp":{"enabled":true,"version":2},
                    "detour":"quic-underlay",
                    "tls":{
                        "enabled":true,
                        "server_name":"localhost",
                        "certificate":certificate
                    }
                }
            ],
            "route":{"final":"naive-h3-out"}
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

    #[tokio::test]
    #[ignore = "requires the pinned Go Cronet toolchain"]
    async fn pinned_cronet_bbr2_client_survives_loss_reorder_and_rate_shift() {
        const PAYLOAD_SIZE: usize = 2 * 1024 * 1024;

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = vec![0_u8; PAYLOAD_SIZE];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let mut ca_parameters = CertificateParams::default();
        let now = time::OffsetDateTime::now_utc();
        ca_parameters.not_before = now - time::Duration::days(1);
        ca_parameters.not_after = now + time::Duration::days(30);
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
        let mut leaf_parameters =
            CertificateParams::new(vec!["naive.example.com".into()]).unwrap();
        leaf_parameters.not_before = now - time::Duration::days(1);
        leaf_parameters.not_after = now + time::Duration::days(30);
        leaf_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_certificate = leaf_parameters
            .signed_by(&leaf_key, &ca_certificate, &ca_key)
            .unwrap();
        let certificate =
            format!("{}\n{}", leaf_certificate.pem(), ca_certificate.pem());
        let trusted_root = ca_certificate.pem();
        let inbound_options: NaiveInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1",
                "listen_port":0,
                "network":"udp",
                "users":[{"username":"alice","password":"secret"}],
                "tls":{
                    "enabled":true,
                    "certificate":certificate,
                    "key":leaf_key.serialize_pem()
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
            NaiveInbound::new("naive-cronet", inbound_options, router, direct)
                .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let server = inbound.local_addr().unwrap();
        let (proxy, proxy_task) = spawn_udp_impairment_proxy(server).await;

        let temporary = tempfile::tempdir().unwrap();
        let certificate_path = temporary.path().join("ca.pem");
        let netlog_path = temporary.path().join("cronet-netlog.json");
        std::fs::write(&certificate_path, trusted_root).unwrap();
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.join("../..");
        let fixture = manifest.join("tests/fixtures/naive-go-client/main.go");
        let status = tokio::task::spawn_blocking(move || {
            std::process::Command::new("go")
                .args(["run", fixture.to_str().unwrap()])
                .current_dir(workspace.join("inner/sing-box"))
                .env("SINGBOX_NAIVE_RUST_SERVER", proxy.to_string())
                .env("SINGBOX_NAIVE_TARGET", target_address.to_string())
                .env("SINGBOX_NAIVE_CA", certificate_path)
                .env("SINGBOX_NAIVE_NETLOG", &netlog_path)
                .status()
                .map(|status| (status, netlog_path))
        })
        .await
        .unwrap()
        .unwrap();

        proxy_task.abort();
        inbound.close().await.unwrap();
        if !status.0.success() {
            let path = temporary.keep();
            panic!(
                "pinned Cronet client failed; NetLog kept at {}",
                path.display()
            );
        }
        echo.await.unwrap();
        let netlog = std::fs::read(status.1).unwrap();
        assert!(
            netlog.windows(4).any(|window| window == b"B2ON"),
            "Cronet NetLog did not record the BBRv2 connection option"
        );
    }
}
