//! Snell v5 TCP inbound.

use std::{
    collections::HashSet,
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
    adapter::Stream,
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::Network,
    },
    inbound::{
        TcpInboundContext, TcpInboundInjector, TcpInjectFuture,
        inherited_tcp_metadata, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_stream,
        socks::proxy_packet_connection, with_tcp_inbound_context,
    },
    option::{SnellInboundOptions, SnellUser},
    outbound::OutboundManager,
    protocol::snell::{
        COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_PING, COMMAND_UDP,
        ObfsMode, SaltReplayCache, V5ServerSession, accept_v5_server_session,
        wrap_obfs_server,
    },
    protocol::snell_v6::{
        Mode as SnellV6Mode, V6ServerSession, accept_v6_server_session,
    },
    route::{Action, Metadata, Router},
};

#[derive(Debug, thiserror::Error)]
pub enum SnellInboundError {
    #[error("invalid Snell inbound configuration: {0}")]
    Config(String),
}

pub struct SnellInbound {
    name: String,
    tag: String,
    options: SnellInboundOptions,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
    salt_replay: Arc<SaltReplayCache>,
}

#[derive(Clone)]
pub struct SnellTcpInjector {
    tag: String,
    psk: String,
    users: Vec<SnellUser>,
    salt_replay: Arc<SaltReplayCache>,
    version: i32,
    obfs_mode: ObfsMode,
    v6_mode: SnellV6Mode,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
}

impl SnellTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: SnellInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, SnellInboundError> {
        let inbound = SnellInbound::new(tag, options, router, outbounds)?;
        Ok(Self {
            tag: inbound.tag,
            psk: inbound.options.psk,
            users: inbound.options.users,
            salt_replay: inbound.salt_replay,
            version: inbound.options.version,
            obfs_mode: ObfsMode::parse(&inbound.options.obfs_mode).map_err(
                |error| SnellInboundError::Config(error.to_string()),
            )?,
            v6_mode: SnellV6Mode::parse(&inbound.options.mode).map_err(
                |error| SnellInboundError::Config(error.to_string()),
            )?,
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

impl TcpInboundInjector for SnellTcpInjector {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a> {
        let source = context.source;
        Box::pin(with_tcp_inbound_context(context, async move {
            handle_connection(
                stream,
                source,
                &self.tag,
                &self.psk,
                &self.users,
                &self.salt_replay,
                self.version,
                self.obfs_mode,
                self.v6_mode,
                &self.router,
                &self.outbounds,
                self.udp_timeout,
            )
            .await
        }))
    }
}

impl SnellInbound {
    pub fn new(
        tag: impl Into<String>,
        options: SnellInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, SnellInboundError> {
        if options.psk.is_empty() {
            return Err(SnellInboundError::Config(
                "missing pre-shared key".into(),
            ));
        }
        match options.version {
            5 => {
                ObfsMode::parse(&options.obfs_mode).map_err(|error| {
                    SnellInboundError::Config(error.to_string())
                })?;
            }
            6 => {
                if !(12..=255).contains(&options.psk.len()) {
                    return Err(SnellInboundError::Config(
                        "snell: psk length must be between 12 and 255 bytes"
                            .into(),
                    ));
                }
                SnellV6Mode::parse(&options.mode).map_err(|error| {
                    SnellInboundError::Config(error.to_string())
                })?;
            }
            _ => {
                return Err(SnellInboundError::Config(
                    "unsupported Snell server version".into(),
                ));
            }
        }
        let mut keys = HashSet::new();
        for user in &options.users {
            if user.userkey.is_empty() || user.userkey.len() > u8::MAX as usize
            {
                return Err(SnellInboundError::Config(
                    "user key must contain 1–255 bytes".into(),
                ));
            }
            if !keys.insert(user.userkey.as_bytes()) {
                return Err(SnellInboundError::Config(
                    "duplicate user key".into(),
                ));
            }
        }
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/snell[{tag}]"),
            tag,
            options,
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
            salt_replay: Arc::new(SaltReplayCache::default()),
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
        let psk = self.options.psk.clone();
        let users = self.options.users.clone();
        let salt_replay = self.salt_replay.clone();
        let obfs_mode = ObfsMode::parse(&self.options.obfs_mode)?;
        let version = self.options.version;
        let v6_mode = SnellV6Mode::parse(&self.options.mode)?;
        let udp_timeout = self
            .options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        self.task = Some(tokio::spawn(async move {
            accept_loop(
                listener,
                cancellation,
                tag,
                psk,
                users,
                salt_replay,
                version,
                obfs_mode,
                v6_mode,
                udp_timeout,
                router,
                outbounds,
            )
            .await
        }));
        Ok(())
    }
}

impl Lifecycle for SnellInbound {
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
    psk: String,
    users: Vec<SnellUser>,
    salt_replay: Arc<SaltReplayCache>,
    version: i32,
    obfs_mode: ObfsMode,
    v6_mode: SnellV6Mode,
    udp_timeout: std::time::Duration,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let tag = tag.clone();
                let psk = psk.clone();
                let users = users.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                let salt_replay = salt_replay.clone();
                connections.spawn(async move {
                    let _ = handle_connection(
                        Box::new(stream), source, &tag, &psk, &users,
                        &salt_replay, version, obfs_mode, v6_mode, &router, &outbounds,
                        udp_timeout,
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

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    raw: Stream,
    source: SocketAddr,
    tag: &str,
    psk: &str,
    users: &[SnellUser],
    salt_replay: &SaltReplayCache,
    version: i32,
    obfs_mode: ObfsMode,
    v6_mode: SnellV6Mode,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    if version == 5 {
        let (session, request, early_payload) = accept_v5_server_session(
            wrap_obfs_server(raw, obfs_mode)?,
            psk.as_bytes(),
            Some(salt_replay),
        )
        .await?;
        return handle_v5_session(
            session,
            request,
            early_payload,
            source,
            tag,
            users,
            router,
            outbounds,
            udp_timeout,
        )
        .await;
    }

    if version == 6 {
        let (session, request, early_payload) =
            accept_v6_server_session(raw, psk.as_bytes(), v6_mode).await?;
        return handle_v6_session(
            session,
            request,
            early_payload,
            source,
            tag,
            users,
            router,
            outbounds,
            udp_timeout,
        )
        .await;
    }
    Err(io::Error::other("unsupported Snell version"))
}

#[allow(clippy::too_many_arguments)]
async fn handle_v5_session(
    mut session: V5ServerSession,
    mut request: crate::protocol::snell::Request,
    mut early_payload: Vec<u8>,
    source: SocketAddr,
    tag: &str,
    users: &[SnellUser],
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let reusable = request.command == COMMAND_CONNECT_V2;
    loop {
        match request.command {
            COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
                let destination = request.destination.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing Snell destination",
                    )
                })?;
                let user = authenticate(users, &request.client_id)?;
                let (bridge, client) = tokio::io::duplex(64 * 1024);
                let (bridge_result, proxy_result) = tokio::join!(
                    session.bridge_logical(bridge, early_payload),
                    proxy_tcp(
                        Box::new(client),
                        source,
                        tag,
                        destination,
                        user,
                        router,
                        outbounds,
                    ),
                );
                bridge_result?;
                proxy_result?;
                if !reusable {
                    return Ok(());
                }
                (request, early_payload) = session.next_request().await?;
            }
            COMMAND_UDP => {
                let user = authenticate(users, &request.client_id)?;
                let packets = session.into_packet_connection().await?;
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
            COMMAND_PING => return session.write_pong().await,
            command => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported Snell command {command}"),
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_v6_session(
    mut session: V6ServerSession,
    mut request: crate::protocol::snell::Request,
    mut early_payload: Vec<u8>,
    source: SocketAddr,
    tag: &str,
    users: &[SnellUser],
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let reusable = request.command == COMMAND_CONNECT_V2;
    loop {
        match request.command {
            COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
                let destination = request.destination.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing Snell destination",
                    )
                })?;
                let user = authenticate(users, &request.client_id)?;
                let (bridge, client) = tokio::io::duplex(64 * 1024);
                let (bridge_result, proxy_result) = tokio::join!(
                    session.bridge_logical(bridge, early_payload),
                    proxy_tcp(
                        Box::new(client),
                        source,
                        tag,
                        destination,
                        user,
                        router,
                        outbounds,
                    ),
                );
                bridge_result?;
                proxy_result?;
                if !reusable {
                    return Ok(());
                }
                (request, early_payload) = session.next_request().await?;
            }
            COMMAND_UDP => {
                if !early_payload.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell: v6 UDP request contains early payload",
                    ));
                }
                let user = authenticate(users, &request.client_id)?;
                let packets = session.into_packet_connection().await?;
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
            COMMAND_PING => return session.write_pong().await,
            command => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported Snell command {command}"),
                ));
            }
        }
    }
}

async fn proxy_tcp(
    client: Stream,
    source: SocketAddr,
    tag: &str,
    destination: crate::common::network::SocksAddr,
    user: String,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()> {
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        network: Some(Network::Tcp),
        user,
        ..inherited_tcp_metadata(source, tag)
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
    let destination = decision
        .destination(metadata.destination.as_ref().unwrap_or(&destination));
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

fn authenticate(users: &[SnellUser], presented: &[u8]) -> io::Result<String> {
    if users.is_empty() {
        return Ok(String::new());
    }
    users
        .iter()
        .enumerate()
        .find(|(_, user)| {
            constant_time_equal(user.userkey.as_bytes(), presented)
        })
        .map(|(index, user)| {
            if user.name.is_empty() {
                index.to_string()
            } else {
                user.name.clone()
            }
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bad Snell user key",
            )
        })
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0)
                ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use super::*;
    use crate::{
        adapter::Dialer,
        common::lifecycle::Lifecycle,
        option::{Addr, DirectOutboundOptions, ListenOptions, Options},
        protocol::{
            direct::DirectOutbound,
            snell::SnellV4Outbound,
            snell_v6::{Mode as SnellV6Mode, SnellV6Outbound},
        },
    };

    #[tokio::test]
    async fn v5_inbound_routes_authenticated_v4_tcp() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = SnellInbound::new(
            "snell-in",
            SnellInboundOptions {
                listen: ListenOptions {
                    listen: Some(Addr("127.0.0.1".parse().unwrap())),
                    listen_port: 0,
                    ..Default::default()
                },
                version: 5,
                psk: "secret".into(),
                users: vec![SnellUser {
                    name: "alice".into(),
                    userkey: "user-key".into(),
                }],
                ..Default::default()
            },
            router,
            outbounds,
        )
        .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let outbound = SnellV4Outbound::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            inbound.local_addr().unwrap().into(),
            b"secret".to_vec(),
            b"user-key".to_vec(),
        )
        .unwrap();
        let mut stream =
            outbound.dial_tcp(&target_address.into()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        echo.await.unwrap();
        inbound.close().await.unwrap();
    }

    #[tokio::test]
    async fn v5_inbound_routes_authenticated_v4_udp() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut payload = [0_u8; 64];
            let (size, source) = target.recv_from(&mut payload).await.unwrap();
            assert_eq!(&payload[..size], b"ping datagram");
            target.send_to(b"pong datagram", source).await.unwrap();
        });

        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = SnellInbound::new(
            "snell-in",
            SnellInboundOptions {
                listen: ListenOptions {
                    listen: Some(Addr("127.0.0.1".parse().unwrap())),
                    listen_port: 0,
                    ..Default::default()
                },
                version: 5,
                psk: "secret".into(),
                users: vec![SnellUser {
                    name: "alice".into(),
                    userkey: "user-key".into(),
                }],
                ..Default::default()
            },
            router,
            outbounds,
        )
        .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let outbound = SnellV4Outbound::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            inbound.local_addr().unwrap().into(),
            b"secret".to_vec(),
            b"user-key".to_vec(),
        )
        .unwrap();
        let packets =
            outbound.listen_udp(&target_address.into()).await.unwrap();
        packets
            .send_to(b"ping datagram", &target_address.into())
            .await
            .unwrap();
        let mut response = [0_u8; 64];
        let (size, source) = packets.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"pong datagram");
        assert_eq!(source, target_address.into());
        echo.await.unwrap();
        inbound.close().await.unwrap();
    }

    #[tokio::test]
    async fn v6_unshaped_inbound_routes_authenticated_tcp() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = SnellInbound::new(
            "snell-v6-in",
            SnellInboundOptions {
                listen: ListenOptions {
                    listen: Some(Addr("127.0.0.1".parse().unwrap())),
                    listen_port: 0,
                    ..Default::default()
                },
                version: 6,
                psk: "secretsecret".into(),
                users: vec![SnellUser {
                    name: "alice".into(),
                    userkey: "user-key".into(),
                }],
                mode: "unshaped".into(),
                ..Default::default()
            },
            router,
            outbounds,
        )
        .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let outbound = SnellV6Outbound::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            inbound.local_addr().unwrap().into(),
            b"secretsecret".to_vec(),
            b"user-key".to_vec(),
            SnellV6Mode::Unshaped,
            false,
        )
        .unwrap();
        let mut stream =
            outbound.dial_tcp(&target_address.into()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        echo.await.unwrap();
        inbound.close().await.unwrap();
    }

    async fn assert_reused_tcp_sessions(version: i32, mode: &str) {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            for index in 0..2_u8 {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut payload = [0_u8; 2];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(payload, [b'0' + index, b'!']);
                stream.write_all(&payload).await.unwrap();
            }
        });

        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let mut inbound = SnellInbound::new(
            "snell-reuse-in",
            SnellInboundOptions {
                listen: ListenOptions {
                    listen: Some(Addr("127.0.0.1".parse().unwrap())),
                    listen_port: 0,
                    ..Default::default()
                },
                version,
                psk: "secretsecret".into(),
                users: vec![SnellUser {
                    name: "alice".into(),
                    userkey: "user-key".into(),
                }],
                mode: mode.into(),
                ..Default::default()
            },
            router,
            outbounds,
        )
        .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let upstream =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let outbound: Arc<dyn Dialer> = if version == 5 {
            Arc::new(
                SnellV4Outbound::new_with_obfs(
                    upstream,
                    inbound.local_addr().unwrap().into(),
                    b"secretsecret".to_vec(),
                    b"user-key".to_vec(),
                    ObfsMode::None,
                    String::new(),
                    true,
                )
                .unwrap(),
            )
        } else {
            Arc::new(
                SnellV6Outbound::new(
                    upstream,
                    inbound.local_addr().unwrap().into(),
                    b"secretsecret".to_vec(),
                    b"user-key".to_vec(),
                    SnellV6Mode::parse(mode).unwrap(),
                    true,
                )
                .unwrap(),
            )
        };
        for index in 0..2_u8 {
            let mut stream =
                outbound.dial_tcp(&target_address.into()).await.unwrap();
            stream.write_all(&[b'0' + index, b'!']).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, [b'0' + index, b'!']);
        }
        echo.await.unwrap();
        inbound.close().await.unwrap();
    }

    #[tokio::test]
    async fn v5_inbound_accepts_two_reused_logical_connections() {
        assert_reused_tcp_sessions(5, "").await;
    }

    #[tokio::test]
    async fn v6_inbound_accepts_two_reused_logical_connections() {
        assert_reused_tcp_sessions(6, "default").await;
    }
}
