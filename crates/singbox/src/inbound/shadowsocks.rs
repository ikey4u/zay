//! Shadowsocks TCP/UDP inbound integrated with native routing.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use bytes::BytesMut;
use shadowsocks::{
    ServerConfig,
    config::{ServerType, ServerUser, ServerUserManager},
    context::Context as ShadowsocksContext,
    crypto::CipherKind,
    net::UdpSocket as ShadowsocksUdpSocket,
    relay::{
        tcprelay::proxy_stream::ProxyServerStream,
        udprelay::{
            ProxySocket,
            crypto_io::{decrypt_client_payload, encrypt_server_payload},
            options::UdpSocketControlData,
            proxy_socket::UdpSocketType,
        },
    },
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Stream,
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        ntp::NtpClock,
    },
    inbound::{
        PacketDestinationNat, TcpInboundContext, TcpInboundInjector,
        TcpInjectFuture, hijack_dns_packet_with_context,
        inherited_tcp_metadata, prepare_tcp_inbound_detour,
        serve_hijacked_dns_stream_with_context, sniff_and_route_packet_session,
        sniff_and_route_stream,
        socks::{proxy_packet_connection, restore_fake_ip},
        with_tcp_inbound_context,
    },
    option::{
        Network as ConfigNetwork, ShadowsocksInboundOptions, ShadowsocksUser,
    },
    outbound::OutboundManager,
    protocol::{
        shadowsocks::{
            from_address, parse_method, server_config,
            shadowsocks_context_with_clock, to_address,
        },
        shadowsocks_aead192::{
            Aes192GcmMethod, LegacyAeadKind, MultiLegacyAeadServer, SALT_LENGTH,
        },
        shadowsocks_relay::ShadowsocksRelayServer,
        uot,
    },
    route::{Action, Metadata, Router},
    service::ssm_api::SsmTrafficManager,
};

#[derive(Clone)]
pub struct ShadowsocksTcpInjector {
    tag: String,
    method: ShadowsocksInboundMethod,
    user_names: Arc<HashMap<Vec<u8>, String>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
    ntp_clock: Option<NtpClock>,
}

impl ShadowsocksTcpInjector {
    pub fn new(
        tag: impl Into<String>,
        options: ShadowsocksInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, ShadowsocksInboundError> {
        Self::new_with_clock(tag, options, router, outbounds, None)
    }

    pub fn new_with_clock(
        tag: impl Into<String>,
        options: ShadowsocksInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        ntp_clock: Option<NtpClock>,
    ) -> Result<Self, ShadowsocksInboundError> {
        let inbound = ShadowsocksInbound::new_with_clock(
            tag, options, router, outbounds, ntp_clock,
        )?;
        let multiplex_brutal = crate::protocol::mux::server_brutal_options(
            inbound
                .options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )
        .map_err(|error| ShadowsocksInboundError::Config(error.to_string()))?;
        Ok(Self {
            tag: inbound.tag,
            method: inbound.method,
            user_names: inbound.user_names,
            router: inbound.router,
            outbounds: inbound.outbounds,
            udp_timeout: udp_timeout(&inbound.options),
            multiplex_enabled: inbound
                .options
                .multiplex
                .as_ref()
                .is_some_and(|multiplex| multiplex.enabled),
            multiplex_padding: inbound.options.multiplex.as_ref().is_some_and(
                |multiplex| multiplex.enabled && multiplex.padding,
            ),
            multiplex_brutal,
            ntp_clock: inbound.ntp_clock,
        })
    }
}

impl TcpInboundInjector for ShadowsocksTcpInjector {
    fn inject<'a>(
        &'a self,
        stream: Stream,
        context: TcpInboundContext,
    ) -> TcpInjectFuture<'a> {
        let source = context.source;
        Box::pin(with_tcp_inbound_context(context, async move {
            handle_tcp_stream(
                stream,
                source,
                &self.tag,
                self.method.clone(),
                self.user_names.clone(),
                self.router.clone(),
                self.outbounds.clone(),
                self.udp_timeout,
                self.multiplex_enabled,
                self.multiplex_padding,
                self.multiplex_brutal,
                self.ntp_clock.clone(),
            )
            .await
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ShadowsocksInboundError {
    #[error("invalid Shadowsocks inbound configuration: {0}")]
    Config(String),
    #[error("unsupported Shadowsocks inbound functionality: {0}")]
    Unsupported(String),
}

pub struct ShadowsocksInbound {
    name: String,
    tag: String,
    options: ShadowsocksInboundOptions,
    method: ShadowsocksInboundMethod,
    user_names: Arc<HashMap<Vec<u8>, String>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
    ntp_clock: Option<NtpClock>,
}

#[derive(Clone)]
enum ShadowsocksInboundMethod {
    Library {
        config: Box<ServerConfig>,
        method: CipherKind,
    },
    Aes192(Aes192GcmMethod),
    LegacyMulti(MultiLegacyAeadServer),
    Relay(ShadowsocksRelayServer),
    Managed(ManagedShadowsocksHandle),
}

#[derive(Clone)]
pub struct ManagedShadowsocksHandle {
    inner: Arc<ManagedShadowsocksInner>,
}

struct ManagedShadowsocksInner {
    method_name: String,
    password: String,
    bind_address: SocksAddr,
    state: RwLock<ManagedShadowsocksState>,
    traffic: RwLock<Option<Arc<SsmTrafficManager>>>,
}

#[derive(Clone)]
struct ManagedShadowsocksState {
    generation: u64,
    method: ManagedShadowsocksMethod,
    user_names: Arc<HashMap<Vec<u8>, String>>,
}

#[derive(Clone)]
enum ManagedShadowsocksMethod {
    Library {
        config: Box<ServerConfig>,
        method: CipherKind,
    },
    Legacy(MultiLegacyAeadServer),
}

impl ManagedShadowsocksHandle {
    fn new(
        method_name: &str,
        password: &str,
        bind_address: SocksAddr,
    ) -> Result<Self, ShadowsocksInboundError> {
        let (method, user_names) = build_managed_method(
            method_name,
            password,
            &bind_address,
            std::iter::empty::<(String, String)>(),
        )?;
        Ok(Self {
            inner: Arc::new(ManagedShadowsocksInner {
                method_name: method_name.to_owned(),
                password: password.to_owned(),
                bind_address,
                state: RwLock::new(ManagedShadowsocksState {
                    generation: 0,
                    method,
                    user_names: Arc::new(user_names),
                }),
                traffic: RwLock::new(None),
            }),
        })
    }

    pub(crate) fn update_users(
        &self,
        users: impl IntoIterator<Item = (String, String)>,
    ) -> io::Result<()> {
        let users = users.into_iter().collect::<Vec<_>>();
        let mut names = std::collections::HashSet::new();
        for (name, _) in &users {
            if !names.insert(name.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("duplicate SSM username {name:?}"),
                ));
            }
        }
        let (method, user_names) = build_managed_method(
            &self.inner.method_name,
            &self.inner.password,
            &self.inner.bind_address,
            users,
        )
        .map_err(io::Error::other)?;
        let mut state = self.inner.state.write().map_err(|_| {
            io::Error::other("managed Shadowsocks state lock poisoned")
        })?;
        state.generation = state.generation.wrapping_add(1);
        state.method = method;
        state.user_names = Arc::new(user_names);
        Ok(())
    }

    pub(crate) fn set_traffic(&self, traffic: Arc<SsmTrafficManager>) {
        *self
            .inner
            .traffic
            .write()
            .expect("managed Shadowsocks traffic lock poisoned") =
            Some(traffic);
    }

    fn snapshot(
        &self,
    ) -> io::Result<(ManagedShadowsocksState, Option<Arc<SsmTrafficManager>>)>
    {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| {
                io::Error::other("managed Shadowsocks state lock poisoned")
            })?
            .clone();
        let traffic = self
            .inner
            .traffic
            .read()
            .map_err(|_| {
                io::Error::other("managed Shadowsocks traffic lock poisoned")
            })?
            .clone();
        Ok((state, traffic))
    }
}

fn build_managed_method(
    method_name: &str,
    password: &str,
    bind_address: &SocksAddr,
    users: impl IntoIterator<Item = (String, String)>,
) -> Result<
    (ManagedShadowsocksMethod, HashMap<Vec<u8>, String>),
    ShadowsocksInboundError,
> {
    let users = users.into_iter().collect::<Vec<_>>();
    if LegacyAeadKind::parse(method_name).is_ok() {
        let method = MultiLegacyAeadServer::new(method_name, users).map_err(
            |error| ShadowsocksInboundError::Config(error.to_string()),
        )?;
        return Ok((ManagedShadowsocksMethod::Legacy(method), HashMap::new()));
    }
    let method = parse_method(method_name)
        .map_err(|error| ShadowsocksInboundError::Config(error.to_string()))?;
    if !matches!(
        method,
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM
            | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
    ) {
        return Err(ShadowsocksInboundError::Unsupported(
            "managed servers support legacy AEAD and AEAD-2022 AES methods only".into(),
        ));
    }
    let mut config = server_config(bind_address, password, method)
        .map_err(|error| ShadowsocksInboundError::Config(error.to_string()))?;
    let option_users = users
        .into_iter()
        .map(|(name, password)| ShadowsocksUser { name, password })
        .collect::<Vec<_>>();
    let names = configure_users(method, &option_users, &mut config)?;
    Ok((
        ManagedShadowsocksMethod::Library {
            config: Box::new(config),
            method,
        },
        names,
    ))
}

impl ShadowsocksInbound {
    pub fn new(
        tag: impl Into<String>,
        options: ShadowsocksInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<Self, ShadowsocksInboundError> {
        Self::new_with_clock(tag, options, router, outbounds, None)
    }

    pub fn new_with_clock(
        tag: impl Into<String>,
        options: ShadowsocksInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        ntp_clock: Option<NtpClock>,
    ) -> Result<Self, ShadowsocksInboundError> {
        if !options.users.is_empty() && !options.destinations.is_empty() {
            return Err(ShadowsocksInboundError::Config(
                "users and destinations options must not be combined".into(),
            ));
        }
        if options.managed
            && (!options.users.is_empty() || !options.destinations.is_empty())
        {
            return Err(ShadowsocksInboundError::Config(
                "users and destinations options are not supported in managed servers"
                    .into(),
            ));
        }
        crate::protocol::mux::server_brutal_options(
            options
                .multiplex
                .as_ref()
                .filter(|multiplex| multiplex.enabled)
                .and_then(|multiplex| multiplex.brutal.as_ref()),
        )
        .map_err(|error| ShadowsocksInboundError::Config(error.to_string()))?;
        let bind_ip = options
            .listen
            .listen
            .map(|value| value.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let bind_address = SocksAddr::from(SocketAddr::new(
            bind_ip,
            options.listen.listen_port,
        ));
        let (method, user_names) = if options.managed {
            (
                ShadowsocksInboundMethod::Managed(
                    ManagedShadowsocksHandle::new(
                        &options.method,
                        &options.password,
                        bind_address.clone(),
                    )?,
                ),
                HashMap::new(),
            )
        } else if !options.destinations.is_empty() {
            let destinations = options.destinations.iter().map(|destination| {
                (
                    destination.name.clone(),
                    destination.password.clone(),
                    SocksAddr::new(
                        destination.server.server.clone(),
                        destination.server.server_port,
                    ),
                )
            });
            (
                ShadowsocksInboundMethod::Relay(
                    ShadowsocksRelayServer::new(
                        &options.method,
                        &options.password,
                        destinations,
                    )
                    .map_err(|error| {
                        ShadowsocksInboundError::Config(error.to_string())
                    })?,
                ),
                HashMap::new(),
            )
        } else if !options.users.is_empty()
            && LegacyAeadKind::parse(&options.method).is_ok()
        {
            let users =
                options.users.iter().enumerate().map(|(index, user)| {
                    let name = if user.name.is_empty() {
                        index.to_string()
                    } else {
                        user.name.clone()
                    };
                    (name, user.password.clone())
                });
            (
                ShadowsocksInboundMethod::LegacyMulti(
                    MultiLegacyAeadServer::new(&options.method, users)
                        .map_err(|error| {
                            ShadowsocksInboundError::Config(error.to_string())
                        })?,
                ),
                HashMap::new(),
            )
        } else if options.method.eq_ignore_ascii_case("aes-192-gcm") {
            (
                ShadowsocksInboundMethod::Aes192(
                    Aes192GcmMethod::new_server(&options.password).map_err(
                        |error| {
                            ShadowsocksInboundError::Config(error.to_string())
                        },
                    )?,
                ),
                HashMap::new(),
            )
        } else {
            let library_method =
                parse_method(&options.method).map_err(|error| {
                    ShadowsocksInboundError::Config(error.to_string())
                })?;
            let supports_eih = matches!(
                library_method,
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM
                    | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
            );
            if !options.users.is_empty() && !supports_eih {
                return Err(ShadowsocksInboundError::Unsupported(
                        "multi-user mode is currently available for AEAD-2022 AES methods only"
                            .into(),
                    ));
            }
            let mut config =
                server_config(&bind_address, &options.password, library_method)
                    .map_err(|error| {
                        ShadowsocksInboundError::Config(error.to_string())
                    })?;
            let user_names =
                configure_users(library_method, &options.users, &mut config)?;
            (
                ShadowsocksInboundMethod::Library {
                    config: Box::new(config),
                    method: library_method,
                },
                user_names,
            )
        };
        let tag = tag.into();
        Ok(Self {
            name: format!("inbound/shadowsocks[{tag}]"),
            tag,
            options,
            method,
            user_names: Arc::new(user_names),
            router,
            outbounds,
            cancellation: CancellationToken::new(),
            tasks: Vec::new(),
            local_addr: None,
            ntp_clock,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn managed_handle(&self) -> Option<ManagedShadowsocksHandle> {
        match &self.method {
            ShadowsocksInboundMethod::Managed(handle) => Some(handle.clone()),
            _ => None,
        }
    }

    async fn bind(&mut self) -> io::Result<()> {
        let ip = self
            .options
            .listen
            .listen
            .map(|value| value.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let networks = self.options.network.build();
        let tcp_enabled = networks.contains(&ConfigNetwork::Tcp);
        let udp_enabled = networks.contains(&ConfigNetwork::Udp);
        let mut port = self.options.listen.listen_port;

        if tcp_enabled {
            let listener = crate::common::socket::bind_tcp_listener(
                SocketAddr::new(ip, port),
                &self.options.listen,
            )
            .await?;
            let address = listener.local_addr()?;
            port = address.port();
            self.local_addr = Some(address);
            self.tasks.push(tokio::spawn(tcp_loop(
                listener,
                self.cancellation.clone(),
                self.tag.clone(),
                self.method.clone(),
                self.user_names.clone(),
                self.router.clone(),
                self.outbounds.clone(),
                udp_timeout(&self.options),
                self.options
                    .multiplex
                    .as_ref()
                    .is_some_and(|multiplex| multiplex.enabled),
                self.options.multiplex.as_ref().is_some_and(|multiplex| {
                    multiplex.enabled && multiplex.padding
                }),
                crate::protocol::mux::server_brutal_options(
                    self.options
                        .multiplex
                        .as_ref()
                        .filter(|multiplex| multiplex.enabled)
                        .and_then(|multiplex| multiplex.brutal.as_ref()),
                )?,
                self.ntp_clock.clone(),
            )));
        }
        if udp_enabled {
            let socket = UdpSocket::bind(SocketAddr::new(ip, port)).await?;
            let address = socket.local_addr()?;
            self.local_addr.get_or_insert(address);
            self.tasks.push(tokio::spawn(udp_loop(
                socket,
                self.cancellation.clone(),
                self.tag.clone(),
                self.method.clone(),
                self.user_names.clone(),
                self.router.clone(),
                self.outbounds.clone(),
                udp_timeout(&self.options),
                self.ntp_clock.clone(),
            )));
        }
        Ok(())
    }
}

impl Lifecycle for ShadowsocksInbound {
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

fn configure_users(
    method: CipherKind,
    users: &[ShadowsocksUser],
    config: &mut ServerConfig,
) -> Result<HashMap<Vec<u8>, String>, ShadowsocksInboundError> {
    let mut names = HashMap::new();
    if users.is_empty() {
        return Ok(names);
    }
    let mut manager = ServerUserManager::new();
    for (index, user) in users.iter().enumerate() {
        let server_user = ServerUser::with_encoded_key(
            if user.name.is_empty() {
                index.to_string()
            } else {
                user.name.clone()
            },
            &user.password,
        )
        .map_err(|error| ShadowsocksInboundError::Config(error.to_string()))?;
        if server_user.key().len() != method.key_len() {
            return Err(ShadowsocksInboundError::Config(format!(
                "invalid user key length for {method}: expected {}, got {}",
                method.key_len(),
                server_user.key().len()
            )));
        }
        let identity = server_user.key().to_vec();
        if names
            .insert(identity, server_user.name().to_owned())
            .is_some()
        {
            return Err(ShadowsocksInboundError::Config(
                "duplicate Shadowsocks user key".into(),
            ));
        }
        manager.add_user(server_user);
    }
    config.set_user_manager(manager);
    Ok(names)
}

fn udp_timeout(options: &ShadowsocksInboundOptions) -> std::time::Duration {
    options
        .listen
        .udp_timeout
        .0
        .as_std()
        .filter(|value| !value.is_zero())
        .unwrap_or(crate::constant::UDP_TIMEOUT)
}

#[allow(clippy::too_many_arguments)]
async fn tcp_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    method: ShadowsocksInboundMethod,
    user_names: Arc<HashMap<Vec<u8>, String>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
    ntp_clock: Option<NtpClock>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept() => {
                let (stream, source) = result?;
                let method = method.clone();
                let tag = tag.clone(); let user_names = user_names.clone();
                let router = router.clone(); let outbounds = outbounds.clone();
                let ntp_clock = ntp_clock.clone();
                connections.spawn(async move {
                    let socket = crate::adapter::tcp_stream_socket(&stream);
                    let stream = crate::adapter::preserve_stream_socket(
                        Box::new(stream),
                        socket,
                    );
                    handle_tcp_stream(
                        stream, source, &tag, method, user_names,
                        router, outbounds, udp_timeout, multiplex_enabled,
                        multiplex_padding,
                        multiplex_brutal,
                        ntp_clock,
                    ).await
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
async fn handle_tcp_stream(
    stream: Stream,
    source: SocketAddr,
    tag: &str,
    method: ShadowsocksInboundMethod,
    user_names: Arc<HashMap<Vec<u8>, String>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    multiplex_enabled: bool,
    multiplex_padding: bool,
    multiplex_brutal: Option<crate::protocol::mux::BrutalRuntimeOptions>,
    ntp_clock: Option<NtpClock>,
) -> io::Result<()> {
    let socket = crate::adapter::stream_socket(&stream);
    let (method, user_names, traffic) = match method {
        ShadowsocksInboundMethod::Managed(handle) => {
            let (state, traffic) = handle.snapshot()?;
            let method = match state.method {
                ManagedShadowsocksMethod::Library { config, method } => {
                    ShadowsocksInboundMethod::Library { config, method }
                }
                ManagedShadowsocksMethod::Legacy(method) => {
                    ShadowsocksInboundMethod::LegacyMulti(method)
                }
            };
            (method, state.user_names, traffic)
        }
        method => (method, user_names, None),
    };
    let (mut client, destination, user): (Stream, SocksAddr, Option<String>) =
        match method {
            ShadowsocksInboundMethod::Library { config, method } => {
                let context = shadowsocks_context_with_clock(
                    ServerType::Server,
                    ntp_clock,
                );
                let mut client =
                    ProxyServerStream::from_stream_with_user_manager(
                        context,
                        stream,
                        method,
                        config.key(),
                        config.clone_user_manager(),
                    );
                let destination = from_address(client.handshake().await?);
                let user = authenticated_user(client.user_key(), &user_names)?;
                (Box::new(client), destination, user)
            }
            ShadowsocksInboundMethod::Aes192(method) => {
                let (destination, client) =
                    method.accept_stream(stream).await?;
                (client, destination, None)
            }
            ShadowsocksInboundMethod::LegacyMulti(method) => {
                let (user, destination, client) =
                    method.accept_stream(stream).await?;
                (client, destination, Some(user))
            }
            ShadowsocksInboundMethod::Relay(method) => {
                let (user, destination, client) =
                    method.accept_stream(stream).await?;
                (client, destination, Some(user))
            }
            ShadowsocksInboundMethod::Managed(_) => unreachable!(),
        };
    if let (Some(traffic), Some(user)) = (traffic, user.as_deref()) {
        client = traffic.track_tcp(client, user);
    }
    if let Some(version) = uot::destination_version(&destination) {
        let packet = uot::accept(Box::new(client), version).await?;
        return proxy_packet_connection(
            Box::new(packet),
            source,
            tag,
            user,
            &router,
            &outbounds,
            udp_timeout,
        )
        .await;
    }
    if multiplex_enabled && crate::protocol::mux::is_destination(&destination) {
        let client = crate::adapter::preserve_stream_socket(client, socket);
        return crate::protocol::mux::serve_routed_h2mux(
            client,
            source,
            tag.to_owned(),
            user.unwrap_or_default(),
            router,
            outbounds,
            udp_timeout,
            multiplex_padding,
            multiplex_brutal,
        )
        .await;
    }
    proxy_tcp(client, source, tag, destination, user, &router, &outbounds).await
}

fn authenticated_user(
    key: Option<&[u8]>,
    names: &HashMap<Vec<u8>, String>,
) -> io::Result<Option<String>> {
    if names.is_empty() {
        return Ok(None);
    }
    let key = key.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "missing Shadowsocks user identity",
        )
    })?;
    names.get(key).cloned().map(Some).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown Shadowsocks user key",
        )
    })
}

#[allow(clippy::too_many_arguments)]
async fn proxy_tcp<S>(
    client: S,
    source: SocketAddr,
    tag: &str,
    destination: SocksAddr,
    user: Option<String>,
    router: &Router,
    outbounds: &OutboundManager,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (destination, origin_destination) =
        restore_fake_ip(destination, outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(source.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Tcp),
        user: user.unwrap_or_default(),
        ..inherited_tcp_metadata(source, tag)
    };
    if let Some(injector) =
        prepare_tcp_inbound_detour(&mut metadata, outbounds)?
    {
        return injector
            .inject(Box::new(client), TcpInboundContext { source, metadata })
            .await;
    }
    let (mut client, decision) = sniff_and_route_stream(
        Box::new(client),
        &mut metadata,
        router,
        outbounds,
    )
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

#[allow(clippy::too_many_arguments)]
async fn udp_loop(
    socket: UdpSocket,
    cancellation: CancellationToken,
    tag: String,
    method: ShadowsocksInboundMethod,
    user_names: Arc<HashMap<Vec<u8>, String>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    ntp_clock: Option<NtpClock>,
) -> io::Result<()> {
    match method {
        ShadowsocksInboundMethod::Library { config, .. } => {
            udp_loop_library(
                socket,
                cancellation,
                tag,
                *config,
                user_names,
                router,
                outbounds,
                udp_timeout,
                ntp_clock,
            )
            .await
        }
        ShadowsocksInboundMethod::Aes192(method) => {
            udp_loop_aes192(
                socket,
                cancellation,
                tag,
                method,
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }
        ShadowsocksInboundMethod::LegacyMulti(method) => {
            udp_loop_legacy_multi(
                socket,
                cancellation,
                tag,
                method,
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }
        ShadowsocksInboundMethod::Relay(method) => {
            udp_loop_relay(
                socket,
                cancellation,
                tag,
                method,
                router,
                outbounds,
                udp_timeout,
            )
            .await
        }
        ShadowsocksInboundMethod::Managed(handle) => {
            udp_loop_managed(
                socket,
                cancellation,
                tag,
                handle,
                router,
                outbounds,
                udp_timeout,
                ntp_clock,
            )
            .await
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ManagedUdpSessionKey {
    Legacy(SocketAddr, u64, usize),
    Aead2022(SocketAddr, u64, Vec<u8>),
}

#[derive(Clone)]
enum ManagedUdpCipher {
    Legacy {
        method: MultiLegacyAeadServer,
        user_index: usize,
    },
    Aead2022 {
        context: Arc<ShadowsocksContext>,
        method: CipherKind,
        server_key: Vec<u8>,
    },
}

struct ManagedUdpPacket {
    data: Vec<u8>,
    original_destination: SocksAddr,
    user: String,
    control: UdpSocketControlData,
}

#[allow(clippy::too_many_arguments)]
async fn udp_loop_managed(
    socket: UdpSocket,
    cancellation: CancellationToken,
    tag: String,
    handle: ManagedShadowsocksHandle,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    ntp_clock: Option<NtpClock>,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let context = shadowsocks_context_with_clock(ServerType::Server, ntp_clock);
    let mut packet = vec![0_u8; 65_535];
    let mut sessions =
        HashMap::<ManagedUdpSessionKey, mpsc::Sender<ManagedUdpPacket>>::new();
    let (closed_sender, mut closed_receiver) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = socket.recv_from(&mut packet) => Some(result?),
            Some(key) = closed_receiver.recv() => {
                if sessions.get(&key).is_some_and(|sender| sender.is_closed()) {
                    sessions.remove(&key);
                }
                None
            }
        };
        let Some((size, client)) = received else {
            continue;
        };
        let (state, traffic) = handle.snapshot()?;
        let decoded = match state.method {
            ManagedShadowsocksMethod::Legacy(method) => {
                let Ok((user_index, user, destination, data)) =
                    method.open_packet(&packet[..size])
                else {
                    continue;
                };
                (
                    ManagedUdpSessionKey::Legacy(
                        client,
                        state.generation,
                        user_index,
                    ),
                    ManagedUdpCipher::Legacy { method, user_index },
                    ManagedUdpPacket {
                        data,
                        original_destination: destination,
                        user,
                        control: UdpSocketControlData::default(),
                    },
                )
            }
            ManagedShadowsocksMethod::Library { config, method } => {
                let mut decrypted = packet[..size].to_vec();
                let Ok((plain_size, destination, control)) =
                    decrypt_client_payload(
                        &context,
                        method,
                        config.key(),
                        &mut decrypted,
                        config.user_manager(),
                    )
                else {
                    continue;
                };
                let Some(control) = control else { continue };
                let Some(user) = control.user.as_ref() else {
                    continue;
                };
                let user_name = state
                    .user_names
                    .get(user.key())
                    .cloned()
                    .unwrap_or_else(|| user.name().to_owned());
                let identity = user.key().to_vec();
                (
                    ManagedUdpSessionKey::Aead2022(
                        client,
                        control.client_session_id,
                        identity,
                    ),
                    ManagedUdpCipher::Aead2022 {
                        context: context.clone(),
                        method,
                        server_key: config.key().to_vec(),
                    },
                    ManagedUdpPacket {
                        data: decrypted[..plain_size].to_vec(),
                        original_destination: from_address(destination),
                        user: user_name,
                        control,
                    },
                )
            }
        };
        let (key, cipher, message) = decoded;
        if sessions.get(&key).is_none_or(|sender| sender.is_closed()) {
            sessions.remove(&key);
            let (sender, receiver) = mpsc::channel(64);
            sessions.insert(key.clone(), sender);
            if let Some(traffic) = &traffic {
                traffic.record_udp_session(&message.user);
            }
            let socket = socket.clone();
            let tag = tag.clone();
            let router = router.clone();
            let outbounds = outbounds.clone();
            let closed_sender = closed_sender.clone();
            let closed_key = key.clone();
            let traffic = traffic.clone();
            tasks.spawn(async move {
                let _ = proxy_udp_session_managed(
                    socket,
                    cipher,
                    receiver,
                    client,
                    &tag,
                    &router,
                    &outbounds,
                    udp_timeout,
                    traffic,
                )
                .await;
                let _ = closed_sender.send(closed_key);
            });
        }
        let _ = sessions
            .get(&key)
            .expect("managed Shadowsocks UDP session inserted")
            .try_send(message);
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn proxy_udp_session_managed(
    socket: Arc<UdpSocket>,
    cipher: ManagedUdpCipher,
    mut receiver: mpsc::Receiver<ManagedUdpPacket>,
    client: SocketAddr,
    tag: &str,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
    traffic: Option<Arc<SsmTrafficManager>>,
) -> io::Result<()> {
    let first = timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "managed Shadowsocks UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "managed Shadowsocks UDP session closed",
            )
        })?;
    let username = first.user.clone();
    let (destination, origin_destination) =
        restore_fake_ip(first.original_destination.clone(), outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(client.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Udp),
        user: username.clone(),
        ..Metadata::default()
    };
    let mut response_control = first.control.clone();
    let (decision, mut pending) = sniff_and_route_packet_session(
        first,
        &mut receiver,
        |packet: &ManagedUdpPacket| packet.data.as_slice(),
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Ok(());
    }
    if response_control.client_session_id != 0 {
        let mut session_id = [0_u8; 8];
        getrandom::fill(&mut session_id).map_err(io::Error::other)?;
        response_control.server_session_id = u64::from_be_bytes(session_id);
        response_control.packet_id = 0;
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        loop {
            let message = match pending.pop_front() {
                Some(message) => message,
                None => {
                    receive_managed_udp_packet(&mut receiver, udp_timeout)
                        .await?
                }
            };
            if let Some(traffic) = &traffic {
                traffic.record_udp_uplink(&username, message.data.len());
            }
            let response = hijack_dns_packet_with_context(
                &message.data,
                outbounds,
                &metadata,
            )
            .await?;
            update_response_control(&mut response_control, &message.control);
            advance_response_packet_id(&mut response_control);
            send_managed_udp(
                &socket,
                &cipher,
                client,
                &message.original_destination,
                &response_control,
                &response,
            )
            .await?;
            if let Some(traffic) = &traffic {
                traffic.record_udp_downlink(&username, response.len());
            }
        }
    }

    let routed_destination = decision.destination(&destination);
    let mut destination_nat =
        PacketDestinationNat::new(destination.clone(), routed_destination);
    let connection_options = decision.connection_options();
    let udp_timeout = connection_options.udp_timeout.unwrap_or(udp_timeout);
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let outgoing = dialer
        .listen_udp_with_options(
            destination_nat.route_destination(),
            &connection_options.network,
        )
        .await?;
    let mut response = vec![0_u8; 65_535];
    loop {
        if let Some(message) = pending.pop_front() {
            let (destination, _origin_destination) = restore_fake_ip(
                message.original_destination.clone(),
                outbounds,
            )?;
            let routed = destination_nat.translate_destination(
                destination,
                message.original_destination.clone(),
            );
            update_response_control(&mut response_control, &message.control);
            outgoing.send_to(&message.data, &routed).await?;
            if let Some(traffic) = &traffic {
                traffic.record_udp_uplink(&username, message.data.len());
            }
        }
        enum Event {
            Incoming(Option<ManagedUdpPacket>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                message = receiver.recv() => Event::Incoming(message),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "managed Shadowsocks UDP session timed out"))?;
        match event {
            Event::Incoming(Some(message)) => pending.push_back(message),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (response_size, source) = result?;
                advance_response_packet_id(&mut response_control);
                let response_source = destination_nat.translate_source(source);
                send_managed_udp(
                    &socket,
                    &cipher,
                    client,
                    &response_source,
                    &response_control,
                    &response[..response_size],
                )
                .await?;
                if let Some(traffic) = &traffic {
                    traffic.record_udp_downlink(&username, response_size);
                }
            }
        }
    }
}

async fn receive_managed_udp_packet(
    receiver: &mut mpsc::Receiver<ManagedUdpPacket>,
    udp_timeout: std::time::Duration,
) -> io::Result<ManagedUdpPacket> {
    timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "managed Shadowsocks UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "managed Shadowsocks UDP session closed",
            )
        })
}

async fn send_managed_udp(
    socket: &UdpSocket,
    cipher: &ManagedUdpCipher,
    client: SocketAddr,
    source: &SocksAddr,
    control: &UdpSocketControlData,
    payload: &[u8],
) -> io::Result<()> {
    let packet = match cipher {
        ManagedUdpCipher::Legacy { method, user_index } => {
            method.seal_packet(*user_index, source, payload)?
        }
        ManagedUdpCipher::Aead2022 {
            context,
            method,
            server_key,
        } => {
            let key = control
                .user
                .as_ref()
                .map_or(server_key.as_slice(), |user| user.key());
            let mut output = BytesMut::new();
            encrypt_server_payload(
                context,
                *method,
                key,
                &to_address(source),
                control,
                payload,
                &mut output,
            );
            output.to_vec()
        }
    };
    socket.send_to(&packet, client).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn udp_loop_library(
    socket: UdpSocket,
    cancellation: CancellationToken,
    tag: String,
    config: ServerConfig,
    _user_names: Arc<HashMap<Vec<u8>, String>>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
    ntp_clock: Option<NtpClock>,
) -> io::Result<()> {
    let context = shadowsocks_context_with_clock(ServerType::Server, ntp_clock);
    let socket = Arc::new(ProxySocket::from_socket(
        UdpSocketType::Server,
        context,
        &config,
        ShadowsocksUdpSocket::from(socket),
    ));
    let mut packet = vec![0_u8; 65_535];
    let mut sessions =
        HashMap::<(SocketAddr, u64, Vec<u8>), mpsc::Sender<SsUdpPacket>>::new();
    let (closed_sender, mut closed_receiver) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = socket.recv_from_with_ctrl(&mut packet) => result,
            Some(key) = closed_receiver.recv() => {
                if sessions.get(&key).is_some_and(|sender| sender.is_closed()) {
                    sessions.remove(&key);
                }
                continue;
            }
        };
        let Ok((size, client, original_destination, _, control)) = received
        else {
            continue;
        };
        let original_destination = from_address(original_destination);
        let control = control.unwrap_or_default();
        let identity = control
            .user
            .as_ref()
            .map(|user| user.key().to_vec())
            .unwrap_or_default();
        let key = (client, control.client_session_id, identity);
        if sessions.get(&key).is_none_or(|sender| sender.is_closed()) {
            sessions.remove(&key);
            let (sender, receiver) = mpsc::channel(64);
            sessions.insert(key.clone(), sender);
            let socket = socket.clone();
            let tag = tag.clone();
            let router = router.clone();
            let outbounds = outbounds.clone();
            let closed_sender = closed_sender.clone();
            let closed_key = key.clone();
            tasks.spawn(async move {
                let result = proxy_udp_session(
                    socket,
                    receiver,
                    client,
                    &tag,
                    &router,
                    &outbounds,
                    udp_timeout,
                )
                .await;
                let _ = closed_sender.send(closed_key);
                let _ = result;
            });
        }
        let message = SsUdpPacket {
            data: packet[..size].to_vec(),
            original_destination,
            control,
        };
        let _ = sessions
            .get(&key)
            .expect("Shadowsocks UDP session inserted")
            .try_send(message);
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[derive(Clone)]
struct Aes192UdpPacket {
    data: Vec<u8>,
    original_destination: SocksAddr,
}

#[allow(clippy::too_many_arguments)]
async fn udp_loop_aes192(
    socket: UdpSocket,
    cancellation: CancellationToken,
    tag: String,
    method: Aes192GcmMethod,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut packet = vec![0_u8; 65_535];
    let mut sessions =
        HashMap::<SocketAddr, mpsc::Sender<Aes192UdpPacket>>::new();
    let (closed_sender, mut closed_receiver) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = socket.recv_from(&mut packet) => Some(result?),
            Some(client) = closed_receiver.recv() => {
                if sessions.get(&client).is_some_and(|sender| sender.is_closed()) {
                    sessions.remove(&client);
                }
                None
            }
        };
        let Some((size, client)) = received else {
            continue;
        };
        if size < SALT_LENGTH {
            continue;
        }
        let Ok((original_destination, data)) =
            method.open_packet(&packet[..size])
        else {
            continue;
        };
        if sessions
            .get(&client)
            .is_none_or(|sender| sender.is_closed())
        {
            sessions.remove(&client);
            let (sender, receiver) = mpsc::channel(64);
            sessions.insert(client, sender);
            let socket = socket.clone();
            let method = method.clone();
            let tag = tag.clone();
            let router = router.clone();
            let outbounds = outbounds.clone();
            let closed_sender = closed_sender.clone();
            tasks.spawn(async move {
                let _ = proxy_udp_session_aes192(
                    socket,
                    method,
                    receiver,
                    client,
                    &tag,
                    &router,
                    &outbounds,
                    udp_timeout,
                )
                .await;
                let _ = closed_sender.send(client);
            });
        }
        let _ = sessions
            .get(&client)
            .expect("AES-192-GCM UDP session inserted")
            .try_send(Aes192UdpPacket {
                data,
                original_destination,
            });
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn proxy_udp_session_aes192(
    socket: Arc<UdpSocket>,
    method: Aes192GcmMethod,
    mut receiver: mpsc::Receiver<Aes192UdpPacket>,
    client: SocketAddr,
    tag: &str,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let first = receive_aes192_udp_packet(&mut receiver, udp_timeout).await?;
    let (destination, origin_destination) =
        restore_fake_ip(first.original_destination.clone(), outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(client.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Udp),
        ..Metadata::default()
    };
    let (decision, mut pending) = sniff_and_route_packet_session(
        first,
        &mut receiver,
        |packet: &Aes192UdpPacket| packet.data.as_slice(),
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Ok(());
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        loop {
            let message = match pending.pop_front() {
                Some(message) => message,
                None => {
                    receive_aes192_udp_packet(&mut receiver, udp_timeout)
                        .await?
                }
            };
            let response = hijack_dns_packet_with_context(
                &message.data,
                outbounds,
                &metadata,
            )
            .await?;
            send_aes192_udp(
                &socket,
                &method,
                client,
                &message.original_destination,
                &response,
            )
            .await?;
        }
    }

    let routed_destination = decision.destination(&destination);
    let mut destination_nat =
        PacketDestinationNat::new(destination.clone(), routed_destination);
    let connection_options = decision.connection_options();
    let udp_timeout = connection_options.udp_timeout.unwrap_or(udp_timeout);
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let outgoing = dialer
        .listen_udp_with_options(
            destination_nat.route_destination(),
            &connection_options.network,
        )
        .await?;
    let mut response = vec![0_u8; 65_535];
    loop {
        if let Some(message) = pending.pop_front() {
            let (destination, _origin_destination) = restore_fake_ip(
                message.original_destination.clone(),
                outbounds,
            )?;
            let routed = destination_nat.translate_destination(
                destination,
                message.original_destination.clone(),
            );
            outgoing.send_to(&message.data, &routed).await?;
        }
        enum Event {
            Incoming(Option<Aes192UdpPacket>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                message = receiver.recv() => Event::Incoming(message),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(Some(message)) => pending.push_back(message),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (response_size, source) = result?;
                let response_source = destination_nat.translate_source(source);
                send_aes192_udp(
                    &socket,
                    &method,
                    client,
                    &response_source,
                    &response[..response_size],
                )
                .await?;
            }
        }
    }
}

async fn receive_aes192_udp_packet(
    receiver: &mut mpsc::Receiver<Aes192UdpPacket>,
    udp_timeout: std::time::Duration,
) -> io::Result<Aes192UdpPacket> {
    timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Shadowsocks UDP session closed",
            )
        })
}

async fn send_aes192_udp(
    socket: &UdpSocket,
    method: &Aes192GcmMethod,
    client: SocketAddr,
    source: &SocksAddr,
    payload: &[u8],
) -> io::Result<()> {
    let mut salt = [0_u8; SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    let packet = method.seal_packet(&salt, source, payload)?;
    socket.send_to(&packet, client).await?;
    Ok(())
}

#[derive(Clone)]
struct LegacyMultiUdpPacket {
    data: Vec<u8>,
    original_destination: SocksAddr,
    user: String,
}

#[allow(clippy::too_many_arguments)]
async fn udp_loop_legacy_multi(
    socket: UdpSocket,
    cancellation: CancellationToken,
    tag: String,
    method: MultiLegacyAeadServer,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut packet = vec![0_u8; 65_535];
    let mut sessions = HashMap::<
        (SocketAddr, usize),
        mpsc::Sender<LegacyMultiUdpPacket>,
    >::new();
    let (closed_sender, mut closed_receiver) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = socket.recv_from(&mut packet) => Some(result?),
            Some(key) = closed_receiver.recv() => {
                if sessions.get(&key).is_some_and(|sender| sender.is_closed()) {
                    sessions.remove(&key);
                }
                None
            }
        };
        let Some((size, client)) = received else {
            continue;
        };
        let Ok((user_index, user, original_destination, data)) =
            method.open_packet(&packet[..size])
        else {
            continue;
        };
        let key = (client, user_index);
        if sessions.get(&key).is_none_or(|sender| sender.is_closed()) {
            sessions.remove(&key);
            let (sender, receiver) = mpsc::channel(64);
            sessions.insert(key, sender);
            let socket = socket.clone();
            let method = method.clone();
            let tag = tag.clone();
            let router = router.clone();
            let outbounds = outbounds.clone();
            let closed_sender = closed_sender.clone();
            tasks.spawn(async move {
                let _ = proxy_udp_session_legacy_multi(
                    socket,
                    method,
                    receiver,
                    client,
                    user_index,
                    &tag,
                    &router,
                    &outbounds,
                    udp_timeout,
                )
                .await;
                let _ = closed_sender.send(key);
            });
        }
        let _ = sessions
            .get(&key)
            .expect("legacy AEAD multi-user UDP session inserted")
            .try_send(LegacyMultiUdpPacket {
                data,
                original_destination,
                user,
            });
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn proxy_udp_session_legacy_multi(
    socket: Arc<UdpSocket>,
    method: MultiLegacyAeadServer,
    mut receiver: mpsc::Receiver<LegacyMultiUdpPacket>,
    client: SocketAddr,
    user_index: usize,
    tag: &str,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let first =
        receive_legacy_multi_udp_packet(&mut receiver, udp_timeout).await?;
    let (destination, origin_destination) =
        restore_fake_ip(first.original_destination.clone(), outbounds)?;
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(client.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Udp),
        user: first.user.clone(),
        ..Metadata::default()
    };
    let (decision, mut pending) = sniff_and_route_packet_session(
        first,
        &mut receiver,
        |packet: &LegacyMultiUdpPacket| packet.data.as_slice(),
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Ok(());
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        loop {
            let message = match pending.pop_front() {
                Some(message) => message,
                None => {
                    receive_legacy_multi_udp_packet(&mut receiver, udp_timeout)
                        .await?
                }
            };
            let response = hijack_dns_packet_with_context(
                &message.data,
                outbounds,
                &metadata,
            )
            .await?;
            send_legacy_multi_udp(
                &socket,
                &method,
                client,
                user_index,
                &message.original_destination,
                &response,
            )
            .await?;
        }
    }

    let routed_destination = decision.destination(&destination);
    let mut destination_nat =
        PacketDestinationNat::new(destination.clone(), routed_destination);
    let connection_options = decision.connection_options();
    let udp_timeout = connection_options.udp_timeout.unwrap_or(udp_timeout);
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let outgoing = dialer
        .listen_udp_with_options(
            destination_nat.route_destination(),
            &connection_options.network,
        )
        .await?;
    let mut response = vec![0_u8; 65_535];
    loop {
        if let Some(message) = pending.pop_front() {
            let (destination, _origin_destination) = restore_fake_ip(
                message.original_destination.clone(),
                outbounds,
            )?;
            let routed = destination_nat.translate_destination(
                destination,
                message.original_destination.clone(),
            );
            outgoing.send_to(&message.data, &routed).await?;
        }
        enum Event {
            Incoming(Option<LegacyMultiUdpPacket>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                message = receiver.recv() => Event::Incoming(message),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(Some(message)) => pending.push_back(message),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (response_size, source) = result?;
                let response_source = destination_nat.translate_source(source);
                send_legacy_multi_udp(
                    &socket,
                    &method,
                    client,
                    user_index,
                    &response_source,
                    &response[..response_size],
                )
                .await?;
            }
        }
    }
}

async fn receive_legacy_multi_udp_packet(
    receiver: &mut mpsc::Receiver<LegacyMultiUdpPacket>,
    udp_timeout: std::time::Duration,
) -> io::Result<LegacyMultiUdpPacket> {
    timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Shadowsocks UDP session closed",
            )
        })
}

async fn send_legacy_multi_udp(
    socket: &UdpSocket,
    method: &MultiLegacyAeadServer,
    client: SocketAddr,
    user_index: usize,
    source: &SocksAddr,
    payload: &[u8],
) -> io::Result<()> {
    let packet = method.seal_packet(user_index, source, payload)?;
    socket.send_to(&packet, client).await?;
    Ok(())
}

#[derive(Clone)]
struct RelayUdpPacket {
    payload: Vec<u8>,
    destination: SocksAddr,
    user: String,
}

#[allow(clippy::too_many_arguments)]
async fn udp_loop_relay(
    socket: UdpSocket,
    cancellation: CancellationToken,
    tag: String,
    method: ShadowsocksRelayServer,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut packet = vec![0_u8; 65_535];
    let mut sessions =
        HashMap::<(SocketAddr, u64, usize), mpsc::Sender<RelayUdpPacket>>::new(
        );
    let (closed_sender, mut closed_receiver) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = socket.recv_from(&mut packet) => Some(result?),
            Some(key) = closed_receiver.recv() => {
                if sessions.get(&key).is_some_and(|sender| sender.is_closed()) {
                    sessions.remove(&key);
                }
                None
            }
        };
        let Some((size, client)) = received else {
            continue;
        };
        let Ok(relayed) = method.transform_packet(&packet[..size]) else {
            continue;
        };
        let key = (client, relayed.session_id, relayed.user_index);
        if sessions.get(&key).is_none_or(|sender| sender.is_closed()) {
            sessions.remove(&key);
            let (sender, receiver) = mpsc::channel(64);
            sessions.insert(key, sender);
            let socket = socket.clone();
            let tag = tag.clone();
            let router = router.clone();
            let outbounds = outbounds.clone();
            let closed_sender = closed_sender.clone();
            tasks.spawn(async move {
                let _ = proxy_udp_session_relay(
                    socket,
                    receiver,
                    client,
                    &tag,
                    &router,
                    &outbounds,
                    udp_timeout,
                )
                .await;
                let _ = closed_sender.send(key);
            });
        }
        let _ = sessions
            .get(&key)
            .expect("Shadowsocks relay UDP session inserted")
            .try_send(RelayUdpPacket {
                payload: relayed.payload,
                destination: relayed.destination,
                user: relayed.user,
            });
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn proxy_udp_session_relay(
    socket: Arc<UdpSocket>,
    mut receiver: mpsc::Receiver<RelayUdpPacket>,
    client: SocketAddr,
    tag: &str,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let first = timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks relay UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Shadowsocks relay UDP session closed",
            )
        })?;
    let initial_destination = first.destination.clone();
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(client.into()),
        destination: Some(initial_destination.clone()),
        network: Some(Network::Udp),
        user: first.user.clone(),
        ..Metadata::default()
    };
    let (decision, mut pending) = sniff_and_route_packet_session(
        first,
        &mut receiver,
        |packet: &RelayUdpPacket| packet.payload.as_slice(),
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(
        decision.action(),
        Some(Action::Reject { .. } | Action::HijackDns)
    ) {
        return Ok(());
    }
    let route_original = metadata
        .destination
        .as_ref()
        .unwrap_or(&initial_destination);
    let destination = decision.destination(route_original);
    let connection_options = decision.connection_options();
    let udp_timeout = connection_options.udp_timeout.unwrap_or(udp_timeout);
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let outgoing = dialer
        .listen_udp_with_options(&destination, &connection_options.network)
        .await?;
    let mut response = vec![0_u8; 65_535];
    loop {
        if let Some(message) = pending.pop_front() {
            outgoing.send_to(&message.payload, &destination).await?;
        }
        enum Event {
            Incoming(Option<RelayUdpPacket>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                message = receiver.recv() => Event::Incoming(message),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks relay UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(Some(message)) => pending.push_back(message),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (size, _) = result?;
                socket.send_to(&response[..size], client).await?;
            }
        }
    }
}

struct SsUdpPacket {
    data: Vec<u8>,
    original_destination: SocksAddr,
    control: UdpSocketControlData,
}

#[allow(clippy::too_many_arguments)]
async fn proxy_udp_session(
    socket: Arc<ProxySocket<ShadowsocksUdpSocket>>,
    mut receiver: mpsc::Receiver<SsUdpPacket>,
    client: SocketAddr,
    tag: &str,
    router: &Router,
    outbounds: &OutboundManager,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let first = timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Shadowsocks UDP session closed",
            )
        })?;
    let (destination, origin_destination) =
        restore_fake_ip(first.original_destination.clone(), outbounds)?;
    let user = first
        .control
        .user
        .as_ref()
        .map(|value| value.name().to_owned())
        .unwrap_or_default();
    let mut metadata = Metadata {
        inbound: tag.to_owned(),
        source: Some(client.into()),
        destination: Some(destination.clone()),
        origin_destination: origin_destination.clone(),
        fake_ip: origin_destination.is_some(),
        network: Some(Network::Udp),
        user,
        ..Metadata::default()
    };
    let mut response_control = first.control.clone();
    let (decision, mut pending) = sniff_and_route_packet_session(
        first,
        &mut receiver,
        |packet: &SsUdpPacket| packet.data.as_slice(),
        &mut metadata,
        router,
        outbounds,
    )
    .await?;
    if matches!(decision.action(), Some(Action::Reject { .. })) {
        return Ok(());
    }

    if response_control.client_session_id != 0 {
        let mut session_id = [0_u8; 8];
        getrandom::fill(&mut session_id).map_err(io::Error::other)?;
        response_control.server_session_id = u64::from_be_bytes(session_id);
        response_control.packet_id = 0;
    }
    if matches!(decision.action(), Some(Action::HijackDns)) {
        loop {
            let message = match pending.pop_front() {
                Some(message) => message,
                None => {
                    receive_ss_udp_packet(&mut receiver, udp_timeout).await?
                }
            };
            let response = hijack_dns_packet_with_context(
                &message.data,
                outbounds,
                &metadata,
            )
            .await?;
            update_response_control(&mut response_control, &message.control);
            advance_response_packet_id(&mut response_control);
            socket
                .send_to_with_ctrl(
                    client,
                    &to_address(&message.original_destination),
                    &response_control,
                    &response,
                )
                .await
                .map_err(io::Error::from)?;
        }
    }

    let routed_destination = decision.destination(&destination);
    let mut destination_nat =
        PacketDestinationNat::new(destination.clone(), routed_destination);
    let connection_options = decision.connection_options();
    let udp_timeout = connection_options.udp_timeout.unwrap_or(udp_timeout);
    let dialer = if matches!(decision.action(), Some(Action::Direct)) {
        outbounds.direct()
    } else {
        outbounds.select(decision.outbound()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "route outbound not found")
        })?
    };
    let outgoing = dialer
        .listen_udp_with_options(
            destination_nat.route_destination(),
            &connection_options.network,
        )
        .await?;
    let mut response = vec![0_u8; 65_535];
    loop {
        if let Some(message) = pending.pop_front() {
            let (destination, _origin_destination) = restore_fake_ip(
                message.original_destination.clone(),
                outbounds,
            )?;
            let routed = destination_nat.translate_destination(
                destination,
                message.original_destination.clone(),
            );
            update_response_control(&mut response_control, &message.control);
            outgoing.send_to(&message.data, &routed).await?;
        }
        enum Event {
            Incoming(Option<SsUdpPacket>),
            Response(io::Result<(usize, SocksAddr)>),
        }
        let event = timeout(udp_timeout, async {
            tokio::select! {
                message = receiver.recv() => Event::Incoming(message),
                result = outgoing.recv_from(&mut response) => Event::Response(result),
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks UDP session timed out",
            )
        })?;
        match event {
            Event::Incoming(Some(message)) => pending.push_back(message),
            Event::Incoming(None) => return Ok(()),
            Event::Response(result) => {
                let (response_size, source) = result?;
                advance_response_packet_id(&mut response_control);
                let response_source = destination_nat.translate_source(source);
                socket
                    .send_to_with_ctrl(
                        client,
                        &to_address(&response_source),
                        &response_control,
                        &response[..response_size],
                    )
                    .await
                    .map_err(io::Error::from)?;
            }
        }
    }
}

async fn receive_ss_udp_packet(
    receiver: &mut mpsc::Receiver<SsUdpPacket>,
    udp_timeout: std::time::Duration,
) -> io::Result<SsUdpPacket> {
    timeout(udp_timeout, receiver.recv())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Shadowsocks UDP session timed out",
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Shadowsocks UDP session closed",
            )
        })
}

fn update_response_control(
    response: &mut UdpSocketControlData,
    request: &UdpSocketControlData,
) {
    response.client_session_id = request.client_session_id;
    response.user = request.user.clone();
    if request.client_session_id == 0 {
        response.server_session_id = request.server_session_id;
        response.packet_id = request.packet_id;
    }
}

fn advance_response_packet_id(response: &mut UdpSocketControlData) {
    if response.client_session_id != 0 {
        response.packet_id = response.packet_id.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::ShadowsocksInbound;
    use crate::{
        adapter::Dialer,
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
            ntp::{NtpClock, NtpSample},
        },
        option::{
            BrutalOptions, Options, OutboundMultiplexOptions,
            ShadowsocksInboundOptions,
        },
        outbound::OutboundManager,
        protocol::{
            direct::DirectOutbound, mux::MuxClient,
            shadowsocks::ShadowsocksOutbound,
        },
        route::Router,
    };
    use serde_json::json;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    #[tokio::test]
    async fn proxies_aead_tcp_and_udp_end_to_end() {
        proxies_aead_tcp_and_udp("aes-128-gcm", false).await;
    }

    #[tokio::test]
    async fn proxies_tcp_through_negotiated_brutal_mux() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut data = [0; 6];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let options: ShadowsocksInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1", "listen_port":0,
                "method":"aes-128-gcm", "password":"secret",
                "multiplex":{
                    "enabled":true, "padding":true,
                    "brutal":{"enabled":true,"up_mbps":100,"down_mbps":80}
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
            ShadowsocksInbound::new("ss", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let shadowsocks = Arc::new(
            ShadowsocksOutbound::new(
                Arc::new(DirectOutbound::new(Default::default())),
                inbound.local_addr().unwrap().into(),
                "aes-128-gcm",
                "secret",
            )
            .unwrap(),
        );
        let mux = MuxClient::new(
            shadowsocks,
            OutboundMultiplexOptions {
                enabled: true,
                protocol: "smux".into(),
                padding: true,
                brutal: Some(BrutalOptions {
                    enabled: true,
                    up_mbps: 100,
                    down_mbps: 80,
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let mut stream = mux.dial_tcp(&destination.into()).await.unwrap();
        stream.write_all(b"brutal").await.unwrap();
        let mut response = [0; 6];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"brutal");
        inbound.close().await.unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn proxies_xchacha20_tcp_and_udp_end_to_end() {
        proxies_aead_tcp_and_udp("xchacha20-ietf-poly1305", false).await;
    }

    #[tokio::test]
    async fn proxies_aes_192_gcm_tcp_and_udp_end_to_end() {
        proxies_aead_tcp_and_udp("aes-192-gcm", false).await;
    }

    #[tokio::test]
    async fn proxies_legacy_aead_multi_user_tcp_and_udp_end_to_end() {
        for method in [
            "aes-128-gcm",
            "aes-192-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "xchacha20-ietf-poly1305",
        ] {
            proxies_aead_tcp_and_udp(method, true).await;
        }
    }

    async fn proxies_aead_tcp_and_udp(method: &str, multi_user: bool) {
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
            let mut first_source = None;
            for _ in 0..2 {
                let (size, source) =
                    udp_target.recv_from(&mut data).await.unwrap();
                if let Some(first_source) = first_source {
                    assert_eq!(source, first_source);
                } else {
                    first_source = Some(source);
                }
                udp_target.send_to(&data[..size], source).await.unwrap();
            }
        });
        let inbound_json = if multi_user {
            json!({
                "listen":"127.0.0.1", "listen_port":0, "udp_timeout":"5s",
                "method":method,
                "users":[
                    {"name":"alice", "password":"alice-secret"},
                    {"name":"bob", "password":"bob-secret"}
                ]
            })
        } else {
            json!({
                "listen":"127.0.0.1", "listen_port":0, "udp_timeout":"5s",
                "method":method, "password":"secret"
            })
        };
        let options: ShadowsocksInboundOptions =
            serde_json::from_value(inbound_json).unwrap();
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
            ShadowsocksInbound::new("ss", options, router, outbounds).unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let client = ShadowsocksOutbound::new(
            Arc::new(DirectOutbound::new(Default::default())),
            inbound.local_addr().unwrap().into(),
            method,
            if multi_user { "bob-secret" } else { "secret" },
        )
        .unwrap();
        let mut tcp = client.dial_tcp(&tcp_destination.into()).await.unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut response = [0; 16];
        tcp.read_exact(&mut response[..4]).await.unwrap();
        assert_eq!(&response[..4], b"ping");
        let packet = client.listen_udp(&udp_destination.into()).await.unwrap();
        packet
            .send_to(b"datagram", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"datagram");
        assert_eq!(source, SocksAddr::from(udp_destination));
        packet
            .send_to(b"second", &SocksAddr::from(udp_destination))
            .await
            .unwrap();
        let (size, source) = packet.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"second");
        assert_eq!(source, SocksAddr::from(udp_destination));
        inbound.close().await.unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_aead_2022_user_end_to_end() {
        let clock = NtpClock::default();
        clock.update(NtpSample {
            offset_nanos: 120_000_000_000,
            round_trip_nanos: 1,
            stratum: 1,
        });
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut data = [0; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut data = [0; 16];
            let mut first_source = None;
            for _ in 0..2 {
                let (size, source) =
                    udp_target.recv_from(&mut data).await.unwrap();
                if let Some(first_source) = first_source {
                    assert_eq!(source, first_source);
                } else {
                    first_source = Some(source);
                }
                udp_target.send_to(&data[..size], source).await.unwrap();
            }
        });
        let server_key = "AAECAwQFBgcICQoLDA0ODw==";
        let user_key = "EBESExQVFhcYGRobHB0eHw==";
        let options: ShadowsocksInboundOptions =
            serde_json::from_value(json!({
                "listen":"127.0.0.1", "listen_port":0,
                "method":"2022-blake3-aes-128-gcm", "password":server_key,
                "users":[{"name":"alice", "password":user_key}]
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
        let mut inbound = ShadowsocksInbound::new_with_clock(
            "ss-2022",
            options,
            router,
            outbounds,
            Some(clock.clone()),
        )
        .unwrap();
        inbound.start(StartStage::Start).await.unwrap();
        let client = ShadowsocksOutbound::new_with_clock(
            Arc::new(DirectOutbound::new(Default::default())),
            inbound.local_addr().unwrap().into(),
            "2022-blake3-aes-128-gcm",
            &format!("{server_key}:{user_key}"),
            Some(clock),
        )
        .unwrap();
        let mut stream = client.dial_tcp(&destination.into()).await.unwrap();
        stream.write_all(b"user").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"user");
        let packet = client.listen_udp(&udp_destination.into()).await.unwrap();
        let mut response = [0_u8; 16];
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            packet
                .send_to(payload, &SocksAddr::from(udp_destination))
                .await
                .unwrap();
            let (size, source) = packet.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[..size], payload);
            assert_eq!(source, SocksAddr::from(udp_destination));
        }
        inbound.close().await.unwrap();
        echo.await.unwrap();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn relays_aead_2022_eih_tcp_and_udp_end_to_end() {
        for (method, identity_key, user_key) in [
            (
                "2022-blake3-aes-128-gcm",
                "AAECAwQFBgcICQoLDA0ODw==",
                "EBESExQVFhcYGRobHB0eHw==",
            ),
            (
                "2022-blake3-aes-256-gcm",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
            ),
        ] {
            let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_destination = tcp_target.local_addr().unwrap();
            let tcp_echo = tokio::spawn(async move {
                let (mut stream, _) = tcp_target.accept().await.unwrap();
                let mut data = [0; 5];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
            });
            let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_destination = udp_target.local_addr().unwrap();
            let udp_echo = tokio::spawn(async move {
                let mut data = [0; 16];
                for _ in 0..2 {
                    let (size, source) =
                        udp_target.recv_from(&mut data).await.unwrap();
                    udp_target.send_to(&data[..size], source).await.unwrap();
                }
            });
            let runtime_options: Options = serde_json::from_value(json!({
                "dns":{"servers":[
                    {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"},
                    {"type":"hosts","tag":"real","predefined":{"downstream.test":"127.0.0.1"}}
                ],"final":"real"},
                "outbounds":[{
                    "type":"direct",
                    "tag":"direct",
                    "domain_resolver":"real"
                }]
            }))
            .unwrap();
            let outbounds = Arc::new(
                OutboundManager::from_options(&runtime_options, "").unwrap(),
            );
            let relay_fake_address = outbounds
                .dns()
                .resolver("fake")
                .unwrap()
                .lookup(
                    "downstream.test",
                    crate::option::DomainStrategy::Ipv4Only,
                )
                .await
                .unwrap()[0];

            let downstream_options: ShadowsocksInboundOptions =
                serde_json::from_value(json!({
                    "listen":"127.0.0.1", "listen_port":0,
                    "udp_timeout":"5s", "method":method,
                    "password":user_key
                }))
                .unwrap();
            let mut downstream = ShadowsocksInbound::new(
                "downstream",
                downstream_options,
                Arc::new(Router::from_json(&[], "").unwrap()),
                outbounds.clone(),
            )
            .unwrap();
            downstream.start(StartStage::Start).await.unwrap();
            let downstream_address = downstream.local_addr().unwrap();

            let relay_options: ShadowsocksInboundOptions =
                serde_json::from_value(json!({
                    "listen":"127.0.0.1", "listen_port":0,
                    "udp_timeout":"5s", "method":method,
                    "password":identity_key,
                    "destinations":[{
                        "name":"bob", "password":user_key,
                        "server":relay_fake_address.to_string(),
                        "server_port":downstream_address.port()
                    }]
                }))
                .unwrap();
            let relay_router = Arc::new(
                Router::from_json(
                    &[
                        json!({
                            "user":"bob",
                            "domain":"downstream.test",
                            "action":"direct"
                        }),
                        json!({"action":"reject"}),
                    ],
                    "",
                )
                .unwrap(),
            );
            let mut relay = ShadowsocksInbound::new(
                "relay",
                relay_options,
                relay_router,
                outbounds.clone(),
            )
            .unwrap();
            relay.start(StartStage::Start).await.unwrap();
            let client = ShadowsocksOutbound::new(
                Arc::new(DirectOutbound::new(Default::default())),
                relay.local_addr().unwrap().into(),
                method,
                &format!("{identity_key}:{user_key}"),
            )
            .unwrap();

            let mut tcp =
                client.dial_tcp(&tcp_destination.into()).await.unwrap();
            tcp.write_all(b"relay").await.unwrap();
            let mut response = [0_u8; 16];
            tcp.read_exact(&mut response[..5]).await.unwrap();
            assert_eq!(&response[..5], b"relay", "method {method}");

            let packet =
                client.listen_udp(&udp_destination.into()).await.unwrap();
            for payload in [b"first".as_slice(), b"second".as_slice()] {
                packet
                    .send_to(payload, &SocksAddr::from(udp_destination))
                    .await
                    .unwrap();
                let (size, source) =
                    packet.recv_from(&mut response).await.unwrap();
                assert_eq!(&response[..size], payload, "method {method}");
                assert_eq!(source, SocksAddr::from(udp_destination));
            }

            relay.close().await.unwrap();
            downstream.close().await.unwrap();
            tcp_echo.await.unwrap();
            udp_echo.await.unwrap();
        }
    }
}
