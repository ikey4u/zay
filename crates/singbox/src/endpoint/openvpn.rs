//! Runtime-facing userspace OpenVPN client endpoint.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

use super::{
    tokio_smoltcp::{
        BufferSize, Net, NetConfig, UdpSocket as SmoltcpUdpSocket,
        channel_device::ChannelDevice,
        smoltcp::{
            iface::Config as SmoltcpInterfaceConfig,
            phy::{DeviceCapabilities, Medium},
            wire::{HardwareAddress, IpAddress, IpCidr},
        },
    },
    userspace_router::{EndpointFlowContext, UserspaceEndpointRouter},
};
use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, IpPacketPort, IpPacketReturn,
        PacketConnection, PacketFuture, PacketStream, Stream,
    },
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::SocksAddr,
    },
    dns::manager::SharedResolver,
    option::{DomainStrategy, OpenVpnClientEndpointOptions},
    outbound::OutboundManager,
    protocol::openvpn::{
        AuthRetryMode, Challenge, ChallengeKind, ChallengeManager,
        ClientPullChallengeContext, ClientRemoteAdvance, Crv1Challenge,
        DataChannelFraming, OpenVpnClientConnectionCursor,
        OpenVpnClientConnector, OpenVpnClientPacketConnection,
        OpenVpnClientReconnectPolicy, OpenVpnConnectedClient,
        OpenVpnEndpointBuildError, OpenVpnStaticDataSession,
        OpenVpnStaticDataSessionOptions, StaticDataSessionError,
        TunnelConfiguration, build_openvpn_client_tunnel_state,
        load_openvpn_static_key_material, openvpn_client_auth_failure_info,
        openvpn_client_reconnect_policy, pack_dynamic_challenge_response,
        parse_crv1_challenge, resolve_allow_compression_policy,
        resolve_auth_retry_mode, resolve_auth_token_credentials,
        resolve_compression_settings, resolve_openvpn_key_direction,
    },
};

struct OpenVpnClientNetwork {
    net: Arc<Net>,
    packet_output: tokio::sync::mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
    failure: CancellationToken,
    failure_message: Arc<Mutex<Option<OpenVpnClientFailure>>>,
    _flow_router: Arc<UserspaceEndpointRouter>,
    _tasks: Vec<AbortOnDropHandle<()>>,
}

#[derive(Clone)]
enum OpenVpnClientDataSession {
    Tls(Arc<OpenVpnConnectedClient>),
    Static(Arc<OpenVpnStaticDataSession>),
}

#[derive(Clone)]
struct OpenVpnClientFailure {
    message: String,
    policy: OpenVpnClientReconnectPolicy,
}

pub struct OpenVpnClientDialer {
    net: RwLock<Option<Arc<Net>>>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
    packet_port: Arc<OpenVpnPacketPort>,
}

struct OpenVpnPacketPortState {
    output: tokio::sync::mpsc::Sender<Vec<u8>>,
    inet4_address: Option<IpAddr>,
    inet6_address: Option<IpAddr>,
    mtu: usize,
    block_ipv6: bool,
    preferred_routes: Vec<crate::protocol::openvpn::OpenVpnIpPrefix>,
    excluded_routes: Vec<crate::protocol::openvpn::OpenVpnIpPrefix>,
    preferred_domains: Vec<String>,
}

#[derive(Default)]
struct OpenVpnPacketPort {
    state: RwLock<Option<OpenVpnPacketPortState>>,
    return_path: RwLock<Option<Weak<dyn IpPacketReturn>>>,
}

impl OpenVpnPacketPort {
    fn activate(
        &self,
        output: tokio::sync::mpsc::Sender<Vec<u8>>,
        configuration: &TunnelConfiguration,
    ) -> io::Result<()> {
        let mut preferred_domains = configuration.dns_routes.clone();
        preferred_domains.extend(configuration.search_domains.iter().cloned());
        if let Some(server) = configuration
            .dns_servers
            .iter()
            .min_by_key(|server| server.priority)
        {
            preferred_domains.extend(server.resolve_domains.iter().cloned());
        }
        *self.state.write().map_err(|_| {
            io::Error::other("OpenVPN packet port lock poisoned")
        })? = Some(OpenVpnPacketPortState {
            output,
            inet4_address: configuration.local_ipv4.iter().find_map(|prefix| {
                match prefix.address {
                    IpAddr::V4(address) => Some(IpAddr::V4(address)),
                    IpAddr::V6(_) => None,
                }
            }),
            inet6_address: configuration.local_ipv6.iter().find_map(|prefix| {
                match prefix.address {
                    IpAddr::V6(address) => Some(IpAddr::V6(address)),
                    IpAddr::V4(_) => None,
                }
            }),
            mtu: if configuration.tun_mtu == 0 {
                1500
            } else {
                configuration.tun_mtu.max(576) as usize
            },
            block_ipv6: configuration.block_ipv6,
            preferred_routes: configuration
                .ipv4_routes
                .iter()
                .chain(&configuration.ipv6_routes)
                .map(|route| route.prefix)
                .collect(),
            excluded_routes: configuration
                .excluded_ipv4_routes
                .iter()
                .chain(&configuration.excluded_ipv6_routes)
                .map(|route| route.prefix)
                .collect(),
            preferred_domains,
        });
        Ok(())
    }

    fn block_ipv6(&self) -> bool {
        self.state
            .read()
            .ok()
            .and_then(|state| state.as_ref().map(|state| state.block_ipv6))
            .unwrap_or_default()
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.state.read().is_ok_and(|state| {
            state.as_ref().is_some_and(|state| {
                state
                    .preferred_routes
                    .iter()
                    .any(|prefix| openvpn_prefix_contains(*prefix, address))
                    && !state
                        .excluded_routes
                        .iter()
                        .any(|prefix| openvpn_prefix_contains(*prefix, address))
            })
        })
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.state.read().is_ok_and(|state| {
            state.as_ref().is_some_and(|state| {
                state
                    .preferred_domains
                    .iter()
                    .any(|suffix| openvpn_domain_matches(suffix, domain))
            })
        })
    }

    fn deactivate(&self) -> io::Result<()> {
        self.state
            .write()
            .map_err(|_| io::Error::other("OpenVPN packet port lock poisoned"))?
            .take();
        Ok(())
    }

    fn return_packet(&self, packet: &[u8]) -> bool {
        let return_path = self
            .return_path
            .read()
            .ok()
            .and_then(|return_path| return_path.as_ref()?.upgrade());
        let Some(return_path) = return_path else {
            return false;
        };
        let headroom = return_path.return_headroom();
        let mut framed = vec![0; headroom + packet.len()];
        framed[headroom..].copy_from_slice(packet);
        return_path.return_packets(vec![framed]).is_empty()
    }
}

impl IpPacketPort for OpenVpnPacketPort {
    fn port_addresses(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        self.state.read().map_or((None, None), |state| {
            state.as_ref().map_or((None, None), |state| {
                (state.inet4_address, state.inet6_address)
            })
        })
    }

    fn port_mtu(&self) -> usize {
        self.state
            .read()
            .ok()
            .and_then(|state| state.as_ref().map(|state| state.mtu))
            .unwrap_or_default()
    }

    fn attach_return(
        &self,
        return_path: Weak<dyn IpPacketReturn>,
    ) -> io::Result<()> {
        let mut current = self.return_path.write().map_err(|_| {
            io::Error::other("OpenVPN packet return lock poisoned")
        })?;
        if let Some(existing) = current.as_ref()
            && existing.upgrade().is_some()
        {
            if existing.ptr_eq(&return_path) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN packet return path is already attached",
            ));
        }
        *current = Some(return_path);
        Ok(())
    }

    fn detach_return(&self, return_path: &Weak<dyn IpPacketReturn>) {
        if let Ok(mut current) = self.return_path.write()
            && current
                .as_ref()
                .is_some_and(|existing| existing.ptr_eq(return_path))
        {
            current.take();
        }
    }

    fn write_packets<'a>(
        &'a self,
        packets: Vec<Vec<u8>>,
    ) -> PacketFuture<'a, ()> {
        Box::pin(async move {
            let (output, block_ipv6) = self
                .state
                .read()
                .map_err(|_| {
                    io::Error::other("OpenVPN packet port lock poisoned")
                })?
                .as_ref()
                .map(|state| (state.output.clone(), state.block_ipv6))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "OpenVPN endpoint is not started",
                    )
                })?;
            for packet in packets {
                if packet.is_empty() {
                    continue;
                }
                // The pinned OpenVPN system device silently drops IPv6 read
                // from the TUN after a pushed `block-ipv6`, while its
                // userspace device rejects IPv6 dials. This packet-port gate
                // covers the raw system-interface path as well as callers
                // writing packets directly.
                if block_ipv6
                    && packet.first().is_some_and(|byte| byte >> 4 == 6)
                {
                    continue;
                }
                output.send(packet).await.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "OpenVPN packet transport is closed",
                    )
                })?;
            }
            Ok(())
        })
    }
}

impl Default for OpenVpnClientDialer {
    fn default() -> Self {
        Self {
            net: RwLock::default(),
            resolver: None,
            strategy: DomainStrategy::AsIs,
            packet_port: Arc::default(),
        }
    }
}

#[derive(Clone)]
pub struct OpenVpnClientEndpointHandle {
    client: Arc<Mutex<Option<Arc<OpenVpnConnectedClient>>>>,
    static_session: Arc<Mutex<Option<Arc<OpenVpnStaticDataSession>>>>,
    tunnel_configuration: Arc<RwLock<Option<TunnelConfiguration>>>,
    network: Arc<Mutex<Option<Arc<OpenVpnClientNetwork>>>>,
    dialer: Arc<OpenVpnClientDialer>,
    last_error: Arc<RwLock<Option<String>>>,
    challenge_manager: Arc<ChallengeManager>,
    flow: EndpointFlowContext,
}

impl OpenVpnClientEndpointHandle {
    pub fn client(&self) -> Option<Arc<OpenVpnConnectedClient>> {
        self.client.lock().ok()?.clone()
    }

    pub fn tunnel_configuration(&self) -> Option<TunnelConfiguration> {
        self.client()
            .map(|client| client.tunnel_configuration())
            .or_else(|| self.tunnel_configuration.read().ok()?.clone())
    }

    pub fn static_session(&self) -> Option<Arc<OpenVpnStaticDataSession>> {
        self.static_session.lock().ok()?.clone()
    }

    pub fn dialer(&self) -> Arc<dyn Dialer> {
        self.dialer.clone()
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.read().ok()?.clone()
    }

    pub fn challenge_manager(&self) -> Arc<ChallengeManager> {
        self.challenge_manager.clone()
    }
}

pub struct OpenVpnClientEndpointService {
    name: String,
    options: OpenVpnClientEndpointOptions,
    base_path: PathBuf,
    transport_dialer: Arc<dyn Dialer>,
    handle: OpenVpnClientEndpointHandle,
    cancellation: CancellationToken,
    reconnect_task: Option<AbortOnDropHandle<()>>,
}

impl OpenVpnClientEndpointService {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_resolver(
        tag: impl Into<String>,
        options: OpenVpnClientEndpointOptions,
        base_path: &Path,
        transport_dialer: Arc<dyn Dialer>,
        resolver: SharedResolver,
        strategy: DomainStrategy,
        router: Arc<crate::route::Router>,
        outbounds: Arc<OutboundManager>,
    ) -> (Self, OpenVpnClientEndpointHandle) {
        let tag = tag.into();
        let handle = OpenVpnClientEndpointHandle {
            client: Arc::default(),
            static_session: Arc::default(),
            tunnel_configuration: Arc::default(),
            network: Arc::default(),
            dialer: Arc::new(OpenVpnClientDialer {
                net: RwLock::default(),
                resolver: Some(resolver),
                strategy,
                packet_port: Arc::default(),
            }),
            last_error: Arc::default(),
            challenge_manager: Arc::default(),
            flow: EndpointFlowContext {
                tag: tag.clone(),
                router,
                outbounds,
                udp_timeout: crate::constant::UDP_TIMEOUT,
                udp_mapping: options.endpoint.udp_mapping,
                udp_filtering: options.endpoint.udp_filtering,
                udp_nat_max: options.endpoint.udp_nat_max,
            },
        };
        (
            Self {
                name: format!("endpoint/{tag}"),
                options,
                base_path: base_path.to_owned(),
                transport_dialer,
                handle: handle.clone(),
                cancellation: CancellationToken::new(),
                reconnect_task: None,
            },
            handle,
        )
    }

    async fn start_static(
        &mut self,
        stage: StartStage,
    ) -> Result<(), LifecycleError> {
        let connector = endpoint_openvpn_connector(
            self.options.clone(),
            &self.base_path,
            self.transport_dialer.clone(),
            &self.handle,
        );
        let cursor = connector.connection_cursor().map_err(|error| {
            LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            }
        })?;
        let (session, configuration) = connect_openvpn_static_client(
            &connector,
            &cursor,
            &self.options,
            &self.base_path,
        )
        .await
        .map_err(|error| LifecycleError::Start {
            component: self.name.clone(),
            stage,
            message: error.to_string(),
        })?;
        let network = OpenVpnClientNetwork::start_static(
            session.clone(),
            configuration.clone(),
            self.handle.dialer.packet_port.clone(),
            &self.handle.flow,
        )
        .map_err(|error| LifecycleError::Start {
            component: self.name.clone(),
            stage,
            message: error.to_string(),
        })?;
        self.handle
            .dialer
            .activate(
                network.net.clone(),
                &configuration,
                network.packet_output.clone(),
            )
            .map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })?;
        *self.handle.static_session.lock().map_err(|_| {
            LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: "OpenVPN static session lock poisoned".into(),
            }
        })? = Some(session);
        *self
            .handle
            .network
            .lock()
            .map_err(|_| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: "OpenVPN network handle lock poisoned".into(),
            })? = Some(network);
        *self.handle.tunnel_configuration.write().map_err(|_| {
            LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: "OpenVPN tunnel configuration lock poisoned".into(),
            }
        })? = Some(configuration);
        let options = self.options.clone();
        let base_path = self.base_path.clone();
        let transport_dialer = self.transport_dialer.clone();
        let handle = self.handle.clone();
        let cancellation = self.cancellation.clone();
        self.reconnect_task =
            Some(AbortOnDropHandle::new(tokio::spawn(async move {
                maintain_openvpn_static_client(
                    options,
                    base_path,
                    transport_dialer,
                    handle,
                    cancellation,
                    cursor,
                )
                .await;
            })));
        Ok(())
    }
}

impl OpenVpnClientDataSession {
    async fn read_data_packet(&self) -> Result<Vec<u8>, OpenVpnClientFailure> {
        match self {
            Self::Tls(client) => client
                .active
                .read_data_packet()
                .await
                .map_err(|error| {
                    let error = crate::protocol::openvpn::OpenVpnClientConnectorError::ActiveSession(error);
                    OpenVpnClientFailure {
                        message: error.to_string(),
                        policy: openvpn_client_reconnect_policy(&error, true),
                    }
                }),
            Self::Static(session) =>
                session.read_data_packet().await.map_err(|error| {
                    OpenVpnClientFailure {
                        message: error.to_string(),
                        policy: initialized_reconnect_policy(),
                    }
                }),
        }
    }

    async fn write_data_packet(
        &self,
        packet: &[u8],
    ) -> Result<(), OpenVpnClientFailure> {
        match self {
            Self::Tls(client) => client
                .active
                .write_data_packet(packet)
                .await
                .map(|_| ())
                .map_err(|error| {
                    let error = crate::protocol::openvpn::OpenVpnClientConnectorError::ActiveSession(error);
                    OpenVpnClientFailure {
                        message: error.to_string(),
                        policy: openvpn_client_reconnect_policy(&error, true),
                    }
                }),
            Self::Static(session) =>
                session.write_data_packet(packet).await.map(|_| ()).map_err(
                    |error| OpenVpnClientFailure {
                        message: error.to_string(),
                        policy: initialized_reconnect_policy(),
                    },
                ),
        }
    }
}

impl Lifecycle for OpenVpnClientEndpointService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.cancellation = CancellationToken::new();
            if self.options.normalized_mode() == "static_key" {
                return self.start_static(stage).await;
            }
            self.handle.challenge_manager.note_credentials_sent(false);
            let mut session_options = self.options.clone();
            acquire_static_challenge_credentials(
                &mut session_options,
                &self.handle.challenge_manager,
                self.cancellation.clone(),
            )
            .await
            .map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })?;
            let connector = endpoint_openvpn_connector(
                session_options.clone(),
                &self.base_path,
                self.transport_dialer.clone(),
                &self.handle,
            );
            let cursor = connector.connection_cursor().map_err(|error| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                }
            })?;
            let configured_options = self.options.clone();
            let mut credential_interactive =
                self.handle.challenge_manager.sent_interactive_credentials();
            let client = loop {
                self.handle
                    .challenge_manager
                    .note_credentials_sent(credential_interactive);
                let challenge_context = ClientPullChallengeContext {
                    manager: self.handle.challenge_manager.clone(),
                    owner: 1,
                    username: session_options.username.clone(),
                    cancellation: self.cancellation.clone(),
                };
                let connector = endpoint_openvpn_connector(
                    session_options.clone(),
                    &self.base_path,
                    self.transport_dialer.clone(),
                    &self.handle,
                );
                match connector
                    .connect_at_cursor(&cursor, Some(&challenge_context))
                    .await
                {
                    Ok(client) => break Arc::new(client),
                    Err(error) => {
                        let auth_failure =
                            openvpn_client_auth_failure_info(&error).cloned();
                        let Some(info) =
                            auth_failure.filter(|info| !info.temporary)
                        else {
                            return Err(LifecycleError::Start {
                                component: self.name.clone(),
                                stage,
                                message: error.to_string(),
                            });
                        };
                        if let Some(challenge) =
                            parse_crv1_challenge(&info.reason)
                        {
                            if self
                                .handle
                                .challenge_manager
                                .sent_interactive_credentials()
                            {
                                self.handle
                                    .challenge_manager
                                    .note_previous_auth_failure(
                                        "OpenVPN authentication failed",
                                    );
                            }
                            let rejected_username =
                                session_options.username.clone();
                            session_options = configured_options.clone();
                            session_options.username =
                                if challenge.username.is_empty() {
                                    rejected_username
                                } else {
                                    challenge.username.clone()
                                };
                            acquire_dynamic_challenge_credentials(
                                &mut session_options,
                                &self.handle.challenge_manager,
                                challenge,
                                self.cancellation.clone(),
                            )
                            .await
                            .map_err(
                                |challenge_error| LifecycleError::Start {
                                    component: self.name.clone(),
                                    stage,
                                    message: challenge_error.to_string(),
                                },
                            )?;
                            credential_interactive = true;
                            continue;
                        }
                        if resolve_auth_retry_mode(
                            &configured_options.auth_retry,
                        ) == AuthRetryMode::Interact
                            && self
                                .handle
                                .challenge_manager
                                .sent_interactive_credentials()
                        {
                            self.handle
                                .challenge_manager
                                .note_previous_auth_failure(
                                    if info.reason.is_empty() {
                                        "OpenVPN authentication failed"
                                    } else {
                                        &info.reason
                                    },
                                );
                            session_options = configured_options.clone();
                            self.handle
                                .challenge_manager
                                .note_credentials_sent(false);
                            acquire_static_challenge_credentials(
                                &mut session_options,
                                &self.handle.challenge_manager,
                                self.cancellation.clone(),
                            )
                            .await
                            .map_err(
                                |challenge_error| LifecycleError::Start {
                                    component: self.name.clone(),
                                    stage,
                                    message: challenge_error.to_string(),
                                },
                            )?;
                            credential_interactive = self
                                .handle
                                .challenge_manager
                                .sent_interactive_credentials();
                            continue;
                        }
                        return Err(LifecycleError::Start {
                            component: self.name.clone(),
                            stage,
                            message: error.to_string(),
                        });
                    }
                }
            };
            let configuration = client.tunnel_configuration();
            let network = OpenVpnClientNetwork::start(
                client.clone(),
                self.handle.dialer.packet_port.clone(),
                &self.handle.flow,
            )
            .map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })?;
            self.handle
                .dialer
                .activate(
                    network.net.clone(),
                    &configuration,
                    network.packet_output.clone(),
                )
                .map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })?;
            *self.handle.client.lock().map_err(|_| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "OpenVPN client handle lock poisoned".into(),
                }
            })? = Some(client);
            *self.handle.tunnel_configuration.write().map_err(|_| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "OpenVPN tunnel configuration lock poisoned"
                        .into(),
                }
            })? = self
                .handle
                .client()
                .map(|client| client.tunnel_configuration());
            *self.handle.network.lock().map_err(|_| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "OpenVPN network handle lock poisoned".into(),
                }
            })? = Some(network);
            let cancellation = self.cancellation.clone();
            let credential_options = session_options;
            let base_path = self.base_path.clone();
            let transport_dialer = self.transport_dialer.clone();
            let handle = self.handle.clone();
            self.reconnect_task =
                Some(AbortOnDropHandle::new(tokio::spawn(async move {
                    maintain_openvpn_client(
                        configured_options,
                        credential_options,
                        base_path,
                        transport_dialer,
                        handle,
                        cancellation,
                        cursor,
                    )
                    .await;
                })));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            self.reconnect_task.take();
            self.handle.challenge_manager.close();
            self.handle.dialer.deactivate().map_err(|error| {
                LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                }
            })?;
            lock(&self.handle.network, "OpenVPN network handle")?.take();
            if let Some(client) =
                lock(&self.handle.client, "OpenVPN client handle")?.take()
            {
                client.active.close();
            }
            if let Some(session) =
                lock(&self.handle.static_session, "OpenVPN static session")?
                    .take()
            {
                session.close();
            }
            write_rw(
                &self.handle.tunnel_configuration,
                "OpenVPN tunnel configuration",
            )?
            .take();
            if let Ok(mut last_error) = self.handle.last_error.write() {
                last_error.take();
            }
            Ok(())
        })
    }
}

impl OpenVpnClientNetwork {
    fn start(
        client: Arc<OpenVpnConnectedClient>,
        packet_port: Arc<OpenVpnPacketPort>,
        flow: &EndpointFlowContext,
    ) -> io::Result<Arc<Self>> {
        let configuration = client.tunnel_configuration();
        Self::start_session(
            OpenVpnClientDataSession::Tls(client),
            configuration,
            packet_port,
            flow,
        )
    }

    fn start_static(
        session: Arc<OpenVpnStaticDataSession>,
        configuration: TunnelConfiguration,
        packet_port: Arc<OpenVpnPacketPort>,
        flow: &EndpointFlowContext,
    ) -> io::Result<Arc<Self>> {
        Self::start_session(
            OpenVpnClientDataSession::Static(session),
            configuration,
            packet_port,
            flow,
        )
    }

    fn start_session(
        session: OpenVpnClientDataSession,
        configuration: TunnelConfiguration,
        packet_port: Arc<OpenVpnPacketPort>,
        flow: &EndpointFlowContext,
    ) -> io::Result<Arc<Self>> {
        let addresses = configuration
            .local_ipv4
            .iter()
            .chain(&configuration.local_ipv6)
            .map(|prefix| {
                format!("{}/{}", prefix.address, prefix.prefix_len).parse()
            })
            .collect::<Result<Vec<IpCidr>, _>>()
            .map_err(|()| invalid("invalid OpenVPN stack address"))?;
        if addresses.is_empty() {
            return Err(invalid("OpenVPN server assigned no tunnel address"));
        }
        let effective_mtu = if configuration.tun_mtu == 0 {
            1500
        } else {
            configuration.tun_mtu.max(576) as usize
        };
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = effective_mtu;
        capabilities.medium = Medium::Ip;
        let (device, ingress, egress, mut output, icmp_errors) =
            ChannelDevice::new(capabilities);
        let (packet_output, mut raw_output) = tokio::sync::mpsc::channel(256);
        let gateways = addresses
            .iter()
            .map(IpCidr::address)
            .collect::<Vec<IpAddress>>();
        let mut net_config = NetConfig::new(
            SmoltcpInterfaceConfig::new(HardwareAddress::Ip),
            addresses,
            gateways,
            Some(BufferSize {
                tcp_rx_size: 128 * 1024,
                tcp_tx_size: 128 * 1024,
                udp_rx_size: 128 * 1024,
                udp_tx_size: 128 * 1024,
                udp_rx_meta_size: 256,
                udp_tx_meta_size: 256,
            }),
        );
        net_config.icmp_errors = Some(icmp_errors);
        let net = Arc::new(Net::new(device, net_config)?);
        let local_networks = configuration
            .local_ipv4
            .iter()
            .chain(&configuration.local_ipv6)
            .map(|prefix| {
                format!("{}/{}", prefix.address, prefix.prefix_len).parse()
            })
            .collect::<Result<Vec<ipnet::IpNet>, _>>()
            .map_err(|_| invalid("invalid OpenVPN flow-router address"))?;
        let flow_router = UserspaceEndpointRouter::new(
            &net,
            egress,
            flow.tag.clone(),
            local_networks,
            true,
            Vec::new(),
            flow.router.clone(),
            flow.outbounds.clone(),
            flow.udp_timeout,
            flow.udp_mapping,
            flow.udp_filtering,
            flow.udp_nat_max,
            effective_mtu,
        );
        let cancellation = CancellationToken::new();
        let failure = CancellationToken::new();
        let failure_message = Arc::new(Mutex::new(None));

        let incoming_session = session.clone();
        let incoming_cancellation = cancellation.clone();
        let incoming_failure = failure.clone();
        let incoming_failure_message = failure_message.clone();
        let incoming_flow_router = flow_router.clone();
        let incoming = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = incoming_cancellation.cancelled() => break,
                    packet = incoming_session.read_data_packet() => packet,
                };
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        signal_network_failure(
                            &incoming_failure,
                            &incoming_failure_message,
                            OpenVpnClientFailure {
                                message: format!(
                                    "OpenVPN data receive failed: {}",
                                    error.message
                                ),
                                policy: error.policy,
                            },
                        );
                        break;
                    }
                };
                if packet_port.return_packet(&packet) {
                    continue;
                }
                match incoming_flow_router.prepare_packet(&packet).await {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        signal_network_failure(
                            &incoming_failure,
                            &incoming_failure_message,
                            OpenVpnClientFailure {
                                message: format!(
                                    "OpenVPN inbound flow routing failed: {error}"
                                ),
                                policy: initialized_reconnect_policy(),
                            },
                        );
                        break;
                    }
                }
                if ingress.send(Ok(packet)).await.is_err() {
                    signal_network_failure(
                        &incoming_failure,
                        &incoming_failure_message,
                        OpenVpnClientFailure {
                            message: "OpenVPN userspace stack stopped receiving packets".into(),
                            policy: initialized_reconnect_policy(),
                        },
                    );
                    break;
                }
            }
        });

        let outgoing_session = session.clone();
        let outgoing_cancellation = cancellation.clone();
        let outgoing_failure = failure.clone();
        let outgoing_failure_message = failure_message.clone();
        let outgoing = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = outgoing_cancellation.cancelled() => break,
                    packet = output.recv() => packet,
                    packet = raw_output.recv() => packet,
                };
                let Some(packet) = packet else {
                    signal_network_failure(
                        &outgoing_failure,
                        &outgoing_failure_message,
                        OpenVpnClientFailure {
                            message: "OpenVPN userspace stack stopped producing packets".into(),
                            policy: initialized_reconnect_policy(),
                        },
                    );
                    break;
                };
                if let Err(error) =
                    outgoing_session.write_data_packet(&packet).await
                {
                    signal_network_failure(
                        &outgoing_failure,
                        &outgoing_failure_message,
                        OpenVpnClientFailure {
                            message: format!(
                                "OpenVPN data send failed: {}",
                                error.message
                            ),
                            policy: error.policy,
                        },
                    );
                    break;
                }
            }
        });

        let supervisor = match session {
            OpenVpnClientDataSession::Tls(supervisor_client) => {
                let supervisor_cancellation = cancellation.clone();
                let supervisor_failure = failure.clone();
                let supervisor_failure_message = failure_message.clone();
                Some(AbortOnDropHandle::new(tokio::spawn(async move {
                    if let Err(error) = supervisor_client
                        .run_renegotiation_supervisor(supervisor_cancellation)
                        .await
                    {
                        let policy =
                            openvpn_client_reconnect_policy(&error, true);
                        signal_network_failure(
                            &supervisor_failure,
                            &supervisor_failure_message,
                            OpenVpnClientFailure {
                                message: format!(
                                    "OpenVPN session supervisor failed: {error}"
                                ),
                                policy,
                            },
                        );
                    }
                })))
            }
            OpenVpnClientDataSession::Static(_) => None,
        };
        let mut tasks = vec![
            AbortOnDropHandle::new(incoming),
            AbortOnDropHandle::new(outgoing),
        ];
        tasks.extend(supervisor);
        Ok(Arc::new(Self {
            net,
            packet_output,
            cancellation,
            failure,
            failure_message,
            _flow_router: flow_router,
            _tasks: tasks,
        }))
    }

    async fn wait_failure(&self) -> OpenVpnClientFailure {
        self.failure.cancelled().await;
        self.failure_message
            .lock()
            .ok()
            .and_then(|message| message.clone())
            .unwrap_or_else(|| OpenVpnClientFailure {
                message: "OpenVPN session stopped".into(),
                policy: initialized_reconnect_policy(),
            })
    }
}

impl Drop for OpenVpnClientNetwork {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl OpenVpnClientDialer {
    fn activate(
        &self,
        net: Arc<Net>,
        configuration: &TunnelConfiguration,
        packet_output: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> io::Result<()> {
        self.packet_port.activate(packet_output, configuration)?;
        *self
            .net
            .write()
            .map_err(|_| io::Error::other("OpenVPN network lock poisoned"))? =
            Some(net);
        Ok(())
    }

    fn deactivate(&self) -> io::Result<()> {
        self.packet_port.deactivate()?;
        self.net
            .write()
            .map_err(|_| io::Error::other("OpenVPN network lock poisoned"))?
            .take();
        Ok(())
    }

    fn net(&self) -> io::Result<Arc<Net>> {
        self.net
            .read()
            .map_err(|_| io::Error::other("OpenVPN network lock poisoned"))?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "OpenVPN endpoint is not started",
                )
            })
    }

    async fn resolve(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<Vec<SocketAddr>> {
        let mut addresses = match (destination, &self.resolver) {
            (SocksAddr::Domain { host, port }, Some(resolver)) => Ok(resolver
                .lookup(host, self.strategy)
                .await?
                .into_iter()
                .map(|address| SocketAddr::new(address, *port))
                .collect()),
            _ => destination.resolve().await,
        }?;
        if self.packet_port.block_ipv6() {
            addresses.retain(SocketAddr::is_ipv4);
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "IPv6 blocked by pushed block-ipv6",
                ));
            }
        }
        Ok(addresses)
    }
}

impl Dialer for OpenVpnClientDialer {
    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        Some(self.packet_port.clone())
    }

    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let net = self.net()?;
            let addresses = self.resolve(destination).await?;
            let mut last_error = None;
            let local_port = net.get_port();
            for address in addresses {
                match net.tcp_connect(address, local_port).await {
                    Ok(stream) => return Ok(Box::new(stream) as Stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no address found for {destination}"),
                )
            }))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let net = self.net()?;
            let addresses = self.resolve(destination).await?;
            let mut last_error = None;
            for destination in addresses {
                let bind = match destination {
                    SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                    SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
                };
                match net.udp_bind(bind).await {
                    Ok(socket) => {
                        return Ok(Box::new(OpenVpnPacketConnection {
                            socket: Arc::new(socket),
                            resolver: self.resolver.clone(),
                            strategy: self.strategy,
                        }) as PacketStream);
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no address found for {destination}"),
                )
            }))
        })
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let net = self.net()?;
            let destination = self
                .resolve(destination)
                .await?
                .into_iter()
                .find(|destination| destination.is_ipv4() == source.is_ipv4())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "no compatible OpenVPN ICMP destination",
                    )
                })?;
            net.exchange_icmp(
                packet,
                source,
                destination.ip(),
                hop_limit,
                crate::constant::ICMP_TIMEOUT,
            )
            .await
        })
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.packet_port.preferred_domain(domain)
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.packet_port.preferred_address(address)
    }
}

fn openvpn_prefix_contains(
    prefix: crate::protocol::openvpn::OpenVpnIpPrefix,
    address: IpAddr,
) -> bool {
    ipnet::IpNet::new(prefix.address, prefix.prefix_len)
        .is_ok_and(|prefix| prefix.contains(&address))
}

fn openvpn_domain_matches(suffix: &str, domain: &str) -> bool {
    let suffix = suffix.trim().to_ascii_lowercase();
    if suffix == "." {
        return true;
    }
    let suffix = suffix.trim_end_matches('.');
    if suffix.is_empty() {
        return false;
    }
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

struct OpenVpnPacketConnection {
    socket: Arc<SmoltcpUdpSocket>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
}

impl PacketConnection for OpenVpnPacketConnection {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let local_is_ipv4 = self.socket.local_addr()?.is_ipv4();
            let addresses = match (destination, &self.resolver) {
                (SocksAddr::Domain { host, port }, Some(resolver)) => resolver
                    .lookup(host, self.strategy)
                    .await?
                    .into_iter()
                    .map(|address| SocketAddr::new(address, *port))
                    .collect(),
                _ => destination.resolve().await?,
            };
            let address = addresses
                .into_iter()
                .find(|address| address.is_ipv4() == local_is_ipv4)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!(
                            "no compatible address found for {destination}"
                        ),
                    )
                })?;
            self.socket.send_to(data, address).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let (size, source) = self.socket.recv_from(data).await?;
            Ok((size, source.into()))
        })
    }
}

const OPENVPN_RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const OPENVPN_RECONNECT_MAXIMUM_BACKOFF: Duration = Duration::from_secs(60);

async fn acquire_static_challenge_credentials(
    options: &mut OpenVpnClientEndpointOptions,
    manager: &Arc<ChallengeManager>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if options.static_challenge.is_empty() {
        return Ok(());
    }
    let credentials_required =
        options.username.is_empty() && options.password.is_empty();
    let mut challenge = Challenge::new(if credentials_required {
        ChallengeKind::Credentials
    } else {
        ChallengeKind::Secret
    });
    challenge.username.clone_from(&options.username);
    challenge.echo = options.static_challenge_echo;
    if credentials_required {
        challenge
            .secret_message
            .clone_from(&options.static_challenge);
    } else {
        challenge.message.clone_from(&options.static_challenge);
    }
    let response = manager
        .await_response(0, challenge, cancellation)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    if credentials_required {
        options.username = response.username;
        options.password = response.password;
    }
    let encoded_password = STANDARD.encode(options.password.as_bytes());
    let encoded_response = STANDARD.encode(response.secret.as_bytes());
    options.password = format!("SCRV1:{encoded_password}:{encoded_response}");
    manager.note_response_submitted();
    Ok(())
}

async fn acquire_dynamic_challenge_credentials(
    options: &mut OpenVpnClientEndpointOptions,
    manager: &Arc<ChallengeManager>,
    challenge: Crv1Challenge,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut request = Challenge::new(ChallengeKind::Secret);
    request.username.clone_from(&challenge.username);
    request.message.clone_from(&challenge.challenge_text);
    request.echo = challenge.echo;
    let response = manager
        .await_response(0, request, cancellation)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    if !challenge.username.is_empty() {
        options.username = challenge.username;
    }
    options.password =
        pack_dynamic_challenge_response(&challenge.state_id, &response.secret);
    manager.note_response_submitted();
    Ok(())
}

async fn maintain_openvpn_client(
    configured_options: OpenVpnClientEndpointOptions,
    mut credential_options: OpenVpnClientEndpointOptions,
    base_path: PathBuf,
    transport_dialer: Arc<dyn Dialer>,
    handle: OpenVpnClientEndpointHandle,
    cancellation: CancellationToken,
    mut cursor: OpenVpnClientConnectionCursor,
) {
    let mut backoff = OPENVPN_RECONNECT_INITIAL_BACKOFF;
    let mut credential_interactive =
        handle.challenge_manager.sent_interactive_credentials();
    loop {
        let network = match handle.network.lock() {
            Ok(network) => network.clone(),
            Err(_) => return,
        };
        let Some(network) = network else { return };
        let failure = tokio::select! {
            _ = cancellation.cancelled() => return,
            failure = network.wait_failure() => failure,
        };
        if let Ok(mut last_error) = handle.last_error.write() {
            *last_error = Some(failure.message.clone());
        }
        cursor.advance(failure.policy.advance);
        backoff = backoff.max(failure.policy.minimum_backoff);
        let mut active_auth_token = None;
        if let Ok(running_client) = handle.client.lock()
            && let Some(client) = running_client.as_ref()
        {
            let tunnel = client.tunnel_configuration();
            active_auth_token = resolve_auth_token_credentials(
                &configured_options.username,
                &tunnel.auth_token,
                &tunnel.auth_token_user,
                &credential_options.username,
            );
        }
        let _ = handle.dialer.deactivate();
        if let Ok(mut running_network) = handle.network.lock() {
            running_network.take();
        }
        if let Ok(mut running_client) = handle.client.lock()
            && let Some(client) = running_client.take()
        {
            client.active.close();
        }

        let mut retry_immediately = false;
        loop {
            if !retry_immediately {
                tokio::select! {
                    _ = cancellation.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(OPENVPN_RECONNECT_MAXIMUM_BACKOFF);
            }
            retry_immediately = false;
            let mut reconnect_options = credential_options.clone();
            let using_auth_token = if let Some((username, password)) =
                active_auth_token.as_ref()
            {
                reconnect_options.username.clone_from(username);
                reconnect_options.password.clone_from(password);
                true
            } else {
                false
            };
            handle.challenge_manager.note_credentials_sent(
                !using_auth_token && credential_interactive,
            );
            let connector = endpoint_openvpn_connector(
                reconnect_options.clone(),
                &base_path,
                transport_dialer.clone(),
                &handle,
            );
            let challenge_context = ClientPullChallengeContext {
                manager: handle.challenge_manager.clone(),
                owner: 1,
                username: reconnect_options.username.clone(),
                cancellation: cancellation.clone(),
            };
            let connection = tokio::select! {
                _ = cancellation.cancelled() => return,
                connection = connector.connect_at_cursor(&cursor, Some(&challenge_context)) => connection,
            };
            let client = match connection {
                Ok(client) => Arc::new(client),
                Err(error) => {
                    let auth_failure =
                        openvpn_client_auth_failure_info(&error).cloned();
                    if let Some(info) = auth_failure.as_ref()
                        && !info.temporary
                    {
                        if using_auth_token {
                            active_auth_token = None;
                        } else if let Some(challenge) =
                            parse_crv1_challenge(&info.reason)
                        {
                            if handle
                                .challenge_manager
                                .sent_interactive_credentials()
                            {
                                handle
                                    .challenge_manager
                                    .note_previous_auth_failure(
                                        "OpenVPN authentication failed",
                                    );
                            }
                            let rejected_username =
                                reconnect_options.username.clone();
                            credential_options = configured_options.clone();
                            credential_options.username =
                                if challenge.username.is_empty() {
                                    rejected_username
                                } else {
                                    challenge.username.clone()
                                };
                            if let Err(challenge_error) =
                                acquire_dynamic_challenge_credentials(
                                    &mut credential_options,
                                    &handle.challenge_manager,
                                    challenge,
                                    cancellation.clone(),
                                )
                                .await
                            {
                                if let Ok(mut last_error) =
                                    handle.last_error.write()
                                {
                                    *last_error =
                                        Some(challenge_error.to_string());
                                }
                                return;
                            }
                            credential_interactive = true;
                            backoff = OPENVPN_RECONNECT_INITIAL_BACKOFF;
                            retry_immediately = true;
                            continue;
                        } else {
                            match resolve_auth_retry_mode(
                                &configured_options.auth_retry,
                            ) {
                                AuthRetryMode::None => {
                                    if let Ok(mut last_error) =
                                        handle.last_error.write()
                                    {
                                        *last_error = Some(error.to_string());
                                    }
                                    return;
                                }
                                AuthRetryMode::Interact
                                    if handle
                                        .challenge_manager
                                        .sent_interactive_credentials() =>
                                {
                                    handle
                                        .challenge_manager
                                        .note_previous_auth_failure(
                                            if info.reason.is_empty() {
                                                "OpenVPN authentication failed"
                                            } else {
                                                &info.reason
                                            },
                                        );
                                    credential_options =
                                        configured_options.clone();
                                    handle
                                        .challenge_manager
                                        .note_credentials_sent(false);
                                    if let Err(challenge_error) =
                                        acquire_static_challenge_credentials(
                                            &mut credential_options,
                                            &handle.challenge_manager,
                                            cancellation.clone(),
                                        )
                                        .await
                                    {
                                        if let Ok(mut last_error) =
                                            handle.last_error.write()
                                        {
                                            *last_error = Some(
                                                challenge_error.to_string(),
                                            );
                                        }
                                        return;
                                    }
                                    credential_interactive = handle
                                        .challenge_manager
                                        .sent_interactive_credentials();
                                    backoff = OPENVPN_RECONNECT_INITIAL_BACKOFF;
                                    retry_immediately = true;
                                    continue;
                                }
                                AuthRetryMode::NoInteract
                                | AuthRetryMode::Interact => {}
                            }
                        }
                    }
                    let policy = openvpn_client_reconnect_policy(&error, false);
                    cursor.advance(policy.advance);
                    backoff = backoff.max(policy.minimum_backoff);
                    if let Ok(mut last_error) = handle.last_error.write() {
                        *last_error = Some(error.to_string());
                    }
                    continue;
                }
            };
            let configuration = client.tunnel_configuration();
            let network = match OpenVpnClientNetwork::start(
                client.clone(),
                handle.dialer.packet_port.clone(),
                &handle.flow,
            ) {
                Ok(network) => network,
                Err(error) => {
                    client.active.close();
                    if let Ok(mut last_error) = handle.last_error.write() {
                        *last_error = Some(error.to_string());
                    }
                    cursor.advance(ClientRemoteAdvance::NextAddress);
                    continue;
                }
            };
            if let Err(error) = handle.dialer.activate(
                network.net.clone(),
                &configuration,
                network.packet_output.clone(),
            ) {
                client.active.close();
                if let Ok(mut last_error) = handle.last_error.write() {
                    *last_error = Some(error.to_string());
                }
                cursor.advance(ClientRemoteAdvance::NextAddress);
                continue;
            }
            let installed = match (handle.client.lock(), handle.network.lock())
            {
                (Ok(mut running_client), Ok(mut running_network)) => {
                    *running_client = Some(client);
                    *running_network = Some(network);
                    true
                }
                _ => false,
            };
            if !installed {
                let _ = handle.dialer.deactivate();
                return;
            }
            if let Ok(mut last_error) = handle.last_error.write() {
                last_error.take();
            }
            backoff = OPENVPN_RECONNECT_INITIAL_BACKOFF;
            break;
        }
    }
}

fn signal_network_failure(
    failure: &CancellationToken,
    message: &Mutex<Option<OpenVpnClientFailure>>,
    error: OpenVpnClientFailure,
) {
    if let Ok(mut message) = message.lock()
        && message.is_none()
    {
        *message = Some(error);
    }
    failure.cancel();
}

fn initialized_reconnect_policy() -> OpenVpnClientReconnectPolicy {
    OpenVpnClientReconnectPolicy {
        advance: ClientRemoteAdvance::Stay,
        minimum_backoff: Duration::ZERO,
    }
}

fn endpoint_openvpn_connector(
    options: OpenVpnClientEndpointOptions,
    base_path: &Path,
    transport_dialer: Arc<dyn Dialer>,
    handle: &OpenVpnClientEndpointHandle,
) -> OpenVpnClientConnector {
    let connector =
        OpenVpnClientConnector::new(options, base_path, transport_dialer);
    match &handle.dialer.resolver {
        Some(resolver) => connector
            .with_remote_resolver(resolver.clone(), handle.dialer.strategy),
        None => connector,
    }
}

async fn connect_openvpn_static_client(
    connector: &OpenVpnClientConnector,
    cursor: &OpenVpnClientConnectionCursor,
    options: &OpenVpnClientEndpointOptions,
    base_path: &Path,
) -> Result<
    (Arc<OpenVpnStaticDataSession>, TunnelConfiguration),
    OpenVpnStaticClientConnectError,
> {
    let OpenVpnClientPacketConnection {
        transport,
        remote,
        destination,
    } = connector.dial_at_cursor(cursor).await?;
    let compression = resolve_compression_settings(
        &options.compression,
        &options.compression_lzo,
    )?;
    let allow_compression = resolve_allow_compression_policy(
        &options.allow_compression,
        compression,
    )?;
    let static_key_material = load_openvpn_static_key_material(
        &options.static_key,
        &options.static_key_path,
        base_path,
    )?;
    let remote_ip = match destination {
        SocksAddr::Ip(address) => Some(address.ip()),
        SocksAddr::Domain { .. } => None,
    };
    let session = Arc::new(OpenVpnStaticDataSession::new(
        transport,
        OpenVpnStaticDataSessionOptions {
            static_key_material,
            key_direction: resolve_openvpn_key_direction(
                &options.key_direction,
            ),
            cipher: options.cipher.clone(),
            auth: if options.auth.is_empty() {
                "SHA1".into()
            } else {
                options.auth.clone()
            },
            replay_window_size: options.replay_window,
            replay_window_time: options
                .replay_window_time
                .as_std()
                .unwrap_or_default(),
            framing: DataChannelFraming::new(
                compression,
                options.fragment,
                allow_compression,
            ),
            fragment: options.fragment,
            mss_fix: if options.mss_fix_disabled {
                0
            } else {
                options.mss_fix
            },
            mss_fix_mode: options.mss_fix_mode.clone(),
            transport_network: remote.network,
            remote_ip,
            ping_interval: options.ping_interval.as_std().unwrap_or_default(),
            ping_restart: if options.ping_restart_disabled {
                Duration::ZERO
            } else {
                options.ping_restart.as_std().unwrap_or_default()
            },
        },
    )?);
    let mut configuration =
        build_openvpn_client_tunnel_state(options).configuration();
    configuration.topology = if options.topology.is_empty() {
        "p2p".into()
    } else {
        options.topology.clone()
    };
    configuration.selected_cipher.clone_from(&options.cipher);
    configuration.selected_auth = if options.auth.is_empty() {
        "SHA1".into()
    } else {
        options.auth.clone()
    };
    configuration.ping_restart = if options.ping_restart_disabled {
        Duration::ZERO
    } else {
        options.ping_restart.as_std().unwrap_or_default()
    };
    Ok((session, configuration))
}

#[derive(Debug, thiserror::Error)]
enum OpenVpnStaticClientConnectError {
    #[error(transparent)]
    Connector(#[from] crate::protocol::openvpn::OpenVpnClientConnectorError),
    #[error(transparent)]
    Build(#[from] OpenVpnEndpointBuildError),
    #[error(transparent)]
    Compression(#[from] crate::protocol::openvpn::CompressionError),
    #[error(transparent)]
    Session(#[from] StaticDataSessionError),
}

async fn maintain_openvpn_static_client(
    options: OpenVpnClientEndpointOptions,
    base_path: PathBuf,
    transport_dialer: Arc<dyn Dialer>,
    handle: OpenVpnClientEndpointHandle,
    cancellation: CancellationToken,
    mut cursor: OpenVpnClientConnectionCursor,
) {
    let mut backoff = OPENVPN_RECONNECT_INITIAL_BACKOFF;
    loop {
        let network = match handle.network.lock() {
            Ok(network) => network.clone(),
            Err(_) => return,
        };
        let Some(network) = network else { return };
        let failure = tokio::select! {
            _ = cancellation.cancelled() => return,
            failure = network.wait_failure() => failure,
        };
        if let Ok(mut last_error) = handle.last_error.write() {
            *last_error = Some(failure.message);
        }
        cursor.advance(failure.policy.advance);
        let _ = handle.dialer.deactivate();
        if let Ok(mut running_network) = handle.network.lock() {
            running_network.take();
        }
        if let Ok(mut running_session) = handle.static_session.lock()
            && let Some(session) = running_session.take()
        {
            session.close();
        }
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(OPENVPN_RECONNECT_MAXIMUM_BACKOFF);
            let connector = endpoint_openvpn_connector(
                options.clone(),
                &base_path,
                transport_dialer.clone(),
                &handle,
            );
            let connected = tokio::select! {
                _ = cancellation.cancelled() => return,
                connected = connect_openvpn_static_client(
                    &connector,
                    &cursor,
                    &options,
                    &base_path,
                ) => connected,
            };
            let (session, configuration) = match connected {
                Ok(connected) => connected,
                Err(OpenVpnStaticClientConnectError::Connector(error)) => {
                    let policy = openvpn_client_reconnect_policy(&error, false);
                    cursor.advance(policy.advance);
                    backoff = backoff.max(policy.minimum_backoff);
                    if let Ok(mut last_error) = handle.last_error.write() {
                        *last_error = Some(error.to_string());
                    }
                    continue;
                }
                Err(error) => {
                    if let Ok(mut last_error) = handle.last_error.write() {
                        *last_error = Some(error.to_string());
                    }
                    return;
                }
            };
            let network = match OpenVpnClientNetwork::start_static(
                session.clone(),
                configuration.clone(),
                handle.dialer.packet_port.clone(),
                &handle.flow,
            ) {
                Ok(network) => network,
                Err(error) => {
                    session.close();
                    cursor.advance(ClientRemoteAdvance::NextAddress);
                    if let Ok(mut last_error) = handle.last_error.write() {
                        *last_error = Some(error.to_string());
                    }
                    continue;
                }
            };
            if let Err(error) = handle.dialer.activate(
                network.net.clone(),
                &configuration,
                network.packet_output.clone(),
            ) {
                session.close();
                cursor.advance(ClientRemoteAdvance::NextAddress);
                if let Ok(mut last_error) = handle.last_error.write() {
                    *last_error = Some(error.to_string());
                }
                continue;
            }
            let installed = match (
                handle.static_session.lock(),
                handle.network.lock(),
                handle.tunnel_configuration.write(),
            ) {
                (Ok(mut active), Ok(mut running_network), Ok(mut tunnel)) => {
                    *active = Some(session);
                    *running_network = Some(network);
                    *tunnel = Some(configuration);
                    true
                }
                _ => false,
            };
            if !installed {
                let _ = handle.dialer.deactivate();
                return;
            }
            if let Ok(mut last_error) = handle.last_error.write() {
                last_error.take();
            }
            backoff = OPENVPN_RECONNECT_INITIAL_BACKOFF;
            break;
        }
    }
}

fn lock<'a, T>(
    mutex: &'a Mutex<T>,
    name: &str,
) -> Result<std::sync::MutexGuard<'a, T>, LifecycleError> {
    mutex.lock().map_err(|_| LifecycleError::Close {
        component: name.into(),
        message: format!("{name} lock poisoned"),
    })
}

fn write_rw<'a, T>(
    lock: &'a RwLock<T>,
    name: &str,
) -> Result<std::sync::RwLockWriteGuard<'a, T>, LifecycleError> {
    lock.write().map_err(|_| LifecycleError::Close {
        component: name.into(),
        message: format!("{name} lock poisoned"),
    })
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::openvpn::ChallengeResponse;

    #[tokio::test]
    async fn pushed_block_ipv6_rejects_dials_and_drops_tun_packets() {
        let packet_port = Arc::new(OpenVpnPacketPort::default());
        let (output, mut packets) = tokio::sync::mpsc::channel(2);
        packet_port
            .activate(
                output,
                &TunnelConfiguration {
                    block_ipv6: true,
                    ..TunnelConfiguration::default()
                },
            )
            .unwrap();
        let dialer = OpenVpnClientDialer {
            net: RwLock::default(),
            resolver: None,
            strategy: DomainStrategy::AsIs,
            packet_port: packet_port.clone(),
        };
        let ipv6 =
            SocksAddr::from("[2001:db8::1]:443".parse::<SocketAddr>().unwrap());
        let error = dialer.resolve(&ipv6).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NetworkUnreachable);
        assert!(error.to_string().contains("block-ipv6"));

        let mut ipv6_packet = vec![0_u8; 40];
        ipv6_packet[0] = 0x60;
        let mut ipv4_packet = vec![0_u8; 20];
        ipv4_packet[0] = 0x45;
        packet_port
            .write_packets(vec![ipv6_packet, ipv4_packet.clone()])
            .await
            .unwrap();
        assert_eq!(packets.recv().await.unwrap(), ipv4_packet);
        assert!(packets.try_recv().is_err());
    }

    #[test]
    fn negotiated_routes_and_domains_drive_endpoint_preference() {
        use crate::protocol::openvpn::{
            OpenVpnIpPrefix, TunnelDnsServer, TunnelRoute,
        };

        let route = |address, prefix_len| TunnelRoute {
            prefix: OpenVpnIpPrefix {
                address,
                prefix_len,
            },
            gateway: None,
            metric: 0,
        };
        let mut configuration = TunnelConfiguration {
            ipv4_routes: vec![route("10.0.0.0".parse().unwrap(), 8)],
            excluded_ipv4_routes: vec![route("10.20.0.0".parse().unwrap(), 16)],
            dns_routes: vec!["corp.example".into()],
            search_domains: vec!["search.example.".into()],
            ..TunnelConfiguration::default()
        };
        configuration.dns_servers = vec![
            TunnelDnsServer {
                priority: 20,
                addresses: Vec::new(),
                resolve_domains: vec!["later.example".into()],
                dnssec: String::new(),
                transport: String::new(),
                sni: String::new(),
            },
            TunnelDnsServer {
                priority: 10,
                addresses: Vec::new(),
                resolve_domains: vec!["first.example".into()],
                dnssec: String::new(),
                transport: String::new(),
                sni: String::new(),
            },
        ];
        let packet_port = OpenVpnPacketPort::default();
        let (output, _packets) = tokio::sync::mpsc::channel(1);
        packet_port.activate(output, &configuration).unwrap();

        assert!(packet_port.preferred_address("10.1.2.3".parse().unwrap()));
        assert!(!packet_port.preferred_address("10.20.1.2".parse().unwrap()));
        assert!(packet_port.preferred_domain("host.corp.example"));
        assert!(packet_port.preferred_domain("SEARCH.EXAMPLE"));
        assert!(packet_port.preferred_domain("a.first.example"));
        assert!(!packet_port.preferred_domain("a.later.example"));
        assert!(openvpn_domain_matches(".", "anything.example"));
    }

    #[tokio::test]
    async fn static_challenge_is_exposed_and_packed_as_scrv1() {
        let manager = Arc::new(ChallengeManager::default());
        let mut updates = manager.subscribe();
        let task_manager = manager.clone();
        let task = tokio::spawn(async move {
            let mut options: OpenVpnClientEndpointOptions =
                serde_json::from_value(serde_json::json!({
                    "server": "vpn.test",
                    "server_port": 1194,
                    "username": "alice",
                    "password": "password",
                    "static_challenge": "One-time password",
                    "static_challenge_echo": true,
                    "tls": {
                        "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                }))
                .unwrap();
            acquire_static_challenge_credentials(
                &mut options,
                &task_manager,
                CancellationToken::new(),
            )
            .await
            .unwrap();
            options
        });
        updates.changed().await.unwrap();
        let challenge = manager.pending().unwrap();
        assert_eq!(challenge.kind, ChallengeKind::Secret);
        assert_eq!(challenge.message, "One-time password");
        assert!(challenge.echo);
        manager
            .complete(
                &challenge.id,
                ChallengeResponse {
                    secret: "123456".into(),
                    ..ChallengeResponse::default()
                },
            )
            .await
            .unwrap();
        let options = task.await.unwrap();
        assert_eq!(options.username, "alice");
        assert_eq!(options.password, "SCRV1:cGFzc3dvcmQ=:MTIzNDU2");
        assert!(manager.sent_interactive_credentials());
    }
}
