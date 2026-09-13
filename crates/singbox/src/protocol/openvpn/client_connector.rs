use std::{io, path::PathBuf, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Dialer,
    common::network::SocksAddr,
    dns::manager::SharedResolver,
    option::{DomainStrategy, OpenVpnClientEndpointOptions},
};

use super::{
    AllowCompressionPolicy, AuthFailedAdvance, AuthFailedInfo,
    ClientPullChallengeContext, ClientPullError, ClientPullOptions,
    ClientPullResult, ClientPullStateError, ClientRemoteAdvance,
    ClientTlsDataChannelOptions, ClientTunnelState, CompressionError,
    CompressionSettings, DataChannelFraming, IncomingControlEvent,
    OpenVpnActiveDataSession, OpenVpnClientSecurity, OpenVpnEndpointBuildError,
    OpenVpnIpPrefix, OpenVpnPacketTransport, OpenVpnTlsSession, Packet,
    PullFilter, SoftResetCoordinator, SoftResetStateError,
    TlsClientNegotiationError, TlsKeyMethodMessage, TlsSessionError,
    TunnelConfiguration, TunnelRoute, advertised_data_ciphers,
    build_openvpn_client_security, build_tls_client_peer_info,
    build_tls_options_string, dial_openvpn_packet_transport,
    establish_tls_client_renegotiation,
    establish_tls_client_renegotiation_from_reset,
    establish_tls_client_session,
    negotiate_tls_client_data_channel_with_challenges,
    negotiate_tls_client_renegotiation_data_channel,
    resolve_allow_compression_policy, resolve_compression_settings,
    split_local_address_prefixes, split_tunnel_routes,
};

pub const OPENVPN_DEFAULT_TLS_TIMEOUT: Duration = Duration::from_secs(2);
pub const OPENVPN_DEFAULT_HANDSHAKE_WINDOW: Duration = Duration::from_secs(60);
pub const OPENVPN_DEFAULT_RENEGOTIATION_INTERVAL: Duration =
    Duration::from_secs(3600);
pub const OPENVPN_PRE_PULL_UDP_PING_RESTART: Duration =
    Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnClientRemote {
    pub destination: SocksAddr,
    pub network: String,
}

pub fn openvpn_client_remotes(
    options: &OpenVpnClientEndpointOptions,
) -> Vec<OpenVpnClientRemote> {
    let default_network = options.normalized_network();
    if !options.server.server.is_empty() {
        return vec![OpenVpnClientRemote {
            destination: SocksAddr::new(
                options.server.server.clone(),
                options.server.server_port,
            ),
            network: default_network.to_owned(),
        }];
    }
    options
        .servers
        .iter()
        .map(|remote| OpenVpnClientRemote {
            destination: SocksAddr::new(
                remote.server.server.clone(),
                remote.server.server_port,
            ),
            network: if remote.network.is_empty() {
                default_network.to_owned()
            } else {
                remote.network.clone()
            },
        })
        .collect()
}

/// Stable remote/address position used by the long-lived client supervisor.
/// `remote-random` is applied once when the cursor is created, rather than on
/// every reconnect attempt.
#[derive(Debug, Clone)]
pub struct OpenVpnClientConnectionCursor {
    remotes: Vec<OpenVpnClientRemote>,
    remote_index: usize,
    address_index: usize,
}

impl OpenVpnClientConnectionCursor {
    pub fn new(options: &OpenVpnClientEndpointOptions) -> Self {
        let mut remotes = openvpn_client_remotes(options);
        if options.remote_random {
            shuffle_remotes(&mut remotes);
        }
        Self {
            remotes,
            remote_index: 0,
            address_index: 0,
        }
    }

    pub fn current(&self) -> Option<&OpenVpnClientRemote> {
        self.remotes.get(self.remote_index)
    }

    pub fn remote_index(&self) -> usize {
        self.remote_index
    }

    pub fn address_index(&self) -> usize {
        self.address_index
    }

    pub fn advance(&mut self, advance: ClientRemoteAdvance) {
        match advance {
            ClientRemoteAdvance::Stay => {}
            ClientRemoteAdvance::NextAddress => {
                self.address_index = self.address_index.saturating_add(1);
            }
            ClientRemoteAdvance::NextRemote => {
                if !self.remotes.is_empty() {
                    self.remote_index =
                        (self.remote_index + 1) % self.remotes.len();
                }
                self.address_index = 0;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenVpnClientReconnectPolicy {
    pub advance: ClientRemoteAdvance,
    pub minimum_backoff: Duration,
}

/// Preserve the server-directed retry metadata before an endpoint turns an
/// error into user-facing text. This mirrors sing-openvpn's
/// `nextConnectionCursor` and `applyClientSessionErrorBackoff` rules.
pub fn openvpn_client_reconnect_policy(
    error: &OpenVpnClientConnectorError,
    initialized: bool,
) -> OpenVpnClientReconnectPolicy {
    let mut policy = OpenVpnClientReconnectPolicy {
        advance: if initialized {
            ClientRemoteAdvance::Stay
        } else {
            ClientRemoteAdvance::NextAddress
        },
        minimum_backoff: Duration::ZERO,
    };
    match error {
        OpenVpnClientConnectorError::RemoteAddressExhausted { .. } => {
            policy.advance = ClientRemoteAdvance::NextRemote;
        }
        OpenVpnClientConnectorError::Negotiation(
            TlsClientNegotiationError::Pull(ClientPullError::State(state)),
        ) => match state {
            ClientPullStateError::ServerRestart { advance } => {
                policy.advance = *advance;
            }
            ClientPullStateError::AuthenticationFailed(info)
                if info.temporary =>
            {
                policy.advance = match info.advance {
                    AuthFailedAdvance::Stay => ClientRemoteAdvance::Stay,
                    AuthFailedAdvance::NextAddress => {
                        ClientRemoteAdvance::NextAddress
                    }
                    AuthFailedAdvance::NextRemote => {
                        ClientRemoteAdvance::NextRemote
                    }
                };
                policy.minimum_backoff =
                    Duration::from_secs(u64::from(info.backoff_seconds));
            }
            _ => {}
        },
        _ => {}
    }
    policy
}

pub fn openvpn_client_auth_failure_info(
    error: &OpenVpnClientConnectorError,
) -> Option<&AuthFailedInfo> {
    match error {
        OpenVpnClientConnectorError::Negotiation(
            TlsClientNegotiationError::Pull(ClientPullError::State(
                ClientPullStateError::AuthenticationFailed(info),
            )),
        ) => Some(info),
        _ => None,
    }
}

pub struct OpenVpnClientConnection {
    pub session: OpenVpnTlsSession,
    pub transport: Arc<dyn OpenVpnPacketTransport>,
    pub security: OpenVpnClientSecurity,
    pub remote: OpenVpnClientRemote,
}

pub struct OpenVpnClientNegotiationPlan {
    pub key_method: TlsKeyMethodMessage,
    pub pull: ClientPullOptions,
    pub data: ClientTlsDataChannelOptions,
    pub compression: CompressionSettings,
    pub allow_compression: AllowCompressionPolicy,
    pub fragment_size: usize,
}

pub struct OpenVpnConnectedClient {
    pub active: OpenVpnActiveDataSession,
    pub pull: ClientPullResult,
    pub security: OpenVpnClientSecurity,
    pub remote: OpenVpnClientRemote,
    options: OpenVpnClientEndpointOptions,
    soft_resets: Mutex<SoftResetCoordinator>,
    tunnel: Mutex<ClientTunnelState>,
}

impl OpenVpnConnectedClient {
    pub fn tunnel_configuration(&self) -> TunnelConfiguration {
        self.tunnel.lock().configuration()
    }

    /// Performs one complete locally initiated soft reset.  The method is the
    /// atomic building block used by an endpoint supervisor for interval and
    /// data-budget driven renegotiation.
    pub async fn renegotiate(
        &self,
    ) -> Result<bool, OpenVpnClientConnectorError> {
        let now = std::time::Instant::now();
        let reset = self.soft_resets.lock().begin_local(now)?;
        if !reset.created {
            return Ok(false);
        }
        let plan =
            build_openvpn_client_negotiation_plan(&self.options, &self.remote)?;
        let handshake_window = positive_or(
            self.options.handshake_window.as_std(),
            OPENVPN_DEFAULT_HANDSHAKE_WINDOW,
        );
        let session = establish_tls_client_renegotiation(
            &self.active.tls_session().control,
            &self.active.tls_session().session,
            &self.security.tls_context,
            &self.security.control_protection,
            reset.key_id,
            handshake_window,
            self.remote.network.ends_with('6'),
        )
        .await;
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                let _ = self
                    .soft_resets
                    .lock()
                    .finish_failed(reset.key_id, reset.sequence);
                return Err(error.into());
            }
        };
        let negotiated = negotiate_tls_client_renegotiation_data_channel(
            session,
            plan.key_method,
            &self.pull.selected_cipher,
            &self.pull.selected_auth,
            plan.data,
        )
        .await;
        let negotiated = match negotiated {
            Ok(negotiated) => negotiated,
            Err(error) => {
                let _ = self
                    .soft_resets
                    .lock()
                    .finish_failed(reset.key_id, reset.sequence);
                return Err(error.into());
            }
        };
        let promoted = self
            .active
            .install_client_renegotiation(
                reset.sequence,
                negotiated,
                std::time::Instant::now(),
            )
            .await;
        let promoted = match promoted {
            Ok(promoted) => promoted,
            Err(error) => {
                let _ = self
                    .soft_resets
                    .lock()
                    .finish_failed(reset.key_id, reset.sequence);
                return Err(error.into());
            }
        };
        let coordinator_promoted = self.soft_resets.lock().finish_success(
            reset.key_id,
            reset.sequence,
            std::time::Instant::now(),
        )?;
        Ok(promoted && coordinator_promoted)
    }

    /// Accepts a peer-initiated `P_CONTROL_SOFT_RESET_V1` while retaining the
    /// client TLS role and promoting the newly derived traffic key.
    pub async fn accept_remote_renegotiation(
        &self,
        soft_reset: &Packet,
    ) -> Result<bool, OpenVpnClientConnectorError> {
        let reset = self
            .soft_resets
            .lock()
            .begin_remote(soft_reset.key_id, std::time::Instant::now())?;
        if !reset.created {
            return Ok(false);
        }
        let plan =
            build_openvpn_client_negotiation_plan(&self.options, &self.remote)?;
        let handshake_window = positive_or(
            self.options.handshake_window.as_std(),
            OPENVPN_DEFAULT_HANDSHAKE_WINDOW,
        );
        let session = establish_tls_client_renegotiation_from_reset(
            &self.active.tls_session().control,
            &self.active.tls_session().session,
            &self.security.tls_context,
            &self.security.control_protection,
            soft_reset,
            handshake_window,
            self.remote.network.ends_with('6'),
        )
        .await;
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                let _ = self
                    .soft_resets
                    .lock()
                    .finish_failed(reset.key_id, reset.sequence);
                return Err(error.into());
            }
        };
        let negotiated = negotiate_tls_client_renegotiation_data_channel(
            session,
            plan.key_method,
            &self.pull.selected_cipher,
            &self.pull.selected_auth,
            plan.data,
        )
        .await;
        let negotiated = match negotiated {
            Ok(negotiated) => negotiated,
            Err(error) => {
                let _ = self
                    .soft_resets
                    .lock()
                    .finish_failed(reset.key_id, reset.sequence);
                return Err(error.into());
            }
        };
        let promoted = self
            .active
            .install_client_renegotiation(
                reset.sequence,
                negotiated,
                std::time::Instant::now(),
            )
            .await;
        let promoted = match promoted {
            Ok(promoted) => promoted,
            Err(error) => {
                let _ = self
                    .soft_resets
                    .lock()
                    .finish_failed(reset.key_id, reset.sequence);
                return Err(error.into());
            }
        };
        let coordinator_promoted = self.soft_resets.lock().finish_success(
            reset.key_id,
            reset.sequence,
            std::time::Instant::now(),
        )?;
        Ok(promoted && coordinator_promoted)
    }

    pub async fn handle_next_remote_reset(
        &self,
    ) -> Result<bool, OpenVpnClientConnectorError> {
        match self.active.next_reset_event().await? {
            IncomingControlEvent::SoftReset(packet) => {
                self.accept_remote_renegotiation(&packet).await
            }
            IncomingControlEvent::HardReset(_) => {
                Err(OpenVpnClientConnectorError::SessionRestartRequired)
            }
            IncomingControlEvent::TlsCiphertext(_)
            | IncomingControlEvent::Data(_) => {
                Err(OpenVpnClientConnectorError::UnexpectedControlEvent)
            }
        }
    }

    /// Drives all in-session client rekey triggers. Returning an error asks
    /// the outer endpoint lifecycle to reconnect/fail over to another remote.
    pub async fn run_renegotiation_supervisor(
        self: Arc<Self>,
        cancellation: CancellationToken,
    ) -> Result<(), OpenVpnClientConnectorError> {
        let renegotiation_interval = if self.options.renegotiate_disabled {
            Duration::ZERO
        } else {
            positive_or(
                self.options.renegotiate_interval.as_std(),
                OPENVPN_DEFAULT_RENEGOTIATION_INTERVAL,
            )
        };
        let interval_enabled = !renegotiation_interval.is_zero();
        let timer_period = if interval_enabled {
            renegotiation_interval
        } else {
            OPENVPN_DEFAULT_RENEGOTIATION_INTERVAL
        };
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + timer_period,
            timer_period,
        );
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut budget_poll = tokio::time::interval(Duration::from_millis(100));
        budget_poll
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        budget_poll.tick().await;
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                reset = self.handle_next_remote_reset() => {
                    reset?;
                }
                _ = interval.tick(), if interval_enabled => {
                    self.renegotiate().await?;
                }
                _ = budget_poll.tick() => {
                    if self.active.take_renegotiation_request() {
                        self.renegotiate().await?;
                    }
                }
            }
        }
    }
}

pub struct OpenVpnClientConnector {
    options: OpenVpnClientEndpointOptions,
    base_path: PathBuf,
    dialer: Arc<dyn Dialer>,
    remote_resolver: Option<SharedResolver>,
    remote_strategy: DomainStrategy,
}

pub struct OpenVpnClientPacketConnection {
    pub transport: Arc<dyn OpenVpnPacketTransport>,
    pub remote: OpenVpnClientRemote,
    pub destination: SocksAddr,
}

impl OpenVpnClientConnector {
    pub fn new(
        options: OpenVpnClientEndpointOptions,
        base_path: impl Into<PathBuf>,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self {
            options,
            base_path: base_path.into(),
            dialer,
            remote_resolver: None,
            remote_strategy: DomainStrategy::AsIs,
        }
    }

    pub fn with_remote_resolver(
        mut self,
        resolver: SharedResolver,
        strategy: DomainStrategy,
    ) -> Self {
        self.remote_resolver = Some(resolver);
        self.remote_strategy = strategy;
        self
    }

    pub fn options(&self) -> &OpenVpnClientEndpointOptions {
        &self.options
    }

    pub fn connection_cursor(
        &self,
    ) -> Result<OpenVpnClientConnectionCursor, OpenVpnClientConnectorError>
    {
        self.options.validate().map_err(|error| {
            OpenVpnClientConnectorError::Options(error.to_string())
        })?;
        Ok(OpenVpnClientConnectionCursor::new(&self.options))
    }

    async fn resolve_cursor_destination(
        &self,
        remote: &OpenVpnClientRemote,
        address_index: usize,
    ) -> Result<SocksAddr, OpenVpnClientConnectorError> {
        let SocksAddr::Domain { host, port } = &remote.destination else {
            if address_index == 0 {
                return Ok(remote.destination.clone());
            }
            return Err(OpenVpnClientConnectorError::RemoteAddressExhausted {
                remote: remote.destination.clone(),
                address_index,
            });
        };
        let mut addresses = match &self.remote_resolver {
            Some(resolver) => {
                resolver.lookup(host, self.remote_strategy).await?
            }
            None => remote
                .destination
                .resolve()
                .await?
                .into_iter()
                .map(|address| address.ip())
                .collect(),
        };
        if remote.network.ends_with('4') {
            addresses.retain(std::net::IpAddr::is_ipv4);
        } else if remote.network.ends_with('6') {
            addresses.retain(std::net::IpAddr::is_ipv6);
        }
        let address =
            addresses.get(address_index).copied().ok_or_else(|| {
                OpenVpnClientConnectorError::RemoteAddressExhausted {
                    remote: remote.destination.clone(),
                    address_index,
                }
            })?;
        Ok(SocksAddr::from(std::net::SocketAddr::new(address, *port)))
    }

    /// Establish exactly the remote and resolved-address position selected by
    /// the persistent supervisor cursor.
    pub async fn dial_at_cursor(
        &self,
        cursor: &OpenVpnClientConnectionCursor,
    ) -> Result<OpenVpnClientPacketConnection, OpenVpnClientConnectorError>
    {
        self.options.validate().map_err(|error| {
            OpenVpnClientConnectorError::Options(error.to_string())
        })?;
        let remote = cursor.current().cloned().ok_or_else(|| {
            OpenVpnClientConnectorError::Options(
                "OpenVPN client has no remotes".into(),
            )
        })?;
        let destination = self
            .resolve_cursor_destination(&remote, cursor.address_index())
            .await?;
        let network = if remote.network.starts_with("tcp") {
            "tcp"
        } else {
            "udp"
        };
        let transport = dial_openvpn_packet_transport(
            self.dialer.as_ref(),
            &destination,
            network,
            u16::MAX as usize,
        )
        .await?;
        Ok(OpenVpnClientPacketConnection {
            transport,
            remote,
            destination,
        })
    }

    /// Establish exactly the remote and resolved-address position selected by
    /// the persistent supervisor cursor.
    pub async fn connect_tls_at_cursor(
        &self,
        cursor: &OpenVpnClientConnectionCursor,
    ) -> Result<OpenVpnClientConnection, OpenVpnClientConnectorError> {
        if self.options.normalized_mode() != "tls" {
            return Err(OpenVpnClientConnectorError::UnsupportedMode(
                self.options.normalized_mode().to_owned(),
            ));
        }
        let connection = self.dial_at_cursor(cursor).await?;
        let security =
            build_openvpn_client_security(&self.options, &self.base_path)?;
        let session = establish_tls_client_session(
            connection.transport.clone(),
            &security.tls_context,
            security.control_protection.new_session_protection(),
            security.wrapped_client_key.clone(),
            positive_or(
                self.options.tls_timeout.as_std(),
                OPENVPN_DEFAULT_TLS_TIMEOUT,
            ),
            positive_or(
                self.options.handshake_window.as_std(),
                OPENVPN_DEFAULT_HANDSHAKE_WINDOW,
            ),
            connection.remote.network.ends_with('6'),
        )
        .await?;
        Ok(OpenVpnClientConnection {
            session,
            transport: connection.transport,
            security,
            remote: connection.remote,
        })
    }

    /// Tries every configured remote and returns the first completed hard
    /// reset + TLS session. A failed remote never poisons the next attempt's
    /// control replay/packet-id state because security is rebuilt per attempt.
    pub async fn connect_tls(
        &self,
    ) -> Result<OpenVpnClientConnection, OpenVpnClientConnectorError> {
        self.options.validate().map_err(|error| {
            OpenVpnClientConnectorError::Options(error.to_string())
        })?;
        let mut remotes = openvpn_client_remotes(&self.options);
        if self.options.remote_random {
            shuffle_remotes(&mut remotes);
        }
        let tls_timeout = positive_or(
            self.options.tls_timeout.as_std(),
            OPENVPN_DEFAULT_TLS_TIMEOUT,
        );
        let handshake_window = positive_or(
            self.options.handshake_window.as_std(),
            OPENVPN_DEFAULT_HANDSHAKE_WINDOW,
        );
        let mut failures = Vec::new();
        for remote in remotes {
            let network = if remote.network.starts_with("tcp") {
                "tcp"
            } else {
                "udp"
            };
            let transport = match dial_openvpn_packet_transport(
                self.dialer.as_ref(),
                &remote.destination,
                network,
                u16::MAX as usize,
            )
            .await
            {
                Ok(transport) => transport,
                Err(error) => {
                    failures.push(format!("{}: {error}", remote.destination));
                    continue;
                }
            };
            let security = match build_openvpn_client_security(
                &self.options,
                &self.base_path,
            ) {
                Ok(security) => security,
                Err(error) => return Err(error.into()),
            };
            let session = establish_tls_client_session(
                transport.clone(),
                &security.tls_context,
                security.control_protection.new_session_protection(),
                security.wrapped_client_key.clone(),
                tls_timeout,
                handshake_window,
                remote.network.ends_with('6'),
            )
            .await;
            match session {
                Ok(session) => {
                    return Ok(OpenVpnClientConnection {
                        session,
                        transport,
                        security,
                        remote,
                    });
                }
                Err(error) => failures.push(format!(
                    "{} over {}: {error}",
                    remote.destination, remote.network
                )),
            }
        }
        Err(OpenVpnClientConnectorError::AllRemotesFailed(failures))
    }

    /// Establishes the transport, reliable control/TLS channel, key-method 2,
    /// PUSH exchange and initial encrypted data channel in one reusable call.
    pub async fn connect(
        &self,
        challenge_context: Option<&ClientPullChallengeContext>,
    ) -> Result<OpenVpnConnectedClient, OpenVpnClientConnectorError> {
        let connection = self.connect_tls().await?;
        let plan = build_openvpn_client_negotiation_plan(
            &self.options,
            &connection.remote,
        )?;
        let negotiated = negotiate_tls_client_data_channel_with_challenges(
            connection.session,
            plan.key_method,
            plan.pull,
            plan.data,
            challenge_context,
        )
        .await?;
        let pull = negotiated.pull.clone();
        let active = OpenVpnActiveDataSession::from_client(
            connection.transport,
            negotiated,
            plan.fragment_size,
        );
        let mut tunnel = build_openvpn_client_tunnel_state(&self.options);
        tunnel.apply_pushed_options(&pull.options);
        Ok(OpenVpnConnectedClient {
            active,
            pull,
            security: connection.security,
            remote: connection.remote,
            options: self.options.clone(),
            soft_resets: Mutex::new(SoftResetCoordinator::new(
                0,
                positive_or(
                    self.options.handshake_window.as_std(),
                    OPENVPN_DEFAULT_HANDSHAKE_WINDOW,
                ),
            )),
            tunnel: Mutex::new(tunnel),
        })
    }

    /// Complete negotiation at the exact persistent cursor position.
    pub async fn connect_at_cursor(
        &self,
        cursor: &OpenVpnClientConnectionCursor,
        challenge_context: Option<&ClientPullChallengeContext>,
    ) -> Result<OpenVpnConnectedClient, OpenVpnClientConnectorError> {
        let connection = self.connect_tls_at_cursor(cursor).await?;
        let plan = build_openvpn_client_negotiation_plan(
            &self.options,
            &connection.remote,
        )?;
        let negotiated = negotiate_tls_client_data_channel_with_challenges(
            connection.session,
            plan.key_method,
            plan.pull,
            plan.data,
            challenge_context,
        )
        .await?;
        let pull = negotiated.pull.clone();
        let active = OpenVpnActiveDataSession::from_client(
            connection.transport,
            negotiated,
            plan.fragment_size,
        );
        let mut tunnel = build_openvpn_client_tunnel_state(&self.options);
        tunnel.apply_pushed_options(&pull.options);
        Ok(OpenVpnConnectedClient {
            active,
            pull,
            security: connection.security,
            remote: connection.remote,
            options: self.options.clone(),
            soft_resets: Mutex::new(SoftResetCoordinator::new(
                0,
                positive_or(
                    self.options.handshake_window.as_std(),
                    OPENVPN_DEFAULT_HANDSHAKE_WINDOW,
                ),
            )),
            tunnel: Mutex::new(tunnel),
        })
    }
}

pub fn build_openvpn_client_tunnel_state(
    options: &OpenVpnClientEndpointOptions,
) -> ClientTunnelState {
    let local_addresses = options
        .address
        .as_slice()
        .iter()
        .map(|prefix| OpenVpnIpPrefix {
            address: prefix.0.addr(),
            prefix_len: prefix.0.prefix_len(),
        })
        .collect::<Vec<_>>();
    let (local_ipv4, local_ipv6) =
        split_local_address_prefixes(&local_addresses);
    let routes = options
        .routes
        .as_slice()
        .iter()
        .map(|prefix| TunnelRoute {
            prefix: OpenVpnIpPrefix {
                address: prefix.0.addr(),
                prefix_len: prefix.0.prefix_len(),
            },
            gateway: None,
            metric: 0,
        })
        .collect::<Vec<_>>();
    let route_gateway = options.route_gateway.as_ref().map(|value| value.0);
    let vpn_gateway = options.peer_address.as_ref().map(|value| value.0);
    let vpn_gateway_ipv6 =
        options.peer_address_ipv6.as_ref().map(|value| value.0);
    let (ipv4_routes, ipv6_routes) = split_tunnel_routes(
        &routes,
        route_gateway,
        vpn_gateway,
        vpn_gateway_ipv6,
        options.route_metric,
    );
    let mut ping_restart = if options.ping_restart_disabled {
        Duration::ZERO
    } else {
        options.ping_restart.as_std().unwrap_or_default()
    };
    if ping_restart.is_zero()
        && !options.ping_restart_disabled
        && options.normalized_network().starts_with("udp")
    {
        ping_restart = OPENVPN_PRE_PULL_UDP_PING_RESTART;
    }
    ClientTunnelState::new(
        TunnelConfiguration {
            dev_type: "tun".into(),
            topology: options.topology.clone(),
            tun_mtu: options.endpoint.mtu,
            local_ipv4,
            local_ipv6,
            vpn_gateway,
            vpn_gateway_ipv6,
            ipv4_routes,
            ipv6_routes,
            redirect_gateway: options.redirect_gateway,
            redirect_gateway_flags: options
                .redirect_gateway_flags
                .as_slice()
                .to_vec(),
            redirect_private: options.redirect_private,
            block_ipv6: options.block_ipv6,
            route_metric: options.route_metric,
            route_gateway,
            ping_interval: options.ping_interval.as_std().unwrap_or_default(),
            ping_restart,
            explicit_exit_notify: options.explicit_exit_notify,
            ..TunnelConfiguration::default()
        },
        options.route_no_pull,
    )
}

pub fn build_openvpn_client_negotiation_plan(
    options: &OpenVpnClientEndpointOptions,
    remote: &OpenVpnClientRemote,
) -> Result<OpenVpnClientNegotiationPlan, OpenVpnClientConnectorError> {
    options.validate().map_err(|error| {
        OpenVpnClientConnectorError::Options(error.to_string())
    })?;
    if options.normalized_mode() != "tls" {
        return Err(OpenVpnClientConnectorError::UnsupportedMode(
            options.normalized_mode().to_owned(),
        ));
    }
    let compression = resolve_compression_settings(
        &options.compression,
        &options.compression_lzo,
    )?;
    let allow_compression = resolve_allow_compression_policy(
        &options.allow_compression,
        compression,
    )?;
    let configured_ciphers = options.data_ciphers.as_slice().to_vec();
    let preferred_cipher = advertised_data_ciphers(&configured_ciphers)
        .into_iter()
        .next()
        .unwrap_or_else(|| "AES-256-GCM".into());
    let selected_auth = if options.auth.is_empty() {
        "SHA1"
    } else {
        &options.auth
    };
    let tls_auth_enabled = options
        .tls
        .as_ref()
        .and_then(|tls| tls.control_wrap.as_ref())
        .is_some_and(|wrap| wrap.kind == "tls_auth");
    let local_options_string = build_tls_options_string(
        &remote.network,
        true,
        tls_auth_enabled,
        compression,
        &preferred_cipher,
        selected_auth,
        options.endpoint.mtu,
    );
    let peer_info = build_tls_client_peer_info(
        &configured_ciphers,
        true,
        options.endpoint.mtu,
        allow_compression,
        std::env::consts::OS,
    );
    let hand_window = positive_or(
        options.handshake_window.as_std(),
        OPENVPN_DEFAULT_HANDSHAKE_WINDOW,
    );
    let renegotiation_interval = if options.renegotiate_disabled {
        Duration::ZERO
    } else {
        positive_or(
            options.renegotiate_interval.as_std(),
            OPENVPN_DEFAULT_RENEGOTIATION_INTERVAL,
        )
    };
    let pre_pull_ping_restart = if options.ping_restart_disabled {
        Duration::ZERO
    } else if let Some(value) = options
        .ping_restart
        .as_std()
        .filter(|value| !value.is_zero())
    {
        value
    } else if remote.network.starts_with("udp") {
        OPENVPN_PRE_PULL_UDP_PING_RESTART
    } else {
        Duration::ZERO
    };
    let filters = options
        .pull_filters
        .iter()
        .map(|filter| PullFilter {
            action: filter.action.clone(),
            text: filter.text.clone(),
        })
        .collect();
    let remote_host = match &remote.destination {
        SocksAddr::Ip(address) => Some(address.ip()),
        SocksAddr::Domain { .. } => None,
    };
    Ok(OpenVpnClientNegotiationPlan {
        key_method: TlsKeyMethodMessage {
            options_string: local_options_string.clone(),
            username: options.username.clone(),
            password: options.password.clone(),
            peer_info,
            ..TlsKeyMethodMessage::default()
        },
        pull: ClientPullOptions {
            configured_ciphers,
            fallback_cipher: options.data_ciphers_fallback.clone(),
            remote_cipher: String::new(),
            configured_auth: options.auth.clone(),
            remote_host,
            filters,
            hand_window,
            renegotiation_interval,
            pre_pull_ping_restart,
        },
        data: ClientTlsDataChannelOptions {
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
            peer_id: None,
            local_options_string,
            renegotiation_bytes: options.renegotiate_bytes,
            renegotiation_packets: options.renegotiate_packets,
        },
        compression,
        allow_compression,
        fragment_size: options.fragment as usize,
    })
}

fn positive_or(value: Option<Duration>, default: Duration) -> Duration {
    value.filter(|value| !value.is_zero()).unwrap_or(default)
}

fn shuffle_remotes(remotes: &mut [OpenVpnClientRemote]) {
    for index in (1..remotes.len()).rev() {
        let mut random = [0_u8; 8];
        if getrandom::fill(&mut random).is_err() {
            return;
        }
        let selected =
            (u64::from_ne_bytes(random) % (index as u64 + 1)) as usize;
        remotes.swap(index, selected);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenVpnClientConnectorError {
    #[error("invalid OpenVPN client options: {0}")]
    Options(String),
    #[error("unsupported OpenVPN client connector mode: {0}")]
    UnsupportedMode(String),
    #[error(transparent)]
    Build(#[from] OpenVpnEndpointBuildError),
    #[error(transparent)]
    Tls(#[from] TlsSessionError),
    #[error(transparent)]
    Negotiation(#[from] TlsClientNegotiationError),
    #[error(transparent)]
    Compression(#[from] CompressionError),
    #[error(transparent)]
    ActiveSession(#[from] super::ActiveDataSessionError),
    #[error(transparent)]
    SoftReset(#[from] SoftResetStateError),
    #[error("OpenVPN peer requested a full session restart")]
    SessionRestartRequired,
    #[error("unexpected event on the OpenVPN reset channel")]
    UnexpectedControlEvent,
    #[error("all OpenVPN remotes failed: {0:?}")]
    AllRemotesFailed(Vec<String>),
    #[error(
        "OpenVPN remote {remote} has no resolved address at index {address_index}"
    )]
    RemoteAddressExhausted {
        remote: SocksAddr,
        address_index: usize,
    },
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::{io, net::IpAddr, sync::Arc};

    use super::*;
    use crate::{
        dns::{LookupFuture, Resolver},
        protocol::direct::DirectOutbound,
    };

    struct CursorResolver;

    impl Resolver for CursorResolver {
        fn lookup<'a>(
            &'a self,
            domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                if domain != "vpn.example" {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "unexpected OpenVPN remote",
                    ));
                }
                Ok(vec![
                    IpAddr::V6("2001:db8::7".parse().unwrap()),
                    IpAddr::V4("192.0.2.7".parse().unwrap()),
                    IpAddr::V4("192.0.2.8".parse().unwrap()),
                ])
            })
        }
    }

    fn cursor_options() -> OpenVpnClientEndpointOptions {
        serde_json::from_value(serde_json::json!({
            "network": "tcp4",
            "servers": [
                {"server": "vpn.example", "server_port": 1194},
                {"server": "192.0.2.20", "server_port": 443}
            ],
            "tls": {
                "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn cursor_resolves_one_exact_family_filtered_address() {
        let options = cursor_options();
        let connector = OpenVpnClientConnector::new(
            options.clone(),
            ".",
            Arc::new(DirectOutbound::new(Default::default())),
        )
        .with_remote_resolver(Arc::new(CursorResolver), DomainStrategy::AsIs);
        let mut cursor = OpenVpnClientConnectionCursor::new(&options);
        assert_eq!(
            connector
                .resolve_cursor_destination(
                    cursor.current().unwrap(),
                    cursor.address_index(),
                )
                .await
                .unwrap(),
            SocksAddr::new("192.0.2.7", 1194)
        );
        cursor.advance(ClientRemoteAdvance::NextAddress);
        assert_eq!(
            connector
                .resolve_cursor_destination(
                    cursor.current().unwrap(),
                    cursor.address_index(),
                )
                .await
                .unwrap(),
            SocksAddr::new("192.0.2.8", 1194)
        );
        cursor.advance(ClientRemoteAdvance::NextAddress);
        assert!(matches!(
            connector
                .resolve_cursor_destination(
                    cursor.current().unwrap(),
                    cursor.address_index(),
                )
                .await,
            Err(OpenVpnClientConnectorError::RemoteAddressExhausted {
                address_index: 2,
                ..
            })
        ));
        cursor.advance(ClientRemoteAdvance::NextRemote);
        assert_eq!(cursor.remote_index(), 1);
        assert_eq!(cursor.address_index(), 0);
        cursor.advance(ClientRemoteAdvance::NextRemote);
        assert_eq!(cursor.remote_index(), 0);
    }

    #[test]
    fn reconnect_policy_preserves_server_advance_and_backoff() {
        let restart = OpenVpnClientConnectorError::Negotiation(
            TlsClientNegotiationError::Pull(ClientPullError::State(
                ClientPullStateError::ServerRestart {
                    advance: ClientRemoteAdvance::NextAddress,
                },
            )),
        );
        assert_eq!(
            openvpn_client_reconnect_policy(&restart, true),
            OpenVpnClientReconnectPolicy {
                advance: ClientRemoteAdvance::NextAddress,
                minimum_backoff: Duration::ZERO,
            }
        );

        let temporary = OpenVpnClientConnectorError::Negotiation(
            TlsClientNegotiationError::Pull(ClientPullError::State(
                ClientPullStateError::AuthenticationFailed(
                    super::super::AuthFailedInfo {
                        failed: true,
                        temporary: true,
                        reason: "maintenance".into(),
                        backoff_seconds: 17,
                        advance: AuthFailedAdvance::NextRemote,
                    },
                ),
            )),
        );
        assert_eq!(
            openvpn_client_reconnect_policy(&temporary, false),
            OpenVpnClientReconnectPolicy {
                advance: ClientRemoteAdvance::NextRemote,
                minimum_backoff: Duration::from_secs(17),
            }
        );

        let exhausted = OpenVpnClientConnectorError::RemoteAddressExhausted {
            remote: SocksAddr::new("vpn.example", 1194),
            address_index: 3,
        };
        assert_eq!(
            openvpn_client_reconnect_policy(&exhausted, false).advance,
            ClientRemoteAdvance::NextRemote
        );
        assert_eq!(
            openvpn_client_reconnect_policy(
                &OpenVpnClientConnectorError::SessionRestartRequired,
                true,
            )
            .advance,
            ClientRemoteAdvance::Stay
        );
    }

    #[test]
    fn expands_primary_and_per_remote_network_defaults() {
        let primary: OpenVpnClientEndpointOptions = serde_json::from_value(
            serde_json::json!({
                "server": "vpn.example",
                "server_port": 1194,
                "network": "tcp6",
                "tls": {"peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
            }),
        )
        .unwrap();
        assert_eq!(openvpn_client_remotes(&primary)[0].network, "tcp6");

        let multiple: OpenVpnClientEndpointOptions = serde_json::from_value(
            serde_json::json!({
                "network": "udp4",
                "servers": [
                    {"server": "one.example", "server_port": 1194},
                    {"server": "two.example", "server_port": 443, "network": "tcp"}
                ],
                "tls": {"peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
            }),
        )
        .unwrap();
        let remotes = openvpn_client_remotes(&multiple);
        assert_eq!(remotes[0].network, "udp4");
        assert_eq!(remotes[1].network, "tcp");
    }

    #[test]
    fn builds_key_method_pull_and_data_options_from_endpoint_json() {
        let options: OpenVpnClientEndpointOptions = serde_json::from_value(
            serde_json::json!({
                "server": "192.0.2.7",
                "server_port": 1194,
                "network": "udp4",
                "mtu": 1400,
                "username": "alice",
                "password": "secret",
                "data_ciphers": ["AES-128-GCM", "AES-256-GCM"],
                "auth": "SHA256",
                "compression": "stub-v2",
                "fragment": 1200,
                "replay_window": 128,
                "replay_window_time": "30s",
                "renegotiate_bytes": 4096,
                "renegotiate_packets": 100,
                "pull_filters": [{"action": "ignore", "text": "route "}],
                "tls": {
                    "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }),
        )
        .unwrap();
        let remote = openvpn_client_remotes(&options).remove(0);
        let plan =
            build_openvpn_client_negotiation_plan(&options, &remote).unwrap();
        assert_eq!(plan.key_method.username, "alice");
        assert_eq!(plan.key_method.password, "secret");
        assert!(plan.key_method.options_string.contains("tun-mtu 1400"));
        assert!(
            plan.key_method
                .options_string
                .contains("cipher AES-128-GCM")
        );
        assert!(plan.key_method.peer_info.contains("IV_MTU=1400\n"));
        assert_eq!(plan.pull.remote_host, Some("192.0.2.7".parse().unwrap()));
        assert_eq!(plan.pull.pre_pull_ping_restart, Duration::from_secs(120));
        assert_eq!(plan.pull.filters[0].action, "ignore");
        assert_eq!(plan.data.replay_window_size, 128);
        assert_eq!(plan.data.replay_window_time, Duration::from_secs(30));
        assert!(plan.data.framing.is_some());
        assert_eq!(plan.data.renegotiation_bytes, 4096);
        assert_eq!(plan.data.renegotiation_packets, 100);
        assert_eq!(plan.fragment_size, 1200);
    }

    #[test]
    fn applies_upstream_tls_timing_defaults() {
        let options: OpenVpnClientEndpointOptions = serde_json::from_value(
            serde_json::json!({
                "server": "vpn.example",
                "server_port": 443,
                "network": "tcp",
                "tls": {
                    "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }),
        )
        .unwrap();
        let remote = openvpn_client_remotes(&options).remove(0);
        let plan =
            build_openvpn_client_negotiation_plan(&options, &remote).unwrap();
        assert_eq!(plan.pull.hand_window, Duration::from_secs(60));
        assert_eq!(plan.pull.renegotiation_interval, Duration::from_secs(3600));
        assert_eq!(plan.pull.pre_pull_ping_restart, Duration::ZERO);
    }

    #[test]
    fn builds_initial_tunnel_state_before_server_push() {
        let options: OpenVpnClientEndpointOptions = serde_json::from_value(
            serde_json::json!({
                "server": "vpn.example",
                "server_port": 1194,
                "network": "udp",
                "mtu": 1420,
                "address": ["10.8.0.2/24", "fd00::2/64"],
                "peer_address": "10.8.0.1",
                "peer_address_ipv6": "fd00::1",
                "routes": ["192.0.2.0/24", "2001:db8::/32"],
                "route_metric": 7,
                "redirect_gateway": true,
                "explicit_exit_notify": 2,
                "tls": {
                    "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }),
        )
        .unwrap();
        let state = build_openvpn_client_tunnel_state(&options);
        let configuration = state.configuration();
        assert_eq!(configuration.tun_mtu, 1420);
        assert_eq!(configuration.local_ipv4.len(), 1);
        assert_eq!(configuration.local_ipv6.len(), 1);
        assert_eq!(configuration.ipv4_routes[0].metric, 7);
        assert_eq!(
            configuration.ipv4_routes[0].gateway,
            Some("10.8.0.1".parse().unwrap())
        );
        assert_eq!(
            configuration.ipv6_routes[0].gateway,
            Some("fd00::1".parse().unwrap())
        );
        assert!(configuration.redirect_gateway);
        assert_eq!(configuration.explicit_exit_notify, 2);
        assert_eq!(configuration.ping_restart, Duration::from_secs(120));
    }
}
