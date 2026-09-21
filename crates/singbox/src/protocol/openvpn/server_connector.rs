use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use openssl::{error::ErrorStack, x509::X509Ref};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::{
    ActiveDataSessionError, CompressionSettings, IncomingControlEvent, IpPool,
    IpPoolError, OpenVpnActiveDataSession, OpenVpnEndpointBuildError,
    OpenVpnIpPrefix, OpenVpnPacketTransport, OpenVpnServerSecurity,
    PushedAddress, PushedLocalAddress, PushedOptions, PushedRoute,
    PushedRouteEntry, ServerPushAssignment, ServerTlsDataChannelOptions,
    ServerTlsRenegotiationDataOptions, SoftResetCoordinator,
    SoftResetStateError, TlsServerNegotiationError, TunnelDnsServer,
    build_openvpn_server_security, build_tls_options_string,
    build_tls_server_peer_info, establish_tls_server_renegotiation,
    establish_tls_server_renegotiation_local, establish_tls_server_session,
    negotiate_tls_server_data_channel_with_async_assignment,
    negotiate_tls_server_renegotiation_data_channel,
};
use crate::option::OpenVpnServerEndpointOptions;

pub const OPENVPN_DEFAULT_SERVER_MAX_CLIENTS: usize = 1024;
pub const OPENVPN_DEFAULT_SERVER_MTU: u32 = 1500;
pub const OPENVPN_DEFAULT_SERVER_HANDSHAKE_WINDOW: Duration =
    Duration::from_secs(60);
pub const OPENVPN_SERVER_SCHEDULED_EXIT_INTERVAL: Duration =
    Duration::from_secs(5);

#[derive(Debug, Default)]
struct OpenVpnServerResources {
    active: usize,
    next_peer_id: u32,
    peer_ids: HashSet<u32>,
}

#[derive(Default)]
struct OpenVpnServerIdentityState {
    next_generation: u64,
    sessions: HashMap<String, OpenVpnServerIdentityEntry>,
}

struct OpenVpnServerIdentityEntry {
    generation: u64,
    cancellation: CancellationToken,
    finished: watch::Receiver<bool>,
}

/// Configuration and shared resource state for a TLS OpenVPN server.
///
/// Listener ownership is deliberately separate: TCP and UDP frontends can
/// feed packet transports into the same allocator/negotiator.
pub struct OpenVpnServerConnector {
    options: OpenVpnServerEndpointOptions,
    base_path: PathBuf,
    security: Arc<OpenVpnServerSecurity>,
    pool: Arc<IpPool>,
    data_options: ServerTlsDataChannelOptions,
    users: HashMap<String, String>,
    resources: Arc<Mutex<OpenVpnServerResources>>,
    identities: Arc<Mutex<OpenVpnServerIdentityState>>,
    max_clients: usize,
}

pub struct OpenVpnConnectedServerClient {
    pub active: OpenVpnActiveDataSession,
    pub assignment: ServerPushAssignment,
    pub username: String,
    authenticated_identity: String,
    certificate_identity: Option<OpenVpnClientCertificateIdentity>,
    security: Arc<OpenVpnServerSecurity>,
    data_options: ServerTlsDataChannelOptions,
    expected_password: Option<String>,
    selected_cipher: String,
    selected_auth: String,
    soft_resets: Mutex<SoftResetCoordinator>,
    renegotiation_interval: Duration,
    renegotiation_disabled: bool,
    remote_is_ipv6: bool,
    replacement_cancellation: CancellationToken,
    _lease: OpenVpnServerLease,
    _identity_lease: Option<OpenVpnServerIdentityLease>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenVpnClientCertificateIdentity {
    pub(crate) common_name: String,
    pub(crate) certificate_hashes: Vec<[u8; 32]>,
}

impl OpenVpnClientCertificateIdentity {
    fn identity_key(&self) -> String {
        if !self.common_name.is_empty() {
            format!("x509-cn:{}", self.common_name)
        } else {
            format!("x509-sha256:{}", hex::encode(self.certificate_hashes[0]))
        }
    }
}

struct OpenVpnServerLease {
    pool: Arc<IpPool>,
    resources: Arc<Mutex<OpenVpnServerResources>>,
    addresses: Vec<IpAddr>,
    peer_id: u32,
    assignment: ServerPushAssignment,
}

struct OpenVpnServerIdentityLease {
    identity: String,
    generation: u64,
    state: Arc<Mutex<OpenVpnServerIdentityState>>,
    finished: watch::Sender<bool>,
}

impl OpenVpnServerConnector {
    pub fn new(
        options: OpenVpnServerEndpointOptions,
        base_path: &Path,
    ) -> Result<Self, OpenVpnServerConnectorError> {
        options.validate().map_err(|error| {
            OpenVpnServerConnectorError::Options(error.to_string())
        })?;
        if options.normalized_mode() != "tls" {
            return Err(OpenVpnServerConnectorError::UnsupportedMode(
                options.normalized_mode().into(),
            ));
        }
        let security =
            Arc::new(build_openvpn_server_security(&options, base_path)?);
        let topology = if options.topology.is_empty() {
            "subnet"
        } else {
            &options.topology
        };
        let address_pools = options
            .address
            .as_slice()
            .iter()
            .map(|prefix| OpenVpnIpPrefix {
                address: prefix.0.addr(),
                prefix_len: prefix.0.prefix_len(),
            })
            .collect::<Vec<_>>();
        let mut pool = IpPool::new(&address_pools, topology)?;
        if let Some(address) = address_pools.iter().find_map(|prefix| {
            let IpAddr::V4(address) = prefix.address else {
                return None;
            };
            Some(address)
        }) {
            pool.set_server_ipv4(Some(address))?;
        }
        if let Some(address) = address_pools.iter().find_map(|prefix| {
            let IpAddr::V6(address) = prefix.address else {
                return None;
            };
            Some(address)
        }) {
            pool.set_server_ipv6(Some(address))?;
        }
        let data_options = build_openvpn_server_data_channel_options(&options)?;
        let users = options
            .users
            .iter()
            .map(|user| (user.username.clone(), user.password.clone()))
            .collect();
        let max_clients = if options.max_clients == 0 {
            OPENVPN_DEFAULT_SERVER_MAX_CLIENTS
        } else {
            options.max_clients as usize
        };
        Ok(Self {
            options,
            base_path: base_path.to_owned(),
            security,
            pool: Arc::new(pool),
            data_options,
            users,
            resources: Arc::default(),
            identities: Arc::default(),
            max_clients,
        })
    }

    pub fn options(&self) -> &OpenVpnServerEndpointOptions {
        &self.options
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    pub fn active_clients(&self) -> usize {
        self.resources.lock().active
    }

    pub async fn accept(
        &self,
        transport: Arc<dyn OpenVpnPacketTransport>,
        remote_is_ipv6: bool,
    ) -> Result<OpenVpnConnectedServerClient, OpenVpnServerConnectorError> {
        let protection =
            self.security.control_protection.new_session_protection();
        let handshake_window = self.data_options.handshake_window;
        let session = establish_tls_server_session(
            transport.clone(),
            &self.security.tls_context,
            &protection,
            handshake_window,
            remote_is_ipv6,
        )
        .await?;
        let certificate_identity =
            client_certificate_identity(session.tls.ssl())
                .map_err(super::TlsSessionError::from)?;
        let certificate_identity_key = certificate_identity
            .as_ref()
            .map(OpenVpnClientCertificateIdentity::identity_key);
        let duplicate_cn = self.options.duplicate_cn;
        let replacement_cancellation = CancellationToken::new();
        let lease = Arc::new(Mutex::new(None::<OpenVpnServerLease>));
        let allocated_lease = lease.clone();
        let identity_lease =
            Arc::new(Mutex::new(None::<OpenVpnServerIdentityLease>));
        let allocated_identity_lease = identity_lease.clone();
        let replacement_for_authorization = replacement_cancellation.clone();
        let negotiation =
            negotiate_tls_server_data_channel_with_async_assignment(
                session,
                self.data_options.clone(),
                move |username, password| {
                    let username = username.to_owned();
                    let password = password.to_owned();
                    let certificate_identity_key =
                        certificate_identity_key.clone();
                    let replacement_cancellation =
                        replacement_for_authorization.clone();
                    async move {
                        self.verify_credentials(&username, &password)?;
                        let identity = if duplicate_cn {
                            String::new()
                        } else if let Some(identity) = certificate_identity_key
                        {
                            identity
                        } else if username.is_empty() {
                            String::new()
                        } else {
                            format!("username:{username}")
                        };
                        let new_identity_lease = self
                            .reserve_identity(
                                &identity,
                                replacement_cancellation,
                            )
                            .await?;
                        let new_lease = self.allocate(&identity)?;
                        let assignment = new_lease.assignment.clone();
                        *allocated_identity_lease.lock() = new_identity_lease;
                        *allocated_lease.lock() = Some(new_lease);
                        Ok(assignment)
                    }
                },
            );
        let negotiated = tokio::select! {
            result = negotiation => result?,
            _ = replacement_cancellation.cancelled() => {
                return Err(OpenVpnServerConnectorError::SessionRestartRequired);
            }
        };
        let lease = lease
            .lock()
            .take()
            .ok_or(OpenVpnServerConnectorError::MissingLease)?;
        let identity_lease = identity_lease.lock().take();
        let assignment = lease.assignment.clone();
        let username = negotiated.client_key_method.username.clone();
        let authenticated_identity = certificate_identity
            .as_ref()
            .map(OpenVpnClientCertificateIdentity::identity_key)
            .unwrap_or_else(|| {
                if username.is_empty() {
                    String::new()
                } else {
                    format!("username:{username}")
                }
            });
        let expected_password = self.users.get(&username).cloned();
        let selected_cipher = negotiated.selected_cipher.clone();
        let selected_auth = negotiated.selected_auth.clone();
        let soft_resets = Mutex::new(SoftResetCoordinator::new(
            negotiated.session.session.current_key_id(),
            self.data_options.handshake_window,
        ));
        let renegotiation_interval = self
            .options
            .renegotiate_interval
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(Duration::from_secs(3600));
        Ok(OpenVpnConnectedServerClient {
            active: OpenVpnActiveDataSession::from_server(
                transport, negotiated, 0,
            ),
            assignment,
            username,
            authenticated_identity,
            certificate_identity,
            security: self.security.clone(),
            data_options: self.data_options.clone(),
            expected_password,
            selected_cipher,
            selected_auth,
            soft_resets,
            renegotiation_interval,
            renegotiation_disabled: self.options.renegotiate_disabled,
            remote_is_ipv6,
            replacement_cancellation,
            _lease: lease,
            _identity_lease: identity_lease,
        })
    }

    fn verify_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        if self.users.is_empty() {
            return Ok(());
        }
        let accepted = self.users.get(username).is_some_and(|expected| {
            constant_time_equal(expected.as_bytes(), password.as_bytes())
        });
        accepted
            .then_some(())
            .ok_or_else(|| "invalid username or password".into())
    }

    async fn reserve_identity(
        &self,
        identity: &str,
        cancellation: CancellationToken,
    ) -> Result<Option<OpenVpnServerIdentityLease>, String> {
        if identity.is_empty() || self.options.duplicate_cn {
            return Ok(None);
        }
        let (finished_sender, finished_receiver) = watch::channel(false);
        let (generation, existing) = {
            let mut state = self.identities.lock();
            state.next_generation = state.next_generation.wrapping_add(1);
            let generation = state.next_generation;
            let existing = state.sessions.insert(
                identity.to_owned(),
                OpenVpnServerIdentityEntry {
                    generation,
                    cancellation: cancellation.clone(),
                    finished: finished_receiver,
                },
            );
            (generation, existing)
        };
        let lease = OpenVpnServerIdentityLease {
            identity: identity.to_owned(),
            generation,
            state: self.identities.clone(),
            finished: finished_sender,
        };
        if let Some(mut existing) = existing {
            existing.cancellation.cancel();
            let wait_for_exit = async {
                while !*existing.finished.borrow() {
                    if existing.finished.changed().await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                result = tokio::time::timeout(
                    OPENVPN_SERVER_SCHEDULED_EXIT_INTERVAL,
                    wait_for_exit,
                ) => {
                    if result.is_err() {
                        return Err(
                            "timed out replacing prior OpenVPN session for authenticated identity"
                                .into(),
                        );
                    }
                }
                _ = cancellation.cancelled() => {
                    return Err(
                        "OpenVPN peer was replaced during authentication".into()
                    );
                }
            }
        }
        let current = self
            .identities
            .lock()
            .sessions
            .get(identity)
            .is_some_and(|entry| entry.generation == generation);
        if !current {
            return Err(
                "OpenVPN peer was replaced during authentication".into()
            );
        }
        Ok(Some(lease))
    }

    fn allocate(&self, identity: &str) -> Result<OpenVpnServerLease, String> {
        let peer_id = {
            let mut resources = self.resources.lock();
            if resources.active >= self.max_clients {
                return Err("OpenVPN maximum client count reached".into());
            }
            let mut selected = None;
            for _ in 0..self.max_clients.max(1) {
                let candidate = resources.next_peer_id & 0x00ff_ffff;
                resources.next_peer_id = (candidate + 1) & 0x00ff_ffff;
                // 0xffffff is MAX_PEER_ID on the wire and means that Data-v2
                // peer-id demultiplexing is disabled. Never lease it.
                if candidate == 0x00ff_ffff {
                    continue;
                }
                if resources.peer_ids.insert(candidate) {
                    selected = Some(candidate);
                    break;
                }
            }
            let peer_id = selected
                .ok_or_else(|| "OpenVPN peer-id space exhausted".to_owned())?;
            resources.active += 1;
            peer_id
        };
        match self.allocate_for_peer(identity, peer_id) {
            Ok(lease) => Ok(lease),
            Err(error) => {
                release_peer_id(&self.resources, peer_id);
                Err(error.to_string())
            }
        }
    }

    fn allocate_for_peer(
        &self,
        identity: &str,
        peer_id: u32,
    ) -> Result<OpenVpnServerLease, IpPoolError> {
        let mut addresses = Vec::new();
        let mut assignment = ServerPushAssignment {
            peer_id: Some(peer_id),
            ..ServerPushAssignment::default()
        };
        if self.pool.has_ipv4() {
            let lease = self.pool.allocate_ipv4_for_identity(identity)?;
            addresses.push(IpAddr::V4(lease.client));
            let prefix_len = match self.pool.ipv4_topology() {
                "subnet" => self.pool.ipv4_prefix().unwrap().prefix_len,
                "p2p" => 32,
                "net30" => 30,
                _ => unreachable!(),
            };
            assignment.local_address_ipv4 = Some(PushedLocalAddress {
                prefix: OpenVpnIpPrefix {
                    address: IpAddr::V4(lease.client),
                    prefix_len,
                },
                peer: lease.peer.map(IpAddr::V4),
                raw: String::new(),
            });
            assignment.ipv4_topology = self.pool.ipv4_topology().into();
            assignment.server_ipv4 = self.pool.server_ipv4();
        }
        if self.pool.has_ipv6() {
            match self.pool.allocate_ipv6_for_identity(identity) {
                Ok(address) => {
                    addresses.push(IpAddr::V6(address));
                    assignment.local_address_ipv6 = Some(PushedLocalAddress {
                        prefix: OpenVpnIpPrefix {
                            address: IpAddr::V6(address),
                            prefix_len: self
                                .pool
                                .ipv6_prefix()
                                .unwrap()
                                .prefix_len,
                        },
                        peer: self.pool.server_ipv6().map(IpAddr::V6),
                        raw: String::new(),
                    });
                }
                Err(error) => {
                    for address in addresses {
                        self.pool.release(address);
                    }
                    return Err(error);
                }
            }
        }
        Ok(OpenVpnServerLease {
            pool: self.pool.clone(),
            resources: self.resources.clone(),
            addresses,
            peer_id,
            assignment,
        })
    }
}

impl OpenVpnConnectedServerClient {
    pub fn authenticated_identity(&self) -> &str {
        &self.authenticated_identity
    }

    pub(crate) fn certificate_identity(
        &self,
    ) -> Option<&OpenVpnClientCertificateIdentity> {
        self.certificate_identity.as_ref()
    }

    pub async fn replacement_cancelled(&self) {
        self.replacement_cancellation.cancelled().await;
    }

    /// Perform a complete server-initiated TLS soft reset while preserving the
    /// client's address lease and peer-id assignment.
    pub async fn renegotiate(
        &self,
    ) -> Result<bool, OpenVpnServerConnectorError> {
        let now = std::time::Instant::now();
        let reset = self.soft_resets.lock().begin_local(now)?;
        if !reset.created {
            return Ok(false);
        }
        let session = establish_tls_server_renegotiation_local(
            &self.active.tls_session().control,
            &self.active.tls_session().session,
            &self.security.tls_context,
            &self.security.control_protection,
            reset.key_id,
            self.data_options.handshake_window,
            self.remote_is_ipv6,
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
        self.finish_renegotiation(reset, session).await
    }

    /// Accept a client-initiated `P_CONTROL_SOFT_RESET_V1` while retaining the
    /// TLS server role.
    pub async fn accept_remote_renegotiation(
        &self,
        soft_reset: &super::Packet,
    ) -> Result<bool, OpenVpnServerConnectorError> {
        let reset = self
            .soft_resets
            .lock()
            .begin_remote(soft_reset.key_id, std::time::Instant::now())?;
        if !reset.created {
            return Ok(false);
        }
        let session = establish_tls_server_renegotiation(
            &self.active.tls_session().control,
            &self.active.tls_session().session,
            &self.security.tls_context,
            &self.security.control_protection,
            soft_reset,
            self.data_options.handshake_window,
            self.remote_is_ipv6,
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
        self.finish_renegotiation(reset, session).await
    }

    pub async fn handle_next_remote_reset(
        &self,
    ) -> Result<bool, OpenVpnServerConnectorError> {
        let event = self.active.next_reset_event().await?;
        match event {
            IncomingControlEvent::SoftReset(packet) => {
                self.accept_remote_renegotiation(&packet).await
            }
            IncomingControlEvent::HardReset(_) => {
                Err(OpenVpnServerConnectorError::SessionRestartRequired)
            }
            IncomingControlEvent::TlsCiphertext(_)
            | IncomingControlEvent::Data(_) => {
                Err(OpenVpnServerConnectorError::UnexpectedControlEvent)
            }
        }
    }

    /// Drive interval, data-budget and peer initiated rekeys for one active
    /// server client. Any error terminates only that client session.
    pub async fn run_renegotiation_supervisor(
        self: Arc<Self>,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<(), OpenVpnServerConnectorError> {
        let interval_enabled = !self.renegotiation_disabled
            && !self.renegotiation_interval.is_zero();
        let timer_period = if interval_enabled {
            self.renegotiation_interval
        } else {
            Duration::from_secs(3600)
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

    async fn finish_renegotiation(
        &self,
        reset: super::BeginSoftReset,
        session: super::OpenVpnTlsRenegotiationSession,
    ) -> Result<bool, OpenVpnServerConnectorError> {
        let current_certificate_identity =
            client_certificate_identity(session.tls.ssl())
                .map_err(super::TlsSessionError::from)?;
        if current_certificate_identity != self.certificate_identity {
            let _ = self
                .soft_resets
                .lock()
                .finish_failed(reset.key_id, reset.sequence);
            return Err(
                OpenVpnServerConnectorError::PeerCertificateIdentityChanged,
            );
        }
        let expected_username = self.username.clone();
        let expected_password = self.expected_password.clone();
        let negotiated = negotiate_tls_server_renegotiation_data_channel(
            session,
            self.renegotiation_data_options(),
            move |username, password| {
                let accepted = username == expected_username
                    && expected_password.as_ref().is_none_or(|expected| {
                        constant_time_equal(
                            expected.as_bytes(),
                            password.as_bytes(),
                        )
                    });
                accepted
                    .then_some(())
                    .ok_or_else(|| "invalid username or password".into())
            },
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
            .install_server_renegotiation(
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

    fn renegotiation_data_options(&self) -> ServerTlsRenegotiationDataOptions {
        let selected_cipher = self.selected_cipher.clone();
        let selected_auth = self.selected_auth.clone();
        let local_options_string = build_tls_options_string(
            &self.data_options.protocol,
            false,
            self.data_options.tls_auth_enabled,
            self.data_options.compression,
            &selected_cipher,
            &selected_auth,
            self.data_options.tun_mtu,
        );
        ServerTlsRenegotiationDataOptions {
            selected_cipher,
            selected_auth,
            local_options_string,
            server_peer_info: self.data_options.server_peer_info.clone(),
            replay_window_size: self.data_options.replay_window_size,
            replay_window_time: self.data_options.replay_window_time,
            framing: self.data_options.framing.clone(),
            peer_id: self.assignment.peer_id,
        }
    }
}

impl Drop for OpenVpnServerLease {
    fn drop(&mut self) {
        for address in self.addresses.drain(..) {
            self.pool.release(address);
        }
        release_peer_id(&self.resources, self.peer_id);
    }
}

impl Drop for OpenVpnServerIdentityLease {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if state
            .sessions
            .get(&self.identity)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            state.sessions.remove(&self.identity);
        }
        drop(state);
        let _ = self.finished.send(true);
    }
}

pub fn build_openvpn_server_data_channel_options(
    options: &OpenVpnServerEndpointOptions,
) -> Result<ServerTlsDataChannelOptions, OpenVpnServerConnectorError> {
    options.validate().map_err(|error| {
        OpenVpnServerConnectorError::Options(error.to_string())
    })?;
    let configured_ciphers = options.data_ciphers.as_slice().to_vec();
    let tls_auth_enabled = options
        .tls
        .as_ref()
        .and_then(|tls| tls.control_wrap.as_ref())
        .is_some_and(|wrap| wrap.kind == "tls_auth");
    let tun_mtu = if options.endpoint.mtu == 0 {
        OPENVPN_DEFAULT_SERVER_MTU
    } else {
        options.endpoint.mtu
    };
    let mut pushed_options = build_server_pushed_options(options)?;
    pushed_options.tun_mtu = tun_mtu;
    Ok(ServerTlsDataChannelOptions {
        configured_ciphers: configured_ciphers.clone(),
        fallback_cipher: options.data_ciphers_fallback.clone(),
        configured_auth: options.auth.clone(),
        protocol: options.normalized_network().into(),
        tls_auth_enabled,
        compression: CompressionSettings::default(),
        tun_mtu,
        server_peer_info: build_tls_server_peer_info(&configured_ciphers),
        pushed_options,
        assignment: ServerPushAssignment::default(),
        replay_window_size: options.replay_window,
        replay_window_time: options
            .replay_window_time
            .as_std()
            .unwrap_or_default(),
        framing: None,
        renegotiation_bytes: options.renegotiate_bytes,
        renegotiation_packets: options.renegotiate_packets,
        handshake_window: options
            .handshake_window
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(OPENVPN_DEFAULT_SERVER_HANDSHAKE_WINDOW),
    })
}

pub fn build_server_pushed_options(
    options: &OpenVpnServerEndpointOptions,
) -> Result<PushedOptions, OpenVpnServerConnectorError> {
    let Some(push) = options.push.as_ref() else {
        return Ok(PushedOptions::default());
    };
    let routes = push
        .routes
        .as_slice()
        .iter()
        .map(|prefix| PushedRouteEntry {
            route: PushedRoute {
                prefix: OpenVpnIpPrefix {
                    address: prefix.0.addr(),
                    prefix_len: prefix.0.prefix_len(),
                },
                gateway: None,
                metric: 0,
                excluded: false,
            },
            raw: String::new(),
        })
        .collect();
    let dns = push
        .dns
        .as_slice()
        .iter()
        .map(|address| PushedAddress {
            address: address.0,
            raw: String::new(),
            option_name: "dhcp-option DNS".into(),
        })
        .collect();
    let mut dns_servers = Vec::with_capacity(push.dns_servers.len());
    for server in &push.dns_servers {
        let mut addresses =
            Vec::with_capacity(server.addresses.as_slice().len());
        for value in server.addresses.as_slice() {
            addresses.push(parse_dns_server_address(value)?);
        }
        dns_servers.push(TunnelDnsServer {
            priority: server.priority,
            addresses,
            resolve_domains: server.resolve_domains.as_slice().to_vec(),
            dnssec: server.dnssec.clone(),
            transport: server.transport.clone(),
            sni: server.sni.clone(),
        });
    }
    let redirect_gateway_flags = if push.redirect_gateway
        && push.redirect_gateway_flags.as_slice().is_empty()
    {
        vec!["def1".into()]
    } else {
        push.redirect_gateway_flags.as_slice().to_vec()
    };
    let ping_interval = push.ping_interval.as_std().unwrap_or_default();
    let ping_restart = push.ping_restart.as_std().unwrap_or_default();
    Ok(PushedOptions {
        routes,
        dns,
        dns_servers,
        search_domains: push.search_domains.as_slice().to_vec(),
        dhcp_options: push.dhcp_options.as_slice().to_vec(),
        block_outside_dns: push.block_outside_dns,
        redirect_gateway: push.redirect_gateway,
        redirect_gateway_flags,
        ping_interval,
        ping_interval_enabled: !ping_interval.is_zero(),
        ping_restart,
        ping_restart_enabled: !ping_restart.is_zero(),
        ..PushedOptions::default()
    })
}

fn parse_dns_server_address(
    value: &str,
) -> Result<SocketAddr, OpenVpnServerConnectorError> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    value
        .parse::<IpAddr>()
        .map(|address| SocketAddr::new(address, 0))
        .map_err(|_| {
            OpenVpnServerConnectorError::InvalidDnsAddress(value.into())
        })
}

fn release_peer_id(resources: &Mutex<OpenVpnServerResources>, peer_id: u32) {
    let mut resources = resources.lock();
    if resources.peer_ids.remove(&peer_id) {
        resources.active = resources.active.saturating_sub(1);
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn client_certificate_identity(
    ssl: &openssl::ssl::SslRef,
) -> Result<Option<OpenVpnClientCertificateIdentity>, ErrorStack> {
    let Some(leaf) = ssl.peer_certificate() else {
        return Ok(None);
    };
    let mut certificates = vec![leaf.as_ref()];
    if let Some(chain) = ssl.peer_cert_chain() {
        certificates.extend(chain.iter());
    }
    client_certificate_identity_from_chain(&certificates).map(Some)
}

fn client_certificate_identity_from_chain(
    certificates: &[&X509Ref],
) -> Result<OpenVpnClientCertificateIdentity, ErrorStack> {
    debug_assert!(!certificates.is_empty());
    let leaf = certificates[0];
    let mut common_name = String::new();
    for entry in leaf
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
    {
        common_name = entry.data().to_string()?;
    }
    let mut certificate_hashes = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        certificate_hashes.push(Sha256::digest(certificate.to_der()?).into());
    }
    Ok(OpenVpnClientCertificateIdentity {
        common_name,
        certificate_hashes,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum OpenVpnServerConnectorError {
    #[error("invalid OpenVPN server options: {0}")]
    Options(String),
    #[error("unsupported OpenVPN server connector mode: {0}")]
    UnsupportedMode(String),
    #[error(transparent)]
    Build(#[from] OpenVpnEndpointBuildError),
    #[error(transparent)]
    Pool(#[from] IpPoolError),
    #[error(transparent)]
    Negotiation(#[from] TlsServerNegotiationError),
    #[error(transparent)]
    Tls(#[from] super::TlsSessionError),
    #[error(transparent)]
    Active(#[from] ActiveDataSessionError),
    #[error(transparent)]
    SoftReset(#[from] SoftResetStateError),
    #[error("OpenVPN client requested a hard session restart")]
    SessionRestartRequired,
    #[error("unexpected OpenVPN control event during renegotiation")]
    UnexpectedControlEvent,
    #[error("OpenVPN client certificate identity changed during renegotiation")]
    PeerCertificateIdentityChanged,
    #[error("invalid pushed OpenVPN DNS server address: {0}")]
    InvalidDnsAddress(String),
    #[error("OpenVPN server negotiation completed without an address lease")]
    MissingLease,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        option::OpenVpnClientEndpointOptions,
        protocol::openvpn::{
            OpenVpnClientConnectorError, OpenVpnClientSecurity,
            build_openvpn_client_negotiation_plan,
            build_openvpn_client_security, establish_tls_client_session,
            negotiate_tls_client_data_channel_with_challenges,
            openvpn_client_remotes,
        },
    };

    struct MemoryPacketTransport {
        receive: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        send: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl OpenVpnPacketTransport for MemoryPacketTransport {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            self.receive.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "packet link closed",
                )
            })
        }

        async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.send.send(packet.to_vec()).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "packet link closed")
            })
        }
    }

    fn packet_pair() -> (
        Arc<dyn OpenVpnPacketTransport>,
        Arc<dyn OpenVpnPacketTransport>,
    ) {
        let (left_send, right_receive) = mpsc::channel(128);
        let (right_send, left_receive) = mpsc::channel(128);
        (
            Arc::new(MemoryPacketTransport {
                receive: tokio::sync::Mutex::new(left_receive),
                send: left_send,
            }),
            Arc::new(MemoryPacketTransport {
                receive: tokio::sync::Mutex::new(right_receive),
                send: right_send,
            }),
        )
    }

    fn options() -> OpenVpnServerEndpointOptions {
        serde_json::from_value(serde_json::json!({
            "address": ["10.8.0.1/24", "fd00::1/120"],
            "network": "tcp",
            "max_clients": 2,
            "users": [{"username": "alice", "password": "secret"}],
            "data_ciphers": ["AES-128-GCM", "AES-256-GCM"],
            "auth": "SHA256",
            "mtu": 1400,
            "replay_window": 128,
            "replay_window_time": "30s",
            "renegotiate_bytes": 4096,
            "renegotiate_packets": 100,
            "push": {
                "routes": ["10.9.0.0/16", "fd01::/64"],
                "dns": ["1.1.1.1", "2606:4700:4700::1111"],
                "dns_servers": [{
                    "priority": 10,
                    "addresses": ["9.9.9.9", "[2620:fe::fe]:853"],
                    "resolve_domains": ["example.com"],
                    "dnssec": "yes",
                    "transport": "dot",
                    "sni": "dns.example"
                }],
                "search_domains": ["corp.example"],
                "dhcp_options": ["DOMAIN corp.example"],
                "redirect_gateway": true,
                "block_outside_dns": true,
                "ping_interval": "10s",
                "ping_restart": "30s"
            },
            "tls": {
                "certificate": "certificate",
                "key": "key",
                "verify_client_certificate": "none"
            }
        }))
        .unwrap()
    }

    #[test]
    fn maps_server_data_and_push_options() {
        let options = options();
        let plan = build_openvpn_server_data_channel_options(&options).unwrap();
        assert_eq!(plan.protocol, "tcp");
        assert_eq!(plan.tun_mtu, 1400);
        assert_eq!(plan.configured_auth, "SHA256");
        assert_eq!(plan.replay_window_size, 128);
        assert!(plan.server_peer_info.contains("IV_NCP=2"));
        assert_eq!(plan.pushed_options.routes.len(), 2);
        assert_eq!(plan.pushed_options.dns.len(), 2);
        assert_eq!(plan.pushed_options.dns_servers[0].addresses[0].port(), 0);
        assert_eq!(plan.pushed_options.dns_servers[0].addresses[1].port(), 853);
        assert_eq!(plan.pushed_options.redirect_gateway_flags, vec!["def1"]);
        assert!(plan.pushed_options.ping_interval_enabled);
        assert!(plan.pushed_options.ping_restart_enabled);
    }

    #[test]
    fn constant_time_user_check_and_resource_limit_match_server_policy() {
        let mut options = options();
        options.tls = None;
        assert!(constant_time_equal(b"secret", b"secret"));
        assert!(!constant_time_equal(b"secret", b"secrex"));
        assert!(!constant_time_equal(b"secret", b"secret-long"));
        let pushed = build_server_pushed_options(&options).unwrap();
        assert_eq!(pushed.search_domains, vec!["corp.example"]);
    }

    #[test]
    fn certificate_identity_uses_cn_for_session_key_and_hashes_for_rekey() {
        let certificate = |common_name: &str| {
            let key = KeyPair::generate().unwrap();
            let mut parameters =
                CertificateParams::new(vec!["vpn.test".into()]).unwrap();
            parameters
                .distinguished_name
                .push(rcgen::DnType::CommonName, common_name);
            openssl::x509::X509::from_pem(
                parameters.self_signed(&key).unwrap().pem().as_bytes(),
            )
            .unwrap()
        };
        let first = certificate("alice");
        let replacement = certificate("alice");
        let first_identity =
            client_certificate_identity_from_chain(&[first.as_ref()]).unwrap();
        let replacement_identity =
            client_certificate_identity_from_chain(&[replacement.as_ref()])
                .unwrap();
        assert_eq!(first_identity.identity_key(), "x509-cn:alice");
        assert_eq!(replacement_identity.identity_key(), "x509-cn:alice");
        assert_ne!(first_identity, replacement_identity);
    }

    #[tokio::test]
    async fn connector_authenticates_allocates_and_carries_data() {
        let key = KeyPair::generate().unwrap();
        let mut certificate_parameters =
            CertificateParams::new(vec!["vpn.test".into()]).unwrap();
        certificate_parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "vpn.test");
        certificate_parameters.key_usages =
            vec![KeyUsagePurpose::DigitalSignature];
        certificate_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate =
            certificate_parameters.self_signed(&key).unwrap().pem();
        let server_options: OpenVpnServerEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "address": "10.8.0.1/29",
                "topology": "subnet",
                "network": "tcp",
                "mtu": 1400,
                "users": [{"username": "alice", "password": "secret"}],
                "data_ciphers": "AES-256-GCM",
                "tls": {
                    "certificate": certificate,
                    "key": key.serialize_pem(),
                    "verify_client_certificate": "none"
                }
            }))
            .unwrap();
        let connector =
            OpenVpnServerConnector::new(server_options, Path::new("."))
                .unwrap();
        let client_options: OpenVpnClientEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "server": "127.0.0.1",
                "server_port": 1194,
                "network": "tcp",
                "username": "alice",
                "password": "secret",
                "data_ciphers": "AES-256-GCM",
                "tls": {
                    "server_name": "vpn.test",
                    "server_name_type": "name",
                    "certificate": certificate,
                    "remote_certificate_tls": "server"
                }
            }))
            .unwrap();
        let OpenVpnClientSecurity {
            tls_context,
            control_protection,
            wrapped_client_key,
        } = build_openvpn_client_security(&client_options, Path::new("."))
            .unwrap();
        let remote = openvpn_client_remotes(&client_options).remove(0);
        let plan =
            build_openvpn_client_negotiation_plan(&client_options, &remote)
                .unwrap();
        let (client_transport, server_transport) = packet_pair();
        let client_link = client_transport.clone();
        let server = connector.accept(server_transport, false);
        let client = async {
            let session = establish_tls_client_session(
                client_transport,
                &tls_context,
                control_protection,
                wrapped_client_key,
                Duration::from_millis(100),
                Duration::from_secs(5),
                false,
            )
            .await
            .map_err(OpenVpnClientConnectorError::from)?;
            negotiate_tls_client_data_channel_with_challenges(
                session,
                plan.key_method,
                plan.pull,
                plan.data,
                None,
            )
            .await
            .map_err(OpenVpnClientConnectorError::from)
        };
        let (server, client) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(server, client)
            })
            .await
            .unwrap();
        let server = server.unwrap();
        let client = client.unwrap();
        assert_eq!(server.username, "alice");
        assert_eq!(server.authenticated_identity(), "username:alice");
        assert_eq!(
            server
                .assignment
                .local_address_ipv4
                .as_ref()
                .unwrap()
                .prefix,
            OpenVpnIpPrefix {
                address: "10.8.0.2".parse().unwrap(),
                prefix_len: 29,
            }
        );
        assert_eq!(client.pull.options.tun_mtu, 1400);
        assert_eq!(connector.active_clients(), 1);
        let client = OpenVpnActiveDataSession::from_client(
            client_link,
            client,
            plan.fragment_size,
        );
        client.write_data_packet(b"client packet").await.unwrap();
        assert_eq!(
            server.active.read_data_packet().await.unwrap(),
            b"client packet"
        );
        drop(server);
        assert_eq!(connector.active_clients(), 0);
        client.close();
    }
}
