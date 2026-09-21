//! Runtime-facing userspace AnyConnect/OpenConnect endpoint.

use std::{
    collections::VecDeque,
    fs, io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{Method, StatusCode};
use network_interface::{NetworkInterface, NetworkInterfaceConfig as _};
use openssl::{pkey::PKey, x509::X509};
use tokio::{
    io::AsyncWriteExt,
    sync::{Notify, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;

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
        NetworkDialOptions, PacketConnection, PacketFuture, PacketStream,
        Stream, VisionDialFuture, stream_local_addr, stream_peer_addr,
    },
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::SocksAddr,
        tls::{build_client_config, outbound_tls_root_store},
    },
    dns::{
        manager::SharedResolver, openconnect::OpenConnectConfigurationProvider,
    },
    option::{
        DomainStrategy, Listable, OpenConnectEndpointOptions,
        OutboundTlsOptions, ServerCertificateFingerprint,
        ServerCertificateFingerprintAlgorithm,
    },
    outbound::OutboundManager,
    protocol::openconnect::{
        AnyConnectAuthClientIdentity, AnyConnectAuthFormEntry,
        AnyConnectAuthHttpClient, AnyConnectAuthHttpRequest,
        AnyConnectAuthMobileIdentity, AnyConnectAuthPrefillOptions,
        AnyConnectAuthenticatedSession, AnyConnectAuthenticationProgress,
        AnyConnectAuthenticator, AnyConnectAuthenticatorOptions,
        AnyConnectCredentialCache, AnyConnectCstpConnectError,
        AnyConnectCstpConnectorOptions,
        AnyConnectDataChannel as AnyConnectChannel,
        AnyConnectDataChannelEvent as AnyConnectChannelEvent,
        AnyConnectMcaIdentity, AnyConnectMcaPrivateKey,
        AnyConnectSoftwareTokenGenerator, CertificateDtls10ClientIdentity,
        CertificateDtls10ClientOptions, CertificateDtlsClientOptions,
        CertificateDtlsConnection, CstpCompressionMode, CstpConnectOptions,
        CstpMobileIdentity, CstpResponseOptions,
        DialerAnyConnectAuthHttpTransport, F5_DEFAULT_USER_AGENT,
        F5_MAXIMUM_AUTHENTICATION_BODY, F5_TLS_CONNECT_TIMEOUT,
        F5AuthenticatedSession, F5AuthenticationProgress, F5Authenticator,
        F5AuthenticatorOptions, F5TunnelError,
        FORTINET_MAXIMUM_AUTHENTICATION_BODY, FORTINET_PROTOCOL_USER_AGENT,
        FortinetAuthenticatedSession, FortinetAuthenticationProgress,
        FortinetAuthenticator, FortinetAuthenticatorOptions,
        FortinetTunnelError, GlobalProtectAuthenticatedSession,
        GlobalProtectAuthenticationProgress, GlobalProtectAuthenticator,
        GlobalProtectAuthenticatorOptions,
        GlobalProtectConfigurationParseOptions,
        GlobalProtectConfigurationRequestOptions, GlobalProtectEspProbe,
        GlobalProtectFailureClass, GlobalProtectHipError,
        GlobalProtectHipRunner, GlobalProtectHipRunnerOptions,
        GlobalProtectTunnelOperation, GpstError, GpstSession,
        GpstSessionOptions, NETWORK_CONNECT_DEFAULT_USER_AGENT,
        NETWORK_CONNECT_ONCP_KMP_CONTROL, NETWORK_CONNECT_ONCP_KMP_DATA,
        NETWORK_CONNECT_ONCP_KMP_ESP, NETWORK_CONNECT_TNCC_DEFAULT_USER_AGENT,
        NetworkConnectAuthenticatedSession,
        NetworkConnectAuthenticationProgress, NetworkConnectAuthenticator,
        NetworkConnectAuthenticatorOptions, NetworkConnectBuiltInTnccRunner,
        NetworkConnectEspConfiguration, NetworkConnectEspParameters,
        NetworkConnectOncpReader, NetworkConnectOncpWriter,
        NetworkConnectTnccCertificate, NetworkConnectTnccIdentity,
        NetworkConnectTnccRunner, OPENCONNECT_DEFAULT_MTU,
        OpenConnectAuthChallenge, OpenConnectAuthResponse,
        OpenConnectEspKeySet, OpenConnectEspKeySetConfig, OpenConnectEspProbe,
        OpenConnectEspSession, OpenConnectEspSessionOptions,
        OpenConnectOathTokenFactory, OpenConnectSecurIdTokenFactory,
        PPP_MINIMUM_IPV6_MTU, PPP_MINIMUM_MRU,
        PULSE_AUTHENTICATION_FRAME_LIMIT, PULSE_CONFIGURATION_FRAME_LIMIT,
        PULSE_EAP_EXPANDED_JUNIPER, PULSE_EAP_RESPONSE,
        PULSE_EAP_TYPE_IDENTITY, PULSE_EAP_TYPE_TTLS,
        PULSE_IFT_CLIENT_AUTH_RESPONSE, PULSE_IFT_HEADER_SIZE,
        PULSE_IFT_VERSION_REQUEST, PULSE_LOGOUT_TIMEOUT,
        PULSE_MAXIMUM_AUTHENTICATION_STEPS, PULSE_MAXIMUM_LOGOUT_BODY,
        PULSE_VENDOR_JUNIPER, PULSE_VENDOR_TCG, PppDatagramCarrier,
        PppDatagramSession, PppDatagramSessionOptions, PppEncapsulation,
        PppNegotiatorOptions, PppStreamSession, PppStreamSessionOptions,
        PulseChallengeKind, PulseChallengeParser,
        PulseConfigurationAccumulator, PulseConfigurationAction,
        PulseEspConfiguration, PulseIftConnection, PulseIftEncoder,
        PulseTtlsTransport, TunnelConfiguration, build_f5_connect_request,
        build_fortinet_dtls_connect_request,
        build_fortinet_tls_connect_request,
        build_globalprotect_configuration_request,
        build_network_connect_oncp_request,
        build_pulse_authentication_client_avps,
        build_pulse_authentication_payload, build_pulse_eap,
        build_pulse_expanded_response, build_pulse_sign_in_response,
        build_pulse_upgrade_request, calculate_ppp_tunnel_mtu,
        classify_globalprotect_tunnel_http_status, connect_anyconnect_cstp,
        connect_certificate_dtls, connect_certificate_dtls10,
        encode_network_connect_oncp_authentication_packet,
        encode_network_connect_oncp_esp_control,
        encode_network_connect_oncp_mtu_control, establish_gpst,
        f5_dtls_record_mtu, fortinet_dtls_record_mtu,
        logout_globalprotect_session, new_openconnect_auth_challenge,
        parse_f5_options, parse_f5_profile, parse_f5_tunnel_start,
        parse_fortinet_xml_configuration,
        parse_globalprotect_tunnel_configuration,
        parse_network_connect_oncp_configuration_payload,
        parse_network_connect_oncp_esp_control,
        parse_network_connect_oncp_esp_rekey, parse_network_connect_oncp_kmp,
        parse_pulse_authentication_eap, parse_pulse_avps,
        parse_pulse_fatal_error, prepare_network_connect_esp,
        read_f5_tunnel_start, read_fortinet_tls_tunnel_start,
        read_pulse_ift_frame, read_pulse_inner_eap,
        read_pulse_upgrade_response, valid_fortinet_dtls_server_hello,
        valid_fortinet_ppp_datagram, validate_openconnect_form_response,
        validate_pulse_authentication_success,
        validate_pulse_initial_challenge, validate_pulse_version_response,
        write_pulse_inner_eap,
    },
};

#[derive(Default)]
pub struct OpenConnectEndpointDialer {
    net: RwLock<Option<Arc<Net>>>,
    configuration: RwLock<Option<TunnelConfiguration>>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
    packet_port: Arc<OpenConnectPacketPort>,
}

struct OpenConnectPacketPortState {
    output: mpsc::Sender<Vec<u8>>,
    inet4_address: Option<IpAddr>,
    inet6_address: Option<IpAddr>,
    mtu: usize,
}

#[derive(Default)]
struct OpenConnectPacketPort {
    state: RwLock<Option<OpenConnectPacketPortState>>,
    return_path: RwLock<Option<Weak<dyn IpPacketReturn>>>,
}

impl OpenConnectPacketPort {
    fn activate(
        &self,
        output: mpsc::Sender<Vec<u8>>,
        configuration: &TunnelConfiguration,
    ) -> io::Result<()> {
        let inet4_address = configuration
            .addresses
            .iter()
            .map(ipnet::IpNet::addr)
            .find(IpAddr::is_ipv4);
        let inet6_address = configuration
            .addresses
            .iter()
            .map(ipnet::IpNet::addr)
            .find(IpAddr::is_ipv6);
        *self.state.write().map_err(|_| {
            io::Error::other("OpenConnect packet port lock poisoned")
        })? = Some(OpenConnectPacketPortState {
            output,
            inet4_address,
            inet6_address,
            mtu: configuration.mtu as usize,
        });
        Ok(())
    }

    fn deactivate(&self) -> io::Result<()> {
        self.state
            .write()
            .map_err(|_| {
                io::Error::other("OpenConnect packet port lock poisoned")
            })?
            .take();
        Ok(())
    }

    fn update_mtu(&self, mtu: usize) -> io::Result<()> {
        if let Some(state) = self
            .state
            .write()
            .map_err(|_| {
                io::Error::other("OpenConnect packet port lock poisoned")
            })?
            .as_mut()
        {
            state.mtu = mtu;
        }
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

impl IpPacketPort for OpenConnectPacketPort {
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
            io::Error::other("OpenConnect packet return lock poisoned")
        })?;
        if let Some(existing) = current.as_ref()
            && existing.upgrade().is_some()
        {
            if existing.ptr_eq(&return_path) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenConnect packet return path is already attached",
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
            let output = self
                .state
                .read()
                .map_err(|_| {
                    io::Error::other("OpenConnect packet port lock poisoned")
                })?
                .as_ref()
                .map(|state| state.output.clone())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "OpenConnect endpoint is not started",
                    )
                })?;
            for packet in packets {
                if packet.is_empty() {
                    continue;
                }
                output.send(packet).await.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "OpenConnect packet transport is closed",
                    )
                })?;
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct OpenConnectEndpointHandle {
    dialer: Arc<OpenConnectEndpointDialer>,
    tunnel_configuration: Arc<RwLock<Option<TunnelConfiguration>>>,
    dtls_active: Arc<RwLock<bool>>,
    last_dtls_error: Arc<RwLock<Option<String>>>,
    last_error: Arc<RwLock<Option<String>>>,
    challenge_manager: Arc<OpenConnectChallengeManager>,
    successful_reconnections: Arc<AtomicU64>,
    userspace_stack_generation: Arc<AtomicU64>,
    token_factory: Option<OpenConnectOathTokenFactory>,
    securid_token_factory: Option<OpenConnectSecurIdTokenFactory>,
    flow: EndpointFlowContext,
}

impl OpenConnectEndpointHandle {
    pub fn dialer(&self) -> Arc<dyn Dialer> {
        self.dialer.clone()
    }

    pub(crate) fn dns_configuration_provider(
        &self,
    ) -> Arc<dyn OpenConnectConfigurationProvider> {
        self.dialer.clone()
    }

    pub fn tunnel_configuration(&self) -> Option<TunnelConfiguration> {
        self.tunnel_configuration.read().ok()?.clone()
    }

    pub fn dtls_active(&self) -> bool {
        self.dtls_active.read().is_ok_and(|active| *active)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.read().ok()?.clone()
    }

    pub fn last_dtls_error(&self) -> Option<String> {
        self.last_dtls_error.read().ok()?.clone()
    }

    pub fn challenge_manager(&self) -> Arc<OpenConnectChallengeManager> {
        self.challenge_manager.clone()
    }

    /// Number of tunnel transports successfully restored after initial start.
    pub fn successful_reconnections(&self) -> u64 {
        self.successful_reconnections.load(Ordering::Acquire)
    }

    /// Number of userspace network stacks created for this endpoint.
    ///
    /// A reconnect that preserves the assigned addresses and MTU reuses the
    /// existing stack, so this value does not increase and existing flows stay
    /// attached to the same smoltcp instance.
    pub fn userspace_stack_generation(&self) -> u64 {
        self.userspace_stack_generation.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct OpenConnectChallengeState {
    pending: Option<OpenConnectAuthChallenge>,
    response: Option<(String, OpenConnectAuthResponse)>,
    closed: bool,
}

/// Embedding-host bridge for form and browser authentication challenges.
#[derive(Default)]
pub struct OpenConnectChallengeManager {
    state: Mutex<OpenConnectChallengeState>,
    changed: Notify,
}

impl OpenConnectChallengeManager {
    pub fn pending(&self) -> Option<OpenConnectAuthChallenge> {
        self.state.lock().ok()?.pending.clone()
    }

    pub async fn wait_pending(&self) -> io::Result<OpenConnectAuthChallenge> {
        loop {
            let notified = self.changed.notified();
            {
                let state = self.state.lock().map_err(|_| {
                    io::Error::other("OpenConnect challenge lock poisoned")
                })?;
                if let Some(challenge) = &state.pending {
                    return Ok(challenge.clone());
                }
                if state.closed {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "OpenConnect challenge manager is closed",
                    ));
                }
            }
            notified.await;
        }
    }

    pub fn respond(
        &self,
        challenge_id: &str,
        response: OpenConnectAuthResponse,
    ) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::other("OpenConnect challenge lock poisoned")
        })?;
        let pending = state.pending.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no OpenConnect authentication challenge is pending",
            )
        })?;
        if pending.id != challenge_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OpenConnect authentication challenge ID does not match",
            ));
        }
        state.response = Some((challenge_id.to_owned(), response));
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    async fn await_response(
        &self,
        challenge: OpenConnectAuthChallenge,
        cancellation: &CancellationToken,
    ) -> io::Result<OpenConnectAuthResponse> {
        {
            let mut state = self.state.lock().map_err(|_| {
                io::Error::other("OpenConnect challenge lock poisoned")
            })?;
            if state.closed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "OpenConnect challenge manager is closed",
                ));
            }
            state.response = None;
            state.pending = Some(challenge.clone());
        }
        self.changed.notify_waiters();
        loop {
            let notified = self.changed.notified();
            {
                let mut state = self.state.lock().map_err(|_| {
                    io::Error::other("OpenConnect challenge lock poisoned")
                })?;
                if state.closed {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "OpenConnect challenge manager is closed",
                    ));
                }
                if let Some((id, response)) = state.response.take()
                    && id == challenge.id
                {
                    state.pending = None;
                    return Ok(response);
                }
            }
            tokio::select! {
                _ = cancellation.cancelled() => {
                    self.clear_pending();
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "OpenConnect authentication challenge cancelled",
                    ));
                }
                _ = notified => {}
            }
        }
    }

    fn reopen(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = OpenConnectChallengeState::default();
        }
        self.changed.notify_waiters();
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.pending = None;
            state.response = None;
        }
        self.changed.notify_waiters();
    }

    fn clear_pending(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.pending = None;
            state.response = None;
        }
        self.changed.notify_waiters();
    }
}

pub struct OpenConnectEndpointService {
    name: String,
    options: OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: OpenConnectEndpointHandle,
    cancellation: CancellationToken,
    network: Arc<Mutex<Option<Arc<OpenConnectNetwork>>>>,
    globalprotect_session:
        Arc<RwLock<Option<GlobalProtectAuthenticatedSession>>>,
    f5_session: Arc<RwLock<Option<F5AuthenticatedSession>>>,
    pulse_session: Arc<RwLock<Option<PulseAuthenticatedSession>>>,
    network_connect_session: Arc<RwLock<Option<NetworkConnectEndpointSession>>>,
    fortinet_reconnect_state: Arc<Mutex<FortinetReconnectState>>,
    f5_reconnect_state: Arc<Mutex<F5ReconnectState>>,
    supervisor_task: Option<JoinHandle<()>>,
}

struct UdpBindPortDialer {
    inner: Arc<dyn Dialer>,
    local_port: u16,
}

impl Dialer for UdpBindPortDialer {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        self.inner.dial_tcp(destination)
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        self.inner.dial_tcp_with_options(destination, options)
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        self.inner.bind_tcp(destination)
    }

    fn dial_vision_tcp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> VisionDialFuture<'a> {
        self.inner.dial_vision_tcp(destination)
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        self.inner.listen_udp_on(destination, self.local_port)
    }

    fn listen_udp_on<'a>(
        &'a self,
        destination: &'a SocksAddr,
        _local_port: u16,
    ) -> PacketFuture<'a, PacketStream> {
        self.inner.listen_udp_on(destination, self.local_port)
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        self.inner
            .exchange_icmp(packet, source, hop_limit, destination)
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        self.inner.exchange_icmp_with_options(
            packet,
            source,
            hop_limit,
            destination,
            options,
        )
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.inner.preferred_domain(domain)
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.inner.preferred_address(address)
    }

    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        self.inner.packet_port()
    }
}

#[derive(Debug, Clone)]
enum OpenConnectAuthenticatedSession {
    AnyConnect(AnyConnectAuthenticatedSession),
    GlobalProtect(GlobalProtectAuthenticatedSession),
    Fortinet(FortinetAuthenticatedSession),
    F5(F5AuthenticatedSession),
    Pulse(PulseAuthenticatedSession),
    NetworkConnect(NetworkConnectEndpointSession),
}

#[derive(Clone)]
struct NetworkConnectEndpointSession {
    authenticated: NetworkConnectAuthenticatedSession,
    tncc: Option<Arc<tokio::sync::Mutex<NetworkConnectTnccRunner>>>,
}

impl std::fmt::Debug for NetworkConnectEndpointSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkConnectEndpointSession")
            .field("authenticated", &self.authenticated)
            .field("tncc_active", &self.tncc.is_some())
            .finish()
    }
}

enum OpenConnectDataChannel {
    AnyConnect(Box<AnyConnectChannel>),
    GlobalProtect(Box<GlobalProtectDataChannel>),
    Fortinet(Box<FortinetDataChannel>),
    F5(Box<F5DataChannel>),
    Pulse(Box<PulseDataChannel>),
    NetworkConnect(Box<NetworkConnectDataChannel>),
}

enum OpenConnectDataChannelEvent {
    Data(Vec<u8>),
    TransportStateChanged,
}

#[derive(Clone)]
enum OpenConnectTransportError {
    Retryable(String),
    Terminal(String),
}

impl OpenConnectTransportError {
    fn message(&self) -> &str {
        match self {
            Self::Retryable(message) | Self::Terminal(message) => message,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

struct NetworkConnectDataChannel {
    reader: NetworkConnectOncpReader<tokio::io::ReadHalf<TlsStream<Stream>>>,
    writer: NetworkConnectOncpWriter<tokio::io::WriteHalf<TlsStream<Stream>>>,
    dialer: Arc<dyn Dialer>,
    mtu: usize,
    queue_length: usize,
    dpd_override: Option<Duration>,
    queued_packets: VecDeque<Vec<u8>>,
    esp: Option<OpenConnectEspSession>,
    esp_attempt: Option<JoinHandle<Result<OpenConnectEspSession, String>>>,
    esp_configuration: Option<NetworkConnectEspConfiguration>,
    esp_parameters: Option<NetworkConnectEspParameters>,
    esp_enabled: bool,
    last_esp_error: Option<String>,
    cancellation: CancellationToken,
    tncc_task: Option<JoinHandle<()>>,
    tncc_failure: Arc<Mutex<Option<String>>>,
    closed: bool,
}

#[derive(Clone)]
struct PulseAuthenticatedSession {
    server_url: url::Url,
    accepted_address: IpAddr,
    cookie: Vec<u8>,
    authentication_expiration: Option<std::time::SystemTime>,
    idle_timeout: Duration,
    live_connection:
        Arc<tokio::sync::Mutex<Option<PulseIftConnection<Stream>>>>,
    graceful_bye: Arc<AtomicBool>,
}

impl std::fmt::Debug for PulseAuthenticatedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PulseAuthenticatedSession")
            .field("server_url", &self.server_url)
            .field("accepted_address", &self.accepted_address)
            .field("cookie_length", &self.cookie.len())
            .field("authentication_expiration", &self.authentication_expiration)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

struct PulseDataChannel {
    reader: tokio::io::ReadHalf<Stream>,
    writer: tokio::io::WriteHalf<Stream>,
    encoder: PulseIftEncoder,
    mtu: usize,
    allow_ipv4: bool,
    allow_ipv6: bool,
    closed: bool,
    terminal: bool,
    graceful_bye: Arc<AtomicBool>,
    esp: Option<OpenConnectEspSession>,
    late_esp: Option<PulseLateEspState>,
    last_esp_error: Option<String>,
}

#[derive(Clone)]
struct PulseEspAttempt {
    dialer: Arc<dyn Dialer>,
    configuration: PulseEspConfiguration,
    mtu: usize,
    dpd: Duration,
    queue_length: usize,
    cancellation: CancellationToken,
}

struct PulseLateEspState {
    template: PulseEspAttempt,
    next_attempt: tokio::time::Instant,
    attempt: Option<JoinHandle<Result<OpenConnectEspSession, String>>>,
}

enum PulseAuthenticationCarrier {
    Direct(Arc<tokio::sync::Mutex<PulseIftConnection<Stream>>>),
    Ttls(Box<TlsStream<PulseTtlsTransport<Stream>>>),
}

impl PulseAuthenticationCarrier {
    async fn receive_expanded(
        &mut self,
    ) -> Result<crate::protocol::openconnect::PulseEapPacket, String> {
        match self {
            Self::Direct(outer) => {
                let frame = outer
                    .lock()
                    .await
                    .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                    .await
                    .map_err(|error| error.to_string())?;
                parse_pulse_authentication_eap(&frame)
                    .map_err(|error| error.to_string())
            }
            Self::Ttls(stream) => read_pulse_inner_eap(stream)
                .await
                .map_err(|error| error.to_string()),
        }
    }

    async fn send_expanded(
        &mut self,
        identifier: u8,
        content: &[u8],
    ) -> Result<(), String> {
        let packet = build_pulse_expanded_response(identifier, content)
            .map_err(|error| error.to_string())?;
        match self {
            Self::Direct(outer) => outer
                .lock()
                .await
                .write_frame(
                    PULSE_VENDOR_TCG,
                    PULSE_IFT_CLIENT_AUTH_RESPONSE,
                    &build_pulse_authentication_payload(&packet),
                )
                .await
                .map_err(|error| error.to_string()),
            Self::Ttls(stream) => {
                write_pulse_inner_eap(stream, &packet)
                    .await
                    .map_err(|error| error.to_string())?;
                stream.flush().await.map_err(|error| error.to_string())
            }
        }
    }

    async fn flush(&mut self) -> Result<(), String> {
        match self {
            Self::Direct(_) => Ok(()),
            Self::Ttls(stream) => {
                stream.flush().await.map_err(|error| error.to_string())
            }
        }
    }
}

struct F5DataChannel {
    transport: F5PppTransport,
    last_dtls_error: Option<String>,
    late_dtls: Option<F5LateDtlsState>,
    reconnect_state: Arc<Mutex<F5ReconnectState>>,
}

enum F5PppTransport {
    Tls(PppStreamSession),
    Dtls(PppDatagramSession),
}

const F5_LATE_DTLS_RETRY_PERIOD: Duration = Duration::from_secs(5);
const F5_LATE_DTLS_TAKEOVER_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
struct F5LateDtlsAttempt {
    options: OpenConnectEndpointOptions,
    dialer: Arc<dyn Dialer>,
    authenticated: F5AuthenticatedSession,
    configuration: crate::protocol::openconnect::F5TunnelConfiguration,
    connect_request: Vec<u8>,
    accepted_address: IpAddr,
    reconnect_snapshot: F5ReconnectState,
    cancellation: CancellationToken,
}

struct F5LateDtlsState {
    template: F5LateDtlsAttempt,
    next_attempt: tokio::time::Instant,
    attempt: Option<JoinHandle<F5DtlsSessionResult>>,
}

type F5DtlsSessionResult = Result<
    (PppDatagramSession, TunnelConfiguration, Option<IpAddr>),
    EndpointConnectError,
>;

enum FortinetPppTransport {
    Tls(PppStreamSession),
    Dtls(PppDatagramSession),
}

const FORTINET_LATE_DTLS_RETRY_PERIOD: Duration = Duration::from_secs(5);
const FORTINET_LATE_DTLS_NEGOTIATION_WINDOW: Duration = Duration::from_secs(10);

struct FortinetDataChannel {
    transport: FortinetPppTransport,
    last_dtls_error: Option<String>,
    late_dtls: Option<FortinetLateDtlsState>,
    reconnect_state: Arc<Mutex<FortinetReconnectState>>,
}

#[derive(Clone)]
struct FortinetLateDtlsAttempt {
    dialer: Arc<dyn Dialer>,
    remote: SocketAddr,
    connection_options: CertificateDtlsClientOptions,
    connect_request: Vec<u8>,
    configuration: crate::protocol::openconnect::FortinetTunnelConfiguration,
    reconnect_snapshot: FortinetReconnectState,
    queue_length: usize,
    cancellation: CancellationToken,
}

struct FortinetLateDtlsState {
    template: FortinetLateDtlsAttempt,
    next_attempt: tokio::time::Instant,
    attempt: Option<FortinetLateDtlsTask>,
}

type FortinetDtlsSessionResult =
    Result<(PppDatagramSession, Option<IpAddr>), EndpointConnectError>;
type FortinetLateDtlsTask = JoinHandle<FortinetDtlsSessionResult>;

struct GlobalProtectDataChannel {
    transport: GlobalProtectTransport,
    fallback: GlobalProtectGpstFallback,
    last_esp_error: Option<String>,
    hip_runner: GlobalProtectHipRunner,
    next_hip_check: Option<tokio::time::Instant>,
    rekey_deadline: Option<tokio::time::Instant>,
    cancellation: CancellationToken,
}

enum GlobalProtectTransport {
    Esp(OpenConnectEspSession),
    Gpst(GpstSession),
}

#[derive(Clone)]
struct GlobalProtectGpstFallback {
    dialer: Arc<dyn Dialer>,
    tls: OutboundTlsOptions,
    tls_host: String,
    remote: SocksAddr,
    tunnel_path: String,
    opaque_query: String,
    mtu: usize,
    dpd: Duration,
    keepalive: Duration,
    queue_length: usize,
}

struct OpenConnectSupervisorShared {
    network_slot: Arc<Mutex<Option<Arc<OpenConnectNetwork>>>>,
    globalprotect_session:
        Arc<RwLock<Option<GlobalProtectAuthenticatedSession>>>,
    f5_session: Arc<RwLock<Option<F5AuthenticatedSession>>>,
    pulse_session: Arc<RwLock<Option<PulseAuthenticatedSession>>>,
    network_connect_session: Arc<RwLock<Option<NetworkConnectEndpointSession>>>,
    fortinet_reconnect_state: Arc<Mutex<FortinetReconnectState>>,
    f5_reconnect_state: Arc<Mutex<F5ReconnectState>>,
}

#[derive(Debug, Clone, Default)]
struct FortinetReconnectState {
    connected_once: bool,
    force_reauthentication: bool,
    previous_ipv4: Option<ipnet::Ipv4Net>,
    previous_ipv6: Option<ipnet::Ipv6Net>,
    source_ip: Option<IpAddr>,
    dropped_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Default)]
struct F5ReconnectState {
    connected_once: bool,
    previous_ipv4: Option<ipnet::Ipv4Net>,
    previous_ipv6: Option<ipnet::Ipv6Net>,
    source_ip: Option<IpAddr>,
    skip_initial_dtls: bool,
}

impl GlobalProtectGpstFallback {
    async fn connect(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<GpstSession, EndpointConnectError> {
        let raw_stream = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(EndpointConnectError::Other(
                    "GlobalProtect GPST start cancelled".into(),
                ));
            }
            result = self.dialer.dial_tcp(&self.remote) => result,
        }
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let tls = build_client_config(&self.tls_host, &self.tls, &[])
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let stream = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(EndpointConnectError::Other(
                    "GlobalProtect GPST TLS start cancelled".into(),
                ));
            }
            result = tls.connect_stream(raw_stream) => result,
        }
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let mut stream = stream.into_stream();
        let establishment = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(EndpointConnectError::Other(
                    "GlobalProtect GPST establishment cancelled".into(),
                ));
            }
            result = establish_gpst(
                &mut stream,
                &self.tunnel_path,
                &self.opaque_query,
            ) => result,
        };
        establishment.map_err(|error| match error {
            GpstError::HttpStatus {
                status,
                class: GlobalProtectFailureClass::SessionRejected,
            } => EndpointConnectError::SessionRejected(status),
            error => EndpointConnectError::Other(error.to_string()),
        })?;
        GpstSession::start(
            Box::new(stream),
            GpstSessionOptions {
                mtu: self.mtu,
                dpd: self.dpd,
                keepalive: self.keepalive,
                queue_length: self.queue_length,
            },
        )
        .map_err(|error| EndpointConnectError::Other(error.to_string()))
    }
}

impl GlobalProtectDataChannel {
    fn esp_active(&self) -> bool {
        matches!(self.transport, GlobalProtectTransport::Esp(_))
    }

    async fn switch_to_gpst(&mut self, cause: String) -> Result<(), String> {
        if let GlobalProtectTransport::Esp(session) = &mut self.transport {
            session.close().await;
        } else {
            return Err(cause);
        }
        self.last_esp_error = Some(cause);
        self.transport = GlobalProtectTransport::Gpst(
            self.fallback
                .connect(&self.cancellation)
                .await
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    async fn read_transport(&mut self) -> Result<Vec<u8>, String> {
        match &mut self.transport {
            GlobalProtectTransport::Esp(session) => session
                .read_data_packet()
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "GlobalProtect ESP channel closed".into()),
            GlobalProtectTransport::Gpst(session) => session
                .read_data_packet()
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "GlobalProtect GPST channel closed".into()),
        }
    }

    async fn perform_periodic_hip(&mut self) -> Result<(), String> {
        let was_gpst =
            matches!(self.transport, GlobalProtectTransport::Gpst(_));
        if was_gpst
            && let GlobalProtectTransport::Gpst(session) = &mut self.transport
        {
            session.close().await.map_err(|error| error.to_string())?;
        }
        let result = self
            .hip_runner
            .check()
            .await
            .map_err(|error| error.to_string())?;
        if was_gpst {
            self.transport = GlobalProtectTransport::Gpst(
                self.fallback
                    .connect(&self.cancellation)
                    .await
                    .map_err(|error| error.to_string())?,
            );
        }
        self.next_hip_check = (!result.next_check.is_zero())
            .then(|| tokio::time::Instant::now() + result.next_check);
        Ok(())
    }

    async fn receive_data(&mut self) -> Result<Vec<u8>, String> {
        loop {
            enum Event {
                Packet(Result<Vec<u8>, String>),
                Hip,
                Rekey,
            }
            let next_hip_check = self.next_hip_check;
            let rekey_deadline = self.rekey_deadline;
            let event = tokio::select! {
                packet = self.read_transport() => Event::Packet(packet),
                _ = wait_openconnect_deadline(next_hip_check) => Event::Hip,
                _ = wait_openconnect_deadline(rekey_deadline) => Event::Rekey,
            };
            match event {
                Event::Packet(Ok(packet)) => return Ok(packet),
                Event::Packet(Err(error)) if self.esp_active() => {
                    self.switch_to_gpst(error).await?;
                }
                Event::Packet(Err(error)) => return Err(error),
                Event::Hip => self.perform_periodic_hip().await?,
                Event::Rekey => {
                    return Err("GlobalProtect tunnel rekey is due".into());
                }
            }
        }
    }

    async fn send_data(&mut self, packet: &[u8]) -> Result<(), String> {
        let result = match &mut self.transport {
            GlobalProtectTransport::Esp(session) => session
                .write_data_packet(packet)
                .await
                .map_err(|error| error.to_string()),
            GlobalProtectTransport::Gpst(session) => session
                .write_data_packet(packet)
                .await
                .map_err(|error| error.to_string()),
        };
        if let Err(error) = result {
            if !self.esp_active() {
                return Err(error);
            }
            self.switch_to_gpst(error).await?;
            if let GlobalProtectTransport::Gpst(session) = &mut self.transport {
                session
                    .write_data_packet(packet)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<(), String> {
        self.cancellation.cancel();
        match &mut self.transport {
            GlobalProtectTransport::Esp(session) => {
                session.close().await;
                Ok(())
            }
            GlobalProtectTransport::Gpst(session) => {
                session.close().await.map_err(|error| error.to_string())
            }
        }
    }
}

async fn wait_openconnect_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

impl FortinetLateDtlsAttempt {
    async fn connect(
        &self,
    ) -> Result<(PppDatagramSession, Option<IpAddr>), EndpointConnectError>
    {
        let connection = connect_certificate_dtls(
            self.dialer.clone(),
            self.remote,
            self.connection_options.clone(),
            &self.cancellation,
        )
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let source_ip = connection.local_address().map(|address| address.ip());
        validate_fortinet_reconnect_source(
            &self.configuration,
            &self.reconnect_snapshot,
            source_ip,
        )?;
        let data_mtu = connection.data_mtu().saturating_sub(10);
        if data_mtu < usize::from(PPP_MINIMUM_MRU) {
            return Err(EndpointConnectError::Other(
                "Fortinet DTLS data MTU is too small for PPP".into(),
            ));
        }
        let initial_datagram = probe_fortinet_dtls(
            &connection,
            &self.connect_request,
            &self.cancellation,
        )
        .await
        .map_err(EndpointConnectError::Other)?;
        let ppp_mtu = self
            .configuration
            .configuration
            .mtu
            .min(u32::try_from(data_mtu).unwrap_or(u32::MAX));
        let channel = tokio::time::timeout(
            FORTINET_LATE_DTLS_NEGOTIATION_WINDOW,
            PppDatagramSession::connect(
                Arc::new(connection),
                PppDatagramSessionOptions {
                    negotiator: fortinet_ppp_options(
                        &self.configuration,
                        ppp_mtu,
                        self.reconnect_snapshot.connected_once,
                    ),
                    queue_length: self.queue_length,
                    initial_datagram,
                },
            ),
        )
        .await
        .map_err(|_| {
            EndpointConnectError::Other(
                "Fortinet late DTLS PPP negotiation timed out".into(),
            )
        })?
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        Ok((channel, source_ip))
    }
}

impl FortinetDataChannel {
    fn dtls_active(&self) -> bool {
        matches!(self.transport, FortinetPppTransport::Dtls(_))
    }

    async fn send_data(&mut self, packet: &[u8]) -> Result<(), String> {
        match &mut self.transport {
            FortinetPppTransport::Tls(session) => session
                .write_data_packet(packet)
                .await
                .map_err(|error| error.to_string()),
            FortinetPppTransport::Dtls(session) => session
                .write_data_packet(packet)
                .await
                .map_err(|error| error.to_string()),
        }
    }

    async fn receive_data(&mut self) -> Result<Vec<u8>, String> {
        loop {
            if let FortinetPppTransport::Dtls(session) = &mut self.transport {
                return session
                    .read_data_packet()
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "Fortinet PPP channel closed".into());
            }
            let Some(late) = self.late_dtls.as_mut() else {
                let FortinetPppTransport::Tls(session) = &mut self.transport
                else {
                    unreachable!()
                };
                return session
                    .read_data_packet()
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "Fortinet PPP channel closed".into());
            };
            if late.attempt.is_none()
                && tokio::time::Instant::now() < late.next_attempt
            {
                let FortinetPppTransport::Tls(session) = &mut self.transport
                else {
                    unreachable!()
                };
                let packet = tokio::select! {
                    packet = session.read_data_packet() => Some(packet),
                    _ = tokio::time::sleep_until(late.next_attempt) => None,
                };
                if let Some(packet) = packet {
                    return packet
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| "Fortinet PPP channel closed".into());
                }
            }
            if late.attempt.is_none() {
                let template = late.template.clone();
                late.attempt = Some(tokio::spawn(async move {
                    tokio::time::timeout(
                        Duration::from_secs(5)
                            + FORTINET_LATE_DTLS_NEGOTIATION_WINDOW,
                        template.connect(),
                    )
                    .await
                    .map_err(|_| {
                        EndpointConnectError::Other(
                            "Fortinet late DTLS takeover timed out".into(),
                        )
                    })?
                }));
            }
            enum LateDtlsEvent {
                Tls(
                    Result<
                        Option<Vec<u8>>,
                        crate::protocol::openconnect::PppStreamSessionError,
                    >,
                ),
                Dtls(
                    Box<
                        Result<
                            FortinetDtlsSessionResult,
                            tokio::task::JoinError,
                        >,
                    >,
                ),
            }
            let event = {
                let FortinetPppTransport::Tls(session) = &mut self.transport
                else {
                    unreachable!()
                };
                let attempt = late.attempt.as_mut().expect("attempt started");
                tokio::select! {
                    packet = session.read_data_packet() => LateDtlsEvent::Tls(packet),
                    result = attempt => LateDtlsEvent::Dtls(Box::new(result)),
                }
            };
            match event {
                LateDtlsEvent::Tls(packet) => {
                    return packet
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| "Fortinet PPP channel closed".into());
                }
                LateDtlsEvent::Dtls(result) => match *result {
                    Ok(Ok((channel, _source_ip))) => {
                        self.transport = FortinetPppTransport::Dtls(channel);
                        self.last_dtls_error = None;
                        self.late_dtls = None;
                    }
                    Ok(Err(EndpointConnectError::SessionRejected(status))) => {
                        if let Ok(mut state) = self.reconnect_state.lock() {
                            state.force_reauthentication = true;
                        }
                        return Err(format!(
                            "Fortinet late DTLS session rejected with HTTP status {status}"
                        ));
                    }
                    Ok(Err(error)) => {
                        self.last_dtls_error = Some(error.to_string());
                        late.attempt = None;
                        late.next_attempt = tokio::time::Instant::now()
                            + FORTINET_LATE_DTLS_RETRY_PERIOD;
                    }
                    Err(error) => {
                        self.last_dtls_error = Some(format!(
                            "Fortinet late DTLS task failed: {error}"
                        ));
                        late.attempt = None;
                        late.next_attempt = tokio::time::Instant::now()
                            + FORTINET_LATE_DTLS_RETRY_PERIOD;
                    }
                },
            }
        }
    }

    async fn close(&mut self) -> Result<(), String> {
        if let Some(mut late) = self.late_dtls.take()
            && let Some(attempt) = late.attempt.take()
        {
            attempt.abort();
            let _ = attempt.await;
        }
        match &mut self.transport {
            FortinetPppTransport::Tls(session) => {
                session.close().await.map_err(|error| error.to_string())
            }
            FortinetPppTransport::Dtls(session) => {
                session.close().await.map_err(|error| error.to_string())
            }
        }
    }
}

impl F5LateDtlsAttempt {
    async fn connect(&self) -> F5DtlsSessionResult {
        connect_f5_dtls(
            &self.options,
            self.dialer.clone(),
            &self.authenticated,
            &self.configuration,
            &self.connect_request,
            self.accepted_address,
            &self.reconnect_snapshot,
            &self.cancellation,
        )
        .await
    }
}

impl F5DataChannel {
    fn dtls_active(&self) -> bool {
        matches!(self.transport, F5PppTransport::Dtls(_))
    }

    async fn send_data(&mut self, packet: &[u8]) -> Result<(), String> {
        let result = match &mut self.transport {
            F5PppTransport::Tls(session) => session
                .write_data_packet(packet)
                .await
                .map_err(|error| error.to_string()),
            F5PppTransport::Dtls(session) => session
                .write_data_packet(packet)
                .await
                .map_err(|error| error.to_string()),
        };
        if result.is_err()
            && self.dtls_active()
            && let Ok(mut state) = self.reconnect_state.lock()
        {
            state.skip_initial_dtls = true;
        }
        result
    }

    async fn receive_data(&mut self) -> Result<Vec<u8>, String> {
        loop {
            if let F5PppTransport::Dtls(session) = &mut self.transport {
                return match session.read_data_packet().await {
                    Ok(Some(packet)) => Ok(packet),
                    Ok(None) => Err("F5 PPP channel closed".into()),
                    Err(error) => {
                        if let Ok(mut state) = self.reconnect_state.lock() {
                            state.skip_initial_dtls = true;
                        }
                        Err(error.to_string())
                    }
                };
            }
            let Some(late) = self.late_dtls.as_mut() else {
                let F5PppTransport::Tls(session) = &mut self.transport else {
                    unreachable!()
                };
                return session
                    .read_data_packet()
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "F5 PPP channel closed".into());
            };
            if late.attempt.is_none()
                && tokio::time::Instant::now() < late.next_attempt
            {
                let F5PppTransport::Tls(session) = &mut self.transport else {
                    unreachable!()
                };
                let packet = tokio::select! {
                    packet = session.read_data_packet() => Some(packet),
                    _ = tokio::time::sleep_until(late.next_attempt) => None,
                };
                if let Some(packet) = packet {
                    return packet
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| "F5 PPP channel closed".into());
                }
            }
            if late.attempt.is_none() {
                let template = late.template.clone();
                late.attempt = Some(tokio::spawn(async move {
                    tokio::time::timeout(
                        F5_LATE_DTLS_TAKEOVER_TIMEOUT,
                        template.connect(),
                    )
                    .await
                    .map_err(|_| {
                        EndpointConnectError::Other(
                            "F5 late DTLS takeover timed out".into(),
                        )
                    })?
                }));
            }
            enum Event {
                Tls(
                    Result<
                        Option<Vec<u8>>,
                        crate::protocol::openconnect::PppStreamSessionError,
                    >,
                ),
                Dtls(Box<Result<F5DtlsSessionResult, tokio::task::JoinError>>),
            }
            let event = {
                let F5PppTransport::Tls(session) = &mut self.transport else {
                    unreachable!()
                };
                let attempt = late.attempt.as_mut().expect("attempt started");
                tokio::select! {
                    packet = session.read_data_packet() => Event::Tls(packet),
                    result = attempt => Event::Dtls(Box::new(result)),
                }
            };
            match event {
                Event::Tls(packet) => {
                    return packet
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| "F5 PPP channel closed".into());
                }
                Event::Dtls(result) => match *result {
                    Ok(Ok((channel, _, source_ip))) => {
                        if let Ok(mut state) = self.reconnect_state.lock() {
                            state.source_ip = source_ip;
                            state.skip_initial_dtls = false;
                        }
                        self.transport = F5PppTransport::Dtls(channel);
                        self.last_dtls_error = None;
                        self.late_dtls = None;
                    }
                    Ok(Err(EndpointConnectError::SessionRejected(status))) => {
                        return Err(format!(
                            "F5 late DTLS session rejected with HTTP status {status}"
                        ));
                    }
                    Ok(Err(error)) => {
                        self.last_dtls_error = Some(error.to_string());
                        late.attempt = None;
                        late.next_attempt = tokio::time::Instant::now()
                            + F5_LATE_DTLS_RETRY_PERIOD;
                    }
                    Err(error) => {
                        self.last_dtls_error =
                            Some(format!("F5 late DTLS task failed: {error}"));
                        late.attempt = None;
                        late.next_attempt = tokio::time::Instant::now()
                            + F5_LATE_DTLS_RETRY_PERIOD;
                    }
                },
            }
        }
    }

    async fn close(&mut self) -> Result<(), String> {
        if let Some(mut late) = self.late_dtls.take()
            && let Some(attempt) = late.attempt.take()
        {
            attempt.abort();
            let _ = attempt.await;
        }
        match &mut self.transport {
            F5PppTransport::Tls(session) => {
                session.close().await.map_err(|error| error.to_string())
            }
            F5PppTransport::Dtls(session) => {
                session.close().await.map_err(|error| error.to_string())
            }
        }
    }
}

impl NetworkConnectDataChannel {
    fn start_periodic_tncc(
        &mut self,
        runner: Option<Arc<tokio::sync::Mutex<NetworkConnectTnccRunner>>>,
        override_interval: Option<Duration>,
    ) {
        let Some(runner) = runner else {
            return;
        };
        let cancellation = self.cancellation.clone();
        let failure = self.tncc_failure.clone();
        self.tncc_task = Some(tokio::spawn(async move {
            let runner_interval = runner.lock().await.interval();
            let interval = override_interval.unwrap_or(runner_interval);
            if interval.is_zero() {
                return;
            }
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => return,
                    _ = tokio::time::sleep(interval) => {}
                }
                let result = runner.lock().await.refresh().await;
                if let Err(error) = result {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(format!(
                            "periodic Network Connect TNCC failed: {error}"
                        ));
                    }
                    cancellation.cancel();
                    return;
                }
            }
        }));
    }

    fn cancellation_error(&self) -> String {
        self.tncc_failure
            .lock()
            .ok()
            .and_then(|error| error.clone())
            .unwrap_or_else(|| "Network Connect data channel cancelled".into())
    }

    fn valid_packet(&self, packet: &[u8]) -> bool {
        packet.len() <= self.mtu
            && crate::protocol::openconnect::validate_network_connect_ipv4_packet(
                packet, true,
            )
            .is_ok()
    }

    fn start_esp_attempt(&mut self) {
        let Some(configuration) = self.esp_configuration.clone() else {
            return;
        };
        let dialer = self.dialer.clone();
        let mtu = self.mtu;
        let queue_length = self.queue_length;
        let cancellation = self.cancellation.clone();
        self.esp_attempt = Some(tokio::spawn(async move {
            let keys = OpenConnectEspKeySet::new(&configuration.keys)
                .map(Arc::new)
                .map_err(|error| error.to_string())?;
            let mut session = OpenConnectEspSession::connect(
                dialer,
                OpenConnectEspSessionOptions {
                    remote: configuration.remote,
                    keys,
                    mtu,
                    dpd: configuration.dpd,
                    probe: OpenConnectEspProbe::Pulse,
                    probe_next_header: crate::protocol::openconnect::OPENCONNECT_ESP_IPV4_NEXT_HEADER,
                    accept_lzo: true,
                    queue_length,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
            let established = tokio::select! {
                _ = cancellation.cancelled() => {
                    Err("Network Connect ESP establishment cancelled".to_owned())
                }
                result = session.establish() => {
                    result.map_err(|error| error.to_string())
                }
            };
            if let Err(error) = established {
                session.close().await;
                return Err(error);
            }
            Ok(session)
        }));
    }

    async fn accept_esp_attempt(
        &mut self,
        result: Result<
            Result<OpenConnectEspSession, String>,
            tokio::task::JoinError,
        >,
    ) -> Result<(), String> {
        self.esp_attempt = None;
        match result {
            Ok(Ok(session)) => {
                let control = encode_network_connect_oncp_esp_control(true)
                    .map_err(|error| error.to_string())?;
                self.writer
                    .write_record(&control)
                    .await
                    .map_err(|error| error.to_string())?;
                self.writer
                    .flush()
                    .await
                    .map_err(|error| error.to_string())?;
                self.esp = Some(session);
                self.esp_enabled = true;
                self.last_esp_error = None;
            }
            Ok(Err(error)) => {
                self.last_esp_error = Some(error);
                self.esp_configuration = None;
                self.esp_parameters = None;
            }
            Err(error) => {
                self.last_esp_error =
                    Some(format!("Network Connect ESP task failed: {error}"));
                self.esp_configuration = None;
                self.esp_parameters = None;
            }
        }
        Ok(())
    }

    async fn fallback_from_esp(&mut self, error: String) -> Result<(), String> {
        self.last_esp_error = Some(error);
        if self.esp_enabled {
            let control = encode_network_connect_oncp_esp_control(false)
                .map_err(|error| error.to_string())?;
            self.writer
                .write_record(&control)
                .await
                .map_err(|error| error.to_string())?;
            self.writer
                .flush()
                .await
                .map_err(|error| error.to_string())?;
        }
        self.esp_enabled = false;
        if let Some(mut session) = self.esp.take() {
            session.close().await;
        }
        self.esp_configuration = None;
        self.esp_parameters = None;
        Ok(())
    }

    async fn handle_kmp(
        &mut self,
        message_type: u16,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        match message_type {
            NETWORK_CONNECT_ONCP_KMP_DATA => {
                let mut remaining = payload.as_slice();
                while !remaining.is_empty() {
                    let length = crate::protocol::openconnect::validate_network_connect_ipv4_packet(
                        remaining, false,
                    )
                    .map_err(|error| error.to_string())?;
                    self.queued_packets.push_back(remaining[..length].to_vec());
                    remaining = &remaining[length..];
                }
            }
            NETWORK_CONNECT_ONCP_KMP_ESP => {
                let (Some(previous), Some(current)) = (
                    self.esp_parameters.clone(),
                    self.esp_configuration.clone(),
                ) else {
                    return Ok(());
                };
                if self.esp.is_none() {
                    return Ok(());
                }
                let mut parameters = match parse_network_connect_oncp_esp_rekey(
                    &payload, previous,
                ) {
                    Ok(parameters) => parameters,
                    Err(error) => {
                        return self
                            .fallback_from_esp(format!(
                                "Network Connect ESP rekey failed: {error}"
                            ))
                            .await;
                    }
                };
                if let Some(dpd) = self.dpd_override {
                    parameters.dpd = dpd;
                }
                if parameters.port != current.port {
                    return self
                        .fallback_from_esp(
                            "Network Connect ESP rekey changed UDP port".into(),
                        )
                        .await;
                }
                let (configuration, response) =
                    match prepare_network_connect_esp(
                        current.remote.ip(),
                        &parameters,
                    ) {
                        Ok(result) => result,
                        Err(error) => {
                            return self
                                .fallback_from_esp(format!(
                                    "Network Connect ESP rekey failed: {error}"
                                ))
                                .await;
                        }
                    };
                self.esp
                    .as_ref()
                    .expect("checked above")
                    .install_keys(&configuration.keys)
                    .map_err(|error| error.to_string())?;
                self.writer
                    .write_record(&response)
                    .await
                    .map_err(|error| error.to_string())?;
                self.writer
                    .flush()
                    .await
                    .map_err(|error| error.to_string())?;
                self.esp_configuration = Some(configuration);
                self.esp_parameters = Some(parameters);
            }
            NETWORK_CONNECT_ONCP_KMP_CONTROL => {
                if !parse_network_connect_oncp_esp_control(&payload)
                    .map_err(|error| error.to_string())?
                {
                    self.esp_enabled = false;
                    if let Some(mut session) = self.esp.take() {
                        session.close().await;
                    }
                    self.esp_configuration = None;
                    self.esp_parameters = None;
                }
            }
            _ => {
                return Err(format!(
                    "oNCP received unknown KMP {message_type}"
                ));
            }
        }
        Ok(())
    }

    async fn send_data(&mut self, packet: &[u8]) -> Result<(), String> {
        if self.closed {
            return Err("Network Connect data channel is closed".into());
        }
        if !self.valid_packet(packet) {
            return Err("invalid Network Connect IPv4 data packet".into());
        }
        if self.esp_enabled
            && let Some(session) = self.esp.as_mut()
        {
            match session.write_data_packet(packet).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    self.fallback_from_esp(error.to_string()).await?;
                }
            }
        }
        self.writer
            .write_kmp(NETWORK_CONNECT_ONCP_KMP_DATA, packet)
            .await
            .map_err(|error| error.to_string())?;
        self.writer.flush().await.map_err(|error| error.to_string())
    }

    async fn receive_data(&mut self) -> Result<Vec<u8>, String> {
        if self.closed {
            return Err("Network Connect data channel is closed".into());
        }
        loop {
            if let Some(packet) = self.queued_packets.pop_front() {
                return Ok(packet);
            }
            if self.esp_enabled
                && let Some(esp) = self.esp.as_mut()
            {
                enum Event {
                    Oncp(Result<(u16, Vec<u8>), crate::protocol::openconnect::NetworkConnectOncpError>),
                    Esp(Result<Option<Vec<u8>>, crate::protocol::openconnect::OpenConnectEspChannelError>),
                }
                let event = tokio::select! {
                    _ = self.cancellation.cancelled() => {
                        return Err(self.cancellation_error());
                    }
                    message = self.reader.read_kmp() => Event::Oncp(message),
                    packet = esp.read_data_packet() => Event::Esp(packet),
                };
                match event {
                    Event::Oncp(result) => {
                        let (message_type, payload) =
                            result.map_err(|error| error.to_string())?;
                        self.handle_kmp(message_type, payload).await?;
                    }
                    Event::Esp(Ok(Some(packet))) => {
                        if self.valid_packet(&packet) {
                            return Ok(packet);
                        }
                    }
                    Event::Esp(Ok(None)) => {
                        self.fallback_from_esp(
                            "Network Connect ESP channel closed".into(),
                        )
                        .await?;
                    }
                    Event::Esp(Err(error)) => {
                        self.fallback_from_esp(error.to_string()).await?;
                    }
                }
                continue;
            }
            if self.esp_attempt.is_some() {
                enum Event {
                    Oncp(Result<(u16, Vec<u8>), crate::protocol::openconnect::NetworkConnectOncpError>),
                    Esp(Result<Result<OpenConnectEspSession, String>, tokio::task::JoinError>),
                }
                let event = {
                    let attempt = self.esp_attempt.as_mut().unwrap();
                    tokio::select! {
                        _ = self.cancellation.cancelled() => {
                            return Err(self.cancellation_error());
                        }
                        message = self.reader.read_kmp() => Event::Oncp(message),
                        result = attempt => Event::Esp(result),
                    }
                };
                match event {
                    Event::Oncp(result) => {
                        let (message_type, payload) =
                            result.map_err(|error| error.to_string())?;
                        self.handle_kmp(message_type, payload).await?;
                    }
                    Event::Esp(result) => {
                        self.accept_esp_attempt(result).await?
                    }
                }
                continue;
            }
            let (message_type, payload) = tokio::select! {
                _ = self.cancellation.cancelled() => {
                    return Err(self.cancellation_error());
                }
                result = self.reader.read_kmp() => result,
            }
            .map_err(|error| error.to_string())?;
            self.handle_kmp(message_type, payload).await?;
        }
    }

    async fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.cancellation.cancel();
        if let Some(task) = self.tncc_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(attempt) = self.esp_attempt.take() {
            attempt.abort();
            let _ = attempt.await;
        }
        let mut first_error = None;
        if self.esp_enabled {
            let disable = async {
                let control = encode_network_connect_oncp_esp_control(false)
                    .map_err(|error| error.to_string())?;
                self.writer
                    .write_record(&control)
                    .await
                    .map_err(|error| error.to_string())?;
                self.writer.flush().await.map_err(|error| error.to_string())
            };
            if let Err(error) =
                tokio::time::timeout(Duration::from_secs(2), disable)
                    .await
                    .map_err(|_| {
                        "Network Connect ESP disable timed out".to_owned()
                    })
                    .and_then(|result| result)
            {
                first_error = Some(error);
            }
        }
        if let Some(mut session) = self.esp.take() {
            session.close().await;
        }
        if let Err(error) = self.writer.shutdown().await
            && first_error.is_none()
        {
            first_error = Some(error.to_string());
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl OpenConnectDataChannel {
    fn dtls_active(&self) -> bool {
        match self {
            Self::AnyConnect(channel) => channel.dtls_active(),
            Self::GlobalProtect(channel) => channel.esp_active(),
            Self::Fortinet(channel) => channel.dtls_active(),
            Self::F5(channel) => channel.dtls_active(),
            Self::Pulse(channel) => channel
                .esp
                .as_ref()
                .is_some_and(OpenConnectEspSession::ready),
            Self::NetworkConnect(channel) => channel.esp_enabled,
        }
    }

    fn last_dtls_error(&self) -> Option<&str> {
        match self {
            Self::AnyConnect(channel) => channel.last_dtls_error(),
            Self::GlobalProtect(channel) => channel.last_esp_error.as_deref(),
            Self::Fortinet(channel) => channel.last_dtls_error.as_deref(),
            Self::F5(channel) => channel.last_dtls_error.as_deref(),
            Self::Pulse(channel) => channel.last_esp_error.as_deref(),
            Self::NetworkConnect(channel) => channel.last_esp_error.as_deref(),
        }
    }

    fn anyconnect_configuration(&self) -> Option<&TunnelConfiguration> {
        match self {
            Self::AnyConnect(channel) => {
                Some(&channel.negotiated().configuration)
            }
            _ => None,
        }
    }

    async fn send_data(&mut self, packet: &[u8]) -> Result<(), String> {
        match self {
            Self::AnyConnect(channel) => channel
                .send_data(packet)
                .await
                .map_err(|error| error.to_string()),
            Self::GlobalProtect(channel) => channel.send_data(packet).await,
            Self::Fortinet(channel) => channel.send_data(packet).await,
            Self::F5(channel) => channel.send_data(packet).await,
            Self::Pulse(channel) => channel.send_data(packet).await,
            Self::NetworkConnect(channel) => channel.send_data(packet).await,
        }
    }

    async fn receive_event(
        &mut self,
    ) -> Result<OpenConnectDataChannelEvent, OpenConnectTransportError> {
        match self {
            Self::AnyConnect(channel) => match channel.receive_event().await {
                Err(error) if error.is_terminal() => {
                    Err(OpenConnectTransportError::Terminal(error.to_string()))
                }
                Err(error) => {
                    Err(OpenConnectTransportError::Retryable(error.to_string()))
                }
                Ok(event) => match event {
                    AnyConnectChannelEvent::Data(packet) => {
                        Ok(OpenConnectDataChannelEvent::Data(packet))
                    }
                    AnyConnectChannelEvent::TransportStateChanged => {
                        Ok(OpenConnectDataChannelEvent::TransportStateChanged)
                    }
                },
            },
            Self::GlobalProtect(channel) => channel
                .receive_data()
                .await
                .map(OpenConnectDataChannelEvent::Data)
                .map_err(OpenConnectTransportError::Retryable),
            Self::Fortinet(channel) => channel
                .receive_data()
                .await
                .map(OpenConnectDataChannelEvent::Data)
                .map_err(OpenConnectTransportError::Retryable),
            Self::F5(channel) => channel
                .receive_data()
                .await
                .map(OpenConnectDataChannelEvent::Data)
                .map_err(OpenConnectTransportError::Retryable),
            Self::Pulse(channel) => channel
                .receive_data()
                .await
                .map(OpenConnectDataChannelEvent::Data)
                .map_err(OpenConnectTransportError::Retryable),
            Self::NetworkConnect(channel) => channel
                .receive_data()
                .await
                .map(OpenConnectDataChannelEvent::Data)
                .map_err(OpenConnectTransportError::Retryable),
        }
    }

    async fn close(&mut self) -> Result<(), String> {
        match self {
            Self::AnyConnect(channel) => {
                channel.close().await.map_err(|error| error.to_string())
            }
            Self::GlobalProtect(channel) => channel.close().await,
            Self::Fortinet(channel) => channel.close().await,
            Self::F5(channel) => channel.close().await,
            Self::Pulse(channel) => channel.close().await,
            Self::NetworkConnect(channel) => channel.close().await,
        }
    }
}

impl PulseEspAttempt {
    async fn connect(&self) -> Result<OpenConnectEspSession, String> {
        let keys = OpenConnectEspKeySet::new(&self.configuration.keys)
            .map(Arc::new)
            .map_err(|error| error.to_string())?;
        let mut session = OpenConnectEspSession::connect(
            self.dialer.clone(),
            OpenConnectEspSessionOptions {
                remote: self.configuration.remote,
                keys,
                mtu: self.mtu,
                dpd: self.dpd,
                probe: OpenConnectEspProbe::Pulse,
                probe_next_header: self.configuration.probe_next_header,
                accept_lzo: true,
                queue_length: self.queue_length,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
        let established = tokio::select! {
            _ = self.cancellation.cancelled() => {
                Err("Pulse ESP establishment cancelled".to_owned())
            }
            result = session.establish() => result.map_err(|error| error.to_string()),
        };
        if let Err(error) = established {
            session.close().await;
            return Err(error);
        }
        Ok(session)
    }
}

impl PulseDataChannel {
    fn valid_packet(&self, packet: &[u8]) -> bool {
        let version =
            crate::protocol::openconnect::pulse_packet_version(packet);
        !packet.is_empty()
            && packet.len() <= self.mtu
            && matches!(version, 4 | 6)
            && (version != 4 || self.allow_ipv4)
            && (version != 6 || self.allow_ipv6)
    }

    fn esp_allows_packet(&self, packet: &[u8]) -> bool {
        let Some(late) = &self.late_esp else {
            return false;
        };
        let version =
            crate::protocol::openconnect::pulse_packet_version(packet);
        late.template.configuration.cross_family
            || (version == 4
                && late.template.configuration.remote.ip().is_ipv4())
            || (version == 6
                && late.template.configuration.remote.ip().is_ipv6())
    }

    fn schedule_esp_retry(&mut self) {
        if let Some(late) = self.late_esp.as_mut() {
            late.next_attempt = tokio::time::Instant::now()
                + late.template.configuration.fallback;
            late.attempt = None;
        }
    }

    async fn handle_ift_frame(
        &mut self,
        frame: crate::protocol::openconnect::PulseIftFrame,
    ) -> Result<Option<Vec<u8>>, String> {
        if frame.vendor != PULSE_VENDOR_JUNIPER {
            return Ok(None);
        }
        match frame.frame_type {
            4 if self.valid_packet(&frame.payload) => Ok(Some(frame.payload)),
            0x93 => {
                self.terminal = true;
                let (reason, message) = parse_pulse_fatal_error(&frame.payload)
                    .map_err(|error| error.to_string())?;
                Err(format!("Pulse fatal error {reason}: {message}"))
            }
            1 => {
                let rekey = self
                    .late_esp
                    .as_ref()
                    .map(|late| late.template.configuration.clone())
                    .ok_or_else(|| {
                        "server requested Pulse ESP rekey without an active ESP configuration"
                            .to_owned()
                    })
                    .and_then(|previous| {
                        PulseConfigurationAccumulator::parse_esp_rekey(
                            &frame.payload,
                            &previous,
                        )
                        .map_err(|error| error.to_string())
                    });
                match rekey {
                    Ok((configuration, response)) => {
                        if let Some(late) = self.late_esp.as_mut() {
                            if let Some(attempt) = late.attempt.take() {
                                attempt.abort();
                            }
                            late.template.configuration = configuration.clone();
                            late.next_attempt = tokio::time::Instant::now();
                        }
                        if let Some(esp) = self.esp.as_ref()
                            && let Err(error) =
                                esp.install_keys(&configuration.keys)
                        {
                            self.last_esp_error = Some(format!(
                                "Pulse ESP rekey failed; suppressing ESP: {error}"
                            ));
                            self.late_esp = None;
                            if let Some(mut esp) = self.esp.take() {
                                esp.close().await;
                            }
                            return Ok(None);
                        }
                        self.encoder
                            .write(
                                &mut self.writer,
                                PULSE_VENDOR_JUNIPER,
                                1,
                                &response,
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                        self.writer
                            .flush()
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                    Err(error) => {
                        self.last_esp_error = Some(format!(
                            "Pulse ESP rekey failed; suppressing ESP: {error}"
                        ));
                        if let Some(late) = self.late_esp.as_mut()
                            && let Some(attempt) = late.attempt.take()
                        {
                            attempt.abort();
                        }
                        self.late_esp = None;
                        if let Some(mut esp) = self.esp.take() {
                            esp.close().await;
                        }
                    }
                }
                Ok(None)
            }
            0x96 => Ok(None),
            _ => Ok(None),
        }
    }

    async fn read_ift_frame(
        &mut self,
    ) -> Result<crate::protocol::openconnect::PulseIftFrame, String> {
        match read_pulse_ift_frame(
            &mut self.reader,
            self.mtu.max(PULSE_AUTHENTICATION_FRAME_LIMIT)
                + PULSE_IFT_HEADER_SIZE,
        )
        .await
        {
            Ok(frame) => Ok(frame),
            Err(error) => {
                self.terminal = true;
                Err(error.to_string())
            }
        }
    }

    async fn send_data(&mut self, packet: &[u8]) -> Result<(), String> {
        if self.closed {
            return Err("Pulse data channel is closed".into());
        }
        if !self.valid_packet(packet) {
            return Err("invalid Pulse data packet".into());
        }
        if self.esp_allows_packet(packet)
            && let Some(esp) = self.esp.as_mut()
        {
            match esp.write_data_packet(packet).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    self.last_esp_error = Some(error.to_string());
                    esp.close().await;
                    self.esp = None;
                    self.schedule_esp_retry();
                }
            }
        }
        if let Err(error) = self
            .encoder
            .write(&mut self.writer, PULSE_VENDOR_JUNIPER, 4, packet)
            .await
        {
            self.terminal = true;
            return Err(error.to_string());
        }
        if let Err(error) = self.writer.flush().await {
            self.terminal = true;
            return Err(error.to_string());
        }
        Ok(())
    }

    async fn receive_data(&mut self) -> Result<Vec<u8>, String> {
        if self.closed {
            return Err("Pulse data channel is closed".into());
        }
        loop {
            if let Some(esp) = self.esp.as_mut() {
                enum ActiveEvent {
                    Ift(Result<crate::protocol::openconnect::PulseIftFrame, crate::protocol::openconnect::PulseIftError>),
                    Esp(Result<Option<Vec<u8>>, crate::protocol::openconnect::OpenConnectEspChannelError>),
                }
                let event = tokio::select! {
                    frame = read_pulse_ift_frame(
                        &mut self.reader,
                        self.mtu.max(PULSE_AUTHENTICATION_FRAME_LIMIT) + PULSE_IFT_HEADER_SIZE,
                    ) => ActiveEvent::Ift(frame),
                    packet = esp.read_data_packet() => ActiveEvent::Esp(packet),
                };
                match event {
                    ActiveEvent::Ift(Ok(frame)) => {
                        if let Some(packet) =
                            self.handle_ift_frame(frame).await?
                        {
                            return Ok(packet);
                        }
                    }
                    ActiveEvent::Ift(Err(error)) => {
                        self.terminal = true;
                        return Err(error.to_string());
                    }
                    ActiveEvent::Esp(Ok(Some(packet))) => {
                        if self.valid_packet(&packet)
                            && self.esp_allows_packet(&packet)
                        {
                            return Ok(packet);
                        }
                    }
                    ActiveEvent::Esp(Ok(None)) => {
                        self.last_esp_error =
                            Some("Pulse ESP channel closed".into());
                        self.esp = None;
                        self.schedule_esp_retry();
                    }
                    ActiveEvent::Esp(Err(error)) => {
                        self.last_esp_error = Some(error.to_string());
                        if let Some(mut esp) = self.esp.take() {
                            esp.close().await;
                        }
                        self.schedule_esp_retry();
                    }
                }
                continue;
            }

            if self.late_esp.is_some() {
                let start_now = {
                    let late = self.late_esp.as_ref().unwrap();
                    late.attempt.is_none()
                        && tokio::time::Instant::now() >= late.next_attempt
                };
                if start_now {
                    let late = self.late_esp.as_mut().unwrap();
                    let template = late.template.clone();
                    late.attempt =
                        Some(tokio::spawn(
                            async move { template.connect().await },
                        ));
                }
                let attempt_running = self
                    .late_esp
                    .as_ref()
                    .is_some_and(|late| late.attempt.is_some());
                if attempt_running {
                    enum PendingEvent {
                        Ift(
                            Result<
                                crate::protocol::openconnect::PulseIftFrame,
                                crate::protocol::openconnect::PulseIftError,
                            >,
                        ),
                        Esp(
                            Result<
                                Result<OpenConnectEspSession, String>,
                                tokio::task::JoinError,
                            >,
                        ),
                    }
                    let event = {
                        let late = self.late_esp.as_mut().unwrap();
                        let attempt = late.attempt.as_mut().unwrap();
                        tokio::select! {
                            frame = read_pulse_ift_frame(
                                &mut self.reader,
                                self.mtu.max(PULSE_AUTHENTICATION_FRAME_LIMIT) + PULSE_IFT_HEADER_SIZE,
                            ) => PendingEvent::Ift(frame),
                            result = attempt => PendingEvent::Esp(result),
                        }
                    };
                    match event {
                        PendingEvent::Ift(Ok(frame)) => {
                            if let Some(packet) =
                                self.handle_ift_frame(frame).await?
                            {
                                return Ok(packet);
                            }
                        }
                        PendingEvent::Ift(Err(error)) => {
                            self.terminal = true;
                            return Err(error.to_string());
                        }
                        PendingEvent::Esp(Ok(Ok(session))) => {
                            self.esp = Some(session);
                            self.last_esp_error = None;
                            if let Some(late) = self.late_esp.as_mut() {
                                late.attempt = None;
                            }
                        }
                        PendingEvent::Esp(Ok(Err(error))) => {
                            self.last_esp_error = Some(error);
                            self.schedule_esp_retry();
                        }
                        PendingEvent::Esp(Err(error)) => {
                            self.last_esp_error =
                                Some(format!("Pulse ESP task failed: {error}"));
                            self.schedule_esp_retry();
                        }
                    }
                    continue;
                }
                let next_attempt = self.late_esp.as_ref().unwrap().next_attempt;
                tokio::select! {
                    frame = self.read_ift_frame() => {
                        if let Some(packet) =
                            self.handle_ift_frame(frame?).await?
                        {
                            return Ok(packet);
                        }
                    }
                    _ = tokio::time::sleep_until(next_attempt) => {}
                }
                continue;
            }

            let frame = self.read_ift_frame().await?;
            if let Some(packet) = self.handle_ift_frame(frame).await? {
                return Ok(packet);
            }
        }
    }

    async fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if let Some(late) = self.late_esp.as_mut()
            && let Some(attempt) = late.attempt.take()
        {
            attempt.abort();
            let _ = attempt.await;
        }
        if let Some(mut esp) = self.esp.take() {
            esp.close().await;
        }
        if self.terminal {
            let _ = self.writer.shutdown().await;
            return Ok(());
        }
        let result = self
            .encoder
            .write(&mut self.writer, PULSE_VENDOR_JUNIPER, 0x89, &[])
            .await
            .map_err(|error| error.to_string());
        if result.is_ok() {
            self.graceful_bye.store(true, Ordering::Release);
        }
        let _ = self.writer.flush().await;
        let _ = self.writer.shutdown().await;
        result
    }
}

impl OpenConnectEndpointService {
    pub fn new_with_resolver(
        tag: impl Into<String>,
        mut options: OpenConnectEndpointOptions,
        transport_dialer: Arc<dyn Dialer>,
        resolver: SharedResolver,
        strategy: DomainStrategy,
        router: Arc<crate::route::Router>,
        outbounds: Arc<OutboundManager>,
    ) -> io::Result<(Self, OpenConnectEndpointHandle)> {
        if !matches!(
            options.flavor.as_str(),
            "" | "anyconnect" | "gp" | "fortinet" | "f5" | "pulse" | "nc"
        ) {
            return Err(unsupported(format!(
                "OpenConnect flavor {:?} is not ported yet",
                options.flavor
            )));
        }
        normalize_openconnect_tls_client_key(&mut options)?;
        validate_runtime_options(&options)?;
        let transport_dialer = if options.dtls_local_port == 0 {
            transport_dialer
        } else {
            Arc::new(UdpBindPortDialer {
                inner: transport_dialer,
                local_port: options.dtls_local_port,
            }) as Arc<dyn Dialer>
        };
        let token_factory = load_openconnect_oath_token_factory(&options)?;
        let securid_token_factory =
            load_openconnect_securid_token_factory(&options)?;
        let tag = tag.into();
        let handle = OpenConnectEndpointHandle {
            dialer: Arc::new(OpenConnectEndpointDialer {
                net: RwLock::default(),
                configuration: RwLock::default(),
                resolver: Some(resolver),
                strategy,
                packet_port: Arc::default(),
            }),
            tunnel_configuration: Arc::default(),
            dtls_active: Arc::default(),
            last_dtls_error: Arc::default(),
            last_error: Arc::default(),
            challenge_manager: Arc::default(),
            successful_reconnections: Arc::default(),
            userspace_stack_generation: Arc::default(),
            token_factory,
            securid_token_factory,
            flow: EndpointFlowContext {
                tag: tag.clone(),
                router,
                outbounds,
                udp_timeout: options
                    .udp_timeout
                    .as_std()
                    .filter(|duration| !duration.is_zero())
                    .unwrap_or(crate::constant::UDP_TIMEOUT),
                udp_mapping: options.udp_mapping,
                udp_filtering: options.udp_filtering,
                udp_nat_max: options.udp_nat_max,
            },
        };
        Ok((
            Self {
                name: format!("endpoint/{tag}"),
                options,
                transport_dialer,
                handle: handle.clone(),
                cancellation: CancellationToken::new(),
                network: Arc::default(),
                globalprotect_session: Arc::default(),
                f5_session: Arc::default(),
                pulse_session: Arc::default(),
                network_connect_session: Arc::default(),
                fortinet_reconnect_state: Arc::default(),
                f5_reconnect_state: Arc::default(),
                supervisor_task: None,
            },
            handle,
        ))
    }

    async fn authenticate(
        &self,
    ) -> Result<OpenConnectAuthenticatedSession, String> {
        authenticate_openconnect(
            &self.options,
            self.transport_dialer.clone(),
            &self.handle,
            &self.cancellation,
        )
        .await
    }

    async fn connect_authenticated(
        &self,
        authenticated: &OpenConnectAuthenticatedSession,
    ) -> Result<
        (OpenConnectDataChannel, TunnelConfiguration),
        EndpointConnectError,
    > {
        connect_authenticated_openconnect(
            &self.options,
            self.transport_dialer.clone(),
            authenticated,
            &self.cancellation,
            &self.globalprotect_session,
            &self.fortinet_reconnect_state,
            &self.f5_reconnect_state,
        )
        .await
    }
}

#[derive(Debug)]
enum EndpointConnectError {
    SessionRejected(u16),
    Terminal(String),
    Other(String),
}

async fn authenticate_openconnect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: &OpenConnectEndpointHandle,
    cancellation: &CancellationToken,
) -> Result<OpenConnectAuthenticatedSession, String> {
    match options.flavor.as_str() {
        "gp" => authenticate_globalprotect(
            options,
            transport_dialer,
            handle,
            cancellation,
        )
        .await
        .map(OpenConnectAuthenticatedSession::GlobalProtect),
        "fortinet" => authenticate_fortinet(
            options,
            transport_dialer,
            handle,
            cancellation,
        )
        .await
        .map(OpenConnectAuthenticatedSession::Fortinet),
        "f5" => {
            authenticate_f5(options, transport_dialer, handle, cancellation)
                .await
                .map(OpenConnectAuthenticatedSession::F5)
        }
        "pulse" => authenticate_pulse(
            options,
            transport_dialer,
            &handle.challenge_manager,
            cancellation,
            false,
            None,
            openconnect_software_token_generator(handle),
        )
        .await
        .map(OpenConnectAuthenticatedSession::Pulse),
        "nc" => authenticate_network_connect(
            options,
            transport_dialer,
            handle,
            cancellation,
        )
        .await
        .map(OpenConnectAuthenticatedSession::NetworkConnect),
        _ => authenticate_anyconnect(
            options,
            transport_dialer,
            handle,
            cancellation,
        )
        .await
        .map(OpenConnectAuthenticatedSession::AnyConnect),
    }
}

async fn connect_authenticated_openconnect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    authenticated: &OpenConnectAuthenticatedSession,
    cancellation: &CancellationToken,
    globalprotect_session: &RwLock<Option<GlobalProtectAuthenticatedSession>>,
    fortinet_reconnect_state: &Arc<Mutex<FortinetReconnectState>>,
    f5_reconnect_state: &Arc<Mutex<F5ReconnectState>>,
) -> Result<(OpenConnectDataChannel, TunnelConfiguration), EndpointConnectError>
{
    match authenticated {
        OpenConnectAuthenticatedSession::AnyConnect(authenticated) => {
            let (channel, configuration) = connect_authenticated_anyconnect(
                options,
                transport_dialer,
                authenticated,
                cancellation,
            )
            .await?;
            Ok((
                OpenConnectDataChannel::AnyConnect(Box::new(channel)),
                configuration,
            ))
        }
        OpenConnectAuthenticatedSession::GlobalProtect(authenticated) => {
            connect_authenticated_globalprotect(
                options,
                transport_dialer,
                authenticated,
                cancellation,
                globalprotect_session,
            )
            .await
        }
        OpenConnectAuthenticatedSession::Fortinet(authenticated) => {
            let (channel, configuration) = connect_authenticated_fortinet(
                options,
                transport_dialer,
                authenticated,
                cancellation,
                fortinet_reconnect_state,
            )
            .await?;
            Ok((
                OpenConnectDataChannel::Fortinet(Box::new(channel)),
                configuration,
            ))
        }
        OpenConnectAuthenticatedSession::F5(authenticated) => {
            let (channel, configuration) = connect_authenticated_f5(
                options,
                transport_dialer,
                authenticated,
                cancellation,
                f5_reconnect_state,
            )
            .await?;
            Ok((OpenConnectDataChannel::F5(Box::new(channel)), configuration))
        }
        OpenConnectAuthenticatedSession::Pulse(authenticated) => {
            let (channel, configuration) = connect_authenticated_pulse(
                options,
                transport_dialer,
                authenticated,
                cancellation,
            )
            .await?;
            Ok((
                OpenConnectDataChannel::Pulse(Box::new(channel)),
                configuration,
            ))
        }
        OpenConnectAuthenticatedSession::NetworkConnect(authenticated) => {
            let (channel, configuration) =
                connect_authenticated_network_connect(
                    options,
                    transport_dialer,
                    authenticated,
                    cancellation,
                )
                .await?;
            Ok((
                OpenConnectDataChannel::NetworkConnect(Box::new(channel)),
                configuration,
            ))
        }
    }
}

impl std::fmt::Display for EndpointConnectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionRejected(status) => write!(
                formatter,
                "OpenConnect session was rejected with HTTP {status}"
            ),
            Self::Terminal(message) | Self::Other(message) => {
                formatter.write_str(message)
            }
        }
    }
}

fn openconnect_software_token_generator(
    handle: &OpenConnectEndpointHandle,
) -> Option<Box<dyn AnyConnectSoftwareTokenGenerator>> {
    handle
        .token_factory
        .as_ref()
        .map(|factory| {
            Box::new(factory.generator())
                as Box<dyn AnyConnectSoftwareTokenGenerator>
        })
        .or_else(|| {
            handle.securid_token_factory.as_ref().map(|factory| {
                Box::new(factory.generator())
                    as Box<dyn AnyConnectSoftwareTokenGenerator>
            })
        })
}

async fn authenticate_network_connect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: &OpenConnectEndpointHandle,
    cancellation: &CancellationToken,
) -> Result<NetworkConnectEndpointSession, String> {
    let transport = Arc::new(endpoint_auth_http_transport(
        options,
        transport_dialer.clone(),
    ));
    let http = AnyConnectAuthHttpClient::new(
        transport,
        network_connect_user_agent(options),
    );
    let mut authenticator = NetworkConnectAuthenticator::new(
        http,
        &options.server,
        NetworkConnectAuthenticatorOptions {
            username: options.username.clone(),
            password: options.password.clone(),
            auth_group: options.auth_group.clone(),
            generated_token: None,
            direct_cookie: (!options.cookie.is_empty())
                .then(|| options.cookie.clone()),
        },
    )
    .map_err(|error| error.to_string())?;
    let mut response = None;
    let mut pending_progress = None;
    let mut tncc: Option<Arc<tokio::sync::Mutex<NetworkConnectTnccRunner>>> =
        None;
    loop {
        let progress = if let Some(progress) = pending_progress.take() {
            progress
        } else {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err("Network Connect authentication cancelled".into());
                }
                result = authenticator.advance(response.as_ref()) => result,
            }
            .map_err(|error| error.to_string())?
        };
        match progress {
            NetworkConnectAuthenticationProgress::Complete(session) => {
                if let Some(runner) = &tncc
                    && let Some((_, cookie)) = session
                        .cookies
                        .iter()
                        .find(|(name, _)| name == "DSPREAUTH")
                {
                    runner
                        .lock()
                        .await
                        .replace_preauthentication_cookie(cookie)
                        .map_err(|error| error.to_string())?;
                }
                return Ok(NetworkConnectEndpointSession {
                    authenticated: session,
                    tncc,
                });
            }
            NetworkConnectAuthenticationProgress::Challenge(challenge) => {
                let automatic = match &challenge.kind {
                    crate::protocol::openconnect::OpenConnectAuthChallengeKind::Form(form)
                        if form.fields.iter().all(|field| {
                            !field.value.is_empty()
                                || (field.kind
                                    == crate::protocol::openconnect::OpenConnectAuthPromptKind::Select
                                    && field.options.len() == 1)
                        }) => Some(OpenConnectAuthResponse::Form(
                            form.fields
                                .iter()
                                .map(|field| {
                                    let value = if field.value.is_empty() {
                                        field.options[0].value.clone()
                                    } else {
                                        field.value.clone()
                                    };
                                    (field.submission_key.clone(), value)
                                })
                                .collect(),
                        )),
                    _ => None,
                };
                response = Some(if let Some(automatic) = automatic {
                    automatic
                } else {
                    handle
                        .challenge_manager
                        .await_response(challenge, cancellation)
                        .await
                        .map_err(|error| error.to_string())?
                });
            }
            NetworkConnectAuthenticationProgress::Tncc(request) => {
                let tncc_options = options.tncc.clone().unwrap_or_default();
                let accepted_address = request.authenticated_address.ok_or_else(|| {
                    "Network Connect TNCC requires the accepted gateway address"
                        .to_owned()
                })?;
                let mut runner = if tncc_options.wrapper_path.is_empty() {
                    let transport = Arc::new(
                        endpoint_auth_http_transport(
                            options,
                            transport_dialer.clone(),
                        )
                        .with_pinned_address(accepted_address),
                    );
                    let user_agent = if tncc_options.user_agent.is_empty() {
                        NETWORK_CONNECT_TNCC_DEFAULT_USER_AGENT.to_owned()
                    } else {
                        tncc_options.user_agent.clone()
                    };
                    let http =
                        AnyConnectAuthHttpClient::new(transport, user_agent);
                    let identity = network_connect_tncc_identity(
                        options,
                        tncc_options.machine_identification_enabled,
                    )?;
                    let certificates =
                        load_network_connect_tncc_certificates(&tncc_options)?;
                    NetworkConnectTnccRunner::BuiltIn(
                        NetworkConnectBuiltInTnccRunner::new(
                            http,
                            request.server_url.clone(),
                            &request.cookies,
                            tncc_options.device_id,
                            identity,
                            certificates,
                        )
                        .map_err(|error| error.to_string())?,
                    )
                } else {
                    let host =
                        request.server_url.host_str().ok_or_else(|| {
                            "Network Connect TNCC gateway URL has no host"
                                .to_owned()
                        })?;
                    let peer_certificate = request
                        .peer_certificate_der
                        .as_deref()
                        .ok_or_else(|| {
                            "external Network Connect TNCC wrapper requires the accepted TLS peer certificate"
                                .to_owned()
                        })?;
                    NetworkConnectTnccRunner::external(
                        tncc_options.wrapper_path,
                        host,
                        &options.local_hostname,
                        peer_certificate,
                    )
                    .map_err(|error| error.to_string())?
                };
                let updated_cookie = tokio::select! {
                    _ = cancellation.cancelled() => {
                        return Err("Network Connect TNCC cancelled".into());
                    }
                    result = runner.start(
                        &request.preauthentication_cookie,
                        &request.sign_in_url,
                    ) => result,
                }
                .map_err(|error| error.to_string())?;
                tncc = Some(Arc::new(tokio::sync::Mutex::new(runner)));
                pending_progress = Some(
                    authenticator
                        .resume_tncc(&updated_cookie)
                        .await
                        .map_err(|error| error.to_string())?,
                );
                response = None;
            }
        }
    }
}

fn network_connect_tncc_identity(
    options: &OpenConnectEndpointOptions,
    enabled: bool,
) -> Result<NetworkConnectTnccIdentity, String> {
    if !enabled {
        return Ok(NetworkConnectTnccIdentity::default());
    }
    let mut mac_addresses = NetworkInterface::show()
        .map_err(|error| {
            format!("list network interfaces for Network Connect TNCC: {error}")
        })?
        .into_iter()
        .filter_map(|interface| interface.mac_addr)
        .map(|address| address.to_ascii_lowercase())
        .filter(|address| {
            address.bytes().any(|byte| byte != b'0' && byte != b':')
        })
        .collect::<Vec<_>>();
    mac_addresses.sort();
    mac_addresses.dedup();
    Ok(NetworkConnectTnccIdentity {
        machine_identification: true,
        platform: if options.reported_os.is_empty() {
            format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
        } else {
            options.reported_os.clone()
        },
        hostname: options.local_hostname.clone(),
        mac_addresses,
    })
}

fn load_network_connect_tncc_certificates(
    options: &crate::option::OpenConnectTnccOptions,
) -> Result<Vec<NetworkConnectTnccCertificate>, String> {
    let mut certificates = Vec::new();
    for (index, material) in options.certificates.iter().enumerate() {
        let content = load_openconnect_material(
            material.certificate.as_slice(),
            &material.certificate_path,
            &format!("TNCC certificate {index}"),
        )
        .map_err(|error| error.to_string())?;
        certificates.extend(
            NetworkConnectTnccCertificate::from_pem_bundle(&content)
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(certificates)
}

async fn connect_authenticated_network_connect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    session: &NetworkConnectEndpointSession,
    cancellation: &CancellationToken,
) -> Result<
    (NetworkConnectDataChannel, TunnelConfiguration),
    EndpointConnectError,
> {
    let authenticated = &session.authenticated;
    let host = authenticated.server_url.host_str().ok_or_else(|| {
        EndpointConnectError::Other(
            "Network Connect server URL has no host".into(),
        )
    })?;
    let port = authenticated
        .server_url
        .port_or_known_default()
        .ok_or_else(|| {
            EndpointConnectError::Other(
                "Network Connect server URL has no port".into(),
            )
        })?;
    let destination = SocksAddr::new(
        authenticated
            .authenticated_address
            .map_or_else(|| host.to_owned(), |address| address.to_string()),
        port,
    );
    let raw = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "Network Connect oNCP connection cancelled".into(),
            ));
        }
        result = transport_dialer.dial_tcp(&destination) => result,
    }
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let accepted_address = stream_peer_addr(&raw)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?
        .map(|address| address.ip())
        .or(authenticated.authenticated_address)
        .or_else(|| host.parse().ok())
        .ok_or_else(|| {
            EndpointConnectError::Other(
            "Network Connect endpoint did not expose an accepted IP address"
                .into(),
        )
        })?;
    let tls = build_client_config(
        host,
        &endpoint_tls_options(options),
        &["http/1.1"],
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let stream = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "Network Connect oNCP TLS handshake cancelled".into(),
            ));
        }
        result = tokio::time::timeout(
            Duration::from_secs(30),
            TlsConnector::from(tls.config).connect(tls.server_name, raw),
        ) => result.map_err(|_| EndpointConnectError::Other(
            "Network Connect oNCP TLS handshake timed out".into(),
        ))?,
    }
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = NetworkConnectOncpReader::new(read_half);
    let mut writer = NetworkConnectOncpWriter::new(write_half);
    let request = build_network_connect_oncp_request(
        &authenticated.server_url,
        &network_connect_user_agent(options),
        &authenticated.cookies,
        &authenticated.dsid,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    writer
        .write_bytes(&request)
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let (status, _) = reader
        .read_http_response_header()
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if status == 302 || (400..500).contains(&status) {
        return Err(EndpointConnectError::SessionRejected(status));
    }
    if status != 200 {
        return Err(EndpointConnectError::Other(format!(
            "Network Connect oNCP endpoint returned HTTP {status}"
        )));
    }
    let authentication = encode_network_connect_oncp_authentication_packet(
        &options.local_hostname,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    writer
        .write_bytes(&authentication)
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let configuration_message = reader
        .read_initial_configuration()
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let (header, configuration_payload) =
        parse_network_connect_oncp_kmp(&configuration_message, false)
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if header.message_type
        != crate::protocol::openconnect::NETWORK_CONNECT_ONCP_KMP_CONFIGURATION
    {
        return Err(EndpointConnectError::Other(format!(
            "Network Connect expected KMP 301, received {}",
            header.message_type
        )));
    }
    let mut parsed = parse_network_connect_oncp_configuration_payload(
        configuration_payload,
        accepted_address,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    parsed.configuration = normalize_openconnect_configuration(
        parsed.configuration,
        options.ipv6_disabled,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let dpd_override = options
        .dpd_interval
        .as_std()
        .filter(|interval| !interval.is_zero());
    if let Some(dpd) = dpd_override {
        parsed.esp_parameters.dpd = dpd;
    }
    let mtu_control =
        encode_network_connect_oncp_mtu_control(parsed.configuration.mtu)
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    writer
        .write_record(&mtu_control)
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let mut esp_configuration = None;
    let mut esp_parameters = None;
    let mut last_esp_error = None;
    if !options.no_udp && accepted_address.is_ipv4() {
        match prepare_network_connect_esp(
            accepted_address,
            &parsed.esp_parameters,
        ) {
            Ok((configuration, response)) => {
                writer.write_record(&response).await.map_err(|error| {
                    EndpointConnectError::Other(error.to_string())
                })?;
                esp_configuration = Some(configuration);
                esp_parameters = Some(parsed.esp_parameters.clone());
            }
            Err(error) => {
                last_esp_error = Some(format!(
                    "Network Connect ESP configuration unusable: {error}"
                ));
            }
        }
    }
    writer
        .flush()
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let configuration = parsed.configuration;
    let channel_cancellation = cancellation.child_token();
    let mut channel = NetworkConnectDataChannel {
        reader,
        writer,
        dialer: transport_dialer,
        mtu: configuration.mtu as usize,
        queue_length: endpoint_queue_length(options),
        dpd_override,
        queued_packets: VecDeque::new(),
        esp: None,
        esp_attempt: None,
        esp_configuration,
        esp_parameters,
        esp_enabled: false,
        last_esp_error,
        cancellation: channel_cancellation,
        tncc_task: None,
        tncc_failure: Arc::default(),
        closed: false,
    };
    channel.start_esp_attempt();
    channel.start_periodic_tncc(
        session.tncc.clone(),
        options
            .trojan_interval
            .as_std()
            .filter(|interval| !interval.is_zero()),
    );
    Ok((channel, configuration))
}

async fn authenticate_pulse(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    challenge_manager: &OpenConnectChallengeManager,
    cancellation: &CancellationToken,
    reconnecting: bool,
    pinned_address: Option<IpAddr>,
    mut token_generator: Option<Box<dyn AnyConnectSoftwareTokenGenerator>>,
) -> Result<PulseAuthenticatedSession, String> {
    let server_url = url::Url::parse(&normalize_server_url(&options.server))
        .map_err(|error| format!("invalid Pulse server URL: {error}"))?;
    if server_url.scheme() != "https" {
        return Err("Pulse server URL must use HTTPS".into());
    }
    if !server_url.username().is_empty() || server_url.password().is_some() {
        return Err("Pulse server URL must not contain user information".into());
    }
    let host = server_url
        .host_str()
        .ok_or_else(|| "Pulse server URL has no host".to_owned())?;
    let port = server_url
        .port_or_known_default()
        .ok_or_else(|| "Pulse server URL has no port".to_owned())?;
    let reported_os = if options.reported_os.is_empty() {
        "linux-64"
    } else {
        options.reported_os.as_str()
    };
    if !matches!(
        reported_os,
        "linux" | "linux-64" | "win" | "mac-intel" | "android" | "apple-ios"
    ) {
        return Err(format!("unsupported Pulse reported OS: {reported_os}"));
    }
    let destination = SocksAddr::new(
        pinned_address
            .map_or_else(|| host.to_owned(), |address| address.to_string()),
        port,
    );
    let raw = tokio::select! {
        _ = cancellation.cancelled() => return Err("Pulse authentication cancelled".into()),
        result = transport_dialer.dial_tcp(&destination) => result,
    }
    .map_err(|error| format!("connect Pulse TLS endpoint: {error}"))?;
    let accepted_address = stream_peer_addr(&raw)
        .map_err(|error| error.to_string())?
        .map(|address| address.ip())
        .or(pinned_address)
        .or_else(|| host.parse().ok())
        .ok_or_else(|| {
            "Pulse TLS endpoint did not expose its accepted IP address"
                .to_owned()
        })?;
    let local_address = stream_local_addr(&raw)
        .map_err(|error| error.to_string())?
        .map(|address| address.ip());
    let tls = build_client_config(
        host,
        &endpoint_tls_options(options),
        &["http/1.1"],
    )
    .map_err(|error| error.to_string())?;
    let mut stream = tokio::select! {
        _ = cancellation.cancelled() => return Err("Pulse authentication cancelled".into()),
        result = tokio::time::timeout(
            crate::protocol::openconnect::PULSE_CONNECT_TIMEOUT,
            TlsConnector::from(tls.config).connect(tls.server_name, raw),
        ) => result.map_err(|_| "Pulse TLS handshake timed out".to_owned())?,
    }
    .map_err(|error| format!("handshake Pulse TLS endpoint: {error}"))?;
    let cookies = if !options.cookie.is_empty() {
        vec![("DSID".to_owned(), options.cookie.clone())]
    } else {
        Vec::new()
    };
    let upgrade = build_pulse_upgrade_request(
        &server_url,
        &endpoint_user_agent(options),
        &cookies,
    )
    .map_err(|error| error.to_string())?;
    stream
        .write_all(&upgrade)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;
    read_pulse_upgrade_response(&mut stream, reconnecting)
        .await
        .map_err(|error| error.to_string())?;
    let stream: Stream = Box::new(stream);
    let outer =
        Arc::new(tokio::sync::Mutex::new(PulseIftConnection::new(stream)));
    {
        let mut connection = outer.lock().await;
        connection
            .write_frame(
                PULSE_VENDOR_TCG,
                PULSE_IFT_VERSION_REQUEST,
                &[0, 1, 2, 2],
            )
            .await
            .map_err(|error| error.to_string())?;
        let frame = connection
            .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
            .await
            .map_err(|error| error.to_string())?;
        validate_pulse_version_response(&frame)
            .map_err(|error| error.to_string())?;
        let client_information = format!(
            "clientHostName={}{} clientCapabilities={{}}\n\0",
            options.local_hostname,
            local_address
                .map(|address| format!(" clientIp={address}"))
                .unwrap_or_default(),
        );
        connection
            .write_frame(
                PULSE_VENDOR_JUNIPER,
                0x88,
                client_information.as_bytes(),
            )
            .await
            .map_err(|error| error.to_string())?;
        let frame = connection
            .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
            .await
            .map_err(|error| error.to_string())?;
        validate_pulse_initial_challenge(&frame)
            .map_err(|error| error.to_string())?;
    }
    let identity = build_pulse_eap(
        PULSE_EAP_RESPONSE,
        1,
        PULSE_EAP_TYPE_IDENTITY,
        0,
        b"anonymous",
    )
    .map_err(|error| error.to_string())?;
    let first_packet = {
        let mut connection = outer.lock().await;
        connection
            .write_frame(
                PULSE_VENDOR_TCG,
                PULSE_IFT_CLIENT_AUTH_RESPONSE,
                &build_pulse_authentication_payload(&identity),
            )
            .await
            .map_err(|error| error.to_string())?;
        let frame = connection
            .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
            .await
            .map_err(|error| error.to_string())?;
        parse_pulse_authentication_eap(&frame)
            .map_err(|error| error.to_string())?
    };
    let (mut carrier, server_information) = if first_packet.type_value
        == PULSE_EAP_EXPANDED_JUNIPER
        && first_packet.subtype == 1
    {
        (
            PulseAuthenticationCarrier::Direct(outer.clone()),
            first_packet,
        )
    } else {
        if first_packet.type_value != u32::from(PULSE_EAP_TYPE_TTLS) {
            return Err(format!(
                "server requested unsupported Pulse outer EAP type: {}",
                first_packet.type_value
            ));
        }
        let inner_tls =
            build_client_config(host, &endpoint_tls_options(options), &[])
                .map_err(|error| error.to_string())?;
        let transport =
            PulseTtlsTransport::new(outer.clone(), first_packet.identifier);
        let mut ttls = tokio::select! {
            _ = cancellation.cancelled() => return Err("Pulse EAP-TTLS handshake cancelled".into()),
            result = tokio::time::timeout(
                crate::protocol::openconnect::PULSE_CONNECT_TIMEOUT,
                TlsConnector::from(inner_tls.config)
                    .connect(inner_tls.server_name, transport),
            ) => result.map_err(|_| "Pulse EAP-TTLS handshake timed out".to_owned())?,
        }
        .map_err(|error| format!("handshake Pulse EAP-TTLS session: {error}"))?;
        write_pulse_inner_eap(&mut ttls, &identity)
            .await
            .map_err(|error| error.to_string())?;
        ttls.flush().await.map_err(|error| error.to_string())?;
        let server_information = read_pulse_inner_eap(&mut ttls)
            .await
            .map_err(|error| error.to_string())?;
        (
            PulseAuthenticationCarrier::Ttls(Box::new(ttls)),
            server_information,
        )
    };
    parse_pulse_avps(&server_information.payload)
        .map_err(|error| format!("parse Pulse server information: {error}"))?;
    let mut parser = PulseChallengeParser::default();
    if !options.cookie.is_empty() {
        parser.set_cookie(options.cookie.as_bytes().to_vec());
    }
    let client_avps = build_pulse_authentication_client_avps(
        pulse_reported_os(reported_os),
        &endpoint_user_agent(options),
        options.ipv6_disabled,
        parser.cookie(),
    )
    .map_err(|error| error.to_string())?;
    carrier
        .send_expanded(server_information.identifier, &client_avps)
        .await?;
    for _ in 0..PULSE_MAXIMUM_AUTHENTICATION_STEPS {
        let packet = carrier.receive_expanded().await?;
        let mut challenge = parser
            .parse_challenge(
                &packet,
                reconnecting,
                !options.tls.client_certificate.0.is_empty()
                    || !options.tls.client_certificate_path.is_empty(),
                std::time::SystemTime::now(),
            )
            .map_err(|error| error.to_string())?;
        match challenge.kind {
            PulseChallengeKind::Cookie => {
                carrier
                    .send_expanded(challenge.outer_identifier, &[])
                    .await?;
                carrier.flush().await?;
                drop(carrier);
                let frame = outer
                    .lock()
                    .await
                    .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                    .await
                    .map_err(|error| error.to_string())?;
                validate_pulse_authentication_success(&frame)
                    .map_err(|error| error.to_string())?;
                let cookie = parser
                    .cookie()
                    .filter(|cookie| !cookie.is_empty())
                    .ok_or_else(|| {
                        "Pulse authentication completed without a cookie"
                            .to_owned()
                    })?
                    .to_vec();
                return Ok(PulseAuthenticatedSession {
                    server_url,
                    accepted_address,
                    cookie,
                    authentication_expiration: parser
                        .authentication_expires_at(),
                    idle_timeout: parser.idle_timeout(),
                    live_connection: Arc::new(tokio::sync::Mutex::new(Some(
                        Arc::try_unwrap(outer)
                            .map_err(|_| {
                                "Pulse connection is still shared".to_owned()
                            })?
                            .into_inner(),
                    ))),
                    graceful_bye: Arc::new(AtomicBool::new(false)),
                });
            }
            PulseChallengeKind::SignIn => {
                let content = build_pulse_sign_in_response()
                    .map_err(|error| error.to_string())?;
                carrier
                    .send_expanded(challenge.outer_identifier, &content)
                    .await?;
            }
            _ => {
                if reconnecting {
                    return Err(
                        "Pulse cookie reconnect requires user interaction"
                            .into(),
                    );
                }
                loop {
                    let token_can_generate =
                        token_generator.as_ref().is_some_and(|generator| {
                            generator.can_generate(&challenge.gtc_prompt)
                        });
                    let prompt = challenge
                        .prompt_form(token_can_generate)
                        .map_err(|error| error.to_string())?;
                    let mut values = pulse_prefilled_values(options, &prompt);
                    if challenge.kind == PulseChallengeKind::Gtc
                        && token_can_generate
                        && let Some(generator) = token_generator.as_mut()
                    {
                        let token = generator
                            .generate(&challenge.gtc_prompt)
                            .map_err(|error| error.to_string())?;
                        values.insert(
                            crate::protocol::openconnect::PULSE_TOKEN_SUBMISSION_KEY
                                .into(),
                            token,
                        );
                    }
                    let values = if values.len() == prompt.fields.len() {
                        values
                    } else {
                        let public = new_openconnect_auth_challenge(
                            "",
                            pulse_challenge_message(challenge.kind),
                            challenge.error_message.clone(),
                            crate::protocol::openconnect::OpenConnectAuthChallengeKind::Form(
                                prompt.clone(),
                            ),
                        );
                        let response = challenge_manager
                            .await_response(public, cancellation)
                            .await
                            .map_err(|error| error.to_string())?;
                        let OpenConnectAuthResponse::Form(values) = response
                        else {
                            return Err("Pulse authentication response type does not match".into());
                        };
                        validate_openconnect_form_response(
                            &prompt.fields,
                            &values,
                        )
                        .map_err(|error| error.to_string())?;
                        values
                    };
                    let response = challenge
                        .build_response(&values)
                        .map_err(|error| error.to_string())?;
                    if let Some(message) = response.retry_message {
                        challenge.error_message = message;
                        continue;
                    }
                    carrier
                        .send_expanded(
                            challenge.outer_identifier,
                            &response.content,
                        )
                        .await?;
                    break;
                }
            }
        }
    }
    Err(format!(
        "Pulse authentication exceeded {PULSE_MAXIMUM_AUTHENTICATION_STEPS} wire steps"
    ))
}

fn pulse_reported_os(reported_os: &str) -> &'static str {
    match reported_os {
        "mac-intel" => "Mac",
        "apple-ios" => "iOS",
        "linux" | "linux-64" => "Linux",
        "android" => "Android",
        _ => "Windows",
    }
}

fn pulse_challenge_message(kind: PulseChallengeKind) -> &'static str {
    match kind {
        PulseChallengeKind::RealmEntry => "Enter Pulse user realm:",
        PulseChallengeKind::RealmChoice => "Choose Pulse user realm:",
        PulseChallengeKind::RegionChoice => "Choose Pulse region:",
        PulseChallengeKind::Session => {
            "Session limit reached. Choose session to terminate:"
        }
        PulseChallengeKind::Password => "Enter Pulse credentials:",
        PulseChallengeKind::PasswordChange => {
            "Password expired. Please change password:"
        }
        PulseChallengeKind::Gtc => "Token code request:",
        _ => "Pulse authentication:",
    }
}

fn pulse_prefilled_values(
    options: &OpenConnectEndpointOptions,
    form: &crate::protocol::openconnect::OpenConnectAuthPromptForm,
) -> std::collections::BTreeMap<String, String> {
    use crate::protocol::openconnect::{
        PULSE_PASSWORD_SUBMISSION_KEY, PULSE_REALM_CHOICE_SUBMISSION_KEY,
        PULSE_REALM_SUBMISSION_KEY, PULSE_USERNAME_SUBMISSION_KEY,
    };
    let mut values = std::collections::BTreeMap::new();
    for field in &form.fields {
        let value = match field.submission_key.as_str() {
            PULSE_USERNAME_SUBMISSION_KEY if !options.username.is_empty() => {
                Some(options.username.clone())
            }
            PULSE_PASSWORD_SUBMISSION_KEY if !options.password.is_empty() => {
                Some(options.password.clone())
            }
            PULSE_REALM_SUBMISSION_KEY if !options.auth_group.is_empty() => {
                Some(options.auth_group.clone())
            }
            PULSE_REALM_CHOICE_SUBMISSION_KEY
                if !options.auth_group.is_empty()
                    && field
                        .options
                        .iter()
                        .any(|choice| choice.value == options.auth_group) =>
            {
                Some(options.auth_group.clone())
            }
            _ => None,
        };
        if let Some(value) = value {
            values.insert(field.submission_key.clone(), value);
        }
    }
    values
}

async fn connect_authenticated_pulse(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    authenticated: &PulseAuthenticatedSession,
    cancellation: &CancellationToken,
) -> Result<(PulseDataChannel, TunnelConfiguration), EndpointConnectError> {
    let mut connection = authenticated
        .live_connection
        .lock()
        .await
        .take()
        .ok_or(EndpointConnectError::SessionRejected(401))?;
    let mut accumulator = PulseConfigurationAccumulator::new(
        authenticated.accepted_address,
        authenticated.authentication_expiration,
        authenticated.idle_timeout,
        options.ipv6_disabled,
        options.no_udp,
    );
    loop {
        let frame = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(EndpointConnectError::Other(
                    "Pulse configuration cancelled".into(),
                ));
            }
            result = connection.read_frame(PULSE_CONFIGURATION_FRAME_LIMIT) => result,
        }
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        match accumulator
            .apply_frame(&frame)
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?
        {
            PulseConfigurationAction::Complete => break,
            PulseConfigurationAction::EspResponse(response) => {
                connection
                    .write_frame(PULSE_VENDOR_JUNIPER, 1, &response)
                    .await
                    .map_err(|error| {
                        EndpointConnectError::Other(error.to_string())
                    })?;
                connection
                    .write_frame(PULSE_VENDOR_JUNIPER, 5, b"ncmo=1\n\0")
                    .await
                    .map_err(|error| {
                        EndpointConnectError::Other(error.to_string())
                    })?;
            }
            PulseConfigurationAction::Ignored
            | PulseConfigurationAction::Applied => {}
        }
    }
    let parsed = accumulator
        .finish()
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let configuration = normalize_openconnect_configuration(
        parsed.configuration.clone(),
        options.ipv6_disabled,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let allow_ipv4 = parsed.assigned_ipv4.is_some();
    let allow_ipv6 = parsed.assigned_ipv6.is_some();
    let late_esp = parsed.esp.clone().map(|esp| {
        let dpd = options
            .dpd_interval
            .as_std()
            .filter(|interval| !interval.is_zero())
            .unwrap_or(esp.fallback);
        PulseLateEspState {
            template: PulseEspAttempt {
                dialer: transport_dialer,
                configuration: esp,
                mtu: configuration.mtu as usize,
                dpd,
                queue_length: endpoint_queue_length(options),
                cancellation: cancellation.child_token(),
            },
            next_attempt: tokio::time::Instant::now(),
            attempt: None,
        }
    });
    let next_sequence = connection.next_sequence();
    let stream = connection.into_inner();
    let (reader, writer) = tokio::io::split(stream);
    Ok((
        PulseDataChannel {
            reader,
            writer,
            encoder: PulseIftEncoder::with_sequence(next_sequence),
            mtu: configuration.mtu as usize,
            allow_ipv4,
            allow_ipv6,
            closed: false,
            terminal: false,
            graceful_bye: authenticated.graceful_bye.clone(),
            esp: None,
            late_esp,
            last_esp_error: None,
        },
        configuration,
    ))
}

async fn authenticate_anyconnect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: &OpenConnectEndpointHandle,
    cancellation: &CancellationToken,
) -> Result<AnyConnectAuthenticatedSession, String> {
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(endpoint_auth_http_transport(options, transport_dialer)),
        endpoint_user_agent(options),
    );
    if let Some(token) =
        options.token.as_ref().filter(|token| token.mode == "oidc")
    {
        http.set_bearer_token(
            load_openconnect_token_secret(token)
                .map_err(|error| error.to_string())?,
        );
    }
    let mut authenticator = AnyConnectAuthenticator::new(
        http,
        normalize_server_url(&options.server),
        endpoint_authenticator_options(options)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if let Some(token_factory) = handle.token_factory.as_ref() {
        authenticator
            .set_software_token_generator(Box::new(token_factory.generator()));
    } else if let Some(token_factory) = handle.securid_token_factory.as_ref() {
        authenticator
            .set_software_token_generator(Box::new(token_factory.generator()));
    }
    let mut progress = authenticator
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    loop {
        match progress {
            AnyConnectAuthenticationProgress::Complete(session) => {
                return Ok(session);
            }
            AnyConnectAuthenticationProgress::Challenge(challenge) => {
                let challenge_id = challenge.id.clone();
                let response = handle
                    .challenge_manager
                    .await_response(challenge, cancellation)
                    .await
                    .map_err(|error| error.to_string())?;
                progress = authenticator
                    .respond(&challenge_id, response)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

async fn authenticate_globalprotect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: &OpenConnectEndpointHandle,
    cancellation: &CancellationToken,
) -> Result<GlobalProtectAuthenticatedSession, String> {
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(endpoint_auth_http_transport(options, transport_dialer)),
        globalprotect_user_agent(options),
    );
    if let Some(token) =
        options.token.as_ref().filter(|token| token.mode == "oidc")
    {
        http.set_bearer_token(
            load_openconnect_token_secret(token)
                .map_err(|error| error.to_string())?,
        );
    }
    let mut authenticator = GlobalProtectAuthenticator::new(
        http,
        &options.server,
        GlobalProtectAuthenticatorOptions {
            username: options.username.clone(),
            password: options.password.clone(),
            auth_group: options.auth_group.clone(),
            direct_cookie: (!options.cookie.is_empty())
                .then(|| options.cookie.clone()),
            reported_os: options.reported_os.clone(),
            local_hostname: options.local_hostname.clone(),
            external_auth_disabled: options.external_auth_disabled,
            ipv6_disabled: options.ipv6_disabled,
            previous_ipv4: None,
            previous_ipv6: None,
        },
    )
    .map_err(|error| error.to_string())?;
    if let Some(token_factory) = handle.token_factory.as_ref() {
        authenticator
            .set_software_token_generator(Box::new(token_factory.generator()));
    } else if let Some(token_factory) = handle.securid_token_factory.as_ref() {
        authenticator
            .set_software_token_generator(Box::new(token_factory.generator()));
    }
    let mut progress = authenticator
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    loop {
        match progress {
            GlobalProtectAuthenticationProgress::Complete(session) => {
                return Ok(session);
            }
            GlobalProtectAuthenticationProgress::Challenge(challenge) => {
                let challenge_id = challenge.id.clone();
                let response = handle
                    .challenge_manager
                    .await_response(challenge, cancellation)
                    .await
                    .map_err(|error| error.to_string())?;
                progress = authenticator
                    .respond(&challenge_id, response)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

async fn authenticate_fortinet(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: &OpenConnectEndpointHandle,
    cancellation: &CancellationToken,
) -> Result<FortinetAuthenticatedSession, String> {
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(endpoint_auth_http_transport(options, transport_dialer)),
        fortinet_user_agent(options),
    );
    if let Some(token) =
        options.token.as_ref().filter(|token| token.mode == "oidc")
    {
        http.set_bearer_token(
            load_openconnect_token_secret(token)
                .map_err(|error| error.to_string())?,
        );
    }
    let host_check = options.fortinet_host_check.as_ref();
    let mut authenticator = FortinetAuthenticator::new(
        http,
        &options.server,
        FortinetAuthenticatorOptions {
            username: options.username.clone(),
            password: options.password.clone(),
            direct_cookie: (!options.cookie.is_empty())
                .then(|| options.cookie.clone()),
            external_auth_disabled: options.external_auth_disabled,
            host_check: host_check
                .map(|options| options.hostcheck.clone())
                .unwrap_or_default(),
            check_virtual_desktop: host_check
                .map(|options| options.check_virtual_desktop.clone())
                .unwrap_or_default(),
        },
    )
    .map_err(|error| error.to_string())?;
    if let Some(token_factory) = handle.token_factory.as_ref() {
        authenticator
            .set_software_token_generator(Box::new(token_factory.generator()));
    } else if let Some(token_factory) = handle.securid_token_factory.as_ref() {
        authenticator
            .set_software_token_generator(Box::new(token_factory.generator()));
    }
    let mut progress = authenticator
        .begin()
        .await
        .map_err(|error| error.to_string())?;
    loop {
        match progress {
            FortinetAuthenticationProgress::Complete(session) => {
                return Ok(session);
            }
            FortinetAuthenticationProgress::Challenge(challenge) => {
                let challenge_id = challenge.id.clone();
                let response = handle
                    .challenge_manager
                    .await_response(challenge, cancellation)
                    .await
                    .map_err(|error| error.to_string())?;
                progress = authenticator
                    .respond(&challenge_id, response)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

async fn authenticate_f5(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: &OpenConnectEndpointHandle,
    cancellation: &CancellationToken,
) -> Result<F5AuthenticatedSession, String> {
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(endpoint_auth_http_transport(options, transport_dialer)),
        f5_user_agent(options),
    );
    if let Some(token) =
        options.token.as_ref().filter(|token| token.mode == "oidc")
    {
        http.set_bearer_token(
            load_openconnect_token_secret(token)
                .map_err(|error| error.to_string())?,
        );
    }
    let mut authenticator = F5Authenticator::new(
        http,
        &options.server,
        F5AuthenticatorOptions {
            username: options.username.clone(),
            password: options.password.clone(),
            auth_group: options.auth_group.clone(),
            direct_cookie: (!options.cookie.is_empty())
                .then(|| options.cookie.clone()),
        },
    )
    .map_err(|error| error.to_string())?;
    let mut progress = authenticator
        .advance(None)
        .await
        .map_err(|error| error.to_string())?;
    loop {
        match progress {
            F5AuthenticationProgress::Complete(session) => return Ok(session),
            F5AuthenticationProgress::Challenge(challenge) => {
                let response = handle
                    .challenge_manager
                    .await_response(challenge, cancellation)
                    .await
                    .map_err(|error| error.to_string())?;
                progress = authenticator
                    .advance(Some(&response))
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

async fn connect_authenticated_globalprotect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    authenticated: &GlobalProtectAuthenticatedSession,
    cancellation: &CancellationToken,
    globalprotect_session: &RwLock<Option<GlobalProtectAuthenticatedSession>>,
) -> Result<(OpenConnectDataChannel, TunnelConfiguration), EndpointConnectError>
{
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(endpoint_auth_http_transport(
            options,
            transport_dialer.clone(),
        )),
        globalprotect_user_agent(options),
    );
    let mut configuration_url = authenticated.server_url.clone();
    configuration_url.set_path(
        crate::protocol::openconnect::GLOBALPROTECT_CONFIGURATION_PATH,
    );
    configuration_url.set_query(None);
    let configuration_body = build_globalprotect_configuration_request(
        &GlobalProtectConfigurationRequestOptions {
            client_version: authenticated.client_version.clone(),
            ipv6_disabled: options.ipv6_disabled,
            reported_os: if options.reported_os.is_empty() {
                "linux-64".into()
            } else {
                options.reported_os.clone()
            },
            opaque_query: authenticated.opaque_query.clone(),
            previous_ipv4: authenticated.previous_ipv4,
            previous_ipv6: authenticated.previous_ipv6,
        },
    );
    let response = http
        .execute(crate::protocol::openconnect::AnyConnectAuthHttpRequest {
            method: Method::POST,
            url: configuration_url,
            content_type: Some("application/x-www-form-urlencoded".into()),
            body: configuration_body.into_bytes(),
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: false,
        })
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if response.status != StatusCode::OK {
        let class = classify_globalprotect_tunnel_http_status(
            response.status.as_u16(),
            GlobalProtectTunnelOperation::Configuration,
        )
        .expect("non-success status has a class");
        return if class == GlobalProtectFailureClass::SessionRejected {
            Err(EndpointConnectError::SessionRejected(
                response.status.as_u16(),
            ))
        } else {
            Err(EndpointConnectError::Other(format!(
                "GlobalProtect configuration returned HTTP {} ({class:?})",
                response.status
            )))
        };
    }
    if response.body == b"errors getting SSL/VPN config" {
        return Err(EndpointConnectError::SessionRejected(200));
    }
    let authenticated_address = response
        .authenticated_address
        .or(authenticated.authenticated_address)
        .or_else(|| authenticated.server_url.host_str()?.parse().ok());
    let mut active_session = authenticated.clone();
    active_session.authenticated_address = authenticated_address;
    *globalprotect_session.write().map_err(|_| {
        EndpointConnectError::Other(
            "GlobalProtect session state lock poisoned".into(),
        )
    })? = Some(active_session);
    let mut parse_options = if let Some(address) = authenticated_address {
        GlobalProtectConfigurationParseOptions::new(address)
    } else {
        GlobalProtectConfigurationParseOptions::new_unpinned()
    };
    parse_options.ipv6_disabled = options.ipv6_disabled;
    parse_options.no_udp = options.no_udp;
    parse_options.requested_mtu = options.mtu;
    parse_options.base_mtu = options.base_mtu;
    parse_options.dpd_override = options
        .dpd_interval
        .as_std()
        .filter(|duration| !duration.is_zero());
    let parsed = parse_globalprotect_tunnel_configuration(
        &response.body,
        &parse_options,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;

    let mut hip_transport =
        endpoint_auth_http_transport(options, transport_dialer.clone());
    if let Some(address) = authenticated_address {
        hip_transport = hip_transport.with_pinned_address(address);
    }
    let hip_http = AnyConnectAuthHttpClient::new(
        Arc::new(hip_transport),
        globalprotect_user_agent(options),
    );
    let hip_interval = options
        .trojan_interval
        .as_std()
        .filter(|interval| !interval.is_zero())
        .unwrap_or(authenticated.hip_report_interval);
    let mut hip_runner = GlobalProtectHipRunner::new(
        hip_http,
        GlobalProtectHipRunnerOptions {
            server_url: authenticated.server_url.clone(),
            authenticated_address,
            opaque_query: authenticated.opaque_query.clone(),
            assigned_ipv4: parsed.assigned_ipv4,
            assigned_ipv6: parsed.assigned_ipv6,
            app_version: authenticated.client_version.clone(),
            reported_os: if options.reported_os.is_empty() {
                "linux-64".into()
            } else {
                options.reported_os.clone()
            },
            local_hostname: options.local_hostname.clone(),
            interval: hip_interval,
        },
    )
    .map_err(map_globalprotect_hip_error)?;
    if let Some(wrapper) = options
        .hip
        .as_ref()
        .filter(|hip| !hip.wrapper_path.is_empty())
    {
        hip_runner.set_wrapper_path(&wrapper.wrapper_path);
    }
    let hip_result = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "GlobalProtect HIP check cancelled".into(),
            ));
        }
        result = hip_runner.check() => result,
    }
    .map_err(map_globalprotect_hip_error)?;

    let host = authenticated.server_url.host_str().ok_or_else(|| {
        EndpointConnectError::Other("GlobalProtect gateway has no host".into())
    })?;
    let port = authenticated
        .server_url
        .port_or_known_default()
        .ok_or_else(|| {
            EndpointConnectError::Other(
                "GlobalProtect gateway has no port".into(),
            )
        })?;
    let configuration = normalize_openconnect_configuration(
        parsed.configuration.clone(),
        options.ipv6_disabled,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let channel_cancellation = cancellation.child_token();
    let fallback = GlobalProtectGpstFallback {
        dialer: transport_dialer.clone(),
        tls: endpoint_tls_options(options),
        tls_host: host.to_owned(),
        remote: SocksAddr::new(
            authenticated_address
                .map_or_else(|| host.to_owned(), |address| address.to_string()),
            port,
        ),
        tunnel_path: parsed.tunnel_path.clone(),
        opaque_query: authenticated.opaque_query.clone(),
        mtu: configuration.mtu as usize,
        dpd: parsed.dpd,
        keepalive: parsed.keepalive,
        queue_length: endpoint_queue_length(options),
    };
    let mut last_esp_error = None;
    let esp_attempt: Option<Result<OpenConnectEspSession, String>> =
        if let Some(esp) = parsed.esp.as_ref() {
            let assigned = match esp.magic {
                IpAddr::V4(_) => parsed.assigned_ipv4.map(IpAddr::V4),
                IpAddr::V6(_) => parsed.assigned_ipv6.map(IpAddr::V6),
            };
            Some(if let Some(assigned) = assigned {
                let keys = OpenConnectEspKeySet::new(
                    &OpenConnectEspKeySetConfig::from(esp),
                )
                .map(Arc::new)
                .map_err(|error| error.to_string());
                match keys {
                    Ok(keys) => {
                        let session = OpenConnectEspSession::connect(
                            transport_dialer.clone(),
                            OpenConnectEspSessionOptions {
                                remote: esp.remote,
                                keys,
                                mtu: configuration.mtu as usize,
                                dpd: parsed.dpd,
                                probe: OpenConnectEspProbe::GlobalProtect(
                                    GlobalProtectEspProbe {
                                        assigned,
                                        magic: esp.magic,
                                    },
                                ),
                                probe_next_header: 0,
                                accept_lzo: true,
                                queue_length: endpoint_queue_length(options),
                            },
                        )
                        .await
                        .map_err(|error| error.to_string());
                        match session {
                            Ok(mut session) => {
                                let result = tokio::select! {
                                    _ = cancellation.cancelled() => {
                                        Err("GlobalProtect ESP establishment cancelled".into())
                                    }
                                    result = session.establish() => {
                                        result.map_err(|error| error.to_string())
                                    }
                                };
                                match result {
                                    Ok(()) => Ok(session),
                                    Err(error) => {
                                        session.close().await;
                                        Err(error)
                                    }
                                }
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            } else {
                Err(format!(
                    "GlobalProtect ESP has no assigned {} address",
                    if esp.magic.is_ipv4() { "IPv4" } else { "IPv6" }
                ))
            })
        } else {
            None
        };
    let transport = match esp_attempt {
        Some(Ok(session)) => GlobalProtectTransport::Esp(session),
        Some(Err(error)) => {
            if cancellation.is_cancelled() {
                return Err(EndpointConnectError::Other(error));
            }
            last_esp_error = Some(error);
            GlobalProtectTransport::Gpst(
                fallback.connect(&channel_cancellation).await?,
            )
        }
        None => GlobalProtectTransport::Gpst(
            fallback.connect(&channel_cancellation).await?,
        ),
    };
    Ok((
        OpenConnectDataChannel::GlobalProtect(Box::new(
            GlobalProtectDataChannel {
                transport,
                fallback,
                last_esp_error,
                hip_runner,
                next_hip_check: (!hip_result.next_check.is_zero()).then(|| {
                    tokio::time::Instant::now() + hip_result.next_check
                }),
                rekey_deadline: (!parsed.rekey.is_zero())
                    .then(|| tokio::time::Instant::now() + parsed.rekey),
                cancellation: channel_cancellation,
            },
        )),
        configuration,
    ))
}

fn map_globalprotect_hip_error(
    error: GlobalProtectHipError,
) -> EndpointConnectError {
    match &error {
        GlobalProtectHipError::HttpStatus {
            status,
            class: GlobalProtectFailureClass::SessionRejected,
            ..
        } => EndpointConnectError::SessionRejected(status.as_u16()),
        GlobalProtectHipError::Response {
            class: GlobalProtectFailureClass::SessionRejected,
            ..
        } => EndpointConnectError::SessionRejected(200),
        _ => EndpointConnectError::Other(error.to_string()),
    }
}

async fn connect_authenticated_anyconnect(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    authenticated: &AnyConnectAuthenticatedSession,
    cancellation: &CancellationToken,
) -> Result<(AnyConnectChannel, TunnelConfiguration), EndpointConnectError> {
    let connection = connect_anyconnect_cstp(
        transport_dialer.clone(),
        authenticated,
        endpoint_cstp_options(options, endpoint_tls_options(options)),
    )
    .await
    .map_err(|error| match error {
        AnyConnectCstpConnectError::SessionRejected(status) => {
            EndpointConnectError::SessionRejected(status)
        }
        error => EndpointConnectError::Other(error.to_string()),
    })?;
    let channel = AnyConnectChannel::establish(
        transport_dialer,
        connection,
        cancellation,
    )
    .await
    .map_err(|error| {
        if error.is_terminal() {
            EndpointConnectError::Terminal(error.to_string())
        } else {
            EndpointConnectError::Other(error.to_string())
        }
    })?;
    let configuration = normalize_openconnect_configuration(
        channel.negotiated().configuration.clone(),
        options.ipv6_disabled,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    Ok((channel, configuration))
}

async fn connect_authenticated_f5(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    authenticated: &F5AuthenticatedSession,
    cancellation: &CancellationToken,
    reconnect_state: &Arc<Mutex<F5ReconnectState>>,
) -> Result<(F5DataChannel, TunnelConfiguration), EndpointConnectError> {
    if authenticated
        .authentication_expiration
        .is_some_and(|expiration| expiration <= std::time::SystemTime::now())
    {
        return Err(EndpointConnectError::SessionRejected(401));
    }
    let base_transport =
        endpoint_auth_http_transport(options, transport_dialer.clone());
    let transport = match authenticated.authenticated_address {
        Some(address) => base_transport.with_pinned_address(address),
        None => base_transport,
    };
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(transport),
        f5_user_agent(options),
    );
    for (name, value) in &authenticated.cookies {
        http.set_cookie(&authenticated.server_url, name, value)
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    }
    let mut profile_url = authenticated.server_url.clone();
    profile_url.set_path("/vdesk/vpn/index.php3");
    profile_url.set_query(Some("outform=xml&client_version=2.0"));
    profile_url.set_fragment(None);
    let profile_response =
        execute_f5_configuration_request(&mut http, profile_url, "profile")
            .await?;
    let profile = parse_f5_profile(&profile_response.body)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if profile.contains(['\r', '\n', '#']) {
        return Err(EndpointConnectError::Other(
            "F5 profile parameters contain invalid request characters".into(),
        ));
    }
    let mut options_url = authenticated.server_url.clone();
    options_url.set_path("/vdesk/vpn/connect.php3");
    options_url
        .set_query(Some(&format!("{profile}&outform=xml&client_version=2.0")));
    options_url.set_fragment(None);
    let options_response =
        execute_f5_configuration_request(&mut http, options_url, "options")
            .await?;
    let mut parsed = parse_f5_options(
        &options_response.body,
        authenticated.authentication_expiration,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if options.ipv6_disabled {
        parsed.want_ipv6 = false;
        if !parsed.want_ipv4 {
            return Err(EndpointConnectError::Other(
                "F5 server did not provide IPv4 tunnel configuration".into(),
            ));
        }
    }
    let accepted_address = options_response
        .authenticated_address
        .or(profile_response.authenticated_address)
        .or(authenticated.authenticated_address)
        .or_else(|| authenticated.server_url.host_str()?.parse().ok())
        .ok_or_else(|| {
            EndpointConnectError::Other(
                "F5 configuration endpoint exposed no accepted address".into(),
            )
        })?;
    let encapsulation = if parsed.hdlc {
        PppEncapsulation::F5Hdlc
    } else {
        PppEncapsulation::F5
    };
    parsed.configuration.mtu = calculate_ppp_tunnel_mtu(
        options.mtu,
        options.base_mtu,
        accepted_address.is_ipv6(),
        encapsulation,
    );
    let ipv6_disabled = options.ipv6_disabled
        || parsed.configuration.mtu < PPP_MINIMUM_IPV6_MTU;
    if ipv6_disabled {
        parsed.want_ipv6 = false;
        if !parsed.want_ipv4 {
            return Err(EndpointConnectError::Other(
                "calculated F5 tunnel MTU is too small for IPv6-only configuration"
                    .into(),
            ));
        }
    }
    parsed.configuration.remote_address = Some(accepted_address);
    parsed.configuration = normalize_openconnect_configuration(
        parsed.configuration,
        ipv6_disabled,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let reconnect_snapshot = reconnect_state
        .lock()
        .map_err(|_| {
            EndpointConnectError::Other(
                "F5 reconnect state lock poisoned".into(),
            )
        })?
        .clone();
    let connect_request = build_f5_connect_request(
        &authenticated.server_url,
        &options.local_hostname,
        &f5_user_agent(options),
        &parsed,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let port = authenticated
        .server_url
        .port_or_known_default()
        .ok_or_else(|| {
            EndpointConnectError::Other("F5 tunnel URL has no port".into())
        })?;
    let destination = SocksAddr::Ip(SocketAddr::new(accepted_address, port));
    let mut last_dtls_error = None;
    let mut late_dtls_template = None;
    if parsed.dtls_enabled
        && !options.no_udp
        && !reconnect_snapshot.skip_initial_dtls
    {
        if let Some(reason) =
            f5_dtls_unsupported_reason(&endpoint_tls_options(options))
        {
            last_dtls_error = Some(reason);
        } else {
            let template = F5LateDtlsAttempt {
                options: options.clone(),
                dialer: transport_dialer.clone(),
                authenticated: authenticated.clone(),
                configuration: parsed.clone(),
                connect_request: connect_request.clone(),
                accepted_address,
                reconnect_snapshot: reconnect_snapshot.clone(),
                cancellation: cancellation.clone(),
            };
            match tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(EndpointConnectError::Other(
                    "F5 DTLS tunnel start cancelled".into(),
                ));
            }
            result = tokio::time::timeout(
                Duration::from_secs(5),
                    template.connect(),
            ) => result,
            } {
                Ok(Ok((channel, configuration, source_ip))) => {
                    store_f5_reconnect_state(
                        reconnect_state,
                        channel.tunnel_configuration(),
                        source_ip,
                    )?;
                    return Ok((
                        F5DataChannel {
                            transport: F5PppTransport::Dtls(channel),
                            last_dtls_error: None,
                            late_dtls: None,
                            reconnect_state: reconnect_state.clone(),
                        },
                        configuration,
                    ));
                }
                Ok(Err(EndpointConnectError::SessionRejected(status))) => {
                    return Err(EndpointConnectError::SessionRejected(status));
                }
                Ok(Err(error)) => {
                    last_dtls_error = Some(error.to_string());
                    late_dtls_template = Some(template);
                }
                Err(_) => {
                    last_dtls_error =
                        Some("F5 initial DTLS window timed out".into());
                    late_dtls_template = Some(template);
                }
            }
        }
    }
    let raw_stream = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "F5 TLS tunnel start cancelled".into(),
            ));
        }
        result = transport_dialer.dial_tcp(&destination) => result,
    }
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let source_ip = stream_local_addr(&raw_stream)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?
        .map(|address| address.ip());
    if reconnect_snapshot.connected_once
        && reconnect_snapshot.source_ip.is_some()
        && reconnect_snapshot.source_ip != source_ip
    {
        return Err(EndpointConnectError::SessionRejected(401));
    }
    let host = authenticated.server_url.host_str().ok_or_else(|| {
        EndpointConnectError::Other("F5 tunnel URL has no host".into())
    })?;
    let tls = build_client_config(
        host,
        &endpoint_tls_options(options),
        &["http/1.1"],
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let tunnel = async {
        let mut stream = TlsConnector::from(tls.config)
            .connect(tls.server_name, raw_stream)
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        stream
            .write_all(&connect_request)
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let start = read_f5_tunnel_start(&mut stream).await.map_err(
            |error| match error {
                F5TunnelError::SessionRejected(status) => {
                    EndpointConnectError::SessionRejected(status.as_u16())
                }
                error => EndpointConnectError::Other(error.to_string()),
            },
        )?;
        Ok::<_, EndpointConnectError>((stream, start))
    };
    let (stream, start) = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "F5 TLS tunnel start cancelled".into(),
            ));
        }
        result = tokio::time::timeout(F5_TLS_CONNECT_TIMEOUT, tunnel) => {
            result.map_err(|_| EndpointConnectError::Other(
                "F5 TLS tunnel start timed out".into(),
            ))??
        }
    };
    let mut proposed_ipv4 = start.proposed_ipv4;
    let mut proposed_ipv6 = start.proposed_ipv6;
    if reconnect_snapshot.connected_once {
        proposed_ipv4 = reconnect_snapshot.previous_ipv4;
        proposed_ipv6 = reconnect_snapshot.previous_ipv6;
    }
    let ppp_options = PppNegotiatorOptions {
        encapsulation,
        want_ipv4: parsed.want_ipv4,
        want_ipv6: parsed.want_ipv6,
        ipv4_address: proposed_ipv4,
        ipv6_address: proposed_ipv6,
        lock_addresses: reconnect_snapshot.connected_once,
        mtu: parsed.configuration.mtu,
        request_ipv4_name_servers: parsed.want_ipv4
            && parsed.configuration.dns.is_empty()
            && parsed.configuration.nbns.is_empty(),
        echo_interval: options.dpd_interval.as_std().unwrap_or(Duration::ZERO),
        ..Default::default()
    };
    let channel = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "F5 PPP negotiation cancelled".into(),
            ));
        }
        result = PppStreamSession::connect(
            Box::new(stream),
            PppStreamSessionOptions {
                negotiator: ppp_options,
                queue_length: endpoint_queue_length(options),
                initial_payload: Vec::new(),
            },
        ) => result.map_err(|error| EndpointConnectError::Other(error.to_string()))?,
    };
    let configuration = merge_fortinet_ppp_configuration(
        parsed.configuration,
        channel.tunnel_configuration(),
    )?;
    store_f5_reconnect_state(
        reconnect_state,
        channel.tunnel_configuration(),
        source_ip,
    )?;
    if let Some(template) = late_dtls_template.as_mut() {
        template.reconnect_snapshot.connected_once = true;
        template.reconnect_snapshot.source_ip = source_ip;
        template.reconnect_snapshot.previous_ipv4 =
            channel.tunnel_configuration().addresses.iter().find_map(
                |prefix| match prefix {
                    ipnet::IpNet::V4(prefix) => Some(*prefix),
                    ipnet::IpNet::V6(_) => None,
                },
            );
        template.reconnect_snapshot.previous_ipv6 =
            channel.tunnel_configuration().addresses.iter().find_map(
                |prefix| match prefix {
                    ipnet::IpNet::V6(prefix) => Some(*prefix),
                    ipnet::IpNet::V4(_) => None,
                },
            );
    }
    Ok((
        F5DataChannel {
            transport: F5PppTransport::Tls(channel),
            last_dtls_error,
            late_dtls: late_dtls_template.map(|template| F5LateDtlsState {
                template,
                next_attempt: tokio::time::Instant::now()
                    + F5_LATE_DTLS_RETRY_PERIOD,
                attempt: None,
            }),
            reconnect_state: reconnect_state.clone(),
        },
        configuration,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn connect_f5_dtls(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    authenticated: &F5AuthenticatedSession,
    parsed: &crate::protocol::openconnect::F5TunnelConfiguration,
    connect_request: &[u8],
    accepted_address: IpAddr,
    reconnect: &F5ReconnectState,
    cancellation: &CancellationToken,
) -> Result<
    (PppDatagramSession, TunnelConfiguration, Option<IpAddr>),
    EndpointConnectError,
> {
    let remote = SocketAddr::new(accepted_address, parsed.dtls_port);
    let server_name = if options.tls.server_name.is_empty() {
        authenticated
            .server_url
            .host_str()
            .unwrap_or_default()
            .to_owned()
    } else {
        options.tls.server_name.clone()
    };
    let roots = outbound_tls_root_store(&endpoint_tls_options(options))
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let record_mtu = f5_dtls_record_mtu(accepted_address);
    let client_identity_pem = load_f5_dtls_identity_pem(options)?;
    let (carrier, data_mtu, source_ip): (
        Arc<dyn PppDatagramCarrier>,
        usize,
        Option<IpAddr>,
    ) = if parsed.dtls12 {
        let connection = connect_certificate_dtls(
            transport_dialer,
            remote,
            CertificateDtlsClientOptions {
                server_name,
                record_mtu,
                roots_cas: roots,
                insecure_skip_verify: options.tls.insecure,
                client_identity_pem,
                ..Default::default()
            },
            cancellation,
        )
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let data_mtu = connection.data_mtu();
        let source_ip = connection.local_address().map(|address| address.ip());
        (Arc::new(connection), data_mtu, source_ip)
    } else {
        if !options.allow_insecure_crypto {
            return Err(EndpointConnectError::Other(
                "F5 DTLS 1.0 requires allow_insecure_crypto".into(),
            ));
        }
        let destination = SocksAddr::Ip(remote);
        let packet = transport_dialer
            .listen_udp(&destination)
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let source_ip = packet
            .local_addr()
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?
            .map(|address| address.ip());
        let client_identity = load_f5_dtls10_identity(options)?;
        let connection = connect_certificate_dtls10(
            packet,
            destination,
            &CertificateDtls10ClientOptions {
                server_name,
                record_mtu,
                roots_cas: roots,
                insecure_skip_verify: options.tls.insecure,
                client_identity,
                ..Default::default()
            },
            cancellation,
        )
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let data_mtu = record_mtu.saturating_sub(80);
        (Arc::new(connection), data_mtu, source_ip)
    };
    if reconnect.connected_once
        && reconnect.source_ip.is_some()
        && reconnect.source_ip != source_ip
    {
        return Err(EndpointConnectError::SessionRejected(401));
    }
    if connect_request.len() > data_mtu {
        return Err(EndpointConnectError::Other(
            "F5 DTLS connect request exceeds negotiated datagram MTU".into(),
        ));
    }
    let (start, initial_datagram) =
        probe_f5_dtls(carrier.as_ref(), connect_request, cancellation).await?;
    let data_mtu = data_mtu.saturating_sub(8);
    if data_mtu < usize::from(PPP_MINIMUM_MRU) {
        return Err(EndpointConnectError::Other(
            "F5 DTLS data MTU is too small for PPP".into(),
        ));
    }
    let mut proposed_ipv4 = start.proposed_ipv4;
    let mut proposed_ipv6 = start.proposed_ipv6;
    if reconnect.connected_once {
        proposed_ipv4 = reconnect.previous_ipv4;
        proposed_ipv6 = reconnect.previous_ipv6;
    }
    let mtu = parsed
        .configuration
        .mtu
        .min(u32::try_from(data_mtu).unwrap_or(u32::MAX));
    let session = PppDatagramSession::connect(
        carrier,
        PppDatagramSessionOptions {
            negotiator: PppNegotiatorOptions {
                encapsulation: PppEncapsulation::F5,
                want_ipv4: parsed.want_ipv4,
                want_ipv6: parsed.want_ipv6,
                ipv4_address: proposed_ipv4,
                ipv6_address: proposed_ipv6,
                lock_addresses: reconnect.connected_once,
                mtu,
                request_ipv4_name_servers: parsed.want_ipv4
                    && parsed.configuration.dns.is_empty()
                    && parsed.configuration.nbns.is_empty(),
                echo_interval: options
                    .dpd_interval
                    .as_std()
                    .unwrap_or(Duration::ZERO),
                ..Default::default()
            },
            queue_length: endpoint_queue_length(options),
            initial_datagram,
        },
    )
    .await
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let configuration = merge_fortinet_ppp_configuration(
        parsed.configuration.clone(),
        session.tunnel_configuration(),
    )?;
    Ok((session, configuration, source_ip))
}

async fn probe_f5_dtls(
    carrier: &dyn PppDatagramCarrier,
    connect_request: &[u8],
    cancellation: &CancellationToken,
) -> Result<
    (crate::protocol::openconnect::F5TunnelStart, Vec<u8>),
    EndpointConnectError,
> {
    let mut buffer = vec![0_u8; 65_535];
    loop {
        let written = carrier
            .send(connect_request)
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        if written != connect_request.len() {
            return Err(EndpointConnectError::Other(
                "short F5 DTLS application probe write".into(),
            ));
        }
        let count = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(EndpointConnectError::Other(
                    "F5 DTLS application probe cancelled".into(),
                ));
            }
            result = tokio::time::timeout(
                Duration::from_secs(1),
                carrier.receive(&mut buffer),
            ) => match result {
                Ok(result) => result.map_err(|error| EndpointConnectError::Other(error.to_string()))?,
                Err(_) => continue,
            },
        };
        let content = &buffer[..count];
        let end = content
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
            .or_else(|| {
                content
                    .windows(2)
                    .position(|window| window == b"\n\n")
                    .map(|position| position + 2)
            })
            .ok_or_else(|| {
                EndpointConnectError::Other(
                    "incomplete F5 DTLS application response header".into(),
                )
            })?;
        let start = parse_f5_tunnel_start(&content[..end]).map_err(
            |error| match error {
                F5TunnelError::SessionRejected(status) => {
                    EndpointConnectError::SessionRejected(status.as_u16())
                }
                error => EndpointConnectError::Other(error.to_string()),
            },
        )?;
        if start.status != StatusCode::OK {
            return Err(EndpointConnectError::Other(format!(
                "F5 DTLS application probe returned HTTP {}",
                start.status
            )));
        }
        return Ok((start, content[end..].to_vec()));
    }
}

fn load_f5_dtls_identity_pem(
    options: &OpenConnectEndpointOptions,
) -> Result<Option<String>, EndpointConnectError> {
    let configured = !options.tls.client_certificate.as_slice().is_empty()
        || !options.tls.client_certificate_path.is_empty();
    if !configured {
        return Ok(None);
    }
    let certificate = load_openconnect_material(
        options.tls.client_certificate.as_slice(),
        &options.tls.client_certificate_path,
        "F5 DTLS client certificate",
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let key = load_openconnect_material(
        options.tls.client_key.as_slice(),
        &options.tls.client_key_path,
        "F5 DTLS client private key",
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let key = String::from_utf8(key)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let certificate = String::from_utf8(certificate)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    Ok(Some(format!("{key}\n{certificate}")))
}

fn load_f5_dtls10_identity(
    options: &OpenConnectEndpointOptions,
) -> Result<Option<CertificateDtls10ClientIdentity>, EndpointConnectError> {
    let Some(pem) = load_f5_dtls_identity_pem(options)? else {
        return Ok(None);
    };
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certificates = rustls_pemfile::certs(&mut reader)
        .map(|certificate| certificate.map(|certificate| certificate.to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let private_key = PKey::private_key_from_pem(pem.as_bytes())
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    CertificateDtls10ClientIdentity::new(certificates, private_key)
        .map(Some)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))
}

async fn execute_f5_configuration_request(
    http: &mut AnyConnectAuthHttpClient,
    url: url::Url,
    description: &str,
) -> Result<
    crate::protocol::openconnect::AnyConnectAuthHttpResponse,
    EndpointConnectError,
> {
    let response = http
        .execute(crate::protocol::openconnect::AnyConnectAuthHttpRequest {
            method: Method::GET,
            url,
            content_type: None,
            body: Vec::new(),
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: false,
        })
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if response.body.len() > F5_MAXIMUM_AUTHENTICATION_BODY {
        return Err(EndpointConnectError::Other(format!(
            "F5 {description} response exceeds {F5_MAXIMUM_AUTHENTICATION_BODY} bytes"
        )));
    }
    if matches!(
        response.status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Err(EndpointConnectError::SessionRejected(
            response.status.as_u16(),
        ));
    }
    if response.status.is_redirection() {
        return Err(EndpointConnectError::SessionRejected(
            response.status.as_u16(),
        ));
    }
    if response.status != StatusCode::OK {
        return Err(EndpointConnectError::Other(format!(
            "F5 {description} returned HTTP {}",
            response.status
        )));
    }
    Ok(response)
}

fn store_f5_reconnect_state(
    state: &Mutex<F5ReconnectState>,
    configuration: &TunnelConfiguration,
    source_ip: Option<IpAddr>,
) -> Result<(), EndpointConnectError> {
    let mut state = state.lock().map_err(|_| {
        EndpointConnectError::Other("F5 reconnect state lock poisoned".into())
    })?;
    state.previous_ipv4 = configuration.addresses.iter().find_map(|prefix| {
        if let ipnet::IpNet::V4(prefix) = prefix {
            Some(*prefix)
        } else {
            None
        }
    });
    state.previous_ipv6 = configuration.addresses.iter().find_map(|prefix| {
        if let ipnet::IpNet::V6(prefix) = prefix {
            Some(*prefix)
        } else {
            None
        }
    });
    state.source_ip = source_ip;
    state.connected_once = true;
    Ok(())
}

async fn connect_authenticated_fortinet(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    authenticated: &FortinetAuthenticatedSession,
    cancellation: &CancellationToken,
    reconnect_state: &Arc<Mutex<FortinetReconnectState>>,
) -> Result<(FortinetDataChannel, TunnelConfiguration), EndpointConnectError> {
    let base_transport =
        endpoint_auth_http_transport(options, transport_dialer.clone());
    let transport = match authenticated.authenticated_address {
        Some(address) => base_transport.with_pinned_address(address),
        None => base_transport,
    };
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(transport),
        fortinet_user_agent(options),
    );
    for (name, value) in &authenticated.cookies {
        http.set_cookie(&authenticated.server_url, name, value)
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    }
    let mut configuration_url = authenticated.server_url.clone();
    configuration_url.set_path("/remote/fortisslvpn_xml");
    configuration_url
        .set_query((!options.ipv6_disabled).then_some("dual_stack=1"));
    configuration_url.set_fragment(None);
    let response = http
        .execute(crate::protocol::openconnect::AnyConnectAuthHttpRequest {
            method: Method::GET,
            url: configuration_url,
            content_type: None,
            body: Vec::new(),
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: false,
        })
        .await
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if response.body.len() > FORTINET_MAXIMUM_AUTHENTICATION_BODY {
        return Err(EndpointConnectError::Other(format!(
            "Fortinet configuration response exceeds {} bytes",
            FORTINET_MAXIMUM_AUTHENTICATION_BODY
        )));
    }
    if matches!(
        response.status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Err(EndpointConnectError::SessionRejected(
            response.status.as_u16(),
        ));
    }
    if response.status.is_redirection() {
        let login_redirect = response
            .headers
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|location| response.final_url.join(location).ok())
            .is_some_and(|location| {
                location.path().starts_with("/remote/login")
            });
        return if login_redirect {
            Err(EndpointConnectError::SessionRejected(
                response.status.as_u16(),
            ))
        } else {
            Err(EndpointConnectError::Other(format!(
                "Fortinet configuration returned an unexpected redirect: {}",
                response.status
            )))
        };
    }
    if response.status != StatusCode::OK {
        return Err(EndpointConnectError::Other(format!(
            "Fortinet configuration returned HTTP {}",
            response.status
        )));
    }
    let mut parsed = parse_fortinet_xml_configuration(
        &response.body,
        std::time::SystemTime::now(),
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    if options.ipv6_disabled {
        parsed.want_ipv6 = false;
        parsed.proposed_ipv6 = None;
        if !parsed.want_ipv4 {
            return Err(EndpointConnectError::Other(
                "Fortinet server did not provide IPv4 tunnel configuration"
                    .into(),
            ));
        }
    }
    if let Some(interval) = options
        .dpd_interval
        .as_std()
        .filter(|duration| !duration.is_zero())
    {
        parsed.echo_interval = interval;
    }
    let accepted_address = response
        .authenticated_address
        .or(authenticated.authenticated_address)
        .or_else(|| authenticated.server_url.host_str()?.parse().ok())
        .ok_or_else(|| {
            EndpointConnectError::Other(
                "Fortinet configuration endpoint exposed no accepted address"
                    .into(),
            )
        })?;
    parsed.configuration.mtu = calculate_ppp_tunnel_mtu(
        options.mtu,
        options.base_mtu,
        accepted_address.is_ipv6(),
        PppEncapsulation::Fortinet,
    );
    let ipv6_disabled = options.ipv6_disabled
        || parsed.configuration.mtu < PPP_MINIMUM_IPV6_MTU;
    if ipv6_disabled {
        parsed.want_ipv6 = false;
        parsed.proposed_ipv6 = None;
        if !parsed.want_ipv4 {
            return Err(EndpointConnectError::Other(
                "calculated Fortinet tunnel MTU is too small for IPv6-only configuration"
                    .into(),
            ));
        }
    }
    parsed.configuration.remote_address = Some(accepted_address);
    parsed.configuration = normalize_openconnect_configuration(
        parsed.configuration,
        ipv6_disabled,
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let reconnect_snapshot = reconnect_state
        .lock()
        .map_err(|_| {
            EndpointConnectError::Other(
                "Fortinet reconnect state lock poisoned".into(),
            )
        })?
        .clone();
    validate_fortinet_reconnect(&parsed, &reconnect_snapshot)?;
    if reconnect_snapshot.connected_once {
        if let Some(address) = reconnect_snapshot.previous_ipv4 {
            parsed.proposed_ipv4 = Some(address);
        }
        if let Some(address) = reconnect_snapshot.previous_ipv6 {
            parsed.proposed_ipv6 = Some(address);
        }
    }
    let mut tunnel_url = authenticated.server_url.clone();
    tunnel_url.set_path("/remote/sslvpn-tunnel");
    tunnel_url.set_query(None);
    tunnel_url.set_fragment(None);
    let cookies = http.cookie_pairs(&tunnel_url);
    let cookie_refs = cookies
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let svpn_cookie = cookies
        .iter()
        .find(|(name, value)| name == "SVPNCOOKIE" && !value.is_empty())
        .map(|(_, value)| value.clone())
        .ok_or(EndpointConnectError::SessionRejected(401))?;
    let tunnel_request = build_fortinet_tls_connect_request(
        &tunnel_url,
        &cookie_refs,
        &fortinet_user_agent(options),
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let port = tunnel_url.port_or_known_default().ok_or_else(|| {
        EndpointConnectError::Other("Fortinet tunnel URL has no port".into())
    })?;
    let remote = SocketAddr::new(accepted_address, port);
    let destination = SocksAddr::Ip(remote);
    let mut last_dtls_error = None;
    let mut late_dtls_template = None;
    if parsed.dtls_enabled && !options.no_udp {
        let tls_options = endpoint_tls_options(options);
        if let Some(reason) = fortinet_dtls_unsupported_reason(&tls_options) {
            last_dtls_error = Some(reason);
        } else {
            let roots =
                outbound_tls_root_store(&tls_options).map_err(|error| {
                    EndpointConnectError::Other(error.to_string())
                })?;
            let dtls_request = build_fortinet_dtls_connect_request(
                &svpn_cookie,
            )
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
            let server_name = if tls_options.server_name.is_empty() {
                tunnel_url.host_str().unwrap_or_default().to_owned()
            } else {
                tls_options.server_name.clone()
            };
            let template = FortinetLateDtlsAttempt {
                dialer: transport_dialer.clone(),
                remote,
                connection_options: CertificateDtlsClientOptions {
                    server_name,
                    record_mtu: fortinet_dtls_record_mtu(accepted_address),
                    roots_cas: roots,
                    insecure_skip_verify: tls_options.insecure,
                    ..Default::default()
                },
                connect_request: dtls_request,
                configuration: parsed.clone(),
                reconnect_snapshot: reconnect_snapshot.clone(),
                queue_length: endpoint_queue_length(options),
                cancellation: cancellation.clone(),
            };
            match tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err(EndpointConnectError::Other(
                        "Fortinet DTLS tunnel start cancelled".into(),
                    ));
                }
                result = tokio::time::timeout(Duration::from_secs(5), template.connect()) => result,
            } {
                Ok(Ok((channel, source_ip))) => {
                    let configuration = merge_fortinet_ppp_configuration(
                        parsed.configuration,
                        channel.tunnel_configuration(),
                    )?;
                    store_fortinet_reconnect_state(
                        reconnect_state,
                        channel.tunnel_configuration(),
                        source_ip,
                    )?;
                    return Ok((
                        FortinetDataChannel {
                            transport: FortinetPppTransport::Dtls(channel),
                            last_dtls_error: None,
                            late_dtls: None,
                            reconnect_state: reconnect_state.clone(),
                        },
                        configuration,
                    ));
                }
                Ok(Err(EndpointConnectError::SessionRejected(status))) => {
                    return Err(EndpointConnectError::SessionRejected(status));
                }
                Ok(Err(error)) => {
                    last_dtls_error = Some(error.to_string());
                    late_dtls_template = Some(template);
                }
                Err(_) => {
                    last_dtls_error =
                        Some("Fortinet initial DTLS window timed out".into());
                    late_dtls_template = Some(template);
                }
            }
        }
    }
    let raw_stream = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "Fortinet TLS tunnel start cancelled".into(),
            ));
        }
        result = transport_dialer.dial_tcp(&destination) => result,
    }
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let source_ip = stream_local_addr(&raw_stream)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))?
        .map(|address| address.ip());
    validate_fortinet_reconnect_source(
        &parsed,
        &reconnect_snapshot,
        source_ip,
    )?;
    let host = tunnel_url.host_str().ok_or_else(|| {
        EndpointConnectError::Other("Fortinet tunnel URL has no host".into())
    })?;
    let tls = build_client_config(
        host,
        &endpoint_tls_options(options),
        &["http/1.1"],
    )
    .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
    let tunnel = async {
        let mut stream = TlsConnector::from(tls.config)
            .connect(tls.server_name, raw_stream)
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        stream
            .write_all(&tunnel_request)
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| EndpointConnectError::Other(error.to_string()))?;
        let start = read_fortinet_tls_tunnel_start(&mut stream).await.map_err(
            |error| match error {
                FortinetTunnelError::SessionRejected(status) => {
                    EndpointConnectError::SessionRejected(status)
                }
                error => EndpointConnectError::Other(error.to_string()),
            },
        )?;
        Ok::<_, EndpointConnectError>((stream, start))
    };
    let (stream, start) = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "Fortinet TLS tunnel start cancelled".into(),
            ));
        }
        result = tokio::time::timeout(
            crate::protocol::openconnect::FORTINET_TLS_CONNECT_TIMEOUT,
            tunnel,
        ) => result.map_err(|_| EndpointConnectError::Other(
            "Fortinet TLS tunnel start timed out".into(),
        ))??,
    };
    let ppp_configuration = fortinet_ppp_options(
        &parsed,
        parsed.configuration.mtu,
        reconnect_snapshot.connected_once,
    );
    let channel = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(EndpointConnectError::Other(
                "Fortinet PPP negotiation cancelled".into(),
            ));
        }
        result = PppStreamSession::connect(
            Box::new(stream),
            PppStreamSessionOptions {
                negotiator: ppp_configuration,
                queue_length: endpoint_queue_length(options),
                initial_payload: start.initial_payload,
            },
        ) => result.map_err(|error| EndpointConnectError::Other(error.to_string()))?,
    };
    let configuration = merge_fortinet_ppp_configuration(
        parsed.configuration,
        channel.tunnel_configuration(),
    )?;
    store_fortinet_reconnect_state(
        reconnect_state,
        channel.tunnel_configuration(),
        source_ip,
    )?;
    if let Some(template) = late_dtls_template.as_mut() {
        template.reconnect_snapshot.connected_once = true;
        template.reconnect_snapshot.source_ip = source_ip;
        template.reconnect_snapshot.previous_ipv4 =
            channel.tunnel_configuration().addresses.iter().find_map(
                |prefix| match prefix {
                    ipnet::IpNet::V4(prefix) => Some(*prefix),
                    ipnet::IpNet::V6(_) => None,
                },
            );
        template.reconnect_snapshot.previous_ipv6 =
            channel.tunnel_configuration().addresses.iter().find_map(
                |prefix| match prefix {
                    ipnet::IpNet::V6(prefix) => Some(*prefix),
                    ipnet::IpNet::V4(_) => None,
                },
            );
        template.configuration.proposed_ipv4 =
            template.reconnect_snapshot.previous_ipv4;
        template.configuration.proposed_ipv6 =
            template.reconnect_snapshot.previous_ipv6;
    }
    Ok((
        FortinetDataChannel {
            transport: FortinetPppTransport::Tls(channel),
            last_dtls_error,
            late_dtls: late_dtls_template.map(|template| {
                FortinetLateDtlsState {
                    template,
                    next_attempt: tokio::time::Instant::now()
                        + FORTINET_LATE_DTLS_RETRY_PERIOD,
                    attempt: None,
                }
            }),
            reconnect_state: reconnect_state.clone(),
        },
        configuration,
    ))
}

fn fortinet_ppp_options(
    configuration: &crate::protocol::openconnect::FortinetTunnelConfiguration,
    mtu: u32,
    lock_addresses: bool,
) -> PppNegotiatorOptions {
    PppNegotiatorOptions {
        encapsulation: PppEncapsulation::Fortinet,
        want_ipv4: configuration.want_ipv4,
        want_ipv6: configuration.want_ipv6,
        ipv4_address: configuration.proposed_ipv4,
        ipv6_address: configuration.proposed_ipv6,
        lock_addresses,
        mtu,
        request_ipv4_name_servers: configuration.want_ipv4
            && configuration.configuration.dns.is_empty(),
        echo_interval: configuration.echo_interval,
        ..Default::default()
    }
}

fn validate_fortinet_reconnect(
    configuration: &crate::protocol::openconnect::FortinetTunnelConfiguration,
    state: &FortinetReconnectState,
) -> Result<(), EndpointConnectError> {
    if state.force_reauthentication
        || configuration
            .configuration
            .authentication_expiration
            .is_some_and(|expiration| {
                expiration <= std::time::SystemTime::now()
            })
    {
        return Err(EndpointConnectError::SessionRejected(401));
    }
    if !state.connected_once {
        return Ok(());
    }
    let allowed = configuration.reconnect_allowed
        && !configuration.cleanup_timeout.is_zero()
        && state.dropped_at.is_some_and(|dropped_at| {
            std::time::Instant::now().saturating_duration_since(dropped_at)
                < configuration.cleanup_timeout
        });
    if allowed {
        Ok(())
    } else {
        Err(EndpointConnectError::SessionRejected(401))
    }
}

fn validate_fortinet_reconnect_source(
    configuration: &crate::protocol::openconnect::FortinetTunnelConfiguration,
    state: &FortinetReconnectState,
    source_ip: Option<IpAddr>,
) -> Result<(), EndpointConnectError> {
    if state.connected_once
        && configuration.check_source_ip
        && (state.source_ip.is_none() || source_ip != state.source_ip)
    {
        return Err(EndpointConnectError::SessionRejected(401));
    }
    Ok(())
}

fn store_fortinet_reconnect_state(
    state: &Mutex<FortinetReconnectState>,
    configuration: &TunnelConfiguration,
    source_ip: Option<IpAddr>,
) -> Result<(), EndpointConnectError> {
    let mut state = state.lock().map_err(|_| {
        EndpointConnectError::Other(
            "Fortinet reconnect state lock poisoned".into(),
        )
    })?;
    state.previous_ipv4 = configuration.addresses.iter().find_map(|prefix| {
        if let ipnet::IpNet::V4(prefix) = prefix {
            Some(*prefix)
        } else {
            None
        }
    });
    state.previous_ipv6 = configuration.addresses.iter().find_map(|prefix| {
        if let ipnet::IpNet::V6(prefix) = prefix {
            Some(*prefix)
        } else {
            None
        }
    });
    state.source_ip = source_ip;
    state.connected_once = true;
    state.force_reauthentication = false;
    state.dropped_at = None;
    Ok(())
}

fn merge_fortinet_ppp_configuration(
    mut base: TunnelConfiguration,
    negotiated: &TunnelConfiguration,
) -> Result<TunnelConfiguration, EndpointConnectError> {
    base.mtu = negotiated.mtu;
    base.addresses.clone_from(&negotiated.addresses);
    if base.dns.is_empty() {
        base.dns.clone_from(&negotiated.dns);
    }
    if base.nbns.is_empty() {
        base.nbns.clone_from(&negotiated.nbns);
    }
    normalize_openconnect_configuration(base, false)
        .map_err(|error| EndpointConnectError::Other(error.to_string()))
}

fn fortinet_dtls_unsupported_reason(
    tls: &OutboundTlsOptions,
) -> Option<String> {
    let unsupported = !tls.server_certificate_fingerprints.is_empty()
        || !tls.certificate_public_key_sha256.as_slice().is_empty()
        || !tls.client_certificate.as_slice().is_empty()
        || !tls.client_certificate_path.is_empty()
        || !tls.client_key.as_slice().is_empty()
        || !tls.client_key_path.is_empty()
        || !tls.cipher_suites.as_slice().is_empty()
        || !tls.curve_preferences.as_slice().is_empty()
        || !tls.alpn.as_slice().is_empty()
        || tls.disable_sni
        || !tls.engine.is_empty()
        || !tls.spoof.is_empty()
        || tls.utls.as_ref().is_some_and(|options| options.enabled)
        || tls.reality.as_ref().is_some_and(|options| options.enabled)
        || tls.ech.as_ref().is_some_and(|options| options.enabled)
        || tls.min_version == "1.3"
        || (!tls.max_version.is_empty() && tls.max_version != "1.2");
    unsupported.then(|| {
        "Fortinet DTLS cannot preserve the configured TLS policy; using TLS carrier"
            .into()
    })
}

fn f5_dtls_unsupported_reason(tls: &OutboundTlsOptions) -> Option<String> {
    let unsupported = !tls.server_certificate_fingerprints.is_empty()
        || !tls.certificate_public_key_sha256.as_slice().is_empty()
        || !tls.cipher_suites.as_slice().is_empty()
        || !tls.curve_preferences.as_slice().is_empty()
        || !tls.alpn.as_slice().is_empty()
        || tls.disable_sni
        || !tls.engine.is_empty()
        || !tls.spoof.is_empty()
        || tls.utls.as_ref().is_some_and(|options| options.enabled)
        || tls.reality.as_ref().is_some_and(|options| options.enabled)
        || tls.ech.as_ref().is_some_and(|options| options.enabled)
        || tls.min_version == "1.3";
    unsupported.then(|| {
        "F5 DTLS cannot preserve the configured TLS policy; using TLS carrier"
            .into()
    })
}

async fn probe_fortinet_dtls(
    connection: &CertificateDtlsConnection,
    client_hello: &[u8],
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                return Err("Fortinet DTLS probe cancelled".into());
            }
            result = connection.write(client_hello) => {
                let written = result.map_err(|error| error.to_string())?;
                if written != client_hello.len() {
                    return Err(format!(
                        "short Fortinet DTLS client hello write: wrote {written} of {} bytes",
                        client_hello.len()
                    ));
                }
            }
        }
        let read = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err("Fortinet DTLS probe cancelled".into());
            }
            result = tokio::time::timeout(
                Duration::from_secs(1),
                connection.read(&mut buffer),
            ) => result,
        };
        let Ok(read) = read else { continue };
        let size = read.map_err(|error| error.to_string())?;
        let response = &buffer[..size];
        if valid_fortinet_dtls_server_hello(response) {
            return Ok(Vec::new());
        }
        if valid_fortinet_ppp_datagram(response) {
            return Ok(response.to_vec());
        }
        return Err("malformed or rejected Fortinet DTLS server hello".into());
    }
}

fn normalize_openconnect_configuration(
    mut configuration: TunnelConfiguration,
    ipv6_disabled: bool,
) -> io::Result<TunnelConfiguration> {
    if configuration.mtu == 0 {
        configuration.mtu = OPENCONNECT_DEFAULT_MTU;
    }
    if ipv6_disabled {
        configuration
            .addresses
            .retain(|prefix| prefix.addr().is_ipv4());
        configuration
            .routes
            .retain(|route| route.prefix.addr().is_ipv4());
        configuration
            .excluded_routes
            .retain(|route| route.prefix.addr().is_ipv4());
        configuration.dns.retain(IpAddr::is_ipv4);
        configuration.nbns.retain(IpAddr::is_ipv4);
        for rule in &mut configuration.split_dns_rules {
            rule.servers.retain(IpAddr::is_ipv4);
        }
        configuration
            .split_dns_rules
            .retain(|rule| !rule.servers.is_empty());
    }
    if let Some(remote_address) = configuration.remote_address.map(|address| {
        if let IpAddr::V6(address) = address
            && let Some(address) = address.to_ipv4_mapped()
        {
            return IpAddr::V4(address);
        }
        address
    }) && !configuration
        .excluded_routes
        .iter()
        .any(|route| route.prefix.contains(&remote_address))
    {
        configuration.excluded_routes.push(
            crate::protocol::openconnect::TunnelRoute {
                prefix: ipnet::IpNet::new(
                    remote_address,
                    if remote_address.is_ipv4() { 32 } else { 128 },
                )
                .map_err(|error| {
                    invalid(format!(
                        "invalid OpenConnect remote address route: {error}"
                    ))
                })?,
                gateway: None,
                metric: 0,
            },
        );
    }
    for dns_address in configuration.dns.clone() {
        add_openconnect_dns_route(&mut configuration, dns_address)?;
    }
    let rule_servers = configuration
        .split_dns_rules
        .iter()
        .flat_map(|rule| rule.servers.iter().copied())
        .collect::<Vec<_>>();
    for dns_address in rule_servers {
        add_openconnect_dns_route(&mut configuration, dns_address)?;
    }
    Ok(configuration)
}

fn add_openconnect_dns_route(
    configuration: &mut TunnelConfiguration,
    dns_address: IpAddr,
) -> io::Result<()> {
    let excluded = configuration
        .excluded_routes
        .iter()
        .any(|route| route.prefix.contains(&dns_address));
    let included = configuration
        .routes
        .iter()
        .any(|route| route.prefix.contains(&dns_address));
    if !excluded && !included {
        configuration
            .routes
            .push(crate::protocol::openconnect::TunnelRoute {
                prefix: ipnet::IpNet::new(
                    dns_address,
                    if dns_address.is_ipv4() { 32 } else { 128 },
                )
                .map_err(|error| {
                    invalid(format!(
                        "invalid OpenConnect DNS address route: {error}"
                    ))
                })?,
                gateway: None,
                metric: 0,
            });
    }
    Ok(())
}

fn openconnect_preferred_address(
    configuration: &TunnelConfiguration,
    address: IpAddr,
) -> bool {
    configuration
        .routes
        .iter()
        .any(|route| route.prefix.contains(&address))
        && !configuration
            .excluded_routes
            .iter()
            .any(|route| route.prefix.contains(&address))
}

fn openconnect_preferred_domain(
    configuration: &TunnelConfiguration,
    domain: &str,
) -> bool {
    let domain = canonical_openconnect_domain(domain);
    configuration
        .search_domains
        .iter()
        .chain(&configuration.split_dns)
        .chain(
            configuration
                .split_dns_rules
                .iter()
                .flat_map(|rule| rule.domains.iter()),
        )
        .map(|suffix| canonical_openconnect_domain(suffix))
        .any(|suffix| {
            !suffix.is_empty()
                && (domain == suffix
                    || domain
                        .strip_suffix(&suffix)
                        .is_some_and(|prefix| prefix.ends_with('.')))
        })
}

fn canonical_openconnect_domain(domain: &str) -> String {
    domain.trim().trim_matches('.').to_ascii_lowercase()
}

fn build_openconnect_network(
    channel: OpenConnectDataChannel,
    configuration: &TunnelConfiguration,
    handle: &OpenConnectEndpointHandle,
    queue_length: usize,
) -> io::Result<Arc<OpenConnectNetwork>> {
    OpenConnectNetwork::start(
        channel,
        configuration,
        handle.tunnel_configuration.clone(),
        handle.last_error.clone(),
        handle.dtls_active.clone(),
        handle.last_dtls_error.clone(),
        handle.dialer.clone(),
        queue_length,
        handle.flow.clone(),
    )
}

fn publish_openconnect_network(
    network: Arc<OpenConnectNetwork>,
    configuration: TunnelConfiguration,
    handle: &OpenConnectEndpointHandle,
    network_slot: &Mutex<Option<Arc<OpenConnectNetwork>>>,
) -> io::Result<()> {
    handle.dialer.update_configuration(configuration.clone())?;
    handle
        .dialer
        .activate(network.net.clone(), network.packet_output.clone())?;
    *handle.tunnel_configuration.write().map_err(|_| {
        io::Error::other("OpenConnect configuration lock poisoned")
    })? = Some(configuration);
    *handle
        .dtls_active
        .write()
        .map_err(|_| io::Error::other("OpenConnect DTLS lock poisoned"))? =
        network.dtls_active;
    *handle.last_dtls_error.write().map_err(|_| {
        io::Error::other("OpenConnect DTLS error lock poisoned")
    })? = network.initial_dtls_error.clone();
    *handle
        .last_error
        .write()
        .map_err(|_| io::Error::other("OpenConnect error lock poisoned"))? =
        None;
    network_slot
        .lock()
        .map_err(|_| io::Error::other("OpenConnect network lock poisoned"))?
        .replace(network);
    handle
        .userspace_stack_generation
        .fetch_add(1, Ordering::AcqRel);
    Ok(())
}

async fn run_openconnect_supervisor(
    options: OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    handle: OpenConnectEndpointHandle,
    cancellation: CancellationToken,
    shared: OpenConnectSupervisorShared,
    mut authenticated: OpenConnectAuthenticatedSession,
    mut network: Arc<OpenConnectNetwork>,
) {
    const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
    const MAXIMUM_BACKOFF: Duration = Duration::from_secs(60);
    const DEFAULT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(300);

    loop {
        let failure = tokio::select! {
            _ = cancellation.cancelled() => return,
            failure = network.wait_failure() => failure,
        };
        let Some(failure) = failure else {
            return;
        };
        let terminal_failure = failure.is_terminal();
        let failure = failure.message().to_owned();
        if matches!(
            &authenticated,
            OpenConnectAuthenticatedSession::Fortinet(_)
        ) && let Ok(mut state) = shared.fortinet_reconnect_state.lock()
            && state.connected_once
            && state.dropped_at.is_none()
        {
            state.dropped_at = Some(std::time::Instant::now());
        }
        if let Ok(mut message) = handle.last_error.write() {
            *message = Some(failure);
        }
        if terminal_failure {
            return;
        }

        let mut backoff = INITIAL_BACKOFF;
        let mut remaining = options
            .reconnect_timeout
            .as_std()
            .filter(|timeout| !timeout.is_zero())
            .unwrap_or(DEFAULT_RECONNECT_TIMEOUT);
        let mut authenticate_again = false;
        let mut reuse_stack = true;

        loop {
            if authenticate_again {
                let authentication = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    result = authenticate_openconnect(
                        &options,
                        transport_dialer.clone(),
                        &handle,
                        &cancellation,
                    ) => result,
                };
                match authentication {
                    Ok(session) => {
                        if matches!(
                            &session,
                            OpenConnectAuthenticatedSession::Fortinet(_)
                        ) && let Ok(mut state) =
                            shared.fortinet_reconnect_state.lock()
                        {
                            *state = FortinetReconnectState::default();
                        }
                        if matches!(
                            &session,
                            OpenConnectAuthenticatedSession::F5(_)
                        ) && let Ok(mut state) =
                            shared.f5_reconnect_state.lock()
                        {
                            *state = F5ReconnectState::default();
                        }
                        if let OpenConnectAuthenticatedSession::F5(session) =
                            &session
                            && let Ok(mut slot) = shared.f5_session.write()
                        {
                            *slot = Some(session.clone());
                        }
                        if let OpenConnectAuthenticatedSession::Pulse(session) =
                            &session
                            && let Ok(mut slot) = shared.pulse_session.write()
                        {
                            *slot = Some(session.clone());
                        }
                        if let OpenConnectAuthenticatedSession::NetworkConnect(
                            session,
                        ) = &session
                            && let Ok(mut slot) =
                                shared.network_connect_session.write()
                        {
                            *slot = Some(session.clone());
                        }
                        authenticated = session;
                        authenticate_again = false;
                    }
                    Err(error) => {
                        if !wait_openconnect_backoff(
                            &cancellation,
                            &mut backoff,
                            &mut remaining,
                            &handle,
                            error,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                }
            }

            let connection = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = connect_authenticated_openconnect(
                    &options,
                    transport_dialer.clone(),
                    &authenticated,
                    &cancellation,
                    &shared.globalprotect_session,
                    &shared.fortinet_reconnect_state,
                    &shared.f5_reconnect_state,
                ) => result,
            };
            let (channel, configuration) = match connection {
                Ok(connection) => connection,
                Err(EndpointConnectError::Terminal(error)) => {
                    if let Ok(mut message) = handle.last_error.write() {
                        *message = Some(error);
                    }
                    return;
                }
                Err(EndpointConnectError::SessionRejected(_)) => {
                    if let OpenConnectAuthenticatedSession::Pulse(previous) =
                        &authenticated
                    {
                        let previous = previous.clone();
                        let mut reconnect_options = options.clone();
                        let cookie =
                            match String::from_utf8(previous.cookie.clone()) {
                                Ok(cookie) => cookie,
                                Err(_) => {
                                    authenticate_again = true;
                                    continue;
                                }
                            };
                        reconnect_options.cookie = cookie;
                        let reconnect = tokio::select! {
                            _ = cancellation.cancelled() => return,
                            result = authenticate_pulse(
                                &reconnect_options,
                                transport_dialer.clone(),
                                &handle.challenge_manager,
                                &cancellation,
                                true,
                                Some(previous.accepted_address),
                                openconnect_software_token_generator(&handle),
                            ) => result,
                        };
                        match reconnect {
                            Ok(session) => {
                                if let Ok(mut slot) =
                                    shared.pulse_session.write()
                                {
                                    *slot = Some(session.clone());
                                }
                                authenticated =
                                    OpenConnectAuthenticatedSession::Pulse(
                                        session,
                                    );
                                continue;
                            }
                            Err(error) => {
                                if let Ok(mut message) =
                                    handle.last_error.write()
                                {
                                    *message = Some(format!(
                                        "Pulse cookie reconnect failed: {error}"
                                    ));
                                }
                            }
                        }
                    }
                    authenticate_again = true;
                    continue;
                }
                Err(error) => {
                    if !wait_openconnect_backoff(
                        &cancellation,
                        &mut backoff,
                        &mut remaining,
                        &handle,
                        error.to_string(),
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
            };
            if reuse_stack && network.is_compatible(&configuration) {
                match network.replace_channel(channel).await {
                    Ok(()) => {
                        let publish_result = handle
                            .dialer
                            .update_configuration(configuration.clone())
                            .and_then(|()| {
                                handle
                                    .dialer
                                    .activate(
                                        network.net.clone(),
                                        network.packet_output.clone(),
                                    )?;
                                *handle.tunnel_configuration.write().map_err(
                                    |_| {
                                        io::Error::other(
                                            "OpenConnect configuration lock poisoned",
                                        )
                                    },
                                )? = Some(configuration);
                                *handle.last_error.write().map_err(|_| {
                                    io::Error::other(
                                        "OpenConnect error lock poisoned",
                                    )
                                })? = None;
                                Ok(())
                            });
                        if publish_result.is_ok() {
                            handle
                                .successful_reconnections
                                .fetch_add(1, Ordering::AcqRel);
                            break;
                        }
                        reuse_stack = false;
                    }
                    Err(_) => reuse_stack = false,
                }
                if !wait_openconnect_backoff(
                    &cancellation,
                    &mut backoff,
                    &mut remaining,
                    &handle,
                    "failed to reuse OpenConnect userspace network".into(),
                )
                .await
                {
                    return;
                }
                continue;
            }
            let replacement = match build_openconnect_network(
                channel,
                &configuration,
                &handle,
                endpoint_queue_length(&options),
            ) {
                Ok(network) => network,
                Err(error) => {
                    if !wait_openconnect_backoff(
                        &cancellation,
                        &mut backoff,
                        &mut remaining,
                        &handle,
                        error.to_string(),
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
            };
            if let Err(error) = publish_openconnect_network(
                replacement.clone(),
                configuration,
                &handle,
                &shared.network_slot,
            ) {
                replacement.close().await;
                if !wait_openconnect_backoff(
                    &cancellation,
                    &mut backoff,
                    &mut remaining,
                    &handle,
                    error.to_string(),
                )
                .await
                {
                    return;
                }
                continue;
            }
            network.close().await;
            network = replacement;
            handle
                .successful_reconnections
                .fetch_add(1, Ordering::AcqRel);
            break;
        }
    }

    async fn wait_openconnect_backoff(
        cancellation: &CancellationToken,
        backoff: &mut Duration,
        remaining: &mut Duration,
        handle: &OpenConnectEndpointHandle,
        error: String,
    ) -> bool {
        if let Ok(mut message) = handle.last_error.write() {
            *message = Some(error);
        }
        if remaining.is_zero() {
            if let Ok(mut message) = handle.last_error.write() {
                *message =
                    Some("OpenConnect reconnect timeout exceeded".into());
            }
            return false;
        }
        let wait = (*backoff).min(*remaining);
        tokio::select! {
            _ = cancellation.cancelled() => return false,
            _ = tokio::time::sleep(wait) => {}
        }
        *remaining = remaining.saturating_sub(wait);
        *backoff = backoff.saturating_mul(2).min(MAXIMUM_BACKOFF);
        true
    }
}

async fn logout_globalprotect_endpoint(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    session: GlobalProtectAuthenticatedSession,
) -> Result<(), String> {
    let Some(authenticated_address) = session.authenticated_address else {
        return Ok(());
    };
    let transport = endpoint_auth_http_transport(options, transport_dialer)
        .with_pinned_address(authenticated_address);
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(transport),
        globalprotect_user_agent(options),
    );
    tokio::time::timeout(
        Duration::from_secs(5),
        logout_globalprotect_session(&mut http, &session),
    )
    .await
    .map_err(|_| "GlobalProtect logout timed out".to_owned())?
    .map_err(|error| error.to_string())
}

async fn logout_f5_endpoint(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    session: F5AuthenticatedSession,
) -> Result<(), String> {
    let Some(authenticated_address) = session.authenticated_address else {
        return Ok(());
    };
    if session.mrh_session.is_empty() {
        return Ok(());
    }
    let transport = endpoint_auth_http_transport(options, transport_dialer)
        .with_pinned_address(authenticated_address);
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(transport),
        f5_user_agent(options),
    );
    for (name, value) in &session.cookies {
        http.set_cookie(&session.server_url, name, value)
            .map_err(|error| error.to_string())?;
    }
    let mut url = session.server_url;
    url.set_path("/vdesk/hangup.php3");
    url.set_query(Some("hangup_error=1"));
    url.set_fragment(None);
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        http.execute(AnyConnectAuthHttpRequest {
            method: Method::GET,
            url,
            content_type: None,
            body: Vec::new(),
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: false,
        }),
    )
    .await
    .map_err(|_| "F5 logout timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    if response.body.len() > F5_MAXIMUM_AUTHENTICATION_BODY {
        return Err(format!(
            "F5 logout response exceeds {F5_MAXIMUM_AUTHENTICATION_BODY} bytes"
        ));
    }
    if !response.status.is_success() {
        return Err(format!("F5 logout returned HTTP {}", response.status));
    }
    Ok(())
}

async fn logout_pulse_endpoint(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    session: PulseAuthenticatedSession,
) -> Result<(), String> {
    if let Some(connection) = session.live_connection.lock().await.take() {
        let mut stream = connection.into_inner();
        let _ = stream.shutdown().await;
    }
    if session.graceful_bye.load(Ordering::Acquire) || session.cookie.is_empty()
    {
        return Ok(());
    }
    let cookie = std::str::from_utf8(&session.cookie)
        .map_err(|_| "Pulse DSID cookie is not valid UTF-8".to_owned())?;
    let transport = endpoint_auth_http_transport(options, transport_dialer)
        .with_pinned_address(session.accepted_address);
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(transport),
        endpoint_user_agent(options),
    );
    http.set_cookie(&session.server_url, "DSID", cookie)
        .map_err(|error| error.to_string())?;
    let mut url = session.server_url;
    url.set_path("/dana-na/auth/logout.cgi");
    url.set_query(None);
    url.set_fragment(None);
    let response = tokio::time::timeout(
        PULSE_LOGOUT_TIMEOUT,
        http.execute(AnyConnectAuthHttpRequest {
            method: Method::GET,
            url,
            content_type: None,
            body: Vec::new(),
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: false,
        }),
    )
    .await
    .map_err(|_| "Pulse logout timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    if response.body.len() > PULSE_MAXIMUM_LOGOUT_BODY {
        return Err(format!(
            "Pulse logout response exceeds {PULSE_MAXIMUM_LOGOUT_BODY} bytes"
        ));
    }
    if !response.status.is_success() {
        return Err(format!("Pulse logout returned HTTP {}", response.status));
    }
    Ok(())
}

async fn logout_network_connect_endpoint(
    options: &OpenConnectEndpointOptions,
    transport_dialer: Arc<dyn Dialer>,
    session: NetworkConnectEndpointSession,
) -> Result<(), String> {
    let NetworkConnectEndpointSession {
        authenticated,
        tncc,
    } = session;
    let tncc_close_result = if let Some(runner) = tncc {
        runner
            .lock()
            .await
            .close()
            .await
            .map_err(|error| error.to_string())
    } else {
        Ok(())
    };
    if authenticated.dsid.is_empty() {
        return tncc_close_result;
    }
    let Some(authenticated_address) = authenticated.authenticated_address
    else {
        return tncc_close_result;
    };
    let transport = endpoint_auth_http_transport(options, transport_dialer)
        .with_pinned_address(authenticated_address);
    let mut http = AnyConnectAuthHttpClient::new(
        Arc::new(transport),
        network_connect_user_agent(options),
    );
    for (name, value) in &authenticated.cookies {
        http.set_cookie(&authenticated.server_url, name, value)
            .map_err(|error| error.to_string())?;
    }
    let mut url = authenticated.server_url;
    url.set_path("/dana-na/auth/logout.cgi");
    url.set_query(None);
    url.set_fragment(None);
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        http.execute(AnyConnectAuthHttpRequest {
            method: Method::GET,
            url,
            content_type: None,
            body: Vec::new(),
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: false,
        }),
    )
    .await
    .map_err(|_| "Network Connect logout timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    if response.body.len()
        > crate::protocol::openconnect::NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_BODY
    {
        return Err(format!(
            "Network Connect logout response exceeds {} bytes",
            crate::protocol::openconnect::NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_BODY
        ));
    }
    if response.status != StatusCode::OK {
        return Err(format!(
            "Network Connect logout returned HTTP {}",
            response.status
        ));
    }
    tncc_close_result
}

impl Lifecycle for OpenConnectEndpointService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.cancellation = CancellationToken::new();
            self.handle.challenge_manager.reopen();
            *self.fortinet_reconnect_state.lock().map_err(|_| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "Fortinet reconnect state lock poisoned".into(),
                }
            })? = FortinetReconnectState::default();
            *self.f5_reconnect_state.lock().map_err(|_| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "F5 reconnect state lock poisoned".into(),
                }
            })? = F5ReconnectState::default();
            let authentication = tokio::select! {
                _ = self.cancellation.cancelled() => {
                    return Err(LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: "OpenConnect endpoint start cancelled".into(),
                    });
                }
                authentication = self.authenticate() => authentication,
            };
            let authenticated =
                authentication.map_err(|message| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message,
                })?;
            if let OpenConnectAuthenticatedSession::F5(session) = &authenticated
            {
                *self.f5_session.write().map_err(|_| {
                    LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: "F5 session lock poisoned".into(),
                    }
                })? = Some(session.clone());
            }
            if let OpenConnectAuthenticatedSession::Pulse(session) =
                &authenticated
            {
                *self.pulse_session.write().map_err(|_| {
                    LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: "Pulse session lock poisoned".into(),
                    }
                })? = Some(session.clone());
            }
            if let OpenConnectAuthenticatedSession::NetworkConnect(session) =
                &authenticated
            {
                *self.network_connect_session.write().map_err(|_| {
                    LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: "Network Connect session lock poisoned".into(),
                    }
                })? = Some(session.clone());
            }
            let connection = tokio::select! {
                _ = self.cancellation.cancelled() => {
                    return Err(LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: "OpenConnect endpoint start cancelled".into(),
                    });
                }
                connection = self.connect_authenticated(&authenticated) => connection,
            };
            let (channel, configuration) =
                connection.map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })?;
            let network = build_openconnect_network(
                channel,
                &configuration,
                &self.handle,
                endpoint_queue_length(&self.options),
            )
            .map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })?;
            publish_openconnect_network(
                network.clone(),
                configuration,
                &self.handle,
                &self.network,
            )
            .map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })?;
            self.supervisor_task =
                Some(tokio::spawn(run_openconnect_supervisor(
                    self.options.clone(),
                    self.transport_dialer.clone(),
                    self.handle.clone(),
                    self.cancellation.clone(),
                    OpenConnectSupervisorShared {
                        network_slot: self.network.clone(),
                        globalprotect_session: self
                            .globalprotect_session
                            .clone(),
                        f5_session: self.f5_session.clone(),
                        pulse_session: self.pulse_session.clone(),
                        network_connect_session: self
                            .network_connect_session
                            .clone(),
                        fortinet_reconnect_state: self
                            .fortinet_reconnect_state
                            .clone(),
                        f5_reconnect_state: self.f5_reconnect_state.clone(),
                    },
                    authenticated,
                    network,
                )));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            self.handle.challenge_manager.close();
            if let Some(mut task) = self.supervisor_task.take()
                && tokio::time::timeout(Duration::from_secs(5), &mut task)
                    .await
                    .is_err()
            {
                task.abort();
                let _ = task.await;
            }
            self.handle.dialer.deactivate().map_err(|error| {
                LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                }
            })?;
            let network = lock(&self.network)?.take();
            if let Some(network) = network {
                network.close().await;
            }
            let globalprotect_session =
                write_rw(&self.globalprotect_session)?.take();
            let logout_result = if let Some(session) = globalprotect_session {
                logout_globalprotect_endpoint(
                    &self.options,
                    self.transport_dialer.clone(),
                    session,
                )
                .await
            } else {
                Ok(())
            };
            let f5_session = write_rw(&self.f5_session)?.take();
            let f5_logout_result = if let Some(session) = f5_session {
                logout_f5_endpoint(
                    &self.options,
                    self.transport_dialer.clone(),
                    session,
                )
                .await
            } else {
                Ok(())
            };
            let pulse_session = write_rw(&self.pulse_session)?.take();
            let pulse_logout_result = if let Some(session) = pulse_session {
                logout_pulse_endpoint(
                    &self.options,
                    self.transport_dialer.clone(),
                    session,
                )
                .await
            } else {
                Ok(())
            };
            let network_connect_session =
                write_rw(&self.network_connect_session)?.take();
            let network_connect_logout_result =
                if let Some(session) = network_connect_session {
                    logout_network_connect_endpoint(
                        &self.options,
                        self.transport_dialer.clone(),
                        session,
                    )
                    .await
                } else {
                    Ok(())
                };
            write_rw(&self.handle.tunnel_configuration)?.take();
            *write_rw(&self.handle.dtls_active)? = false;
            logout_result
                .and(f5_logout_result)
                .and(pulse_logout_result)
                .and(network_connect_logout_result)
                .map_err(|message| LifecycleError::Close {
                    component: self.name.clone(),
                    message,
                })
        })
    }
}

struct OpenConnectNetwork {
    net: Arc<Net>,
    packet_output: mpsc::Sender<Vec<u8>>,
    addresses: Vec<ipnet::IpNet>,
    mtu: Arc<AtomicU32>,
    dtls_active: bool,
    initial_dtls_error: Option<String>,
    cancellation: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
    failure: Arc<Mutex<Option<OpenConnectTransportError>>>,
    failed: Arc<Notify>,
    replacement: mpsc::Sender<OpenConnectReplacement>,
    _flow_router: Arc<UserspaceEndpointRouter>,
}

struct OpenConnectReplacement {
    channel: OpenConnectDataChannel,
    installed: oneshot::Sender<()>,
}

impl OpenConnectNetwork {
    #[allow(clippy::too_many_arguments)]
    fn start(
        channel: OpenConnectDataChannel,
        configuration: &TunnelConfiguration,
        tunnel_configuration: Arc<RwLock<Option<TunnelConfiguration>>>,
        last_error: Arc<RwLock<Option<String>>>,
        dtls_active: Arc<RwLock<bool>>,
        last_dtls_error: Arc<RwLock<Option<String>>>,
        dialer: Arc<OpenConnectEndpointDialer>,
        queue_length: usize,
        flow: EndpointFlowContext,
    ) -> io::Result<Arc<Self>> {
        let initial_dtls_active = channel.dtls_active();
        let initial_dtls_error = channel.last_dtls_error().map(str::to_owned);
        let addresses = configuration
            .addresses
            .iter()
            .map(|prefix| prefix.to_string().parse())
            .collect::<Result<Vec<IpCidr>, _>>()
            .map_err(|()| invalid("invalid OpenConnect stack address"))?;
        if addresses.is_empty() {
            return Err(invalid(
                "OpenConnect server assigned no tunnel address",
            ));
        }
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit =
            configuration.mtu.max(576) as usize;
        capabilities.medium = Medium::Ip;
        let (device, ingress, egress, mut output, icmp_errors) =
            ChannelDevice::new_with_capacity(capabilities, queue_length);
        let (packet_output, mut raw_output) = mpsc::channel(queue_length);
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
        let flow_router = UserspaceEndpointRouter::new(
            &net,
            egress,
            flow.tag,
            configuration.addresses.clone(),
            true,
            Vec::new(),
            flow.router,
            flow.outbounds,
            flow.udp_timeout,
            flow.udp_mapping,
            flow.udp_filtering,
            flow.udp_nat_max,
            configuration.mtu.max(576) as usize,
        );
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let failure = Arc::new(Mutex::new(None));
        let task_failure = failure.clone();
        let failed = Arc::new(Notify::new());
        let task_failed = failed.clone();
        let (replacement, mut replacements) =
            mpsc::channel::<OpenConnectReplacement>(1);
        let packet_port = dialer.packet_port.clone();
        let incoming_flow_router = flow_router.clone();
        let live_mtu = Arc::new(AtomicU32::new(configuration.mtu));
        let task_live_mtu = live_mtu.clone();
        let task_net = net.clone();
        let task = tokio::spawn(async move {
            let mut channel = Some(channel);
            loop {
                let Some(active_channel) = channel.as_mut() else {
                    let replacement = tokio::select! {
                        _ = task_cancellation.cancelled() => break,
                        replacement = replacements.recv() => replacement,
                    };
                    let Some(replacement) = replacement else {
                        break;
                    };
                    if let Ok(mut active) = dtls_active.write() {
                        *active = replacement.channel.dtls_active();
                    }
                    if let Ok(mut message) = last_dtls_error.write() {
                        *message = replacement
                            .channel
                            .last_dtls_error()
                            .map(str::to_owned);
                    }
                    channel = Some(replacement.channel);
                    let _ = replacement.installed.send(());
                    continue;
                };
                enum Event {
                    Outgoing(Option<Vec<u8>>),
                    Incoming(
                        Result<
                            OpenConnectDataChannelEvent,
                            OpenConnectTransportError,
                        >,
                    ),
                }
                let event = tokio::select! {
                    _ = task_cancellation.cancelled() => break,
                    packet = output.recv() => Event::Outgoing(packet),
                    packet = raw_output.recv() => Event::Outgoing(packet),
                    packet = active_channel.receive_event() => Event::Incoming(packet),
                };
                let result: Result<(), OpenConnectTransportError> = match event
                {
                    Event::Outgoing(Some(packet)) => {
                        let result = active_channel
                            .send_data(&packet)
                            .await
                            .map_err(OpenConnectTransportError::Retryable);
                        publish_openconnect_transport_status(
                            active_channel,
                            &dtls_active,
                            &last_dtls_error,
                        );
                        result
                    }
                    Event::Outgoing(None) => {
                        Err(OpenConnectTransportError::Retryable(
                            "OpenConnect userspace packet output closed".into(),
                        ))
                    }
                    Event::Incoming(Ok(
                        OpenConnectDataChannelEvent::TransportStateChanged,
                    )) => {
                        publish_openconnect_transport_status(
                            active_channel,
                            &dtls_active,
                            &last_dtls_error,
                        );
                        match apply_anyconnect_mtu_update(
                            active_channel,
                            &task_net,
                            &incoming_flow_router,
                            &dialer,
                            &tunnel_configuration,
                            &task_live_mtu,
                        ) {
                            Ok(()) => continue,
                            Err(error) => {
                                Err(OpenConnectTransportError::Retryable(
                                    error.to_string(),
                                ))
                            }
                        }
                    }
                    Event::Incoming(Ok(OpenConnectDataChannelEvent::Data(
                        packet,
                    ))) => {
                        publish_openconnect_transport_status(
                            active_channel,
                            &dtls_active,
                            &last_dtls_error,
                        );
                        if packet_port.return_packet(&packet) {
                            continue;
                        }
                        match incoming_flow_router.prepare_packet(&packet).await
                        {
                            Err(error) => Err(
                                OpenConnectTransportError::Retryable(format!(
                                    "OpenConnect inbound flow routing failed: {error}"
                                )),
                            ),
                            Ok(false) => continue,
                            Ok(true)
                                if ingress.send(Ok(packet)).await.is_err() =>
                            {
                                Err(OpenConnectTransportError::Retryable(
                                    "OpenConnect userspace packet input closed"
                                        .into(),
                                ))
                            }
                            Ok(true) => continue,
                        }
                    }
                    Event::Incoming(Err(error)) => Err(error),
                };
                if let Err(error) = result {
                    if let Ok(mut message) = last_error.write() {
                        *message = Some(error.message().to_owned());
                    }
                    if let Some(mut failed_channel) = channel.take() {
                        let _ = failed_channel.close().await;
                    }
                    if let Ok(mut active) = dtls_active.write() {
                        *active = false;
                    }
                    let _ = dialer.deactivate();
                    if let Ok(mut failure) = task_failure.lock() {
                        *failure = Some(error);
                    }
                    task_failed.notify_waiters();
                }
            }
            if let Some(mut active_channel) = channel {
                let _ = active_channel.close().await;
            }
            if let Ok(mut active) = dtls_active.write() {
                *active = false;
            }
            let _ = dialer.deactivate();
        });
        Ok(Arc::new(Self {
            net,
            packet_output,
            addresses: configuration.addresses.clone(),
            mtu: live_mtu,
            dtls_active: initial_dtls_active,
            initial_dtls_error,
            cancellation,
            task: Mutex::new(Some(task)),
            failure,
            failed,
            replacement,
            _flow_router: flow_router,
        }))
    }

    fn is_compatible(&self, configuration: &TunnelConfiguration) -> bool {
        self.addresses == configuration.addresses
            && self.mtu.load(Ordering::Acquire) == configuration.mtu
    }

    async fn replace_channel(
        &self,
        channel: OpenConnectDataChannel,
    ) -> io::Result<()> {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = None;
        }
        let (installed, waiting) = oneshot::channel();
        self.replacement
            .send(OpenConnectReplacement { channel, installed })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "OpenConnect transport supervisor is closed",
                )
            })?;
        waiting.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "OpenConnect replacement transport was not installed",
            )
        })
    }

    async fn wait_failure(&self) -> Option<OpenConnectTransportError> {
        loop {
            let notified = self.failed.notified();
            if let Ok(failure) = self.failure.lock()
                && let Some(message) = failure.clone()
            {
                return Some(message);
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => return None,
                _ = notified => {}
            }
        }
    }

    async fn close(&self) {
        self.cancellation.cancel();
        let task = self.task.lock().ok().and_then(|mut task| task.take());
        if let Some(mut task) = task
            && tokio::time::timeout(
                std::time::Duration::from_secs(5),
                &mut task,
            )
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

fn publish_openconnect_transport_status(
    channel: &OpenConnectDataChannel,
    dtls_active: &RwLock<bool>,
    last_dtls_error: &RwLock<Option<String>>,
) {
    if let Ok(mut active) = dtls_active.write() {
        *active = channel.dtls_active();
    }
    if let Ok(mut message) = last_dtls_error.write() {
        *message = channel.last_dtls_error().map(str::to_owned);
    }
}

fn apply_anyconnect_mtu_update(
    channel: &OpenConnectDataChannel,
    net: &Net,
    flow_router: &UserspaceEndpointRouter,
    dialer: &OpenConnectEndpointDialer,
    tunnel_configuration: &RwLock<Option<TunnelConfiguration>>,
    live_mtu: &AtomicU32,
) -> io::Result<()> {
    let Some(configuration) = channel.anyconnect_configuration() else {
        return Ok(());
    };
    let current_mtu = live_mtu.load(Ordering::Acquire);
    if configuration.mtu >= current_mtu {
        return Ok(());
    }
    let configuration = configuration.clone();
    let negotiated_mtu = configuration.mtu;
    let effective_mtu = configuration.mtu.max(576) as usize;
    dialer.update_configuration(configuration.clone())?;
    *tunnel_configuration.write().map_err(|_| {
        io::Error::other("OpenConnect configuration lock poisoned")
    })? = Some(configuration);
    net.set_mtu(effective_mtu);
    flow_router.set_effective_mtu(effective_mtu);
    live_mtu.store(current_mtu.min(negotiated_mtu), Ordering::Release);
    Ok(())
}

impl Drop for OpenConnectNetwork {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut task) = self.task.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

impl OpenConnectEndpointDialer {
    fn activate(
        &self,
        net: Arc<Net>,
        packet_output: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<()> {
        let configuration = self
            .configuration
            .read()
            .map_err(|_| {
                io::Error::other("OpenConnect configuration lock poisoned")
            })?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "OpenConnect configuration is unavailable",
                )
            })?;
        self.packet_port.activate(packet_output, &configuration)?;
        *self.net.write().map_err(|_| {
            io::Error::other("OpenConnect network lock poisoned")
        })? = Some(net);
        Ok(())
    }

    fn deactivate(&self) -> io::Result<()> {
        self.packet_port.deactivate()?;
        self.net
            .write()
            .map_err(|_| io::Error::other("OpenConnect network lock poisoned"))?
            .take();
        Ok(())
    }

    fn update_configuration(
        &self,
        configuration: TunnelConfiguration,
    ) -> io::Result<()> {
        self.packet_port.update_mtu(configuration.mtu as usize)?;
        *self.configuration.write().map_err(|_| {
            io::Error::other("OpenConnect configuration lock poisoned")
        })? = Some(configuration);
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.net.read().is_ok_and(|net| net.is_some())
    }

    fn net(&self) -> io::Result<Arc<Net>> {
        self.net
            .read()
            .map_err(|_| io::Error::other("OpenConnect network lock poisoned"))?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "OpenConnect endpoint is not started",
                )
            })
    }

    async fn resolve(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<Vec<SocketAddr>> {
        match (destination, &self.resolver) {
            (SocksAddr::Domain { host, port }, Some(resolver)) => Ok(resolver
                .lookup(host, self.strategy)
                .await?
                .into_iter()
                .map(|address| SocketAddr::new(address, *port))
                .collect()),
            _ => destination.resolve().await,
        }
    }
}

impl Dialer for OpenConnectEndpointDialer {
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
                        return Ok(Box::new(OpenConnectPacketConnection {
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
                        "no compatible OpenConnect ICMP destination",
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
        if !self.is_active() {
            return false;
        }
        let Ok(configuration) = self.configuration.read() else {
            return false;
        };
        configuration.as_ref().is_some_and(|configuration| {
            openconnect_preferred_domain(configuration, domain)
        })
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        if !self.is_active() {
            return false;
        }
        let Ok(configuration) = self.configuration.read() else {
            return false;
        };
        configuration.as_ref().is_some_and(|configuration| {
            openconnect_preferred_address(configuration, address)
        })
    }
}

impl OpenConnectConfigurationProvider for OpenConnectEndpointDialer {
    fn tunnel_configuration(&self) -> Option<TunnelConfiguration> {
        if !self.is_active() {
            return None;
        }
        self.configuration.read().ok()?.clone()
    }
}

struct OpenConnectPacketConnection {
    socket: Arc<SmoltcpUdpSocket>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
}

impl PacketConnection for OpenConnectPacketConnection {
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

fn endpoint_authenticator_options(
    options: &OpenConnectEndpointOptions,
) -> io::Result<AnyConnectAuthenticatorOptions> {
    let mca_identity = load_openconnect_mca_identity(options)?;
    let mut host_scan =
        crate::protocol::openconnect::AnyConnectHostScanOptions::default();
    if let Some(csd) = options
        .csd
        .as_ref()
        .filter(|csd| !csd.wrapper_path.is_empty())
    {
        host_scan.wrapper_path = csd.wrapper_path.clone().into();
        host_scan.wrapper_client_certificate_der =
            load_openconnect_client_certificate_der(options)?;
    }
    Ok(AnyConnectAuthenticatorOptions {
        identity: AnyConnectAuthClientIdentity {
            version: options.version.clone(),
            reported_os: options.reported_os.clone(),
            mobile: options.mobile.as_ref().map(|mobile| {
                AnyConnectAuthMobileIdentity {
                    platform_version: mobile.platform_version.clone(),
                    device_type: mobile.device_type.clone(),
                    device_unique_id: mobile.device_unique_id.clone(),
                }
            }),
            external_auth_disabled: options.external_auth_disabled,
            multiple_certificate_authentication: mca_identity.is_some(),
        },
        prefill: AnyConnectAuthPrefillOptions {
            credentials: AnyConnectCredentialCache {
                username: nonempty(&options.username),
                password: nonempty(&options.password),
                auth_group: nonempty(&options.auth_group),
            },
            form_entries: options
                .form_entries
                .iter()
                .map(|entry| AnyConnectAuthFormEntry {
                    form_id: entry.form_id.clone(),
                    submission_key: entry.submission_key.clone(),
                    name: entry.name.clone(),
                    value: entry.value.clone(),
                    promote: entry.promote,
                })
                .collect(),
            token_type: options
                .token
                .as_ref()
                .and_then(|token| nonempty(&token.mode)),
            generated_token: None,
        },
        xml_post_disabled: options.xml_post_disabled,
        external_auth_disabled: options.external_auth_disabled,
        password_authentication_disabled: options
            .password_authentication_disabled,
        client_certificate_configured: !options
            .tls
            .client_certificate
            .0
            .is_empty()
            || !options.tls.client_certificate_path.is_empty(),
        direct_cookie: nonempty(&options.cookie),
        mca_identity,
        host_scan,
    })
}

fn load_openconnect_client_certificate_der(
    options: &OpenConnectEndpointOptions,
) -> io::Result<Option<Vec<u8>>> {
    if options.tls.client_certificate.as_slice().is_empty()
        && options.tls.client_certificate_path.is_empty()
    {
        return Ok(None);
    }
    let content = load_openconnect_material(
        options.tls.client_certificate.as_slice(),
        &options.tls.client_certificate_path,
        "client certificate",
    )?;
    let certificate = if content.starts_with(b"-----BEGIN") {
        X509::stack_from_pem(&content)
            .map_err(|error| {
                invalid(format!(
                    "parse OpenConnect client certificate: {error}"
                ))
            })?
            .into_iter()
            .next()
            .ok_or_else(|| {
                invalid("OpenConnect client certificate chain is empty")
            })?
    } else {
        X509::from_der(&content).map_err(|error| {
            invalid(format!("parse OpenConnect client certificate: {error}"))
        })?
    };
    certificate.to_der().map(Some).map_err(|error| {
        invalid(format!("encode OpenConnect client certificate: {error}"))
    })
}

fn load_openconnect_oath_token_factory(
    options: &OpenConnectEndpointOptions,
) -> io::Result<Option<OpenConnectOathTokenFactory>> {
    let Some(token) = options.token.as_ref() else {
        return Ok(None);
    };
    if matches!(token.mode.as_str(), "oidc" | "stoken") {
        load_openconnect_token_secret(token)?;
        return Ok(None);
    }
    if !matches!(token.mode.as_str(), "totp" | "hotp") {
        return Err(unsupported(format!(
            "OpenConnect software-token mode {:?} is not ported yet",
            token.mode
        )));
    }
    let secret = load_openconnect_token_secret(token)?;
    OpenConnectOathTokenFactory::new(&token.mode, &secret, token.counter)
        .map(Some)
        .map_err(|error| invalid(error.to_string()))
}

fn load_openconnect_securid_token_factory(
    options: &OpenConnectEndpointOptions,
) -> io::Result<Option<OpenConnectSecurIdTokenFactory>> {
    let Some(token) = options
        .token
        .as_ref()
        .filter(|token| token.mode == "stoken")
    else {
        return Ok(None);
    };
    let secret = load_openconnect_token_secret(token)?;
    OpenConnectSecurIdTokenFactory::new(
        &secret,
        &token.pin,
        &token.password,
        &token.device_id,
    )
    .map(Some)
    .map_err(|error| invalid(error.to_string()))
}

fn load_openconnect_token_secret(
    token: &crate::option::OpenConnectTokenOptions,
) -> io::Result<String> {
    if !token.secret.is_empty() && !token.secret_path.is_empty() {
        return Err(invalid(
            "OpenConnect token contains both secret and secret_path",
        ));
    }
    let secret = if token.secret_path.is_empty() {
        token.secret.clone()
    } else {
        fs::read_to_string(&token.secret_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "read OpenConnect software-token secret {}: {error}",
                    token.secret_path
                ),
            )
        })?
    };
    if secret.trim().is_empty() {
        return Err(invalid("OpenConnect software token requires a secret"));
    }
    Ok(secret.trim().to_owned())
}

fn load_openconnect_mca_identity(
    options: &OpenConnectEndpointOptions,
) -> io::Result<Option<AnyConnectMcaIdentity>> {
    let certificate_configured =
        !options.tls.mca_certificate.as_slice().is_empty()
            || !options.tls.mca_certificate_path.is_empty();
    let key_configured = !options.tls.mca_key.as_slice().is_empty()
        || !options.tls.mca_key_path.is_empty();
    if certificate_configured != key_configured {
        return Err(invalid(
            "OpenConnect MCA certificate and private key must be configured together",
        ));
    }
    if !certificate_configured {
        return Ok(None);
    }
    let certificate_bytes = load_openconnect_material(
        options.tls.mca_certificate.as_slice(),
        &options.tls.mca_certificate_path,
        "MCA certificate",
    )?;
    let certificates = if certificate_bytes.starts_with(b"-----BEGIN") {
        X509::stack_from_pem(&certificate_bytes).map_err(|error| {
            invalid(format!("parse OpenConnect MCA certificate: {error}"))
        })?
    } else {
        vec![X509::from_der(&certificate_bytes).map_err(|error| {
            invalid(format!("parse OpenConnect MCA certificate: {error}"))
        })?]
    };
    if certificates.is_empty() {
        return Err(invalid("OpenConnect MCA certificate chain is empty"));
    }
    let certificates_der = certificates
        .iter()
        .map(|certificate| {
            certificate.to_der().map_err(|error| {
                invalid(format!("encode OpenConnect MCA certificate: {error}"))
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let key_bytes = load_openconnect_material(
        options.tls.mca_key.as_slice(),
        &options.tls.mca_key_path,
        "MCA private key",
    )?;
    let password =
        nonempty(&options.tls.mca_key_password).map(String::into_bytes);
    let private_key = if key_bytes.starts_with(b"-----BEGIN") {
        AnyConnectMcaPrivateKey::Pem(key_bytes)
    } else {
        AnyConnectMcaPrivateKey::Der(key_bytes)
    };
    let parsed_key = match (&private_key, password.as_deref()) {
        (AnyConnectMcaPrivateKey::Pem(key), Some(password)) => {
            PKey::private_key_from_pem_passphrase(key, password)
        }
        (AnyConnectMcaPrivateKey::Pem(key), None) => {
            PKey::private_key_from_pem(key)
        }
        (AnyConnectMcaPrivateKey::Der(key), Some(password)) => {
            PKey::private_key_from_pkcs8_passphrase(key, password)
        }
        (AnyConnectMcaPrivateKey::Der(key), None) => {
            PKey::private_key_from_der(key)
                .or_else(|_| PKey::private_key_from_pkcs8(key))
        }
    }
    .map_err(|error| {
        invalid(format!("parse OpenConnect MCA private key: {error}"))
    })?;
    let leaf_key = certificates[0].public_key().map_err(|error| {
        invalid(format!("parse OpenConnect MCA public key: {error}"))
    })?;
    if !parsed_key.public_eq(&leaf_key) {
        return Err(invalid(
            "OpenConnect MCA private key does not match leaf certificate",
        ));
    }
    Ok(Some(AnyConnectMcaIdentity {
        certificates_der,
        private_key,
        private_key_password: password,
    }))
}

fn normalize_openconnect_tls_client_key(
    options: &mut OpenConnectEndpointOptions,
) -> io::Result<()> {
    if options.tls.client_key_password.is_empty() {
        return Ok(());
    }
    let certificate_configured =
        !options.tls.client_certificate.as_slice().is_empty()
            || !options.tls.client_certificate_path.is_empty();
    let key_configured = !options.tls.client_key.as_slice().is_empty()
        || !options.tls.client_key_path.is_empty();
    if !certificate_configured || !key_configured {
        return Err(invalid(
            "encrypted OpenConnect TLS client key requires a client certificate and key",
        ));
    }
    let key_bytes = load_openconnect_material(
        options.tls.client_key.as_slice(),
        &options.tls.client_key_path,
        "TLS client private key",
    )?;
    let password = options.tls.client_key_password.as_bytes();
    let private_key = if key_bytes.starts_with(b"-----BEGIN") {
        PKey::private_key_from_pem_passphrase(&key_bytes, password)
    } else {
        PKey::private_key_from_pkcs8_passphrase(&key_bytes, password)
    }
    .map_err(|error| {
        invalid(format!(
            "decrypt OpenConnect TLS client private key: {error}"
        ))
    })?;
    let certificate_bytes = load_openconnect_material(
        options.tls.client_certificate.as_slice(),
        &options.tls.client_certificate_path,
        "TLS client certificate",
    )?;
    let leaf = if certificate_bytes.starts_with(b"-----BEGIN") {
        X509::stack_from_pem(&certificate_bytes)
            .map_err(|error| {
                invalid(format!(
                    "parse OpenConnect TLS client certificate: {error}"
                ))
            })?
            .into_iter()
            .next()
            .ok_or_else(|| {
                invalid("OpenConnect TLS client certificate chain is empty")
            })?
    } else {
        X509::from_der(&certificate_bytes).map_err(|error| {
            invalid(format!(
                "parse OpenConnect TLS client certificate: {error}"
            ))
        })?
    };
    let public_key = leaf.public_key().map_err(|error| {
        invalid(format!(
            "parse OpenConnect TLS client certificate public key: {error}"
        ))
    })?;
    if !private_key.public_eq(&public_key) {
        return Err(invalid(
            "OpenConnect TLS client private key does not match leaf certificate",
        ));
    }
    let unencrypted_pem =
        private_key.private_key_to_pem_pkcs8().map_err(|error| {
            invalid(format!(
                "encode decrypted OpenConnect TLS client private key: {error}"
            ))
        })?;
    options.tls.client_key = Listable(vec![
        String::from_utf8(unencrypted_pem).map_err(|error| {
            invalid(format!(
                "encode decrypted OpenConnect TLS client private key as PEM: {error}"
            ))
        })?,
    ]);
    options.tls.client_key_path.clear();
    options.tls.client_key_password.clear();
    Ok(())
}

fn load_openconnect_material(
    inline: &[String],
    path: &str,
    name: &str,
) -> io::Result<Vec<u8>> {
    if !path.is_empty() {
        return fs::read(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("read OpenConnect {name} at {path}: {error}"),
            )
        });
    }
    Ok(inline.join("\n").into_bytes())
}

fn endpoint_cstp_options(
    options: &OpenConnectEndpointOptions,
    tls: OutboundTlsOptions,
) -> AnyConnectCstpConnectorOptions {
    let compression_mode = if options.compression_mode == "all" {
        CstpCompressionMode::All
    } else {
        CstpCompressionMode::Stateless
    };
    AnyConnectCstpConnectorOptions {
        tls,
        connect: CstpConnectOptions {
            user_agent: endpoint_user_agent(options),
            local_hostname: options.local_hostname.clone(),
            mobile: options.mobile.as_ref().map(|mobile| CstpMobileIdentity {
                client_version: options.version.clone(),
                platform: options.reported_os.clone(),
                platform_version: mobile.platform_version.clone(),
                device_type: mobile.device_type.clone(),
                device_unique_id: mobile.device_unique_id.clone(),
            }),
            compression_disabled: options.compression_disabled,
            compression_mode,
            base_mtu: options.base_mtu,
            tunnel_mtu: options.mtu,
            ipv6_disabled: options.ipv6_disabled,
            no_udp: options.no_udp,
            allow_insecure_crypto: options.allow_insecure_crypto,
            ..Default::default()
        },
        response: CstpResponseOptions {
            ipv6_disabled: options.ipv6_disabled,
            no_udp: options.no_udp,
            compression_disabled: options.compression_disabled,
            compression_mode,
            dpd_override: options
                .dpd_interval
                .as_std()
                .filter(|duration| !duration.is_zero()),
            authenticated_address: None,
        },
        queue_length: endpoint_queue_length(options),
        ..Default::default()
    }
}

fn endpoint_queue_length(options: &OpenConnectEndpointOptions) -> usize {
    if options.queue_length == 0 {
        32
    } else {
        options.queue_length as usize
    }
}

fn endpoint_tls_options(
    options: &OpenConnectEndpointOptions,
) -> OutboundTlsOptions {
    let fingerprints =
        openconnect_peer_fingerprints(options.tls.peer_fingerprint.as_slice())
            .unwrap_or_default();
    let pinned = !fingerprints.is_empty();
    OutboundTlsOptions {
        enabled: true,
        server_name: options.tls.server_name.clone(),
        insecure: options.tls.insecure,
        certificate: if pinned {
            Listable::default()
        } else {
            options.tls.certificate_authority.clone()
        },
        certificate_path: if pinned {
            String::new()
        } else {
            options.tls.certificate_authority_path.clone()
        },
        server_certificate_fingerprints: fingerprints,
        cipher_suites: if options.pfs {
            Listable(vec![
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
            ])
        } else {
            Listable::default()
        },
        system_trust_disabled: options.tls.system_trust_disabled,
        certificate_store: options.certificate_store.clone(),
        ntp_clock: options.ntp_clock.clone(),
        client_certificate: options.tls.client_certificate.clone(),
        client_certificate_path: options.tls.client_certificate_path.clone(),
        client_key: options.tls.client_key.clone(),
        client_key_path: options.tls.client_key_path.clone(),
        ..Default::default()
    }
}

fn endpoint_auth_http_transport(
    options: &OpenConnectEndpointOptions,
    dialer: Arc<dyn Dialer>,
) -> DialerAnyConnectAuthHttpTransport {
    DialerAnyConnectAuthHttpTransport::new(
        dialer,
        endpoint_tls_options(options),
    )
    .with_keep_alive_disabled(options.http_keep_alive_disabled)
}

fn validate_runtime_options(
    options: &OpenConnectEndpointOptions,
) -> io::Result<()> {
    load_openconnect_oath_token_factory(options)?;
    load_openconnect_securid_token_factory(options)?;
    openconnect_peer_fingerprints(options.tls.peer_fingerprint.as_slice())?;
    load_openconnect_mca_identity(options)?;
    if let Some(tncc) = &options.tncc
        && tncc.wrapper_path.is_empty()
    {
        load_network_connect_tncc_certificates(tncc).map_err(invalid)?;
    }
    if options
        .csd
        .as_ref()
        .is_some_and(|csd| !csd.wrapper_path.is_empty())
    {
        load_openconnect_client_certificate_der(options)?;
    }
    Ok(())
}

fn openconnect_peer_fingerprints(
    fingerprints: &[String],
) -> io::Result<Vec<ServerCertificateFingerprint>> {
    fingerprints
        .iter()
        .map(|fingerprint| {
            let (algorithm, encoded, maximum_length, case_sensitive) =
                if let Some(encoded) = fingerprint.strip_prefix("sha1:") {
                    (
                        ServerCertificateFingerprintAlgorithm::SpkiSha1Hex,
                        encoded,
                        40,
                        false,
                    )
                } else if let Some(encoded) =
                    fingerprint.strip_prefix("sha256:")
                {
                    (
                        ServerCertificateFingerprintAlgorithm::SpkiSha256Hex,
                        encoded,
                        64,
                        false,
                    )
                } else if let Some(encoded) =
                    fingerprint.strip_prefix("pin-sha256:")
                {
                    (
                        ServerCertificateFingerprintAlgorithm::SpkiSha256Base64,
                        encoded,
                        44,
                        true,
                    )
                } else if fingerprint.contains(':') {
                    return Err(unsupported(format!(
                        "unsupported OpenConnect peer fingerprint {fingerprint:?}"
                    )));
                } else {
                    (
                        ServerCertificateFingerprintAlgorithm::CertificateSha1Hex,
                        fingerprint.as_str(),
                        40,
                        false,
                    )
                };
            if encoded.len() < 4 || encoded.len() > maximum_length {
                return Err(invalid(format!(
                    "invalid OpenConnect peer fingerprint {fingerprint:?}"
                )));
            }
            if case_sensitive {
                let valid = encoded.bytes().enumerate().all(|(index, value)| {
                    value.is_ascii_alphanumeric()
                        || value == b'+'
                        || value == b'/'
                        || (value == b'=' && index >= encoded.len() - 2)
                });
                if !valid {
                    return Err(invalid(format!(
                        "invalid OpenConnect peer fingerprint {fingerprint:?}"
                    )));
                }
                if encoded.len() == maximum_length
                    && STANDARD
                        .decode(encoded)
                        .ok()
                        .filter(|decoded| decoded.len() == 32)
                        .is_none()
                {
                    return Err(invalid(format!(
                        "invalid OpenConnect peer fingerprint {fingerprint:?}"
                    )));
                }
            } else if !encoded.bytes().all(|value| value.is_ascii_hexdigit()) {
                return Err(invalid(format!(
                    "invalid OpenConnect peer fingerprint {fingerprint:?}"
                )));
            };
            Ok(ServerCertificateFingerprint {
                algorithm,
                encoded_prefix: if case_sensitive {
                    encoded.to_owned()
                } else {
                    encoded.to_ascii_lowercase()
                },
            })
        })
        .collect()
}

fn endpoint_user_agent(options: &OpenConnectEndpointOptions) -> String {
    if options.user_agent.is_empty() {
        "Open AnyConnect VPN Agent".into()
    } else {
        options.user_agent.clone()
    }
}

fn globalprotect_user_agent(options: &OpenConnectEndpointOptions) -> String {
    if options.user_agent.is_empty() {
        crate::protocol::openconnect::GLOBALPROTECT_USER_AGENT.into()
    } else {
        options.user_agent.clone()
    }
}

fn fortinet_user_agent(options: &OpenConnectEndpointOptions) -> String {
    if options.user_agent.is_empty() {
        FORTINET_PROTOCOL_USER_AGENT.into()
    } else {
        options.user_agent.clone()
    }
}

fn f5_user_agent(options: &OpenConnectEndpointOptions) -> String {
    if options.user_agent.is_empty() {
        F5_DEFAULT_USER_AGENT.into()
    } else {
        options.user_agent.clone()
    }
}

fn network_connect_user_agent(options: &OpenConnectEndpointOptions) -> String {
    if options.user_agent.is_empty() {
        NETWORK_CONNECT_DEFAULT_USER_AGENT.into()
    } else {
        options.user_agent.clone()
    }
}

fn normalize_server_url(server: &str) -> String {
    if server.contains("://") {
        server.to_owned()
    } else {
        format!("https://{server}")
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

fn lock<T>(
    mutex: &Mutex<T>,
) -> Result<std::sync::MutexGuard<'_, T>, LifecycleError> {
    mutex.lock().map_err(|_| LifecycleError::Close {
        component: "OpenConnect endpoint".into(),
        message: "state lock poisoned".into(),
    })
}

fn write_rw<T>(
    lock: &RwLock<T>,
) -> Result<std::sync::RwLockWriteGuard<'_, T>, LifecycleError> {
    lock.write().map_err(|_| LifecycleError::Close {
        component: "OpenConnect endpoint".into(),
        message: "state lock poisoned".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UdpPortProbeDialer {
        requested: Arc<Mutex<Vec<u16>>>,
    }

    impl Dialer for UdpPortProbeDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TCP is not used by the UDP bind-port probe",
                ))
            })
        }

        fn listen_udp_on<'a>(
            &'a self,
            _destination: &'a SocksAddr,
            local_port: u16,
        ) -> PacketFuture<'a, PacketStream> {
            self.requested.lock().unwrap().push(local_port);
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "UDP bind-port probe completed",
                ))
            })
        }
    }

    struct PulseTcpDialer;

    impl Dialer for PulseTcpDialer {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                let address = match destination {
                    SocksAddr::Ip(address) => *address,
                    SocksAddr::Domain { host, port } => {
                        tokio::net::lookup_host((host.as_str(), *port))
                            .await?
                            .next()
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "test destination did not resolve",
                                )
                            })?
                    }
                };
                Ok(Box::new(tokio::net::TcpStream::connect(address).await?)
                    as Stream)
            })
        }
    }

    #[tokio::test]
    async fn dtls_local_port_is_applied_to_every_physical_udp_open() {
        let requested = Arc::new(Mutex::new(Vec::new()));
        let dialer = UdpBindPortDialer {
            inner: Arc::new(UdpPortProbeDialer {
                requested: requested.clone(),
            }),
            local_port: 45_000,
        };
        let destination = SocksAddr::new("vpn.example", 443);
        let error = match dialer.listen_udp(&destination).await {
            Ok(_) => panic!("UDP bind-port probe unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        let error = match dialer.listen_udp_on(&destination, 12_345).await {
            Ok(_) => panic!("UDP bind-port override unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(*requested.lock().unwrap(), [45_000, 45_000]);
    }

    fn pulse_request(identifier: u8, content: &[u8]) -> Vec<u8> {
        let packet = build_pulse_eap(
            crate::protocol::openconnect::PULSE_EAP_REQUEST,
            identifier,
            crate::protocol::openconnect::PULSE_EAP_TYPE_EXPANDED,
            1,
            content,
        )
        .unwrap();
        build_pulse_authentication_payload(&packet)
    }

    fn pulse_main_configuration_frame()
    -> crate::protocol::openconnect::PulseIftFrame {
        fn attribute(kind: u16, value: &[u8], destination: &mut Vec<u8>) {
            destination.extend_from_slice(&kind.to_be_bytes());
            destination.extend_from_slice(&(value.len() as u16).to_be_bytes());
            destination.extend_from_slice(value);
        }
        let mut attributes = Vec::new();
        attribute(1, &[10, 23, 0, 2], &mut attributes);
        attribute(2, &[255, 255, 255, 0], &mut attributes);
        attribute(3, &[10, 23, 0, 53], &mut attributes);
        attribute(0x4005, &1400_u32.to_be_bytes(), &mut attributes);
        let mut block = vec![0_u8; 8];
        block[4..8].copy_from_slice(&0x03000000_u32.to_be_bytes());
        block.extend_from_slice(&attributes);
        let block_length = block.len() as u32;
        block[..4].copy_from_slice(&block_length.to_be_bytes());
        let mut section = vec![0x2e, 0, 0, 8, 0, 0, 0, 0];
        section.extend_from_slice(&block);
        let mut payload = vec![0_u8; 28];
        payload[16..20].copy_from_slice(&0x2c20f000_u32.to_be_bytes());
        payload.extend_from_slice(&section);
        let length = payload.len() as u32;
        payload[24..28].copy_from_slice(&length.to_be_bytes());
        crate::protocol::openconnect::PulseIftFrame {
            vendor: PULSE_VENDOR_JUNIPER,
            frame_type: 1,
            sequence: 0,
            payload,
        }
    }

    fn route(prefix: &str) -> crate::protocol::openconnect::TunnelRoute {
        crate::protocol::openconnect::TunnelRoute {
            prefix: prefix.parse().unwrap(),
            gateway: None,
            metric: 0,
        }
    }

    fn fortinet_reconnect_configuration()
    -> crate::protocol::openconnect::FortinetTunnelConfiguration {
        parse_fortinet_xml_configuration(
            br#"<sslvpn-tunnel>
              <auth-ses tun-connect-without-reauth="1" check-src-ip="1" tun-user-ses-timeout="90"/>
              <ipv4><assigned-addr ipv4="10.23.0.2"/></ipv4>
              <ipv6><assigned-addr ipv6="2001:db8::2" prefix-len="64"/></ipv6>
            </sslvpn-tunnel>"#,
            std::time::SystemTime::now(),
        )
        .unwrap()
    }

    #[test]
    fn enforces_fortinet_reconnect_policy_and_cleanup_window() {
        let configuration = fortinet_reconnect_configuration();
        assert!(
            validate_fortinet_reconnect(
                &configuration,
                &FortinetReconnectState::default()
            )
            .is_ok()
        );

        let recent = FortinetReconnectState {
            connected_once: true,
            dropped_at: Some(
                std::time::Instant::now() - Duration::from_secs(1),
            ),
            ..Default::default()
        };
        assert!(validate_fortinet_reconnect(&configuration, &recent).is_ok());

        let expired = FortinetReconnectState {
            dropped_at: Some(
                std::time::Instant::now() - Duration::from_secs(91),
            ),
            ..recent.clone()
        };
        assert!(matches!(
            validate_fortinet_reconnect(&configuration, &expired),
            Err(EndpointConnectError::SessionRejected(401))
        ));

        let mut disabled = configuration.clone();
        disabled.reconnect_allowed = false;
        assert!(matches!(
            validate_fortinet_reconnect(&disabled, &recent),
            Err(EndpointConnectError::SessionRejected(401))
        ));

        let forced = FortinetReconnectState {
            force_reauthentication: true,
            ..Default::default()
        };
        assert!(matches!(
            validate_fortinet_reconnect(&configuration, &forced),
            Err(EndpointConnectError::SessionRejected(401))
        ));
    }

    #[test]
    fn rejects_expired_fortinet_authentication_before_reconnect() {
        let mut configuration = fortinet_reconnect_configuration();
        configuration.configuration.authentication_expiration =
            Some(std::time::SystemTime::UNIX_EPOCH);
        assert!(matches!(
            validate_fortinet_reconnect(
                &configuration,
                &FortinetReconnectState::default()
            ),
            Err(EndpointConnectError::SessionRejected(401))
        ));
    }

    #[test]
    fn stores_and_locks_fortinet_reconnect_addresses() {
        let mut configuration = fortinet_reconnect_configuration();
        configuration.configuration.addresses = vec![
            "10.23.0.2/32".parse().unwrap(),
            "2001:db8::2/64".parse().unwrap(),
        ];
        let state = Mutex::new(FortinetReconnectState {
            dropped_at: Some(std::time::Instant::now()),
            ..Default::default()
        });
        store_fortinet_reconnect_state(
            &state,
            &configuration.configuration,
            Some("192.0.2.10".parse().unwrap()),
        )
        .unwrap();
        let snapshot = state.lock().unwrap().clone();
        assert!(snapshot.connected_once);
        assert_eq!(snapshot.source_ip.unwrap().to_string(), "192.0.2.10");
        assert_eq!(snapshot.previous_ipv4.unwrap().to_string(), "10.23.0.2/32");
        assert_eq!(
            snapshot.previous_ipv6.unwrap().to_string(),
            "2001:db8::2/64"
        );
        assert!(snapshot.dropped_at.is_none());

        configuration.proposed_ipv4 = snapshot.previous_ipv4;
        configuration.proposed_ipv6 = snapshot.previous_ipv6;
        let options = fortinet_ppp_options(&configuration, 1350, true);
        assert!(options.lock_addresses);
        assert_eq!(options.ipv4_address, snapshot.previous_ipv4);
        assert_eq!(options.ipv6_address, snapshot.previous_ipv6);
    }

    #[test]
    fn stores_f5_reconnect_addresses_and_source() {
        let configuration = TunnelConfiguration {
            mtu: 1350,
            remote_address: None,
            addresses: vec![
                "10.42.0.7/32".parse().unwrap(),
                "2001:db8:42::7/64".parse().unwrap(),
            ],
            routes: Vec::new(),
            excluded_routes: Vec::new(),
            dns: Vec::new(),
            nbns: Vec::new(),
            search_domains: Vec::new(),
            split_dns: Vec::new(),
            split_dns_rules: Vec::new(),
            proxy_auto_config_url: String::new(),
            banner: String::new(),
            tunnel_all_dns: false,
            client_bypass_protocol: false,
            idle_timeout: Duration::ZERO,
            authentication_expiration: None,
        };
        let state = Mutex::new(F5ReconnectState::default());
        store_f5_reconnect_state(
            &state,
            &configuration,
            Some("192.0.2.20".parse().unwrap()),
        )
        .unwrap();
        let state = state.lock().unwrap();
        assert!(state.connected_once);
        assert_eq!(state.previous_ipv4.unwrap().to_string(), "10.42.0.7/32");
        assert_eq!(
            state.previous_ipv6.unwrap().to_string(),
            "2001:db8:42::7/64"
        );
        assert_eq!(state.source_ip.unwrap().to_string(), "192.0.2.20");
        assert!(!state.skip_initial_dtls);
    }

    #[test]
    fn f5_dtls_falls_back_when_stream_tls_pins_cannot_be_preserved() {
        let mut tls = OutboundTlsOptions::default();
        tls.server_certificate_fingerprints.push(
            ServerCertificateFingerprint {
                algorithm: ServerCertificateFingerprintAlgorithm::SpkiSha256Hex,
                encoded_prefix: "00".repeat(32),
            },
        );
        assert!(f5_dtls_unsupported_reason(&tls).is_some());
        tls.server_certificate_fingerprints.clear();
        assert!(f5_dtls_unsupported_reason(&tls).is_none());
    }

    #[test]
    fn enforces_fortinet_reconnect_source_ip_when_requested() {
        let configuration = fortinet_reconnect_configuration();
        let state = FortinetReconnectState {
            connected_once: true,
            source_ip: Some("192.0.2.10".parse().unwrap()),
            ..Default::default()
        };
        assert!(
            validate_fortinet_reconnect_source(
                &configuration,
                &state,
                Some("192.0.2.10".parse().unwrap())
            )
            .is_ok()
        );
        assert!(matches!(
            validate_fortinet_reconnect_source(
                &configuration,
                &state,
                Some("192.0.2.11".parse().unwrap())
            ),
            Err(EndpointConnectError::SessionRejected(401))
        ));
        assert!(matches!(
            validate_fortinet_reconnect_source(&configuration, &state, None),
            Err(EndpointConnectError::SessionRejected(401))
        ));

        let mut unchecked = configuration;
        unchecked.check_source_ip = false;
        assert!(
            validate_fortinet_reconnect_source(
                &unchecked,
                &state,
                Some("192.0.2.11".parse().unwrap())
            )
            .is_ok()
        );
    }

    #[test]
    fn normalizes_and_matches_negotiated_split_tunnel_policy() {
        let configuration = normalize_openconnect_configuration(
            TunnelConfiguration {
                mtu: 1300,
                remote_address: Some("198.51.100.9".parse().unwrap()),
                addresses: vec!["10.8.0.2/24".parse().unwrap()],
                routes: vec![route("10.0.0.0/8")],
                excluded_routes: vec![route("10.99.0.0/16")],
                dns: vec!["172.16.0.53".parse().unwrap()],
                nbns: Vec::new(),
                search_domains: vec![" Search.Example. ".into()],
                split_dns: vec!["corp.example".into()],
                split_dns_rules: vec![
                    crate::protocol::openconnect::TunnelSplitDnsRule {
                        domains: vec!["secure.corp.example".into()],
                        servers: vec!["172.17.0.54".parse().unwrap()],
                    },
                ],
                proxy_auto_config_url: String::new(),
                banner: String::new(),
                tunnel_all_dns: false,
                client_bypass_protocol: false,
                idle_timeout: Duration::ZERO,
                authentication_expiration: None,
            },
            false,
        )
        .unwrap();
        assert!(configuration
            .excluded_routes
            .iter()
            .any(|route| route.prefix == "198.51.100.9/32".parse().unwrap()));
        assert!(
            configuration
                .routes
                .iter()
                .any(|route| route.prefix == "172.16.0.53/32".parse().unwrap())
        );
        assert!(
            configuration
                .routes
                .iter()
                .any(|route| route.prefix == "172.17.0.54/32".parse().unwrap())
        );
        assert!(openconnect_preferred_address(
            &configuration,
            "10.20.30.40".parse().unwrap()
        ));
        assert!(!openconnect_preferred_address(
            &configuration,
            "10.99.1.1".parse().unwrap()
        ));
        assert!(openconnect_preferred_address(
            &configuration,
            "172.16.0.53".parse().unwrap()
        ));
        assert!(!openconnect_preferred_address(
            &configuration,
            "198.51.100.9".parse().unwrap()
        ));
        assert!(openconnect_preferred_domain(
            &configuration,
            "Host.Corp.Example."
        ));
        assert!(openconnect_preferred_domain(
            &configuration,
            "search.example"
        ));
        assert!(openconnect_preferred_domain(
            &configuration,
            "host.secure.corp.example"
        ));
        assert!(!openconnect_preferred_domain(
            &configuration,
            "notcorp.example"
        ));
    }

    #[test]
    fn ipv6_disabled_filters_tunnel_and_split_dns_policy() {
        let configuration = normalize_openconnect_configuration(
            TunnelConfiguration {
                mtu: 1300,
                remote_address: None,
                addresses: vec![
                    "10.8.0.2/24".parse().unwrap(),
                    "2001:db8::2/64".parse().unwrap(),
                ],
                routes: vec![route("10.0.0.0/8"), route("2001:db8:1::/48")],
                excluded_routes: vec![
                    route("192.0.2.0/24"),
                    route("2001:db8:2::/48"),
                ],
                dns: vec![
                    "10.8.0.53".parse().unwrap(),
                    "2001:db8::53".parse().unwrap(),
                ],
                nbns: vec![
                    "10.8.0.54".parse().unwrap(),
                    "2001:db8::54".parse().unwrap(),
                ],
                search_domains: Vec::new(),
                split_dns: Vec::new(),
                split_dns_rules: vec![
                    crate::protocol::openconnect::TunnelSplitDnsRule {
                        domains: vec!["mixed.example".into()],
                        servers: vec![
                            "10.8.0.55".parse().unwrap(),
                            "2001:db8::55".parse().unwrap(),
                        ],
                    },
                    crate::protocol::openconnect::TunnelSplitDnsRule {
                        domains: vec!["v6.example".into()],
                        servers: vec!["2001:db8::56".parse().unwrap()],
                    },
                ],
                proxy_auto_config_url: String::new(),
                banner: String::new(),
                tunnel_all_dns: false,
                client_bypass_protocol: false,
                idle_timeout: Duration::ZERO,
                authentication_expiration: None,
            },
            true,
        )
        .unwrap();

        assert!(
            configuration
                .addresses
                .iter()
                .all(|prefix| prefix.addr().is_ipv4())
        );
        assert!(
            configuration
                .routes
                .iter()
                .all(|route| route.prefix.addr().is_ipv4())
        );
        assert!(
            configuration
                .excluded_routes
                .iter()
                .all(|route| route.prefix.addr().is_ipv4())
        );
        assert!(configuration.dns.iter().all(IpAddr::is_ipv4));
        assert!(configuration.nbns.iter().all(IpAddr::is_ipv4));
        assert_eq!(configuration.split_dns_rules.len(), 1);
        assert_eq!(configuration.split_dns_rules[0].domains, ["mixed.example"]);
        assert_eq!(
            configuration.split_dns_rules[0].servers,
            ["10.8.0.55".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn normalizes_default_mtu_and_unmaps_remote_address_route() {
        let configuration = normalize_openconnect_configuration(
            TunnelConfiguration {
                mtu: 0,
                remote_address: Some("::ffff:198.51.100.9".parse().unwrap()),
                addresses: vec!["10.8.0.2/24".parse().unwrap()],
                routes: Vec::new(),
                excluded_routes: Vec::new(),
                dns: Vec::new(),
                nbns: Vec::new(),
                search_domains: Vec::new(),
                split_dns: Vec::new(),
                split_dns_rules: Vec::new(),
                proxy_auto_config_url: String::new(),
                banner: String::new(),
                tunnel_all_dns: false,
                client_bypass_protocol: false,
                idle_timeout: Duration::ZERO,
                authentication_expiration: None,
            },
            false,
        )
        .unwrap();

        assert_eq!(configuration.mtu, OPENCONNECT_DEFAULT_MTU);
        assert!(configuration.excluded_routes.iter().any(|route| {
            route.prefix == "198.51.100.9/32".parse().unwrap()
        }));
        assert!(!configuration.excluded_routes.iter().any(|route| {
            route.prefix == "::ffff:198.51.100.9/128".parse().unwrap()
        }));
    }

    #[test]
    fn maps_endpoint_options_into_authentication_and_cstp_policies() {
        let options: OpenConnectEndpointOptions = serde_json::from_str(
            r#"{
                "server":"vpn.example",
                "username":"alice",
                "password":"secret",
                "auth_group":"staff",
                "reported_os":"linux-64",
                "version":"5.1",
                "compression_mode":"all",
                "mtu":1300,
                "base_mtu":1400,
                "no_udp":true,
                "dpd_interval":"12s",
                "form_entries":[{"form_id":"main","name":"answer","value":"42"}],
                "tls":{"insecure":true,"server_name":"gateway.example"}
            }"#,
        )
        .unwrap();
        let auth = endpoint_authenticator_options(&options).unwrap();
        assert_eq!(auth.prefill.credentials.username.as_deref(), Some("alice"));
        assert_eq!(
            auth.prefill.credentials.password.as_deref(),
            Some("secret")
        );
        assert_eq!(
            auth.prefill.credentials.auth_group.as_deref(),
            Some("staff")
        );
        assert_eq!(auth.prefill.form_entries.len(), 1);
        let cstp =
            endpoint_cstp_options(&options, endpoint_tls_options(&options));
        assert_eq!(cstp.connect.compression_mode, CstpCompressionMode::All);
        assert_eq!(cstp.connect.tunnel_mtu, 1300);
        assert_eq!(cstp.connect.base_mtu, 1400);
        assert!(cstp.connect.no_udp);
        assert_eq!(
            cstp.response.dpd_override,
            Some(std::time::Duration::from_secs(12))
        );
        assert_eq!(cstp.queue_length, 32);
        assert!(cstp.tls.insecure);
        assert_eq!(cstp.tls.server_name, "gateway.example");
        assert_eq!(
            normalize_server_url(&options.server),
            "https://vpn.example"
        );
    }

    #[test]
    fn rejects_runtime_features_without_native_adapters() {
        let mut options = OpenConnectEndpointOptions {
            server: "vpn.example".into(),
            ..Default::default()
        };
        options.tls.peer_fingerprint.0.push("md5:deadbeef".into());
        assert!(validate_runtime_options(&options).is_err());
    }

    #[test]
    fn maps_all_peer_fingerprint_formats_and_private_root_policy() {
        let mut options = OpenConnectEndpointOptions {
            server: "vpn.example".into(),
            ..Default::default()
        };
        options.tls.system_trust_disabled = true;
        let encoded_pin = STANDARD.encode([7_u8; 32]);
        options.tls.peer_fingerprint.0 = vec![
            "A1B2".into(),
            "sha1:C3D4".into(),
            "sha256:E5F6".into(),
            format!("pin-sha256:{}", &encoded_pin[..12]),
        ];
        validate_runtime_options(&options).unwrap();
        let tls = endpoint_tls_options(&options);
        assert!(tls.system_trust_disabled);
        assert_eq!(
            tls.server_certificate_fingerprints,
            vec![
                ServerCertificateFingerprint {
                    algorithm: ServerCertificateFingerprintAlgorithm::CertificateSha1Hex,
                    encoded_prefix: "a1b2".into(),
                },
                ServerCertificateFingerprint {
                    algorithm: ServerCertificateFingerprintAlgorithm::SpkiSha1Hex,
                    encoded_prefix: "c3d4".into(),
                },
                ServerCertificateFingerprint {
                    algorithm: ServerCertificateFingerprintAlgorithm::SpkiSha256Hex,
                    encoded_prefix: "e5f6".into(),
                },
                ServerCertificateFingerprint {
                    algorithm: ServerCertificateFingerprintAlgorithm::SpkiSha256Base64,
                    encoded_prefix: encoded_pin[..12].into(),
                },
            ]
        );
        assert!(tls.certificate.as_slice().is_empty());
        assert!(tls.certificate_path.is_empty());

        options.tls.peer_fingerprint.0 =
            vec![format!("sha256:{}", hex::encode([9_u8; 32]))];
        let tls = endpoint_tls_options(&options);
        assert_eq!(
            tls.server_certificate_fingerprints[0].encoded_prefix,
            hex::encode([9_u8; 32])
        );
    }

    #[test]
    fn applies_pfs_cipher_filter_and_http_keepalive_policy() {
        let options = OpenConnectEndpointOptions {
            pfs: true,
            http_keep_alive_disabled: true,
            ..Default::default()
        };
        let tls = endpoint_tls_options(&options);
        assert_eq!(tls.cipher_suites.as_slice().len(), 6);
        assert!(
            tls.cipher_suites
                .as_slice()
                .iter()
                .all(|suite| suite.contains("_ECDHE_"))
        );
        let transport =
            endpoint_auth_http_transport(&options, Arc::new(PulseTcpDialer));
        assert!(transport.keep_alive_disabled());
    }

    #[test]
    fn rejects_malformed_peer_fingerprints_like_the_go_parser() {
        for fingerprint in [
            "abc",
            "sha1:xyz1",
            "sha256:123",
            "pin-sha256:ab=cd",
            "md5:deadbeef",
        ] {
            assert!(
                openconnect_peer_fingerprints(&[fingerprint.into()]).is_err(),
                "accepted {fingerprint:?}"
            );
        }
        let invalid_full_base64 = format!("pin-sha256:{}", "A".repeat(44));
        assert!(openconnect_peer_fingerprints(&[invalid_full_base64]).is_err());
    }

    #[test]
    fn loads_encrypted_mca_identity_into_authenticator() {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate =
            rcgen::CertificateParams::new(vec!["mca.example".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
        let parsed_key =
            PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap();
        let encrypted_key = parsed_key
            .private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                b"correct horse",
            )
            .unwrap();
        let mut options = OpenConnectEndpointOptions {
            server: "vpn.example".into(),
            ..Default::default()
        };
        options.tls.mca_certificate.0 = vec![certificate.pem()];
        options.tls.mca_key.0 = vec![String::from_utf8(encrypted_key).unwrap()];
        options.tls.mca_key_password = "correct horse".into();
        validate_runtime_options(&options).unwrap();
        let auth = endpoint_authenticator_options(&options).unwrap();
        assert!(auth.identity.multiple_certificate_authentication);
        let identity = auth.mca_identity.unwrap();
        assert_eq!(identity.certificates_der.len(), 1);
        assert_eq!(
            identity.private_key_password.as_deref(),
            Some(b"correct horse".as_slice())
        );

        options.tls.mca_key_password = "wrong".into();
        assert!(validate_runtime_options(&options).is_err());
    }

    #[test]
    fn decrypts_and_validates_tls_client_private_key_before_connect() {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate =
            rcgen::CertificateParams::new(vec!["client.example".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
        let parsed_key =
            PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap();
        let encrypted_key = parsed_key
            .private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                b"client password",
            )
            .unwrap();
        let mut options = OpenConnectEndpointOptions {
            server: "vpn.example".into(),
            ..Default::default()
        };
        options.tls.client_certificate.0 = vec![certificate.pem()];
        options.tls.client_key.0 =
            vec![String::from_utf8(encrypted_key).unwrap()];
        options.tls.client_key_password = "client password".into();

        let mut wrong_password = options.clone();
        wrong_password.tls.client_key_password = "wrong".into();
        assert!(
            normalize_openconnect_tls_client_key(&mut wrong_password).is_err()
        );

        normalize_openconnect_tls_client_key(&mut options).unwrap();
        assert!(options.tls.client_key_password.is_empty());
        assert!(options.tls.client_key_path.is_empty());
        let normalized = options.tls.client_key.as_slice()[0].as_bytes();
        let normalized_key = PKey::private_key_from_pem(normalized).unwrap();
        let leaf = X509::from_pem(certificate.pem().as_bytes()).unwrap();
        assert!(normalized_key.public_eq(&leaf.public_key().unwrap()));
    }

    #[test]
    fn loads_oath_and_oidc_tokens_and_validates_stoken_material() {
        let mut options = OpenConnectEndpointOptions {
            server: "vpn.example".into(),
            ..Default::default()
        };
        options.token = Some(crate::option::OpenConnectTokenOptions {
            mode: "hotp".into(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            counter: 0,
            ..Default::default()
        });
        validate_runtime_options(&options).unwrap();
        let factory = load_openconnect_oath_token_factory(&options)
            .unwrap()
            .unwrap();
        let mut generator = factory.generator();
        use crate::protocol::openconnect::AnyConnectSoftwareTokenGenerator as _;
        assert_eq!(generator.generate("").unwrap(), "755224");
        assert_eq!(factory.current_counter(), 1);

        options.token.as_mut().unwrap().mode = "oidc".into();
        options.token.as_mut().unwrap().secret = "bearer-token".into();
        validate_runtime_options(&options).unwrap();
        assert!(
            load_openconnect_oath_token_factory(&options)
                .unwrap()
                .is_none()
        );

        options.token.as_mut().unwrap().mode = "stoken".into();
        assert_eq!(
            validate_runtime_options(&options).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn network_connect_oncp_data_plane_round_trip() {
        use rcgen::generate_simple_self_signed;
        use rustls::{
            ServerConfig,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use tokio::{io::AsyncReadExt as _, net::TcpListener};
        use tokio_rustls::TlsAcceptor;

        fn server_kmp(message_type: u16, payload: &[u8]) -> Vec<u8> {
            let mut message =
                crate::protocol::openconnect::encode_network_connect_oncp_kmp(
                    message_type,
                    payload,
                )
                .unwrap();
            message[12] = 0;
            message
        }

        fn group(identifier: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
            let payload = attributes.concat();
            crate::protocol::openconnect::encode_network_connect_oncp_tlv(
                identifier, &payload,
            )
            .unwrap()
        }

        fn ipv4_packet(ttl: u8) -> Vec<u8> {
            let mut packet = vec![0_u8; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
            packet[8] = ttl;
            packet
        }

        let certified =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n")
            );
            assert!(request.contains("Cookie: DSID=session-cookie\r\n"));
            assert!(request.contains("Content-Length: 256\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            stream.flush().await.unwrap();

            let authentication_length = stream.read_u16_le().await.unwrap();
            let mut authentication =
                vec![0; usize::from(authentication_length)];
            stream.read_exact(&mut authentication).await.unwrap();
            assert_eq!(&authentication[..5], &[0, 4, 0, 0, 0]);
            assert!(
                authentication.windows(8).any(|value| value == b"zay-test")
            );

            let assigned =
                crate::protocol::openconnect::encode_network_connect_oncp_tlv(
                    1,
                    &[10, 55, 0, 2],
                )
                .unwrap();
            let netmask =
                crate::protocol::openconnect::encode_network_connect_oncp_tlv(
                    2,
                    &[255, 255, 255, 0],
                )
                .unwrap();
            let mtu =
                crate::protocol::openconnect::encode_network_connect_oncp_tlv(
                    2,
                    &1400_u32.to_be_bytes(),
                )
                .unwrap();
            let mut configuration = group(1, &[assigned, netmask]);
            configuration.extend_from_slice(&group(6, &[mtu]));
            let configuration = server_kmp(
                crate::protocol::openconnect::NETWORK_CONNECT_ONCP_KMP_CONFIGURATION,
                &configuration,
            );
            let mut hostname_response = vec![0];
            hostname_response.extend_from_slice(&configuration);
            stream
                .write_all(
                    &crate::protocol::openconnect::encode_network_connect_oncp_record(
                        &hostname_response,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();

            let mtu_length = stream.read_u16_le().await.unwrap();
            let mut mtu_control = vec![0; usize::from(mtu_length)];
            stream.read_exact(&mut mtu_control).await.unwrap();
            let (header, _) =
                parse_network_connect_oncp_kmp(&mtu_control, true).unwrap();
            assert_eq!(header.message_type, NETWORK_CONNECT_ONCP_KMP_CONTROL);

            let data_length = stream.read_u16_le().await.unwrap();
            let mut data = vec![0; usize::from(data_length)];
            stream.read_exact(&mut data).await.unwrap();
            let (header, outgoing) =
                parse_network_connect_oncp_kmp(&data, true).unwrap();
            assert_eq!(header.message_type, NETWORK_CONNECT_ONCP_KMP_DATA);
            assert_eq!(outgoing[8], 32);
            let incoming =
                server_kmp(NETWORK_CONNECT_ONCP_KMP_DATA, &ipv4_packet(64));
            stream
                .write_all(
                    &crate::protocol::openconnect::encode_network_connect_oncp_record(
                        &incoming,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let mut remainder = Vec::new();
            let _ = stream.read_to_end(&mut remainder).await;
        });

        let server_url = url::Url::parse(&format!(
            "https://localhost:{}/login",
            address.port()
        ))
        .unwrap();
        let session = NetworkConnectEndpointSession {
            authenticated: NetworkConnectAuthenticatedSession {
                server_url: server_url.clone(),
                authenticated_address: Some(address.ip()),
                peer_certificate_der: None,
                dsid: "session-cookie".into(),
                cookies: vec![("DSID".into(), "session-cookie".into())],
            },
            tncc: None,
        };
        let options = OpenConnectEndpointOptions {
            server: server_url.to_string(),
            flavor: "nc".into(),
            local_hostname: "zay-test".into(),
            no_udp: true,
            tls: crate::option::OpenConnectTlsOptions {
                insecure: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let cancellation = CancellationToken::new();
        let (mut channel, configuration) =
            connect_authenticated_network_connect(
                &options,
                Arc::new(PulseTcpDialer),
                &session,
                &cancellation,
            )
            .await
            .unwrap();
        assert_eq!(configuration.mtu, 1400);
        assert_eq!(configuration.addresses[0].to_string(), "10.55.0.2/24");
        channel.send_data(&ipv4_packet(32)).await.unwrap();
        let incoming = channel.receive_data().await.unwrap();
        assert_eq!(incoming[8], 64);
        channel.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn network_connect_logout_uses_pinned_dsid() {
        use rcgen::generate_simple_self_signed;
        use rustls::{
            ServerConfig,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use tokio::{io::AsyncReadExt as _, net::TcpListener};
        use tokio_rustls::TlsAcceptor;

        let certified =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request
                    .starts_with("GET /dana-na/auth/logout.cgi HTTP/1.1\r\n")
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("cookie: dsid=session-cookie\r\n")
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });
        let server_url = url::Url::parse(&format!(
            "https://localhost:{}/login?q=1",
            address.port()
        ))
        .unwrap();
        let options = OpenConnectEndpointOptions {
            server: server_url.to_string(),
            flavor: "nc".into(),
            tls: crate::option::OpenConnectTlsOptions {
                insecure: true,
                ..Default::default()
            },
            ..Default::default()
        };
        logout_network_connect_endpoint(
            &options,
            Arc::new(PulseTcpDialer),
            NetworkConnectEndpointSession {
                authenticated: NetworkConnectAuthenticatedSession {
                    server_url,
                    authenticated_address: Some(address.ip()),
                    peer_certificate_der: None,
                    dsid: "session-cookie".into(),
                    cookies: vec![("DSID".into(), "session-cookie".into())],
                },
                tncc: None,
            },
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pulse_direct_authentication_reaches_ift_data_plane() {
        use rcgen::generate_simple_self_signed;
        use rustls::{
            ServerConfig,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use tokio::{io::AsyncReadExt as _, net::TcpListener};
        use tokio_rustls::TlsAcceptor;

        let certified =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            assert!(
                String::from_utf8_lossy(&request)
                    .contains("Upgrade: IF-T/TLS 1.0\r\n")
            );
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: IF-T/TLS 1.0\r\n\r\n",
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let mut connection = PulseIftConnection::new(stream);
            let version = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            assert_eq!(version.frame_type, PULSE_IFT_VERSION_REQUEST);
            connection
                .write_frame(
                    PULSE_VENDOR_TCG,
                    crate::protocol::openconnect::PULSE_IFT_VERSION_RESPONSE,
                    &[0, 1, 2, 2],
                )
                .await
                .unwrap();
            assert_eq!(
                connection
                    .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                    .await
                    .unwrap()
                    .frame_type,
                0x88
            );
            connection
                .write_frame(
                    PULSE_VENDOR_TCG,
                    crate::protocol::openconnect::PULSE_IFT_CLIENT_AUTH_CHALLENGE,
                    &crate::protocol::openconnect::PULSE_IFT_AUTHENTICATION_JUNIPER
                        .to_be_bytes(),
                )
                .await
                .unwrap();
            let identity = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            assert_eq!(
                crate::protocol::openconnect::parse_pulse_eap(
                    &identity.payload[4..]
                )
                .unwrap()
                .payload,
                b"anonymous"
            );
            connection
                .write_frame(PULSE_VENDOR_TCG, 5, &pulse_request(2, &[]))
                .await
                .unwrap();
            let client_information = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            let client_packet = crate::protocol::openconnect::parse_pulse_eap(
                &client_information.payload[4..],
            )
            .unwrap();
            assert_eq!(
                parse_pulse_avps(&client_packet.payload).unwrap().len(),
                2
            );

            let password_inner = build_pulse_eap(
                crate::protocol::openconnect::PULSE_EAP_REQUEST,
                3,
                crate::protocol::openconnect::PULSE_EAP_TYPE_EXPANDED,
                2,
                &[crate::protocol::openconnect::PULSE_JUNIPER_PASSWORD_REQUEST],
            )
            .unwrap();
            let mut password_avp = Vec::new();
            crate::protocol::openconnect::append_pulse_avp(
                &mut password_avp,
                crate::protocol::openconnect::PULSE_AVP_EAP_MESSAGE,
                0,
                &password_inner,
            )
            .unwrap();
            connection
                .write_frame(
                    PULSE_VENDOR_TCG,
                    5,
                    &pulse_request(4, &password_avp),
                )
                .await
                .unwrap();
            let response = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            let response = crate::protocol::openconnect::parse_pulse_eap(
                &response.payload[4..],
            )
            .unwrap();
            assert_eq!(parse_pulse_avps(&response.payload).unwrap().len(), 2);

            let mut cookie = Vec::new();
            crate::protocol::openconnect::append_pulse_avp(
                &mut cookie,
                0xd53,
                crate::protocol::openconnect::PULSE_VENDOR_JUNIPER2,
                b"session-cookie",
            )
            .unwrap();
            connection
                .write_frame(PULSE_VENDOR_TCG, 5, &pulse_request(5, &cookie))
                .await
                .unwrap();
            let _ = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            let mut success =
                crate::protocol::openconnect::PULSE_IFT_AUTHENTICATION_JUNIPER
                    .to_be_bytes()
                    .to_vec();
            success.extend_from_slice(&[
                crate::protocol::openconnect::PULSE_EAP_SUCCESS,
                5,
                0,
                4,
            ]);
            connection
                .write_frame(
                    PULSE_VENDOR_TCG,
                    crate::protocol::openconnect::PULSE_IFT_CLIENT_AUTH_SUCCESS,
                    &success,
                )
                .await
                .unwrap();
            let configuration = pulse_main_configuration_frame();
            connection
                .write_frame(
                    configuration.vendor,
                    configuration.frame_type,
                    &configuration.payload,
                )
                .await
                .unwrap();
            connection
                .write_frame(PULSE_VENDOR_JUNIPER, 0x8f, &[])
                .await
                .unwrap();
            let outgoing = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            assert_eq!((outgoing.frame_type, outgoing.payload[0] >> 4), (4, 4));
            assert_eq!(outgoing.sequence, 6);
            let mut incoming = outgoing.payload;
            incoming[8] = 64;
            connection
                .write_frame(PULSE_VENDOR_JUNIPER, 4, &incoming)
                .await
                .unwrap();
            let close = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            assert_eq!((close.frame_type, close.sequence), (0x89, 7));
        });

        let options = OpenConnectEndpointOptions {
            server: format!("https://{address}/"),
            flavor: "pulse".into(),
            username: "alice".into(),
            password: "secret".into(),
            reported_os: "linux-64".into(),
            tls: crate::option::OpenConnectTlsOptions {
                insecure: true,
                ..Default::default()
            },
            no_udp: true,
            ..Default::default()
        };
        let cancellation = CancellationToken::new();
        let dialer: Arc<dyn Dialer> = Arc::new(PulseTcpDialer);
        let authenticated = authenticate_pulse(
            &options,
            dialer.clone(),
            &OpenConnectChallengeManager::default(),
            &cancellation,
            false,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(authenticated.cookie, b"session-cookie");
        let (mut channel, configuration) = connect_authenticated_pulse(
            &options,
            dialer,
            &authenticated,
            &cancellation,
        )
        .await
        .unwrap();
        assert_eq!(configuration.addresses[0].to_string(), "10.23.0.2/24");
        let packet = vec![0x45_u8; 20];
        channel.send_data(&packet).await.unwrap();
        let response = channel.receive_data().await.unwrap();
        assert_eq!((response[0] >> 4, response[8]), (4, 64));
        channel.close().await.unwrap();
        assert!(authenticated.graceful_bye.load(Ordering::Acquire));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pulse_abnormal_close_logs_out_with_pinned_dsid() {
        use rcgen::generate_simple_self_signed;
        use rustls::{
            ServerConfig,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use tokio::{io::AsyncReadExt as _, net::TcpListener};
        use tokio_rustls::TlsAcceptor;

        let certified =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            let lower_request = request.to_ascii_lowercase();
            assert!(
                request
                    .starts_with("GET /dana-na/auth/logout.cgi HTTP/1.1\r\n")
            );
            assert!(
                lower_request.contains(&format!(
                    "host: localhost:{}\r\n",
                    address.port()
                ))
            );
            assert!(lower_request.contains("cookie: dsid=session-cookie\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });
        let server_url = url::Url::parse(&format!(
            "https://localhost:{}/vpn?q=1",
            address.port()
        ))
        .unwrap();
        let session = PulseAuthenticatedSession {
            server_url: server_url.clone(),
            accepted_address: address.ip(),
            cookie: b"session-cookie".to_vec(),
            authentication_expiration: None,
            idle_timeout: Duration::ZERO,
            live_connection: Arc::default(),
            graceful_bye: Arc::new(AtomicBool::new(false)),
        };
        let options = OpenConnectEndpointOptions {
            server: server_url.to_string(),
            flavor: "pulse".into(),
            tls: crate::option::OpenConnectTlsOptions {
                insecure: true,
                ..Default::default()
            },
            ..Default::default()
        };
        logout_pulse_endpoint(&options, Arc::new(PulseTcpDialer), session)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pulse_cookie_reconnect_is_pinned_and_noninteractive() {
        use rcgen::generate_simple_self_signed;
        use rustls::{
            ServerConfig,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use tokio::{io::AsyncReadExt as _, net::TcpListener};
        use tokio_rustls::TlsAcceptor;

        let certified =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request =
                String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.contains("host: localhost:"));
            assert!(request.contains("cookie: dsid=old-cookie\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: IF-T/TLS 1.0\r\n\r\n",
                )
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let mut connection = PulseIftConnection::new(stream);
            assert_eq!(
                connection
                    .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                    .await
                    .unwrap()
                    .frame_type,
                PULSE_IFT_VERSION_REQUEST
            );
            connection
                .write_frame(
                    PULSE_VENDOR_TCG,
                    crate::protocol::openconnect::PULSE_IFT_VERSION_RESPONSE,
                    &[0, 1, 2, 2],
                )
                .await
                .unwrap();
            let _ = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            connection
                .write_frame(
                    PULSE_VENDOR_TCG,
                    crate::protocol::openconnect::PULSE_IFT_CLIENT_AUTH_CHALLENGE,
                    &crate::protocol::openconnect::PULSE_IFT_AUTHENTICATION_JUNIPER
                        .to_be_bytes(),
                )
                .await
                .unwrap();
            let _ = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            connection
                .write_frame(PULSE_VENDOR_TCG, 5, &pulse_request(2, &[]))
                .await
                .unwrap();
            let client_information = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            let client_packet = crate::protocol::openconnect::parse_pulse_eap(
                &client_information.payload[4..],
            )
            .unwrap();
            let avps = parse_pulse_avps(&client_packet.payload).unwrap();
            assert!(
                avps.iter()
                    .any(|avp| avp.code == 0xd53 && avp.data == b"old-cookie")
            );
            let mut cookie = Vec::new();
            crate::protocol::openconnect::append_pulse_avp(
                &mut cookie,
                0xd53,
                crate::protocol::openconnect::PULSE_VENDOR_JUNIPER2,
                b"new-cookie",
            )
            .unwrap();
            connection
                .write_frame(PULSE_VENDOR_TCG, 5, &pulse_request(3, &cookie))
                .await
                .unwrap();
            let _ = connection
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            let mut success =
                crate::protocol::openconnect::PULSE_IFT_AUTHENTICATION_JUNIPER
                    .to_be_bytes()
                    .to_vec();
            success.extend_from_slice(&[
                crate::protocol::openconnect::PULSE_EAP_SUCCESS,
                3,
                0,
                4,
            ]);
            connection
                .write_frame(
                    PULSE_VENDOR_TCG,
                    crate::protocol::openconnect::PULSE_IFT_CLIENT_AUTH_SUCCESS,
                    &success,
                )
                .await
                .unwrap();
            let _ = connection.into_inner().shutdown().await;
        });
        let options = OpenConnectEndpointOptions {
            server: format!("https://localhost:{}/", address.port()),
            flavor: "pulse".into(),
            cookie: "old-cookie".into(),
            tls: crate::option::OpenConnectTlsOptions {
                insecure: true,
                ..Default::default()
            },
            ..Default::default()
        };
        // The hostname remains localhost for SNI/Host, while the dial target
        // is the accepted address captured by the previous session.
        let authenticated = authenticate_pulse(
            &options,
            Arc::new(PulseTcpDialer),
            &OpenConnectChallengeManager::default(),
            &CancellationToken::new(),
            true,
            Some(address.ip()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(authenticated.accepted_address, address.ip());
        assert_eq!(authenticated.cookie, b"new-cookie");
        if let Some(connection) =
            authenticated.live_connection.lock().await.take()
        {
            let mut stream = connection.into_inner();
            let _ = stream.shutdown().await;
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn challenge_manager_publishes_and_validates_host_response() {
        let manager = Arc::new(OpenConnectChallengeManager::default());
        let challenge = OpenConnectAuthChallenge {
            id: "challenge-1".into(),
            banner: String::new(),
            message: "Password".into(),
            error: String::new(),
            kind: super::super::super::protocol::openconnect::OpenConnectAuthChallengeKind::Form(
                Default::default(),
            ),
        };
        let waiter = {
            let manager = manager.clone();
            let challenge = challenge.clone();
            tokio::spawn(async move {
                let cancellation = CancellationToken::new();
                manager.await_response(challenge, &cancellation).await
            })
        };
        assert_eq!(manager.wait_pending().await.unwrap(), challenge);
        assert!(
            manager
                .respond(
                    "wrong",
                    OpenConnectAuthResponse::Form(Default::default())
                )
                .is_err()
        );
        manager
            .respond(
                "challenge-1",
                OpenConnectAuthResponse::Form(Default::default()),
            )
            .unwrap();
        assert_eq!(
            waiter.await.unwrap().unwrap(),
            OpenConnectAuthResponse::Form(Default::default())
        );
        assert!(manager.pending().is_none());
    }
}
