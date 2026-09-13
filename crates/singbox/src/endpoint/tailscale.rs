//! Userspace IP network backed by the dynamic Tailscale WireGuard engine.
//!
//! The network reuses the same smoltcp and inbound flow-router substrate as
//! the static WireGuard endpoint. It remains a library object: zay can use its
//! `Dialer`, subscribe to transport events, or attach the routed variant to
//! the normal singbox router without a nested Tailscale process.

use std::{
    collections::HashSet,
    convert::Infallible,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use async_trait::async_trait;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig as _};
use rand::Rng as _;
use tokio::{
    sync::{broadcast, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, IpPacketPort, IpPacketReturn,
        PacketConnection, PacketFuture, PacketStream, Stream,
    },
    common::lifecycle::{
        Lifecycle, LifecycleError, LifecycleFuture, StartStage,
    },
    common::network::SocksAddr,
    dns::tailscale::TailscaleNetmapProvider,
    option::{OutboundTlsOptions, TailscaleEndpointOptions, UdpNatBehavior},
    outbound::OutboundManager,
    protocol::{
        direct::DirectOutbound,
        tailscale_control_supervisor::{
            TailscaleControlBootstrap, TailscaleControlConnector,
            TailscaleControlSupervisor, TailscaleControlSupervisorEvent,
            TailscaleControlSupervisorOptions, TailscaleNetmapConsumer,
            TailscaleTs2021DialConnector,
            bootstrap_tailscale_control_with_tls_options,
            build_tailscale_control_connector,
        },
        tailscale_control_types::{
            TailscaleHostinfo, TailscaleMachinePublicKey, TailscaleNetmapState,
            TailscaleNodePublicKey, TailscaleService,
        },
        tailscale_derp_manager::{
            TailscaleDerpManager, TailscaleDerpManagerOptions,
        },
        tailscale_derp_map::{
            TailscaleDerpMapController, TailscaleRoutePolicy,
        },
        tailscale_disco_socket::{
            TailscaleDiscoSocket, TailscaleDiscoSocketOptions,
        },
        tailscale_netcheck::{
            TAILSCALE_RESTUN_INTERVAL, TAILSCALE_STUN_PROBE_TIMEOUT,
            TailscalePortMapping, discover_tailscale_endpoints,
        },
        tailscale_ssh::{
            TAILSCALE_CAPABILITY_SSH_ENVIRONMENT_VARIABLES,
            TailscaleSshConnectionHandler, TailscaleSshControlDelegateClient,
            TailscaleSshCurrentUserProcessBackend, TailscaleSshDelegateClient,
            TailscaleSshRecordingNotifier,
            load_or_generate_tailscale_ssh_server_identity,
            serve_tailscale_ssh_connection, tailscale_ssh_peer_identity,
        },
        tailscale_state::{
            TAILSCALE_DEFAULT_CONTROL_URL, TailscaleNodeFile,
            TailscaleNodeStateStore, TailscalePrivateKey,
        },
        tailscale_taildrop::{
            TailscaleTaildropError, TailscaleTaildropEvent,
            TailscaleTaildropInbox, TailscaleTaildropPeerAccess,
            TailscaleTaildropReceiver, TailscaleTaildropTarget,
            handle_tailscale_taildrop_request, send_tailscale_taildrop_file,
            tailscale_taildrop_targets,
        },
        tailscale_tka::{
            TailscaleNetworkLockPrivateKey, resign_tailscale_node_key_signature,
        },
        tailscale_tka_sync::TailscalePersistentTkaSynchronizer,
        tailscale_wireguard::{
            TailscaleWireGuardEngine, TailscaleWireGuardEvent,
            TailscaleWireGuardHandle,
        },
    },
    route::Router,
};

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
    userspace_router::UserspaceEndpointRouter,
};

const EVENT_QUEUE_DEPTH: usize = 64;
pub const TAILSCALE_CAPABILITY_VERSION: u32 = 142;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleUserspaceNetworkConfig {
    pub addresses: Vec<ipnet::IpNet>,
    pub mtu: usize,
    pub udp_timeout: Duration,
    pub udp_mapping: UdpNatBehavior,
    pub udp_filtering: UdpNatBehavior,
    pub udp_nat_max: u32,
}

impl TailscaleUserspaceNetworkConfig {
    pub fn new(addresses: Vec<ipnet::IpNet>) -> Self {
        Self {
            addresses,
            mtu: 1280,
            udp_timeout: crate::constant::UDP_TIMEOUT,
            udp_mapping: UdpNatBehavior::EndpointIndependent,
            udp_filtering: UdpNatBehavior::EndpointIndependent,
            udp_nat_max: 0,
        }
    }

    pub fn from_netmap(netmap: &TailscaleNetmapState) -> io::Result<Self> {
        let node = netmap
            .node
            .as_ref()
            .ok_or_else(|| invalid("Tailscale netmap has no local node"))?;
        let addresses = node
            .addresses
            .iter()
            .map(|address| {
                address.parse().map_err(|_| {
                    invalid(format!(
                        "invalid local Tailscale address {address:?}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let config = Self::new(addresses);
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> io::Result<()> {
        if self.addresses.is_empty() {
            return Err(invalid(
                "Tailscale userspace network requires a local address",
            ));
        }
        if self.mtu < 1280 {
            return Err(invalid(
                "Tailscale userspace network MTU is below 1280",
            ));
        }
        Ok(())
    }
}

/// Dialer backed by the embedded Tailscale userspace network.
pub struct TailscaleUserspaceDialer {
    net: Arc<Net>,
    packet_port: Arc<TailscalePacketPort>,
}

struct TailscalePacketPort {
    engine: TailscaleWireGuardHandle,
    inet4_address: Option<IpAddr>,
    inet6_address: Option<IpAddr>,
    mtu: usize,
    return_path: RwLock<Option<Weak<dyn IpPacketReturn>>>,
}

impl TailscalePacketPort {
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

impl IpPacketPort for TailscalePacketPort {
    fn port_addresses(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        (self.inet4_address, self.inet6_address)
    }

    fn port_mtu(&self) -> usize {
        self.mtu
    }

    fn attach_return(
        &self,
        return_path: Weak<dyn IpPacketReturn>,
    ) -> io::Result<()> {
        let mut current = self.return_path.write().map_err(|_| {
            io::Error::other("Tailscale packet return lock poisoned")
        })?;
        if let Some(existing) = current.as_ref()
            && existing.upgrade().is_some()
        {
            if existing.ptr_eq(&return_path) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Tailscale packet return path is already attached",
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
            for packet in packets {
                if packet.is_empty() {
                    continue;
                }
                self.engine
                    .send_ip_packet(&packet)
                    .await
                    .map_err(io::Error::other)?;
            }
            Ok(())
        })
    }
}

/// A running smoltcp network and its dynamic WireGuard control handle.
pub struct TailscaleUserspaceNetwork {
    net: Arc<Net>,
    engine: TailscaleWireGuardHandle,
    events: broadcast::Sender<TailscaleWireGuardEvent>,
    cancellation: CancellationToken,
    tasks: Option<Vec<JoinHandle<()>>>,
    _flow_router: Option<Arc<UserspaceEndpointRouter>>,
    packet_port: Arc<TailscalePacketPort>,
}

impl TailscaleUserspaceNetwork {
    pub fn start(
        engine: TailscaleWireGuardEngine,
        config: TailscaleUserspaceNetworkConfig,
    ) -> io::Result<Self> {
        Self::start_inner(engine, config, None)
    }

    pub fn start_routed(
        tag: impl Into<String>,
        engine: TailscaleWireGuardEngine,
        config: TailscaleUserspaceNetworkConfig,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> io::Result<Self> {
        Self::start_inner(engine, config, Some((tag.into(), router, outbounds)))
    }

    fn start_inner(
        mut engine: TailscaleWireGuardEngine,
        config: TailscaleUserspaceNetworkConfig,
        flow: Option<(String, Arc<Router>, Arc<OutboundManager>)>,
    ) -> io::Result<Self> {
        config.validate()?;
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = config.mtu;
        capabilities.medium = Medium::Ip;
        let (device, ingress, egress, mut output, icmp_errors) =
            ChannelDevice::new(capabilities);
        let addresses = config
            .addresses
            .iter()
            .map(|prefix| prefix.to_string().parse())
            .collect::<Result<Vec<IpCidr>, _>>()
            .map_err(|()| invalid("invalid Tailscale stack address"))?;
        let gateways = addresses
            .iter()
            .map(IpCidr::address)
            .collect::<Vec<IpAddress>>();
        let interface = SmoltcpInterfaceConfig::new(HardwareAddress::Ip);
        let mut net_config = NetConfig::new(
            interface,
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
        let flow_router = flow.map(|(tag, router, outbounds)| {
            UserspaceEndpointRouter::new(
                &net,
                egress,
                tag,
                config.addresses.clone(),
                true,
                Vec::new(),
                router,
                outbounds,
                config.udp_timeout,
                config.udp_mapping,
                config.udp_filtering,
                config.udp_nat_max,
                config.mtu,
            )
        });
        let engine_handle = engine.handle();
        let packet_port = Arc::new(TailscalePacketPort {
            engine: engine_handle.clone(),
            inet4_address: config
                .addresses
                .iter()
                .map(ipnet::IpNet::addr)
                .find(IpAddr::is_ipv4),
            inet6_address: config
                .addresses
                .iter()
                .map(ipnet::IpNet::addr)
                .find(IpAddr::is_ipv6),
            mtu: config.mtu,
            return_path: RwLock::new(None),
        });
        let cancellation = CancellationToken::new();
        let (events, _) = broadcast::channel(EVENT_QUEUE_DEPTH);

        let incoming_cancellation = cancellation.clone();
        let incoming_events = events.clone();
        let incoming_flow_router = flow_router.clone();
        let incoming_packet_port = packet_port.clone();
        let incoming_task = tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = incoming_cancellation.cancelled() => break,
                    event = engine.next_event() => event,
                };
                let Some(event) = event else { break };
                match event {
                    TailscaleWireGuardEvent::IpPacket { packet, .. } => {
                        if incoming_packet_port.return_packet(&packet) {
                            continue;
                        }
                        if let Some(flow_router) = &incoming_flow_router {
                            match flow_router.prepare_packet(&packet).await {
                                Ok(true) => {}
                                Ok(false) | Err(_) => continue,
                            }
                        }
                        if ingress.send(Ok(packet)).await.is_err() {
                            break;
                        }
                    }
                    event => {
                        let _ = incoming_events.send(event);
                    }
                }
            }
            let _ = engine.close().await;
        });

        let outgoing_cancellation = cancellation.clone();
        let outgoing_engine = engine_handle.clone();
        let outgoing_events = events.clone();
        let outgoing_task = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = outgoing_cancellation.cancelled() => break,
                    packet = output.recv() => packet,
                };
                let Some(packet) = packet else { break };
                if let Err(error) =
                    outgoing_engine.send_ip_packet(&packet).await
                {
                    let _ = outgoing_events.send(
                        TailscaleWireGuardEvent::Error(error.to_string()),
                    );
                }
            }
        });

        Ok(Self {
            net,
            engine: engine_handle,
            events,
            cancellation,
            tasks: Some(vec![incoming_task, outgoing_task]),
            _flow_router: flow_router,
            packet_port,
        })
    }

    pub fn dialer(&self) -> Arc<dyn Dialer> {
        Arc::new(TailscaleUserspaceDialer {
            net: self.net.clone(),
            packet_port: self.packet_port.clone(),
        })
    }

    pub fn engine(&self) -> TailscaleWireGuardHandle {
        self.engine.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TailscaleWireGuardEvent> {
        self.events.subscribe()
    }

    async fn tcp_bind(
        &self,
        address: SocketAddr,
    ) -> io::Result<super::tokio_smoltcp::TcpListener> {
        self.net.tcp_bind(address).await
    }

    pub async fn close(mut self) -> io::Result<()> {
        self.cancellation.cancel();
        if let Some(tasks) = self.tasks.take() {
            for task in tasks {
                task.await.map_err(|error| {
                    io::Error::other(format!(
                        "Tailscale userspace network task failed: {error}"
                    ))
                })?;
            }
        }
        Ok(())
    }
}

impl Drop for TailscaleUserspaceNetwork {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(tasks) = self.tasks.take() {
            for task in tasks {
                task.abort();
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TailscaleEndpointPhase {
    #[default]
    Stopped,
    Connecting,
    NeedsLogin,
    Running,
    Failed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleEndpointStatus {
    pub phase: TailscaleEndpointPhase,
    pub auth_url: String,
    pub addresses: Vec<ipnet::IpNet>,
    pub control_generation: u64,
    pub peers: usize,
    pub endpoints: Vec<SocketAddr>,
    pub node_key_expired: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TailscaleEndpointEvent {
    DebugCommand {
        exit_code: Option<i32>,
        disable_log_tail: bool,
        sleep: Duration,
    },
    NodeKeyRotationRequired {
        node_key_signature: Option<Vec<u8>>,
    },
}

fn local_interface_prefixes() -> Vec<ipnet::IpNet> {
    let Ok(interfaces) = NetworkInterface::show() else {
        return Vec::new();
    };
    let mut prefixes = Vec::new();
    for interface in interfaces {
        if interface.internal {
            continue;
        }
        for address in interface.addr {
            let prefix = match address {
                Addr::V4(address) if !address.ip.is_loopback() => {
                    ipnet::Ipv4Net::with_netmask(
                        address.ip,
                        address.netmask.unwrap_or(Ipv4Addr::BROADCAST),
                    )
                    .map(ipnet::IpNet::V4)
                }
                Addr::V6(address) if !address.ip.is_loopback() => {
                    ipnet::Ipv6Net::with_netmask(
                        address.ip,
                        address
                            .netmask
                            .unwrap_or(Ipv6Addr::from([u8::MAX; 16])),
                    )
                    .map(ipnet::IpNet::V6)
                }
                _ => continue,
            };
            if let Ok(prefix) = prefix
                && !prefixes.contains(&prefix)
            {
                prefixes.push(prefix);
            }
        }
    }
    prefixes
}

pub struct TailscaleEndpointDialer {
    current: RwLock<Option<Arc<dyn Dialer>>>,
    fallback: Arc<dyn Dialer>,
    exit_node_allow_lan_access: bool,
    lan_prefixes: RwLock<Vec<ipnet::IpNet>>,
    preferred_prefixes: RwLock<Vec<ipnet::IpNet>>,
    preferred_domains: RwLock<TailscalePreferredDomains>,
}

impl Default for TailscaleEndpointDialer {
    fn default() -> Self {
        Self::new(false)
    }
}

#[derive(Default)]
struct TailscalePreferredDomains {
    exact: HashSet<String>,
    suffixes: Vec<String>,
    search_domains: bool,
}

impl TailscaleEndpointDialer {
    fn new(exit_node_allow_lan_access: bool) -> Self {
        Self {
            current: RwLock::new(None),
            fallback: Arc::new(DirectOutbound::new(Default::default())),
            exit_node_allow_lan_access,
            lan_prefixes: RwLock::new(local_interface_prefixes()),
            preferred_prefixes: RwLock::new(Vec::new()),
            preferred_domains: RwLock::new(Default::default()),
        }
    }

    fn current(&self) -> io::Result<Arc<dyn Dialer>> {
        self.current
            .read()
            .map_err(|_| {
                io::Error::other("Tailscale endpoint dialer lock poisoned")
            })?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Tailscale endpoint is not ready",
                )
            })
    }

    fn set_network(&self, network: Option<Arc<dyn Dialer>>) {
        if let Ok(mut current) = self.current.write() {
            *current = network;
        }
    }

    fn set_netmap(&self, netmap: &TailscaleNetmapState) {
        if self.exit_node_allow_lan_access
            && let Ok(mut prefixes) = self.lan_prefixes.write()
        {
            *prefixes = local_interface_prefixes();
        }
        let prefixes = netmap
            .peers
            .values()
            .flat_map(|peer| &peer.allowed_ips)
            .filter_map(|prefix| prefix.parse::<ipnet::IpNet>().ok())
            // Match sing-box's PeerForIP route preference: exit-node /0
            // routes are usable when selected explicitly, but never make the
            // endpoint the automatic preferred outbound for every address.
            .filter(|prefix| prefix.prefix_len() > 0)
            .collect();
        if let Ok(mut current) = self.preferred_prefixes.write() {
            *current = prefixes;
        }
        let mut domains = TailscalePreferredDomains::default();
        for node in netmap.node.iter().chain(netmap.peers.values()) {
            if !node.name.is_empty() {
                domains.exact.insert(canonical_domain(&node.name));
            }
        }
        if let Some(config) = &netmap.dns_config {
            for record in &config.extra_records {
                domains.exact.insert(canonical_domain(&record.name));
            }
            for domain in &config.domains {
                domains.exact.insert(canonical_domain(domain));
            }
            domains.suffixes = config
                .routes
                .keys()
                .map(|domain| canonical_domain(domain))
                .collect();
            if config.proxied {
                domains.suffixes.extend(
                    config
                        .domains
                        .iter()
                        .map(|domain| canonical_domain(domain)),
                );
            }
            domains.search_domains = !config.domains.is_empty();
        }
        if let Ok(mut current) = self.preferred_domains.write() {
            *current = domains;
        }
    }

    fn should_bypass_lan(&self, destination: &SocksAddr) -> bool {
        if !self.exit_node_allow_lan_access {
            return false;
        }
        let SocksAddr::Ip(destination) = destination else {
            return false;
        };
        self.lan_prefixes.read().is_ok_and(|prefixes| {
            prefixes
                .iter()
                .any(|prefix| prefix.contains(&destination.ip()))
        })
    }

    fn selected(&self, destination: &SocksAddr) -> io::Result<Arc<dyn Dialer>> {
        if self.should_bypass_lan(destination) {
            Ok(self.fallback.clone())
        } else {
            self.current()
        }
    }

    async fn selected_destination(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<(Arc<dyn Dialer>, SocksAddr)> {
        if self.exit_node_allow_lan_access && destination.is_domain() {
            for resolved in destination.resolve().await? {
                let resolved = SocksAddr::Ip(resolved);
                if self.should_bypass_lan(&resolved) {
                    return Ok((self.fallback.clone(), resolved));
                }
            }
        }
        Ok((self.selected(destination)?, destination.clone()))
    }
}

impl Dialer for TailscaleEndpointDialer {
    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        self.current().ok()?.packet_port()
    }

    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let (dialer, destination) =
                self.selected_destination(destination).await?;
            dialer.dial_tcp(&destination).await
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let (dialer, destination) =
                self.selected_destination(destination).await?;
            dialer.listen_udp(&destination).await
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
            let (dialer, destination) =
                self.selected_destination(destination).await?;
            dialer
                .exchange_icmp(packet, source, hop_limit, &destination)
                .await
        })
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.preferred_prefixes.read().is_ok_and(|prefixes| {
            prefixes.iter().any(|prefix| prefix.contains(&address))
        })
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        let domain = canonical_domain(domain);
        self.preferred_domains.read().is_ok_and(|domains| {
            domains.exact.contains(&domain)
                || domains.suffixes.iter().any(|suffix| {
                    suffix.is_empty()
                        || domain == *suffix
                        || domain
                            .strip_suffix(suffix)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
                || (!domain.contains('.') && domains.search_domains)
        })
    }
}

#[derive(Clone)]
pub struct TailscaleEndpointHandle {
    dialer: Arc<TailscaleEndpointDialer>,
    status: Arc<RwLock<TailscaleEndpointStatus>>,
    netmap: watch::Receiver<Option<Arc<TailscaleNetmapState>>>,
    events: broadcast::Sender<TailscaleEndpointEvent>,
    exit_node: String,
    taildrop: TailscaleTaildropReceiver,
    certificate_control:
        watch::Receiver<Option<Arc<TailscaleCertificateControl>>>,
    state_directory: PathBuf,
}

pub(crate) struct TailscaleCertificateControl {
    connector: Arc<TailscaleTs2021DialConnector>,
    node_key: TailscaleNodePublicKey,
}

#[derive(Clone)]
pub(crate) struct TailscaleCertificateEndpoint {
    netmap: watch::Receiver<Option<Arc<TailscaleNetmapState>>>,
    control: watch::Receiver<Option<Arc<TailscaleCertificateControl>>>,
    state_directory: PathBuf,
}

impl TailscaleCertificateEndpoint {
    pub(crate) fn netmap_receiver(
        &self,
    ) -> watch::Receiver<Option<Arc<TailscaleNetmapState>>> {
        self.netmap.clone()
    }

    pub(crate) fn control_receiver(
        &self,
    ) -> watch::Receiver<Option<Arc<TailscaleCertificateControl>>> {
        self.control.clone()
    }

    pub(crate) fn state_directory(&self) -> &Path {
        &self.state_directory
    }
}

impl TailscaleCertificateControl {
    pub(crate) async fn set_dns(
        &self,
        name: String,
        value: String,
    ) -> Result<(), String> {
        self.connector
            .set_dns(self.node_key, name, value)
            .await
            .map_err(|error| error.to_string())
    }
}

impl TailscaleEndpointHandle {
    pub fn dialer(&self) -> Arc<dyn Dialer> {
        self.dialer.clone()
    }

    pub fn status(&self) -> TailscaleEndpointStatus {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    pub fn netmap(&self) -> Option<Arc<TailscaleNetmapState>> {
        self.netmap.borrow().clone()
    }

    /// DNS names for which the control plane currently permits this node to
    /// obtain public TLS certificates.
    pub fn certificate_domains(&self) -> Vec<String> {
        self.netmap()
            .and_then(|netmap| netmap.dns_config.clone())
            .map(|dns| dns.certificate_domains)
            .unwrap_or_default()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TailscaleEndpointEvent> {
        self.events.subscribe()
    }

    pub fn taildrop_targets(
        &self,
    ) -> Result<Vec<TailscaleTaildropTarget>, TailscaleTaildropError> {
        let netmap =
            self.netmap().ok_or(TailscaleTaildropError::NotConnected)?;
        tailscale_taildrop_targets(&netmap)
    }

    pub async fn send_taildrop_file<R>(
        &self,
        peer_stable_id: &str,
        file_name: &str,
        size: u64,
        content: R,
        progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    ) -> Result<(), TailscaleTaildropError>
    where
        R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin + Send + 'static,
    {
        let netmap =
            self.netmap().ok_or(TailscaleTaildropError::NotConnected)?;
        send_tailscale_taildrop_file(
            self.dialer.clone(),
            &netmap,
            peer_stable_id,
            file_name,
            size,
            content,
            progress,
        )
        .await
    }

    pub fn taildrop_receiver(&self) -> TailscaleTaildropReceiver {
        self.taildrop.clone()
    }

    pub async fn taildrop_inbox(
        &self,
    ) -> Result<TailscaleTaildropInbox, TailscaleTaildropError> {
        self.taildrop.inbox().await
    }

    pub fn subscribe_taildrop_inbox(&self) -> broadcast::Receiver<()> {
        self.taildrop.subscribe()
    }

    pub fn subscribe_taildrop_events(
        &self,
    ) -> broadcast::Receiver<TailscaleTaildropEvent> {
        self.taildrop.subscribe_events()
    }

    pub async fn mark_taildrop_inbox_read(&self) {
        self.taildrop.mark_inbox_read().await;
    }

    pub async fn taildrop_waiting_file_count(
        &self,
    ) -> Result<usize, TailscaleTaildropError> {
        self.taildrop.waiting_file_count().await
    }

    pub async fn taildrop_unread_file_count(&self) -> usize {
        self.taildrop.unread_file_count().await
    }

    pub async fn taildrop_receiving_file_count(&self) -> usize {
        self.taildrop.receiving_file_count().await
    }

    pub async fn open_taildrop_file(
        &self,
        file_name: &str,
    ) -> Result<(tokio::fs::File, u64), TailscaleTaildropError> {
        self.taildrop.open_file(file_name).await
    }

    pub async fn delete_taildrop_file(
        &self,
        file_name: &str,
    ) -> Result<(), TailscaleTaildropError> {
        self.taildrop.delete_file(file_name).await
    }

    pub async fn cancel_taildrop_receiving(
        &self,
        sender_id: &str,
        file_name: &str,
    ) -> Result<(), TailscaleTaildropError> {
        self.taildrop.cancel_receiving(sender_id, file_name).await
    }

    pub(crate) fn dns_netmap_provider(
        &self,
    ) -> Arc<dyn TailscaleNetmapProvider> {
        Arc::new(self.clone())
    }

    pub(crate) fn certificate_endpoint(&self) -> TailscaleCertificateEndpoint {
        TailscaleCertificateEndpoint {
            netmap: self.netmap.clone(),
            control: self.certificate_control.clone(),
            state_directory: self.state_directory.clone(),
        }
    }
}

impl TailscaleNetmapProvider for TailscaleEndpointHandle {
    fn netmap(&self) -> Option<Arc<TailscaleNetmapState>> {
        self.netmap()
    }

    fn exit_node(&self) -> Option<String> {
        (!self.exit_node.is_empty()).then(|| self.exit_node.clone())
    }
}

/// Staged, embeddable Tailscale endpoint. Startup runs in the background so
/// an interactive control-server login does not block the owning Runtime.
pub struct TailscaleEndpointService {
    name: String,
    tag: String,
    options: TailscaleEndpointOptions,
    state_directory: PathBuf,
    transport_dialer: Arc<dyn Dialer>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    handle: TailscaleEndpointHandle,
    netmap: watch::Sender<Option<Arc<TailscaleNetmapState>>>,
    certificate_control:
        watch::Sender<Option<Arc<TailscaleCertificateControl>>>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TailscaleEndpointService {
    pub fn new(
        tag: impl Into<String>,
        options: TailscaleEndpointOptions,
        base_path: &Path,
        transport_dialer: Arc<dyn Dialer>,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> io::Result<(Self, TailscaleEndpointHandle)> {
        options.validate().map_err(invalid)?;
        let state_directory = if options.state_directory.is_empty() {
            base_path.join("tailscale")
        } else {
            let configured = PathBuf::from(&options.state_directory);
            if configured.is_absolute() {
                configured
            } else {
                base_path.join(configured)
            }
        };
        let taildrop_directory = if options.taildrop_directory.is_empty() {
            base_path.join("Taildrop")
        } else {
            let configured = PathBuf::from(&options.taildrop_directory);
            if configured.is_absolute() {
                configured
            } else {
                base_path.join(configured)
            }
        };
        let tag = tag.into();
        let (netmap, netmap_rx) = watch::channel(None);
        let (certificate_control, certificate_control_rx) =
            watch::channel(None);
        let (events, _) = broadcast::channel(EVENT_QUEUE_DEPTH);
        let handle = TailscaleEndpointHandle {
            dialer: Arc::new(TailscaleEndpointDialer::new(
                options.exit_node_allow_lan_access
                    && !options.exit_node.is_empty(),
            )),
            status: Arc::default(),
            netmap: netmap_rx,
            events,
            exit_node: options.exit_node.clone(),
            taildrop: TailscaleTaildropReceiver::from_directory(
                taildrop_directory,
            ),
            certificate_control: certificate_control_rx,
            state_directory: state_directory.clone(),
        };
        Ok((
            Self {
                name: format!("endpoint/{tag}"),
                tag,
                options,
                state_directory,
                transport_dialer,
                router,
                outbounds,
                handle: handle.clone(),
                netmap,
                certificate_control,
                cancellation: CancellationToken::new(),
                task: None,
            },
            handle,
        ))
    }
}

struct EndpointNetmapConsumer {
    inner: TailscaleDerpMapController,
    latest: watch::Sender<Option<Arc<TailscaleNetmapState>>>,
    dialer: Arc<TailscaleEndpointDialer>,
    ssh_policy: Arc<
        RwLock<
            Option<
                crate::protocol::tailscale_control_types::TailscaleSshPolicy,
            >,
        >,
    >,
}

#[async_trait]
impl TailscaleNetmapConsumer for EndpointNetmapConsumer {
    async fn apply_netmap(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> Result<(), String> {
        let routed = self.inner.routed_netmap(netmap);
        self.inner.apply_netmap(netmap).await?;
        self.dialer.set_netmap(&routed);
        if let Ok(mut policy) = self.ssh_policy.write() {
            *policy = netmap.ssh_policy.clone();
        }
        self.latest.send_replace(Some(Arc::new(netmap.clone())));
        Ok(())
    }
}

async fn register_rotated_tailscale_node_key(
    session: &mut dyn crate::protocol::tailscale_control_supervisor::TailscaleControlSession,
    request: &mut crate::protocol::tailscale_control_types::TailscaleRegisterRequest,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    loop {
        let response = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            result = session.register(request) => result.map_err(|error| error.to_string())?,
        };
        if !response.error.is_empty() {
            return Err(response.error);
        }
        if response.node_key_expired {
            return Err(
                "Tailscale control rejected the freshly rotated node key as expired"
                    .into(),
            );
        }
        if response.node_key_signature.is_some() {
            return Err(
                "Tailscale node key rotation requires TKA signature re-signing"
                    .into(),
            );
        }
        if response.machine_authorized {
            return Ok(());
        }
        if response.auth_url.is_empty() {
            return Err(
                "Tailscale rotated node key is not authorized and no AuthURL was returned"
                    .into(),
            );
        }
        if request.followup == response.auth_url {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
        request.followup = response.auth_url;
    }
}

#[allow(clippy::too_many_arguments)]
async fn rotate_tailscale_node_key(
    store: &TailscaleNodeStateStore,
    node_file: &mut TailscaleNodeFile,
    bootstrap: &TailscaleControlBootstrap,
    transport_dialer: Arc<dyn Dialer>,
    options: &TailscaleEndpointOptions,
    hostinfo: &TailscaleHostinfo,
    network_lock_key: &TailscaleNetworkLockPrivateKey,
    old_node_key_signature: Option<Vec<u8>>,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    let rotation = node_file
        .begin_node_key_rotation()
        .map_err(|error| error.to_string())?;
    let node_key_signature = old_node_key_signature
        .map(|signature| {
            resign_tailscale_node_key_signature(
                network_lock_key,
                rotation.new_node_key(),
                &signature,
            )
        })
        .transpose()
        .map_err(|error| error.to_string())?;
    let mut request = rotation.register_request(
        TAILSCALE_CAPABILITY_VERSION,
        options.auth_key.clone(),
        options.ephemeral,
        String::new(),
        node_key_signature,
        Some(hostinfo.clone()),
    );
    request.network_lock_key = network_lock_key.public_key();
    let mut tls_options = OutboundTlsOptions::default();
    tls_options.set_runtime_context(
        options.ntp_clock.clone(),
        options.certificate_store.clone(),
    );
    let connector = build_tailscale_control_connector(
        transport_dialer,
        bootstrap,
        node_file.machine_key.expose_secret(),
        TAILSCALE_CAPABILITY_VERSION as u16,
        Vec::new(),
        Some(&tls_options),
    )
    .map_err(|error| error.to_string())?;
    let mut session = tokio::select! {
        _ = cancellation.cancelled() => return Ok(()),
        result = connector.connect() => result.map_err(|error| error.to_string())?,
    };
    register_rotated_tailscale_node_key(
        session.as_mut(),
        &mut request,
        cancellation,
    )
    .await?;
    if cancellation.is_cancelled() {
        return Ok(());
    }
    store
        .commit_rotation(node_file, rotation)
        .await
        .map_err(|error| error.to_string())
}

fn taildrop_peer_access(
    netmap: &TailscaleNetmapState,
    source: IpAddr,
) -> Option<TailscaleTaildropPeerAccess> {
    let source = match source {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        source => source,
    };
    let peer = netmap.peers.values().find(|peer| {
        peer.addresses.iter().any(|address| {
            address
                .parse::<ipnet::IpNet>()
                .is_ok_and(|prefix| prefix.contains(&source))
        })
    })?;
    let self_node = netmap.node.as_ref()?;
    let mut peer_capabilities =
        peer.capabilities.iter().cloned().collect::<HashSet<_>>();
    peer_capabilities.extend(peer.capability_map.keys().cloned());
    Some(TailscaleTaildropPeerAccess {
        stable_id: peer.stable_id.clone(),
        name: peer.name.trim_end_matches('.').into(),
        unsigned_peer_api_only: peer.unsigned_peer_api_only,
        self_untagged: self_node.tags.is_empty(),
        peer_capabilities,
        self_file_sharing_enabled: self_node.capabilities.iter().any(|value| {
            value
                == crate::protocol::tailscale_taildrop::TAILSCALE_CAPABILITY_FILE_SHARING
        }) || self_node.capability_map.contains_key(
            crate::protocol::tailscale_taildrop::TAILSCALE_CAPABILITY_FILE_SHARING,
        ),
    })
}

async fn start_taildrop_peer_api(
    network: &TailscaleUserspaceNetwork,
    addresses: &[ipnet::IpNet],
    port: u16,
    receiver: TailscaleTaildropReceiver,
    netmap: watch::Receiver<Option<Arc<TailscaleNetmapState>>>,
    cancellation: CancellationToken,
) -> Result<Vec<JoinHandle<()>>, String> {
    let mut tasks = Vec::new();
    let mut bound = HashSet::new();
    for address in addresses {
        let address = SocketAddr::new(address.addr(), port);
        if !bound.insert(address) {
            continue;
        }
        let mut listener =
            network.tcp_bind(address).await.map_err(|error| {
                format!("bind Tailscale PeerAPI {address}: {error}")
            })?;
        let receiver = receiver.clone();
        let netmap = netmap.clone();
        let listener_cancellation = cancellation.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = listener_cancellation.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, source)) = accepted else {
                    break;
                };
                let receiver = receiver.clone();
                let access = netmap
                    .borrow()
                    .as_ref()
                    .and_then(|netmap| {
                        taildrop_peer_access(netmap, source.ip())
                    })
                    .unwrap_or_default();
                let connection_cancellation = listener_cancellation.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let receiver = receiver.clone();
                        let access = access.clone();
                        async move {
                            Ok::<_, Infallible>(
                                handle_tailscale_taildrop_request(
                                    &receiver, &access, request,
                                )
                                .await,
                            )
                        }
                    });
                    let connection = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service);
                    tokio::select! {
                        _ = connection_cancellation.cancelled() => {}
                        _ = connection => {}
                    }
                });
            }
        }));
    }
    if tasks.is_empty() {
        return Err("Tailscale PeerAPI has no bindable local address".into());
    }
    Ok(tasks)
}

#[allow(clippy::too_many_arguments)]
async fn start_tailscale_ssh_server(
    network: &TailscaleUserspaceNetwork,
    addresses: &[ipnet::IpNet],
    config: Arc<russh::server::Config>,
    policy: Arc<
        RwLock<
            Option<
                crate::protocol::tailscale_control_types::TailscaleSshPolicy,
            >,
        >,
    >,
    netmap: watch::Receiver<Option<Arc<TailscaleNetmapState>>>,
    dialer: Arc<dyn Dialer>,
    delegation_client: Option<Arc<dyn TailscaleSshDelegateClient>>,
    recording_notifier: Option<Arc<dyn TailscaleSshRecordingNotifier>>,
    node_key: String,
    capability_version: u32,
    options: crate::option::TailscaleSshServerOptions,
    cancellation: CancellationToken,
) -> Result<Vec<JoinHandle<()>>, String> {
    let mut tasks = Vec::new();
    let mut bound = HashSet::new();
    for address in addresses {
        let address = SocketAddr::new(address.addr(), 22);
        if !bound.insert(address) {
            continue;
        }
        let mut listener =
            network.tcp_bind(address).await.map_err(|error| {
                format!("bind Tailscale SSH listener {address}: {error}")
            })?;
        let config = config.clone();
        let policy = policy.clone();
        let netmap = netmap.clone();
        let dialer = dialer.clone();
        let delegation_client = delegation_client.clone();
        let recording_notifier = recording_notifier.clone();
        let node_key = node_key.clone();
        let listener_cancellation = cancellation.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = listener_cancellation.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, source)) = accepted else {
                    break;
                };
                let Some(peer) = netmap
                    .borrow()
                    .as_ref()
                    .and_then(|netmap| {
                        tailscale_ssh_peer_identity(netmap, source.ip())
                    })
                else {
                    continue;
                };
                let environment_capability = netmap
                    .borrow()
                    .as_ref()
                    .and_then(|netmap| netmap.node.as_ref())
                    .is_some_and(|node| {
                        node.capabilities.iter().any(|value| {
                            value
                                == TAILSCALE_CAPABILITY_SSH_ENVIRONMENT_VARIABLES
                        }) || node.capability_map.contains_key(
                            TAILSCALE_CAPABILITY_SSH_ENVIRONMENT_VARIABLES,
                        )
                    });
                let destination = netmap
                    .borrow()
                    .as_ref()
                    .and_then(|netmap| netmap.node.as_ref())
                    .and_then(|node| {
                        node.addresses
                            .iter()
                            .find_map(|address| {
                                address
                                    .parse::<ipnet::IpNet>()
                                    .ok()
                                    .map(|prefix| prefix.addr())
                            })
                            .map(|address| (address, node.id))
                    });
                let connection_cancellation =
                    listener_cancellation.child_token();
                let mut handler = TailscaleSshConnectionHandler::new(
                    policy.clone(),
                    peer,
                    source.ip(),
                    dialer.clone(),
                    options.disable_forwarding,
                )
                .with_connection_addresses(source, address)
                .with_session_backend(
                    Arc::new(TailscaleSshCurrentUserProcessBackend),
                    options.disable_pty,
                    options.disable_sftp,
                    environment_capability,
                );
                if let (Some(delegation_client), Some((destination_ip, destination_node_id))) =
                    (delegation_client.clone(), destination)
                {
                    handler = handler.with_delegation(
                        delegation_client,
                        destination_ip,
                        destination_node_id,
                        connection_cancellation.clone(),
                    );
                }
                if let Some(recording_notifier) = recording_notifier.clone() {
                    handler = handler.with_recording_notifier(
                        recording_notifier,
                        node_key.clone(),
                        capability_version,
                    );
                }
                let config = config.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = connection_cancellation.cancelled() => {}
                        _ = serve_tailscale_ssh_connection(config, stream, handler) => {}
                    }
                });
            }
        }));
    }
    if tasks.is_empty() {
        return Err("Tailscale SSH has no bindable local address".into());
    }
    Ok(tasks)
}

#[allow(clippy::too_many_arguments)]
async fn run_tailscale_endpoint(
    tag: String,
    options: TailscaleEndpointOptions,
    state_directory: PathBuf,
    transport_dialer: Arc<dyn Dialer>,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    dialer: Arc<TailscaleEndpointDialer>,
    status: Arc<RwLock<TailscaleEndpointStatus>>,
    latest_tx: watch::Sender<Option<Arc<TailscaleNetmapState>>>,
    endpoint_events: broadcast::Sender<TailscaleEndpointEvent>,
    taildrop: TailscaleTaildropReceiver,
    certificate_control_tx: watch::Sender<
        Option<Arc<TailscaleCertificateControl>>,
    >,
    cancellation: CancellationToken,
) -> Result<(), String> {
    update_endpoint_status(&status, |status| {
        status.phase = TailscaleEndpointPhase::Connecting;
        status.node_key_expired = false;
        status.last_error = None;
    });
    let control_url = if options.control_url.is_empty() {
        TAILSCALE_DEFAULT_CONTROL_URL
    } else {
        &options.control_url
    };
    let mut tls_options = OutboundTlsOptions::default();
    tls_options.set_runtime_context(
        options.ntp_clock.clone(),
        options.certificate_store.clone(),
    );
    let tls_options = Some(tls_options);
    let bootstrap = tokio::select! {
        _ = cancellation.cancelled() => return Ok(()),
        result = bootstrap_tailscale_control_with_tls_options(
            transport_dialer.clone(),
            control_url,
            TAILSCALE_CAPABILITY_VERSION,
            tls_options.as_ref(),
        ) => result.map_err(|error| error.to_string())?,
    };
    let store =
        TailscaleNodeStateStore::from_directory(state_directory.clone());
    let mut node_file = store
        .load_or_create(
            control_url,
            TailscaleMachinePublicKey::from_bytes(
                bootstrap
                    .control_public_key()
                    .map_err(|error| error.to_string())?,
            ),
        )
        .await
        .map_err(|error| error.to_string())?;
    let tka_state = store
        .load_or_create_tka()
        .await
        .map_err(|error| error.to_string())?;
    let network_lock_key = tka_state.network_lock_key.clone();
    let initial_tka_head = tka_state
        .authority()
        .map_err(|error| error.to_string())?
        .map(|authority| authority.head().to_string())
        .unwrap_or_default();
    let tka_synchronizer = Arc::new(TailscalePersistentTkaSynchronizer::new(
        store.clone(),
        tka_state,
    ));
    let disco_private =
        TailscalePrivateKey::generate().map_err(|error| error.to_string())?;
    let node_private = node_file.node_key.expose_secret();
    let node_public = node_file
        .node_key
        .public_bytes()
        .map_err(|error| error.to_string())?;
    let derp_manager =
        TailscaleDerpManager::spawn(TailscaleDerpManagerOptions::default());
    let socket = TailscaleDiscoSocket::bind_dual_stack(
        options.listen_port,
        Some(derp_manager),
        TailscaleDiscoSocketOptions::new(
            node_public,
            disco_private.expose_secret(),
        ),
    )
    .await
    .map_err(|error| error.to_string())?;
    let socket_handle = socket.handle();
    let mut port_mapping_task = socket_handle.local_addr().map(|address| {
        tokio::spawn(TailscalePortMapping::start(address.port()))
    });
    let mut port_mapping: Option<TailscalePortMapping> = None;
    let engine = TailscaleWireGuardEngine::spawn(
        socket,
        crate::protocol::tailscale_wireguard::TailscaleWireGuardOptions::new(
            node_private,
        ),
    )
    .map_err(|error| error.to_string())?;
    let engine_handle = engine.handle();
    let derp_controller = TailscaleDerpMapController::new_with_route_policy(
        engine_handle.clone(),
        transport_dialer.clone(),
        node_private,
        tls_options.clone(),
        TailscaleRoutePolicy {
            accept_routes: options.accept_routes,
            exit_node: options.exit_node.clone(),
        },
    );
    let mut latest_rx = latest_tx.subscribe();
    let ssh_policy = Arc::new(RwLock::new(None));
    let consumer = Arc::new(EndpointNetmapConsumer {
        inner: derp_controller,
        latest: latest_tx.clone(),
        dialer: dialer.clone(),
        ssh_policy: ssh_policy.clone(),
    });
    let hostname = if options.hostname.is_empty() {
        sysinfo::System::host_name().unwrap_or_else(|| "sing-box".into())
    } else {
        options.hostname.clone()
    };
    let mut routable_ips = options
        .advertise_routes
        .iter()
        .map(|prefix| prefix.0.to_string())
        .collect::<Vec<_>>();
    if options.advertise_exit_node {
        routable_ips.extend(["0.0.0.0/0".into(), "::/0".into()]);
    }
    let peer_api_port = if options.listen_port == 0 {
        rand::thread_rng().gen_range(49152..=u16::MAX)
    } else {
        options.listen_port
    };
    let ssh_identity = if options
        .ssh_server
        .is_some_and(|ssh_server| ssh_server.enabled)
    {
        Some(
            load_or_generate_tailscale_ssh_server_identity(&state_directory)
                .await
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    let hostinfo =
        crate::protocol::tailscale_control_types::TailscaleHostinfo {
            ipn_version: format!("sing-box/{}", crate::VERSION),
            os: std::env::consts::OS.into(),
            hostname,
            app: "sing-box".into(),
            package: "singbox-rust".into(),
            routable_ips,
            request_tags: options.advertise_tags.0.clone(),
            ssh_host_keys: ssh_identity
                .as_ref()
                .map(|identity| vec![identity.public_key.clone()])
                .unwrap_or_default(),
            services: vec![
                TailscaleService {
                    protocol: "peerapi4".into(),
                    port: peer_api_port,
                    description: String::new(),
                },
                TailscaleService {
                    protocol: "peerapi6".into(),
                    port: peer_api_port,
                    description: String::new(),
                },
            ],
            ..Default::default()
        };
    let mut register = node_file
        .register_request(
            TAILSCALE_CAPABILITY_VERSION,
            options.auth_key.clone(),
            options.ephemeral,
            Some(hostinfo.clone()),
        )
        .map_err(|error| error.to_string())?;
    register.network_lock_key = network_lock_key.public_key();
    let mut map = node_file
        .map_request(
            TAILSCALE_CAPABILITY_VERSION,
            disco_private
                .disco_public_key()
                .map_err(|error| error.to_string())?,
            Some(hostinfo.clone()),
            Vec::new(),
        )
        .map_err(|error| error.to_string())?;
    map.tka_head = initial_tka_head;
    let connector = Arc::new(
        build_tailscale_control_connector(
            transport_dialer.clone(),
            &bootstrap,
            node_file.machine_key.expose_secret(),
            TAILSCALE_CAPABILITY_VERSION as u16,
            Vec::new(),
            tls_options.as_ref(),
        )
        .map_err(|error| error.to_string())?,
    );
    let certificate_node_key = node_file
        .node_key
        .node_public_key()
        .map_err(|error| error.to_string())?;
    let ssh_node_key = certificate_node_key.to_string();
    certificate_control_tx.send_replace(Some(Arc::new(
        TailscaleCertificateControl {
            connector: connector.clone(),
            node_key: certificate_node_key,
        },
    )));
    let ssh_control_client =
        Arc::new(TailscaleSshControlDelegateClient::new(connector.clone()));
    let ssh_delegation_client: Arc<dyn TailscaleSshDelegateClient> =
        ssh_control_client.clone();
    let ssh_recording_notifier: Arc<dyn TailscaleSshRecordingNotifier> =
        ssh_control_client;
    let supervisor = TailscaleControlSupervisor::spawn_with_tka(
        connector,
        consumer,
        register,
        map,
        TailscaleControlSupervisorOptions::default(),
        Some(tka_synchronizer),
    );
    let mut control_events = supervisor.subscribe();
    let initial_netmap = loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                supervisor.close().await.map_err(|error| error.to_string())?;
                engine.close().await.map_err(|error| error.to_string())?;
                return Ok(());
            }
            event = control_events.recv() => {
                match event {
                    Ok(TailscaleControlSupervisorEvent::Registered { generation, machine_authorized, auth_url }) => {
                        update_endpoint_status(&status, |status| {
                            status.control_generation = generation;
                            status.auth_url = auth_url;
                            status.phase = if machine_authorized {
                                TailscaleEndpointPhase::Connecting
                            } else {
                                TailscaleEndpointPhase::NeedsLogin
                            };
                        });
                    }
                    Ok(TailscaleControlSupervisorEvent::Disconnected { error, .. }) => {
                        update_endpoint_status(&status, |status| status.last_error = Some(error));
                    }
                    Ok(TailscaleControlSupervisorEvent::DebugCommand { exit_code, disable_log_tail, sleep, .. }) => {
                        let _ = endpoint_events.send(TailscaleEndpointEvent::DebugCommand {
                            exit_code,
                            disable_log_tail,
                            sleep,
                        });
                    }
                    Ok(TailscaleControlSupervisorEvent::NodeKeyRotationRequired { node_key_signature, .. }) => {
                        update_endpoint_status(&status, |status| {
                            status.node_key_expired = true;
                        });
                        let _ = endpoint_events.send(TailscaleEndpointEvent::NodeKeyRotationRequired {
                            node_key_signature: node_key_signature.clone(),
                        });
                        if let Some(task) = port_mapping_task.take() {
                            task.abort();
                        }
                        supervisor.close().await.map_err(|error| error.to_string())?;
                        engine.close().await.map_err(|error| error.to_string())?;
                        if let Some(mapping) = port_mapping.take() {
                            mapping.close().await;
                        }
                        rotate_tailscale_node_key(
                            &store,
                            &mut node_file,
                            &bootstrap,
                            transport_dialer.clone(),
                            &options,
                            &hostinfo,
                            &network_lock_key,
                            node_key_signature,
                            &cancellation,
                        ).await?;
                        latest_tx.send_replace(None);
                        return Box::pin(run_tailscale_endpoint(
                            tag,
                            options,
                            state_directory,
                            transport_dialer,
                            router,
                            outbounds,
                            dialer,
                            status,
                            latest_tx,
                            endpoint_events,
                            taildrop,
                            certificate_control_tx,
                            cancellation,
                        )).await;
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return Err("Tailscale control supervisor closed".into()),
                }
            }
            changed = latest_rx.changed() => {
                changed.map_err(|_| "Tailscale netmap stream closed".to_owned())?;
                if let Some(netmap) = latest_rx.borrow().clone()
                    && netmap.node.as_ref().is_some_and(|node| !node.addresses.is_empty())
                {
                    break netmap;
                }
            }
        }
    };
    let endpoint_report = tokio::select! {
        _ = cancellation.cancelled() => {
            supervisor.close().await.map_err(|error| error.to_string())?;
            engine.close().await.map_err(|error| error.to_string())?;
            return Ok(());
        }
        result = discover_tailscale_endpoints(
            &socket_handle,
            &initial_netmap,
            TAILSCALE_STUN_PROBE_TIMEOUT,
        ) => result.map_err(|error| error.to_string())?,
    };
    let mut advertised_endpoints = endpoint_report
        .endpoints
        .iter()
        .map(|endpoint| endpoint.address)
        .collect::<Vec<_>>();
    socket_handle
        .set_advertised_endpoints(advertised_endpoints.clone())
        .map_err(|error| error.to_string())?;
    let (mut map_endpoints, mut endpoint_types) =
        endpoint_report.map_request_values();
    supervisor
        .update_endpoints(map_endpoints.clone(), endpoint_types.clone())
        .map_err(|error| error.to_string())?;
    let mut network_config =
        TailscaleUserspaceNetworkConfig::from_netmap(&initial_netmap)
            .map_err(|error| error.to_string())?;
    network_config.udp_timeout = options
        .udp_timeout
        .0
        .as_std()
        .filter(|duration| !duration.is_zero())
        .unwrap_or(crate::constant::UDP_TIMEOUT);
    let addresses = network_config.addresses.clone();
    let network = TailscaleUserspaceNetwork::start_routed(
        tag.clone(),
        engine,
        network_config,
        router.clone(),
        outbounds.clone(),
    )
    .map_err(|error| error.to_string())?;
    let peer_api_cancellation = cancellation.child_token();
    let peer_api_tasks = start_taildrop_peer_api(
        &network,
        &addresses,
        peer_api_port,
        taildrop.clone(),
        latest_tx.subscribe(),
        peer_api_cancellation.clone(),
    )
    .await?;
    let ssh_cancellation = cancellation.child_token();
    let ssh_tasks = if let (Some(identity), Some(ssh_options)) =
        (ssh_identity, options.ssh_server)
    {
        start_tailscale_ssh_server(
            &network,
            &addresses,
            identity.config,
            ssh_policy,
            latest_tx.subscribe(),
            dialer.clone(),
            Some(ssh_delegation_client),
            Some(ssh_recording_notifier),
            ssh_node_key,
            TAILSCALE_CAPABILITY_VERSION,
            ssh_options,
            ssh_cancellation.clone(),
        )
        .await?
    } else {
        Vec::new()
    };
    dialer.set_network(Some(network.dialer()));
    update_endpoint_status(&status, |status| {
        status.phase = TailscaleEndpointPhase::Running;
        status.addresses = addresses;
        status.endpoints = advertised_endpoints.clone();
        status.auth_url.clear();
        status.last_error = None;
    });
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut restun = tokio::time::interval(TAILSCALE_RESTUN_INTERVAL);
    let mut rotation_signature = None;
    restun.tick().await;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            event = control_events.recv() => {
                match event {
                    Ok(TailscaleControlSupervisorEvent::Registered { generation, machine_authorized, auth_url }) => {
                        update_endpoint_status(&status, |status| {
                            status.control_generation = generation;
                            status.auth_url = auth_url;
                            if !machine_authorized {
                                status.phase = TailscaleEndpointPhase::NeedsLogin;
                            }
                        });
                    }
                    Ok(TailscaleControlSupervisorEvent::Disconnected { error, .. }) => {
                        update_endpoint_status(&status, |status| status.last_error = Some(error));
                    }
                    Ok(TailscaleControlSupervisorEvent::DebugCommand { exit_code, disable_log_tail, sleep, .. }) => {
                        let _ = endpoint_events.send(TailscaleEndpointEvent::DebugCommand {
                            exit_code,
                            disable_log_tail,
                            sleep,
                        });
                    }
                    Ok(TailscaleControlSupervisorEvent::NodeKeyRotationRequired { node_key_signature, .. }) => {
                        update_endpoint_status(&status, |status| {
                            status.node_key_expired = true;
                        });
                        let _ = endpoint_events.send(TailscaleEndpointEvent::NodeKeyRotationRequired {
                            node_key_signature: node_key_signature.clone(),
                        });
                        rotation_signature = Some(node_key_signature);
                        break;
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = interval.tick() => {
                let control = supervisor.status();
                let wireguard = network.engine().status();
                update_endpoint_status(&status, |status| {
                    status.control_generation = control.generation;
                    status.peers = wireguard.peers;
                    status.last_error = control.last_error.or(wireguard.last_error);
                });
            }
            _ = restun.tick() => {
                let Some(netmap) = latest_rx.borrow().clone() else {
                    continue;
                };
                match discover_tailscale_endpoints(
                    &socket_handle,
                    &netmap,
                    TAILSCALE_STUN_PROBE_TIMEOUT,
                ).await {
                    Ok(mut report) => {
                        if let Some(address) = port_mapping
                            .as_ref()
                            .and_then(TailscalePortMapping::external_addr)
                        {
                            report.add_port_mapped_endpoint(address);
                        }
                        let all_stun_failed = !report.stun_servers_tried.is_empty()
                            && report.stun_failures.len() == report.stun_servers_tried.len();
                        let (new_endpoints, new_types) = report.map_request_values();
                        if !all_stun_failed
                            && (new_endpoints != map_endpoints || new_types != endpoint_types)
                        {
                            advertised_endpoints = report
                                .endpoints
                                .iter()
                                .map(|endpoint| endpoint.address)
                                .collect();
                            socket_handle
                                .set_advertised_endpoints(advertised_endpoints.clone())
                                .map_err(|error| error.to_string())?;
                            supervisor
                                .update_endpoints(new_endpoints.clone(), new_types.clone())
                                .map_err(|error| error.to_string())?;
                            map_endpoints = new_endpoints;
                            endpoint_types = new_types;
                            update_endpoint_status(&status, |status| {
                                status.endpoints = advertised_endpoints.clone();
                            });
                        }
                    }
                    Err(error) => {
                        update_endpoint_status(&status, |status| {
                            status.last_error = Some(format!("Tailscale endpoint discovery failed: {error}"));
                        });
                    }
                }
            }
            mapping_result = async {
                match port_mapping_task.as_mut() {
                    Some(task) => Some(task.await),
                    None => std::future::pending().await,
                }
            }, if port_mapping_task.is_some() => {
                port_mapping_task = None;
                if let Some(Ok(Ok(mapping))) = mapping_result
                    && let Some(address) = mapping.external_addr()
                {
                    let address_text = address.to_string();
                    if let Some(index) = map_endpoints
                        .iter()
                        .position(|endpoint| endpoint == &address_text)
                    {
                        map_endpoints.remove(index);
                        endpoint_types.remove(index);
                    }
                    map_endpoints.insert(0, address_text);
                    endpoint_types.insert(0, 3);
                    advertised_endpoints.retain(|endpoint| *endpoint != address);
                    advertised_endpoints.insert(0, address);
                    socket_handle
                        .set_advertised_endpoints(advertised_endpoints.clone())
                        .map_err(|error| error.to_string())?;
                    supervisor
                        .update_endpoints(map_endpoints.clone(), endpoint_types.clone())
                        .map_err(|error| error.to_string())?;
                    update_endpoint_status(&status, |status| {
                        status.endpoints = advertised_endpoints.clone();
                    });
                    port_mapping = Some(mapping);
                }
            }
        }
    }
    if let Some(task) = port_mapping_task {
        task.abort();
    }
    peer_api_cancellation.cancel();
    for task in peer_api_tasks {
        let _ = task.await;
    }
    ssh_cancellation.cancel();
    for task in ssh_tasks {
        let _ = task.await;
    }
    dialer.set_network(None);
    supervisor
        .close()
        .await
        .map_err(|error| error.to_string())?;
    network.close().await.map_err(|error| error.to_string())?;
    if let Some(mapping) = port_mapping {
        mapping.close().await;
    }
    if let Some(node_key_signature) = rotation_signature {
        rotate_tailscale_node_key(
            &store,
            &mut node_file,
            &bootstrap,
            transport_dialer.clone(),
            &options,
            &hostinfo,
            &network_lock_key,
            node_key_signature,
            &cancellation,
        )
        .await?;
        latest_tx.send_replace(None);
        return Box::pin(run_tailscale_endpoint(
            tag,
            options,
            state_directory,
            transport_dialer,
            router,
            outbounds,
            dialer,
            status,
            latest_tx,
            endpoint_events,
            taildrop,
            certificate_control_tx,
            cancellation,
        ))
        .await;
    }
    Ok(())
}

fn update_endpoint_status(
    status: &RwLock<TailscaleEndpointStatus>,
    update: impl FnOnce(&mut TailscaleEndpointStatus),
) {
    if let Ok(mut status) = status.write() {
        update(&mut status);
    }
}

impl Lifecycle for TailscaleEndpointService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.handle.taildrop.start().await.map_err(|error| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                }
            })?;
            self.cancellation = CancellationToken::new();
            let options = self.options.clone();
            let tag = self.tag.clone();
            let state_directory = self.state_directory.clone();
            let transport_dialer = self.transport_dialer.clone();
            let router = self.router.clone();
            let outbounds = self.outbounds.clone();
            let dialer = self.handle.dialer.clone();
            let status = self.handle.status.clone();
            let netmap = self.netmap.clone();
            let events = self.handle.events.clone();
            let taildrop = self.handle.taildrop.clone();
            let certificate_control = self.certificate_control.clone();
            let cancellation = self.cancellation.clone();
            self.task = Some(tokio::spawn(async move {
                let result = run_tailscale_endpoint(
                    tag,
                    options,
                    state_directory,
                    transport_dialer,
                    router,
                    outbounds,
                    dialer,
                    status.clone(),
                    netmap,
                    events,
                    taildrop,
                    certificate_control.clone(),
                    cancellation,
                )
                .await;
                certificate_control.send_replace(None);
                if let Err(error) = result {
                    update_endpoint_status(&status, |status| {
                        status.phase = TailscaleEndpointPhase::Failed;
                        status.last_error = Some(error);
                    });
                }
            }));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            self.handle.dialer.set_network(None);
            self.handle.taildrop.close().await;
            if let Some(task) = self.task.take() {
                task.await.map_err(|error| LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                })?;
            }
            update_endpoint_status(&self.handle.status, |status| {
                status.phase = TailscaleEndpointPhase::Stopped;
            });
            Ok(())
        })
    }
}

impl Dialer for TailscaleUserspaceDialer {
    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        Some(self.packet_port.clone())
    }

    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let addresses = destination.resolve().await?;
            let mut last_error = None;
            let local_port = self.net.get_port();
            for address in addresses {
                match self.net.tcp_connect(address, local_port).await {
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
            let addresses = destination.resolve().await?;
            let mut last_error = None;
            for destination in addresses {
                let bind = match destination {
                    SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                    SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
                };
                match self.net.udp_bind(bind).await {
                    Ok(socket) => {
                        return Ok(Box::new(TailscalePacketConnection {
                            socket: Arc::new(socket),
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
            let destination = destination
                .resolve()
                .await?
                .into_iter()
                .find(|destination| destination.is_ipv4() == source.is_ipv4())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "no compatible Tailscale ICMP destination",
                    )
                })?;
            self.net
                .exchange_icmp(
                    packet,
                    source,
                    destination.ip(),
                    hop_limit,
                    crate::constant::ICMP_TIMEOUT,
                )
                .await
        })
    }
}

struct TailscalePacketConnection {
    socket: Arc<SmoltcpUdpSocket>,
}

impl PacketConnection for TailscalePacketConnection {
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
            let destination = destination
                .resolve()
                .await?
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
            self.socket.send_to(data, destination).await
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

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    use boringtun::x25519::{PublicKey, StaticSecret};
    use russh::{client, keys::PublicKey as SshPublicKey};
    use std::{collections::VecDeque, sync::Mutex};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct AcceptSshHostKey;

    impl client::Handler for AcceptSshHostKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &SshPublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[test]
    fn peer_api_source_is_mapped_to_taildrop_access_policy() {
        let mut netmap = TailscaleNetmapState {
            node: Some(crate::protocol::tailscale_control_types::TailscaleNode {
                capabilities: vec![
                    crate::protocol::tailscale_taildrop::TAILSCALE_CAPABILITY_FILE_SHARING
                        .into(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        netmap.peers.insert(
            1,
            crate::protocol::tailscale_control_types::TailscaleNode {
                stable_id: "peer-1".into(),
                name: "alice.tail.example.".into(),
                addresses: vec!["100.64.0.2/32".into()],
                capability_map: [(
                    crate::protocol::tailscale_taildrop::TAILSCALE_PEER_CAPABILITY_FILE_SHARING_SEND
                        .into(),
                    Vec::new(),
                )]
                .into(),
                ..Default::default()
            },
        );
        let access = taildrop_peer_access(
            &netmap,
            "100.64.0.2".parse::<IpAddr>().unwrap(),
        )
        .unwrap();
        assert_eq!(access.stable_id, "peer-1");
        assert_eq!(access.name, "alice.tail.example");
        assert!(access.self_untagged);
        assert!(access.self_file_sharing_enabled);
        assert!(access.peer_capabilities.contains(
            crate::protocol::tailscale_taildrop::TAILSCALE_PEER_CAPABILITY_FILE_SHARING_SEND
        ));
        assert!(
            taildrop_peer_access(
                &netmap,
                "100.64.0.3".parse::<IpAddr>().unwrap()
            )
            .is_none()
        );
    }

    use crate::protocol::{
        tailscale_control::TailscaleControlError,
        tailscale_control_supervisor::{
            TailscaleControlMapStream, TailscaleControlSession,
        },
        tailscale_control_types::{
            TailscaleDnsConfig, TailscaleDnsRecord, TailscaleMapRequest,
            TailscaleNode, TailscaleNodePublicKey, TailscaleRegisterRequest,
            TailscaleRegisterResponse,
        },
        tailscale_disco::tailscale_disco_public_key,
        tailscale_disco_socket::{
            TailscaleDiscoSocket, TailscaleDiscoSocketEvent,
            TailscaleDiscoSocketOptions,
        },
        tailscale_wireguard::{
            TailscaleWireGuardOptions, TailscaleWireGuardPeer,
        },
    };

    struct RotationSession {
        requests: Arc<Mutex<Vec<TailscaleRegisterRequest>>>,
        responses: VecDeque<TailscaleRegisterResponse>,
    }

    #[async_trait]
    impl TailscaleControlSession for RotationSession {
        async fn register(
            &mut self,
            request: &TailscaleRegisterRequest,
        ) -> Result<TailscaleRegisterResponse, TailscaleControlError> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(self.responses.pop_front().unwrap())
        }

        async fn start_map(
            &mut self,
            _request: &TailscaleMapRequest,
        ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>
        {
            panic!("rotation registration must not start a map stream")
        }
    }

    #[tokio::test]
    async fn rotated_node_key_registration_completes_followup_before_commit() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut session = RotationSession {
            requests: requests.clone(),
            responses: VecDeque::from([
                TailscaleRegisterResponse {
                    auth_url: "https://login.example/rotated".into(),
                    ..Default::default()
                },
                TailscaleRegisterResponse {
                    machine_authorized: true,
                    ..Default::default()
                },
            ]),
        };
        let mut request = TailscaleRegisterRequest {
            old_node_key: TailscaleNodePublicKey::from_bytes([1; 32]),
            node_key: TailscaleNodePublicKey::from_bytes([2; 32]),
            ..Default::default()
        };
        register_rotated_tailscale_node_key(
            &mut session,
            &mut request,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].old_node_key.as_bytes(), &[1; 32]);
        assert_eq!(requests[0].node_key.as_bytes(), &[2; 32]);
        assert!(requests[0].followup.is_empty());
        assert_eq!(requests[1].followup, "https://login.example/rotated");
    }

    #[tokio::test]
    async fn stable_endpoint_dialer_reports_readiness_and_dynamic_routes() {
        let dialer = TailscaleEndpointDialer::default();
        let destination = SocksAddr::new("100.64.0.2", 80);
        let error = match dialer.dial_tcp(&destination).await {
            Ok(_) => panic!("unready Tailscale endpoint unexpectedly dialed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        let mut netmap = TailscaleNetmapState::default();
        netmap.peers.insert(
            2,
            TailscaleNode {
                id: 2,
                key: TailscaleNodePublicKey::from_bytes([2; 32]),
                allowed_ips: vec![
                    "100.64.0.2/32".into(),
                    "10.0.0.0/8".into(),
                    "0.0.0.0/0".into(),
                    "::/0".into(),
                ],
                ..Default::default()
            },
        );
        netmap.dns_config = Some(TailscaleDnsConfig {
            routes: [("corp.example.".into(), Vec::new())].into(),
            domains: vec!["tailnet.ts.net.".into()],
            extra_records: vec![TailscaleDnsRecord {
                name: "service.corp.example.".into(),
                record_type: "A".into(),
                value: "100.64.0.9".into(),
            }],
            ..Default::default()
        });
        dialer.set_netmap(&netmap);
        assert!(dialer.preferred_address("100.64.0.2".parse().unwrap()));
        assert!(dialer.preferred_address("10.1.2.3".parse().unwrap()));
        assert!(!dialer.preferred_address("192.0.2.1".parse().unwrap()));
        assert!(dialer.preferred_domain("host.corp.example"));
        assert!(dialer.preferred_domain("service.corp.example"));
        assert!(dialer.preferred_domain("printer"));
        assert!(!dialer.preferred_domain("public.example"));
    }

    #[test]
    fn exit_node_lan_access_bypasses_live_interface_prefixes() {
        let dialer = TailscaleEndpointDialer::new(true);
        *dialer.lan_prefixes.write().unwrap() = vec![
            "192.168.50.0/24".parse().unwrap(),
            "fd00:1234::/64".parse().unwrap(),
        ];
        assert!(
            dialer.should_bypass_lan(&SocksAddr::new("192.168.50.20", 443))
        );
        assert!(
            dialer
                .selected(&SocksAddr::new("192.168.50.20", 443))
                .is_ok()
        );
        assert!(
            dialer.should_bypass_lan(&SocksAddr::new("fd00:1234::20", 443))
        );
        assert!(!dialer.should_bypass_lan(&SocksAddr::new("8.8.8.8", 53)));
        assert_eq!(
            dialer
                .selected(&SocksAddr::new("8.8.8.8", 53))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotConnected
        );

        let disabled = TailscaleEndpointDialer::new(false);
        *disabled.lan_prefixes.write().unwrap() =
            vec!["192.168.50.0/24".parse().unwrap()];
        assert!(
            !disabled.should_bypass_lan(&SocksAddr::new("192.168.50.20", 443))
        );
    }

    fn node_keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = [seed; 32];
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        (private, public)
    }

    fn peer(
        node_key: [u8; 32],
        disco_key: [u8; 32],
        endpoint: SocketAddr,
        allowed_ip: &str,
    ) -> TailscaleWireGuardPeer {
        TailscaleWireGuardPeer {
            node_key,
            disco_key,
            home_derp_region: None,
            endpoints: vec![endpoint],
            allowed_ips: vec![allowed_ip.parse().unwrap()],
        }
    }

    async fn wait_path(engine: &mut TailscaleWireGuardEngine, peer: [u8; 32]) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(TailscaleWireGuardEvent::Transport(
                    TailscaleDiscoSocketEvent::PathChanged {
                        peer: changed,
                        best: Some(_),
                    },
                )) = engine.next_event().await
                    && changed == peer
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn userspace_network_carries_udp_over_dynamic_wireguard() {
        let (private_a, node_a) = node_keys(71);
        let (private_b, node_b) = node_keys(72);
        let disco_private_a = [73; 32];
        let disco_private_b = [74; 32];
        let disco_a = tailscale_disco_public_key(disco_private_a).unwrap();
        let disco_b = tailscale_disco_public_key(disco_private_b).unwrap();
        let socket_a = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new(node_a, disco_private_a),
        )
        .await
        .unwrap();
        let address_a = socket_a.local_addr().unwrap();
        let socket_b = TailscaleDiscoSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            TailscaleDiscoSocketOptions::new(node_b, disco_private_b),
        )
        .await
        .unwrap();
        let address_b = socket_b.local_addr().unwrap();
        let mut engine_a = TailscaleWireGuardEngine::spawn(
            socket_a,
            TailscaleWireGuardOptions::new(private_a),
        )
        .unwrap();
        let mut engine_b = TailscaleWireGuardEngine::spawn(
            socket_b,
            TailscaleWireGuardOptions::new(private_b),
        )
        .unwrap();
        engine_a
            .set_peers(vec![peer(node_b, disco_b, address_b, "100.64.0.2/32")])
            .await
            .unwrap();
        engine_b
            .set_peers(vec![peer(node_a, disco_a, address_a, "100.64.0.1/32")])
            .await
            .unwrap();
        engine_a.probe_peer(node_b).unwrap();
        engine_b.probe_peer(node_a).unwrap();
        wait_path(&mut engine_a, node_b).await;
        wait_path(&mut engine_b, node_a).await;

        let network_a = TailscaleUserspaceNetwork::start(
            engine_a,
            TailscaleUserspaceNetworkConfig::new(vec![
                "100.64.0.1/32".parse().unwrap(),
            ]),
        )
        .unwrap();
        let network_b = TailscaleUserspaceNetwork::start(
            engine_b,
            TailscaleUserspaceNetworkConfig::new(vec![
                "100.64.0.2/32".parse().unwrap(),
            ]),
        )
        .unwrap();
        let destination_a =
            SocksAddr::from("100.64.0.1:9".parse::<SocketAddr>().unwrap());
        let receiver =
            network_b.dialer().listen_udp(&destination_a).await.unwrap();
        let receiver_address = receiver.local_addr().unwrap().unwrap();
        let destination_b = SocksAddr::from(receiver_address);
        let sender =
            network_a.dialer().listen_udp(&destination_b).await.unwrap();
        sender
            .send_to(b"tailnet-udp", &destination_b)
            .await
            .unwrap();

        let mut buffer = [0_u8; 64];
        let (size, source) = tokio::time::timeout(
            Duration::from_secs(5),
            receiver.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..size], b"tailnet-udp");
        assert!(matches!(source, SocksAddr::Ip(_)));

        let directory = tempfile::tempdir().unwrap();
        let taildrop = TailscaleTaildropReceiver::new(directory.path())
            .await
            .unwrap();
        let mut server_netmap = TailscaleNetmapState {
            node: Some(crate::protocol::tailscale_control_types::TailscaleNode {
                addresses: vec!["100.64.0.2/32".into()],
                capabilities: vec![
                    crate::protocol::tailscale_taildrop::TAILSCALE_CAPABILITY_FILE_SHARING
                        .into(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        server_netmap.peers.insert(
            1,
            crate::protocol::tailscale_control_types::TailscaleNode {
                id: 1,
                stable_id: "peer-a".into(),
                name: "alice.tail.example.".into(),
                user: 8,
                addresses: vec!["100.64.0.1/32".into()],
                ..Default::default()
            },
        );
        server_netmap.user_profiles.insert(
            8,
            crate::protocol::tailscale_control_types::TailscaleUserProfile {
                id: 8,
                login_name: "alice@example.com".into(),
                ..Default::default()
            },
        );
        server_netmap.ssh_policy = Some(
            crate::protocol::tailscale_control_types::TailscaleSshPolicy {
                rules: vec![
                    crate::protocol::tailscale_control_types::TailscaleSshRule {
                        principals: vec![
                            crate::protocol::tailscale_control_types::TailscaleSshPrincipal {
                                user_login: "alice@example.com".into(),
                                ..Default::default()
                            },
                        ],
                        ssh_users: [("root".into(), "operator".into())].into(),
                        action: Some(
                            crate::protocol::tailscale_control_types::TailscaleSshAction {
                                accept: true,
                                allow_local_port_forwarding: true,
                                ..Default::default()
                            },
                        ),
                        ..Default::default()
                    },
                ],
            },
        );
        let (server_netmap_tx, server_netmap_rx) =
            watch::channel(Some(Arc::new(server_netmap)));
        let peer_api_cancellation = CancellationToken::new();
        let peer_api_tasks = start_taildrop_peer_api(
            &network_b,
            &["100.64.0.2/32".parse().unwrap()],
            41112,
            taildrop.clone(),
            server_netmap_rx.clone(),
            peer_api_cancellation.clone(),
        )
        .await
        .unwrap();

        let ssh_identity =
            load_or_generate_tailscale_ssh_server_identity(directory.path())
                .await
                .unwrap();
        let ssh_policy = Arc::new(RwLock::new(
            server_netmap_rx
                .borrow()
                .as_ref()
                .and_then(|netmap| netmap.ssh_policy.clone()),
        ));
        let ssh_cancellation = CancellationToken::new();
        let ssh_tasks = start_tailscale_ssh_server(
            &network_b,
            &["100.64.0.2/32".parse().unwrap()],
            ssh_identity.config,
            ssh_policy,
            server_netmap_rx.clone(),
            Arc::new(DirectOutbound::new(
                crate::option::DirectOutboundOptions::default(),
            )),
            None,
            None,
            String::new(),
            0,
            crate::option::TailscaleSshServerOptions {
                enabled: true,
                ..Default::default()
            },
            ssh_cancellation.clone(),
        )
        .await
        .unwrap();

        let mut client_netmap = TailscaleNetmapState {
            node: Some(crate::protocol::tailscale_control_types::TailscaleNode {
                user: 7,
                capabilities: vec![
                    crate::protocol::tailscale_taildrop::TAILSCALE_CAPABILITY_FILE_SHARING
                        .into(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        client_netmap.peers.insert(
            2,
            crate::protocol::tailscale_control_types::TailscaleNode {
                stable_id: "peer-b".into(),
                user: 7,
                addresses: vec!["100.64.0.2/32".into()],
                hostinfo: Some(TailscaleHostinfo {
                    services: vec![TailscaleService {
                        protocol: "peerapi4".into(),
                        port: 41112,
                        description: String::new(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        send_tailscale_taildrop_file(
            network_a.dialer(),
            &client_netmap,
            "peer-b",
            "over-wireguard.txt",
            8,
            std::io::Cursor::new(b"taildrop".to_vec()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            tokio::fs::read(directory.path().join("over-wireguard.txt"))
                .await
                .unwrap(),
            b"taildrop"
        );

        let target =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let ssh_stream = network_a
            .dialer()
            .dial_tcp(&SocksAddr::new("100.64.0.2", 22))
            .await
            .unwrap();
        let mut ssh_client = client::connect_stream(
            Arc::new(client::Config::default()),
            ssh_stream,
            AcceptSshHostKey,
        )
        .await
        .unwrap();
        assert!(
            ssh_client
                .authenticate_password("root", "ignored-by-tailnet-policy")
                .await
                .unwrap()
                .success()
        );
        let channel = ssh_client
            .channel_open_direct_tcpip(
                target_address.ip().to_string(),
                u32::from(target_address.port()),
                "100.64.0.1",
                12345,
            )
            .await
            .unwrap();
        let mut forwarded = channel.into_stream();
        forwarded.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        forwarded.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        drop(forwarded);
        drop(ssh_client);
        echo.await.unwrap();

        drop(server_netmap_tx);
        peer_api_cancellation.cancel();
        for task in peer_api_tasks {
            task.await.unwrap();
        }
        ssh_cancellation.cancel();
        for task in ssh_tasks {
            task.await.unwrap();
        }
        network_a.close().await.unwrap();
        network_b.close().await.unwrap();
    }
}
