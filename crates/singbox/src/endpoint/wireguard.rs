//! WireGuard userspace packet engine used by the endpoint implementation.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};
use tokio::sync::mpsc;
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
    userspace_router::UserspaceEndpointRouter,
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
    option::{DomainStrategy, UdpNatBehavior, WireGuardEndpointOptions},
    outbound::OutboundManager,
    route::Router,
};

const MIN_PACKET_BUFFER: usize = 2048;
const WIREGUARD_OVERHEAD: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireGuardAction {
    WriteToNetwork(Vec<u8>),
    WriteToTunnelV4(Vec<u8>, IpAddr),
    WriteToTunnelV6(Vec<u8>, IpAddr),
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPacket {
    pub data: Vec<u8>,
    pub source: IpAddr,
    pub peer_index: usize,
}

/// Decode the 32-byte standard-base64 key format used by wg(8) and sing-box.
pub fn decode_key(value: &str) -> io::Result<[u8; 32]> {
    let decoded = STANDARD.decode(value).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid WireGuard base64 key: {error}"),
        )
    })?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid WireGuard key length: expected 32 bytes, got {}",
                decoded.len()
            ),
        )
    })
}

/// One NoiseIK tunnel to a configured WireGuard peer.
///
/// Boringtun's state machine is synchronous. The mutex makes a peer safe to
/// share between Tokio tasks, and results are copied out of the temporary
/// destination buffer so they can be queued independently.
pub struct WireGuardPeerTunnel {
    tunnel: Mutex<Tunn>,
}

struct WireGuardRuntimePeer {
    index: usize,
    tunnel: WireGuardPeerTunnel,
    connection: Arc<dyn PacketConnection>,
    destination: RwLock<SocksAddr>,
    allowed_ips: Vec<ipnet::IpNet>,
    reserved: [u8; 3],
}

/// Running userspace WireGuard UDP endpoint.
///
/// Without `listen_port`, the endpoint owns one routed UDP packet connection
/// per peer so arbitrary outbound detours remain usable. With `listen_port`,
/// peers share one bound socket and authenticated packets are dispatched to
/// the matching Noise tunnel. Both modes preserve roaming, reserved bytes,
/// timers and longest-prefix packet routing. Platform TUN creation remains a
/// separate layer.
pub struct WireGuardEndpoint {
    config: WireGuardEndpointConfig,
    peers: Vec<Arc<WireGuardRuntimePeer>>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<io::Result<WireGuardPacket>>>,
    cancellation: CancellationToken,
}

/// A userspace TCP/IP stack whose IP packets are carried by WireGuard.
struct WireGuardNetwork {
    net: Arc<Net>,
    cancellation: CancellationToken,
    _flow_router: Option<Arc<UserspaceEndpointRouter>>,
    _tasks: Vec<AbortOnDropHandle<()>>,
}

/// Raw-IP port shared by the stable endpoint dialer and the running
/// WireGuard transport. Keeping it separate from the lifecycle-owned endpoint
/// lets route tables retain a stable `Arc<dyn Dialer>` across restarts.
struct WireGuardPacketPort {
    endpoint: RwLock<Option<Arc<WireGuardEndpoint>>>,
    inet4_address: Option<IpAddr>,
    inet6_address: Option<IpAddr>,
    mtu: usize,
    return_path: RwLock<Option<Weak<dyn IpPacketReturn>>>,
}

/// Stable dialer registered before the endpoint lifecycle starts. Its network
/// is activated during `Start` and removed during `Close`.
pub struct WireGuardDialer {
    net: RwLock<Option<Arc<Net>>>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
    packet_port: Arc<WireGuardPacketPort>,
}

#[derive(Clone, Default)]
pub struct WireGuardEndpointHandle {
    endpoint: Arc<Mutex<Option<Arc<WireGuardEndpoint>>>>,
    network: Arc<Mutex<Option<Arc<WireGuardNetwork>>>>,
    dialer: Arc<WireGuardDialer>,
}

impl WireGuardEndpointHandle {
    pub fn endpoint(&self) -> Option<Arc<WireGuardEndpoint>> {
        self.endpoint.lock().ok()?.clone()
    }

    pub fn dialer(&self) -> Arc<dyn Dialer> {
        self.dialer.clone()
    }
}

pub struct WireGuardEndpointService {
    name: String,
    tag: String,
    config: WireGuardEndpointConfig,
    dialer: Arc<dyn Dialer>,
    flow_router: Option<(Arc<Router>, Arc<OutboundManager>)>,
    handle: WireGuardEndpointHandle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeerConfig {
    pub address: String,
    pub port: u16,
    pub public_key: [u8; 32],
    pub pre_shared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<ipnet::IpNet>,
    pub persistent_keepalive_interval: u16,
    pub reserved: [u8; 3],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardEndpointConfig {
    pub private_key: [u8; 32],
    pub mtu: u32,
    pub addresses: Vec<ipnet::IpNet>,
    pub listen_port: u16,
    pub udp_timeout: Duration,
    pub udp_mapping: UdpNatBehavior,
    pub udp_filtering: UdpNatBehavior,
    pub udp_nat_max: u32,
    pub peers: Vec<WireGuardPeerConfig>,
}

impl WireGuardEndpointConfig {
    pub fn from_options(
        options: &WireGuardEndpointOptions,
    ) -> io::Result<Self> {
        if options.private_key.is_empty() {
            return Err(invalid("missing WireGuard private key"));
        }
        if options.address.as_slice().is_empty() {
            return Err(invalid("missing WireGuard interface address"));
        }
        if options.listen_port != 0 && !options.dialer.detour.is_empty() {
            return Err(invalid("WireGuard listen_port conflicts with detour"));
        }
        let private_key = decode_key(&options.private_key)?;
        let mut peers = Vec::with_capacity(options.peers.len());
        for (index, peer) in options.peers.iter().enumerate() {
            if peer.public_key.is_empty() {
                return Err(invalid(format!(
                    "missing public key for WireGuard peer {index}"
                )));
            }
            if peer.allowed_ips.as_slice().is_empty() {
                return Err(invalid(format!(
                    "missing allowed ips for WireGuard peer {index}"
                )));
            }
            let reserved = match peer.reserved.as_slice() {
                [] => [0; 3],
                [first, second, third] => [*first, *second, *third],
                value => {
                    return Err(invalid(format!(
                        "invalid reserved value for WireGuard peer {index}: expected 3 bytes, got {}",
                        value.len()
                    )));
                }
            };
            peers.push(WireGuardPeerConfig {
                address: peer.address.clone(),
                port: peer.port,
                public_key: decode_key(&peer.public_key)?,
                pre_shared_key: (!peer.pre_shared_key.is_empty())
                    .then(|| decode_key(&peer.pre_shared_key))
                    .transpose()?,
                allowed_ips: peer
                    .allowed_ips
                    .as_slice()
                    .iter()
                    .map(|prefix| prefix.0)
                    .collect(),
                persistent_keepalive_interval: peer
                    .persistent_keepalive_interval,
                reserved,
            });
        }
        Ok(Self {
            private_key,
            mtu: if options.mtu == 0 { 1408 } else { options.mtu },
            addresses: options
                .address
                .as_slice()
                .iter()
                .map(|prefix| prefix.0)
                .collect(),
            listen_port: options.listen_port,
            udp_timeout: options
                .udp_timeout
                .as_std()
                .filter(|duration| !duration.is_zero())
                .unwrap_or(crate::constant::UDP_TIMEOUT),
            udp_mapping: options.udp_mapping,
            udp_filtering: options.udp_filtering,
            udp_nat_max: options.udp_nat_max,
            peers,
        })
    }

    /// Match the same longest allowed-prefix peer selection used by
    /// wireguard-go's AllowedIPs trie.
    pub fn peer_for_destination(
        &self,
        destination: IpAddr,
    ) -> Option<(usize, &WireGuardPeerConfig)> {
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| {
                peer.allowed_ips
                    .iter()
                    .filter(|prefix| prefix.contains(&destination))
                    .map(ipnet::IpNet::prefix_len)
                    .max()
                    .map(|prefix_len| (prefix_len, index, peer))
            })
            .max_by_key(|(prefix_len, index, _)| (*prefix_len, *index))
            .map(|(_, index, peer)| (index, peer))
    }
}

impl WireGuardPacketPort {
    fn new(config: &WireGuardEndpointConfig) -> Self {
        let inet4_address = config
            .addresses
            .iter()
            .map(ipnet::IpNet::addr)
            .find(IpAddr::is_ipv4);
        let inet6_address = config
            .addresses
            .iter()
            .map(ipnet::IpNet::addr)
            .find(IpAddr::is_ipv6);
        Self {
            endpoint: RwLock::new(None),
            inet4_address,
            inet6_address,
            mtu: config.mtu as usize,
            return_path: RwLock::new(None),
        }
    }

    fn activate(&self, endpoint: Arc<WireGuardEndpoint>) -> io::Result<()> {
        *self.endpoint.write().map_err(|_| {
            io::Error::other("WireGuard packet port lock poisoned")
        })? = Some(endpoint);
        Ok(())
    }

    fn deactivate(&self) -> io::Result<()> {
        self.endpoint
            .write()
            .map_err(|_| {
                io::Error::other("WireGuard packet port lock poisoned")
            })?
            .take();
        Ok(())
    }

    fn endpoint(&self) -> io::Result<Arc<WireGuardEndpoint>> {
        self.endpoint
            .read()
            .map_err(|_| {
                io::Error::other("WireGuard packet port lock poisoned")
            })?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "WireGuard endpoint is not started",
                )
            })
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.endpoint
            .read()
            .ok()
            .and_then(|endpoint| endpoint.clone())
            .is_some_and(|endpoint| {
                endpoint.config.peer_for_destination(address).is_some()
            })
    }

    /// Offer one decrypted packet to the attached dispatcher. Returns true
    /// only when that dispatcher consumed the packet.
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

impl IpPacketPort for WireGuardPacketPort {
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
            io::Error::other("WireGuard packet return lock poisoned")
        })?;
        if let Some(existing) = current.as_ref()
            && existing.upgrade().is_some()
        {
            if existing.ptr_eq(&return_path) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "WireGuard packet return path is already attached",
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
            let endpoint = self.endpoint()?;
            for packet in packets {
                if packet.is_empty() {
                    continue;
                }
                endpoint.send_ip_packet(&packet).await?;
            }
            Ok(())
        })
    }
}

impl Default for WireGuardDialer {
    fn default() -> Self {
        let config = WireGuardEndpointConfig {
            private_key: [0; 32],
            mtu: 1408,
            addresses: Vec::new(),
            listen_port: 0,
            udp_timeout: crate::constant::UDP_TIMEOUT,
            udp_mapping: UdpNatBehavior::EndpointIndependent,
            udp_filtering: UdpNatBehavior::EndpointIndependent,
            udp_nat_max: 0,
            peers: Vec::new(),
        };
        Self {
            net: RwLock::default(),
            resolver: None,
            strategy: DomainStrategy::AsIs,
            packet_port: Arc::new(WireGuardPacketPort::new(&config)),
        }
    }
}

impl WireGuardEndpoint {
    pub async fn start(
        config: WireGuardEndpointConfig,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        if config.peers.is_empty() {
            return Err(invalid(
                "WireGuard endpoint requires at least one peer",
            ));
        }

        let shared_connection = if config.listen_port == 0 {
            None
        } else {
            let destination = config
                .peers
                .iter()
                .find(|peer| !peer.address.is_empty() && peer.port != 0)
                .map(|peer| SocksAddr::new(peer.address.clone(), peer.port))
                .unwrap_or_else(|| {
                    SocksAddr::from(SocketAddr::from(([127, 0, 0, 1], 9)))
                });
            Some(Arc::<dyn PacketConnection>::from(
                dialer
                    .listen_udp_on(&destination, config.listen_port)
                    .await?,
            ))
        };
        let mut peers = Vec::with_capacity(config.peers.len());
        for (index, peer) in config.peers.iter().enumerate() {
            if (peer.address.is_empty() || peer.port == 0)
                && config.listen_port == 0
            {
                return Err(invalid(format!(
                    "WireGuard peer {index} has no usable endpoint"
                )));
            }
            let destination = if peer.address.is_empty() || peer.port == 0 {
                SocksAddr::from(SocketAddr::from(([127, 0, 0, 1], 9)))
            } else {
                SocksAddr::new(peer.address.clone(), peer.port)
            };
            let connection: Arc<dyn PacketConnection> = match &shared_connection
            {
                Some(connection) => connection.clone(),
                None => Arc::from(dialer.listen_udp(&destination).await?),
            };
            peers.push(Arc::new(WireGuardRuntimePeer {
                index,
                tunnel: WireGuardPeerTunnel::new(
                    config.private_key,
                    peer.public_key,
                    peer.pre_shared_key,
                    peer.persistent_keepalive_interval,
                    u32::try_from(index + 1)
                        .map_err(|_| invalid("too many WireGuard peers"))?,
                ),
                connection,
                destination: RwLock::new(destination),
                allowed_ips: peer.allowed_ips.clone(),
                reserved: peer.reserved,
            }));
        }

        let cancellation = CancellationToken::new();
        let (incoming_tx, incoming_rx) = mpsc::channel(256);
        if let Some(connection) = shared_connection {
            spawn_receive_loop(
                connection,
                peers.clone(),
                incoming_tx.clone(),
                cancellation.clone(),
            );
        } else {
            for peer in &peers {
                spawn_receive_loop(
                    peer.connection.clone(),
                    vec![peer.clone()],
                    incoming_tx.clone(),
                    cancellation.clone(),
                );
            }
        }
        for peer in &peers {
            spawn_timer_loop(
                peer.clone(),
                incoming_tx.clone(),
                cancellation.clone(),
            );
        }
        drop(incoming_tx);

        Ok(Self {
            config,
            peers,
            incoming: tokio::sync::Mutex::new(incoming_rx),
            cancellation,
        })
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn peer_local_addr(
        &self,
        peer_index: usize,
    ) -> io::Result<Option<SocketAddr>> {
        self.peers
            .get(peer_index)
            .ok_or_else(|| invalid("WireGuard peer index out of range"))?
            .connection
            .local_addr()
    }

    pub fn peer_destination(&self, peer_index: usize) -> io::Result<SocksAddr> {
        self.peers
            .get(peer_index)
            .ok_or_else(|| invalid("WireGuard peer index out of range"))?
            .destination()
    }

    pub async fn send_ip_packet(&self, packet: &[u8]) -> io::Result<usize> {
        if packet.len() > self.config.mtu as usize {
            return Err(invalid(format!(
                "WireGuard packet exceeds MTU {}",
                self.config.mtu
            )));
        }
        let destination = Tunn::dst_address(packet).ok_or_else(|| {
            invalid("invalid IP packet for WireGuard endpoint")
        })?;
        let (peer_index, _) = self
            .config
            .peer_for_destination(destination)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no WireGuard peer for {destination}"),
                )
            })?;
        let peer = &self.peers[peer_index];
        let action = peer.tunnel.encapsulate(packet)?;
        deliver_action(peer, action, None, false).await?;
        Ok(packet.len())
    }

    pub async fn receive_ip_packet(&self) -> io::Result<WireGuardPacket> {
        self.incoming.lock().await.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WireGuard endpoint is closed",
            ))
        })
    }

    pub fn close(&self) {
        self.cancellation.cancel();
    }
}

impl WireGuardNetwork {
    fn start(
        endpoint: Arc<WireGuardEndpoint>,
        packet_port: Arc<WireGuardPacketPort>,
        flow: Option<(&str, Arc<Router>, Arc<OutboundManager>)>,
    ) -> io::Result<Arc<Self>> {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = endpoint.config.mtu as usize;
        capabilities.medium = Medium::Ip;
        let (device, ingress, egress, mut output, icmp_errors) =
            ChannelDevice::new(capabilities);

        let addresses: Vec<IpCidr> = endpoint
            .config
            .addresses
            .iter()
            .map(|prefix| prefix.to_string().parse())
            .collect::<Result<_, _>>()
            .map_err(|()| invalid("invalid WireGuard stack address"))?;
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
                endpoint.config.addresses.clone(),
                true,
                Vec::new(),
                router,
                outbounds,
                endpoint.config.udp_timeout,
                endpoint.config.udp_mapping,
                endpoint.config.udp_filtering,
                endpoint.config.udp_nat_max,
                endpoint.config.mtu as usize,
            )
        });
        let cancellation = CancellationToken::new();

        let incoming_endpoint = endpoint.clone();
        let incoming_cancellation = cancellation.clone();
        let incoming_flow_router = flow_router.clone();
        let incoming_packet_port = packet_port;
        let incoming_task = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = incoming_cancellation.cancelled() => break,
                    packet = incoming_endpoint.receive_ip_packet() => packet,
                };
                let Ok(packet) = packet else { break };
                if incoming_packet_port.return_packet(&packet.data) {
                    continue;
                }
                if let Some(flow_router) = &incoming_flow_router {
                    match flow_router.prepare_packet(&packet.data).await {
                        Ok(true) => {}
                        Ok(false) | Err(_) => continue,
                    }
                }
                if ingress.send(Ok(packet.data)).await.is_err() {
                    break;
                }
            }
        });

        let outgoing_endpoint = endpoint;
        let outgoing_cancellation = cancellation.clone();
        let outgoing_task = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = outgoing_cancellation.cancelled() => break,
                    packet = output.recv() => packet,
                };
                let Some(packet) = packet else { break };
                if outgoing_endpoint.send_ip_packet(&packet).await.is_err() {
                    break;
                }
            }
        });

        Ok(Arc::new(Self {
            net,
            cancellation,
            _flow_router: flow_router,
            _tasks: vec![
                AbortOnDropHandle::new(incoming_task),
                AbortOnDropHandle::new(outgoing_task),
            ],
        }))
    }
}

impl Drop for WireGuardNetwork {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl WireGuardDialer {
    fn with_resolver(
        config: &WireGuardEndpointConfig,
        resolver: SharedResolver,
        strategy: DomainStrategy,
    ) -> Self {
        Self {
            net: RwLock::default(),
            resolver: Some(resolver),
            strategy,
            packet_port: Arc::new(WireGuardPacketPort::new(config)),
        }
    }

    fn without_resolver(config: &WireGuardEndpointConfig) -> Self {
        Self {
            net: RwLock::default(),
            resolver: None,
            strategy: DomainStrategy::AsIs,
            packet_port: Arc::new(WireGuardPacketPort::new(config)),
        }
    }

    fn activate(&self, net: Arc<Net>) -> io::Result<()> {
        *self.net.write().map_err(|_| {
            io::Error::other("WireGuard network lock poisoned")
        })? = Some(net);
        Ok(())
    }

    fn deactivate(&self) -> io::Result<()> {
        self.net
            .write()
            .map_err(|_| io::Error::other("WireGuard network lock poisoned"))?
            .take();
        Ok(())
    }

    fn net(&self) -> io::Result<Arc<Net>> {
        self.net
            .read()
            .map_err(|_| io::Error::other("WireGuard network lock poisoned"))?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "WireGuard endpoint is not started",
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

impl Dialer for WireGuardDialer {
    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        Some(self.packet_port.clone())
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.packet_port.preferred_address(address)
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
                        return Ok(Box::new(WireGuardPacketConnection {
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
                        "no compatible WireGuard ICMP destination",
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
}

struct WireGuardPacketConnection {
    socket: Arc<SmoltcpUdpSocket>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
}

impl PacketConnection for WireGuardPacketConnection {
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

impl WireGuardEndpointService {
    pub fn new(
        tag: impl Into<String>,
        config: WireGuardEndpointConfig,
        dialer: Arc<dyn Dialer>,
    ) -> (Self, WireGuardEndpointHandle) {
        Self::new_inner(tag, config, dialer, None, None)
    }

    pub(crate) fn new_with_resolver(
        tag: impl Into<String>,
        config: WireGuardEndpointConfig,
        dialer: Arc<dyn Dialer>,
        resolver: SharedResolver,
        strategy: DomainStrategy,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> (Self, WireGuardEndpointHandle) {
        Self::new_inner(
            tag,
            config,
            dialer,
            Some((resolver, strategy)),
            Some((router, outbounds)),
        )
    }

    fn new_inner(
        tag: impl Into<String>,
        config: WireGuardEndpointConfig,
        dialer: Arc<dyn Dialer>,
        resolver: Option<(SharedResolver, DomainStrategy)>,
        flow_router: Option<(Arc<Router>, Arc<OutboundManager>)>,
    ) -> (Self, WireGuardEndpointHandle) {
        let tag = tag.into();
        let endpoint_dialer = match resolver {
            Some((resolver, strategy)) => Arc::new(
                WireGuardDialer::with_resolver(&config, resolver, strategy),
            ),
            None => Arc::new(WireGuardDialer::without_resolver(&config)),
        };
        let handle = WireGuardEndpointHandle {
            endpoint: Arc::default(),
            network: Arc::default(),
            dialer: endpoint_dialer,
        };
        (
            Self {
                name: format!("endpoint/{tag}"),
                tag,
                config,
                dialer,
                flow_router,
                handle: handle.clone(),
            },
            handle,
        )
    }
}

impl Lifecycle for WireGuardEndpointService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            let endpoint = WireGuardEndpoint::start(
                self.config.clone(),
                self.dialer.clone(),
            )
            .await
            .map(Arc::new)
            .map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })?;
            self.handle
                .dialer
                .packet_port
                .activate(endpoint.clone())
                .map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })?;
            let flow = self.flow_router.as_ref().map(|(router, outbounds)| {
                (&*self.tag, router.clone(), outbounds.clone())
            });
            let network = WireGuardNetwork::start(
                endpoint.clone(),
                self.handle.dialer.packet_port.clone(),
                flow,
            )
            .map_err(|error| {
                let _ = self.handle.dialer.packet_port.deactivate();
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                }
            })?;
            self.handle.dialer.activate(network.net.clone()).map_err(
                |error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                },
            )?;
            *self.handle.endpoint.lock().map_err(|_| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "WireGuard endpoint handle lock poisoned".into(),
                }
            })? = Some(endpoint);
            *self.handle.network.lock().map_err(|_| {
                LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: "WireGuard network handle lock poisoned".into(),
                }
            })? = Some(network);
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.handle.dialer.deactivate().map_err(|error| {
                LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                }
            })?;
            self.handle
                .dialer
                .packet_port
                .deactivate()
                .map_err(|error| LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                })?;
            self.handle
                .network
                .lock()
                .map_err(|_| LifecycleError::Close {
                    component: self.name.clone(),
                    message: "WireGuard network handle lock poisoned".into(),
                })?
                .take();
            let endpoint = self
                .handle
                .endpoint
                .lock()
                .map_err(|_| LifecycleError::Close {
                    component: self.name.clone(),
                    message: "WireGuard endpoint handle lock poisoned".into(),
                })?
                .take();
            if let Some(endpoint) = endpoint {
                endpoint.close();
            }
            Ok(())
        })
    }
}

impl Drop for WireGuardEndpoint {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl WireGuardRuntimePeer {
    fn destination(&self) -> io::Result<SocksAddr> {
        self.destination
            .read()
            .map(|destination| destination.clone())
            .map_err(|_| io::Error::other("WireGuard endpoint lock poisoned"))
    }

    fn observe_source(&self, source: &SocksAddr) -> io::Result<()> {
        if matches!(source, SocksAddr::Ip(_)) {
            *self.destination.write().map_err(|_| {
                io::Error::other("WireGuard endpoint lock poisoned")
            })? = source.clone();
        }
        Ok(())
    }

    async fn send_network(&self, mut packet: Vec<u8>) -> io::Result<()> {
        set_reserved(&mut packet, self.reserved);
        let destination = self.destination()?;
        self.connection.send_to(&packet, &destination).await?;
        Ok(())
    }
}

fn spawn_receive_loop(
    connection: Arc<dyn PacketConnection>,
    peers: Vec<Arc<WireGuardRuntimePeer>>,
    incoming: mpsc::Sender<io::Result<WireGuardPacket>>,
    cancellation: CancellationToken,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let result = tokio::select! {
                _ = cancellation.cancelled() => break,
                result = connection.recv_from(&mut buffer) => result,
            };
            let (size, source) = match result {
                Ok(result) => result,
                Err(error) => {
                    let _ = incoming.send(Err(error)).await;
                    break;
                }
            };
            let datagram = &buffer[..size];
            let source_ip = match source {
                SocksAddr::Ip(address) => Some(address.ip()),
                SocksAddr::Domain { .. } => None,
            };
            for peer in &peers {
                if datagram.len() > 3 && datagram[1..4] != peer.reserved {
                    continue;
                }
                let mut peer_datagram = datagram.to_vec();
                clear_reserved(&mut peer_datagram);
                let action =
                    match peer.tunnel.decapsulate(source_ip, &peer_datagram) {
                        Ok(action) => action,
                        Err(_) => continue,
                    };
                if matches!(
                    &action,
                    WireGuardAction::WriteToNetwork(_)
                        | WireGuardAction::WriteToTunnelV4(_, _)
                        | WireGuardAction::WriteToTunnelV6(_, _)
                ) && let Err(error) = peer.observe_source(&source)
                {
                    let _ = incoming.send(Err(error)).await;
                    return;
                }
                if let Err(error) =
                    deliver_action(peer, action, Some(&incoming), true).await
                {
                    let _ = incoming.send(Err(error)).await;
                    return;
                }
                break;
            }
        }
    });
}

fn spawn_timer_loop(
    peer: Arc<WireGuardRuntimePeer>,
    incoming: mpsc::Sender<io::Result<WireGuardPacket>>,
    cancellation: CancellationToken,
) {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = timer.tick() => {}
            }
            match peer.tunnel.update_timers() {
                Ok(action) => {
                    if let Err(error) =
                        deliver_action(&peer, action, None, false).await
                    {
                        let _ = incoming.send(Err(error)).await;
                        break;
                    }
                }
                Err(error) => {
                    let _ = incoming.send(Err(error)).await;
                    break;
                }
            }
        }
    });
}

async fn deliver_action(
    peer: &WireGuardRuntimePeer,
    mut action: WireGuardAction,
    incoming: Option<&mpsc::Sender<io::Result<WireGuardPacket>>>,
    drain_queued: bool,
) -> io::Result<()> {
    loop {
        match action {
            WireGuardAction::WriteToNetwork(packet) => {
                peer.send_network(packet).await?;
            }
            WireGuardAction::WriteToTunnelV4(data, source)
            | WireGuardAction::WriteToTunnelV6(data, source) => {
                if !peer
                    .allowed_ips
                    .iter()
                    .any(|prefix| prefix.contains(&source))
                {
                    if !drain_queued {
                        return Ok(());
                    }
                    action = peer.tunnel.decapsulate(None, &[])?;
                    continue;
                }
                let incoming = incoming.ok_or_else(|| {
                    io::Error::other(
                        "unexpected WireGuard tunnel packet from local action",
                    )
                })?;
                incoming
                    .send(Ok(WireGuardPacket {
                        data,
                        source,
                        peer_index: peer.index,
                    }))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "WireGuard endpoint receive queue is closed",
                        )
                    })?;
            }
            WireGuardAction::Done => return Ok(()),
        }
        if !drain_queued {
            return Ok(());
        }
        action = peer.tunnel.decapsulate(None, &[])?;
    }
}

fn set_reserved(packet: &mut [u8], reserved: [u8; 3]) {
    if packet.len() > 3 {
        packet[1..4].copy_from_slice(&reserved);
    }
}

fn clear_reserved(packet: &mut [u8]) {
    set_reserved(packet, [0; 3]);
}

impl WireGuardPeerTunnel {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        pre_shared_key: Option<[u8; 32]>,
        persistent_keepalive_interval: u16,
        index: u32,
    ) -> Self {
        let keepalive = (persistent_keepalive_interval != 0)
            .then_some(persistent_keepalive_interval);
        Self {
            tunnel: Mutex::new(Tunn::new(
                StaticSecret::from(private_key),
                PublicKey::from(peer_public_key),
                pre_shared_key,
                keepalive,
                index,
                None,
            )),
        }
    }

    pub fn from_base64(
        private_key: &str,
        peer_public_key: &str,
        pre_shared_key: Option<&str>,
        persistent_keepalive_interval: u16,
        index: u32,
    ) -> io::Result<Self> {
        Ok(Self::new(
            decode_key(private_key)?,
            decode_key(peer_public_key)?,
            pre_shared_key.map(decode_key).transpose()?,
            persistent_keepalive_interval,
            index,
        ))
    }

    pub fn handshake_initiation(&self) -> io::Result<WireGuardAction> {
        let mut output = vec![0_u8; MIN_PACKET_BUFFER];
        let result = self
            .tunnel
            .lock()
            .map_err(|_| io::Error::other("WireGuard tunnel lock poisoned"))?
            .format_handshake_initiation(&mut output, false);
        action(result)
    }

    pub fn encapsulate(&self, packet: &[u8]) -> io::Result<WireGuardAction> {
        let mut output = packet_buffer(packet.len());
        let result = self
            .tunnel
            .lock()
            .map_err(|_| io::Error::other("WireGuard tunnel lock poisoned"))?
            .encapsulate(packet, &mut output);
        action(result)
    }

    pub fn decapsulate(
        &self,
        source: Option<IpAddr>,
        datagram: &[u8],
    ) -> io::Result<WireGuardAction> {
        let mut output = packet_buffer(datagram.len());
        let result = self
            .tunnel
            .lock()
            .map_err(|_| io::Error::other("WireGuard tunnel lock poisoned"))?
            .decapsulate(source, datagram, &mut output);
        action(result)
    }

    pub fn update_timers(&self) -> io::Result<WireGuardAction> {
        let mut output = vec![0_u8; MIN_PACKET_BUFFER];
        let result = self
            .tunnel
            .lock()
            .map_err(|_| io::Error::other("WireGuard tunnel lock poisoned"))?
            .update_timers(&mut output);
        match result {
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                Ok(WireGuardAction::Done)
            }
            result => action(result),
        }
    }
}

fn packet_buffer(input_size: usize) -> Vec<u8> {
    vec![
        0_u8;
        input_size
            .saturating_add(WIREGUARD_OVERHEAD)
            .max(MIN_PACKET_BUFFER)
    ]
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn action(result: TunnResult<'_>) -> io::Result<WireGuardAction> {
    match result {
        TunnResult::WriteToNetwork(packet) => {
            Ok(WireGuardAction::WriteToNetwork(packet.to_vec()))
        }
        TunnResult::WriteToTunnelV4(packet, address) => {
            Ok(WireGuardAction::WriteToTunnelV4(
                packet.to_vec(),
                IpAddr::V4(address),
            ))
        }
        TunnResult::WriteToTunnelV6(packet, address) => {
            Ok(WireGuardAction::WriteToTunnelV6(
                packet.to_vec(),
                IpAddr::V6(address),
            ))
        }
        TunnResult::Done => Ok(WireGuardAction::Done),
        TunnResult::Err(error) => Err(io::Error::other(format!(
            "WireGuard tunnel error: {error:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        option::DirectOutboundOptions, protocol::direct::DirectOutbound,
    };

    fn keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = [seed; 32];
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        (private, public)
    }

    fn network(action: WireGuardAction) -> Vec<u8> {
        match action {
            WireGuardAction::WriteToNetwork(packet) => packet,
            action => panic!("expected a network packet, got {action:?}"),
        }
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        vec![
            0x45,
            0,
            0,
            24,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
            source[0],
            source[1],
            source[2],
            source[3],
            destination[0],
            destination[1],
            destination[2],
            destination[3],
            b'p',
            b'i',
            b'n',
            b'g',
        ]
    }

    fn endpoint_config(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        endpoint: SocketAddr,
        local_ip: &str,
        allowed_ip: &str,
        reserved: [u8; 3],
    ) -> WireGuardEndpointConfig {
        WireGuardEndpointConfig {
            private_key,
            mtu: 1408,
            addresses: vec![local_ip.parse().unwrap()],
            listen_port: 0,
            udp_timeout: crate::constant::UDP_TIMEOUT,
            udp_mapping: UdpNatBehavior::EndpointIndependent,
            udp_filtering: UdpNatBehavior::EndpointIndependent,
            udp_nat_max: 0,
            peers: vec![WireGuardPeerConfig {
                address: endpoint.ip().to_string(),
                port: endpoint.port(),
                public_key: peer_public_key,
                pre_shared_key: None,
                allowed_ips: vec![allowed_ip.parse().unwrap()],
                persistent_keepalive_interval: 0,
                reserved,
            }],
        }
    }

    #[test]
    fn key_codec_accepts_wg_base64_and_rejects_wrong_length() {
        let key = [0x42; 32];
        assert_eq!(decode_key(&STANDARD.encode(key)).unwrap(), key);
        assert!(decode_key(&STANDARD.encode([0_u8; 31])).is_err());
        assert!(decode_key("not base64").is_err());
    }

    #[test]
    fn preferred_address_tracks_started_endpoint_allowed_ips() {
        let (private, _) = keys(41);
        let (_, peer_public) = keys(42);
        let config = endpoint_config(
            private,
            peer_public,
            "127.0.0.1:9".parse().unwrap(),
            "10.0.0.1/32",
            "10.0.0.0/8",
            [0; 3],
        );
        let dialer = WireGuardDialer::without_resolver(&config);
        assert!(!dialer.preferred_address("10.1.2.3".parse().unwrap()));

        let (_incoming_tx, incoming_rx) = mpsc::channel(1);
        let endpoint = Arc::new(WireGuardEndpoint {
            config,
            peers: Vec::new(),
            incoming: tokio::sync::Mutex::new(incoming_rx),
            cancellation: CancellationToken::new(),
        });
        dialer.packet_port.activate(endpoint).unwrap();
        assert!(dialer.preferred_address("10.1.2.3".parse().unwrap()));
        assert!(!dialer.preferred_address("192.0.2.1".parse().unwrap()));

        dialer.packet_port.deactivate().unwrap();
        assert!(!dialer.preferred_address("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn peers_handshake_and_exchange_an_ipv4_packet() {
        let (alice_private, alice_public) = keys(1);
        let (bob_private, bob_public) = keys(2);
        let alice =
            WireGuardPeerTunnel::new(alice_private, bob_public, None, 0, 1);
        let bob =
            WireGuardPeerTunnel::new(bob_private, alice_public, None, 0, 2);

        let initiation = network(alice.handshake_initiation().unwrap());
        let response = network(bob.decapsulate(None, &initiation).unwrap());
        let keepalive = network(alice.decapsulate(None, &response).unwrap());
        assert_eq!(
            bob.decapsulate(None, &keepalive).unwrap(),
            WireGuardAction::Done
        );

        let packet = vec![
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51,
            100, 2, b'p', b'i', b'n', b'g',
        ];
        let encrypted = network(alice.encapsulate(&packet).unwrap());
        match bob.decapsulate(None, &encrypted).unwrap() {
            WireGuardAction::WriteToTunnelV4(decrypted, _) => {
                assert_eq!(decrypted, packet);
            }
            action => panic!("expected an IPv4 packet, got {action:?}"),
        }
    }

    #[test]
    fn endpoint_options_validate_and_route_longest_allowed_prefix() {
        let (_, peer_one_public) = keys(3);
        let (_, peer_two_public) = keys(4);
        let options: WireGuardEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "address": ["10.0.0.1/32"],
                "private_key": STANDARD.encode([1_u8; 32]),
                "peers": [
                    {
                        "public_key": STANDARD.encode(peer_one_public),
                        "allowed_ips": ["0.0.0.0/0"]
                    },
                    {
                        "address": "peer.example",
                        "port": 51820,
                        "public_key": STANDARD.encode(peer_two_public),
                        "allowed_ips": ["10.0.0.0/8"],
                        "reserved": [1, 2, 3]
                    }
                ]
            }))
            .unwrap();
        let config = WireGuardEndpointConfig::from_options(&options).unwrap();
        assert_eq!(config.mtu, 1408);
        assert_eq!(
            config
                .peer_for_destination("10.1.2.3".parse().unwrap())
                .unwrap()
                .0,
            1
        );
        assert_eq!(
            config
                .peer_for_destination("192.0.2.1".parse().unwrap())
                .unwrap()
                .0,
            0
        );
        assert_eq!(config.peers[1].reserved, [1, 2, 3]);
    }

    #[test]
    fn endpoint_options_reject_upstream_configuration_errors() {
        let (_, public) = keys(5);
        let base = serde_json::json!({
            "address": ["10.0.0.1/32"],
            "private_key": STANDARD.encode([1_u8; 32]),
            "peers": [{
                "public_key": STANDARD.encode(public),
                "allowed_ips": ["0.0.0.0/0"]
            }]
        });
        let mut missing_allowed = base.clone();
        missing_allowed["peers"][0]["allowed_ips"] = serde_json::json!([]);
        let options = serde_json::from_value(missing_allowed).unwrap();
        assert!(
            WireGuardEndpointConfig::from_options(&options)
                .unwrap_err()
                .to_string()
                .contains("missing allowed ips")
        );

        let mut invalid_reserved = base.clone();
        invalid_reserved["peers"][0]["reserved"] = serde_json::json!([1, 2]);
        let options = serde_json::from_value(invalid_reserved).unwrap();
        assert!(
            WireGuardEndpointConfig::from_options(&options)
                .unwrap_err()
                .to_string()
                .contains("expected 3 bytes")
        );

        let mut conflicting = base;
        conflicting["listen_port"] = serde_json::json!(51820);
        conflicting["detour"] = serde_json::json!("proxy");
        let options = serde_json::from_value(conflicting).unwrap();
        assert!(
            WireGuardEndpointConfig::from_options(&options)
                .unwrap_err()
                .to_string()
                .contains("conflicts")
        );
    }

    #[test]
    fn reserved_bytes_are_applied_and_removed_without_changing_type() {
        let mut packet = vec![1, 0, 0, 0, 9, 8, 7];
        set_reserved(&mut packet, [0xaa, 0xbb, 0xcc]);
        assert_eq!(&packet[..4], &[1, 0xaa, 0xbb, 0xcc]);
        clear_reserved(&mut packet);
        assert_eq!(&packet[..4], &[1, 0, 0, 0]);
    }

    #[tokio::test]
    async fn udp_endpoints_roam_handshake_and_exchange_ip_packets() {
        let (alice_private, alice_public) = keys(11);
        let (bob_private, bob_public) = keys(12);
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));

        // Bob binds first. Its placeholder destination is replaced by the
        // authenticated source of Alice's first handshake, matching
        // WireGuard endpoint roaming behavior.
        let bob = WireGuardEndpoint::start(
            endpoint_config(
                bob_private,
                alice_public,
                "127.0.0.1:9".parse().unwrap(),
                "10.0.0.2/32",
                "10.0.0.1/32",
                [1, 2, 3],
            ),
            dialer.clone(),
        )
        .await
        .unwrap();
        let bob_bound = bob.peer_local_addr(0).unwrap().unwrap();
        let bob_underlay = SocketAddr::new(
            if bob_bound.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            },
            bob_bound.port(),
        );
        let rogue = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        rogue.send_to(&[1, 9, 9, 9], bob_underlay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            bob.peer_destination(0).unwrap(),
            SocksAddr::from("127.0.0.1:9".parse::<SocketAddr>().unwrap())
        );
        let alice = WireGuardEndpoint::start(
            endpoint_config(
                alice_private,
                bob_public,
                bob_underlay,
                "10.0.0.1/32",
                "10.0.0.2/32",
                [1, 2, 3],
            ),
            dialer,
        )
        .await
        .unwrap();

        let outbound = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        assert_eq!(alice.send_ip_packet(&outbound).await.unwrap(), 24);
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            bob.receive_ip_packet(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.data, outbound);
        assert_eq!(received.source, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(received.peer_index, 0);
        let alice_bound = alice.peer_local_addr(0).unwrap().unwrap();
        assert_eq!(bob.peer_destination(0).unwrap().port(), alice_bound.port());

        let response = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);
        bob.send_ip_packet(&response).await.unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            alice.receive_ip_packet(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.data, response);

        let spoofed = ipv4_packet([10, 0, 0, 99], [10, 0, 0, 2]);
        alice.send_ip_packet(&spoofed).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                bob.receive_ip_packet()
            )
            .await
            .is_err(),
            "a peer must not inject a source outside its AllowedIPs"
        );

        alice.close();
        bob.close();
    }

    #[tokio::test]
    async fn userspace_stack_carries_tcp_over_wireguard() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (alice_private, alice_public) = keys(21);
        let (bob_private, bob_public) = keys(22);
        let (_, decoy_public) = keys(23);
        let underlay: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));

        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bob_listen_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let mut bob_config = endpoint_config(
            bob_private,
            alice_public,
            "127.0.0.1:9".parse().unwrap(),
            "10.0.0.2/32",
            "10.0.0.1/32",
            [0; 3],
        );
        bob_config.listen_port = bob_listen_port;
        bob_config.addresses.push("fd00::2/128".parse().unwrap());
        bob_config.peers[0]
            .allowed_ips
            .push("fd00::1/128".parse().unwrap());
        let mut decoy = bob_config.peers[0].clone();
        decoy.public_key = decoy_public;
        decoy.allowed_ips = vec!["10.0.0.3/32".parse().unwrap()];
        decoy.reserved = [9, 9, 9];
        bob_config.peers.insert(0, decoy);
        let bob_endpoint = Arc::new(
            WireGuardEndpoint::start(bob_config, underlay.clone())
                .await
                .unwrap(),
        );
        let bob_underlay = bob_endpoint.peer_local_addr(0).unwrap().unwrap();
        assert_eq!(bob_underlay.port(), bob_listen_port);
        assert_eq!(
            bob_endpoint.peer_local_addr(1).unwrap().unwrap(),
            bob_underlay,
            "all peers must share the configured listen socket"
        );
        let bob_underlay = SocketAddr::new(
            if bob_underlay.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            },
            bob_underlay.port(),
        );
        let mut alice_config = endpoint_config(
            alice_private,
            bob_public,
            bob_underlay,
            "10.0.0.1/32",
            "10.0.0.2/32",
            [0; 3],
        );
        alice_config.addresses.push("fd00::1/128".parse().unwrap());
        alice_config.peers[0]
            .allowed_ips
            .push("fd00::2/128".parse().unwrap());
        let alice_endpoint = Arc::new(
            WireGuardEndpoint::start(alice_config, underlay)
                .await
                .unwrap(),
        );

        let bob_port = Arc::new(WireGuardPacketPort::new(&bob_endpoint.config));
        let alice_port =
            Arc::new(WireGuardPacketPort::new(&alice_endpoint.config));
        let bob_network =
            WireGuardNetwork::start(bob_endpoint, bob_port, None).unwrap();
        let alice_network =
            WireGuardNetwork::start(alice_endpoint, alice_port, None).unwrap();
        let mut listener = bob_network
            .net
            .tcp_bind("10.0.0.2:32123".parse().unwrap())
            .await
            .unwrap();
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, source) = listener.accept().await.unwrap();
            assert_eq!(source.ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
            received_rx.await.unwrap();
        });

        let dialer = WireGuardDialer::default();
        dialer.activate(alice_network.net.clone()).unwrap();
        let destination =
            SocksAddr::from("10.0.0.2:32123".parse::<SocketAddr>().unwrap());
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            dialer.dial_tcp(&destination),
        )
        .await
        .unwrap()
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"pong");
        received_tx.send(()).unwrap();
        server.await.unwrap();

        let udp_destination = "10.0.0.2:32124".parse::<SocketAddr>().unwrap();
        let udp_server =
            bob_network.net.udp_bind(udp_destination).await.unwrap();
        let udp_destination = SocksAddr::from(udp_destination);
        let udp_client = dialer.listen_udp(&udp_destination).await.unwrap();
        udp_client
            .send_to(b"hello", &udp_destination)
            .await
            .unwrap();
        let mut datagram = [0_u8; 32];
        let (size, source) = tokio::time::timeout(
            Duration::from_secs(5),
            udp_server.recv_from(&mut datagram),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&datagram[..size], b"hello");
        udp_server.send_to(b"world", source).await.unwrap();
        let (size, source) = tokio::time::timeout(
            Duration::from_secs(5),
            udp_client.recv_from(&mut datagram),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&datagram[..size], b"world");
        assert_eq!(source, udp_destination);

        let mut ipv6_listener = bob_network
            .net
            .tcp_bind("[fd00::2]:32125".parse().unwrap())
            .await
            .unwrap();
        let (ipv6_received_tx, ipv6_received_rx) =
            tokio::sync::oneshot::channel();
        let ipv6_server = tokio::spawn(async move {
            let (mut stream, source) = ipv6_listener.accept().await.unwrap();
            assert_eq!(source.ip(), "fd00::1".parse::<IpAddr>().unwrap());
            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping6");
            stream.write_all(b"pong6").await.unwrap();
            stream.flush().await.unwrap();
            ipv6_received_rx.await.unwrap();
        });
        let ipv6_destination =
            SocksAddr::from("[fd00::2]:32125".parse::<SocketAddr>().unwrap());
        let mut ipv6_stream = tokio::time::timeout(
            Duration::from_secs(5),
            dialer.dial_tcp(&ipv6_destination),
        )
        .await
        .unwrap()
        .unwrap();
        ipv6_stream.write_all(b"ping6").await.unwrap();
        let mut ipv6_response = [0_u8; 5];
        tokio::time::timeout(
            Duration::from_secs(5),
            ipv6_stream.read_exact(&mut ipv6_response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&ipv6_response, b"pong6");
        ipv6_received_tx.send(()).unwrap();
        ipv6_server.await.unwrap();
    }
}
