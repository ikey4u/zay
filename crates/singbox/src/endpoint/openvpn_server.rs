//! Runtime-facing userspace OpenVPN server endpoint.
//!
//! The endpoint owns the TCP or UDP listener, authenticates each TLS client
//! through [`OpenVpnServerConnector`], and maintains an exact tunnel-address
//! route table.  A shared smoltcp network makes the endpoint tag usable as a
//! regular TCP/UDP outbound while connected clients come and go.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex, OnceLock, RwLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{Mutex as AsyncMutex, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, IpPacketPort, IpPacketReturn,
        PacketConnection, PacketFuture, PacketStream, Stream,
    },
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::SocksAddr,
        socket::{bind_tcp_listener, bind_udp_listener},
    },
    dns::manager::SharedResolver,
    option::{DomainStrategy, OpenVpnServerEndpointOptions},
    outbound::OutboundManager,
    protocol::openvpn::{
        Opcode, OpenVpnClientCertificateIdentity, OpenVpnConnectedServerClient,
        OpenVpnDatagramTransport, OpenVpnPacketTransport,
        OpenVpnServerConnector, OpenVpnServerConnectorError,
        OpenVpnStaticDataSession, OpenVpnStaticDataSessionOptions,
        StaticDataSessionError, load_openvpn_static_key_material,
        openvpn_stream_transport, resolve_openvpn_key_direction,
    },
};

use super::tokio_smoltcp::{
    BufferSize, Net, NetConfig, UdpSocket as SmoltcpUdpSocket,
    channel_device::ChannelDevice,
    smoltcp::{
        iface::Config as SmoltcpInterfaceConfig,
        phy::{DeviceCapabilities, Medium},
        wire::{HardwareAddress, IpAddress, IpCidr},
    },
};
use super::userspace_router::UserspaceEndpointRouter;

const OPENVPN_SERVER_PACKET_BUFFER: usize = 65_535;

#[derive(Clone)]
pub struct OpenVpnServerEndpointHandle {
    connector: Option<Arc<OpenVpnServerConnector>>,
    network: Arc<Mutex<Option<Arc<OpenVpnServerNetwork>>>>,
    dialer: Arc<OpenVpnServerDialer>,
    local_addr: Arc<RwLock<Option<SocketAddr>>>,
    last_error: Arc<RwLock<Option<String>>>,
}

impl OpenVpnServerEndpointHandle {
    pub fn dialer(&self) -> Arc<dyn Dialer> {
        self.dialer.clone()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.read().ok().and_then(|address| *address)
    }

    pub fn active_clients(&self) -> usize {
        self.connector
            .as_ref()
            .map_or(0, |connector| connector.active_clients())
            + self
                .network
                .lock()
                .ok()
                .and_then(|network| network.clone())
                .map_or(0, |network| usize::from(network.has_static_client()))
    }

    pub fn client_addresses(&self) -> Vec<IpAddr> {
        self.network
            .lock()
            .ok()
            .and_then(|network| network.clone())
            .map(|network| network.client_addresses())
            .unwrap_or_default()
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.read().ok().and_then(|error| error.clone())
    }

    /// Request a fresh TLS/data key for every distinct active client.
    pub async fn renegotiate_clients(&self) -> Vec<Result<bool, String>> {
        let clients = self
            .network
            .lock()
            .ok()
            .and_then(|network| network.clone())
            .map(|network| network.clients())
            .unwrap_or_default();
        let mut results = Vec::with_capacity(clients.len());
        for client in clients {
            results.push(
                client
                    .renegotiate()
                    .await
                    .map_err(|error| error.to_string()),
            );
        }
        results
    }
}

pub struct OpenVpnServerEndpointService {
    name: String,
    tag: String,
    options: OpenVpnServerEndpointOptions,
    connector: Option<Arc<OpenVpnServerConnector>>,
    base_path: std::path::PathBuf,
    resolver: SharedResolver,
    strategy: DomainStrategy,
    router: Arc<crate::route::Router>,
    outbounds: Arc<OutboundManager>,
    handle: OpenVpnServerEndpointHandle,
    cancellation: CancellationToken,
    listener_task: Option<JoinHandle<()>>,
}

impl OpenVpnServerEndpointService {
    pub fn new_with_resolver(
        tag: impl Into<String>,
        options: OpenVpnServerEndpointOptions,
        base_path: &Path,
        resolver: SharedResolver,
        strategy: DomainStrategy,
        router: Arc<crate::route::Router>,
        outbounds: Arc<OutboundManager>,
    ) -> Result<(Self, OpenVpnServerEndpointHandle), OpenVpnServerConnectorError>
    {
        let tag = tag.into();
        options.validate().map_err(|error| {
            OpenVpnServerConnectorError::Options(error.to_string())
        })?;
        let connector = if options.normalized_mode() == "tls" {
            Some(Arc::new(OpenVpnServerConnector::new(
                options.clone(),
                base_path,
            )?))
        } else {
            None
        };
        let handle = OpenVpnServerEndpointHandle {
            connector: connector.clone(),
            network: Arc::default(),
            dialer: Arc::new(OpenVpnServerDialer {
                net: RwLock::default(),
                resolver: Some(resolver.clone()),
                strategy,
                packet_port: Arc::new(OpenVpnServerPacketPort::new(&options)),
            }),
            local_addr: Arc::default(),
            last_error: Arc::default(),
        };
        Ok((
            Self {
                name: format!("endpoint/{tag}"),
                tag,
                options,
                connector,
                base_path: base_path.to_owned(),
                resolver,
                strategy,
                router,
                outbounds,
                handle: handle.clone(),
                cancellation: CancellationToken::new(),
                listener_task: None,
            },
            handle,
        ))
    }

    async fn start_listener(&mut self) -> io::Result<()> {
        self.cancellation = CancellationToken::new();
        if let Ok(mut error) = self.handle.last_error.write() {
            error.take();
        }
        let network = OpenVpnServerNetwork::start(
            &self.options,
            &self.tag,
            self.router.clone(),
            self.outbounds.clone(),
            self.handle.last_error.clone(),
            self.handle.dialer.packet_port.clone(),
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("create OpenVPN server userspace network: {error}"),
            )
        })?;
        let listen_ip = self
            .options
            .listen
            .listen
            .map(|address| address.0)
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let listen_address =
            SocketAddr::new(listen_ip, self.options.listen.listen_port);
        let connector = self.connector.clone();
        let cancellation = self.cancellation.clone();
        let task_network = network.clone();
        let last_error = self.handle.last_error.clone();
        let (local_addr, listener_task) = match (
            self.options.normalized_mode(),
            self.options.normalized_network(),
        ) {
            ("tls", "tcp") => {
                let listener =
                    bind_tcp_listener(listen_address, &self.options.listen)
                        .await?;
                let local_addr = listener.local_addr()?;
                let task = tokio::spawn(async move {
                    if let Err(error) = tcp_server_loop(
                        listener,
                        connector.expect("TLS connector exists"),
                        task_network,
                        cancellation,
                    )
                    .await
                        && let Ok(mut last_error) = last_error.write()
                    {
                        *last_error = Some(error.to_string());
                    }
                });
                (local_addr, task)
            }
            ("tls", "udp") => {
                let socket = Arc::new(
                    bind_udp_listener(listen_address, &self.options.listen)
                        .await?,
                );
                let local_addr = socket.local_addr()?;
                let task = tokio::spawn(async move {
                    if let Err(error) = udp_server_loop(
                        socket,
                        connector.expect("TLS connector exists"),
                        task_network,
                        cancellation,
                    )
                    .await
                        && let Ok(mut last_error) = last_error.write()
                    {
                        *last_error = Some(error.to_string());
                    }
                });
                (local_addr, task)
            }
            ("static_key", "tcp") => {
                let listener =
                    bind_tcp_listener(listen_address, &self.options.listen)
                        .await
                        .map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!(
                                    "bind OpenVPN static-key TCP listener {listen_address} with {:?}: {error}",
                                    self.options.listen
                                ),
                            )
                        })?;
                let local_addr = listener.local_addr()?;
                let options = self.options.clone();
                let base_path = self.base_path.clone();
                let task = tokio::spawn(async move {
                    if let Err(error) = static_tcp_server_loop(
                        listener,
                        options,
                        base_path,
                        task_network,
                        cancellation,
                    )
                    .await
                        && let Ok(mut last_error) = last_error.write()
                    {
                        *last_error = Some(error.to_string());
                    }
                });
                (local_addr, task)
            }
            ("static_key", "udp") => {
                let remote = resolve_static_server_remote(
                    &self.options,
                    &self.resolver,
                    self.strategy,
                )
                .await?;
                let static_listen_address =
                    if self.options.listen.listen.is_some() {
                        listen_address
                    } else {
                        SocketAddr::new(
                            if remote.is_ipv4() {
                                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                            } else {
                                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                            },
                            listen_address.port(),
                        )
                    };
                let socket = Arc::new(
                    bind_udp_listener(
                        static_listen_address,
                        &self.options.listen,
                    )
                    .await?,
                );
                let local_addr = socket.local_addr()?;
                socket.connect(remote).await?;
                let options = self.options.clone();
                let base_path = self.base_path.clone();
                let task = tokio::spawn(async move {
                    if let Err(error) = static_udp_server_loop(
                        socket,
                        remote,
                        options,
                        base_path,
                        task_network,
                        cancellation,
                    )
                    .await
                        && let Ok(mut last_error) = last_error.write()
                    {
                        *last_error = Some(error.to_string());
                    }
                });
                (local_addr, task)
            }
            (mode, network_name) => {
                return Err(invalid(format!(
                    "unsupported OpenVPN server mode/network {mode:?}/{network_name:?}"
                )));
            }
        };
        self.handle
            .dialer
            .activate(network.net.clone(), &network)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "activate OpenVPN server userspace network: {error}"
                    ),
                )
            })?;
        *lock(&self.handle.network, "OpenVPN server network")? = Some(network);
        *write(&self.handle.local_addr, "OpenVPN server address")? =
            Some(local_addr);
        self.listener_task = Some(listener_task);
        Ok(())
    }
}

impl Lifecycle for OpenVpnServerEndpointService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.start_listener()
                .await
                .map_err(|error| LifecycleError::Start {
                    component: self.name.clone(),
                    stage,
                    message: error.to_string(),
                })
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(listener_task) = self.listener_task.take() {
                listener_task.await.map_err(|error| LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                })?;
            }
            self.handle.dialer.deactivate().map_err(|error| {
                LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                }
            })?;
            lock(&self.handle.network, "OpenVPN server network")
                .map_err(|error| LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                })?
                .take();
            write(&self.handle.local_addr, "OpenVPN server address")
                .map_err(|error| LifecycleError::Close {
                    component: self.name.clone(),
                    message: error.to_string(),
                })?
                .take();
            Ok(())
        })
    }
}

struct OpenVpnServerNetwork {
    net: Arc<Net>,
    ingress: mpsc::Sender<io::Result<Vec<u8>>>,
    routes: Arc<RwLock<HashMap<IpAddr, Arc<OpenVpnConnectedServerClient>>>>,
    static_routes: Arc<RwLock<HashMap<IpAddr, Arc<OpenVpnStaticDataSession>>>>,
    last_error: Arc<RwLock<Option<String>>>,
    cancellation: CancellationToken,
    flow_router: Arc<UserspaceEndpointRouter>,
    packet_port: Arc<OpenVpnServerPacketPort>,
    _output_task: AbortOnDropHandle<()>,
}

impl OpenVpnServerNetwork {
    fn start(
        options: &OpenVpnServerEndpointOptions,
        tag: &str,
        router: Arc<crate::route::Router>,
        outbounds: Arc<OutboundManager>,
        last_error: Arc<RwLock<Option<String>>>,
        packet_port: Arc<OpenVpnServerPacketPort>,
    ) -> io::Result<Arc<Self>> {
        let addresses = options
            .address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0.to_string().parse::<IpCidr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|()| invalid("invalid OpenVPN server stack address"))?;
        let gateways = addresses
            .iter()
            .map(IpCidr::address)
            .collect::<Vec<IpAddress>>();
        let local_networks = options
            .address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        let effective_mtu = if options.endpoint.mtu == 0 {
            1500
        } else {
            options.endpoint.mtu.max(576) as usize
        };
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = effective_mtu;
        capabilities.medium = Medium::Ip;
        let (device, ingress, egress, mut output, icmp_errors) =
            ChannelDevice::new(capabilities);
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
        let udp_timeout = options
            .listen
            .udp_timeout
            .0
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(crate::constant::UDP_TIMEOUT);
        let flow_router = UserspaceEndpointRouter::new(
            &net,
            egress,
            tag,
            local_networks,
            false,
            Vec::new(),
            router,
            outbounds,
            udp_timeout,
            options.endpoint.udp_mapping,
            options.endpoint.udp_filtering,
            options.endpoint.udp_nat_max,
            effective_mtu,
        );
        let routes = Arc::new(RwLock::new(HashMap::<
            IpAddr,
            Arc<OpenVpnConnectedServerClient>,
        >::new()));
        let static_routes = Arc::new(RwLock::new(HashMap::<
            IpAddr,
            Arc<OpenVpnStaticDataSession>,
        >::new()));
        let cancellation = CancellationToken::new();
        let task_routes = routes.clone();
        let task_static_routes = static_routes.clone();
        let task_cancellation = cancellation.clone();
        let output_task = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = task_cancellation.cancelled() => break,
                    packet = output.recv() => packet,
                };
                let Some(packet) = packet else { break };
                let Some(destination) = packet_destination(&packet) else {
                    continue;
                };
                let client = task_routes
                    .read()
                    .ok()
                    .and_then(|routes| routes.get(&destination).cloned());
                if let Some(client) = client {
                    let _ = client.active.write_data_packet(&packet).await;
                } else if let Some(client) = task_static_routes
                    .read()
                    .ok()
                    .and_then(|routes| routes.get(&destination).cloned())
                {
                    let _ = client.write_data_packet(&packet).await;
                }
            }
        });
        Ok(Arc::new(Self {
            net,
            ingress,
            routes,
            static_routes,
            last_error,
            cancellation,
            flow_router,
            packet_port,
            _output_task: AbortOnDropHandle::new(output_task),
        }))
    }

    fn register(
        &self,
        client: Arc<OpenVpnConnectedServerClient>,
    ) -> io::Result<Vec<IpAddr>> {
        let mut addresses = Vec::new();
        if let Some(address) = &client.assignment.local_address_ipv4 {
            addresses.push(address.prefix.address);
        }
        if let Some(address) = &client.assignment.local_address_ipv6 {
            addresses.push(address.prefix.address);
        }
        if addresses.is_empty() {
            return Err(invalid("OpenVPN server allocated no client address"));
        }
        let mut routes = write(&self.routes, "OpenVPN server route table")?;
        for address in &addresses {
            if routes.contains_key(address) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "OpenVPN client address {address} is already active"
                    ),
                ));
            }
        }
        for address in &addresses {
            routes.insert(*address, client.clone());
        }
        Ok(addresses)
    }

    fn unregister(
        &self,
        addresses: &[IpAddr],
        client: &Arc<OpenVpnConnectedServerClient>,
    ) {
        if let Ok(mut routes) = self.routes.write() {
            for address in addresses {
                if routes
                    .get(address)
                    .is_some_and(|active| Arc::ptr_eq(active, client))
                {
                    routes.remove(address);
                }
            }
        }
    }

    fn client_addresses(&self) -> Vec<IpAddr> {
        let mut addresses = self
            .routes
            .read()
            .map(|routes| routes.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        if let Ok(static_routes) = self.static_routes.read() {
            addresses.extend(static_routes.keys().copied());
        }
        addresses.sort();
        addresses.dedup();
        addresses
    }

    fn has_static_client(&self) -> bool {
        self.static_routes
            .read()
            .is_ok_and(|routes| !routes.is_empty())
    }

    fn register_static(
        &self,
        client: Arc<OpenVpnStaticDataSession>,
        addresses: &[IpAddr],
    ) -> io::Result<()> {
        if addresses.is_empty() {
            return Err(invalid(
                "OpenVPN static-key server has no peer address",
            ));
        }
        let mut routes = write(
            &self.static_routes,
            "OpenVPN static-key server route table",
        )?;
        for active in routes.values() {
            active.close();
        }
        routes.clear();
        for address in addresses {
            routes.insert(*address, client.clone());
        }
        Ok(())
    }

    fn unregister_static(&self, client: &Arc<OpenVpnStaticDataSession>) {
        if let Ok(mut routes) = self.static_routes.write() {
            routes.retain(|_, active| !Arc::ptr_eq(active, client));
        }
    }

    fn clients(&self) -> Vec<Arc<OpenVpnConnectedServerClient>> {
        let mut clients = Vec::new();
        if let Ok(routes) = self.routes.read() {
            for client in routes.values() {
                if !clients.iter().any(|active| Arc::ptr_eq(active, client)) {
                    clients.push(client.clone());
                }
            }
        }
        clients
    }

    fn record_error(&self, error: &io::Error) {
        if let Ok(mut last_error) = self.last_error.write() {
            *last_error = Some(error.to_string());
        }
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let destination = packet_destination(packet).ok_or_else(|| {
            invalid("OpenVPN server packet port received a malformed IP packet")
        })?;
        let client = self
            .routes
            .read()
            .ok()
            .and_then(|routes| routes.get(&destination).cloned());
        if let Some(client) = client {
            client
                .active
                .write_data_packet(packet)
                .await
                .map(|_| ())
                .map_err(io::Error::other)
        } else if let Some(client) = self
            .static_routes
            .read()
            .ok()
            .and_then(|routes| routes.get(&destination).cloned())
        {
            client
                .write_data_packet(packet)
                .await
                .map(|_| ())
                .map_err(io::Error::other)
        } else {
            Err(io::Error::new(
                io::ErrorKind::HostUnreachable,
                format!("no OpenVPN server client route for {destination}"),
            ))
        }
    }
}

impl Drop for OpenVpnServerNetwork {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut routes) = self.routes.write() {
            for client in routes.values() {
                client.active.close();
            }
            routes.clear();
        }
        if let Ok(mut routes) = self.static_routes.write() {
            for client in routes.values() {
                client.close();
            }
            routes.clear();
        }
    }
}

async fn resolve_static_server_remote(
    options: &OpenVpnServerEndpointOptions,
    resolver: &SharedResolver,
    strategy: DomainStrategy,
) -> io::Result<SocketAddr> {
    let destination =
        SocksAddr::new(options.remote.clone(), options.remote_port);
    match destination {
        SocksAddr::Ip(address) => Ok(address),
        SocksAddr::Domain { host, port } => resolver
            .lookup(&host, strategy)
            .await?
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no address found for {host}"),
                )
            }),
    }
}

fn static_server_peer_addresses(
    options: &OpenVpnServerEndpointOptions,
) -> Vec<IpAddr> {
    options
        .peer_address
        .iter()
        .chain(options.peer_address_ipv6.iter())
        .map(|address| address.0)
        .collect()
}

fn new_static_server_session(
    options: &OpenVpnServerEndpointOptions,
    base_path: &Path,
    transport: Arc<dyn OpenVpnPacketTransport>,
    remote_ip: Option<IpAddr>,
) -> io::Result<Arc<OpenVpnStaticDataSession>> {
    let static_key_material = load_openvpn_static_key_material(
        &options.static_key,
        &options.static_key_path,
        base_path,
    )
    .map_err(io::Error::other)?;
    OpenVpnStaticDataSession::new(
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
            framing: None,
            fragment: 0,
            mss_fix: if options.mss_fix_disabled {
                0
            } else {
                options.mss_fix
            },
            mss_fix_mode: options.mss_fix_mode.clone(),
            transport_network: options.normalized_network().into(),
            remote_ip,
            ping_interval: options.ping_interval.as_std().unwrap_or_default(),
            ping_restart: options.ping_restart.as_std().unwrap_or_default(),
        },
    )
    .map(Arc::new)
    .map_err(io::Error::other)
}

async fn serve_static_server_session(
    session: Arc<OpenVpnStaticDataSession>,
    network: Arc<OpenVpnServerNetwork>,
    peer_addresses: Vec<IpAddr>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    network.register_static(session.clone(), &peer_addresses)?;
    let result = loop {
        let packet = tokio::select! {
            _ = cancellation.cancelled() => break Ok(()),
            packet = session.read_data_packet() => packet,
        };
        let packet = match packet {
            Ok(packet) => packet,
            Err(StaticDataSessionError::Closed)
                if cancellation.is_cancelled() =>
            {
                break Ok(());
            }
            Err(error) => break Err(io::Error::other(error)),
        };
        let source = packet_source(&packet).ok_or_else(|| {
            invalid("OpenVPN static-key peer sent a malformed IP packet")
        })?;
        if !peer_addresses.contains(&source) {
            break Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "OpenVPN static-key peer source {source} does not match its configured peer address"
                ),
            ));
        }
        if network.packet_port.return_packet(&packet) {
            continue;
        }
        match network.flow_router.prepare_packet(&packet).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                network.record_error(&error);
                continue;
            }
        }
        if network.ingress.send(Ok(packet)).await.is_err() {
            break Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "OpenVPN static-key server userspace stack stopped",
            ));
        }
    };
    session.close();
    network.unregister_static(&session);
    if let Err(error) = &result {
        network.record_error(error);
    }
    result
}

async fn static_tcp_server_loop(
    listener: TcpListener,
    options: OpenVpnServerEndpointOptions,
    base_path: std::path::PathBuf,
    network: Arc<OpenVpnServerNetwork>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let peer_addresses = static_server_peer_addresses(&options);
    loop {
        let accepted = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (stream, remote) = accepted?;
        let transport = openvpn_stream_transport(Box::new(stream) as Stream);
        let session = new_static_server_session(
            &options,
            &base_path,
            transport,
            Some(remote.ip()),
        )?;
        let _ = serve_static_server_session(
            session,
            network.clone(),
            peer_addresses.clone(),
            cancellation.child_token(),
        )
        .await;
    }
}

async fn static_udp_server_loop(
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    options: OpenVpnServerEndpointOptions,
    base_path: std::path::PathBuf,
    network: Arc<OpenVpnServerNetwork>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let peer_addresses = static_server_peer_addresses(&options);
    let transport: Arc<dyn OpenVpnPacketTransport> = Arc::new(
        OpenVpnDatagramTransport::new(socket, OPENVPN_SERVER_PACKET_BUFFER),
    );
    loop {
        let session = new_static_server_session(
            &options,
            &base_path,
            transport.clone(),
            Some(remote.ip()),
        )?;
        let result = serve_static_server_session(
            session,
            network.clone(),
            peer_addresses.clone(),
            cancellation.child_token(),
        )
        .await;
        if cancellation.is_cancelled() {
            return Ok(());
        }
        if let Err(error) = result {
            network.record_error(&error);
        }
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
        }
    }
}

async fn tcp_server_loop(
    listener: TcpListener,
    connector: Arc<OpenVpnServerConnector>,
    network: Arc<OpenVpnServerNetwork>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, remote) = accepted?;
                let transport = openvpn_stream_transport(Box::new(stream) as Stream);
                clients.spawn(serve_server_transport(
                    connector.clone(),
                    network.clone(),
                    transport,
                    None,
                    remote.is_ipv6(),
                    cancellation.child_token(),
                ));
            }
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    Ok(())
}

#[derive(Clone)]
struct OpenVpnServerUdpPacket {
    packet: Vec<u8>,
    source: SocketAddr,
}

#[derive(Default)]
struct OpenVpnServerUdpClients {
    active_by_address: HashMap<SocketAddr, Arc<OpenVpnServerUdpClient>>,
    initial_by_address: HashMap<SocketAddr, Arc<OpenVpnServerUdpClient>>,
    by_peer_id: HashMap<u32, Arc<OpenVpnServerUdpClient>>,
}

struct OpenVpnServerUdpClient {
    generation: u64,
    session_id: [u8; 8],
    sender: mpsc::Sender<OpenVpnServerUdpPacket>,
    peer_id: OnceLock<u32>,
    certificate_identity: OnceLock<Option<OpenVpnClientCertificateIdentity>>,
    remote: RwLock<SocketAddr>,
    write_access: AsyncMutex<()>,
    cancellation: CancellationToken,
}

struct OpenVpnServerUdpTransport {
    socket: Arc<UdpSocket>,
    clients: Arc<Mutex<OpenVpnServerUdpClients>>,
    client: Arc<OpenVpnServerUdpClient>,
    incoming: AsyncMutex<mpsc::Receiver<OpenVpnServerUdpPacket>>,
}

impl OpenVpnServerUdpTransport {
    fn activate(
        &self,
        peer_id: u32,
        certificate_identity: Option<OpenVpnClientCertificateIdentity>,
    ) -> io::Result<()> {
        self.client.peer_id.set(peer_id).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN UDP peer-id was already registered",
            )
        })?;
        self.client
            .certificate_identity
            .set(certificate_identity)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "OpenVPN UDP certificate identity was already registered",
                )
            })?;
        let mut clients = lock(&self.clients, "OpenVPN UDP client map")?;
        let remote = *read(&self.client.remote, "OpenVPN UDP peer address")?;
        if !clients
            .initial_by_address
            .get(&remote)
            .is_some_and(|client| Arc::ptr_eq(client, &self.client))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "OpenVPN UDP initial session was displaced before authentication",
            ));
        }
        if let Some(existing) = clients.by_peer_id.get(&peer_id)
            && !Arc::ptr_eq(existing, &self.client)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("OpenVPN UDP peer-id {peer_id} is already active"),
            ));
        }
        clients.initial_by_address.remove(&remote);
        let displaced = clients
            .active_by_address
            .insert(remote, self.client.clone())
            .filter(|client| !Arc::ptr_eq(client, &self.client));
        if let Some(displaced) = &displaced {
            clients
                .active_by_address
                .retain(|_, client| !Arc::ptr_eq(client, displaced));
            clients
                .by_peer_id
                .retain(|_, client| !Arc::ptr_eq(client, displaced));
        }
        clients.by_peer_id.insert(peer_id, self.client.clone());
        drop(clients);
        if let Some(displaced) = displaced {
            displaced.cancellation.cancel();
        }
        Ok(())
    }

    async fn float_authenticated_source(
        &self,
        source: SocketAddr,
    ) -> io::Result<bool> {
        let _write_access = self.client.write_access.lock().await;
        let current = *read(&self.client.remote, "OpenVPN UDP peer address")?;
        if current == source {
            return Ok(true);
        }

        let displaced = {
            let mut clients = lock(&self.clients, "OpenVPN UDP client map")?;
            let Some(peer_id) = self.client.peer_id.get().copied() else {
                return Ok(false);
            };
            if !clients
                .by_peer_id
                .get(&peer_id)
                .is_some_and(|client| Arc::ptr_eq(client, &self.client))
            {
                return Ok(false);
            }

            let existing = clients.active_by_address.get(&source).cloned();
            if let Some(existing) = &existing
                && !Arc::ptr_eq(existing, &self.client)
            {
                let Some(own_identity) = self.client.certificate_identity.get()
                else {
                    return Ok(false);
                };
                let Some(existing_identity) =
                    existing.certificate_identity.get()
                else {
                    return Ok(false);
                };
                if own_identity != existing_identity {
                    return Ok(false);
                }
                clients
                    .active_by_address
                    .retain(|_, client| !Arc::ptr_eq(client, existing));
                clients
                    .by_peer_id
                    .retain(|_, client| !Arc::ptr_eq(client, existing));
            }

            clients.active_by_address.retain(|address, client| {
                !Arc::ptr_eq(client, &self.client) || *address == source
            });
            clients
                .active_by_address
                .insert(source, self.client.clone());
            *write(&self.client.remote, "OpenVPN UDP peer address")? = source;
            existing.filter(|client| !Arc::ptr_eq(client, &self.client))
        };
        if let Some(displaced) = displaced {
            displaced.cancellation.cancel();
        }
        Ok(true)
    }
}

#[async_trait]
impl OpenVpnPacketTransport for OpenVpnServerUdpTransport {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        self.read_packet_with_source()
            .await
            .map(|(packet, _)| packet)
    }

    async fn read_packet_with_source(
        &self,
    ) -> io::Result<(Vec<u8>, Option<SocketAddr>)> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .map(|packet| (packet.packet, Some(packet.source)))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "OpenVPN UDP client transport closed",
                )
            })
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let _write_access = self.client.write_access.lock().await;
        let remote = *read(&self.client.remote, "OpenVPN UDP peer address")?;
        let written = self.socket.send_to(packet, remote).await?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short OpenVPN server UDP packet write",
            ));
        }
        Ok(())
    }

    async fn accept_authenticated_packet_source(
        &self,
        source: Option<SocketAddr>,
    ) -> io::Result<bool> {
        match source {
            Some(source) => self.float_authenticated_source(source).await,
            None => Ok(true),
        }
    }

    fn connection_oriented(&self) -> bool {
        false
    }
}

async fn udp_server_loop(
    socket: Arc<UdpSocket>,
    connector: Arc<OpenVpnServerConnector>,
    network: Arc<OpenVpnServerNetwork>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let clients = Arc::new(Mutex::new(OpenVpnServerUdpClients::default()));
    let generation = AtomicU64::new(1);
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0_u8; OPENVPN_SERVER_PACKET_BUFFER];
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => break,
            received = socket.recv_from(&mut buffer) => received,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let (length, remote) = received?;
        let raw_packet = buffer[..length].to_vec();
        let hard_reset_session_id = udp_hard_reset_session_id(&raw_packet);
        let data_peer_id = udp_data_v2_peer_id(&raw_packet);
        let control_session_id = udp_control_session_id(&raw_packet);
        let existing = {
            let clients = lock(&clients, "OpenVPN UDP client map")?;
            match data_peer_id {
                Some(peer_id) => clients.by_peer_id.get(&peer_id),
                None if control_session_id.is_some() => {
                    let session_id = control_session_id.unwrap();
                    clients
                        .initial_by_address
                        .get(&remote)
                        .filter(|client| client.session_id == session_id)
                        .or_else(|| {
                            clients.active_by_address.get(&remote).filter(
                                |client| client.session_id == session_id,
                            )
                        })
                }
                None => clients.active_by_address.get(&remote),
            }
            .cloned()
        };
        if let Some(existing) = existing
            && existing
                .sender
                .send(OpenVpnServerUdpPacket {
                    packet: raw_packet.clone(),
                    source: remote,
                })
                .await
                .is_ok()
        {
            continue;
        }
        let Some(session_id) = hard_reset_session_id else {
            continue;
        };
        let (sender, receiver) = mpsc::channel(256);
        sender
            .send(OpenVpnServerUdpPacket {
                packet: raw_packet,
                source: remote,
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "new UDP client queue closed",
                )
            })?;
        let generation = generation.fetch_add(1, Ordering::Relaxed);
        let child_cancellation = cancellation.child_token();
        let client = Arc::new(OpenVpnServerUdpClient {
            generation,
            session_id,
            sender,
            peer_id: OnceLock::new(),
            certificate_identity: OnceLock::new(),
            remote: RwLock::new(remote),
            write_access: AsyncMutex::new(()),
            cancellation: child_cancellation.clone(),
        });
        let displaced = lock(&clients, "OpenVPN UDP client map")?
            .initial_by_address
            .insert(remote, client.clone());
        if let Some(displaced) = displaced {
            displaced.cancellation.cancel();
        }
        let udp_transport = Arc::new(OpenVpnServerUdpTransport {
            socket: socket.clone(),
            clients: clients.clone(),
            client: client.clone(),
            incoming: AsyncMutex::new(receiver),
        });
        let transport: Arc<dyn OpenVpnPacketTransport> = udp_transport.clone();
        let connector = connector.clone();
        let network = network.clone();
        let clients = clients.clone();
        tasks.spawn(async move {
            let result = serve_server_transport(
                connector,
                network,
                transport,
                Some(udp_transport),
                remote.is_ipv6(),
                child_cancellation,
            )
            .await;
            if let Ok(mut clients) = clients.lock() {
                clients
                    .active_by_address
                    .retain(|_, entry| entry.generation != generation);
                clients
                    .initial_by_address
                    .retain(|_, entry| entry.generation != generation);
                clients
                    .by_peer_id
                    .retain(|_, entry| entry.generation != generation);
            }
            result
        });
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// OpenVPN control protection intentionally leaves the opcode/key-id byte and
/// eight-byte local session id in cleartext.  Do not parse beyond this header:
/// tls-auth and tls-crypt insert their authentication fields immediately after
/// it, where an unprotected packet parser would expect the ACK count.
fn udp_hard_reset_session_id(raw_packet: &[u8]) -> Option<[u8; 8]> {
    let (&header, body) = raw_packet.split_first()?;
    if !matches!(
        Opcode::from_wire(header >> 3),
        Opcode::ControlHardResetClientV1
            | Opcode::ControlHardResetClientV2
            | Opcode::ControlHardResetClientV3
    ) {
        return None;
    }
    Some(
        body.get(..8)?
            .try_into()
            .expect("checked session-id length"),
    )
}

fn udp_control_session_id(raw_packet: &[u8]) -> Option<[u8; 8]> {
    let (&header, body) = raw_packet.split_first()?;
    let opcode = Opcode::from_wire(header >> 3);
    if !opcode.is_control() && opcode != Opcode::AcknowledgmentV1 {
        return None;
    }
    Some(
        body.get(..8)?
            .try_into()
            .expect("checked session-id length"),
    )
}

/// Data-v2 leaves its 24-bit peer id in cleartext. It selects only a
/// candidate session; the source address is not trusted until the selected
/// session authenticates the encrypted data packet.
fn udp_data_v2_peer_id(raw_packet: &[u8]) -> Option<u32> {
    if raw_packet.len() < 4
        || Opcode::from_wire(raw_packet[0] >> 3) != Opcode::DataV2
    {
        return None;
    }
    let peer_id =
        u32::from_be_bytes([0, raw_packet[1], raw_packet[2], raw_packet[3]]);
    (peer_id != 0x00ff_ffff).then_some(peer_id)
}

async fn serve_server_transport(
    connector: Arc<OpenVpnServerConnector>,
    network: Arc<OpenVpnServerNetwork>,
    transport: Arc<dyn OpenVpnPacketTransport>,
    udp_transport: Option<Arc<OpenVpnServerUdpTransport>>,
    remote_is_ipv6: bool,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let client = match connector.accept(transport, remote_is_ipv6).await {
        Ok(client) => Arc::new(client),
        Err(error) => {
            let error = io::Error::other(error);
            network.record_error(&error);
            return Err(error);
        }
    };
    if let (Some(udp_transport), Some(peer_id)) =
        (&udp_transport, client.assignment.peer_id)
    {
        udp_transport
            .activate(peer_id, client.certificate_identity().cloned())?;
    }
    let addresses = network.register(client.clone())?;
    let supervisor_cancellation = cancellation.child_token();
    let supervisor = client
        .clone()
        .run_renegotiation_supervisor(supervisor_cancellation.clone());
    tokio::pin!(supervisor);
    let result = loop {
        let packet = tokio::select! {
            _ = cancellation.cancelled() => break Ok(()),
            _ = client.replacement_cancelled() => break Ok(()),
            result = &mut supervisor => {
                break result.map_err(io::Error::other);
            }
            packet = client.active.read_data_packet() => packet,
        };
        let packet = match packet {
            Ok(packet) => packet,
            Err(error) => break Err(io::Error::other(error)),
        };
        let source = packet_source(&packet).ok_or_else(|| {
            invalid("OpenVPN client sent a malformed IP packet")
        })?;
        if !addresses.contains(&source) {
            break Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "OpenVPN client {source} is outside its assigned addresses"
                ),
            ));
        }
        if network.packet_port.return_packet(&packet) {
            continue;
        }
        match network.flow_router.prepare_packet(&packet).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                network.record_error(&error);
                continue;
            }
        }
        if network.ingress.send(Ok(packet)).await.is_err() {
            break Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "OpenVPN server userspace stack stopped",
            ));
        }
    };
    supervisor_cancellation.cancel();
    client.active.close();
    network.unregister(&addresses, &client);
    if let Err(error) = &result {
        network.record_error(error);
    }
    result
}

pub struct OpenVpnServerDialer {
    net: RwLock<Option<Arc<Net>>>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
    packet_port: Arc<OpenVpnServerPacketPort>,
}

struct OpenVpnServerPacketPort {
    network: RwLock<Option<Weak<OpenVpnServerNetwork>>>,
    inet4_address: Option<IpAddr>,
    inet6_address: Option<IpAddr>,
    mtu: usize,
    return_path: RwLock<Option<Weak<dyn IpPacketReturn>>>,
}

impl OpenVpnServerPacketPort {
    fn new(options: &OpenVpnServerEndpointOptions) -> Self {
        Self {
            network: RwLock::new(None),
            inet4_address: options
                .address
                .as_slice()
                .iter()
                .map(|prefix| prefix.0.addr())
                .find(IpAddr::is_ipv4),
            inet6_address: options
                .address
                .as_slice()
                .iter()
                .map(|prefix| prefix.0.addr())
                .find(IpAddr::is_ipv6),
            mtu: if options.endpoint.mtu == 0 {
                1500
            } else {
                options.endpoint.mtu.max(576) as usize
            },
            return_path: RwLock::new(None),
        }
    }

    fn activate(&self, network: &Arc<OpenVpnServerNetwork>) -> io::Result<()> {
        *write(&self.network, "OpenVPN server packet port")? =
            Some(Arc::downgrade(network));
        Ok(())
    }

    fn deactivate(&self) -> io::Result<()> {
        write(&self.network, "OpenVPN server packet port")?.take();
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

impl IpPacketPort for OpenVpnServerPacketPort {
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
        let mut current =
            write(&self.return_path, "OpenVPN server packet return")?;
        if let Some(existing) = current.as_ref()
            && existing.upgrade().is_some()
        {
            if existing.ptr_eq(&return_path) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN server packet return path is already attached",
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
            let network = read(&self.network, "OpenVPN server packet port")?
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "OpenVPN server endpoint is not started",
                    )
                })?;
            for packet in packets {
                if packet.is_empty() {
                    continue;
                }
                network.write_packet(&packet).await?;
            }
            Ok(())
        })
    }
}

impl Default for OpenVpnServerDialer {
    fn default() -> Self {
        Self {
            net: RwLock::default(),
            resolver: None,
            strategy: DomainStrategy::AsIs,
            packet_port: Arc::new(OpenVpnServerPacketPort {
                network: RwLock::new(None),
                inet4_address: None,
                inet6_address: None,
                mtu: 1500,
                return_path: RwLock::new(None),
            }),
        }
    }
}

impl OpenVpnServerDialer {
    fn activate(
        &self,
        net: Arc<Net>,
        network: &Arc<OpenVpnServerNetwork>,
    ) -> io::Result<()> {
        self.packet_port.activate(network)?;
        *write(&self.net, "OpenVPN server network")? = Some(net);
        Ok(())
    }

    fn deactivate(&self) -> io::Result<()> {
        self.packet_port.deactivate()?;
        write(&self.net, "OpenVPN server network")?.take();
        Ok(())
    }

    fn net(&self) -> io::Result<Arc<Net>> {
        read(&self.net, "OpenVPN server network")?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "OpenVPN server endpoint is not started",
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

impl Dialer for OpenVpnServerDialer {
    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        Some(self.packet_port.clone())
    }

    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let net = self.net()?;
            let addresses = self.resolve(destination).await?;
            let local_port = net.get_port();
            let mut last_error = None;
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
                        return Ok(Box::new(OpenVpnServerPacketConnection {
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
                        "no compatible OpenVPN server ICMP destination",
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

struct OpenVpnServerPacketConnection {
    socket: Arc<SmoltcpUdpSocket>,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
}

impl PacketConnection for OpenVpnServerPacketConnection {
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
            let address = self
                .resolve(destination)
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

impl OpenVpnServerPacketConnection {
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

fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        Some(6) if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).ok()?,
        ))),
        _ => None,
    }
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        Some(6) if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).ok()?,
        ))),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn lock<'a, T>(
    mutex: &'a Mutex<T>,
    name: &str,
) -> io::Result<std::sync::MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other(format!("{name} lock poisoned")))
}

fn read<'a, T>(
    lock: &'a RwLock<T>,
    name: &str,
) -> io::Result<std::sync::RwLockReadGuard<'a, T>> {
    lock.read()
        .map_err(|_| io::Error::other(format!("{name} lock poisoned")))
}

fn write<'a, T>(
    lock: &'a RwLock<T>,
    name: &str,
) -> io::Result<std::sync::RwLockWriteGuard<'a, T>> {
    lock.write()
        .map_err(|_| io::Error::other(format!("{name} lock poisoned")))
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv6Addr,
        sync::{Arc, Mutex, OnceLock, RwLock},
    };

    use tokio::sync::{Mutex as AsyncMutex, mpsc};
    use tokio_util::sync::CancellationToken;

    use super::{
        Opcode, OpenVpnClientCertificateIdentity, OpenVpnServerUdpClient,
        OpenVpnServerUdpClients, OpenVpnServerUdpTransport, packet_destination,
        packet_source, udp_data_v2_peer_id, udp_hard_reset_session_id,
    };

    async fn test_udp_transport(
        clients: Arc<Mutex<OpenVpnServerUdpClients>>,
        generation: u64,
        remote: std::net::SocketAddr,
        peer_id: u32,
        certificate_identity: Option<OpenVpnClientCertificateIdentity>,
    ) -> Arc<OpenVpnServerUdpTransport> {
        let socket =
            Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (sender, receiver) = mpsc::channel(8);
        let client = Arc::new(OpenVpnServerUdpClient {
            generation,
            session_id: generation.to_be_bytes(),
            sender,
            peer_id: OnceLock::new(),
            certificate_identity: OnceLock::new(),
            remote: RwLock::new(remote),
            write_access: AsyncMutex::new(()),
            cancellation: CancellationToken::new(),
        });
        clients
            .lock()
            .unwrap()
            .initial_by_address
            .insert(remote, client.clone());
        let transport = Arc::new(OpenVpnServerUdpTransport {
            socket,
            clients,
            client,
            incoming: AsyncMutex::new(receiver),
        });
        transport.activate(peer_id, certificate_identity).unwrap();
        transport
    }

    #[test]
    fn extracts_ipv4_and_ipv6_route_addresses() {
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[12..16].copy_from_slice(&[10, 8, 0, 2]);
        ipv4[16..20].copy_from_slice(&[10, 8, 0, 1]);
        assert_eq!(packet_source(&ipv4).unwrap().to_string(), "10.8.0.2");
        assert_eq!(packet_destination(&ipv4).unwrap().to_string(), "10.8.0.1");

        let mut ipv6 = vec![0_u8; 40];
        ipv6[0] = 0x60;
        ipv6[8..24]
            .copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        ipv6[24..40]
            .copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(packet_source(&ipv6).unwrap().to_string(), "fd00::2");
        assert_eq!(packet_destination(&ipv6).unwrap().to_string(), "fd00::1");
    }

    #[test]
    fn extracts_udp_session_before_control_protection_fields() {
        let session_id = *b"client01";
        let mut protected =
            vec![Opcode::ControlHardResetClientV3.wire_value() << 3];
        protected.extend_from_slice(&session_id);
        // The next byte is deliberately not a valid unprotected ACK count.
        // tls-auth/tls-crypt put packet-id/authentication material here.
        protected.extend_from_slice(&[0xff; 48]);
        assert_eq!(udp_hard_reset_session_id(&protected), Some(session_id));

        protected[0] = Opcode::ControlV1.wire_value() << 3;
        assert_eq!(udp_hard_reset_session_id(&protected), None);
        assert_eq!(udp_hard_reset_session_id(&protected[..8]), None);
    }

    #[test]
    fn extracts_data_v2_peer_id_without_treating_sentinel_as_a_route() {
        let mut packet = vec![Opcode::DataV2.wire_value() << 3, 1, 2, 3];
        packet.extend_from_slice(b"encrypted");
        assert_eq!(udp_data_v2_peer_id(&packet), Some(0x010203));

        packet[1..4].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert_eq!(udp_data_v2_peer_id(&packet), None);
        packet[0] = Opcode::DataV1.wire_value() << 3;
        assert_eq!(udp_data_v2_peer_id(&packet), None);
        assert_eq!(udp_data_v2_peer_id(&packet[..3]), None);
    }

    #[tokio::test]
    async fn udp_float_refuses_different_certificate_and_evicts_equal_peer() {
        let clients = Arc::new(Mutex::new(OpenVpnServerUdpClients::default()));
        let identity = |hash| {
            Some(OpenVpnClientCertificateIdentity {
                common_name: "client".into(),
                certificate_hashes: vec![[hash; 32]],
            })
        };
        let first_address = "127.0.0.1:10001".parse().unwrap();
        let conflicting_address = "127.0.0.1:10002".parse().unwrap();
        let equal_address = "127.0.0.1:10003".parse().unwrap();
        let first = test_udp_transport(
            clients.clone(),
            1,
            first_address,
            1,
            identity(1),
        )
        .await;
        let conflicting = test_udp_transport(
            clients.clone(),
            2,
            conflicting_address,
            2,
            identity(2),
        )
        .await;
        assert!(
            !first
                .float_authenticated_source(conflicting_address)
                .await
                .unwrap()
        );
        assert_eq!(*first.client.remote.read().unwrap(), first_address);
        assert!(!conflicting.client.cancellation.is_cancelled());

        let equal = test_udp_transport(
            clients.clone(),
            3,
            equal_address,
            3,
            identity(1),
        )
        .await;
        assert!(
            first
                .float_authenticated_source(equal_address)
                .await
                .unwrap()
        );
        assert_eq!(*first.client.remote.read().unwrap(), equal_address);
        assert!(equal.client.cancellation.is_cancelled());
        let clients = clients.lock().unwrap();
        assert!(
            clients
                .active_by_address
                .get(&equal_address)
                .is_some_and(|client| Arc::ptr_eq(client, &first.client))
        );
        assert!(!clients.by_peer_id.contains_key(&3));
    }
}
