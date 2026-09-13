use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
use std::os::fd::AsRawFd as _;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::{Mutex as AsyncMutex, oneshot},
    time::timeout,
};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::common::platform_network::AutoDetectInterfaceProvider;
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
use crate::common::platform_network::{
    PlatformNetworkInterface, PlatformNetworkProvider, PlatformSocket,
    select_platform_networks,
};
use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, NetworkDialOptions, PacketConnection,
        PacketFuture, PacketStream, Stream, apply_udp_connect,
    },
    common::{
        network::SocksAddr,
        socket::{
            apply_icmp_dialer_options, apply_tcp_dialer_options,
            apply_udp_dialer_options, with_network_namespace,
        },
    },
    dns::manager::SharedResolver,
    option::{
        DirectOutboundOptions, DomainStrategy,
        InterfaceType as OptionInterfaceType, Listable,
        NetworkStrategy as OptionNetworkStrategy,
    },
};

#[derive(Clone)]
pub struct DirectOutbound {
    options: DirectOutboundOptions,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
    udp_fragment_default: bool,
    icmp_flows: Arc<IcmpFlowTable>,
    preference_source: Option<Arc<dyn Dialer>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_provider: Option<Arc<dyn PlatformNetworkProvider>>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network_last_fallback: Arc<Mutex<Option<Instant>>>,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    auto_detect_interface_provider: Option<Arc<AutoDetectInterfaceProvider>>,
}

impl DirectOutbound {
    pub fn new(options: DirectOutboundOptions) -> Self {
        Self {
            options,
            resolver: None,
            strategy: DomainStrategy::AsIs,
            udp_fragment_default: true,
            icmp_flows: Arc::new(IcmpFlowTable::default()),
            preference_source: None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_provider: None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_last_fallback: Arc::new(Mutex::new(None)),
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            auto_detect_interface_provider: None,
        }
    }

    pub fn with_resolver(
        options: DirectOutboundOptions,
        resolver: SharedResolver,
        strategy: DomainStrategy,
    ) -> Self {
        Self::with_resolver_and_udp_fragment_default(
            options, resolver, strategy, true,
        )
    }

    /// Build the default dialer used underneath another protocol or a route
    /// action. Unlike an explicit `type: direct` outbound, sing-box's generic
    /// `dialer.New` path disables UDP fragmentation unless the user overrides
    /// `udp_fragment`.
    pub(crate) fn with_underlay_resolver(
        options: DirectOutboundOptions,
        resolver: SharedResolver,
        strategy: DomainStrategy,
    ) -> Self {
        Self::with_resolver_and_udp_fragment_default(
            options, resolver, strategy, false,
        )
    }

    pub(crate) fn with_resolver_and_udp_fragment_default(
        options: DirectOutboundOptions,
        resolver: SharedResolver,
        strategy: DomainStrategy,
        udp_fragment_default: bool,
    ) -> Self {
        Self {
            options,
            resolver: Some(resolver),
            strategy,
            udp_fragment_default,
            icmp_flows: Arc::new(IcmpFlowTable::default()),
            preference_source: None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_provider: None,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network_last_fallback: Arc::new(Mutex::new(None)),
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            auto_detect_interface_provider: None,
        }
    }

    /// Attach the runtime-scoped Android/Apple network provider used by
    /// explicit `network_strategy`/`network_type` dialer options.
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    pub fn with_platform_network_provider(
        mut self,
        provider: Arc<dyn PlatformNetworkProvider>,
    ) -> Self {
        self.platform_network_provider = Some(provider);
        self
    }

    /// Attach the runtime-owned desktop default-interface monitor.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) fn with_auto_detect_interface_provider(
        mut self,
        provider: Arc<AutoDetectInterfaceProvider>,
    ) -> Self {
        self.auto_detect_interface_provider = Some(provider);
        self
    }

    /// Preserve a dynamic VPN endpoint's negotiated preferred routes while
    /// using this direct dialer for an OS-bound system interface.
    pub(crate) fn with_preference_source(
        mut self,
        source: Arc<dyn Dialer>,
    ) -> Self {
        self.preference_source = Some(source);
        self
    }

    async fn socket_options_for(
        &self,
        destination: SocketAddr,
    ) -> io::Result<crate::option::AbstractDialerOptions> {
        let options = self.options.dialer.abstract_options.clone();
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let options = {
            let mut options = options;
            if uses_platform_network_selection(&options) {
                validate_platform_network_conflicts(&options)?;
                if self.platform_network_provider.is_some() {
                    return Ok(options);
                }
                // Pinned sing-box only activates these graphical-client hints
                // when auto_detect_interface installs a platform bridge.
                options.network_strategy = None;
                options.network_type = Default::default();
                options.fallback_network_type = Default::default();
            }
            options
        };
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let mut options = options;
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        {
            if options.bind_interface.is_empty()
                && options.inet4_bind_address.is_none()
                && options.inet6_bind_address.is_none()
                && let Some(provider) =
                    self.auto_detect_interface_provider.as_ref()
            {
                options.bind_interface =
                    provider.interface_for(destination).await?;
            }
            Ok(options)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = destination;
            Ok(options)
        }
    }

    fn with_network_dial_options(&self, route: &NetworkDialOptions) -> Self {
        let mut direct = self.clone();
        let options = &mut direct.options.dialer.abstract_options;
        if let Some(strategy) = route.strategy {
            options.network_strategy = Some(OptionNetworkStrategy(strategy));
        }
        if !route.network_type.is_empty() {
            options.network_type = Listable(
                route
                    .network_type
                    .iter()
                    .copied()
                    .map(OptionInterfaceType)
                    .collect(),
            );
        }
        if !route.fallback_network_type.is_empty() {
            options.fallback_network_type = Listable(
                route
                    .fallback_network_type
                    .iter()
                    .copied()
                    .map(OptionInterfaceType)
                    .collect(),
            );
        }
        if let Some(delay) =
            route.fallback_delay.filter(|delay| !delay.is_zero())
        {
            options.fallback_delay = crate::option::Duration::from_nanos(
                i64::try_from(delay.as_nanos()).unwrap_or(i64::MAX),
            );
        }
        direct
    }

    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    fn should_use_platform_network_selection(
        &self,
        options: &crate::option::AbstractDialerOptions,
    ) -> bool {
        if !uses_platform_network_selection(options) {
            return false;
        }
        self.platform_network_provider.is_some()
    }

    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    fn platform_fast_fallback_active(&self) -> bool {
        self.platform_network_last_fallback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|last_fallback| {
                last_fallback.elapsed() < PLATFORM_FAST_FALLBACK_WINDOW
            })
    }

    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    fn mark_platform_fallback(&self) {
        *self
            .platform_network_last_fallback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(Instant::now());
    }

    async fn connect(&self, destination: &SocksAddr) -> io::Result<TcpStream> {
        let addresses = self.resolve(destination).await?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses for {destination}"),
            ));
        }
        let options = &self.options.dialer.abstract_options;
        let timeout_duration = options
            .connect_timeout
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(Duration::from_secs(5));
        let addresses4: Vec<_> = addresses
            .iter()
            .copied()
            .filter(SocketAddr::is_ipv4)
            .collect();
        let addresses6: Vec<_> = addresses
            .iter()
            .copied()
            .filter(SocketAddr::is_ipv6)
            .collect();
        if addresses4.is_empty() || addresses6.is_empty() {
            return self.connect_serial(&addresses, timeout_duration).await;
        }
        let (primary, fallback) = if self.strategy == DomainStrategy::PreferIpv6
        {
            (addresses6, addresses4)
        } else {
            (addresses4, addresses6)
        };
        let fallback_delay = options
            .fallback_delay
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(Duration::from_millis(300));
        let primary_connect = self.connect_serial(&primary, timeout_duration);
        tokio::pin!(primary_connect);
        match timeout(fallback_delay, &mut primary_connect).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(primary_error)) => self
                .connect_serial(&fallback, timeout_duration)
                .await
                .map_err(|_| primary_error),
            Err(_) => {
                let fallback_connect =
                    self.connect_serial(&fallback, timeout_duration);
                tokio::pin!(fallback_connect);
                let mut primary_error = None;
                let mut fallback_error = None;
                loop {
                    tokio::select! {
                        result = &mut primary_connect, if primary_error.is_none() => match result {
                            Ok(stream) => return Ok(stream),
                            Err(error) => primary_error = Some(error),
                        },
                        result = &mut fallback_connect, if fallback_error.is_none() => match result {
                            Ok(stream) => return Ok(stream),
                            Err(error) => fallback_error = Some(error),
                        },
                    }
                    if fallback_error.is_some()
                        && let Some(error) = primary_error.take()
                    {
                        return Err(error);
                    }
                }
            }
        }
    }

    async fn connect_serial(
        &self,
        addresses: &[SocketAddr],
        timeout_duration: Duration,
    ) -> io::Result<TcpStream> {
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let options = &self.options.dialer.abstract_options;
        let mut last_error = None;
        for address in addresses.iter().copied() {
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            if self.should_use_platform_network_selection(options) {
                match self
                    .connect_address_on_platform_network(
                        address,
                        timeout_duration,
                    )
                    .await
                {
                    Ok(stream) => return Ok(stream),
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                }
            }
            let socket_options = self.socket_options_for(address).await?;
            let namespace = socket_options.netns.clone();
            let socket = with_network_namespace(&namespace, move || {
                let socket = new_tcp_socket(
                    address,
                    socket_options.tcp_multi_path && address.is_ipv4(),
                )?;
                apply_tcp_dialer_options(&socket, address, &socket_options)?;
                let bind = match address.ip() {
                    IpAddr::V4(_) => socket_options
                        .inet4_bind_address
                        .map(|address| address.0),
                    IpAddr::V6(_) => socket_options
                        .inet6_bind_address
                        .map(|address| address.0),
                };
                if let Some(bind) = bind {
                    socket.bind(SocketAddr::new(bind, 0))?;
                }
                Ok(socket)
            })
            .await?;
            match timeout(timeout_duration, socket.connect(address)).await {
                Ok(Ok(stream)) => {
                    stream.set_nodelay(true)?;
                    return Ok(stream);
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connect to {address} timed out"),
                    ));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::other("connect failed")))
    }

    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    async fn connect_address_on_platform_network(
        &self,
        address: SocketAddr,
        timeout_duration: Duration,
    ) -> io::Result<TcpStream> {
        let options = &self.options.dialer.abstract_options;
        validate_platform_network_conflicts(options)?;
        let provider =
            self.platform_network_provider.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "network_strategy requires a PlatformNetworkProvider",
                )
            })?;
        let selection =
            select_platform_networks(options, provider.network_interfaces()?)?;
        if selection.primary.is_empty() {
            let result = race_tcp_interfaces(
                provider,
                selection.fallback,
                address,
                options,
                timeout_duration,
            )
            .await;
            if result.is_ok() && !self.platform_fast_fallback_active() {
                self.mark_platform_fallback();
            }
            return result;
        }
        if selection.fallback.is_empty() {
            return race_tcp_interfaces(
                provider,
                selection.primary,
                address,
                options,
                timeout_duration,
            )
            .await;
        }
        let fallback_delay = options
            .fallback_delay
            .as_std()
            .filter(|duration| !duration.is_zero())
            .unwrap_or(Duration::from_millis(300));
        if self.platform_fast_fallback_active() {
            return race_tcp_interfaces_fast_fallback(FastFallbackRace {
                provider: provider.clone(),
                primary_interfaces: selection.primary,
                fallback_interfaces: selection.fallback,
                address,
                options: options.clone(),
                timeout_duration,
                fallback_delay,
                last_fallback: self.platform_network_last_fallback.clone(),
            })
            .await;
        }
        let primary = race_tcp_interfaces(
            provider,
            selection.primary,
            address,
            options,
            timeout_duration,
        );
        tokio::pin!(primary);
        match timeout(fallback_delay, &mut primary).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(primary_error)) => {
                let result = race_tcp_interfaces(
                    provider,
                    selection.fallback,
                    address,
                    options,
                    timeout_duration,
                )
                .await
                .map_err(|_| primary_error);
                if result.is_ok() {
                    self.mark_platform_fallback();
                }
                result
            }
            Err(_) => {
                let fallback = race_tcp_interfaces(
                    provider,
                    selection.fallback,
                    address,
                    options,
                    timeout_duration,
                );
                tokio::pin!(fallback);
                tokio::select! {
                    result = &mut primary => match result {
                        Ok(stream) => Ok(stream),
                        Err(primary_error) => {
                            let result = fallback.await.map_err(|_| primary_error);
                            if result.is_ok() {
                                self.mark_platform_fallback();
                            }
                            result
                        },
                    },
                    result = &mut fallback => match result {
                        Ok(stream) => {
                            self.mark_platform_fallback();
                            Ok(stream)
                        },
                        Err(_) => primary.await,
                    },
                }
            }
        }
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

    async fn listen_packet(
        &self,
        destination: &SocksAddr,
        local_port: u16,
        disable_domain_unmapping: bool,
    ) -> io::Result<DirectPacketConnection> {
        let addresses = self.resolve(destination).await?;
        let target = addresses.first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses for {destination}"),
            )
        })?;
        let options = &self.options.dialer.abstract_options;
        let bind = match target.ip() {
            IpAddr::V4(_) => options
                .inet4_bind_address
                .map(|address| address.0)
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            IpAddr::V6(_) => options
                .inet6_bind_address
                .map(|address| address.0)
                .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        };
        let mut socket_options = self.socket_options_for(*target).await?;
        if socket_options.udp_fragment.is_none() && !self.udp_fragment_default {
            socket_options.udp_fragment = Some(false);
        }
        let target = *target;
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        if self.should_use_platform_network_selection(&socket_options) {
            return self
                .listen_packet_on_platform_network(
                    target,
                    bind,
                    local_port,
                    socket_options,
                    disable_domain_unmapping,
                )
                .await;
        }
        let namespace = socket_options.netns.clone();
        let socket = with_network_namespace(&namespace, move || {
            let socket = Socket::new(
                if target.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                },
                Type::DGRAM,
                Some(Protocol::UDP),
            )?;
            apply_udp_dialer_options(&socket, target, &socket_options)?;
            socket.set_nonblocking(true)?;
            socket.bind(&SocketAddr::new(bind, local_port).into())?;
            let socket: std::net::UdpSocket = socket.into();
            Ok(socket)
        })
        .await?;
        let socket = UdpSocket::from_std(socket)?;
        Ok(DirectPacketConnection {
            socket,
            resolver: self.resolver.clone(),
            strategy: self.strategy,
            domain_unmapping: Mutex::new(HashMap::new()),
            disable_domain_unmapping,
        })
    }

    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    async fn listen_packet_on_platform_network(
        &self,
        target: SocketAddr,
        bind: IpAddr,
        local_port: u16,
        options: crate::option::AbstractDialerOptions,
        disable_domain_unmapping: bool,
    ) -> io::Result<DirectPacketConnection> {
        validate_platform_network_conflicts(&options)?;
        let provider =
            self.platform_network_provider.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "network_strategy requires a PlatformNetworkProvider",
                )
            })?;
        let selection =
            select_platform_networks(&options, provider.network_interfaces()?)?;
        let mut errors = Vec::new();
        for interface in selection.primary.into_iter().chain(selection.fallback)
        {
            match open_udp_on_platform_interface(
                provider.clone(),
                interface,
                target,
                bind,
                local_port,
                options.clone(),
            )
            .await
            {
                Ok(socket) => {
                    return Ok(DirectPacketConnection {
                        socket,
                        resolver: self.resolver.clone(),
                        strategy: self.strategy,
                        domain_unmapping: Mutex::new(HashMap::new()),
                        disable_domain_unmapping,
                    });
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        Err(io::Error::other(errors.join("; ")))
    }

    async fn exchange_icmp_packet(
        &self,
        packet: &[u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &SocksAddr,
    ) -> io::Result<IcmpResponse> {
        if packet.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated ICMP echo request",
            ));
        }
        let ipv4 = source.is_ipv4();
        let request_type = if ipv4 { 8 } else { 128 };
        if packet[0] != request_type || packet[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only ICMP echo requests can be forwarded",
            ));
        }
        let identifier = u16::from_be_bytes([packet[4], packet[5]]);
        let sequence = u16::from_be_bytes([packet[6], packet[7]]);
        let target = self
            .resolve(destination)
            .await?
            .into_iter()
            .find(|address| address.is_ipv4() == ipv4)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no compatible ICMP address for {destination}"),
                )
            })?;
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        if self.should_use_platform_network_selection(
            &self.options.dialer.abstract_options,
        ) {
            let options = &self.options.dialer.abstract_options;
            validate_platform_network_conflicts(options)?;
            let provider =
                self.platform_network_provider.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "network_strategy requires a PlatformNetworkProvider",
                    )
                })?;
            let selection = select_platform_networks(
                options,
                provider.network_interfaces()?,
            )?;
            let mut errors = Vec::new();
            for interface in
                selection.primary.into_iter().chain(selection.fallback)
            {
                let flow = self
                    .icmp_flows
                    .flow_for(
                        IcmpFlowKey {
                            source,
                            destination: target.ip(),
                            identifier,
                            platform_network: Some(platform_network_key(
                                &interface,
                            )),
                        },
                        target,
                        options,
                        Some((provider.clone(), interface)),
                    )
                    .await;
                match flow {
                    Ok(flow) => {
                        return flow
                            .exchange(packet, sequence, hop_limit)
                            .await;
                    }
                    Err(error) => errors.push(error.to_string()),
                }
            }
            return Err(io::Error::other(errors.join("; ")));
        }
        let socket_options = self.socket_options_for(target).await?;
        let flow = self
            .icmp_flows
            .flow_for(
                IcmpFlowKey {
                    source,
                    destination: target.ip(),
                    identifier,
                    #[cfg(any(
                        target_os = "android",
                        target_os = "ios",
                        target_os = "macos"
                    ))]
                    platform_network: None,
                },
                target,
                &socket_options,
                #[cfg(any(
                    target_os = "android",
                    target_os = "ios",
                    target_os = "macos"
                ))]
                None,
            )
            .await?;
        flow.exchange(packet, sequence, hop_limit).await
    }
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
const PLATFORM_FAST_FALLBACK_WINDOW: Duration = Duration::from_secs(15);

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
fn uses_platform_network_selection(
    options: &crate::option::AbstractDialerOptions,
) -> bool {
    options.network_strategy.is_some()
        || !options.network_type.as_slice().is_empty()
        || !options.fallback_network_type.as_slice().is_empty()
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
fn validate_platform_network_conflicts(
    options: &crate::option::AbstractDialerOptions,
) -> io::Result<()> {
    let disables_default_bind = !options.bind_interface.is_empty()
        || options.inet4_bind_address.is_some()
        || options.inet6_bind_address.is_some();
    let explicit_selection = options.network_strategy.is_some()
        || (!options.network_type.as_slice().is_empty()
            && options.fallback_network_type.as_slice().is_empty()
            && options
                .fallback_delay
                .as_std()
                .is_none_or(|delay| delay.is_zero()));
    if (disables_default_bind || options.tcp_fast_open) && explicit_selection {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "network_strategy conflicts with bind_interface, inet4_bind_address, inet6_bind_address and tcp_fast_open",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
fn platform_network_key(interface: &PlatformNetworkInterface) -> u64 {
    use std::hash::{Hash as _, Hasher as _};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    interface.id.hash(&mut hasher);
    interface.index.hash(&mut hasher);
    hasher.finish()
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
async fn race_tcp_interfaces(
    provider: &Arc<dyn PlatformNetworkProvider>,
    interfaces: Vec<PlatformNetworkInterface>,
    address: SocketAddr,
    options: &crate::option::AbstractDialerOptions,
    timeout_duration: Duration,
) -> io::Result<TcpStream> {
    use futures_util::{StreamExt as _, stream::FuturesUnordered};

    if interfaces.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no available network interface",
        ));
    }
    let mut attempts = interfaces
        .into_iter()
        .map(|interface| {
            connect_tcp_interface(
                provider.clone(),
                interface,
                address,
                options.clone(),
                timeout_duration,
            )
        })
        .collect::<FuturesUnordered<_>>();
    let mut errors = Vec::new();
    while let Some(result) = attempts.next().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => errors.push(error.to_string()),
        }
    }
    Err(io::Error::other(errors.join("; ")))
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
struct FastFallbackRace {
    provider: Arc<dyn PlatformNetworkProvider>,
    primary_interfaces: Vec<PlatformNetworkInterface>,
    fallback_interfaces: Vec<PlatformNetworkInterface>,
    address: SocketAddr,
    options: crate::option::AbstractDialerOptions,
    timeout_duration: Duration,
    fallback_delay: Duration,
    last_fallback: Arc<Mutex<Option<Instant>>>,
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
async fn race_tcp_interfaces_fast_fallback(
    race: FastFallbackRace,
) -> io::Result<TcpStream> {
    let FastFallbackRace {
        provider,
        primary_interfaces,
        fallback_interfaces,
        address,
        options,
        timeout_duration,
        fallback_delay,
        last_fallback,
    } = race;
    let primary_provider = provider.clone();
    let primary_options = options.clone();
    let started_at = Instant::now();
    let mut primary = tokio::spawn(async move {
        race_tcp_interfaces(
            &primary_provider,
            primary_interfaces,
            address,
            &primary_options,
            timeout_duration,
        )
        .await
    });
    let mut primary_abort = AbortTaskOnDrop::new(primary.abort_handle());
    let fallback = race_tcp_interfaces(
        &provider,
        fallback_interfaces,
        address,
        &options,
        timeout_duration,
    );
    tokio::pin!(fallback);
    tokio::select! {
        primary_result = &mut primary => {
            primary_abort.disarm();
            match primary_result.map_err(|error| io::Error::other(error.to_string()))? {
                Ok(stream) => Ok(stream),
                Err(primary_error) => fallback.await.map_err(|_| primary_error),
            }
        }
        fallback_result = &mut fallback => {
            match fallback_result {
                Ok(stream) => {
                    primary_abort.disarm();
                    tokio::spawn(async move {
                        clear_fast_fallback_if_primary_recovers(
                            primary,
                            started_at,
                            fallback_delay,
                            last_fallback,
                        )
                        .await;
                    });
                    Ok(stream)
                }
                Err(_) => {
                    let result = primary
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    primary_abort.disarm();
                    result
                },
            }
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
struct AbortTaskOnDrop(Option<tokio::task::AbortHandle>);

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
impl AbortTaskOnDrop {
    fn new(handle: tokio::task::AbortHandle) -> Self {
        Self(Some(handle))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
impl Drop for AbortTaskOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
async fn clear_fast_fallback_if_primary_recovers<T>(
    primary: tokio::task::JoinHandle<io::Result<T>>,
    started_at: Instant,
    fallback_delay: Duration,
    last_fallback: Arc<Mutex<Option<Instant>>>,
) {
    if primary.await.is_ok_and(|result| result.is_ok())
        && started_at.elapsed() <= fallback_delay
    {
        *last_fallback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
async fn connect_tcp_interface(
    provider: Arc<dyn PlatformNetworkProvider>,
    interface: PlatformNetworkInterface,
    address: SocketAddr,
    mut options: crate::option::AbstractDialerOptions,
    timeout_duration: Duration,
) -> io::Result<TcpStream> {
    options.network_strategy = None;
    options.network_type = Default::default();
    options.fallback_network_type = Default::default();
    let namespace = options.netns.clone();
    let interface_name = interface.name.clone();
    let interface_index = interface.index;
    let socket = with_network_namespace(&namespace, move || {
        let socket = new_tcp_socket(
            address,
            options.tcp_multi_path && address.is_ipv4(),
        )?;
        apply_tcp_dialer_options(&socket, address, &options)?;
        provider.bind_socket(
            PlatformSocket {
                raw_handle: i64::from(socket.as_raw_fd()),
                ipv6: address.is_ipv6(),
            },
            &interface,
        )?;
        let bind = match address.ip() {
            IpAddr::V4(_) => {
                options.inet4_bind_address.map(|address| address.0)
            }
            IpAddr::V6(_) => {
                options.inet6_bind_address.map(|address| address.0)
            }
        };
        if let Some(bind) = bind {
            socket.bind(SocketAddr::new(bind, 0))?;
        }
        Ok(socket)
    })
    .await
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "prepare TCP socket for {interface_name} ({}): {error}",
                interface_index
            ),
        )
    })?;
    match timeout(timeout_duration, socket.connect(address)).await {
        Ok(Ok(stream)) => {
            stream.set_nodelay(true)?;
            Ok(stream)
        }
        Ok(Err(error)) => Err(io::Error::new(
            error.kind(),
            format!(
                "dial {interface_name} ({}) to {address}: {error}",
                interface_index
            ),
        )),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "dial {interface_name} ({}) to {address} timed out",
                interface_index
            ),
        )),
    }
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
async fn open_udp_on_platform_interface(
    provider: Arc<dyn PlatformNetworkProvider>,
    interface: PlatformNetworkInterface,
    target: SocketAddr,
    bind: IpAddr,
    local_port: u16,
    mut options: crate::option::AbstractDialerOptions,
) -> io::Result<UdpSocket> {
    options.network_strategy = None;
    options.network_type = Default::default();
    options.fallback_network_type = Default::default();
    let namespace = options.netns.clone();
    let interface_name = interface.name.clone();
    let interface_index = interface.index;
    let socket = with_network_namespace(&namespace, move || {
        let socket = Socket::new(
            if target.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        apply_udp_dialer_options(&socket, target, &options)?;
        provider.bind_socket(
            PlatformSocket {
                raw_handle: i64::from(socket.as_raw_fd()),
                ipv6: target.is_ipv6(),
            },
            &interface,
        )?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::new(bind, local_port).into())?;
        let socket: std::net::UdpSocket = socket.into();
        Ok(socket)
    })
    .await
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "listen UDP on {interface_name} ({interface_index}): {error}"
            ),
        )
    })?;
    UdpSocket::from_std(socket)
}

const ICMP_REQUESTS_LIMIT: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IcmpFlowKey {
    source: IpAddr,
    destination: IpAddr,
    identifier: u16,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
    platform_network: Option<u64>,
}

struct IcmpFlowTable {
    flows: Mutex<HashMap<IcmpFlowKey, Arc<IcmpFlow>>>,
    idle_timeout: Duration,
}

impl Default for IcmpFlowTable {
    fn default() -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            idle_timeout: crate::constant::ICMP_TIMEOUT,
        }
    }
}

impl IcmpFlowTable {
    async fn flow_for(
        &self,
        key: IcmpFlowKey,
        target: SocketAddr,
        options: &crate::option::AbstractDialerOptions,
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        platform_network: Option<(
            Arc<dyn PlatformNetworkProvider>,
            PlatformNetworkInterface,
        )>,
    ) -> io::Result<Arc<IcmpFlow>> {
        {
            let mut flows = self.flows.lock().map_err(|_| {
                io::Error::other("ICMP flow table lock poisoned")
            })?;
            flows.retain(|_, flow| !flow.closed.load(Ordering::Acquire));
            if let Some(flow) = flows.get(&key) {
                return Ok(flow.clone());
            }
        }
        let created = IcmpFlow::new(
            key,
            target,
            options,
            self.idle_timeout,
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            platform_network,
        )
        .await?;
        let (flow, inserted) = {
            let mut flows = self.flows.lock().map_err(|_| {
                io::Error::other("ICMP flow table lock poisoned")
            })?;
            flows.retain(|_, flow| !flow.closed.load(Ordering::Acquire));
            if let Some(flow) = flows.get(&key) {
                (flow.clone(), false)
            } else {
                flows.insert(key, created.clone());
                (created, true)
            }
        };
        if inserted {
            flow.start_reader();
        }
        Ok(flow)
    }

    #[cfg(all(test, unix))]
    fn flow_count(&self) -> usize {
        let mut flows = self.flows.lock().expect("ICMP flow table lock");
        flows.retain(|_, flow| !flow.closed.load(Ordering::Acquire));
        flows.len()
    }
}

struct PendingIcmpRequest {
    token: u64,
    sender: oneshot::Sender<IcmpResponse>,
}

struct IcmpFlow {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    source: IpAddr,
    ipv4: bool,
    identifier: u16,
    idle_timeout: Duration,
    last_active: Mutex<std::time::Instant>,
    pending: Mutex<HashMap<u16, VecDeque<PendingIcmpRequest>>>,
    send_access: AsyncMutex<()>,
    next_token: AtomicU64,
    closed: AtomicBool,
}

impl IcmpFlow {
    async fn new(
        key: IcmpFlowKey,
        target: SocketAddr,
        options: &crate::option::AbstractDialerOptions,
        idle_timeout: Duration,
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        platform_network: Option<(
            Arc<dyn PlatformNetworkProvider>,
            PlatformNetworkInterface,
        )>,
    ) -> io::Result<Arc<Self>> {
        let ipv4 = target.is_ipv4();
        let bind = match target.ip() {
            IpAddr::V4(_) => options
                .inet4_bind_address
                .map(|address| address.0)
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            IpAddr::V6(_) => options
                .inet6_bind_address
                .map(|address| address.0)
                .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        };
        let namespace = options.netns.clone();
        let socket_options = options.clone();
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "macos"
        ))]
        let socket_options = if platform_network.is_some() {
            let mut socket_options = socket_options;
            socket_options.network_strategy = None;
            socket_options.network_type = Default::default();
            socket_options.fallback_network_type = Default::default();
            socket_options
        } else {
            socket_options
        };
        let socket = with_network_namespace(&namespace, move || {
            let socket = Socket::new(
                if ipv4 { Domain::IPV4 } else { Domain::IPV6 },
                Type::DGRAM,
                Some(if ipv4 {
                    Protocol::ICMPV4
                } else {
                    Protocol::ICMPV6
                }),
            )?;
            apply_icmp_dialer_options(&socket, target, &socket_options)?;
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "macos"
            ))]
            if let Some((provider, interface)) = platform_network.as_ref() {
                provider.bind_socket(
                    PlatformSocket {
                        raw_handle: i64::from(socket.as_raw_fd()),
                        ipv6: target.is_ipv6(),
                    },
                    interface,
                )?;
            }
            socket.bind(&SocketAddr::new(bind, 0).into())?;
            socket.set_nonblocking(true)?;
            let socket: std::net::UdpSocket = socket.into();
            Ok(socket)
        })
        .await?;
        Ok(Arc::new(Self {
            socket: Arc::new(UdpSocket::from_std(socket)?),
            target,
            source: key.source,
            ipv4,
            identifier: key.identifier,
            idle_timeout,
            last_active: Mutex::new(std::time::Instant::now()),
            pending: Mutex::new(HashMap::new()),
            send_access: AsyncMutex::new(()),
            next_token: AtomicU64::new(1),
            closed: AtomicBool::new(false),
        }))
    }

    fn start_reader(self: &Arc<Self>) {
        let flow = self.clone();
        tokio::spawn(async move { flow.read_loop().await });
    }

    async fn exchange(
        self: &Arc<Self>,
        packet: &[u8],
        sequence: u16,
        hop_limit: u8,
    ) -> io::Result<IcmpResponse> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "ICMP flow is closed",
            ));
        }
        let (sender, receiver) = oneshot::channel();
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| io::Error::other("ICMP request lock poisoned"))?;
            let request_count =
                pending.values().map(VecDeque::len).sum::<usize>();
            if request_count >= ICMP_REQUESTS_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "too many pending ICMP requests in flow",
                ));
            }
            pending
                .entry(sequence)
                .or_default()
                .push_back(PendingIcmpRequest { token, sender });
        }
        let _guard = PendingIcmpGuard {
            flow: Arc::downgrade(self),
            sequence,
            token,
        };
        self.touch();
        self.send_packet(packet, hop_limit).await?;
        timeout(self.idle_timeout, receiver)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "ICMP exchange with {} timed out",
                        self.target.ip()
                    ),
                )
            })?
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "ICMP flow closed before receiving a reply",
                )
            })
    }

    async fn send_packet(
        &self,
        packet: &[u8],
        hop_limit: u8,
    ) -> io::Result<()> {
        let _send_guard = self.send_access.lock().await;
        if self.ipv4 {
            self.socket.set_ttl(u32::from(hop_limit.max(1)))?;
        } else {
            socket2::SockRef::from(self.socket.as_ref())
                .set_unicast_hops_v6(u32::from(hop_limit.max(1)))?;
        }
        self.socket.send_to(packet, self.target).await?;
        Ok(())
    }

    async fn read_loop(self: Arc<Self>) {
        let mut response = vec![0_u8; 65_535];
        loop {
            match timeout(
                self.idle_timeout,
                self.socket.recv_from(&mut response),
            )
            .await
            {
                Ok(Ok((length, response_source))) => {
                    if let Ok((icmp_offset, hop_limit, response_ip)) =
                        received_icmp_layout(
                            &response[..length],
                            response_source.ip(),
                            self.ipv4,
                        )
                    {
                        self.dispatch_response(
                            &response[icmp_offset..length],
                            response_ip,
                            hop_limit,
                        );
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    let idle = self
                        .last_active
                        .lock()
                        .map(|last| last.elapsed() >= self.idle_timeout)
                        .unwrap_or(true);
                    let no_pending = self
                        .pending
                        .lock()
                        .map(|pending| pending.is_empty())
                        .unwrap_or(true);
                    if idle && no_pending {
                        break;
                    }
                }
            }
        }
        self.closed.store(true, Ordering::Release);
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
    }

    fn dispatch_response(
        &self,
        message: &[u8],
        response_ip: IpAddr,
        hop_limit: u8,
    ) {
        let Some((sequence, packet)) = self.prepare_response(message) else {
            return;
        };
        let sender = self.pending.lock().ok().and_then(|mut pending| {
            let queue = pending.get_mut(&sequence)?;
            let sender = queue.pop_front()?.sender;
            if queue.is_empty() {
                pending.remove(&sequence);
            }
            Some(sender)
        });
        let Some(sender) = sender else {
            return;
        };
        self.touch();
        let _ = sender.send(IcmpResponse {
            source: response_ip,
            packet,
            hop_limit,
        });
    }

    fn prepare_response(&self, message: &[u8]) -> Option<(u16, Vec<u8>)> {
        if message.len() < 8 {
            return None;
        }
        let echo_reply = if self.ipv4 { 0 } else { 129 };
        if message[0] == echo_reply && message[1] == 0 {
            let sequence = u16::from_be_bytes([message[6], message[7]]);
            let mut packet = message.to_vec();
            packet[4..6].copy_from_slice(&self.identifier.to_be_bytes());
            if self.ipv4 {
                packet[2..4].fill(0);
                let checksum = internet_checksum(&packet);
                packet[2..4].copy_from_slice(&checksum.to_be_bytes());
            }
            return Some((sequence, packet));
        }
        match (self.source, self.target.ip()) {
            (IpAddr::V4(source), IpAddr::V4(target)) => {
                rewrite_icmpv4_error(message, source, target, self.identifier)
            }
            (IpAddr::V6(source), IpAddr::V6(target)) => {
                rewrite_icmpv6_error(message, source, target, self.identifier)
            }
            _ => None,
        }
    }

    fn touch(&self) {
        if let Ok(mut last_active) = self.last_active.lock() {
            *last_active = std::time::Instant::now();
        }
    }

    fn remove_pending(&self, sequence: u16, token: u64) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let Some(queue) = pending.get_mut(&sequence) else {
            return;
        };
        if let Some(index) =
            queue.iter().position(|request| request.token == token)
        {
            queue.remove(index);
        }
        if queue.is_empty() {
            pending.remove(&sequence);
        }
    }

    #[cfg(all(test, unix))]
    fn pending_count(&self) -> usize {
        self.pending
            .lock()
            .expect("ICMP request lock")
            .values()
            .map(VecDeque::len)
            .sum()
    }
}

struct PendingIcmpGuard {
    flow: Weak<IcmpFlow>,
    sequence: u16,
    token: u64,
}

impl Drop for PendingIcmpGuard {
    fn drop(&mut self) {
        if let Some(flow) = self.flow.upgrade() {
            flow.remove_pending(self.sequence, self.token);
        }
    }
}

pub(crate) fn rewrite_icmpv4_error(
    message: &[u8],
    source: std::net::Ipv4Addr,
    target: std::net::Ipv4Addr,
    identifier: u16,
) -> Option<(u16, Vec<u8>)> {
    if message.len() < 36 || !matches!(message[0], 3 | 11) {
        return None;
    }
    let inner_offset = 8;
    if message[inner_offset] >> 4 != 4 {
        return None;
    }
    let inner_header_len = usize::from(message[inner_offset] & 0x0f) * 4;
    let inner_icmp_offset = inner_offset.checked_add(inner_header_len)?;
    if inner_header_len < 20 || message.len() < inner_icmp_offset + 8 {
        return None;
    }
    if message[inner_offset + 9] != 1
        || message[inner_icmp_offset] != 8
        || message[inner_icmp_offset + 1] != 0
        || message[inner_offset + 16..inner_offset + 20] != target.octets()
    {
        return None;
    }
    let sequence = u16::from_be_bytes([
        message[inner_icmp_offset + 6],
        message[inner_icmp_offset + 7],
    ]);
    let mut packet = message.to_vec();
    packet[inner_offset + 12..inner_offset + 16]
        .copy_from_slice(&source.octets());
    packet[inner_icmp_offset + 4..inner_icmp_offset + 6]
        .copy_from_slice(&identifier.to_be_bytes());
    packet[inner_icmp_offset + 2..inner_icmp_offset + 4].fill(0);
    let inner_icmp_checksum = internet_checksum(&packet[inner_icmp_offset..]);
    packet[inner_icmp_offset + 2..inner_icmp_offset + 4]
        .copy_from_slice(&inner_icmp_checksum.to_be_bytes());
    packet[inner_offset + 10..inner_offset + 12].fill(0);
    let inner_ip_checksum =
        internet_checksum(&packet[inner_offset..inner_icmp_offset]);
    packet[inner_offset + 10..inner_offset + 12]
        .copy_from_slice(&inner_ip_checksum.to_be_bytes());
    packet[2..4].fill(0);
    let outer_checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&outer_checksum.to_be_bytes());
    Some((sequence, packet))
}

pub(crate) fn rewrite_icmpv6_error(
    message: &[u8],
    source: std::net::Ipv6Addr,
    target: std::net::Ipv6Addr,
    identifier: u16,
) -> Option<(u16, Vec<u8>)> {
    if message.len() < 56 || !matches!(message[0], 1..=4) {
        return None;
    }
    let inner_offset = 8;
    if message[inner_offset] >> 4 != 6
        || message[inner_offset + 6] != 58
        || message[inner_offset + 24..inner_offset + 40] != target.octets()
    {
        return None;
    }
    let inner_icmp_offset = inner_offset + 40;
    if message[inner_icmp_offset] != 128 || message[inner_icmp_offset + 1] != 0
    {
        return None;
    }
    let sequence = u16::from_be_bytes([
        message[inner_icmp_offset + 6],
        message[inner_icmp_offset + 7],
    ]);
    let mut packet = message.to_vec();
    packet[inner_offset + 8..inner_offset + 24]
        .copy_from_slice(&source.octets());
    packet[inner_icmp_offset + 4..inner_icmp_offset + 6]
        .copy_from_slice(&identifier.to_be_bytes());
    packet[inner_icmp_offset + 2..inner_icmp_offset + 4].fill(0);
    let checksum =
        icmpv6_checksum(source, target, &packet[inner_icmp_offset..]);
    packet[inner_icmp_offset + 2..inner_icmp_offset + 4]
        .copy_from_slice(&checksum.to_be_bytes());
    Some((sequence, packet))
}

fn icmpv6_checksum(
    source: std::net::Ipv6Addr,
    destination: std::net::Ipv6Addr,
    message: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + message.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(message);
    internet_checksum(&pseudo)
}

fn received_icmp_layout(
    packet: &[u8],
    socket_source: IpAddr,
    ipv4: bool,
) -> io::Result<(usize, u8, IpAddr)> {
    if ipv4 && packet.first().is_some_and(|value| value >> 4 == 4) {
        if packet.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated IPv4 ICMP response",
            ));
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if header_len < 20 || packet.len() < header_len + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IPv4 ICMP response header",
            ));
        }
        return Ok((
            header_len,
            packet[8],
            IpAddr::V4(std::net::Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
        ));
    }
    if !ipv4 && packet.first().is_some_and(|value| value >> 4 == 6) {
        if packet.len() < 48 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated IPv6 ICMP response",
            ));
        }
        return Ok((
            40,
            packet[7],
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24])
                    .expect("checked IPv6 response"),
            )),
        ));
    }
    Ok((0, 64, socket_source))
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn new_tcp_socket(
    address: SocketAddr,
    tcp_multi_path: bool,
) -> io::Result<TcpSocket> {
    #[cfg(target_os = "linux")]
    if tcp_multi_path {
        // Go's net.Dialer transparently falls back to ordinary TCP when MPTCP
        // is unavailable in the running kernel. Preserve that behavior.
        if let Ok(socket) =
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::MPTCP))
        {
            socket.set_nonblocking(true)?;
            let stream: std::net::TcpStream = socket.into();
            return Ok(TcpSocket::from_std_stream(stream));
        }
    }
    let _ = tcp_multi_path;
    match address.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
}

impl Dialer for DirectOutbound {
    fn icmp_flow_addresses(&self) -> Option<(Option<IpAddr>, Option<IpAddr>)> {
        Some((
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        ))
    }

    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = self.connect(destination).await?;
            Ok(Box::new(stream) as Stream)
        })
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let direct = self.with_network_dial_options(options);
            let stream = direct.connect(destination).await?;
            Ok(Box::new(stream) as Stream)
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            Ok(Box::new(self.listen_packet(destination, 0, false).await?)
                as PacketStream)
        })
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let direct = self.with_network_dial_options(options);
            let packets = Box::new(
                direct
                    .listen_packet(
                        destination,
                        0,
                        options.udp_disable_domain_unmapping,
                    )
                    .await?,
            ) as PacketStream;
            Ok(apply_udp_connect(
                packets,
                destination,
                options.udp_connect,
                options.udp_disable_domain_unmapping,
            ))
        })
    }

    fn listen_udp_on<'a>(
        &'a self,
        destination: &'a SocksAddr,
        local_port: u16,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            Ok(Box::new(
                self.listen_packet(destination, local_port, false).await?,
            ) as PacketStream)
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
            self.exchange_icmp_packet(packet, source, hop_limit, destination)
                .await
        })
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async move {
            let direct = self.with_network_dial_options(options);
            direct
                .exchange_icmp_packet(packet, source, hop_limit, destination)
                .await
        })
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        self.preference_source
            .as_ref()
            .is_some_and(|source| source.preferred_domain(domain))
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        self.preference_source
            .as_ref()
            .is_some_and(|source| source.preferred_address(address))
    }
}

struct DirectPacketConnection {
    socket: UdpSocket,
    resolver: Option<SharedResolver>,
    strategy: DomainStrategy,
    domain_unmapping: Mutex<HashMap<SocketAddr, SocksAddr>>,
    disable_domain_unmapping: bool,
}

impl PacketConnection for DirectPacketConnection {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let addresses = match (destination, &self.resolver) {
                (SocksAddr::Domain { host, port }, Some(resolver)) => resolver
                    .lookup(host, self.strategy)
                    .await?
                    .into_iter()
                    .map(|address| SocketAddr::new(address, *port))
                    .collect(),
                _ => destination.resolve().await?,
            };
            let local_is_ipv4 = self.socket.local_addr()?.is_ipv4();
            let mut last_error = None;
            for address in addresses
                .into_iter()
                .filter(|address| address.is_ipv4() == local_is_ipv4)
            {
                match self.socket.send_to(data, address).await {
                    Ok(size) => {
                        if !self.disable_domain_unmapping
                            && matches!(destination, SocksAddr::Domain { .. })
                        {
                            let mut mappings = self
                                .domain_unmapping
                                .lock()
                                .expect("direct UDP domain map poisoned");
                            if mappings.len() >= 1024 {
                                mappings.clear();
                            }
                            mappings.insert(address, destination.clone());
                        }
                        return Ok(size);
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no compatible address for {destination}"),
                )
            }))
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let (size, source) = self.socket.recv_from(data).await?;
            let source = self
                .domain_unmapping
                .lock()
                .expect("direct UDP domain map poisoned")
                .get(&source)
                .cloned()
                .unwrap_or_else(|| source.into());
            Ok((size, source))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    #[cfg(target_os = "macos")]
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    #[cfg(target_os = "macos")]
    use super::clear_fast_fallback_if_primary_recovers;
    use super::{
        DirectOutbound, icmpv6_checksum, internet_checksum,
        rewrite_icmpv4_error, rewrite_icmpv6_error,
    };
    #[cfg(unix)]
    use super::{PendingIcmpGuard, PendingIcmpRequest};
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use crate::common::platform_network::AutoDetectInterfaceProvider;
    #[cfg(target_os = "macos")]
    use crate::common::platform_network::{
        PlatformNetworkInterface, PlatformNetworkProvider, PlatformSocket,
    };
    use crate::{
        adapter::{DialFuture, Dialer, NetworkDialOptions},
        common::network::SocksAddr,
        constant::{InterfaceType, NetworkStrategy},
        dns::{LookupFuture, Resolver},
        option::{DirectOutboundOptions, DomainStrategy},
    };

    struct PreferredEndpoint;

    #[cfg(target_os = "macos")]
    struct RecordingPlatformNetworkProvider {
        binds: AtomicUsize,
    }

    #[cfg(target_os = "macos")]
    impl PlatformNetworkProvider for RecordingPlatformNetworkProvider {
        fn network_interfaces(
            &self,
        ) -> io::Result<Vec<PlatformNetworkInterface>> {
            Ok(vec![PlatformNetworkInterface {
                id: "test-wifi".into(),
                name: "lo0".into(),
                index: 1,
                interface_type: InterfaceType::Wifi,
                is_default: true,
                is_own: false,
            }])
        }

        fn bind_socket(
            &self,
            _socket: PlatformSocket,
            interface: &PlatformNetworkInterface,
        ) -> io::Result<()> {
            assert_eq!(interface.id, "test-wifi");
            self.binds.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl Dialer for PreferredEndpoint {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "preference-only test endpoint",
                ))
            })
        }

        fn preferred_domain(&self, domain: &str) -> bool {
            domain == "internal.example"
        }

        fn preferred_address(&self, address: IpAddr) -> bool {
            address == "10.0.0.1".parse::<IpAddr>().unwrap()
        }
    }

    #[test]
    fn os_bound_direct_dialer_preserves_endpoint_preference() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default())
            .with_preference_source(Arc::new(PreferredEndpoint));
        assert!(direct.preferred_domain("internal.example"));
        assert!(!direct.preferred_domain("public.example"));
        assert!(direct.preferred_address("10.0.0.1".parse().unwrap()));
        assert!(!direct.preferred_address("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn route_network_options_override_direct_defaults_per_connection() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let routed = direct.with_network_dial_options(&NetworkDialOptions {
            strategy: Some(NetworkStrategy::Fallback),
            network_type: vec![InterfaceType::Wifi],
            fallback_network_type: vec![InterfaceType::Cellular],
            fallback_delay: Some(std::time::Duration::from_millis(125)),
            ..Default::default()
        });
        let options = &routed.options.dialer.abstract_options;
        assert_eq!(
            options.network_strategy.map(|strategy| strategy.0),
            Some(NetworkStrategy::Fallback)
        );
        assert_eq!(options.network_type.as_slice()[0].0, InterfaceType::Wifi);
        assert_eq!(
            options.fallback_network_type.as_slice()[0].0,
            InterfaceType::Cellular
        );
        assert_eq!(
            options.fallback_delay.as_std(),
            Some(std::time::Duration::from_millis(125))
        );
    }

    #[test]
    fn explicit_direct_and_generic_underlay_keep_distinct_udp_defaults() {
        let resolver = Arc::new(FixedUdpResolver(IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
        let explicit = DirectOutbound::with_resolver(
            DirectOutboundOptions::default(),
            resolver.clone(),
            DomainStrategy::AsIs,
        );
        let underlay = DirectOutbound::with_underlay_resolver(
            DirectOutboundOptions::default(),
            resolver,
            DomainStrategy::AsIs,
        );
        assert!(explicit.udp_fragment_default);
        assert!(!underlay.udp_fragment_default);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[tokio::test]
    async fn desktop_auto_detect_binds_only_unconfigured_dialers() {
        let provider = Arc::new(AutoDetectInterfaceProvider::default());
        let destination: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let direct = DirectOutbound::new(DirectOutboundOptions::default())
            .with_auto_detect_interface_provider(provider.clone());
        let detected = direct.socket_options_for(destination).await.unwrap();
        assert!(!detected.bind_interface.is_empty());

        let mut explicit = DirectOutboundOptions::default();
        explicit.dialer.abstract_options.bind_interface = "manual0".into();
        let direct = DirectOutbound::new(explicit)
            .with_auto_detect_interface_provider(provider);
        let preserved = direct.socket_options_for(destination).await.unwrap();
        assert_eq!(preserved.bind_interface, "manual0");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_platform_provider_executes_route_network_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
        });
        let provider = Arc::new(RecordingPlatformNetworkProvider {
            binds: AtomicUsize::new(0),
        });
        let direct = DirectOutbound::new(DirectOutboundOptions::default())
            .with_platform_network_provider(provider.clone());
        let stream = direct
            .dial_tcp_with_options(
                &address.into(),
                &NetworkDialOptions {
                    strategy: Some(NetworkStrategy::Default),
                    network_type: vec![InterfaceType::Wifi],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        drop(stream);
        accepted.await.unwrap();
        assert_eq!(provider.binds.load(Ordering::Relaxed), 1);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_without_platform_provider_ignores_graphical_network_hint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
        });
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let stream = direct
            .dial_tcp_with_options(
                &address.into(),
                &NetworkDialOptions {
                    strategy: Some(NetworkStrategy::Hybrid),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        drop(stream);
        accepted.await.unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_fast_fallback_state_is_shared_and_expires_after_tcp_timeout() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let routed = direct.with_network_dial_options(&NetworkDialOptions {
            strategy: Some(NetworkStrategy::Fallback),
            ..Default::default()
        });
        direct.mark_platform_fallback();
        assert!(routed.platform_fast_fallback_active());

        *direct.platform_network_last_fallback.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(16));
        assert!(!routed.platform_fast_fallback_active());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn fast_fallback_clears_only_for_rapid_primary_recovery() {
        let state = Arc::new(Mutex::new(Some(Instant::now())));
        clear_fast_fallback_if_primary_recovers(
            tokio::spawn(async { Ok::<(), io::Error>(()) }),
            Instant::now(),
            Duration::from_secs(1),
            state.clone(),
        )
        .await;
        assert!(state.lock().unwrap().is_none());

        *state.lock().unwrap() = Some(Instant::now());
        clear_fast_fallback_if_primary_recovers(
            tokio::spawn(async { Ok::<(), io::Error>(()) }),
            Instant::now() - Duration::from_millis(50),
            Duration::from_millis(10),
            state.clone(),
        )
        .await;
        assert!(state.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn dials_and_transfers_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let mut options = DirectOutboundOptions::default();
        options.dialer.abstract_options.disable_tcp_keep_alive = true;
        let direct = DirectOutbound::new(options);
        let mut stream = direct.dial_tcp(&address.into()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut bytes = [0_u8; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn packet_connection_exposes_physical_local_address() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let connection = direct
            .listen_udp(&"127.0.0.1:3478".parse::<SocketAddr>().unwrap().into())
            .await
            .unwrap();
        let local = connection.local_addr().unwrap().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn udp_domain_unmapping_is_enabled_unless_route_disables_it() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_address = server.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut packet = [0_u8; 16];
            for _ in 0..4 {
                let (size, source) =
                    server.recv_from(&mut packet).await.unwrap();
                server.send_to(&packet[..size], source).await.unwrap();
            }
        });
        let direct = DirectOutbound::with_resolver(
            DirectOutboundOptions::default(),
            Arc::new(FixedUdpResolver(server_address.ip())),
            DomainStrategy::AsIs,
        );
        let destination = SocksAddr::new("udp.test", server_address.port());
        for (disabled, connected, expect_domain) in [
            (false, false, true),
            (true, false, false),
            (false, true, true),
            (true, true, false),
        ] {
            let options = NetworkDialOptions {
                udp_disable_domain_unmapping: disabled,
                udp_connect: connected,
                ..Default::default()
            };
            let connection = direct
                .listen_udp_with_options(&destination, &options)
                .await
                .unwrap();
            let requested_destination = if connected {
                SocksAddr::new("wrong.invalid", 1)
            } else {
                destination.clone()
            };
            connection
                .send_to(b"ping", &requested_destination)
                .await
                .unwrap();
            let mut response = [0_u8; 16];
            let (size, source) =
                connection.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[..size], b"ping");
            assert_eq!(
                matches!(source, SocksAddr::Domain { .. }),
                expect_domain
            );
        }
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_multipath_option_connects_with_platform_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0_u8; 5];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let mut options = DirectOutboundOptions::default();
        options.dialer.abstract_options.tcp_multi_path = true;
        let direct = DirectOutbound::new(options);
        let mut stream = direct.dial_tcp(&address.into()).await.unwrap();
        stream.write_all(b"mptcp").await.unwrap();
        let mut bytes = [0_u8; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"mptcp");
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn sends_and_receives_udp_datagrams() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut data = [0_u8; 16];
            let (size, source) = echo.recv_from(&mut data).await.unwrap();
            echo.send_to(&data[..size], source).await.unwrap();
        });
        let mut options = DirectOutboundOptions::default();
        options.dialer.abstract_options.reuse_addr = true;
        let direct = DirectOutbound::new(options);
        let packet = direct.listen_udp(&echo_address.into()).await.unwrap();
        packet
            .send_to(b"datagram", &echo_address.into())
            .await
            .unwrap();
        let mut data = [0_u8; 16];
        let (size, source) = packet.recv_from(&mut data).await.unwrap();
        assert_eq!(&data[..size], b"datagram");
        assert_eq!(source, echo_address.into());
        task.await.unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn exchanges_unprivileged_ipv4_icmp_echo() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let mut request = b"\x08\x00\x00\x00\x12\x34\x56\x78rust-icmp".to_vec();
        let checksum = internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        let response = direct
            .exchange_icmp(
                &request,
                IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)),
                64,
                &SocksAddr::new("127.0.0.1", 0),
            )
            .await
            .unwrap();
        assert_eq!(response.source, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(response.packet[0], 0);
        assert_eq!(&response.packet[4..8], b"\x12\x34\x56\x78");
        assert_eq!(&response.packet[8..], b"rust-icmp");
        assert_eq!(internet_checksum(&response.packet), 0);

        request[6..8].copy_from_slice(&0x5679_u16.to_be_bytes());
        request[2..4].fill(0);
        let checksum = internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        let response = direct
            .exchange_icmp(
                &request,
                IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)),
                64,
                &SocksAddr::new("127.0.0.1", 0),
            )
            .await
            .unwrap();
        assert_eq!(&response.packet[4..8], b"\x12\x34\x56\x79");
        assert_eq!(direct.icmp_flows.flow_count(), 1);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn dispatches_concurrent_icmp_replies_by_sequence() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let make_request = |sequence: u16, payload: &[u8]| {
            let mut request = vec![8, 0, 0, 0, 0x23, 0x45];
            request.extend_from_slice(&sequence.to_be_bytes());
            request.extend_from_slice(payload);
            let checksum = internet_checksum(&request);
            request[2..4].copy_from_slice(&checksum.to_be_bytes());
            request
        };
        let first = make_request(7, b"first");
        let second = make_request(8, b"second");
        let source = IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2));
        let destination = SocksAddr::new("127.0.0.1", 0);
        let (first_response, second_response) = tokio::join!(
            direct.exchange_icmp(&first, source, 64, &destination),
            direct.exchange_icmp(&second, source, 64, &destination),
        );
        let first_response = first_response.unwrap();
        let second_response = second_response.unwrap();
        assert_eq!(&first_response.packet[6..8], &7_u16.to_be_bytes());
        assert_eq!(&first_response.packet[8..], b"first");
        assert_eq!(&second_response.packet[6..8], &8_u16.to_be_bytes());
        assert_eq!(&second_response.packet[8..], b"second");
        assert_eq!(direct.icmp_flows.flow_count(), 1);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn cancelled_icmp_request_releases_its_pending_slot() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let mut request = b"\x08\x00\x00\x00\x34\x56\x00\x01guard".to_vec();
        let checksum = internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        direct
            .exchange_icmp(
                &request,
                IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)),
                64,
                &SocksAddr::new("127.0.0.1", 0),
            )
            .await
            .unwrap();
        let flow = direct
            .icmp_flows
            .flows
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        flow.pending
            .lock()
            .unwrap()
            .entry(99)
            .or_default()
            .push_back(PendingIcmpRequest { token: 7, sender });
        assert_eq!(flow.pending_count(), 1);
        let guard = PendingIcmpGuard {
            flow: Arc::downgrade(&flow),
            sequence: 99,
            token: 7,
        };
        drop(guard);
        assert_eq!(flow.pending_count(), 0);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn expires_idle_icmp_flows() {
        let mut direct = DirectOutbound::new(DirectOutboundOptions::default());
        Arc::get_mut(&mut direct.icmp_flows).unwrap().idle_timeout =
            std::time::Duration::from_millis(100);
        let mut request = b"\x08\x00\x00\x00\x45\x67\x00\x01idle".to_vec();
        let checksum = internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        direct
            .exchange_icmp(
                &request,
                IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)),
                37,
                &SocksAddr::new("127.0.0.1", 0),
            )
            .await
            .unwrap();
        assert_eq!(direct.icmp_flows.flow_count(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_eq!(direct.icmp_flows.flow_count(), 0);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn exchanges_unprivileged_ipv6_icmp_echo() {
        let direct = DirectOutbound::new(DirectOutboundOptions::default());
        let request = b"\x80\x00\x00\x00\xab\xcd\x00\x09rust-icmp6";
        let response = direct
            .exchange_icmp(
                request,
                IpAddr::V6("fd00::2".parse().unwrap()),
                64,
                &SocksAddr::new("::1", 0),
            )
            .await
            .unwrap();
        assert_eq!(response.source, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert_eq!(response.packet[0], 129);
        assert_eq!(&response.packet[4..8], b"\xab\xcd\x00\x09");
        assert_eq!(&response.packet[8..], b"rust-icmp6");
    }

    #[test]
    fn rewrites_embedded_ipv4_echo_in_traceroute_error() {
        let source: std::net::Ipv4Addr = "10.0.0.2".parse().unwrap();
        let target: std::net::Ipv4Addr = "198.51.100.7".parse().unwrap();
        let mut message = vec![0_u8; 36];
        message[0] = 11;
        message[8] = 0x45;
        message[10..12].copy_from_slice(&28_u16.to_be_bytes());
        message[16] = 1;
        message[17] = 1;
        message[20..24].copy_from_slice(&[192, 0, 2, 10]);
        message[24..28].copy_from_slice(&target.octets());
        message[28] = 8;
        message[32..34].copy_from_slice(&0xbeef_u16.to_be_bytes());
        message[34..36].copy_from_slice(&9_u16.to_be_bytes());
        let (sequence, rewritten) =
            rewrite_icmpv4_error(&message, source, target, 0x1234).unwrap();
        assert_eq!(sequence, 9);
        assert_eq!(&rewritten[20..24], &source.octets());
        assert_eq!(&rewritten[32..34], &0x1234_u16.to_be_bytes());
        assert_eq!(internet_checksum(&rewritten), 0);
        assert_eq!(internet_checksum(&rewritten[8..28]), 0);
        assert_eq!(internet_checksum(&rewritten[28..]), 0);
    }

    #[test]
    fn rewrites_embedded_ipv6_echo_in_traceroute_error() {
        let source: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let target: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        let mut message = vec![0_u8; 56];
        message[0] = 3;
        message[8] = 0x60;
        message[12..14].copy_from_slice(&8_u16.to_be_bytes());
        message[14] = 58;
        message[15] = 1;
        message[16..32].copy_from_slice(
            &"2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        message[32..48].copy_from_slice(&target.octets());
        message[48] = 128;
        message[52..54].copy_from_slice(&0xbeef_u16.to_be_bytes());
        message[54..56].copy_from_slice(&10_u16.to_be_bytes());
        let (sequence, rewritten) =
            rewrite_icmpv6_error(&message, source, target, 0x5678).unwrap();
        assert_eq!(sequence, 10);
        assert_eq!(&rewritten[16..32], &source.octets());
        assert_eq!(&rewritten[52..54], &0x5678_u16.to_be_bytes());
        assert_eq!(icmpv6_checksum(source, target, &rewritten[48..]), 0);
    }

    #[tokio::test]
    async fn happy_eyeballs_falls_back_between_address_families() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let direct = DirectOutbound::with_resolver(
            DirectOutboundOptions::default(),
            Arc::new(DualStackResolver),
            DomainStrategy::PreferIpv6,
        );
        let mut stream = direct
            .dial_tcp(&SocksAddr::new("dual.test", port))
            .await
            .unwrap();
        stream.write_all(b"race").await.unwrap();
        let mut bytes = [0_u8; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"race");
        echo.await.unwrap();
    }

    struct DualStackResolver;

    struct FixedUdpResolver(IpAddr);

    impl Resolver for FixedUdpResolver {
        fn lookup<'a>(
            &'a self,
            domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                if domain != "udp.test" {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "unexpected domain",
                    ));
                }
                Ok(vec![self.0])
            })
        }
    }

    impl Resolver for DualStackResolver {
        fn lookup<'a>(
            &'a self,
            domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                if domain != "dual.test" {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "unexpected domain",
                    ));
                }
                Ok(vec![
                    IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                ])
            })
        }
    }
}
