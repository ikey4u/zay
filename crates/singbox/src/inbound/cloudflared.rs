//! Configured Cloudflare Tunnel inbound lifecycle.

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
    thread::JoinHandle,
    time::Duration,
};

use async_trait::async_trait;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, RecordType},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    adapter::{
        DialFuture, Dialer, IcmpResponse, PacketConnection, PacketFuture,
        PacketStream, Stream,
    },
    common::{
        certificate_store::CertificateStore,
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::{Network, SocksAddr},
        ntp::NtpClock,
    },
    dns::{LookupOptions, Resolver},
    option::{CloudflaredInboundOptions, DomainStrategy},
    outbound::OutboundManager,
    protocol::{
        cloudflared::{
            CloudflaredEdgeResolver, CloudflaredError,
            CloudflaredIncomingDatagramVersion, CloudflaredProtocolSelection,
            CloudflaredRegistrationOptions, CloudflaredSrvRecord,
            cloudflared_remote_datagram_version, discover_cloudflared_edges,
            parse_cloudflared_token,
        },
        cloudflared_factory::{
            CloudflaredConnectionFeatureSelector,
            CloudflaredEdgeConnectionFactory,
        },
        cloudflared_ingress::CloudflaredConfigManager,
        cloudflared_origin::CloudflaredOriginService,
        cloudflared_supervisor::CloudflaredHaSupervisor,
    },
    route::{Action, ConnectionOverride, Metadata, RouteDecision, Router},
};

const FEATURE_SERIALIZED_HEADERS: &str = "serialized_headers";
const FEATURE_DATAGRAM_V2: &str = "support_datagram_v2";
const FEATURE_DATAGRAM_V3: &str = "support_datagram_v3_2";
const FEATURE_QUIC_EOF: &str = "support_quic_eof";
const FEATURE_REMOTE_CONFIG: &str = "allow_remote_config";
const FEATURE_POST_QUANTUM: &str = "postquantum";
const FEATURE_SELECTOR_HOST: &str = "cfd-features.argotunnel.com";
const FEATURE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const FEATURE_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum CloudflaredInboundError {
    #[error(transparent)]
    Protocol(#[from] CloudflaredError),
    #[error("invalid Cloudflare Tunnel options: {0}")]
    Options(String),
    #[error("spawn Cloudflare Tunnel supervisor: {0}")]
    Spawn(io::Error),
    #[error("Cloudflare Tunnel supervisor did not initialize")]
    StartupChannel,
}

#[derive(Clone)]
pub struct CloudflaredInboundHandle {
    origin: Arc<CloudflaredOriginService>,
    terminal_error: Arc<Mutex<Option<String>>>,
}

impl CloudflaredInboundHandle {
    pub fn active_flows(&self) -> u64 {
        self.origin.active_flows()
    }

    pub fn config(&self) -> &Arc<CloudflaredConfigManager> {
        self.origin.config()
    }

    pub fn terminal_error(&self) -> Option<String> {
        self.terminal_error
            .lock()
            .expect("cloudflared status lock poisoned")
            .clone()
    }
}

/// Lifecycle component which discovers Cloudflare edges and owns all HA
/// connections. Cap'n Proto RPC futures are local, so the supervisor runs on
/// a private current-thread runtime while this type remains embeddable and
/// `Send + Sync`.
pub struct CloudflaredInbound {
    name: String,
    options: CloudflaredInboundOptions,
    resolver: Arc<dyn CloudflaredEdgeResolver>,
    feature_resolver: Arc<dyn Resolver>,
    feature_strategy: DomainStrategy,
    tunnel_dialer: Arc<dyn Dialer>,
    origin: Arc<CloudflaredOriginService>,
    cancellation: CancellationToken,
    thread: Option<JoinHandle<Result<(), String>>>,
    terminal_error: Arc<Mutex<Option<String>>>,
    ntp_clock: Option<NtpClock>,
}

impl CloudflaredInbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: impl Into<String>,
        options: CloudflaredInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        control_dialer: Arc<dyn Dialer>,
        tunnel_dialer: Arc<dyn Dialer>,
        control_resolver: Arc<dyn Resolver>,
        control_strategy: DomainStrategy,
        tunnel_resolver: Arc<dyn Resolver>,
        tunnel_strategy: DomainStrategy,
    ) -> Result<(Self, CloudflaredInboundHandle), CloudflaredInboundError> {
        Self::new_with_runtime_context(
            tag,
            options,
            router,
            outbounds,
            control_dialer,
            tunnel_dialer,
            control_resolver,
            control_strategy,
            tunnel_resolver,
            tunnel_strategy,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_runtime_context(
        tag: impl Into<String>,
        options: CloudflaredInboundOptions,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        control_dialer: Arc<dyn Dialer>,
        tunnel_dialer: Arc<dyn Dialer>,
        control_resolver: Arc<dyn Resolver>,
        control_strategy: DomainStrategy,
        tunnel_resolver: Arc<dyn Resolver>,
        tunnel_strategy: DomainStrategy,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Result<(Self, CloudflaredInboundHandle), CloudflaredInboundError> {
        options
            .validate()
            .map_err(CloudflaredInboundError::Options)?;
        let name = tag.into();
        let config = Arc::new(CloudflaredConfigManager::new());
        let route_dialer: Arc<dyn Dialer> = Arc::new(CloudflaredRouteDialer {
            inbound: name.clone(),
            router,
            outbounds,
        });
        let origin = Arc::new(
            CloudflaredOriginService::with_access_dialer_and_runtime_context(
                config,
                route_dialer,
                control_dialer,
                ntp_clock.clone(),
                certificate_store,
            ),
        );
        let terminal_error = Arc::new(Mutex::new(None));
        let handle = CloudflaredInboundHandle {
            origin: origin.clone(),
            terminal_error: terminal_error.clone(),
        };
        Ok((
            Self {
                name,
                options,
                resolver: Arc::new(RuntimeEdgeResolver {
                    control_resolver: control_resolver.clone(),
                    control_strategy,
                    tunnel_resolver,
                    tunnel_strategy,
                }),
                feature_resolver: control_resolver,
                feature_strategy: control_strategy,
                tunnel_dialer,
                ntp_clock,
                origin,
                cancellation: CancellationToken::new(),
                thread: None,
                terminal_error,
            },
            handle,
        ))
    }

    async fn launch(&mut self) -> Result<(), CloudflaredInboundError> {
        if self.thread.is_some() {
            return Ok(());
        }
        let credentials = parse_cloudflared_token(&self.options.token)?;
        let region = if credentials.endpoint.is_empty() {
            self.options.region.as_str()
        } else {
            credentials.endpoint.as_str()
        };
        let edges = discover_cloudflared_edges(
            self.resolver.as_ref(),
            region,
            self.options.edge_ip_version,
        )
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let selection = CloudflaredProtocolSelection::new(
            &self.options.protocol,
            self.options.post_quantum,
        )?;
        let feature_selector = Arc::new(RuntimeFeatureSelector::new(
            credentials.account_tag.clone(),
            self.options.datagram_version.clone(),
            self.options.post_quantum,
            self.feature_resolver.clone(),
            self.feature_strategy,
        ));
        // Upstream treats feature-DNS failure as non-fatal and retains v2.
        let _ = feature_selector.refresh().await;
        let (datagram_version, client_features) = feature_selector.snapshot();
        let registration = CloudflaredRegistrationOptions {
            credentials,
            connection_index: 0,
            client_id: Uuid::new_v4().as_bytes().to_vec(),
            client_features,
            client_version: "sing-cloudflared".into(),
            client_arch: cloudflared_client_arch(),
            origin_local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            replace_existing: false,
            compression_quality: 0,
            previous_attempts: 0,
        };
        let factory = Arc::new(
            CloudflaredEdgeConnectionFactory::new_with_clock(
                self.tunnel_dialer.clone(),
                registration,
                self.options.effective_grace_period(),
                datagram_version,
                self.options.post_quantum,
                self.origin.clone(),
                self.origin.clone(),
                self.origin.config().clone(),
                self.ntp_clock.clone(),
            )?
            .with_feature_selector(feature_selector.clone()),
        );
        let supervisor = CloudflaredHaSupervisor::new(
            edges,
            self.options.effective_ha_connections(),
            selection,
            factory,
        )?;
        let cancellation = self.cancellation.child_token();
        let terminal_error = self.terminal_error.clone();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name(format!("cloudflared-{}", self.name))
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| error.to_string());
                let Ok(runtime) = runtime else {
                    let message = runtime.unwrap_err();
                    let _ = started_tx.send(Err(message.clone()));
                    *terminal_error
                        .lock()
                        .expect("cloudflared status lock poisoned") =
                        Some(message.clone());
                    return Err(message);
                };
                let _ = started_tx.send(Ok(()));
                let local = tokio::task::LocalSet::new();
                let refresh_cancellation = cancellation.clone();
                let result = local
                    .block_on(&runtime, async move {
                        tokio::task::spawn_local(
                            feature_selector.refresh_loop(refresh_cancellation),
                        );
                        supervisor.run(cancellation).await
                    })
                    .map_err(|error| error.to_string());
                if let Err(error) = &result {
                    *terminal_error
                        .lock()
                        .expect("cloudflared status lock poisoned") =
                        Some(error.clone());
                }
                result
            })
            .map_err(CloudflaredInboundError::Spawn)?;
        let started = tokio::task::spawn_blocking(move || started_rx.recv())
            .await
            .map_err(|_| CloudflaredInboundError::StartupChannel)?
            .map_err(|_| CloudflaredInboundError::StartupChannel)?;
        if let Err(message) = started {
            let _ = thread.join();
            return Err(CloudflaredInboundError::Protocol(
                CloudflaredError::Transport(message),
            ));
        }
        self.thread = Some(thread);
        Ok(())
    }
}

struct RuntimeFeatureSelector {
    account_tag: String,
    configured: bool,
    post_quantum: bool,
    resolver: Arc<dyn Resolver>,
    strategy: DomainStrategy,
    current: RwLock<CloudflaredIncomingDatagramVersion>,
}

impl RuntimeFeatureSelector {
    fn new(
        account_tag: String,
        configured: String,
        post_quantum: bool,
        resolver: Arc<dyn Resolver>,
        strategy: DomainStrategy,
    ) -> Self {
        Self {
            account_tag,
            configured: !configured.is_empty(),
            post_quantum,
            resolver,
            strategy,
            current: RwLock::new(if configured == "v3" {
                CloudflaredIncomingDatagramVersion::V3
            } else {
                CloudflaredIncomingDatagramVersion::V2
            }),
        }
    }

    async fn refresh(&self) -> Result<(), CloudflaredError> {
        if self.configured {
            return Ok(());
        }
        let name = Name::from_ascii(format!("{FEATURE_SELECTOR_HOST}."))
            .map_err(|error| {
                CloudflaredError::EdgeDiscovery(error.to_string())
            })?;
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, RecordType::TXT));
        let response = tokio::time::timeout(
            FEATURE_LOOKUP_TIMEOUT,
            self.resolver.exchange_with_options(
                &request,
                LookupOptions {
                    strategy: self.strategy,
                    ..Default::default()
                },
            ),
        )
        .await
        .map_err(|_| {
            CloudflaredError::EdgeDiscovery(
                "Cloudflare feature lookup timed out".into(),
            )
        })?
        .map_err(|error| CloudflaredError::EdgeDiscovery(error.to_string()))?;
        let record = response.answers.iter().find_map(|record| {
            let RData::TXT(txt) = &record.data else {
                return None;
            };
            Some(
                txt.txt_data
                    .iter()
                    .flat_map(|part| part.iter().copied())
                    .collect::<Vec<_>>(),
            )
        });
        let Some(record) = record else {
            return Err(CloudflaredError::EdgeDiscovery(
                "feature response contains no TXT record".into(),
            ));
        };
        let version = match cloudflared_remote_datagram_version(
            &self.account_tag,
            &record,
        )? {
            "v3" => CloudflaredIncomingDatagramVersion::V3,
            _ => CloudflaredIncomingDatagramVersion::V2,
        };
        *self
            .current
            .write()
            .expect("cloudflared feature lock poisoned") = version;
        Ok(())
    }

    async fn refresh_loop(self: Arc<Self>, cancellation: CancellationToken) {
        if self.configured {
            cancellation.cancelled().await;
            return;
        }
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return,
                () = tokio::time::sleep(FEATURE_REFRESH_INTERVAL) => {
                    let _ = self.refresh().await;
                }
            }
        }
    }
}

impl CloudflaredConnectionFeatureSelector for RuntimeFeatureSelector {
    fn snapshot(&self) -> (CloudflaredIncomingDatagramVersion, Vec<String>) {
        let version = *self
            .current
            .read()
            .expect("cloudflared feature lock poisoned");
        let mut features = vec![
            FEATURE_SERIALIZED_HEADERS.into(),
            FEATURE_DATAGRAM_V2.into(),
            FEATURE_QUIC_EOF.into(),
            FEATURE_REMOTE_CONFIG.into(),
        ];
        if version == CloudflaredIncomingDatagramVersion::V3 {
            features.push(FEATURE_DATAGRAM_V3.into());
        }
        if self.post_quantum {
            features.push(FEATURE_POST_QUANTUM.into());
        }
        (version, features)
    }
}

impl Lifecycle for CloudflaredInbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start {
                return Ok(());
            }
            self.launch().await.map_err(|error| LifecycleError::Start {
                component: self.name.clone(),
                stage,
                message: error.to_string(),
            })
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            self.origin.close_datagrams().await;
            if let Some(thread) = self.thread.take() {
                let result = tokio::task::spawn_blocking(move || thread.join())
                    .await
                    .map_err(|error| LifecycleError::Close {
                        component: self.name.clone(),
                        message: error.to_string(),
                    })?;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(message)) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message,
                        });
                    }
                    Err(_) => {
                        return Err(LifecycleError::Close {
                            component: self.name.clone(),
                            message: "Cloudflare Tunnel supervisor panicked"
                                .into(),
                        });
                    }
                }
            }
            Ok(())
        })
    }
}

struct RuntimeEdgeResolver {
    control_resolver: Arc<dyn Resolver>,
    control_strategy: DomainStrategy,
    tunnel_resolver: Arc<dyn Resolver>,
    tunnel_strategy: DomainStrategy,
}

#[async_trait]
impl CloudflaredEdgeResolver for RuntimeEdgeResolver {
    async fn lookup_srv(
        &self,
        service: &str,
        protocol: &str,
        name: &str,
    ) -> Result<Vec<CloudflaredSrvRecord>, CloudflaredError> {
        let fqdn =
            format!("_{service}._{protocol}.{}.", name.trim_end_matches('.'));
        let name = Name::from_ascii(&fqdn).map_err(|error| {
            CloudflaredError::EdgeDiscovery(error.to_string())
        })?;
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, RecordType::SRV));
        let response = self
            .control_resolver
            .exchange_with_options(
                &request,
                LookupOptions {
                    strategy: self.control_strategy,
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| {
                CloudflaredError::EdgeDiscovery(error.to_string())
            })?;
        let records = response
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(srv) => Some(CloudflaredSrvRecord {
                    target: srv.target.to_utf8().trim_end_matches('.').into(),
                    port: srv.port,
                    priority: srv.priority,
                    weight: srv.weight,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Err(CloudflaredError::EdgeDiscovery(
                "SRV response contains no edge records".into(),
            ));
        }
        Ok(records)
    }

    async fn lookup_ip(
        &self,
        host: &str,
    ) -> Result<Vec<IpAddr>, CloudflaredError> {
        self.tunnel_resolver
            .lookup_with_options(
                host,
                LookupOptions {
                    strategy: self.tunnel_strategy,
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| CloudflaredError::EdgeDiscovery(error.to_string()))
    }
}

struct CloudflaredRouteDialer {
    inbound: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
}

impl CloudflaredRouteDialer {
    fn metadata(
        inbound: String,
        network: Network,
        source: Option<IpAddr>,
        destination: &SocksAddr,
    ) -> Metadata {
        Metadata {
            inbound,
            source: source.map(|ip| SocksAddr::Ip(SocketAddr::new(ip, 0))),
            destination: Some(destination.clone()),
            network: Some(network),
            ..Default::default()
        }
    }

    fn terminal_route(
        outbounds: &OutboundManager,
        metadata: &Metadata,
        fallback_destination: &SocksAddr,
        decision: &RouteDecision<'_>,
    ) -> io::Result<(Arc<dyn Dialer>, SocksAddr, ConnectionOverride)> {
        if matches!(
            decision.action(),
            Some(Action::Reject { .. } | Action::HijackDns)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cloudflare Tunnel flow rejected by route rule",
            ));
        }
        let original = metadata
            .destination
            .as_ref()
            .unwrap_or(fallback_destination);
        let destination = decision.destination(original);
        let connection_options = decision.connection_options().clone();
        let dialer = if matches!(decision.action(), Some(Action::Direct)) {
            outbounds.direct()
        } else {
            outbounds.select(decision.outbound()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Cloudflare Tunnel route outbound not found",
                )
            })?
        };
        Ok((dialer, destination, connection_options))
    }

    async fn proxy_tcp(
        mut stream: Stream,
        inbound: String,
        original_destination: SocksAddr,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> io::Result<()> {
        let mut metadata =
            Self::metadata(inbound, Network::Tcp, None, &original_destination);
        let (routed_stream, decision) = super::sniff_and_route_stream(
            stream,
            &mut metadata,
            &router,
            &outbounds,
        )
        .await?;
        stream = routed_stream;
        if matches!(decision.action(), Some(Action::Reject { .. })) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cloudflare Tunnel flow rejected by route rule",
            ));
        }
        if matches!(decision.action(), Some(Action::HijackDns)) {
            return super::serve_hijacked_dns_stream_with_context(
                stream, &outbounds, &metadata,
            )
            .await;
        }
        let (dialer, destination, options) = Self::terminal_route(
            &outbounds,
            &metadata,
            &original_destination,
            &decision,
        )?;
        let remote = dialer
            .dial_tcp_with_options(&destination, &options.network)
            .await?;
        let mut remote = super::apply_routed_tcp_options(remote, &options)?;
        tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
        Ok(())
    }

    async fn proxy_udp(
        mut incoming: mpsc::Receiver<CloudflaredRoutedPacket>,
        responses: mpsc::Sender<CloudflaredRoutedPacket>,
        inbound: String,
        original_destination: SocksAddr,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
    ) -> io::Result<()> {
        let first = incoming.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Cloudflare Tunnel UDP connection closed before first packet",
            )
        })?;
        let mut metadata =
            Self::metadata(inbound, Network::Udp, None, &original_destination);
        let (decision, pending) = super::sniff_and_route_packet_session(
            first,
            &mut incoming,
            |packet| packet.payload.as_slice(),
            &mut metadata,
            &router,
            &outbounds,
        )
        .await?;
        if matches!(decision.action(), Some(Action::Reject { .. })) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cloudflare Tunnel flow rejected by route rule",
            ));
        }
        if matches!(decision.action(), Some(Action::HijackDns)) {
            return Self::proxy_hijacked_udp(
                pending, incoming, responses, metadata, outbounds,
            )
            .await;
        }
        let (dialer, destination, options) = Self::terminal_route(
            &outbounds,
            &metadata,
            &original_destination,
            &decision,
        )?;
        let outgoing = dialer
            .listen_udp_with_options(&destination, &options.network)
            .await?;
        let outgoing = super::wrap_packet_destination_nat(
            outgoing,
            original_destination,
            destination,
        );
        for packet in pending {
            outgoing
                .send_to(&packet.payload, &packet.destination)
                .await?;
        }
        let mut response = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                packet = incoming.recv() => {
                    let Some(packet) = packet else { return Ok(()); };
                    outgoing.send_to(&packet.payload, &packet.destination).await?;
                }
                result = outgoing.recv_from(&mut response) => {
                    let (size, source) = result?;
                    responses.send(CloudflaredRoutedPacket {
                        payload: response[..size].to_vec(),
                        destination: source,
                    }).await.map_err(|_| io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Cloudflare Tunnel UDP response connection closed",
                    ))?;
                }
            }
        }
    }

    async fn proxy_hijacked_udp(
        mut pending: VecDeque<CloudflaredRoutedPacket>,
        mut incoming: mpsc::Receiver<CloudflaredRoutedPacket>,
        responses: mpsc::Sender<CloudflaredRoutedPacket>,
        metadata: Metadata,
        outbounds: Arc<OutboundManager>,
    ) -> io::Result<()> {
        loop {
            let packet = match pending.pop_front() {
                Some(packet) => packet,
                None => match incoming.recv().await {
                    Some(packet) => packet,
                    None => return Ok(()),
                },
            };
            let payload = super::hijack_dns_packet_with_context(
                &packet.payload,
                &outbounds,
                &metadata,
            )
            .await?;
            responses
                .send(CloudflaredRoutedPacket {
                    payload,
                    destination: packet.destination,
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Cloudflare Tunnel UDP response connection closed",
                    )
                })?;
        }
    }

    async fn route_icmp(
        &self,
        source: IpAddr,
        destination: &SocksAddr,
    ) -> io::Result<(Arc<dyn Dialer>, SocksAddr, ConnectionOverride)> {
        let mut metadata = Self::metadata(
            self.inbound.clone(),
            Network::Icmp,
            Some(source),
            destination,
        );
        super::restore_fake_ip_metadata(&mut metadata, &self.outbounds)?;
        let mut state = self.router.route_state();
        loop {
            let decision =
                self.router.route_pre_match_next(&metadata, &mut state);
            match decision.action().cloned() {
                // Go's PreMatch skips sniff for ICMP. Resolve is retained so
                // a restored FakeIP domain can feed following CIDR rules.
                Some(Action::Sniff(_)) => continue,
                Some(Action::Resolve(options)) => {
                    let routed = metadata
                        .destination
                        .as_ref()
                        .map(|value| decision.destination(value));
                    super::resolve_metadata(
                        &mut metadata,
                        routed.as_ref(),
                        &options,
                        &self.outbounds,
                    )
                    .await?;
                }
                Some(Action::Bypass { outbound, .. })
                    if outbound.is_empty() =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Cloudflare Tunnel ICMP flow bypassed by route rule",
                    ));
                }
                _ => {
                    return Self::terminal_route(
                        &self.outbounds,
                        &metadata,
                        destination,
                        &decision,
                    );
                }
            }
        }
    }
}

#[derive(Debug)]
struct CloudflaredRoutedPacket {
    payload: Vec<u8>,
    destination: SocksAddr,
}

struct CloudflaredRoutedPacketConnection {
    packets: mpsc::Sender<CloudflaredRoutedPacket>,
    responses: tokio::sync::Mutex<mpsc::Receiver<CloudflaredRoutedPacket>>,
}

impl PacketConnection for CloudflaredRoutedPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            self.packets
                .send(CloudflaredRoutedPacket {
                    payload: data.to_vec(),
                    destination: destination.clone(),
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Cloudflare Tunnel UDP route connection closed",
                    )
                })?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let packet =
                self.responses.lock().await.recv().await.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Cloudflare Tunnel UDP route connection closed",
                    )
                })?;
            if packet.payload.len() > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cloudflare Tunnel UDP receive buffer is too small",
                ));
            }
            data[..packet.payload.len()].copy_from_slice(&packet.payload);
            Ok((packet.payload.len(), packet.destination))
        })
    }
}

impl Dialer for CloudflaredRouteDialer {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            // Match upstream's pipe-backed router dialer: origin dispatch can
            // return immediately, while sniff/resolve actions consume the
            // actual payload before the terminal outbound is selected.
            let (client, server) = tokio::io::duplex(64 * 1024);
            let inbound = self.inbound.clone();
            let original_destination = destination.clone();
            let router = self.router.clone();
            let outbounds = self.outbounds.clone();
            tokio::spawn(async move {
                let _ = Self::proxy_tcp(
                    Box::new(server),
                    inbound,
                    original_destination,
                    router,
                    outbounds,
                )
                .await;
            });
            Ok(Box::new(client) as Stream)
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let original_destination = destination.clone();
            let (packets, incoming) = mpsc::channel(64);
            let (responses, received) = mpsc::channel(64);
            let inbound = self.inbound.clone();
            let router = self.router.clone();
            let outbounds = self.outbounds.clone();
            tokio::spawn(async move {
                let _ = Self::proxy_udp(
                    incoming,
                    responses,
                    inbound,
                    original_destination,
                    router,
                    outbounds,
                )
                .await;
            });
            Ok(Box::new(CloudflaredRoutedPacketConnection {
                packets,
                responses: tokio::sync::Mutex::new(received),
            }) as PacketStream)
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
            let (dialer, routed_destination, options) =
                self.route_icmp(source, destination).await?;
            if routed_destination != *destination {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "ICMP route destination override is not supported",
                ));
            }
            validate_icmp_flow_addresses(
                dialer.icmp_flow_addresses(),
                destination,
            )?;
            dialer
                .exchange_icmp_with_options(
                    packet,
                    source,
                    hop_limit,
                    destination,
                    &options.network,
                )
                .await
        })
    }
}

fn validate_icmp_flow_addresses(
    addresses: Option<(Option<IpAddr>, Option<IpAddr>)>,
    destination: &SocksAddr,
) -> io::Result<()> {
    let Some((ipv4, ipv6)) = addresses else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "outbound is not an ICMP flow outbound",
        ));
    };
    let SocksAddr::Ip(destination) = destination else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Cloudflare Tunnel ICMP destination must be an IP address",
        ));
    };
    let port_address = if destination.is_ipv4() { ipv4 } else { ipv6 };
    if !port_address.is_some_and(|address| address.is_unspecified()) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported ICMP flow outbound from Cloudflare Tunnel",
        ));
    }
    Ok(())
}

fn cloudflared_client_arch() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        value => value,
    };
    format!("{}_{}", std::env::consts::OS, arch)
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::{
        Record,
        rdata::{SRV, TXT},
    };
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    use super::*;
    use crate::dns::{LookupFuture, MessageFuture};

    struct UnusedResolver;

    impl Resolver for UnusedResolver {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async { Err(io::Error::other("unused")) })
        }

        fn exchange<'a>(&'a self, _request: &'a Message) -> MessageFuture<'a> {
            Box::pin(async { Err(io::Error::other("unused")) })
        }
    }

    #[test]
    fn configured_feature_snapshot_matches_upstream_lists() {
        let resolver: Arc<dyn Resolver> = Arc::new(UnusedResolver);
        let v2 = RuntimeFeatureSelector::new(
            "account".into(),
            "v2".into(),
            false,
            resolver.clone(),
            DomainStrategy::AsIs,
        );
        let (version, features) = v2.snapshot();
        assert_eq!(version, CloudflaredIncomingDatagramVersion::V2);
        assert_eq!(
            features,
            [
                FEATURE_SERIALIZED_HEADERS,
                FEATURE_DATAGRAM_V2,
                FEATURE_QUIC_EOF,
                FEATURE_REMOTE_CONFIG,
            ]
        );

        let v3 = RuntimeFeatureSelector::new(
            "account".into(),
            "v3".into(),
            true,
            resolver,
            DomainStrategy::AsIs,
        );
        let (version, features) = v3.snapshot();
        assert_eq!(version, CloudflaredIncomingDatagramVersion::V3);
        assert!(features.iter().any(|value| value == FEATURE_DATAGRAM_V3));
        assert!(features.iter().any(|value| value == FEATURE_POST_QUANTUM));
    }

    #[test]
    fn client_arch_uses_go_compatible_names() {
        let arch = cloudflared_client_arch();
        assert!(arch.starts_with(std::env::consts::OS));
        #[cfg(target_arch = "x86_64")]
        assert!(arch.ends_with("_amd64"));
        #[cfg(target_arch = "aarch64")]
        assert!(arch.ends_with("_arm64"));
    }

    #[test]
    fn icmp_route_requires_unspecified_flow_port_for_address_family() {
        let destination = SocksAddr::new("198.51.100.1", 0);
        assert!(
            validate_icmp_flow_addresses(
                Some((
                    Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
                )),
                &destination,
            )
            .is_ok()
        );
        assert_eq!(
            validate_icmp_flow_addresses(None, &destination)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            validate_icmp_flow_addresses(
                Some((Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), None)),
                &destination,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Unsupported
        );
        assert!(
            validate_icmp_flow_addresses(
                Some((Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), None,)),
                &SocksAddr::new("2001:db8::1", 0),
            )
            .is_err()
        );
    }

    struct FeatureResolver;

    impl Resolver for FeatureResolver {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async { Err(io::Error::other("unused")) })
        }

        fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
            Box::pin(async move {
                assert_eq!(request.queries[0].query_type(), RecordType::TXT);
                assert_eq!(
                    request.queries[0].name().to_utf8(),
                    "cfd-features.argotunnel.com."
                );
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    OpCode::Query,
                );
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    60,
                    RData::TXT(TXT::new(vec![r#"{"dv3_2":100}"#.into()])),
                ));
                Ok(response)
            })
        }
    }

    #[tokio::test]
    async fn automatic_feature_lookup_enables_v3_for_selected_account() {
        let selector = RuntimeFeatureSelector::new(
            "account".into(),
            String::new(),
            false,
            Arc::new(FeatureResolver),
            DomainStrategy::AsIs,
        );
        selector.refresh().await.unwrap();
        let (version, features) = selector.snapshot();
        assert_eq!(version, CloudflaredIncomingDatagramVersion::V3);
        assert!(features.iter().any(|value| value == FEATURE_DATAGRAM_V3));
    }

    struct SrvResolver;

    impl Resolver for SrvResolver {
        fn lookup<'a>(
            &'a self,
            _domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async { Err(io::Error::other("SRV resolver only")) })
        }

        fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
            Box::pin(async move {
                assert_eq!(request.queries[0].query_type(), RecordType::SRV);
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    OpCode::Query,
                );
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    60,
                    RData::SRV(SRV::new(
                        10,
                        20,
                        7844,
                        Name::from_ascii("edge.example.").unwrap(),
                    )),
                ));
                Ok(response)
            })
        }
    }

    struct EdgeIpResolver;

    impl Resolver for EdgeIpResolver {
        fn lookup<'a>(
            &'a self,
            domain: &'a str,
            _strategy: DomainStrategy,
        ) -> LookupFuture<'a> {
            Box::pin(async move {
                assert_eq!(domain, "edge.example");
                Ok(vec!["192.0.2.10".parse().unwrap()])
            })
        }
    }

    #[tokio::test]
    async fn edge_discovery_uses_control_for_srv_and_tunnel_for_addresses() {
        let resolver = RuntimeEdgeResolver {
            control_resolver: Arc::new(SrvResolver),
            control_strategy: DomainStrategy::AsIs,
            tunnel_resolver: Arc::new(EdgeIpResolver),
            tunnel_strategy: DomainStrategy::Ipv4Only,
        };
        let regions = discover_cloudflared_edges(&resolver, "fed", 4)
            .await
            .unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(
            regions[0][0].address,
            "192.0.2.10:7844".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn route_dialer_runs_payload_sniff_actions_for_tcp_and_udp() {
        let outbounds = Arc::new(
            OutboundManager::from_options(
                &crate::option::Options::default(),
                "",
            )
            .unwrap(),
        );

        let tcp_fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_fallback_address = tcp_fallback.local_addr().unwrap();
        let tcp_selected = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_selected_port = tcp_selected.local_addr().unwrap().port();
        let request =
            b"GET /cloudflared HTTP/1.1\r\nHost: origin.example\r\n\r\n";
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_selected.accept().await.unwrap();
            let mut payload = vec![0_u8; request.len()];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, request);
            stream.write_all(b"selected").await.unwrap();
        });
        let tcp_router = Arc::new(
            Router::from_json(
                &[
                    json!({"action":"sniff", "sniffer":"http"}),
                    json!({
                        "protocol":"http",
                        "domain":"origin.example",
                        "override_port":tcp_selected_port
                    }),
                ],
                "",
            )
            .unwrap(),
        );
        let tcp_dialer = CloudflaredRouteDialer {
            inbound: "cloudflared-test".into(),
            router: tcp_router,
            outbounds: outbounds.clone(),
        };
        let mut tcp = tcp_dialer
            .dial_tcp(&tcp_fallback_address.into())
            .await
            .unwrap();
        tcp.write_all(request).await.unwrap();
        let mut tcp_response = [0_u8; 8];
        tcp.read_exact(&mut tcp_response).await.unwrap();
        assert_eq!(&tcp_response, b"selected");
        tcp_echo.await.unwrap();
        drop(tcp_fallback);

        let udp_fallback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_fallback_address = udp_fallback.local_addr().unwrap();
        let udp_selected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_selected_port = udp_selected.local_addr().unwrap().port();
        let udp_echo = tokio::spawn(async move {
            let mut payload = [0_u8; 512];
            let (size, source) =
                udp_selected.recv_from(&mut payload).await.unwrap();
            udp_selected
                .send_to(&payload[..size], source)
                .await
                .unwrap();
        });
        let udp_router = Arc::new(
            Router::from_json(
                &[
                    json!({"action":"sniff", "sniffer":"dns"}),
                    json!({
                        "protocol":"dns",
                        "override_port":udp_selected_port
                    }),
                ],
                "",
            )
            .unwrap(),
        );
        let udp_dialer = CloudflaredRouteDialer {
            inbound: "cloudflared-test".into(),
            router: udp_router,
            outbounds,
        };
        let packets = udp_dialer
            .listen_udp(&udp_fallback_address.into())
            .await
            .unwrap();
        let query = hex::decode(
            "740701000001000000000000012a06676f6f676c6503636f6d0000010001",
        )
        .unwrap();
        packets
            .send_to(&query, &udp_fallback_address.into())
            .await
            .unwrap();
        let mut udp_response = [0_u8; 512];
        let (size, source) =
            packets.recv_from(&mut udp_response).await.unwrap();
        assert_eq!(source, udp_fallback_address.into());
        assert_eq!(&udp_response[..size], query);
        udp_echo.await.unwrap();
        drop(udp_fallback);
    }

    #[tokio::test]
    async fn route_dialer_runs_resolve_before_terminal_cidr_rule() {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_target.local_addr().unwrap().port();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut payload = [0_u8; 7];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let options: crate::option::Options = serde_json::from_value(json!({
            "dns": {"servers": [{
                "type":"hosts",
                "tag":"route-dns",
                "predefined":{"resolved.origin":"127.0.0.1"}
            }]},
            "outbounds": [
                {
                    "type":"direct",
                    "tag":"direct",
                    "domain_resolver":"route-dns"
                },
                {"type":"block", "tag":"block"}
            ]
        }))
        .unwrap();
        let outbounds =
            Arc::new(OutboundManager::from_options(&options, "block").unwrap());
        let router = Arc::new(
            Router::from_json(
                &[
                    json!({
                        "domain":"resolved.origin",
                        "action":"resolve",
                        "server":"route-dns"
                    }),
                    json!({"ip_cidr":"127.0.0.0/8", "outbound":"direct"}),
                ],
                "block",
            )
            .unwrap(),
        );
        let dialer = CloudflaredRouteDialer {
            inbound: "cloudflared-resolve".into(),
            router,
            outbounds,
        };
        let mut stream = dialer
            .dial_tcp(&SocksAddr::new("resolved.origin", tcp_port))
            .await
            .unwrap();
        stream.write_all(b"resolve").await.unwrap();
        let mut response = [0_u8; 7];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"resolve");
        tcp_echo.await.unwrap();
    }
}
