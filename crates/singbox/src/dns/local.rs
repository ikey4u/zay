//! System DNS transport using sing-box dialers.
//!
//! Hickory remains responsible for reading each platform's DNS configuration,
//! while the wire exchanges use this crate's UDP/TCP transports.  This keeps
//! local DNS subject to the same bind, protect, physical-network and outbound
//! detour options as every other sing-box dialer.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::Name,
};
use hickory_resolver::config::{ProtocolConfig, ResolverConfig, ResolverOpts};
use tokio::time::timeout;

use crate::{
    adapter::Dialer,
    common::network::SocksAddr,
    dns::{
        client::{ExchangeFuture, Transport},
        transport::{TcpTransport, UdpTransport},
    },
};

pub struct LocalTransport {
    tag: String,
    dialer: Arc<dyn Dialer>,
    state: StdMutex<LocalState>,
    refresh_system: bool,
    source: LocalConfigurationSource,
    server_offset: AtomicU64,
    #[cfg(target_vendor = "apple")]
    darwin: Option<super::local_darwin::DarwinSystemResolver>,
    #[cfg(not(target_vendor = "apple"))]
    mdns: super::mdns::MdnsTransport,
}

#[derive(Clone, Copy)]
enum LocalConfigurationSource {
    System,
    #[cfg(target_os = "linux")]
    SystemdResolved,
}

#[derive(Clone)]
struct LocalServer {
    primary: Arc<dyn Transport>,
    fallback: Option<Arc<dyn Transport>>,
}

#[derive(Clone)]
struct LocalState {
    search: Vec<Name>,
    ndots: usize,
    timeout: std::time::Duration,
    attempts: usize,
    rotate: bool,
    trust_ad: bool,
    servers: Vec<LocalServer>,
    signature: String,
    checked_at: Instant,
}

impl LocalTransport {
    pub fn new(
        tag: impl Into<String>,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        Self::new_with_prefer_go(tag, dialer, false)
    }

    pub fn new_with_prefer_go(
        tag: impl Into<String>,
        dialer: Arc<dyn Dialer>,
        prefer_go: bool,
    ) -> io::Result<Self> {
        let tag = tag.into();
        #[cfg(not(target_os = "linux"))]
        let _ = prefer_go;
        #[cfg(target_os = "linux")]
        if !prefer_go
            && let Ok(Some(configuration)) =
                super::local_resolved_linux::read_configuration()
        {
            return Self::from_resolved_configuration(
                tag,
                dialer,
                configuration,
            );
        }
        let (config, options, rotate, trust_ad) = read_system_configuration()?;
        Self::from_config_with_flags(
            tag, dialer, config, options, rotate, trust_ad, true,
        )
    }

    #[cfg(test)]
    fn from_config(
        tag: impl Into<String>,
        dialer: Arc<dyn Dialer>,
        config: ResolverConfig,
        options: ResolverOpts,
    ) -> io::Result<Self> {
        Self::from_config_with_flags(
            tag, dialer, config, options, false, false, false,
        )
    }

    fn from_config_with_flags(
        tag: impl Into<String>,
        dialer: Arc<dyn Dialer>,
        config: ResolverConfig,
        options: ResolverOpts,
        rotate: bool,
        trust_ad: bool,
        refresh_system: bool,
    ) -> io::Result<Self> {
        let tag = tag.into();
        let state = Self::build_state(
            &tag,
            dialer.clone(),
            config,
            options,
            rotate,
            trust_ad,
        )?;
        #[cfg(not(target_vendor = "apple"))]
        let mdns =
            super::mdns::MdnsTransport::new(format!("{tag}/mdns"), Vec::new());
        Ok(Self {
            tag,
            dialer,
            state: StdMutex::new(state),
            refresh_system,
            source: LocalConfigurationSource::System,
            server_offset: AtomicU64::new(0),
            #[cfg(target_vendor = "apple")]
            darwin: refresh_system
                .then(super::local_darwin::DarwinSystemResolver::new),
            #[cfg(not(target_vendor = "apple"))]
            mdns,
        })
    }

    #[cfg(target_os = "linux")]
    fn from_resolved_configuration(
        tag: String,
        dialer: Arc<dyn Dialer>,
        configuration: super::local_resolved_linux::ResolvedConfiguration,
    ) -> io::Result<Self> {
        let state =
            Self::build_resolved_state(&tag, dialer.clone(), configuration)?;
        let mdns =
            super::mdns::MdnsTransport::new(format!("{tag}/mdns"), Vec::new());
        Ok(Self {
            tag,
            dialer,
            state: StdMutex::new(state),
            refresh_system: true,
            source: LocalConfigurationSource::SystemdResolved,
            server_offset: AtomicU64::new(0),
            mdns,
        })
    }

    fn build_state(
        tag: &str,
        dialer: Arc<dyn Dialer>,
        config: ResolverConfig,
        options: ResolverOpts,
        rotate: bool,
        trust_ad: bool,
    ) -> io::Result<LocalState> {
        let mut servers = Vec::new();
        let mut signature = String::new();
        for (index, server) in config.name_servers().iter().enumerate() {
            let connection = server.connections.first().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("system DNS server {} has no transport", server.ip),
                )
            })?;
            let address =
                SocksAddr::Ip(SocketAddr::new(server.ip, connection.port));
            signature.push_str(&format!(
                "{}:{}:{:?};",
                server.ip, connection.port, connection.protocol
            ));
            let transport_tag = format!("{tag}/system/{index}");
            #[allow(unreachable_patterns)]
            let transport: Arc<dyn Transport> = match connection.protocol {
                ProtocolConfig::Udp => Arc::new(UdpTransport::new(
                    transport_tag,
                    address,
                    dialer.clone(),
                )),
                ProtocolConfig::Tcp => Arc::new(TcpTransport::new(
                    transport_tag,
                    address,
                    dialer.clone(),
                )),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "system DNS configuration uses a non-local transport",
                    ));
                }
            };
            servers.push(LocalServer {
                primary: transport,
                fallback: None,
            });
        }
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "system DNS configuration contains no servers",
            ));
        }
        let mut search = config.search().to_vec();
        if search.is_empty()
            && let Some(domain) = config.domain()
        {
            search.push(domain.clone());
        }
        signature.push_str(&format!(
            "search={search:?};ndots={};timeout={:?};attempts={};rotate={rotate};trust_ad={trust_ad}",
            options.ndots, options.timeout, options.attempts
        ));
        Ok(LocalState {
            search,
            ndots: options.ndots,
            timeout: options.timeout,
            attempts: options.attempts.max(1),
            rotate,
            trust_ad,
            servers,
            signature,
            checked_at: Instant::now(),
        })
    }

    #[cfg(target_os = "linux")]
    fn build_resolved_state(
        tag: &str,
        dialer: Arc<dyn Dialer>,
        configuration: super::local_resolved_linux::ResolvedConfiguration,
    ) -> io::Result<LocalState> {
        use crate::{
            common::tls::build_client_config, dns::transport::TlsTransport,
            option::OutboundTlsOptions,
        };

        let mut servers = Vec::with_capacity(configuration.servers.len());
        for (index, specification) in configuration.servers.iter().enumerate() {
            let plain = || -> Arc<dyn Transport> {
                Arc::new(UdpTransport::new(
                    format!("{tag}/resolved/{index}/udp"),
                    SocksAddr::Ip(specification.socket_address(false)),
                    dialer.clone(),
                ))
            };
            let tls = || -> io::Result<Arc<dyn Transport>> {
                let server_name = specification.tls_server_name();
                let options = OutboundTlsOptions {
                    enabled: true,
                    server_name: server_name.clone(),
                    ..Default::default()
                };
                let tls = build_client_config(&server_name, &options, &[])
                    .map_err(|error| io::Error::other(error.to_string()))?;
                Ok(Arc::new(TlsTransport::new(
                    format!("{tag}/resolved/{index}/tls"),
                    SocksAddr::Ip(specification.socket_address(true)),
                    dialer.clone(),
                    tls,
                )))
            };
            let server = match configuration.tls_mode {
                super::local_resolved_linux::ResolvedTlsMode::Disabled => {
                    LocalServer {
                        primary: plain(),
                        fallback: None,
                    }
                }
                super::local_resolved_linux::ResolvedTlsMode::Required => {
                    LocalServer {
                        primary: tls()?,
                        fallback: None,
                    }
                }
                super::local_resolved_linux::ResolvedTlsMode::Opportunistic => {
                    LocalServer {
                        primary: tls()?,
                        fallback: Some(plain()),
                    }
                }
            };
            servers.push(server);
        }
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "systemd-resolved link has no valid DNS servers",
            ));
        }
        let mut options = ResolverOpts::default();
        options.attempts = 1;
        Ok(LocalState {
            search: Vec::new(),
            ndots: options.ndots,
            timeout: options.timeout,
            attempts: options.attempts,
            rotate: false,
            trust_ad: false,
            servers,
            signature: configuration.signature,
            checked_at: Instant::now(),
        })
    }

    fn current_state(&self) -> LocalState {
        const REFRESH_INTERVAL: std::time::Duration =
            std::time::Duration::from_secs(1);
        {
            let state = self.state.lock().expect("local DNS state poisoned");
            if !self.refresh_system
                || state.checked_at.elapsed() < REFRESH_INTERVAL
            {
                return state.clone();
            }
        }
        let refreshed = match self.source {
            LocalConfigurationSource::System => read_system_configuration()
                .and_then(|(config, options, rotate, trust_ad)| {
                    Self::build_state(
                        &self.tag,
                        self.dialer.clone(),
                        config,
                        options,
                        rotate,
                        trust_ad,
                    )
                }),
            #[cfg(target_os = "linux")]
            LocalConfigurationSource::SystemdResolved => {
                super::local_resolved_linux::read_configuration().and_then(
                    |configuration| {
                        let configuration = configuration.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                "systemd-resolved no longer manages resolv.conf",
                            )
                        })?;
                        Self::build_resolved_state(
                            &self.tag,
                            self.dialer.clone(),
                            configuration,
                        )
                    },
                )
            }
        };
        let mut state = self.state.lock().expect("local DNS state poisoned");
        if let Ok(refreshed) = refreshed
            && refreshed.signature != state.signature
        {
            *state = refreshed;
        }
        state.checked_at = Instant::now();
        state.clone()
    }

    #[cfg(test)]
    fn name_candidates(&self, name: &Name) -> io::Result<Vec<Name>> {
        self.name_candidates_with_state(&self.current_state(), name)
    }

    fn name_candidates_with_state(
        &self,
        state: &LocalState,
        name: &Name,
    ) -> io::Result<Vec<Name>> {
        let text = name.to_ascii();
        if text.len() > 254 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS name exceeds 254 bytes",
            ));
        }
        if name.is_fqdn() {
            return (!avoid_dns(&text)).then(|| vec![name.clone()]).ok_or_else(
                || {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "DNS name is not queryable",
                    )
                },
            );
        }

        let rooted = Name::from_ascii(format!("{text}.")).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        })?;
        let has_ndots = text.matches('.').count() >= state.ndots;
        let mut names = Vec::with_capacity(state.search.len() + 1);
        if has_ndots && !avoid_dns(&rooted.to_ascii()) {
            names.push(rooted.clone());
        }
        for suffix in &state.search {
            let candidate = Name::from_ascii(format!(
                "{}.{}",
                text.trim_end_matches('.'),
                suffix.to_ascii()
            ))
            .map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidInput, error)
            })?;
            if candidate.to_ascii().len() <= 254
                && !avoid_dns(&candidate.to_ascii())
            {
                names.push(candidate);
            }
        }
        if !has_ndots && !avoid_dns(&rooted.to_ascii()) {
            names.push(rooted);
        }
        if names.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS name has no queryable candidates",
            ));
        }
        Ok(names)
    }

    async fn exchange_candidate(
        &self,
        state: &LocalState,
        request: &Message,
        original_name: &Name,
        candidate: &Name,
    ) -> io::Result<Message> {
        let mut candidate_request = request.clone();
        candidate_request.queries[0].name = candidate.clone();
        candidate_request.metadata.recursion_desired = true;
        candidate_request.metadata.authentic_data = state.trust_ad;
        let offset = if state.rotate {
            self.server_offset.fetch_add(1, Ordering::Relaxed) as usize
        } else {
            0
        };
        let mut last_error = None;
        for attempt in 0..state.attempts {
            for server_index in 0..state.servers.len() {
                let index =
                    (offset + attempt + server_index) % state.servers.len();
                let server = &state.servers[index];
                let primary = timeout(
                    state.timeout,
                    server.primary.exchange(&candidate_request),
                )
                .await;
                let result = match primary {
                    Ok(Err(_)) | Err(_) if server.fallback.is_some() => {
                        timeout(
                            state.timeout,
                            server
                                .fallback
                                .as_ref()
                                .expect("fallback checked")
                                .exchange(&candidate_request),
                        )
                        .await
                    }
                    result => result,
                };
                match result {
                    Ok(Ok(mut response)) => {
                        response.queries = request.queries.clone();
                        for record in &mut response.answers {
                            if record.name.eq_case(candidate) {
                                record.name = original_name.clone();
                            }
                        }
                        return Ok(response);
                    }
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_) => {
                        last_error = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "system DNS query to server {index} timed out"
                            ),
                        ));
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::other("system DNS query has no available server")
        }))
    }
}

impl Transport for LocalTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let [query] = request.queries.as_slice() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "local DNS exchange requires exactly one question",
                ));
            };
            #[cfg(target_vendor = "apple")]
            if super::mdns::is_local_domain(&query.name().to_ascii())
                && let Some(darwin) = &self.darwin
            {
                if avoid_dns(&query.name().to_ascii()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "DNS name is not queryable",
                    ));
                }
                return darwin.exchange(request).await;
            }
            #[cfg(not(target_vendor = "apple"))]
            if super::mdns::is_local_domain(&query.name().to_ascii()) {
                return self.mdns.exchange(request).await;
            }
            let state = self.current_state();
            let original_name = query.name.clone();
            let candidates =
                self.name_candidates_with_state(&state, &original_name)?;
            let mut last_name_error = None;
            let mut last_error = None;
            for candidate in candidates {
                match self
                    .exchange_candidate(
                        &state,
                        request,
                        &original_name,
                        &candidate,
                    )
                    .await
                {
                    Ok(response)
                        if response.metadata.response_code
                            != ResponseCode::NXDomain =>
                    {
                        return Ok(response);
                    }
                    Ok(response) => last_name_error = Some(response),
                    Err(error) => last_error = Some(error),
                }
            }
            if let Some(response) = last_name_error {
                return Ok(response);
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::other("system DNS search returned no response")
            }))
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        Some(super::mdns::is_local_domain(domain))
    }
}

fn avoid_dns(name: &str) -> bool {
    name.trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(".onion")
}

fn read_system_configuration()
-> io::Result<(ResolverConfig, ResolverOpts, bool, bool)> {
    #[cfg(target_vendor = "apple")]
    if let Some((config, options)) =
        super::local_darwin::read_primary_service_configuration()?
    {
        return Ok((config, options, false, false));
    }
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((config, options)) => Ok((config, options, false, false)),
        Err(system_error) => {
            #[cfg(unix)]
            {
                let bytes = std::fs::read("/etc/resolv.conf").map_err(
                    |error| {
                        io::Error::other(format!(
                            "read system DNS configuration ({system_error}); fallback /etc/resolv.conf: {error}"
                        ))
                    },
                )?;
                let parsed = resolv_conf::Config::parse(&bytes).map_err(
                    |error| {
                        io::Error::other(format!(
                            "read system DNS configuration ({system_error}); parse fallback /etc/resolv.conf: {error}"
                        ))
                    },
                )?;
                let name_servers = parsed
                    .nameservers
                    .iter()
                    .map(|address| {
                        if parsed.use_vc {
                            hickory_resolver::config::NameServerConfig::tcp(
                                address.clone().into(),
                            )
                        } else {
                            hickory_resolver::config::NameServerConfig::udp_and_tcp(
                                address.clone().into(),
                            )
                        }
                    })
                    .collect::<Vec<_>>();
                if name_servers.is_empty() {
                    return Err(io::Error::other(format!(
                        "read system DNS configuration ({system_error}); fallback /etc/resolv.conf has no servers"
                    )));
                }
                let domain = parsed
                    .get_system_domain()
                    .and_then(|value| Name::from_ascii(value.as_str()).ok());
                let search = parsed
                    .get_last_search_or_domain()
                    .filter(|value| value.as_str() != "--")
                    .filter_map(|value| Name::from_ascii(value.as_str()).ok())
                    .collect();
                let config =
                    ResolverConfig::from_parts(domain, search, name_servers);
                let mut options = ResolverOpts::default();
                options.ndots = parsed.ndots as usize;
                options.timeout =
                    std::time::Duration::from_secs(u64::from(parsed.timeout));
                options.attempts = parsed.attempts as usize;
                Ok((config, options, parsed.rotate, parsed.trust_ad))
            }
            #[cfg(not(unix))]
            {
                Err(io::Error::other(system_error.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::IpAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
        serialize::binary::{
            BinDecodable, BinDecoder, BinEncodable, BinEncoder,
        },
    };
    use hickory_resolver::config::{
        NameServerConfig, ResolverConfig, ResolverOpts,
    };
    use tokio::net::UdpSocket;

    use super::{LocalServer, LocalTransport};
    use crate::{
        dns::client::{ExchangeFuture, Transport},
        option::DirectOutboundOptions,
        protocol::direct::DirectOutbound,
    };

    struct FailingTransport;

    impl Transport for FailingTransport {
        fn tag(&self) -> &str {
            "fail"
        }

        fn exchange<'a>(&'a self, _request: &'a Message) -> ExchangeFuture<'a> {
            Box::pin(async { Err(io::Error::other("primary failed")) })
        }
    }

    struct AnswerTransport(Arc<AtomicUsize>);

    impl Transport for AnswerTransport {
        fn tag(&self) -> &str {
            "answer"
        }

        fn exchange<'a>(&'a self, request: &'a Message) -> ExchangeFuture<'a> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::Relaxed);
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    OpCode::Query,
                );
                response.queries = request.queries.clone();
                response.add_answer(Record::from_rdata(
                    request.queries[0].name.clone(),
                    60,
                    RData::A(A::new(192, 0, 2, 10)),
                ));
                Ok(response)
            })
        }
    }

    fn transport(search: &[&str], ndots: usize) -> LocalTransport {
        let config = ResolverConfig::from_parts(
            None,
            search
                .iter()
                .map(|name| Name::from_ascii(*name).unwrap())
                .collect(),
            vec![NameServerConfig::udp(IpAddr::from([127, 0, 0, 1]))],
        );
        let mut options = ResolverOpts::default();
        options.ndots = ndots;
        options.timeout = Duration::from_millis(20);
        options.attempts = 1;
        LocalTransport::from_config(
            "local",
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            config,
            options,
        )
        .unwrap()
    }

    #[test]
    fn system_search_order_matches_resolv_conf_ndots() {
        let local = transport(&["corp.example."], 1);
        let short = local
            .name_candidates(&Name::from_ascii("printer").unwrap())
            .unwrap();
        assert_eq!(
            short.iter().map(Name::to_ascii).collect::<Vec<_>>(),
            ["printer.corp.example.", "printer."]
        );
        let dotted = local
            .name_candidates(&Name::from_ascii("www.example").unwrap())
            .unwrap();
        assert_eq!(
            dotted.iter().map(Name::to_ascii).collect::<Vec<_>>(),
            ["www.example.", "www.example.corp.example."]
        );
    }

    #[test]
    fn system_search_rejects_onion_names() {
        let local = transport(&[], 1);
        let error = local
            .name_candidates(&Name::from_ascii("hidden.onion.").unwrap())
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_mdns_domains_match_upstream_zones() {
        assert!(crate::dns::mdns::is_local_domain("printer.local."));
        assert!(crate::dns::mdns::is_local_domain("254.169.in-addr.arpa."));
        assert!(crate::dns::mdns::is_local_domain("1.0.0.0.8.e.f.ip6.arpa."));
        assert!(!crate::dns::mdns::is_local_domain("notlocal.example."));
        assert!(!crate::dns::mdns::is_local_domain("local.example."));
    }

    #[tokio::test]
    async fn search_exchange_restores_original_question_and_answer_name() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut bytes = [0_u8; 2048];
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request =
                Message::read(&mut BinDecoder::new(&bytes[..size])).unwrap();
            assert_eq!(request.queries[0].name.to_ascii(), "printer.lan.");
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                OpCode::Query,
            );
            response.queries = request.queries.clone();
            response.add_answer(Record::from_rdata(
                request.queries[0].name.clone(),
                60,
                RData::A(A::new(192, 0, 2, 9)),
            ));
            let mut output = Vec::new();
            response.emit(&mut BinEncoder::new(&mut output)).unwrap();
            socket.send_to(&output, peer).await.unwrap();
        });

        let mut server = NameServerConfig::udp(IpAddr::from([127, 0, 0, 1]));
        server.connections[0].port = port;
        let config = ResolverConfig::from_parts(
            None,
            vec![Name::from_ascii("lan.").unwrap()],
            vec![server],
        );
        let mut options = ResolverOpts::default();
        options.ndots = 1;
        options.timeout = Duration::from_secs(1);
        options.attempts = 1;
        let local = LocalTransport::from_config(
            "local",
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            config,
            options,
        )
        .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("printer").unwrap(),
            RecordType::A,
        ));
        let response = local.exchange(&request).await.unwrap();
        assert_eq!(response.queries[0].name.to_ascii(), "printer");
        assert_eq!(response.answers[0].name.to_ascii(), "printer");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn server_fallback_runs_after_primary_transport_error() {
        let local = transport(&[], 1);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut state = local.current_state();
        state.timeout = Duration::from_secs(1);
        state.servers = vec![LocalServer {
            primary: Arc::new(FailingTransport),
            fallback: Some(Arc::new(AnswerTransport(calls.clone()))),
        }];
        let name = Name::from_ascii("resolver.example.").unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(name.clone(), RecordType::A));
        let response = local
            .exchange_candidate(&state, &request, &name, &name)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(response.answers.len(), 1);
    }
}
