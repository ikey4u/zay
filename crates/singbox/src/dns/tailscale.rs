//! DNS resolver driven by the live Tailscale control-plane netmap.

use std::{
    borrow::Cow,
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
};

use bytes::Bytes;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, StatusCode,
    client::conn::http1,
    header::{ACCEPT, CONTENT_TYPE, HOST},
};
use hyper_util::rt::TokioIo;

use crate::{
    adapter::{DialFuture, Dialer, IcmpResponse, PacketFuture, PacketStream},
    common::{
        certificate_store::CertificateStore, network::SocksAddr, ntp::NtpClock,
        tls::build_client_config,
    },
    constant,
    dns::{
        LookupFuture, LookupOptions, MessageFuture, Resolver, apply_strategy,
        client::{Client, ExchangeFuture, Transport},
        manager::SharedResolver,
        transport::{HttpsTransport, RemoteResolver, UdpTransport},
    },
    option::{
        DirectOutboundOptions, DomainStrategy, Listable, OutboundTlsOptions,
    },
    protocol::{
        direct::DirectOutbound,
        tailscale_control_types::{
            TailscaleDnsConfig, TailscaleDnsResolver, TailscaleNetmapState,
            TailscaleNode,
        },
    },
};

/// Provides the latest fully merged netmap without tying DNS construction to
/// the endpoint's concrete runtime type.
pub trait TailscaleNetmapProvider: Send + Sync {
    fn netmap(&self) -> Option<Arc<TailscaleNetmapState>>;

    /// Stable ID, DNS name, or Tailscale address of the selected exit node.
    fn exit_node(&self) -> Option<String> {
        None
    }
}

#[derive(Clone)]
struct BoundEndpoint {
    dialer: Arc<dyn Dialer>,
    provider: Arc<dyn TailscaleNetmapProvider>,
    fallback: Arc<dyn Dialer>,
}

/// Dynamic Tailscale DNS transport. Control map changes are observed for every
/// query, while concrete upstream transports are cached and reused by address.
pub struct TailscaleResolver {
    tag: String,
    endpoint_tag: String,
    accept_default_resolvers: bool,
    accept_search_domain: bool,
    endpoint: RwLock<Option<BoundEndpoint>>,
    resolvers: Mutex<HashMap<String, SharedResolver>>,
    client: Arc<Client>,
    default_strategy: DomainStrategy,
    client_subnet: Option<ipnet::IpNet>,
    certificate_store: Option<CertificateStore>,
    ntp_clock: Option<NtpClock>,
}

impl TailscaleResolver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: impl Into<String>,
        endpoint_tag: impl Into<String>,
        accept_default_resolvers: bool,
        accept_search_domain: bool,
        client: Arc<Client>,
        default_strategy: DomainStrategy,
        client_subnet: Option<ipnet::IpNet>,
    ) -> Self {
        Self::new_with_runtime_context(
            tag,
            endpoint_tag,
            accept_default_resolvers,
            accept_search_domain,
            client,
            default_strategy,
            client_subnet,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_runtime_context(
        tag: impl Into<String>,
        endpoint_tag: impl Into<String>,
        accept_default_resolvers: bool,
        accept_search_domain: bool,
        client: Arc<Client>,
        default_strategy: DomainStrategy,
        client_subnet: Option<ipnet::IpNet>,
        certificate_store: Option<CertificateStore>,
        ntp_clock: Option<NtpClock>,
    ) -> Self {
        Self {
            tag: tag.into(),
            endpoint_tag: endpoint_tag.into(),
            accept_default_resolvers,
            accept_search_domain,
            endpoint: RwLock::new(None),
            resolvers: Mutex::new(HashMap::new()),
            client,
            default_strategy,
            client_subnet,
            certificate_store,
            ntp_clock,
        }
    }

    pub fn endpoint_tag(&self) -> &str {
        &self.endpoint_tag
    }

    pub fn is_bound(&self) -> bool {
        self.endpoint.read().is_ok_and(|value| value.is_some())
    }

    pub fn bind(
        &self,
        dialer: Arc<dyn Dialer>,
        provider: Arc<dyn TailscaleNetmapProvider>,
    ) -> io::Result<()> {
        let mut endpoint = self.endpoint.write().map_err(|_| {
            io::Error::other("Tailscale DNS endpoint lock poisoned")
        })?;
        if endpoint.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Tailscale DNS server {:?} is already bound", self.tag),
            ));
        }
        *endpoint = Some(BoundEndpoint {
            dialer,
            provider,
            fallback: Arc::new(DirectOutbound::new(
                DirectOutboundOptions::default(),
            )),
        });
        Ok(())
    }

    fn bound(&self) -> io::Result<BoundEndpoint> {
        self.endpoint
            .read()
            .map_err(|_| {
                io::Error::other("Tailscale DNS endpoint lock poisoned")
            })?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "Tailscale DNS endpoint {:?} is not available",
                        self.endpoint_tag
                    ),
                )
            })
    }

    fn netmap(
        &self,
        endpoint: &BoundEndpoint,
    ) -> io::Result<Arc<TailscaleNetmapState>> {
        endpoint.provider.netmap().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Tailscale DNS configuration is not ready",
            )
        })
    }

    fn search_names(
        &self,
        config: &TailscaleDnsConfig,
        domain: &str,
    ) -> Vec<String> {
        let canonical = canonical_domain(domain);
        if self.accept_search_domain && !canonical.contains('.') {
            return config
                .domains
                .iter()
                .map(|suffix| canonical_domain(suffix))
                .filter(|suffix| !suffix.is_empty())
                .map(|suffix| format!("{canonical}.{suffix}"))
                .collect();
        }
        vec![canonical]
    }

    fn host_addresses(
        &self,
        netmap: &TailscaleNetmapState,
        domain: &str,
    ) -> Option<Vec<IpAddr>> {
        let canonical = canonical_domain(domain);
        let mut explicit = HashMap::<String, Vec<IpAddr>>::new();
        if let Some(config) = &netmap.dns_config {
            for record in &config.extra_records {
                if !matches!(record.record_type.as_str(), "" | "A" | "AAAA") {
                    continue;
                }
                if let Ok(address) = record.value.parse() {
                    explicit
                        .entry(canonical_domain(&record.name))
                        .or_default()
                        .push(address);
                }
            }
        }
        if let Some(addresses) = explicit.get(&canonical) {
            return Some(addresses.clone());
        }

        let mut magic = HashMap::<String, Vec<IpAddr>>::new();
        for node in netmap.node.iter().chain(netmap.peers.values()) {
            if node.name.is_empty() {
                continue;
            }
            let addresses = node
                .addresses
                .iter()
                .filter_map(|address| {
                    address
                        .parse::<ipnet::IpNet>()
                        .map(|prefix| prefix.addr())
                        .or_else(|_| address.parse())
                        .ok()
                })
                .collect::<Vec<_>>();
            if !addresses.is_empty() {
                magic.insert(canonical_domain(&node.name), addresses);
            }
        }
        if let Some(addresses) = magic.get(&canonical) {
            return Some(addresses.clone());
        }
        let mut parent = canonical.as_str();
        while let Some((_, suffix)) = parent.split_once('.') {
            if let Some(addresses) = magic.get(suffix) {
                return Some(addresses.clone());
            }
            parent = suffix;
        }
        None
    }

    fn matching_resolvers<'a>(
        &self,
        config: &'a TailscaleDnsConfig,
        domain: &str,
        allow_default: bool,
    ) -> Option<&'a [TailscaleDnsResolver]> {
        let canonical = canonical_domain(domain);
        let route = config
            .routes
            .iter()
            .filter(|(suffix, _)| domain_matches(&canonical, suffix))
            .max_by_key(|(suffix, _)| canonical_domain(suffix).len());
        if let Some((_, resolvers)) = route {
            return Some(resolvers);
        }
        if config.proxied
            && config
                .domains
                .iter()
                .any(|suffix| domain_matches(&canonical, suffix))
        {
            return Some(&[]);
        }
        if !allow_default || !self.accept_default_resolvers {
            return None;
        }
        if !config.resolvers.is_empty() {
            Some(&config.resolvers)
        } else if !config.routes.is_empty() || config.proxied {
            Some(&config.fallback_resolvers)
        } else {
            None
        }
    }

    fn effective_config<'a>(
        &self,
        endpoint: &BoundEndpoint,
        netmap: &'a TailscaleNetmapState,
    ) -> io::Result<Cow<'a, TailscaleDnsConfig>> {
        let config = netmap.dns_config.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Tailscale DNS configuration is not ready",
            )
        })?;
        let Some(exit_node) = endpoint.provider.exit_node() else {
            return Ok(Cow::Borrowed(config));
        };
        let Some(peer) = selected_exit_node(netmap, &exit_node) else {
            return Ok(Cow::Borrowed(config));
        };

        if let Some(doh_url) = exit_node_dns_proxy_url(netmap, peer) {
            let mut effective = config.clone();
            effective
                .resolvers
                .retain(|resolver| resolver.use_with_exit_node);
            if effective.resolvers.is_empty() {
                effective.resolvers.push(TailscaleDnsResolver {
                    address: doh_url,
                    ..Default::default()
                });
            }
            effective.routes.retain(|_, resolvers| {
                if resolvers.is_empty() {
                    return true;
                }
                resolvers.retain(|resolver| resolver.use_with_exit_node);
                !resolvers.is_empty()
            });
            return Ok(Cow::Owned(effective));
        }

        if config.resolvers.is_empty()
            && peer.is_wireguard_only
            && !peer.exit_node_dns_resolvers.is_empty()
        {
            let mut effective = config.clone();
            effective.resolvers = peer.exit_node_dns_resolvers.clone();
            return Ok(Cow::Owned(effective));
        }
        Ok(Cow::Borrowed(config))
    }

    async fn resolver_for(
        &self,
        endpoint: &BoundEndpoint,
        resolver: &TailscaleDnsResolver,
    ) -> io::Result<SharedResolver> {
        let parsed = ParsedResolver::parse(&resolver.address)?;
        let server_address = parsed.resolve(resolver).await?;
        let cache_key = format!("{}|{}", resolver.address, server_address);
        if let Some(cached) = self
            .resolvers
            .lock()
            .map_err(|_| io::Error::other("Tailscale DNS cache lock poisoned"))?
            .get(&cache_key)
            .cloned()
        {
            return Ok(cached);
        }

        let routed: Arc<dyn Dialer> = Arc::new(TailscaleDnsDialer {
            endpoint: endpoint.dialer.clone(),
            fallback: endpoint.fallback.clone(),
        });
        let tag = format!("{}/{}", self.tag, cache_key);
        let built: SharedResolver = match parsed {
            ParsedResolver::Udp { .. } => {
                Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    UdpTransport::new(tag, server_address.into(), routed),
                    self.client.clone(),
                    self.default_strategy,
                    self.client_subnet,
                ))
            }
            ParsedResolver::Http {
                url, secure, host, ..
            } => {
                let dialer = if secure {
                    routed
                } else {
                    endpoint.dialer.clone()
                };
                if secure {
                    let mut tls_options = OutboundTlsOptions {
                        enabled: true,
                        alpn: Listable(vec!["h2".into(), "http/1.1".into()]),
                        ..Default::default()
                    };
                    tls_options.set_runtime_context(
                        self.ntp_clock.clone(),
                        self.certificate_store.clone(),
                    );
                    let tls = build_client_config(
                        &host,
                        &tls_options,
                        &["h2", "http/1.1"],
                    )
                    .map_err(|error| io::Error::other(error.to_string()))?;
                    Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                        HttpsTransport::new(
                            tag,
                            server_address.into(),
                            dialer,
                            tls,
                            url.to_string(),
                            Default::default(),
                        ),
                        self.client.clone(),
                        self.default_strategy,
                        self.client_subnet,
                    ))
                } else {
                    Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                        PlainHttpTransport {
                            tag,
                            server: server_address.into(),
                            dialer,
                            uri: url.to_string(),
                            authority: url_authority(&url),
                        },
                        self.client.clone(),
                        self.default_strategy,
                        self.client_subnet,
                    ))
                }
            }
        };
        self.resolvers
            .lock()
            .map_err(|_| io::Error::other("Tailscale DNS cache lock poisoned"))?
            .insert(cache_key, built.clone());
        Ok(built)
    }

    async fn exchange_once(
        &self,
        endpoint: &BoundEndpoint,
        netmap: &TailscaleNetmapState,
        request: &Message,
        options: LookupOptions,
        allow_default: bool,
    ) -> io::Result<Message> {
        let [query] = request.queries.as_slice() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Tailscale DNS exchange requires exactly one question",
            ));
        };
        if let Some(addresses) =
            self.host_addresses(netmap, &query.name().to_utf8())
        {
            return Ok(host_response(request, addresses));
        }
        let config = self.effective_config(endpoint, netmap)?;
        let Some(resolvers) = self.matching_resolvers(
            &config,
            &query.name().to_utf8(),
            allow_default,
        ) else {
            return Ok(status_response(request, ResponseCode::NXDomain));
        };
        if resolvers.is_empty() {
            return Ok(status_response(request, ResponseCode::NXDomain));
        }
        let mut last_error = None;
        for configured in resolvers {
            match self.resolver_for(endpoint, configured).await {
                Ok(resolver) => {
                    match resolver.exchange_with_options(request, options).await
                    {
                        Ok(response) => return Ok(response),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "missing Tailscale DNS resolvers",
            )
        }))
    }

    fn preferred_domain_in(
        &self,
        netmap: &TailscaleNetmapState,
        domain: &str,
    ) -> bool {
        if self.host_addresses(netmap, domain).is_some() {
            return true;
        }
        let Some(config) = &netmap.dns_config else {
            return false;
        };
        let canonical = canonical_domain(domain);
        (self.accept_search_domain
            && !canonical.contains('.')
            && !config.domains.is_empty())
            || config
                .routes
                .keys()
                .any(|suffix| domain_matches(&canonical, suffix))
            || (config.proxied
                && config
                    .domains
                    .iter()
                    .any(|suffix| domain_matches(&canonical, suffix)))
    }

    /// Reports whether the live Tailscale configuration owns this domain.
    /// Embedding applications can use this for `preferred_by` routing.
    pub fn preferred_domain(&self, domain: &str) -> bool {
        self.bound()
            .ok()
            .and_then(|endpoint| endpoint.provider.netmap())
            .is_some_and(|netmap| self.preferred_domain_in(&netmap, domain))
    }
}

impl Resolver for TailscaleResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        self.lookup_with_options(
            domain,
            LookupOptions {
                strategy,
                ..Default::default()
            },
        )
    }

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        options: LookupOptions,
    ) -> LookupFuture<'a> {
        Box::pin(async move {
            let mut addresses = Vec::new();
            let types: &[RecordType] = match options.strategy {
                DomainStrategy::Ipv4Only => &[RecordType::A],
                DomainStrategy::Ipv6Only => &[RecordType::AAAA],
                DomainStrategy::PreferIpv6 => {
                    &[RecordType::AAAA, RecordType::A]
                }
                _ => &[RecordType::A, RecordType::AAAA],
            };
            let mut last_error = None;
            for record_type in types {
                let name = Name::from_ascii(domain).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        error.to_string(),
                    )
                })?;
                let mut request = Message::query();
                request.add_query(Query::query(name, *record_type));
                match self.exchange_with_options(&request, options).await {
                    Ok(response)
                        if response.metadata.response_code
                            == ResponseCode::NoError =>
                    {
                        addresses.extend(response.answers.iter().filter_map(
                            |record| match &record.data {
                                RData::A(address) => {
                                    Some(IpAddr::V4(address.0))
                                }
                                RData::AAAA(address) => {
                                    Some(IpAddr::V6(address.0))
                                }
                                _ => None,
                            },
                        ));
                    }
                    Ok(response) => {
                        last_error = Some(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "Tailscale DNS response code: {}",
                                response.metadata.response_code
                            ),
                        ));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            apply_strategy(&mut addresses, options.strategy);
            addresses.dedup();
            if addresses.is_empty() {
                return Err(last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Tailscale DNS response for {domain:?} has no addresses"),
                    )
                }));
            }
            Ok(addresses)
        })
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        self.exchange_with_options(request, LookupOptions::default())
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a Message,
        options: LookupOptions,
    ) -> MessageFuture<'a> {
        Box::pin(async move {
            let [original_query] = request.queries.as_slice() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Tailscale DNS exchange requires exactly one question",
                ));
            };
            let endpoint = self.bound()?;
            let netmap = self.netmap(&endpoint)?;
            let config = self.effective_config(&endpoint, &netmap)?;
            let names =
                self.search_names(&config, &original_query.name().to_utf8());
            if names.is_empty() {
                return Ok(status_response(request, ResponseCode::NXDomain));
            }
            let original_name = original_query.name().clone();
            let searching = names.len() > 1
                || canonical_domain(&original_name.to_utf8()) != names[0];
            let mut last_error = None;
            for name in names {
                let expanded_name =
                    Name::from_ascii(&name).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            error.to_string(),
                        )
                    })?;
                let mut expanded = request.clone();
                expanded.queries[0].set_name(expanded_name.clone());
                match self
                    .exchange_once(
                        &endpoint, &netmap, &expanded, options, !searching,
                    )
                    .await
                {
                    Ok(mut response)
                        if response.metadata.response_code
                            != ResponseCode::NXDomain =>
                    {
                        response.queries = request.queries.clone();
                        for answer in &mut response.answers {
                            if answer.name == expanded_name {
                                answer.name = original_name.clone();
                            }
                        }
                        return Ok(response);
                    }
                    Ok(response) => last_error = Some(response),
                    Err(error) => return Err(error),
                }
            }
            Ok(last_error.unwrap_or_else(|| {
                status_response(request, ResponseCode::NXDomain)
            }))
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        Some(TailscaleResolver::preferred_domain(self, domain))
    }
}

#[derive(Clone)]
struct TailscaleDnsDialer {
    endpoint: Arc<dyn Dialer>,
    fallback: Arc<dyn Dialer>,
}

impl TailscaleDnsDialer {
    fn selected(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<&Arc<dyn Dialer>> {
        let SocksAddr::Ip(address) = destination else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Tailscale DNS upstream must be resolved before dialing",
            ));
        };
        Ok(if self.endpoint.preferred_address(address.ip()) {
            &self.endpoint
        } else {
            &self.fallback
        })
    }
}

impl Dialer for TailscaleDnsDialer {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            self.selected(destination)?.dial_tcp(destination).await
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            self.selected(destination)?.listen_udp(destination).await
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
            self.selected(destination)?
                .exchange_icmp(packet, source, hop_limit, destination)
                .await
        })
    }
}

enum ParsedResolver {
    Udp {
        host: String,
        port: u16,
    },
    Http {
        url: url::Url,
        secure: bool,
        host: String,
        port: u16,
    },
}

impl ParsedResolver {
    fn parse(value: &str) -> io::Result<Self> {
        if let Ok(url) = url::Url::parse(value)
            && matches!(url.scheme(), "http" | "https")
        {
            let host = url
                .host_str()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Tailscale DNS URL has no host",
                    )
                })?
                .to_owned();
            let secure = url.scheme() == "https";
            let port = url.port().unwrap_or(if secure { 443 } else { 80 });
            return Ok(Self::Http {
                url,
                secure,
                host,
                port,
            });
        }
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Ok(Self::Udp {
                host: address.ip().to_string(),
                port: address.port(),
            });
        }
        if let Ok(address) = value.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Ok(Self::Udp {
                host: address.to_string(),
                port: 53,
            });
        }
        let destination = if value.rsplit_once(':').is_some() {
            value.parse::<SocksAddr>()?
        } else {
            SocksAddr::new(value, 53)
        };
        Ok(Self::Udp {
            host: destination.host(),
            port: destination.port(),
        })
    }

    async fn resolve(
        &self,
        resolver: &TailscaleDnsResolver,
    ) -> io::Result<SocketAddr> {
        let (host, port) = match self {
            Self::Udp { host, port } | Self::Http { host, port, .. } => {
                (host, *port)
            }
        };
        if let Ok(address) = host.parse() {
            return Ok(SocketAddr::new(address, port));
        }
        if let Some(address) = resolver
            .bootstrap_resolution
            .first()
            .and_then(|value| value.trim_matches(['[', ']']).parse().ok())
        {
            return Ok(SocketAddr::new(address, port));
        }
        tokio::net::lookup_host((host.as_str(), port))
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Tailscale DNS resolver {host:?} has no addresses"),
                )
            })
    }
}

struct PlainHttpTransport {
    tag: String,
    server: SocksAddr,
    dialer: Arc<dyn Dialer>,
    uri: String,
    authority: String,
}

impl Transport for PlainHttpTransport {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn exchange<'a>(&'a self, message: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let original_id = message.metadata.id;
            let mut wire = message.clone();
            wire.metadata.id = 0;
            let mut payload = Vec::new();
            wire.emit(&mut BinEncoder::new(&mut payload))
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    )
                })?;
            let stream = self.dialer.dial_tcp(&self.server).await?;
            let (mut sender, connection) =
                http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
            tokio::spawn(connection);
            let request = Request::post(&self.uri)
                .header(HOST, &self.authority)
                .header(CONTENT_TYPE, "application/dns-message")
                .header(ACCEPT, "application/dns-message")
                .body(Full::new(Bytes::from(payload)))
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        error.to_string(),
                    )
                })?;
            let response = sender
                .send_request(request)
                .await
                .map_err(io::Error::other)?;
            if response.status() != StatusCode::OK {
                return Err(io::Error::other(format!(
                    "unexpected Tailscale DNS over HTTP status: {}",
                    response.status()
                )));
            }
            let bytes = response
                .into_body()
                .collect()
                .await
                .map_err(io::Error::other)?
                .to_bytes();
            let mut response = Message::read(&mut BinDecoder::new(&bytes))
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    )
                })?;
            response.metadata.id = original_id;
            Ok(response)
        })
    }
}

fn host_response(request: &Message, addresses: Vec<IpAddr>) -> Message {
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.queries = request.queries.clone();
    let Some(query) = request.queries.first() else {
        return response;
    };
    for address in addresses {
        let data = match (query.query_type(), address) {
            (RecordType::A, IpAddr::V4(address)) => Some(RData::A(A(address))),
            (RecordType::AAAA, IpAddr::V6(address)) => {
                Some(RData::AAAA(AAAA(address)))
            }
            _ => None,
        };
        if let Some(data) = data {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                constant::DEFAULT_DNS_TTL,
                data,
            ));
        }
    }
    response
}

fn status_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.queries = request.queries.clone();
    response.metadata.response_code = code;
    response
}

fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_matches('.').to_ascii_lowercase()
}

fn domain_matches(domain: &str, suffix: &str) -> bool {
    let domain = canonical_domain(domain);
    let suffix = canonical_domain(suffix);
    suffix.is_empty()
        || domain == suffix
        || domain
            .strip_suffix(&suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn url_authority(url: &url::Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) if host.contains(':') => {
            format!("[{host}]:{port}")
        }
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        _ => String::new(),
    }
}

fn selected_exit_node<'a>(
    netmap: &'a TailscaleNetmapState,
    selected: &str,
) -> Option<&'a TailscaleNode> {
    let selected_name = canonical_domain(selected);
    netmap.peers.values().find(|peer| {
        peer.stable_id == selected
            || canonical_domain(&peer.name) == selected_name
            || peer.addresses.iter().any(|address| {
                address
                    .parse::<ipnet::IpNet>()
                    .is_ok_and(|prefix| prefix.addr().to_string() == selected)
            })
    })
}

fn exit_node_dns_proxy_url(
    netmap: &TailscaleNetmapState,
    peer: &TailscaleNode,
) -> Option<String> {
    let supports_proxy = peer.capability_version >= 26
        || peer.hostinfo.as_ref().is_some_and(|hostinfo| {
            hostinfo.services.iter().any(|service| {
                service.protocol == "peerapi-dns-proxy" && service.port > 0
            })
        });
    if !supports_proxy {
        return None;
    }
    let self_has_v4 = netmap.node.as_ref().is_some_and(|node| {
        node.addresses.iter().any(|address| {
            address
                .parse::<ipnet::IpNet>()
                .is_ok_and(|prefix| prefix.addr().is_ipv4())
        })
    });
    let self_has_v6 = netmap.node.as_ref().is_some_and(|node| {
        node.addresses.iter().any(|address| {
            address
                .parse::<ipnet::IpNet>()
                .is_ok_and(|prefix| prefix.addr().is_ipv6())
        })
    });
    let hostinfo = peer.hostinfo.as_ref()?;
    let port_for = |protocol: &str| {
        hostinfo
            .services
            .iter()
            .find(|service| service.protocol == protocol && service.port > 0)
            .map(|service| service.port)
    };
    let address_for = |ipv4: bool| {
        peer.addresses.iter().find_map(|address| {
            address
                .parse::<ipnet::IpNet>()
                .ok()
                .map(|prefix| prefix.addr())
                .filter(|address| address.is_ipv4() == ipv4)
        })
    };
    let socket = if self_has_v4 {
        address_for(true)
            .zip(port_for("peerapi4"))
            .map(|(address, port)| SocketAddr::new(address, port))
    } else {
        None
    }
    .or_else(|| {
        self_has_v6
            .then(|| address_for(false).zip(port_for("peerapi6")))
            .flatten()
            .map(|(address, port)| SocketAddr::new(address, port))
    })?;
    Some(format!("http://{socket}/dns-query"))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;
    use crate::adapter::{PacketConnection, Stream};
    use crate::protocol::tailscale_control_types::{
        TailscaleDnsRecord, TailscaleHostinfo, TailscaleNode, TailscaleService,
    };

    struct StaticProvider(Arc<TailscaleNetmapState>);

    impl TailscaleNetmapProvider for StaticProvider {
        fn netmap(&self) -> Option<Arc<TailscaleNetmapState>> {
            Some(self.0.clone())
        }
    }

    struct ExitProvider {
        netmap: Arc<TailscaleNetmapState>,
        exit_node: String,
    }

    impl TailscaleNetmapProvider for ExitProvider {
        fn netmap(&self) -> Option<Arc<TailscaleNetmapState>> {
            Some(self.netmap.clone())
        }

        fn exit_node(&self) -> Option<String> {
            Some(self.exit_node.clone())
        }
    }

    #[derive(Clone, Default)]
    struct MockDnsDialer;

    impl Dialer for MockDnsDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(16 * 1024);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |request: Request<hyper::body::Incoming>| async move {
                            let bytes = request
                                .into_body()
                                .collect()
                                .await
                                .unwrap()
                                .to_bytes();
                            let response = dns_answer(&bytes);
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::new(Full::new(Bytes::from(
                                    response,
                                ))),
                            )
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(server), service)
                        .await;
                });
                Ok(Box::new(client) as Stream)
            })
        }

        fn listen_udp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, PacketStream> {
            Box::pin(async move {
                Ok(Box::new(MockDnsPacket::default()) as PacketStream)
            })
        }

        fn preferred_address(&self, _address: IpAddr) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct MockDnsPacket {
        response: StdMutex<Vec<u8>>,
    }

    impl PacketConnection for MockDnsPacket {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                *self.response.lock().unwrap() = dns_answer(data);
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let response = self.response.lock().unwrap().clone();
                data[..response.len()].copy_from_slice(&response);
                Ok((response.len(), SocksAddr::new("100.100.100.100", 53)))
            })
        }
    }

    fn dns_answer(request: &[u8]) -> Vec<u8> {
        let request = Message::read(&mut BinDecoder::new(request)).unwrap();
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.queries = request.queries.clone();
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            60,
            RData::A(A("100.64.0.42".parse().unwrap())),
        ));
        let mut output = Vec::new();
        response.emit(&mut BinEncoder::new(&mut output)).unwrap();
        output
    }

    fn netmap() -> TailscaleNetmapState {
        TailscaleNetmapState {
            node: Some(TailscaleNode {
                name: "local.tailnet.ts.net.".into(),
                addresses: vec!["100.64.0.1/32".into()],
                ..Default::default()
            }),
            dns_config: Some(TailscaleDnsConfig {
                routes: [("corp.example.".into(), Vec::new())].into(),
                domains: vec!["tailnet.ts.net.".into()],
                proxied: true,
                extra_records: vec![TailscaleDnsRecord {
                    name: "service.corp.example.".into(),
                    record_type: "A".into(),
                    value: "100.64.0.9".into(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn routes_hosts_magic_dns_and_search_domains_match_upstream_policy() {
        let resolver = TailscaleResolver::new(
            "ts-dns",
            "ts",
            true,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
        );
        let netmap = netmap();
        assert_eq!(
            resolver.host_addresses(&netmap, "service.corp.example"),
            Some(vec!["100.64.0.9".parse().unwrap()])
        );
        assert_eq!(
            resolver.host_addresses(&netmap, "sub.local.tailnet.ts.net"),
            Some(vec!["100.64.0.1".parse().unwrap()])
        );
        assert!(resolver.preferred_domain_in(&netmap, "a.corp.example"));
        assert!(
            resolver.preferred_domain_in(&netmap, "missing.tailnet.ts.net")
        );
        assert!(resolver.preferred_domain_in(&netmap, "printer"));
        assert_eq!(
            resolver
                .search_names(netmap.dns_config.as_ref().unwrap(), "printer"),
            ["printer.tailnet.ts.net"]
        );
        assert!(
            resolver
                .matching_resolvers(
                    netmap.dns_config.as_ref().unwrap(),
                    "missing.tailnet.ts.net",
                    false,
                )
                .is_some_and(<[_]>::is_empty)
        );

        let fallback_only = TailscaleDnsConfig {
            fallback_resolvers: vec![TailscaleDnsResolver {
                address: "8.8.8.8".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            resolver
                .matching_resolvers(&fallback_only, "public.example", true)
                .is_none()
        );
    }

    #[test]
    fn parses_udp_http_and_https_resolver_addresses() {
        assert!(matches!(
            ParsedResolver::parse("100.100.100.100").unwrap(),
            ParsedResolver::Udp { port: 53, .. }
        ));
        assert!(matches!(
            ParsedResolver::parse("http://100.100.100.100/dns-query").unwrap(),
            ParsedResolver::Http {
                secure: false,
                port: 80,
                ..
            }
        ));
        assert!(matches!(
            ParsedResolver::parse("https://dns.example:8443/query").unwrap(),
            ParsedResolver::Http {
                secure: true,
                port: 8443,
                ..
            }
        ));
    }

    #[test]
    fn exit_node_dns_policy_filters_marked_resolvers_and_preserves_empty_routes()
     {
        let marked = TailscaleDnsResolver {
            address: "9.9.9.9".into(),
            use_with_exit_node: true,
            ..Default::default()
        };
        let ordinary = TailscaleDnsResolver {
            address: "8.8.8.8".into(),
            ..Default::default()
        };
        let mut netmap = netmap();
        netmap.peers.insert(
            7,
            TailscaleNode {
                stable_id: "exit-7".into(),
                capability_version: 26,
                addresses: vec!["100.64.0.7/32".into()],
                hostinfo: Some(TailscaleHostinfo {
                    services: vec![
                        TailscaleService {
                            protocol: "peerapi4".into(),
                            port: 444,
                            ..Default::default()
                        },
                        TailscaleService {
                            protocol: "peerapi-dns-proxy".into(),
                            port: 1,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let config = netmap.dns_config.as_mut().unwrap();
        config.resolvers = vec![ordinary.clone(), marked.clone()];
        config.routes = [
            ("empty.example.".into(), Vec::new()),
            ("drop.example.".into(), vec![ordinary]),
            ("keep.example.".into(), vec![marked.clone()]),
        ]
        .into();
        let resolver = TailscaleResolver::new(
            "ts-dns",
            "ts",
            true,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
        );
        resolver
            .bind(
                Arc::new(MockDnsDialer),
                Arc::new(ExitProvider {
                    netmap: Arc::new(netmap.clone()),
                    exit_node: "exit-7".into(),
                }),
            )
            .unwrap();
        let endpoint = resolver.bound().unwrap();
        let effective = resolver.effective_config(&endpoint, &netmap).unwrap();
        assert_eq!(effective.resolvers, std::slice::from_ref(&marked));
        assert!(effective.routes.contains_key("empty.example."));
        assert!(!effective.routes.contains_key("drop.example."));
        assert_eq!(effective.routes["keep.example."], [marked]);
    }

    #[test]
    fn exit_node_dns_policy_synthesizes_peer_doh_and_uses_wireguard_resolvers()
    {
        let mut proxy_netmap = netmap();
        proxy_netmap.peers.insert(
            7,
            TailscaleNode {
                stable_id: "exit-7".into(),
                capability_version: 26,
                addresses: vec!["100.64.0.7/32".into()],
                hostinfo: Some(TailscaleHostinfo {
                    services: vec![TailscaleService {
                        protocol: "peerapi4".into(),
                        port: 444,
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let resolver = TailscaleResolver::new(
            "ts-dns",
            "ts",
            true,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
        );
        resolver
            .bind(
                Arc::new(MockDnsDialer),
                Arc::new(ExitProvider {
                    netmap: Arc::new(proxy_netmap.clone()),
                    exit_node: "exit-7".into(),
                }),
            )
            .unwrap();
        let endpoint = resolver.bound().unwrap();
        let effective =
            resolver.effective_config(&endpoint, &proxy_netmap).unwrap();
        assert_eq!(
            effective.resolvers[0].address,
            "http://100.64.0.7:444/dns-query"
        );

        let wireguard_resolver = TailscaleDnsResolver {
            address: "1.1.1.1".into(),
            ..Default::default()
        };
        let mut wireguard_netmap = netmap();
        wireguard_netmap.peers.insert(
            8,
            TailscaleNode {
                stable_id: "wg-exit".into(),
                is_wireguard_only: true,
                exit_node_dns_resolvers: vec![wireguard_resolver.clone()],
                ..Default::default()
            },
        );
        let provider = ExitProvider {
            netmap: Arc::new(wireguard_netmap.clone()),
            exit_node: "wg-exit".into(),
        };
        let endpoint = BoundEndpoint {
            dialer: Arc::new(MockDnsDialer),
            provider: Arc::new(provider),
            fallback: Arc::new(MockDnsDialer),
        };
        let effective = resolver
            .effective_config(&endpoint, &wireguard_netmap)
            .unwrap();
        assert_eq!(effective.resolvers, [wireguard_resolver]);
    }

    #[test]
    fn hosts_exchange_preserves_question_and_filters_address_family() {
        let request_name = Name::from_ascii("service.corp.example.").unwrap();
        let mut request = Message::query();
        request.metadata.id = 7;
        request.add_query(Query::query(request_name.clone(), RecordType::A));
        let response = host_response(
            &request,
            vec![
                "100.64.0.9".parse().unwrap(),
                "fd7a:115c:a1e0::9".parse().unwrap(),
            ],
        );
        assert_eq!(response.metadata.id, 7);
        assert_eq!(response.queries, request.queries);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].name, request_name);
        assert_eq!(response.answers[0].ttl, constant::DEFAULT_DNS_TTL);
    }

    #[tokio::test]
    async fn bound_resolver_answers_live_extra_records_without_network() {
        let resolver = TailscaleResolver::new(
            "ts-dns",
            "ts",
            true,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
        );
        resolver
            .bind(
                Arc::new(DirectOutbound::new(Default::default())),
                Arc::new(StaticProvider(Arc::new(netmap()))),
            )
            .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("service.corp.example.").unwrap(),
            RecordType::A,
        ));
        let response = resolver.exchange(&request).await.unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert!(resolver.preferred_domain("a.corp.example"));
    }

    #[tokio::test]
    async fn udp_and_plain_http_upstreams_exchange_dns_wire_without_os_sockets()
    {
        for address in ["100.100.100.100", "http://100.100.100.100/dns-query"] {
            let mut netmap = netmap();
            netmap.dns_config.as_mut().unwrap().routes.insert(
                "wire.example.".into(),
                vec![TailscaleDnsResolver {
                    address: address.into(),
                    ..Default::default()
                }],
            );
            let resolver = TailscaleResolver::new(
                format!("ts-dns-{address}"),
                "ts",
                true,
                false,
                Arc::new(Client::new(Default::default())),
                DomainStrategy::AsIs,
                None,
            );
            resolver
                .bind(
                    Arc::new(MockDnsDialer),
                    Arc::new(StaticProvider(Arc::new(netmap))),
                )
                .unwrap();
            let addresses = resolver
                .lookup("host.wire.example", DomainStrategy::Ipv4Only)
                .await
                .unwrap();
            assert_eq!(addresses, ["100.64.0.42".parse::<IpAddr>().unwrap()]);
        }
    }
}
