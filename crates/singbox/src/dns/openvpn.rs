//! DNS resolver driven by a live OpenVPN client tunnel configuration.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
};

use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};

use crate::{
    adapter::Dialer,
    common::{
        certificate_store::CertificateStore, ntp::NtpClock,
        tls::build_client_config,
    },
    dns::{
        LookupFuture, LookupOptions, MessageFuture, Resolver, apply_strategy,
        client::Client,
        manager::SharedResolver,
        transport::{
            HttpsTransport, RemoteResolver, TlsTransport, UdpTransport,
        },
    },
    endpoint::openvpn::OpenVpnClientEndpointHandle,
    option::{DomainStrategy, Listable, OutboundTlsOptions},
    protocol::openvpn::{TunnelConfiguration, TunnelDnsServer},
};

pub trait OpenVpnConfigurationProvider: Send + Sync {
    fn tunnel_configuration(&self) -> Option<TunnelConfiguration>;
}

impl OpenVpnConfigurationProvider for OpenVpnClientEndpointHandle {
    fn tunnel_configuration(&self) -> Option<TunnelConfiguration> {
        OpenVpnClientEndpointHandle::tunnel_configuration(self)
    }
}

#[derive(Clone)]
struct BoundEndpoint {
    dialer: Arc<dyn Dialer>,
    configuration: Arc<dyn OpenVpnConfigurationProvider>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ResolverSpec {
    Plain(SocketAddr),
    Tls {
        address: SocketAddr,
        server_name: String,
    },
    Https {
        address: SocketAddr,
        server_name: String,
    },
}

#[derive(Debug, Default)]
struct ResolverPlan {
    routes: Vec<(String, Vec<ResolverSpec>)>,
    search_domains: Vec<String>,
    default_resolvers: Vec<ResolverSpec>,
}

pub struct OpenVpnResolver {
    tag: String,
    endpoint_tag: String,
    accept_default_resolvers: bool,
    accept_search_domain: bool,
    endpoint: RwLock<Option<BoundEndpoint>>,
    configuration: Mutex<Option<TunnelConfiguration>>,
    resolvers: Mutex<HashMap<ResolverSpec, SharedResolver>>,
    client: Arc<Client>,
    default_strategy: DomainStrategy,
    client_subnet: Option<ipnet::IpNet>,
    certificate_store: Option<CertificateStore>,
    ntp_clock: Option<NtpClock>,
}

impl OpenVpnResolver {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
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
            configuration: Mutex::new(None),
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
        self.endpoint
            .read()
            .is_ok_and(|endpoint| endpoint.is_some())
    }

    pub fn bind(
        &self,
        dialer: Arc<dyn Dialer>,
        configuration: Arc<dyn OpenVpnConfigurationProvider>,
    ) -> io::Result<()> {
        let mut endpoint = self.endpoint.write().map_err(|_| {
            io::Error::other("OpenVPN DNS endpoint lock poisoned")
        })?;
        if endpoint.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("OpenVPN DNS server {:?} is already bound", self.tag),
            ));
        }
        *endpoint = Some(BoundEndpoint {
            dialer,
            configuration,
        });
        Ok(())
    }

    fn bound(&self) -> io::Result<BoundEndpoint> {
        self.endpoint
            .read()
            .map_err(|_| {
                io::Error::other("OpenVPN DNS endpoint lock poisoned")
            })?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "OpenVPN DNS endpoint {:?} is not available",
                        self.endpoint_tag
                    ),
                )
            })
    }

    fn plan(configuration: &TunnelConfiguration) -> io::Result<ResolverPlan> {
        let search_domains = normalize_domains(&configuration.search_domains);
        let mut plan = ResolverPlan {
            search_domains,
            ..Default::default()
        };
        let selected = if configuration.dns_servers.is_empty() {
            configuration
                .dns
                .iter()
                .copied()
                .map(|address| {
                    ResolverSpec::Plain(SocketAddr::new(address, 53))
                })
                .collect::<Vec<_>>()
        } else {
            let mut servers = configuration.dns_servers.clone();
            servers.sort_by_key(|server| server.priority);
            let server = &servers[0];
            if server.dnssec == "yes" {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "OpenVPN DNSSEC validation is required but is not supported",
                ));
            }
            let selected = server
                .addresses
                .iter()
                .copied()
                .map(|address| resolver_spec(server, address))
                .collect::<io::Result<Vec<_>>>()?;
            if selected.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "OpenVPN DNS server {} has no addresses",
                        server.priority
                    ),
                ));
            }
            for domain in &server.resolve_domains {
                let domain = normalize_domain(domain);
                if !domain.is_empty() {
                    plan.routes.push((domain, selected.clone()));
                }
            }
            selected
        };

        if configuration.dns_servers.is_empty() {
            if configuration.dns_routes.is_empty() {
                plan.default_resolvers = selected.clone();
            } else {
                if selected.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "OpenVPN DOMAIN-ROUTE requires traditional pushed DNS servers",
                    ));
                }
                for domain in &configuration.dns_routes {
                    let domain = normalize_domain(domain);
                    if !domain.is_empty() {
                        plan.routes.push((domain, selected.clone()));
                    }
                }
            }
        } else if configuration
            .dns_servers
            .iter()
            .min_by_key(|server| server.priority)
            .is_some_and(|server| server.resolve_domains.is_empty())
        {
            plan.default_resolvers = selected.clone();
        }

        if !plan.search_domains.is_empty() && selected.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OpenVPN search domains require pushed DNS servers",
            ));
        }
        for domain in &plan.search_domains {
            plan.routes.push((domain.clone(), selected.clone()));
        }
        Ok(plan)
    }

    fn search_names(&self, plan: &ResolverPlan, domain: &str) -> Vec<String> {
        let canonical = canonical_domain(domain);
        let mut names = Vec::new();
        if self.accept_search_domain && !canonical.contains('.') {
            for suffix in &plan.search_domains {
                names.push(format!("{canonical}.{suffix}"));
            }
        }
        names.push(canonical);
        names
    }

    fn matching_resolvers(
        &self,
        plan: &ResolverPlan,
        domain: &str,
        allow_default: bool,
    ) -> Vec<ResolverSpec> {
        plan.routes
            .iter()
            .filter(|(suffix, _)| domain_matches(suffix, domain))
            .max_by_key(|(suffix, _)| suffix.len())
            .map(|(_, resolvers)| resolvers.clone())
            .or_else(|| {
                (allow_default && self.accept_default_resolvers)
                    .then(|| plan.default_resolvers.clone())
            })
            .unwrap_or_default()
    }

    fn prefers_domain(&self, domain: &str) -> bool {
        let Ok(endpoint) = self.bound() else {
            return false;
        };
        let Some(configuration) = endpoint.configuration.tunnel_configuration()
        else {
            return false;
        };
        Self::plan(&configuration).is_ok_and(|plan| {
            let domain = canonical_domain(domain);
            plan.routes
                .iter()
                .any(|(suffix, _)| domain_matches(suffix, &domain))
        })
    }

    fn resolver_for(
        &self,
        endpoint: &BoundEndpoint,
        spec: &ResolverSpec,
    ) -> io::Result<SharedResolver> {
        if let Some(resolver) = self
            .resolvers
            .lock()
            .map_err(|_| io::Error::other("OpenVPN DNS cache lock poisoned"))?
            .get(spec)
            .cloned()
        {
            return Ok(resolver);
        }
        let tag = format!("{}/{}", self.tag, resolver_spec_label(spec));
        let resolver: SharedResolver = match spec {
            ResolverSpec::Plain(address) => {
                Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    UdpTransport::new(
                        tag,
                        (*address).into(),
                        endpoint.dialer.clone(),
                    ),
                    self.client.clone(),
                    self.default_strategy,
                    self.client_subnet,
                ))
            }
            ResolverSpec::Tls {
                address,
                server_name,
            } => {
                let tls = self.tls(server_name, &[])?;
                Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    TlsTransport::new(
                        tag,
                        (*address).into(),
                        endpoint.dialer.clone(),
                        tls,
                    ),
                    self.client.clone(),
                    self.default_strategy,
                    self.client_subnet,
                ))
            }
            ResolverSpec::Https {
                address,
                server_name,
            } => {
                let tls = self.tls(server_name, &["h2", "http/1.1"])?;
                let authority = if address.port() == 443 {
                    if server_name.contains(':') {
                        format!("[{server_name}]")
                    } else {
                        server_name.clone()
                    }
                } else if server_name.contains(':') {
                    format!("[{server_name}]:{}", address.port())
                } else {
                    format!("{server_name}:{}", address.port())
                };
                let uri = format!("https://{authority}/dns-query");
                Arc::new(RemoteResolver::with_client_strategy_and_subnet(
                    HttpsTransport::new(
                        tag,
                        (*address).into(),
                        endpoint.dialer.clone(),
                        tls,
                        uri,
                        Default::default(),
                    ),
                    self.client.clone(),
                    self.default_strategy,
                    self.client_subnet,
                ))
            }
        };
        self.resolvers
            .lock()
            .map_err(|_| io::Error::other("OpenVPN DNS cache lock poisoned"))?
            .insert(spec.clone(), resolver.clone());
        Ok(resolver)
    }

    fn refresh_configuration(
        &self,
        configuration: &TunnelConfiguration,
    ) -> io::Result<()> {
        let mut current = self.configuration.lock().map_err(|_| {
            io::Error::other("OpenVPN DNS configuration lock poisoned")
        })?;
        if current.as_ref() == Some(configuration) {
            return Ok(());
        }
        self.resolvers
            .lock()
            .map_err(|_| io::Error::other("OpenVPN DNS cache lock poisoned"))?
            .clear();
        *current = Some(configuration.clone());
        Ok(())
    }

    async fn lookup_type(
        &self,
        domain: &str,
        record_type: RecordType,
        options: LookupOptions,
    ) -> io::Result<Vec<std::net::IpAddr>> {
        let name = Name::from_ascii(domain).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid OpenVPN DNS name: {error}"),
            )
        })?;
        let mut request = Message::query();
        request.add_query(Query::query(name, record_type));
        let response = self.exchange_with_options(&request, options).await?;
        if response.metadata.response_code != ResponseCode::NoError {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "OpenVPN DNS response code: {}",
                    response.metadata.response_code
                ),
            ));
        }
        Ok(response
            .answers
            .iter()
            .filter_map(|answer| match &answer.data {
                RData::A(address) => Some(std::net::IpAddr::V4(address.0)),
                RData::AAAA(address) => Some(std::net::IpAddr::V6(address.0)),
                _ => None,
            })
            .collect())
    }

    async fn lookup_inner(
        &self,
        domain: &str,
        mut options: LookupOptions,
    ) -> io::Result<Vec<std::net::IpAddr>> {
        if options.strategy == DomainStrategy::AsIs {
            options.strategy = self.default_strategy;
        }
        let mut addresses = match options.strategy {
            DomainStrategy::Ipv4Only => {
                self.lookup_type(domain, RecordType::A, options).await?
            }
            DomainStrategy::Ipv6Only => {
                self.lookup_type(domain, RecordType::AAAA, options).await?
            }
            _ => {
                let (ipv4, ipv6) = tokio::join!(
                    self.lookup_type(domain, RecordType::A, options),
                    self.lookup_type(domain, RecordType::AAAA, options),
                );
                match (ipv4, ipv6) {
                    (Ok(mut ipv4), Ok(ipv6)) => {
                        ipv4.extend(ipv6);
                        ipv4
                    }
                    (Ok(addresses), Err(_)) | (Err(_), Ok(addresses))
                        if !addresses.is_empty() =>
                    {
                        addresses
                    }
                    (Err(ipv4), Err(ipv6)) => {
                        return Err(io::Error::new(
                            ipv4.kind(),
                            format!(
                                "IPv4 OpenVPN DNS lookup failed: {ipv4}; IPv6 OpenVPN DNS lookup failed: {ipv6}"
                            ),
                        ));
                    }
                    (Ok(_), Err(error)) | (Err(error), Ok(_)) => {
                        return Err(error);
                    }
                }
            }
        };
        apply_strategy(&mut addresses, options.strategy);
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "OpenVPN DNS response for {domain:?} has no matching address"
                ),
            ));
        }
        Ok(addresses)
    }

    fn tls(
        &self,
        server_name: &str,
        default_alpn: &[&str],
    ) -> io::Result<crate::common::tls::ClientTlsConfig> {
        let mut options = OutboundTlsOptions {
            enabled: true,
            server_name: server_name.to_owned(),
            alpn: Listable(
                default_alpn.iter().map(|value| (*value).into()).collect(),
            ),
            ..Default::default()
        };
        options.set_runtime_context(
            self.ntp_clock.clone(),
            self.certificate_store.clone(),
        );
        build_client_config(server_name, &options, default_alpn)
            .map_err(|error| io::Error::other(error.to_string()))
    }

    async fn exchange_once(
        &self,
        endpoint: &BoundEndpoint,
        plan: &ResolverPlan,
        request: &Message,
        options: LookupOptions,
        allow_default: bool,
    ) -> io::Result<Message> {
        let [query] = request.queries.as_slice() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OpenVPN DNS exchange requires exactly one question",
            ));
        };
        let resolvers = self.matching_resolvers(
            plan,
            &query.name().to_utf8(),
            allow_default,
        );
        if resolvers.is_empty() {
            return Ok(status_response(request, ResponseCode::NXDomain));
        }
        let mut last_error = None;
        for spec in resolvers {
            match self.resolver_for(endpoint, &spec) {
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
                "missing OpenVPN DNS resolver",
            )
        }))
    }
}

impl Resolver for OpenVpnResolver {
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
        Box::pin(self.lookup_inner(domain, options))
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
                    "OpenVPN DNS exchange requires exactly one question",
                ));
            };
            let endpoint = self.bound()?;
            let configuration = endpoint
                .configuration
                .tunnel_configuration()
                .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "OpenVPN tunnel DNS configuration is not ready",
                )
            })?;
            self.refresh_configuration(&configuration)?;
            let plan = match Self::plan(&configuration) {
                Ok(plan) => plan,
                Err(error) => {
                    tracing::error!(%error, "update OpenVPN DNS resolvers");
                    return Ok(status_response(
                        request,
                        ResponseCode::NXDomain,
                    ));
                }
            };
            let original_name = original_query.name().clone();
            let original_domain = canonical_domain(&original_name.to_utf8());
            let names = self.search_names(&plan, &original_domain);
            let mut last_response = None;
            let mut last_error = None;
            for name in names {
                let expanded_name =
                    Name::from_ascii(&name).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid OpenVPN DNS name: {error}"),
                        )
                    })?;
                let mut expanded = request.clone();
                expanded.queries[0].set_name(expanded_name.clone());
                match self
                    .exchange_once(
                        &endpoint,
                        &plan,
                        &expanded,
                        options,
                        name == original_domain,
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
                    Ok(response) => last_response = Some(response),
                    Err(error) => last_error = Some(error),
                }
            }
            if let Some(response) = last_response {
                Ok(response)
            } else {
                Err(last_error.unwrap_or_else(|| no_resolver(&original_domain)))
            }
        })
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        Some(self.prefers_domain(domain))
    }
}

fn resolver_spec(
    server: &TunnelDnsServer,
    mut address: SocketAddr,
) -> io::Result<ResolverSpec> {
    let transport = if server.transport.is_empty() {
        "plain".to_owned()
    } else {
        server.transport.to_ascii_lowercase()
    };
    let server_name = if server.sni.is_empty() {
        address.ip().to_string()
    } else {
        server.sni.clone()
    };
    match transport.as_str() {
        "plain" => {
            if address.port() == 0 {
                address.set_port(53);
            }
            Ok(ResolverSpec::Plain(address))
        }
        "dot" => {
            if address.port() == 0 {
                address.set_port(853);
            }
            Ok(ResolverSpec::Tls {
                address,
                server_name,
            })
        }
        "doh" => {
            if address.port() == 0 {
                address.set_port(443);
            }
            Ok(ResolverSpec::Https {
                address,
                server_name,
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported OpenVPN DNS transport: {}", server.transport),
        )),
    }
}

fn resolver_spec_label(spec: &ResolverSpec) -> String {
    match spec {
        ResolverSpec::Plain(address) => format!("udp/{address}"),
        ResolverSpec::Tls { address, .. } => format!("dot/{address}"),
        ResolverSpec::Https { address, .. } => format!("doh/{address}"),
    }
}

fn normalize_domain(domain: &str) -> String {
    let normalized = domain.trim().to_ascii_lowercase();
    if normalized == "." {
        return normalized;
    }
    let normalized = normalized.trim_end_matches('.');
    if normalized.is_empty() {
        String::new()
    } else {
        format!("{normalized}.")
    }
}

fn normalize_domains(domains: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for domain in domains {
        let domain = normalize_domain(domain);
        if !domain.is_empty() && domain != "." && !normalized.contains(&domain)
        {
            normalized.push(domain);
        }
    }
    normalized
}

fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_matches(suffix: &str, domain: &str) -> bool {
    let suffix = suffix.trim().to_ascii_lowercase();
    if suffix == "." {
        return true;
    }
    let suffix = suffix.trim_end_matches('.');
    let domain = canonical_domain(domain);
    !suffix.is_empty()
        && (domain == suffix || domain.ends_with(&format!(".{suffix}")))
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

fn no_resolver(domain: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no OpenVPN DNS resolver for {domain:?}"),
    )
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{MessageType, Query},
        rr::{RData, Record, RecordType, rdata::A},
        serialize::binary::{
            BinDecodable, BinDecoder, BinEncodable, BinEncoder,
        },
    };

    use super::*;
    use crate::{
        option::DirectOutboundOptions, protocol::direct::DirectOutbound,
    };

    struct StaticProvider(TunnelConfiguration);

    impl OpenVpnConfigurationProvider for StaticProvider {
        fn tunnel_configuration(&self) -> Option<TunnelConfiguration> {
            Some(self.0.clone())
        }
    }

    fn modern_configuration() -> TunnelConfiguration {
        TunnelConfiguration {
            dns_servers: vec![
                TunnelDnsServer {
                    priority: 20,
                    addresses: vec!["10.0.0.20:0".parse().unwrap()],
                    resolve_domains: vec!["ignored.example".into()],
                    dnssec: String::new(),
                    transport: String::new(),
                    sni: String::new(),
                },
                TunnelDnsServer {
                    priority: 10,
                    addresses: vec!["10.0.0.10:0".parse().unwrap()],
                    resolve_domains: vec!["corp.example".into()],
                    dnssec: String::new(),
                    transport: "plain".into(),
                    sni: String::new(),
                },
            ],
            search_domains: vec!["search.example".into()],
            ..Default::default()
        }
    }

    #[test]
    fn lowest_priority_modern_server_drives_routes_and_searches() {
        let plan = OpenVpnResolver::plan(&modern_configuration()).unwrap();
        assert!(plan.default_resolvers.is_empty());
        assert_eq!(plan.search_domains, ["search.example."]);
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.routes[0].0, "corp.example.");
        assert_eq!(
            plan.routes[0].1,
            [ResolverSpec::Plain("10.0.0.10:53".parse().unwrap())]
        );
    }

    #[test]
    fn longest_route_and_default_acceptance_match_upstream() {
        let resolver = OpenVpnResolver::new(
            "vpn-dns",
            "vpn",
            true,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
            None,
            None,
        );
        let mut plan = ResolverPlan {
            default_resolvers: vec![ResolverSpec::Plain(
                "1.1.1.1:53".parse().unwrap(),
            )],
            ..Default::default()
        };
        let broad = ResolverSpec::Plain("10.0.0.1:53".parse().unwrap());
        let narrow = ResolverSpec::Plain("10.0.0.2:53".parse().unwrap());
        plan.routes.push(("example.".into(), vec![broad]));
        plan.routes
            .push(("corp.example.".into(), vec![narrow.clone()]));
        assert_eq!(
            resolver.matching_resolvers(&plan, "a.corp.example", true),
            [narrow]
        );
        assert_eq!(
            resolver.matching_resolvers(&plan, "public.test", true),
            plan.default_resolvers
        );
        assert!(
            resolver
                .matching_resolvers(&plan, "public.test", false)
                .is_empty()
        );
    }

    #[test]
    fn modern_transport_ports_dnssec_and_search_normalization_are_exact() {
        let server = TunnelDnsServer {
            priority: 1,
            addresses: Vec::new(),
            resolve_domains: Vec::new(),
            dnssec: String::new(),
            transport: "DoH".into(),
            sni: "resolver.example".into(),
        };
        assert_eq!(
            resolver_spec(&server, "[2001:db8::1]:0".parse().unwrap()).unwrap(),
            ResolverSpec::Https {
                address: "[2001:db8::1]:443".parse().unwrap(),
                server_name: "resolver.example".into(),
            }
        );
        assert_eq!(
            normalize_domains(&[
                " Corp.Example. ".into(),
                "corp.example".into(),
                ".".into(),
            ]),
            ["corp.example."]
        );
        let mut configuration = modern_configuration();
        configuration.dns_servers[1].dnssec = "yes".into();
        assert_eq!(
            OpenVpnResolver::plan(&configuration).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let mut configuration = modern_configuration();
        configuration.dns_servers[1].resolve_domains = vec!["  ".into()];
        let plan = OpenVpnResolver::plan(&configuration).unwrap();
        assert!(plan.routes.iter().all(|(domain, _)| !domain.is_empty()));
        assert!(plan.default_resolvers.is_empty());
    }

    #[tokio::test]
    async fn raw_udp_search_exchange_restores_original_question_and_owner() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0_u8; 4096];
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request =
                Message::read(&mut BinDecoder::new(&bytes[..size])).unwrap();
            assert_eq!(request.queries[0].name().to_utf8(), "printer.corp.");
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                request.metadata.op_code,
            );
            response.queries = request.queries.clone();
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A("192.0.2.44".parse().unwrap())),
            ));
            let mut response_bytes = Vec::new();
            response
                .emit(&mut BinEncoder::new(&mut response_bytes))
                .unwrap();
            socket.send_to(&response_bytes, peer).await.unwrap();
        });

        let resolver = OpenVpnResolver::new(
            "vpn-dns",
            "vpn",
            false,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
            None,
            None,
        );
        resolver
            .bind(
                Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
                Arc::new(StaticProvider(TunnelConfiguration {
                    dns_servers: vec![TunnelDnsServer {
                        priority: 1,
                        addresses: vec![server_address],
                        resolve_domains: Vec::new(),
                        dnssec: String::new(),
                        transport: "plain".into(),
                        sni: String::new(),
                    }],
                    search_domains: vec!["corp".into()],
                    ..Default::default()
                })),
            )
            .unwrap();
        let original = Name::from_ascii("printer.").unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(original.clone(), RecordType::A));
        let response = resolver.exchange(&request).await.unwrap();
        assert_eq!(response.queries[0].name(), &original);
        assert_eq!(response.answers[0].name, original);
        assert_eq!(
            response.answers[0].data,
            RData::A(A("192.0.2.44".parse().unwrap()))
        );
        server.await.unwrap();
    }
}
