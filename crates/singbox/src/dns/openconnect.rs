//! DNS resolver driven by a live OpenConnect tunnel configuration.

use std::{
    io,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};

use crate::{
    adapter::Dialer,
    common::network::SocksAddr,
    dns::{
        LookupFuture, LookupOptions, MessageFuture, Resolver, apply_strategy,
        client::Client,
        transport::{RemoteResolver, UdpTransport},
    },
    option::DomainStrategy,
    protocol::openconnect::TunnelConfiguration,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResolverPlan {
    routes: Vec<(String, Vec<IpAddr>)>,
    search_domains: Vec<String>,
    default_servers: Vec<IpAddr>,
}

pub trait OpenConnectConfigurationProvider: Send + Sync {
    fn tunnel_configuration(&self) -> Option<TunnelConfiguration>;
}

#[derive(Clone)]
struct BoundEndpoint {
    dialer: Arc<dyn Dialer>,
    configuration: Arc<dyn OpenConnectConfigurationProvider>,
}

pub struct OpenConnectResolver {
    tag: String,
    endpoint_tag: String,
    accept_default_resolvers: bool,
    accept_search_domain: bool,
    endpoint: RwLock<Option<BoundEndpoint>>,
    client: Arc<Client>,
    default_strategy: DomainStrategy,
    client_subnet: Option<ipnet::IpNet>,
}

impl OpenConnectResolver {
    pub fn new(
        tag: impl Into<String>,
        endpoint_tag: impl Into<String>,
        accept_default_resolvers: bool,
        accept_search_domain: bool,
        client: Arc<Client>,
        default_strategy: DomainStrategy,
        client_subnet: Option<ipnet::IpNet>,
    ) -> Self {
        Self {
            tag: tag.into(),
            endpoint_tag: endpoint_tag.into(),
            accept_default_resolvers,
            accept_search_domain,
            endpoint: RwLock::new(None),
            client,
            default_strategy,
            client_subnet,
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
        configuration: Arc<dyn OpenConnectConfigurationProvider>,
    ) -> io::Result<()> {
        let mut endpoint = self.endpoint.write().map_err(|_| {
            io::Error::other("OpenConnect DNS endpoint lock poisoned")
        })?;
        if endpoint.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "OpenConnect DNS server {:?} is already bound",
                    self.tag
                ),
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
                io::Error::other("OpenConnect DNS endpoint lock poisoned")
            })?
            .clone()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "OpenConnect DNS endpoint {:?} is not available",
                        self.endpoint_tag
                    ),
                )
            })
    }

    fn plan(&self, configuration: &TunnelConfiguration) -> ResolverPlan {
        let default_servers = unique_addresses(&configuration.dns);
        let mut routes: Vec<(String, Vec<IpAddr>)> = Vec::new();
        for rule in &configuration.split_dns_rules {
            let servers = unique_addresses(&rule.servers);
            for domain in &rule.domains {
                let domain = canonical_domain(domain);
                if domain.is_empty() {
                    continue;
                }
                if let Some((_, existing)) =
                    routes.iter_mut().find(|(route, _)| route == &domain)
                {
                    for server in &servers {
                        if !existing.contains(server) {
                            existing.push(*server);
                        }
                    }
                } else {
                    routes.push((domain, servers.clone()));
                }
            }
        }
        for domain in configuration
            .split_dns
            .iter()
            .chain(&configuration.search_domains)
        {
            let domain = canonical_domain(domain);
            if !domain.is_empty()
                && !routes.iter().any(|(route, _)| route == &domain)
            {
                routes.push((domain, default_servers.clone()));
            }
        }
        let search_domains = configuration
            .search_domains
            .iter()
            .map(|domain| canonical_domain(domain))
            .filter(|domain| !domain.is_empty())
            .fold(Vec::new(), |mut domains, domain| {
                if !domains.contains(&domain) {
                    domains.push(domain);
                }
                domains
            });
        let default_servers = if self.accept_default_resolvers
            && (configuration.tunnel_all_dns
                || (configuration.split_dns.is_empty()
                    && configuration.split_dns_rules.is_empty()))
        {
            default_servers
        } else {
            Vec::new()
        };
        ResolverPlan {
            routes,
            search_domains,
            default_servers,
        }
    }

    fn servers_for_domain(
        &self,
        plan: &ResolverPlan,
        domain: &str,
    ) -> Vec<IpAddr> {
        plan.routes
            .iter()
            .filter(|(suffix, _)| domain_matches(domain, suffix))
            .max_by_key(|(suffix, _)| suffix.len())
            .map(|(_, servers)| servers.clone())
            .unwrap_or_else(|| plan.default_servers.clone())
    }

    fn search_names(&self, plan: &ResolverPlan, domain: &str) -> Vec<String> {
        let canonical = canonical_domain(domain);
        let mut names = Vec::new();
        if self.accept_search_domain && !canonical.contains('.') {
            for suffix in &plan.search_domains {
                names.push(format!("{canonical}.{suffix}."));
            }
        }
        names.push(canonical);
        names
    }

    fn prefers_domain(&self, domain: &str) -> bool {
        let Ok(endpoint) = self.bound() else {
            return false;
        };
        let Some(configuration) = endpoint.configuration.tunnel_configuration()
        else {
            return false;
        };
        let domain = canonical_domain(domain);
        self.plan(&configuration)
            .routes
            .iter()
            .any(|(suffix, _)| domain_matches(&domain, suffix))
    }

    fn resolver_for(
        &self,
        endpoint: &BoundEndpoint,
        server: IpAddr,
    ) -> RemoteResolver {
        RemoteResolver::with_client_strategy_and_subnet(
            UdpTransport::new(
                format!("{}/{}", self.tag, server),
                SocksAddr::new(server.to_string(), 53),
                endpoint.dialer.clone(),
            ),
            self.client.clone(),
            self.default_strategy,
            self.client_subnet,
        )
    }

    async fn lookup_type(
        &self,
        domain: &str,
        record_type: RecordType,
        options: LookupOptions,
    ) -> io::Result<Vec<IpAddr>> {
        let name = Name::from_ascii(domain).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid OpenConnect DNS name: {error}"),
            )
        })?;
        let mut request = Message::query();
        request.add_query(Query::query(name, record_type));
        let response = self.exchange_with_options(&request, options).await?;
        if response.metadata.response_code != ResponseCode::NoError {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "OpenConnect DNS response code: {}",
                    response.metadata.response_code
                ),
            ));
        }
        Ok(response
            .answers
            .iter()
            .filter_map(|answer| match &answer.data {
                RData::A(address) => Some(IpAddr::V4(address.0)),
                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            })
            .collect())
    }

    async fn lookup_inner(
        &self,
        domain: &str,
        mut options: LookupOptions,
    ) -> io::Result<Vec<IpAddr>> {
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
                                "IPv4 OpenConnect DNS lookup failed: {ipv4}; IPv6 OpenConnect DNS lookup failed: {ipv6}"
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
                    "OpenConnect DNS response for {domain:?} has no matching address"
                ),
            ));
        }
        Ok(addresses)
    }

    async fn exchange_once(
        &self,
        endpoint: &BoundEndpoint,
        plan: &ResolverPlan,
        request: &Message,
        options: LookupOptions,
    ) -> io::Result<Message> {
        let [query] = request.queries.as_slice() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OpenConnect DNS exchange requires exactly one question",
            ));
        };
        let domain = query.name().to_utf8();
        let servers = self.servers_for_domain(plan, &domain);
        if servers.is_empty() {
            return Ok(status_response(request, ResponseCode::NXDomain));
        }
        let mut last_error = None;
        for server in servers {
            match self
                .resolver_for(endpoint, server)
                .exchange_with_options(request, options)
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| no_resolver(&domain)))
    }
}

impl Resolver for OpenConnectResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        self.lookup_with_options(
            domain,
            LookupOptions {
                strategy,
                ..LookupOptions::default()
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
                    "OpenConnect DNS exchange requires exactly one question",
                ));
            };
            let endpoint = self.bound()?;
            let configuration = endpoint
                .configuration
                .tunnel_configuration()
                .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "OpenConnect tunnel DNS configuration is not ready",
                )
            })?;
            let original_name = original_query.name().clone();
            let plan = self.plan(&configuration);
            let original_domain = canonical_domain(&original_name.to_utf8());
            let names = self.search_names(&plan, &original_domain);
            let mut last_response = None;
            let mut last_error = None;
            for name in names {
                let expanded_name =
                    Name::from_ascii(&name).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid OpenConnect DNS name: {error}"),
                        )
                    })?;
                let mut expanded = request.clone();
                expanded.queries[0].set_name(expanded_name.clone());
                match self
                    .exchange_once(&endpoint, &plan, &expanded, options)
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

fn unique_addresses(addresses: &[IpAddr]) -> Vec<IpAddr> {
    addresses
        .iter()
        .copied()
        .fold(Vec::new(), |mut result, address| {
            if !result.contains(&address) {
                result.push(address);
            }
            result
        })
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
    !suffix.is_empty()
        && (domain == suffix
            || domain
                .strip_suffix(&suffix)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

fn no_resolver(domain: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no OpenConnect DNS resolver for {domain:?}"),
    )
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex as StdMutex, time::Duration};

    use super::*;
    use crate::{
        adapter::{DialFuture, PacketConnection, PacketFuture, PacketStream},
        protocol::openconnect::{TunnelRoute, TunnelSplitDnsRule},
    };
    use hickory_proto::{
        rr::{Record, rdata::A},
        serialize::binary::{
            BinDecodable, BinDecoder, BinEncodable, BinEncoder,
        },
    };

    struct StaticProvider(TunnelConfiguration);

    impl OpenConnectConfigurationProvider for StaticProvider {
        fn tunnel_configuration(&self) -> Option<TunnelConfiguration> {
            Some(self.0.clone())
        }
    }

    #[derive(Clone, Default)]
    struct MockDnsDialer {
        destinations: Arc<StdMutex<Vec<SocksAddr>>>,
    }

    impl Dialer for MockDnsDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "mock DNS dialer has no TCP transport",
                ))
            })
        }

        fn listen_udp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, PacketStream> {
            let destinations = self.destinations.clone();
            let destination = destination.clone();
            Box::pin(async move {
                destinations.lock().unwrap().push(destination);
                Ok(Box::new(MockDnsPacket::default()) as PacketStream)
            })
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
                Ok((response.len(), SocksAddr::new("10.8.0.54", 53)))
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
            RData::A(A("192.0.2.54".parse().unwrap())),
        ));
        let mut output = Vec::new();
        response.emit(&mut BinEncoder::new(&mut output)).unwrap();
        output
    }

    fn configuration() -> TunnelConfiguration {
        TunnelConfiguration {
            mtu: 1300,
            remote_address: None,
            addresses: vec!["10.8.0.2/24".parse().unwrap()],
            routes: vec![TunnelRoute {
                prefix: "10.0.0.0/8".parse().unwrap(),
                gateway: None,
                metric: 0,
            }],
            excluded_routes: Vec::new(),
            dns: vec!["10.8.0.53".parse().unwrap()],
            nbns: Vec::new(),
            search_domains: vec!["search.example".into()],
            split_dns: vec!["corp.example".into()],
            split_dns_rules: vec![
                TunnelSplitDnsRule {
                    domains: vec!["secure.corp.example".into()],
                    servers: vec!["10.8.0.54".parse().unwrap()],
                },
                TunnelSplitDnsRule {
                    domains: vec!["secure.corp.example".into()],
                    servers: vec![
                        "10.8.0.54".parse().unwrap(),
                        "10.8.0.55".parse().unwrap(),
                    ],
                },
            ],
            proxy_auto_config_url: String::new(),
            banner: String::new(),
            tunnel_all_dns: false,
            client_bypass_protocol: false,
            idle_timeout: Duration::ZERO,
            authentication_expiration: None,
        }
    }

    #[test]
    fn routes_split_domains_and_expands_single_label_searches() {
        let resolver = OpenConnectResolver::new(
            "oc-dns",
            "oc",
            true,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
        );
        let configuration = configuration();
        let plan = resolver.plan(&configuration);
        assert_eq!(
            resolver.servers_for_domain(&plan, "a.corp.example."),
            configuration.dns
        );
        assert_eq!(
            resolver.servers_for_domain(&plan, "host.secure.corp.example."),
            [
                "10.8.0.54".parse::<IpAddr>().unwrap(),
                "10.8.0.55".parse::<IpAddr>().unwrap(),
            ]
        );
        assert!(
            resolver
                .servers_for_domain(&plan, "public.example")
                .is_empty()
        );
        assert_eq!(
            resolver.search_names(&plan, "printer"),
            ["printer.search.example.", "printer"]
        );
        assert_eq!(
            resolver.search_names(&plan, "host.example"),
            ["host.example"]
        );
    }

    #[test]
    fn tunnel_all_dns_and_default_acceptance_follow_upstream_policy() {
        let resolver = OpenConnectResolver::new(
            "oc-dns",
            "oc",
            true,
            false,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
        );
        let mut configuration = configuration();
        configuration.tunnel_all_dns = true;
        let plan = resolver.plan(&configuration);
        assert_eq!(
            resolver.servers_for_domain(&plan, "public.example"),
            configuration.dns
        );
        configuration.tunnel_all_dns = false;
        configuration.split_dns.clear();
        configuration.split_dns_rules.clear();
        let plan = resolver.plan(&configuration);
        assert_eq!(
            resolver.servers_for_domain(&plan, "public.example"),
            configuration.dns
        );
    }

    #[tokio::test]
    async fn split_rule_server_handles_search_exchange_and_restores_owner() {
        let mut configuration = configuration();
        configuration.split_dns.clear();
        configuration.split_dns_rules = vec![TunnelSplitDnsRule {
            domains: vec!["search.example".into()],
            servers: vec!["10.8.0.54".parse().unwrap()],
        }];
        let dialer = MockDnsDialer::default();
        let destinations = dialer.destinations.clone();
        let resolver = OpenConnectResolver::new(
            "oc-dns",
            "oc",
            false,
            true,
            Arc::new(Client::new(Default::default())),
            DomainStrategy::AsIs,
            None,
        );
        resolver
            .bind(Arc::new(dialer), Arc::new(StaticProvider(configuration)))
            .unwrap();

        let original = Name::from_ascii("printer.").unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(original.clone(), RecordType::A));
        let response = resolver.exchange(&request).await.unwrap();
        assert_eq!(response.queries[0].name(), &original);
        assert_eq!(response.answers[0].name, original);
        assert_eq!(
            response.answers[0].data,
            RData::A(A("192.0.2.54".parse().unwrap()))
        );
        assert_eq!(
            destinations.lock().unwrap().as_slice(),
            [SocksAddr::new("10.8.0.54", 53)]
        );
    }
}
