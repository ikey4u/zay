//! DNS wire types and the first native resolver transport.

pub mod client;
pub mod dhcp;
pub mod fakeip;
pub mod local;
#[cfg(target_vendor = "apple")]
mod local_darwin;
#[cfg(target_os = "linux")]
mod local_resolved_linux;
pub mod manager;
pub mod mdns;
pub mod openconnect;
pub mod openvpn;
pub mod persistent;
pub mod rule;
pub mod tailscale;
pub mod transport;

use std::{future::Future, io, net::IpAddr, pin::Pin, time::Duration};

use hickory_proto::op::Message;
pub use hickory_proto::{op, rr, serialize};
use hickory_resolver::TokioResolver;

use crate::option::{DomainResolveOptions, DomainStrategy};

pub type LookupFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;
pub type MessageFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Message>> + Send + 'a>>;

#[derive(Debug, Default, Clone, Copy)]
pub struct LookupOptions {
    pub strategy: DomainStrategy,
    pub timeout: Option<Duration>,
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: Option<ipnet::IpNet>,
    pub remove_client_subnet: bool,
}

pub trait Resolver: Send + Sync {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a>;

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        options: LookupOptions,
    ) -> LookupFuture<'a> {
        self.lookup(domain, options.strategy)
    }

    fn exchange<'a>(&'a self, _request: &'a Message) -> MessageFuture<'a> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "resolver does not expose raw DNS exchange",
            ))
        })
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a Message,
        _options: LookupOptions,
    ) -> MessageFuture<'a> {
        self.exchange(request)
    }

    /// `None` means this resolver does not implement sing-box's
    /// `DNSTransportWithPreferredDomain` contract. Implementations return
    /// `Some(false)` when the contract is supported but the domain is not
    /// preferred.
    fn preferred_domain(&self, _domain: &str) -> Option<bool> {
        None
    }
}

/// Applies one dialer's configured DNS query options to every lookup it
/// performs. This mirrors sing-box's `resolveDialer`, whose bootstrap
/// resolver carries the complete `DNSQueryOptions`, not only its strategy.
pub(crate) struct ConfiguredResolver {
    inner: std::sync::Arc<dyn Resolver>,
    options: LookupOptions,
}

impl ConfiguredResolver {
    pub(crate) fn new(
        inner: std::sync::Arc<dyn Resolver>,
        options: &DomainResolveOptions,
        legacy_strategy: DomainStrategy,
    ) -> Self {
        let strategy = if options.strategy == DomainStrategy::AsIs {
            legacy_strategy
        } else {
            options.strategy
        };
        Self {
            inner,
            options: LookupOptions {
                strategy,
                timeout: options
                    .timeout
                    .as_std()
                    .filter(|timeout| !timeout.is_zero()),
                disable_cache: options.disable_cache,
                disable_optimistic_cache: options.disable_optimistic_cache,
                rewrite_ttl: options.rewrite_ttl,
                client_subnet: options
                    .client_subnet
                    .as_ref()
                    .map(|prefix| prefix.0),
                ..LookupOptions::default()
            },
        }
    }

    pub(crate) fn strategy(&self) -> DomainStrategy {
        self.options.strategy
    }
}

impl Resolver for ConfiguredResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        _strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        self.inner.lookup_with_options(domain, self.options)
    }

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        _options: LookupOptions,
    ) -> LookupFuture<'a> {
        self.inner.lookup_with_options(domain, self.options)
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        self.inner.exchange_with_options(request, self.options)
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a Message,
        _options: LookupOptions,
    ) -> MessageFuture<'a> {
        self.inner.exchange_with_options(request, self.options)
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        self.inner.preferred_domain(domain)
    }
}

impl<T: Resolver + ?Sized> Resolver for std::sync::Arc<T> {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        (**self).lookup(domain, strategy)
    }

    fn lookup_with_options<'a>(
        &'a self,
        domain: &'a str,
        options: LookupOptions,
    ) -> LookupFuture<'a> {
        (**self).lookup_with_options(domain, options)
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        (**self).exchange(request)
    }

    fn exchange_with_options<'a>(
        &'a self,
        request: &'a Message,
        options: LookupOptions,
    ) -> MessageFuture<'a> {
        (**self).exchange_with_options(request, options)
    }

    fn preferred_domain(&self, domain: &str) -> Option<bool> {
        (**self).preferred_domain(domain)
    }
}

/// Resolver backed by the operating system's configured DNS servers through
/// Hickory's native async client. This is the Rust counterpart of the upstream
/// `local` DNS transport, not `getaddrinfo` in a blocking thread.
pub struct SystemResolver {
    inner: TokioResolver,
}

impl SystemResolver {
    pub fn new() -> io::Result<Self> {
        let builder = TokioResolver::builder_tokio()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let inner = builder
            .build()
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self { inner })
    }
}

impl Resolver for SystemResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        Box::pin(async move {
            let response = self
                .inner
                .lookup_ip(domain)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            let mut addresses: Vec<_> = response.iter().collect();
            apply_strategy(&mut addresses, strategy);
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "DNS response for {domain:?} has no matching address"
                    ),
                ));
            }
            Ok(addresses)
        })
    }

    fn exchange<'a>(&'a self, request: &'a Message) -> MessageFuture<'a> {
        Box::pin(async move {
            let [query] = request.queries.as_slice() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "system DNS raw exchange requires exactly one question",
                ));
            };
            let lookup = self
                .inner
                .lookup(query.name().clone(), query.query_type())
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            let mut response = lookup.message().clone();
            response.metadata.id = request.metadata.id;
            response.queries = request.queries.clone();
            Ok(response)
        })
    }
}

pub fn apply_strategy(addresses: &mut Vec<IpAddr>, strategy: DomainStrategy) {
    match strategy {
        DomainStrategy::AsIs => {}
        DomainStrategy::PreferIpv4 => {
            addresses.sort_by_key(|address| u8::from(address.is_ipv6()));
        }
        DomainStrategy::PreferIpv6 => {
            addresses.sort_by_key(|address| u8::from(address.is_ipv4()));
        }
        DomainStrategy::Ipv4Only => addresses.retain(IpAddr::is_ipv4),
        DomainStrategy::Ipv6Only => addresses.retain(IpAddr::is_ipv6),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
        serialize::binary::{
            BinDecodable, BinDecoder, BinEncodable, BinEncoder,
        },
    };

    use super::{
        ConfiguredResolver, LookupFuture, LookupOptions, Resolver,
        apply_strategy,
    };
    use crate::option::{DomainResolveOptions, DomainStrategy};

    struct RecordingResolver {
        options: Arc<Mutex<Option<LookupOptions>>>,
    }

    impl Resolver for RecordingResolver {
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
            _domain: &'a str,
            options: LookupOptions,
        ) -> LookupFuture<'a> {
            *self.options.lock().unwrap() = Some(options);
            Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
        }
    }

    #[test]
    fn strategies_filter_and_stably_prefer_address_families() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut addresses = vec![v6, v4];
        apply_strategy(&mut addresses, DomainStrategy::PreferIpv4);
        assert_eq!(addresses, [v4, v6]);
        apply_strategy(&mut addresses, DomainStrategy::Ipv6Only);
        assert_eq!(addresses, [v6]);
    }

    #[tokio::test]
    async fn configured_resolver_preserves_all_dialer_query_options() {
        let configured: DomainResolveOptions =
            serde_json::from_value(serde_json::json!({
                "server": "bootstrap",
                "timeout": "2s",
                "disable_cache": true,
                "disable_optimistic_cache": true,
                "rewrite_ttl": 17,
                "client_subnet": "192.0.2.0/24"
            }))
            .unwrap();
        let recorded = Arc::new(Mutex::new(None));
        let resolver = ConfiguredResolver::new(
            Arc::new(RecordingResolver {
                options: recorded.clone(),
            }),
            &configured,
            DomainStrategy::Ipv6Only,
        );

        resolver
            .lookup("bootstrap.test", DomainStrategy::PreferIpv4)
            .await
            .unwrap();
        let options = recorded.lock().unwrap().unwrap();
        assert_eq!(options.strategy, DomainStrategy::Ipv6Only);
        assert_eq!(options.timeout, Some(Duration::from_secs(2)));
        assert!(options.disable_cache);
        assert!(options.disable_optimistic_cache);
        assert_eq!(options.rewrite_ttl, Some(17));
        assert_eq!(
            options.client_subnet,
            Some("192.0.2.0/24".parse().unwrap())
        );
    }

    #[test]
    fn hickory_wire_message_round_trips_without_compatibility_wrapper() {
        let mut message =
            Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut bytes = Vec::new();
        message.emit(&mut BinEncoder::new(&mut bytes)).unwrap();
        let decoded = Message::read(&mut BinDecoder::new(&bytes)).unwrap();
        assert_eq!(decoded.id, 0x1234);
        assert_eq!(decoded.queries[0].query_type(), RecordType::A);
    }
}
