//! In-memory fake-IP allocator compatible with sing-box's address rotation.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use ipnet::IpNet;

use crate::{
    dns::{
        LookupFuture, Resolver, apply_strategy,
        persistent::{PersistentDnsCache, PersistentFakeIpMetadata},
    },
    option::DomainStrategy,
};

pub struct FakeIpResolver {
    inet4_range: Option<IpNet>,
    inet6_range: Option<IpNet>,
    persistent_cache: Option<Arc<PersistentDnsCache>>,
    state: Mutex<State>,
}

struct State {
    current4: Option<IpAddr>,
    current6: Option<IpAddr>,
    last4: Option<IpAddr>,
    last6: Option<IpAddr>,
    by_address: HashMap<IpAddr, String>,
    by_domain4: HashMap<String, IpAddr>,
    by_domain6: HashMap<String, IpAddr>,
}

impl FakeIpResolver {
    pub fn new(
        inet4_range: Option<IpNet>,
        inet6_range: Option<IpNet>,
    ) -> io::Result<Self> {
        Self::new_with_cache(inet4_range, inet6_range, None)
    }

    pub fn new_with_cache(
        inet4_range: Option<IpNet>,
        inet6_range: Option<IpNet>,
        persistent_cache: Option<Arc<PersistentDnsCache>>,
    ) -> io::Result<Self> {
        if inet4_range.is_none() && inet6_range.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one of inet4_range or inet6_range must be set",
            ));
        }
        if inet4_range
            .as_ref()
            .is_some_and(|range| !range.addr().is_ipv4())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inet4_range must contain IPv4 addresses",
            ));
        }
        if inet6_range
            .as_ref()
            .is_some_and(|range| !range.addr().is_ipv6())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inet6_range must contain IPv6 addresses",
            ));
        }
        let mut current4 =
            inet4_range.as_ref().and_then(|range| next(range.addr()));
        let mut current6 =
            inet6_range.as_ref().and_then(|range| next(range.addr()));
        let last4 = inet4_range.as_ref().map(broadcast_address);
        let last6 = inet6_range.as_ref().map(broadcast_address);
        if let Some(cache) = &persistent_cache {
            let metadata = cache.load_fakeip_metadata()?;
            if let Some(metadata) = metadata.filter(|metadata| {
                metadata.inet4_range == inet4_range
                    && metadata.inet6_range == inet6_range
                    && valid_current(metadata.current4, inet4_range.as_ref())
                    && valid_current(metadata.current6, inet6_range.as_ref())
            }) {
                current4 = metadata.current4;
                current6 = metadata.current6;
            } else {
                cache.clear_fakeip()?;
                cache.save_fakeip_metadata(&PersistentFakeIpMetadata {
                    inet4_range,
                    inet6_range,
                    current4,
                    current6,
                })?;
            }
        }
        Ok(Self {
            inet4_range,
            inet6_range,
            persistent_cache,
            state: Mutex::new(State {
                current4,
                current6,
                last4,
                last6,
                by_address: HashMap::new(),
                by_domain4: HashMap::new(),
                by_domain6: HashMap::new(),
            }),
        })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        self.inet4_range
            .as_ref()
            .is_some_and(|range| range.contains(&address))
            || self
                .inet6_range
                .as_ref()
                .is_some_and(|range| range.contains(&address))
    }

    pub fn create(&self, domain: &str, ipv6: bool) -> io::Result<IpAddr> {
        let domain = canonical_domain(domain);
        let mut state = self.state.lock().expect("fake-IP mutex poisoned");
        if let Some(address) = if ipv6 {
            state.by_domain6.get(&domain)
        } else {
            state.by_domain4.get(&domain)
        } {
            return Ok(*address);
        }
        if let Some(address) = self
            .persistent_cache
            .as_ref()
            .and_then(|cache| {
                cache.load_fakeip_by_domain(&domain, ipv6).ok().flatten()
            })
            .filter(|address| {
                if ipv6 {
                    self.inet6_range
                        .as_ref()
                        .is_some_and(|range| range.contains(address))
                } else {
                    self.inet4_range
                        .as_ref()
                        .is_some_and(|range| range.contains(address))
                }
            })
        {
            insert_mapping(&mut state, address, domain);
            return Ok(address);
        }
        let (range, current, last) = if ipv6 {
            (self.inet6_range.as_ref(), state.current6, state.last6)
        } else {
            (self.inet4_range.as_ref(), state.current4, state.last4)
        };
        let range = range.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                if ipv6 {
                    "missing IPv6 fakeip address range"
                } else {
                    "missing IPv4 fakeip address range"
                },
            )
        })?;
        let mut address = current.and_then(next).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "fake-IP range exhausted",
            )
        })?;
        if Some(address) == last || !range.contains(&address) {
            address = next(range.addr()).and_then(next).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "fake-IP range has no usable addresses",
                )
            })?;
        }
        if ipv6 {
            state.current6 = Some(address);
        } else {
            state.current4 = Some(address);
        }
        insert_mapping(&mut state, address, domain.clone());
        if let Some(cache) = &self.persistent_cache {
            let _ = cache.save_fakeip(address, &domain);
            let _ = cache.save_fakeip_metadata(&PersistentFakeIpMetadata {
                inet4_range: self.inet4_range,
                inet6_range: self.inet6_range,
                current4: state.current4,
                current6: state.current6,
            });
        }
        Ok(address)
    }

    pub fn lookup_domain(&self, address: IpAddr) -> Option<String> {
        let mut state = self.state.lock().expect("fake-IP mutex poisoned");
        if let Some(domain) = state.by_address.get(&address) {
            return Some(domain.clone());
        }
        let domain = self
            .persistent_cache
            .as_ref()?
            .load_fakeip_by_address(address)
            .ok()??;
        self.contains(address).then(|| {
            insert_mapping(&mut state, address, domain.clone());
            domain
        })
    }

    pub fn reset(&self) {
        let mut state = self.state.lock().expect("fake-IP mutex poisoned");
        state.by_address.clear();
        state.by_domain4.clear();
        state.by_domain6.clear();
        if let Some(cache) = &self.persistent_cache {
            let _ = cache.clear_fakeip();
        }
    }
}

fn valid_current(current: Option<IpAddr>, range: Option<&IpNet>) -> bool {
    match (current, range) {
        (None, None) => true,
        (Some(current), Some(range)) => range.contains(&current),
        _ => false,
    }
}

fn insert_mapping(state: &mut State, address: IpAddr, domain: String) {
    if let Some(old_domain) = state.by_address.insert(address, domain.clone()) {
        if address.is_ipv6() {
            state.by_domain6.remove(&old_domain);
        } else {
            state.by_domain4.remove(&old_domain);
        }
    }
    let previous_address = if address.is_ipv6() {
        state.by_domain6.insert(domain.clone(), address)
    } else {
        state.by_domain4.insert(domain.clone(), address)
    };
    if let Some(previous_address) = previous_address
        && previous_address != address
        && state.by_address.get(&previous_address) == Some(&domain)
    {
        state.by_address.remove(&previous_address);
    }
}

impl Resolver for FakeIpResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: DomainStrategy,
    ) -> LookupFuture<'a> {
        Box::pin(async move {
            let mut addresses = Vec::with_capacity(2);
            if strategy != DomainStrategy::Ipv6Only
                && self.inet4_range.is_some()
            {
                addresses.push(self.create(domain, false)?);
            }
            if strategy != DomainStrategy::Ipv4Only
                && self.inet6_range.is_some()
            {
                addresses.push(self.create(domain, true)?);
            }
            apply_strategy(&mut addresses, strategy);
            if addresses.is_empty() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("fake-IP has no address family for {domain:?}"),
                ))
            } else {
                Ok(addresses)
            }
        })
    }
}

fn canonical_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn next(address: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V4(address) => u32::from(address)
            .checked_add(1)
            .map(Ipv4Addr::from)
            .map(IpAddr::V4),
        IpAddr::V6(address) => u128::from(address)
            .checked_add(1)
            .map(Ipv6Addr::from)
            .map(IpAddr::V6),
    }
}

fn broadcast_address(range: &IpNet) -> IpAddr {
    match range {
        IpNet::V4(range) => {
            let host_mask = u32::MAX >> range.prefix_len();
            IpAddr::V4(Ipv4Addr::from(u32::from(range.addr()) | host_mask))
        }
        IpNet::V6(range) => {
            let host_mask = u128::MAX >> range.prefix_len();
            IpAddr::V6(Ipv6Addr::from(u128::from(range.addr()) | host_mask))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc};

    use super::FakeIpResolver;
    use crate::{
        dns::{Resolver, persistent::PersistentDnsCache},
        option::DomainStrategy,
    };

    #[test]
    fn allocates_stably_and_evicts_on_wrap() {
        let resolver =
            FakeIpResolver::new(Some("198.18.0.0/30".parse().unwrap()), None)
                .unwrap();
        let first = resolver.create("Example.COM.", false).unwrap();
        assert_eq!(first, "198.18.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(resolver.create("example.com", false).unwrap(), first);
        assert_eq!(
            resolver.lookup_domain(first).as_deref(),
            Some("example.com")
        );
        let wrapped = resolver.create("other.test", false).unwrap();
        assert_eq!(wrapped, first);
        assert!(resolver.lookup_domain(first).is_some());
        assert_ne!(
            resolver.create("example.com", false).unwrap(),
            "198.18.0.3".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn resolver_obeys_address_family_strategy() {
        let resolver = FakeIpResolver::new(
            Some("198.18.0.0/15".parse().unwrap()),
            Some("fc00::/18".parse().unwrap()),
        )
        .unwrap();
        let ipv6 = Resolver::lookup(
            &resolver,
            "example.com",
            DomainStrategy::Ipv6Only,
        )
        .await
        .unwrap();
        assert_eq!(ipv6.len(), 1);
        assert!(ipv6[0].is_ipv6());
        assert!(resolver.contains(ipv6[0]));
    }

    #[test]
    fn persistent_mapping_and_allocator_position_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            PersistentDnsCache::open(
                directory.path().join("cache.db"),
                "profile-a",
            )
            .unwrap(),
        );
        let range = "198.18.0.0/29".parse().unwrap();
        let first = FakeIpResolver::new_with_cache(
            Some(range),
            None,
            Some(cache.clone()),
        )
        .unwrap();
        let example = first.create("Example.COM.", false).unwrap();
        assert_eq!(example, "198.18.0.2".parse::<IpAddr>().unwrap());
        drop(first);

        let second =
            FakeIpResolver::new_with_cache(Some(range), None, Some(cache))
                .unwrap();
        assert_eq!(
            second.lookup_domain(example).as_deref(),
            Some("example.com")
        );
        assert_eq!(second.create("example.com", false).unwrap(), example);
        assert_eq!(
            second.create("other.test", false).unwrap(),
            "198.18.0.3".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn changing_ranges_discards_incompatible_persistent_mapping() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            PersistentDnsCache::open(directory.path().join("cache.db"), "")
                .unwrap(),
        );
        let first = FakeIpResolver::new_with_cache(
            Some("198.18.0.0/29".parse().unwrap()),
            None,
            Some(cache.clone()),
        )
        .unwrap();
        let old_address = first.create("example.com", false).unwrap();
        drop(first);

        let second = FakeIpResolver::new_with_cache(
            Some("198.19.0.0/29".parse().unwrap()),
            None,
            Some(cache),
        )
        .unwrap();
        assert_eq!(second.lookup_domain(old_address), None);
        assert_eq!(
            second.create("example.com", false).unwrap(),
            "198.19.0.2".parse::<IpAddr>().unwrap()
        );
    }
}
