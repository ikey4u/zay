use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use hashlink::LinkedHashMap;
use parking_lot::Mutex;

use crate::{common::network::SocksAddr, option::UdpNatBehavior};

const UDP_NAT_MIN_SIZE: usize = 4_096;
#[cfg(any(not(target_os = "ios"), test))]
const UDP_NAT_MAX_SIZE: usize = 16_384;

pub(crate) fn udp_nat_max(configured: u32) -> usize {
    if configured != 0 {
        return configured as usize;
    }
    #[cfg(target_os = "ios")]
    {
        UDP_NAT_MIN_SIZE
    }
    #[cfg(not(target_os = "ios"))]
    {
        udp_nat_default_max_for_memory(
            sysinfo::System::new_all().total_memory(),
        )
    }
}

#[cfg(any(not(target_os = "ios"), test))]
fn udp_nat_default_max_for_memory(total_memory: u64) -> usize {
    if total_memory == 0 {
        return UDP_NAT_MAX_SIZE;
    }
    usize::try_from(total_memory / 16_384)
        .unwrap_or(UDP_NAT_MAX_SIZE)
        .clamp(UDP_NAT_MIN_SIZE, UDP_NAT_MAX_SIZE)
}

pub(crate) struct UdpNatFilter {
    filtering: UdpNatBehavior,
    cache: Option<Arc<Mutex<FilterCache>>>,
    next_session_id: AtomicU64,
}

impl UdpNatFilter {
    pub(crate) fn new(
        mapping: UdpNatBehavior,
        filtering: UdpNatBehavior,
        max_size: usize,
    ) -> Self {
        Self {
            filtering,
            cache: (behavior_rank(filtering) > behavior_rank(mapping)).then(
                || {
                    Arc::new(Mutex::new(FilterCache {
                        max_size,
                        peers: LinkedHashMap::new(),
                    }))
                },
            ),
            next_session_id: AtomicU64::new(1),
        }
    }

    pub(crate) fn open(&self, initial: &SocksAddr) -> UdpNatFilterSession {
        let id = self.cache.as_ref().map(|_| {
            loop {
                let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
                if id != 0 {
                    break id;
                }
            }
        });
        UdpNatFilterSession(Arc::new(FilterSessionInner {
            id,
            filtering: self.filtering,
            initial: FilterPeer::from_destination(self.filtering, initial),
            cache: self.cache.clone(),
        }))
    }
}

#[derive(Clone)]
pub(crate) struct UdpNatFilterSession(Arc<FilterSessionInner>);

impl UdpNatFilterSession {
    pub(crate) fn record(&self, destination: &SocksAddr) {
        let Some(cache) = &self.0.cache else {
            return;
        };
        let Some(peer) =
            FilterPeer::from_destination(self.0.filtering, destination)
        else {
            return;
        };
        if self.0.initial == Some(peer) {
            return;
        }
        let Some(session_id) = self.0.id else {
            return;
        };
        let key = FilterKey { session_id, peer };
        let mut cache = cache.lock();
        if cache.peers.to_back(&key).is_none() {
            cache.peers.insert(key, ());
        }
        while cache.peers.len() > cache.max_size {
            cache.peers.pop_front();
        }
    }

    pub(crate) fn allows(&self, source: &SocksAddr) -> bool {
        if self.0.filtering == UdpNatBehavior::EndpointIndependent {
            return true;
        }
        let Some(peer) = FilterPeer::from_destination(self.0.filtering, source)
        else {
            return true;
        };
        if self.0.initial == Some(peer) {
            return true;
        }
        let (Some(cache), Some(session_id)) = (&self.0.cache, self.0.id) else {
            return false;
        };
        cache
            .lock()
            .peers
            .to_back(&FilterKey { session_id, peer })
            .is_some()
    }

    #[cfg(test)]
    fn cached_len(&self) -> usize {
        self.0
            .cache
            .as_ref()
            .map_or(0, |cache| cache.lock().peers.len())
    }
}

struct FilterSessionInner {
    id: Option<u64>,
    filtering: UdpNatBehavior,
    initial: Option<FilterPeer>,
    cache: Option<Arc<Mutex<FilterCache>>>,
}

impl Drop for FilterSessionInner {
    fn drop(&mut self) {
        let (Some(cache), Some(session_id)) = (&self.cache, self.id) else {
            return;
        };
        cache
            .lock()
            .peers
            .retain(|key, _| key.session_id != session_id);
    }
}

struct FilterCache {
    max_size: usize,
    peers: LinkedHashMap<FilterKey, ()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FilterKey {
    session_id: u64,
    peer: FilterPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FilterPeer {
    address: IpAddr,
    port: u16,
}

impl FilterPeer {
    fn from_destination(
        filtering: UdpNatBehavior,
        destination: &SocksAddr,
    ) -> Option<Self> {
        let SocksAddr::Ip(destination) = destination else {
            return None;
        };
        let address = match destination.ip() {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or(IpAddr::V6(address), IpAddr::V4),
            address => address,
        };
        Some(Self {
            address,
            port: if filtering == UdpNatBehavior::AddressDependent {
                0
            } else {
                destination.port()
            },
        })
    }
}

const fn behavior_rank(behavior: UdpNatBehavior) -> u8 {
    match behavior {
        UdpNatBehavior::EndpointIndependent => 0,
        UdpNatBehavior::AddressDependent => 1,
        UdpNatBehavior::AddressAndPortDependent => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::{UdpNatFilter, udp_nat_default_max_for_memory, udp_nat_max};
    use crate::{common::network::SocksAddr, option::UdpNatBehavior};

    #[test]
    fn default_capacity_matches_upstream_memory_bounds() {
        assert_eq!(udp_nat_default_max_for_memory(0), 16_384);
        assert_eq!(udp_nat_default_max_for_memory(32 * 1024 * 1024), 4_096);
        assert_eq!(udp_nat_default_max_for_memory(128 * 1024 * 1024), 8_192);
        assert_eq!(udp_nat_default_max_for_memory(1024 * 1024 * 1024), 16_384);
        assert_eq!(udp_nat_max(777), 777);
    }

    #[test]
    fn domains_are_always_allowed_and_mapped_ipv4_is_canonical() {
        let filter = UdpNatFilter::new(
            UdpNatBehavior::EndpointIndependent,
            UdpNatBehavior::AddressDependent,
            4,
        );
        let session = filter.open(&SocksAddr::new("198.51.100.1", 53));
        assert!(session.allows(&SocksAddr::new("example.com", 53)));
        assert!(session.allows(&SocksAddr::new("::ffff:198.51.100.1", 5353)));
    }

    #[test]
    fn dependency_levels_track_address_and_port_exactly() {
        let first = SocksAddr::new("198.51.100.1", 53);
        let same_address = SocksAddr::new("198.51.100.1", 5353);
        let second = SocksAddr::new("198.51.100.2", 53);
        let address_filter = UdpNatFilter::new(
            UdpNatBehavior::EndpointIndependent,
            UdpNatBehavior::AddressDependent,
            4,
        );
        let address_session = address_filter.open(&first);
        assert!(address_session.allows(&same_address));
        assert!(!address_session.allows(&second));

        let endpoint_filter = UdpNatFilter::new(
            UdpNatBehavior::EndpointIndependent,
            UdpNatBehavior::AddressAndPortDependent,
            4,
        );
        let endpoint_session = endpoint_filter.open(&first);
        assert!(!endpoint_session.allows(&same_address));
        endpoint_session.record(&same_address);
        assert!(endpoint_session.allows(&same_address));
    }

    #[test]
    fn shared_lru_is_bounded_refreshed_and_cleaned_per_session() {
        let filter = UdpNatFilter::new(
            UdpNatBehavior::EndpointIndependent,
            UdpNatBehavior::AddressAndPortDependent,
            2,
        );
        let first = filter.open(&SocksAddr::new("198.51.100.1", 1));
        let second = filter.open(&SocksAddr::new("198.51.100.2", 1));
        let first_extra = SocksAddr::new("198.51.100.1", 2);
        let second_extra = SocksAddr::new("198.51.100.2", 2);
        let third_extra = SocksAddr::new("198.51.100.3", 2);
        first.record(&first_extra);
        second.record(&second_extra);
        assert_eq!(first.cached_len(), 2);
        assert!(first.allows(&first_extra));
        second.record(&third_extra);
        assert!(first.allows(&first_extra));
        assert!(!second.allows(&second_extra));
        assert!(second.allows(&third_extra));
        drop(first);
        assert_eq!(second.cached_len(), 1);
        drop(second);
    }
}
