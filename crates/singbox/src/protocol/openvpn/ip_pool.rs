use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::Instant,
};

use super::OpenVpnIpPrefix;

pub const IPV4_TOPOLOGY_SUBNET: &str = "subnet";
pub const IPV4_TOPOLOGY_P2P: &str = "p2p";
pub const IPV4_TOPOLOGY_NET30: &str = "net30";
pub const IP_POOL_MAXIMUM_SIZE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4PoolLease {
    pub client: Ipv4Addr,
    pub peer: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct IpPool {
    ipv4_prefix: Option<OpenVpnIpPrefix>,
    ipv4_topology: String,
    ipv4_server: Option<Ipv4Addr>,
    ipv4_start: Option<Ipv4Addr>,
    ipv4_end: Option<Ipv4Addr>,
    ipv6_prefix: Option<OpenVpnIpPrefix>,
    state: Mutex<IpPoolState>,
}

#[derive(Debug, Default)]
struct IpPoolState {
    ipv4_used: HashSet<Ipv4Addr>,
    ipv4_identity: HashMap<Ipv4Addr, String>,
    ipv4_address: HashMap<String, Ipv4Addr>,
    ipv4_released: HashMap<Ipv4Addr, Instant>,
    ipv6_server: Option<Ipv6Addr>,
    ipv6_used: HashSet<Ipv6Addr>,
    ipv6_identity: HashMap<Ipv6Addr, String>,
    ipv6_address: HashMap<String, Ipv6Addr>,
    ipv6_released: HashMap<Ipv6Addr, Instant>,
}

impl IpPool {
    pub fn new(
        address_pools: &[OpenVpnIpPrefix],
        topology: &str,
    ) -> Result<Self, IpPoolError> {
        let topology = resolve_ipv4_pool_topology(topology)?.to_owned();
        let mut pool = Self {
            ipv4_prefix: None,
            ipv4_topology: topology,
            ipv4_server: None,
            ipv4_start: None,
            ipv4_end: None,
            ipv6_prefix: None,
            state: Mutex::new(IpPoolState::default()),
        };
        if let Some(prefix) = address_pools
            .iter()
            .copied()
            .find(|prefix| prefix.address.is_ipv4() && prefix.prefix_len <= 32)
        {
            pool.configure_ipv4(prefix.masked())?;
        }
        if let Some(prefix) = address_pools
            .iter()
            .copied()
            .find(|prefix| prefix.address.is_ipv6() && prefix.prefix_len <= 128)
        {
            let prefix = prefix.masked();
            let server = match prefix.address {
                IpAddr::V6(address) => next_ipv6(address),
                IpAddr::V4(_) => unreachable!(),
            };
            pool.ipv6_prefix = Some(prefix);
            {
                let mut state = pool.state.lock().unwrap();
                state.ipv6_server = server;
                if let Some(server) = server {
                    state.ipv6_used.insert(server);
                }
            }
        }
        Ok(pool)
    }

    fn configure_ipv4(
        &mut self,
        prefix: OpenVpnIpPrefix,
    ) -> Result<(), IpPoolError> {
        if prefix.prefix_len < 16 || prefix.prefix_len > 29 {
            return Err(IpPoolError::InvalidIpv4Prefix(prefix.prefix_len));
        }
        let IpAddr::V4(network) = prefix.address else {
            return Ok(());
        };
        let broadcast = last_ipv4_in_prefix(prefix).unwrap();
        self.ipv4_prefix = Some(prefix);
        self.ipv4_server = add_ipv4(network, 1);
        match self.ipv4_topology.as_str() {
            IPV4_TOPOLOGY_SUBNET => {
                self.ipv4_start = add_ipv4(network, 2);
                self.ipv4_end = add_ipv4(broadcast, -1);
            }
            IPV4_TOPOLOGY_P2P | IPV4_TOPOLOGY_NET30 => {
                self.ipv4_start = add_ipv4(network, 4);
                self.ipv4_end = add_ipv4(
                    broadcast,
                    if prefix.prefix_len == 29 { 0 } else { -4 },
                );
            }
            _ => unreachable!(),
        }
        if self.ipv4_start.is_none()
            || self.ipv4_end.is_none()
            || u32::from(self.ipv4_start.unwrap())
                > u32::from(self.ipv4_end.unwrap())
        {
            return Err(IpPoolError::NoAllocatableIpv4);
        }
        Ok(())
    }

    pub fn has_ipv4(&self) -> bool {
        self.ipv4_prefix.is_some()
    }

    pub fn has_ipv6(&self) -> bool {
        self.ipv6_prefix.is_some()
    }

    pub fn server_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4_server
    }

    pub fn server_ipv6(&self) -> Option<Ipv6Addr> {
        self.state.lock().unwrap().ipv6_server
    }

    pub fn set_server_ipv4(
        &mut self,
        address: Option<Ipv4Addr>,
    ) -> Result<(), IpPoolError> {
        let Some(address) = address else {
            return Ok(());
        };
        let Some(prefix) = self.ipv4_prefix else {
            return Err(IpPoolError::Ipv4ServerOutsidePool(address));
        };
        if !prefix_contains(prefix, IpAddr::V4(address)) {
            return Err(IpPoolError::Ipv4ServerOutsidePool(address));
        }
        let network = match prefix.address {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => unreachable!(),
        };
        if address == network || Some(address) == last_ipv4_in_prefix(prefix) {
            return Err(IpPoolError::Ipv4ServerNotUsable(address));
        }
        if !self.state.lock().unwrap().ipv4_used.is_empty() {
            return Err(IpPoolError::Ipv4ServerAfterAllocation);
        }
        self.ipv4_server = Some(address);
        Ok(())
    }

    pub fn set_server_ipv6(
        &self,
        address: Option<Ipv6Addr>,
    ) -> Result<(), IpPoolError> {
        let Some(address) = address else {
            return Ok(());
        };
        let Some(prefix) = self.ipv6_prefix else {
            return Err(IpPoolError::Ipv6ServerOutsidePool(address));
        };
        if !prefix_contains(prefix, IpAddr::V6(address)) {
            return Err(IpPoolError::Ipv6ServerOutsidePool(address));
        }
        let mut state = self.state.lock().unwrap();
        if let Some(previous) = state.ipv6_server {
            state.ipv6_used.remove(&previous);
        }
        state.ipv6_server = Some(address);
        state.ipv6_used.insert(address);
        Ok(())
    }

    pub fn ipv4_prefix(&self) -> Option<OpenVpnIpPrefix> {
        self.ipv4_prefix
    }

    pub fn ipv4_topology(&self) -> &str {
        &self.ipv4_topology
    }

    pub fn ipv6_prefix(&self) -> Option<OpenVpnIpPrefix> {
        self.ipv6_prefix
    }

    pub fn allocate_ipv4(&self) -> Result<Ipv4PoolLease, IpPoolError> {
        self.allocate_ipv4_for_identity("")
    }

    pub fn allocate_ipv4_for_identity(
        &self,
        identity: &str,
    ) -> Result<Ipv4PoolLease, IpPoolError> {
        if !self.has_ipv4() {
            return Err(IpPoolError::Ipv4NotConfigured);
        }
        let mut state = self.state.lock().unwrap();
        if !identity.is_empty()
            && let Some(previous) = state.ipv4_address.get(identity).copied()
            && !state.ipv4_used.contains(&previous)
        {
            let lease = self.ipv4_lease(previous);
            commit_ipv4_lease(&mut state, lease, identity);
            return Ok(lease);
        }
        let lease = self
            .find_available_ipv4_lease(&state, identity)
            .ok_or(IpPoolError::Exhausted)?;
        commit_ipv4_lease(&mut state, lease, identity);
        Ok(lease)
    }

    pub fn allocate_ipv6(&self) -> Result<Ipv6Addr, IpPoolError> {
        self.allocate_ipv6_for_identity("")
    }

    pub fn allocate_ipv6_for_identity(
        &self,
        identity: &str,
    ) -> Result<Ipv6Addr, IpPoolError> {
        if !self.has_ipv6() {
            return Err(IpPoolError::Ipv6NotConfigured);
        }
        let mut state = self.state.lock().unwrap();
        if !identity.is_empty()
            && let Some(previous) = state.ipv6_address.get(identity).copied()
            && self.ipv6_contains(previous)
            && Some(previous) != state.ipv6_server
            && !state.ipv6_used.contains(&previous)
        {
            commit_ipv6_address(&mut state, previous, identity);
            return Ok(previous);
        }
        let address = self
            .find_available_ipv6_address(&state, identity)
            .ok_or(IpPoolError::Exhausted)?;
        commit_ipv6_address(&mut state, address, identity);
        Ok(address)
    }

    pub fn release(&self, address: IpAddr) {
        let mut state = self.state.lock().unwrap();
        match address {
            IpAddr::V4(address) => {
                state.ipv4_used.remove(&address);
                if state
                    .ipv4_identity
                    .get(&address)
                    .is_some_and(|identity| !identity.is_empty())
                {
                    state.ipv4_released.insert(address, Instant::now());
                } else {
                    state.ipv4_released.remove(&address);
                }
            }
            IpAddr::V6(address) => {
                state.ipv6_used.remove(&address);
                if state
                    .ipv6_identity
                    .get(&address)
                    .is_some_and(|identity| !identity.is_empty())
                {
                    state.ipv6_released.insert(address, Instant::now());
                } else {
                    state.ipv6_released.remove(&address);
                }
            }
        }
    }

    fn ipv4_lease(&self, address: Ipv4Addr) -> Ipv4PoolLease {
        Ipv4PoolLease {
            client: address,
            peer: match self.ipv4_topology.as_str() {
                IPV4_TOPOLOGY_P2P => self.ipv4_server,
                IPV4_TOPOLOGY_NET30 => add_ipv4(address, -1),
                _ => None,
            },
        }
    }

    fn find_available_ipv4_lease(
        &self,
        state: &IpPoolState,
        identity: &str,
    ) -> Option<Ipv4PoolLease> {
        let mut selected: Option<(Ipv4PoolLease, Option<Instant>)> = None;
        self.visit_ipv4_leases(|candidate| {
            if state.ipv4_used.contains(&candidate.client) {
                return true;
            }
            if identity.is_empty() {
                selected = Some((candidate, None));
                return false;
            }
            let released = state.ipv4_released.get(&candidate.client).copied();
            if selected.as_ref().is_none_or(|(_, current)| {
                release_is_before(released, *current)
            }) {
                selected = Some((candidate, released));
            }
            released.is_some()
        });
        selected.map(|(lease, _)| lease)
    }

    fn visit_ipv4_leases(
        &self,
        mut visitor: impl FnMut(Ipv4PoolLease) -> bool,
    ) {
        let (Some(start), Some(end)) = (self.ipv4_start, self.ipv4_end) else {
            return;
        };
        match self.ipv4_topology.as_str() {
            IPV4_TOPOLOGY_SUBNET | IPV4_TOPOLOGY_P2P => {
                let mut current = Some(start);
                while let Some(client) = current
                    && u32::from(client) <= u32::from(end)
                {
                    current = add_ipv4(client, 1);
                    if Some(client) == self.ipv4_server {
                        continue;
                    }
                    let lease = self.ipv4_lease(client);
                    if !visitor(lease) {
                        return;
                    }
                }
            }
            IPV4_TOPOLOGY_NET30 => {
                let mut current = Some(start);
                while let Some(block) = current
                    && u32::from(block) <= u32::from(end)
                {
                    current = add_ipv4(block, 4);
                    let (Some(peer), Some(client)) =
                        (add_ipv4(block, 1), add_ipv4(block, 2))
                    else {
                        return;
                    };
                    if u32::from(client) > u32::from(end) {
                        return;
                    }
                    if Some(peer) == self.ipv4_server
                        || Some(client) == self.ipv4_server
                    {
                        continue;
                    }
                    if !visitor(Ipv4PoolLease {
                        client,
                        peer: Some(peer),
                    }) {
                        return;
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn find_available_ipv6_address(
        &self,
        state: &IpPoolState,
        identity: &str,
    ) -> Option<Ipv6Addr> {
        let prefix = self.ipv6_prefix?;
        let IpAddr::V6(network) = prefix.address else {
            return None;
        };
        let mut selected: Option<(Ipv6Addr, Option<Instant>)> = None;
        let mut visited = 0;
        let mut current = next_ipv6(network);
        while let Some(address) = current
            && self.ipv6_contains(address)
            && visited < IP_POOL_MAXIMUM_SIZE
        {
            current = next_ipv6(address);
            if Some(address) == state.ipv6_server {
                continue;
            }
            visited += 1;
            if state.ipv6_used.contains(&address) {
                continue;
            }
            if identity.is_empty() {
                return Some(address);
            }
            if !state.ipv6_identity.contains_key(&address)
                && state.ipv6_address.len() >= IP_POOL_MAXIMUM_SIZE
            {
                continue;
            }
            let released = state.ipv6_released.get(&address).copied();
            if selected.as_ref().is_none_or(|(_, current)| {
                release_is_before(released, *current)
            }) {
                selected = Some((address, released));
            }
            if released.is_none() {
                break;
            }
        }
        selected.map(|(address, _)| address)
    }

    fn ipv6_contains(&self, address: Ipv6Addr) -> bool {
        self.ipv6_prefix
            .is_some_and(|prefix| prefix_contains(prefix, IpAddr::V6(address)))
    }
}

pub fn resolve_ipv4_pool_topology(topology: &str) -> Result<&str, IpPoolError> {
    match topology {
        "" => Ok(IPV4_TOPOLOGY_NET30),
        IPV4_TOPOLOGY_SUBNET | IPV4_TOPOLOGY_P2P | IPV4_TOPOLOGY_NET30 => {
            Ok(topology)
        }
        _ => Err(IpPoolError::UnsupportedTopology(topology.into())),
    }
}

fn commit_ipv4_lease(
    state: &mut IpPoolState,
    lease: Ipv4PoolLease,
    identity: &str,
) {
    state.ipv4_used.insert(lease.client);
    state.ipv4_released.remove(&lease.client);
    if let Some(previous_identity) =
        state.ipv4_identity.get(&lease.client).cloned()
        && previous_identity != identity
        && state.ipv4_address.get(&previous_identity) == Some(&lease.client)
    {
        state.ipv4_address.remove(&previous_identity);
    }
    if identity.is_empty() {
        state.ipv4_identity.remove(&lease.client);
    } else {
        if let Some(previous) = state.ipv4_address.get(identity).copied()
            && previous != lease.client
        {
            state.ipv4_identity.remove(&previous);
            state.ipv4_released.remove(&previous);
        }
        state.ipv4_identity.insert(lease.client, identity.into());
        state.ipv4_address.insert(identity.into(), lease.client);
    }
}

fn commit_ipv6_address(
    state: &mut IpPoolState,
    address: Ipv6Addr,
    identity: &str,
) {
    state.ipv6_used.insert(address);
    state.ipv6_released.remove(&address);
    if let Some(previous_identity) = state.ipv6_identity.get(&address).cloned()
        && previous_identity != identity
        && state.ipv6_address.get(&previous_identity) == Some(&address)
    {
        state.ipv6_address.remove(&previous_identity);
    }
    if identity.is_empty() {
        state.ipv6_identity.remove(&address);
    } else {
        if let Some(previous) = state.ipv6_address.get(identity).copied()
            && previous != address
        {
            state.ipv6_identity.remove(&previous);
            state.ipv6_released.remove(&previous);
        }
        state.ipv6_identity.insert(address, identity.into());
        state.ipv6_address.insert(identity.into(), address);
    }
}

fn release_is_before(left: Option<Instant>, right: Option<Instant>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(left), Some(right)) => left < right,
        _ => false,
    }
}

fn prefix_contains(prefix: OpenVpnIpPrefix, address: IpAddr) -> bool {
    if prefix.address.is_ipv4() != address.is_ipv4() {
        return false;
    }
    match (prefix.masked().address, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.prefix_len)
            };
            u32::from(address) & mask == u32::from(network)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix.prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.prefix_len)
            };
            u128::from(address) & mask == u128::from(network)
        }
        _ => false,
    }
}

fn last_ipv4_in_prefix(prefix: OpenVpnIpPrefix) -> Option<Ipv4Addr> {
    let IpAddr::V4(network) = prefix.masked().address else {
        return None;
    };
    let host_bits = 32 - prefix.prefix_len;
    Some(Ipv4Addr::from(
        u32::from(network)
            | if host_bits == 32 {
                u32::MAX
            } else {
                (1_u32 << host_bits) - 1
            },
    ))
}

fn add_ipv4(address: Ipv4Addr, offset: i64) -> Option<Ipv4Addr> {
    let value = i64::from(u32::from(address)) + offset;
    u32::try_from(value).ok().map(Ipv4Addr::from)
}

fn next_ipv6(address: Ipv6Addr) -> Option<Ipv6Addr> {
    u128::from(address).checked_add(1).map(Ipv6Addr::from)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpPoolError {
    #[error("unsupported IPv4 topology: {0}")]
    UnsupportedTopology(String),
    #[error("IPv4 address pool must be between /16 and /29, got /{0}")]
    InvalidIpv4Prefix(u8),
    #[error("IPv4 address pool has no allocatable addresses")]
    NoAllocatableIpv4,
    #[error("ipv4 pool not configured")]
    Ipv4NotConfigured,
    #[error("ipv6 pool not configured")]
    Ipv6NotConfigured,
    #[error("IP pool exhausted")]
    Exhausted,
    #[error("server IPv4 address {0} is outside pool")]
    Ipv4ServerOutsidePool(Ipv4Addr),
    #[error("server IPv4 address {0} is not a usable host")]
    Ipv4ServerNotUsable(Ipv4Addr),
    #[error(
        "cannot change server IPv4 address after allocating client addresses"
    )]
    Ipv4ServerAfterAllocation,
    #[error("server IPv6 address {0} is outside pool")]
    Ipv6ServerOutsidePool(Ipv6Addr),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(value: &str, bits: u8) -> OpenVpnIpPrefix {
        OpenVpnIpPrefix {
            address: value.parse().unwrap(),
            prefix_len: bits,
        }
    }

    #[test]
    fn validates_topology_and_ipv4_pool_sizes() {
        assert_eq!(resolve_ipv4_pool_topology("").unwrap(), "net30");
        assert!(resolve_ipv4_pool_topology("SUBNET").is_err());
        assert!(IpPool::new(&[prefix("10.0.0.0", 15)], "subnet").is_err());
        assert!(IpPool::new(&[prefix("10.0.0.0", 30)], "subnet").is_err());
    }

    #[test]
    fn allocates_each_ipv4_topology_like_openvpn_server_helper() {
        let subnet = IpPool::new(&[prefix("10.0.0.0", 29)], "subnet").unwrap();
        assert_eq!(subnet.server_ipv4(), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(
            subnet.allocate_ipv4().unwrap(),
            Ipv4PoolLease {
                client: "10.0.0.2".parse().unwrap(),
                peer: None
            }
        );

        let p2p = IpPool::new(&[prefix("10.0.0.0", 29)], "p2p").unwrap();
        assert_eq!(
            p2p.allocate_ipv4().unwrap().peer,
            Some("10.0.0.1".parse().unwrap())
        );

        let net30 = IpPool::new(&[prefix("10.0.0.0", 29)], "net30").unwrap();
        assert_eq!(
            net30.allocate_ipv4().unwrap(),
            Ipv4PoolLease {
                client: "10.0.0.6".parse().unwrap(),
                peer: Some("10.0.0.5".parse().unwrap())
            }
        );
        assert_eq!(net30.allocate_ipv4(), Err(IpPoolError::Exhausted));
    }

    #[test]
    fn identities_reclaim_previous_addresses_and_prefer_fresh_slots() {
        let pool = IpPool::new(&[prefix("10.0.0.0", 29)], "subnet").unwrap();
        let alice = pool.allocate_ipv4_for_identity("alice").unwrap();
        pool.release(IpAddr::V4(alice.client));
        let bob = pool.allocate_ipv4_for_identity("bob").unwrap();
        assert_ne!(bob.client, alice.client);
        let occupied = pool.allocate_ipv4().unwrap();
        pool.release(IpAddr::V4(occupied.client));
        let alice_again = pool.allocate_ipv4_for_identity("alice").unwrap();
        assert_eq!(alice_again, alice);
    }

    #[test]
    fn server_override_obeys_pool_and_allocation_rules() {
        let mut pool =
            IpPool::new(&[prefix("10.0.0.0", 29)], "subnet").unwrap();
        assert!(
            pool.set_server_ipv4(Some("10.0.0.0".parse().unwrap()))
                .is_err()
        );
        pool.set_server_ipv4(Some("10.0.0.3".parse().unwrap()))
            .unwrap();
        assert_eq!(pool.server_ipv4(), Some("10.0.0.3".parse().unwrap()));
        pool.allocate_ipv4().unwrap();
        assert_eq!(
            pool.set_server_ipv4(Some("10.0.0.4".parse().unwrap())),
            Err(IpPoolError::Ipv4ServerAfterAllocation)
        );
    }

    #[test]
    fn allocates_ipv6_skipping_server_and_restores_identity() {
        let pool = IpPool::new(&[prefix("fd00::", 120)], "").unwrap();
        assert_eq!(pool.server_ipv6(), Some("fd00::1".parse().unwrap()));
        let alice = pool.allocate_ipv6_for_identity("alice").unwrap();
        assert_eq!(alice, "fd00::2".parse::<Ipv6Addr>().unwrap());
        pool.release(IpAddr::V6(alice));
        let bob = pool.allocate_ipv6_for_identity("bob").unwrap();
        assert_eq!(bob, "fd00::3".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pool.allocate_ipv6_for_identity("alice").unwrap(), alice);
        pool.set_server_ipv6(Some("fd00::ff".parse().unwrap()))
            .unwrap();
        assert_eq!(pool.server_ipv6(), Some("fd00::ff".parse().unwrap()));
    }

    #[test]
    fn uses_only_first_pool_of_each_address_family() {
        let pool = IpPool::new(
            &[
                prefix("10.0.0.0", 29),
                prefix("10.1.0.0", 29),
                prefix("fd00::", 120),
                prefix("fd01::", 120),
            ],
            "subnet",
        )
        .unwrap();
        assert_eq!(pool.ipv4_prefix(), Some(prefix("10.0.0.0", 29)));
        assert_eq!(pool.ipv6_prefix(), Some(prefix("fd00::", 120)));
    }
}
