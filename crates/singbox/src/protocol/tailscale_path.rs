//! Tailscale magicsock peer-path quality and discovery state.
//!
//! This layer deliberately owns no socket. It mirrors the upstream endpoint
//! state machine so an embedding runtime can feed authenticated disco
//! ping/pong messages from either UDP or DERP and receive deterministic send
//! and probe decisions.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use super::tailscale_disco::{
    TAILSCALE_DISCO_KEY_LENGTH, TAILSCALE_DISCO_TRANSACTION_ID_LENGTH,
};

pub const TAILSCALE_PATH_SESSION_ACTIVE_TIMEOUT: Duration =
    Duration::from_secs(45);
pub const TAILSCALE_PATH_UPGRADE_DIRECT_INTERVAL: Duration =
    Duration::from_secs(60);
pub const TAILSCALE_PATH_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
pub const TAILSCALE_PATH_TRUST_DURATION: Duration =
    Duration::from_millis(6_500);
pub const TAILSCALE_PATH_GOOD_ENOUGH_LATENCY: Duration =
    Duration::from_millis(5);
pub const TAILSCALE_PATH_DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
pub const TAILSCALE_PATH_PING_TIMEOUT: Duration = Duration::from_secs(5);
pub const TAILSCALE_PATH_PONG_HISTORY_COUNT: usize = 64;
pub const TAILSCALE_PATH_SAFE_WIRE_MTU: u32 = 1_360;

pub type TailscaleDiscoTransactionId =
    [u8; TAILSCALE_DISCO_TRANSACTION_ID_LENGTH];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleUdpRelayPath {
    pub vni: u32,
    pub server_disco_key: [u8; TAILSCALE_DISCO_KEY_LENGTH],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscalePathQuality {
    pub endpoint: SocketAddr,
    pub relay: Option<TailscaleUdpRelayPath>,
    pub latency: Duration,
    pub wire_mtu: u32,
}

impl TailscalePathQuality {
    pub fn direct(
        endpoint: SocketAddr,
        latency: Duration,
        wire_mtu: u32,
    ) -> Self {
        Self {
            endpoint,
            relay: None,
            latency,
            wire_mtu,
        }
    }

    pub fn is_direct(&self) -> bool {
        self.relay.is_none()
    }

    /// Implements magicsock's exact point-based preference, including its 1%
    /// hysteresis and local/private/IPv6 bonuses.
    pub fn better_than(&self, current: &Self) -> bool {
        if self.endpoint == current.endpoint && self.relay == current.relay {
            return self.wire_mtu > current.wire_mtu;
        }
        match (self.relay.is_some(), current.relay.is_some()) {
            (false, true) => return true,
            (true, false) => return false,
            _ => {}
        }

        let (mut candidate_points, mut current_points) = (0_u128, 0_u128);
        let candidate_latency = self.latency.as_nanos();
        let current_latency = current.latency.as_nanos();
        if candidate_latency > current_latency && candidate_latency > 0 {
            current_points =
                100 - current_latency.saturating_mul(100) / candidate_latency;
        } else if let Some(relative) = candidate_latency
            .saturating_mul(100)
            .checked_div(current_latency)
        {
            candidate_points = 100 - relative;
        }
        candidate_points += address_preference_points(self.endpoint.ip());
        current_points += address_preference_points(current.endpoint.ip());

        if candidate_points <= 1 && current_points == 0 {
            return false;
        }
        candidate_points > current_points
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscalePathPong {
    pub latency: Duration,
    pub received_at: Instant,
    pub from: SocketAddr,
    pub reported_source: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscalePathEndpointSnapshot {
    pub endpoint: SocketAddr,
    pub network_index: Option<i16>,
    pub last_ping: Option<Instant>,
    pub runtime_last_seen: Option<Instant>,
    pub call_me_maybe_at: Option<Instant>,
    pub latest_pong: Option<TailscalePathPong>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscalePathPongOutcome {
    pub target: SocketAddr,
    pub from: SocketAddr,
    pub latency: Duration,
    pub became_best: bool,
    pub best: Option<TailscalePathQuality>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleSendPath {
    pub udp: Option<TailscalePathQuality>,
    pub derp_region: Option<u32>,
}

#[derive(Debug, Clone)]
struct SentPing {
    target: TailscalePathQuality,
    sent_at: Instant,
}

#[derive(Debug, Clone, Default)]
struct EndpointState {
    network_index: Option<i16>,
    last_ping: Option<Instant>,
    runtime_last_seen: Option<Instant>,
    last_runtime_ping: Option<TailscaleDiscoTransactionId>,
    call_me_maybe_at: Option<Instant>,
    recent_pongs: VecDeque<TailscalePathPong>,
}

impl EndpointState {
    fn should_delete(&self, now: Instant) -> bool {
        if self.call_me_maybe_at.is_some() {
            return false;
        }
        match self.runtime_last_seen {
            None => self.network_index.is_none(),
            Some(last_seen) => {
                elapsed(now, last_seen) > TAILSCALE_PATH_SESSION_ACTIVE_TIMEOUT
            }
        }
    }

    fn clear_derived(&mut self) {
        let network_index = self.network_index;
        let runtime_last_seen = self.runtime_last_seen;
        *self = Self {
            network_index,
            runtime_last_seen,
            ..Self::default()
        };
    }

    fn add_pong(&mut self, pong: TailscalePathPong) {
        if self.recent_pongs.len() == TAILSCALE_PATH_PONG_HISTORY_COUNT {
            self.recent_pongs.pop_front();
        }
        self.recent_pongs.push_back(pong);
    }
}

#[derive(Debug, Clone)]
pub struct TailscalePeerPathState {
    derp_region: Option<u32>,
    best: Option<TailscalePathQuality>,
    best_confirmed_at: Option<Instant>,
    trust_best_until: Option<Instant>,
    last_full_ping: Option<Instant>,
    endpoints: HashMap<SocketAddr, EndpointState>,
    call_me_maybe_endpoints: HashSet<SocketAddr>,
    sent_pings: HashMap<TailscaleDiscoTransactionId, SentPing>,
}

impl TailscalePeerPathState {
    pub fn new(derp_region: Option<u32>) -> Self {
        Self {
            derp_region,
            best: None,
            best_confirmed_at: None,
            trust_best_until: None,
            last_full_ping: None,
            endpoints: HashMap::new(),
            call_me_maybe_endpoints: HashSet::new(),
            sent_pings: HashMap::new(),
        }
    }

    pub fn set_derp_region(&mut self, derp_region: Option<u32>) {
        self.derp_region = derp_region;
    }

    pub fn best(&self) -> Option<&TailscalePathQuality> {
        self.best.as_ref()
    }

    pub fn best_confirmed_at(&self) -> Option<Instant> {
        self.best_confirmed_at
    }

    pub fn trust_best_until(&self) -> Option<Instant> {
        self.trust_best_until
    }

    pub fn endpoint_snapshots(&self) -> Vec<TailscalePathEndpointSnapshot> {
        let mut snapshots = self
            .endpoints
            .iter()
            .map(|(endpoint, state)| TailscalePathEndpointSnapshot {
                endpoint: *endpoint,
                network_index: state.network_index,
                last_ping: state.last_ping,
                runtime_last_seen: state.runtime_last_seen,
                call_me_maybe_at: state.call_me_maybe_at,
                latest_pong: state.recent_pongs.back().cloned(),
            })
            .collect::<Vec<_>>();
        snapshots.sort_unstable_by_key(|snapshot| snapshot.endpoint);
        snapshots
    }

    pub fn update_netmap_endpoints(
        &mut self,
        endpoints: &[SocketAddr],
        now: Instant,
    ) {
        for state in self.endpoints.values_mut() {
            state.network_index = None;
        }
        for (index, endpoint) in endpoints.iter().copied().enumerate() {
            let Ok(index) = i16::try_from(index) else {
                break;
            };
            self.endpoints.entry(endpoint).or_default().network_index =
                Some(index);
        }
        self.remove_stale_endpoints(now);
    }

    /// Apply an authenticated CallMeMaybe received through DERP and return
    /// every endpoint that should be pinged immediately.
    pub fn handle_call_me_maybe(
        &mut self,
        endpoints: &[SocketAddr],
        now: Instant,
    ) -> Vec<SocketAddr> {
        let mut advertised = HashSet::new();
        for endpoint in endpoints.iter().copied() {
            if is_ipv6_link_local(endpoint.ip()) {
                continue;
            }
            advertised.insert(endpoint);
            self.endpoints.entry(endpoint).or_default().call_me_maybe_at =
                Some(now);
        }

        let removed = self
            .call_me_maybe_endpoints
            .difference(&advertised)
            .copied()
            .collect::<Vec<_>>();
        for endpoint in removed {
            self.delete_endpoint(endpoint);
        }
        self.call_me_maybe_endpoints = advertised;
        for state in self.endpoints.values_mut() {
            state.last_ping = None;
        }
        self.discovery_candidates(now)
    }

    /// Add a source learned from an authenticated incoming disco Ping.
    /// Returns true when the same transaction was already seen on another
    /// receive path and must not be answered twice.
    pub fn add_candidate_endpoint(
        &mut self,
        endpoint: SocketAddr,
        transaction_id: TailscaleDiscoTransactionId,
        now: Instant,
    ) -> bool {
        let state = self.endpoints.entry(endpoint).or_default();
        let duplicate = state.last_runtime_ping == Some(transaction_id);
        if !duplicate {
            state.last_runtime_ping = Some(transaction_id);
        }
        if state.network_index.is_none() {
            state.runtime_last_seen = Some(now);
        }
        if self.endpoints.len() > 100 {
            self.remove_stale_endpoints(now);
        }
        duplicate
    }

    pub fn discovery_candidates(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.remove_stale_endpoints(now);
        self.last_full_ping = Some(now);
        let mut candidates = self
            .endpoints
            .iter_mut()
            .filter_map(|(endpoint, state)| {
                let recent = state.last_ping.is_some_and(|last_ping| {
                    elapsed(now, last_ping) < TAILSCALE_PATH_DISCO_PING_INTERVAL
                });
                if recent {
                    None
                } else {
                    state.last_ping = Some(now);
                    Some(*endpoint)
                }
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        candidates
    }

    pub fn begin_ping(
        &mut self,
        transaction_id: TailscaleDiscoTransactionId,
        target: TailscalePathQuality,
        now: Instant,
    ) {
        if target.relay.is_none()
            && let Some(state) = self.endpoints.get_mut(&target.endpoint)
        {
            state.last_ping = Some(now);
        }
        self.sent_pings.insert(
            transaction_id,
            SentPing {
                target,
                sent_at: now,
            },
        );
    }

    pub fn expire_pings(
        &mut self,
        now: Instant,
    ) -> Vec<TailscaleDiscoTransactionId> {
        let mut expired = self
            .sent_pings
            .iter()
            .filter_map(|(transaction_id, ping)| {
                (elapsed(now, ping.sent_at) >= TAILSCALE_PATH_PING_TIMEOUT)
                    .then_some(*transaction_id)
            })
            .collect::<Vec<_>>();
        for transaction_id in &expired {
            self.sent_pings.remove(transaction_id);
        }
        expired.sort_unstable();
        expired
    }

    pub fn forget_ping(
        &mut self,
        transaction_id: TailscaleDiscoTransactionId,
    ) -> bool {
        self.sent_pings.remove(&transaction_id).is_some()
    }

    pub fn has_pending_ping(
        &self,
        transaction_id: TailscaleDiscoTransactionId,
    ) -> bool {
        self.sent_pings.contains_key(&transaction_id)
    }

    /// Record a matching authenticated Pong. `via_derp` preserves upstream's
    /// rule that DERP latency never promotes a UDP path.
    pub fn record_pong(
        &mut self,
        transaction_id: TailscaleDiscoTransactionId,
        from: SocketAddr,
        reported_source: SocketAddr,
        via_derp: bool,
        now: Instant,
    ) -> Option<TailscalePathPongOutcome> {
        let sent = self.sent_pings.remove(&transaction_id)?;
        let latency = elapsed(now, sent.sent_at);
        if !via_derp && sent.target.relay.is_none() {
            let state = self.endpoints.get_mut(&sent.target.endpoint)?;
            state.add_pong(TailscalePathPong {
                latency,
                received_at: now,
                from,
                reported_source,
            });
        }

        let mut became_best = false;
        if !via_derp {
            let mut candidate = sent.target.clone();
            candidate.latency = latency;
            if candidate.wire_mtu == 0 {
                candidate.wire_mtu = TAILSCALE_PATH_SAFE_WIRE_MTU;
            }
            let best_untrusted = !self.best_is_trusted(now);
            if best_untrusted
                || self
                    .best
                    .as_ref()
                    .is_none_or(|best| candidate.better_than(best))
            {
                self.best = Some(candidate.clone());
                became_best = true;
            }
            if self.best.as_ref().is_some_and(|best| {
                best.endpoint == candidate.endpoint
                    && best.relay == candidate.relay
            }) {
                self.best = Some(candidate);
                self.best_confirmed_at = Some(now);
                self.trust_best_until =
                    Some(now + TAILSCALE_PATH_TRUST_DURATION);
            }
        }

        Some(TailscalePathPongOutcome {
            target: sent.target.endpoint,
            from,
            latency,
            became_best,
            best: self.best.clone(),
        })
    }

    pub fn send_path(&self, now: Instant) -> TailscaleSendPath {
        if self.best_is_trusted(now) {
            return TailscaleSendPath {
                udp: self.best.clone(),
                derp_region: None,
            };
        }
        TailscaleSendPath {
            udp: self.best.clone(),
            derp_region: self.derp_region,
        }
    }

    pub fn wants_full_ping(&self, now: Instant) -> bool {
        let Some(best) = &self.best else {
            return true;
        };
        if !best.is_direct() || self.last_full_ping.is_none() {
            return true;
        }
        if !self.best_is_trusted(now) {
            return true;
        }
        if best.latency <= TAILSCALE_PATH_GOOD_ENOUGH_LATENCY {
            return false;
        }
        self.last_full_ping.is_some_and(|last_full_ping| {
            elapsed(now, last_full_ping)
                >= TAILSCALE_PATH_UPGRADE_DIRECT_INTERVAL
        })
    }

    pub fn note_bad_endpoint(&mut self, endpoint: SocketAddr) {
        self.clear_best();
        if let Some(state) = self.endpoints.get_mut(&endpoint) {
            state.clear_derived();
        }
    }

    pub fn note_connectivity_change(&mut self) {
        self.clear_best();
        for state in self.endpoints.values_mut() {
            state.clear_derived();
        }
    }

    fn best_is_trusted(&self, now: Instant) -> bool {
        self.trust_best_until.is_some_and(|until| now < until)
    }

    fn clear_best(&mut self) {
        self.best = None;
        self.best_confirmed_at = None;
        self.trust_best_until = None;
    }

    fn remove_stale_endpoints(&mut self, now: Instant) {
        let stale = self
            .endpoints
            .iter()
            .filter_map(|(endpoint, state)| {
                state.should_delete(now).then_some(*endpoint)
            })
            .collect::<Vec<_>>();
        for endpoint in stale {
            self.delete_endpoint(endpoint);
        }
    }

    fn delete_endpoint(&mut self, endpoint: SocketAddr) {
        self.endpoints.remove(&endpoint);
        self.call_me_maybe_endpoints.remove(&endpoint);
        if self
            .best
            .as_ref()
            .is_some_and(|best| best.endpoint == endpoint)
        {
            self.clear_best();
        }
    }
}

fn address_preference_points(address: IpAddr) -> u128 {
    let mut points = if address.is_loopback() {
        50
    } else if is_ipv6_link_local(address) {
        30
    } else if is_private(address) {
        20
    } else {
        0
    };
    if address.is_ipv6() {
        points += 10;
    }
    points
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.is_unique_local(),
    }
}

fn is_ipv6_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => false,
        IpAddr::V6(address) => {
            (address.segments()[0] & 0xffc0) == 0xfe80
                && address != Ipv6Addr::UNSPECIFIED
        }
    }
}

fn elapsed(now: Instant, then: Instant) -> Duration {
    now.checked_duration_since(then).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    fn direct(
        value: &str,
        latency_ms: u64,
        wire_mtu: u32,
    ) -> TailscalePathQuality {
        TailscalePathQuality::direct(
            endpoint(value),
            Duration::from_millis(latency_ms),
            wire_mtu,
        )
    }

    #[test]
    fn path_quality_matches_upstream_latency_locality_and_hysteresis() {
        let public_v4 = direct("203.0.113.1:41641", 100, 1_360);
        assert!(
            !direct("203.0.113.2:41641", 99, 1_360).better_than(&public_v4)
        );
        assert!(direct("203.0.113.2:41641", 98, 1_360).better_than(&public_v4));
        assert!(direct("10.0.0.2:41641", 110, 1_360).better_than(&public_v4));
        assert!(
            direct("[2001:db8::2]:41641", 105, 1_360).better_than(&public_v4)
        );

        let relay = TailscalePathQuality {
            endpoint: endpoint("192.0.2.10:3478"),
            relay: Some(TailscaleUdpRelayPath {
                vni: 7,
                server_disco_key: [1; 32],
            }),
            latency: Duration::from_millis(1),
            wire_mtu: 9_000,
        };
        assert!(public_v4.better_than(&relay));
        assert!(!relay.better_than(&public_v4));
        assert!(
            direct("203.0.113.1:41641", 500, 1_500).better_than(&public_v4)
        );
    }

    #[test]
    fn pong_promotes_direct_path_and_expiry_mirrors_to_derp() {
        let start = Instant::now();
        let mut paths = TailscalePeerPathState::new(Some(12));
        let target = endpoint("203.0.113.9:41641");
        paths.update_netmap_endpoints(&[target], start);
        paths.begin_ping([1; 12], direct("203.0.113.9:41641", 0, 0), start);

        let outcome = paths
            .record_pong(
                [1; 12],
                target,
                endpoint("198.51.100.1:50000"),
                false,
                start + Duration::from_millis(20),
            )
            .unwrap();
        assert!(outcome.became_best);
        assert_eq!(
            outcome.best.unwrap().wire_mtu,
            TAILSCALE_PATH_SAFE_WIRE_MTU
        );
        assert_eq!(
            paths.send_path(start + Duration::from_secs(1)),
            TailscaleSendPath {
                udp: paths.best().cloned(),
                derp_region: None,
            }
        );
        assert_eq!(
            paths.send_path(
                start
                    + Duration::from_millis(20)
                    + TAILSCALE_PATH_TRUST_DURATION,
            ),
            TailscaleSendPath {
                udp: paths.best().cloned(),
                derp_region: Some(12),
            }
        );
    }

    #[test]
    fn derp_pong_never_promotes_a_udp_path() {
        let now = Instant::now();
        let mut paths = TailscalePeerPathState::new(Some(3));
        let derp = endpoint("127.3.3.40:3");
        paths.begin_ping([2; 12], direct("203.0.113.2:41641", 0, 0), now);
        let outcome = paths
            .record_pong(
                [2; 12],
                derp,
                derp,
                true,
                now + Duration::from_millis(10),
            )
            .unwrap();
        assert_eq!(outcome.best, None);
        assert_eq!(paths.send_path(now).derp_region, Some(3));
    }

    #[test]
    fn call_me_maybe_replaces_candidates_and_forces_fresh_pings() {
        let now = Instant::now();
        let first = endpoint("198.51.100.1:41641");
        let second = endpoint("198.51.100.2:41641");
        let link_local = endpoint("[fe80::1]:41641");
        let mut paths = TailscalePeerPathState::new(Some(1));

        assert_eq!(
            paths.handle_call_me_maybe(&[first, link_local], now),
            vec![first]
        );
        assert!(paths.discovery_candidates(now).is_empty());
        assert_eq!(
            paths.handle_call_me_maybe(&[second], now + Duration::from_secs(1)),
            vec![second]
        );
        assert_eq!(
            paths
                .endpoint_snapshots()
                .into_iter()
                .map(|snapshot| snapshot.endpoint)
                .collect::<Vec<_>>(),
            vec![second]
        );
    }

    #[test]
    fn runtime_candidates_deduplicate_and_expire_like_magicsock() {
        let now = Instant::now();
        let dynamic = endpoint("198.51.100.3:41641");
        let mut paths = TailscalePeerPathState::new(None);
        assert!(!paths.add_candidate_endpoint(dynamic, [3; 12], now));
        assert!(paths.add_candidate_endpoint(dynamic, [3; 12], now));
        assert!(!paths.add_candidate_endpoint(dynamic, [4; 12], now));
        assert_eq!(paths.endpoint_snapshots().len(), 1);

        paths.update_netmap_endpoints(
            &[],
            now + TAILSCALE_PATH_SESSION_ACTIVE_TIMEOUT
                + Duration::from_nanos(1),
        );
        assert!(paths.endpoint_snapshots().is_empty());
    }

    #[test]
    fn ping_timeout_and_full_probe_policy_match_upstream_windows() {
        let now = Instant::now();
        let target = endpoint("198.51.100.4:41641");
        let mut paths = TailscalePeerPathState::new(Some(2));
        paths.update_netmap_endpoints(&[target], now);
        assert!(paths.wants_full_ping(now));
        assert_eq!(paths.discovery_candidates(now), vec![target]);
        assert!(
            paths
                .discovery_candidates(now + Duration::from_secs(4))
                .is_empty()
        );

        paths.begin_ping([5; 12], direct("198.51.100.4:41641", 0, 1_360), now);
        assert!(paths.expire_pings(now + Duration::from_secs(4)).is_empty());
        assert_eq!(
            paths.expire_pings(now + TAILSCALE_PATH_PING_TIMEOUT),
            vec![[5; 12]]
        );
    }

    #[test]
    fn connectivity_change_preserves_sources_but_clears_quality() {
        let now = Instant::now();
        let target = endpoint("10.0.0.1:41641");
        let mut paths = TailscalePeerPathState::new(Some(1));
        paths.update_netmap_endpoints(&[target], now);
        paths.begin_ping([6; 12], direct("10.0.0.1:41641", 0, 1_360), now);
        paths
            .record_pong(
                [6; 12],
                target,
                target,
                false,
                now + Duration::from_millis(2),
            )
            .unwrap();
        assert!(paths.best().is_some());

        paths.note_connectivity_change();
        assert!(paths.best().is_none());
        assert_eq!(paths.endpoint_snapshots().len(), 1);
        assert_eq!(paths.endpoint_snapshots()[0].latest_pong, None);
    }
}
