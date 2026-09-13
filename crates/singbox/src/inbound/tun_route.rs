//! Deterministic route planning shared by the platform TUN backends.
//!
//! This mirrors `sing-tun.Options.BuildAutoRouteRanges`.  It intentionally
//! contains no privileged operating-system operations, so callers can inspect
//! the exact route mutation before applying it.

use std::{fmt, io, net::IpAddr};

use async_trait::async_trait;
use ipnet::IpNet;

use crate::option::TunInboundOptions;

/// Platform behavior that affects automatic TUN route construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunRoutePlatform {
    Darwin,
    Linux,
    Windows,
    Other,
}

impl TunRoutePlatform {
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            Self::Darwin
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

/// The routes which a TUN platform backend must install, in upstream order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunRoutePlan {
    routes: Vec<IpNet>,
}

impl TunRoutePlan {
    /// Build a plan from protocol-owned routes.
    ///
    /// VPN endpoint system interfaces receive their routes from the protocol
    /// negotiation or peer configuration rather than `TunInboundOptions`.
    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ))]
    pub(crate) fn from_routes(routes: Vec<IpNet>) -> Self {
        // Multiple WireGuard/Tailscale peers can advertise the same prefix.
        // Installing an identical route twice is rejected by some platform
        // backends, while sing-tun treats the route set as idempotent.
        let mut seen = std::collections::HashSet::new();
        Self {
            routes: routes
                .into_iter()
                .filter(|route| seen.insert(*route))
                .collect(),
        }
    }

    /// Build a plan with the same family gating and exclusions as sing-tun.
    ///
    /// `under_network_extension` only changes Darwin's default-route
    /// workaround. Native macOS uses eight sub-ranges which omit the first
    /// `/8`; Apple NetworkExtension mode can install a real default route.
    pub fn from_options(
        options: &TunInboundOptions,
        platform: TunRoutePlatform,
        under_network_extension: bool,
    ) -> Result<Self, TunRoutePlanError> {
        if !options.route_address_set.as_slice().is_empty()
            || !options.route_exclude_address_set.as_slice().is_empty()
        {
            return Err(TunRoutePlanError::UnresolvedRuleSet);
        }

        Ok(Self::from_options_with_resolved_rule_sets(
            options,
            platform,
            under_network_extension,
            &[],
            &[],
        ))
    }

    pub(crate) fn from_options_with_resolved_rule_sets(
        options: &TunInboundOptions,
        platform: TunRoutePlatform,
        under_network_extension: bool,
        route_set_includes: &[IpNet],
        route_set_excludes: &[IpNet],
    ) -> Self {
        let addresses = options
            .address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        let mut includes = options
            .route_address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        includes.extend_from_slice(route_set_includes);
        let mut excludes = options
            .route_exclude_address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        excludes.extend_from_slice(route_set_excludes);

        let mut routes = Vec::new();
        routes.extend(build_family(
            false,
            &addresses,
            &includes,
            &excludes,
            options.auto_route,
            platform,
            under_network_extension,
        ));
        routes.extend(build_family(
            true,
            &addresses,
            &includes,
            &excludes,
            options.auto_route,
            platform,
            under_network_extension,
        ));
        Self { routes }
    }

    /// Build the effective nftables redirect range used by sing-tun.
    ///
    /// Unlike kernel auto-route planning, an explicit route-address filter and
    /// a dynamic route-address rule-set are applied sequentially, so their
    /// effective range is the intersection. Both exclude sources are then
    /// subtracted. Auto-redirect requires `auto_route`, therefore an address
    /// family with no include filter starts at its default route.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn from_auto_redirect_options_with_resolved_rule_sets(
        options: &TunInboundOptions,
        route_set_includes: &[IpNet],
        route_set_excludes: &[IpNet],
    ) -> Self {
        let addresses = options
            .address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        let explicit_includes = options
            .route_address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        let mut excludes = options
            .route_exclude_address
            .as_slice()
            .iter()
            .map(|prefix| prefix.0)
            .collect::<Vec<_>>();
        excludes.extend_from_slice(route_set_excludes);

        let mut routes = Vec::new();
        routes.extend(build_auto_redirect_family(
            false,
            &addresses,
            &explicit_includes,
            route_set_includes,
            &excludes,
        ));
        routes.extend(build_auto_redirect_family(
            true,
            &addresses,
            &explicit_includes,
            route_set_includes,
            &excludes,
        ));
        Self { routes }
    }

    pub fn routes(&self) -> &[IpNet] {
        &self.routes
    }

    pub fn into_routes(self) -> Vec<IpNet> {
        self.routes
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        self.routes.iter().any(|route| route.contains(&address))
    }
}

#[cfg(any(target_os = "linux", test))]
fn build_auto_redirect_family(
    ipv6: bool,
    addresses: &[IpNet],
    explicit_includes: &[IpNet],
    rule_set_includes: &[IpNet],
    excludes: &[IpNet],
) -> Vec<IpNet> {
    if !addresses
        .iter()
        .any(|network| network.addr().is_ipv6() == ipv6)
    {
        return Vec::new();
    }
    let explicit = explicit_includes
        .iter()
        .copied()
        .filter(|network| network.addr().is_ipv6() == ipv6)
        .collect::<Vec<_>>();
    let dynamic = rule_set_includes
        .iter()
        .copied()
        .filter(|network| network.addr().is_ipv6() == ipv6)
        .collect::<Vec<_>>();
    let mut routes = match (explicit.is_empty(), dynamic.is_empty()) {
        (true, true) => default_routes(ipv6, TunRoutePlatform::Linux, false),
        (false, true) => explicit,
        (true, false) => dynamic,
        (false, false) => explicit
            .into_iter()
            .flat_map(|left| {
                dynamic.iter().filter_map(move |right| {
                    if left.contains(right) {
                        Some(*right)
                    } else if right.contains(&left) {
                        Some(left)
                    } else {
                        None
                    }
                })
            })
            .collect(),
    };
    for excluded in excludes
        .iter()
        .copied()
        .filter(|network| network.addr().is_ipv6() == ipv6)
    {
        routes = routes
            .into_iter()
            .flat_map(|route| subtract(route, excluded))
            .collect();
    }
    IpNet::aggregate(&routes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TunRoutePlanError {
    #[error(
        "TUN route_address_set/route_exclude_address_set must be resolved before route planning"
    )]
    UnresolvedRuleSet,
}

fn build_family(
    ipv6: bool,
    addresses: &[IpNet],
    includes: &[IpNet],
    excludes: &[IpNet],
    auto_route: bool,
    platform: TunRoutePlatform,
    under_network_extension: bool,
) -> Vec<IpNet> {
    let assigned = addresses
        .iter()
        .copied()
        .filter(|network| network.addr().is_ipv6() == ipv6)
        .collect::<Vec<_>>();
    if assigned.is_empty() {
        return Vec::new();
    }

    let explicit = includes
        .iter()
        .copied()
        .filter(|network| network.addr().is_ipv6() == ipv6)
        .collect::<Vec<_>>();
    let has_explicit = !explicit.is_empty();
    let mut family_routes = if has_explicit {
        explicit
    } else if auto_route {
        default_routes(ipv6, platform, under_network_extension)
    } else {
        Vec::new()
    };

    // Preserve the pinned sing-tun behavior exactly, including its `< 32`
    // threshold for both address families.
    if platform == TunRoutePlatform::Darwin && (has_explicit || !auto_route) {
        family_routes.extend(
            assigned
                .iter()
                .filter(|network| network.prefix_len() < 32)
                .map(IpNet::trunc),
        );
    }

    let family_excludes = excludes
        .iter()
        .filter(|network| network.addr().is_ipv6() == ipv6)
        .copied()
        .collect::<Vec<_>>();
    for excluded in &family_excludes {
        family_routes = family_routes
            .into_iter()
            .flat_map(|route| subtract(route, *excluded))
            .collect();
    }
    if !family_excludes.is_empty() {
        family_routes = IpNet::aggregate(&family_routes);
    }
    family_routes
}

fn default_routes(
    ipv6: bool,
    platform: TunRoutePlatform,
    under_network_extension: bool,
) -> Vec<IpNet> {
    if platform != TunRoutePlatform::Darwin || under_network_extension {
        return vec![if ipv6 {
            "::/0".parse().expect("valid IPv6 default route")
        } else {
            "0.0.0.0/0".parse().expect("valid IPv4 default route")
        }];
    }
    let prefixes = [8_u8, 7, 6, 5, 4, 3, 2, 1];
    prefixes
        .into_iter()
        .enumerate()
        .map(|(index, prefix)| {
            let first = 1_u8 << index;
            if ipv6 {
                let mut octets = [0_u8; 16];
                octets[0] = first;
                IpNet::new(IpAddr::from(octets), prefix)
            } else {
                IpNet::new(IpAddr::from([first, 0_u8, 0_u8, 0_u8]), prefix)
            }
            .expect("valid Darwin automatic route")
        })
        .collect()
}

fn subtract(route: IpNet, excluded: IpNet) -> Vec<IpNet> {
    if route.addr().is_ipv6() != excluded.addr().is_ipv6()
        || (!route.contains(&excluded) && !excluded.contains(&route))
    {
        return vec![route];
    }
    if excluded.contains(&route) {
        return Vec::new();
    }

    let next_prefix = route
        .prefix_len()
        .checked_add(1)
        .expect("a containing route cannot already be a host prefix");
    route
        .subnets(next_prefix)
        .expect("one-bit subnet split is valid")
        .flat_map(|child| subtract(child, excluded))
        .collect()
}

/// Route mutation seam used by native platform implementations.
#[async_trait]
pub trait TunRouteBackend: Send {
    async fn add_route(&mut self, route: IpNet) -> io::Result<()>;
    async fn remove_route(&mut self, route: IpNet) -> io::Result<()>;
}

/// Owns routes installed by one TUN instance and removes them in reverse order.
pub struct TunRouteLease<B> {
    backend: B,
    installed: Vec<IpNet>,
}

impl<B> fmt::Debug for TunRouteLease<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunRouteLease")
            .field("installed", &self.installed)
            .finish_non_exhaustive()
    }
}

impl<B: TunRouteBackend> TunRouteLease<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            installed: Vec::new(),
        }
    }

    pub fn installed(&self) -> &[IpNet] {
        &self.installed
    }

    pub async fn install(&mut self, plan: &TunRoutePlan) -> io::Result<()> {
        if !self.installed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "TUN route lease is already installed",
            ));
        }
        for route in plan.routes().iter().copied() {
            if let Err(error) = self.backend.add_route(route).await {
                let rollback = self.remove_all().await.err();
                let mut message = format!("add TUN route {route}: {error}");
                if let Some(rollback) = rollback {
                    message.push_str(&format!("; rollback: {rollback}"));
                }
                return Err(io::Error::new(error.kind(), message));
            }
            self.installed.push(route);
        }
        Ok(())
    }

    pub async fn close(&mut self) -> io::Result<()> {
        self.remove_all().await
    }

    async fn remove_all(&mut self) -> io::Result<()> {
        let mut failures = Vec::new();
        while let Some(route) = self.installed.pop() {
            if let Err(error) = self.backend.remove_route(route).await {
                failures.push(format!("remove TUN route {route}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        io,
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use ipnet::IpNet;
    use serde_json::json;

    use super::{
        TunRouteBackend, TunRouteLease, TunRoutePlan, TunRoutePlatform,
    };
    use crate::option::TunInboundOptions;

    fn options(value: serde_json::Value) -> TunInboundOptions {
        serde_json::from_value(value).unwrap()
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ))]
    #[test]
    fn endpoint_route_plan_deduplicates_peer_prefixes() {
        let default: IpNet = "0.0.0.0/0".parse().unwrap();
        let subnet: IpNet = "10.0.0.0/8".parse().unwrap();
        let plan = TunRoutePlan::from_routes(vec![default, subnet, default]);
        assert_eq!(plan.routes(), &[default, subnet]);
    }

    #[test]
    fn linux_dual_stack_auto_route_uses_default_routes() {
        let options = options(json!({
            "address": ["0.14.0.1/30", "fdfe:dcba::1/126"],
            "auto_route": true
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Linux,
            false,
        )
        .unwrap();
        assert_eq!(
            plan.routes(),
            &["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
        );
    }

    #[test]
    fn darwin_native_auto_route_matches_sing_tun_subranges() {
        let options = options(json!({
            "address": ["10.14.0.1/30", "fdfe:dcba::1/126"],
            "auto_route": true
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Darwin,
            false,
        )
        .unwrap();
        assert_eq!(plan.routes().len(), 16);
        assert!(!plan.contains("0.1.2.3".parse().unwrap()));
        assert!(!plan.contains("0.14.0.1".parse().unwrap()));
        assert!(!plan.contains("::1".parse().unwrap()));
        assert!(plan.contains("1.0.0.1".parse().unwrap()));
        assert!(plan.contains("100::1".parse().unwrap()));
        assert_eq!(plan.routes()[0], "1.0.0.0/8".parse().unwrap());
        assert_eq!(plan.routes()[7], "128.0.0.0/1".parse().unwrap());
        assert_eq!(plan.routes()[8], "100::/8".parse().unwrap());
        assert_eq!(plan.routes()[15], "8000::/1".parse().unwrap());
    }

    #[test]
    fn exclusions_are_subtracted_into_minimal_disjoint_routes() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "auto_route": true,
            "route_exclude_address": ["10.0.0.0/8", "192.168.0.0/16"]
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Linux,
            false,
        )
        .unwrap();
        assert!(!plan.contains("10.1.2.3".parse().unwrap()));
        assert!(!plan.contains("192.168.1.1".parse().unwrap()));
        assert!(plan.contains("8.8.8.8".parse().unwrap()));
        assert!(plan.contains("11.0.0.1".parse().unwrap()));

        for (index, route) in plan.routes().iter().enumerate() {
            for other in &plan.routes()[index + 1..] {
                assert!(!route.contains(other));
                assert!(!other.contains(route));
            }
        }
        let unique = plan.routes().iter().collect::<HashSet<_>>();
        assert_eq!(unique.len(), plan.routes().len());
    }

    #[test]
    fn explicit_routes_are_family_gated_by_tun_addresses() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "route_address": ["203.0.113.0/24", "2001:db8::/32"]
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Linux,
            false,
        )
        .unwrap();
        assert_eq!(plan.routes(), &["203.0.113.0/24".parse().unwrap()]);
    }

    #[test]
    fn darwin_keeps_upstream_assigned_subnet_threshold() {
        let options = options(json!({
            "address": ["10.14.0.9/30", "fdfe:dcba::1/16"]
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Darwin,
            false,
        )
        .unwrap();
        assert_eq!(
            plan.routes(),
            &[
                "10.14.0.8/30".parse().unwrap(),
                "fdfe::/16".parse().unwrap()
            ]
        );
    }

    #[test]
    fn rule_set_routes_require_resolution() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "auto_route": true,
            "route_exclude_address_set": "private"
        }));
        let error = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Linux,
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must be resolved"));
    }

    #[test]
    fn resolved_rule_set_prefixes_join_explicit_routes_and_exclusions() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "route_address": "172.16.0.0/12",
            "route_address_set": "included",
            "route_exclude_address_set": "excluded"
        }));
        let includes = ["10.0.0.0/8".parse().unwrap()];
        let excludes = ["10.1.0.0/16".parse().unwrap()];
        let plan = TunRoutePlan::from_options_with_resolved_rule_sets(
            &options,
            TunRoutePlatform::Linux,
            false,
            &includes,
            &excludes,
        );
        assert!(plan.contains("10.0.0.1".parse().unwrap()));
        assert!(!plan.contains("10.1.0.1".parse().unwrap()));
        assert!(plan.contains("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn auto_redirect_intersects_explicit_and_dynamic_includes() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "auto_route": true,
            "route_address": "10.0.0.0/8",
            "route_exclude_address": "10.20.30.0/24",
            "route_address_set": "included",
            "route_exclude_address_set": "excluded"
        }));
        let includes = [
            "10.20.0.0/16".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
        ];
        let excludes = ["10.20.40.0/24".parse().unwrap()];
        let plan =
            TunRoutePlan::from_auto_redirect_options_with_resolved_rule_sets(
                &options, &includes, &excludes,
            );
        assert!(plan.contains("10.20.1.1".parse().unwrap()));
        assert!(!plan.contains("10.21.1.1".parse().unwrap()));
        assert!(!plan.contains("172.16.1.1".parse().unwrap()));
        assert!(!plan.contains("10.20.30.1".parse().unwrap()));
        assert!(!plan.contains("10.20.40.1".parse().unwrap()));
    }

    #[derive(Clone)]
    struct MockBackend {
        events: Arc<Mutex<Vec<String>>>,
        fail_add: Option<IpNet>,
    }

    #[async_trait]
    impl TunRouteBackend for MockBackend {
        async fn add_route(&mut self, route: IpNet) -> io::Result<()> {
            self.events.lock().unwrap().push(format!("add {route}"));
            if self.fail_add == Some(route) {
                Err(io::Error::other("synthetic add failure"))
            } else {
                Ok(())
            }
        }

        async fn remove_route(&mut self, route: IpNet) -> io::Result<()> {
            self.events.lock().unwrap().push(format!("remove {route}"));
            Ok(())
        }
    }

    #[tokio::test]
    async fn install_failure_rolls_back_in_reverse_order() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "route_address": [
                "198.51.100.0/24",
                "203.0.113.0/24",
                "192.0.2.0/24"
            ]
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Linux,
            false,
        )
        .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut lease = TunRouteLease::new(MockBackend {
            events: events.clone(),
            fail_add: Some("203.0.113.0/24".parse().unwrap()),
        });
        let error = lease.install(&plan).await.unwrap_err();
        assert!(error.to_string().contains("synthetic add failure"));
        assert!(lease.installed().is_empty());
        assert_eq!(
            *events.lock().unwrap(),
            [
                "add 198.51.100.0/24",
                "add 203.0.113.0/24",
                "remove 198.51.100.0/24"
            ]
        );
    }

    #[tokio::test]
    async fn close_is_reverse_ordered_and_idempotent() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "route_address": ["198.51.100.0/24", "192.0.2.0/24"]
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Linux,
            false,
        )
        .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut lease = TunRouteLease::new(MockBackend {
            events: events.clone(),
            fail_add: None,
        });
        lease.install(&plan).await.unwrap();
        lease.close().await.unwrap();
        lease.close().await.unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                "add 198.51.100.0/24",
                "add 192.0.2.0/24",
                "remove 192.0.2.0/24",
                "remove 198.51.100.0/24"
            ]
        );
    }

    #[test]
    fn contains_accepts_ip_addresses() {
        let options = options(json!({
            "address": "10.14.0.1/30",
            "route_address": "203.0.113.0/24"
        }));
        let plan = TunRoutePlan::from_options(
            &options,
            TunRoutePlatform::Other,
            false,
        )
        .unwrap();
        assert!(plan.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
    }
}
