use std::{collections::HashSet, net::IpAddr, time::Duration};

use super::{
    OpenVpnIpPrefix, PushOptionsKind, PushedAddress, PushedLocalAddress,
    PushedOptionParseError, PushedOptions, PushedRouteEntry, TunnelDnsServer,
    filter_openvpn_non_dns_dhcp_options,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRoute {
    pub prefix: OpenVpnIpPrefix,
    pub gateway: Option<IpAddr>,
    pub metric: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TunnelConfiguration {
    pub dev_type: String,
    pub topology: String,
    pub tun_mtu: u32,
    pub local_ipv4: Vec<OpenVpnIpPrefix>,
    pub local_ipv6: Vec<OpenVpnIpPrefix>,
    pub vpn_gateway: Option<IpAddr>,
    pub vpn_gateway_ipv6: Option<IpAddr>,
    pub ipv4_routes: Vec<TunnelRoute>,
    pub ipv6_routes: Vec<TunnelRoute>,
    pub excluded_ipv4_routes: Vec<TunnelRoute>,
    pub excluded_ipv6_routes: Vec<TunnelRoute>,
    pub dns: Vec<IpAddr>,
    pub dns_servers: Vec<TunnelDnsServer>,
    pub dhcp_options: Vec<String>,
    pub search_domains: Vec<String>,
    pub dns_routes: Vec<String>,
    pub block_ipv6: bool,
    pub block_outside_dns: bool,
    pub redirect_gateway: bool,
    pub redirect_gateway_flags: Vec<String>,
    pub redirect_private: bool,
    pub route_metric: i32,
    pub route_gateway: Option<IpAddr>,
    pub ping_interval: Duration,
    pub ping_restart: Duration,
    pub auth_token: String,
    pub auth_token_user: String,
    pub explicit_exit_notify: u32,
    pub peer_id: Option<u32>,
    pub selected_cipher: String,
    pub selected_auth: String,
    pub protocol_flags: Vec<String>,
    pub key_derivation: String,
    pub inactive_timeout: Duration,
    pub inactive_minimum_bytes: u64,
    pub session_timeout: Duration,
    pub ping_exit: Duration,
    pub ping_timer_remote: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelConfigurationEventReason {
    Initial,
    PushUpdate,
    Renegotiation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedOptionsApplyResult {
    pub reason: TunnelConfigurationEventReason,
    pub configuration: TunnelConfiguration,
    pub pull_filter_rejection: String,
    pub parse_errors: Vec<PushedOptionParseError>,
}

#[derive(Debug, Clone)]
pub struct ClientTunnelState {
    configuration: TunnelConfiguration,
    route_no_pull: bool,
    pulled_options_received: bool,
    modern_dns_configured: bool,
    modern_search_domains: Vec<String>,
    pull_filter_rejection: String,
}

impl ClientTunnelState {
    pub fn new(
        configuration: TunnelConfiguration,
        route_no_pull: bool,
    ) -> Self {
        Self {
            configuration,
            route_no_pull,
            pulled_options_received: false,
            modern_dns_configured: false,
            modern_search_domains: Vec::new(),
            pull_filter_rejection: String::new(),
        }
    }

    pub fn configuration(&self) -> TunnelConfiguration {
        self.configuration.clone()
    }

    pub fn pull_filter_rejection(&self) -> &str {
        &self.pull_filter_rejection
    }

    pub fn apply_pushed_options(
        &mut self,
        options: &PushedOptions,
    ) -> PushedOptionsApplyResult {
        self.pull_filter_rejection = options.pull_filter_rejection.clone();
        let initial = !self.pulled_options_received;
        let reason = if options.kind == PushOptionsKind::Update {
            TunnelConfigurationEventReason::PushUpdate
        } else if initial {
            TunnelConfigurationEventReason::Initial
        } else {
            TunnelConfigurationEventReason::Renegotiation
        };
        self.pulled_options_received = true;
        let mut configuration = self.configuration.clone();
        append_unique_strings(
            &mut self.modern_search_domains,
            &options.modern_search_domains,
        );

        if options.ping_restart_enabled != options.ping_exit_set {
            if options.ping_restart_enabled {
                configuration.ping_exit = Duration::ZERO;
            } else {
                configuration.ping_restart = Duration::ZERO;
            }
        }
        if !options.topology.is_empty() {
            configuration.topology.clone_from(&options.topology);
        }
        replace_local_family(
            &mut configuration.local_ipv4,
            &mut configuration.vpn_gateway,
            &local_addresses_by_family(&options.local_address, true),
        );
        replace_local_family(
            &mut configuration.local_ipv6,
            &mut configuration.vpn_gateway_ipv6,
            &local_addresses_by_family(&options.local_address, false),
        );
        if options.tun_mtu > 0 {
            configuration.tun_mtu = options.tun_mtu;
        }

        if !self.route_no_pull {
            if options.modern_dns && !self.modern_dns_configured {
                configuration.dns.clear();
                configuration
                    .search_domains
                    .clone_from(&self.modern_search_domains);
                configuration.dns_routes.clear();
                configuration.dhcp_options =
                    filter_openvpn_non_dns_dhcp_options(
                        &configuration.dhcp_options,
                    );
                self.modern_dns_configured = true;
            }
            if self.modern_dns_configured {
                append_unique_addresses(
                    &mut configuration.dns,
                    &pushed_addresses(&options.modern_dns_addresses),
                );
                merge_tunnel_dns_servers(
                    &mut configuration.dns_servers,
                    &options.dns_servers,
                );
                append_unique_strings(
                    &mut configuration.search_domains,
                    &options.modern_search_domains,
                );
                append_unique_strings(
                    &mut configuration.dhcp_options,
                    &filter_openvpn_non_dns_dhcp_options(&options.dhcp_options),
                );
            } else {
                append_unique_addresses(
                    &mut configuration.dns,
                    &pushed_addresses(&options.dns),
                );
                append_unique_strings(
                    &mut configuration.dhcp_options,
                    &options.dhcp_options,
                );
                append_unique_strings(
                    &mut configuration.search_domains,
                    &options.search_domains,
                );
                append_unique_strings(
                    &mut configuration.dns_routes,
                    &options.dns_routes,
                );
            }
            configuration.block_ipv6 |= options.block_ipv6;
            configuration.block_outside_dns |= options.block_outside_dns;
            if options.route_metric_set {
                configuration.route_metric = options.route_metric;
            }
        }

        if options.ping_interval_enabled {
            configuration.ping_interval = options.ping_interval;
        }
        if options.ping_restart_enabled {
            configuration.ping_restart = options.ping_restart;
        }
        if !options.auth_token.is_empty() {
            configuration.auth_token.clone_from(&options.auth_token);
        }
        if !options.auth_token_user.is_empty() {
            configuration
                .auth_token_user
                .clone_from(&options.auth_token_user);
        }
        if options.explicit_exit_notify_set {
            configuration.explicit_exit_notify = options.explicit_exit_notify;
        }
        if options.peer_id.is_some() {
            configuration.peer_id = options.peer_id;
        }
        replace_nonempty(
            &mut configuration.selected_cipher,
            &options.selected_cipher,
        );
        replace_nonempty(
            &mut configuration.selected_auth,
            &options.selected_auth,
        );
        if !options.protocol_flags.is_empty() {
            configuration
                .protocol_flags
                .clone_from(&options.protocol_flags);
        }
        replace_nonempty(
            &mut configuration.key_derivation,
            &options.key_derivation,
        );
        if options.inactive_timeout_set {
            configuration.inactive_timeout = options.inactive_timeout;
            configuration.inactive_minimum_bytes =
                options.inactive_minimum_bytes;
        }
        if options.session_timeout_set {
            configuration.session_timeout = options.session_timeout;
        }
        if options.ping_exit_set {
            configuration.ping_exit = options.ping_exit;
        }
        configuration.ping_timer_remote |= options.ping_timer_remote;

        let mut parse_errors = options.parse_errors.clone();
        if options.route_gateway.is_some() || options.route_gateway_vpn {
            let gateway = options.route_gateway.or_else(|| {
                (options.route_gateway_vpn
                    && !configuration
                        .topology
                        .trim()
                        .eq_ignore_ascii_case("subnet"))
                .then_some(configuration.vpn_gateway)
                .flatten()
            });
            if gateway.is_some() {
                configuration.route_gateway = gateway;
            } else {
                parse_errors.push(PushedOptionParseError {
                    name: "route-gateway".into(),
                    value: route_gateway_filter_value(options),
                    message: "invalid pushed route gateway".into(),
                });
            }
        }

        if !self.route_no_pull {
            let ipv4 = routes_by_family(&options.routes, true);
            let ipv6 = routes_by_family(&options.routes, false);
            append_unique_tunnel_routes(
                &mut configuration.ipv4_routes,
                &pushed_tunnel_routes(&ipv4, configuration.route_metric),
            );
            append_unique_tunnel_routes(
                &mut configuration.ipv6_routes,
                &pushed_tunnel_routes(&ipv6, configuration.route_metric),
            );
            for excluded in &options.excluded_routes {
                let route = TunnelRoute {
                    prefix: excluded.route.prefix.masked(),
                    gateway: excluded.route.gateway,
                    metric: excluded.route.metric,
                };
                if route.prefix.address.is_ipv4() {
                    append_unique_tunnel_routes(
                        &mut configuration.excluded_ipv4_routes,
                        &[route],
                    );
                } else {
                    append_unique_tunnel_routes(
                        &mut configuration.excluded_ipv6_routes,
                        &[route],
                    );
                }
            }
            if options.redirect_gateway {
                configuration.redirect_gateway = true;
                configuration
                    .redirect_gateway_flags
                    .clone_from(&options.redirect_gateway_flags);
            }
            configuration.redirect_private |= options.redirect_private;
        }

        let ipv4_gateway = configuration
            .route_gateway
            .filter(IpAddr::is_ipv4)
            .or(configuration.vpn_gateway.filter(IpAddr::is_ipv4));
        fill_tunnel_route_gateways(
            &mut configuration.ipv4_routes,
            ipv4_gateway,
        );
        fill_tunnel_route_gateways(
            &mut configuration.ipv6_routes,
            configuration.vpn_gateway_ipv6.filter(IpAddr::is_ipv6),
        );

        self.configuration = configuration.clone();
        PushedOptionsApplyResult {
            reason,
            configuration,
            pull_filter_rejection: self.pull_filter_rejection.clone(),
            parse_errors,
        }
    }
}

pub fn route_no_pull_blocks_option(name: &str) -> bool {
    matches!(
        name,
        "route"
            | "route-ipv6"
            | "route-metric"
            | "redirect-gateway"
            | "redirect-private"
            | "dns"
            | "dhcp-option"
            | "block-ipv6"
            | "block-outside-dns"
    )
}

pub fn merge_tunnel_dns_servers(
    destination: &mut Vec<TunnelDnsServer>,
    servers: &[TunnelDnsServer],
) {
    for server in servers {
        if let Some(existing) = destination
            .iter_mut()
            .find(|existing| existing.priority == server.priority)
        {
            existing.clone_from(server);
        } else {
            destination.push(server.clone());
        }
    }
    destination.sort_by_key(|server| server.priority);
}

pub fn split_local_address_prefixes(
    values: &[OpenVpnIpPrefix],
) -> (Vec<OpenVpnIpPrefix>, Vec<OpenVpnIpPrefix>) {
    values
        .iter()
        .copied()
        .partition(|prefix| prefix.address.is_ipv4())
}

pub fn split_tunnel_routes(
    values: &[TunnelRoute],
    route_gateway: Option<IpAddr>,
    vpn_gateway: Option<IpAddr>,
    vpn_gateway_ipv6: Option<IpAddr>,
    route_metric: i32,
) -> (Vec<TunnelRoute>, Vec<TunnelRoute>) {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for value in values {
        let mut route = value.clone();
        route.prefix = route.prefix.masked();
        if route.metric == 0 {
            route.metric = route_metric;
        }
        if route.prefix.address.is_ipv4() {
            route.gateway = route.gateway.or(route_gateway).or(vpn_gateway);
            ipv4.push(route);
        } else {
            route.gateway = route.gateway.or(vpn_gateway_ipv6);
            ipv6.push(route);
        }
    }
    (ipv4, ipv6)
}

pub fn fill_tunnel_route_gateways(
    routes: &mut [TunnelRoute],
    gateway: Option<IpAddr>,
) {
    let Some(gateway) = gateway else {
        return;
    };
    for route in routes {
        if route.gateway.is_none()
            && route.prefix.address.is_ipv4() == gateway.is_ipv4()
        {
            route.gateway = Some(gateway);
        }
    }
}

fn replace_nonempty(destination: &mut String, value: &str) {
    if !value.is_empty() {
        destination.clear();
        destination.push_str(value);
    }
}

fn local_addresses_by_family(
    values: &[PushedLocalAddress],
    ipv4: bool,
) -> Vec<PushedLocalAddress> {
    values
        .iter()
        .filter(|value| value.prefix.address.is_ipv4() == ipv4)
        .cloned()
        .collect()
}

fn replace_local_family(
    prefixes: &mut Vec<OpenVpnIpPrefix>,
    vpn_gateway: &mut Option<IpAddr>,
    values: &[PushedLocalAddress],
) {
    if values.is_empty() {
        return;
    }
    prefixes.clear();
    *vpn_gateway = None;
    for value in values {
        if vpn_gateway.is_none() {
            *vpn_gateway = value.peer;
        }
        if !prefixes.contains(&value.prefix) {
            prefixes.push(value.prefix);
        }
    }
}

fn routes_by_family(
    values: &[PushedRouteEntry],
    ipv4: bool,
) -> Vec<PushedRouteEntry> {
    values
        .iter()
        .filter(|value| value.route.prefix.address.is_ipv4() == ipv4)
        .cloned()
        .collect()
}

fn pushed_addresses(values: &[PushedAddress]) -> Vec<IpAddr> {
    values.iter().map(|value| value.address).collect()
}

fn pushed_tunnel_routes(
    values: &[PushedRouteEntry],
    route_metric: i32,
) -> Vec<TunnelRoute> {
    values
        .iter()
        .map(|value| TunnelRoute {
            prefix: value.route.prefix.masked(),
            gateway: value.route.gateway,
            metric: if value.route.metric == 0 {
                route_metric
            } else {
                value.route.metric
            },
        })
        .collect()
}

fn append_unique_addresses(destination: &mut Vec<IpAddr>, values: &[IpAddr]) {
    for value in values {
        if !destination.contains(value) {
            destination.push(*value);
        }
    }
}

fn append_unique_strings(destination: &mut Vec<String>, values: &[String]) {
    let mut seen: HashSet<_> = destination.iter().cloned().collect();
    for value in values {
        if seen.insert(value.clone()) {
            destination.push(value.clone());
        }
    }
}

fn append_unique_tunnel_routes(
    destination: &mut Vec<TunnelRoute>,
    values: &[TunnelRoute],
) {
    for value in values {
        let mut value = value.clone();
        value.prefix = value.prefix.masked();
        if !destination.contains(&value) {
            destination.push(value);
        }
    }
}

fn route_gateway_filter_value(options: &PushedOptions) -> String {
    if !options.route_gateway_raw.is_empty() {
        options.route_gateway_raw.clone()
    } else if options.route_gateway_vpn {
        "vpn_gateway".into()
    } else {
        options
            .route_gateway
            .map(|address| address.to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::openvpn::decode_push_reply_payload_with_filters;

    fn prefix(value: &str, bits: u8) -> OpenVpnIpPrefix {
        OpenVpnIpPrefix {
            address: value.parse().unwrap(),
            prefix_len: bits,
        }
    }

    #[test]
    fn initial_push_replaces_addresses_and_fills_route_gateways() {
        let initial = TunnelConfiguration {
            local_ipv4: vec![prefix("192.0.2.2", 24)],
            route_metric: 3,
            ..TunnelConfiguration::default()
        };
        let (options, _) = decode_push_reply_payload_with_filters(
            b"PUSH_REPLY,topology net30,ifconfig 10.8.0.2 10.8.0.1,ifconfig-ipv6 fd00::2/64 fd00::1,route 10.9.1.5 255.255.255.0,route-ipv6 fd01::/64,route-metric 7,route-gateway vpn_gateway",
            None,
            &[],
        )
        .unwrap();
        let mut state = ClientTunnelState::new(initial, false);
        let result = state.apply_pushed_options(&options);
        assert_eq!(result.reason, TunnelConfigurationEventReason::Initial);
        assert_eq!(result.configuration.local_ipv4, [prefix("10.8.0.2", 30)]);
        assert_eq!(
            result.configuration.vpn_gateway,
            Some("10.8.0.1".parse().unwrap())
        );
        assert_eq!(
            result.configuration.route_gateway,
            Some("10.8.0.1".parse().unwrap())
        );
        assert_eq!(result.configuration.ipv4_routes[0].metric, 7);
        assert_eq!(
            result.configuration.ipv4_routes[0].gateway,
            Some("10.8.0.1".parse().unwrap())
        );
        assert_eq!(
            result.configuration.ipv6_routes[0].gateway,
            Some("fd00::1".parse().unwrap())
        );
        assert!(result.parse_errors.is_empty());
    }

    #[test]
    fn update_and_renegotiation_reasons_and_timer_exclusion_match() {
        let mut state =
            ClientTunnelState::new(TunnelConfiguration::default(), false);
        let (first, _) = decode_push_reply_payload_with_filters(
            b"PUSH_REPLY,ping-restart 30",
            None,
            &[],
        )
        .unwrap();
        assert_eq!(
            state.apply_pushed_options(&first).reason,
            TunnelConfigurationEventReason::Initial
        );
        let (second, _) = decode_push_reply_payload_with_filters(
            b"PUSH_REPLY,ping-exit 12",
            None,
            &[],
        )
        .unwrap();
        let result = state.apply_pushed_options(&second);
        assert_eq!(
            result.reason,
            TunnelConfigurationEventReason::Renegotiation
        );
        assert_eq!(result.configuration.ping_restart, Duration::ZERO);
        assert_eq!(result.configuration.ping_exit, Duration::from_secs(12));
        let (update, _) = decode_push_reply_payload_with_filters(
            b"PUSH_UPDATE,ping 5",
            None,
            &[],
        )
        .unwrap();
        assert_eq!(
            state.apply_pushed_options(&update).reason,
            TunnelConfigurationEventReason::PushUpdate
        );
    }

    #[test]
    fn modern_dns_transition_clears_legacy_state_and_merges_by_priority() {
        let initial = TunnelConfiguration {
            dns: vec!["8.8.8.8".parse().unwrap()],
            dhcp_options: vec!["DNS 8.8.8.8".into(), "WINS 192.0.2.1".into()],
            search_domains: vec!["legacy.example".into()],
            dns_routes: vec!["legacy.route".into()],
            ..TunnelConfiguration::default()
        };
        let mut state = ClientTunnelState::new(initial, false);
        let (legacy, _) = decode_push_reply_payload_with_filters(
            b"PUSH_REPLY,dhcp-option DOMAIN accumulated.example",
            None,
            &[],
        )
        .unwrap();
        state.apply_pushed_options(&legacy);
        let (modern, _) = decode_push_reply_payload_with_filters(
            b"PUSH_UPDATE,dns search-domains modern.example,dns server 7 address 1.1.1.1,dns server 2 address 9.9.9.9",
            None,
            &[],
        )
        .unwrap();
        let result = state.apply_pushed_options(&modern);
        assert_eq!(
            result.configuration.dns,
            [
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "9.9.9.9".parse().unwrap()
            ]
        );
        assert_eq!(result.configuration.search_domains, ["modern.example"]);
        assert!(result.configuration.dns_routes.is_empty());
        assert_eq!(result.configuration.dhcp_options, ["WINS 192.0.2.1"]);
        assert_eq!(result.configuration.dns_servers[0].priority, 2);
    }

    #[test]
    fn route_no_pull_still_applies_link_crypto_auth_and_timers() {
        let mut state =
            ClientTunnelState::new(TunnelConfiguration::default(), true);
        let (options, _) = decode_push_reply_payload_with_filters(
            b"PUSH_REPLY,ifconfig 10.8.0.2 10.8.0.1,route 10.9.0.0 255.255.0.0,dhcp-option DNS 1.1.1.1,redirect-gateway,block-ipv6,route-metric 9,ping 5,cipher AES-256-GCM,auth-token token",
            None,
            &[],
        )
        .unwrap();
        let result = state.apply_pushed_options(&options);
        assert_eq!(result.configuration.local_ipv4.len(), 1);
        assert!(result.configuration.ipv4_routes.is_empty());
        assert!(result.configuration.dns.is_empty());
        assert!(!result.configuration.redirect_gateway);
        assert!(!result.configuration.block_ipv6);
        assert_eq!(result.configuration.route_metric, 0);
        assert_eq!(result.configuration.ping_interval, Duration::from_secs(5));
        assert_eq!(result.configuration.selected_cipher, "AES-256-GCM");
        assert_eq!(result.configuration.auth_token, "token");
        assert!(route_no_pull_blocks_option("dns"));
        assert!(!route_no_pull_blocks_option("ifconfig"));
    }

    #[test]
    fn subnet_vpn_gateway_token_is_reported_as_invalid() {
        let mut state = ClientTunnelState::new(
            TunnelConfiguration {
                topology: "subnet".into(),
                vpn_gateway: Some("10.8.0.1".parse().unwrap()),
                ..TunnelConfiguration::default()
            },
            false,
        );
        let (options, _) = decode_push_reply_payload_with_filters(
            b"PUSH_REPLY,route-gateway vpn_gateway",
            None,
            &[],
        )
        .unwrap();
        let result = state.apply_pushed_options(&options);
        assert!(result.configuration.route_gateway.is_none());
        assert_eq!(result.parse_errors.len(), 1);
    }

    #[test]
    fn split_routes_applies_family_gateway_and_default_metric() {
        let routes = [
            TunnelRoute {
                prefix: prefix("10.2.1.7", 16),
                gateway: None,
                metric: 0,
            },
            TunnelRoute {
                prefix: prefix("fd00::123", 64),
                gateway: None,
                metric: 4,
            },
        ];
        let (ipv4, ipv6) = split_tunnel_routes(
            &routes,
            Some("10.8.0.1".parse().unwrap()),
            None,
            Some("fd00::1".parse().unwrap()),
            9,
        );
        assert_eq!(
            ipv4[0].prefix.address,
            "10.2.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(ipv4[0].metric, 9);
        assert_eq!(ipv4[0].gateway, Some("10.8.0.1".parse().unwrap()));
        assert_eq!(ipv6[0].gateway, Some("fd00::1".parse().unwrap()));
    }
}
