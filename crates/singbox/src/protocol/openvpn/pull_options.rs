use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use super::{
    OpenVpnIpPrefix, PushedRoute, parse_ifconfig_ipv6, parse_ifconfig_prefix,
    parse_ifconfig_vpn_gateway, parse_pushed_route, parse_pushed_route_ipv6,
};

pub const PUSH_REQUEST_PAYLOAD: &str = "PUSH_REQUEST";
pub const LEGACY_PULL_REQUEST_PAYLOAD: &str = "PULL_REQUEST";
pub const PUSH_REPLY_PAYLOAD_PREFIX: &str = "PUSH_REPLY";
pub const PUSH_UPDATE_PAYLOAD_PREFIX: &str = "PUSH_UPDATE";
pub const PUSHED_OPTION_LINE_MAX_PARAMETERS: usize = 16;
pub const PEER_ID_MAX_VALUE: u32 = (1 << 24) - 1;
pub const MAX_TUNNEL_DNS_SERVER_ADDRESSES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOptionsKind {
    Reply,
    Update,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullFilter {
    pub action: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedOptionParseError {
    pub name: String,
    pub value: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedExcludedRoute {
    pub name: String,
    pub value: String,
    pub route: PushedRoute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedLocalAddress {
    pub prefix: OpenVpnIpPrefix,
    pub peer: Option<IpAddr>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedRouteEntry {
    pub route: PushedRoute,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedAddress {
    pub address: IpAddr,
    pub raw: String,
    pub option_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelDnsServer {
    pub priority: i32,
    pub addresses: Vec<SocketAddr>,
    pub resolve_domains: Vec<String>,
    pub dnssec: String,
    pub transport: String,
    pub sni: String,
}

impl TunnelDnsServer {
    fn new(priority: i32) -> Self {
        Self {
            priority,
            addresses: Vec::new(),
            resolve_domains: Vec::new(),
            dnssec: String::new(),
            transport: String::new(),
            sni: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedCompressionDirective {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedOptions {
    pub kind: PushOptionsKind,
    pub modern_dns: bool,
    pub modern_dns_addresses: Vec<PushedAddress>,
    pub modern_search_domains: Vec<String>,
    pub pull_filter_rejection: String,
    pub topology: String,
    pub tun_mtu: u32,
    pub local_address: Vec<PushedLocalAddress>,
    pub route_gateway: Option<IpAddr>,
    pub route_gateway_vpn: bool,
    pub route_gateway_raw: String,
    pub routes: Vec<PushedRouteEntry>,
    pub dns: Vec<PushedAddress>,
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
    pub route_metric_set: bool,
    pub ping_interval: Duration,
    pub ping_interval_enabled: bool,
    pub ping_restart: Duration,
    pub ping_restart_enabled: bool,
    pub auth_token: String,
    pub auth_token_user: String,
    pub peer_id: Option<u32>,
    pub selected_cipher: String,
    pub selected_auth: String,
    pub protocol_flags: Vec<String>,
    pub key_derivation: String,
    pub explicit_exit_notify: u32,
    pub explicit_exit_notify_set: bool,
    pub compression_directives: Vec<PushedCompressionDirective>,
    pub inactive_timeout: Duration,
    pub inactive_minimum_bytes: u64,
    pub inactive_timeout_set: bool,
    pub session_timeout: Duration,
    pub session_timeout_set: bool,
    pub ping_exit: Duration,
    pub ping_exit_set: bool,
    pub ping_timer_remote: bool,
    pub parse_errors: Vec<PushedOptionParseError>,
    pub excluded_routes: Vec<PushedExcludedRoute>,
}

impl Default for PushedOptions {
    fn default() -> Self {
        Self {
            kind: PushOptionsKind::Reply,
            modern_dns: false,
            modern_dns_addresses: Vec::new(),
            modern_search_domains: Vec::new(),
            pull_filter_rejection: String::new(),
            topology: String::new(),
            tun_mtu: 0,
            local_address: Vec::new(),
            route_gateway: None,
            route_gateway_vpn: false,
            route_gateway_raw: String::new(),
            routes: Vec::new(),
            dns: Vec::new(),
            dns_servers: Vec::new(),
            dhcp_options: Vec::new(),
            search_domains: Vec::new(),
            dns_routes: Vec::new(),
            block_ipv6: false,
            block_outside_dns: false,
            redirect_gateway: false,
            redirect_gateway_flags: Vec::new(),
            redirect_private: false,
            route_metric: 0,
            route_metric_set: false,
            ping_interval: Duration::ZERO,
            ping_interval_enabled: false,
            ping_restart: Duration::ZERO,
            ping_restart_enabled: false,
            auth_token: String::new(),
            auth_token_user: String::new(),
            peer_id: None,
            selected_cipher: String::new(),
            selected_auth: String::new(),
            protocol_flags: Vec::new(),
            key_derivation: String::new(),
            explicit_exit_notify: 0,
            explicit_exit_notify_set: false,
            compression_directives: Vec::new(),
            inactive_timeout: Duration::ZERO,
            inactive_minimum_bytes: 0,
            inactive_timeout_set: false,
            session_timeout: Duration::ZERO,
            session_timeout_set: false,
            ping_exit: Duration::ZERO,
            ping_exit_set: false,
            ping_timer_remote: false,
            parse_errors: Vec::new(),
            excluded_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct WirePushedOptions {
    topology: String,
    tun_mtu: u32,
    ifconfig: String,
    ifconfig_ipv6: String,
    route_gateway: String,
    route: Vec<String>,
    route_ipv6: Vec<String>,
    dns: Vec<String>,
    dhcp_options: Vec<String>,
    block_ipv6: bool,
    block_outside_dns: bool,
    redirect_gateway: bool,
    redirect_gateway_flags: Vec<String>,
    redirect_private: bool,
    route_metric: i32,
    route_metric_set: bool,
    ping_interval: Duration,
    ping_interval_enabled: bool,
    ping_restart: Duration,
    ping_restart_enabled: bool,
    auth_token: String,
    auth_token_user: String,
    peer_id: Option<u32>,
    selected_cipher: String,
    selected_auth: String,
    protocol_flags: Vec<String>,
    key_derivation: String,
    explicit_exit_notify: u32,
    explicit_exit_notify_set: bool,
    compression_directives: Vec<PushedCompressionDirective>,
    inactive_timeout: Duration,
    inactive_minimum_bytes: u64,
    inactive_timeout_set: bool,
    session_timeout: Duration,
    session_timeout_set: bool,
    ping_exit: Duration,
    ping_exit_set: bool,
    ping_timeout_action: PingTimeoutAction,
    ping_timer_remote: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum PingTimeoutAction {
    #[default]
    None,
    Restart,
    Exit,
}

pub fn split_push_reply_payload_lines(
    payload: &[u8],
) -> Option<(String, Vec<String>)> {
    let payload = normalize_control_payload(payload);
    if payload.is_empty() {
        return None;
    }
    let mut lines = payload.split(',');
    let command = lines.next()?.trim().to_owned();
    if !command.eq_ignore_ascii_case(PUSH_REPLY_PAYLOAD_PREFIX)
        && !command.eq_ignore_ascii_case(PUSH_UPDATE_PAYLOAD_PREFIX)
    {
        return None;
    }
    Some((command, lines.map(ToOwned::to_owned).collect()))
}

pub fn append_push_reply_payload_segment(
    mut accumulated_lines: Vec<String>,
    payload: &[u8],
) -> Option<(Vec<String>, u8)> {
    let (command, lines) = split_push_reply_payload_lines(payload)?;
    if accumulated_lines.is_empty() {
        accumulated_lines.push(command);
    }
    let mut continuation = 0;
    for line in lines {
        if let Some(parameters) = parse_pushed_option_line(&line)
            && parameters.len() >= 2
            && parameters[0].eq_ignore_ascii_case("push-continuation")
            && let Ok(value) = parameters[1].parse::<u8>()
            && value <= 2
        {
            continuation = value;
        }
        accumulated_lines.push(line);
    }
    Some((accumulated_lines, continuation))
}

pub fn decode_push_reply_payload_with_filters(
    payload: &[u8],
    remote_host: Option<IpAddr>,
    filters: &[PullFilter],
) -> Option<(PushedOptions, u8)> {
    let (command, lines) = split_push_reply_payload_lines(payload)?;
    Some(decode_push_reply_option_lines(
        &command,
        &lines,
        remote_host,
        filters,
    ))
}

pub fn decode_push_reply_option_lines(
    command: &str,
    lines: &[String],
    remote_host: Option<IpAddr>,
    filters: &[PullFilter],
) -> (PushedOptions, u8) {
    let kind = if command.eq_ignore_ascii_case(PUSH_UPDATE_PAYLOAD_PREFIX) {
        PushOptionsKind::Update
    } else {
        PushOptionsKind::Reply
    };
    let mut wire = WirePushedOptions::default();
    let mut continuation = 0;
    let mut pull_filter_rejection = String::new();
    for payload_line in lines {
        let option_line = payload_line.trim_start_matches(|character| {
            matches!(
                character,
                ' ' | '\t' | '\r' | '\n' | '\u{000b}' | '\u{000c}'
            )
        });
        let (allowed, rejected) = apply_pull_filters(filters, option_line);
        if rejected {
            pull_filter_rejection = option_line.to_owned();
            break;
        }
        if !allowed {
            continue;
        }
        let Some(parameters) = parse_pushed_option_line(payload_line) else {
            continue;
        };
        let name = &parameters[0];
        let value = parameters[1..].join(" ");
        match name.to_ascii_lowercase().as_str() {
            "topology" if !value.is_empty() => wire.topology = value,
            "tun-mtu" => {
                let value = parse_pushed_positive_integer(&value);
                if value > 0 {
                    wire.tun_mtu = value as u32;
                }
            }
            "ifconfig" if !value.is_empty() => wire.ifconfig = value,
            "ifconfig-ipv6" if !value.is_empty() => wire.ifconfig_ipv6 = value,
            "route" if !value.is_empty() => wire.route.push(value),
            "route-gateway" if !value.is_empty() => wire.route_gateway = value,
            "route-ipv6" if !value.is_empty() => wire.route_ipv6.push(value),
            "dns" if !value.is_empty() => wire.dns.push(value),
            "dhcp-option" if !value.is_empty() => wire.dhcp_options.push(value),
            "block-ipv6" => wire.block_ipv6 = true,
            "block-outside-dns" => wire.block_outside_dns = true,
            "redirect-gateway" => {
                wire.redirect_gateway = true;
                if !value.is_empty() {
                    wire.redirect_gateway_flags = fields(&value);
                }
            }
            "redirect-private" => {
                wire.redirect_private = true;
                if !value.is_empty() {
                    wire.redirect_gateway_flags = fields(&value);
                }
            }
            "route-metric" if !value.is_empty() => {
                wire.route_metric = parse_pushed_positive_integer(&value);
                wire.route_metric_set = true;
            }
            "ping" if !value.is_empty() => {
                wire.ping_interval = parse_pushed_second_count(&value);
                wire.ping_interval_enabled = true;
            }
            "ping-restart" if !value.is_empty() => {
                wire.ping_restart = parse_pushed_second_count(&value);
                wire.ping_restart_enabled = true;
                wire.ping_timeout_action = PingTimeoutAction::Restart;
            }
            "auth-token" => wire.auth_token = value,
            "auth-token-user" => wire.auth_token_user = value,
            "peer-id" => {
                if let Ok(value) = value.trim().parse::<u32>()
                    && value <= PEER_ID_MAX_VALUE
                {
                    wire.peer_id = Some(value);
                }
            }
            "cipher" if !value.is_empty() => wire.selected_cipher = value,
            "auth" if !value.is_empty() => wire.selected_auth = value,
            "protocol-flags" if !value.is_empty() => {
                wire.protocol_flags = fields(&value);
            }
            "key-derivation" if !value.is_empty() => {
                wire.key_derivation = value.trim().to_ascii_lowercase();
            }
            "explicit-exit-notify" => {
                wire.explicit_exit_notify = if value.is_empty() {
                    1
                } else {
                    parse_pushed_positive_integer(&value) as u32
                };
                wire.explicit_exit_notify_set = true;
            }
            "compress" | "comp-lzo" => {
                wire.compression_directives
                    .push(PushedCompressionDirective {
                        name: name.to_ascii_lowercase(),
                        value: value.trim().to_owned(),
                    });
            }
            "inactive" => {
                let values: Vec<_> = value.split_whitespace().collect();
                if let Some(timeout) = values.first() {
                    wire.inactive_timeout = parse_pushed_second_count(timeout);
                    wire.inactive_timeout_set = true;
                    if let Some(minimum) = values.get(1)
                        && let Ok(minimum) = minimum.parse::<i64>()
                        && minimum > 0
                    {
                        wire.inactive_minimum_bytes = minimum as u64;
                    }
                }
            }
            "session-timeout" if !value.is_empty() => {
                wire.session_timeout = parse_pushed_second_count(&value);
                wire.session_timeout_set = true;
            }
            "ping-exit" if !value.is_empty() => {
                wire.ping_exit = parse_pushed_second_count(&value);
                wire.ping_exit_set = true;
                wire.ping_timeout_action = PingTimeoutAction::Exit;
            }
            "ping-timer-rem" => wire.ping_timer_remote = true,
            "push-continuation" => {
                if let Ok(value) = value.parse::<u8>()
                    && value <= 2
                {
                    continuation = value;
                }
            }
            _ => {}
        }
    }
    let mut options = pushed_options_from_wire(wire, remote_host);
    options.kind = kind;
    options.pull_filter_rejection = pull_filter_rejection;
    (options, continuation)
}

pub fn parse_pushed_positive_integer(value: &str) -> i32 {
    let text = value.trim_start_matches(|character| {
        matches!(
            character,
            ' ' | '\t' | '\n' | '\u{000b}' | '\u{000c}' | '\r'
        )
    });
    let bytes = text.as_bytes();
    let mut end = usize::from(matches!(bytes.first(), Some(b'+') | Some(b'-')));
    let digit_start = end;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if end == digit_start {
        return 0;
    }
    let parsed = text[..end].parse::<i64>().unwrap_or_else(|_| {
        if bytes.first() == Some(&b'-') {
            i64::MIN
        } else {
            i64::MAX
        }
    });
    let truncated = parsed as i32;
    truncated.max(0)
}

pub fn parse_pushed_second_count(value: &str) -> Duration {
    Duration::from_secs(parse_pushed_positive_integer(value) as u64)
}

pub fn apply_pull_filters(
    filters: &[PullFilter],
    option_line: &str,
) -> (bool, bool) {
    for filter in filters {
        if !option_line.starts_with(&filter.text) {
            continue;
        }
        return match filter.action.as_str() {
            "accept" => (true, false),
            "ignore" => (false, false),
            "reject" => (false, true),
            _ => continue,
        };
    }
    (true, false)
}

fn pushed_options_from_wire(
    wire: WirePushedOptions,
    remote_host: Option<IpAddr>,
) -> PushedOptions {
    let mut options = PushedOptions {
        topology: wire.topology.clone(),
        tun_mtu: wire.tun_mtu,
        dhcp_options: wire.dhcp_options.clone(),
        block_ipv6: wire.block_ipv6,
        block_outside_dns: wire.block_outside_dns,
        redirect_gateway: wire.redirect_gateway,
        redirect_gateway_flags: wire.redirect_gateway_flags,
        redirect_private: wire.redirect_private,
        route_metric: wire.route_metric,
        route_metric_set: wire.route_metric_set,
        ping_interval: wire.ping_interval,
        ping_interval_enabled: wire.ping_interval_enabled,
        ping_restart: wire.ping_restart,
        ping_restart_enabled: wire.ping_restart_enabled,
        auth_token: wire.auth_token,
        auth_token_user: wire.auth_token_user,
        peer_id: wire.peer_id,
        selected_cipher: wire.selected_cipher,
        selected_auth: wire.selected_auth,
        protocol_flags: wire.protocol_flags,
        key_derivation: wire.key_derivation,
        explicit_exit_notify: wire.explicit_exit_notify,
        explicit_exit_notify_set: wire.explicit_exit_notify_set,
        compression_directives: wire.compression_directives,
        inactive_timeout: wire.inactive_timeout,
        inactive_minimum_bytes: wire.inactive_minimum_bytes,
        inactive_timeout_set: wire.inactive_timeout_set,
        session_timeout: wire.session_timeout,
        session_timeout_set: wire.session_timeout_set,
        ping_exit: wire.ping_exit,
        ping_exit_set: wire.ping_exit_set,
        ping_timer_remote: wire.ping_timer_remote,
        ..PushedOptions::default()
    };
    match wire.ping_timeout_action {
        PingTimeoutAction::Restart => {
            options.ping_exit = Duration::ZERO;
            options.ping_exit_set = false;
        }
        PingTimeoutAction::Exit => {
            options.ping_restart = Duration::ZERO;
            options.ping_restart_enabled = false;
        }
        PingTimeoutAction::None => {}
    }
    if !wire.ifconfig.is_empty() {
        options.add_wire_ifconfig(&wire.ifconfig, &wire.topology);
    }
    if !wire.ifconfig_ipv6.is_empty() {
        options.add_wire_ifconfig_ipv6(&wire.ifconfig_ipv6);
    }
    options.set_wire_route_gateway(&wire.route_gateway);
    for value in wire.route {
        options.add_wire_route(&value, remote_host);
    }
    for value in wire.route_ipv6 {
        options.add_wire_route_ipv6(&value, remote_host);
    }
    for value in wire.dns {
        options.add_wire_dns_option_v2(&value);
    }
    let empty_priorities: Vec<_> = options
        .dns_servers
        .iter()
        .filter(|server| server.addresses.is_empty())
        .map(|server| server.priority)
        .collect();
    options
        .dns_servers
        .retain(|server| !server.addresses.is_empty());
    for priority in empty_priorities {
        options.add_parse_error(
            "dns",
            &format!("server {priority}"),
            "dns server has no address assigned",
        );
    }
    options.modern_dns = !options.dns_servers.is_empty();
    if !options.modern_dns {
        for value in &wire.dhcp_options {
            options.add_wire_dhcp_option_dns(value);
        }
    } else {
        options.dhcp_options =
            filter_openvpn_non_dns_dhcp_options(&options.dhcp_options);
    }
    options
}

impl PushedOptions {
    fn add_wire_ifconfig(&mut self, value: &str, topology: &str) {
        let raw = value.trim();
        if raw.is_empty() {
            return;
        }
        match parse_ifconfig_prefix(raw, topology) {
            Ok(prefix) => self.local_address.push(PushedLocalAddress {
                prefix,
                peer: parse_ifconfig_vpn_gateway(&[raw.to_owned()], topology)
                    .map(IpAddr::V4),
                raw: raw.to_owned(),
            }),
            Err(error) => {
                self.add_parse_error("ifconfig", raw, &error.to_string())
            }
        }
    }

    fn add_wire_ifconfig_ipv6(&mut self, value: &str) {
        let raw = value.trim();
        if raw.is_empty() {
            return;
        }
        match parse_ifconfig_ipv6(raw) {
            Ok((prefix, peer)) => self.local_address.push(PushedLocalAddress {
                prefix,
                peer: Some(IpAddr::V6(peer)),
                raw: raw.to_owned(),
            }),
            Err(error) => {
                self.add_parse_error("ifconfig-ipv6", raw, &error.to_string())
            }
        }
    }

    fn set_wire_route_gateway(&mut self, value: &str) {
        let raw = value.trim();
        if raw.is_empty() {
            return;
        }
        self.route_gateway_raw = raw.to_owned();
        let Some(value) = raw.split_whitespace().next() else {
            return;
        };
        if value.eq_ignore_ascii_case("vpn_gateway") {
            self.route_gateway_vpn = true;
        } else if let Ok(address) = value.parse() {
            self.route_gateway = Some(address);
        } else {
            self.add_parse_error(
                "route-gateway",
                raw,
                "invalid pushed route gateway",
            );
        }
    }

    fn add_wire_route(&mut self, value: &str, remote_host: Option<IpAddr>) {
        self.add_wire_route_inner(
            "route",
            value,
            parse_pushed_route(value, remote_host),
        );
    }

    fn add_wire_route_ipv6(
        &mut self,
        value: &str,
        remote_host: Option<IpAddr>,
    ) {
        self.add_wire_route_inner(
            "route-ipv6",
            value,
            parse_pushed_route_ipv6(value, remote_host),
        );
    }

    fn add_wire_route_inner(
        &mut self,
        name: &str,
        value: &str,
        result: Result<PushedRoute, super::RouteOptionError>,
    ) {
        let raw = value.trim();
        if raw.is_empty() {
            return;
        }
        match result {
            Ok(route) if route.excluded => {
                self.excluded_routes.push(PushedExcludedRoute {
                    name: name.to_owned(),
                    value: raw.to_owned(),
                    route,
                });
            }
            Ok(route) => self.routes.push(PushedRouteEntry {
                route,
                raw: raw.to_owned(),
            }),
            Err(error) => self.add_parse_error(name, raw, &error.to_string()),
        }
    }

    fn add_wire_dns_option_v2(&mut self, value: &str) {
        let raw = value.trim();
        let values: Vec<_> = raw.split_whitespace().collect();
        let Some(first) = values.first() else {
            return;
        };
        if first.eq_ignore_ascii_case("search-domains") {
            if values.len() < 2 {
                self.add_parse_error(
                    "dns",
                    raw,
                    "dns search-domains requires domain value",
                );
                return;
            }
            for domain in &values[1..] {
                if validate_tunnel_dns_domain(domain) {
                    append_unique(&mut self.search_domains, domain);
                    append_unique(&mut self.modern_search_domains, domain);
                } else {
                    self.add_parse_error(
                        "dns",
                        raw,
                        &format!("dns search domain contains invalid characters: {domain}"),
                    );
                }
            }
            return;
        }
        if !first.eq_ignore_ascii_case("server") {
            return;
        }
        if values.len() < 3 {
            self.add_parse_error(
                "dns",
                raw,
                &format!("invalid dns server option: {raw}"),
            );
            return;
        }
        let Ok(priority) = values[1].parse::<i32>() else {
            self.add_parse_error(
                "dns",
                raw,
                &format!("parse dns server priority: {}", values[1]),
            );
            return;
        };
        if !(0..=127).contains(&priority) {
            self.add_parse_error(
                "dns",
                raw,
                "pushed dns server priority must be between 0 and 127",
            );
            return;
        }
        let index = self.tunnel_dns_server_index(priority);
        match values[2].to_ascii_lowercase().as_str() {
            "address" => {
                if values.len() < 4 {
                    self.add_parse_error(
                        "dns",
                        raw,
                        "dns server address requires address value",
                    );
                    return;
                }
                for value in &values[3..] {
                    if self.dns_servers[index].addresses.len()
                        >= MAX_TUNNEL_DNS_SERVER_ADDRESSES
                    {
                        self.add_parse_error(
                            "dns",
                            raw,
                            &format!(
                                "dns server address maximum exceeded: {value}"
                            ),
                        );
                        return;
                    }
                    match parse_tunnel_dns_address(value) {
                        Ok(address) => {
                            self.dns_servers[index].addresses.push(address);
                            let pushed = PushedAddress {
                                address: address.ip(),
                                raw: raw.to_owned(),
                                option_name: "dns".into(),
                            };
                            self.dns.push(pushed.clone());
                            self.modern_dns_addresses.push(pushed);
                        }
                        Err(message) => self.add_parse_error(
                            "dns",
                            raw,
                            &format!(
                                "parse dns server address: {value}: {message}"
                            ),
                        ),
                    }
                }
            }
            "resolve-domains" => {
                if values.len() < 4 {
                    self.add_parse_error(
                        "dns",
                        raw,
                        "dns server resolve-domains requires domain value",
                    );
                    return;
                }
                for domain in &values[3..] {
                    if validate_tunnel_dns_domain(domain) {
                        append_unique(
                            &mut self.dns_servers[index].resolve_domains,
                            domain,
                        );
                    } else {
                        self.add_parse_error(
                            "dns",
                            raw,
                            &format!("dns resolve domain contains invalid characters: {domain}"),
                        );
                    }
                }
            }
            "dnssec" => {
                if values.len() != 4 {
                    self.add_parse_error(
                        "dns",
                        raw,
                        "dns server dnssec requires one value",
                    );
                } else {
                    let value = values[3].to_ascii_lowercase();
                    if matches!(value.as_str(), "yes" | "optional" | "no") {
                        self.dns_servers[index].dnssec = value;
                    } else {
                        self.add_parse_error(
                            "dns",
                            raw,
                            &format!("invalid dnssec mode: {}", values[3]),
                        );
                    }
                }
            }
            "transport" => {
                if values.len() != 4 {
                    self.add_parse_error(
                        "dns",
                        raw,
                        "dns server transport requires one value",
                    );
                } else {
                    let transport = match values[3] {
                        "plain" => Some("plain"),
                        "DoT" => Some("dot"),
                        "DoH" => Some("doh"),
                        _ => None,
                    };
                    if let Some(transport) = transport {
                        self.dns_servers[index].transport = transport.into();
                    } else {
                        self.add_parse_error(
                            "dns",
                            raw,
                            &format!("invalid dns transport: {}", values[3]),
                        );
                    }
                }
            }
            "sni" => {
                if values.len() != 4 {
                    self.add_parse_error(
                        "dns",
                        raw,
                        "dns server sni requires one value",
                    );
                } else if !validate_tunnel_dns_domain(values[3]) {
                    self.add_parse_error(
                        "dns",
                        raw,
                        &format!(
                            "dns server sni contains invalid characters: {}",
                            values[3]
                        ),
                    );
                } else {
                    self.dns_servers[index].sni = values[3].to_owned();
                }
            }
            _ => self.add_parse_error(
                "dns",
                raw,
                &format!("unsupported dns server option: {}", values[2]),
            ),
        }
    }

    fn tunnel_dns_server_index(&mut self, priority: i32) -> usize {
        if let Some(index) = self
            .dns_servers
            .iter()
            .position(|server| server.priority == priority)
        {
            return index;
        }
        self.dns_servers.push(TunnelDnsServer::new(priority));
        self.dns_servers.len() - 1
    }

    fn add_wire_dhcp_option_dns(&mut self, value: &str) {
        let raw = value.trim();
        let values: Vec<_> = raw.split_whitespace().collect();
        let Some(name) = values.first().map(|name| name.to_ascii_uppercase())
        else {
            return;
        };
        if matches!(
            name.as_str(),
            "DOMAIN" | "ADAPTER_DOMAIN_SUFFIX" | "DOMAIN-SEARCH"
        ) {
            self.add_dhcp_domains(&name, raw, &values[1..], false);
            return;
        }
        if name == "DOMAIN-ROUTE" {
            self.add_dhcp_domains(&name, raw, &values[1..], true);
            return;
        }
        if name != "DNS" && name != "DNS6" {
            return;
        }
        if values.len() < 2 {
            self.add_parse_error(
                "dhcp-option",
                raw,
                &format!("dhcp-option {name} requires address value"),
            );
            return;
        }
        for value in &values[1..] {
            match value.parse::<IpAddr>() {
                Ok(address)
                    if (name == "DNS" && address.is_ipv4())
                        || (name == "DNS6" && address.is_ipv6()) =>
                {
                    self.dns.push(PushedAddress {
                        address,
                        raw: raw.to_owned(),
                        option_name: "dhcp-option".into(),
                    });
                }
                Ok(_) => self.add_parse_error(
                    "dhcp-option",
                    raw,
                    &format!("dhcp-option {name} expected matching address family: {value}"),
                ),
                Err(error) => self.add_parse_error(
                    "dhcp-option",
                    raw,
                    &format!("parse dhcp-option {name} address: {value}: {error}"),
                ),
            }
        }
    }

    fn add_dhcp_domains(
        &mut self,
        name: &str,
        raw: &str,
        domains: &[&str],
        route: bool,
    ) {
        if domains.is_empty() {
            self.add_parse_error(
                "dhcp-option",
                raw,
                &format!("dhcp-option {name} requires domain value"),
            );
            return;
        }
        for domain in domains {
            if !validate_tunnel_dns_domain(domain) {
                self.add_parse_error(
                    "dhcp-option",
                    raw,
                    &format!(
                        "dhcp-option {name} contains invalid domain: {domain}"
                    ),
                );
            } else if route {
                append_unique(&mut self.dns_routes, domain);
            } else {
                append_unique(&mut self.search_domains, domain);
            }
        }
    }

    fn add_parse_error(&mut self, name: &str, value: &str, message: &str) {
        self.parse_errors.push(PushedOptionParseError {
            name: name.to_owned(),
            value: value.to_owned(),
            message: message.to_owned(),
        });
    }
}

pub fn parse_tunnel_dns_address(value: &str) -> Result<SocketAddr, String> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, 0));
    }
    let address: SocketAddr =
        value.parse().map_err(|error| format!("{error}"))?;
    if address.port() == 0 {
        return Err("dns server port must not be zero".into());
    }
    Ok(address)
}

pub fn validate_tunnel_dns_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.bytes().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, b'.' | b'-' | b'_')
                || character >= 0x80
        })
}

pub fn filter_openvpn_non_dns_dhcp_options(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|value| {
            let Some(name) = value.split_whitespace().next() else {
                return true;
            };
            !matches!(
                name.to_ascii_uppercase().as_str(),
                "DNS"
                    | "DNS6"
                    | "DOMAIN"
                    | "ADAPTER_DOMAIN_SUFFIX"
                    | "DOMAIN-SEARCH"
                    | "DOMAIN-ROUTE"
            )
        })
        .cloned()
        .collect()
}

pub fn normalize_control_payload(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload)
        .trim_matches('\0')
        .trim()
        .to_owned()
}

pub fn parse_pushed_option_line(line: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Initial,
        Quoted,
        SingleQuoted,
        Unquoted,
        Done,
    }
    fn space(character: u8) -> bool {
        matches!(character, 0 | b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
    }

    let bytes = line.as_bytes();
    let mut parameters = Vec::with_capacity(4);
    let mut parameter = Vec::new();
    let mut state = State::Initial;
    let mut backslash = false;
    for index in 0..=bytes.len() {
        let character = bytes.get(index).copied().unwrap_or(0);
        if !backslash && character == b'\\' && state != State::SingleQuoted {
            backslash = true;
            continue;
        }
        if backslash
            && character != b'\\'
            && character != b'"'
            && !space(character)
        {
            return None;
        }
        let mut stored = None;
        match state {
            State::Initial => {
                if space(character) {
                    // Continue below.
                } else if matches!(character, b';' | b'#') {
                    break;
                } else if !backslash && character == b'"' {
                    state = State::Quoted;
                } else if !backslash && character == b'\'' {
                    state = State::SingleQuoted;
                } else {
                    stored = Some(character);
                    state = State::Unquoted;
                }
            }
            State::Unquoted => {
                if !backslash && space(character) {
                    state = State::Done;
                } else {
                    stored = Some(character);
                }
            }
            State::Quoted => {
                if !backslash && character == b'"' {
                    state = State::Done;
                } else {
                    stored = Some(character);
                }
            }
            State::SingleQuoted => {
                if character == b'\'' {
                    state = State::Done;
                } else {
                    stored = Some(character);
                }
            }
            State::Done => unreachable!(),
        }
        if state == State::Done {
            parameters.push(String::from_utf8(parameter).ok()?);
            parameter = Vec::new();
            state = State::Initial;
            if parameters.len() >= PUSHED_OPTION_LINE_MAX_PARAMETERS {
                break;
            }
        }
        backslash = false;
        if let Some(stored) = stored
            && stored != 0
        {
            parameter.push(stored);
        }
    }
    (state == State::Initial && !parameters.is_empty()).then_some(parameters)
}

fn fields(value: &str) -> Vec<String> {
    value.split_whitespace().map(ToOwned::to_owned).collect()
}

fn append_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|item| item == value) {
        values.push(value.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_parser_matches_openvpn_quotes_escapes_comments_and_limit() {
        assert_eq!(
            parse_pushed_option_line(
                r#"route "10.0.0.0 255.0.0.0" vpn_gateway"#
            ),
            Some(vec![
                "route".into(),
                "10.0.0.0 255.0.0.0".into(),
                "vpn_gateway".into()
            ])
        );
        assert_eq!(
            parse_pushed_option_line(r#"dhcp-option DOMAIN foo\ bar"#),
            Some(vec![
                "dhcp-option".into(),
                "DOMAIN".into(),
                "foo bar".into()
            ])
        );
        assert_eq!(
            parse_pushed_option_line(r#"auth-token 'a\\b' # ignored"#),
            Some(vec!["auth-token".into(), r"a\\b".into()])
        );
        assert!(parse_pushed_option_line(r"route bad\q").is_none());
        assert!(parse_pushed_option_line("route \"unterminated").is_none());
        let too_many = (0..20)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(parse_pushed_option_line(&too_many).unwrap().len(), 16);
    }

    #[test]
    fn positive_atoi_matches_strtol_truncation() {
        assert_eq!(parse_pushed_positive_integer("  +12seconds"), 12);
        assert_eq!(parse_pushed_positive_integer("-3"), 0);
        assert_eq!(parse_pushed_positive_integer("4294967297"), 1);
        assert_eq!(
            parse_pushed_positive_integer("999999999999999999999999"),
            0
        );
        assert_eq!(parse_pushed_positive_integer("garbage"), 0);
    }

    #[test]
    fn segments_and_filters_preserve_raw_comma_semantics() {
        let (lines, continuation) = append_push_reply_payload_segment(
            Vec::new(),
            b" PUSH_REPLY,route 10.0.0.0 255.0.0.0,push-continuation 2\0",
        )
        .unwrap();
        assert_eq!(continuation, 2);
        assert_eq!(lines.len(), 3);
        let filters = [PullFilter {
            action: "reject".into(),
            text: "route ".into(),
        }];
        let (options, _) = decode_push_reply_payload_with_filters(
            b"PUSH_REPLY,ping 10, route 10.0.0.0 255.0.0.0,ping 20",
            None,
            &filters,
        )
        .unwrap();
        assert_eq!(options.ping_interval, Duration::from_secs(10));
        assert_eq!(options.pull_filter_rejection, "route 10.0.0.0 255.0.0.0");
    }

    #[test]
    fn decodes_addresses_routes_timers_and_last_timeout_action() {
        let payload = b"PUSH_REPLY,topology subnet,tun-mtu 1500,ifconfig 10.8.0.2 255.255.255.0,ifconfig-ipv6 fd00::2/64 fd00::1,route 10.9.1.5 255.255.255.0 remote_host 42,route 0.0.0.0/1 net_gateway,route-ipv6 fd01::123/64 vpn_gateway 7,route-gateway vpn_gateway,redirect-gateway def1 bypass-dhcp,route-metric 9,ping 5,ping-restart 30,ping-exit 12,peer-id 16777215,explicit-exit-notify,inactive 60 -1,session-timeout 120,protocol-flags cc-exit tls-ekm,key-derivation tls-ekm,compress lz4-v2";
        let (options, continuation) = decode_push_reply_payload_with_filters(
            payload,
            Some("203.0.113.7".parse().unwrap()),
            &[],
        )
        .unwrap();
        assert_eq!(continuation, 0);
        assert_eq!(options.local_address.len(), 2);
        assert_eq!(options.routes.len(), 2);
        assert_eq!(options.excluded_routes.len(), 1);
        assert!(options.route_gateway_vpn);
        assert_eq!(options.route_metric, 9);
        assert_eq!(options.ping_interval, Duration::from_secs(5));
        assert_eq!(options.ping_exit, Duration::from_secs(12));
        assert!(!options.ping_restart_enabled);
        assert_eq!(options.peer_id, Some(PEER_ID_MAX_VALUE));
        assert_eq!(options.explicit_exit_notify, 1);
        assert_eq!(options.inactive_minimum_bytes, 0);
        assert_eq!(options.protocol_flags, ["cc-exit", "tls-ekm"]);
        assert_eq!(options.key_derivation, "tls-ekm");
    }

    #[test]
    fn modern_dns_supersedes_legacy_dns_but_keeps_non_dns_dhcp() {
        let payload = b"PUSH_REPLY,dns server 7 address 1.1.1.1 [2606:4700:4700::1111]:853,dns server 7 resolve-domains example.com example.com,dns server 7 dnssec optional,dns server 7 transport DoT,dns server 7 sni dns.example,dns search-domains corp.example,dhcp-option DNS 8.8.8.8,dhcp-option DOMAIN legacy.example,dhcp-option WINS 192.0.2.1";
        let (options, _) =
            decode_push_reply_payload_with_filters(payload, None, &[]).unwrap();
        assert!(options.modern_dns);
        assert_eq!(options.dns_servers.len(), 1);
        assert_eq!(options.dns_servers[0].addresses.len(), 2);
        assert_eq!(options.dns_servers[0].resolve_domains, ["example.com"]);
        assert_eq!(options.dns_servers[0].dnssec, "optional");
        assert_eq!(options.dns_servers[0].transport, "dot");
        assert_eq!(options.dns_servers[0].sni, "dns.example");
        assert_eq!(options.search_domains, ["corp.example"]);
        assert_eq!(options.dhcp_options, ["WINS 192.0.2.1"]);
        assert_eq!(options.dns.len(), 2);
        assert!(options.parse_errors.is_empty());
    }

    #[test]
    fn legacy_dns_and_dns_errors_follow_upstream_precedence() {
        let payload = b"PUSH_REPLY,dns server 1 resolve-domains empty.example,dhcp-option DNS 8.8.8.8,dhcp-option DNS6 2001:4860:4860::8888,dhcp-option DOMAIN example.com example.com,dhcp-option DOMAIN-ROUTE .,dhcp-option DNS ::1";
        let (options, _) =
            decode_push_reply_payload_with_filters(payload, None, &[]).unwrap();
        assert!(!options.modern_dns);
        assert!(options.dns_servers.is_empty());
        assert_eq!(options.dns.len(), 2);
        assert_eq!(options.search_domains, ["example.com"]);
        assert_eq!(options.dns_routes, ["."]);
        assert_eq!(options.parse_errors.len(), 2);
    }

    #[test]
    fn rejects_out_of_range_peer_and_dns_values() {
        let addresses = (1..=9)
            .map(|value| format!("192.0.2.{value}"))
            .collect::<Vec<_>>()
            .join(" ");
        let payload = format!(
            "PUSH_UPDATE,peer-id 16777216,dns server 128 address 1.1.1.1,dns server 2 address {addresses},dns server 2 transport dot,push-continuation 1"
        );
        let (options, continuation) = decode_push_reply_payload_with_filters(
            payload.as_bytes(),
            None,
            &[],
        )
        .unwrap();
        assert_eq!(options.kind, PushOptionsKind::Update);
        assert_eq!(continuation, 1);
        assert_eq!(options.peer_id, None);
        assert_eq!(options.dns_servers[0].addresses.len(), 8);
        assert_eq!(options.parse_errors.len(), 3);
    }
}
