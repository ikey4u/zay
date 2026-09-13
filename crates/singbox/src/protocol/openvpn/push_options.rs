use std::net::{IpAddr, Ipv4Addr};

use super::{
    CipherNegotiationError, OpenVpnIpPrefix, PUSH_REPLY_PAYLOAD_PREFIX,
    PushedAddress, PushedLocalAddress, PushedOptions, PushedRoute,
    PushedRouteEntry, TLS_IV_PROTO_CC_EXIT_NOTIFY, TLS_IV_PROTO_DATA_V2,
    TLS_IV_PROTO_TLS_KEY_EXPORT, peer_info_cipher_list, peer_info_mtu,
    peer_supports_iv_proto_flag, split_server_push_reply_fields,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerPushAssignment {
    pub local_address_ipv4: Option<PushedLocalAddress>,
    pub local_address_ipv6: Option<PushedLocalAddress>,
    pub ipv4_topology: String,
    pub server_ipv4: Option<Ipv4Addr>,
    pub peer_id: Option<u32>,
}

/// Apply per-peer tunnel allocation and capability negotiation before
/// serializing the server's configured push options.
pub fn build_server_push_reply_payloads(
    configured: &PushedOptions,
    peer_info: &str,
    selected_cipher: &str,
    assignment: &ServerPushAssignment,
) -> Result<Vec<Vec<u8>>, CipherNegotiationError> {
    let mut options = configured.clone();
    // These fields are negotiated below rather than accepted from static push
    // configuration.
    options.selected_cipher.clear();
    options.peer_id = None;
    options.protocol_flags.clear();
    options.key_derivation.clear();
    if peer_info_mtu(peer_info).is_none() {
        options.tun_mtu = 0;
    }
    if let Some(address) = &assignment.local_address_ipv4 {
        replace_pushed_local_address_by_family(
            &mut options.local_address,
            address.clone(),
        );
    }
    if let Some(address) = &assignment.local_address_ipv6 {
        replace_pushed_local_address_by_family(
            &mut options.local_address,
            address.clone(),
        );
    }
    if !assignment.ipv4_topology.is_empty() {
        options.topology.clone_from(&assignment.ipv4_topology);
        match assignment.ipv4_topology.as_str() {
            "subnet"
                if options.route_gateway.is_none()
                    && !options.route_gateway_vpn
                    && options.route_gateway_raw.is_empty() =>
            {
                options.route_gateway = assignment.server_ipv4.map(IpAddr::V4);
            }
            "net30" => {
                if let Some(server) = assignment.server_ipv4 {
                    let route = PushedRouteEntry {
                        route: PushedRoute {
                            prefix: OpenVpnIpPrefix {
                                address: IpAddr::V4(server),
                                prefix_len: 32,
                            },
                            gateway: None,
                            metric: 0,
                            excluded: false,
                        },
                        raw: String::new(),
                    };
                    if !options
                        .routes
                        .iter()
                        .any(|existing| existing.route == route.route)
                    {
                        options.routes.push(route);
                    }
                }
            }
            _ => {}
        }
    }
    let mut fields = build_push_reply_option_fields(&options);
    let (_, client_cipher_list_known) = peer_info_cipher_list(peer_info);
    if !selected_cipher.is_empty() && client_cipher_list_known {
        fields.push(format!("cipher {selected_cipher}"));
    }
    if let Some(peer_id) = assignment.peer_id.filter(|_| {
        peer_supports_iv_proto_flag(peer_info, TLS_IV_PROTO_DATA_V2)
    }) {
        fields.push(format!("peer-id {peer_id}"));
    }
    let supports_cc_exit =
        peer_supports_iv_proto_flag(peer_info, TLS_IV_PROTO_CC_EXIT_NOTIFY);
    let supports_tls_export =
        peer_supports_iv_proto_flag(peer_info, TLS_IV_PROTO_TLS_KEY_EXPORT);
    if supports_cc_exit {
        fields.push(if supports_tls_export {
            "protocol-flags cc-exit tls-ekm".into()
        } else {
            "protocol-flags cc-exit".into()
        });
    } else if supports_tls_export {
        fields.push("key-derivation tls-ekm".into());
    }
    split_server_push_reply_fields(&fields)
}

pub fn build_push_reply_option_fields(options: &PushedOptions) -> Vec<String> {
    let mut fields = vec![PUSH_REPLY_PAYLOAD_PREFIX.to_owned()];
    push_trimmed(&mut fields, "topology", &options.topology);
    if options.tun_mtu > 0 {
        fields.push(format!("tun-mtu {}", options.tun_mtu));
    }
    for address in &options.local_address {
        let value = match address.prefix.address {
            IpAddr::V4(_) => format_pushed_ifconfig(address, &options.topology),
            IpAddr::V6(_) => format_pushed_ifconfig_ipv6(address),
        };
        if !value.is_empty() {
            fields.push(format!(
                "{} {value}",
                if address.prefix.address.is_ipv4() {
                    "ifconfig"
                } else {
                    "ifconfig-ipv6"
                }
            ));
        }
    }
    let route_gateway = format_pushed_route_gateway(options);
    if !route_gateway.is_empty() {
        fields.push(format!("route-gateway {route_gateway}"));
    }
    for route in &options.routes {
        let value = format_pushed_route(route);
        if value.is_empty() {
            continue;
        }
        fields.push(format!(
            "{} {value}",
            if route.route.prefix.address.is_ipv4() {
                "route"
            } else {
                "route-ipv6"
            }
        ));
    }
    for address in &options.dns {
        fields.push(format!(
            "dhcp-option {} {}",
            if address.address.is_ipv4() {
                "DNS"
            } else {
                "DNS6"
            },
            address.address
        ));
    }
    if !options.search_domains.is_empty() {
        fields.push(format!(
            "dns search-domains {}",
            options.search_domains.join(" ")
        ));
    }
    let mut servers = options.dns_servers.clone();
    servers.sort_by_key(|server| server.priority);
    for server in servers {
        let priority = server.priority;
        if !server.addresses.is_empty() {
            let values = server
                .addresses
                .iter()
                .map(|address| {
                    if address.port() == 0 {
                        address.ip().to_string()
                    } else {
                        address.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            fields.push(format!("dns server {priority} address {values}"));
        }
        if !server.resolve_domains.is_empty() {
            fields.push(format!(
                "dns server {priority} resolve-domains {}",
                server.resolve_domains.join(" ")
            ));
        }
        if !server.dnssec.is_empty() {
            fields.push(format!(
                "dns server {priority} dnssec {}",
                server.dnssec
            ));
        }
        if !server.transport.is_empty() {
            let transport = match server.transport.as_str() {
                "doh" => "DoH",
                "dot" => "DoT",
                value => value,
            };
            fields.push(format!("dns server {priority} transport {transport}"));
        }
        if !server.sni.is_empty() {
            fields.push(format!("dns server {priority} sni {}", server.sni));
        }
    }
    for value in &options.dhcp_options {
        push_trimmed(&mut fields, "dhcp-option", value);
    }
    if options.block_ipv6 {
        fields.push("block-ipv6".into());
    }
    if options.block_outside_dns {
        fields.push("block-outside-dns".into());
    }
    if options.redirect_gateway {
        let flags = options.redirect_gateway_flags.join(" ");
        if flags.trim().is_empty() {
            fields.push("redirect-gateway".into());
        } else {
            fields.push(format!("redirect-gateway {}", flags.trim()));
        }
    }
    if options.redirect_private {
        fields.push("redirect-private".into());
    }
    if options.route_metric != 0 {
        fields.push(format!("route-metric {}", options.route_metric));
    }
    if options.ping_interval_enabled {
        fields.push(format!("ping {}", options.ping_interval.as_secs()));
    }
    if options.ping_restart_enabled {
        fields.push(format!("ping-restart {}", options.ping_restart.as_secs()));
    }
    push_trimmed(&mut fields, "auth-token", &options.auth_token);
    push_trimmed(&mut fields, "auth-token-user", &options.auth_token_user);
    if let Some(peer_id) = options.peer_id {
        fields.push(format!("peer-id {peer_id}"));
    }
    push_trimmed(&mut fields, "cipher", &options.selected_cipher);
    push_trimmed(&mut fields, "auth", &options.selected_auth);
    if !options.protocol_flags.is_empty() {
        fields.push(format!(
            "protocol-flags {}",
            options.protocol_flags.join(" ")
        ));
    }
    push_trimmed(&mut fields, "key-derivation", &options.key_derivation);
    if options.explicit_exit_notify > 0 {
        fields.push(format!(
            "explicit-exit-notify {}",
            options.explicit_exit_notify
        ));
    }
    for directive in &options.compression_directives {
        let name = directive.name.trim();
        let value = directive.value.trim();
        if !name.is_empty() {
            fields.push(if value.is_empty() {
                name.to_owned()
            } else {
                format!("{name} {value}")
            });
        }
    }
    if !options.inactive_timeout.is_zero() {
        let mut value =
            format!("inactive {}", options.inactive_timeout.as_secs());
        if options.inactive_minimum_bytes > 0 {
            value.push_str(&format!(" {}", options.inactive_minimum_bytes));
        }
        fields.push(value);
    }
    if !options.session_timeout.is_zero() {
        fields.push(format!(
            "session-timeout {}",
            options.session_timeout.as_secs()
        ));
    }
    if !options.ping_exit.is_zero() {
        fields.push(format!("ping-exit {}", options.ping_exit.as_secs()));
    }
    if options.ping_timer_remote {
        fields.push("ping-timer-rem".into());
    }
    fields
}

fn push_trimmed(fields: &mut Vec<String>, name: &str, value: &str) {
    let value = value.trim();
    if !value.is_empty() {
        fields.push(format!("{name} {value}"));
    }
}

pub fn apply_pushed_ipv6_local_address_peer(
    values: &mut [PushedLocalAddress],
    peer: IpAddr,
) {
    if !peer.is_ipv6() {
        return;
    }
    for value in values {
        if value.prefix.address.is_ipv6()
            && value.peer.is_none_or(|address| !address.is_ipv6())
        {
            value.peer = Some(peer);
        }
    }
}

pub fn has_pushed_local_address_family(
    values: &[PushedLocalAddress],
    ipv4: bool,
) -> bool {
    values
        .iter()
        .any(|value| value.prefix.address.is_ipv4() == ipv4)
}

pub fn replace_pushed_local_address_by_family(
    values: &mut Vec<PushedLocalAddress>,
    replacement: PushedLocalAddress,
) {
    let ipv4 = replacement.prefix.address.is_ipv4();
    values.retain(|value| value.prefix.address.is_ipv4() != ipv4);
    values.push(replacement);
}

pub fn pushed_routes_from_prefixes(
    values: &[OpenVpnIpPrefix],
) -> Vec<PushedRouteEntry> {
    values
        .iter()
        .copied()
        .filter(is_valid_prefix)
        .map(|prefix| PushedRouteEntry {
            route: PushedRoute {
                prefix: prefix.masked(),
                gateway: None,
                metric: 0,
                excluded: false,
            },
            raw: String::new(),
        })
        .collect()
}

pub fn pushed_addresses_from_addresses(
    values: &[IpAddr],
) -> Vec<PushedAddress> {
    values
        .iter()
        .map(|address| PushedAddress {
            address: *address,
            raw: String::new(),
            option_name: String::new(),
        })
        .collect()
}

pub fn format_pushed_ifconfig(
    value: &PushedLocalAddress,
    topology: &str,
) -> String {
    if !is_valid_prefix(&value.prefix) || !value.prefix.address.is_ipv4() {
        return String::new();
    }
    let topology = topology.trim().to_ascii_lowercase();
    if let Some(peer) = value.peer.filter(IpAddr::is_ipv4)
        && topology != "subnet"
    {
        return format!("{} {peer}", value.prefix.address);
    }
    if matches!(topology.as_str(), "p2p" | "net30") {
        return String::new();
    }
    format_ifconfig_prefix(value.prefix)
}

pub fn format_pushed_ifconfig_ipv6(value: &PushedLocalAddress) -> String {
    if !is_valid_prefix(&value.prefix) || !value.prefix.address.is_ipv6() {
        return String::new();
    }
    let Some(peer) = value.peer.filter(IpAddr::is_ipv6) else {
        return String::new();
    };
    format!(
        "{}/{} {peer}",
        value.prefix.address, value.prefix.prefix_len
    )
}

pub fn format_pushed_route_gateway(options: &PushedOptions) -> String {
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

pub fn format_pushed_route(route: &PushedRouteEntry) -> String {
    if !route.raw.is_empty() {
        return route.raw.clone();
    }
    if !is_valid_prefix(&route.route.prefix) {
        return String::new();
    }
    let prefix = route.route.prefix.masked();
    let mut value = if prefix.address.is_ipv4() {
        format_ipv4_route_prefix(prefix)
    } else {
        format!("{}/{}", prefix.address, prefix.prefix_len)
    };
    if let Some(gateway) = route.route.gateway {
        value.push_str(&format!(" {gateway}"));
        if route.route.metric != 0 {
            value.push_str(&format!(" {}", route.route.metric));
        }
    }
    value
}

pub fn format_ifconfig_prefix(prefix: OpenVpnIpPrefix) -> String {
    if !is_valid_prefix(&prefix) || !prefix.address.is_ipv4() {
        return String::new();
    }
    format!(
        "{} {}",
        prefix.address,
        ipv4_mask(prefix.prefix_len).unwrap()
    )
}

pub fn format_ipv4_route_prefix(prefix: OpenVpnIpPrefix) -> String {
    if !is_valid_prefix(&prefix) || !prefix.address.is_ipv4() {
        return String::new();
    }
    let prefix = prefix.masked();
    format!(
        "{} {}",
        prefix.address,
        ipv4_mask(prefix.prefix_len).unwrap()
    )
}

fn is_valid_prefix(prefix: &OpenVpnIpPrefix) -> bool {
    (prefix.address.is_ipv4() && prefix.prefix_len <= 32)
        || (prefix.address.is_ipv6() && prefix.prefix_len <= 128)
}

fn ipv4_mask(bits: u8) -> Option<Ipv4Addr> {
    (bits <= 32).then(|| {
        Ipv4Addr::from(if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        })
    })
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use super::*;
    use crate::protocol::openvpn::{
        PushedCompressionDirective, TunnelDnsServer,
        decode_push_reply_option_lines,
    };

    fn prefix(value: &str, bits: u8) -> OpenVpnIpPrefix {
        OpenVpnIpPrefix {
            address: value.parse().unwrap(),
            prefix_len: bits,
        }
    }

    #[test]
    fn formats_ifconfig_topologies_and_routes() {
        let subnet = PushedLocalAddress {
            prefix: prefix("10.8.0.2", 24),
            peer: None,
            raw: String::new(),
        };
        assert_eq!(
            format_pushed_ifconfig(&subnet, "subnet"),
            "10.8.0.2 255.255.255.0"
        );
        assert_eq!(format_pushed_ifconfig(&subnet, "net30"), "");
        let p2p = PushedLocalAddress {
            peer: Some("10.8.0.1".parse().unwrap()),
            ..subnet
        };
        assert_eq!(format_pushed_ifconfig(&p2p, "net30"), "10.8.0.2 10.8.0.1");
        let route = PushedRouteEntry {
            route: PushedRoute {
                prefix: prefix("10.9.1.5", 24),
                gateway: Some("10.8.0.1".parse().unwrap()),
                metric: 7,
                excluded: false,
            },
            raw: String::new(),
        };
        assert_eq!(
            format_pushed_route(&route),
            "10.9.1.0 255.255.255.0 10.8.0.1 7"
        );
    }

    #[test]
    fn formats_push_fields_in_upstream_order() {
        let options = PushedOptions {
            topology: "subnet".into(),
            tun_mtu: 1500,
            local_address: vec![
                PushedLocalAddress {
                    prefix: prefix("10.8.0.2", 24),
                    peer: None,
                    raw: String::new(),
                },
                PushedLocalAddress {
                    prefix: prefix("fd00::2", 64),
                    peer: Some("fd00::1".parse().unwrap()),
                    raw: String::new(),
                },
            ],
            route_gateway_vpn: true,
            routes: pushed_routes_from_prefixes(&[
                prefix("10.9.1.5", 24),
                prefix("fd01::123", 64),
            ]),
            dns: pushed_addresses_from_addresses(&[
                "1.1.1.1".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ]),
            search_domains: vec!["corp.example".into()],
            dns_servers: vec![TunnelDnsServer {
                priority: 7,
                addresses: vec![SocketAddr::new("9.9.9.9".parse().unwrap(), 0)],
                resolve_domains: vec!["example.com".into()],
                dnssec: "yes".into(),
                transport: "doh".into(),
                sni: "dns.example".into(),
            }],
            dhcp_options: vec!["WINS 192.0.2.1".into()],
            block_ipv6: true,
            redirect_gateway: true,
            redirect_gateway_flags: vec!["def1".into()],
            route_metric: 9,
            ping_interval: Duration::from_secs(5),
            ping_interval_enabled: true,
            auth_token: " token ".into(),
            peer_id: Some(42),
            protocol_flags: vec!["cc-exit".into(), "tls-ekm".into()],
            explicit_exit_notify: 2,
            compression_directives: vec![PushedCompressionDirective {
                name: "compress".into(),
                value: "stub-v2".into(),
            }],
            inactive_timeout: Duration::from_secs(60),
            inactive_minimum_bytes: 100,
            ping_timer_remote: true,
            ..PushedOptions::default()
        };
        let fields = build_push_reply_option_fields(&options);
        assert_eq!(fields[0], "PUSH_REPLY");
        assert_eq!(fields[1], "topology subnet");
        assert!(fields.contains(&"route 10.9.1.0 255.255.255.0".into()));
        assert!(fields.contains(&"route-ipv6 fd01::/64".into()));
        assert!(fields.contains(&"dns server 7 transport DoH".into()));
        assert_eq!(fields.last().unwrap(), "ping-timer-rem");
    }

    #[test]
    fn push_fields_decode_back_to_equivalent_wire_options() {
        let original = PushedOptions {
            topology: "subnet".into(),
            tun_mtu: 1400,
            local_address: vec![PushedLocalAddress {
                prefix: prefix("10.8.0.2", 24),
                peer: None,
                raw: String::new(),
            }],
            routes: pushed_routes_from_prefixes(&[prefix("10.9.0.0", 16)]),
            ping_restart: Duration::from_secs(30),
            ping_restart_enabled: true,
            selected_cipher: "AES-256-GCM".into(),
            ..PushedOptions::default()
        };
        let fields = build_push_reply_option_fields(&original);
        let (decoded, continuation) =
            decode_push_reply_option_lines(&fields[0], &fields[1..], None, &[]);
        assert_eq!(continuation, 0);
        assert_eq!(decoded.topology, original.topology);
        assert_eq!(decoded.tun_mtu, original.tun_mtu);
        assert_eq!(
            decoded.local_address[0].prefix,
            original.local_address[0].prefix
        );
        assert_eq!(
            decoded.routes[0].route.prefix,
            original.routes[0].route.prefix
        );
        assert_eq!(decoded.ping_restart, original.ping_restart);
        assert_eq!(decoded.selected_cipher, original.selected_cipher);
    }

    #[test]
    fn family_helpers_replace_only_matching_addresses() {
        let mut addresses = vec![
            PushedLocalAddress {
                prefix: prefix("10.0.0.2", 24),
                peer: None,
                raw: String::new(),
            },
            PushedLocalAddress {
                prefix: prefix("fd00::2", 64),
                peer: None,
                raw: String::new(),
            },
        ];
        assert!(has_pushed_local_address_family(&addresses, true));
        apply_pushed_ipv6_local_address_peer(
            &mut addresses,
            "fd00::1".parse().unwrap(),
        );
        assert_eq!(addresses[1].peer, Some("fd00::1".parse().unwrap()));
        replace_pushed_local_address_by_family(
            &mut addresses,
            PushedLocalAddress {
                prefix: prefix("10.1.0.2", 16),
                peer: None,
                raw: String::new(),
            },
        );
        assert_eq!(addresses.len(), 2);
        assert_eq!(
            addresses[1].prefix.address,
            "10.1.0.2".parse::<IpAddr>().unwrap()
        );
    }
}
