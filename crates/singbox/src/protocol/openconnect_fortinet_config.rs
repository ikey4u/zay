//! Fortinet XML tunnel configuration and carrier request primitives.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, SystemTime},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;
use url::Url;

use super::{
    TunnelConfiguration, TunnelRoute, TunnelSplitDnsRule, gp_config::parse_xml,
};

pub const FORTINET_DEFAULT_TUNNEL_MTU: u32 = 1400;

pub type FortinetSplitDnsRule = TunnelSplitDnsRule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortinetTunnelConfiguration {
    pub configuration: TunnelConfiguration,
    pub split_dns_rules: Vec<FortinetSplitDnsRule>,
    pub want_ipv4: bool,
    pub want_ipv6: bool,
    pub proposed_ipv4: Option<Ipv4Net>,
    pub proposed_ipv6: Option<Ipv6Net>,
    pub dtls_enabled: bool,
    pub echo_interval: Duration,
    pub reconnect_allowed: bool,
    pub check_source_ip: bool,
    pub cleanup_timeout: Duration,
    pub platform: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FortinetConfigurationError {
    #[error("invalid Fortinet XML: {0}")]
    InvalidXml(String),
    #[error("invalid Fortinet configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid Fortinet tunnel request: {0}")]
    InvalidRequest(String),
}

pub fn parse_fortinet_xml_configuration(
    content: &[u8],
    now: SystemTime,
) -> Result<FortinetTunnelConfiguration, FortinetConfigurationError> {
    let root = parse_xml(content).map_err(|error| {
        FortinetConfigurationError::InvalidXml(error.to_string())
    })?;
    if root.name != "sslvpn-tunnel" {
        return Err(invalid("VPN configuration has no sslvpn-tunnel root"));
    }
    let mut result = FortinetTunnelConfiguration {
        configuration: empty_tunnel_configuration(),
        split_dns_rules: Vec::new(),
        want_ipv4: false,
        want_ipv6: false,
        proposed_ipv4: None,
        proposed_ipv6: None,
        dtls_enabled: root
            .attribute("dtls")
            .map(parse_boolean)
            .transpose()?
            .unwrap_or(false),
        echo_interval: Duration::ZERO,
        reconnect_allowed: false,
        check_source_ip: false,
        cleanup_timeout: Duration::ZERO,
        platform: String::new(),
    };
    let mut ipv4_include_routes = 0;
    let mut ipv6_include_routes = 0;
    for child in &root.children {
        match child.name.as_str() {
            "dtls-config" => {
                if let Some(value) = child.attribute("heartbeat-interval") {
                    result.echo_interval = parse_duration(value)?;
                }
            }
            "idle-timeout" => {
                if let Some(value) = child.attribute("val") {
                    result.configuration.idle_timeout = parse_duration(value)?;
                }
            }
            "auth-timeout" => {
                if let Some(value) = child.attribute("val") {
                    let timeout = parse_duration(value)?;
                    if !timeout.is_zero() {
                        result.configuration.authentication_expiration =
                            now.checked_add(timeout);
                        if result
                            .configuration
                            .authentication_expiration
                            .is_none()
                        {
                            return Err(invalid(
                                "authentication timeout overflows system time",
                            ));
                        }
                    }
                }
            }
            "auth-ses" => parse_reconnect_policy(child, &mut result)?,
            "fos" => result.platform = format_platform(child),
            "ipv4" => {
                ipv4_include_routes +=
                    parse_ip_section(child, false, &mut result)?;
            }
            "ipv6" => {
                ipv6_include_routes +=
                    parse_ip_section(child, true, &mut result)?;
            }
            _ => {}
        }
    }
    if result.want_ipv4 && ipv4_include_routes == 0 {
        result.configuration.routes.push(TunnelRoute {
            prefix: IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            gateway: None,
            metric: 0,
        });
    }
    if result.want_ipv6 && ipv6_include_routes == 0 {
        result.configuration.routes.push(TunnelRoute {
            prefix: IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()),
            gateway: None,
            metric: 0,
        });
    }
    if !result.want_ipv4 && !result.want_ipv6 {
        return Err(invalid(
            "VPN configuration enables no usable network family",
        ));
    }
    result
        .configuration
        .split_dns_rules
        .clone_from(&result.split_dns_rules);
    Ok(result)
}

pub fn build_fortinet_tls_connect_request(
    request_url: &Url,
    cookies: &[(&str, &str)],
    user_agent: &str,
) -> Result<Vec<u8>, FortinetConfigurationError> {
    if request_url.scheme() != "https" {
        return Err(request("tunnel URL is not HTTPS"));
    }
    let host = request_url
        .host_str()
        .ok_or_else(|| request("tunnel URL has no host"))?;
    let port = request_url.port_or_known_default().unwrap_or(443);
    let host_header = if port != 443 {
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
            _ => format!("{host}:{port}"),
        }
    } else if matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if host_header.contains(['\r', '\n']) {
        return Err(request("tunnel Host contains a line break"));
    }
    if cookies.is_empty() {
        return Err(request("tunnel request has no cookies"));
    }
    let mut cookie_header = String::new();
    for (index, (name, value)) in cookies.iter().enumerate() {
        if name.is_empty()
            || format!("{name}{value}").contains(['\r', '\n', ';'])
        {
            return Err(request(
                "tunnel cookie contains invalid request characters",
            ));
        }
        if index != 0 {
            cookie_header.push_str("; ");
        }
        cookie_header.push_str(name);
        cookie_header.push('=');
        cookie_header.push_str(value);
    }
    Ok(format!(
        "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nCookie: {cookie_header}\r\n\r\n"
    )
    .into_bytes())
}

pub fn build_fortinet_dtls_connect_request(
    cookie: &str,
) -> Result<Vec<u8>, FortinetConfigurationError> {
    if cookie.is_empty() || cookie.as_bytes().contains(&0) {
        return Err(request("DTLS cookie is empty or contains NUL"));
    }
    const PREFIX: &[u8] = b"GFtype\0clthello\0SVPNCOOKIE\0";
    let total_length = 2_usize
        .checked_add(PREFIX.len())
        .and_then(|length| length.checked_add(cookie.len()))
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| request("DTLS client hello length overflows"))?;
    let wire_length = u16::try_from(total_length)
        .map_err(|_| request("DTLS client hello exceeds its length field"))?;
    let mut result = Vec::with_capacity(total_length);
    result.extend_from_slice(&wire_length.to_be_bytes());
    result.extend_from_slice(PREFIX);
    result.extend_from_slice(cookie.as_bytes());
    result.push(0);
    Ok(result)
}

fn parse_reconnect_policy(
    node: &super::gp_config::XmlNode,
    result: &mut FortinetTunnelConfiguration,
) -> Result<(), FortinetConfigurationError> {
    let Some(value) = node.attribute("tun-connect-without-reauth") else {
        return Ok(());
    };
    result.reconnect_allowed = parse_boolean(value)?;
    if !result.reconnect_allowed {
        return Ok(());
    }
    if let Some(value) = node.attribute("check-src-ip") {
        result.check_source_ip = parse_boolean(value)?;
    }
    let Some(value) = node.attribute("tun-user-ses-timeout") else {
        result.reconnect_allowed = false;
        return Ok(());
    };
    result.cleanup_timeout = parse_duration(value)?;
    if result.cleanup_timeout.is_zero() {
        result.reconnect_allowed = false;
    }
    Ok(())
}

fn parse_ip_section(
    node: &super::gp_config::XmlNode,
    ipv6: bool,
    result: &mut FortinetTunnelConfiguration,
) -> Result<usize, FortinetConfigurationError> {
    let mut include_routes = 0;
    for child in &node.children {
        match child.name.as_str() {
            "assigned-addr" => {
                let prefix = parse_assigned_address(child, ipv6)?;
                if let IpNet::V6(prefix) = prefix {
                    result.want_ipv6 = true;
                    result.proposed_ipv6 = Some(prefix);
                } else if let IpNet::V4(prefix) = prefix {
                    result.want_ipv4 = true;
                    result.proposed_ipv4 = Some(prefix);
                }
            }
            "dns" => parse_dns(child, ipv6, result)?,
            "split-dns" => {
                result.split_dns_rules.push(parse_split_dns(child, ipv6)?)
            }
            "split-tunnel-info" => {
                let excluded = child
                    .attribute("negate")
                    .map(parse_boolean)
                    .transpose()?
                    .unwrap_or(false);
                for address in
                    child.children.iter().filter(|node| node.name == "addr")
                {
                    let route = TunnelRoute {
                        prefix: parse_route(address, ipv6)?,
                        gateway: None,
                        metric: 0,
                    };
                    if excluded {
                        result.configuration.excluded_routes.push(route);
                    } else {
                        result.configuration.routes.push(route);
                        include_routes += 1;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(include_routes)
}

fn parse_assigned_address(
    node: &super::gp_config::XmlNode,
    ipv6: bool,
) -> Result<IpNet, FortinetConfigurationError> {
    if ipv6 {
        let value = required_attribute(node, "ipv6", "assigned IPv6 address")?;
        let address = value.parse::<Ipv6Addr>().map_err(|_| {
            invalid(format!("assigned address is invalid: {value}"))
        })?;
        if address.to_ipv4_mapped().is_some() {
            return Err(invalid(format!(
                "assigned address is invalid: {value}"
            )));
        }
        let bits = node
            .attribute("prefix-len")
            .map(parse_prefix::<128>)
            .transpose()?
            .unwrap_or(128);
        return Ipv6Net::new(address, bits).map(IpNet::V6).map_err(|error| {
            invalid(format!("assigned IPv6 prefix is invalid: {error}"))
        });
    }
    let value = required_attribute(node, "ipv4", "assigned IPv4 address")?;
    value
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid(format!("assigned address is invalid: {value}")))
        .and_then(|address| {
            Ipv4Net::new(address, 32)
                .map(IpNet::V4)
                .map_err(|error| invalid(error.to_string()))
        })
}

fn parse_dns(
    node: &super::gp_config::XmlNode,
    ipv6: bool,
    result: &mut FortinetTunnelConfiguration,
) -> Result<(), FortinetConfigurationError> {
    if let Some(domain) = node.attribute("domain").map(str::trim)
        && !domain.is_empty()
    {
        result.configuration.search_domains.push(domain.to_owned());
    }
    let attribute = if ipv6 { "ipv6" } else { "ip" };
    let Some(value) = node.attribute(attribute).map(str::trim) else {
        return Ok(());
    };
    if value.is_empty() {
        return Ok(());
    }
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| invalid(format!("DNS address is invalid: {value}")))?;
    if address.is_ipv6() != ipv6
        || matches!(address, IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
    {
        return Err(invalid(format!("DNS address is invalid: {value}")));
    }
    if result.configuration.dns.len() < 3 {
        result.configuration.dns.push(address);
    }
    Ok(())
}

fn parse_split_dns(
    node: &super::gp_config::XmlNode,
    ipv6: bool,
) -> Result<FortinetSplitDnsRule, FortinetConfigurationError> {
    let domains = required_attribute(node, "domains", "split-DNS domains")?
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if domains.iter().any(String::is_empty) {
        return Err(invalid("split-DNS rule contains an empty domain"));
    }
    let mut unique_domains = HashSet::new();
    let domains = domains
        .into_iter()
        .filter(|domain| unique_domains.insert(domain.clone()))
        .collect();
    let mut indexed = HashMap::new();
    let mut highest_nonempty = 0;
    for (name, value) in &node.attributes {
        let Some(suffix) = name.strip_prefix("dnsserver") else {
            continue;
        };
        let index = suffix.parse::<usize>().map_err(|_| {
            invalid(format!("split-DNS server attribute is invalid: {name}"))
        })?;
        if !(1..=9).contains(&index)
            || indexed.insert(index, value.trim()).is_some()
        {
            return Err(invalid(format!(
                "duplicate or invalid split-DNS server attribute: {name}"
            )));
        }
        if !value.trim().is_empty() {
            highest_nonempty = highest_nonempty.max(index);
        }
    }
    let mut servers = Vec::new();
    for index in 1..=highest_nonempty {
        let value = indexed
            .get(&index)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                invalid("split-DNS servers are empty or non-contiguous")
            })?;
        let address = value.parse::<IpAddr>().map_err(|_| {
            invalid(format!("split-DNS server is invalid: {value}"))
        })?;
        if address.is_ipv6() != ipv6
            || matches!(address, IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
        {
            return Err(invalid(format!(
                "split-DNS server is invalid: {value}"
            )));
        }
        if !servers.contains(&address) {
            servers.push(address);
        }
    }
    if servers.is_empty() {
        return Err(invalid("split-DNS rule omitted dedicated servers"));
    }
    Ok(FortinetSplitDnsRule { domains, servers })
}

fn parse_route(
    node: &super::gp_config::XmlNode,
    ipv6: bool,
) -> Result<IpNet, FortinetConfigurationError> {
    if ipv6 {
        let address = required_attribute(node, "ipv6", "IPv6 route address")?;
        let prefix =
            required_attribute(node, "prefix-len", "IPv6 route prefix")?;
        let address = address
            .trim()
            .parse::<Ipv6Addr>()
            .map_err(|_| invalid("IPv6 route address is invalid"))?;
        if address.to_ipv4_mapped().is_some() {
            return Err(invalid("IPv6 route address is IPv4-mapped"));
        }
        let bits = parse_prefix::<128>(prefix)?;
        return Ipv6Net::new(address, bits)
            .map(|prefix| prefix.trunc())
            .map(IpNet::V6)
            .map_err(|error| {
                invalid(format!("IPv6 route is invalid: {error}"))
            });
    }
    let address = required_attribute(node, "ip", "IPv4 route address")?
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid("IPv4 route address is invalid"))?;
    let mask = required_attribute(node, "mask", "IPv4 route mask")?
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid("IPv4 route mask is invalid"))?;
    let bits = contiguous_ipv4_mask(mask).ok_or_else(|| {
        invalid(format!("IPv4 route mask is not contiguous: {mask}"))
    })?;
    Ipv4Net::new(address, bits)
        .map(|prefix| prefix.trunc())
        .map(IpNet::V4)
        .map_err(|error| invalid(format!("IPv4 route is invalid: {error}")))
}

fn parse_boolean(value: &str) -> Result<bool, FortinetConfigurationError> {
    match value.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        value => Err(invalid(format!("invalid Fortinet boolean: {value}"))),
    }
}

fn parse_duration(value: &str) -> Result<Duration, FortinetConfigurationError> {
    let seconds = value.trim().parse::<u64>().map_err(|_| {
        invalid(format!("invalid nonnegative integer: {value}"))
    })?;
    const MAX_GO_DURATION_SECONDS: u64 = i64::MAX as u64 / 1_000_000_000;
    (seconds <= MAX_GO_DURATION_SECONDS)
        .then_some(Duration::from_secs(seconds))
        .ok_or_else(|| {
            invalid(format!("duration exceeds supported range: {value}"))
        })
}

fn parse_prefix<const MAX: u8>(
    value: &str,
) -> Result<u8, FortinetConfigurationError> {
    let bits = value
        .trim()
        .parse::<u8>()
        .map_err(|_| invalid(format!("invalid prefix length: {value}")))?;
    (bits <= MAX)
        .then_some(bits)
        .ok_or_else(|| invalid(format!("invalid prefix length: {value}")))
}

fn contiguous_ipv4_mask(mask: Ipv4Addr) -> Option<u8> {
    let mask = u32::from(mask);
    let bits = mask.leading_ones() as u8;
    let expected = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (mask == expected).then_some(bits)
}

fn format_platform(node: &super::gp_config::XmlNode) -> String {
    let mut result = node.attribute("platform").unwrap_or_default().to_owned();
    for (name, prefix) in [
        ("major", " v"),
        ("minor", "."),
        ("patch", "."),
        ("build", " build "),
        ("branch", " branch "),
        ("mr_num", " mr_num "),
    ] {
        if let Some(value) = node.attribute(name) {
            result.push_str(prefix);
            result.push_str(value);
        }
    }
    result.trim().to_owned()
}

fn required_attribute<'a>(
    node: &'a super::gp_config::XmlNode,
    name: &str,
    description: &str,
) -> Result<&'a str, FortinetConfigurationError> {
    node.attribute(name)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid(format!("{description} is empty")))
}

fn empty_tunnel_configuration() -> TunnelConfiguration {
    TunnelConfiguration {
        mtu: FORTINET_DEFAULT_TUNNEL_MTU,
        remote_address: None,
        addresses: Vec::new(),
        routes: Vec::new(),
        excluded_routes: Vec::new(),
        dns: Vec::new(),
        nbns: Vec::new(),
        search_domains: Vec::new(),
        split_dns: Vec::new(),
        split_dns_rules: Vec::new(),
        proxy_auto_config_url: String::new(),
        banner: String::new(),
        tunnel_all_dns: false,
        client_bypass_protocol: false,
        idle_timeout: Duration::ZERO,
        authentication_expiration: None,
    }
}

fn invalid(message: impl Into<String>) -> FortinetConfigurationError {
    FortinetConfigurationError::InvalidConfiguration(message.into())
}

fn request(message: impl Into<String>) -> FortinetConfigurationError {
    FortinetConfigurationError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_dual_stack_configuration() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let configuration = parse_fortinet_xml_configuration(
            br#"<sslvpn-tunnel dtls="1">
              <dtls-config heartbeat-interval="15"/>
              <idle-timeout val="30"/><auth-timeout val="60"/>
              <auth-ses tun-connect-without-reauth="1" check-src-ip="1" tun-user-ses-timeout="90"/>
              <fos platform="FortiOS" major="7" minor="4" patch="2" build="1"/>
              <ipv4>
                <assigned-addr ipv4="10.1.2.3"/>
                <dns ip="10.0.0.53" domain="corp.example"/>
                <split-dns domains="corp.example, dev.example" dnsserver1="10.0.0.53" dnsserver2="10.0.0.54"/>
                <split-tunnel-info><addr ip="192.0.2.9" mask="255.255.255.0"/></split-tunnel-info>
                <split-tunnel-info negate="1"><addr ip="198.51.100.1" mask="255.255.255.255"/></split-tunnel-info>
              </ipv4>
              <ipv6><assigned-addr ipv6="2001:db8::2" prefix-len="64"/></ipv6>
            </sslvpn-tunnel>"#,
            now,
        )
        .unwrap();
        assert!(configuration.want_ipv4 && configuration.want_ipv6);
        assert!(configuration.dtls_enabled);
        assert_eq!(configuration.echo_interval, Duration::from_secs(15));
        assert_eq!(
            configuration.configuration.idle_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            configuration.configuration.authentication_expiration,
            Some(now + Duration::from_secs(60))
        );
        assert!(
            configuration.reconnect_allowed && configuration.check_source_ip
        );
        assert_eq!(configuration.cleanup_timeout, Duration::from_secs(90));
        assert_eq!(configuration.platform, "FortiOS v7.4.2 build 1");
        assert_eq!(
            configuration.configuration.routes[0].prefix.to_string(),
            "192.0.2.0/24"
        );
        assert_eq!(
            configuration.configuration.excluded_routes[0]
                .prefix
                .to_string(),
            "198.51.100.1/32"
        );
        assert_eq!(configuration.split_dns_rules[0].servers.len(), 2);
        assert_eq!(
            configuration.configuration.split_dns_rules,
            configuration.split_dns_rules
        );
        assert!(configuration.configuration.routes.iter().any(|route| {
            route.prefix
                == IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap())
        }));
    }

    #[test]
    fn adds_ipv4_default_route_when_server_omits_includes() {
        let configuration = parse_fortinet_xml_configuration(
            br#"<sslvpn-tunnel><ipv4><assigned-addr ipv4="10.0.0.2"/></ipv4></sslvpn-tunnel>"#,
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(
            configuration.configuration.routes[0].prefix.to_string(),
            "0.0.0.0/0"
        );
    }

    #[test]
    fn rejects_noncontiguous_routes_and_split_dns_gaps() {
        let route = br#"<sslvpn-tunnel><ipv4><assigned-addr ipv4="10.0.0.2"/><split-tunnel-info><addr ip="10.0.0.0" mask="255.0.255.0"/></split-tunnel-info></ipv4></sslvpn-tunnel>"#;
        assert!(
            parse_fortinet_xml_configuration(route, SystemTime::UNIX_EPOCH)
                .is_err()
        );
        let dns = br#"<sslvpn-tunnel><ipv4><assigned-addr ipv4="10.0.0.2"/><split-dns domains="x" dnsserver2="10.0.0.2"/></ipv4></sslvpn-tunnel>"#;
        assert!(
            parse_fortinet_xml_configuration(dns, SystemTime::UNIX_EPOCH)
                .is_err()
        );
    }

    #[test]
    fn builds_exact_tls_and_dtls_requests() {
        let url = Url::parse("https://[2001:db8::1]:8443/remote/sslvpn-tunnel")
            .unwrap();
        let request = build_fortinet_tls_connect_request(
            &url,
            &[("SVPNCOOKIE", "secret"), ("x", "y")],
            "agent/1",
        )
        .unwrap();
        assert_eq!(
            request,
            b"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\nUser-Agent: agent/1\r\nCookie: SVPNCOOKIE=secret; x=y\r\n\r\n"
        );
        let hello = build_fortinet_dtls_connect_request("secret").unwrap();
        assert_eq!(
            usize::from(u16::from_be_bytes([hello[0], hello[1]])),
            hello.len()
        );
        assert_eq!(&hello[2..], b"GFtype\0clthello\0SVPNCOOKIE\0secret\0");
    }
}
