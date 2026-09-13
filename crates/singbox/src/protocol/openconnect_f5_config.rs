//! F5 VPN profile/options configuration and TCP connect request primitives.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, SystemTime},
};

use base64::Engine as _;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;
use url::Url;

use super::{TunnelConfiguration, TunnelRoute, gp_config::parse_xml};

pub const F5_CONFIGURATION_CLIENT_VERSION: &str = "2.0";
pub const F5_DEFAULT_TUNNEL_MTU: u32 = 1400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F5TunnelConfiguration {
    pub configuration: TunnelConfiguration,
    pub session_id: String,
    pub ur_z: String,
    pub want_ipv4: bool,
    pub want_ipv6: bool,
    pub hdlc: bool,
    pub dtls_enabled: bool,
    pub dtls_port: u16,
    pub dtls12: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum F5ConfigurationError {
    #[error("invalid F5 XML: {0}")]
    InvalidXml(String),
    #[error("invalid F5 configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid F5 connect request: {0}")]
    InvalidRequest(String),
}

pub fn parse_f5_profile(
    content: &[u8],
) -> Result<String, F5ConfigurationError> {
    let root = parse_xml(content)
        .map_err(|error| F5ConfigurationError::InvalidXml(error.to_string()))?;
    if root.name != "favorites" || root.attribute("type") != Some("VPN") {
        return Err(invalid("VPN profile has no VPN favorites root"));
    }
    root.children
        .iter()
        .filter(|child| child.name == "favorite")
        .filter_map(|favorite| favorite.child_text("params"))
        .map(str::trim)
        .find(|parameters| !parameters.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid("VPN profile has no favorite parameters"))
}

pub fn parse_f5_options(
    content: &[u8],
    authentication_expiration: Option<SystemTime>,
) -> Result<F5TunnelConfiguration, F5ConfigurationError> {
    let root = parse_xml(content)
        .map_err(|error| F5ConfigurationError::InvalidXml(error.to_string()))?;
    if root.name != "favorite" {
        return Err(invalid("VPN options root is not favorite"));
    }
    let object = root
        .children
        .first()
        .filter(|child| child.name == "object")
        .ok_or_else(|| invalid("VPN options favorite has no object"))?;
    let mut result = F5TunnelConfiguration {
        configuration: TunnelConfiguration {
            mtu: F5_DEFAULT_TUNNEL_MTU,
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
            authentication_expiration,
        },
        session_id: String::new(),
        ur_z: String::new(),
        want_ipv4: false,
        want_ipv6: false,
        hdlc: false,
        dtls_enabled: false,
        dtls_port: 0,
        dtls12: false,
    };
    let mut default_route = false;
    let mut dtls_advertised = false;
    let mut dns_count = 0;
    let mut nbns_count = 0;
    for field in &object.children {
        let name = field.name.as_str();
        let value = field.text.trim();
        match name {
            "ur_Z" => result.ur_z = value.to_owned(),
            "Session_ID" => result.session_id = value.to_owned(),
            "IPV4_0" => result.want_ipv4 = parse_f5_boolean(value)?,
            "IPV6_0" => result.want_ipv6 = parse_f5_boolean(value)?,
            "hdlc_framing" => result.hdlc = parse_f5_boolean(value)?,
            "idle_session_timeout" => {
                result.configuration.idle_timeout = Duration::from_secs(
                    parse_nonnegative_integer(value, "idle timeout")?,
                );
            }
            "tunnel_dtls" => dtls_advertised = parse_f5_boolean(value)?,
            "tunnel_port_dtls" => {
                result.dtls_port = if value.is_empty() {
                    0
                } else {
                    value.parse::<u16>().map_err(|_| {
                        invalid(format!("DTLS port is invalid: {value}"))
                    })?
                };
            }
            "dtls_v1_2_supported" => result.dtls12 = parse_f5_boolean(value)?,
            "UseDefaultGateway0" => default_route = parse_f5_boolean(value)?,
            _ if indexed(name, "DNS") || indexed(name, "DNS6_") => {
                if !value.is_empty() && dns_count < 3 {
                    result.configuration.dns.push(parse_ip(value, "DNS")?);
                    dns_count += 1;
                }
            }
            _ if indexed(name, "WINS") => {
                if !value.is_empty() && nbns_count < 3 {
                    result.configuration.nbns.push(parse_ip(value, "NBNS")?);
                    nbns_count += 1;
                }
            }
            _ if indexed(name, "DNSSuffix") => {
                if !value.is_empty() {
                    result.configuration.search_domains.push(value.to_owned());
                }
            }
            _ if indexed(name, "DNS_SPLIT") => result
                .configuration
                .split_dns
                .extend(value.split_whitespace().map(str::to_owned)),
            _ if indexed(name, "LAN") || indexed(name, "LAN6_") => {
                result.configuration.routes.extend(parse_routes(value)?);
            }
            _ if indexed(name, "ExcludeSubnets")
                || indexed(name, "ExcludeSubnets6_") =>
            {
                result
                    .configuration
                    .excluded_routes
                    .extend(parse_routes(value)?);
            }
            _ => {}
        }
    }
    if result.session_id.is_empty() || result.ur_z.is_empty() {
        return Err(invalid("VPN options is missing Session_ID or ur_Z"));
    }
    if !result.want_ipv4 && !result.want_ipv6 {
        return Err(invalid("VPN options enables no network family"));
    }
    if default_route {
        if result.want_ipv4 {
            result.configuration.routes.push(TunnelRoute {
                prefix: IpNet::V4(
                    Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                ),
                gateway: None,
                metric: 0,
            });
        }
        if result.want_ipv6 {
            result.configuration.routes.push(TunnelRoute {
                prefix: IpNet::V6(
                    Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
                ),
                gateway: None,
                metric: 0,
            });
        }
    }
    result.dtls_enabled =
        dtls_advertised && result.dtls_port != 0 && !result.hdlc;
    Ok(result)
}

pub fn build_f5_connect_request(
    endpoint: &Url,
    local_hostname: &str,
    user_agent: &str,
    configuration: &F5TunnelConfiguration,
) -> Result<Vec<u8>, F5ConfigurationError> {
    if endpoint.scheme() != "https" {
        return Err(request("connect endpoint is not HTTPS"));
    }
    for (description, value) in [
        ("session ID", configuration.session_id.as_str()),
        ("ur_Z", configuration.ur_z.as_str()),
        ("local hostname", local_hostname),
        ("user agent", user_agent),
    ] {
        if value.contains(['\r', '\n']) {
            return Err(request(format!(
                "connect {description} contains a line break"
            )));
        }
    }
    let host = endpoint
        .host_str()
        .ok_or_else(|| request("connect endpoint has no host"))?;
    let port = endpoint.port_or_known_default().unwrap_or(443);
    let host_header = if port != 443 {
        if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let yes_no = |value| if value { "yes" } else { "no" };
    let hostname =
        base64::engine::general_purpose::STANDARD.encode(local_hostname);
    Ok(format!(
        "GET /myvpn?sess={}&hdlc_framing={}&ipv4={}&ipv6={}&Z={}&hostname={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n",
        configuration.session_id,
        yes_no(configuration.hdlc),
        yes_no(configuration.want_ipv4),
        yes_no(configuration.want_ipv6),
        configuration.ur_z,
        hostname,
        host_header,
        user_agent,
    )
    .into_bytes())
}

pub fn parse_f5_boolean(value: &str) -> Result<bool, F5ConfigurationError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "" | "0" | "no" | "false" | "off" => Ok(false),
        value => value
            .parse::<i64>()
            .map(|integer| integer != 0)
            .map_err(|_| invalid(format!("invalid F5 boolean value: {value}"))),
    }
}

fn parse_nonnegative_integer(
    value: &str,
    description: &str,
) -> Result<u64, F5ConfigurationError> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| invalid(format!("invalid F5 {description}: {value}")))
}

fn indexed(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|suffix| suffix.as_bytes().first())
        .is_some_and(u8::is_ascii_digit)
}

fn parse_ip(
    value: &str,
    description: &str,
) -> Result<IpAddr, F5ConfigurationError> {
    value
        .parse::<IpAddr>()
        .map(|address| match address {
            IpAddr::V6(address) if address.to_ipv4_mapped().is_some() => {
                IpAddr::V4(address.to_ipv4_mapped().unwrap())
            }
            address => address,
        })
        .map_err(|_| {
            invalid(format!("{description} address is invalid: {value}"))
        })
}

fn parse_routes(value: &str) -> Result<Vec<TunnelRoute>, F5ConfigurationError> {
    value
        .split_whitespace()
        .map(|word| {
            word.parse::<IpNet>()
                .map(|prefix| TunnelRoute {
                    prefix: prefix.trunc(),
                    gateway: None,
                    metric: 0,
                })
                .map_err(|_| invalid(format!("F5 route is invalid: {word}")))
        })
        .collect()
}

fn invalid(message: impl Into<String>) -> F5ConfigurationError {
    F5ConfigurationError::InvalidConfiguration(message.into())
}

fn request(message: impl Into<String>) -> F5ConfigurationError {
    F5ConfigurationError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_selects_first_nonempty_vpn_favorite() {
        assert_eq!(
            parse_f5_profile(
                br#"<favorites type="VPN"><favorite><params> </params></favorite><favorite><params>resourcename=/Common/vpn&amp;foo=bar</params></favorite></favorites>"#,
            )
            .unwrap(),
            "resourcename=/Common/vpn&foo=bar"
        );
        assert!(parse_f5_profile(b"<favorites type=\"WEB\"/>").is_err());
    }

    #[test]
    fn options_parse_network_dns_routes_and_dtls() {
        let xml = br#"<favorite><object>
          <ur_Z>token</ur_Z><Session_ID>session</Session_ID>
          <IPV4_0>yes</IPV4_0><IPV6_0>1</IPV6_0>
          <hdlc_framing>no</hdlc_framing><idle_session_timeout>90</idle_session_timeout>
          <tunnel_dtls>true</tunnel_dtls><tunnel_port_dtls>4443</tunnel_port_dtls>
          <dtls_v1_2_supported>0</dtls_v1_2_supported><UseDefaultGateway0>0</UseDefaultGateway0>
          <DNS0>10.0.0.53</DNS0><DNS1>10.0.0.54</DNS1><DNS2>10.0.0.55</DNS2><DNS3>10.0.0.56</DNS3>
          <DNS6_0>2001:db8::53</DNS6_0><WINS0>10.0.0.10</WINS0>
          <DNSSuffix0>corp.example</DNSSuffix0><DNS_SPLIT0>one.example two.example</DNS_SPLIT0>
          <LAN0>10.0.0.7/8 192.168.1.1/24</LAN0><LAN6_0>2001:db8:1::1/64</LAN6_0>
          <ExcludeSubnets0>203.0.113.9/24</ExcludeSubnets0>
        </object></favorite>"#;
        let configuration = parse_f5_options(xml, None).unwrap();
        assert_eq!(configuration.session_id, "session");
        assert_eq!(configuration.ur_z, "token");
        assert!(configuration.want_ipv4 && configuration.want_ipv6);
        assert!(configuration.dtls_enabled);
        assert_eq!(configuration.dtls_port, 4443);
        assert!(!configuration.dtls12);
        assert_eq!(
            configuration.configuration.idle_timeout,
            Duration::from_secs(90)
        );
        assert_eq!(configuration.configuration.dns.len(), 3);
        assert_eq!(
            configuration.configuration.nbns,
            ["10.0.0.10".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            configuration.configuration.routes[0].prefix.to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            configuration.configuration.excluded_routes[0]
                .prefix
                .to_string(),
            "203.0.113.0/24"
        );
    }

    #[test]
    fn default_routes_follow_enabled_families_and_hdlc_disables_dtls() {
        let configuration = parse_f5_options(
            br#"<favorite><object><ur_Z>z</ur_Z><Session_ID>s</Session_ID><IPV4_0>1</IPV4_0><IPV6_0>0</IPV6_0><UseDefaultGateway0>1</UseDefaultGateway0><hdlc_framing>1</hdlc_framing><tunnel_dtls>1</tunnel_dtls><tunnel_port_dtls>443</tunnel_port_dtls></object></favorite>"#,
            None,
        )
        .unwrap();
        assert_eq!(
            configuration.configuration.routes[0].prefix.to_string(),
            "0.0.0.0/0"
        );
        assert!(!configuration.dtls_enabled);
    }

    #[test]
    fn connect_request_matches_f5_wire_shape() {
        let mut configuration = parse_f5_options(
            br#"<favorite><object><ur_Z>a+b</ur_Z><Session_ID>sid</Session_ID><IPV4_0>1</IPV4_0><IPV6_0>0</IPV6_0></object></favorite>"#,
            None,
        )
        .unwrap();
        configuration.hdlc = true;
        let request = build_f5_connect_request(
            &Url::parse("https://[2001:db8::1]:8443/").unwrap(),
            "workstation",
            "F5 Client/1",
            &configuration,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "GET /myvpn?sess=sid&hdlc_framing=yes&ipv4=yes&ipv6=no&Z=a+b&hostname=d29ya3N0YXRpb24= HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\nUser-Agent: F5 Client/1\r\n\r\n"
        );
    }

    #[test]
    fn malformed_options_fail_closed() {
        assert!(parse_f5_options(b"<favorite/>", None).is_err());
        assert!(parse_f5_options(br#"<favorite><object><ur_Z>z</ur_Z><Session_ID>s</Session_ID><IPV4_0>maybe</IPV4_0></object></favorite>"#, None).is_err());
        assert!(parse_f5_options(br#"<favorite><object><ur_Z>z</ur_Z><Session_ID>s</Session_ID><IPV4_0>1</IPV4_0><LAN0>bad</LAN0></object></favorite>"#, None).is_err());
    }
}
