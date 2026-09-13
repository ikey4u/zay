use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenVpnIpPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl OpenVpnIpPrefix {
    pub fn masked(self) -> Self {
        let address = match self.address {
            IpAddr::V4(address) => {
                let bits = u32::from(address);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
            IpAddr::V6(address) => {
                let bits = u128::from(address);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        };
        Self { address, ..self }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushedRoute {
    pub prefix: OpenVpnIpPrefix,
    pub gateway: Option<IpAddr>,
    pub metric: i32,
    pub excluded: bool,
}

pub fn parse_ifconfig_vpn_gateway(
    values: &[String],
    topology: &str,
) -> Option<Ipv4Addr> {
    if topology.trim().eq_ignore_ascii_case("subnet") {
        return None;
    }
    values.iter().find_map(|value| {
        let gateway: Ipv4Addr =
            value.split_whitespace().nth(1)?.parse().ok()?;
        (!is_ipv4_mask_gateway(gateway)).then_some(gateway)
    })
}

pub fn is_net_gateway_token(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "net_gateway" | "dhcp"
    )
}

pub fn parse_ifconfig_prefix(
    value: &str,
    topology: &str,
) -> Result<OpenVpnIpPrefix, RouteOptionError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(RouteOptionError::EmptyIfconfig);
    }
    if value.contains('/') {
        return parse_prefix(value);
    }
    let fields: Vec<_> = value.split_whitespace().collect();
    if fields.len() != 2 {
        return Err(RouteOptionError::InvalidIfconfig(value.into()));
    }
    let local: Ipv4Addr = fields[0]
        .parse()
        .map_err(|_| RouteOptionError::ExpectedIpv4(fields[0].into()))?;
    let mask_bits = dotted_ipv4_mask_bits(fields[1]);
    let topology = if topology.trim().is_empty() {
        if mask_bits.is_some() {
            "subnet"
        } else {
            "net30"
        }
    } else {
        topology.trim()
    };
    let prefix_len = match topology.to_ascii_lowercase().as_str() {
        "subnet" => mask_bits.ok_or_else(|| {
            RouteOptionError::SubnetRequiresMask(value.into())
        })?,
        "p2p" => {
            fields[1].parse::<Ipv4Addr>().map_err(|_| {
                RouteOptionError::ExpectedIpv4(fields[1].into())
            })?;
            32
        }
        "net30" => {
            fields[1].parse::<Ipv4Addr>().map_err(|_| {
                RouteOptionError::ExpectedIpv4(fields[1].into())
            })?;
            30
        }
        _ => {
            return Err(RouteOptionError::UnsupportedTopology(topology.into()));
        }
    };
    Ok(OpenVpnIpPrefix {
        address: local.into(),
        prefix_len,
    })
}

pub fn parse_ipv6_address_prefix(
    token: &str,
) -> Result<OpenVpnIpPrefix, RouteOptionError> {
    let (address, bits) = match token.split_once('/') {
        None => (token, 64),
        Some((address, "")) => (address, 0),
        Some((address, bits)) => {
            let bits = bits.parse::<u8>().map_err(|_| {
                RouteOptionError::InvalidPrefixBits(bits.into())
            })?;
            if bits > 128 {
                return Err(RouteOptionError::InvalidPrefixBits(
                    bits.to_string(),
                ));
            }
            (address, bits)
        }
    };
    let address = parse_ipv6_address(address)?;
    Ok(OpenVpnIpPrefix {
        address: address.into(),
        prefix_len: bits,
    })
}

pub fn parse_ifconfig_ipv6(
    row: &str,
) -> Result<(OpenVpnIpPrefix, Ipv6Addr), RouteOptionError> {
    let fields: Vec<_> = row.split_whitespace().collect();
    if fields.len() != 2 {
        return Err(RouteOptionError::InvalidIfconfigIpv6(row.into()));
    }
    let prefix = parse_ipv6_address_prefix(fields[0])?;
    let remote = parse_ipv6_address(fields[1])?;
    if !(64..=124).contains(&prefix.prefix_len) {
        return Err(RouteOptionError::IfconfigIpv6Prefix(prefix.prefix_len));
    }
    Ok((prefix, remote))
}

pub fn parse_pushed_route(
    row: &str,
    remote_host: Option<IpAddr>,
) -> Result<PushedRoute, RouteOptionError> {
    let fields: Vec<_> = row.split_whitespace().collect();
    let destination = fields.first().ok_or(RouteOptionError::EmptyRoute)?;
    let (address, prefix_len, mut index) = if destination.contains('/') {
        let prefix = parse_prefix(destination)?;
        if !prefix.address.is_ipv4() {
            return Err(RouteOptionError::ExpectedIpv4((*destination).into()));
        }
        (prefix.address, prefix.prefix_len, 1)
    } else {
        let address: Ipv4Addr = destination.parse().map_err(|_| {
            RouteOptionError::ExpectedIpv4((*destination).into())
        })?;
        let mut bits = 32;
        let mut index = 1;
        if let Some(mask) =
            fields.get(1).and_then(|value| dotted_ipv4_mask_bits(value))
        {
            bits = mask;
            index = 2;
        }
        (address.into(), bits, index)
    };
    let mut gateway = None;
    let mut metric = 0;
    let mut excluded = false;
    if let Some(value) = fields.get(index) {
        if let Ok(value) = value.parse::<i32>() {
            metric = value;
            index += 1;
        } else {
            (gateway, excluded) =
                parse_route_gateway(value, remote_host, true)?;
            index += 1;
        }
    }
    if let Some(value) = fields.get(index) {
        metric = value
            .parse()
            .map_err(|_| RouteOptionError::InvalidMetric((*value).into()))?;
    }
    Ok(PushedRoute {
        prefix: OpenVpnIpPrefix {
            address,
            prefix_len,
        },
        gateway,
        metric,
        excluded,
    })
}

pub fn parse_pushed_route_ipv6(
    row: &str,
    remote_host: Option<IpAddr>,
) -> Result<PushedRoute, RouteOptionError> {
    let fields: Vec<_> = row.split_whitespace().collect();
    let destination = fields.first().ok_or(RouteOptionError::EmptyRouteIpv6)?;
    let prefix = parse_ipv6_address_prefix(destination)?.masked();
    let mut gateway = None;
    let mut metric = 0;
    let mut excluded = false;
    let mut index = 1;
    if let Some(value) = fields.get(index) {
        if let Ok(value) = value.parse::<i32>() {
            metric = value;
            index += 1;
        } else {
            (gateway, excluded) =
                parse_route_gateway(value, remote_host, false)?;
            index += 1;
        }
    }
    if let Some(value) = fields.get(index) {
        metric = value
            .parse()
            .map_err(|_| RouteOptionError::InvalidMetric((*value).into()))?;
    }
    Ok(PushedRoute {
        prefix,
        gateway,
        metric,
        excluded,
    })
}

fn parse_route_gateway(
    token: &str,
    remote_host: Option<IpAddr>,
    ipv4: bool,
) -> Result<(Option<IpAddr>, bool), RouteOptionError> {
    let token = token.trim();
    if token.is_empty() || token.eq_ignore_ascii_case("vpn_gateway") {
        return Ok((None, false));
    }
    if token.eq_ignore_ascii_case("remote_host") {
        return Ok((
            remote_host.filter(|address| address.is_ipv4() == ipv4),
            false,
        ));
    }
    if is_net_gateway_token(token) {
        return Ok((None, true));
    }
    let gateway: IpAddr = token
        .parse()
        .map_err(|_| RouteOptionError::InvalidGateway(token.into()))?;
    if gateway.is_ipv4() != ipv4 {
        return Err(RouteOptionError::WrongGatewayFamily(token.into()));
    }
    Ok((Some(gateway), false))
}

fn parse_prefix(token: &str) -> Result<OpenVpnIpPrefix, RouteOptionError> {
    let (address, prefix) = token
        .split_once('/')
        .ok_or_else(|| RouteOptionError::InvalidPrefix(token.into()))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| RouteOptionError::InvalidPrefix(token.into()))?;
    let prefix_len: u8 = prefix
        .parse()
        .map_err(|_| RouteOptionError::InvalidPrefixBits(prefix.into()))?;
    if (address.is_ipv4() && prefix_len > 32) || prefix_len > 128 {
        return Err(RouteOptionError::InvalidPrefixBits(prefix.into()));
    }
    Ok(OpenVpnIpPrefix {
        address,
        prefix_len,
    })
}

fn parse_ipv6_address(token: &str) -> Result<Ipv6Addr, RouteOptionError> {
    if token.contains('%') {
        return Err(RouteOptionError::ExpectedIpv6(token.into()));
    }
    token
        .parse()
        .map_err(|_| RouteOptionError::ExpectedIpv6(token.into()))
}

fn dotted_ipv4_mask_bits(token: &str) -> Option<u8> {
    let mask = u32::from(token.parse::<Ipv4Addr>().ok()?);
    let inverted = !mask;
    ((inverted & inverted.wrapping_add(1)) == 0)
        .then_some(mask.count_ones() as u8)
}

fn is_ipv4_mask_gateway(address: Ipv4Addr) -> bool {
    dotted_ipv4_mask_bits(&address.to_string()).is_some_and(|bits| bits < 32)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteOptionError {
    #[error("empty ifconfig")]
    EmptyIfconfig,
    #[error("invalid ifconfig: {0}")]
    InvalidIfconfig(String),
    #[error("ifconfig subnet topology requires a dotted-quad netmask: {0}")]
    SubnetRequiresMask(String),
    #[error("unsupported OpenVPN topology: {0}")]
    UnsupportedTopology(String),
    #[error("expected an IPv4 address: {0}")]
    ExpectedIpv4(String),
    #[error("expected an IPv6 address without a zone: {0}")]
    ExpectedIpv6(String),
    #[error("invalid IP prefix: {0}")]
    InvalidPrefix(String),
    #[error("invalid IP prefix length: {0}")]
    InvalidPrefixBits(String),
    #[error("ifconfig-ipv6 expects local and remote endpoints: {0}")]
    InvalidIfconfigIpv6(String),
    #[error("ifconfig-ipv6 prefix must be between 64 and 124, got {0}")]
    IfconfigIpv6Prefix(u8),
    #[error("empty route")]
    EmptyRoute,
    #[error("empty route-ipv6")]
    EmptyRouteIpv6,
    #[error("invalid route gateway: {0}")]
    InvalidGateway(String),
    #[error("route gateway uses the wrong address family: {0}")]
    WrongGatewayFamily(String),
    #[error("invalid route metric: {0}")]
    InvalidMetric(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ifconfig_topologies_and_ipv6_defaults() {
        assert_eq!(
            parse_ifconfig_prefix("10.8.0.2 255.255.255.0", "").unwrap(),
            OpenVpnIpPrefix {
                address: "10.8.0.2".parse().unwrap(),
                prefix_len: 24
            }
        );
        assert_eq!(
            parse_ifconfig_prefix("10.8.0.2 10.8.0.1", "p2p")
                .unwrap()
                .prefix_len,
            32
        );
        assert_eq!(
            parse_ipv6_address_prefix("fd00::2").unwrap().prefix_len,
            64
        );
        assert_eq!(
            parse_ipv6_address_prefix("fd00::2/").unwrap().prefix_len,
            0
        );
        assert!(parse_ifconfig_ipv6("fd00::2/63 fd00::1").is_err());
        assert!(parse_ifconfig_ipv6("fd00::2/64 fd00::1").is_ok());
    }

    #[test]
    fn finds_non_mask_p2p_gateway() {
        assert_eq!(
            parse_ifconfig_vpn_gateway(
                &["10.8.0.2 255.255.255.0".into(), "10.8.0.2 10.8.0.1".into()],
                "net30"
            ),
            Some("10.8.0.1".parse().unwrap())
        );
        assert_eq!(
            parse_ifconfig_vpn_gateway(&["10.0.0.2 10.0.0.1".into()], "subnet"),
            None
        );
    }

    #[test]
    fn parses_ipv4_route_gateway_metric_and_exclusion_tokens() {
        let route = parse_pushed_route(
            "10.9.1.5 255.255.255.0 remote_host 42",
            Some("203.0.113.7".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(route.prefix.address, "10.9.1.5".parse::<IpAddr>().unwrap());
        assert_eq!(route.prefix.prefix_len, 24);
        assert_eq!(route.gateway, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(route.metric, 42);
        assert!(!route.excluded);

        let excluded =
            parse_pushed_route("0.0.0.0/1 net_gateway", None).unwrap();
        assert!(excluded.excluded);
    }

    #[test]
    fn parses_and_masks_ipv6_routes() {
        let route = parse_pushed_route_ipv6("fd00::123/64 vpn_gateway 7", None)
            .unwrap();
        assert_eq!(route.prefix.address, "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(route.prefix.prefix_len, 64);
        assert_eq!(route.metric, 7);
    }
}
