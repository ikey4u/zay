use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use tokio::net::lookup_host;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
    Icmp,
}

impl Network {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

/// Matches sing's definition of a non-public address.  The upstream
/// `ip_is_private` rule is deliberately broader than the Rust standard
/// library's RFC-private helpers: loopback, link-local, multicast, and
/// unspecified addresses are private for routing purposes too.
pub(crate) fn is_private_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_link_local()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            address.is_unique_local()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.is_unspecified()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl SocksAddr {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        match host.parse::<IpAddr>() {
            Ok(address) => Self::Ip(SocketAddr::new(address, port)),
            Err(_) => Self::Domain { host, port },
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ip(address) => address.ip().to_string(),
            Self::Domain { host, .. } => host.clone(),
        }
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    pub const fn is_domain(&self) -> bool {
        matches!(self, Self::Domain { .. })
    }

    pub async fn resolve(&self) -> io::Result<Vec<SocketAddr>> {
        match self {
            Self::Ip(address) => Ok(vec![*address]),
            Self::Domain { host, port } => {
                Ok(lookup_host((host.as_str(), *port)).await?.collect())
            }
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(formatter),
            Self::Domain { host, port } => write!(formatter, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl FromStr for SocksAddr {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse() {
            return Ok(Self::Ip(address));
        }
        let (host, port) = value.rsplit_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing destination port",
            )
        })?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty destination host",
            ));
        }
        let port = port.parse::<u16>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid destination port: {error}"),
            )
        })?;
        Ok(Self::new(host, port))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{SocksAddr, is_private_address};

    #[test]
    fn parses_ip_domain_and_ipv6_addresses() {
        assert!(!"127.0.0.1:53".parse::<SocksAddr>().unwrap().is_domain());
        assert!("example.com:443".parse::<SocksAddr>().unwrap().is_domain());
        assert_eq!(
            "[2001:db8::1]:853".parse::<SocksAddr>().unwrap().port(),
            853
        );
        assert!("missing-port".parse::<SocksAddr>().is_err());
    }

    #[test]
    fn private_address_matches_sing_non_public_semantics() {
        for address in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "fc00::1",
            "::1",
            "fe80::1",
            "::",
            "ff02::1",
        ] {
            let address = address.parse::<IpAddr>().unwrap();
            assert!(is_private_address(&address), "{address} must be private");
        }
        for address in ["8.8.8.8", "2001:4860:4860::8888"] {
            let address = address.parse::<IpAddr>().unwrap();
            assert!(!is_private_address(&address), "{address} must be public");
        }
    }
}
