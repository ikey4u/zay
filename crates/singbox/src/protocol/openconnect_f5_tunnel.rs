//! F5 TLS/DTLS application-probe response parsing.

use std::{io, net::IpAddr};

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const F5_TLS_CONNECT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);
pub const F5_MAXIMUM_STATUS_LINE: usize = 8192;
pub const F5_MAXIMUM_HEADER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F5TunnelStart {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub proposed_ipv4: Option<Ipv4Net>,
    pub proposed_ipv6: Option<Ipv6Net>,
}

#[derive(Debug, Error)]
pub enum F5TunnelError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("F5 tunnel rejected the session with HTTP {0}")]
    SessionRejected(StatusCode),
    #[error("F5 tunnel returned unexpected HTTP {0}")]
    UnexpectedStatus(StatusCode),
    #[error("invalid F5 HTTP status line")]
    InvalidStatusLine,
    #[error("invalid F5 HTTP status code")]
    InvalidStatusCode,
    #[error("F5 HTTP line exceeds {0} bytes")]
    LineTooLarge(usize),
    #[error("F5 HTTP headers exceed {0} bytes")]
    HeadersTooLarge(usize),
    #[error("malformed F5 HTTP response header")]
    MalformedHeader,
    #[error("F5 tunnel returned an invalid {family} address: {value}")]
    InvalidAddress { family: &'static str, value: String },
}

/// Read the response header without reading beyond its terminating empty line.
/// This deliberately avoids a buffered reader: any following bytes are the
/// first PPP frame and must remain in the stream.
pub async fn read_f5_tunnel_start<S>(
    stream: &mut S,
) -> Result<F5TunnelStart, F5TunnelError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut content = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        content.push(byte[0]);
        if content.len() > F5_MAXIMUM_HEADER_SIZE {
            return Err(F5TunnelError::HeadersTooLarge(F5_MAXIMUM_HEADER_SIZE));
        }
        if content.ends_with(b"\r\n\r\n") || content.ends_with(b"\n\n") {
            break;
        }
    }
    parse_f5_tunnel_start(&content)
}

pub fn parse_f5_tunnel_start(
    content: &[u8],
) -> Result<F5TunnelStart, F5TunnelError> {
    if content.len() > F5_MAXIMUM_HEADER_SIZE {
        return Err(F5TunnelError::HeadersTooLarge(F5_MAXIMUM_HEADER_SIZE));
    }
    let text = std::str::from_utf8(content)
        .map_err(|_| F5TunnelError::MalformedHeader)?;
    let mut lines = text.lines().map(|line| line.trim_end_matches('\r'));
    let status_line = lines.next().ok_or(F5TunnelError::InvalidStatusLine)?;
    if status_line.len() > F5_MAXIMUM_STATUS_LINE {
        return Err(F5TunnelError::LineTooLarge(F5_MAXIMUM_STATUS_LINE));
    }
    let mut status_parts = status_line.split_whitespace();
    if !status_parts
        .next()
        .is_some_and(|part| part.starts_with("HTTP/"))
    {
        return Err(F5TunnelError::InvalidStatusLine);
    }
    let status_number = status_parts
        .next()
        .ok_or(F5TunnelError::InvalidStatusCode)?
        .parse::<u16>()
        .map_err(|_| F5TunnelError::InvalidStatusCode)?;
    let status = StatusCode::from_u16(status_number)
        .map_err(|_| F5TunnelError::InvalidStatusCode)?;
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.len() > F5_MAXIMUM_STATUS_LINE {
            return Err(F5TunnelError::LineTooLarge(F5_MAXIMUM_STATUS_LINE));
        }
        let (name, value) =
            line.split_once(':').ok_or(F5TunnelError::MalformedHeader)?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| F5TunnelError::MalformedHeader)?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| F5TunnelError::MalformedHeader)?;
        headers.append(name, value);
    }
    match status {
        StatusCode::OK | StatusCode::CREATED => {}
        StatusCode::GATEWAY_TIMEOUT => {
            return Err(F5TunnelError::SessionRejected(status));
        }
        status if status.is_client_error() => {
            return Err(F5TunnelError::SessionRejected(status));
        }
        status => return Err(F5TunnelError::UnexpectedStatus(status)),
    }
    let (proposed_ipv4, proposed_ipv6) = parse_f5_proposed_addresses(&headers)?;
    Ok(F5TunnelStart {
        status,
        headers,
        proposed_ipv4,
        proposed_ipv6,
    })
}

pub fn parse_f5_proposed_addresses(
    headers: &HeaderMap,
) -> Result<(Option<Ipv4Net>, Option<Ipv6Net>), F5TunnelError> {
    let ipv4 = parse_address_header(headers, "x-vpn-client-ip", "IPv4")?;
    let proposed_ipv4 = match ipv4 {
        Some(IpAddr::V4(address)) => Some(Ipv4Net::new(address, 32).unwrap()),
        Some(address) => {
            return Err(F5TunnelError::InvalidAddress {
                family: "IPv4",
                value: address.to_string(),
            });
        }
        None => None,
    };
    let ipv6 = parse_address_header(headers, "x-vpn-client-ipv6", "IPv6")?;
    let proposed_ipv6 = match ipv6 {
        Some(IpAddr::V6(address)) if address.to_ipv4_mapped().is_none() => {
            Some(Ipv6Net::new(address, 64).unwrap())
        }
        Some(address) => {
            return Err(F5TunnelError::InvalidAddress {
                family: "IPv6",
                value: address.to_string(),
            });
        }
        None => None,
    };
    Ok((proposed_ipv4, proposed_ipv6))
}

pub fn f5_dtls_record_mtu(address: IpAddr) -> usize {
    if address.is_ipv6() { 1232 } else { 1400 }
}

fn parse_address_header(
    headers: &HeaderMap,
    name: &'static str,
    family: &'static str,
) -> Result<Option<IpAddr>, F5TunnelError> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value.to_str().map(str::trim).map_err(|_| {
        F5TunnelError::InvalidAddress {
            family,
            value: "<non-UTF-8>".into(),
        }
    })?;
    if value.is_empty() {
        return Ok(None);
    }
    value.parse::<IpAddr>().map(Some).map_err(|_| {
        F5TunnelError::InvalidAddress {
            family,
            value: value.to_owned(),
        }
    })
}

pub fn f5_proposed_addresses_as_ipnets(start: &F5TunnelStart) -> Vec<IpNet> {
    start
        .proposed_ipv4
        .map(IpNet::V4)
        .into_iter()
        .chain(start.proposed_ipv6.map(IpNet::V6))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_success_and_proposed_addresses() {
        let start = parse_f5_tunnel_start(
            b"HTTP/1.1 201 Created\r\nX-VPN-client-IP: 10.0.0.7\r\nX-VPN-client-IPv6: 2001:db8::7\r\n\r\n",
        )
        .unwrap();
        assert_eq!(start.status, StatusCode::CREATED);
        assert_eq!(start.proposed_ipv4.unwrap().to_string(), "10.0.0.7/32");
        assert_eq!(start.proposed_ipv6.unwrap().to_string(), "2001:db8::7/64");
    }

    #[test]
    fn classifies_rejection_and_malformed_values() {
        assert!(matches!(
            parse_f5_tunnel_start(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n"),
            Err(F5TunnelError::SessionRejected(StatusCode::GATEWAY_TIMEOUT))
        ));
        assert!(matches!(
            parse_f5_tunnel_start(
                b"HTTP/1.1 200 OK\r\nX-VPN-client-IP: 2001:db8::1\r\n\r\n"
            ),
            Err(F5TunnelError::InvalidAddress { family: "IPv4", .. })
        ));
        assert!(matches!(
            parse_f5_tunnel_start(b"garbage\r\n\r\n"),
            Err(F5TunnelError::InvalidStatusLine)
        ));
    }

    #[tokio::test]
    async fn async_reader_stops_before_first_ppp_byte() {
        let mut stream = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nX-VPN-client-IP: 10.1.2.3\r\n\r\nPPP".to_vec(),
        );
        let start = read_f5_tunnel_start(&mut stream).await.unwrap();
        assert_eq!(start.proposed_ipv4.unwrap().to_string(), "10.1.2.3/32");
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"PPP");
    }

    #[test]
    fn record_mtu_tracks_outer_ip_family() {
        assert_eq!(f5_dtls_record_mtu("192.0.2.1".parse().unwrap()), 1400);
        assert_eq!(f5_dtls_record_mtu("2001:db8::1".parse().unwrap()), 1232);
    }
}
