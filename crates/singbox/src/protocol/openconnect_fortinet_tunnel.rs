//! Fortinet response-less TLS switch and DTLS probe classification.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FORTINET_TLS_CONNECT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);
pub const FORTINET_MAXIMUM_STATUS_LINE: usize = 8192;
pub const FORTINET_MAXIMUM_HEADER_SIZE: usize = 1024 * 1024;
pub const FORTINET_DTLS_IPV4_RECORD_MTU: usize = 1400;
pub const FORTINET_DTLS_IPV6_RECORD_MTU: usize = 1232;

const HTTP_PREFIX: &[u8] = b"HTTP/";
const FORTINET_DTLS_SERVER_HELLO_PREFIX: &[u8] =
    b"GFtype\0svrhello\0handshake\0";
const FORTINET_PPP_MAGIC: u16 = 0x5050;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortinetTlsTunnelStart {
    /// Bytes already read from the first PPP frame while excluding HTTP.
    pub initial_payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum FortinetTunnelError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Fortinet TLS tunnel rejected the session with HTTP {0}")]
    SessionRejected(u16),
    #[error("Fortinet response-less TLS switch returned HTTP {0}")]
    UnexpectedHttpStatus(u16),
    #[error("invalid Fortinet HTTP status line")]
    InvalidStatusLine,
    #[error("invalid Fortinet HTTP status code")]
    InvalidStatusCode,
    #[error("Fortinet HTTP line exceeds {0} bytes")]
    LineTooLarge(usize),
    #[error("Fortinet HTTP headers exceed {0} bytes")]
    HeadersTooLarge(usize),
    #[error("malformed Fortinet HTTP response header")]
    MalformedHeader,
}

/// Classify the first TLS tunnel bytes without losing a partial PPP frame.
///
/// FortiGate normally switches directly from the request to PPP, without an
/// HTTP success response. Authentication failures instead arrive as HTTP.
pub async fn read_fortinet_tls_tunnel_start<R>(
    reader: &mut R,
) -> Result<FortinetTlsTunnelStart, FortinetTunnelError>
where
    R: AsyncRead + Unpin,
{
    let mut pending = Vec::with_capacity(HTTP_PREFIX.len());
    while pending.len() < HTTP_PREFIX.len() {
        pending.push(reader.read_u8().await?);
        if pending != HTTP_PREFIX[..pending.len()] {
            return Ok(FortinetTlsTunnelStart {
                initial_payload: pending,
            });
        }
    }
    let suffix = read_bounded_line(
        reader,
        FORTINET_MAXIMUM_STATUS_LINE - HTTP_PREFIX.len(),
    )
    .await?;
    let mut status_line = HTTP_PREFIX.to_vec();
    status_line.extend_from_slice(&suffix);
    let status_line = std::str::from_utf8(&status_line)
        .map_err(|_| FortinetTunnelError::InvalidStatusLine)?;
    let mut fields = status_line.split_ascii_whitespace();
    let protocol = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if !protocol.starts_with("HTTP/") {
        return Err(FortinetTunnelError::InvalidStatusLine);
    }
    let status = status
        .parse::<u16>()
        .ok()
        .filter(|status| (100..=999).contains(status))
        .ok_or(FortinetTunnelError::InvalidStatusCode)?;
    let mut header_bytes = 0_usize;
    loop {
        let remaining = FORTINET_MAXIMUM_HEADER_SIZE
            .checked_sub(header_bytes)
            .ok_or(FortinetTunnelError::HeadersTooLarge(
                FORTINET_MAXIMUM_HEADER_SIZE,
            ))?;
        if remaining == 0 {
            return Err(FortinetTunnelError::HeadersTooLarge(
                FORTINET_MAXIMUM_HEADER_SIZE,
            ));
        }
        let line = read_bounded_line(reader, remaining).await?;
        header_bytes = header_bytes.saturating_add(line.len() + 2);
        if header_bytes > FORTINET_MAXIMUM_HEADER_SIZE {
            return Err(FortinetTunnelError::HeadersTooLarge(
                FORTINET_MAXIMUM_HEADER_SIZE,
            ));
        }
        if line.is_empty() {
            break;
        }
        if !line.contains(&b':') {
            return Err(FortinetTunnelError::MalformedHeader);
        }
    }
    if (400..=499).contains(&status) {
        Err(FortinetTunnelError::SessionRejected(status))
    } else {
        Err(FortinetTunnelError::UnexpectedHttpStatus(status))
    }
}

pub fn valid_fortinet_dtls_server_hello(content: &[u8]) -> bool {
    if content.len() < 2 + FORTINET_DTLS_SERVER_HELLO_PREFIX.len() + 2
        || usize::from(u16::from_be_bytes([content[0], content[1]]))
            != content.len()
        || content[2..].get(..FORTINET_DTLS_SERVER_HELLO_PREFIX.len())
            != Some(FORTINET_DTLS_SERVER_HELLO_PREFIX)
    {
        return false;
    }
    let status = &content[2 + FORTINET_DTLS_SERVER_HELLO_PREFIX.len()..];
    status == b"ok" || status == b"ok\0"
}

pub fn valid_fortinet_ppp_datagram(content: &[u8]) -> bool {
    if content.len() < 6
        || usize::from(u16::from_be_bytes([content[0], content[1]]))
            != content.len()
        || u16::from_be_bytes([content[2], content[3]]) != FORTINET_PPP_MAGIC
    {
        return false;
    }
    let payload_length =
        usize::from(u16::from_be_bytes([content[4], content[5]]));
    payload_length > 0 && payload_length + 6 == content.len()
}

pub fn fortinet_dtls_record_mtu(accepted_address: std::net::IpAddr) -> usize {
    if accepted_address.is_ipv6() {
        FORTINET_DTLS_IPV6_RECORD_MTU
    } else {
        FORTINET_DTLS_IPV4_RECORD_MTU
    }
}

async fn read_bounded_line<R>(
    reader: &mut R,
    maximum: usize,
) -> Result<Vec<u8>, FortinetTunnelError>
where
    R: AsyncRead + Unpin,
{
    let mut content = Vec::new();
    loop {
        let byte = reader.read_u8().await?;
        if byte == b'\n' {
            if content.last() == Some(&b'\r') {
                content.pop();
            }
            return Ok(content);
        }
        if content.len() >= maximum {
            return Err(FortinetTunnelError::LineTooLarge(maximum));
        }
        content.push(byte);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preserves_non_http_ppp_prefix() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            server.write_all(b"\0\x0cPP\0\x06packet").await.unwrap();
        });
        let start = read_fortinet_tls_tunnel_start(&mut client).await.unwrap();
        assert_eq!(start.initial_payload, [0]);
        let mut remainder = [0_u8; 11];
        client.read_exact(&mut remainder).await.unwrap();
        assert_eq!(&remainder, b"\x0cPP\0\x06packet");
    }

    #[tokio::test]
    async fn classifies_http_failures_and_malformed_headers() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            server
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        assert!(matches!(
            read_fortinet_tls_tunnel_start(&mut client).await,
            Err(FortinetTunnelError::SessionRejected(401))
        ));

        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n")
                .await
                .unwrap();
        });
        assert!(matches!(
            read_fortinet_tls_tunnel_start(&mut client).await,
            Err(FortinetTunnelError::MalformedHeader)
        ));
    }

    #[test]
    fn validates_dtls_probe_packets() {
        let mut hello = Vec::from([0, 0]);
        hello.extend_from_slice(FORTINET_DTLS_SERVER_HELLO_PREFIX);
        hello.extend_from_slice(b"ok\0");
        let length = hello.len() as u16;
        hello[..2].copy_from_slice(&length.to_be_bytes());
        assert!(valid_fortinet_dtls_server_hello(&hello));
        assert!(!valid_fortinet_dtls_server_hello(&hello[..hello.len() - 1]));
        assert!(valid_fortinet_ppp_datagram(b"\0\x0cPP\0\x06packet"));
        assert_eq!(
            fortinet_dtls_record_mtu("2001:db8::1".parse().unwrap()),
            1232
        );
    }
}
