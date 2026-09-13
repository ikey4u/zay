//! Pulse IF-T/TLS HTTP upgrade and tunnel control frames.

use std::io;

use http::StatusCode;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use url::Url;

pub const PULSE_CONNECT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);
pub const PULSE_LOGOUT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);
pub const PULSE_MAXIMUM_HTTP_HEADER: usize = 1024 * 1024;
pub const PULSE_MAXIMUM_LOGOUT_BODY: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum PulseTunnelError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid Pulse server URL")]
    InvalidServerUrl,
    #[error("Pulse IF-T/TLS upgrade response is malformed")]
    MalformedUpgradeResponse,
    #[error("Pulse IF-T/TLS upgrade headers exceed {0} bytes")]
    UpgradeHeadersTooLarge(usize),
    #[error("Pulse session was rejected with HTTP {0}")]
    SessionRejected(StatusCode),
    #[error("Pulse authentication failed with HTTP {0}")]
    AuthenticationFailed(StatusCode),
    #[error("Pulse IF-T/TLS upgrade returned HTTP {0}")]
    UnexpectedStatus(StatusCode),
    #[error("server sent a malformed Pulse fatal error")]
    MalformedFatalError,
}

pub fn build_pulse_upgrade_request(
    server_url: &Url,
    user_agent: &str,
    cookies: &[(String, String)],
) -> Result<Vec<u8>, PulseTunnelError> {
    if server_url.scheme() != "https" || server_url.host_str().is_none() {
        return Err(PulseTunnelError::InvalidServerUrl);
    }
    if user_agent.contains(['\r', '\n'])
        || cookies.iter().any(|(name, value)| {
            name.is_empty()
                || name.contains(['\r', '\n', ';', '='])
                || value.contains(['\r', '\n', ';'])
        })
    {
        return Err(PulseTunnelError::MalformedUpgradeResponse);
    }
    let mut target = server_url.path().to_owned();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = server_url.query() {
        target.push('?');
        target.push_str(query);
    }
    let hostname = server_url.host_str().unwrap();
    let hostname = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname.to_owned()
    };
    let host = match server_url.port() {
        Some(port) => format!("{hostname}:{port}"),
        None => hostname,
    };
    let mut request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n"
    );
    if !cookies.is_empty() {
        request.push_str("Cookie: ");
        for (index, (name, value)) in cookies.iter().enumerate() {
            if index > 0 {
                request.push_str("; ");
            }
            request.push_str(name);
            request.push('=');
            request.push_str(value);
        }
        request.push_str("\r\n");
    }
    request.push_str(
        "Content-Type: EAP\r\nUpgrade: IF-T/TLS 1.0\r\nContent-Length: 0\r\n\r\n",
    );
    Ok(request.into_bytes())
}

pub async fn read_pulse_upgrade_response<R>(
    reader: &mut R,
    reconnecting: bool,
) -> Result<(), PulseTunnelError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut content = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        reader.read_exact(&mut byte).await?;
        content.push(byte[0]);
        if content.len() > PULSE_MAXIMUM_HTTP_HEADER {
            return Err(PulseTunnelError::UpgradeHeadersTooLarge(
                PULSE_MAXIMUM_HTTP_HEADER,
            ));
        }
        if content.ends_with(b"\r\n\r\n") || content.ends_with(b"\n\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&content)
        .map_err(|_| PulseTunnelError::MalformedUpgradeResponse)?;
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .and_then(|status| StatusCode::from_u16(status).ok())
        .ok_or(PulseTunnelError::MalformedUpgradeResponse)?;
    if status == StatusCode::SWITCHING_PROTOCOLS {
        return Ok(());
    }
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Err(if reconnecting {
            PulseTunnelError::SessionRejected(status)
        } else {
            PulseTunnelError::AuthenticationFailed(status)
        });
    }
    Err(PulseTunnelError::UnexpectedStatus(status))
}

pub fn parse_pulse_fatal_error(
    payload: &[u8],
) -> Result<(u32, String), PulseTunnelError> {
    let message = String::from_utf8_lossy(payload);
    let message = message.trim_end_matches('\n');
    let (reason, encoded) = message
        .strip_prefix("errorType=")
        .and_then(|message| message.split_once(" errorString="))
        .ok_or(PulseTunnelError::MalformedFatalError)?;
    let reason = reason
        .parse::<u32>()
        .map_err(|_| PulseTunnelError::MalformedFatalError)?;
    let form_text = encoded.replace('+', " ");
    let decoded = percent_encoding::percent_decode_str(&form_text)
        .decode_utf8()
        .map_or_else(|_| encoded.to_owned(), |value| value.into_owned());
    Ok((reason, decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_request_preserves_path_query_and_cookie() {
        let request = build_pulse_upgrade_request(
            &Url::parse("https://vpn.example:444/path?q=1").unwrap(),
            "agent",
            &[("DSID".to_owned(), "cookie".to_owned())],
        )
        .unwrap();
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with(
            "GET /path?q=1 HTTP/1.1\r\nHost: vpn.example:444\r\n"
        ));
        assert!(request.contains("Cookie: DSID=cookie\r\n"));
        assert!(
            request.ends_with(
                "Upgrade: IF-T/TLS 1.0\r\nContent-Length: 0\r\n\r\n"
            )
        );
    }

    #[tokio::test]
    async fn upgrade_response_stops_at_header_boundary() {
        let mut reader = std::io::Cursor::new(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: IF-T/TLS 1.0\r\n\r\nIFT"
                .to_vec(),
        );
        read_pulse_upgrade_response(&mut reader, false)
            .await
            .unwrap();
        let mut suffix = [0_u8; 3];
        reader.read_exact(&mut suffix).await.unwrap();
        assert_eq!(&suffix, b"IFT");
    }

    #[test]
    fn fatal_error_is_decoded() {
        assert_eq!(
            parse_pulse_fatal_error(
                b"errorType=7 errorString=session%20expired\n"
            )
            .unwrap(),
            (7, "session expired".to_owned())
        );
        assert_eq!(
            parse_pulse_fatal_error(b"errorType=8 errorString=a%3Db+c\n")
                .unwrap(),
            (8, "a=b c".to_owned())
        );
        assert!(parse_pulse_fatal_error(b"bad").is_err());
    }
}
