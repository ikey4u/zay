//! AnyConnect authenticated-session to CSTP connector.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use thiserror::Error;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader,
    ReadBuf,
};

use super::{
    AnyConnectAuthenticatedSession, CstpConnectOptions, CstpDtlsNegotiation,
    CstpDtlsNegotiationOptions, CstpError, CstpNegotiatedState,
    CstpResponseOptions, CstpSession, CstpSessionOptions,
    build_cstp_connect_request, parse_cstp_dtls_negotiation,
    parse_cstp_response, read_cstp_http_response,
};
use crate::{
    adapter::{Dialer, Stream},
    common::{network::SocksAddr, tls::build_client_config},
    option::OutboundTlsOptions,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const LEGACY_DTLS_MASTER_SECRET_SIZE: usize = 48;
const ANYCONNECT_DTLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-openconnect-psk";
const ANYCONNECT_DTLS_PSK_SIZE: usize = 32;

#[derive(Default, PartialEq, Eq)]
pub struct AnyConnectDtlsPsk([u8; ANYCONNECT_DTLS_PSK_SIZE]);

impl Clone for AnyConnectDtlsPsk {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl AnyConnectDtlsPsk {
    pub fn from_bytes(secret: [u8; ANYCONNECT_DTLS_PSK_SIZE]) -> Self {
        Self(secret)
    }

    pub fn as_bytes(&self) -> &[u8; ANYCONNECT_DTLS_PSK_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for AnyConnectDtlsPsk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("AnyConnectDtlsPsk")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl Drop for AnyConnectDtlsPsk {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone)]
pub struct AnyConnectCstpConnectorOptions {
    pub tls: OutboundTlsOptions,
    pub connect: CstpConnectOptions,
    pub response: CstpResponseOptions,
    pub queue_length: usize,
    pub connect_timeout: Duration,
}

impl Default for AnyConnectCstpConnectorOptions {
    fn default() -> Self {
        Self {
            tls: OutboundTlsOptions::default(),
            connect: CstpConnectOptions::default(),
            response: CstpResponseOptions::default(),
            queue_length: 64,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

pub struct AnyConnectCstpConnection {
    pub negotiated: CstpNegotiatedState,
    pub dtls: Option<CstpDtlsNegotiation>,
    /// Present only for the standard `PSK-NEGOTIATE` DTLS mode.
    pub dtls_psk: Option<AnyConnectDtlsPsk>,
    pub session: CstpSession,
}

#[derive(Debug, Error)]
pub enum AnyConnectCstpConnectError {
    #[error("invalid authenticated AnyConnect session: {0}")]
    InvalidSession(String),
    #[error("connect AnyConnect CSTP transport: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cstp(#[from] CstpError),
    #[error("CSTP CONNECT session was rejected with HTTP {0}")]
    SessionRejected(u16),
    #[error("CSTP CONNECT was rejected with HTTP {status}: {reason}")]
    HttpStatus { status: u16, reason: String },
    #[error("AnyConnect CSTP setup timed out after {0:?}")]
    Timeout(Duration),
}

pub async fn connect_anyconnect_cstp(
    dialer: Arc<dyn Dialer>,
    authenticated: &AnyConnectAuthenticatedSession,
    options: AnyConnectCstpConnectorOptions,
) -> Result<AnyConnectCstpConnection, AnyConnectCstpConnectError> {
    let timeout = if options.connect_timeout.is_zero() {
        DEFAULT_CONNECT_TIMEOUT
    } else {
        options.connect_timeout
    };
    tokio::time::timeout(
        timeout,
        connect_anyconnect_cstp_inner(dialer, authenticated, options),
    )
    .await
    .map_err(|_| AnyConnectCstpConnectError::Timeout(timeout))?
}

async fn connect_anyconnect_cstp_inner(
    dialer: Arc<dyn Dialer>,
    authenticated: &AnyConnectAuthenticatedSession,
    mut options: AnyConnectCstpConnectorOptions,
) -> Result<AnyConnectCstpConnection, AnyConnectCstpConnectError> {
    if authenticated.webvpn_cookie.is_empty() {
        return Err(AnyConnectCstpConnectError::InvalidSession(
            "webvpn cookie is empty".into(),
        ));
    }
    let server_host = authenticated
        .server_url
        .host_str()
        .ok_or_else(|| {
            AnyConnectCstpConnectError::InvalidSession(
                "server URL has no host".into(),
            )
        })?
        .to_owned();
    if authenticated.server_url.scheme() != "https" {
        return Err(AnyConnectCstpConnectError::InvalidSession(
            "server URL is not HTTPS".into(),
        ));
    }
    let server_port = authenticated
        .server_url
        .port_or_known_default()
        .ok_or_else(|| {
            AnyConnectCstpConnectError::InvalidSession(
                "server URL has no port".into(),
            )
        })?;
    let destination_host = authenticated
        .authenticated_address
        .map_or_else(|| server_host.clone(), |address| address.to_string());
    let raw = dialer
        .dial_tcp(&SocksAddr::new(destination_host, server_port))
        .await?;
    let mut tls_options = options.tls.clone();
    tls_options.enabled = true;
    let tls = build_client_config(&server_host, &tls_options, &["http/1.1"])
        .map_err(io::Error::other)?;
    let mut stream = tls.connect_stream(raw).await?;

    options.connect.server =
        authority(&server_host, authenticated.server_url.port());
    options.connect.cookie = authenticated.webvpn_cookie.clone();
    options.connect.remote_is_ipv6 = authenticated
        .authenticated_address
        .is_some_and(|address| address.is_ipv6());
    if !options.connect.no_udp && options.connect.dtls_master_secret.is_empty()
    {
        options.connect.dtls_master_secret =
            vec![0; LEGACY_DTLS_MASTER_SECRET_SIZE];
        getrandom::fill(&mut options.connect.dtls_master_secret)
            .map_err(io::Error::other)?;
    }
    let request = build_cstp_connect_request(&options.connect)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let response = read_cstp_http_response(&mut reader).await?;
    if matches!(response.status_code, 401 | 403) {
        return Err(AnyConnectCstpConnectError::SessionRejected(
            response.status_code,
        ));
    }
    if response.status_code != 200 {
        let reason = response
            .headers
            .get("x-reason")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        return Err(AnyConnectCstpConnectError::HttpStatus {
            status: response.status_code,
            reason,
        });
    }
    options.response.authenticated_address =
        authenticated.authenticated_address;
    let negotiated = parse_cstp_response(
        &response.headers,
        &options.response,
        SystemTime::now(),
    )?;
    let dtls = if options.connect.no_udp {
        None
    } else {
        parse_cstp_dtls_negotiation(
            &response.dtls_options,
            &CstpDtlsNegotiationOptions {
                server_host,
                server_port,
                authenticated_address: authenticated.authenticated_address,
                master_secret: options.connect.dtls_master_secret,
                mtu: negotiated.configuration.mtu,
                compression_disabled: options.response.compression_disabled,
                compression_mode: options.response.compression_mode,
                dpd_override: options.response.dpd_override,
                allow_insecure_crypto: options.connect.allow_insecure_crypto,
            },
        )?
    };
    let dtls_psk = if dtls
        .as_ref()
        .is_some_and(|negotiation| negotiation.cipher_suite == "PSK-NEGOTIATE")
    {
        let mut secret = AnyConnectDtlsPsk::default();
        reader.get_ref().export_keying_material(
            &mut secret.0,
            ANYCONNECT_DTLS_EXPORTER_LABEL,
            None,
        )?;
        Some(secret)
    } else {
        None
    };

    let prefix = reader.buffer().to_vec();
    reader.consume(prefix.len());
    let stream: Stream = Box::new(PrefixedStream {
        prefix,
        offset: 0,
        inner: reader.into_inner().into_stream(),
    });
    let session = CstpSession::start(
        stream,
        CstpSessionOptions {
            mtu: negotiated.configuration.mtu as usize,
            compression: negotiated.compression,
            dpd: negotiated.dpd,
            keepalive: negotiated.keepalive,
            rekey: negotiated.rekey,
            rekey_method: negotiated.rekey_method,
            queue_length: options.queue_length.max(1),
        },
    )?;
    Ok(AnyConnectCstpConnection {
        negotiated,
        dtls,
        dtls_psk,
        session,
    })
}

fn authority(host: &str, explicit_port: Option<u16>) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    explicit_port.map_or(host.clone(), |port| format!("{host}:{port}"))
}

struct PrefixedStream {
    prefix: Vec<u8>,
    offset: usize,
    inner: Stream,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buffer.remaining() > 0 {
            let size = buffer
                .remaining()
                .min(self.prefix.len().saturating_sub(self.offset));
            let end = self.offset + size;
            buffer.put_slice(&self.prefix[self.offset..end]);
            self.offset = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::{
        adapter::Dialer,
        option::DirectOutboundOptions,
        protocol::{direct::DirectOutbound, openconnect::CstpCompressionMode},
    };

    #[tokio::test]
    async fn authenticated_session_connects_and_preserves_prefetched_packet() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            let mut tail = [0_u8; 4];
            while tail != *b"\r\n\r\n" {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                tail.rotate_left(1);
                tail[3] = byte[0];
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n")
            );
            assert!(request.contains("Cookie: webvpn=session-cookie\r\n"));
            assert!(request.contains("X-CSTP-Address-Type: IPv6,IPv4\r\n"));
            let payload = b"\x45\x00\x00\x14";
            let mut response = b"HTTP/1.1 200 OK\r\nX-CSTP-MTU: 1300\r\nX-CSTP-Address: 10.8.0.2\r\nX-CSTP-Netmask: 255.255.255.0\r\nX-CSTP-DPD: 30\r\nX-DTLS12-CipherSuite: PSK-NEGOTIATE\r\nX-DTLS12-App-ID: 0102\r\n\r\n".to_vec();
            response.extend_from_slice(b"STF\x01");
            response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            response.extend_from_slice(&[0, 0]);
            response.extend_from_slice(payload);
            stream.write_all(&response).await.unwrap();
            stream.flush().await.unwrap();
            let mut exporter = [0_u8; ANYCONNECT_DTLS_PSK_SIZE];
            stream
                .get_ref()
                .1
                .export_keying_material(
                    &mut exporter,
                    ANYCONNECT_DTLS_EXPORTER_LABEL,
                    None,
                )
                .unwrap();
            let mut disconnect = [0_u8; 8];
            let _ = stream.read_exact(&mut disconnect).await;
            exporter
        });

        let authenticated = AnyConnectAuthenticatedSession {
            server_url: format!("https://{address}/").parse().unwrap(),
            authenticated_address: None,
            peer_certificate_der: None,
            webvpn_cookie: "session-cookie".into(),
        };
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let mut connected = connect_anyconnect_cstp(
            dialer,
            &authenticated,
            AnyConnectCstpConnectorOptions {
                tls: OutboundTlsOptions {
                    insecure: true,
                    ..Default::default()
                },
                connect: CstpConnectOptions {
                    user_agent: "agent".into(),
                    local_hostname: "host".into(),
                    no_udp: false,
                    compression_mode: CstpCompressionMode::Stateless,
                    ..Default::default()
                },
                response: CstpResponseOptions {
                    no_udp: false,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            connected.negotiated.configuration.addresses[0].to_string(),
            "10.8.0.2/24"
        );
        assert_eq!(
            connected.session.read_data_packet().await.unwrap(),
            Some(b"\x45\x00\x00\x14".to_vec())
        );
        assert_eq!(
            connected.dtls.as_ref().unwrap().cipher_suite,
            "PSK-NEGOTIATE"
        );
        let exported = *connected.dtls_psk.as_ref().unwrap().as_bytes();
        connected.session.close().await.unwrap();
        assert_eq!(exported, server.await.unwrap());
    }
}
