//! Certificate-authenticated DTLS 1.2 transport for PPP OpenConnect flavors.
//!
//! Fortinet and F5 use ordinary server certificates rather than the
//! AnyConnect PSK/resumption handshake. The wire protocol is delegated to the
//! mature `dtls` crate; this module only adapts sing-box's routed packet API
//! and provides bounded handshake/data operations.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use dtls::{config::Config, conn::DTLSConn};
use rustls::RootCertStore;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use webrtc_util::Conn;

use crate::{
    adapter::{Dialer, PacketStream},
    common::network::SocksAddr,
};

pub const CERTIFICATE_DTLS_HANDSHAKE_TIMEOUT: Duration =
    Duration::from_secs(15);
pub const CERTIFICATE_DTLS_FLIGHT_INTERVAL: Duration =
    Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct CertificateDtlsClientOptions {
    pub server_name: String,
    pub record_mtu: usize,
    pub roots_cas: RootCertStore,
    pub insecure_skip_verify: bool,
    /// PKCS#8 private key followed by the certificate chain in PEM format.
    pub client_identity_pem: Option<String>,
    pub handshake_timeout: Duration,
    pub flight_interval: Duration,
}

impl Default for CertificateDtlsClientOptions {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            record_mtu: 1200,
            roots_cas: RootCertStore::empty(),
            insecure_skip_verify: false,
            client_identity_pem: None,
            handshake_timeout: CERTIFICATE_DTLS_HANDSHAKE_TIMEOUT,
            flight_interval: CERTIFICATE_DTLS_FLIGHT_INTERVAL,
        }
    }
}

#[derive(Debug, Error)]
pub enum CertificateDtlsError {
    #[error("certificate DTLS server must be an IP socket address")]
    InvalidServerAddress,
    #[error("certificate DTLS record MTU is too small: {0}")]
    InvalidMtu(usize),
    #[error("connect certificate DTLS UDP transport: {0}")]
    Dial(#[source] io::Error),
    #[error("certificate DTLS handshake timed out")]
    HandshakeTimeout,
    #[error("certificate DTLS handshake was cancelled")]
    Cancelled,
    #[error("establish certificate DTLS 1.2: {0}")]
    Handshake(String),
    #[error("invalid certificate DTLS client identity: {0}")]
    InvalidClientIdentity(String),
    #[error(
        "certificate DTLS payload is {actual} bytes for data MTU {maximum}"
    )]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("certificate DTLS I/O: {0}")]
    Io(String),
}

/// Established certificate DTLS application-data channel.
pub struct CertificateDtlsConnection {
    connection: Arc<DTLSConn>,
    local_address: Option<SocketAddr>,
    remote_address: SocketAddr,
    record_mtu: usize,
    data_mtu: usize,
}

impl CertificateDtlsConnection {
    pub fn local_address(&self) -> Option<SocketAddr> {
        self.local_address
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.remote_address
    }

    pub fn record_mtu(&self) -> usize {
        self.record_mtu
    }

    /// Conservative application-data MTU valid for every suite offered by
    /// the dependency, including AES-CBC's padding and MAC overhead.
    pub fn data_mtu(&self) -> usize {
        self.data_mtu
    }

    pub async fn read(
        &self,
        content: &mut [u8],
    ) -> Result<usize, CertificateDtlsError> {
        self.connection
            .read(content, None)
            .await
            .map_err(|error| CertificateDtlsError::Io(error.to_string()))
    }

    pub async fn write(
        &self,
        content: &[u8],
    ) -> Result<usize, CertificateDtlsError> {
        if content.len() > self.data_mtu {
            return Err(CertificateDtlsError::PayloadTooLarge {
                actual: content.len(),
                maximum: self.data_mtu,
            });
        }
        self.connection
            .write(content, None)
            .await
            .map_err(|error| CertificateDtlsError::Io(error.to_string()))
    }

    pub async fn close(&self) -> Result<(), CertificateDtlsError> {
        match self.connection.close().await {
            Ok(())
            | Err(dtls::Error::ErrConnClosed)
            | Err(dtls::Error::ErrAlertFatalOrClose) => Ok(()),
            Err(error) => Err(CertificateDtlsError::Io(error.to_string())),
        }
    }
}

#[async_trait]
impl super::PppDatagramCarrier for CertificateDtlsConnection {
    async fn send(&self, content: &[u8]) -> io::Result<usize> {
        self.write(content).await.map_err(dtls_io_error)
    }

    async fn receive(&self, content: &mut [u8]) -> io::Result<usize> {
        self.read(content).await.map_err(dtls_io_error)
    }

    async fn close(&self) -> io::Result<()> {
        CertificateDtlsConnection::close(self)
            .await
            .map_err(dtls_io_error)
    }
}

fn dtls_io_error(error: CertificateDtlsError) -> io::Error {
    let kind = match error {
        CertificateDtlsError::Cancelled => io::ErrorKind::Interrupted,
        CertificateDtlsError::HandshakeTimeout => io::ErrorKind::TimedOut,
        CertificateDtlsError::PayloadTooLarge { .. } => {
            io::ErrorKind::InvalidData
        }
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

pub async fn connect_certificate_dtls(
    dialer: Arc<dyn Dialer>,
    destination: SocketAddr,
    options: CertificateDtlsClientOptions,
    cancellation: &CancellationToken,
) -> Result<CertificateDtlsConnection, CertificateDtlsError> {
    // `dtls` uses rustls' process-level verifier and does not expose a
    // provider field. Installation is idempotent and leaves an embedding
    // application's previously selected provider untouched.
    let _ = rustls::crypto::ring::default_provider().install_default();
    if options.record_mtu <= 64 {
        return Err(CertificateDtlsError::InvalidMtu(options.record_mtu));
    }
    let packet = dialer
        .listen_udp(&SocksAddr::Ip(destination))
        .await
        .map_err(CertificateDtlsError::Dial)?;
    let local_address =
        packet.local_addr().map_err(CertificateDtlsError::Dial)?;
    let adapter = Arc::new(RoutedPacketConn {
        packet,
        destination,
        local_address,
    });
    let certificates = options
        .client_identity_pem
        .as_deref()
        .map(dtls::crypto::Certificate::from_pem)
        .transpose()
        .map_err(|error| {
            CertificateDtlsError::InvalidClientIdentity(error.to_string())
        })?
        .into_iter()
        .collect();
    let config = Config {
        certificates,
        server_name: options.server_name,
        mtu: options.record_mtu,
        roots_cas: options.roots_cas,
        insecure_skip_verify: options.insecure_skip_verify,
        flight_interval: options.flight_interval,
        ..Default::default()
    };
    let handshake = DTLSConn::new(adapter, config, true, None);
    let connection = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(CertificateDtlsError::Cancelled);
        }
        result = tokio::time::timeout(options.handshake_timeout, handshake) => {
            result.map_err(|_| CertificateDtlsError::HandshakeTimeout)?
                .map_err(|error| CertificateDtlsError::Handshake(error.to_string()))?
        }
    };
    Ok(CertificateDtlsConnection {
        connection: Arc::new(connection),
        local_address,
        remote_address: destination,
        record_mtu: options.record_mtu,
        data_mtu: certificate_dtls_data_mtu(options.record_mtu),
    })
}

/// Worst-case DTLS 1.2 application payload for the supported AES-CBC suite.
pub fn certificate_dtls_data_mtu(record_mtu: usize) -> usize {
    if record_mtu <= 29 {
        return 0;
    }
    ((record_mtu - 29) / 16 * 16).saturating_sub(21)
}

struct RoutedPacketConn {
    packet: PacketStream,
    destination: SocketAddr,
    local_address: Option<SocketAddr>,
}

#[async_trait]
impl Conn for RoutedPacketConn {
    async fn connect(&self, address: SocketAddr) -> webrtc_util::Result<()> {
        if address == self.destination {
            Ok(())
        } else {
            Err(webrtc_util::Error::Other(
                "certificate DTLS transport cannot change peer".into(),
            ))
        }
    }

    async fn recv(&self, content: &mut [u8]) -> webrtc_util::Result<usize> {
        loop {
            let (size, source) = self.packet.recv_from(content).await?;
            if source == SocksAddr::Ip(self.destination) {
                return Ok(size);
            }
        }
    }

    async fn recv_from(
        &self,
        content: &mut [u8],
    ) -> webrtc_util::Result<(usize, SocketAddr)> {
        self.recv(content)
            .await
            .map(|size| (size, self.destination))
    }

    async fn send(&self, content: &[u8]) -> webrtc_util::Result<usize> {
        self.packet
            .send_to(content, &SocksAddr::Ip(self.destination))
            .await
            .map_err(Into::into)
    }

    async fn send_to(
        &self,
        content: &[u8],
        target: SocketAddr,
    ) -> webrtc_util::Result<usize> {
        if target != self.destination {
            return Err(webrtc_util::Error::Other(
                "certificate DTLS transport cannot change peer".into(),
            ));
        }
        self.send(content).await
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.local_address.unwrap_or_else(|| {
            SocketAddr::new(
                if self.destination.is_ipv4() {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                },
                0,
            )
        }))
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.destination)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::{Mutex, mpsc};

    use super::*;
    use crate::adapter::{DialFuture, PacketConnection, PacketFuture};

    #[test]
    fn computes_conservative_data_mtu() {
        assert_eq!(certificate_dtls_data_mtu(1400), 1339);
        assert_eq!(certificate_dtls_data_mtu(1232), 1179);
        assert_eq!(certificate_dtls_data_mtu(29), 0);
    }

    struct MemoryPacket {
        source: SocketAddr,
        outbound: mpsc::Sender<(Vec<u8>, SocksAddr)>,
        inbound: Mutex<mpsc::Receiver<(Vec<u8>, SocksAddr)>>,
    }

    impl PacketConnection for MemoryPacket {
        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(Some(self.source))
        }

        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                self.outbound
                    .send((data.to_vec(), SocksAddr::Ip(self.source)))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "closed")
                    })?;
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let (packet, source) = self
                    .inbound
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "closed")
                })?;
                if packet.len() > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "buffer too small",
                    ));
                }
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), source))
            })
        }
    }

    struct MemoryDialer(Mutex<Option<PacketStream>>);

    impl Dialer for MemoryDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(io::ErrorKind::Unsupported, "TCP is unused"))
            })
        }

        fn listen_udp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, PacketStream> {
            Box::pin(async move {
                self.0.lock().await.take().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AlreadyExists, "already used")
                })
            })
        }
    }

    fn memory_packet_pair(
        left: SocketAddr,
        right: SocketAddr,
    ) -> (PacketStream, PacketStream) {
        let (left_tx, left_rx) = mpsc::channel(32);
        let (right_tx, right_rx) = mpsc::channel(32);
        (
            Box::new(MemoryPacket {
                source: left,
                outbound: left_tx,
                inbound: Mutex::new(right_rx),
            }),
            Box::new(MemoryPacket {
                source: right,
                outbound: right_tx,
                inbound: Mutex::new(left_rx),
            }),
        )
    }

    #[tokio::test]
    async fn establishes_certificate_dtls_over_routed_packet_api() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let server_address: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let (client_packet, server_packet) =
            memory_packet_pair(client_address, server_address);
        let server_adapter = Arc::new(RoutedPacketConn {
            packet: server_packet,
            destination: client_address,
            local_address: Some(server_address),
        });
        let certificate =
            dtls::crypto::Certificate::generate_self_signed(vec![
                "localhost".into(),
            ])
            .unwrap();
        let server = tokio::spawn(async move {
            let connection = DTLSConn::new(
                server_adapter,
                Config {
                    certificates: vec![certificate],
                    flight_interval: Duration::from_millis(20),
                    ..Default::default()
                },
                false,
                None,
            )
            .await
            .unwrap();
            let mut content = [0_u8; 32];
            let count = connection.read(&mut content, None).await.unwrap();
            assert_eq!(&content[..count], b"ping");
            connection.write(b"pong", None).await.unwrap();
            let _ = connection.read(&mut content, None).await;
            connection.close().await.unwrap();
        });
        let connection = connect_certificate_dtls(
            Arc::new(MemoryDialer(Mutex::new(Some(client_packet)))),
            server_address,
            CertificateDtlsClientOptions {
                server_name: "localhost".into(),
                record_mtu: 1400,
                insecure_skip_verify: true,
                flight_interval: Duration::from_millis(20),
                ..Default::default()
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        connection.write(b"ping").await.unwrap();
        let mut content = [0_u8; 32];
        let count = connection.read(&mut content).await.unwrap();
        assert_eq!(&content[..count], b"pong");
        connection.close().await.unwrap();
        server.await.unwrap();
    }
}
