//! Standard TLS client construction shared by transports and protocols.

use std::{
    collections::HashSet,
    fs,
    future::Future,
    io,
    io::BufReader,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};
use rustls::{
    CipherSuite, ClientConfig, DigitallySignedStruct, DistinguishedName,
    NamedGroup, RootCertStore, ServerConfig, SignatureScheme,
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    client::{EchConfig, EchMode, WebPkiServerVerifier},
    crypto::{
        ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
        verify_tls12_signature, verify_tls13_signature,
    },
    pki_types::{
        CertificateDer, EchConfigListBytes, PrivateKeyDer, PrivatePkcs8KeyDer,
        ServerName, UnixTime,
    },
    server::danger::{ClientCertVerified, ClientCertVerifier},
    server::{ClientHello, EchServerKey, FixedEchKeys, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha1_11::Sha1;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::{
    adapter::{
        DialFuture, Dialer, Stream, VisionDialFuture, VisionDirectSwitch,
        VisionTransport,
    },
    option::{
        ClientAuthType, CurvePreference, InboundTlsOptions, OutboundTlsOptions,
        ServerCertificateFingerprint, ServerCertificateFingerprintAlgorithm,
    },
};

use super::reality_tls::{RealityServerRuntime, install_reality_client};
use super::utls::SingBoxUtlsCustomizer;
use super::{certificate_store::CertificateStore, ntp::NtpClock};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("unsupported TLS option: {0}")]
    Unsupported(String),
    #[error("invalid TLS server name {name:?}: {message}")]
    ServerName { name: String, message: String },
    #[error("read TLS certificate file {path:?}: {source}")]
    ReadCertificate { path: String, source: io::Error },
    #[error("read TLS private key file {path:?}: {source}")]
    ReadPrivateKey { path: String, source: io::Error },
    #[error("read ECH config file {path:?}: {source}")]
    ReadEchConfig { path: String, source: io::Error },
    #[error("read ECH key file {path:?}: {source}")]
    ReadEchKey { path: String, source: io::Error },
    #[error("parse TLS certificate: {0}")]
    Certificate(String),
    #[error("parse TLS private key: {0}")]
    PrivateKey(String),
    #[error("discover ECH config: {0}")]
    EchDiscovery(String),
    #[error("parse ECH server keys: {0}")]
    EchKey(String),
}

/// One ECHConfigList obtained from a DNS HTTPS record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchConfigRecord {
    pub config_list: Vec<u8>,
    pub ttl: Duration,
}

/// Async source used by dynamic outbound ECH discovery.
pub trait EchConfigResolver: Send + Sync {
    fn resolve_ech<'a>(
        &'a self,
        server_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<EchConfigRecord>> + Send + 'a>>;
}

pub(crate) struct DynamicEchConfig {
    endpoint_host: String,
    query_server_name: String,
    default_alpn: Vec<String>,
    options: OutboundTlsOptions,
    resolver: Arc<dyn EchConfigResolver>,
    clock: Option<NtpClock>,
    cache: tokio::sync::Mutex<Option<(Instant, Arc<ClientConfig>)>>,
}

pub(crate) struct EchRetryConfig {
    endpoint_host: String,
    default_alpn: Vec<String>,
    options: OutboundTlsOptions,
    clock: Option<NtpClock>,
    cache: tokio::sync::Mutex<Option<(Option<Instant>, Arc<ClientConfig>)>>,
}

#[derive(Debug)]
struct NtpTimeProvider(NtpClock);

impl rustls::time_provider::TimeProvider for NtpTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(UnixTime::since_unix_epoch)
    }
}

#[derive(Clone)]
pub struct ClientTlsConfig {
    pub config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
    pub handshake_timeout: Option<Duration>,
    pub(crate) fragment: bool,
    pub(crate) record_fragment: bool,
    pub(crate) fragment_fallback_delay: Duration,
    pub(crate) spoof: String,
    pub(crate) spoof_method: crate::common::tls_spoof::TlsSpoofMethod,
    pub(crate) dynamic_ech: Option<Arc<DynamicEchConfig>>,
    pub(crate) ech_retry: Option<Arc<EchRetryConfig>>,
    pub(crate) backend: ClientTlsBackend,
    pub(crate) kernel_tx: bool,
    pub(crate) kernel_rx: bool,
}

#[derive(Clone)]
pub(crate) enum ClientTlsBackend {
    Rustls,
    OpenSsl(Arc<OpenSslClientBackend>),
    #[cfg(target_vendor = "apple")]
    Apple(Arc<crate::common::apple_tls::AppleTlsBackend>),
    #[cfg(windows)]
    Windows(Arc<crate::common::windows_tls::WindowsTlsBackend>),
}

pub(crate) struct OpenSslClientBackend {
    endpoint_host: String,
    default_alpn: Vec<String>,
    options: OutboundTlsOptions,
    clock: Option<NtpClock>,
}

/// Result of a client TLS handshake independent of the concrete TLS backend.
///
/// Protocol implementations should use this type instead of downcasting a
/// rustls stream.  That keeps ALPN and peer-certificate inspection available
/// when a platform or legacy TLS backend is selected.
pub struct ClientTlsStream {
    inner: ClientTlsStreamInner,
    socket: Option<crate::adapter::StreamSocket>,
    negotiated_alpn: Option<Vec<u8>>,
    peer_certificates: Vec<Vec<u8>>,
}

enum ClientTlsStreamInner {
    Rustls(Box<tokio_rustls::client::TlsStream<Stream>>),
    #[cfg(target_os = "linux")]
    Ktls(Box<crate::common::ktls::KtlsStream>),
    OpenSsl(tokio_openssl::SslStream<Stream>),
    #[cfg(target_vendor = "apple")]
    Apple(crate::common::apple_tls::AppleTlsStream),
    #[cfg(windows)]
    Windows(Box<crate::common::windows_tls::WindowsTlsStream>),
}

impl ClientTlsStream {
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }

    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> io::Result<()> {
        match &self.inner {
            ClientTlsStreamInner::Rustls(stream) => stream
                .get_ref()
                .1
                .export_keying_material(output, label, context)
                .map(|_| ())
                .map_err(io::Error::other),
            #[cfg(target_os = "linux")]
            ClientTlsStreamInner::Ktls(stream) => {
                stream.export_keying_material(output, label, context)
            }
            ClientTlsStreamInner::OpenSsl(stream) => {
                let label = std::str::from_utf8(label).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TLS exporter label is not UTF-8",
                    )
                })?;
                stream
                    .ssl()
                    .export_keying_material(output, label, context)
                    .map_err(io::Error::other)
            }
            #[cfg(target_vendor = "apple")]
            ClientTlsStreamInner::Apple(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Apple TLS does not expose RFC 5705 exporter material",
            )),
            #[cfg(windows)]
            ClientTlsStreamInner::Windows(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows TLS does not expose RFC 5705 exporter material",
            )),
        }
    }

    pub fn into_stream(self) -> Stream {
        let stream = match self.inner {
            ClientTlsStreamInner::Rustls(stream) => stream as Stream,
            #[cfg(target_os = "linux")]
            ClientTlsStreamInner::Ktls(stream) => stream as Stream,
            ClientTlsStreamInner::OpenSsl(stream) => Box::new(stream) as Stream,
            #[cfg(target_vendor = "apple")]
            ClientTlsStreamInner::Apple(stream) => Box::new(stream) as Stream,
            #[cfg(windows)]
            ClientTlsStreamInner::Windows(stream) => stream as Stream,
        };
        crate::adapter::preserve_stream_socket(stream, self.socket)
    }

    #[cfg(target_os = "linux")]
    fn into_ktls_vision(self) -> io::Result<VisionTransport> {
        let ClientTlsStreamInner::Ktls(mut stream) = self.inner else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Vision kTLS transport requires a kTLS stream",
            ));
        };
        let direct_switch =
            Arc::new(crate::common::ktls::KtlsVisionSwitch::default());
        stream.enable_vision(direct_switch.clone());
        Ok(VisionTransport {
            stream: crate::adapter::preserve_stream_socket(
                stream as Stream,
                self.socket,
            ),
            direct_switch,
        })
    }
}

impl AsyncRead for ClientTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            ClientTlsStreamInner::Rustls(stream) => {
                Pin::new(stream).poll_read(cx, buffer)
            }
            #[cfg(target_os = "linux")]
            ClientTlsStreamInner::Ktls(stream) => {
                Pin::new(stream).poll_read(cx, buffer)
            }
            ClientTlsStreamInner::OpenSsl(stream) => {
                Pin::new(stream).poll_read(cx, buffer)
            }
            #[cfg(target_vendor = "apple")]
            ClientTlsStreamInner::Apple(stream) => {
                Pin::new(stream).poll_read(cx, buffer)
            }
            #[cfg(windows)]
            ClientTlsStreamInner::Windows(stream) => {
                Pin::new(stream).poll_read(cx, buffer)
            }
        }
    }
}

impl AsyncWrite for ClientTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            ClientTlsStreamInner::Rustls(stream) => {
                Pin::new(stream).poll_write(cx, buffer)
            }
            #[cfg(target_os = "linux")]
            ClientTlsStreamInner::Ktls(stream) => {
                Pin::new(stream).poll_write(cx, buffer)
            }
            ClientTlsStreamInner::OpenSsl(stream) => {
                Pin::new(stream).poll_write(cx, buffer)
            }
            #[cfg(target_vendor = "apple")]
            ClientTlsStreamInner::Apple(stream) => {
                Pin::new(stream).poll_write(cx, buffer)
            }
            #[cfg(windows)]
            ClientTlsStreamInner::Windows(stream) => {
                Pin::new(stream).poll_write(cx, buffer)
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            ClientTlsStreamInner::Rustls(stream) => {
                Pin::new(stream).poll_flush(cx)
            }
            #[cfg(target_os = "linux")]
            ClientTlsStreamInner::Ktls(stream) => {
                Pin::new(stream).poll_flush(cx)
            }
            ClientTlsStreamInner::OpenSsl(stream) => {
                Pin::new(stream).poll_flush(cx)
            }
            #[cfg(target_vendor = "apple")]
            ClientTlsStreamInner::Apple(stream) => {
                Pin::new(stream).poll_flush(cx)
            }
            #[cfg(windows)]
            ClientTlsStreamInner::Windows(stream) => {
                Pin::new(stream).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            ClientTlsStreamInner::Rustls(stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
            #[cfg(target_os = "linux")]
            ClientTlsStreamInner::Ktls(stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
            ClientTlsStreamInner::OpenSsl(stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
            #[cfg(target_vendor = "apple")]
            ClientTlsStreamInner::Apple(stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
            #[cfg(windows)]
            ClientTlsStreamInner::Windows(stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
        }
    }
}

#[derive(Clone)]
pub struct ServerTlsConfig {
    pub config: Arc<ServerConfig>,
    pub handshake_timeout: Option<Duration>,
    pub(crate) reality: Option<Arc<RealityServerRuntime>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) kernel_tx: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) kernel_rx: bool,
}

/// TLS stream accepted by either the ordinary rustls backend or the
/// BoringSSL backend used for server-side Encrypted Client Hello.
pub(crate) enum AcceptedServerTlsStream {
    Rustls(Box<tokio_rustls::server::TlsStream<Stream>>),
    #[cfg(target_os = "linux")]
    Ktls {
        stream: Box<crate::common::ktls::KtlsStream>,
        alpn: Option<Vec<u8>>,
    },
}

impl AcceptedServerTlsStream {
    pub(crate) fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Rustls(stream) => stream.get_ref().1.alpn_protocol(),
            #[cfg(target_os = "linux")]
            Self::Ktls { alpn, .. } => alpn.as_deref(),
        }
    }

    /// Reports whether this connection actually decrypted ClientHelloInner.
    /// Ordinary rustls server streams always return false because rustls 0.23
    /// only implements the client half of ECH.
    #[cfg(test)]
    pub(crate) fn ech_accepted(&self) -> bool {
        match self {
            Self::Rustls(stream) => stream.get_ref().1.ech_accepted().is_some(),
            #[cfg(target_os = "linux")]
            Self::Ktls { .. } => false,
        }
    }
}

impl AsyncRead for AcceptedServerTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Rustls(stream) => Pin::new(stream).poll_read(cx, buffer),
            #[cfg(target_os = "linux")]
            Self::Ktls { stream, .. } => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for AcceptedServerTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Rustls(stream) => Pin::new(stream).poll_write(cx, buffer),
            #[cfg(target_os = "linux")]
            Self::Ktls { stream, .. } => {
                Pin::new(stream).poll_write(cx, buffer)
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Rustls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(target_os = "linux")]
            Self::Ktls { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Rustls(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(target_os = "linux")]
            Self::Ktls { stream, .. } => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Thread-safe certificate slot used by managed certificate providers.
///
/// rustls asks a [`ResolvesServerCert`] implementation for a certificate from
/// its synchronous ClientHello callback.  Providers such as ACME and
/// Cloudflare Origin CA obtain and renew certificates asynchronously, so they
/// publish each completed key pair into this slot and every new handshake sees
/// the latest value without rebuilding the listener.
#[derive(Debug, Default)]
pub struct DynamicCertificateResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    acme_tls_alpn: RwLock<std::collections::HashMap<String, Arc<CertifiedKey>>>,
}

impl DynamicCertificateResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, certificate: Arc<CertifiedKey>) {
        *self
            .current
            .write()
            .expect("dynamic certificate resolver lock poisoned") =
            Some(certificate);
    }

    pub fn clear(&self) {
        *self
            .current
            .write()
            .expect("dynamic certificate resolver lock poisoned") = None;
    }

    pub(crate) fn set_acme_tls_alpn(
        &self,
        server_name: String,
        certificate: Arc<CertifiedKey>,
    ) {
        self.acme_tls_alpn
            .write()
            .expect("dynamic certificate resolver lock poisoned")
            .insert(server_name, certificate);
    }

    pub(crate) fn clear_acme_tls_alpn(&self) {
        self.acme_tls_alpn
            .write()
            .expect("dynamic certificate resolver lock poisoned")
            .clear();
    }

    pub fn has_certificate(&self) -> bool {
        self.current
            .read()
            .expect("dynamic certificate resolver lock poisoned")
            .is_some()
    }
}

impl ResolvesServerCert for DynamicCertificateResolver {
    fn resolve(
        &self,
        client_hello: ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        if client_hello
            .alpn()
            .into_iter()
            .flatten()
            .eq([b"acme-tls/1".as_slice()])
        {
            return client_hello.server_name().and_then(|server_name| {
                self.acme_tls_alpn
                    .read()
                    .expect("dynamic certificate resolver lock poisoned")
                    .get(server_name)
                    .cloned()
            });
        }
        self.current
            .read()
            .expect("dynamic certificate resolver lock poisoned")
            .clone()
    }
}

/// Parse a PEM certificate chain and private key into a rustls key pair that a
/// managed certificate provider can atomically publish.
pub fn certified_key_from_pem(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<Arc<CertifiedKey>, TlsError> {
    let certificates = parse_pem_certificates(certificate_pem)?;
    if certificates.is_empty() {
        return Err(TlsError::Certificate("certificate chain is empty".into()));
    }
    let mut key_reader = BufReader::new(private_key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| TlsError::PrivateKey(error.to_string()))?
        .ok_or_else(|| {
            TlsError::PrivateKey("no private key configured".into())
        })?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|error| TlsError::PrivateKey(error.to_string()))?;
    let certified_key = CertifiedKey::new(certificates, signing_key);
    certified_key
        .keys_match()
        .map_err(|error| TlsError::PrivateKey(error.to_string()))?;
    Ok(Arc::new(certified_key))
}

pub fn build_server_config(
    options: &InboundTlsOptions,
) -> Result<ServerTlsConfig, TlsError> {
    build_server_config_with_default_alpn_and_reality_dialer(
        options,
        &[],
        standalone_reality_dialer(options)?,
    )
}

/// Build a server TLS configuration using an NTP-corrected wall clock for
/// client-certificate validity and TLS ticket age checks.
pub fn build_server_config_with_clock(
    options: &InboundTlsOptions,
    clock: Option<NtpClock>,
) -> Result<ServerTlsConfig, TlsError> {
    let mut options = options.clone();
    options.ntp_clock = clock;
    build_server_config(&options)
}

pub fn build_server_config_with_default_alpn(
    options: &InboundTlsOptions,
    default_alpn: &[&str],
) -> Result<ServerTlsConfig, TlsError> {
    build_server_config_with_default_alpn_and_reality_dialer(
        options,
        default_alpn,
        standalone_reality_dialer(options)?,
    )
}

fn standalone_reality_dialer(
    options: &InboundTlsOptions,
) -> Result<Option<Arc<dyn Dialer>>, TlsError> {
    let Some(reality) =
        options.reality.as_ref().filter(|reality| reality.enabled)
    else {
        return Ok(None);
    };
    if !reality.handshake.dialer.detour.is_empty() {
        return Err(TlsError::Unsupported(
            "REALITY handshake detour requires a Runtime outbound registry"
                .into(),
        ));
    }
    Ok(Some(Arc::new(
        crate::protocol::direct::DirectOutbound::new(
            crate::option::DirectOutboundOptions {
                dialer: reality.handshake.dialer.clone(),
                ..Default::default()
            },
        ),
    )))
}

pub(crate) fn build_server_config_with_default_alpn_and_reality_dialer(
    options: &InboundTlsOptions,
    default_alpn: &[&str],
    reality_dialer: Option<Arc<dyn Dialer>>,
) -> Result<ServerTlsConfig, TlsError> {
    if options
        .reality
        .as_ref()
        .is_some_and(|reality| reality.enabled)
    {
        return build_reality_server_config(
            options,
            default_alpn,
            reality_dialer.ok_or_else(|| {
                TlsError::Unsupported(
                    "REALITY server requires a handshake dialer".into(),
                )
            })?,
        );
    }
    build_server_config_with_default_alpn_and_resolver(
        options,
        default_alpn,
        options.certificate_resolver.0.clone(),
    )
}

fn build_reality_server_config(
    options: &InboundTlsOptions,
    default_alpn: &[&str],
    dialer: Arc<dyn Dialer>,
) -> Result<ServerTlsConfig, TlsError> {
    let reality = options
        .reality
        .as_ref()
        .filter(|reality| reality.enabled)
        .expect("enabled REALITY checked");
    if options.certificate_provider.is_some() || options.acme.is_some() {
        return Err(TlsError::Unsupported(
            "certificate_provider and acme are unavailable in REALITY".into(),
        ));
    }
    if !options.curve_preferences.as_slice().is_empty() {
        return Err(TlsError::Unsupported(
            "curve preferences are unavailable in REALITY".into(),
        ));
    }
    if !options.certificate.as_slice().is_empty()
        || !options.certificate_path.is_empty()
        || !options.key.as_slice().is_empty()
        || !options.key_path.is_empty()
        || !options
            .client_certificate_public_key_sha256
            .as_slice()
            .is_empty()
    {
        return Err(TlsError::Unsupported(
            "certificate and key options are unavailable in REALITY".into(),
        ));
    }
    if options.ech.as_ref().is_some_and(|ech| ech.enabled) {
        return Err(TlsError::Unsupported("REALITY conflicts with ECH".into()));
    }
    if reality.handshake.server.server.is_empty()
        || reality.handshake.server.server_port == 0
    {
        return Err(TlsError::Unsupported(
            "REALITY handshake server and server_port are required".into(),
        ));
    }

    let provider = crypto_provider(options.cipher_suites.as_slice(), &[])?;
    let versions =
        protocol_versions(&options.min_version, &options.max_version)?;
    if !versions.contains(&&rustls::version::TLS13) {
        return Err(TlsError::Unsupported(
            "REALITY server requires TLS 1.3".into(),
        ));
    }
    let runtime = Arc::new(
        RealityServerRuntime::new(
            &reality.private_key,
            reality.short_id.as_slice(),
            reality.max_time_difference.as_std().unwrap_or_default(),
            options.server_name.clone(),
            crate::common::network::SocksAddr::new(
                reality.handshake.server.server.clone(),
                reality.handshake.server.server_port,
            ),
            dialer,
        )
        .map_err(TlsError::Unsupported)?,
    );
    let builder = if let Some(clock) = options.ntp_clock.clone() {
        ServerConfig::builder_with_details(
            provider,
            Arc::new(NtpTimeProvider(clock)),
        )
    } else {
        ServerConfig::builder_with_provider(provider)
    };
    let mut config = builder
        .with_protocol_versions(&versions)
        .map_err(|error| TlsError::Unsupported(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(runtime.placeholder_resolver());
    config.alpn_protocols = if options.alpn.as_slice().is_empty() {
        default_alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    } else {
        options
            .alpn
            .as_slice()
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    };
    config.send_tls13_tickets = 0;
    config.enable_secret_extraction = options.kernel_tx || options.kernel_rx;
    Ok(ServerTlsConfig {
        config: Arc::new(config),
        handshake_timeout: options
            .handshake_timeout
            .as_std()
            .filter(|timeout| !timeout.is_zero())
            .or(Some(TLS_HANDSHAKE_TIMEOUT)),
        reality: Some(runtime),
        kernel_tx: options.kernel_tx,
        kernel_rx: options.kernel_rx,
    })
}

/// Build a server configuration backed by a managed certificate resolver.
///
/// The resolver is required when `certificate_provider` is configured.  This
/// separate entry point keeps the ordinary static-certificate builder small
/// while allowing the runtime certificate-provider manager to inject shared or
/// inline providers.
pub fn build_server_config_with_default_alpn_and_resolver(
    options: &InboundTlsOptions,
    default_alpn: &[&str],
    certificate_resolver: Option<Arc<dyn ResolvesServerCert>>,
) -> Result<ServerTlsConfig, TlsError> {
    validate_server_supported(options, certificate_resolver.is_some())?;
    let managed_certificate = certificate_resolver.is_some();
    if managed_certificate && options.insecure {
        return Err(TlsError::Unsupported(
            "insecure is unused with certificate_provider".into(),
        ));
    }
    let mut certificates = Vec::new();
    let mut key_bytes = Vec::new();
    if !managed_certificate {
        for certificate in options.certificate.as_slice() {
            certificates
                .extend(parse_pem_certificates(certificate.as_bytes())?);
        }
        if !options.certificate_path.is_empty() {
            let bytes =
                fs::read(&options.certificate_path).map_err(|source| {
                    TlsError::ReadCertificate {
                        path: options.certificate_path.clone(),
                        source,
                    }
                })?;
            certificates.extend(parse_pem_certificates(&bytes)?);
        }
        for key in options.key.as_slice() {
            key_bytes.extend_from_slice(key.as_bytes());
            key_bytes.push(b'\n');
        }
        if !options.key_path.is_empty() {
            key_bytes = fs::read(&options.key_path).map_err(|source| {
                TlsError::ReadPrivateKey {
                    path: options.key_path.clone(),
                    source,
                }
            })?;
        }
    }
    let dynamic_certificate =
        certificates.is_empty() && key_bytes.is_empty() && options.insecure;
    if certificates.is_empty() && !dynamic_certificate && !managed_certificate {
        return Err(TlsError::Certificate(
            "no server certificate configured".into(),
        ));
    }
    if key_bytes.is_empty() && !dynamic_certificate && !managed_certificate {
        return Err(TlsError::PrivateKey("no private key configured".into()));
    }
    let key = if dynamic_certificate || managed_certificate {
        None
    } else {
        let mut key_reader = BufReader::new(key_bytes.as_slice());
        Some(
            rustls_pemfile::private_key(&mut key_reader)
                .map_err(|error| TlsError::PrivateKey(error.to_string()))?
                .ok_or_else(|| {
                    TlsError::PrivateKey("no private key configured".into())
                })?,
        )
    };
    let provider = crypto_provider(
        options.cipher_suites.as_slice(),
        options.curve_preferences.as_slice(),
    )?;
    let client_verify_provider = provider.clone();
    let certificate_provider = provider.clone();
    let versions =
        protocol_versions(&options.min_version, &options.max_version)?;
    let builder = if let Some(clock) = options.ntp_clock.clone() {
        ServerConfig::builder_with_details(
            provider,
            Arc::new(NtpTimeProvider(clock)),
        )
    } else {
        ServerConfig::builder_with_provider(provider)
    }
    .with_protocol_versions(&versions)
    .map_err(|error| TlsError::Unsupported(error.to_string()))?;
    let has_client_ca = !options.client_certificate.as_slice().is_empty()
        || !options.client_certificate_path.as_slice().is_empty();
    let client_authentication = if has_client_ca
        && options.client_authentication == ClientAuthType::No
    {
        ClientAuthType::RequireAndVerify
    } else {
        options.client_authentication
    };
    let builder = match client_authentication {
        ClientAuthType::No => builder.with_no_client_auth(),
        ClientAuthType::VerifyIfGiven | ClientAuthType::RequireAndVerify => {
            if has_client_ca {
                let mut client_roots = RootCertStore::empty();
                for certificate in options.client_certificate.as_slice() {
                    add_pem_certificates(
                        &mut client_roots,
                        certificate.as_bytes(),
                    )?;
                }
                for path in options.client_certificate_path.as_slice() {
                    let bytes = fs::read(path).map_err(|source| {
                        TlsError::ReadCertificate {
                            path: path.clone(),
                            source,
                        }
                    })?;
                    add_pem_certificates(&mut client_roots, &bytes)?;
                }
                let verifier =
                    rustls::server::WebPkiClientVerifier::builder_with_provider(
                        Arc::new(client_roots),
                        client_verify_provider,
                    );
                let verifier = if client_authentication
                    == ClientAuthType::VerifyIfGiven
                {
                    verifier.allow_unauthenticated()
                } else {
                    verifier
                }
                .build()
                .map_err(|error| TlsError::Certificate(error.to_string()))?;
                builder.with_client_cert_verifier(verifier)
            } else if !options
                .client_certificate_public_key_sha256
                .as_slice()
                .is_empty()
            {
                builder.with_client_cert_verifier(Arc::new(
                    AnyClientCertVerifier {
                        mandatory: client_authentication
                            == ClientAuthType::RequireAndVerify,
                        provider: client_verify_provider,
                        public_key_sha256: options
                            .client_certificate_public_key_sha256
                            .as_slice()
                            .iter()
                            .map(|value| value.0.clone())
                            .collect(),
                    },
                ))
            } else {
                return Err(TlsError::Certificate(
                    "missing client certificate authority or public-key pin"
                        .into(),
                ));
            }
        }
        ClientAuthType::Request | ClientAuthType::RequireAny => builder
            .with_client_cert_verifier(Arc::new(AnyClientCertVerifier {
                mandatory: client_authentication == ClientAuthType::RequireAny,
                provider: client_verify_provider,
                public_key_sha256: Vec::new(),
            })),
    };
    let ech_keys = build_ech_server_keys(options)?;
    let mut config = if let Some(certificate_resolver) = certificate_resolver {
        builder.with_cert_resolver(certificate_resolver)
    } else if dynamic_certificate {
        builder.with_cert_resolver(Arc::new(InsecureCertificateResolver {
            provider: certificate_provider,
            certificates: std::sync::Mutex::new(
                std::collections::HashMap::new(),
            ),
        }))
    } else {
        builder
            .with_single_cert(certificates, key.expect("static key validated"))
            .map_err(|error| TlsError::Certificate(error.to_string()))?
    };
    config.alpn_protocols = if options.alpn.as_slice().is_empty() {
        default_alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    } else {
        options
            .alpn
            .as_slice()
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    };
    if options.certificate_resolver.1
        && !config
            .alpn_protocols
            .iter()
            .any(|protocol| protocol == b"acme-tls/1")
    {
        config.alpn_protocols.insert(0, b"acme-tls/1".to_vec());
    }
    if !ech_keys.is_empty() {
        config.ech_keys = Arc::new(FixedEchKeys::new(ech_keys));
    }
    config.enable_secret_extraction = options.kernel_tx || options.kernel_rx;
    Ok(ServerTlsConfig {
        config: Arc::new(config),
        handshake_timeout: options
            .handshake_timeout
            .as_std()
            .filter(|timeout| !timeout.is_zero())
            .or(Some(TLS_HANDSHAKE_TIMEOUT)),
        reality: None,
        kernel_tx: options.kernel_tx,
        kernel_rx: options.kernel_rx,
    })
}

fn build_ech_server_keys(
    options: &InboundTlsOptions,
) -> Result<Vec<EchServerKey>, TlsError> {
    let Some(ech) = options.ech.as_ref().filter(|ech| ech.enabled) else {
        return Ok(Vec::new());
    };
    if ech.pq_signature_schemes_enabled || ech.dynamic_record_sizing_disabled {
        return Err(TlsError::Unsupported(
            "legacy ECH options are deprecated and unavailable".into(),
        ));
    }
    let key_pem = if !ech.key.as_slice().is_empty() {
        let mut joined = ech.key.as_slice().join("\n").into_bytes();
        joined.push(b'\n');
        joined
    } else if !ech.key_path.is_empty() {
        fs::read(&ech.key_path).map_err(|source| TlsError::ReadEchKey {
            path: ech.key_path.clone(),
            source,
        })?
    } else {
        return Err(TlsError::EchKey("missing ECH keys".into()));
    };
    let ech_keys = parse_ech_server_keys(&key_pem)?;
    ech_keys
        .into_iter()
        .map(|(private_key, config)| {
            EchServerKey::from_raw(
                &config,
                private_key,
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map(|key| key.with_retry(false))
            .map_err(|error| TlsError::EchKey(error.to_string()))
        })
        .collect()
}

type RawEchServerKey = (Vec<u8>, Vec<u8>);

fn parse_ech_server_keys(
    pem_bytes: &[u8],
) -> Result<Vec<RawEchServerKey>, TlsError> {
    let block = pem::parse(pem_bytes)
        .map_err(|error| TlsError::EchKey(error.to_string()))?;
    if block.tag() != "ECH KEYS" {
        return Err(TlsError::EchKey("invalid ECH keys PEM type".into()));
    }
    let mut wire = block.contents();
    let mut keys = Vec::new();
    while !wire.is_empty() {
        let private_key = take_u16_field(&mut wire, "private key")?;
        let config = take_u16_field(&mut wire, "ECH config")?;
        keys.push((private_key.to_vec(), config.to_vec()));
    }
    if keys.is_empty() {
        return Err(TlsError::EchKey("empty ECH keys".into()));
    }
    Ok(keys)
}

fn take_u16_field<'a>(
    wire: &mut &'a [u8],
    field: &str,
) -> Result<&'a [u8], TlsError> {
    let length_bytes: [u8; 2] = wire
        .get(..2)
        .ok_or_else(|| TlsError::EchKey(format!("error parsing {field}")))?
        .try_into()
        .expect("two-byte slice");
    let length = usize::from(u16::from_be_bytes(length_bytes));
    let value = wire
        .get(2..2 + length)
        .ok_or_else(|| TlsError::EchKey(format!("error parsing {field}")))?;
    *wire = &wire[2 + length..];
    Ok(value)
}

pub struct ClientTlsDialer<D> {
    upstream: D,
    tls: ClientTlsConfig,
}

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_FRAGMENT_FALLBACK_DELAY: Duration = Duration::from_millis(500);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

struct TlsFragmentWrite {
    fragments: Vec<Vec<u8>>,
    fragment_index: usize,
    offset: usize,
    original_len: usize,
    delay: Option<Pin<Box<Sleep>>>,
}

/// Splits the first complete TLS ClientHello at a random byte of its first
/// SNI label. This mirrors sing-box's fallback path when the underlying TCP
/// socket cannot expose platform ACK notifications: packet fragmentation is
/// separated by the configured delay, while record fragmentation rewrites
/// each piece as an independent handshake record.
struct TlsFragmentStream {
    inner: Stream,
    split_packet: bool,
    split_record: bool,
    fallback_delay: Duration,
    first_write_started: bool,
    pending: Option<TlsFragmentWrite>,
}

impl TlsFragmentStream {
    fn new(
        inner: Stream,
        split_packet: bool,
        split_record: bool,
        fallback_delay: Duration,
    ) -> Self {
        Self {
            inner,
            split_packet,
            split_record,
            fallback_delay,
            first_write_started: false,
            pending: None,
        }
    }

    fn prepare(&self, buffer: &[u8]) -> Option<TlsFragmentWrite> {
        let server_name_range = tls_client_hello_server_name(buffer)?;
        let server_name = &buffer[server_name_range.start
            ..server_name_range.start + server_name_range.len];
        let label_offset = if server_name.starts_with(b"...") {
            4
        } else {
            0
        };
        let label_len = server_name[label_offset..]
            .iter()
            .position(|byte| *byte == b'.')
            .unwrap_or(server_name.len() - label_offset);
        if label_len == 0 {
            return None;
        }
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).ok()?;
        let random = u64::from_ne_bytes(random) as usize;
        let split = server_name_range.start + label_offset + random % label_len;
        let ranges = [0..split, split..buffer.len()];
        let mut fragments = Vec::with_capacity(2);
        for range in ranges {
            let payload = if self.split_record {
                let payload_start = range.start.max(TLS_RECORD_HEADER_LEN);
                &buffer[payload_start..range.end]
            } else {
                &buffer[range]
            };
            if self.split_record {
                let payload_len = u16::try_from(payload.len()).ok()?;
                let mut record =
                    Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
                record.extend_from_slice(&buffer[..3]);
                record.extend_from_slice(&payload_len.to_be_bytes());
                record.extend_from_slice(payload);
                fragments.push(record);
            } else {
                fragments.push(payload.to_vec());
            }
        }
        if !self.split_packet {
            let joined = fragments.into_iter().flatten().collect();
            fragments = vec![joined];
        }
        Some(TlsFragmentWrite {
            fragments,
            fragment_index: 0,
            offset: 0,
            original_len: buffer.len(),
            delay: None,
        })
    }
}

impl AsyncRead for TlsFragmentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for TlsFragmentStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.first_write_started {
            self.first_write_started = true;
            self.pending = self.prepare(buffer);
        }
        if self.pending.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, buffer);
        }
        loop {
            let mut pending = self.pending.take().expect("pending write set");
            if let Some(mut delay) = pending.delay.take()
                && delay.as_mut().poll(cx).is_pending()
            {
                pending.delay = Some(delay);
                self.pending = Some(pending);
                return Poll::Pending;
            }
            let fragment = &pending.fragments[pending.fragment_index];
            match Pin::new(&mut self.inner)
                .poll_write(cx, &fragment[pending.offset..])
            {
                Poll::Pending => {
                    self.pending = Some(pending);
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write fragmented TLS ClientHello",
                    )));
                }
                Poll::Ready(Ok(size)) => pending.offset += size,
            }
            if pending.offset < fragment.len() {
                self.pending = Some(pending);
                continue;
            }
            pending.fragment_index += 1;
            pending.offset = 0;
            if pending.fragment_index == pending.fragments.len() {
                return Poll::Ready(Ok(pending.original_len));
            }
            if self.split_packet && !self.fallback_delay.is_zero() {
                pending.delay =
                    Some(Box::pin(tokio::time::sleep(self.fallback_delay)));
            }
            self.pending = Some(pending);
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy)]
struct TlsServerNameRange {
    start: usize,
    len: usize,
}

fn tls_client_hello_server_name(payload: &[u8]) -> Option<TlsServerNameRange> {
    if payload.len() < TLS_RECORD_HEADER_LEN || payload[0] != 22 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    if payload.len() != TLS_RECORD_HEADER_LEN + record_len {
        return None;
    }
    let handshake = &payload[TLS_RECORD_HEADER_LEN..];
    if handshake.len() < 4 + 2 + 32 + 1 || handshake[0] != 1 {
        return None;
    }
    let handshake_len = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    if handshake.len() != 4 + handshake_len {
        return None;
    }
    let version = u16::from_be_bytes([handshake[4], handshake[5]]);
    if version & 0xfffc != 0x0300 && version != 0x0304 {
        return None;
    }
    let mut offset = 4 + 2 + 32;
    let session_len = usize::from(*handshake.get(offset)?);
    offset += 1 + session_len;
    let cipher_len = usize::from(u16::from_be_bytes([
        *handshake.get(offset)?,
        *handshake.get(offset + 1)?,
    ]));
    offset += 2 + cipher_len;
    let compression_len = usize::from(*handshake.get(offset)?);
    offset += 1 + compression_len;
    let extensions_len = usize::from(u16::from_be_bytes([
        *handshake.get(offset)?,
        *handshake.get(offset + 1)?,
    ]));
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    if extensions_end > handshake.len() {
        return None;
    }
    while offset < extensions_end {
        let extension_type = u16::from_be_bytes([
            *handshake.get(offset)?,
            *handshake.get(offset + 1)?,
        ]);
        let extension_len = usize::from(u16::from_be_bytes([
            *handshake.get(offset + 2)?,
            *handshake.get(offset + 3)?,
        ]));
        offset += 4;
        let extension_end = offset.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        if extension_type == 0 {
            let list_len = usize::from(u16::from_be_bytes([
                *handshake.get(offset)?,
                *handshake.get(offset + 1)?,
            ]));
            if list_len + 2 > extension_len || *handshake.get(offset + 2)? != 0
            {
                return None;
            }
            let name_len = usize::from(u16::from_be_bytes([
                *handshake.get(offset + 3)?,
                *handshake.get(offset + 4)?,
            ]));
            let name_start = offset + 5;
            if name_start.checked_add(name_len)? > extension_end {
                return None;
            }
            return Some(TlsServerNameRange {
                start: TLS_RECORD_HEADER_LEN + name_start,
                len: name_len,
            });
        }
        offset = extension_end;
    }
    None
}

#[derive(Debug, Default)]
struct TlsVisionSwitch {
    read_direct: AtomicBool,
    write_direct: AtomicBool,
    read_direct_active: AtomicBool,
    write_direct_active: AtomicBool,
}

impl VisionDirectSwitch for TlsVisionSwitch {
    fn request_read_direct(&self) {
        self.read_direct.store(true, Ordering::Release);
    }

    fn request_write_direct(&self) {
        self.write_direct.store(true, Ordering::Release);
    }

    fn read_direct_active(&self) -> bool {
        self.read_direct_active.load(Ordering::Acquire)
    }

    fn write_direct_active(&self) -> bool {
        self.write_direct_active.load(Ordering::Acquire)
    }
}

/// Prevent rustls from reading beyond one complete outer TLS record in a
/// single `read_tls` call.  Vision peers can append raw inner-TLS bytes
/// immediately after their final encrypted Direct record; allowing one socket
/// read to consume both makes rustls authenticate the raw suffix as another
/// outer record before Vision can retire that direction.
struct TlsRecordStream {
    inner: Stream,
    switch: Arc<TlsVisionSwitch>,
    header: [u8; 5],
    header_filled: usize,
    header_sent: usize,
    payload_remaining: Option<usize>,
}

impl TlsRecordStream {
    fn new(inner: Stream, switch: Arc<TlsVisionSwitch>) -> Self {
        Self {
            inner,
            switch,
            header: [0; 5],
            header_filled: 0,
            header_sent: 0,
            payload_remaining: None,
        }
    }
}

impl AsyncRead for TlsRecordStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.switch.read_direct_active.load(Ordering::Acquire) {
            return Pin::new(&mut self.inner).poll_read(cx, output);
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(remaining) = self.payload_remaining {
                if remaining == 0 {
                    self.payload_remaining = None;
                    self.header_filled = 0;
                    self.header_sent = 0;
                    continue;
                }
                let limit = output.remaining().min(remaining);
                let (result, initialized, filled) = {
                    let mut input = output.take(limit);
                    let result =
                        Pin::new(&mut self.inner).poll_read(cx, &mut input);
                    (result, input.initialized().len(), input.filled().len())
                };
                // `ReadBuf::take` borrows the parent's unfilled memory but
                // tracks initialization and fill length independently.
                // Propagate both counters before interpreting the result.
                // SAFETY: the nested read buffer reports exactly the prefix
                // initialized by the underlying `AsyncRead` implementation.
                unsafe { output.assume_init(initialized) };
                output.advance(filled);
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if filled == 0 => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated outer TLS record",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        self.payload_remaining = Some(remaining - filled);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            while self.header_filled < self.header.len() {
                let start = self.header_filled;
                let mut scratch = [0_u8; 5];
                let mut input =
                    ReadBuf::new(&mut scratch[..self.header.len() - start]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut input) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if input.filled().is_empty() => {
                        if self.header_filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated outer TLS record header",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        let end = start + input.filled().len();
                        self.header[start..end].copy_from_slice(input.filled());
                        self.header_filled += input.filled().len();
                    }
                }
            }
            let available = self.header.len() - self.header_sent;
            let size = output.remaining().min(available);
            let end = self.header_sent + size;
            output.put_slice(&self.header[self.header_sent..end]);
            self.header_sent = end;
            if self.header_sent == self.header.len() {
                self.payload_remaining =
                    Some(usize::from(u16::from_be_bytes([
                        self.header[3],
                        self.header[4],
                    ])));
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for TlsRecordStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct SwitchableTlsStream {
    tls: TlsStream<Stream>,
    switch: Arc<TlsVisionSwitch>,
    read_direct: bool,
    write_direct: bool,
    read_ahead: Vec<u8>,
    read_offset: usize,
}

impl SwitchableTlsStream {
    fn new(tls: TlsStream<Stream>, switch: Arc<TlsVisionSwitch>) -> Self {
        Self {
            tls,
            switch,
            read_direct: false,
            write_direct: false,
            read_ahead: Vec::new(),
            read_offset: 0,
        }
    }

    fn switch_read_if_requested(&mut self) {
        if self.read_direct
            || !self.switch.read_direct.swap(false, Ordering::AcqRel)
        {
            return;
        }
        let (plaintext, raw) = match &mut self.tls {
            TlsStream::Client(tls) => {
                tls.get_mut().1.dangerous_take_read_ahead()
            }
            TlsStream::Server(tls) => {
                tls.get_mut().1.dangerous_take_read_ahead()
            }
        };
        let plaintext_len = plaintext.len();
        let raw_len = raw.len();
        self.read_ahead = [plaintext, raw].concat();
        self.read_offset = 0;
        self.read_direct = true;
        tracing::trace!(
            decrypted = plaintext_len,
            raw = raw_len,
            "VLESS Vision activated raw TLS read direction"
        );
        self.switch
            .read_direct_active
            .store(true, Ordering::Release);
    }

    fn switch_write_if_requested(&mut self) {
        if !self.write_direct
            && self.switch.write_direct.swap(false, Ordering::AcqRel)
        {
            self.write_direct = true;
            tracing::trace!("VLESS Vision activated raw TLS write direction");
            self.switch
                .write_direct_active
                .store(true, Ordering::Release);
        }
    }

    fn raw_stream(&mut self) -> &mut Stream {
        match &mut self.tls {
            TlsStream::Client(tls) => tls.get_mut().0,
            TlsStream::Server(tls) => tls.get_mut().0,
        }
    }
}

impl AsyncRead for SwitchableTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.switch_read_if_requested();
        if self.read_direct {
            if self.read_offset < self.read_ahead.len()
                && buffer.remaining() != 0
            {
                let size = buffer.remaining().min(
                    self.read_ahead.len().saturating_sub(self.read_offset),
                );
                let end = self.read_offset + size;
                buffer.put_slice(&self.read_ahead[self.read_offset..end]);
                self.read_offset = end;
                if self.read_offset == self.read_ahead.len() {
                    self.read_ahead.clear();
                    self.read_offset = 0;
                }
                Poll::Ready(Ok(()))
            } else {
                Pin::new(self.raw_stream()).poll_read(cx, buffer)
            }
        } else {
            Pin::new(&mut self.tls).poll_read(cx, buffer)
        }
    }
}

impl AsyncWrite for SwitchableTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.switch_write_if_requested();
        if self.write_direct {
            Pin::new(self.raw_stream()).poll_write(cx, buffer)
        } else {
            Pin::new(&mut self.tls).poll_write(cx, buffer)
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.switch_write_if_requested();
        if self.write_direct {
            Pin::new(self.raw_stream()).poll_flush(cx)
        } else {
            Pin::new(&mut self.tls).poll_flush(cx)
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.switch_write_if_requested();
        if self.write_direct {
            Pin::new(self.raw_stream()).poll_shutdown(cx)
        } else {
            Pin::new(&mut self.tls).poll_shutdown(cx)
        }
    }
}

impl ServerTlsConfig {
    pub(crate) async fn accept_stream(
        &self,
        stream: Stream,
    ) -> io::Result<AcceptedServerTlsStream> {
        #[cfg(target_os = "linux")]
        let socket = crate::adapter::stream_socket(&stream);
        let handshake = async {
            if let Some(reality) = &self.reality {
                reality.accept(stream, self.config.clone()).await
            } else {
                TlsAcceptor::from(self.config.clone())
                    .accept(stream)
                    .await
                    .map_err(io::Error::other)
            }
        };
        let accepted = if let Some(limit) = self.handshake_timeout {
            timeout(limit, handshake).await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                )
            })?
        } else {
            handshake.await
        }?;
        #[cfg(target_os = "linux")]
        if self.kernel_tx || self.kernel_rx {
            let socket = socket.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "kTLS requires a physical TCP stream",
                )
            })?;
            let alpn =
                accepted.get_ref().1.alpn_protocol().map(ToOwned::to_owned);
            return Ok(AcceptedServerTlsStream::Ktls {
                stream: Box::new(crate::common::ktls::KtlsStream::new_server(
                    accepted,
                    socket,
                    self.kernel_tx,
                    self.kernel_rx,
                )?),
                alpn,
            });
        }
        Ok(AcceptedServerTlsStream::Rustls(Box::new(accepted)))
    }
}

pub(crate) async fn accept_switchable_server_tls(
    stream: Stream,
    tls: ServerTlsConfig,
) -> io::Result<VisionTransport> {
    #[cfg(target_os = "linux")]
    if tls.kernel_tx || tls.kernel_rx {
        let mut stream = tls.accept_stream(stream).await?;
        let AcceptedServerTlsStream::Ktls {
            stream: ktls_stream,
            ..
        } = &mut stream
        else {
            unreachable!("kTLS options must produce a kTLS stream")
        };
        let direct_switch =
            Arc::new(crate::common::ktls::KtlsVisionSwitch::default());
        ktls_stream.enable_vision(direct_switch.clone());
        return Ok(VisionTransport {
            stream: Box::new(stream),
            direct_switch,
        });
    }
    let direct_switch = Arc::new(TlsVisionSwitch::default());
    let stream: Stream =
        Box::new(TlsRecordStream::new(stream, direct_switch.clone()));
    let stream = tls.accept_stream(stream).await?;
    #[cfg(target_os = "linux")]
    let stream = match stream {
        AcceptedServerTlsStream::Rustls(stream) => *stream,
        AcceptedServerTlsStream::Ktls { .. } => {
            unreachable!("kTLS was rejected before the handshake")
        }
    };
    #[cfg(not(target_os = "linux"))]
    let AcceptedServerTlsStream::Rustls(stream) = stream;
    #[cfg(not(target_os = "linux"))]
    let stream = *stream;
    Ok(VisionTransport {
        stream: Box::new(SwitchableTlsStream::new(
            TlsStream::Server(stream),
            direct_switch.clone(),
        )),
        direct_switch,
    })
}

impl<D> ClientTlsDialer<D> {
    pub fn new(upstream: D, tls: ClientTlsConfig) -> Self {
        Self { upstream, tls }
    }
}

impl ClientTlsConfig {
    /// Return the static rustls configuration used by QUIC consumers.
    /// Stream-only backends such as legacy OpenSSL are rejected explicitly.
    pub fn rustls_config(&self) -> Result<Arc<ClientConfig>, TlsError> {
        if self.kernel_tx || self.kernel_rx {
            return Err(TlsError::Unsupported(
                "Linux kTLS is a TCP stream transport and is unavailable for QUIC"
                    .into(),
            ));
        }
        match self.backend {
            ClientTlsBackend::Rustls => Ok(self.config.clone()),
            ClientTlsBackend::OpenSsl(_) => Err(TlsError::Unsupported(
                "TLS 1.0/1.1 is unavailable for QUIC".into(),
            )),
            #[cfg(target_vendor = "apple")]
            ClientTlsBackend::Apple(_) => Err(TlsError::Unsupported(
                "Apple TLS engine is unavailable for QUIC".into(),
            )),
            #[cfg(windows)]
            ClientTlsBackend::Windows(_) => Err(TlsError::Unsupported(
                "Windows TLS engine is unavailable for QUIC".into(),
            )),
        }
    }

    fn wrap_client_stream(&self, stream: Stream) -> io::Result<Stream> {
        let stream = wrap_tls_fragment(
            stream,
            self.fragment,
            self.record_fragment,
            self.fragment_fallback_delay,
        );
        crate::common::tls_spoof::wrap_tls_spoof(
            stream,
            &self.spoof,
            self.spoof_method,
        )
    }

    /// Return the rustls configuration for the next handshake.
    ///
    /// Static configurations return immediately. Dynamic ECH configurations
    /// resolve an HTTPS DNS record once and reuse the resulting configuration
    /// until the record TTL expires.
    pub async fn config_for_handshake(
        &self,
    ) -> Result<Arc<ClientConfig>, TlsError> {
        match self.backend {
            ClientTlsBackend::Rustls => {}
            ClientTlsBackend::OpenSsl(_) => {
                return Err(TlsError::Unsupported(
                    "TLS 1.0/1.1 backend does not expose a rustls handshake"
                        .into(),
                ));
            }
            #[cfg(target_vendor = "apple")]
            ClientTlsBackend::Apple(_) => {
                return Err(TlsError::Unsupported(
                    "Apple TLS engine does not expose a rustls handshake"
                        .into(),
                ));
            }
            #[cfg(windows)]
            ClientTlsBackend::Windows(_) => {
                return Err(TlsError::Unsupported(
                    "Windows TLS engine does not expose a rustls handshake"
                        .into(),
                ));
            }
        }
        if let Some(retry) = &self.ech_retry {
            let now = Instant::now();
            let mut cache = retry.cache.lock().await;
            if let Some((expires_at, config)) = cache.as_ref() {
                if expires_at.is_none_or(|expires_at| now < expires_at) {
                    return Ok(config.clone());
                }
                *cache = None;
            }
            drop(cache);
        }
        let Some(dynamic) = &self.dynamic_ech else {
            return Ok(self.config.clone());
        };
        let mut cache = dynamic.cache.lock().await;
        if let Some((expires_at, config)) = cache.as_ref()
            && Instant::now() < *expires_at
        {
            return Ok(config.clone());
        }
        let record = dynamic
            .resolver
            .resolve_ech(&dynamic.query_server_name)
            .await
            .map_err(|error| TlsError::EchDiscovery(error.to_string()))?;
        if record.config_list.is_empty() {
            return Err(TlsError::EchDiscovery(
                "DNS HTTPS record contains an empty ECH config list".into(),
            ));
        }
        let mut options = dynamic.options.clone();
        let ech = options
            .ech
            .as_mut()
            .expect("dynamic ECH state requires enabled ECH options");
        ech.config = crate::option::Listable(vec![pem::encode(
            &pem::Pem::new("ECH CONFIGS", record.config_list),
        )]);
        ech.config_path.clear();
        let config = build_client_config_with_clock(
            &dynamic.endpoint_host,
            &options,
            &dynamic
                .default_alpn
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            dynamic.clock.clone(),
        )?
        .config;
        let expires_at = Instant::now()
            .checked_add(record.ttl)
            .unwrap_or_else(Instant::now);
        *cache = Some((expires_at, config.clone()));
        Ok(config)
    }

    /// Rebuild this ECH client configuration from a server-provided retry
    /// config list.
    ///
    /// Returns `Ok(None)` when ECH is not enabled. For dynamically discovered
    /// ECH, the replacement remains cached only for the original DNS record's
    /// remaining TTL; a zero/expired TTL still permits the immediate retry but
    /// forces the next independent handshake to query DNS again.
    pub async fn config_for_ech_retry(
        &self,
        config_list: &[u8],
    ) -> Result<Option<Arc<ClientConfig>>, TlsError> {
        let Some(retry) = &self.ech_retry else {
            return Ok(None);
        };
        if config_list.is_empty() {
            return Ok(None);
        }
        let mut options = retry.options.clone();
        let ech = options
            .ech
            .as_mut()
            .expect("ECH retry state requires enabled ECH options");
        ech.config = crate::option::Listable(vec![pem::encode(
            &pem::Pem::new("ECH CONFIGS", config_list.to_vec()),
        )]);
        ech.config_path.clear();
        let config = build_client_config_with_clock(
            &retry.endpoint_host,
            &options,
            &retry
                .default_alpn
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            retry.clock.clone(),
        )?
        .config;
        let expires_at = if let Some(dynamic) = &self.dynamic_ech {
            dynamic
                .cache
                .lock()
                .await
                .as_ref()
                .map(|(expires_at, _)| *expires_at)
        } else {
            None
        };
        *retry.cache.lock().await = Some((expires_at, config.clone()));
        Ok(Some(config))
    }

    /// Perform a TLS handshake over an already connected transport stream.
    ///
    /// ECH retry requires opening a fresh transport connection and is therefore
    /// handled by [`ClientTlsDialer`].  Callers that already own the connected
    /// stream still receive dynamic-ECH discovery, fragmentation, spoofing,
    /// timeout handling, socket metadata preservation, ALPN, and the peer
    /// certificate chain through this backend-neutral entry point.
    pub async fn connect_stream(
        &self,
        connection: Stream,
    ) -> io::Result<ClientTlsStream> {
        self.connect_stream_with_timeout(connection, self.handshake_timeout)
            .await
    }

    /// Perform a TLS handshake with an explicit timeout override.
    pub async fn connect_stream_with_timeout(
        &self,
        connection: Stream,
        handshake_timeout: Option<Duration>,
    ) -> io::Result<ClientTlsStream> {
        let socket = crate::adapter::stream_socket(&connection);
        let connection = self.wrap_client_stream(connection)?;
        match &self.backend {
            ClientTlsBackend::Rustls => {
                let config = self
                    .config_for_handshake()
                    .await
                    .map_err(io::Error::other)?;
                let connection = complete_client_handshake(
                    self,
                    connection,
                    config,
                    handshake_timeout,
                )
                .await
                .map_err(io::Error::other)?;
                let negotiated_alpn = connection
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(ToOwned::to_owned);
                let peer_certificates = connection
                    .get_ref()
                    .1
                    .peer_certificates()
                    .unwrap_or_default()
                    .iter()
                    .map(|certificate| certificate.as_ref().to_vec())
                    .collect();
                #[cfg(target_os = "linux")]
                if self.kernel_tx || self.kernel_rx {
                    let socket = socket.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "kTLS requires a physical TCP stream",
                        )
                    })?;
                    return Ok(ClientTlsStream {
                        inner: ClientTlsStreamInner::Ktls(Box::new(
                            crate::common::ktls::KtlsStream::new_client(
                                connection,
                                socket,
                                self.kernel_tx,
                                self.kernel_rx,
                            )?,
                        )),
                        socket: Some(socket),
                        negotiated_alpn,
                        peer_certificates,
                    });
                }
                Ok(ClientTlsStream {
                    inner: ClientTlsStreamInner::Rustls(Box::new(connection)),
                    socket,
                    negotiated_alpn,
                    peer_certificates,
                })
            }
            ClientTlsBackend::OpenSsl(backend) => {
                let connection = complete_openssl_client_handshake(
                    backend,
                    connection,
                    handshake_timeout,
                )
                .await?;
                let negotiated_alpn =
                    connection.ssl().selected_alpn_protocol().map(Vec::from);
                let mut peer_certificates = Vec::new();
                if let Some(certificate) = connection.ssl().peer_certificate() {
                    peer_certificates
                        .push(certificate.to_der().map_err(io::Error::other)?);
                }
                if let Some(chain) = connection.ssl().peer_cert_chain() {
                    for certificate in chain {
                        let certificate =
                            certificate.to_der().map_err(io::Error::other)?;
                        if !peer_certificates.contains(&certificate) {
                            peer_certificates.push(certificate);
                        }
                    }
                }
                Ok(ClientTlsStream {
                    inner: ClientTlsStreamInner::OpenSsl(connection),
                    socket,
                    negotiated_alpn,
                    peer_certificates,
                })
            }
            #[cfg(target_vendor = "apple")]
            ClientTlsBackend::Apple(backend) => {
                let established =
                    backend.connect(connection, handshake_timeout).await?;
                Ok(ClientTlsStream {
                    inner: ClientTlsStreamInner::Apple(established.stream),
                    socket,
                    negotiated_alpn: established.negotiated_alpn,
                    peer_certificates: established.peer_certificates,
                })
            }
            #[cfg(windows)]
            ClientTlsBackend::Windows(backend) => {
                let established =
                    backend.connect(connection, handshake_timeout).await?;
                Ok(ClientTlsStream {
                    inner: ClientTlsStreamInner::Windows(Box::new(
                        established.stream,
                    )),
                    socket,
                    negotiated_alpn: established.negotiated_alpn,
                    peer_certificates: established.peer_certificates,
                })
            }
        }
    }
}

pub(crate) fn wrap_tls_fragment(
    stream: Stream,
    fragment: bool,
    record_fragment: bool,
    fallback_delay: Duration,
) -> Stream {
    if !fragment && !record_fragment {
        return stream;
    }
    let socket = crate::adapter::stream_socket(&stream);
    crate::adapter::preserve_stream_socket(
        Box::new(TlsFragmentStream::new(
            stream,
            fragment,
            record_fragment,
            if fallback_delay.is_zero() {
                TLS_FRAGMENT_FALLBACK_DELAY
            } else {
                fallback_delay
            },
        )),
        socket,
    )
}

fn ech_retry_config_from_error(error: &io::Error) -> Option<Vec<u8>> {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<rustls::Error>())
    {
        return error.ech_retry_config_list();
    }
    let mut source: &(dyn std::error::Error + 'static) = error;
    loop {
        if let Some(error) = source.downcast_ref::<rustls::Error>() {
            return error.ech_retry_config_list();
        }
        source = source.source()?;
    }
}

async fn complete_client_handshake(
    tls: &ClientTlsConfig,
    connection: Stream,
    config: Arc<ClientConfig>,
    handshake_timeout: Option<Duration>,
) -> io::Result<tokio_rustls::client::TlsStream<Stream>> {
    let handshake =
        TlsConnector::from(config).connect(tls.server_name.clone(), connection);
    if let Some(handshake_timeout) = handshake_timeout {
        timeout(handshake_timeout, handshake).await.map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
        })?
    } else {
        handshake.await
    }
}

async fn complete_openssl_client_handshake(
    backend: &OpenSslClientBackend,
    connection: Stream,
    handshake_timeout: Option<Duration>,
) -> io::Result<tokio_openssl::SslStream<Stream>> {
    let connector = backend.connector().map_err(io::Error::other)?;
    let mut configuration = connector.configure().map_err(io::Error::other)?;
    configuration.set_use_server_name_indication(!backend.options.disable_sni);
    configuration.set_verify_hostname(
        !backend.options.insecure
            && backend
                .options
                .certificate_public_key_sha256
                .as_slice()
                .is_empty()
            && backend.options.server_certificate_fingerprints.is_empty(),
    );
    let server_name = if backend.options.server_name.is_empty() {
        &backend.endpoint_host
    } else {
        &backend.options.server_name
    };
    let ssl = configuration
        .into_ssl(server_name)
        .map_err(io::Error::other)?;
    let mut stream = tokio_openssl::SslStream::new(ssl, connection)
        .map_err(io::Error::other)?;
    let handshake = Pin::new(&mut stream).connect();
    if let Some(handshake_timeout) = handshake_timeout {
        timeout(handshake_timeout, handshake)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                )
            })?
            .map_err(io::Error::other)?;
    } else {
        handshake.await.map_err(io::Error::other)?;
    }
    Ok(stream)
}

impl<D: Dialer> ClientTlsDialer<D> {
    async fn dial_tls_stream(
        &self,
        destination: &crate::common::network::SocksAddr,
    ) -> io::Result<ClientTlsStream> {
        if !matches!(self.tls.backend, ClientTlsBackend::Rustls) {
            let connection = self.upstream.dial_tcp(destination).await?;
            return self.tls.connect_stream(connection).await;
        }
        let mut config = self
            .tls
            .config_for_handshake()
            .await
            .map_err(io::Error::other)?;
        for attempt in 0..2 {
            let connection = self.upstream.dial_tcp(destination).await?;
            let socket = crate::adapter::stream_socket(&connection);
            let connection = self.tls.wrap_client_stream(connection)?;
            match complete_client_handshake(
                &self.tls,
                connection,
                config,
                self.tls.handshake_timeout,
            )
            .await
            {
                Ok(connection) => {
                    let negotiated_alpn = connection
                        .get_ref()
                        .1
                        .alpn_protocol()
                        .map(ToOwned::to_owned);
                    let peer_certificates = connection
                        .get_ref()
                        .1
                        .peer_certificates()
                        .unwrap_or_default()
                        .iter()
                        .map(|certificate| certificate.as_ref().to_vec())
                        .collect();
                    #[cfg(target_os = "linux")]
                    if self.tls.kernel_tx || self.tls.kernel_rx {
                        let socket = socket.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "kTLS requires a physical TCP stream",
                            )
                        })?;
                        return Ok(ClientTlsStream {
                            inner: ClientTlsStreamInner::Ktls(Box::new(
                                crate::common::ktls::KtlsStream::new_client(
                                    connection,
                                    socket,
                                    self.tls.kernel_tx,
                                    self.tls.kernel_rx,
                                )?,
                            )),
                            socket: Some(socket),
                            negotiated_alpn,
                            peer_certificates,
                        });
                    }
                    return Ok(ClientTlsStream {
                        inner: ClientTlsStreamInner::Rustls(Box::new(
                            connection,
                        )),
                        socket,
                        negotiated_alpn,
                        peer_certificates,
                    });
                }
                Err(error) if attempt == 0 => {
                    let Some(retry_list) = ech_retry_config_from_error(&error)
                    else {
                        return Err(error);
                    };
                    let Some(retry_config) = self
                        .tls
                        .config_for_ech_retry(&retry_list)
                        .await
                        .map_err(io::Error::other)?
                    else {
                        return Err(error);
                    };
                    config = retry_config;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("TLS retry loop always returns")
    }
}

impl<D: Dialer> Dialer for ClientTlsDialer<D> {
    fn dial_tcp<'a>(
        &'a self,
        destination: &'a crate::common::network::SocksAddr,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            Ok(self.dial_tls_stream(destination).await?.into_stream())
        })
    }

    fn dial_vision_tcp<'a>(
        &'a self,
        destination: &'a crate::common::network::SocksAddr,
    ) -> VisionDialFuture<'a> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            if self.tls.kernel_tx || self.tls.kernel_rx {
                return self
                    .dial_tls_stream(destination)
                    .await?
                    .into_ktls_vision();
            }
            if !matches!(self.tls.backend, ClientTlsBackend::Rustls) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "selected TLS backend is incompatible with Vision direct mode",
                ));
            }
            let mut config = self
                .tls
                .config_for_handshake()
                .await
                .map_err(io::Error::other)?;
            for attempt in 0..2 {
                let connection = self.upstream.dial_tcp(destination).await?;
                let socket = crate::adapter::stream_socket(&connection);
                let direct_switch = Arc::new(TlsVisionSwitch::default());
                let connection = self.tls.wrap_client_stream(connection)?;
                let connection: Stream = Box::new(TlsRecordStream::new(
                    connection,
                    direct_switch.clone(),
                ));
                match complete_client_handshake(
                    &self.tls,
                    connection,
                    config,
                    self.tls.handshake_timeout,
                )
                .await
                {
                    Ok(connection) => {
                        return Ok(VisionTransport {
                            stream: crate::adapter::preserve_stream_socket(
                                Box::new(SwitchableTlsStream::new(
                                    TlsStream::Client(connection),
                                    direct_switch.clone(),
                                )),
                                socket,
                            ),
                            direct_switch,
                        });
                    }
                    Err(error) if attempt == 0 => {
                        let Some(retry_list) =
                            ech_retry_config_from_error(&error)
                        else {
                            return Err(error);
                        };
                        let Some(retry_config) = self
                            .tls
                            .config_for_ech_retry(&retry_list)
                            .await
                            .map_err(io::Error::other)?
                        else {
                            return Err(error);
                        };
                        config = retry_config;
                    }
                    Err(error) => return Err(error),
                }
            }
            unreachable!("TLS retry loop always returns")
        })
    }
}

pub fn build_client_config(
    endpoint_host: &str,
    options: &OutboundTlsOptions,
    default_alpn: &[&str],
) -> Result<ClientTlsConfig, TlsError> {
    build_client_config_inner(
        endpoint_host,
        options,
        default_alpn,
        None,
        options.ntp_clock.clone(),
    )
}

/// Build an outbound TLS configuration using an NTP-corrected wall clock for
/// certificate validity and TLS ticket age checks.
///
/// An unsynchronized [`NtpClock`] has a zero offset and therefore behaves like
/// the ordinary system clock until the first successful NTP sample arrives.
pub fn build_client_config_with_clock(
    endpoint_host: &str,
    options: &OutboundTlsOptions,
    default_alpn: &[&str],
    clock: Option<NtpClock>,
) -> Result<ClientTlsConfig, TlsError> {
    build_client_config_inner(
        endpoint_host,
        options,
        default_alpn,
        None,
        clock.or_else(|| options.ntp_clock.clone()),
    )
}

/// Build an outbound TLS configuration with a resolver for DNS HTTPS ECH
/// discovery.
///
/// The resolver is only consulted when ECH is enabled without an explicit
/// `config` or `config_path`. This entry point is useful to embedding
/// applications that construct TLS dialers outside [`crate::Runtime`].
pub fn build_client_config_with_ech_resolver(
    endpoint_host: &str,
    options: &OutboundTlsOptions,
    default_alpn: &[&str],
    resolver: Arc<dyn EchConfigResolver>,
) -> Result<ClientTlsConfig, TlsError> {
    build_client_config_inner(
        endpoint_host,
        options,
        default_alpn,
        Some(resolver),
        options.ntp_clock.clone(),
    )
}

/// Build a clock-aware outbound TLS configuration with dynamic ECH support.
pub fn build_client_config_with_ech_resolver_and_clock(
    endpoint_host: &str,
    options: &OutboundTlsOptions,
    default_alpn: &[&str],
    resolver: Arc<dyn EchConfigResolver>,
    clock: Option<NtpClock>,
) -> Result<ClientTlsConfig, TlsError> {
    build_client_config_inner(
        endpoint_host,
        options,
        default_alpn,
        Some(resolver),
        clock.or_else(|| options.ntp_clock.clone()),
    )
}

pub(crate) fn build_client_config_with_runtime_context(
    endpoint_host: &str,
    options: &OutboundTlsOptions,
    default_alpn: &[&str],
    resolver: Arc<dyn EchConfigResolver>,
    clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> Result<ClientTlsConfig, TlsError> {
    let mut options = options.clone();
    options.set_runtime_context(clock.clone(), certificate_store);
    build_client_config_inner(
        endpoint_host,
        &options,
        default_alpn,
        Some(resolver),
        clock,
    )
}

impl OpenSslClientBackend {
    fn connector(&self) -> Result<SslConnector, TlsError> {
        let (minimum, maximum) = tls_version_bounds(
            &self.options.min_version,
            &self.options.max_version,
        )?;
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|error| {
                TlsError::Unsupported(format!(
                    "initialize OpenSSL TLS backend: {error}"
                ))
            })?;
        builder
            .set_min_proto_version(Some(openssl_tls_version(minimum)))
            .map_err(|error| {
                TlsError::Unsupported(format!(
                    "set minimum OpenSSL TLS version: {error}"
                ))
            })?;
        builder
            .set_max_proto_version(Some(openssl_tls_version(maximum)))
            .map_err(|error| {
                TlsError::Unsupported(format!(
                    "set maximum OpenSSL TLS version: {error}"
                ))
            })?;
        if minimum < 2 {
            // OpenSSL 3's default security policy rejects the SHA-1 signatures
            // required by many TLS 1.0/1.1 peers. Go's legacy-version support
            // accepts those signatures, so lower the policy only for this
            // explicitly requested compatibility backend.
            builder.set_security_level(0);
            builder
                .set_cipher_list(OPENSSL_GO_COMPATIBLE_CIPHER_LIST)
                .map_err(|error| {
                    TlsError::Unsupported(format!(
                        "configure legacy TLS cipher suites: {error}"
                    ))
                })?;
        }
        configure_openssl_cipher_suites(
            &mut builder,
            self.options.cipher_suites.as_slice(),
        )?;
        configure_openssl_curves(
            &mut builder,
            self.options.curve_preferences.as_slice(),
        )?;
        let alpn: Vec<&str> = if self.options.alpn.as_slice().is_empty() {
            self.default_alpn.iter().map(String::as_str).collect()
        } else {
            self.options
                .alpn
                .as_slice()
                .iter()
                .map(String::as_str)
                .collect()
        };
        let alpn = encode_openssl_alpn(&alpn)?;
        if !alpn.is_empty() {
            builder.set_alpn_protos(&alpn).map_err(|error| {
                TlsError::Unsupported(format!(
                    "configure OpenSSL ALPN: {error}"
                ))
            })?;
        }
        configure_openssl_trust(&mut builder, &self.options)?;
        configure_openssl_client_certificate(&mut builder, &self.options)?;
        if let Some(clock) = &self.clock {
            let seconds = clock
                .now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| {
                    TlsError::Unsupported(format!(
                        "NTP TLS verification time precedes Unix epoch: {error}"
                    ))
                })?
                .as_secs();
            let seconds = seconds.try_into().map_err(|_| {
                TlsError::Unsupported(
                    "NTP TLS verification time exceeds OpenSSL range".into(),
                )
            })?;
            builder.verify_param_mut().set_time(seconds);
        }
        configure_openssl_verifier(&mut builder, &self.options);
        Ok(builder.build())
    }
}

const OPENSSL_GO_COMPATIBLE_CIPHER_LIST: &str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:",
    "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:",
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
);

fn openssl_tls_version(version: u8) -> SslVersion {
    match version {
        0 => SslVersion::TLS1,
        1 => SslVersion::TLS1_1,
        2 => SslVersion::TLS1_2,
        3 => SslVersion::TLS1_3,
        _ => unreachable!("validated TLS version"),
    }
}

fn encode_openssl_alpn(protocols: &[&str]) -> Result<Vec<u8>, TlsError> {
    let mut encoded = Vec::new();
    for protocol in protocols {
        let length = u8::try_from(protocol.len()).map_err(|_| {
            TlsError::Unsupported(format!(
                "ALPN protocol is longer than 255 bytes: {protocol:?}"
            ))
        })?;
        if length == 0 {
            return Err(TlsError::Unsupported(
                "ALPN protocol must not be empty".into(),
            ));
        }
        encoded.push(length);
        encoded.extend_from_slice(protocol.as_bytes());
    }
    Ok(encoded)
}

fn configure_openssl_cipher_suites(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    suites: &[String],
) -> Result<(), TlsError> {
    if suites.is_empty() {
        return Ok(());
    }
    let mut legacy = Vec::new();
    let mut tls13 = Vec::new();
    for suite in suites {
        let (name, is_tls13) = match suite.as_str() {
            "TLS_AES_128_GCM_SHA256" => (suite.as_str(), true),
            "TLS_AES_256_GCM_SHA384" => (suite.as_str(), true),
            "TLS_CHACHA20_POLY1305_SHA256" => (suite.as_str(), true),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                ("ECDHE-ECDSA-AES128-GCM-SHA256", false)
            }
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                ("ECDHE-RSA-AES128-GCM-SHA256", false)
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                ("ECDHE-ECDSA-AES256-GCM-SHA384", false)
            }
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                ("ECDHE-RSA-AES256-GCM-SHA384", false)
            }
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                ("ECDHE-ECDSA-CHACHA20-POLY1305", false)
            }
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                ("ECDHE-RSA-CHACHA20-POLY1305", false)
            }
            _ => {
                return Err(TlsError::Unsupported(format!(
                    "unknown cipher suite {suite:?}"
                )));
            }
        };
        if is_tls13 {
            tls13.push(name);
        } else {
            legacy.push(name);
        }
    }
    if !legacy.is_empty() {
        builder
            .set_cipher_list(&legacy.join(":"))
            .map_err(|error| {
                TlsError::Unsupported(format!(
                    "configure OpenSSL cipher suites: {error}"
                ))
            })?;
    }
    if !tls13.is_empty() {
        builder
            .set_ciphersuites(&tls13.join(":"))
            .map_err(|error| {
                TlsError::Unsupported(format!(
                    "configure OpenSSL TLS 1.3 cipher suites: {error}"
                ))
            })?;
    }
    Ok(())
}

fn configure_openssl_curves(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    curves: &[CurvePreference],
) -> Result<(), TlsError> {
    if curves.is_empty() {
        return Ok(());
    }
    let groups = curves
        .iter()
        .map(|curve| match curve {
            CurvePreference::P256 => "P-256",
            CurvePreference::P384 => "P-384",
            CurvePreference::P521 => "P-521",
            CurvePreference::X25519 => "X25519",
            CurvePreference::X25519MlKem768 => "X25519MLKEM768",
        })
        .collect::<Vec<_>>()
        .join(":");
    builder.set_groups_list(&groups).map_err(|error| {
        TlsError::Unsupported(format!("configure OpenSSL TLS groups: {error}"))
    })
}

fn parse_openssl_certificates(
    bytes: &[u8],
    source: &str,
) -> Result<Vec<X509>, TlsError> {
    let certificates = X509::stack_from_pem(bytes).map_err(|error| {
        TlsError::Certificate(format!(
            "parse OpenSSL certificates from {source}: {error}"
        ))
    })?;
    if certificates.is_empty() {
        return Err(TlsError::Certificate(format!(
            "no certificates found in {source}"
        )));
    }
    Ok(certificates)
}

fn configure_openssl_trust(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    options: &OutboundTlsOptions,
) -> Result<(), TlsError> {
    let has_per_tls_roots = !options.certificate.as_slice().is_empty()
        || !options.certificate_path.is_empty();
    let mut certificates = Vec::new();
    if !options.system_trust_disabled && !has_per_tls_roots {
        if let Some(store) = &options.certificate_store {
            certificates.extend(
                store
                    .apple_anchors()
                    .map_err(|error| TlsError::Certificate(error.to_string()))?
                    .iter()
                    .map(|certificate| {
                        X509::from_der(certificate.as_ref()).map_err(|error| {
                            TlsError::Certificate(format!(
                                "parse runtime trust anchor: {error}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        } else {
            certificates.extend(parse_openssl_certificates(
                crate::common::certificate_store::MOZILLA_ROOTS,
                "included Mozilla roots",
            )?);
        }
    }
    for (index, certificate) in
        options.certificate.as_slice().iter().enumerate()
    {
        certificates.extend(parse_openssl_certificates(
            certificate.as_bytes(),
            &format!("certificate[{index}]"),
        )?);
    }
    if !options.certificate_path.is_empty() {
        let bytes = fs::read(&options.certificate_path).map_err(|source| {
            TlsError::ReadCertificate {
                path: options.certificate_path.clone(),
                source,
            }
        })?;
        certificates.extend(parse_openssl_certificates(
            &bytes,
            &options.certificate_path,
        )?);
    }
    let mut seen = HashSet::new();
    let mut store = X509StoreBuilder::new().map_err(|error| {
        TlsError::Certificate(format!(
            "initialize OpenSSL trust store: {error}"
        ))
    })?;
    for certificate in certificates {
        let der = certificate.to_der().map_err(|error| {
            TlsError::Certificate(format!(
                "encode OpenSSL trust anchor: {error}"
            ))
        })?;
        if seen.insert(der) {
            store.add_cert(certificate).map_err(|error| {
                TlsError::Certificate(format!(
                    "add OpenSSL trust anchor: {error}"
                ))
            })?;
        }
    }
    builder.set_cert_store(store.build());
    Ok(())
}

fn configure_openssl_client_certificate(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    options: &OutboundTlsOptions,
) -> Result<(), TlsError> {
    let has_certificate = !options.client_certificate.as_slice().is_empty()
        || !options.client_certificate_path.is_empty();
    let has_key = !options.client_key.as_slice().is_empty()
        || !options.client_key_path.is_empty();
    if has_certificate != has_key {
        return Err(TlsError::Certificate(
            "client certificate and client key must be provided together"
                .into(),
        ));
    }
    if !has_certificate {
        return Ok(());
    }
    let mut certificate_bytes = Vec::new();
    for certificate in options.client_certificate.as_slice() {
        certificate_bytes.extend_from_slice(certificate.as_bytes());
        certificate_bytes.push(b'\n');
    }
    if !options.client_certificate_path.is_empty() {
        certificate_bytes.extend(
            fs::read(&options.client_certificate_path).map_err(|source| {
                TlsError::ReadCertificate {
                    path: options.client_certificate_path.clone(),
                    source,
                }
            })?,
        );
    }
    let mut certificates =
        parse_openssl_certificates(&certificate_bytes, "client certificate")?;
    let leaf = certificates.remove(0);
    builder.set_certificate(&leaf).map_err(|error| {
        TlsError::Certificate(format!(
            "configure OpenSSL client certificate: {error}"
        ))
    })?;
    for certificate in certificates {
        builder.add_extra_chain_cert(certificate).map_err(|error| {
            TlsError::Certificate(format!(
                "configure OpenSSL client certificate chain: {error}"
            ))
        })?;
    }
    let mut key_bytes = Vec::new();
    for key in options.client_key.as_slice() {
        key_bytes.extend_from_slice(key.as_bytes());
        key_bytes.push(b'\n');
    }
    if !options.client_key_path.is_empty() {
        key_bytes = fs::read(&options.client_key_path).map_err(|source| {
            TlsError::ReadPrivateKey {
                path: options.client_key_path.clone(),
                source,
            }
        })?;
    }
    let key = PKey::private_key_from_pem(&key_bytes)
        .map_err(|error| TlsError::PrivateKey(error.to_string()))?;
    builder
        .set_private_key(&key)
        .and_then(|()| builder.check_private_key())
        .map_err(|error| TlsError::PrivateKey(error.to_string()))
}

fn configure_openssl_verifier(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    options: &OutboundTlsOptions,
) {
    if !options.server_certificate_fingerprints.is_empty() {
        let fingerprints = options.server_certificate_fingerprints.clone();
        builder.set_verify_callback(
            SslVerifyMode::PEER,
            move |_preverified, context| {
                if context.error_depth() != 0 {
                    return true;
                }
                context.current_cert().is_some_and(|certificate| {
                    let Ok(certificate_der) = certificate.to_der() else {
                        return false;
                    };
                    let Ok(public_key_der) = certificate
                        .public_key()
                        .and_then(|key| key.public_key_to_der())
                    else {
                        return false;
                    };
                    certificate_fingerprints_match(
                        &fingerprints,
                        &certificate_der,
                        &public_key_der,
                    )
                })
            },
        );
    } else if !options.certificate_public_key_sha256.as_slice().is_empty() {
        let pins = options
            .certificate_public_key_sha256
            .as_slice()
            .iter()
            .map(|pin| pin.0.clone())
            .collect::<Vec<_>>();
        builder.set_verify_callback(
            SslVerifyMode::PEER,
            move |_preverified, context| {
                if context.error_depth() != 0 {
                    return true;
                }
                context.current_cert().is_some_and(|certificate| {
                    let Ok(public_key_der) = certificate
                        .public_key()
                        .and_then(|key| key.public_key_to_der())
                    else {
                        return false;
                    };
                    let digest = Sha256::digest(public_key_der);
                    pins.iter().any(|pin| {
                        constant_time_prefix_equal(pin, digest.as_slice())
                            && pin.len() == digest.len()
                    })
                })
            },
        );
    } else if options.insecure {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_verify(SslVerifyMode::PEER);
    }
}

fn build_client_config_inner(
    endpoint_host: &str,
    options: &OutboundTlsOptions,
    default_alpn: &[&str],
    ech_resolver: Option<Arc<dyn EchConfigResolver>>,
    clock: Option<NtpClock>,
) -> Result<ClientTlsConfig, TlsError> {
    validate_supported(options)?;
    let (minimum_version, _maximum_version) =
        tls_version_bounds(&options.min_version, &options.max_version)?;
    let use_apple = options.engine == "apple";
    let use_windows = options.engine == "windows";
    let use_openssl = !use_apple && !use_windows && minimum_version < 2;
    let spoof_method = crate::common::tls_spoof::parse_options(
        &options.spoof,
        &options.spoof_method,
    )
    .map_err(|error| TlsError::Unsupported(error.to_string()))?
    .unwrap_or_default();
    let effective_server_name = if options.server_name.is_empty() {
        endpoint_host
    } else {
        &options.server_name
    };
    if !options.spoof.is_empty() {
        if options.disable_sni
            || effective_server_name.parse::<std::net::IpAddr>().is_ok()
        {
            return Err(TlsError::Unsupported(
                "`spoof` requires TLS ClientHello with SNI".into(),
            ));
        }
        if options.spoof.eq_ignore_ascii_case(effective_server_name) {
            return Err(TlsError::Unsupported(
                "`spoof` must differ from `server_name`".into(),
            ));
        }
    }
    let utls = if options.chrome_quic_parrot {
        Some((SingBoxUtlsCustomizer::chrome_quic(), true))
    } else {
        options
            .utls
            .as_ref()
            .filter(|options| options.enabled)
            .map(|options| {
                SingBoxUtlsCustomizer::resolve(&options.fingerprint)
                    .map_err(|error| TlsError::Unsupported(error.to_string()))
            })
            .transpose()?
    };
    let reality = options.reality.as_ref().filter(|options| options.enabled);
    if use_openssl
        && (utls.is_some()
            || reality.is_some()
            || options.ech.as_ref().is_some_and(|ech| ech.enabled)
            || options.chrome_quic_parrot)
    {
        return Err(TlsError::Unsupported(
            "TLS 1.0/1.1 cannot be combined with uTLS, REALITY, ECH, or QUIC ClientHello parrot"
                .into(),
        ));
    }
    if reality.is_some() && utls.is_none() {
        return Err(TlsError::Unsupported(
            "REALITY requires utls.enabled=true".into(),
        ));
    }
    if reality.is_some() && utls.as_ref().is_some_and(|(_, tls13)| !tls13) {
        return Err(TlsError::Unsupported(
            "REALITY requires a TLS 1.3 uTLS fingerprint".into(),
        ));
    }
    if !options.certificate_public_key_sha256.as_slice().is_empty()
        && (!options.certificate.as_slice().is_empty()
            || !options.certificate_path.is_empty())
    {
        return Err(TlsError::Certificate(
            "certificate_public_key_sha256 conflicts with certificate or certificate_path"
                .into(),
        ));
    }
    if !options.server_certificate_fingerprints.is_empty()
        && (!options.certificate.as_slice().is_empty()
            || !options.certificate_path.is_empty()
            || !options.certificate_public_key_sha256.as_slice().is_empty())
    {
        return Err(TlsError::Certificate(
            "server_certificate_fingerprints conflicts with certificate, certificate_path, or certificate_public_key_sha256"
                .into(),
        ));
    }
    let roots = outbound_tls_root_store(options)?;
    let dynamic_certificate_store =
        options.certificate_store.clone().filter(|_| {
            !options.system_trust_disabled
                && options.certificate.as_slice().is_empty()
                && options.certificate_path.is_empty()
        });

    let provider = if use_openssl || use_apple || use_windows {
        // A rustls configuration remains available for QUIC-only consumers,
        // but stream handshakes use the OpenSSL backend below.
        crypto_provider(&[], &[])?
    } else {
        crypto_provider(
            options.cipher_suites.as_slice(),
            options.curve_preferences.as_slice(),
        )?
    };
    let server_verify_provider = provider.clone();
    let versions = if use_openssl || use_apple || use_windows {
        vec![&rustls::version::TLS12]
    } else if utls.as_ref().is_some_and(|(_, tls13)| !tls13) {
        let configured =
            protocol_versions(&options.min_version, &options.max_version)?;
        if !configured.contains(&&rustls::version::TLS12) {
            return Err(TlsError::Unsupported(
                "selected uTLS fingerprint only supports TLS 1.2".into(),
            ));
        }
        vec![&rustls::version::TLS12]
    } else {
        protocol_versions(&options.min_version, &options.max_version)?
    };
    if let Some((customizer, _)) = &utls
        && !customizer.is_negotiable(&provider, &versions)
    {
        return Err(TlsError::Unsupported(
            "selected uTLS fingerprint has no cipher suite supported by rustls"
                .into(),
        ));
    }
    let builder = if let Some(clock) = clock.clone() {
        ClientConfig::builder_with_details(
            provider,
            Arc::new(NtpTimeProvider(clock)),
        )
    } else {
        ClientConfig::builder_with_provider(provider)
    };
    let ech_enabled = options.ech.as_ref().is_some_and(|ech| ech.enabled);
    let dynamic_ech = options.ech.as_ref().is_some_and(|ech| {
        ech.enabled
            && ech.config.as_slice().is_empty()
            && ech.config_path.is_empty()
    });
    if dynamic_ech && ech_resolver.is_none() {
        return Err(TlsError::Unsupported(
            "dynamic ECH config discovery requires a DNS HTTPS resolver".into(),
        ));
    }
    let builder = if let Some(ech) = enabled_ech(options, dynamic_ech)? {
        builder
            .with_ech(EchMode::Enable(ech))
            .map_err(|error| TlsError::Unsupported(error.to_string()))?
    } else {
        builder
            .with_protocol_versions(&versions)
            .map_err(|error| TlsError::Unsupported(error.to_string()))?
    }
    .with_root_certificates(roots);
    let has_client_certificate =
        !options.client_certificate.as_slice().is_empty()
            || !options.client_certificate_path.is_empty();
    let has_client_key = !options.client_key.as_slice().is_empty()
        || !options.client_key_path.is_empty();
    if has_client_certificate != has_client_key {
        return Err(TlsError::Certificate(
            "client certificate and client key must be provided together"
                .into(),
        ));
    }
    let mut config = if has_client_certificate {
        let mut certificates = Vec::new();
        for certificate in options.client_certificate.as_slice() {
            certificates
                .extend(parse_pem_certificates(certificate.as_bytes())?);
        }
        if !options.client_certificate_path.is_empty() {
            let bytes = fs::read(&options.client_certificate_path).map_err(
                |source| TlsError::ReadCertificate {
                    path: options.client_certificate_path.clone(),
                    source,
                },
            )?;
            certificates.extend(parse_pem_certificates(&bytes)?);
        }
        let mut key_bytes = Vec::new();
        for key in options.client_key.as_slice() {
            key_bytes.extend_from_slice(key.as_bytes());
            key_bytes.push(b'\n');
        }
        if !options.client_key_path.is_empty() {
            key_bytes =
                fs::read(&options.client_key_path).map_err(|source| {
                    TlsError::ReadPrivateKey {
                        path: options.client_key_path.clone(),
                        source,
                    }
                })?;
        }
        let mut key_reader = BufReader::new(key_bytes.as_slice());
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|error| TlsError::PrivateKey(error.to_string()))?
            .ok_or_else(|| {
                TlsError::PrivateKey("no client private key configured".into())
            })?;
        builder
            .with_client_auth_cert(certificates, key)
            .map_err(|error| TlsError::Certificate(error.to_string()))?
    } else {
        builder.with_no_client_auth()
    };
    if !options.server_certificate_fingerprints.is_empty() {
        config.dangerous().set_certificate_verifier(Arc::new(
            CertificateFingerprintServerVerifier {
                fingerprints: options.server_certificate_fingerprints.clone(),
                provider: server_verify_provider.clone(),
            },
        ));
    } else if !options.certificate_public_key_sha256.as_slice().is_empty() {
        config.dangerous().set_certificate_verifier(Arc::new(
            PublicKeyPinServerVerifier {
                public_key_sha256: options
                    .certificate_public_key_sha256
                    .as_slice()
                    .iter()
                    .map(|value| value.0.clone())
                    .collect(),
                provider: server_verify_provider.clone(),
            },
        ));
    } else if options.insecure {
        config.dangerous().set_certificate_verifier(
            SkipServerVerification::new(server_verify_provider.clone()),
        );
    } else if let Some(store) = dynamic_certificate_store {
        config.dangerous().set_certificate_verifier(Arc::new(
            DynamicCertificateStoreVerifier {
                store,
                provider: server_verify_provider.clone(),
            },
        ));
    }
    config.enable_sni = !options.disable_sni;
    let alpn = if options.alpn.as_slice().is_empty() {
        default_alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    } else {
        options
            .alpn
            .as_slice()
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    };
    config.alpn_protocols = alpn;
    if let Some((customizer, _)) = utls {
        customizer.configure(&mut config);
        if let Some(reality) = reality {
            install_reality_client(
                &mut config,
                customizer,
                &reality.public_key,
                &reality.short_id,
                server_verify_provider,
            )
            .map_err(TlsError::Unsupported)?;
        } else {
            config.client_hello_customizer = Some(customizer);
        }
    }
    config.enable_secret_extraction = options.kernel_tx || options.kernel_rx;

    let server_name = if options.server_name.is_empty() {
        endpoint_host
    } else {
        &options.server_name
    };
    let server_name =
        ServerName::try_from(server_name.to_owned()).map_err(|error| {
            TlsError::ServerName {
                name: server_name.to_owned(),
                message: error.to_string(),
            }
        })?;
    Ok(ClientTlsConfig {
        config: Arc::new(config),
        server_name,
        handshake_timeout: options
            .handshake_timeout
            .as_std()
            .filter(|timeout| !timeout.is_zero())
            .or(Some(TLS_HANDSHAKE_TIMEOUT)),
        fragment: options.fragment,
        record_fragment: options.record_fragment,
        fragment_fallback_delay: options
            .fragment_fallback_delay
            .as_std()
            .filter(|delay| !delay.is_zero())
            .unwrap_or(TLS_FRAGMENT_FALLBACK_DELAY),
        spoof: options.spoof.clone(),
        spoof_method,
        dynamic_ech: dynamic_ech.then(|| {
            let server_name = if options.server_name.is_empty() {
                endpoint_host
            } else {
                &options.server_name
            };
            let query_server_name = options
                .ech
                .as_ref()
                .map(|ech| ech.query_server_name.as_str())
                .filter(|name| !name.is_empty())
                .unwrap_or(server_name)
                .to_owned();
            Arc::new(DynamicEchConfig {
                endpoint_host: endpoint_host.to_owned(),
                query_server_name,
                default_alpn: default_alpn
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                options: options.clone(),
                resolver: ech_resolver
                    .expect("dynamic ECH resolver was checked above"),
                clock: clock.clone(),
                cache: tokio::sync::Mutex::new(None),
            })
        }),
        ech_retry: ech_enabled.then(|| {
            Arc::new(EchRetryConfig {
                endpoint_host: endpoint_host.to_owned(),
                default_alpn: default_alpn
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                options: options.clone(),
                clock: clock.clone(),
                cache: tokio::sync::Mutex::new(None),
            })
        }),
        backend: if use_openssl {
            let backend = OpenSslClientBackend {
                endpoint_host: endpoint_host.to_owned(),
                default_alpn: default_alpn
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                options: options.clone(),
                clock,
            };
            // Fail at configuration time rather than deferring malformed
            // certificates, cipher names, or version bounds to first use.
            backend.connector()?;
            ClientTlsBackend::OpenSsl(Arc::new(backend))
        } else if use_apple {
            #[cfg(target_vendor = "apple")]
            {
                ClientTlsBackend::Apple(Arc::new(
                    crate::common::apple_tls::AppleTlsBackend::new(
                        endpoint_host,
                        default_alpn,
                        options.clone(),
                        clock,
                    ),
                ))
            }
            #[cfg(not(target_vendor = "apple"))]
            unreachable!("Apple TLS was rejected on this target")
        } else if use_windows {
            #[cfg(windows)]
            {
                ClientTlsBackend::Windows(Arc::new(
                    crate::common::windows_tls::WindowsTlsBackend::new(
                        endpoint_host,
                        default_alpn,
                        options.clone(),
                        clock,
                    ),
                ))
            }
            #[cfg(not(windows))]
            unreachable!("Windows TLS was rejected on this target")
        } else {
            ClientTlsBackend::Rustls
        },
        kernel_tx: options.kernel_tx,
        kernel_rx: options.kernel_rx,
    })
}

fn tls_version_bounds(
    minimum: &str,
    maximum: &str,
) -> Result<(u8, u8), TlsError> {
    fn parse(value: &str, bound: &str) -> Result<Option<u8>, TlsError> {
        match value {
            "" => Ok(None),
            "1.0" => Ok(Some(0)),
            "1.1" => Ok(Some(1)),
            "1.2" => Ok(Some(2)),
            "1.3" => Ok(Some(3)),
            value => Err(TlsError::Unsupported(format!(
                "invalid {bound} TLS version {value:?}"
            ))),
        }
    }
    let minimum = parse(minimum, "minimum")?.unwrap_or(2);
    let maximum = parse(maximum, "maximum")?.unwrap_or(3);
    if minimum > maximum {
        return Err(TlsError::Unsupported(
            "minimum TLS version exceeds maximum TLS version".into(),
        ));
    }
    Ok((minimum, maximum))
}

fn protocol_versions(
    minimum: &str,
    maximum: &str,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, TlsError> {
    let (minimum, maximum) = tls_version_bounds(minimum, maximum)?;
    if minimum < 2 {
        return Err(TlsError::Unsupported(
            "TLS 1.0/1.1 requires the OpenSSL stream backend".into(),
        ));
    }
    let mut versions = Vec::with_capacity(2);
    if maximum >= 3 && minimum <= 3 {
        versions.push(&rustls::version::TLS13);
    }
    if maximum >= 2 && minimum <= 2 {
        versions.push(&rustls::version::TLS12);
    }
    Ok(versions)
}

fn enabled_ech(
    options: &OutboundTlsOptions,
    allow_dynamic: bool,
) -> Result<Option<EchConfig>, TlsError> {
    let Some(options) = options.ech.as_ref().filter(|options| options.enabled)
    else {
        return Ok(None);
    };
    if options.pq_signature_schemes_enabled
        || options.dynamic_record_sizing_disabled
    {
        return Err(TlsError::Unsupported(
            "legacy ECH options were removed in sing-box 1.13".into(),
        ));
    }
    let contents = if !options.config.as_slice().is_empty() {
        options.config.as_slice().join("\n").into_bytes()
    } else if !options.config_path.is_empty() {
        fs::read(&options.config_path).map_err(|source| {
            TlsError::ReadEchConfig {
                path: options.config_path.clone(),
                source,
            }
        })?
    } else {
        if allow_dynamic {
            return Ok(None);
        }
        return Err(TlsError::Unsupported(
            "dynamic ECH config discovery requires a DNS HTTPS resolver".into(),
        ));
    };
    let block = pem::parse(contents).map_err(|error| {
        TlsError::Unsupported(format!("invalid ECH configs PEM: {error}"))
    })?;
    if block.tag() != "ECH CONFIGS" {
        return Err(TlsError::Unsupported(
            "invalid ECH configs PEM block type".into(),
        ));
    }
    let config = EchConfig::new(
        EchConfigListBytes::from(block.into_contents()),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .map_err(|error| {
        TlsError::Unsupported(format!("invalid ECH config list: {error}"))
    })?;
    Ok(Some(config))
}

#[derive(Debug)]
struct AwsLcP521;

static AWS_LC_P521: AwsLcP521 = AwsLcP521;

impl SupportedKxGroup for AwsLcP521 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let private = aws_lc_rs::agreement::EphemeralPrivateKey::generate(
            &aws_lc_rs::agreement::ECDH_P521,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let public = private
            .compute_public_key()
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        Ok(Box::new(AwsLcP521Exchange { private, public }))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }

    fn fips(&self) -> bool {
        false
    }
}

struct AwsLcP521Exchange {
    private: aws_lc_rs::agreement::EphemeralPrivateKey,
    public: aws_lc_rs::agreement::PublicKey,
}

impl ActiveKeyExchange for AwsLcP521Exchange {
    fn complete(
        self: Box<Self>,
        peer_public_key: &[u8],
    ) -> Result<SharedSecret, rustls::Error> {
        if peer_public_key.len() != 133
            || peer_public_key.first() != Some(&0x04)
        {
            return Err(rustls::Error::General(
                "invalid P521 TLS key share".into(),
            ));
        }
        let peer = aws_lc_rs::agreement::UnparsedPublicKey::new(
            &aws_lc_rs::agreement::ECDH_P521,
            peer_public_key,
        );
        aws_lc_rs::agreement::agree_ephemeral(
            self.private,
            peer,
            rustls::Error::General("invalid P521 TLS key share".into()),
            |secret| Ok::<_, rustls::Error>(SharedSecret::from(secret)),
        )
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_ref()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
}

fn crypto_provider(
    cipher_suites: &[String],
    curve_preferences: &[CurvePreference],
) -> Result<Arc<CryptoProvider>, TlsError> {
    // Go 1.25 includes X25519MLKEM768 first in its default curve list. The
    // AWS-LC rustls provider exposes the same hybrid group; ring does not.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups.push(&AWS_LC_P521);
    if !cipher_suites.is_empty() {
        let tls13: Vec<_> = provider
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| suite.tls13().is_some())
            .collect();
        let mut selected = tls13;
        for name in cipher_suites {
            let identifier =
                cipher_suite_identifier(name).ok_or_else(|| {
                    TlsError::Unsupported(format!(
                        "unknown cipher_suite: {name}"
                    ))
                })?;
            let suite = provider
                .cipher_suites
                .iter()
                .copied()
                .find(|suite| suite.suite() == identifier)
                .ok_or_else(|| {
                    TlsError::Unsupported(format!(
                        "cipher_suite is unavailable: {name}"
                    ))
                })?;
            selected.push(suite);
        }
        provider.cipher_suites = selected;
    }
    if !curve_preferences.is_empty() {
        let mut selected = Vec::with_capacity(curve_preferences.len());
        for preference in curve_preferences {
            let named_group = match preference {
                CurvePreference::P256 => NamedGroup::secp256r1,
                CurvePreference::P384 => NamedGroup::secp384r1,
                CurvePreference::P521 => NamedGroup::secp521r1,
                CurvePreference::X25519 => NamedGroup::X25519,
                CurvePreference::X25519MlKem768 => NamedGroup::X25519MLKEM768,
            };
            let group = provider
                .kx_groups
                .iter()
                .copied()
                .find(|group| group.name() == named_group)
                .ok_or_else(|| {
                    TlsError::Unsupported(format!(
                        "curve preference {preference:?} is unavailable"
                    ))
                })?;
            selected.push(group);
        }
        provider.kx_groups = selected;
    }
    Ok(Arc::new(provider))
}

fn cipher_suite_identifier(name: &str) -> Option<CipherSuite> {
    Some(match name {
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        }
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        }
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        }
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        }
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
        _ => return None,
    })
}

fn validate_supported(options: &OutboundTlsOptions) -> Result<(), TlsError> {
    if options.engine == "apple" {
        #[cfg(target_vendor = "apple")]
        {
            if !options.server_certificate_fingerprints.is_empty() {
                return Err(TlsError::Unsupported(
                    "server certificate fingerprints are unsupported in Apple TLS engine"
                        .into(),
                ));
            }
            return validate_system_tls_options(options, "Apple TLS engine");
        }
        #[cfg(not(target_vendor = "apple"))]
        return Err(TlsError::Unsupported(
            "Apple TLS engine is available only on Apple platforms".into(),
        ));
    }
    if options.engine == "windows" {
        #[cfg(windows)]
        return validate_system_tls_options(options, "Windows TLS engine");
        #[cfg(not(windows))]
        return Err(TlsError::Unsupported(
            "Windows TLS engine is available only on Windows".into(),
        ));
    }
    if !matches!(options.engine.as_str(), "" | "go" | "std" | "rustls") {
        return Err(TlsError::Unsupported(format!(
            "engine {:?}",
            options.engine
        )));
    }
    if options.kernel_tx || options.kernel_rx {
        #[cfg(not(target_os = "linux"))]
        return Err(TlsError::Unsupported(
            "kTLS is available only on Linux".into(),
        ));
        #[cfg(target_os = "linux")]
        crate::common::ktls::load()
            .map_err(|error| TlsError::Unsupported(error.to_string()))?;
    }
    Ok(())
}

#[cfg(any(target_vendor = "apple", windows))]
fn validate_system_tls_options(
    options: &OutboundTlsOptions,
    engine_name: &str,
) -> Result<(), TlsError> {
    let unsupported = [
        (
            options.reality.as_ref().is_some_and(|value| value.enabled),
            "reality",
        ),
        (
            options.utls.as_ref().is_some_and(|value| value.enabled),
            "utls",
        ),
        (
            options.ech.as_ref().is_some_and(|value| value.enabled),
            "ech",
        ),
        (options.disable_sni, "disable_sni"),
        (
            !options.cipher_suites.as_slice().is_empty(),
            "cipher_suites",
        ),
        (
            !options.curve_preferences.as_slice().is_empty(),
            "curve_preferences",
        ),
        (
            !options.client_certificate.as_slice().is_empty()
                || !options.client_certificate_path.is_empty()
                || !options.client_key.as_slice().is_empty()
                || !options.client_key_path.is_empty(),
            "client certificate",
        ),
        (options.fragment || options.record_fragment, "tls fragment"),
        (options.kernel_tx || options.kernel_rx, "ktls"),
        (
            !options.spoof.is_empty() || !options.spoof_method.is_empty(),
            "spoof",
        ),
        (options.chrome_quic_parrot, "QUIC ClientHello parrot"),
    ];
    if let Some((_, option)) = unsupported.into_iter().find(|(used, _)| *used) {
        return Err(TlsError::Unsupported(format!(
            "{option} is unsupported in {engine_name}"
        )));
    }
    if !options.certificate_public_key_sha256.as_slice().is_empty()
        && (!options.certificate.as_slice().is_empty()
            || !options.certificate_path.is_empty())
    {
        return Err(TlsError::Certificate(
            "certificate_public_key_sha256 conflicts with certificate or certificate_path"
                .into(),
        ));
    }
    tls_version_bounds(&options.min_version, &options.max_version)?;
    Ok(())
}

fn validate_server_supported(
    options: &InboundTlsOptions,
    has_certificate_resolver: bool,
) -> Result<(), TlsError> {
    if options.kernel_tx || options.kernel_rx {
        #[cfg(not(target_os = "linux"))]
        return Err(TlsError::Unsupported(
            "kTLS is available only on Linux".into(),
        ));
        #[cfg(target_os = "linux")]
        crate::common::ktls::load()
            .map_err(|error| TlsError::Unsupported(error.to_string()))?;
    }
    let unsupported = [
        (
            options.certificate_provider.is_some() && !has_certificate_resolver,
            "certificate_provider",
        ),
        (options.acme.is_some() && !has_certificate_resolver, "acme"),
        (
            options.reality.as_ref().is_some_and(|value| value.enabled),
            "reality",
        ),
    ];
    if let Some((_, name)) = unsupported.into_iter().find(|(used, _)| *used) {
        return Err(TlsError::Unsupported(name.into()));
    }
    Ok(())
}

#[derive(Debug)]
struct InsecureCertificateResolver {
    provider: Arc<CryptoProvider>,
    certificates:
        std::sync::Mutex<std::collections::HashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for InsecureCertificateResolver {
    fn resolve(
        &self,
        client_hello: ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name().unwrap_or_default();
        let cache_key = server_name.to_owned();
        let mut certificates = self.certificates.lock().ok()?;
        if let Some(certificate) = certificates.get(&cache_key) {
            return Some(certificate.clone());
        }
        let certificate =
            generate_insecure_certificate(server_name, self.provider.as_ref())?;
        certificates.insert(cache_key, certificate.clone());
        Some(certificate)
    }
}

fn generate_insecure_certificate(
    server_name: &str,
    provider: &CryptoProvider,
) -> Option<Arc<CertifiedKey>> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256, RsaKeySize, SerialNumber,
    };
    use time::{Duration as TimeDuration, OffsetDateTime};

    let now = OffsetDateTime::now_utc();
    let mut params = if server_name.is_empty() {
        CertificateParams::new(Vec::<String>::new()).ok()?
    } else {
        CertificateParams::new(vec![server_name.to_owned()]).ok()?
    };
    params.not_before = now - TimeDuration::hours(1);
    params.not_after = now + TimeDuration::hours(1);
    let mut serial = [0_u8; 16];
    getrandom::fill(&mut serial).ok()?;
    serial[0] &= 0x7f;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, server_name);
    params.key_usages = vec![
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key =
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).ok()?;
    let certificate = params.self_signed(&key).ok()?;
    let certified_key = CertifiedKey::from_der(
        vec![CertificateDer::from(certificate.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        provider,
    )
    .ok()?;
    Some(Arc::new(certified_key))
}

fn parse_pem_certificates(
    bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = BufReader::new(bytes);
    let certificates: Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut reader).collect();
    let certificates = certificates
        .map_err(|error| TlsError::Certificate(error.to_string()))?;
    if certificates.is_empty() {
        return Err(TlsError::Certificate(
            "PEM input contains no certificates".into(),
        ));
    }
    Ok(certificates)
}

fn add_pem_certificates(
    roots: &mut RootCertStore,
    bytes: &[u8],
) -> Result<(), TlsError> {
    let certificates = parse_pem_certificates(bytes)?;
    let (accepted, rejected) = roots.add_parsable_certificates(certificates);
    if accepted == 0 || rejected != 0 {
        return Err(TlsError::Certificate(format!(
            "accepted {accepted} certificates and rejected {rejected}"
        )));
    }
    Ok(())
}

/// Build the trust store shared by stream TLS and certificate-based DTLS.
///
/// Protocols such as Fortinet use TLS for authentication and certificate
/// DTLS for the data carrier. Keeping root loading here makes both handshakes
/// honor the same inline CA, CA path, and system-trust policy.
pub(crate) fn outbound_tls_root_store(
    options: &OutboundTlsOptions,
) -> Result<RootCertStore, TlsError> {
    let has_per_tls_roots = !options.certificate.as_slice().is_empty()
        || !options.certificate_path.is_empty();
    let mut roots = if !options.system_trust_disabled && !has_per_tls_roots {
        if let Some(store) = &options.certificate_store {
            store
                .root_store()
                .map_err(|error| TlsError::Certificate(error.to_string()))?
                .as_ref()
                .clone()
        } else {
            RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            )
        }
    } else if options.system_trust_disabled || has_per_tls_roots {
        RootCertStore::empty()
    } else {
        unreachable!("all root-store cases handled")
    };
    for certificate in options.certificate.as_slice() {
        add_pem_certificates(&mut roots, certificate.as_bytes())?;
    }
    if !options.certificate_path.is_empty() {
        let bytes = fs::read(&options.certificate_path).map_err(|source| {
            TlsError::ReadCertificate {
                path: options.certificate_path.clone(),
                source,
            }
        })?;
        add_pem_certificates(&mut roots, &bytes)?;
    }
    Ok(roots)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

#[derive(Debug)]
struct AnyClientCertVerifier {
    mandatory: bool,
    provider: Arc<CryptoProvider>,
    public_key_sha256: Vec<Vec<u8>>,
}

impl ClientCertVerifier for AnyClientCertVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !self.public_key_sha256.is_empty() {
            verify_public_key_sha256(&self.public_key_sha256, end_entity)?;
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct CertificateFingerprintServerVerifier {
    fingerprints: Vec<ServerCertificateFingerprint>,
    provider: Arc<CryptoProvider>,
}

#[derive(Debug)]
struct DynamicCertificateStoreVerifier {
    store: CertificateStore,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for DynamicCertificateStoreVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let roots = self
            .store
            .root_store()
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            roots,
            self.provider.clone(),
        )
        .build()
        .map_err(|error| rustls::Error::General(error.to_string()))?;
        verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for CertificateFingerprintServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        verify_certificate_fingerprints(&self.fingerprints, end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn verify_certificate_fingerprints(
    fingerprints: &[ServerCertificateFingerprint],
    certificate: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let parsed = rustls::server::ParsedCertificate::try_from(certificate)?;
    let public_key = parsed.subject_public_key_info();
    if certificate_fingerprints_match(
        fingerprints,
        certificate.as_ref(),
        public_key.as_ref(),
    ) {
        Ok(())
    } else {
        Err(rustls::Error::General(
            "TLS peer certificate does not match any configured fingerprint"
                .into(),
        ))
    }
}

fn certificate_fingerprints_match(
    fingerprints: &[ServerCertificateFingerprint],
    certificate_der: &[u8],
    public_key_der: &[u8],
) -> bool {
    let certificate_sha1 = hex::encode(Sha1::digest(certificate_der));
    let public_key_sha1 = hex::encode(Sha1::digest(public_key_der));
    let public_key_sha256 = Sha256::digest(public_key_der);
    let public_key_sha256_hex = hex::encode(public_key_sha256);
    let public_key_sha256_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_key_sha256,
    );
    fingerprints.iter().any(|fingerprint| {
        let actual = match fingerprint.algorithm {
            ServerCertificateFingerprintAlgorithm::CertificateSha1Hex => {
                certificate_sha1.as_str()
            }
            ServerCertificateFingerprintAlgorithm::SpkiSha1Hex => {
                public_key_sha1.as_str()
            }
            ServerCertificateFingerprintAlgorithm::SpkiSha256Hex => {
                public_key_sha256_hex.as_str()
            }
            ServerCertificateFingerprintAlgorithm::SpkiSha256Base64 => {
                public_key_sha256_base64.as_str()
            }
        };
        constant_time_prefix_equal(
            fingerprint.encoded_prefix.as_bytes(),
            actual.as_bytes(),
        )
    })
}

fn constant_time_prefix_equal(prefix: &[u8], complete: &[u8]) -> bool {
    prefix.len() <= complete.len()
        && prefix
            .iter()
            .zip(complete)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[derive(Debug)]
struct PublicKeyPinServerVerifier {
    public_key_sha256: Vec<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PublicKeyPinServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        verify_public_key_sha256(&self.public_key_sha256, end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn verify_public_key_sha256(
    known_hashes: &[Vec<u8>],
    certificate: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let parsed = rustls::server::ParsedCertificate::try_from(certificate)?;
    let public_key = parsed.subject_public_key_info();
    let actual = Sha256::digest(public_key.as_ref());
    if known_hashes
        .iter()
        .any(|known| constant_time_equal(known, actual.as_slice()))
    {
        Ok(())
    } else {
        Err(rustls::Error::General(format!(
            "unrecognized remote public key SHA-256: {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                actual,
            )
        )))
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs, io,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac13::Mac as _;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedKey,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
        generate_simple_self_signed,
    };
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer,
    };
    use rustls::{
        ClientConnection, ServerConfig, SignatureAlgorithm, SignatureScheme,
        sign::{
            CertifiedKey as RustlsCertifiedKey, Signer, SigningKey,
            SingleCertAndKey,
        },
    };
    use sha2::{Digest, Sha256, Sha512};
    use x25519_dalek::x25519;

    use super::{
        ClientTlsDialer, EchConfigRecord, EchConfigResolver, TlsFragmentStream,
        TlsRecordStream, TlsVisionSwitch, build_client_config,
        build_client_config_with_clock, build_client_config_with_ech_resolver,
        build_server_config_with_clock, build_server_config_with_default_alpn,
        build_server_config_with_default_alpn_and_reality_dialer,
        crypto_provider, protocol_versions, verify_certificate_fingerprints,
    };
    #[cfg(target_os = "linux")]
    use super::{TlsError, validate_server_supported};

    struct MockEchResolver {
        record: EchConfigRecord,
        calls: AtomicUsize,
        names: Mutex<Vec<String>>,
    }

    fn legacy_openssl_acceptor(
        certificate_pem: &str,
        key_pem: &str,
        version: openssl::ssl::SslVersion,
    ) -> openssl::ssl::SslAcceptor {
        let mut acceptor = openssl::ssl::SslAcceptor::mozilla_intermediate(
            openssl::ssl::SslMethod::tls_server(),
        )
        .unwrap();
        acceptor.set_security_level(0);
        acceptor.set_min_proto_version(Some(version)).unwrap();
        acceptor.set_max_proto_version(Some(version)).unwrap();
        acceptor
            .set_cipher_list(super::OPENSSL_GO_COMPATIBLE_CIPHER_LIST)
            .unwrap();
        let certificate =
            openssl::x509::X509::from_pem(certificate_pem.as_bytes()).unwrap();
        let key = openssl::pkey::PKey::private_key_from_pem(key_pem.as_bytes())
            .unwrap();
        acceptor.set_certificate(&certificate).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.check_private_key().unwrap();
        acceptor.build()
    }

    #[derive(Debug)]
    struct SniCertificateResolver {
        accepted_name: String,
        certificate: Arc<RustlsCertifiedKey>,
        requested_names: Arc<Mutex<Vec<String>>>,
    }

    impl rustls::server::ResolvesServerCert for SniCertificateResolver {
        fn resolve(
            &self,
            client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<RustlsCertifiedKey>> {
            let name =
                client_hello.server_name().unwrap_or_default().to_owned();
            self.requested_names.lock().unwrap().push(name.clone());
            (name == self.accepted_name).then(|| self.certificate.clone())
        }
    }

    impl EchConfigResolver for MockEchResolver {
        fn resolve_ech<'a>(
            &'a self,
            server_name: &'a str,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = io::Result<EchConfigRecord>>
                    + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.names.lock().unwrap().push(server_name.to_owned());
            Box::pin(std::future::ready(Ok(self.record.clone())))
        }
    }
    use crate::option::{
        Base64Bytes, ClientAuthType, CurvePreference, InboundTlsOptions,
        Listable, OutboundEchOptions, OutboundRealityOptions,
        OutboundTlsOptions, OutboundUtlsOptions,
    };
    use crate::{
        adapter::{Dialer, replay_stream},
        common::certificate_store::CertificateStore,
        common::network::SocksAddr,
        common::reality::{
            REALITY_PROTOCOL_VERSION, derive_reality_auth_key_from_x25519,
            open_reality_session_id, parse_reality_client_hello,
        },
        common::reality_tls::{
            spawn_reality_cover_stub, spawn_reality_cover_stub_with_record_lens,
        },
        option::{
            CertificateOptions, CertificateStoreKind, DirectOutboundOptions,
        },
        protocol::direct::DirectOutbound,
    };
    use serde_json::json;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf,
    };
    use tokio::net::TcpStream;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    /// REALITY deliberately signs TLS 1.3 with Ed25519 even when the imitated
    /// browser did not advertise Ed25519.  Its Go server bypasses the normal
    /// TLS signature-scheme negotiation in exactly this way.
    #[derive(Debug)]
    struct RealitySigningKey(Arc<dyn SigningKey>);

    impl SigningKey for RealitySigningKey {
        fn choose_scheme(
            &self,
            _offered: &[SignatureScheme],
        ) -> Option<Box<dyn Signer>> {
            self.0.choose_scheme(&[SignatureScheme::ED25519])
        }

        fn public_key(
            &self,
        ) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
            self.0.public_key()
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            self.0.algorithm()
        }
    }

    struct RecordingIo<T> {
        inner: T,
        writes: Arc<Mutex<Vec<u8>>>,
    }

    impl<T: AsyncRead + Unpin> AsyncRead for RecordingIo<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingIo<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            match Pin::new(&mut self.inner).poll_write(context, buffer) {
                Poll::Ready(Ok(written)) => {
                    self.writes
                        .lock()
                        .unwrap()
                        .extend_from_slice(&buffer[..written]);
                    Poll::Ready(Ok(written))
                }
                result => result,
            }
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

    fn server_hello_shape(wire: &[u8]) -> ([u8; 32], u16, Vec<u16>) {
        assert!(wire.len() >= 5);
        assert_eq!(wire[0], 22);
        let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let hello = &wire[5..5 + record_len];
        assert_eq!(hello[0], 2);
        let random = hello[6..38].try_into().unwrap();
        let session_id_len = usize::from(hello[38]);
        let mut offset = 39 + session_id_len;
        let cipher = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        offset += 3;
        let extensions_len =
            usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
        offset += 2;
        let extensions_end = offset + extensions_len;
        let mut order = Vec::new();
        while offset < extensions_end {
            let extension =
                u16::from_be_bytes([hello[offset], hello[offset + 1]]);
            let length = usize::from(u16::from_be_bytes([
                hello[offset + 2],
                hello[offset + 3],
            ]));
            order.push(extension);
            offset += 4 + length;
        }
        assert_eq!(offset, extensions_end);
        (random, cipher, order)
    }

    fn first_record_total_len(wire: &[u8], content_type: u8) -> usize {
        let mut offset = 0;
        while offset + 5 <= wire.len() {
            let payload_len = usize::from(u16::from_be_bytes([
                wire[offset + 3],
                wire[offset + 4],
            ]));
            let total_len = 5 + payload_len;
            assert!(offset + total_len <= wire.len());
            if wire[offset] == content_type {
                return total_len;
            }
            offset += total_len;
        }
        panic!("TLS record type {content_type} was not emitted");
    }

    fn record_total_lens(wire: &[u8], content_type: u8) -> Vec<usize> {
        let mut offset = 0;
        let mut lengths = Vec::new();
        while offset + 5 <= wire.len() {
            let payload_len = usize::from(u16::from_be_bytes([
                wire[offset + 3],
                wire[offset + 4],
            ]));
            let total_len = 5 + payload_len;
            assert!(offset + total_len <= wire.len());
            if wire[offset] == content_type {
                lengths.push(total_len);
            }
            offset += total_len;
        }
        lengths
    }

    fn client_hello(server_name: &str) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        let extension_len = 2 + 1 + 2 + server_name.len();
        extensions.extend_from_slice(&(extension_len as u16).to_be_bytes());
        extensions.extend_from_slice(
            &((1 + 2 + server_name.len()) as u16).to_be_bytes(),
        );
        extensions.push(0);
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(server_name.as_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1, 0, 0, 0];
        let body_len = body.len();
        handshake[1] = (body_len >> 16) as u8;
        handshake[2] = (body_len >> 8) as u8;
        handshake[3] = body_len as u8;
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[tokio::test]
    async fn vision_record_limiter_leaves_coalesced_raw_suffix_unread() {
        let (mut writer, reader) = tokio::io::duplex(64);
        writer
            .write_all(b"\x17\x03\x03\x00\x04tls!raw-suffix")
            .await
            .unwrap();

        let direct_switch = Arc::new(TlsVisionSwitch::default());
        let mut stream =
            TlsRecordStream::new(Box::new(reader), direct_switch.clone());
        let mut buffer = [0_u8; 64];

        let header_size = stream.read(&mut buffer).await.unwrap();
        assert_eq!(header_size, 5);
        assert_eq!(&buffer[..header_size], b"\x17\x03\x03\x00\x04");

        let payload_size = stream.read(&mut buffer).await.unwrap();
        assert_eq!(payload_size, 4);
        assert_eq!(&buffer[..payload_size], b"tls!");

        direct_switch
            .read_direct_active
            .store(true, Ordering::Release);
        let raw_size = stream.read(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..raw_size], b"raw-suffix");
    }

    #[tokio::test]
    async fn record_fragment_rewrites_client_hello_at_sni() {
        let hello = client_hello("front.example.com");
        let expected_payload = hello[5..].to_vec();
        let expected_header = hello[..3].to_vec();
        let (writer, mut reader) = tokio::io::duplex(4096);
        let write_task = tokio::spawn(async move {
            let mut stream = TlsFragmentStream::new(
                Box::new(writer),
                false,
                true,
                std::time::Duration::ZERO,
            );
            stream.write_all(&hello).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut fragmented = Vec::new();
        reader.read_to_end(&mut fragmented).await.unwrap();
        write_task.await.unwrap();

        let first_len =
            usize::from(u16::from_be_bytes([fragmented[3], fragmented[4]]));
        let second_offset = 5 + first_len;
        assert!(second_offset > 5 && second_offset < fragmented.len());
        assert_eq!(&fragmented[..3], expected_header);
        assert_eq!(
            &fragmented[second_offset..second_offset + 3],
            expected_header
        );
        let second_len = usize::from(u16::from_be_bytes([
            fragmented[second_offset + 3],
            fragmented[second_offset + 4],
        ]));
        assert_eq!(second_offset + 5 + second_len, fragmented.len());
        let mut payload = fragmented[5..second_offset].to_vec();
        payload.extend_from_slice(&fragmented[second_offset + 5..]);
        assert_eq!(payload, expected_payload);
    }

    #[tokio::test]
    async fn tls_fragment_modes_complete_real_handshakes() {
        for (fragment, record_fragment) in
            [(true, false), (false, true), (true, true)]
        {
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let server = super::build_server_config(&InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![cert.pem()]),
                key: Listable(vec![key_pair.serialize_pem()]),
                ..Default::default()
            })
            .unwrap();
            let client = build_client_config(
                "localhost",
                &OutboundTlsOptions {
                    insecure: true,
                    fragment,
                    record_fragment,
                    fragment_fallback_delay:
                        crate::option::Duration::from_nanos(1_000_000),
                    ..Default::default()
                },
                &[],
            )
            .unwrap();
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let server_task = tokio::spawn(async move {
                let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                    .accept(server_io)
                    .await
                    .unwrap();
                stream.write_all(b"ok").await.unwrap();
            });
            let client_stream =
                client.wrap_client_stream(Box::new(client_io)).unwrap();
            let mut stream = tokio_rustls::TlsConnector::from(client.config)
                .connect(client.server_name, client_stream)
                .await
                .unwrap();
            let mut response = [0_u8; 2];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ok");
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn existing_rustls_config_observes_certificate_store_reload() {
        fn ca() -> (rcgen::Certificate, KeyPair) {
            let mut parameters = CertificateParams::default();
            parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            parameters.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let key = KeyPair::generate().unwrap();
            (parameters.self_signed(&key).unwrap(), key)
        }

        async fn handshake(
            client: &super::ClientTlsConfig,
            server: &super::ServerTlsConfig,
        ) -> bool {
            let (client_io, server_io) = tokio::io::duplex(32 * 1024);
            let acceptor = TlsAcceptor::from(server.config.clone());
            let server_task =
                tokio::spawn(async move { acceptor.accept(server_io).await });
            let result = TlsConnector::from(client.config.clone())
                .connect(client.server_name.clone(), client_io)
                .await;
            let success = result.is_ok();
            drop(result);
            let _ =
                tokio::time::timeout(Duration::from_secs(1), server_task).await;
            success
        }

        let (old_ca, _) = ca();
        let (new_ca, new_ca_key) = ca();
        let mut leaf_parameters =
            CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_parameters
            .signed_by(&leaf_key, &new_ca, &new_ca_key)
            .unwrap();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![format!(
                "{}\n{}",
                leaf.pem(),
                new_ca.pem()
            )]),
            key: Listable(vec![leaf_key.serialize_pem()]),
            ..Default::default()
        })
        .unwrap();

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("roots.pem");
        fs::write(&path, old_ca.pem()).unwrap();
        let store = CertificateStore::new(
            &CertificateOptions {
                store: CertificateStoreKind::None,
                certificate_path: Listable(vec!["roots.pem".into()]),
                ..Default::default()
            },
            directory.path(),
        )
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions::default()
                .with_certificate_store(store.clone()),
            &[],
        )
        .unwrap();

        assert!(!handshake(&client, &server).await);
        fs::write(&path, new_ca.pem()).unwrap();
        assert!(store.reload().unwrap());
        assert!(handshake(&client, &server).await);
    }

    #[tokio::test]
    async fn rustls_uses_ntp_clock_for_certificate_validity() {
        let mut ca_parameters = CertificateParams::default();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap();
        ca_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_893_456_000).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();

        let mut leaf_parameters =
            CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_609_459_200).unwrap();
        leaf_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_640_995_200).unwrap();
        leaf_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_certificate = leaf_parameters
            .signed_by(&leaf_key, &ca_certificate, &ca_key)
            .unwrap();

        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![format!(
                "{}\n{}",
                leaf_certificate.pem(),
                ca_certificate.pem()
            )]),
            key: Listable(vec![leaf_key.serialize_pem()]),
            ..Default::default()
        })
        .unwrap();
        let clock = crate::common::ntp::NtpClock::default();
        let client = build_client_config_with_clock(
            "localhost",
            &OutboundTlsOptions {
                certificate: Listable(vec![ca_certificate.pem()]),
                ..Default::default()
            },
            &[],
            Some(clock.clone()),
        )
        .unwrap();
        let system_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        let target_unix_nanos = 1_625_097_600_i128 * 1_000_000_000;
        clock.update(crate::common::ntp::NtpSample {
            offset_nanos: i64::try_from(target_unix_nanos - system_unix_nanos)
                .unwrap(),
            round_trip_nanos: 1,
            stratum: 1,
        });

        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"ntp-time").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ntp-time");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rustls_server_uses_ntp_clock_for_client_certificate_validity() {
        let mut ca_parameters = CertificateParams::default();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap();
        ca_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_893_456_000).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();

        let mut server_parameters =
            CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap();
        server_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_893_456_000).unwrap();
        server_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_certificate = server_parameters
            .signed_by(&server_key, &ca_certificate, &ca_key)
            .unwrap();

        let mut client_parameters =
            CertificateParams::new(vec!["client.test".into()]).unwrap();
        client_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_609_459_200).unwrap();
        client_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_640_995_200).unwrap();
        client_parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_certificate = client_parameters
            .signed_by(&client_key, &ca_certificate, &ca_key)
            .unwrap();

        let clock = crate::common::ntp::NtpClock::default();
        let server = build_server_config_with_clock(
            &InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![format!(
                    "{}\n{}",
                    server_certificate.pem(),
                    ca_certificate.pem()
                )]),
                key: Listable(vec![server_key.serialize_pem()]),
                client_authentication:
                    crate::option::ClientAuthType::RequireAndVerify,
                client_certificate: Listable(vec![ca_certificate.pem()]),
                ..Default::default()
            },
            Some(clock.clone()),
        )
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                client_certificate: Listable(vec![format!(
                    "{}\n{}",
                    client_certificate.pem(),
                    ca_certificate.pem()
                )]),
                client_key: Listable(vec![client_key.serialize_pem()]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let system_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        let target_unix_nanos = 1_625_097_600_i128 * 1_000_000_000;
        clock.update(crate::common::ntp::NtpSample {
            offset_nanos: i64::try_from(target_unix_nanos - system_unix_nanos)
                .unwrap(),
            round_trip_nanos: 1,
            stratum: 1,
        });

        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"ok").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn insecure_server_generates_a_certificate_for_client_sni() {
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            insecure: true,
            server_name: "accepted-but-not-forced.example".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(server.handshake_timeout, Some(Duration::from_secs(15)));
        let client = build_client_config(
            "ephemeral.example",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        assert_eq!(client.handshake_timeout, Some(Duration::from_secs(15)));
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"ephemeral").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 9];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ephemeral");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn managed_certificate_resolver_publishes_without_rebuilding_tls() {
        let options = InboundTlsOptions {
            enabled: true,
            certificate_provider: Some(
                crate::option::CertificateProviderOptions::Reference(
                    "managed".into(),
                ),
            ),
            ..Default::default()
        };
        assert!(super::build_server_config(&options).is_err());

        let resolver = Arc::new(super::DynamicCertificateResolver::new());
        let server = super::build_server_config_with_default_alpn_and_resolver(
            &options,
            &[],
            Some(resolver.clone()),
        )
        .unwrap();
        assert!(!resolver.has_certificate());

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["managed.example".into()])
                .unwrap();
        resolver.set(
            super::certified_key_from_pem(
                cert.pem().as_bytes(),
                key_pair.serialize_pem().as_bytes(),
            )
            .unwrap(),
        );
        assert!(resolver.has_certificate());

        let client = build_client_config(
            "managed.example",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"managed").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 7];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"managed");
        server_task.await.unwrap();

        resolver.clear();
        assert!(!resolver.has_certificate());
    }

    #[tokio::test]
    async fn managed_resolver_selects_acme_tls_alpn_certificate_by_sni() {
        let mut options = InboundTlsOptions {
            enabled: true,
            certificate_provider: Some(
                crate::option::CertificateProviderOptions::Reference(
                    "managed".into(),
                ),
            ),
            ..Default::default()
        };
        options.certificate_resolver.1 = true;
        let resolver = Arc::new(super::DynamicCertificateResolver::new());
        let server = super::build_server_config_with_default_alpn_and_resolver(
            &options,
            &[],
            Some(resolver.clone()),
        )
        .unwrap();

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["managed.example".into()])
                .unwrap();
        resolver.set(
            super::certified_key_from_pem(
                cert.pem().as_bytes(),
                key_pair.serialize_pem().as_bytes(),
            )
            .unwrap(),
        );
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["managed.example".into()])
                .unwrap();
        let expected = cert.der().to_vec();
        resolver.set_acme_tls_alpn(
            "managed.example".into(),
            super::certified_key_from_pem(
                cert.pem().as_bytes(),
                key_pair.serialize_pem().as_bytes(),
            )
            .unwrap(),
        );

        let client = build_client_config(
            "managed.example",
            &OutboundTlsOptions {
                insecure: true,
                alpn: Listable(vec!["acme-tls/1".into()]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
        });
        let stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let peer = stream.get_ref().1.peer_certificates().unwrap();
        assert_eq!(peer[0].as_ref(), expected);
        server_task.await.unwrap();

        resolver.clear_acme_tls_alpn();
    }

    #[test]
    fn builds_standard_and_insecure_client_configs() {
        let standard = build_client_config(
            "dns.example",
            &OutboundTlsOptions::default(),
            &["dot"],
        )
        .unwrap();
        assert_eq!(standard.config.alpn_protocols, [b"dot".to_vec()]);

        let insecure = OutboundTlsOptions {
            insecure: true,
            disable_sni: true,
            ..Default::default()
        };
        let config = build_client_config("127.0.0.1", &insecure, &[]).unwrap();
        assert!(!config.config.enable_sni);
    }

    #[tokio::test]
    async fn static_ech_config_emits_encrypted_client_hello() {
        let pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let client = build_client_config(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    config: Listable(vec![pair.config_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        let handshake = tokio::spawn(async move {
            tokio_rustls::TlsConnector::from(client.config)
                .connect(client.server_name, client_io)
                .await
        });
        let mut header = [0_u8; 5];
        server_io.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 22);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut hello = vec![0_u8; length];
        server_io.read_exact(&mut hello).await.unwrap();
        assert!(hello.windows(2).any(|window| window == [0xfe, 0x0d]));
        handshake.abort();
    }

    #[tokio::test]
    async fn ech_server_decrypts_inner_hello_and_carries_application_data() {
        let ech = crate::common::keygen::generate_ech_keypair("public.example")
            .unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(["secret.example".into()]).unwrap();
        let server = build_server_config_with_default_alpn(
            &InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![cert.pem()]),
                key: Listable(vec![key_pair.serialize_pem()]),
                ech: Some(crate::option::InboundEchOptions {
                    enabled: true,
                    key: Listable(vec![ech.key_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &["h2", "http/1.1"],
        )
        .unwrap();
        let client = build_client_config(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                alpn: Listable(vec!["h2".into()]),
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    config: Listable(vec![ech.config_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream =
                server.accept_stream(Box::new(server_io)).await.unwrap();
            assert!(stream.ech_accepted());
            assert_eq!(stream.alpn_protocol(), Some(b"h2".as_slice()));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let mut stream = TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.ech_status(),
            rustls::client::EchStatus::Accepted
        );
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn ech_server_preserves_acceptance_across_hello_retry_request() {
        let ech = crate::common::keygen::generate_ech_keypair("public.example")
            .unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(["secret.example".into()]).unwrap();
        let server = build_server_config_with_default_alpn(
            &InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![cert.pem()]),
                key: Listable(vec![key_pair.serialize_pem()]),
                curve_preferences: Listable(vec![CurvePreference::P256]),
                ech: Some(crate::option::InboundEchOptions {
                    enabled: true,
                    key: Listable(vec![ech.key_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let client = build_client_config(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    config: Listable(vec![ech.config_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let writes = Arc::new(Mutex::new(Vec::new()));
        let client_io = RecordingIo {
            inner: client_io,
            writes: writes.clone(),
        };
        let server_task = tokio::spawn(async move {
            let mut stream =
                server.accept_stream(Box::new(server_io)).await.unwrap();
            assert!(stream.ech_accepted());
            stream.write_all(b"ok").await.unwrap();
        });
        let mut stream = TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.ech_status(),
            rustls::client::EchStatus::Accepted
        );
        assert_eq!(
            stream
                .get_ref()
                .1
                .negotiated_key_exchange_group()
                .unwrap()
                .name(),
            rustls::NamedGroup::secp256r1
        );
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        drop(stream);
        server_task.await.unwrap();
        assert!(record_total_lens(&writes.lock().unwrap(), 22).len() >= 2);
    }

    #[tokio::test]
    async fn ech_server_accepts_quic_with_inner_server_name() {
        let ech = crate::common::keygen::generate_ech_keypair("public.example")
            .unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(["secret.example".into()]).unwrap();
        let requested_names = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(SniCertificateResolver {
            accepted_name: "secret.example".into(),
            certificate: super::certified_key_from_pem(
                cert.pem().as_bytes(),
                key_pair.serialize_pem().as_bytes(),
            )
            .unwrap(),
            requested_names: requested_names.clone(),
        });
        let server = super::build_server_config_with_default_alpn_and_resolver(
            &InboundTlsOptions {
                enabled: true,
                certificate_provider: Some(
                    crate::option::CertificateProviderOptions::Reference(
                        "managed".into(),
                    ),
                ),
                ech: Some(crate::option::InboundEchOptions {
                    enabled: true,
                    key: Listable(vec![ech.key_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &["doq"],
            Some(resolver),
        )
        .unwrap();
        let endpoint = crate::transport::quic::server_endpoint(
            server,
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let mut payload = [0_u8; 4];
            receive.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            send.write_all(b"pong").await.unwrap();
            send.shutdown().await.unwrap();
            let mut acknowledgement = [0_u8; 1];
            receive.read_exact(&mut acknowledgement).await.unwrap();
            assert_eq!(&acknowledgement, b"!");
        });
        let client = build_client_config(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    config: Listable(vec![ech.config_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &["doq"],
        )
        .unwrap();
        let dialer = crate::transport::quic::QuicDialer::new(
            address.into(),
            "secret.example",
            client,
        )
        .unwrap();
        let mut stream = dialer.dial_tcp(&address.into()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        stream.write_all(b"!").await.unwrap();
        stream.shutdown().await.unwrap();
        server_task.await.unwrap();
        assert_eq!(
            requested_names.lock().unwrap().as_slice(),
            ["secret.example"]
        );
    }

    #[tokio::test]
    async fn ech_server_rewinds_to_outer_hello_when_inner_certificate_is_missing()
     {
        let ech = crate::common::keygen::generate_ech_keypair("public.example")
            .unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(["public.example".into()]).unwrap();
        let requested_names = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(SniCertificateResolver {
            accepted_name: "public.example".into(),
            certificate: super::certified_key_from_pem(
                cert.pem().as_bytes(),
                key_pair.serialize_pem().as_bytes(),
            )
            .unwrap(),
            requested_names: requested_names.clone(),
        });
        let server = super::build_server_config_with_default_alpn_and_resolver(
            &InboundTlsOptions {
                enabled: true,
                certificate_provider: Some(
                    crate::option::CertificateProviderOptions::Reference(
                        "managed".into(),
                    ),
                ),
                ech: Some(crate::option::InboundEchOptions {
                    enabled: true,
                    key: Listable(vec![ech.key_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
            Some(resolver),
        )
        .unwrap();
        let client = build_client_config(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    config: Listable(vec![ech.config_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server.accept_stream(Box::new(server_io)).await
        });
        let client_result = TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await;
        assert!(
            client_result.is_err(),
            "ECH rejection must reach the client"
        );
        assert!(server_task.await.unwrap().is_err());
        assert_eq!(
            requested_names.lock().unwrap().as_slice(),
            ["secret.example", "public.example"]
        );
    }

    #[tokio::test]
    #[ignore = "requires the pinned Go sing-box toolchain"]
    async fn ech_server_interoperates_with_pinned_go_client() {
        let ech = crate::common::keygen::generate_ech_keypair("public.example")
            .unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(["secret.example".into()]).unwrap();
        let server = build_server_config_with_default_alpn(
            &InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![cert.pem()]),
                key: Listable(vec![key_pair.serialize_pem()]),
                ech: Some(crate::option::InboundEchOptions {
                    enabled: true,
                    key: Listable(vec![ech.key_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream =
                server.accept_stream(Box::new(stream)).await.unwrap();
            assert!(stream.ech_accepted());
            let mut payload = [0_u8; 11];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"go-ech-rust");
            stream.write_all(&payload).await.unwrap();
        });

        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.join("../..");
        let fixture = manifest.join("tests/fixtures/ech-go-client/main.go");
        let status = tokio::task::spawn_blocking(move || {
            std::process::Command::new("go")
                .args(["run", fixture.to_str().unwrap()])
                .current_dir(workspace.join("inner/sing-box"))
                .env("SINGBOX_ECH_RUST_SERVER", address.to_string())
                .env(
                    "SINGBOX_ECH_CONFIG",
                    base64::engine::general_purpose::STANDARD
                        .encode(ech.config_pem),
                )
                .status()
        })
        .await
        .unwrap()
        .unwrap();
        assert!(status.success());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn utls_static_ech_emits_encrypted_client_hello() {
        let pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let client = build_client_config(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                utls: Some(crate::option::OutboundUtlsOptions {
                    enabled: true,
                    fingerprint: "chrome".into(),
                }),
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    config: Listable(vec![pair.config_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        let handshake = tokio::spawn(async move {
            tokio_rustls::TlsConnector::from(client.config)
                .connect(client.server_name, client_io)
                .await
        });
        let mut header = [0_u8; 5];
        server_io.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 22);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut hello = vec![0_u8; length];
        server_io.read_exact(&mut hello).await.unwrap();
        assert!(hello.windows(2).any(|window| window == [0xfe, 0x0d]));
        let mut flight = header.to_vec();
        flight.extend_from_slice(&hello);
        let server_name = super::tls_client_hello_server_name(&flight)
            .map(|range| &flight[range.start..range.start + range.len])
            .unwrap();
        assert_eq!(server_name, b"public.example");
        handshake.abort();
    }

    #[tokio::test]
    #[ignore = "requires the pinned Go sing-box toolchain"]
    async fn utls_static_ech_interoperates_with_pinned_go_server() {
        let pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let client = build_client_config(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                utls: Some(OutboundUtlsOptions {
                    enabled: true,
                    fingerprint: "chrome".into(),
                }),
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    config: Listable(vec![pair.config_pem]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();

        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.join("../..");
        let fixture = manifest.join("tests/fixtures/ech-go-server/main.go");
        let mut child = std::process::Command::new("go")
            .args(["run", fixture.to_str().unwrap()])
            .current_dir(workspace.join("inner/sing-box"))
            .env(
                "SINGBOX_ECH_KEY",
                base64::engine::general_purpose::STANDARD.encode(pair.key_pem),
            )
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut address,
        )
        .unwrap();

        let io = TcpStream::connect(address.trim()).await.unwrap();
        let mut stream = TlsConnector::from(client.config)
            .connect(client.server_name, io)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.ech_status(),
            rustls::client::EchStatus::Accepted
        );
        stream.write_all(b"utls-ech-go").await.unwrap();
        let mut response = [0; 11];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"utls-ech-go");
        drop(stream);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn ech_rejects_missing_dynamic_and_invalid_static_configs() {
        let dynamic = OutboundTlsOptions {
            ech: Some(OutboundEchOptions {
                enabled: true,
                query_server_name: "public.example".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = match build_client_config("secret.example", &dynamic, &[]) {
            Ok(_) => panic!("dynamic ECH config unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("dynamic ECH"));

        let invalid = OutboundTlsOptions {
            ech: Some(OutboundEchOptions {
                enabled: true,
                config: Listable(vec![
                    "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
                        .into(),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = match build_client_config("secret.example", &invalid, &[]) {
            Ok(_) => panic!("invalid ECH config unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("block type"));
    }

    #[tokio::test]
    async fn dynamic_ech_resolves_query_name_and_caches_for_record_ttl() {
        let pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let config_list = pem::parse(pair.config_pem).unwrap().into_contents();
        let resolver = Arc::new(MockEchResolver {
            record: EchConfigRecord {
                config_list,
                ttl: Duration::from_secs(60),
            },
            calls: AtomicUsize::new(0),
            names: Mutex::new(Vec::new()),
        });
        let client = build_client_config_with_ech_resolver(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    query_server_name: "discovery.example".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &["h2"],
            resolver.clone(),
        )
        .unwrap();

        let first = client.config_for_handshake().await.unwrap();
        let second = client.config_for_handshake().await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            resolver.names.lock().unwrap().as_slice(),
            ["discovery.example"]
        );
        assert_eq!(first.alpn_protocols, [b"h2".to_vec()]);
    }

    #[tokio::test]
    async fn ech_retry_config_replaces_dynamic_cache_until_dns_ttl() {
        let stale_pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let replacement_pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let resolver = Arc::new(MockEchResolver {
            record: EchConfigRecord {
                config_list: pem::parse(stale_pair.config_pem)
                    .unwrap()
                    .into_contents(),
                ttl: Duration::from_secs(60),
            },
            calls: AtomicUsize::new(0),
            names: Mutex::new(Vec::new()),
        });
        let client = build_client_config_with_ech_resolver(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
            resolver.clone(),
        )
        .unwrap();
        let stale = client.config_for_handshake().await.unwrap();
        let replacement = client
            .config_for_ech_retry(
                &pem::parse(replacement_pair.config_pem)
                    .unwrap()
                    .into_contents(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!Arc::ptr_eq(&stale, &replacement));
        assert!(Arc::ptr_eq(
            &replacement,
            &client.config_for_handshake().await.unwrap()
        ));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    #[ignore = "requires the pinned Go sing-box toolchain"]
    async fn dynamic_ech_interoperates_with_pinned_go_server() {
        let pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let resolver = Arc::new(MockEchResolver {
            record: EchConfigRecord {
                config_list: pem::parse(&pair.config_pem)
                    .unwrap()
                    .into_contents(),
                ttl: Duration::from_secs(60),
            },
            calls: AtomicUsize::new(0),
            names: Mutex::new(Vec::new()),
        });
        let client = build_client_config_with_ech_resolver(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    query_server_name: "discovery.example".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
            resolver.clone(),
        )
        .unwrap();

        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.join("../..");
        let fixture = manifest.join("tests/fixtures/ech-go-server/main.go");
        let mut child = std::process::Command::new("go")
            .args(["run", fixture.to_str().unwrap()])
            .current_dir(workspace.join("inner/sing-box"))
            .env(
                "SINGBOX_ECH_KEY",
                base64::engine::general_purpose::STANDARD.encode(pair.key_pem),
            )
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut address,
        )
        .unwrap();

        let io = TcpStream::connect(address.trim()).await.unwrap();
        let config = client.config_for_handshake().await.unwrap();
        let mut stream = TlsConnector::from(config)
            .connect(client.server_name, io)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.ech_status(),
            rustls::client::EchStatus::Accepted
        );
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            resolver.names.lock().unwrap().as_slice(),
            ["discovery.example"]
        );
        stream.write_all(b"dynamic-ech-go").await.unwrap();
        let mut response = [0; 14];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"dynamic-ech-go");
        drop(stream);
        assert!(child.wait().unwrap().success());
    }

    #[tokio::test]
    #[ignore = "requires the pinned Go sing-box toolchain"]
    async fn ech_rejection_retries_with_go_server_config() {
        let stale_pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let current_pair =
            crate::common::keygen::generate_ech_keypair("public.example")
                .unwrap();
        let resolver = Arc::new(MockEchResolver {
            record: EchConfigRecord {
                config_list: pem::parse(stale_pair.config_pem)
                    .unwrap()
                    .into_contents(),
                ttl: Duration::from_secs(60),
            },
            calls: AtomicUsize::new(0),
            names: Mutex::new(Vec::new()),
        });
        let client = build_client_config_with_ech_resolver(
            "secret.example",
            &OutboundTlsOptions {
                insecure: true,
                ech: Some(OutboundEchOptions {
                    enabled: true,
                    query_server_name: "discovery.example".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &[],
            resolver.clone(),
        )
        .unwrap();

        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.join("../..");
        let fixture = manifest.join("tests/fixtures/ech-go-server/main.go");
        let mut child = std::process::Command::new("go")
            .args(["run", fixture.to_str().unwrap()])
            .current_dir(workspace.join("inner/sing-box"))
            .env(
                "SINGBOX_ECH_KEY",
                base64::engine::general_purpose::STANDARD
                    .encode(current_pair.key_pem),
            )
            .env("SINGBOX_ECH_SEND_RETRY", "1")
            .env("SINGBOX_ECH_ACCEPTS", "2")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut address,
        )
        .unwrap();
        let remote = SocksAddr::from(
            address.trim().parse::<std::net::SocketAddr>().unwrap(),
        );
        let dialer = ClientTlsDialer::new(
            DirectOutbound::new(DirectOutboundOptions::default()),
            client,
        );
        let mut stream = dialer.dial_tcp(&remote).await.unwrap();
        stream.write_all(b"ech-retry-go").await.unwrap();
        let mut response = [0; 12];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ech-retry-go");
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
        drop(stream);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn rejects_unknown_tls_engine() {
        let options = OutboundTlsOptions {
            engine: "utls".into(),
            ..Default::default()
        };
        assert!(build_client_config("dns.example", &options, &[]).is_err());
    }

    #[tokio::test]
    async fn rustls_buffered_handoff_preserves_exporter_and_key_updates() {
        fn assert_same_secret(
            left: rustls::ConnectionTrafficSecrets,
            right: rustls::ConnectionTrafficSecrets,
        ) {
            match (left, right) {
                (
                    rustls::ConnectionTrafficSecrets::Aes128Gcm {
                        key: left_key,
                        iv: left_iv,
                    },
                    rustls::ConnectionTrafficSecrets::Aes128Gcm {
                        key: right_key,
                        iv: right_iv,
                    },
                )
                | (
                    rustls::ConnectionTrafficSecrets::Aes256Gcm {
                        key: left_key,
                        iv: left_iv,
                    },
                    rustls::ConnectionTrafficSecrets::Aes256Gcm {
                        key: right_key,
                        iv: right_iv,
                    },
                )
                | (
                    rustls::ConnectionTrafficSecrets::Chacha20Poly1305 {
                        key: left_key,
                        iv: left_iv,
                    },
                    rustls::ConnectionTrafficSecrets::Chacha20Poly1305 {
                        key: right_key,
                        iv: right_iv,
                    },
                ) => {
                    assert_eq!(left_key.as_ref(), right_key.as_ref());
                    assert_eq!(left_iv.as_ref(), right_iv.as_ref());
                }
                _ => panic!(
                    "client and server derived different traffic ciphers"
                ),
            }
        }

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_pem = cert.pem();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![certificate_pem.clone()]),
            key: Listable(vec![key_pair.serialize_pem()]),
            min_version: "1.3".into(),
            max_version: "1.3".into(),
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                certificate: Listable(vec![certificate_pem]),
                min_version: "1.3".into(),
                max_version: "1.3".into(),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let mut server_config = (*server.config).clone();
        server_config.enable_secret_extraction = true;
        let mut client_config = (*client.config).clone();
        client_config.enable_secret_extraction = true;
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(server_config))
                .accept(Box::new(server_io) as crate::adapter::Stream)
                .await
                .unwrap()
        });
        let client_stream = TlsConnector::from(Arc::new(client_config))
            .connect(
                client.server_name,
                Box::new(client_io) as crate::adapter::Stream,
            )
            .await
            .unwrap();
        let server_stream = server_task.await.unwrap();
        let (_, client_connection) = client_stream.into_inner();
        let (_, server_connection) = server_stream.into_inner();
        let (client_initial, mut client_kernel) = client_connection
            .dangerous_into_kernel_connection()
            .unwrap();
        let (server_initial, mut server_kernel) = server_connection
            .dangerous_into_kernel_connection()
            .unwrap();

        assert!(client_initial.tx.0 < client_kernel.confidentiality_limit());
        assert!(server_initial.tx.0 < server_kernel.confidentiality_limit());
        let mut client_exporter = [0_u8; 32];
        let mut server_exporter = [0_u8; 32];
        client_kernel
            .export_keying_material(
                &mut client_exporter,
                b"EXPORTER-singbox-kernel-handoff",
                Some(b"context"),
            )
            .unwrap();
        server_kernel
            .export_keying_material(
                &mut server_exporter,
                b"EXPORTER-singbox-kernel-handoff",
                Some(b"context"),
            )
            .unwrap();
        assert_eq!(client_exporter, server_exporter);
        assert_same_secret(
            client_kernel.update_tx_secret().unwrap().1,
            server_kernel.update_rx_secret().unwrap().1,
        );
        assert_same_secret(
            server_kernel.update_tx_secret().unwrap().1,
            client_kernel.update_rx_secret().unwrap().1,
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_ktls_is_enabled_for_streams_and_rejected_for_quic() {
        for (kernel_tx, kernel_rx) in
            [(true, false), (false, true), (true, true)]
        {
            let options = OutboundTlsOptions {
                kernel_tx,
                kernel_rx,
                ..Default::default()
            };
            let config =
                build_client_config("dns.example", &options, &[]).unwrap();
            assert!(config.config.enable_secret_extraction);
            assert!(config.config_for_handshake().await.is_ok());
            assert!(matches!(
                config.rustls_config(),
                Err(TlsError::Unsupported(message)) if message.contains("QUIC")
            ));
        }

        for (kernel_tx, kernel_rx) in
            [(true, false), (false, true), (true, true)]
        {
            let options = InboundTlsOptions {
                kernel_tx,
                kernel_rx,
                ..Default::default()
            };
            validate_server_supported(&options, false).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a Linux host with the TLS ULP and TLS 1.3 RX support"]
    async fn linux_ktls_loopback_covers_independent_tx_rx_directions() {
        for (kernel_tx, kernel_rx) in
            [(true, false), (false, true), (true, true)]
        {
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let certificate_pem = cert.pem();
            let server = super::build_server_config(&InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![certificate_pem.clone()]),
                key: Listable(vec![key_pair.serialize_pem()]),
                min_version: "1.3".into(),
                max_version: "1.3".into(),
                kernel_tx,
                kernel_rx,
                ..Default::default()
            })
            .unwrap();
            let client = build_client_config(
                "localhost",
                &OutboundTlsOptions {
                    certificate: Listable(vec![certificate_pem]),
                    min_version: "1.3".into(),
                    max_version: "1.3".into(),
                    kernel_tx,
                    kernel_rx,
                    ..Default::default()
                },
                &[],
            )
            .unwrap();
            let listener =
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let (transport, _) = listener.accept().await.unwrap();
                let mut stream =
                    server.accept_stream(Box::new(transport)).await.unwrap();
                let mut request = [0_u8; 11];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"client-data");
                stream.write_all(b"server-data").await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let transport = TcpStream::connect(address).await.unwrap();
            let mut stream =
                client.connect_stream(Box::new(transport)).await.unwrap();
            let mut exporter = [0_u8; 32];
            stream
                .export_keying_material(
                    &mut exporter,
                    b"EXPORTER-singbox-ktls-test",
                    None,
                )
                .unwrap();
            assert_ne!(exporter, [0_u8; 32]);
            stream.write_all(b"client-data").await.unwrap();
            let mut response = [0_u8; 11];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"server-data");
            stream.shutdown().await.unwrap();
            server_task.await.unwrap();
        }
    }

    #[test]
    fn validates_outbound_tls_spoof_options_before_dialing() {
        let valid = OutboundTlsOptions {
            spoof: "allowed.example".into(),
            spoof_method: "wrong-md5".into(),
            ..Default::default()
        };
        let config = build_client_config("real.example", &valid, &[]).unwrap();
        assert_eq!(config.spoof, "allowed.example");
        assert_eq!(
            config.spoof_method,
            crate::common::tls_spoof::TlsSpoofMethod::WrongMd5
        );

        for options in [
            OutboundTlsOptions {
                spoof_method: "wrong-ack".into(),
                ..Default::default()
            },
            OutboundTlsOptions {
                spoof: "real.example".into(),
                ..Default::default()
            },
            OutboundTlsOptions {
                spoof: "allowed.example".into(),
                disable_sni: true,
                ..Default::default()
            },
            OutboundTlsOptions {
                spoof: "allowed.example".into(),
                spoof_method: "unknown".into(),
                ..Default::default()
            },
        ] {
            assert!(
                build_client_config("real.example", &options, &[]).is_err()
            );
        }
    }

    #[test]
    fn static_utls_profiles_shape_real_client_hellos() {
        fn hello_extensions(bytes: &[u8]) -> Vec<u16> {
            assert_eq!(bytes[0], 22);
            let record_len =
                usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
            let hello = &bytes[5..5 + record_len];
            assert_eq!(hello[0], 1);
            let mut offset = 4 + 2 + 32;
            let session_id_len = usize::from(hello[offset]);
            offset += 1 + session_id_len;
            let cipher_len = usize::from(u16::from_be_bytes([
                hello[offset],
                hello[offset + 1],
            ]));
            offset += 2 + cipher_len;
            let compression_len = usize::from(hello[offset]);
            offset += 1 + compression_len;
            let extensions_len = usize::from(u16::from_be_bytes([
                hello[offset],
                hello[offset + 1],
            ]));
            offset += 2;
            let end = offset + extensions_len;
            let mut extensions = Vec::new();
            while offset < end {
                let extension =
                    u16::from_be_bytes([hello[offset], hello[offset + 1]]);
                let length = usize::from(u16::from_be_bytes([
                    hello[offset + 2],
                    hello[offset + 3],
                ]));
                extensions.push(extension);
                offset += 4 + length;
            }
            assert_eq!(offset, end);
            extensions
        }

        fn hello_cipher_suites(bytes: &[u8]) -> Vec<u16> {
            assert_eq!(bytes[0], 22);
            let record_len =
                usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
            let hello = &bytes[5..5 + record_len];
            let mut offset = 4 + 2 + 32;
            let session_id_len = usize::from(hello[offset]);
            offset += 1 + session_id_len;
            let cipher_len = usize::from(u16::from_be_bytes([
                hello[offset],
                hello[offset + 1],
            ]));
            offset += 2;
            hello[offset..offset + cipher_len]
                .chunks_exact(2)
                .map(|suite| u16::from_be_bytes([suite[0], suite[1]]))
                .collect()
        }

        fn grease(value: u16) -> bool {
            value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
        }

        let options = OutboundTlsOptions {
            insecure: true,
            utls: Some(OutboundUtlsOptions {
                enabled: true,
                fingerprint: "chrome".into(),
            }),
            ..Default::default()
        };
        let config = build_client_config("dns.example", &options, &[]).unwrap();
        assert!(config.config.client_hello_customizer.is_some());

        let mut observed_orders = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let mut connection = ClientConnection::new(
                config.config.clone(),
                config.server_name.clone(),
            )
            .unwrap();
            let mut first_flight = Vec::new();
            connection.write_tls(&mut first_flight).unwrap();
            let advertised_suites = hello_cipher_suites(&first_flight);
            assert!(
                advertised_suites.contains(&0xc013),
                "unimplemented legacy suites remain on the fingerprint wire"
            );
            let extensions = hello_extensions(&first_flight);
            assert!(grease(extensions[0]));
            assert!(grease(*extensions.last().unwrap()));
            observed_orders.insert(
                extensions
                    .into_iter()
                    .filter(|extension| !grease(*extension))
                    .collect::<Vec<_>>(),
            );
        }
        assert!(
            observed_orders.len() > 1,
            "Chrome 133 extension order must be shuffled per connection"
        );

        for fingerprint in [
            "firefox",
            "edge",
            "safari",
            "qq",
            "ios",
            "android",
            "random",
            "randomized",
        ] {
            let options = OutboundTlsOptions {
                insecure: true,
                utls: Some(OutboundUtlsOptions {
                    enabled: true,
                    fingerprint: fingerprint.into(),
                }),
                ..Default::default()
            };
            let config = build_client_config("dns.example", &options, &[])
                .unwrap_or_else(|error| {
                    panic!("{fingerprint} config failed: {error}")
                });
            let mut connection =
                ClientConnection::new(config.config, config.server_name)
                    .unwrap_or_else(|error| {
                        panic!("{fingerprint} ClientHello failed: {error}")
                    });
            let mut first_flight = Vec::new();
            connection.write_tls(&mut first_flight).unwrap();
            assert_eq!(first_flight[0], 22, "{fingerprint}");
        }

        let unnegotiable = OutboundTlsOptions {
            utls: Some(OutboundUtlsOptions {
                enabled: true,
                fingerprint: "360".into(),
            }),
            ..Default::default()
        };
        let error = match build_client_config("dns.example", &unnegotiable, &[])
        {
            Ok(_) => panic!("unnegotiable uTLS fingerprint was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("cipher suite"));
    }

    #[tokio::test]
    async fn reality_client_emits_authenticated_hello_and_completes_tls13() {
        let server_private_key = [0x31; 32];
        let server_public_key =
            x25519(server_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let options = OutboundTlsOptions {
            utls: Some(OutboundUtlsOptions {
                enabled: true,
                fingerprint: "chrome".into(),
            }),
            reality: Some(OutboundRealityOptions {
                enabled: true,
                public_key: URL_SAFE_NO_PAD.encode(server_public_key),
                short_id: "01020304".into(),
            }),
            ..Default::default()
        };
        let client =
            build_client_config("reality.example", &options, &[]).unwrap();
        let (client_io, mut server_io) = tokio::io::duplex(128 * 1024);
        let client_task = tokio::spawn(async move {
            TlsConnector::from(client.config)
                .connect(client.server_name, client_io)
                .await
        });

        let mut record_header = [0; 5];
        server_io.read_exact(&mut record_header).await.unwrap();
        assert_eq!(record_header[0], 22);
        let record_len = usize::from(u16::from_be_bytes([
            record_header[3],
            record_header[4],
        ]));
        let mut handshake = vec![0; record_len];
        server_io.read_exact(&mut handshake).await.unwrap();
        let hello = parse_reality_client_hello(&handshake).unwrap();
        let auth_key = derive_reality_auth_key_from_x25519(
            server_private_key,
            hello.x25519_public_key,
            &hello.random,
        )
        .unwrap();
        let metadata = open_reality_session_id(
            &auth_key,
            &hello.random,
            hello.session_id_offset,
            &mut handshake.clone(),
        )
        .unwrap();
        assert_eq!(metadata.version, REALITY_PROTOCOL_VERSION);
        assert_eq!(&metadata.short_id[..4], &[1, 2, 3, 4]);
        assert_eq!(&metadata.short_id[4..], &[0; 4]);

        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let certificate =
            CertificateParams::new(vec!["reality.example".to_owned()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
        let mut certificate_der = certificate.der().to_vec();
        let mut mac =
            <hmac13::Hmac<Sha512> as hmac13::KeyInit>::new_from_slice(
                &auth_key,
            )
            .unwrap();
        mac.update(key.public_key_raw());
        let binding = mac.finalize().into_bytes();
        let signature_offset = certificate_der.len() - binding.len();
        certificate_der[signature_offset..].copy_from_slice(&binding);

        let provider = crypto_provider(&[], &[]).unwrap();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )))
            .unwrap();
        let certified_key = RustlsCertifiedKey::new(
            vec![CertificateDer::from(certificate_der)],
            Arc::new(RealitySigningKey(signing_key)),
        );
        let server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(
                certified_key,
            )));
        let mut prefix = record_header.to_vec();
        prefix.extend_from_slice(&handshake);
        let server_io = replay_stream(Box::new(server_io), prefix);
        let mut server_stream = TlsAcceptor::from(Arc::new(server))
            .accept(server_io)
            .await
            .unwrap();
        let mut client_stream = client_task.await.unwrap().unwrap();
        client_stream.write_all(b"reality-ok").await.unwrap();
        let mut payload = [0; 10];
        server_stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"reality-ok");
    }

    async fn run_reality_server_with_cover_record_lens(
        cover_record_lens: Vec<usize>,
    ) -> Vec<u8> {
        let (cover_address, cover_task) =
            spawn_reality_cover_stub_with_record_lens(cover_record_lens).await;
        let server_private_key = [0x31; 32];
        let server_public_key =
            x25519(server_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled": true,
            "server_name": "reality.example",
            "reality": {
                "enabled": true,
                "private_key": URL_SAFE_NO_PAD.encode(server_private_key),
                "short_id": ["01020304"],
                "handshake": {
                    "server": cover_address.ip().to_string(),
                    "server_port": cover_address.port()
                }
            }
        }))
        .unwrap();
        let server = build_server_config_with_default_alpn_and_reality_dialer(
            &server_options,
            &[],
            Some(Arc::new(DirectOutbound::new(
                DirectOutboundOptions::default(),
            ))),
        )
        .unwrap();
        let client = build_client_config(
            "reality.example",
            &OutboundTlsOptions {
                utls: Some(OutboundUtlsOptions {
                    enabled: true,
                    fingerprint: "chrome".into(),
                }),
                reality: Some(OutboundRealityOptions {
                    enabled: true,
                    public_key: URL_SAFE_NO_PAD.encode(server_public_key),
                    short_id: "01020304".into(),
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server_writes = Arc::new(Mutex::new(Vec::new()));
        let recorded_server_writes = server_writes.clone();
        let server_task = tokio::spawn(async move {
            let server_io = RecordingIo {
                inner: server_io,
                writes: recorded_server_writes,
            };
            let mut stream =
                server.accept_stream(Box::new(server_io)).await.unwrap();
            let mut payload = [0; 13];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"reality-round");
            stream.write_all(b"trip").await.unwrap();
        });
        let mut client_stream = TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        assert_eq!(
            client_stream
                .get_ref()
                .1
                .negotiated_cipher_suite()
                .unwrap()
                .suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
        client_stream.write_all(b"reality-round").await.unwrap();
        let mut response = [0; 4];
        client_stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"trip");
        drop(client_stream);
        server_task.await.unwrap();
        cover_task.await.unwrap();
        server_writes.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn reality_server_authenticates_client_and_carries_application_data()
    {
        let server_writes =
            run_reality_server_with_cover_record_lens(vec![1_205]).await;
        let (random, cipher, extension_order) =
            server_hello_shape(&server_writes);
        assert_eq!(random, [0x42; 32]);
        assert_eq!(cipher, 0x1303);
        assert_eq!(extension_order, [43, 51]);
        assert_eq!(first_record_total_len(&server_writes, 23), 1_205);
    }

    #[tokio::test]
    async fn reality_server_mirrors_split_cover_handshake_record_lengths() {
        let expected = vec![500, 4_000, 500, 500, 300];
        let server_writes =
            run_reality_server_with_cover_record_lens(expected.clone()).await;
        let application_records = record_total_lens(&server_writes, 23);
        assert!(application_records.len() >= expected.len());
        assert_eq!(&application_records[..expected.len()], expected);
    }

    #[tokio::test]
    async fn reality_server_forwards_unauthenticated_connection_to_cover() {
        let cover = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_address = cover.local_addr().unwrap();
        let cover_task = tokio::spawn(async move {
            let (mut stream, _) = cover.accept().await.unwrap();
            let mut request = [0; 18];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"GET / HTTP/1.0\r\n\r\n");
            stream.write_all(b"cover-ok").await.unwrap();
        });
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled": true,
            "server_name": "reality.example",
            "reality": {
                "enabled": true,
                "private_key": URL_SAFE_NO_PAD.encode([0x31; 32]),
                "short_id": ["01020304"],
                "handshake": {
                    "server": cover_address.ip().to_string(),
                    "server_port": cover_address.port()
                }
            }
        }))
        .unwrap();
        let server = build_server_config_with_default_alpn_and_reality_dialer(
            &server_options,
            &[],
            Some(Arc::new(DirectOutbound::new(
                DirectOutboundOptions::default(),
            ))),
        )
        .unwrap();
        let (mut client_io, server_io) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            match server.accept_stream(Box::new(server_io)).await {
                Ok(_) => panic!("unauthenticated REALITY connection accepted"),
                Err(error) => error,
            }
        });
        client_io
            .write_all(b"GET / HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        client_io.shutdown().await.unwrap();
        let mut response = Vec::new();
        client_io.read_to_end(&mut response).await.unwrap();
        assert_eq!(&response, b"cover-ok");
        assert_eq!(
            server_task.await.unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        cover_task.await.unwrap();
    }

    #[tokio::test]
    async fn reality_server_falls_back_when_cover_server_hello_is_invalid() {
        let cover = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_address = cover.local_addr().unwrap();
        let cover_task = tokio::spawn(async move {
            let (mut stream, _) = cover.accept().await.unwrap();
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            let length =
                usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let private_key = [0x31; 32];
        let public_key =
            x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled": true,
            "server_name": "reality.example",
            "reality": {
                "enabled": true,
                "private_key": URL_SAFE_NO_PAD.encode(private_key),
                "short_id": ["01020304"],
                "handshake": {
                    "server": cover_address.ip().to_string(),
                    "server_port": cover_address.port()
                }
            }
        }))
        .unwrap();
        let server = build_server_config_with_default_alpn_and_reality_dialer(
            &options,
            &[],
            Some(Arc::new(DirectOutbound::new(
                DirectOutboundOptions::default(),
            ))),
        )
        .unwrap();
        let client = build_client_config(
            "reality.example",
            &OutboundTlsOptions {
                utls: Some(OutboundUtlsOptions {
                    enabled: true,
                    fingerprint: "chrome".into(),
                }),
                reality: Some(OutboundRealityOptions {
                    enabled: true,
                    public_key: URL_SAFE_NO_PAD.encode(public_key),
                    short_id: "01020304".into(),
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            server.accept_stream(Box::new(server_io)).await
        });
        let client_result = TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await;
        assert!(client_result.is_err());
        assert!(server_task.await.unwrap().is_err());
        cover_task.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires the pinned Go sing-box toolchain"]
    async fn reality_server_interoperates_with_pinned_go_client() {
        let (cover_address, cover_task) = spawn_reality_cover_stub().await;
        let private_key = [0x31; 32];
        let public_key =
            x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled": true,
            "server_name": "reality.example",
            "reality": {
                "enabled": true,
                "private_key": URL_SAFE_NO_PAD.encode(private_key),
                "short_id": ["01020304"],
                "handshake": {
                    "server": cover_address.ip().to_string(),
                    "server_port": cover_address.port()
                }
            }
        }))
        .unwrap();
        let server = build_server_config_with_default_alpn_and_reality_dialer(
            &options,
            &[],
            Some(Arc::new(DirectOutbound::new(
                DirectOutboundOptions::default(),
            ))),
        )
        .unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream =
                server.accept_stream(Box::new(stream)).await.unwrap();
            let mut payload = [0; 15];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"go-reality-rust");
            stream.write_all(&payload).await.unwrap();
        });
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.join("../..");
        let sing_box = workspace.join("inner/sing-box");
        let fixture = manifest.join("tests/fixtures/reality-go-client/main.go");
        let public_key = URL_SAFE_NO_PAD.encode(public_key);
        let status = tokio::task::spawn_blocking(move || {
            std::process::Command::new("go")
                .args(["run", "-tags", "with_utls", fixture.to_str().unwrap()])
                .current_dir(sing_box)
                .env("SINGBOX_REALITY_RUST_SERVER", address.to_string())
                .env("SINGBOX_REALITY_PUBLIC_KEY", public_key)
                .status()
        })
        .await
        .unwrap()
        .unwrap();
        assert!(status.success());
        server_task.await.unwrap();
        cover_task.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires the pinned Go REALITY interoperability server"]
    async fn reality_client_interoperates_with_pinned_go_server() {
        let address = std::env::var("SINGBOX_REALITY_GO_SERVER")
            .expect("SINGBOX_REALITY_GO_SERVER must contain host:port");
        let server_private_key = [0x31; 32];
        let server_public_key =
            x25519(server_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let client = build_client_config(
            "reality.example",
            &OutboundTlsOptions {
                utls: Some(OutboundUtlsOptions {
                    enabled: true,
                    fingerprint: "chrome".into(),
                }),
                reality: Some(OutboundRealityOptions {
                    enabled: true,
                    public_key: URL_SAFE_NO_PAD.encode(server_public_key),
                    short_id: "01020304".into(),
                }),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let io = TcpStream::connect(address).await.unwrap();
        let mut stream = TlsConnector::from(client.config)
            .connect(client.server_name, io)
            .await
            .unwrap();
        stream.write_all(b"rust-reality-go").await.unwrap();
        let mut response = [0; 15];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"rust-reality-go");
    }

    #[test]
    fn constrains_supported_tls_versions() {
        let tls12 = protocol_versions("1.2", "1.2").unwrap();
        assert_eq!(tls12, [&rustls::version::TLS12]);
        let tls13 = protocol_versions("1.3", "").unwrap();
        assert_eq!(tls13, [&rustls::version::TLS13]);
        assert!(protocol_versions("1.3", "1.2").is_err());
        assert!(protocol_versions("1.1", "1.3").is_err());
    }

    #[tokio::test]
    async fn legacy_tls_versions_interoperate_through_library_stream_api() {
        for (version_name, version) in [
            ("1.0", openssl::ssl::SslVersion::TLS1),
            ("1.1", openssl::ssl::SslVersion::TLS1_1),
        ] {
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let acceptor = legacy_openssl_acceptor(
                &cert.pem(),
                &key_pair.serialize_pem(),
                version,
            );

            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let server_task = tokio::spawn(async move {
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut stream =
                    tokio_openssl::SslStream::new(ssl, server_io).unwrap();
                Pin::new(&mut stream).accept().await.unwrap();
                let negotiated = stream.ssl().version_str().to_owned();
                stream.write_all(b"legacy").await.unwrap();
                negotiated
            });
            let client = build_client_config(
                "localhost",
                &OutboundTlsOptions {
                    insecure: true,
                    min_version: version_name.into(),
                    max_version: version_name.into(),
                    ..Default::default()
                },
                &[],
            )
            .unwrap();
            assert!(matches!(
                client.backend,
                super::ClientTlsBackend::OpenSsl(_)
            ));
            let mut stream =
                client.connect_stream(Box::new(client_io)).await.unwrap();
            assert!(!stream.peer_certificates().is_empty());
            let mut exporter = [0_u8; 32];
            stream
                .export_keying_material(
                    &mut exporter,
                    b"EXPORTER-singbox-legacy-test",
                    None,
                )
                .unwrap();
            assert_ne!(exporter, [0_u8; 32]);
            let mut response = [0_u8; 6];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"legacy");
            let negotiated = server_task.await.unwrap();
            assert_eq!(
                negotiated,
                if version_name == "1.0" {
                    "TLSv1"
                } else {
                    "TLSv1.1"
                }
            );
        }
    }

    #[tokio::test]
    async fn legacy_tls_honors_custom_roots_and_spki_pins() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let certificate =
            openssl::x509::X509::from_pem(certificate_pem.as_bytes()).unwrap();
        let public_key = certificate
            .public_key()
            .unwrap()
            .public_key_to_der()
            .unwrap();
        let spki_pin = Sha256::digest(public_key).to_vec();

        for (endpoint_host, mut options) in [
            (
                "localhost",
                OutboundTlsOptions {
                    certificate: Listable(vec![certificate_pem.clone()]),
                    ..Default::default()
                },
            ),
            (
                "name-deliberately-does-not-match.example",
                OutboundTlsOptions {
                    certificate_public_key_sha256: Listable(vec![Base64Bytes(
                        spki_pin.clone(),
                    )]),
                    ..Default::default()
                },
            ),
        ] {
            options.min_version = "1.1".into();
            options.max_version = "1.1".into();
            let acceptor = legacy_openssl_acceptor(
                &certificate_pem,
                &key_pem,
                openssl::ssl::SslVersion::TLS1_1,
            );
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let server_task = tokio::spawn(async move {
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut stream =
                    tokio_openssl::SslStream::new(ssl, server_io).unwrap();
                Pin::new(&mut stream).accept().await.unwrap();
                stream.write_all(b"trusted").await.unwrap();
            });
            let client =
                build_client_config(endpoint_host, &options, &[]).unwrap();
            let mut stream =
                client.connect_stream(Box::new(client_io)).await.unwrap();
            let mut response = [0_u8; 7];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"trusted");
            server_task.await.unwrap();
        }
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn apple_system_tls_interoperates_over_existing_tcp_stream() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_pem = cert.pem();
        let certificate =
            openssl::x509::X509::from_pem(certificate_pem.as_bytes()).unwrap();
        let public_key = certificate
            .public_key()
            .unwrap()
            .public_key_to_der()
            .unwrap();
        let spki_pin = Sha256::digest(public_key).to_vec();
        let server = build_server_config_with_default_alpn(
            &InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![certificate_pem.clone()]),
                key: Listable(vec![key_pair.serialize_pem()]),
                min_version: "1.2".into(),
                max_version: "1.2".into(),
                ..Default::default()
            },
            &["h2"],
        )
        .unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (transport, _) = listener.accept().await.unwrap();
                let mut stream = TlsAcceptor::from(server.config.clone())
                    .accept(transport)
                    .await
                    .unwrap();
                let mut request = [0_u8; 5];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"apple");
                stream.write_all(b"native").await.unwrap();
            }
        });

        for (endpoint_host, options) in [
            (
                "localhost",
                OutboundTlsOptions {
                    engine: "apple".into(),
                    certificate: Listable(vec![certificate_pem.clone()]),
                    min_version: "1.2".into(),
                    max_version: "1.2".into(),
                    alpn: Listable(vec!["h2".into()]),
                    ..Default::default()
                },
            ),
            (
                "deliberately-mismatched.example",
                OutboundTlsOptions {
                    engine: "apple".into(),
                    certificate_public_key_sha256: Listable(vec![Base64Bytes(
                        spki_pin.clone(),
                    )]),
                    min_version: "1.2".into(),
                    max_version: "1.2".into(),
                    alpn: Listable(vec!["h2".into()]),
                    ..Default::default()
                },
            ),
        ] {
            let client =
                build_client_config(endpoint_host, &options, &[]).unwrap();
            assert!(matches!(
                client.backend,
                super::ClientTlsBackend::Apple(_)
            ));
            let transport = TcpStream::connect(address).await.unwrap();
            let mut stream = client
                .connect_stream_with_timeout(
                    Box::new(transport),
                    Some(Duration::from_secs(5)),
                )
                .await
                .unwrap();
            assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]));
            assert!(!stream.peer_certificates().is_empty());
            stream.write_all(b"apple").await.unwrap();
            let mut response = [0_u8; 6];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"native");
        }
        server_task.await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_system_tls_interoperates_over_existing_stream() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_pem = cert.pem();
        let certificate =
            openssl::x509::X509::from_pem(certificate_pem.as_bytes()).unwrap();
        let spki_pin = Sha256::digest(
            certificate
                .public_key()
                .unwrap()
                .public_key_to_der()
                .unwrap(),
        )
        .to_vec();
        let server = build_server_config_with_default_alpn(
            &InboundTlsOptions {
                enabled: true,
                certificate: Listable(vec![certificate_pem.clone()]),
                key: Listable(vec![key_pair.serialize_pem()]),
                min_version: "1.2".into(),
                max_version: "1.2".into(),
                ..Default::default()
            },
            &["h2"],
        )
        .unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (transport, _) = listener.accept().await.unwrap();
                let mut stream = TlsAcceptor::from(server.config.clone())
                    .accept(transport)
                    .await
                    .unwrap();
                let mut request = [0_u8; 7];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"windows");
                stream.write_all(b"schannel").await.unwrap();
            }
        });

        for (endpoint_host, options) in [
            (
                "localhost",
                OutboundTlsOptions {
                    engine: "windows".into(),
                    certificate: Listable(vec![certificate_pem.clone()]),
                    min_version: "1.2".into(),
                    max_version: "1.2".into(),
                    alpn: Listable(vec!["h2".into()]),
                    ..Default::default()
                },
            ),
            (
                "deliberately-mismatched.example",
                OutboundTlsOptions {
                    engine: "windows".into(),
                    certificate_public_key_sha256: Listable(vec![Base64Bytes(
                        spki_pin.clone(),
                    )]),
                    min_version: "1.2".into(),
                    max_version: "1.2".into(),
                    alpn: Listable(vec!["h2".into()]),
                    ..Default::default()
                },
            ),
        ] {
            let client =
                build_client_config(endpoint_host, &options, &[]).unwrap();
            assert!(matches!(
                client.backend,
                super::ClientTlsBackend::Windows(_)
            ));
            let transport = TcpStream::connect(address).await.unwrap();
            let mut stream = client
                .connect_stream_with_timeout(
                    Box::new(transport),
                    Some(Duration::from_secs(5)),
                )
                .await
                .unwrap();
            assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]));
            assert!(!stream.peer_certificates().is_empty());
            stream.write_all(b"windows").await.unwrap();
            let mut response = [0_u8; 8];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"schannel");
        }
        server_task.await.unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_system_tls_rejects_options_unsupported_by_sing_box() {
        for options in [
            OutboundTlsOptions {
                engine: "apple".into(),
                disable_sni: true,
                ..Default::default()
            },
            OutboundTlsOptions {
                engine: "apple".into(),
                fragment: true,
                ..Default::default()
            },
            OutboundTlsOptions {
                engine: "apple".into(),
                cipher_suites: Listable(vec![
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
                ]),
                ..Default::default()
            },
        ] {
            assert!(build_client_config("localhost", &options, &[]).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_system_tls_rejects_options_unsupported_by_sing_box() {
        for options in [
            OutboundTlsOptions {
                engine: "windows".into(),
                disable_sni: true,
                ..Default::default()
            },
            OutboundTlsOptions {
                engine: "windows".into(),
                fragment: true,
                ..Default::default()
            },
            OutboundTlsOptions {
                engine: "windows".into(),
                cipher_suites: Listable(vec![
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
                ]),
                ..Default::default()
            },
        ] {
            assert!(build_client_config("localhost", &options, &[]).is_err());
        }
    }

    #[test]
    fn configures_go_compatible_cipher_suites_and_curves() {
        let defaults = crypto_provider(&[], &[]).unwrap();
        assert_eq!(
            defaults.kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768
        );
        let provider = crypto_provider(
            &[
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
            ],
            &[CurvePreference::P384, CurvePreference::X25519],
        )
        .unwrap();
        let suites: Vec<_> = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect();
        assert_eq!(
            &suites[3..],
            &[
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ]
        );
        let groups: Vec<_> = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert_eq!(
            groups,
            [rustls::NamedGroup::secp384r1, rustls::NamedGroup::X25519]
        );

        assert!(
            crypto_provider(&["TLS_AES_128_GCM_SHA256".into()], &[]).is_err()
        );
        let p521 = crypto_provider(&[], &[CurvePreference::P521]).unwrap();
        assert_eq!(p521.kx_groups[0].name(), rustls::NamedGroup::secp521r1);
        let hybrid =
            crypto_provider(&[], &[CurvePreference::X25519MlKem768]).unwrap();
        assert_eq!(
            hybrid.kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768
        );
    }

    #[tokio::test]
    async fn tls12_cipher_and_curve_constraints_interoperate() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let suite = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_owned();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![cert.pem()]),
            key: Listable(vec![key_pair.serialize_pem()]),
            min_version: "1.2".into(),
            max_version: "1.2".into(),
            cipher_suites: Listable(vec![suite.clone()]),
            curve_preferences: Listable(vec![CurvePreference::P256]),
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                min_version: "1.2".into(),
                max_version: "1.2".into(),
                cipher_suites: Listable(vec![suite]),
                curve_preferences: Listable(vec![CurvePreference::P256]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"v12").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 3];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"v12");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn x25519_mlkem768_tls13_handshake_interoperates() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![cert.pem()]),
            key: Listable(vec![key_pair.serialize_pem()]),
            min_version: "1.3".into(),
            max_version: "1.3".into(),
            curve_preferences: Listable(vec![CurvePreference::X25519MlKem768]),
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                min_version: "1.3".into(),
                max_version: "1.3".into(),
                curve_preferences: Listable(vec![
                    CurvePreference::X25519MlKem768,
                ]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"pq").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pq");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn p521_tls13_handshake_interoperates() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![cert.pem()]),
            key: Listable(vec![key_pair.serialize_pem()]),
            min_version: "1.3".into(),
            max_version: "1.3".into(),
            curve_preferences: Listable(vec![CurvePreference::P521]),
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                min_version: "1.3".into(),
                max_version: "1.3".into(),
                curve_preferences: Listable(vec![CurvePreference::P521]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"p521").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"p521");
        server_task.await.unwrap();
    }

    #[test]
    fn builds_client_certificate_authentication_and_rejects_half_pairs() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let options = OutboundTlsOptions {
            client_certificate: crate::option::Listable(vec![cert.pem()]),
            client_key: crate::option::Listable(vec![key_pair.serialize_pem()]),
            ..Default::default()
        };
        let config = build_client_config("server.test", &options, &[]).unwrap();
        assert!(config.config.client_auth_cert_resolver.has_certs());

        let missing_key = OutboundTlsOptions {
            client_certificate: options.client_certificate,
            ..Default::default()
        };
        assert!(build_client_config("server.test", &missing_key, &[]).is_err());
    }

    #[tokio::test]
    async fn client_and_server_mutual_tls_configs_interoperate() {
        let CertifiedKey {
            cert: server_cert,
            key_pair: server_key,
        } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let CertifiedKey {
            cert: client_cert,
            key_pair: client_key,
        } = generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: crate::option::Listable(vec![server_cert.pem()]),
            key: crate::option::Listable(vec![server_key.serialize_pem()]),
            client_authentication: ClientAuthType::RequireAndVerify,
            client_certificate: crate::option::Listable(vec![
                client_cert.pem(),
            ]),
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                client_certificate: crate::option::Listable(vec![
                    client_cert.pem(),
                ]),
                client_key: crate::option::Listable(vec![
                    client_key.serialize_pem(),
                ]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"ok").await.unwrap();
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn request_client_certificate_allows_anonymous_clients() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![cert.pem()]),
            key: Listable(vec![key_pair.serialize_pem()]),
            client_authentication: ClientAuthType::Request,
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
        });
        let client_result = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await;
        assert!(client_result.is_ok());
        assert!(server_task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn require_any_client_certificate_checks_presence_not_chain() {
        let CertifiedKey {
            cert: server_cert,
            key_pair: server_key,
        } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_options = InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![server_cert.pem()]),
            key: Listable(vec![server_key.serialize_pem()]),
            client_authentication: ClientAuthType::RequireAny,
            ..Default::default()
        };

        let anonymous = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let server = super::build_server_config(&server_options).unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
        });
        let _ = tokio_rustls::TlsConnector::from(anonymous.config)
            .connect(anonymous.server_name, client_io)
            .await;
        assert!(server_task.await.unwrap().is_err());

        let CertifiedKey {
            cert: client_cert,
            key_pair: client_key,
        } = generate_simple_self_signed(vec!["untrusted-client.test".into()])
            .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                client_certificate: Listable(vec![client_cert.pem()]),
                client_key: Listable(vec![client_key.serialize_pem()]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let server = super::build_server_config(&server_options).unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await
        });
        let client_result = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await;
        assert!(client_result.is_ok());
        assert!(server_task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn server_public_key_pin_accepts_only_the_configured_spki() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = super::parse_pem_certificates(cert.pem().as_bytes())
            .unwrap()
            .remove(0);
        let parsed =
            rustls::server::ParsedCertificate::try_from(&certificate).unwrap();
        let pin =
            Sha256::digest(parsed.subject_public_key_info().as_ref()).to_vec();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![cert.pem()]),
            key: Listable(vec![key_pair.serialize_pem()]),
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                certificate_public_key_sha256: Listable(vec![Base64Bytes(pin)]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await?;
            stream.write_all(b"ok").await?;
            Ok::<_, std::io::Error>(())
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        assert!(server_task.await.unwrap().is_ok());

        let conflict = OutboundTlsOptions {
            certificate: Listable(vec![cert.pem()]),
            certificate_public_key_sha256: Listable(vec![Base64Bytes(vec![
                0;
                32
            ])]),
            ..Default::default()
        };
        assert!(build_client_config("localhost", &conflict, &[]).is_err());
    }

    #[test]
    fn legacy_and_abbreviated_certificate_fingerprints_match() {
        use crate::option::{
            ServerCertificateFingerprint, ServerCertificateFingerprintAlgorithm,
        };

        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = super::parse_pem_certificates(cert.pem().as_bytes())
            .unwrap()
            .remove(0);
        let parsed =
            rustls::server::ParsedCertificate::try_from(&certificate).unwrap();
        let spki = parsed.subject_public_key_info();
        let certificate_sha1 =
            hex::encode(sha1_11::Sha1::digest(certificate.as_ref()));
        let spki_sha1 = hex::encode(sha1_11::Sha1::digest(spki.as_ref()));
        let spki_sha256 = Sha256::digest(spki.as_ref());
        let spki_sha256_hex = hex::encode(spki_sha256);
        let spki_sha256_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            spki_sha256,
        );
        let fingerprints = vec![
            ServerCertificateFingerprint {
                algorithm:
                    ServerCertificateFingerprintAlgorithm::CertificateSha1Hex,
                encoded_prefix: certificate_sha1[..8].into(),
            },
            ServerCertificateFingerprint {
                algorithm: ServerCertificateFingerprintAlgorithm::SpkiSha1Hex,
                encoded_prefix: spki_sha1[..8].into(),
            },
            ServerCertificateFingerprint {
                algorithm: ServerCertificateFingerprintAlgorithm::SpkiSha256Hex,
                encoded_prefix: spki_sha256_hex[..8].into(),
            },
            ServerCertificateFingerprint {
                algorithm:
                    ServerCertificateFingerprintAlgorithm::SpkiSha256Base64,
                encoded_prefix: spki_sha256_base64[..8].into(),
            },
        ];
        for fingerprint in fingerprints {
            verify_certificate_fingerprints(&[fingerprint], &certificate)
                .unwrap();
        }
        assert!(
            verify_certificate_fingerprints(
                &[ServerCertificateFingerprint {
                    algorithm:
                        ServerCertificateFingerprintAlgorithm::SpkiSha256Hex,
                    encoded_prefix: "0000".into(),
                }],
                &certificate,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn client_public_key_pin_accepts_an_untrusted_certificate() {
        let CertifiedKey {
            cert: server_cert,
            key_pair: server_key,
        } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let CertifiedKey {
            cert: client_cert,
            key_pair: client_key,
        } = generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let certificate =
            super::parse_pem_certificates(client_cert.pem().as_bytes())
                .unwrap()
                .remove(0);
        let parsed =
            rustls::server::ParsedCertificate::try_from(&certificate).unwrap();
        let pin =
            Sha256::digest(parsed.subject_public_key_info().as_ref()).to_vec();
        let server = super::build_server_config(&InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![server_cert.pem()]),
            key: Listable(vec![server_key.serialize_pem()]),
            client_authentication: ClientAuthType::RequireAndVerify,
            client_certificate_public_key_sha256: Listable(vec![Base64Bytes(
                pin,
            )]),
            ..Default::default()
        })
        .unwrap();
        let client = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                insecure: true,
                client_certificate: Listable(vec![client_cert.pem()]),
                client_key: Listable(vec![client_key.serialize_pem()]),
                ..Default::default()
            },
            &[],
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server.config)
                .accept(server_io)
                .await?;
            stream.write_all(b"ok").await?;
            Ok::<_, std::io::Error>(())
        });
        let mut stream = tokio_rustls::TlsConnector::from(client.config)
            .connect(client.server_name, client_io)
            .await
            .unwrap();
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        assert!(server_task.await.unwrap().is_ok());
    }
}
