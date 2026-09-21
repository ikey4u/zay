//! Live rustls client glue for sing-box REALITY.

use std::{
    collections::VecDeque,
    fmt, io,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac13::Mac as _;
use rand::{RngCore as _, rngs::OsRng};
use rustls::{
    CertificateError, CipherSuite, ClientConfig, DigitallySignedStruct,
    Error as RustlsError, NamedGroup, ServerConfig, SignatureAlgorithm,
    SignatureScheme,
    client::{
        ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan,
        ClientHelloSessionId, FinalizesClientHello, FixedX25519KeyShare,
        danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        },
    },
    crypto::{CryptoProvider, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ResolvesServerCert,
    sign::{CertifiedKey, Signer, SigningKey},
};
use sha2::Sha512;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional};
use tokio_rustls::{TlsAcceptor, server::TlsStream as ServerTlsStream};
use zeroize::Zeroizing;

use super::{
    reality::{
        RealityCertificateVerification, RealityClientParameters,
        RealityServerParameters, derive_reality_auth_key_from_x25519,
        open_reality_session_id, parse_reality_client_hello,
        prepare_reality_client_hello, verify_reality_certificate_der,
    },
    utls::SingBoxUtlsCustomizer,
};
use crate::{
    adapter::{Dialer, Stream, replay_stream},
    common::network::SocksAddr,
};

const MAX_PENDING_AUTH_KEYS: usize = 1_024;
const MAX_CLIENT_HELLO_LEN: usize = 64 * 1024;
const MAX_COVER_RECORD_LEN: usize = 16 * 1024;
const TLS_HANDSHAKE_RECORD: u8 = 22;
const TLS_CHANGE_CIPHER_SPEC_RECORD: u8 = 20;
const TLS_APPLICATION_DATA_RECORD: u8 = 23;
const TLS_SERVER_HELLO: u8 = 2;
const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];
const TLS_VERSION_1_3: [u8; 2] = [0x03, 0x04];
const TLS_EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const TLS_EXTENSION_KEY_SHARE: u16 = 51;
const TLS_GROUP_X25519: u16 = 0x001d;
const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoverServerHello {
    random: [u8; 32],
    cipher_suite: CipherSuite,
    key_share_group: NamedGroup,
    extension_order: Vec<u16>,
    handshake_record_lens: Option<Vec<usize>>,
}

#[derive(Debug, Default)]
struct RealityAuthState {
    pending: Mutex<VecDeque<Zeroizing<[u8; 32]>>>,
}

impl RealityAuthState {
    fn push(&self, key: [u8; 32]) -> Result<(), RustlsError> {
        let mut pending = self.pending.lock().map_err(|_| {
            RustlsError::General("REALITY auth state lock was poisoned".into())
        })?;
        if pending.len() == MAX_PENDING_AUTH_KEYS {
            pending.pop_front();
        }
        pending.push_back(Zeroizing::new(key));
        Ok(())
    }

    fn verify_and_remove(
        &self,
        certificate: &[u8],
    ) -> Result<bool, RustlsError> {
        let mut pending = self.pending.lock().map_err(|_| {
            RustlsError::General("REALITY auth state lock was poisoned".into())
        })?;
        let mut matched = None;
        for (index, key) in pending.iter().enumerate() {
            match verify_reality_certificate_der(key, certificate) {
                Ok(RealityCertificateVerification::Verified) => {
                    matched = Some(index);
                    break;
                }
                Ok(RealityCertificateVerification::NotReality) => {}
                Err(_) => {
                    return Err(RustlsError::InvalidCertificate(
                        CertificateError::BadEncoding,
                    ));
                }
            }
        }
        if let Some(index) = matched {
            pending.remove(index);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct RealityClientHelloCustomizer {
    utls: Arc<SingBoxUtlsCustomizer>,
    parameters: RealityClientParameters,
    state: Arc<RealityAuthState>,
}

impl fmt::Debug for RealityClientHelloCustomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityClientHelloCustomizer")
            .field("utls", &self.utls)
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

impl ClientHelloCustomizer for RealityClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        if context.is_quic {
            return Err(RustlsError::General(
                "REALITY is unavailable for QUIC TLS".into(),
            ));
        }
        let mut hello_random = [0; 32];
        let mut private_key = [0; 32];
        OsRng.try_fill_bytes(&mut hello_random).map_err(|error| {
            RustlsError::General(format!(
                "REALITY ClientHello random generation failed: {error}"
            ))
        })?;
        OsRng.try_fill_bytes(&mut private_key).map_err(|error| {
            RustlsError::General(format!(
                "REALITY X25519 key generation failed: {error}"
            ))
        })?;
        let finalizer = Arc::new(RealityClientHelloFinalizer {
            private_key: Zeroizing::new(private_key),
            parameters: self.parameters.clone(),
            state: self.state.clone(),
        });
        let plan = self
            .utls
            .build_reality_plan(context)?
            .with_random(hello_random)
            .with_session_id(ClientHelloSessionId::try_from(vec![0; 32])?)
            .with_fixed_x25519(FixedX25519KeyShare::new(private_key))
            .with_finalizer(finalizer);
        Ok(Some(plan))
    }
}

struct RealityClientHelloFinalizer {
    private_key: Zeroizing<[u8; 32]>,
    parameters: RealityClientParameters,
    state: Arc<RealityAuthState>,
}

impl fmt::Debug for RealityClientHelloFinalizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityClientHelloFinalizer")
            .field("private_key", &"<redacted>")
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

impl FinalizesClientHello for RealityClientHelloFinalizer {
    fn finalize_client_hello(
        &self,
        bytes: &mut Vec<u8>,
    ) -> Result<(), RustlsError> {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let prepared = prepare_reality_client_hello(
            *self.private_key,
            &self.parameters,
            unix_time,
            bytes.clone(),
        )
        .map_err(|error| {
            RustlsError::General(format!(
                "REALITY ClientHello finalization failed: {error}"
            ))
        })?;
        if prepared.client_hello.len() != bytes.len() {
            return Err(RustlsError::General(
                "REALITY ClientHello finalizer changed its length".into(),
            ));
        }
        bytes.copy_from_slice(&prepared.client_hello);
        self.state.push(prepared.auth_key)
    }
}

struct RealityServerVerifier {
    state: Arc<RealityAuthState>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for RealityServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityServerVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RealityServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if self.state.verify_and_remove(end_entity.as_ref())? {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
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

pub(crate) fn install_reality_client(
    config: &mut ClientConfig,
    utls: Arc<SingBoxUtlsCustomizer>,
    public_key: &str,
    short_id: &str,
    provider: Arc<CryptoProvider>,
) -> Result<(), String> {
    let parameters = RealityClientParameters::parse(public_key, short_id)
        .map_err(|error| error.to_string())?;
    let state = Arc::new(RealityAuthState::default());
    config.resumption = rustls::client::Resumption::disabled();
    config.reality_dummy_ticket_compatibility = true;
    config.client_hello_customizer =
        Some(Arc::new(RealityClientHelloCustomizer {
            utls,
            parameters,
            state: state.clone(),
        }));
    config.dangerous().set_certificate_verifier(Arc::new(
        RealityServerVerifier { state, provider },
    ));
    Ok(())
}

#[derive(Clone)]
pub(crate) struct RealityServerRuntime {
    parameters: RealityServerParameters,
    server_name: String,
    destination: SocksAddr,
    dialer: Arc<dyn Dialer>,
    identity: Arc<RealityServerIdentity>,
}

impl fmt::Debug for RealityServerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityServerRuntime")
            .field("parameters", &self.parameters)
            .field("server_name", &self.server_name)
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

struct RealityServerIdentity {
    certificate: Vec<u8>,
    public_key: [u8; 32],
    signing_key: Arc<dyn SigningKey>,
}

impl fmt::Debug for RealityServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityServerIdentity")
            .field("certificate_len", &self.certificate.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct RealitySigningKey(Arc<dyn SigningKey>);

impl SigningKey for RealitySigningKey {
    fn choose_scheme(
        &self,
        _offered: &[SignatureScheme],
    ) -> Option<Box<dyn Signer>> {
        self.0.choose_scheme(&[SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

#[derive(Debug)]
struct RealityCertificateResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for RealityCertificateResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl RealityServerRuntime {
    pub(crate) fn new(
        private_key: &str,
        short_ids: &[String],
        max_time_difference: std::time::Duration,
        server_name: String,
        destination: SocksAddr,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, String> {
        let parameters = RealityServerParameters::parse(
            private_key,
            short_ids,
            max_time_difference,
        )
        .map_err(|error| error.to_string())?;
        let identity = Arc::new(RealityServerIdentity::generate()?);
        Ok(Self {
            parameters,
            server_name,
            destination,
            dialer,
            identity,
        })
    }

    pub(crate) fn placeholder_resolver(&self) -> Arc<dyn ResolvesServerCert> {
        self.certificate_resolver(&[0; 32])
    }

    fn certificate_resolver(
        &self,
        auth_key: &[u8; 32],
    ) -> Arc<dyn ResolvesServerCert> {
        let mut certificate = self.identity.certificate.clone();
        let mut mac =
            <hmac13::Hmac<Sha512> as hmac13::KeyInit>::new_from_slice(auth_key)
                .expect("HMAC accepts every key length");
        mac.update(&self.identity.public_key);
        let binding = mac.finalize().into_bytes();
        let offset = certificate.len() - binding.len();
        certificate[offset..].copy_from_slice(&binding);
        let key =
            Arc::new(RealitySigningKey(self.identity.signing_key.clone()));
        Arc::new(RealityCertificateResolver(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(certificate)],
            key,
        ))))
    }

    pub(crate) async fn accept(
        &self,
        mut stream: Stream,
        base_config: Arc<ServerConfig>,
    ) -> io::Result<ServerTlsStream<Stream>> {
        // Pinned REALITY opens the cover connection before inspecting the
        // ClientHello. This keeps invalid clients indistinguishable from a
        // direct connection even when the cover is unavailable or slow.
        let mut target = self.dialer.dial_tcp(&self.destination).await?;
        let mut prefix = Vec::new();
        let client_hello = read_client_hello(&mut stream, &mut prefix).await;
        let authenticated = client_hello
            .as_deref()
            .and_then(|hello| self.authenticate(hello).ok());

        // The pinned Go implementation mirrors every byte consumed from the
        // client into the cover connection. Sending the complete pre-read
        // prefix here preserves the same cover transcript without coupling
        // authentication to socket read boundaries.
        target.write_all(&prefix).await?;

        let Some(auth_key) = authenticated else {
            let relay_result =
                copy_bidirectional(&mut stream, &mut target).await;
            let _ = stream.shutdown().await;
            let _ = target.shutdown().await;
            return match relay_result {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "REALITY forwarded an unauthenticated connection",
                )),
                Err(error) => Err(error),
            };
        };

        // REALITY only accepts an authenticated client when the configured
        // cover also produces a valid TLS 1.3 ServerHello for the same
        // ClientHello.  Its random is part of the observable cover identity,
        // so feed it into the narrow rustls compatibility hook.  The remaining
        // encrypted-record length mirror is layered on this preflight.
        let mut cover_prefix = Vec::new();
        let cover_hello = match read_cover_server_hello(
            &mut target,
            &mut cover_prefix,
        )
        .await
        {
            Ok(hello) => hello,
            Err(_) => {
                stream.write_all(&cover_prefix).await?;
                let relay_result =
                    copy_bidirectional(&mut stream, &mut target).await;
                let _ = stream.shutdown().await;
                let _ = target.shutdown().await;
                return match relay_result {
                    Ok(_) => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "REALITY cover did not produce a valid TLS 1.3 ServerHello",
                    )),
                    Err(error) => Err(error),
                };
            }
        };
        drop(target);

        let mut config = (*base_config).clone();
        config.cert_resolver = self.certificate_resolver(&auth_key);
        config.send_tls13_tickets = 0;
        config.reality_server_random = Some(cover_hello.random);
        config.reality_cipher_suite = Some(cover_hello.cipher_suite);
        config.reality_key_exchange_group = Some(cover_hello.key_share_group);
        config.reality_server_extension_order =
            Some(cover_hello.extension_order);
        config.reality_handshake_record_lens =
            cover_hello.handshake_record_lens;
        let stream = replay_stream(stream, prefix);
        TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .map_err(io::Error::other)
    }

    fn authenticate(&self, client_hello: &[u8]) -> Result<[u8; 32], String> {
        let hello = parse_reality_client_hello(client_hello)
            .map_err(|error| error.to_string())?;
        if hello.server_name != self.server_name {
            return Err("REALITY server name is not allowed".into());
        }
        let auth_key = derive_reality_auth_key_from_x25519(
            self.parameters.private_key,
            hello.x25519_public_key,
            &hello.random,
        )
        .map_err(|error| error.to_string())?;
        let mut client_hello = client_hello.to_vec();
        let metadata = open_reality_session_id(
            &auth_key,
            &hello.random,
            hello.session_id_offset,
            &mut client_hello,
        )
        .map_err(|error| error.to_string())?;
        self.parameters
            .validate_metadata(&metadata, SystemTime::now())
            .map_err(|error| error.to_string())?;
        Ok(auth_key)
    }
}

async fn read_cover_server_hello(
    stream: &mut Stream,
    saved: &mut Vec<u8>,
) -> io::Result<CoverServerHello> {
    let mut header = [0; 5];
    read_exact_saving(stream, &mut header, saved).await?;
    if header[0] != TLS_HANDSHAKE_RECORD || header[1..3] != TLS_VERSION_1_2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover returned a non-TLS-1.3 ServerHello record",
        ));
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 || length > MAX_COVER_RECORD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover ServerHello record has an invalid length",
        ));
    }
    let mut payload = vec![0; length];
    read_exact_saving(stream, &mut payload, saved).await?;
    let mut hello = parse_cover_server_hello(&payload)?;
    hello.handshake_record_lens =
        read_cover_handshake_record_lens(stream, saved).await?;
    Ok(hello)
}

async fn read_cover_handshake_record_lens(
    stream: &mut Stream,
    saved: &mut Vec<u8>,
) -> io::Result<Option<Vec<usize>>> {
    for _ in 0..8 {
        let (content_type, payload) = read_cover_record(stream, saved).await?;
        match content_type {
            TLS_CHANGE_CIPHER_SPEC_RECORD if payload == [1] => continue,
            TLS_APPLICATION_DATA_RECORD => {
                let total_len = 5 + payload.len();
                if total_len > 512 {
                    return Ok(Some(vec![total_len]));
                }

                // With a small first encrypted record, pinned Go treats the
                // next three application-data records as Certificate,
                // CertificateVerify and Finished, then mirrors four records.
                let mut record_lens = vec![total_len];
                for _ in 0..3 {
                    let (content_type, payload) =
                        read_cover_record(stream, saved).await?;
                    if content_type != TLS_APPLICATION_DATA_RECORD {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "REALITY cover split handshake has an invalid record type",
                        ));
                    }
                    record_lens.push(5 + payload.len());
                }
                if let Some((content_type, payload)) =
                    try_read_cover_record(stream, saved).await?
                {
                    if content_type != TLS_APPLICATION_DATA_RECORD {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "REALITY cover ticket has an invalid record type",
                        ));
                    }
                    record_lens.push(5 + payload.len());
                }
                return Ok(Some(record_lens));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "REALITY cover returned an invalid post-ServerHello flight",
                ));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "REALITY cover sent too many records before its encrypted handshake",
    ))
}

async fn read_cover_record(
    stream: &mut Stream,
    saved: &mut Vec<u8>,
) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    read_exact_saving(stream, &mut header, saved).await?;
    read_cover_record_payload(stream, saved, header).await
}

async fn try_read_cover_record(
    stream: &mut Stream,
    saved: &mut Vec<u8>,
) -> io::Result<Option<(u8, Vec<u8>)>> {
    match tokio::time::timeout(
        Duration::from_millis(5),
        read_cover_record(stream, saved),
    )
    .await
    {
        Ok(result) => result.map(Some),
        Err(_) => Ok(None),
    }
}

async fn read_cover_record_payload(
    stream: &mut Stream,
    saved: &mut Vec<u8>,
    header: [u8; 5],
) -> io::Result<(u8, Vec<u8>)> {
    if header[1..3] != TLS_VERSION_1_2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover returned an invalid TLS 1.3 record version",
        ));
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 || length > MAX_COVER_RECORD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover returned an invalid handshake record length",
        ));
    }
    let mut payload = vec![0; length];
    read_exact_saving(stream, &mut payload, saved).await?;
    Ok((header[0], payload))
}

async fn read_exact_saving(
    stream: &mut Stream,
    buffer: &mut [u8],
    saved: &mut Vec<u8>,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        let read = stream.read(&mut buffer[offset..]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before the REALITY probe completed",
            ));
        }
        saved.extend_from_slice(&buffer[offset..offset + read]);
        offset += read;
    }
    Ok(())
}

fn parse_cover_server_hello(payload: &[u8]) -> io::Result<CoverServerHello> {
    if payload.len() < 4 || payload[0] != TLS_SERVER_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover response is not a ServerHello",
        ));
    }
    let handshake_length = (usize::from(payload[1]) << 16)
        | (usize::from(payload[2]) << 8)
        | usize::from(payload[3]);
    if handshake_length.checked_add(4) != Some(payload.len())
        || payload.len() < 4 + 2 + 32 + 1 + 2 + 1 + 2
        || payload[4..6] != TLS_VERSION_1_2
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover returned a malformed ServerHello",
        ));
    }

    let random: [u8; 32] = payload[6..38]
        .try_into()
        .expect("validated ServerHello random length");
    let session_id_length = usize::from(payload[38]);
    let mut offset =
        39usize.checked_add(session_id_length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid session ID")
        })?;
    if offset + 5 > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover ServerHello is truncated",
        ));
    }
    let cipher_suite = match u16::from_be_bytes([
        payload[offset],
        payload[offset + 1],
    ]) {
        0x1301 => CipherSuite::TLS13_AES_128_GCM_SHA256,
        0x1302 => CipherSuite::TLS13_AES_256_GCM_SHA384,
        0x1303 => CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY cover did not negotiate a supported TLS 1.3 cipher",
            ));
        }
    };
    if payload[offset + 2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover did not negotiate a supported TLS 1.3 cipher",
        ));
    }
    offset += 3;
    let extensions_length =
        usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
    offset += 2;
    if offset.checked_add(extensions_length) != Some(payload.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover ServerHello extensions are malformed",
        ));
    }

    let mut has_tls13 = false;
    let mut key_share_group = None;
    let mut extension_order = Vec::new();
    while offset < payload.len() {
        if offset + 4 > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY cover ServerHello extension is truncated",
            ));
        }
        let extension_type =
            u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        extension_order.push(extension_type);
        let extension_length = usize::from(u16::from_be_bytes([
            payload[offset + 2],
            payload[offset + 3],
        ]));
        offset += 4;
        let end = offset.checked_add(extension_length).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid extension length",
            )
        })?;
        if end > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY cover ServerHello extension exceeds its record",
            ));
        }
        let extension = &payload[offset..end];
        match extension_type {
            TLS_EXTENSION_SUPPORTED_VERSIONS => {
                has_tls13 |= extension == TLS_VERSION_1_3;
            }
            TLS_EXTENSION_KEY_SHARE if extension.len() >= 4 => {
                let group = u16::from_be_bytes([extension[0], extension[1]]);
                let key_length = usize::from(u16::from_be_bytes([
                    extension[2],
                    extension[3],
                ]));
                if key_length + 4 == extension.len() {
                    key_share_group = match (group, key_length) {
                        (TLS_GROUP_X25519, 32) => Some(NamedGroup::X25519),
                        (TLS_GROUP_X25519_MLKEM768, 1120) => {
                            Some(NamedGroup::X25519MLKEM768)
                        }
                        _ => None,
                    };
                }
            }
            _ => {}
        }
        offset = end;
    }
    let Some(key_share_group) = key_share_group else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover ServerHello lacks a supported key share",
        ));
    };
    if !has_tls13 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY cover ServerHello did not select TLS 1.3",
        ));
    }
    Ok(CoverServerHello {
        random,
        cipher_suite,
        key_share_group,
        extension_order,
        handshake_record_lens: None,
    })
}

#[cfg(test)]
pub(crate) async fn spawn_reality_cover_stub()
-> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_reality_cover_stub_with_record_lens(vec![1_205]).await
}

#[cfg(test)]
pub(crate) async fn spawn_reality_cover_stub_with_record_lens(
    encrypted_record_lens: Vec<usize>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    assert!(!encrypted_record_lens.is_empty());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind REALITY cover stub");
    let address = listener.local_addr().expect("cover stub address");
    let task = tokio::spawn(async move {
        let (mut stream, _) =
            listener.accept().await.expect("accept cover probe");
        let mut header = [0; 5];
        stream
            .read_exact(&mut header)
            .await
            .expect("read cover ClientHello header");
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut payload = vec![0; length];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read cover ClientHello record");

        let mut extensions = Vec::new();
        extensions
            .extend_from_slice(&TLS_EXTENSION_SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&2_u16.to_be_bytes());
        extensions.extend_from_slice(&TLS_VERSION_1_3);
        extensions.extend_from_slice(&TLS_EXTENSION_KEY_SHARE.to_be_bytes());
        extensions.extend_from_slice(&36_u16.to_be_bytes());
        extensions.extend_from_slice(&TLS_GROUP_X25519.to_be_bytes());
        extensions.extend_from_slice(&32_u16.to_be_bytes());
        extensions.extend_from_slice(&x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut body = Vec::new();
        body.extend_from_slice(&TLS_VERSION_1_2);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        // Prefer ChaCha in the synthetic cover so the end-to-end test proves
        // the REALITY server follows the cover instead of rustls' AES-first
        // provider order.
        body.extend_from_slice(&0x1303_u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = Vec::with_capacity(body.len() + 4);
        handshake.push(TLS_SERVER_HELLO);
        handshake.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        handshake.extend_from_slice(&body);
        let mut record = vec![TLS_HANDSHAKE_RECORD, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        let mut response = record;
        response.extend_from_slice(&[
            TLS_CHANGE_CIPHER_SPEC_RECORD,
            0x03,
            0x03,
            0,
            1,
            1,
        ]);
        for total_len in encrypted_record_lens {
            let encrypted_len = u16::try_from(total_len - 5)
                .expect("cover encrypted record length");
            let mut encrypted = vec![
                TLS_APPLICATION_DATA_RECORD,
                0x03,
                0x03,
                (encrypted_len >> 8) as u8,
                encrypted_len as u8,
            ];
            encrypted.resize(total_len, 0);
            response.extend_from_slice(&encrypted);
        }
        stream
            .write_all(&response)
            .await
            .expect("write cover handshake shape");
        // REALITY keeps the cover connection alive until the authenticated
        // handshake has completed. Closing immediately lets the Go server's
        // background cover probe race with the client Finished message and
        // tear down an otherwise valid connection.
        let mut probe = [0_u8; 1];
        let _ = stream.read(&mut probe).await;
    });
    (address, task)
}

impl RealityServerIdentity {
    fn generate() -> Result<Self, String> {
        use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let pair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|error| error.to_string())?;
        let public_key: [u8; 32] = pair
            .public_key_raw()
            .try_into()
            .map_err(|_| "REALITY Ed25519 public key has invalid length")?;
        let certificate = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| error.to_string())?
            .self_signed(&pair)
            .map_err(|error| error.to_string())?
            .der()
            .to_vec();
        if certificate.len() < 64 {
            return Err("REALITY certificate is too short".into());
        }
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pair.serialize_der(),
        ));
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
                .map_err(|error| error.to_string())?;
        Ok(Self {
            certificate,
            public_key,
            signing_key,
        })
    }
}

async fn read_client_hello(
    stream: &mut Stream,
    prefix: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut expected = None;
    loop {
        let mut header = [0; 5];
        if read_exact_saving(stream, &mut header, prefix)
            .await
            .is_err()
        {
            return None;
        }
        if header[0] != 22
            || u16::from_be_bytes([header[1], header[2]]) < 0x0301
        {
            return None;
        }
        let record_len =
            usize::from(u16::from_be_bytes([header[3], header[4]]));
        if record_len == 0 || prefix.len() + record_len > MAX_CLIENT_HELLO_LEN {
            return None;
        }
        let mut payload = vec![0; record_len];
        if read_exact_saving(stream, &mut payload, prefix)
            .await
            .is_err()
        {
            return None;
        }
        handshake.extend_from_slice(&payload);
        if expected.is_none() && handshake.len() >= 4 {
            if handshake[0] != 1 {
                return None;
            }
            let length = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            expected = 4usize.checked_add(length);
        }
        if let Some(expected) = expected {
            if expected > MAX_CLIENT_HELLO_LEN {
                return None;
            }
            if handshake.len() >= expected {
                handshake.truncate(expected);
                return Some(handshake);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hmac13::Mac as _;
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use sha2::Sha512;

    use super::{MAX_PENDING_AUTH_KEYS, RealityAuthState};

    fn bound_certificate(key: &[u8; 32]) -> Vec<u8> {
        let signing_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let certificate = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&signing_key)
            .unwrap();
        let mut der = certificate.der().to_vec();
        let mut mac =
            <hmac13::Hmac<Sha512> as hmac13::KeyInit>::new_from_slice(key)
                .unwrap();
        mac.update(signing_key.public_key_raw());
        let binding = mac.finalize().into_bytes();
        let offset = der.len() - binding.len();
        der[offset..].copy_from_slice(&binding);
        der
    }

    #[test]
    fn pending_keys_match_certificates_out_of_handshake_order() {
        let state = RealityAuthState::default();
        let first = [0x11; 32];
        let second = [0x22; 32];
        state.push(first).unwrap();
        state.push(second).unwrap();

        assert!(
            state
                .verify_and_remove(&bound_certificate(&second))
                .unwrap()
        );
        assert!(state.verify_and_remove(&bound_certificate(&first)).unwrap());
        assert!(state.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn pending_key_queue_is_bounded_and_failed_matches_are_retained() {
        let state = RealityAuthState::default();
        for index in 0..=MAX_PENDING_AUTH_KEYS {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&(index as u64).to_be_bytes());
            state.push(key).unwrap();
        }
        assert_eq!(state.pending.lock().unwrap().len(), MAX_PENDING_AUTH_KEYS);
        assert!(
            !state
                .verify_and_remove(&bound_certificate(&[0xff; 32]))
                .unwrap()
        );
        assert_eq!(state.pending.lock().unwrap().len(), MAX_PENDING_AUTH_KEYS);
    }
}
