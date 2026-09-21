//! Standard AnyConnect `PSK-NEGOTIATE` DTLS client.
//!
//! The native handshake matches the pinned Pion configuration, including all
//! six cipher suites, the `X-DTLS-App-ID` ClientHello Session-ID convention,
//! RFC 7627 EMS, cookie exchange, retransmission and Finished verification.
//! The maintained `dtls` crate remains the independent interop oracle in tests.

#[cfg(test)]
use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use std::{io, sync::Arc, time::Duration};

#[cfg(test)]
use async_trait::async_trait;
use openssl::memcmp;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
#[cfg(test)]
use tokio_util::sync::CancellationToken;
#[cfg(test)]
use webrtc_util::{Error as WebRtcUtilError, conn::Conn as WebRtcConnection};

use super::{
    AnyConnectDtlsPsk, CstpDtlsNegotiation, CstpPacketType,
    DTLS12_CONTENT_ALERT, DTLS12_CONTENT_CHANGE_CIPHER_SPEC,
    DTLS12_CONTENT_HANDSHAKE, DTLS12_HANDSHAKE_CLIENT_HELLO,
    DTLS12_HANDSHAKE_FINISHED, DTLS12_HANDSHAKE_HELLO_VERIFY,
    DTLS12_HANDSHAKE_SERVER_HELLO, DTLS12_VERSION, Dtls12ChannelError,
    Dtls12HandshakeError, Dtls12PrfHash, Dtls12Record, Dtls12Session,
    build_dtls12_handshake_message, decrypt_dtls12_record, derive_dtls12_keys,
    dtls12_finished, encrypt_dtls12_record, marshal_dtls12_record,
    parse_dtls12_handshake_message, parse_dtls12_hello_verify,
    parse_dtls12_records, tls12_prf,
};
use crate::{
    adapter::{Dialer, PacketConnection, PacketStream},
    common::network::SocksAddr,
};

const PSK_IDENTITY: &[u8] = b"psk";
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_FLIGHT_INTERVAL: Duration = Duration::from_millis(250);

/// PSK suites offered by the pinned Go implementation, in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyConnectPskCipherSuite {
    ChaCha20Poly1305Sha256,
    Aes128GcmSha256,
    Aes128Ccm,
    Aes128Ccm8,
    Aes256Ccm8,
    Aes128CbcSha256,
}

impl AnyConnectPskCipherSuite {
    pub const ALL: [Self; 6] = [
        Self::ChaCha20Poly1305Sha256,
        Self::Aes128GcmSha256,
        Self::Aes128Ccm,
        Self::Aes128Ccm8,
        Self::Aes256Ccm8,
        Self::Aes128CbcSha256,
    ];

    /// Returns whether the selected mature Rust DTLS backend implements this
    /// exact wire suite today.
    pub const fn supported_by_backend(self) -> bool {
        matches!(
            self,
            Self::Aes128GcmSha256 | Self::Aes128Ccm | Self::Aes128Ccm8
        )
    }

    pub const fn wire_id(self) -> u16 {
        match self {
            Self::ChaCha20Poly1305Sha256 => 0xccab,
            Self::Aes128GcmSha256 => 0x00a8,
            Self::Aes128Ccm => 0xc0a4,
            Self::Aes128Ccm8 => 0xc0a8,
            Self::Aes256Ccm8 => 0xc0a9,
            Self::Aes128CbcSha256 => 0x00ae,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305Sha256 => {
                "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
            }
            Self::Aes128GcmSha256 => "TLS_PSK_WITH_AES_128_GCM_SHA256",
            Self::Aes128Ccm => "TLS_PSK_WITH_AES_128_CCM",
            Self::Aes128Ccm8 => "TLS_PSK_WITH_AES_128_CCM_8",
            Self::Aes256Ccm8 => "TLS_PSK_WITH_AES_256_CCM_8",
            Self::Aes128CbcSha256 => "TLS_PSK_WITH_AES_128_CBC_SHA256",
        }
    }

    /// Convert the wire suite to the common DTLS 1.2 record-protection
    /// descriptor used by the native AnyConnect channel.
    pub fn dtls12_suite(self) -> super::Dtls12Suite {
        super::Dtls12Suite::from_name(self.name(), true)
            .expect("the complete PSK suite inventory is implemented")
    }
}

/// Secret produced by a standard TLS 1.2 PSK handshake.
#[derive(PartialEq, Eq)]
pub struct AnyConnectPskMasterSecret([u8; 48]);

impl AnyConnectPskMasterSecret {
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

impl std::fmt::Debug for AnyConnectPskMasterSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("AnyConnectPskMasterSecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl Drop for AnyConnectPskMasterSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Error)]
pub enum AnyConnectPskWireError {
    #[error("DTLS PSK ClientHello requires a 32-byte random, got {0}")]
    InvalidRandom(usize),
    #[error("DTLS X-DTLS-App-ID exceeds the ClientHello SessionID limit: {0}")]
    AppIdTooLong(usize),
    #[error("DTLS cookie exceeds its one-byte wire length: {0}")]
    CookieTooLong(usize),
    #[error("DTLS PSK exceeds its two-byte wire length: {0}")]
    PskTooLong(usize),
    #[error("DTLS PSK master-secret randoms must both contain 32 bytes")]
    InvalidMasterRandom,
    #[error(transparent)]
    Handshake(#[from] Dtls12HandshakeError),
    #[error(transparent)]
    Record(#[from] super::Dtls12Error),
}

/// Build Pion's standard PSK ClientHello, including AnyConnect's use of the
/// legacy Session-ID field for `X-DTLS-App-ID`.
///
/// The returned transcript contains the complete DTLS handshake message
/// (12-byte header plus body), exactly as required by TLS 1.2 Finished/EMS.
pub fn build_anyconnect_psk_client_hello(
    client_random: &[u8],
    app_id: &[u8],
    cookie: &[u8],
    handshake_sequence: u16,
    record_sequence: u64,
) -> Result<(Vec<u8>, Vec<u8>), AnyConnectPskWireError> {
    if client_random.len() != 32 {
        return Err(AnyConnectPskWireError::InvalidRandom(client_random.len()));
    }
    if app_id.len() > 32 {
        return Err(AnyConnectPskWireError::AppIdTooLong(app_id.len()));
    }
    if cookie.len() > u8::MAX as usize {
        return Err(AnyConnectPskWireError::CookieTooLong(cookie.len()));
    }

    let mut extensions = Vec::with_capacity(35);
    // signature_algorithms: Pion v3.1.5's default preference list.
    const SIGNATURE_SCHEMES: [u16; 10] = [
        0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
        0x0601,
    ];
    extensions.extend_from_slice(&13_u16.to_be_bytes());
    extensions.extend_from_slice(&22_u16.to_be_bytes());
    extensions.extend_from_slice(&20_u16.to_be_bytes());
    for scheme in SIGNATURE_SCHEMES {
        extensions.extend_from_slice(&scheme.to_be_bytes());
    }
    // RFC 5746 renegotiation_info with an empty renegotiated connection.
    extensions.extend_from_slice(&0xff01_u16.to_be_bytes());
    extensions.extend_from_slice(&1_u16.to_be_bytes());
    extensions.push(0);
    // RFC 7627 extended_master_secret request.
    extensions.extend_from_slice(&23_u16.to_be_bytes());
    extensions.extend_from_slice(&0_u16.to_be_bytes());

    let mut body = Vec::with_capacity(
        2 + 32
            + 1
            + app_id.len()
            + 1
            + cookie.len()
            + 2
            + 12
            + 2
            + 2
            + extensions.len(),
    );
    body.extend_from_slice(&DTLS12_VERSION.to_be_bytes());
    body.extend_from_slice(client_random);
    body.push(app_id.len() as u8);
    body.extend_from_slice(app_id);
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);
    body.extend_from_slice(&12_u16.to_be_bytes());
    for suite in AnyConnectPskCipherSuite::ALL {
        body.extend_from_slice(&suite.wire_id().to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let handshake = build_dtls12_handshake_message(
        DTLS12_HANDSHAKE_CLIENT_HELLO,
        handshake_sequence,
        &body,
    )?;
    let record = marshal_dtls12_record(&Dtls12Record {
        content_type: DTLS12_CONTENT_HANDSHAKE,
        epoch: 0,
        sequence: record_sequence,
        payload: handshake.clone(),
    })?;
    Ok((record, handshake))
}

/// RFC 4279 section 2 PSK premaster-secret encoding.
pub fn anyconnect_psk_pre_master_secret(
    psk: &[u8],
) -> Result<Vec<u8>, AnyConnectPskWireError> {
    let length = u16::try_from(psk.len())
        .map_err(|_| AnyConnectPskWireError::PskTooLong(psk.len()))?;
    let mut secret = vec![0; 2 + psk.len() + 2 + psk.len()];
    secret[..2].copy_from_slice(&length.to_be_bytes());
    let second_length = 2 + psk.len();
    secret[second_length..second_length + 2]
        .copy_from_slice(&length.to_be_bytes());
    secret[second_length + 2..].copy_from_slice(psk);
    Ok(secret)
}

/// Derive the TLS 1.2 master secret for Pion's PSK handshake. When the server
/// echoes RFC 7627 EMS, `handshake_transcript` is hashed as the session hash;
/// otherwise the standard client_random || server_random seed is used.
pub fn derive_anyconnect_psk_master_secret(
    psk: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    handshake_transcript: &[u8],
    extended_master_secret: bool,
) -> Result<AnyConnectPskMasterSecret, AnyConnectPskWireError> {
    if client_random.len() != 32 || server_random.len() != 32 {
        return Err(AnyConnectPskWireError::InvalidMasterRandom);
    }
    let mut pre_master = anyconnect_psk_pre_master_secret(psk)?;
    let (label, seed) = if extended_master_secret {
        (
            "extended master secret",
            Sha256::digest(handshake_transcript).to_vec(),
        )
    } else {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);
        ("master secret", seed)
    };
    let mut output =
        tls12_prf(Dtls12PrfHash::Sha256, &pre_master, label, &seed, 48);
    pre_master.fill(0);
    let mut secret = [0; 48];
    secret.copy_from_slice(&output);
    output.fill(0);
    Ok(AnyConnectPskMasterSecret(secret))
}

/// Runtime controls for a standard PSK DTLS connection.
#[derive(Debug, Clone)]
pub struct AnyConnectPskDtlsOptions {
    pub handshake_timeout: Duration,
    pub flight_interval: Duration,
    /// DTLS datagram MTU, including the record overhead. Zero selects the
    /// backend default.
    pub mtu: usize,
    /// Optional per-operation deadline. The Go connection uses context
    /// cancellation; this value provides the equivalent bounded library API.
    pub io_timeout: Option<Duration>,
}

impl Default for AnyConnectPskDtlsOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            flight_interval: DEFAULT_FLIGHT_INTERVAL,
            mtu: 0,
            io_timeout: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum AnyConnectPskDtlsError {
    #[error("DTLS negotiation selected {0}, not PSK-NEGOTIATE")]
    WrongNegotiation(String),
    #[error("DTLS X-DTLS-App-ID exceeds the ClientHello SessionID limit: {0}")]
    AppIdTooLong(usize),
    #[error(
        "the selected Rust DTLS backend cannot inject X-DTLS-App-ID into ClientHello yet"
    )]
    AppIdUnsupported,
    #[error("modern PSK DTLS handshake timed out after {0:?}")]
    HandshakeTimeout(Duration),
    #[error("modern PSK DTLS handshake was cancelled")]
    Cancelled,
    #[error("modern PSK DTLS peer sent an alert during handshake")]
    Alert,
    #[error("modern PSK DTLS peer selected unsupported cipher {0:#06x}")]
    UnsupportedCipher(u16),
    #[error("modern PSK DTLS peer sent unexpected handshake message {0}")]
    UnexpectedHandshake(u8),
    #[error("modern PSK DTLS peer Finished verification failed")]
    FinishedVerification,
    #[error(
        "modern PSK DTLS datagram write was short: wrote {actual} of {expected} bytes"
    )]
    ShortWrite { actual: usize, expected: usize },
    #[error("connect DTLS UDP transport: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] AnyConnectPskWireError),
    #[error(transparent)]
    Channel(#[from] Dtls12ChannelError),
    #[error(transparent)]
    Record(#[from] super::Dtls12Error),
    #[error(transparent)]
    Handshake(#[from] Dtls12HandshakeError),
    #[error("invalid modern PSK DTLS ServerHello")]
    InvalidServerHello,
    #[error("invalid modern PSK DTLS server flight")]
    InvalidServerFlight,
    #[error("generate modern PSK DTLS ClientHello random: {0}")]
    Random(#[from] getrandom::Error),
}

/// Established standard PSK DTLS channel. Payloads are raw AnyConnect DTLS
/// application records; packet-type/compression policy is owned by the common
/// channel coordinator rather than this crypto transport.
pub struct AnyConnectPskDtlsSession {
    connection: Dtls12Session,
    io_timeout: Option<Duration>,
}

impl AnyConnectPskDtlsSession {
    pub async fn detect_mtu(
        &self,
        minimum: usize,
        maximum: usize,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<Option<usize>, AnyConnectPskDtlsError> {
        Ok(super::detect_dtls12_mtu(
            &self.connection,
            minimum,
            maximum,
            cancellation,
            &super::Dtls12MtuProbeOptions::default(),
        )
        .await?)
    }

    pub async fn send(
        &self,
        payload: &[u8],
    ) -> Result<usize, AnyConnectPskDtlsError> {
        if let Some(timeout) = self.io_timeout {
            Ok(tokio::time::timeout(timeout, self.connection.send(payload))
                .await
                .map_err(|_| {
                    AnyConnectPskDtlsError::HandshakeTimeout(timeout)
                })??)
        } else {
            Ok(self.connection.send(payload).await?)
        }
    }

    pub async fn receive(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, AnyConnectPskDtlsError> {
        let payload = if let Some(timeout) = self.io_timeout {
            tokio::time::timeout(timeout, self.connection.receive())
                .await
                .map_err(|_| {
                    AnyConnectPskDtlsError::HandshakeTimeout(timeout)
                })??
        } else {
            self.connection.receive().await?
        };
        if payload.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "receive buffer is too small",
            )
            .into());
        }
        buffer[..payload.len()].copy_from_slice(&payload);
        Ok(payload.len())
    }

    pub async fn close(&self) -> Result<(), AnyConnectPskDtlsError> {
        Ok(self.connection.close().await?)
    }

    /// Encode the first application byte used by AnyConnect's DTLS channel.
    pub fn encode_packet(
        packet_type: CstpPacketType,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = Vec::with_capacity(payload.len() + 1);
        packet.push(packet_type.wire_value());
        packet.extend_from_slice(payload);
        packet
    }
}

/// Open the UDP transport selected by CSTP and establish standard PSK DTLS.
pub async fn dial_anyconnect_psk_dtls(
    dialer: Arc<dyn Dialer>,
    negotiation: &CstpDtlsNegotiation,
    psk: AnyConnectDtlsPsk,
    options: AnyConnectPskDtlsOptions,
) -> Result<AnyConnectPskDtlsSession, AnyConnectPskDtlsError> {
    if negotiation.cipher_suite != "PSK-NEGOTIATE" {
        return Err(AnyConnectPskDtlsError::WrongNegotiation(
            negotiation.cipher_suite.clone(),
        ));
    }
    let destination = SocksAddr::new(&negotiation.host, negotiation.port);
    let packet = dialer.listen_udp(&destination).await?;
    establish_anyconnect_psk_dtls(
        packet,
        destination,
        psk,
        &negotiation.app_id,
        options,
    )
    .await
}

/// Establish standard PSK DTLS over an already-created singbox packet
/// connection. This injected form is useful to endpoint runtimes and tests.
pub async fn establish_anyconnect_psk_dtls(
    packet: PacketStream,
    destination: SocksAddr,
    psk: AnyConnectDtlsPsk,
    app_id: &[u8],
    options: AnyConnectPskDtlsOptions,
) -> Result<AnyConnectPskDtlsSession, AnyConnectPskDtlsError> {
    establish_anyconnect_psk_dtls_native(
        packet,
        destination,
        psk,
        app_id,
        options,
    )
    .await
}

const PSK_SERVER_KEY_EXCHANGE: u8 = 12;
const PSK_SERVER_HELLO_DONE: u8 = 14;
const PSK_CLIENT_KEY_EXCHANGE: u8 = 16;

struct NativePskServerFlight {
    random: [u8; 32],
    suite: AnyConnectPskCipherSuite,
    extended_master_secret: bool,
    transcript: Vec<u8>,
    next_sequence: u16,
    complete: bool,
}

fn parse_native_psk_server_hello(
    body: &[u8],
) -> Result<([u8; 32], AnyConnectPskCipherSuite, bool), AnyConnectPskDtlsError>
{
    if body.len() < 38 || body[..2] != DTLS12_VERSION.to_be_bytes() {
        return Err(AnyConnectPskDtlsError::InvalidServerHello);
    }
    let random: [u8; 32] = body[2..34]
        .try_into()
        .map_err(|_| AnyConnectPskDtlsError::InvalidServerHello)?;
    let session_length = usize::from(body[34]);
    let mut offset = 35 + session_length;
    if session_length > 32 || body.len() < offset + 3 {
        return Err(AnyConnectPskDtlsError::InvalidServerHello);
    }
    let cipher_id = u16::from_be_bytes([body[offset], body[offset + 1]]);
    let suite = AnyConnectPskCipherSuite::ALL
        .into_iter()
        .find(|suite| suite.wire_id() == cipher_id)
        .ok_or(AnyConnectPskDtlsError::UnsupportedCipher(cipher_id))?;
    offset += 2;
    if body[offset] != 0 {
        return Err(AnyConnectPskDtlsError::InvalidServerHello);
    }
    offset += 1;
    if offset == body.len() {
        return Ok((random, suite, false));
    }
    if body.len() < offset + 2 {
        return Err(AnyConnectPskDtlsError::InvalidServerHello);
    }
    let extension_length =
        usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2;
    if body.len() != offset + extension_length {
        return Err(AnyConnectPskDtlsError::InvalidServerHello);
    }
    let mut extended_master_secret = false;
    while offset < body.len() {
        if body.len() < offset + 4 {
            return Err(AnyConnectPskDtlsError::InvalidServerHello);
        }
        let extension_type =
            u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([
            body[offset + 2],
            body[offset + 3],
        ]));
        offset += 4;
        if body.len() < offset + length {
            return Err(AnyConnectPskDtlsError::InvalidServerHello);
        }
        if extension_type == 23 {
            if length != 0 {
                return Err(AnyConnectPskDtlsError::InvalidServerHello);
            }
            extended_master_secret = true;
        }
        offset += length;
    }
    Ok((random, suite, extended_master_secret))
}

fn process_native_psk_server_flight(
    records: &[Dtls12Record],
    flight: &mut Option<NativePskServerFlight>,
    expected_first_sequence: u16,
) -> Result<bool, AnyConnectPskDtlsError> {
    for record in records {
        match record.content_type {
            DTLS12_CONTENT_HANDSHAKE if record.epoch == 0 => {
                let message = parse_dtls12_handshake_message(&record.payload)?;
                if message.message_type == DTLS12_HANDSHAKE_HELLO_VERIFY {
                    continue;
                }
                if let Some(current) = flight.as_ref() {
                    if message.sequence < current.next_sequence {
                        continue;
                    }
                    if message.sequence != current.next_sequence {
                        return Err(
                            AnyConnectPskDtlsError::InvalidServerFlight,
                        );
                    }
                } else if message.sequence != expected_first_sequence
                    || message.message_type != DTLS12_HANDSHAKE_SERVER_HELLO
                {
                    return Err(AnyConnectPskDtlsError::InvalidServerFlight);
                }
                match message.message_type {
                    DTLS12_HANDSHAKE_SERVER_HELLO => {
                        if flight.is_some() {
                            return Err(
                                AnyConnectPskDtlsError::InvalidServerFlight,
                            );
                        }
                        let (random, suite, extended_master_secret) =
                            parse_native_psk_server_hello(&message.body)?;
                        *flight = Some(NativePskServerFlight {
                            random,
                            suite,
                            extended_master_secret,
                            transcript: record.payload.clone(),
                            next_sequence: message.sequence + 1,
                            complete: false,
                        });
                    }
                    PSK_SERVER_KEY_EXCHANGE => {
                        if message.body.len() < 2 {
                            return Err(
                                AnyConnectPskDtlsError::InvalidServerFlight,
                            );
                        }
                        let hint_length = usize::from(u16::from_be_bytes([
                            message.body[0],
                            message.body[1],
                        ]));
                        if message.body.len() != hint_length + 2 {
                            return Err(
                                AnyConnectPskDtlsError::InvalidServerFlight,
                            );
                        }
                        let current = flight.as_mut().ok_or(
                            AnyConnectPskDtlsError::InvalidServerFlight,
                        )?;
                        current.transcript.extend_from_slice(&record.payload);
                        current.next_sequence += 1;
                    }
                    PSK_SERVER_HELLO_DONE => {
                        if !message.body.is_empty() {
                            return Err(
                                AnyConnectPskDtlsError::InvalidServerFlight,
                            );
                        }
                        let current = flight.as_mut().ok_or(
                            AnyConnectPskDtlsError::InvalidServerFlight,
                        )?;
                        current.transcript.extend_from_slice(&record.payload);
                        current.next_sequence += 1;
                        current.complete = true;
                    }
                    other => {
                        return Err(
                            AnyConnectPskDtlsError::UnexpectedHandshake(other),
                        );
                    }
                }
            }
            DTLS12_CONTENT_ALERT => return Err(AnyConnectPskDtlsError::Alert),
            _ => {}
        }
    }
    Ok(flight.as_ref().is_some_and(|flight| flight.complete))
}

async fn send_native_psk_datagram(
    packet: &dyn PacketConnection,
    destination: &SocksAddr,
    datagram: &[u8],
) -> Result<(), AnyConnectPskDtlsError> {
    let actual = packet.send_to(datagram, destination).await?;
    if actual != datagram.len() {
        return Err(AnyConnectPskDtlsError::ShortWrite {
            actual,
            expected: datagram.len(),
        });
    }
    Ok(())
}

async fn receive_native_psk_records(
    packet: &dyn PacketConnection,
    destination: &SocksAddr,
    deadline: Instant,
) -> Result<Option<Vec<Dtls12Record>>, AnyConnectPskDtlsError> {
    let mut datagram = vec![0; 64 * 1024];
    loop {
        let Ok(result) =
            timeout_at(deadline, packet.recv_from(&mut datagram)).await
        else {
            return Ok(None);
        };
        let (size, source) = result?;
        if source != *destination {
            continue;
        }
        return Ok(Some(parse_dtls12_records(&datagram[..size])?));
    }
}

async fn establish_anyconnect_psk_dtls_native(
    packet: PacketStream,
    destination: SocksAddr,
    psk: AnyConnectDtlsPsk,
    app_id: &[u8],
    options: AnyConnectPskDtlsOptions,
) -> Result<AnyConnectPskDtlsSession, AnyConnectPskDtlsError> {
    if app_id.len() > 32 {
        return Err(AnyConnectPskDtlsError::AppIdTooLong(app_id.len()));
    }
    let handshake_timeout = if options.handshake_timeout.is_zero() {
        DEFAULT_HANDSHAKE_TIMEOUT
    } else {
        options.handshake_timeout
    };
    let flight_interval = if options.flight_interval.is_zero() {
        DEFAULT_FLIGHT_INTERVAL
    } else {
        options.flight_interval
    };
    let deadline = Instant::now() + handshake_timeout;
    let mut client_random = [0_u8; 32];
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    client_random[..4].copy_from_slice(&unix_seconds.to_be_bytes());
    getrandom::fill(&mut client_random[4..])?;

    let (initial_hello, initial_transcript) =
        build_anyconnect_psk_client_hello(&client_random, app_id, &[], 0, 0)?;
    let mut hello = initial_hello;
    let mut hello_transcript = initial_transcript;
    let mut expected_server_sequence = 0_u16;
    let mut next_client_handshake_sequence = 1_u16;
    let mut next_client_record_sequence = 1_u64;
    let mut server_flight = None;

    loop {
        send_native_psk_datagram(packet.as_ref(), &destination, &hello).await?;
        let attempt_deadline = (Instant::now() + flight_interval).min(deadline);
        while let Some(records) = receive_native_psk_records(
            packet.as_ref(),
            &destination,
            attempt_deadline,
        )
        .await?
        {
            let mut cookie = None;
            for record in &records {
                if record.content_type == DTLS12_CONTENT_HANDSHAKE
                    && record.epoch == 0
                {
                    let message =
                        parse_dtls12_handshake_message(&record.payload)?;
                    if message.message_type == DTLS12_HANDSHAKE_HELLO_VERIFY {
                        cookie =
                            Some(parse_dtls12_hello_verify(&message.body)?);
                        break;
                    }
                }
            }
            if let Some(cookie) = cookie {
                expected_server_sequence = 1;
                next_client_handshake_sequence = 2;
                next_client_record_sequence = 2;
                (hello, hello_transcript) = build_anyconnect_psk_client_hello(
                    &client_random,
                    app_id,
                    &cookie,
                    1,
                    1,
                )?;
                server_flight = None;
                break;
            }
            if process_native_psk_server_flight(
                &records,
                &mut server_flight,
                expected_server_sequence,
            )? {
                break;
            }
        }
        if server_flight.as_ref().is_some_and(|flight| flight.complete) {
            break;
        }
        if Instant::now() >= deadline {
            return Err(AnyConnectPskDtlsError::HandshakeTimeout(
                handshake_timeout,
            ));
        }
    }

    let server_flight =
        server_flight.ok_or(AnyConnectPskDtlsError::InvalidServerFlight)?;
    let client_key_exchange_body = [
        0,
        PSK_IDENTITY.len() as u8,
        PSK_IDENTITY[0],
        PSK_IDENTITY[1],
        PSK_IDENTITY[2],
    ];
    let client_key_exchange = build_dtls12_handshake_message(
        PSK_CLIENT_KEY_EXCHANGE,
        next_client_handshake_sequence,
        &client_key_exchange_body,
    )?;
    let mut transcript = Vec::with_capacity(
        hello_transcript.len()
            + server_flight.transcript.len()
            + client_key_exchange.len(),
    );
    transcript.extend_from_slice(&hello_transcript);
    transcript.extend_from_slice(&server_flight.transcript);
    transcript.extend_from_slice(&client_key_exchange);
    let master_secret = derive_anyconnect_psk_master_secret(
        psk.as_bytes(),
        &client_random,
        &server_flight.random,
        &transcript,
        server_flight.extended_master_secret,
    )?;
    let suite = server_flight.suite.dtls12_suite();
    let keys = derive_dtls12_keys(
        &suite,
        master_secret.as_bytes(),
        &client_random,
        &server_flight.random,
    );
    let verify_data =
        dtls12_finished(&suite, master_secret.as_bytes(), &transcript, true);
    let client_finished = build_dtls12_handshake_message(
        DTLS12_HANDSHAKE_FINISHED,
        next_client_handshake_sequence + 1,
        &verify_data,
    )?;
    let mut final_flight = marshal_dtls12_record(&Dtls12Record {
        content_type: DTLS12_CONTENT_HANDSHAKE,
        epoch: 0,
        sequence: next_client_record_sequence,
        payload: client_key_exchange,
    })?;
    final_flight.extend(marshal_dtls12_record(&Dtls12Record {
        content_type: DTLS12_CONTENT_CHANGE_CIPHER_SPEC,
        epoch: 0,
        sequence: next_client_record_sequence + 1,
        payload: vec![1],
    })?);
    final_flight.extend(encrypt_dtls12_record(
        &Dtls12Record {
            content_type: DTLS12_CONTENT_HANDSHAKE,
            epoch: 1,
            sequence: 0,
            payload: client_finished.clone(),
        },
        &keys.client_write_key,
        &keys.client_mac_key,
        &keys.client_write_iv,
        &suite,
    )?);

    let mut change_cipher_seen = false;
    let server_finished = loop {
        send_native_psk_datagram(packet.as_ref(), &destination, &final_flight)
            .await?;
        let attempt_deadline = (Instant::now() + flight_interval).min(deadline);
        let mut completed = None;
        while let Some(records) = receive_native_psk_records(
            packet.as_ref(),
            &destination,
            attempt_deadline,
        )
        .await?
        {
            for record in records {
                match record.content_type {
                    DTLS12_CONTENT_CHANGE_CIPHER_SPEC => {
                        if record.epoch != 0 || record.payload != [1] {
                            return Err(
                                AnyConnectPskDtlsError::InvalidServerFlight,
                            );
                        }
                        change_cipher_seen = true;
                    }
                    DTLS12_CONTENT_HANDSHAKE if record.epoch == 1 => {
                        let plaintext = decrypt_dtls12_record(
                            &record,
                            &keys.server_write_key,
                            &keys.server_mac_key,
                            &keys.server_write_iv,
                            &suite,
                        )?;
                        let message =
                            parse_dtls12_handshake_message(&plaintext)?;
                        if message.message_type != DTLS12_HANDSHAKE_FINISHED
                            || message.sequence != server_flight.next_sequence
                            || message.body.len() != 12
                        {
                            return Err(
                                AnyConnectPskDtlsError::InvalidServerFlight,
                            );
                        }
                        let mut server_transcript = transcript.clone();
                        server_transcript.extend_from_slice(&client_finished);
                        let expected = dtls12_finished(
                            &suite,
                            master_secret.as_bytes(),
                            &server_transcript,
                            false,
                        );
                        if !memcmp::eq(&message.body, &expected) {
                            return Err(
                                AnyConnectPskDtlsError::FinishedVerification,
                            );
                        }
                        completed = Some(plaintext);
                    }
                    DTLS12_CONTENT_ALERT => {
                        return Err(AnyConnectPskDtlsError::Alert);
                    }
                    DTLS12_CONTENT_HANDSHAKE if record.epoch == 0 => {}
                    _ => {}
                }
            }
            if change_cipher_seen && completed.is_some() {
                break;
            }
        }
        if change_cipher_seen && let Some(completed) = completed {
            break completed;
        }
        if Instant::now() >= deadline {
            return Err(AnyConnectPskDtlsError::HandshakeTimeout(
                handshake_timeout,
            ));
        }
    };

    drop(psk);
    drop(master_secret);
    Ok(AnyConnectPskDtlsSession {
        connection: Dtls12Session::new(
            packet,
            destination,
            suite,
            keys,
            options.mtu,
            true,
            false,
            vec![final_flight],
            server_finished,
        ),
        io_timeout: options.io_timeout,
    })
}

#[cfg(test)]
struct SingboxPacketConn {
    packet: Arc<dyn PacketConnection>,
    destination: SocksAddr,
    local: SocketAddr,
    remote: SocketAddr,
    cancellation: CancellationToken,
}

#[cfg(test)]
impl SingboxPacketConn {
    fn new(
        packet: Arc<dyn PacketConnection>,
        destination: SocksAddr,
        cancellation: CancellationToken,
    ) -> Self {
        let local = packet.local_addr().ok().flatten().unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        });
        let remote = match destination {
            SocksAddr::Ip(address) => address,
            SocksAddr::Domain { port, .. } => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        };
        Self {
            packet,
            destination,
            local,
            remote,
            cancellation,
        }
    }

    fn closed_error() -> WebRtcUtilError {
        WebRtcUtilError::ErrUseClosedNetworkConn
    }
}

#[cfg(test)]
#[async_trait]
impl WebRtcConnection for SingboxPacketConn {
    async fn connect(
        &self,
        _address: SocketAddr,
    ) -> Result<(), WebRtcUtilError> {
        Ok(())
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<usize, WebRtcUtilError> {
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(Self::closed_error()),
            result = self.packet.recv_from(buffer) => {
                let (size, _) = result?;
                Ok(size)
            }
        }
    }

    async fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr), WebRtcUtilError> {
        Ok((self.recv(buffer).await?, self.remote))
    }

    async fn send(&self, buffer: &[u8]) -> Result<usize, WebRtcUtilError> {
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(Self::closed_error()),
            result = self.packet.send_to(buffer, &self.destination) => Ok(result?),
        }
    }

    async fn send_to(
        &self,
        buffer: &[u8],
        _target: SocketAddr,
    ) -> Result<usize, WebRtcUtilError> {
        self.send(buffer).await
    }

    fn local_addr(&self) -> Result<SocketAddr, WebRtcUtilError> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }

    async fn close(&self) -> Result<(), WebRtcUtilError> {
        self.cancellation.cancel();
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use dtls::{cipher_suite::CipherSuiteId, config::Config, conn::DTLSConn};
    use tokio::sync::{Mutex, mpsc};

    use super::*;

    struct MemoryPacket {
        local: SocketAddr,
        peer: SocketAddr,
        sender: mpsc::Sender<Vec<u8>>,
        receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl PacketConnection for MemoryPacket {
        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(Some(self.local))
        }

        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            _destination: &'a SocksAddr,
        ) -> crate::adapter::PacketFuture<'a, usize> {
            Box::pin(async move {
                self.sender.send(data.to_vec()).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "peer closed")
                })?;
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> crate::adapter::PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let packet =
                    self.receiver.lock().await.recv().await.ok_or_else(
                        || {
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "peer closed",
                            )
                        },
                    )?;
                if packet.len() > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "receive buffer is too small",
                    ));
                }
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), self.peer.into()))
            })
        }
    }

    fn memory_packet_pair() -> (PacketStream, PacketStream) {
        let client_address: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let server_address: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let (client_sender, server_receiver) = mpsc::channel(32);
        let (server_sender, client_receiver) = mpsc::channel(32);
        (
            Box::new(MemoryPacket {
                local: client_address,
                peer: server_address,
                sender: client_sender,
                receiver: Mutex::new(client_receiver),
            }),
            Box::new(MemoryPacket {
                local: server_address,
                peer: client_address,
                sender: server_sender,
                receiver: Mutex::new(server_receiver),
            }),
        )
    }

    #[test]
    fn suite_inventory_matches_pinned_go_preference() {
        assert_eq!(
            AnyConnectPskCipherSuite::ALL.map(|suite| suite.wire_id()),
            [0xccab, 0x00a8, 0xc0a4, 0xc0a8, 0xc0a9, 0x00ae]
        );
        assert_eq!(
            AnyConnectPskCipherSuite::ALL.map(|suite| suite.name()),
            [
                "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_PSK_WITH_AES_128_GCM_SHA256",
                "TLS_PSK_WITH_AES_128_CCM",
                "TLS_PSK_WITH_AES_128_CCM_8",
                "TLS_PSK_WITH_AES_256_CCM_8",
                "TLS_PSK_WITH_AES_128_CBC_SHA256",
            ]
        );
        assert!(!AnyConnectPskCipherSuite::ALL[0].supported_by_backend());
        assert!(AnyConnectPskCipherSuite::ALL[1].supported_by_backend());
        assert!(AnyConnectPskCipherSuite::ALL[2].supported_by_backend());
        assert!(AnyConnectPskCipherSuite::ALL[3].supported_by_backend());
        assert!(!AnyConnectPskCipherSuite::ALL[4].supported_by_backend());
        assert!(!AnyConnectPskCipherSuite::ALL[5].supported_by_backend());
    }

    #[test]
    fn psk_secret_derivation_matches_fixed_go_vectors() {
        let pre_master =
            anyconnect_psk_pre_master_secret(b"openconnect-psk").unwrap();
        assert_eq!(
            hex::encode(&pre_master),
            "000f000000000000000000000000000000000f6f70656e636f6e6e6563742d70736b"
        );

        let standard = derive_anyconnect_psk_master_secret(
            b"openconnect-psk",
            &[0x11; 32],
            &[0x22; 32],
            b"unused",
            false,
        )
        .unwrap();
        assert_eq!(
            hex::encode(standard.as_bytes()),
            "09aeb0549d69541f1a5ba996293b7fcde3e456f17b185ea098ff000163d84a73e954f740c88c1eb924e69973564e5ee9"
        );

        let extended = derive_anyconnect_psk_master_secret(
            b"openconnect-psk",
            &[0x11; 32],
            &[0x22; 32],
            b"client/server handshake transcript",
            true,
        )
        .unwrap();
        assert_eq!(
            hex::encode(extended.as_bytes()),
            "faceb7735d3105f12ce032779f469bd11aec4885d9d7332904eaf75ca42a993c16953406113432ac81053ec1ba34a9f8"
        );
    }

    #[test]
    fn psk_client_hello_matches_pion_wire_body() {
        let mut random = [0x11; 32];
        random[..4].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        let (record, transcript) = build_anyconnect_psk_client_hello(
            &random,
            &[0xaa, 0xbb],
            &[0x21, 0x22, 0x23],
            1,
            0x0102_0304_0506,
        )
        .unwrap();

        let records = parse_dtls12_records(&record).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, DTLS12_CONTENT_HANDSHAKE);
        assert_eq!(records[0].epoch, 0);
        assert_eq!(records[0].sequence, 0x0102_0304_0506);
        assert_eq!(records[0].payload, transcript);
        let message =
            parse_dtls12_handshake_message(&records[0].payload).unwrap();
        assert_eq!(message.message_type, DTLS12_HANDSHAKE_CLIENT_HELLO);
        assert_eq!(message.sequence, 1);
        assert_eq!(
            hex::encode(message.body),
            "fefd010203041111111111111111111111111111111111111111111111111111111102aabb03212223000cccab00a8c0a4c0a8c0a900ae01000023000d001600140403050306030807080408050806040105010601ff0100010000170000"
        );
    }

    #[tokio::test]
    async fn rejects_oversized_app_id_before_network_io() {
        struct UnusedPacket;

        impl PacketConnection for UnusedPacket {
            fn send_to<'a>(
                &'a self,
                _data: &'a [u8],
                _destination: &'a SocksAddr,
            ) -> crate::adapter::PacketFuture<'a, usize> {
                Box::pin(async { unreachable!() })
            }

            fn recv_from<'a>(
                &'a self,
                _data: &'a mut [u8],
            ) -> crate::adapter::PacketFuture<'a, (usize, SocksAddr)>
            {
                Box::pin(async { unreachable!() })
            }
        }

        let result = establish_anyconnect_psk_dtls(
            Box::new(UnusedPacket),
            SocksAddr::new("192.0.2.1", 443),
            AnyConnectDtlsPsk::default(),
            &[0x55; 33],
            AnyConnectPskDtlsOptions::default(),
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("oversized App-ID must be rejected"),
        };
        assert!(matches!(error, AnyConnectPskDtlsError::AppIdTooLong(33)));
    }

    async fn assert_psk_round_trip(cipher_suite: CipherSuiteId) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let secret = [0xa5; 32];
        let (client_packet, server_packet) = memory_packet_pair();
        let server_packet: Arc<dyn PacketConnection> = Arc::from(server_packet);
        let server_transport: Arc<dyn WebRtcConnection + Send + Sync> =
            Arc::new(SingboxPacketConn::new(
                server_packet,
                SocksAddr::new("127.0.0.1", 41000),
                CancellationToken::new(),
            ));
        let server_secret = secret;
        let server = tokio::spawn(async move {
            let config = Config {
                psk: Some(Arc::new(move |_identity: &[u8]| {
                    let secret = server_secret.to_vec();
                    Box::pin(async move { Ok(secret) })
                })),
                psk_identity_hint: Some(b"gateway".to_vec()),
                cipher_suites: vec![cipher_suite],
                flight_interval: Duration::from_millis(10),
                ..Default::default()
            };
            DTLSConn::new(server_transport, config, false, None).await
        });
        let client = establish_anyconnect_psk_dtls(
            client_packet,
            SocksAddr::new("127.0.0.1", 443),
            AnyConnectDtlsPsk::from_bytes(secret),
            &[],
            AnyConnectPskDtlsOptions {
                handshake_timeout: Duration::from_secs(2),
                flight_interval: Duration::from_millis(10),
                io_timeout: Some(Duration::from_secs(2)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let server = server.await.unwrap().unwrap();

        client.send(b"client payload").await.unwrap();
        let mut buffer = [0; 64];
        let size = server
            .read(&mut buffer, Some(Duration::from_secs(2)))
            .await
            .unwrap();
        assert_eq!(&buffer[..size], b"client payload");

        server
            .write(b"server payload", Some(Duration::from_secs(2)))
            .await
            .unwrap();
        let size = client.receive(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..size], b"server payload");

        client.close().await.unwrap();
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn standard_psk_suites_handshake_and_exchange_payloads() {
        for cipher_suite in [
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
        ] {
            assert_psk_round_trip(cipher_suite).await;
        }
    }

    #[test]
    fn packet_type_prefix_matches_anyconnect_wire() {
        assert_eq!(
            AnyConnectPskDtlsSession::encode_packet(
                CstpPacketType::DpdRequest,
                b"probe"
            ),
            b"\x03probe"
        );
    }
}
