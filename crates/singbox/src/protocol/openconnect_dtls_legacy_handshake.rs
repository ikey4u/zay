//! Cisco DTLS 0.9 abbreviated-handshake wire compatibility.
//!
//! AnyConnect injects the CSTP-provided session ID and master secret into a
//! pre-RFC DTLS handshake.  These helpers are transport-independent so a zay
//! owned UDP connector can drive retransmission and cancellation.

use md5::{Digest as _, Md5};
use openssl::memcmp;
use sha1_11::Sha1;
use std::{io, time::Duration};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use super::{
    LegacyDtlsError, LegacyDtlsKeys, LegacyDtlsRecord, LegacyDtlsSession,
    LegacyDtlsSuite, decrypt_legacy_dtls_record, derive_legacy_dtls_keys,
    encrypt_legacy_dtls_record, marshal_legacy_dtls_record,
    parse_legacy_dtls_records, tls10_prf,
};
use crate::{adapter::PacketStream, common::network::SocksAddr};

pub const LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const LEGACY_DTLS_CONTENT_ALERT: u8 = 21;
pub const LEGACY_DTLS_CONTENT_HANDSHAKE: u8 = 22;
pub const LEGACY_DTLS_CONTENT_APPLICATION_DATA: u8 = 23;
pub const LEGACY_DTLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const LEGACY_DTLS_HANDSHAKE_SERVER_HELLO: u8 = 2;
pub const LEGACY_DTLS_HANDSHAKE_HELLO_VERIFY: u8 = 3;
pub const LEGACY_DTLS_HANDSHAKE_FINISHED: u8 = 20;
pub const LEGACY_DTLS_HANDSHAKE_HEADER_LENGTH: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDtlsHandshakeMessage {
    pub message_type: u8,
    pub sequence: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct LegacyDtlsServerFlight {
    pub server_random: Vec<u8>,
    pub server_hello_body: Vec<u8>,
    pub keys: Option<LegacyDtlsKeys>,
    pub change_cipher_seen: bool,
    pub server_finished: Vec<u8>,
}

impl std::fmt::Debug for LegacyDtlsServerFlight {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LegacyDtlsServerFlight")
            .field("server_random", &self.server_random)
            .field("server_hello_body", &self.server_hello_body)
            .field("keys_ready", &self.keys.is_some())
            .field("change_cipher_seen", &self.change_cipher_seen)
            .field("server_finished", &self.server_finished)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum LegacyDtlsHandshakeError {
    #[error(transparent)]
    Record(#[from] LegacyDtlsError),
    #[error("invalid Cisco DTLS 0.9 ClientHello parameters")]
    InvalidClientHello,
    #[error("short Cisco DTLS 0.9 handshake header")]
    ShortHandshake,
    #[error("fragmented or truncated Cisco DTLS 0.9 handshake message")]
    FragmentedHandshake,
    #[error("invalid Cisco DTLS 0.9 HelloVerify version")]
    InvalidHelloVerifyVersion,
    #[error("invalid Cisco DTLS 0.9 HelloVerify cookie")]
    InvalidHelloVerifyCookie,
    #[error("invalid Cisco DTLS 0.9 ServerHello version")]
    InvalidServerHelloVersion,
    #[error("Cisco DTLS 0.9 server did not accept the injected Session-ID")]
    SessionIdRejected,
    #[error("Cisco DTLS 0.9 server selected unexpected cipher: {0:#06x}")]
    UnexpectedCipher(u16),
    #[error("Cisco DTLS 0.9 server selected unsupported compression: {0}")]
    UnsupportedCompression(u8),
    #[error("truncated Cisco DTLS 0.9 ServerHello extensions")]
    TruncatedExtensions,
    #[error("invalid Cisco DTLS 0.9 ServerHello extensions")]
    InvalidExtensions,
    #[error("unexpected Cisco DTLS 0.9 handshake message: {0}")]
    UnexpectedHandshake(u8),
    #[error(
        "Cisco DTLS 0.9 ServerHello has unexpected handshake sequence: {0}"
    )]
    UnexpectedServerHelloSequence(u16),
    #[error("Cisco DTLS 0.9 sent encrypted Finished before ServerHello")]
    FinishedBeforeServerHello,
    #[error("invalid Cisco DTLS 0.9 server Finished")]
    InvalidFinished,
    #[error(
        "Cisco DTLS 0.9 server Finished has unexpected handshake sequence: {0}"
    )]
    UnexpectedFinishedSequence(u16),
    #[error("Cisco DTLS 0.9 server Finished verification failed")]
    FinishedVerification,
    #[error("invalid Cisco DTLS 0.9 ChangeCipherSpec")]
    InvalidChangeCipherSpec,
    #[error("Cisco DTLS 0.9 peer sent an alert during handshake")]
    Alert,
    #[error("unexpected Cisco DTLS 0.9 server-flight record: {0}")]
    UnexpectedRecord(u8),
}

#[derive(Clone, PartialEq, Eq)]
pub struct LegacyDtlsConnectOptions {
    pub session_id: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub cipher_suite: String,
    pub allow_insecure_crypto: bool,
    pub mtu: usize,
    pub strict: bool,
    pub close_alert: bool,
    pub handshake_timeout: Duration,
    pub initial_retry_interval: Duration,
    pub retries: usize,
}

impl std::fmt::Debug for LegacyDtlsConnectOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LegacyDtlsConnectOptions")
            .field("session_id", &self.session_id)
            .field("master_secret", &"[REDACTED]")
            .field("cipher_suite", &self.cipher_suite)
            .field("allow_insecure_crypto", &self.allow_insecure_crypto)
            .field("mtu", &self.mtu)
            .field("strict", &self.strict)
            .field("close_alert", &self.close_alert)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("initial_retry_interval", &self.initial_retry_interval)
            .field("retries", &self.retries)
            .finish()
    }
}

impl Default for LegacyDtlsConnectOptions {
    fn default() -> Self {
        Self {
            session_id: Vec::new(),
            master_secret: Vec::new(),
            cipher_suite: "AES256-SHA".into(),
            allow_insecure_crypto: false,
            mtu: 0,
            strict: true,
            close_alert: false,
            handshake_timeout: Duration::from_secs(15),
            initial_retry_interval: Duration::from_millis(250),
            retries: 6,
        }
    }
}

#[derive(Debug, Error)]
pub enum LegacyDtlsConnectError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Record(#[from] LegacyDtlsError),
    #[error(transparent)]
    Handshake(#[from] LegacyDtlsHandshakeError),
    #[error("Cisco DTLS 0.9 requires a 32-byte X-DTLS-Session-ID, got {0}")]
    InvalidSessionId(usize),
    #[error("Cisco DTLS 0.9 requires a 48-byte master secret, got {0}")]
    InvalidMasterSecret(usize),
    #[error("Cisco DTLS 0.9 handshake was cancelled")]
    Cancelled,
    #[error("Cisco DTLS 0.9 peer did not answer the ClientHello")]
    InitialResponseTimeout,
    #[error("Cisco DTLS 0.9 abbreviated handshake did not complete")]
    ServerFlightTimeout,
    #[error(
        "Cisco DTLS 0.9 HelloVerify has unexpected handshake sequence: {0}"
    )]
    UnexpectedHelloVerifySequence(u16),
    #[error(
        "Cisco DTLS 0.9 datagram write was short: wrote {actual} of {expected} bytes"
    )]
    ShortWrite { actual: usize, expected: usize },
}

enum LegacyDtlsInitialResponse {
    Cookie(Vec<u8>),
    ServerRecords(Vec<LegacyDtlsRecord>),
}

/// Establish the AnyConnect abbreviated Cisco DTLS 0.9 session over a
/// packet connection returned by any singbox outbound dialer.
pub async fn connect_legacy_dtls(
    packet: PacketStream,
    destination: SocksAddr,
    options: &LegacyDtlsConnectOptions,
    cancellation: &CancellationToken,
) -> Result<LegacyDtlsSession, LegacyDtlsConnectError> {
    if options.session_id.len() != 32 {
        return Err(LegacyDtlsConnectError::InvalidSessionId(
            options.session_id.len(),
        ));
    }
    if options.master_secret.len() != 48 {
        return Err(LegacyDtlsConnectError::InvalidMasterSecret(
            options.master_secret.len(),
        ));
    }
    let suite = LegacyDtlsSuite::from_name(
        &options.cipher_suite,
        options.allow_insecure_crypto,
    )?;
    let mut client_random = [0_u8; 32];
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    client_random[..4].copy_from_slice(&unix_seconds.to_be_bytes());
    getrandom::fill(&mut client_random[4..]).map_err(LegacyDtlsError::from)?;
    let deadline = Instant::now() + options.handshake_timeout;
    let initial = exchange_initial_response(
        packet.as_ref(),
        &destination,
        &client_random,
        options,
        &suite,
        cancellation,
        deadline,
    )
    .await?;
    let (cookie, initial_records, record_sequence, server_hello_sequence) =
        match initial {
            LegacyDtlsInitialResponse::Cookie(cookie) => {
                (cookie, Vec::new(), 1, 1)
            }
            LegacyDtlsInitialResponse::ServerRecords(records) => {
                (Vec::new(), records, 0, 0)
            }
        };
    let (client_hello, client_hello_body) = build_legacy_dtls_client_hello(
        &client_random,
        &options.session_id,
        &cookie,
        &suite,
        record_sequence,
    )?;
    let (server_flight, next_record_sequence) = exchange_server_flight(
        packet.as_ref(),
        &destination,
        &client_random,
        &client_hello,
        &client_hello_body,
        &initial_records,
        server_hello_sequence,
        options,
        &suite,
        cancellation,
        deadline,
    )
    .await?;
    let final_flight = build_legacy_dtls_client_final_flight(
        &server_flight,
        &client_hello_body,
        &options.master_secret,
        &suite,
        server_hello_sequence,
        next_record_sequence,
    )?;
    send_handshake_datagram(
        packet.as_ref(),
        &destination,
        &final_flight,
        cancellation,
    )
    .await?;
    let server_finished = build_legacy_dtls_handshake_message(
        LEGACY_DTLS_HANDSHAKE_FINISHED,
        server_hello_sequence + 2,
        &server_flight.server_finished,
    )?;
    let keys = server_flight
        .keys
        .ok_or(LegacyDtlsHandshakeError::FinishedBeforeServerHello)?;
    Ok(LegacyDtlsSession::new(
        packet,
        destination,
        suite,
        keys,
        options.mtu,
        options.strict,
        options.close_alert,
        vec![final_flight],
        server_finished,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn exchange_initial_response(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    client_random: &[u8],
    options: &LegacyDtlsConnectOptions,
    suite: &LegacyDtlsSuite,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<LegacyDtlsInitialResponse, LegacyDtlsConnectError> {
    let (client_hello, _) = build_legacy_dtls_client_hello(
        client_random,
        &options.session_id,
        &[],
        suite,
        0,
    )?;
    let mut retry_interval = options.initial_retry_interval;
    for _ in 0..options.retries {
        send_handshake_datagram(
            packet,
            destination,
            &client_hello,
            cancellation,
        )
        .await?;
        let attempt_deadline = (Instant::now() + retry_interval).min(deadline);
        let Some(records) = receive_handshake_records(
            packet,
            destination,
            suite,
            cancellation,
            attempt_deadline,
        )
        .await?
        else {
            retry_interval = retry_interval.saturating_mul(2);
            continue;
        };
        for record in &records {
            if record.content_type != LEGACY_DTLS_CONTENT_HANDSHAKE
                || record.epoch != 0
            {
                continue;
            }
            let message = parse_legacy_dtls_handshake_message(&record.payload)?;
            match message.message_type {
                LEGACY_DTLS_HANDSHAKE_HELLO_VERIFY => {
                    if message.sequence != 0 {
                        return Err(
                            LegacyDtlsConnectError::UnexpectedHelloVerifySequence(
                                message.sequence,
                            ),
                        );
                    }
                    return Ok(LegacyDtlsInitialResponse::Cookie(
                        parse_legacy_dtls_hello_verify(&message.body, suite)?,
                    ));
                }
                LEGACY_DTLS_HANDSHAKE_SERVER_HELLO => {
                    return Ok(LegacyDtlsInitialResponse::ServerRecords(
                        records,
                    ));
                }
                _ => {}
            }
        }
        retry_interval = retry_interval.saturating_mul(2);
    }
    Err(LegacyDtlsConnectError::InitialResponseTimeout)
}

#[allow(clippy::too_many_arguments)]
async fn exchange_server_flight(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    client_random: &[u8],
    client_hello: &[u8],
    client_hello_body: &[u8],
    initial_records: &[LegacyDtlsRecord],
    server_hello_sequence: u16,
    options: &LegacyDtlsConnectOptions,
    suite: &LegacyDtlsSuite,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<(LegacyDtlsServerFlight, u64), LegacyDtlsConnectError> {
    let mut flight = LegacyDtlsServerFlight::default();
    let mut next_record_sequence = 1_u64;
    if !initial_records.is_empty()
        && process_legacy_dtls_server_records(
            initial_records,
            &mut flight,
            client_hello_body,
            &options.session_id,
            &options.master_secret,
            client_random,
            suite,
            server_hello_sequence,
        )?
    {
        return Ok((flight, next_record_sequence));
    }
    let mut retry_interval = options.initial_retry_interval;
    for attempt in 0..options.retries {
        if attempt > 0 || initial_records.is_empty() {
            let mut encoded_client_hello = client_hello.to_vec();
            encoded_client_hello[5..11]
                .copy_from_slice(&next_record_sequence.to_be_bytes()[2..]);
            next_record_sequence += 1;
            send_handshake_datagram(
                packet,
                destination,
                &encoded_client_hello,
                cancellation,
            )
            .await?;
        }
        let attempt_deadline = (Instant::now() + retry_interval).min(deadline);
        while let Some(records) = receive_handshake_records(
            packet,
            destination,
            suite,
            cancellation,
            attempt_deadline,
        )
        .await?
        {
            if process_legacy_dtls_server_records(
                &records,
                &mut flight,
                client_hello_body,
                &options.session_id,
                &options.master_secret,
                client_random,
                suite,
                server_hello_sequence,
            )? {
                return Ok((flight, next_record_sequence));
            }
        }
        retry_interval = retry_interval.saturating_mul(2);
    }
    Err(LegacyDtlsConnectError::ServerFlightTimeout)
}

async fn send_handshake_datagram(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    datagram: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), LegacyDtlsConnectError> {
    let actual = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            return Err(LegacyDtlsConnectError::Cancelled);
        }
        result = packet.send_to(datagram, destination) => result?,
    };
    if actual != datagram.len() {
        return Err(LegacyDtlsConnectError::ShortWrite {
            actual,
            expected: datagram.len(),
        });
    }
    Ok(())
}

async fn receive_handshake_records(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    suite: &LegacyDtlsSuite,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Option<Vec<LegacyDtlsRecord>>, LegacyDtlsConnectError> {
    let mut datagram = vec![0; 64 * 1024];
    loop {
        let received = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(LegacyDtlsConnectError::Cancelled);
            }
            result = timeout_at(deadline, packet.recv_from(&mut datagram)) => result,
        };
        let Ok(received) = received else {
            return Ok(None);
        };
        let (size, source) = received?;
        if source != *destination {
            continue;
        }
        return Ok(Some(parse_legacy_dtls_records(&datagram[..size], suite)?));
    }
}

pub fn build_legacy_dtls_handshake_message(
    message_type: u8,
    sequence: u16,
    body: &[u8],
) -> Result<Vec<u8>, LegacyDtlsHandshakeError> {
    if body.len() > 0x00ff_ffff {
        return Err(LegacyDtlsHandshakeError::FragmentedHandshake);
    }
    let mut message = vec![0; LEGACY_DTLS_HANDSHAKE_HEADER_LENGTH + body.len()];
    message[0] = message_type;
    write_u24(&mut message[1..4], body.len());
    message[4..6].copy_from_slice(&sequence.to_be_bytes());
    write_u24(&mut message[6..9], 0);
    write_u24(&mut message[9..12], body.len());
    message[12..].copy_from_slice(body);
    Ok(message)
}

pub fn parse_legacy_dtls_handshake_message(
    payload: &[u8],
) -> Result<LegacyDtlsHandshakeMessage, LegacyDtlsHandshakeError> {
    if payload.len() < LEGACY_DTLS_HANDSHAKE_HEADER_LENGTH {
        return Err(LegacyDtlsHandshakeError::ShortHandshake);
    }
    let body_length = read_u24(&payload[1..4]);
    let fragment_offset = read_u24(&payload[6..9]);
    let fragment_length = read_u24(&payload[9..12]);
    if fragment_offset != 0
        || fragment_length != body_length
        || payload.len() != LEGACY_DTLS_HANDSHAKE_HEADER_LENGTH + body_length
    {
        return Err(LegacyDtlsHandshakeError::FragmentedHandshake);
    }
    Ok(LegacyDtlsHandshakeMessage {
        message_type: payload[0],
        sequence: u16::from_be_bytes([payload[4], payload[5]]),
        body: payload[12..].to_vec(),
    })
}

pub fn build_legacy_dtls_client_hello(
    client_random: &[u8],
    session_id: &[u8],
    cookie: &[u8],
    suite: &LegacyDtlsSuite,
    record_sequence: u64,
) -> Result<(Vec<u8>, Vec<u8>), LegacyDtlsHandshakeError> {
    if client_random.len() != 32
        || session_id.len() > u8::MAX as usize
        || cookie.len() > u8::MAX as usize
    {
        return Err(LegacyDtlsHandshakeError::InvalidClientHello);
    }
    let mut body = Vec::with_capacity(75 + cookie.len());
    body.extend_from_slice(&suite.version.to_be_bytes());
    body.extend_from_slice(client_random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);
    body.extend_from_slice(&[0, 2]);
    body.extend_from_slice(&suite.cipher_suite_id.to_be_bytes());
    body.extend_from_slice(&[1, 0, 0, 0]);
    let handshake = build_legacy_dtls_handshake_message(
        LEGACY_DTLS_HANDSHAKE_CLIENT_HELLO,
        0,
        &body,
    )?;
    let record = marshal_legacy_dtls_record(
        &LegacyDtlsRecord {
            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
            epoch: 0,
            sequence: record_sequence,
            payload: handshake,
        },
        suite,
    )?;
    Ok((record, body))
}

pub fn parse_legacy_dtls_hello_verify(
    body: &[u8],
    suite: &LegacyDtlsSuite,
) -> Result<Vec<u8>, LegacyDtlsHandshakeError> {
    if body.len() < 3 || body[..2] != suite.version.to_be_bytes() {
        return Err(LegacyDtlsHandshakeError::InvalidHelloVerifyVersion);
    }
    let cookie_length = usize::from(body[2]);
    if cookie_length == 0 || body.len() != 3 + cookie_length {
        return Err(LegacyDtlsHandshakeError::InvalidHelloVerifyCookie);
    }
    Ok(body[3..].to_vec())
}

pub fn parse_legacy_dtls_server_hello(
    body: &[u8],
    session_id: &[u8],
    suite: &LegacyDtlsSuite,
) -> Result<Vec<u8>, LegacyDtlsHandshakeError> {
    if body.len() < 38 || body[..2] != suite.version.to_be_bytes() {
        return Err(LegacyDtlsHandshakeError::InvalidServerHelloVersion);
    }
    let server_random = body[2..34].to_vec();
    let session_length = usize::from(body[34]);
    let mut position = 35;
    if body.len() < position + session_length + 3
        || body[position..position + session_length] != *session_id
    {
        return Err(LegacyDtlsHandshakeError::SessionIdRejected);
    }
    position += session_length;
    let selected_cipher =
        u16::from_be_bytes([body[position], body[position + 1]]);
    position += 2;
    if selected_cipher != suite.cipher_suite_id {
        return Err(LegacyDtlsHandshakeError::UnexpectedCipher(
            selected_cipher,
        ));
    }
    if body[position] != 0 {
        return Err(LegacyDtlsHandshakeError::UnsupportedCompression(
            body[position],
        ));
    }
    position += 1;
    if position < body.len() {
        if body.len() - position < 2 {
            return Err(LegacyDtlsHandshakeError::TruncatedExtensions);
        }
        let extension_length = usize::from(u16::from_be_bytes([
            body[position],
            body[position + 1],
        ]));
        if body.len() != position + 2 + extension_length {
            return Err(LegacyDtlsHandshakeError::InvalidExtensions);
        }
    }
    Ok(server_random)
}

pub fn legacy_dtls_finished(
    master_secret: &[u8],
    label: &str,
    transcript: &[u8],
) -> Vec<u8> {
    let mut handshake_hash = Md5::digest(transcript).to_vec();
    handshake_hash.extend_from_slice(&Sha1::digest(transcript));
    tls10_prf(master_secret, label, &handshake_hash, 12)
}

#[allow(clippy::too_many_arguments)]
pub fn process_legacy_dtls_server_records(
    records: &[LegacyDtlsRecord],
    flight: &mut LegacyDtlsServerFlight,
    client_hello_body: &[u8],
    session_id: &[u8],
    master_secret: &[u8],
    client_random: &[u8],
    suite: &LegacyDtlsSuite,
    server_hello_sequence: u16,
) -> Result<bool, LegacyDtlsHandshakeError> {
    for record in records {
        match record.content_type {
            LEGACY_DTLS_CONTENT_HANDSHAKE if record.epoch == 0 => {
                let message =
                    parse_legacy_dtls_handshake_message(&record.payload)?;
                if message.message_type == LEGACY_DTLS_HANDSHAKE_HELLO_VERIFY {
                    continue;
                }
                if message.message_type != LEGACY_DTLS_HANDSHAKE_SERVER_HELLO {
                    return Err(LegacyDtlsHandshakeError::UnexpectedHandshake(
                        message.message_type,
                    ));
                }
                if message.sequence != server_hello_sequence {
                    return Err(
                        LegacyDtlsHandshakeError::UnexpectedServerHelloSequence(
                            message.sequence,
                        ),
                    );
                }
                let server_random = parse_legacy_dtls_server_hello(
                    &message.body,
                    session_id,
                    suite,
                )?;
                flight.keys = Some(derive_legacy_dtls_keys(
                    suite,
                    master_secret,
                    client_random,
                    &server_random,
                ));
                flight.server_random = server_random;
                flight.server_hello_body = message.body;
            }
            LEGACY_DTLS_CONTENT_HANDSHAKE if record.epoch == 1 => {
                let keys = flight.keys.as_ref().ok_or(
                    LegacyDtlsHandshakeError::FinishedBeforeServerHello,
                )?;
                let plaintext = decrypt_legacy_dtls_record(
                    record,
                    &keys.server_key,
                    &keys.server_mac_key,
                    suite,
                )?;
                let message = parse_legacy_dtls_handshake_message(&plaintext)?;
                if message.message_type != LEGACY_DTLS_HANDSHAKE_FINISHED
                    || message.body.len() != 12
                {
                    return Err(LegacyDtlsHandshakeError::InvalidFinished);
                }
                if message.sequence != server_hello_sequence + 2 {
                    return Err(
                        LegacyDtlsHandshakeError::UnexpectedFinishedSequence(
                            message.sequence,
                        ),
                    );
                }
                let mut transcript = Vec::with_capacity(
                    client_hello_body.len() + flight.server_hello_body.len(),
                );
                transcript.extend_from_slice(client_hello_body);
                transcript.extend_from_slice(&flight.server_hello_body);
                let expected = legacy_dtls_finished(
                    master_secret,
                    "server finished",
                    &transcript,
                );
                if !memcmp::eq(&message.body, &expected) {
                    return Err(LegacyDtlsHandshakeError::FinishedVerification);
                }
                flight.server_finished = message.body;
            }
            LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC => {
                let expected = [
                    1,
                    ((server_hello_sequence + 1) >> 8) as u8,
                    (server_hello_sequence + 1) as u8,
                ];
                if record.epoch != 0 || record.payload != expected {
                    return Err(
                        LegacyDtlsHandshakeError::InvalidChangeCipherSpec,
                    );
                }
                flight.change_cipher_seen = true;
            }
            LEGACY_DTLS_CONTENT_ALERT => {
                return Err(LegacyDtlsHandshakeError::Alert);
            }
            value => {
                return Err(LegacyDtlsHandshakeError::UnexpectedRecord(value));
            }
        }
    }
    Ok(flight.keys.is_some()
        && flight.change_cipher_seen
        && flight.server_finished.len() == 12)
}

pub fn build_legacy_dtls_client_final_flight(
    flight: &LegacyDtlsServerFlight,
    client_hello_body: &[u8],
    master_secret: &[u8],
    suite: &LegacyDtlsSuite,
    server_hello_sequence: u16,
    unencrypted_record_sequence: u64,
) -> Result<Vec<u8>, LegacyDtlsHandshakeError> {
    let keys = flight
        .keys
        .as_ref()
        .ok_or(LegacyDtlsHandshakeError::FinishedBeforeServerHello)?;
    let mut transcript = Vec::with_capacity(
        client_hello_body.len()
            + flight.server_hello_body.len()
            + flight.server_finished.len(),
    );
    transcript.extend_from_slice(client_hello_body);
    transcript.extend_from_slice(&flight.server_hello_body);
    transcript.extend_from_slice(&flight.server_finished);
    let verify_data =
        legacy_dtls_finished(master_secret, "client finished", &transcript);
    let finished = build_legacy_dtls_handshake_message(
        LEGACY_DTLS_HANDSHAKE_FINISHED,
        server_hello_sequence + 2,
        &verify_data,
    )?;
    let mut result = marshal_legacy_dtls_record(
        &LegacyDtlsRecord {
            content_type: LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC,
            epoch: 0,
            sequence: unencrypted_record_sequence,
            payload: vec![
                1,
                ((server_hello_sequence + 1) >> 8) as u8,
                (server_hello_sequence + 1) as u8,
            ],
        },
        suite,
    )?;
    result.extend(encrypt_legacy_dtls_record(
        &LegacyDtlsRecord {
            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
            epoch: 1,
            sequence: 0,
            payload: finished,
        },
        &keys.client_key,
        &keys.client_mac_key,
        suite,
    )?);
    Ok(result)
}

fn write_u24(output: &mut [u8], value: usize) {
    output[0] = (value >> 16) as u8;
    output[1] = (value >> 8) as u8;
    output[2] = value as u8;
}

fn read_u24(input: &[u8]) -> usize {
    (usize::from(input[0]) << 16)
        | (usize::from(input[1]) << 8)
        | usize::from(input[2])
}

#[cfg(test)]
mod tests {
    use std::{io, sync::Arc};

    use parking_lot::Mutex as SyncMutex;
    use tokio::sync::{Mutex as TokioMutex, mpsc};

    use crate::adapter::{PacketConnection, PacketFuture};

    use super::*;

    fn suite() -> LegacyDtlsSuite {
        LegacyDtlsSuite::from_name("AES128-SHA", false).unwrap()
    }

    #[test]
    fn client_hello_matches_pinned_wire_shape() {
        let (record, body) = build_legacy_dtls_client_hello(
            &[0x11; 32],
            &[0x22; 32],
            &[0xaa, 0xbb],
            &suite(),
            7,
        )
        .unwrap();
        assert_eq!(record[0], LEGACY_DTLS_CONTENT_HANDSHAKE);
        assert_eq!(&record[1..3], &[1, 0]);
        assert_eq!(&record[5..11], &[0, 0, 0, 0, 0, 7]);
        assert_eq!(&body[..2], &[1, 0]);
        assert_eq!(body[34], 32);
        assert_eq!(&body[35..67], &[0x22; 32]);
        assert_eq!(&body[67..], &[2, 0xaa, 0xbb, 0, 2, 0, 0x2f, 1, 0, 0, 0]);
        let handshake =
            parse_legacy_dtls_handshake_message(&record[13..]).unwrap();
        assert_eq!(handshake.body, body);
    }

    #[test]
    fn hello_verify_requires_nonempty_exact_cookie() {
        assert_eq!(
            parse_legacy_dtls_hello_verify(&[1, 0, 2, 0xaa, 0xbb], &suite())
                .unwrap(),
            [0xaa, 0xbb]
        );
        assert!(parse_legacy_dtls_hello_verify(&[1, 0, 0], &suite()).is_err());
    }

    #[test]
    fn server_hello_checks_injected_session_and_cipher() {
        let session = [0x44; 32];
        let mut body = vec![1, 0];
        body.extend_from_slice(&[0x55; 32]);
        body.push(32);
        body.extend_from_slice(&session);
        body.extend_from_slice(&[0, 0x2f, 0, 0, 0]);
        assert_eq!(
            parse_legacy_dtls_server_hello(&body, &session, &suite()).unwrap(),
            [0x55; 32]
        );
        body[35] = 0x45;
        assert!(matches!(
            parse_legacy_dtls_server_hello(&body, &session, &suite()),
            Err(LegacyDtlsHandshakeError::SessionIdRejected)
        ));
    }

    #[test]
    fn handshake_parser_rejects_fragments() {
        let mut message =
            build_legacy_dtls_handshake_message(2, 1, b"hello").unwrap();
        message[8] = 1;
        assert!(matches!(
            parse_legacy_dtls_handshake_message(&message),
            Err(LegacyDtlsHandshakeError::FragmentedHandshake)
        ));
    }

    #[test]
    fn finished_is_twelve_bytes_and_changes_with_label() {
        let server =
            legacy_dtls_finished(&[0x11; 48], "server finished", b"transcript");
        let client =
            legacy_dtls_finished(&[0x11; 48], "client finished", b"transcript");
        assert_eq!(server.len(), 12);
        assert_ne!(server, client);
    }

    #[test]
    fn server_flight_verifies_and_builds_client_final_flight() {
        let suite = suite();
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let session = [0x33; 32];
        let master = [0x44; 48];
        let (_, client_body) = build_legacy_dtls_client_hello(
            &client_random,
            &session,
            b"cookie",
            &suite,
            1,
        )
        .unwrap();
        let mut server_body = vec![1, 0];
        server_body.extend_from_slice(&server_random);
        server_body.push(32);
        server_body.extend_from_slice(&session);
        server_body.extend_from_slice(&[0, 0x2f, 0]);
        let server_hello = build_legacy_dtls_handshake_message(
            LEGACY_DTLS_HANDSHAKE_SERVER_HELLO,
            1,
            &server_body,
        )
        .unwrap();
        let keys = derive_legacy_dtls_keys(
            &suite,
            &master,
            &client_random,
            &server_random,
        );
        let mut transcript = client_body.clone();
        transcript.extend_from_slice(&server_body);
        let server_verify =
            legacy_dtls_finished(&master, "server finished", &transcript);
        let server_finished = build_legacy_dtls_handshake_message(
            LEGACY_DTLS_HANDSHAKE_FINISHED,
            3,
            &server_verify,
        )
        .unwrap();
        let records = vec![
            LegacyDtlsRecord {
                content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                epoch: 0,
                sequence: 1,
                payload: server_hello,
            },
            LegacyDtlsRecord {
                content_type: LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC,
                epoch: 0,
                sequence: 2,
                payload: vec![1, 0, 2],
            },
            LegacyDtlsRecord {
                content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                epoch: 1,
                sequence: 0,
                payload: parse_encrypted_payload(
                    &encrypt_legacy_dtls_record(
                        &LegacyDtlsRecord {
                            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                            epoch: 1,
                            sequence: 0,
                            payload: server_finished,
                        },
                        &keys.server_key,
                        &keys.server_mac_key,
                        &suite,
                    )
                    .unwrap(),
                ),
            },
        ];
        let mut flight = LegacyDtlsServerFlight::default();
        assert!(
            process_legacy_dtls_server_records(
                &records,
                &mut flight,
                &client_body,
                &session,
                &master,
                &client_random,
                &suite,
                1,
            )
            .unwrap()
        );
        let final_flight = build_legacy_dtls_client_final_flight(
            &flight,
            &client_body,
            &master,
            &suite,
            1,
            3,
        )
        .unwrap();
        assert_eq!(final_flight[0], LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC);
        assert_eq!(final_flight[16], LEGACY_DTLS_CONTENT_HANDSHAKE);
    }

    fn parse_encrypted_payload(record: &[u8]) -> Vec<u8> {
        record[13..].to_vec()
    }

    struct ScriptedHandshakeState {
        suite: LegacyDtlsSuite,
        master_secret: [u8; 48],
        incoming: mpsc::UnboundedSender<Vec<u8>>,
        sent: SyncMutex<Vec<Vec<u8>>>,
    }

    impl ScriptedHandshakeState {
        fn accept(&self, datagram: &[u8]) -> io::Result<()> {
            let mut sent = self.sent.lock();
            sent.push(datagram.to_vec());
            let index = sent.len();
            drop(sent);
            match index {
                1 => {
                    let verify = build_legacy_dtls_handshake_message(
                        LEGACY_DTLS_HANDSHAKE_HELLO_VERIFY,
                        0,
                        &[1, 0, 3, 9, 8, 7],
                    )
                    .unwrap();
                    let response = marshal_legacy_dtls_record(
                        &LegacyDtlsRecord {
                            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                            epoch: 0,
                            sequence: 0,
                            payload: verify,
                        },
                        &self.suite,
                    )
                    .unwrap();
                    self.incoming.send(response).unwrap();
                }
                2 => {
                    let record =
                        parse_legacy_dtls_records(datagram, &self.suite)
                            .unwrap()
                            .remove(0);
                    let hello =
                        parse_legacy_dtls_handshake_message(&record.payload)
                            .unwrap();
                    let client_random = &hello.body[2..34];
                    let session_length = usize::from(hello.body[34]);
                    let session = &hello.body[35..35 + session_length];
                    assert_eq!(
                        &hello.body[35 + session_length..38 + session_length],
                        &[3, 9, 8]
                    );
                    let server_random = [0x55; 32];
                    let mut server_body = vec![1, 0];
                    server_body.extend_from_slice(&server_random);
                    server_body.push(session.len() as u8);
                    server_body.extend_from_slice(session);
                    server_body.extend_from_slice(
                        &self.suite.cipher_suite_id.to_be_bytes(),
                    );
                    server_body.push(0);
                    let server_hello = build_legacy_dtls_handshake_message(
                        LEGACY_DTLS_HANDSHAKE_SERVER_HELLO,
                        1,
                        &server_body,
                    )
                    .unwrap();
                    let keys = derive_legacy_dtls_keys(
                        &self.suite,
                        &self.master_secret,
                        client_random,
                        &server_random,
                    );
                    let mut transcript = hello.body;
                    transcript.extend_from_slice(&server_body);
                    let verify_data = legacy_dtls_finished(
                        &self.master_secret,
                        "server finished",
                        &transcript,
                    );
                    let finished = build_legacy_dtls_handshake_message(
                        LEGACY_DTLS_HANDSHAKE_FINISHED,
                        3,
                        &verify_data,
                    )
                    .unwrap();
                    let mut response = marshal_legacy_dtls_record(
                        &LegacyDtlsRecord {
                            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                            epoch: 0,
                            sequence: 1,
                            payload: server_hello,
                        },
                        &self.suite,
                    )
                    .unwrap();
                    response.extend(
                        marshal_legacy_dtls_record(
                            &LegacyDtlsRecord {
                                content_type:
                                    LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC,
                                epoch: 0,
                                sequence: 2,
                                payload: vec![1, 0, 2],
                            },
                            &self.suite,
                        )
                        .unwrap(),
                    );
                    response.extend(
                        encrypt_legacy_dtls_record(
                            &LegacyDtlsRecord {
                                content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                                epoch: 1,
                                sequence: 0,
                                payload: finished,
                            },
                            &keys.server_key,
                            &keys.server_mac_key,
                            &self.suite,
                        )
                        .unwrap(),
                    );
                    self.incoming.send(response).unwrap();
                }
                _ => {}
            }
            Ok(())
        }
    }

    struct ScriptedHandshakePacket {
        state: Arc<ScriptedHandshakeState>,
        incoming: TokioMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        peer: SocksAddr,
    }

    impl PacketConnection for ScriptedHandshakePacket {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                if destination != &self.peer {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected peer",
                    ));
                }
                self.state.accept(data)?;
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let packet = self
                    .incoming
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "closed")
                    })?;
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), self.peer.clone()))
            })
        }
    }

    #[tokio::test]
    async fn connect_driver_completes_cookie_and_abbreviated_flights() {
        let peer = SocksAddr::new("vpn.test", 443);
        let suite = suite();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let state = Arc::new(ScriptedHandshakeState {
            suite,
            master_secret: [0x44; 48],
            incoming: incoming_tx,
            sent: SyncMutex::new(Vec::new()),
        });
        let packet = Box::new(ScriptedHandshakePacket {
            state: state.clone(),
            incoming: TokioMutex::new(incoming_rx),
            peer: peer.clone(),
        });
        let session = connect_legacy_dtls(
            packet,
            peer,
            &LegacyDtlsConnectOptions {
                session_id: vec![0x33; 32],
                master_secret: vec![0x44; 48],
                cipher_suite: "AES128-SHA".into(),
                handshake_timeout: Duration::from_secs(1),
                initial_retry_interval: Duration::from_millis(10),
                ..Default::default()
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!session.is_closed());
        let sent = state.sent.lock();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[2][0], LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC);
        assert_eq!(sent[2][16], LEGACY_DTLS_CONTENT_HANDSHAKE);
    }
}
