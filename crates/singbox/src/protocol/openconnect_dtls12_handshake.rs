//! AnyConnect DTLS 1.2 abbreviated-resumption handshake.
//!
//! CSTP supplies the session ID and master secret.  The client must advertise
//! exactly that session, omit normal TLS extensions, and reject a server which
//! falls back to a full handshake.

use std::{io, time::Duration};

use openssl::memcmp;
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use super::{
    DTLS12_VERSION, Dtls12Error, Dtls12Keys, Dtls12Record, Dtls12Session,
    Dtls12Suite, decrypt_dtls12_record, derive_dtls12_keys, dtls12_finished,
    encrypt_dtls12_record, marshal_dtls12_record, parse_dtls12_records,
};
use crate::{adapter::PacketStream, common::network::SocksAddr};

pub const DTLS12_CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const DTLS12_CONTENT_ALERT: u8 = 21;
pub const DTLS12_CONTENT_HANDSHAKE: u8 = 22;
pub const DTLS12_CONTENT_APPLICATION_DATA: u8 = 23;
pub const DTLS12_HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const DTLS12_HANDSHAKE_SERVER_HELLO: u8 = 2;
pub const DTLS12_HANDSHAKE_HELLO_VERIFY: u8 = 3;
pub const DTLS12_HANDSHAKE_FINISHED: u8 = 20;
pub const DTLS12_HANDSHAKE_HEADER_LENGTH: usize = 12;
const DTLS10_VERSION: u16 = 0xfeff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dtls12HandshakeMessage {
    pub message_type: u8,
    pub sequence: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Dtls12ServerFlight {
    pub server_random: Vec<u8>,
    pub server_hello: Vec<u8>,
    pub keys: Option<Dtls12Keys>,
    pub change_cipher_seen: bool,
    pub server_finished: Vec<u8>,
}

impl std::fmt::Debug for Dtls12ServerFlight {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Dtls12ServerFlight")
            .field("server_random", &self.server_random)
            .field("server_hello", &self.server_hello)
            .field("keys_ready", &self.keys.is_some())
            .field("change_cipher_seen", &self.change_cipher_seen)
            .field("server_finished", &self.server_finished)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum Dtls12HandshakeError {
    #[error(transparent)]
    Record(#[from] Dtls12Error),
    #[error("invalid DTLS 1.2 ClientHello parameters")]
    InvalidClientHello,
    #[error("short DTLS 1.2 handshake header")]
    ShortHandshake,
    #[error("fragmented, coalesced, or truncated DTLS 1.2 handshake message")]
    FragmentedHandshake,
    #[error("invalid DTLS 1.2 HelloVerify version")]
    InvalidHelloVerifyVersion,
    #[error("invalid DTLS 1.2 HelloVerify cookie")]
    InvalidHelloVerifyCookie,
    #[error("invalid DTLS 1.2 ServerHello version")]
    InvalidServerHelloVersion,
    #[error("DTLS 1.2 server did not accept the injected Session-ID")]
    SessionIdRejected,
    #[error("DTLS 1.2 server selected unexpected cipher: {0:#06x}")]
    UnexpectedCipher(u16),
    #[error("DTLS 1.2 server selected unsupported compression: {0}")]
    UnsupportedCompression(u8),
    #[error("truncated DTLS 1.2 ServerHello extensions")]
    TruncatedExtensions,
    #[error("invalid DTLS 1.2 ServerHello extensions")]
    InvalidExtensions,
    #[error("unexpected DTLS 1.2 handshake message: {0}")]
    UnexpectedHandshake(u8),
    #[error("DTLS 1.2 ServerHello has unexpected handshake sequence: {0}")]
    UnexpectedServerHelloSequence(u16),
    #[error("DTLS 1.2 sent encrypted Finished before ServerHello")]
    FinishedBeforeServerHello,
    #[error("invalid DTLS 1.2 server Finished")]
    InvalidFinished,
    #[error("DTLS 1.2 server Finished has unexpected handshake sequence: {0}")]
    UnexpectedFinishedSequence(u16),
    #[error("DTLS 1.2 server Finished verification failed")]
    FinishedVerification,
    #[error("invalid DTLS 1.2 ChangeCipherSpec")]
    InvalidChangeCipherSpec,
    #[error("DTLS 1.2 peer sent an alert during handshake")]
    Alert,
    #[error("unexpected DTLS 1.2 server-flight record: {0}")]
    UnexpectedRecord(u8),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Dtls12ConnectOptions {
    pub session_id: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub cipher_suite: String,
    pub mtu: usize,
    pub strict: bool,
    pub close_alert: bool,
    pub handshake_timeout: Duration,
    pub initial_retry_interval: Duration,
    pub retries: usize,
}

impl std::fmt::Debug for Dtls12ConnectOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Dtls12ConnectOptions")
            .field("session_id", &self.session_id)
            .field("master_secret", &"[REDACTED]")
            .field("cipher_suite", &self.cipher_suite)
            .field("mtu", &self.mtu)
            .field("strict", &self.strict)
            .field("close_alert", &self.close_alert)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("initial_retry_interval", &self.initial_retry_interval)
            .field("retries", &self.retries)
            .finish()
    }
}

impl Default for Dtls12ConnectOptions {
    fn default() -> Self {
        Self {
            session_id: Vec::new(),
            master_secret: Vec::new(),
            cipher_suite: "OC-DTLS1_2-AES256-GCM".into(),
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
pub enum Dtls12ConnectError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Record(#[from] Dtls12Error),
    #[error(transparent)]
    Handshake(#[from] Dtls12HandshakeError),
    #[error(
        "DTLS 1.2 resumption requires a 32-byte X-DTLS-Session-ID, got {0}"
    )]
    InvalidSessionId(usize),
    #[error("DTLS 1.2 resumption requires a 48-byte master secret, got {0}")]
    InvalidMasterSecret(usize),
    #[error("DTLS 1.2 handshake was cancelled")]
    Cancelled,
    #[error("DTLS 1.2 peer did not answer the ClientHello")]
    InitialResponseTimeout,
    #[error("DTLS 1.2 abbreviated handshake did not complete")]
    ServerFlightTimeout,
    #[error("DTLS 1.2 HelloVerify has unexpected handshake sequence: {0}")]
    UnexpectedHelloVerifySequence(u16),
    #[error(
        "DTLS 1.2 datagram write was short: wrote {actual} of {expected} bytes"
    )]
    ShortWrite { actual: usize, expected: usize },
}

enum Dtls12InitialResponse {
    Cookie(Vec<u8>),
    ServerRecords(Vec<Dtls12Record>),
}

/// Establish an injected-session AnyConnect DTLS 1.2 channel.
pub async fn connect_dtls12_resumption(
    packet: PacketStream,
    destination: SocksAddr,
    options: &Dtls12ConnectOptions,
    cancellation: &CancellationToken,
) -> Result<Dtls12Session, Dtls12ConnectError> {
    if options.session_id.len() != 32 {
        return Err(Dtls12ConnectError::InvalidSessionId(
            options.session_id.len(),
        ));
    }
    if options.master_secret.len() != 48 {
        return Err(Dtls12ConnectError::InvalidMasterSecret(
            options.master_secret.len(),
        ));
    }
    let suite = Dtls12Suite::from_name(&options.cipher_suite, true)?;
    let mut client_random = [0_u8; 32];
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    client_random[..4].copy_from_slice(&unix_seconds.to_be_bytes());
    getrandom::fill(&mut client_random[4..]).map_err(Dtls12Error::from)?;

    let deadline = Instant::now() + options.handshake_timeout;
    let (initial_hello, initial_transcript) = build_dtls12_client_hello(
        &client_random,
        &options.session_id,
        &[],
        &suite,
        0,
        0,
    )?;
    let initial = exchange_initial_response(
        packet.as_ref(),
        &destination,
        &initial_hello,
        options,
        cancellation,
        deadline,
    )
    .await?;
    let (
        client_hello,
        client_hello_transcript,
        initial_records,
        next_sequence,
        server_sequence,
    ) = match initial {
        Dtls12InitialResponse::Cookie(cookie) => {
            let (hello, transcript) = build_dtls12_client_hello(
                &client_random,
                &options.session_id,
                &cookie,
                &suite,
                1,
                1,
            )?;
            (hello, transcript, Vec::new(), 2, 1)
        }
        Dtls12InitialResponse::ServerRecords(records) => {
            (initial_hello, initial_transcript, records, 1, 0)
        }
    };
    let server_flight = exchange_server_flight(
        packet.as_ref(),
        &destination,
        &client_random,
        &client_hello,
        &client_hello_transcript,
        &initial_records,
        server_sequence,
        options,
        &suite,
        cancellation,
        deadline,
    )
    .await?;
    let final_flight = build_dtls12_client_final_flight(
        &server_flight,
        &client_hello_transcript,
        &options.master_secret,
        &suite,
        server_sequence,
        next_sequence,
    )?;
    send_handshake_datagram(
        packet.as_ref(),
        &destination,
        &final_flight,
        cancellation,
    )
    .await?;
    let keys = server_flight
        .keys
        .ok_or(Dtls12HandshakeError::FinishedBeforeServerHello)?;
    Ok(Dtls12Session::new(
        packet,
        destination,
        suite,
        keys,
        options.mtu,
        options.strict,
        options.close_alert,
        vec![final_flight],
        server_flight.server_finished,
    ))
}

async fn exchange_initial_response(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    client_hello: &[u8],
    options: &Dtls12ConnectOptions,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Dtls12InitialResponse, Dtls12ConnectError> {
    let mut retry_interval = options.initial_retry_interval;
    for _ in 0..options.retries {
        send_handshake_datagram(
            packet,
            destination,
            client_hello,
            cancellation,
        )
        .await?;
        let attempt_deadline = (Instant::now() + retry_interval).min(deadline);
        let Some(records) = receive_handshake_records(
            packet,
            destination,
            cancellation,
            attempt_deadline,
        )
        .await?
        else {
            retry_interval = retry_interval.saturating_mul(2);
            continue;
        };
        for record in &records {
            if record.content_type != DTLS12_CONTENT_HANDSHAKE
                || record.epoch != 0
            {
                continue;
            }
            let message = parse_dtls12_handshake_message(&record.payload)?;
            match message.message_type {
                DTLS12_HANDSHAKE_HELLO_VERIFY => {
                    if message.sequence != 0 {
                        return Err(
                            Dtls12ConnectError::UnexpectedHelloVerifySequence(
                                message.sequence,
                            ),
                        );
                    }
                    return Ok(Dtls12InitialResponse::Cookie(
                        parse_dtls12_hello_verify(&message.body)?,
                    ));
                }
                DTLS12_HANDSHAKE_SERVER_HELLO => {
                    return Ok(Dtls12InitialResponse::ServerRecords(records));
                }
                _ => {}
            }
        }
        retry_interval = retry_interval.saturating_mul(2);
    }
    Err(Dtls12ConnectError::InitialResponseTimeout)
}

#[allow(clippy::too_many_arguments)]
async fn exchange_server_flight(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    client_random: &[u8],
    client_hello: &[u8],
    client_hello_transcript: &[u8],
    initial_records: &[Dtls12Record],
    server_sequence: u16,
    options: &Dtls12ConnectOptions,
    suite: &Dtls12Suite,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Dtls12ServerFlight, Dtls12ConnectError> {
    let mut flight = Dtls12ServerFlight::default();
    if !initial_records.is_empty()
        && process_dtls12_server_records(
            initial_records,
            &mut flight,
            client_hello_transcript,
            &options.session_id,
            &options.master_secret,
            client_random,
            suite,
            server_sequence,
        )?
    {
        return Ok(flight);
    }
    let mut retry_interval = options.initial_retry_interval;
    for attempt in 0..options.retries {
        if attempt > 0 || initial_records.is_empty() {
            send_handshake_datagram(
                packet,
                destination,
                client_hello,
                cancellation,
            )
            .await?;
        }
        let attempt_deadline = (Instant::now() + retry_interval).min(deadline);
        while let Some(records) = receive_handshake_records(
            packet,
            destination,
            cancellation,
            attempt_deadline,
        )
        .await?
        {
            if process_dtls12_server_records(
                &records,
                &mut flight,
                client_hello_transcript,
                &options.session_id,
                &options.master_secret,
                client_random,
                suite,
                server_sequence,
            )? {
                return Ok(flight);
            }
        }
        retry_interval = retry_interval.saturating_mul(2);
    }
    Err(Dtls12ConnectError::ServerFlightTimeout)
}

async fn send_handshake_datagram(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    datagram: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), Dtls12ConnectError> {
    let actual = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            return Err(Dtls12ConnectError::Cancelled);
        }
        result = packet.send_to(datagram, destination) => result?,
    };
    if actual != datagram.len() {
        return Err(Dtls12ConnectError::ShortWrite {
            actual,
            expected: datagram.len(),
        });
    }
    Ok(())
}

async fn receive_handshake_records(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Option<Vec<Dtls12Record>>, Dtls12ConnectError> {
    let mut datagram = vec![0; 64 * 1024];
    loop {
        let received = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(Dtls12ConnectError::Cancelled);
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
        return Ok(Some(parse_dtls12_records(&datagram[..size])?));
    }
}

pub fn build_dtls12_handshake_message(
    message_type: u8,
    sequence: u16,
    body: &[u8],
) -> Result<Vec<u8>, Dtls12HandshakeError> {
    if body.len() > 0x00ff_ffff {
        return Err(Dtls12HandshakeError::FragmentedHandshake);
    }
    let mut message = vec![0; DTLS12_HANDSHAKE_HEADER_LENGTH + body.len()];
    message[0] = message_type;
    write_u24(&mut message[1..4], body.len());
    message[4..6].copy_from_slice(&sequence.to_be_bytes());
    write_u24(&mut message[6..9], 0);
    write_u24(&mut message[9..12], body.len());
    message[12..].copy_from_slice(body);
    Ok(message)
}

pub fn parse_dtls12_handshake_message(
    payload: &[u8],
) -> Result<Dtls12HandshakeMessage, Dtls12HandshakeError> {
    if payload.len() < DTLS12_HANDSHAKE_HEADER_LENGTH {
        return Err(Dtls12HandshakeError::ShortHandshake);
    }
    let body_length = read_u24(&payload[1..4]);
    let fragment_offset = read_u24(&payload[6..9]);
    let fragment_length = read_u24(&payload[9..12]);
    if fragment_offset != 0
        || fragment_length != body_length
        || payload.len() != DTLS12_HANDSHAKE_HEADER_LENGTH + body_length
    {
        return Err(Dtls12HandshakeError::FragmentedHandshake);
    }
    Ok(Dtls12HandshakeMessage {
        message_type: payload[0],
        sequence: u16::from_be_bytes([payload[4], payload[5]]),
        body: payload[12..].to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_dtls12_client_hello(
    client_random: &[u8],
    session_id: &[u8],
    cookie: &[u8],
    suite: &Dtls12Suite,
    handshake_sequence: u16,
    record_sequence: u64,
) -> Result<(Vec<u8>, Vec<u8>), Dtls12HandshakeError> {
    if client_random.len() != 32
        || session_id.len() > u8::MAX as usize
        || cookie.len() > u8::MAX as usize
    {
        return Err(Dtls12HandshakeError::InvalidClientHello);
    }
    let mut body = Vec::with_capacity(75 + cookie.len());
    body.extend_from_slice(&DTLS12_VERSION.to_be_bytes());
    body.extend_from_slice(client_random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);
    body.extend_from_slice(&[0, 2]);
    body.extend_from_slice(&suite.cipher_suite_id.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    // Pion's nil extension list is encoded as an explicit zero length.
    body.extend_from_slice(&[0, 0]);
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

pub fn parse_dtls12_hello_verify(
    body: &[u8],
) -> Result<Vec<u8>, Dtls12HandshakeError> {
    if body.len() < 3 {
        return Err(Dtls12HandshakeError::InvalidHelloVerifyVersion);
    }
    let version = u16::from_be_bytes([body[0], body[1]]);
    if version != DTLS10_VERSION && version != DTLS12_VERSION {
        return Err(Dtls12HandshakeError::InvalidHelloVerifyVersion);
    }
    let cookie_length = usize::from(body[2]);
    if cookie_length == 0 || body.len() != 3 + cookie_length {
        return Err(Dtls12HandshakeError::InvalidHelloVerifyCookie);
    }
    Ok(body[3..].to_vec())
}

pub fn parse_dtls12_server_hello(
    body: &[u8],
    session_id: &[u8],
    suite: &Dtls12Suite,
) -> Result<Vec<u8>, Dtls12HandshakeError> {
    if body.len() < 38 || body[..2] != DTLS12_VERSION.to_be_bytes() {
        return Err(Dtls12HandshakeError::InvalidServerHelloVersion);
    }
    let server_random = body[2..34].to_vec();
    let session_length = usize::from(body[34]);
    let mut offset = 35;
    if body.len() < offset + session_length + 3 {
        return Err(Dtls12HandshakeError::SessionIdRejected);
    }
    if body[offset..offset + session_length] != *session_id {
        return Err(Dtls12HandshakeError::SessionIdRejected);
    }
    offset += session_length;
    let cipher = u16::from_be_bytes([body[offset], body[offset + 1]]);
    if cipher != suite.cipher_suite_id {
        return Err(Dtls12HandshakeError::UnexpectedCipher(cipher));
    }
    offset += 2;
    if body[offset] != 0 {
        return Err(Dtls12HandshakeError::UnsupportedCompression(body[offset]));
    }
    offset += 1;
    if offset != body.len() {
        if body.len() < offset + 2 {
            return Err(Dtls12HandshakeError::TruncatedExtensions);
        }
        let extension_length =
            usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
        if body.len() != offset + 2 + extension_length {
            return Err(Dtls12HandshakeError::InvalidExtensions);
        }
    }
    Ok(server_random)
}

#[allow(clippy::too_many_arguments)]
pub fn process_dtls12_server_records(
    records: &[Dtls12Record],
    flight: &mut Dtls12ServerFlight,
    client_hello: &[u8],
    session_id: &[u8],
    master_secret: &[u8],
    client_random: &[u8],
    suite: &Dtls12Suite,
    server_sequence: u16,
) -> Result<bool, Dtls12HandshakeError> {
    for record in records {
        match record.content_type {
            DTLS12_CONTENT_HANDSHAKE if record.epoch == 0 => {
                let message = parse_dtls12_handshake_message(&record.payload)?;
                if message.message_type == DTLS12_HANDSHAKE_HELLO_VERIFY {
                    continue;
                }
                if message.message_type != DTLS12_HANDSHAKE_SERVER_HELLO {
                    return Err(Dtls12HandshakeError::UnexpectedHandshake(
                        message.message_type,
                    ));
                }
                if message.sequence != server_sequence {
                    return Err(
                        Dtls12HandshakeError::UnexpectedServerHelloSequence(
                            message.sequence,
                        ),
                    );
                }
                let server_random = parse_dtls12_server_hello(
                    &message.body,
                    session_id,
                    suite,
                )?;
                flight.keys = Some(derive_dtls12_keys(
                    suite,
                    master_secret,
                    client_random,
                    &server_random,
                ));
                flight.server_random = server_random;
                flight.server_hello = record.payload.clone();
            }
            DTLS12_CONTENT_HANDSHAKE if record.epoch == 1 => {
                let keys = flight
                    .keys
                    .as_ref()
                    .ok_or(Dtls12HandshakeError::FinishedBeforeServerHello)?;
                let plaintext = decrypt_dtls12_record(
                    record,
                    &keys.server_write_key,
                    &keys.server_mac_key,
                    &keys.server_write_iv,
                    suite,
                )?;
                let message = parse_dtls12_handshake_message(&plaintext)?;
                if message.message_type != DTLS12_HANDSHAKE_FINISHED
                    || message.body.len() != 12
                {
                    return Err(Dtls12HandshakeError::InvalidFinished);
                }
                if message.sequence != server_sequence + 1 {
                    return Err(
                        Dtls12HandshakeError::UnexpectedFinishedSequence(
                            message.sequence,
                        ),
                    );
                }
                let mut transcript = Vec::with_capacity(
                    client_hello.len() + flight.server_hello.len(),
                );
                transcript.extend_from_slice(client_hello);
                transcript.extend_from_slice(&flight.server_hello);
                let expected =
                    dtls12_finished(suite, master_secret, &transcript, false);
                if !memcmp::eq(&message.body, &expected) {
                    return Err(Dtls12HandshakeError::FinishedVerification);
                }
                flight.server_finished = plaintext;
            }
            DTLS12_CONTENT_CHANGE_CIPHER_SPEC => {
                if record.epoch != 0 || record.payload != [1] {
                    return Err(Dtls12HandshakeError::InvalidChangeCipherSpec);
                }
                flight.change_cipher_seen = true;
            }
            DTLS12_CONTENT_ALERT => return Err(Dtls12HandshakeError::Alert),
            value => {
                return Err(Dtls12HandshakeError::UnexpectedRecord(value));
            }
        }
    }
    Ok(flight.keys.is_some()
        && flight.change_cipher_seen
        && !flight.server_finished.is_empty())
}

pub fn build_dtls12_client_final_flight(
    flight: &Dtls12ServerFlight,
    client_hello: &[u8],
    master_secret: &[u8],
    suite: &Dtls12Suite,
    server_sequence: u16,
    unencrypted_record_sequence: u64,
) -> Result<Vec<u8>, Dtls12HandshakeError> {
    let keys = flight
        .keys
        .as_ref()
        .ok_or(Dtls12HandshakeError::FinishedBeforeServerHello)?;
    let mut transcript = Vec::with_capacity(
        client_hello.len()
            + flight.server_hello.len()
            + flight.server_finished.len(),
    );
    transcript.extend_from_slice(client_hello);
    transcript.extend_from_slice(&flight.server_hello);
    transcript.extend_from_slice(&flight.server_finished);
    let verify_data = dtls12_finished(suite, master_secret, &transcript, true);
    let finished = build_dtls12_handshake_message(
        DTLS12_HANDSHAKE_FINISHED,
        server_sequence + 1,
        &verify_data,
    )?;
    let mut result = marshal_dtls12_record(&Dtls12Record {
        content_type: DTLS12_CONTENT_CHANGE_CIPHER_SPEC,
        epoch: 0,
        sequence: unencrypted_record_sequence,
        payload: vec![1],
    })?;
    result.extend(encrypt_dtls12_record(
        &Dtls12Record {
            content_type: DTLS12_CONTENT_HANDSHAKE,
            epoch: 1,
            sequence: 0,
            payload: finished,
        },
        &keys.client_write_key,
        &keys.client_mac_key,
        &keys.client_write_iv,
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
    use std::{collections::VecDeque, sync::Arc};

    use super::*;
    use crate::adapter::{PacketConnection, PacketFuture};

    fn suite() -> Dtls12Suite {
        Dtls12Suite::from_name("OC-DTLS1_2-AES128-GCM", true).unwrap()
    }

    fn server_hello(
        sequence: u16,
        session_id: &[u8],
        suite: &Dtls12Suite,
        server_random: &[u8; 32],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&DTLS12_VERSION.to_be_bytes());
        body.extend_from_slice(server_random);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&suite.cipher_suite_id.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0]);
        build_dtls12_handshake_message(
            DTLS12_HANDSHAKE_SERVER_HELLO,
            sequence,
            &body,
        )
        .unwrap()
    }

    #[test]
    fn client_hello_uses_dtls12_injected_session_and_no_extensions() {
        let suite = suite();
        let session_id = [0x22; 32];
        let (record, transcript) = build_dtls12_client_hello(
            &[0x11; 32],
            &session_id,
            &[1, 2, 3],
            &suite,
            1,
            7,
        )
        .unwrap();
        let record = parse_dtls12_records(&record).unwrap().remove(0);
        assert_eq!(record.sequence, 7);
        let message = parse_dtls12_handshake_message(&record.payload).unwrap();
        assert_eq!(message.sequence, 1);
        assert_eq!(message.body[..2], DTLS12_VERSION.to_be_bytes());
        assert_eq!(message.body[34], 32);
        assert_eq!(&message.body[35..67], &session_id);
        assert_eq!(&message.body[67..71], &[3, 1, 2, 3]);
        assert_eq!(&message.body[71..], &[0, 2, 0x00, 0x9c, 1, 0, 0, 0]);
        assert_eq!(record.payload, transcript);
    }

    #[test]
    fn hello_verify_accepts_dtls10_or_dtls12_version() {
        assert_eq!(
            parse_dtls12_hello_verify(&[0xfe, 0xff, 2, 7, 8]).unwrap(),
            [7, 8]
        );
        assert_eq!(
            parse_dtls12_hello_verify(&[0xfe, 0xfd, 1, 9]).unwrap(),
            [9]
        );
        assert!(matches!(
            parse_dtls12_hello_verify(&[1, 0, 1, 9]),
            Err(Dtls12HandshakeError::InvalidHelloVerifyVersion)
        ));
    }

    #[test]
    fn server_hello_requires_exact_resumed_session_and_cipher() {
        let suite = suite();
        let session_id = [0x22; 32];
        let hello = server_hello(1, &session_id, &suite, &[0x33; 32]);
        let message = parse_dtls12_handshake_message(&hello).unwrap();
        assert_eq!(
            parse_dtls12_server_hello(&message.body, &session_id, &suite)
                .unwrap(),
            [0x33; 32]
        );
        assert!(matches!(
            parse_dtls12_server_hello(&message.body, &[0x44; 32], &suite),
            Err(Dtls12HandshakeError::SessionIdRejected)
        ));
    }

    #[test]
    fn abbreviated_server_flight_and_client_final_flight_verify() {
        let suite = suite();
        let session_id = [0x22; 32];
        let master_secret = [0x44; 48];
        let client_random = [0x11; 32];
        let server_random = [0x33; 32];
        let (_, client_hello) = build_dtls12_client_hello(
            &client_random,
            &session_id,
            &[9, 8],
            &suite,
            1,
            1,
        )
        .unwrap();
        let server_hello = server_hello(1, &session_id, &suite, &server_random);
        let keys = derive_dtls12_keys(
            &suite,
            &master_secret,
            &client_random,
            &server_random,
        );
        let mut server_transcript = client_hello.clone();
        server_transcript.extend_from_slice(&server_hello);
        let server_verify =
            dtls12_finished(&suite, &master_secret, &server_transcript, false);
        let server_finished = build_dtls12_handshake_message(
            DTLS12_HANDSHAKE_FINISHED,
            2,
            &server_verify,
        )
        .unwrap();
        let mut datagram = marshal_dtls12_record(&Dtls12Record {
            content_type: DTLS12_CONTENT_HANDSHAKE,
            epoch: 0,
            sequence: 1,
            payload: server_hello.clone(),
        })
        .unwrap();
        datagram.extend(
            marshal_dtls12_record(&Dtls12Record {
                content_type: DTLS12_CONTENT_CHANGE_CIPHER_SPEC,
                epoch: 0,
                sequence: 2,
                payload: vec![1],
            })
            .unwrap(),
        );
        datagram.extend(
            encrypt_dtls12_record(
                &Dtls12Record {
                    content_type: DTLS12_CONTENT_HANDSHAKE,
                    epoch: 1,
                    sequence: 0,
                    payload: server_finished.clone(),
                },
                &keys.server_write_key,
                &keys.server_mac_key,
                &keys.server_write_iv,
                &suite,
            )
            .unwrap(),
        );
        let records = parse_dtls12_records(&datagram).unwrap();
        let mut flight = Dtls12ServerFlight::default();
        assert!(
            process_dtls12_server_records(
                &records,
                &mut flight,
                &client_hello,
                &session_id,
                &master_secret,
                &client_random,
                &suite,
                1,
            )
            .unwrap()
        );
        assert_eq!(flight.server_finished, server_finished);

        let final_flight = build_dtls12_client_final_flight(
            &flight,
            &client_hello,
            &master_secret,
            &suite,
            1,
            2,
        )
        .unwrap();
        let final_records = parse_dtls12_records(&final_flight).unwrap();
        assert_eq!(final_records.len(), 2);
        assert_eq!(final_records[0].payload, [1]);
        let client_finished = decrypt_dtls12_record(
            &final_records[1],
            &keys.client_write_key,
            &keys.client_mac_key,
            &keys.client_write_iv,
            &suite,
        )
        .unwrap();
        let message = parse_dtls12_handshake_message(&client_finished).unwrap();
        let mut client_transcript = server_transcript;
        client_transcript.extend_from_slice(&server_finished);
        assert_eq!(
            message.body,
            dtls12_finished(&suite, &master_secret, &client_transcript, true)
        );
    }

    #[test]
    fn handshake_parser_rejects_fragmentation() {
        let mut message =
            build_dtls12_handshake_message(1, 0, b"hello").unwrap();
        message[8] = 1;
        assert!(matches!(
            parse_dtls12_handshake_message(&message),
            Err(Dtls12HandshakeError::FragmentedHandshake)
        ));
    }

    struct ScriptState {
        phase: u8,
        queued: VecDeque<Vec<u8>>,
        destination: SocksAddr,
        session_id: [u8; 32],
        master_secret: [u8; 48],
        server_random: [u8; 32],
        suite: Dtls12Suite,
        client_hello: Vec<u8>,
        server_hello: Vec<u8>,
        server_finished: Vec<u8>,
        keys: Option<Dtls12Keys>,
    }

    struct ScriptPacket {
        state: Arc<std::sync::Mutex<ScriptState>>,
    }

    impl PacketConnection for ScriptPacket {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                match state.phase {
                    0 => {
                        let records = parse_dtls12_records(data).unwrap();
                        let hello =
                            parse_dtls12_handshake_message(&records[0].payload)
                                .unwrap();
                        assert_eq!(hello.sequence, 0);
                        assert_eq!(hello.body[67], 0);
                        let verify = build_dtls12_handshake_message(
                            DTLS12_HANDSHAKE_HELLO_VERIFY,
                            0,
                            &[0xfe, 0xfd, 3, 7, 8, 9],
                        )
                        .unwrap();
                        state.queued.push_back(
                            marshal_dtls12_record(&Dtls12Record {
                                content_type: DTLS12_CONTENT_HANDSHAKE,
                                epoch: 0,
                                sequence: 0,
                                payload: verify,
                            })
                            .unwrap(),
                        );
                        state.phase = 1;
                    }
                    1 => {
                        let records = parse_dtls12_records(data).unwrap();
                        let hello =
                            parse_dtls12_handshake_message(&records[0].payload)
                                .unwrap();
                        assert_eq!(hello.sequence, 1);
                        assert_eq!(&hello.body[67..71], &[3, 7, 8, 9]);
                        let mut client_random = [0_u8; 32];
                        client_random.copy_from_slice(&hello.body[2..34]);
                        state.client_hello = records[0].payload.clone();
                        state.server_hello = server_hello(
                            1,
                            &state.session_id,
                            &state.suite,
                            &state.server_random,
                        );
                        let keys = derive_dtls12_keys(
                            &state.suite,
                            &state.master_secret,
                            &client_random,
                            &state.server_random,
                        );
                        let mut transcript = state.client_hello.clone();
                        transcript.extend_from_slice(&state.server_hello);
                        let verify = dtls12_finished(
                            &state.suite,
                            &state.master_secret,
                            &transcript,
                            false,
                        );
                        state.server_finished = build_dtls12_handshake_message(
                            DTLS12_HANDSHAKE_FINISHED,
                            2,
                            &verify,
                        )
                        .unwrap();
                        let mut flight = marshal_dtls12_record(&Dtls12Record {
                            content_type: DTLS12_CONTENT_HANDSHAKE,
                            epoch: 0,
                            sequence: 1,
                            payload: state.server_hello.clone(),
                        })
                        .unwrap();
                        flight.extend(
                            marshal_dtls12_record(&Dtls12Record {
                                content_type: DTLS12_CONTENT_CHANGE_CIPHER_SPEC,
                                epoch: 0,
                                sequence: 2,
                                payload: vec![1],
                            })
                            .unwrap(),
                        );
                        flight.extend(
                            encrypt_dtls12_record(
                                &Dtls12Record {
                                    content_type: DTLS12_CONTENT_HANDSHAKE,
                                    epoch: 1,
                                    sequence: 0,
                                    payload: state.server_finished.clone(),
                                },
                                &keys.server_write_key,
                                &keys.server_mac_key,
                                &keys.server_write_iv,
                                &state.suite,
                            )
                            .unwrap(),
                        );
                        state.keys = Some(keys);
                        state.queued.push_back(flight);
                        state.phase = 2;
                    }
                    2 => {
                        let records = parse_dtls12_records(data).unwrap();
                        assert_eq!(records.len(), 2);
                        assert_eq!(records[0].payload, [1]);
                        let keys = state.keys.as_ref().unwrap();
                        let plaintext = decrypt_dtls12_record(
                            &records[1],
                            &keys.client_write_key,
                            &keys.client_mac_key,
                            &keys.client_write_iv,
                            &state.suite,
                        )
                        .unwrap();
                        let finished =
                            parse_dtls12_handshake_message(&plaintext).unwrap();
                        let mut transcript = state.client_hello.clone();
                        transcript.extend_from_slice(&state.server_hello);
                        transcript.extend_from_slice(&state.server_finished);
                        assert_eq!(
                            finished.body,
                            dtls12_finished(
                                &state.suite,
                                &state.master_secret,
                                &transcript,
                                true,
                            )
                        );
                        state.phase = 3;
                    }
                    phase => panic!("unexpected scripted phase {phase}"),
                }
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                let packet = state.queued.pop_front().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::WouldBlock, "empty script")
                })?;
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), state.destination.clone()))
            })
        }
    }

    #[tokio::test]
    async fn connect_driver_completes_cookie_abbreviated_handshake() {
        let destination = SocksAddr::new("vpn.test", 443);
        let state = Arc::new(std::sync::Mutex::new(ScriptState {
            phase: 0,
            queued: VecDeque::new(),
            destination: destination.clone(),
            session_id: [0x22; 32],
            master_secret: [0x44; 48],
            server_random: [0x33; 32],
            suite: suite(),
            client_hello: Vec::new(),
            server_hello: Vec::new(),
            server_finished: Vec::new(),
            keys: None,
        }));
        let packet = Box::new(ScriptPacket {
            state: state.clone(),
        });
        let options = Dtls12ConnectOptions {
            session_id: vec![0x22; 32],
            master_secret: vec![0x44; 48],
            cipher_suite: "OC-DTLS1_2-AES128-GCM".into(),
            handshake_timeout: Duration::from_secs(1),
            initial_retry_interval: Duration::from_millis(5),
            retries: 2,
            ..Default::default()
        };
        let session = connect_dtls12_resumption(
            packet,
            destination,
            &options,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!session.is_closed());
        assert_eq!(state.lock().unwrap().phase, 3);
    }
}
