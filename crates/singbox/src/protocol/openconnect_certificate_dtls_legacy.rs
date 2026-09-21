//! Complete certificate-authenticated DTLS 1.0 client handshake.
//!
//! F5 gateways which do not advertise DTLS 1.2 use this TLS-1.0-era wire
//! protocol. The resulting data channel is the shared legacy CBC session and
//! remains usable through singbox's routed UDP abstraction.

use std::{io, time::Duration};

use rustls::RootCertStore;
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use super::{
    CERTIFICATE_DTLS_FLIGHT_INTERVAL, CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE,
    CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE_REQUEST,
    CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE_VERIFY,
    CERTIFICATE_DTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE,
    CERTIFICATE_DTLS_HANDSHAKE_FINISHED,
    CERTIFICATE_DTLS_HANDSHAKE_HELLO_VERIFY,
    CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO,
    CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO_DONE,
    CERTIFICATE_DTLS_HANDSHAKE_SERVER_KEY_EXCHANGE,
    CERTIFICATE_DTLS_HANDSHAKE_TIMEOUT, CertificateDtls10CipherSuite,
    CertificateDtls10ClientIdentity, CertificateDtls10CryptoError,
    CertificateDtls10WireError, CertificateDtlsHandshakeReassembler,
    LEGACY_DTLS_CONTENT_ALERT, LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC,
    LEGACY_DTLS_CONTENT_HANDSHAKE, LegacyDtlsError, LegacyDtlsKeys,
    LegacyDtlsRecord, LegacyDtlsSession, LegacyDtlsSuite,
    build_certificate_dtls10_client_hello,
    build_certificate_dtls10_key_exchange, certificate_dtls10_cipher_suites,
    certificate_dtls10_curves, certificate_dtls10_finished,
    certificate_dtls10_master_secret, decrypt_legacy_dtls_record,
    derive_legacy_dtls_keys, encrypt_legacy_dtls_record,
    fragment_certificate_dtls10_handshake_records,
    marshal_certificate_dtls_handshake,
    marshal_certificate_dtls10_certificate_chain, marshal_legacy_dtls_record,
    parse_certificate_dtls10_certificate_chain,
    parse_certificate_dtls10_certificate_request,
    parse_certificate_dtls10_hello_verify,
    parse_certificate_dtls10_server_hello,
    parse_complete_certificate_dtls_handshake, parse_legacy_dtls_records,
    verify_certificate_dtls10_server_chain,
};
use crate::{adapter::PacketStream, common::network::SocksAddr};

const CERTIFICATE_DTLS10_HANDSHAKE_RETRIES: usize = 7;

#[derive(Debug, Clone)]
pub struct CertificateDtls10ClientOptions {
    pub server_name: String,
    pub record_mtu: usize,
    pub roots_cas: RootCertStore,
    pub insecure_skip_verify: bool,
    pub cipher_suites: Vec<u16>,
    pub curves: Vec<u16>,
    pub handshake_timeout: Duration,
    pub flight_interval: Duration,
    pub retries: usize,
    pub client_identity: Option<CertificateDtls10ClientIdentity>,
}

impl Default for CertificateDtls10ClientOptions {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            record_mtu: 1200,
            roots_cas: RootCertStore::empty(),
            insecure_skip_verify: false,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            handshake_timeout: CERTIFICATE_DTLS_HANDSHAKE_TIMEOUT,
            flight_interval: CERTIFICATE_DTLS_FLIGHT_INTERVAL,
            retries: CERTIFICATE_DTLS10_HANDSHAKE_RETRIES,
            client_identity: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum CertificateDtls10ConnectError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Record(#[from] LegacyDtlsError),
    #[error(transparent)]
    Wire(#[from] CertificateDtls10WireError),
    #[error(transparent)]
    Crypto(#[from] CertificateDtls10CryptoError),
    #[error("certificate DTLS 1.0 handshake was cancelled")]
    Cancelled,
    #[error("certificate DTLS 1.0 peer did not answer ClientHello")]
    InitialResponseTimeout,
    #[error("certificate DTLS 1.0 server flight did not complete")]
    ServerFlightTimeout,
    #[error("certificate DTLS 1.0 server Finished did not arrive")]
    ServerFinishedTimeout,
    #[error("certificate DTLS 1.0 datagram write was short")]
    ShortWrite,
    #[error("certificate DTLS 1.0 peer sent handshake alert {0:?}")]
    Alert(Option<u8>),
    #[error("unexpected certificate DTLS 1.0 server handshake message {0}")]
    UnexpectedMessage(u8),
    #[error("incomplete certificate DTLS 1.0 server flight")]
    IncompleteServerFlight,
    #[error("certificate DTLS 1.0 server Finished verification failed")]
    FinishedVerification,
    #[error("invalid certificate DTLS 1.0 ChangeCipherSpec")]
    InvalidChangeCipherSpec,
}

struct ServerFlight {
    random: [u8; 32],
    cipher_suite: CertificateDtls10CipherSuite,
    certificates: Vec<Vec<u8>>,
    server_key_exchange: Vec<u8>,
    certificate_requested: bool,
    certificate_types: Vec<u8>,
    acceptable_cas: Vec<Vec<u8>>,
    complete: bool,
}

/// Establish a legacy F5 certificate DTLS session over an already-dialed
/// packet transport. Client-certificate requests are answered with the TLS
/// 1.0 empty Certificate message; server authentication follows `roots_cas`
/// and `insecure_skip_verify` exactly.
pub async fn connect_certificate_dtls10(
    packet: PacketStream,
    destination: SocksAddr,
    options: &CertificateDtls10ClientOptions,
    cancellation: &CancellationToken,
) -> Result<LegacyDtlsSession, CertificateDtls10ConnectError> {
    let offered_suites =
        certificate_dtls10_cipher_suites(&options.cipher_suites)?;
    let offered_curves = certificate_dtls10_curves(&options.curves)?;
    let initial_suite = offered_suites[0].legacy_record_suite();
    let mut client_random = [0_u8; 32];
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    client_random[..4].copy_from_slice(&seconds.to_be_bytes());
    getrandom::fill(&mut client_random[4..])
        .map_err(CertificateDtls10CryptoError::from)?;
    let deadline = Instant::now() + options.handshake_timeout;
    let mut reassembler = CertificateDtlsHandshakeReassembler::default();
    let mut client_handshake_sequence = 0_u16;
    let mut client_record_sequence = 0_u64;
    let initial_hello = build_certificate_dtls10_client_hello(
        &client_random,
        &[],
        &offered_suites,
        &offered_curves,
        &options.server_name,
        client_handshake_sequence,
    )?;
    let response = exchange_initial_hello(
        packet.as_ref(),
        &destination,
        &initial_suite,
        &initial_hello,
        &mut client_record_sequence,
        &mut reassembler,
        options,
        cancellation,
        deadline,
    )
    .await?;
    let (client_hello, mut server_sequence) = match response {
        InitialResponse::Cookie(cookie) => {
            client_handshake_sequence += 1;
            reassembler.clear();
            (
                build_certificate_dtls10_client_hello(
                    &client_random,
                    &cookie,
                    &offered_suites,
                    &offered_curves,
                    &options.server_name,
                    client_handshake_sequence,
                )?,
                None,
            )
        }
        InitialResponse::ServerHello(sequence) => {
            (initial_hello, Some(sequence))
        }
    };
    let mut transcript = client_hello.clone();
    let flight = exchange_server_flight(
        packet.as_ref(),
        &destination,
        &initial_suite,
        &client_hello,
        &mut client_record_sequence,
        &mut server_sequence,
        &mut reassembler,
        &offered_suites,
        &mut transcript,
        options,
        cancellation,
        deadline,
    )
    .await?;
    verify_certificate_dtls10_server_chain(
        &flight.certificates,
        &options.roots_cas,
        &options.server_name,
        options.insecure_skip_verify,
    )?;
    let key_exchange = build_certificate_dtls10_key_exchange(
        &client_random,
        &flight.random,
        &flight.certificates[0],
        &flight.server_key_exchange,
        flight.cipher_suite,
        &offered_curves,
    )?;
    let master_secret = certificate_dtls10_master_secret(
        &key_exchange.pre_master_secret,
        &client_random,
        &flight.random,
    );
    let suite = flight.cipher_suite.legacy_record_suite();
    let keys = derive_legacy_dtls_keys(
        &suite,
        &master_secret,
        &client_random,
        &flight.random,
    );
    let final_flight = build_final_flight(
        &suite,
        &keys,
        &master_secret,
        &key_exchange.client_key_exchange,
        flight.certificate_requested,
        &flight.certificate_types,
        &flight.acceptable_cas,
        options.client_identity.as_ref(),
        &mut transcript,
        &mut client_handshake_sequence,
        &mut client_record_sequence,
        options.record_mtu,
    )?;
    let server_finished = exchange_server_finished(
        packet.as_ref(),
        &destination,
        &suite,
        &keys,
        &master_secret,
        &transcript,
        &final_flight,
        options,
        cancellation,
        deadline,
    )
    .await?;
    Ok(LegacyDtlsSession::new(
        packet,
        destination,
        suite,
        keys,
        options.record_mtu,
        true,
        true,
        final_flight,
        server_finished,
    ))
}

enum InitialResponse {
    Cookie(Vec<u8>),
    ServerHello(u16),
}

#[allow(clippy::too_many_arguments)]
async fn exchange_initial_hello(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    suite: &LegacyDtlsSuite,
    hello: &[u8],
    record_sequence: &mut u64,
    reassembler: &mut CertificateDtlsHandshakeReassembler,
    options: &CertificateDtls10ClientOptions,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<InitialResponse, CertificateDtls10ConnectError> {
    let mut interval = options.flight_interval;
    for _ in 0..options.retries {
        let records = fragment_certificate_dtls10_handshake_records(
            hello,
            suite,
            options.record_mtu,
            record_sequence,
        )?;
        send_flight(packet, destination, &records, cancellation).await?;
        let attempt = (Instant::now() + interval).min(deadline);
        while receive_unencrypted(
            packet,
            destination,
            suite,
            reassembler,
            cancellation,
            attempt,
        )
        .await?
        {
            if let Some(sequence) = reassembler
                .find_completed_type(CERTIFICATE_DTLS_HANDSHAKE_HELLO_VERIFY)
            {
                let message = reassembler.take(sequence).expect("found");
                return Ok(InitialResponse::Cookie(
                    parse_certificate_dtls10_hello_verify(&message.body)?,
                ));
            }
            if let Some(sequence) = reassembler
                .find_completed_type(CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO)
            {
                return Ok(InitialResponse::ServerHello(sequence));
            }
        }
        interval = interval.saturating_mul(2);
    }
    Err(CertificateDtls10ConnectError::InitialResponseTimeout)
}

#[allow(clippy::too_many_arguments)]
async fn exchange_server_flight(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    record_suite: &LegacyDtlsSuite,
    hello: &[u8],
    record_sequence: &mut u64,
    server_sequence: &mut Option<u16>,
    reassembler: &mut CertificateDtlsHandshakeReassembler,
    offered_suites: &[CertificateDtls10CipherSuite],
    transcript: &mut Vec<u8>,
    options: &CertificateDtls10ClientOptions,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<ServerFlight, CertificateDtls10ConnectError> {
    let mut flight = None;
    let mut interval = options.flight_interval;
    for attempt_index in 0..options.retries {
        if attempt_index > 0 || server_sequence.is_none() {
            let records = fragment_certificate_dtls10_handshake_records(
                hello,
                record_suite,
                options.record_mtu,
                record_sequence,
            )?;
            send_flight(packet, destination, &records, cancellation).await?;
        }
        let attempt = (Instant::now() + interval).min(deadline);
        loop {
            if server_sequence.is_none() {
                *server_sequence = reassembler.find_completed_type(
                    CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO,
                );
            }
            while let Some(sequence) = *server_sequence {
                let Some(message) = reassembler.take(sequence) else {
                    break;
                };
                *server_sequence = Some(sequence.wrapping_add(1));
                if message.message_type
                    == CERTIFICATE_DTLS_HANDSHAKE_HELLO_VERIFY
                {
                    continue;
                }
                match message.message_type {
                    CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO => {
                        let (random, cipher_suite) =
                            parse_certificate_dtls10_server_hello(
                                &message.body,
                                offered_suites,
                            )?;
                        flight = Some(ServerFlight {
                            random,
                            cipher_suite,
                            certificates: Vec::new(),
                            server_key_exchange: Vec::new(),
                            certificate_requested: false,
                            certificate_types: Vec::new(),
                            acceptable_cas: Vec::new(),
                            complete: false,
                        });
                    }
                    CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE => {
                        let flight = flight.as_mut().ok_or(
                            CertificateDtls10ConnectError::IncompleteServerFlight,
                        )?;
                        flight.certificates =
                            parse_certificate_dtls10_certificate_chain(
                                &message.body,
                            )?;
                    }
                    CERTIFICATE_DTLS_HANDSHAKE_SERVER_KEY_EXCHANGE => {
                        flight
                            .as_mut()
                            .ok_or(CertificateDtls10ConnectError::IncompleteServerFlight)?
                            .server_key_exchange = message.body.clone();
                    }
                    CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE_REQUEST => {
                        let request =
                            parse_certificate_dtls10_certificate_request(
                                &message.body,
                            )?;
                        let flight = flight
                            .as_mut()
                            .ok_or(CertificateDtls10ConnectError::IncompleteServerFlight)?;
                        flight.certificate_requested = true;
                        flight.certificate_types = request.certificate_types;
                        flight.acceptable_cas = request.acceptable_cas;
                    }
                    CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO_DONE => {
                        let flight = flight.as_mut().ok_or(
                            CertificateDtls10ConnectError::IncompleteServerFlight,
                        )?;
                        if !message.body.is_empty()
                            || flight.certificates.is_empty()
                            || (flight.cipher_suite.ecdhe
                                && flight.server_key_exchange.is_empty())
                            || (!flight.cipher_suite.ecdhe
                                && !flight.server_key_exchange.is_empty())
                        {
                            return Err(
                                CertificateDtls10ConnectError::IncompleteServerFlight,
                            );
                        }
                        flight.complete = true;
                    }
                    value => {
                        return Err(
                            CertificateDtls10ConnectError::UnexpectedMessage(
                                value,
                            ),
                        );
                    }
                }
                transcript.extend_from_slice(
                    &marshal_certificate_dtls_handshake(
                        message.message_type,
                        message.sequence,
                        &message.body,
                    )?,
                );
                if flight.as_ref().is_some_and(|flight| flight.complete) {
                    return Ok(flight.expect("checked complete"));
                }
            }
            if !receive_unencrypted(
                packet,
                destination,
                record_suite,
                reassembler,
                cancellation,
                attempt,
            )
            .await?
            {
                break;
            }
        }
        interval = interval.saturating_mul(2);
    }
    Err(CertificateDtls10ConnectError::ServerFlightTimeout)
}

#[allow(clippy::too_many_arguments)]
fn build_final_flight(
    suite: &LegacyDtlsSuite,
    keys: &LegacyDtlsKeys,
    master_secret: &[u8],
    client_key_exchange: &[u8],
    certificate_requested: bool,
    certificate_types: &[u8],
    acceptable_cas: &[Vec<u8>],
    client_identity: Option<&CertificateDtls10ClientIdentity>,
    transcript: &mut Vec<u8>,
    handshake_sequence: &mut u16,
    record_sequence: &mut u64,
    mtu: usize,
) -> Result<Vec<Vec<u8>>, CertificateDtls10ConnectError> {
    let mut flight = Vec::new();
    let selected_identity = certificate_requested
        .then(|| {
            client_identity.filter(|identity| {
                certificate_types.contains(&1)
                    && identity.matches_acceptable_ca(acceptable_cas)
            })
        })
        .flatten();
    if certificate_requested {
        *handshake_sequence = handshake_sequence.wrapping_add(1);
        let certificate_chain = selected_identity
            .map(|identity| identity.certificate_chain.as_slice())
            .unwrap_or_default();
        let empty_certificate =
            marshal_certificate_dtls10_certificate_chain(certificate_chain)?;
        let message = marshal_certificate_dtls_handshake(
            CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE,
            *handshake_sequence,
            &empty_certificate,
        )?;
        transcript.extend_from_slice(&message);
        flight.extend(fragment_certificate_dtls10_handshake_records(
            &message,
            suite,
            mtu,
            record_sequence,
        )?);
    }
    *handshake_sequence = handshake_sequence.wrapping_add(1);
    let key_message = marshal_certificate_dtls_handshake(
        CERTIFICATE_DTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE,
        *handshake_sequence,
        client_key_exchange,
    )?;
    transcript.extend_from_slice(&key_message);
    flight.extend(fragment_certificate_dtls10_handshake_records(
        &key_message,
        suite,
        mtu,
        record_sequence,
    )?);
    if let Some(identity) = selected_identity {
        let signature = identity.sign_transcript(transcript)?;
        *handshake_sequence = handshake_sequence.wrapping_add(1);
        let verify_message = marshal_certificate_dtls_handshake(
            CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE_VERIFY,
            *handshake_sequence,
            &signature,
        )?;
        transcript.extend_from_slice(&verify_message);
        flight.extend(fragment_certificate_dtls10_handshake_records(
            &verify_message,
            suite,
            mtu,
            record_sequence,
        )?);
    }
    flight.push(marshal_legacy_dtls_record(
        &LegacyDtlsRecord {
            content_type: LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC,
            epoch: 0,
            sequence: *record_sequence,
            payload: vec![1],
        },
        suite,
    )?);
    *record_sequence += 1;
    let verify = certificate_dtls10_finished(
        master_secret,
        "client finished",
        transcript,
    );
    *handshake_sequence = handshake_sequence.wrapping_add(1);
    let finished = marshal_certificate_dtls_handshake(
        CERTIFICATE_DTLS_HANDSHAKE_FINISHED,
        *handshake_sequence,
        &verify,
    )?;
    let encrypted = encrypt_legacy_dtls_record(
        &LegacyDtlsRecord {
            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
            epoch: 1,
            sequence: 0,
            payload: finished.clone(),
        },
        &keys.client_key,
        &keys.client_mac_key,
        suite,
    )?;
    if mtu != 0 && encrypted.len() > mtu {
        return Err(CertificateDtls10WireError::MtuTooSmall.into());
    }
    flight.push(encrypted);
    transcript.extend_from_slice(&finished);
    Ok(flight)
}

#[allow(clippy::too_many_arguments)]
async fn exchange_server_finished(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    suite: &LegacyDtlsSuite,
    keys: &LegacyDtlsKeys,
    master_secret: &[u8],
    transcript: &[u8],
    final_flight: &[Vec<u8>],
    options: &CertificateDtls10ClientOptions,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, CertificateDtls10ConnectError> {
    let expected = certificate_dtls10_finished(
        master_secret,
        "server finished",
        transcript,
    );
    let mut interval = options.flight_interval;
    let mut change_cipher_seen = false;
    for _ in 0..options.retries {
        send_flight(packet, destination, final_flight, cancellation).await?;
        let attempt = (Instant::now() + interval).min(deadline);
        loop {
            let Some(records) = receive_records(
                packet,
                destination,
                suite,
                cancellation,
                attempt,
            )
            .await?
            else {
                break;
            };
            for record in records {
                match record.content_type {
                    LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC => {
                        if record.epoch != 0 || record.payload != [1] {
                            return Err(CertificateDtls10ConnectError::InvalidChangeCipherSpec);
                        }
                        change_cipher_seen = true;
                    }
                    LEGACY_DTLS_CONTENT_HANDSHAKE if record.epoch == 0 => {}
                    LEGACY_DTLS_CONTENT_HANDSHAKE => {
                        if record.epoch != 1 || !change_cipher_seen {
                            return Err(CertificateDtls10ConnectError::FinishedVerification);
                        }
                        let plaintext = decrypt_legacy_dtls_record(
                            &record,
                            &keys.server_key,
                            &keys.server_mac_key,
                            suite,
                        )?;
                        let message =
                            parse_complete_certificate_dtls_handshake(
                                &plaintext,
                            )?;
                        if message.message_type
                            != CERTIFICATE_DTLS_HANDSHAKE_FINISHED
                            || message.body != expected
                        {
                            return Err(CertificateDtls10ConnectError::FinishedVerification);
                        }
                        return Ok(plaintext);
                    }
                    LEGACY_DTLS_CONTENT_ALERT => {
                        let alert = if record.epoch == 1 {
                            decrypt_legacy_dtls_record(
                                &record,
                                &keys.server_key,
                                &keys.server_mac_key,
                                suite,
                            )?
                        } else {
                            record.payload
                        };
                        return Err(CertificateDtls10ConnectError::Alert(
                            (alert.len() == 2).then_some(alert[1]),
                        ));
                    }
                    _ => {}
                }
            }
        }
        interval = interval.saturating_mul(2);
    }
    Err(CertificateDtls10ConnectError::ServerFinishedTimeout)
}

async fn receive_unencrypted(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    suite: &LegacyDtlsSuite,
    reassembler: &mut CertificateDtlsHandshakeReassembler,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<bool, CertificateDtls10ConnectError> {
    let Some(records) =
        receive_records(packet, destination, suite, cancellation, deadline)
            .await?
    else {
        return Ok(false);
    };
    for record in records {
        if record.epoch != 0 {
            continue;
        }
        match record.content_type {
            LEGACY_DTLS_CONTENT_HANDSHAKE => {
                reassembler.add(&record.payload)?
            }
            LEGACY_DTLS_CONTENT_ALERT => {
                return Err(CertificateDtls10ConnectError::Alert(
                    (record.payload.len() == 2).then_some(record.payload[1]),
                ));
            }
            LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC => {
                return Err(
                    CertificateDtls10ConnectError::InvalidChangeCipherSpec,
                );
            }
            _ => {}
        }
    }
    Ok(true)
}

async fn receive_records(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    suite: &LegacyDtlsSuite,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Option<Vec<LegacyDtlsRecord>>, CertificateDtls10ConnectError> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let received = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(CertificateDtls10ConnectError::Cancelled);
            }
            result = timeout_at(deadline, packet.recv_from(&mut buffer)) => result,
        };
        let Ok(received) = received else {
            return Ok(None);
        };
        let (size, source) = received?;
        if source != *destination {
            continue;
        }
        return Ok(Some(parse_legacy_dtls_records(&buffer[..size], suite)?));
    }
}

async fn send_flight(
    packet: &dyn crate::adapter::PacketConnection,
    destination: &SocksAddr,
    records: &[Vec<u8>],
    cancellation: &CancellationToken,
) -> Result<(), CertificateDtls10ConnectError> {
    for record in records {
        let length = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(CertificateDtls10ConnectError::Cancelled);
            }
            result = packet.send_to(record, destination) => result?,
        };
        if length != record.len() {
            return Err(CertificateDtls10ConnectError::ShortWrite);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::{Padding, Rsa},
        x509::{X509, X509NameBuilder},
    };
    use parking_lot::Mutex as SyncMutex;
    use tokio::sync::{Mutex as TokioMutex, mpsc};

    use super::*;
    use crate::adapter::{PacketConnection, PacketFuture};

    #[test]
    fn defaults_match_upstream_legacy_policy() {
        let options = CertificateDtls10ClientOptions::default();
        assert_eq!(options.handshake_timeout, Duration::from_secs(15));
        assert_eq!(options.flight_interval, Duration::from_millis(250));
        assert_eq!(options.retries, 7);
        assert_eq!(super::super::CERTIFICATE_DTLS10_VERSION, 0xfeff);
    }

    #[test]
    fn final_flight_can_answer_empty_client_certificate_request() {
        let suite =
            CertificateDtls10CipherSuite::all()[2].legacy_record_suite();
        let keys =
            derive_legacy_dtls_keys(&suite, &[1; 48], &[2; 32], &[3; 32]);
        let mut transcript = b"server flight".to_vec();
        let mut handshake_sequence = 1;
        let mut record_sequence = 4;
        let flight = build_final_flight(
            &suite,
            &keys,
            &[1; 48],
            b"key exchange",
            true,
            &[1],
            &[],
            None,
            &mut transcript,
            &mut handshake_sequence,
            &mut record_sequence,
            1400,
        )
        .unwrap();
        assert_eq!(flight.len(), 4);
        let certificate_record = parse_legacy_dtls_records(&flight[0], &suite)
            .unwrap()
            .remove(0);
        let certificate = parse_complete_certificate_dtls_handshake(
            &certificate_record.payload,
        )
        .unwrap();
        assert_eq!(
            certificate.message_type,
            CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE
        );
        assert_eq!(certificate.body, [0, 0, 0]);
        assert_eq!(flight[2][0], LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC);
        assert_eq!(flight[3][0], LEGACY_DTLS_CONTENT_HANDSHAKE);
    }

    struct TestServerState {
        destination: SocksAddr,
        suite: LegacyDtlsSuite,
        certificate: Vec<u8>,
        key: PKey<Private>,
        incoming: mpsc::UnboundedSender<Vec<u8>>,
        state: SyncMutex<TestServerHandshake>,
    }

    #[derive(Default)]
    struct TestServerHandshake {
        sends: usize,
        transcript: Vec<u8>,
        client_random: [u8; 32],
        server_random: [u8; 32],
        master_secret: Vec<u8>,
        keys: Option<LegacyDtlsKeys>,
        change_cipher_seen: bool,
    }

    impl TestServerState {
        fn accept(&self, datagram: &[u8]) -> io::Result<()> {
            let mut state = self.state.lock();
            state.sends += 1;
            let records = parse_legacy_dtls_records(datagram, &self.suite)
                .map_err(io::Error::other)?;
            if state.sends == 1 {
                let hello_verify = marshal_certificate_dtls_handshake(
                    CERTIFICATE_DTLS_HANDSHAKE_HELLO_VERIFY,
                    0,
                    &[0xfe, 0xff, 3, 9, 8, 7],
                )
                .unwrap();
                self.send_plain_handshake(0, 0, hello_verify);
                return Ok(());
            }
            for record in records {
                match (record.content_type, record.epoch) {
                    (LEGACY_DTLS_CONTENT_HANDSHAKE, 0) => {
                        let message =
                            parse_complete_certificate_dtls_handshake(
                                &record.payload,
                            )
                            .map_err(io::Error::other)?;
                        if message.message_type
                            == super::super::CERTIFICATE_DTLS_HANDSHAKE_CLIENT_HELLO
                        {
                            state.client_random.copy_from_slice(
                                &message.body[2..34],
                            );
                            state.server_random = [0x55; 32];
                            state.transcript = record.payload;
                            drop(state);
                            self.send_server_flight();
                            return Ok(());
                        }
                        if message.message_type
                            == CERTIFICATE_DTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE
                        {
                            state.transcript.extend_from_slice(&record.payload);
                            let encrypted_length =
                                usize::from(u16::from_be_bytes([
                                    message.body[0],
                                    message.body[1],
                                ]));
                            let rsa = self.key.rsa().unwrap();
                            let mut pre_master =
                                vec![0_u8; rsa.size() as usize];
                            let length = rsa
                                .private_decrypt(
                                    &message.body[2..2 + encrypted_length],
                                    &mut pre_master,
                                    Padding::PKCS1,
                                )
                                .unwrap();
                            pre_master.truncate(length);
                            state.master_secret =
                                certificate_dtls10_master_secret(
                                    &pre_master,
                                    &state.client_random,
                                    &state.server_random,
                                );
                            state.keys = Some(derive_legacy_dtls_keys(
                                &self.suite,
                                &state.master_secret,
                                &state.client_random,
                                &state.server_random,
                            ));
                        }
                    }
                    (LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC, 0) => {
                        state.change_cipher_seen = record.payload == [1];
                    }
                    (LEGACY_DTLS_CONTENT_HANDSHAKE, 1) => {
                        assert!(state.change_cipher_seen);
                        let keys = state.keys.as_ref().unwrap();
                        let plaintext = decrypt_legacy_dtls_record(
                            &record,
                            &keys.client_key,
                            &keys.client_mac_key,
                            &self.suite,
                        )
                        .unwrap();
                        let message =
                            parse_complete_certificate_dtls_handshake(
                                &plaintext,
                            )
                            .unwrap();
                        let expected = certificate_dtls10_finished(
                            &state.master_secret,
                            "client finished",
                            &state.transcript,
                        );
                        assert_eq!(message.body, expected);
                        state.transcript.extend_from_slice(&plaintext);
                        let server_verify = certificate_dtls10_finished(
                            &state.master_secret,
                            "server finished",
                            &state.transcript,
                        );
                        let server_finished =
                            marshal_certificate_dtls_handshake(
                                CERTIFICATE_DTLS_HANDSHAKE_FINISHED,
                                4,
                                &server_verify,
                            )
                            .unwrap();
                        let keys = state.keys.as_ref().unwrap();
                        let mut response = marshal_legacy_dtls_record(
                            &LegacyDtlsRecord {
                                content_type:
                                    LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC,
                                epoch: 0,
                                sequence: 4,
                                payload: vec![1],
                            },
                            &self.suite,
                        )
                        .unwrap();
                        response.extend(
                            encrypt_legacy_dtls_record(
                                &LegacyDtlsRecord {
                                    content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                                    epoch: 1,
                                    sequence: 0,
                                    payload: server_finished,
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
            }
            Ok(())
        }

        fn send_plain_handshake(
            &self,
            record_sequence: u64,
            _message_sequence: u16,
            message: Vec<u8>,
        ) {
            self.incoming
                .send(
                    marshal_legacy_dtls_record(
                        &LegacyDtlsRecord {
                            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                            epoch: 0,
                            sequence: record_sequence,
                            payload: message,
                        },
                        &self.suite,
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        fn send_server_flight(&self) {
            let state = self.state.lock();
            let mut server_hello = vec![0xfe, 0xff];
            server_hello.extend_from_slice(&state.server_random);
            server_hello.extend_from_slice(&[0, 0, 0x2f, 0]);
            let server_hello = marshal_certificate_dtls_handshake(
                CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO,
                1,
                &server_hello,
            )
            .unwrap();
            let certificate_body =
                marshal_certificate_dtls10_certificate_chain(
                    std::slice::from_ref(&self.certificate),
                )
                .unwrap();
            let certificate = marshal_certificate_dtls_handshake(
                CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE,
                2,
                &certificate_body,
            )
            .unwrap();
            let done = marshal_certificate_dtls_handshake(
                CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO_DONE,
                3,
                &[],
            )
            .unwrap();
            drop(state);
            let mut response = Vec::new();
            for (record_sequence, message) in
                [server_hello, certificate, done].into_iter().enumerate()
            {
                response.extend(
                    marshal_legacy_dtls_record(
                        &LegacyDtlsRecord {
                            content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                            epoch: 0,
                            sequence: record_sequence as u64 + 1,
                            payload: message.clone(),
                        },
                        &self.suite,
                    )
                    .unwrap(),
                );
                self.state.lock().transcript.extend_from_slice(&message);
            }
            self.incoming.send(response).unwrap();
        }
    }

    struct TestPacket {
        server: Arc<TestServerState>,
        incoming: TokioMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    impl PacketConnection for TestPacket {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                assert_eq!(destination, &self.server.destination);
                self.server.accept(data)?;
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let packet =
                    self.incoming.lock().await.recv().await.ok_or_else(
                        || io::Error::from(io::ErrorKind::UnexpectedEof),
                    )?;
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), self.server.destination.clone()))
            })
        }
    }

    fn test_certificate() -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "vpn.example").unwrap();
        let name = name.build();
        let mut serial = BigNum::new().unwrap();
        serial
            .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        let serial = serial.to_asn1_integer().unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    #[tokio::test]
    async fn completes_cookie_rsa_certificate_handshake_end_to_end() {
        let destination = SocksAddr::new("vpn.example", 443);
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (certificate, key) = test_certificate();
        let suite = CertificateDtls10CipherSuite::from_id(
            super::super::TLS_RSA_WITH_AES_128_CBC_SHA,
        )
        .unwrap()
        .legacy_record_suite();
        let server = Arc::new(TestServerState {
            destination: destination.clone(),
            suite,
            certificate: certificate.to_der().unwrap(),
            key,
            incoming: incoming_tx,
            state: SyncMutex::new(TestServerHandshake::default()),
        });
        let packet = Box::new(TestPacket {
            server: server.clone(),
            incoming: TokioMutex::new(incoming_rx),
        });
        let session = connect_certificate_dtls10(
            packet,
            destination,
            &CertificateDtls10ClientOptions {
                server_name: "vpn.example".into(),
                record_mtu: 1400,
                insecure_skip_verify: true,
                cipher_suites: vec![super::super::TLS_RSA_WITH_AES_128_CBC_SHA],
                flight_interval: Duration::from_millis(5),
                handshake_timeout: Duration::from_secs(1),
                ..Default::default()
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!session.is_closed());
        assert_eq!(server.state.lock().master_secret.len(), 48);
    }
}
