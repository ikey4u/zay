//! Certificate DTLS 1.0 handshake wire format used by legacy F5 gateways.
//!
//! This module deliberately contains no socket or certificate-policy code. It
//! provides the bounded fragmentation/reassembly and message codecs needed by
//! the certificate handshake while reusing the common legacy CBC record layer.

use std::collections::HashMap;

use thiserror::Error;

use super::{
    LEGACY_DTLS_CONTENT_HANDSHAKE, LEGACY_DTLS_MAX_SEQUENCE,
    LEGACY_DTLS_RECORD_HEADER_LENGTH, LegacyDtlsCipher, LegacyDtlsError,
    LegacyDtlsRecord, LegacyDtlsSuite, marshal_legacy_dtls_record,
};

pub const CERTIFICATE_DTLS10_VERSION: u16 = 0xfeff;
pub const CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH: usize = 12;
pub const CERTIFICATE_DTLS_MAX_HANDSHAKE_MESSAGES: usize = 64;
pub const CERTIFICATE_DTLS_MAX_MESSAGE_LENGTH: usize = 16 * 1024 * 1024;
pub const CERTIFICATE_DTLS_MAX_REASSEMBLY_BYTES: usize = 32 * 1024 * 1024;

pub const CERTIFICATE_DTLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO: u8 = 2;
pub const CERTIFICATE_DTLS_HANDSHAKE_HELLO_VERIFY: u8 = 3;
pub const CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE: u8 = 11;
pub const CERTIFICATE_DTLS_HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 12;
pub const CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE_REQUEST: u8 = 13;
pub const CERTIFICATE_DTLS_HANDSHAKE_SERVER_HELLO_DONE: u8 = 14;
pub const CERTIFICATE_DTLS_HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
pub const CERTIFICATE_DTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 16;
pub const CERTIFICATE_DTLS_HANDSHAKE_FINISHED: u8 = 20;

pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateDtls10CipherSuite {
    pub id: u16,
    pub key_length: usize,
    pub ecdhe: bool,
}

impl CertificateDtls10CipherSuite {
    pub const fn all() -> [Self; 4] {
        [
            Self {
                id: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                key_length: 16,
                ecdhe: true,
            },
            Self {
                id: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                key_length: 32,
                ecdhe: true,
            },
            Self {
                id: TLS_RSA_WITH_AES_128_CBC_SHA,
                key_length: 16,
                ecdhe: false,
            },
            Self {
                id: TLS_RSA_WITH_AES_256_CBC_SHA,
                key_length: 32,
                ecdhe: false,
            },
        ]
    }

    pub fn from_id(id: u16) -> Option<Self> {
        Self::all().into_iter().find(|suite| suite.id == id)
    }

    pub fn legacy_record_suite(self) -> LegacyDtlsSuite {
        LegacyDtlsSuite {
            label: "certificate DTLS 1.0".into(),
            version: CERTIFICATE_DTLS10_VERSION,
            cipher: if self.key_length == 16 {
                LegacyDtlsCipher::Aes128
            } else {
                LegacyDtlsCipher::Aes256
            },
            cipher_suite_id: self.id,
        }
    }
}

pub fn certificate_dtls10_cipher_suites(
    configured: &[u16],
) -> Result<Vec<CertificateDtls10CipherSuite>, CertificateDtls10WireError> {
    if configured.is_empty() {
        return Ok(CertificateDtls10CipherSuite::all().to_vec());
    }
    let selected: Vec<_> = configured
        .iter()
        .filter_map(|id| CertificateDtls10CipherSuite::from_id(*id))
        .collect();
    if selected.is_empty() {
        return Err(CertificateDtls10WireError::NoSupportedCipher);
    }
    Ok(selected)
}

pub fn certificate_dtls10_curves(
    configured: &[u16],
) -> Result<Vec<u16>, CertificateDtls10WireError> {
    if configured.is_empty() {
        return Ok(vec![23, 24, 25]);
    }
    let curves: Vec<_> = configured
        .iter()
        .copied()
        .filter(|curve| matches!(curve, 23..=25))
        .collect();
    if curves.is_empty() {
        return Err(CertificateDtls10WireError::NoSupportedCurve);
    }
    Ok(curves)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDtlsHandshakeMessage {
    pub message_type: u8,
    pub sequence: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDtlsCertificateRequest {
    pub certificate_types: Vec<u8>,
    pub acceptable_cas: Vec<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum CertificateDtls10WireError {
    #[error(transparent)]
    Record(#[from] LegacyDtlsError),
    #[error(
        "configured TLS cipher suites have no certificate DTLS 1.0 equivalent"
    )]
    NoSupportedCipher,
    #[error("configured TLS curves have no certificate DTLS 1.0 equivalent")]
    NoSupportedCurve,
    #[error("invalid certificate DTLS 1.0 ClientHello parameters")]
    InvalidClientHello,
    #[error("invalid certificate DTLS 1.0 HelloVerify")]
    InvalidHelloVerify,
    #[error("invalid certificate DTLS 1.0 ServerHello")]
    InvalidServerHello,
    #[error("certificate DTLS 1.0 server selected unoffered cipher {0:#06x}")]
    UnofferedCipher(u16),
    #[error("certificate DTLS 1.0 server selected unsupported compression {0}")]
    UnsupportedCompression(u8),
    #[error("invalid certificate DTLS 1.0 certificate chain")]
    InvalidCertificateChain,
    #[error("invalid certificate DTLS 1.0 CertificateRequest")]
    InvalidCertificateRequest,
    #[error("short certificate DTLS 1.0 handshake message")]
    ShortHandshake,
    #[error("invalid certificate DTLS 1.0 handshake fragment")]
    InvalidFragment,
    #[error("conflicting certificate DTLS 1.0 handshake fragment")]
    ConflictingFragment,
    #[error("certificate DTLS 1.0 handshake has too many messages")]
    TooManyMessages,
    #[error("certificate DTLS 1.0 handshake reassembly exceeds memory limit")]
    ReassemblyLimit,
    #[error("certificate DTLS 1.0 MTU cannot carry a handshake fragment")]
    MtuTooSmall,
    #[error("certificate DTLS 1.0 handshake record sequence exhausted")]
    SequenceExhausted,
}

pub fn build_certificate_dtls10_client_hello(
    client_random: &[u8],
    cookie: &[u8],
    cipher_suites: &[CertificateDtls10CipherSuite],
    curves: &[u16],
    server_name: &str,
    sequence: u16,
) -> Result<Vec<u8>, CertificateDtls10WireError> {
    if client_random.len() != 32
        || cookie.len() > u8::MAX as usize
        || cipher_suites.is_empty()
        || cipher_suites.len() > (u16::MAX as usize / 2)
    {
        return Err(CertificateDtls10WireError::InvalidClientHello);
    }
    let mut body = Vec::with_capacity(128 + cookie.len() + server_name.len());
    body.extend_from_slice(&CERTIFICATE_DTLS10_VERSION.to_be_bytes());
    body.extend_from_slice(client_random);
    body.push(0); // no session ID
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);
    body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.id.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // null compression only
    let extensions = build_client_extensions(server_name, curves)?;
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    marshal_certificate_dtls_handshake(
        CERTIFICATE_DTLS_HANDSHAKE_CLIENT_HELLO,
        sequence,
        &body,
    )
}

fn build_client_extensions(
    server_name: &str,
    curves: &[u16],
) -> Result<Vec<u8>, CertificateDtls10WireError> {
    if server_name.len() > u16::MAX as usize - 5
        || curves.len() > u16::MAX as usize / 2
    {
        return Err(CertificateDtls10WireError::InvalidClientHello);
    }
    let mut extensions = Vec::with_capacity(64 + server_name.len());
    if !server_name.is_empty()
        && server_name.parse::<std::net::IpAddr>().is_err()
    {
        let name = server_name.as_bytes();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        extensions.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(name);
    }
    extensions.extend_from_slice(&10_u16.to_be_bytes());
    extensions
        .extend_from_slice(&((2 + curves.len() * 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&((curves.len() * 2) as u16).to_be_bytes());
    for curve in curves {
        extensions.extend_from_slice(&curve.to_be_bytes());
    }
    extensions.extend_from_slice(&[0, 11, 0, 2, 1, 0]);
    extensions.extend_from_slice(&[0xff, 0x01, 0, 1, 0]);
    Ok(extensions)
}

pub fn parse_certificate_dtls10_hello_verify(
    body: &[u8],
) -> Result<Vec<u8>, CertificateDtls10WireError> {
    if body.len() < 3 || body[..2] != CERTIFICATE_DTLS10_VERSION.to_be_bytes() {
        return Err(CertificateDtls10WireError::InvalidHelloVerify);
    }
    let length = usize::from(body[2]);
    if length == 0 || body.len() != 3 + length {
        return Err(CertificateDtls10WireError::InvalidHelloVerify);
    }
    Ok(body[3..].to_vec())
}

pub fn parse_certificate_dtls10_server_hello(
    body: &[u8],
    offered: &[CertificateDtls10CipherSuite],
) -> Result<([u8; 32], CertificateDtls10CipherSuite), CertificateDtls10WireError>
{
    if body.len() < 38 || body[..2] != CERTIFICATE_DTLS10_VERSION.to_be_bytes()
    {
        return Err(CertificateDtls10WireError::InvalidServerHello);
    }
    let random: [u8; 32] = body[2..34]
        .try_into()
        .map_err(|_| CertificateDtls10WireError::InvalidServerHello)?;
    let position = 35_usize
        .checked_add(usize::from(body[34]))
        .ok_or(CertificateDtls10WireError::InvalidServerHello)?;
    if body.len() < position + 3 {
        return Err(CertificateDtls10WireError::InvalidServerHello);
    }
    let selected = u16::from_be_bytes([body[position], body[position + 1]]);
    let suite = offered
        .iter()
        .copied()
        .find(|suite| suite.id == selected)
        .ok_or(CertificateDtls10WireError::UnofferedCipher(selected))?;
    if body[position + 2] != 0 {
        return Err(CertificateDtls10WireError::UnsupportedCompression(
            body[position + 2],
        ));
    }
    let extension_position = position + 3;
    if extension_position < body.len() {
        if body.len() < extension_position + 2 {
            return Err(CertificateDtls10WireError::InvalidServerHello);
        }
        let length = usize::from(u16::from_be_bytes([
            body[extension_position],
            body[extension_position + 1],
        ]));
        if body.len() != extension_position + 2 + length {
            return Err(CertificateDtls10WireError::InvalidServerHello);
        }
    }
    Ok((random, suite))
}

pub fn parse_certificate_dtls10_certificate_chain(
    body: &[u8],
) -> Result<Vec<Vec<u8>>, CertificateDtls10WireError> {
    if body.len() < 3 {
        return Err(CertificateDtls10WireError::InvalidCertificateChain);
    }
    let total = read_u24(&body[..3]);
    if total == 0 || body.len() != 3 + total {
        return Err(CertificateDtls10WireError::InvalidCertificateChain);
    }
    let mut position = 3;
    let mut certificates = Vec::new();
    while position < body.len() {
        if body.len() - position < 3 {
            return Err(CertificateDtls10WireError::InvalidCertificateChain);
        }
        let length = read_u24(&body[position..position + 3]);
        position += 3;
        if length == 0 || body.len() - position < length {
            return Err(CertificateDtls10WireError::InvalidCertificateChain);
        }
        certificates.push(body[position..position + length].to_vec());
        position += length;
    }
    Ok(certificates)
}

pub fn marshal_certificate_dtls10_certificate_chain(
    certificates: &[Vec<u8>],
) -> Result<Vec<u8>, CertificateDtls10WireError> {
    let total =
        certificates
            .iter()
            .try_fold(0_usize, |total, certificate| {
                if certificate.is_empty() || certificate.len() > 0x00ff_ffff {
                    return Err(
                        CertificateDtls10WireError::InvalidCertificateChain,
                    );
                }
                total
                    .checked_add(3 + certificate.len())
                    .ok_or(CertificateDtls10WireError::InvalidCertificateChain)
            })?;
    if total > 0x00ff_ffff {
        return Err(CertificateDtls10WireError::InvalidCertificateChain);
    }
    let mut body = vec![0; 3];
    write_u24(&mut body, total);
    for certificate in certificates {
        let mut length = [0_u8; 3];
        write_u24(&mut length, certificate.len());
        body.extend_from_slice(&length);
        body.extend_from_slice(certificate);
    }
    Ok(body)
}

pub fn parse_certificate_dtls10_certificate_request(
    body: &[u8],
) -> Result<CertificateDtlsCertificateRequest, CertificateDtls10WireError> {
    if body.is_empty() {
        return Err(CertificateDtls10WireError::InvalidCertificateRequest);
    }
    let type_length = usize::from(body[0]);
    let mut position = 1 + type_length;
    if body.len() < position + 2 {
        return Err(CertificateDtls10WireError::InvalidCertificateRequest);
    }
    let certificate_types = body[1..position].to_vec();
    let authorities_length =
        usize::from(u16::from_be_bytes([body[position], body[position + 1]]));
    position += 2;
    if body.len() - position != authorities_length {
        return Err(CertificateDtls10WireError::InvalidCertificateRequest);
    }
    let mut acceptable_cas = Vec::new();
    while position < body.len() {
        if body.len() - position < 2 {
            return Err(CertificateDtls10WireError::InvalidCertificateRequest);
        }
        let length = usize::from(u16::from_be_bytes([
            body[position],
            body[position + 1],
        ]));
        position += 2;
        if length == 0 || body.len() - position < length {
            return Err(CertificateDtls10WireError::InvalidCertificateRequest);
        }
        acceptable_cas.push(body[position..position + length].to_vec());
        position += length;
    }
    Ok(CertificateDtlsCertificateRequest {
        certificate_types,
        acceptable_cas,
    })
}

pub fn marshal_certificate_dtls_handshake(
    message_type: u8,
    sequence: u16,
    body: &[u8],
) -> Result<Vec<u8>, CertificateDtls10WireError> {
    if body.len() > 0x00ff_ffff {
        return Err(CertificateDtls10WireError::InvalidFragment);
    }
    let mut message = vec![0; CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH];
    message[0] = message_type;
    write_u24(&mut message[1..4], body.len());
    message[4..6].copy_from_slice(&sequence.to_be_bytes());
    write_u24(&mut message[9..12], body.len());
    message.extend_from_slice(body);
    Ok(message)
}

pub fn parse_complete_certificate_dtls_handshake(
    payload: &[u8],
) -> Result<CertificateDtlsHandshakeMessage, CertificateDtls10WireError> {
    if payload.len() < CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH {
        return Err(CertificateDtls10WireError::ShortHandshake);
    }
    let total = read_u24(&payload[1..4]);
    let offset = read_u24(&payload[6..9]);
    let fragment_length = read_u24(&payload[9..12]);
    if offset != 0
        || fragment_length != total
        || payload.len() != CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH + total
    {
        return Err(CertificateDtls10WireError::InvalidFragment);
    }
    Ok(CertificateDtlsHandshakeMessage {
        message_type: payload[0],
        sequence: u16::from_be_bytes([payload[4], payload[5]]),
        body: payload[12..].to_vec(),
    })
}

pub fn fragment_certificate_dtls10_handshake_records(
    message: &[u8],
    suite: &LegacyDtlsSuite,
    mtu: usize,
    record_sequence: &mut u64,
) -> Result<Vec<Vec<u8>>, CertificateDtls10WireError> {
    if message.len() < CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH {
        return Err(CertificateDtls10WireError::ShortHandshake);
    }
    let total = read_u24(&message[1..4]);
    if message.len() != CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH + total {
        return Err(CertificateDtls10WireError::InvalidFragment);
    }
    let maximum = if mtu == 0 {
        total
    } else {
        mtu.checked_sub(
            LEGACY_DTLS_RECORD_HEADER_LENGTH
                + CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH,
        )
        .filter(|maximum| *maximum > 0 || total == 0)
        .ok_or(CertificateDtls10WireError::MtuTooSmall)?
    };
    let mut records = Vec::new();
    let mut offset = 0;
    loop {
        if *record_sequence > LEGACY_DTLS_MAX_SEQUENCE {
            return Err(CertificateDtls10WireError::SequenceExhausted);
        }
        let length = maximum.min(total - offset);
        let mut fragment = vec![0; CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH];
        fragment[..6].copy_from_slice(&message[..6]);
        write_u24(&mut fragment[6..9], offset);
        write_u24(&mut fragment[9..12], length);
        fragment.extend_from_slice(
            &message[CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH + offset
                ..CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH + offset + length],
        );
        records.push(marshal_legacy_dtls_record(
            &LegacyDtlsRecord {
                content_type: LEGACY_DTLS_CONTENT_HANDSHAKE,
                epoch: 0,
                sequence: *record_sequence,
                payload: fragment,
            },
            suite,
        )?);
        *record_sequence += 1;
        offset += length;
        if offset == total {
            break;
        }
    }
    Ok(records)
}

struct CertificateDtlsHandshakeFragment {
    message_type: u8,
    total_length: usize,
    body: Vec<u8>,
    received: Vec<bool>,
}

#[derive(Default)]
pub struct CertificateDtlsHandshakeReassembler {
    fragments: HashMap<u16, CertificateDtlsHandshakeFragment>,
    messages: HashMap<u16, CertificateDtlsHandshakeMessage>,
    allocated_bytes: usize,
}

impl CertificateDtlsHandshakeReassembler {
    pub fn add(
        &mut self,
        mut payload: &[u8],
    ) -> Result<(), CertificateDtls10WireError> {
        while !payload.is_empty() {
            if payload.len() < CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH {
                return Err(CertificateDtls10WireError::ShortHandshake);
            }
            let message_type = payload[0];
            let total = read_u24(&payload[1..4]);
            let sequence = u16::from_be_bytes([payload[4], payload[5]]);
            let offset = read_u24(&payload[6..9]);
            let length = read_u24(&payload[9..12]);
            if total > CERTIFICATE_DTLS_MAX_MESSAGE_LENGTH
                || offset > total
                || length > total - offset
                || payload.len()
                    < CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH + length
            {
                return Err(CertificateDtls10WireError::InvalidFragment);
            }
            let fragment_body = &payload
                [CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH
                    ..CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH + length];
            if let Some(complete) = self.messages.get(&sequence) {
                if complete.message_type != message_type
                    || complete.body.len() != total
                    || complete.body[offset..offset + length] != *fragment_body
                {
                    return Err(
                        CertificateDtls10WireError::ConflictingFragment,
                    );
                }
            } else {
                if !self.fragments.contains_key(&sequence) {
                    if self.fragments.len() + self.messages.len()
                        >= CERTIFICATE_DTLS_MAX_HANDSHAKE_MESSAGES
                    {
                        return Err(
                            CertificateDtls10WireError::TooManyMessages,
                        );
                    }
                    let allocation = total
                        .checked_mul(2)
                        .ok_or(CertificateDtls10WireError::ReassemblyLimit)?;
                    if allocation
                        > CERTIFICATE_DTLS_MAX_REASSEMBLY_BYTES
                            .saturating_sub(self.allocated_bytes)
                    {
                        return Err(
                            CertificateDtls10WireError::ReassemblyLimit,
                        );
                    }
                    self.fragments.insert(
                        sequence,
                        CertificateDtlsHandshakeFragment {
                            message_type,
                            total_length: total,
                            body: vec![0; total],
                            received: vec![false; total],
                        },
                    );
                    self.allocated_bytes += allocation;
                }
                let fragment =
                    self.fragments.get_mut(&sequence).expect("inserted above");
                if fragment.message_type != message_type
                    || fragment.total_length != total
                {
                    return Err(
                        CertificateDtls10WireError::ConflictingFragment,
                    );
                }
                for (index, value) in fragment_body.iter().copied().enumerate()
                {
                    let position = offset + index;
                    if fragment.received[position]
                        && fragment.body[position] != value
                    {
                        return Err(
                            CertificateDtls10WireError::ConflictingFragment,
                        );
                    }
                    fragment.body[position] = value;
                    fragment.received[position] = true;
                }
                if fragment.received.iter().all(|received| *received) {
                    let fragment =
                        self.fragments.remove(&sequence).expect("present");
                    self.allocated_bytes -= fragment.total_length * 2;
                    self.messages.insert(
                        sequence,
                        CertificateDtlsHandshakeMessage {
                            message_type,
                            sequence,
                            body: fragment.body,
                        },
                    );
                }
            }
            payload =
                &payload[CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH + length..];
        }
        Ok(())
    }

    pub fn take(
        &mut self,
        sequence: u16,
    ) -> Option<CertificateDtlsHandshakeMessage> {
        self.messages.remove(&sequence)
    }

    pub fn completed(
        &self,
        sequence: u16,
    ) -> Option<&CertificateDtlsHandshakeMessage> {
        self.messages.get(&sequence)
    }

    pub fn find_completed_type(&self, message_type: u8) -> Option<u16> {
        self.messages.iter().find_map(|(sequence, message)| {
            (message.message_type == message_type).then_some(*sequence)
        })
    }

    pub fn clear(&mut self) {
        self.fragments.clear();
        self.messages.clear();
        self.allocated_bytes = 0;
    }
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
    use super::*;
    use crate::protocol::openconnect::parse_legacy_dtls_records;

    #[test]
    fn default_suites_and_curves_match_upstream_order() {
        assert_eq!(
            certificate_dtls10_cipher_suites(&[])
                .unwrap()
                .iter()
                .map(|suite| suite.id)
                .collect::<Vec<_>>(),
            vec![0xc013, 0xc014, 0x002f, 0x0035]
        );
        assert_eq!(certificate_dtls10_curves(&[]).unwrap(), [23, 24, 25]);
    }

    #[test]
    fn client_hello_has_dtls10_sni_curves_and_renegotiation_extensions() {
        let hello = build_certificate_dtls10_client_hello(
            &[0x11; 32],
            &[9, 8, 7],
            &CertificateDtls10CipherSuite::all(),
            &[23, 24, 25],
            "vpn.example",
            1,
        )
        .unwrap();
        let message =
            parse_complete_certificate_dtls_handshake(&hello).unwrap();
        assert_eq!(
            message.message_type,
            CERTIFICATE_DTLS_HANDSHAKE_CLIENT_HELLO
        );
        assert_eq!(message.sequence, 1);
        assert_eq!(&message.body[..2], &[0xfe, 0xff]);
        assert!(
            message
                .body
                .windows(11)
                .any(|value| value == b"vpn.example")
        );
        assert!(
            message
                .body
                .windows(5)
                .any(|value| value == [0xff, 1, 0, 1, 0])
        );
    }

    #[test]
    fn ip_server_name_is_not_sent_as_sni() {
        let hello = build_certificate_dtls10_client_hello(
            &[0; 32],
            &[],
            &CertificateDtls10CipherSuite::all(),
            &[23],
            "192.0.2.1",
            0,
        )
        .unwrap();
        assert!(!hello.windows(9).any(|value| value == b"192.0.2.1"));
    }

    #[test]
    fn parses_cookie_server_hello_and_certificate_request() {
        assert_eq!(
            parse_certificate_dtls10_hello_verify(&[0xfe, 0xff, 2, 4, 5])
                .unwrap(),
            [4, 5]
        );
        let mut server_hello = vec![0xfe, 0xff];
        server_hello.extend_from_slice(&[0x22; 32]);
        server_hello.extend_from_slice(&[0, 0xc0, 0x13, 0, 0, 0]);
        let (random, suite) = parse_certificate_dtls10_server_hello(
            &server_hello,
            &CertificateDtls10CipherSuite::all(),
        )
        .unwrap();
        assert_eq!(random, [0x22; 32]);
        assert!(suite.ecdhe);
        let request = parse_certificate_dtls10_certificate_request(&[
            2, 1, 2, 0, 7, 0, 2, b'C', b'A', 0, 1, b'B',
        ])
        .unwrap();
        assert_eq!(request.certificate_types, [1, 2]);
        assert_eq!(request.acceptable_cas, [b"CA".to_vec(), b"B".to_vec()]);
    }

    #[test]
    fn certificate_chain_round_trips_and_empty_client_chain_is_supported() {
        let certificates = vec![vec![1, 2, 3], vec![4, 5]];
        let body = marshal_certificate_dtls10_certificate_chain(&certificates)
            .unwrap();
        assert_eq!(
            parse_certificate_dtls10_certificate_chain(&body).unwrap(),
            certificates
        );
        assert_eq!(
            marshal_certificate_dtls10_certificate_chain(&[]).unwrap(),
            [0, 0, 0]
        );
        assert!(
            parse_certificate_dtls10_certificate_chain(&[0, 0, 0]).is_err()
        );
    }

    #[test]
    fn fragmented_records_reassemble_out_of_order() {
        let suite =
            CertificateDtls10CipherSuite::all()[0].legacy_record_suite();
        let message =
            marshal_certificate_dtls_handshake(11, 7, &[0x5a; 80]).unwrap();
        let mut sequence = 4;
        let records = fragment_certificate_dtls10_handshake_records(
            &message,
            &suite,
            LEGACY_DTLS_RECORD_HEADER_LENGTH
                + CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH
                + 23,
            &mut sequence,
        )
        .unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(sequence, 8);
        let mut fragments: Vec<_> = records
            .iter()
            .map(|record| {
                parse_legacy_dtls_records(record, &suite)
                    .unwrap()
                    .remove(0)
                    .payload
            })
            .collect();
        fragments.reverse();
        let mut reassembler = CertificateDtlsHandshakeReassembler::default();
        for fragment in fragments {
            reassembler.add(&fragment).unwrap();
        }
        assert_eq!(reassembler.take(7).unwrap().body, [0x5a; 80]);
    }

    #[test]
    fn overlapping_equal_fragments_are_idempotent_but_conflicts_fail() {
        let message =
            marshal_certificate_dtls_handshake(2, 3, b"server").unwrap();
        let mut reassembler = CertificateDtlsHandshakeReassembler::default();
        reassembler.add(&message).unwrap();
        reassembler.add(&message).unwrap();
        let mut conflict = message;
        conflict[12] ^= 1;
        assert!(matches!(
            reassembler.add(&conflict),
            Err(CertificateDtls10WireError::ConflictingFragment)
        ));
    }

    #[test]
    fn malformed_lengths_and_small_mtu_are_rejected() {
        assert!(parse_complete_certificate_dtls_handshake(&[0; 11]).is_err());
        let message = marshal_certificate_dtls_handshake(1, 0, b"x").unwrap();
        let suite =
            CertificateDtls10CipherSuite::all()[0].legacy_record_suite();
        assert!(matches!(
            fragment_certificate_dtls10_handshake_records(
                &message,
                &suite,
                LEGACY_DTLS_RECORD_HEADER_LENGTH
                    + CERTIFICATE_DTLS_HANDSHAKE_HEADER_LENGTH,
                &mut 0,
            ),
            Err(CertificateDtls10WireError::MtuTooSmall)
        ));
    }
}
