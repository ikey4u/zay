//! Cisco legacy DTLS 0.9 record and TLS 1.0 PRF compatibility.
//!
//! This layer is independent of a UDP socket and handshake state machine so
//! it can be tested against fixed Go/OpenConnect vectors and embedded by the
//! eventual AnyConnect DTLS channel.

use std::fmt;

use getrandom::fill as random_fill;
use hmac13::{Hmac, KeyInit, Mac};
use md5::Md5;
use openssl::{
    error::ErrorStack,
    memcmp,
    symm::{Cipher, Crypter, Mode},
};
use sha1_11::Sha1;
use thiserror::Error;

pub const LEGACY_DTLS_RECORD_HEADER_LENGTH: usize = 13;
pub const LEGACY_DTLS_MAX_SEQUENCE: u64 = 0x0000_ffff_ffff_ffff;
pub const LEGACY_DTLS_MAC_LENGTH: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyDtlsCipher {
    Aes128,
    Aes256,
    TripleDes,
    Des,
}

impl LegacyDtlsCipher {
    pub fn from_name(
        name: &str,
        allow_insecure_crypto: bool,
    ) -> Result<Self, LegacyDtlsError> {
        match name {
            "DHE-RSA-AES128-SHA" | "AES128-SHA" => Ok(Self::Aes128),
            "DHE-RSA-AES256-SHA" | "AES256-SHA" => Ok(Self::Aes256),
            "DES-CBC3-SHA" if allow_insecure_crypto => Ok(Self::TripleDes),
            "DES-CBC-SHA" if allow_insecure_crypto => Ok(Self::Des),
            "DES-CBC3-SHA" | "DES-CBC-SHA" => {
                Err(LegacyDtlsError::DeprecatedCipher(name.into()))
            }
            _ => Err(LegacyDtlsError::UnsupportedCipher(name.into())),
        }
    }

    pub const fn key_length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
            Self::TripleDes => 24,
            Self::Des => 8,
        }
    }

    pub const fn block_length(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes256 => 16,
            Self::TripleDes | Self::Des => 8,
        }
    }

    fn openssl_cipher(self) -> Cipher {
        match self {
            Self::Aes128 => Cipher::aes_128_cbc(),
            Self::Aes256 => Cipher::aes_256_cbc(),
            Self::TripleDes => Cipher::des_ede3_cbc(),
            Self::Des => Cipher::des_cbc(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDtlsSuite {
    pub label: String,
    pub version: u16,
    pub cipher: LegacyDtlsCipher,
    pub cipher_suite_id: u16,
}

impl LegacyDtlsSuite {
    pub fn cisco(cipher: LegacyDtlsCipher) -> Self {
        Self {
            label: "Cisco DTLS 0.9".into(),
            version: 0x0100,
            cipher,
            cipher_suite_id: match cipher {
                LegacyDtlsCipher::Aes128 => 0x002f,
                LegacyDtlsCipher::Aes256 => 0x0035,
                LegacyDtlsCipher::TripleDes => 0x000a,
                LegacyDtlsCipher::Des => 0x0009,
            },
        }
    }

    pub fn from_name(
        name: &str,
        allow_insecure_crypto: bool,
    ) -> Result<Self, LegacyDtlsError> {
        let cipher = LegacyDtlsCipher::from_name(name, allow_insecure_crypto)?;
        let cipher_suite_id = match name {
            "DHE-RSA-AES128-SHA" => 0x0033,
            "DHE-RSA-AES256-SHA" => 0x0039,
            "AES128-SHA" => 0x002f,
            "AES256-SHA" => 0x0035,
            "DES-CBC3-SHA" => 0x000a,
            "DES-CBC-SHA" => 0x0009,
            _ => unreachable!("cipher name was accepted above"),
        };
        Ok(Self {
            label: "Cisco DTLS 0.9".into(),
            version: 0x0100,
            cipher,
            cipher_suite_id,
        })
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct LegacyDtlsKeys {
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

impl fmt::Debug for LegacyDtlsKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDtlsKeys")
            .field("client_mac_key", &"[REDACTED]")
            .field("server_mac_key", &"[REDACTED]")
            .field("client_key", &"[REDACTED]")
            .field("server_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for LegacyDtlsKeys {
    fn drop(&mut self) {
        self.client_mac_key.fill(0);
        self.server_mac_key.fill(0);
        self.client_key.fill(0);
        self.server_key.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDtlsRecord {
    pub content_type: u8,
    pub epoch: u16,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyDtlsReplayWindow {
    initialized: bool,
    maximum: u64,
    bitmap: u64,
}

impl LegacyDtlsReplayWindow {
    pub fn accept(&mut self, sequence: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.maximum = sequence;
            self.bitmap = 1;
            return true;
        }
        if sequence > self.maximum {
            let shift = sequence - self.maximum;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.maximum = sequence;
            return true;
        }
        let difference = self.maximum - sequence;
        if difference >= 64 {
            return false;
        }
        let mask = 1_u64 << difference;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

#[derive(Debug, Error)]
pub enum LegacyDtlsError {
    #[error("unsupported Cisco DTLS 0.9 cipher: {0}")]
    UnsupportedCipher(String),
    #[error("deprecated Cisco DTLS 0.9 cipher is disabled: {0}")]
    DeprecatedCipher(String),
    #[error("invalid Cisco DTLS key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Cisco DTLS record sequence exceeds 48 bits")]
    SequenceOverflow,
    #[error("Cisco DTLS record payload is too large: {0}")]
    PayloadTooLarge(usize),
    #[error("short Cisco DTLS record header: {0} bytes")]
    ShortHeader(usize),
    #[error("unexpected Cisco DTLS record version: {0:#06x}")]
    UnexpectedVersion(u16),
    #[error("truncated Cisco DTLS record payload")]
    TruncatedPayload,
    #[error("encrypted Cisco DTLS record has unexpected epoch: {0}")]
    UnexpectedEpoch(u16),
    #[error("invalid Cisco DTLS CBC record length: {0}")]
    InvalidRecordLength(usize),
    #[error("invalid Cisco DTLS record authentication")]
    InvalidAuthentication,
    #[error("Cisco DTLS cryptographic operation failed: {0}")]
    Crypto(#[from] ErrorStack),
    #[error("generate Cisco DTLS record IV: {0}")]
    Random(#[from] getrandom::Error),
}

pub fn tls10_prf(
    secret: &[u8],
    label: &str,
    seed: &[u8],
    output_length: usize,
) -> Vec<u8> {
    let mut labeled_seed = Vec::with_capacity(label.len() + seed.len());
    labeled_seed.extend_from_slice(label.as_bytes());
    labeled_seed.extend_from_slice(seed);
    let half_length = secret.len().div_ceil(2);
    let mut md5_output =
        p_hash::<Md5>(&secret[..half_length], &labeled_seed, output_length);
    let sha1_output = p_hash::<Sha1>(
        &secret[secret.len() - half_length..],
        &labeled_seed,
        output_length,
    );
    for (left, right) in md5_output.iter_mut().zip(sha1_output) {
        *left ^= right;
    }
    md5_output
}

fn p_hash<D>(secret: &[u8], seed: &[u8], output_length: usize) -> Vec<u8>
where
    D: hmac13::digest::block_api::EagerHash,
{
    let mut a = seed.to_vec();
    let mut output = Vec::with_capacity(output_length);
    while output.len() < output_length {
        let mut advance = <Hmac<D> as KeyInit>::new_from_slice(secret)
            .expect("HMAC accepts arbitrary key lengths");
        advance.update(&a);
        a = advance.finalize().into_bytes().to_vec();
        let mut round = <Hmac<D> as KeyInit>::new_from_slice(secret)
            .expect("HMAC accepts arbitrary key lengths");
        round.update(&a);
        round.update(seed);
        output.extend_from_slice(&round.finalize().into_bytes());
    }
    output.truncate(output_length);
    output
}

pub fn derive_legacy_dtls_keys(
    suite: &LegacyDtlsSuite,
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> LegacyDtlsKeys {
    let key_length = suite.cipher.key_length();
    let material_length = 2 * LEGACY_DTLS_MAC_LENGTH
        + 2 * key_length
        + 2 * suite.cipher.block_length();
    let mut seed =
        Vec::with_capacity(server_random.len() + client_random.len());
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let mut material =
        tls10_prf(master_secret, "key expansion", &seed, material_length);
    let mut offset = 0;
    let client_mac_key =
        take_key(&material, &mut offset, LEGACY_DTLS_MAC_LENGTH);
    let server_mac_key =
        take_key(&material, &mut offset, LEGACY_DTLS_MAC_LENGTH);
    let client_key = take_key(&material, &mut offset, key_length);
    let server_key = take_key(&material, &mut offset, key_length);
    material.fill(0);
    LegacyDtlsKeys {
        client_mac_key,
        server_mac_key,
        client_key,
        server_key,
    }
}

fn take_key(material: &[u8], offset: &mut usize, length: usize) -> Vec<u8> {
    let result = material[*offset..*offset + length].to_vec();
    *offset += length;
    result
}

pub fn parse_legacy_dtls_records(
    mut datagram: &[u8],
    suite: &LegacyDtlsSuite,
) -> Result<Vec<LegacyDtlsRecord>, LegacyDtlsError> {
    let mut records = Vec::with_capacity(3);
    while !datagram.is_empty() {
        if datagram.len() < LEGACY_DTLS_RECORD_HEADER_LENGTH {
            return Err(LegacyDtlsError::ShortHeader(datagram.len()));
        }
        let version = u16::from_be_bytes([datagram[1], datagram[2]]);
        if version != suite.version {
            return Err(LegacyDtlsError::UnexpectedVersion(version));
        }
        let payload_length =
            usize::from(u16::from_be_bytes([datagram[11], datagram[12]]));
        let record_length = LEGACY_DTLS_RECORD_HEADER_LENGTH + payload_length;
        if datagram.len() < record_length {
            return Err(LegacyDtlsError::TruncatedPayload);
        }
        records.push(LegacyDtlsRecord {
            content_type: datagram[0],
            epoch: u16::from_be_bytes([datagram[3], datagram[4]]),
            sequence: read_u48(&datagram[5..11]),
            payload: datagram[LEGACY_DTLS_RECORD_HEADER_LENGTH..record_length]
                .to_vec(),
        });
        datagram = &datagram[record_length..];
    }
    Ok(records)
}

pub fn marshal_legacy_dtls_record(
    record: &LegacyDtlsRecord,
    suite: &LegacyDtlsSuite,
) -> Result<Vec<u8>, LegacyDtlsError> {
    if record.sequence > LEGACY_DTLS_MAX_SEQUENCE {
        return Err(LegacyDtlsError::SequenceOverflow);
    }
    let payload_length = u16::try_from(record.payload.len())
        .map_err(|_| LegacyDtlsError::PayloadTooLarge(record.payload.len()))?;
    let mut encoded =
        vec![0; LEGACY_DTLS_RECORD_HEADER_LENGTH + record.payload.len()];
    encoded[0] = record.content_type;
    encoded[1..3].copy_from_slice(&suite.version.to_be_bytes());
    encoded[3..5].copy_from_slice(&record.epoch.to_be_bytes());
    write_u48(&mut encoded[5..11], record.sequence);
    encoded[11..13].copy_from_slice(&payload_length.to_be_bytes());
    encoded[13..].copy_from_slice(&record.payload);
    Ok(encoded)
}

pub fn encrypt_legacy_dtls_record(
    record: &LegacyDtlsRecord,
    key: &[u8],
    mac_key: &[u8],
    suite: &LegacyDtlsSuite,
) -> Result<Vec<u8>, LegacyDtlsError> {
    let mut iv = vec![0; suite.cipher.block_length()];
    random_fill(&mut iv)?;
    encrypt_legacy_dtls_record_with_iv(record, key, mac_key, suite, &iv)
}

pub fn encrypt_legacy_dtls_record_with_iv(
    record: &LegacyDtlsRecord,
    key: &[u8],
    mac_key: &[u8],
    suite: &LegacyDtlsSuite,
    iv: &[u8],
) -> Result<Vec<u8>, LegacyDtlsError> {
    validate_key_and_iv(key, iv, suite)?;
    let mac = legacy_dtls_record_mac(record, &record.payload, mac_key, suite)?;
    let block_length = suite.cipher.block_length();
    let mut plaintext =
        Vec::with_capacity(record.payload.len() + mac.len() + block_length);
    plaintext.extend_from_slice(&record.payload);
    plaintext.extend_from_slice(&mac);
    let padding_length = block_length - (plaintext.len() % block_length);
    plaintext
        .resize(plaintext.len() + padding_length, (padding_length - 1) as u8);
    let encrypted =
        crypt(false, suite.cipher.openssl_cipher(), key, iv, &plaintext)?;
    plaintext.fill(0);
    let mut protected = record.clone();
    protected.payload = Vec::with_capacity(iv.len() + encrypted.len());
    protected.payload.extend_from_slice(iv);
    protected.payload.extend_from_slice(&encrypted);
    marshal_legacy_dtls_record(&protected, suite)
}

pub fn decrypt_legacy_dtls_record(
    record: &LegacyDtlsRecord,
    key: &[u8],
    mac_key: &[u8],
    suite: &LegacyDtlsSuite,
) -> Result<Vec<u8>, LegacyDtlsError> {
    if record.epoch != 1 {
        return Err(LegacyDtlsError::UnexpectedEpoch(record.epoch));
    }
    let block_length = suite.cipher.block_length();
    let minimum_ciphertext_length =
        ((LEGACY_DTLS_MAC_LENGTH + block_length) / block_length) * block_length;
    if record.payload.len() < block_length + minimum_ciphertext_length
        || !(record.payload.len() - block_length).is_multiple_of(block_length)
    {
        return Err(LegacyDtlsError::InvalidRecordLength(record.payload.len()));
    }
    let (iv, ciphertext) = record.payload.split_at(block_length);
    validate_key_and_iv(key, iv, suite)?;
    let mut plaintext =
        crypt(true, suite.cipher.openssl_cipher(), key, iv, ciphertext)?;
    let padding_length =
        usize::from(*plaintext.last().expect("validated length")) + 1;
    let padding_value = (padding_length - 1) as u8;
    let mut padding_valid =
        usize::from(padding_length <= plaintext.len() - LEGACY_DTLS_MAC_LENGTH);
    for index in 0..plaintext.len().min(256) {
        if index < padding_length {
            padding_valid &= usize::from(
                plaintext[plaintext.len() - 1 - index] == padding_value,
            );
        }
    }
    let safe_padding_length = if padding_valid == 1 {
        padding_length
    } else {
        1
    };
    let payload_length =
        plaintext.len() - safe_padding_length - LEGACY_DTLS_MAC_LENGTH;
    let received_mac = plaintext
        [payload_length..payload_length + LEGACY_DTLS_MAC_LENGTH]
        .to_vec();
    let payload = plaintext[..payload_length].to_vec();
    let expected_mac =
        legacy_dtls_record_mac(record, &payload, mac_key, suite)?;
    let authenticated =
        padding_valid == 1 && memcmp::eq(&received_mac, &expected_mac);
    plaintext.fill(0);
    if !authenticated {
        return Err(LegacyDtlsError::InvalidAuthentication);
    }
    Ok(payload)
}

fn validate_key_and_iv(
    key: &[u8],
    iv: &[u8],
    suite: &LegacyDtlsSuite,
) -> Result<(), LegacyDtlsError> {
    if key.len() != suite.cipher.key_length() {
        return Err(LegacyDtlsError::InvalidKeyLength {
            expected: suite.cipher.key_length(),
            actual: key.len(),
        });
    }
    if iv.len() != suite.cipher.block_length() {
        return Err(LegacyDtlsError::InvalidRecordLength(iv.len()));
    }
    Ok(())
}

fn crypt(
    decrypt: bool,
    cipher: Cipher,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut crypter = Crypter::new(
        cipher,
        if decrypt {
            Mode::Decrypt
        } else {
            Mode::Encrypt
        },
        key,
        Some(iv),
    )?;
    crypter.pad(false);
    let mut output = vec![0; input.len() + cipher.block_size()];
    let mut length = crypter.update(input, &mut output)?;
    length += crypter.finalize(&mut output[length..])?;
    output.truncate(length);
    Ok(output)
}

fn legacy_dtls_record_mac(
    record: &LegacyDtlsRecord,
    payload: &[u8],
    mac_key: &[u8],
    suite: &LegacyDtlsSuite,
) -> Result<Vec<u8>, LegacyDtlsError> {
    let payload_length = u16::try_from(payload.len())
        .map_err(|_| LegacyDtlsError::PayloadTooLarge(payload.len()))?;
    let mut header = [0_u8; LEGACY_DTLS_RECORD_HEADER_LENGTH];
    header[0..2].copy_from_slice(&record.epoch.to_be_bytes());
    write_u48(&mut header[2..8], record.sequence);
    header[8] = record.content_type;
    header[9..11].copy_from_slice(&suite.version.to_be_bytes());
    header[11..13].copy_from_slice(&payload_length.to_be_bytes());
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(mac_key)
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(&header);
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn write_u48(output: &mut [u8], value: u64) {
    output.copy_from_slice(&value.to_be_bytes()[2..]);
}

fn read_u48(input: &[u8]) -> u64 {
    let mut value = [0_u8; 8];
    value[2..].copy_from_slice(input);
    u64::from_be_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls10_prf_matches_pinned_go_vector() {
        assert_eq!(
            hex::encode(tls10_prf(b"secret", "test label", b"seed", 48)),
            "a8ef48e934ebf83df2dffe4aa0445a2845481b5dd6cd2355ef569ef456e33754710d294a45a295bde8431db95319f3f9"
        );
    }

    #[test]
    fn derives_directional_keys_in_upstream_order() {
        let suite = LegacyDtlsSuite::cisco(LegacyDtlsCipher::Aes128);
        let keys = derive_legacy_dtls_keys(
            &suite,
            &[0x11; 48],
            &[0x22; 32],
            &[0x33; 32],
        );
        assert_eq!(keys.client_mac_key.len(), 20);
        assert_eq!(keys.server_mac_key.len(), 20);
        assert_eq!(keys.client_key.len(), 16);
        assert_eq!(keys.server_key.len(), 16);
        assert_ne!(keys.client_key, keys.server_key);
    }

    #[test]
    fn record_header_round_trips_multiple_records() {
        let suite = LegacyDtlsSuite::cisco(LegacyDtlsCipher::Aes128);
        let first = LegacyDtlsRecord {
            content_type: 23,
            epoch: 1,
            sequence: 0x0102_0304_0506,
            payload: b"one".to_vec(),
        };
        let second = LegacyDtlsRecord {
            content_type: 21,
            epoch: 0,
            sequence: 9,
            payload: b"two".to_vec(),
        };
        let mut datagram = marshal_legacy_dtls_record(&first, &suite).unwrap();
        datagram.extend(marshal_legacy_dtls_record(&second, &suite).unwrap());
        assert_eq!(
            parse_legacy_dtls_records(&datagram, &suite).unwrap(),
            [first, second]
        );
    }

    #[test]
    fn deterministic_aes_record_round_trips_and_authenticates_header() {
        let suite = LegacyDtlsSuite::cisco(LegacyDtlsCipher::Aes128);
        let record = LegacyDtlsRecord {
            content_type: 23,
            epoch: 1,
            sequence: 0x0102_0304_0506,
            payload: b"an IP packet".to_vec(),
        };
        let encoded = encrypt_legacy_dtls_record_with_iv(
            &record,
            &[0x11; 16],
            &[0x22; 20],
            &suite,
            &[0x33; 16],
        )
        .unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "1701000001010203040506004033333333333333333333333333333333630895e4a601360521280ee9a19825f852bcde7921eff3e149858514efe7a5b748fdc07e3507b09c733b9f9fad65065d"
        );
        let protected = parse_legacy_dtls_records(&encoded, &suite)
            .unwrap()
            .remove(0);
        assert_eq!(
            decrypt_legacy_dtls_record(
                &protected,
                &[0x11; 16],
                &[0x22; 20],
                &suite,
            )
            .unwrap(),
            record.payload
        );
        let mut tampered = protected;
        tampered.sequence += 1;
        assert!(matches!(
            decrypt_legacy_dtls_record(
                &tampered,
                &[0x11; 16],
                &[0x22; 20],
                &suite,
            ),
            Err(LegacyDtlsError::InvalidAuthentication)
        ));
    }

    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut window = LegacyDtlsReplayWindow::default();
        assert!(window.accept(65));
        assert!(window.accept(64));
        assert!(!window.accept(64));
        assert!(window.accept(130));
        assert!(!window.accept(65));
    }

    #[test]
    fn cipher_policy_matches_anyconnect_names() {
        assert_eq!(
            LegacyDtlsCipher::from_name("AES256-SHA", false).unwrap(),
            LegacyDtlsCipher::Aes256
        );
        assert!(matches!(
            LegacyDtlsCipher::from_name("DES-CBC3-SHA", false),
            Err(LegacyDtlsError::DeprecatedCipher(_))
        ));
        assert_eq!(
            LegacyDtlsCipher::from_name("DES-CBC3-SHA", true).unwrap(),
            LegacyDtlsCipher::TripleDes
        );
    }
}
