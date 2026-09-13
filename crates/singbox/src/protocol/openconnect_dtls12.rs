//! Cisco/OpenConnect DTLS 1.2 abbreviated-session record protection.
//!
//! The ordinary DTLS 1.2 cipher primitives are provided by RustCrypto and
//! OpenSSL.  This module supplies the narrow compatibility layer which mature
//! Rust DTLS clients do not expose: deriving record keys from the 48-byte
//! master secret injected by CSTP and protecting records for the exact cipher
//! suite selected by the AnyConnect gateway.

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit as _, Payload},
};
use ccm::{
    Ccm,
    consts::{U8, U12, U16},
};
use chacha20poly1305::ChaCha20Poly1305;
use getrandom::fill as random_fill;
use hmac13::{Hmac, Mac};
use openssl::{
    error::ErrorStack,
    memcmp,
    symm::{Cipher, Crypter, Mode},
};
use sha1_11::Sha1;
use sha2::{Digest as _, Sha256, Sha384};
use std::fmt;
use thiserror::Error;

pub const DTLS12_VERSION: u16 = 0xfefd;
pub const DTLS12_RECORD_HEADER_LENGTH: usize = 13;
pub const DTLS12_MAX_SEQUENCE: u64 = 0x0000_ffff_ffff_ffff;
pub const DTLS12_AEAD_TAG_LENGTH: usize = 16;
pub const DTLS12_GCM_EXPLICIT_NONCE_LENGTH: usize = 8;
pub const DTLS12_CBC_MAC_LENGTH: usize = 20;
pub const DTLS12_CBC_SHA256_MAC_LENGTH: usize = 32;

type Aes128Ccm = Ccm<aes::Aes128, U16, U12>;
type Aes128Ccm8 = Ccm<aes::Aes128, U8, U12>;
type Aes256Ccm8 = Ccm<aes::Aes256, U8, U12>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dtls12PrfHash {
    Sha256,
    Sha384,
}

impl Dtls12PrfHash {
    pub const fn output_length(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dtls12Cipher {
    Aes128CbcSha1,
    Aes256CbcSha1,
    Aes128CbcSha256,
    Aes128Gcm,
    Aes256Gcm,
    Aes128Ccm,
    Aes128Ccm8,
    Aes256Ccm8,
    ChaCha20Poly1305,
}

impl Dtls12Cipher {
    pub const fn key_length(self) -> usize {
        match self {
            Self::Aes128CbcSha1
            | Self::Aes128CbcSha256
            | Self::Aes128Gcm
            | Self::Aes128Ccm
            | Self::Aes128Ccm8 => 16,
            Self::Aes256CbcSha1
            | Self::Aes256Gcm
            | Self::Aes256Ccm8
            | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub const fn mac_key_length(self) -> usize {
        match self {
            Self::Aes128CbcSha1 | Self::Aes256CbcSha1 => DTLS12_CBC_MAC_LENGTH,
            Self::Aes128CbcSha256 => DTLS12_CBC_SHA256_MAC_LENGTH,
            Self::Aes128Gcm
            | Self::Aes256Gcm
            | Self::Aes128Ccm
            | Self::Aes128Ccm8
            | Self::Aes256Ccm8
            | Self::ChaCha20Poly1305 => 0,
        }
    }

    pub const fn fixed_iv_length(self) -> usize {
        match self {
            Self::Aes128CbcSha1
            | Self::Aes256CbcSha1
            | Self::Aes128CbcSha256 => 16,
            Self::Aes128Gcm
            | Self::Aes256Gcm
            | Self::Aes128Ccm
            | Self::Aes128Ccm8
            | Self::Aes256Ccm8 => 4,
            Self::ChaCha20Poly1305 => 12,
        }
    }

    const fn is_cbc(self) -> bool {
        matches!(
            self,
            Self::Aes128CbcSha1 | Self::Aes256CbcSha1 | Self::Aes128CbcSha256
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dtls12Suite {
    pub name: String,
    pub cipher_suite_id: u16,
    pub cipher: Dtls12Cipher,
    pub prf_hash: Dtls12PrfHash,
    pub psk_cipher: bool,
}

impl Dtls12Suite {
    pub fn from_name(name: &str, dtls12: bool) -> Result<Self, Dtls12Error> {
        let (cipher_suite_id, cipher, prf_hash, psk_cipher) = match name {
            "DHE-RSA-AES128-SHA" if dtls12 => (
                0x0033,
                Dtls12Cipher::Aes128CbcSha1,
                Dtls12PrfHash::Sha256,
                false,
            ),
            "DHE-RSA-AES256-SHA" if dtls12 => (
                0x0039,
                Dtls12Cipher::Aes256CbcSha1,
                Dtls12PrfHash::Sha256,
                false,
            ),
            "AES128-SHA" if dtls12 => (
                0x002f,
                Dtls12Cipher::Aes128CbcSha1,
                Dtls12PrfHash::Sha256,
                false,
            ),
            "AES256-SHA" if dtls12 => (
                0x0035,
                Dtls12Cipher::Aes256CbcSha1,
                Dtls12PrfHash::Sha256,
                false,
            ),
            "ECDHE-RSA-AES128-GCM-SHA256" if dtls12 => (
                0xc02f,
                Dtls12Cipher::Aes128Gcm,
                Dtls12PrfHash::Sha256,
                false,
            ),
            "ECDHE-RSA-AES256-GCM-SHA384" if dtls12 => (
                0xc030,
                Dtls12Cipher::Aes256Gcm,
                Dtls12PrfHash::Sha384,
                false,
            ),
            "AES128-GCM-SHA256" | "OC-DTLS1_2-AES128-GCM" => (
                0x009c,
                Dtls12Cipher::Aes128Gcm,
                Dtls12PrfHash::Sha256,
                false,
            ),
            "AES256-GCM-SHA384" | "OC-DTLS1_2-AES256-GCM" => (
                0x009d,
                Dtls12Cipher::Aes256Gcm,
                Dtls12PrfHash::Sha384,
                false,
            ),
            "OC2-DTLS1_2-CHACHA20-POLY1305" => (
                0xccab,
                Dtls12Cipher::ChaCha20Poly1305,
                Dtls12PrfHash::Sha256,
                true,
            ),
            "TLS_PSK_WITH_AES_128_GCM_SHA256" => {
                (0x00a8, Dtls12Cipher::Aes128Gcm, Dtls12PrfHash::Sha256, true)
            }
            "TLS_PSK_WITH_AES_128_CCM" => {
                (0xc0a4, Dtls12Cipher::Aes128Ccm, Dtls12PrfHash::Sha256, true)
            }
            "TLS_PSK_WITH_AES_128_CCM_8" => (
                0xc0a8,
                Dtls12Cipher::Aes128Ccm8,
                Dtls12PrfHash::Sha256,
                true,
            ),
            "TLS_PSK_WITH_AES_256_CCM_8" => (
                0xc0a9,
                Dtls12Cipher::Aes256Ccm8,
                Dtls12PrfHash::Sha256,
                true,
            ),
            "TLS_PSK_WITH_AES_128_CBC_SHA256" => (
                0x00ae,
                Dtls12Cipher::Aes128CbcSha256,
                Dtls12PrfHash::Sha256,
                true,
            ),
            "DHE-RSA-AES128-SHA"
            | "DHE-RSA-AES256-SHA"
            | "AES128-SHA"
            | "AES256-SHA"
            | "ECDHE-RSA-AES128-GCM-SHA256"
            | "ECDHE-RSA-AES256-GCM-SHA384" => {
                return Err(Dtls12Error::RequiresDtls12(name.into()));
            }
            _ => return Err(Dtls12Error::UnsupportedCipher(name.into())),
        };
        Ok(Self {
            name: name.into(),
            cipher_suite_id,
            cipher,
            prf_hash,
            psk_cipher,
        })
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Dtls12Keys {
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl fmt::Debug for Dtls12Keys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Dtls12Keys")
            .field("client_mac_key", &"[REDACTED]")
            .field("server_mac_key", &"[REDACTED]")
            .field("client_write_key", &"[REDACTED]")
            .field("server_write_key", &"[REDACTED]")
            .field("client_write_iv", &"[REDACTED]")
            .field("server_write_iv", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Dtls12Keys {
    fn drop(&mut self) {
        self.client_mac_key.fill(0);
        self.server_mac_key.fill(0);
        self.client_write_key.fill(0);
        self.server_write_key.fill(0);
        self.client_write_iv.fill(0);
        self.server_write_iv.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dtls12Record {
    pub content_type: u8,
    pub epoch: u16,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum Dtls12Error {
    #[error("unsupported Cisco DTLS 1.2 cipher: {0}")]
    UnsupportedCipher(String),
    #[error("Cisco cipher requires negotiated DTLS 1.2 mode: {0}")]
    RequiresDtls12(String),
    #[error("DTLS 1.2 record sequence exceeds 48 bits")]
    SequenceOverflow,
    #[error("DTLS 1.2 record payload is too large: {0}")]
    PayloadTooLarge(usize),
    #[error("short DTLS 1.2 record header: {0} bytes")]
    ShortHeader(usize),
    #[error("unexpected DTLS record version: {0:#06x}")]
    UnexpectedVersion(u16),
    #[error("truncated DTLS 1.2 record payload")]
    TruncatedPayload,
    #[error("invalid DTLS 1.2 key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error(
        "invalid DTLS 1.2 fixed IV length: expected {expected}, got {actual}"
    )]
    InvalidIvLength { expected: usize, actual: usize },
    #[error("invalid DTLS 1.2 encrypted record length: {0}")]
    InvalidRecordLength(usize),
    #[error("invalid DTLS 1.2 record authentication")]
    InvalidAuthentication,
    #[error("DTLS 1.2 cryptographic operation failed: {0}")]
    Crypto(#[from] ErrorStack),
    #[error("generate DTLS 1.2 record IV: {0}")]
    Random(#[from] getrandom::Error),
}

pub fn tls12_prf(
    hash: Dtls12PrfHash,
    secret: &[u8],
    label: &str,
    seed: &[u8],
    output_length: usize,
) -> Vec<u8> {
    let mut labeled_seed = Vec::with_capacity(label.len() + seed.len());
    labeled_seed.extend_from_slice(label.as_bytes());
    labeled_seed.extend_from_slice(seed);
    match hash {
        Dtls12PrfHash::Sha256 => {
            p_hash::<Sha256>(secret, &labeled_seed, output_length)
        }
        Dtls12PrfHash::Sha384 => {
            p_hash::<Sha384>(secret, &labeled_seed, output_length)
        }
    }
}

fn p_hash<D>(secret: &[u8], seed: &[u8], output_length: usize) -> Vec<u8>
where
    D: hmac13::digest::block_api::EagerHash,
{
    let mut a = seed.to_vec();
    let mut output = Vec::with_capacity(output_length);
    while output.len() < output_length {
        let mut advance = <Hmac<D> as hmac13::KeyInit>::new_from_slice(secret)
            .expect("HMAC accepts arbitrary key lengths");
        advance.update(&a);
        a = advance.finalize().into_bytes().to_vec();
        let mut round = <Hmac<D> as hmac13::KeyInit>::new_from_slice(secret)
            .expect("HMAC accepts arbitrary key lengths");
        round.update(&a);
        round.update(seed);
        output.extend_from_slice(&round.finalize().into_bytes());
    }
    output.truncate(output_length);
    output
}

pub fn derive_dtls12_keys(
    suite: &Dtls12Suite,
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Dtls12Keys {
    let mac_length = suite.cipher.mac_key_length();
    let key_length = suite.cipher.key_length();
    let iv_length = suite.cipher.fixed_iv_length();
    let material_length = 2 * (mac_length + key_length + iv_length);
    let mut seed =
        Vec::with_capacity(server_random.len() + client_random.len());
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let mut material = tls12_prf(
        suite.prf_hash,
        master_secret,
        "key expansion",
        &seed,
        material_length,
    );
    let mut offset = 0;
    let client_mac_key = take_key(&material, &mut offset, mac_length);
    let server_mac_key = take_key(&material, &mut offset, mac_length);
    let client_write_key = take_key(&material, &mut offset, key_length);
    let server_write_key = take_key(&material, &mut offset, key_length);
    let client_write_iv = take_key(&material, &mut offset, iv_length);
    let server_write_iv = take_key(&material, &mut offset, iv_length);
    material.fill(0);
    Dtls12Keys {
        client_mac_key,
        server_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    }
}

pub fn dtls12_finished(
    suite: &Dtls12Suite,
    master_secret: &[u8],
    handshake_bodies: &[u8],
    client: bool,
) -> Vec<u8> {
    let transcript_hash = match suite.prf_hash {
        Dtls12PrfHash::Sha256 => Sha256::digest(handshake_bodies).to_vec(),
        Dtls12PrfHash::Sha384 => Sha384::digest(handshake_bodies).to_vec(),
    };
    tls12_prf(
        suite.prf_hash,
        master_secret,
        if client {
            "client finished"
        } else {
            "server finished"
        },
        &transcript_hash,
        12,
    )
}

fn take_key(material: &[u8], offset: &mut usize, length: usize) -> Vec<u8> {
    let result = material[*offset..*offset + length].to_vec();
    *offset += length;
    result
}

pub fn parse_dtls12_records(
    mut datagram: &[u8],
) -> Result<Vec<Dtls12Record>, Dtls12Error> {
    let mut records = Vec::with_capacity(3);
    while !datagram.is_empty() {
        if datagram.len() < DTLS12_RECORD_HEADER_LENGTH {
            return Err(Dtls12Error::ShortHeader(datagram.len()));
        }
        let version = u16::from_be_bytes([datagram[1], datagram[2]]);
        if version != DTLS12_VERSION {
            return Err(Dtls12Error::UnexpectedVersion(version));
        }
        let payload_length =
            usize::from(u16::from_be_bytes([datagram[11], datagram[12]]));
        let record_length = DTLS12_RECORD_HEADER_LENGTH + payload_length;
        if datagram.len() < record_length {
            return Err(Dtls12Error::TruncatedPayload);
        }
        records.push(Dtls12Record {
            content_type: datagram[0],
            epoch: u16::from_be_bytes([datagram[3], datagram[4]]),
            sequence: read_u48(&datagram[5..11]),
            payload: datagram[DTLS12_RECORD_HEADER_LENGTH..record_length]
                .to_vec(),
        });
        datagram = &datagram[record_length..];
    }
    Ok(records)
}

pub fn marshal_dtls12_record(
    record: &Dtls12Record,
) -> Result<Vec<u8>, Dtls12Error> {
    validate_record(record)?;
    let payload_length = u16::try_from(record.payload.len())
        .map_err(|_| Dtls12Error::PayloadTooLarge(record.payload.len()))?;
    let mut encoded =
        vec![0; DTLS12_RECORD_HEADER_LENGTH + record.payload.len()];
    encoded[0] = record.content_type;
    encoded[1..3].copy_from_slice(&DTLS12_VERSION.to_be_bytes());
    encoded[3..5].copy_from_slice(&record.epoch.to_be_bytes());
    write_u48(&mut encoded[5..11], record.sequence);
    encoded[11..13].copy_from_slice(&payload_length.to_be_bytes());
    encoded[13..].copy_from_slice(&record.payload);
    Ok(encoded)
}

pub fn encrypt_dtls12_record(
    record: &Dtls12Record,
    key: &[u8],
    mac_key: &[u8],
    fixed_iv: &[u8],
    suite: &Dtls12Suite,
) -> Result<Vec<u8>, Dtls12Error> {
    validate_protection(key, mac_key, fixed_iv, suite)?;
    if suite.cipher.is_cbc() {
        let mut explicit_iv = [0_u8; 16];
        random_fill(&mut explicit_iv)?;
        return encrypt_dtls12_cbc_record_with_iv(
            record,
            key,
            mac_key,
            fixed_iv,
            suite,
            &explicit_iv,
        );
    }
    encrypt_dtls12_aead_record(record, key, fixed_iv, suite)
}

pub fn encrypt_dtls12_cbc_record_with_iv(
    record: &Dtls12Record,
    key: &[u8],
    mac_key: &[u8],
    fixed_iv: &[u8],
    suite: &Dtls12Suite,
    explicit_iv: &[u8],
) -> Result<Vec<u8>, Dtls12Error> {
    validate_record(record)?;
    validate_protection(key, mac_key, fixed_iv, suite)?;
    if !suite.cipher.is_cbc() {
        return Err(Dtls12Error::UnsupportedCipher(suite.name.clone()));
    }
    if explicit_iv.len() != 16 {
        return Err(Dtls12Error::InvalidIvLength {
            expected: 16,
            actual: explicit_iv.len(),
        });
    }
    let mac = dtls12_cbc_mac(record, &record.payload, mac_key, suite.cipher)?;
    let mut plaintext =
        Vec::with_capacity(record.payload.len() + mac.len() + 16);
    plaintext.extend_from_slice(&record.payload);
    plaintext.extend_from_slice(&mac);
    let padding_length = 16 - plaintext.len() % 16;
    plaintext
        .resize(plaintext.len() + padding_length, (padding_length - 1) as u8);
    let ciphertext = crypt_cbc(false, key, explicit_iv, &plaintext)?;
    plaintext.fill(0);
    let mut protected = record.clone();
    protected.payload = Vec::with_capacity(16 + ciphertext.len());
    protected.payload.extend_from_slice(explicit_iv);
    protected.payload.extend_from_slice(&ciphertext);
    marshal_dtls12_record(&protected)
}

fn encrypt_dtls12_aead_record(
    record: &Dtls12Record,
    key: &[u8],
    fixed_iv: &[u8],
    suite: &Dtls12Suite,
) -> Result<Vec<u8>, Dtls12Error> {
    validate_record(record)?;
    let aad = dtls12_record_aad(record, record.payload.len())?;
    let mut protected = record.clone();
    match suite.cipher {
        Dtls12Cipher::Aes128Gcm | Dtls12Cipher::Aes256Gcm => {
            let explicit_nonce = record_number(record);
            let mut nonce = [0_u8; 12];
            nonce[..4].copy_from_slice(fixed_iv);
            nonce[4..].copy_from_slice(&explicit_nonce);
            let encrypted =
                aes_gcm_encrypt(key, &nonce, &aad, &record.payload)?;
            protected.payload = Vec::with_capacity(
                DTLS12_GCM_EXPLICIT_NONCE_LENGTH + encrypted.len(),
            );
            protected.payload.extend_from_slice(&explicit_nonce);
            protected.payload.extend_from_slice(&encrypted);
        }
        Dtls12Cipher::Aes128Ccm
        | Dtls12Cipher::Aes128Ccm8
        | Dtls12Cipher::Aes256Ccm8 => {
            let explicit_nonce = record_number(record);
            let mut nonce = [0_u8; 12];
            nonce[..4].copy_from_slice(fixed_iv);
            nonce[4..].copy_from_slice(&explicit_nonce);
            let encrypted = aes_ccm_encrypt(
                key,
                &nonce,
                &aad,
                &record.payload,
                suite.cipher,
            )?;
            protected.payload = Vec::with_capacity(
                DTLS12_GCM_EXPLICIT_NONCE_LENGTH + encrypted.len(),
            );
            protected.payload.extend_from_slice(&explicit_nonce);
            protected.payload.extend_from_slice(&encrypted);
        }
        Dtls12Cipher::ChaCha20Poly1305 => {
            let nonce = chacha_nonce(fixed_iv, record)?;
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
                    Dtls12Error::InvalidKeyLength {
                        expected: 32,
                        actual: key.len(),
                    }
                })?;
            protected.payload = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &record.payload,
                        aad: &aad,
                    },
                )
                .map_err(|_| Dtls12Error::InvalidAuthentication)?;
        }
        Dtls12Cipher::Aes128CbcSha1
        | Dtls12Cipher::Aes256CbcSha1
        | Dtls12Cipher::Aes128CbcSha256 => {
            unreachable!("CBC is handled before AEAD encryption")
        }
    }
    marshal_dtls12_record(&protected)
}

pub fn decrypt_dtls12_record(
    record: &Dtls12Record,
    key: &[u8],
    mac_key: &[u8],
    fixed_iv: &[u8],
    suite: &Dtls12Suite,
) -> Result<Vec<u8>, Dtls12Error> {
    validate_record(record)?;
    validate_protection(key, mac_key, fixed_iv, suite)?;
    match suite.cipher {
        Dtls12Cipher::Aes128CbcSha1
        | Dtls12Cipher::Aes256CbcSha1
        | Dtls12Cipher::Aes128CbcSha256 => {
            decrypt_dtls12_cbc_record(record, key, mac_key, suite.cipher)
        }
        Dtls12Cipher::Aes128Gcm | Dtls12Cipher::Aes256Gcm => {
            decrypt_dtls12_gcm_record(record, key, fixed_iv)
        }
        Dtls12Cipher::Aes128Ccm
        | Dtls12Cipher::Aes128Ccm8
        | Dtls12Cipher::Aes256Ccm8 => {
            decrypt_dtls12_ccm_record(record, key, fixed_iv, suite.cipher)
        }
        Dtls12Cipher::ChaCha20Poly1305 => {
            decrypt_dtls12_chacha_record(record, key, fixed_iv)
        }
    }
}

fn decrypt_dtls12_cbc_record(
    record: &Dtls12Record,
    key: &[u8],
    mac_key: &[u8],
    cipher: Dtls12Cipher,
) -> Result<Vec<u8>, Dtls12Error> {
    let mac_length = cipher.mac_key_length();
    let minimum = 16 + mac_length + 1;
    if record.payload.len() < minimum
        || !record.payload.len().is_multiple_of(16)
    {
        return Err(Dtls12Error::InvalidRecordLength(record.payload.len()));
    }
    let (explicit_iv, ciphertext) = record.payload.split_at(16);
    let mut plaintext = crypt_cbc(true, key, explicit_iv, ciphertext)?;
    let padding_length =
        usize::from(*plaintext.last().expect("validated length")) + 1;
    let padding_value = (padding_length - 1) as u8;
    let mut padding_valid = usize::from(
        padding_length <= plaintext.len().saturating_sub(mac_length),
    );
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
    let payload_length = plaintext.len() - safe_padding_length - mac_length;
    let received_mac =
        plaintext[payload_length..payload_length + mac_length].to_vec();
    let payload = plaintext[..payload_length].to_vec();
    let expected_mac = dtls12_cbc_mac(record, &payload, mac_key, cipher)?;
    let authenticated =
        padding_valid == 1 && memcmp::eq(&received_mac, &expected_mac);
    plaintext.fill(0);
    if !authenticated {
        return Err(Dtls12Error::InvalidAuthentication);
    }
    Ok(payload)
}

fn decrypt_dtls12_gcm_record(
    record: &Dtls12Record,
    key: &[u8],
    fixed_iv: &[u8],
) -> Result<Vec<u8>, Dtls12Error> {
    let minimum = DTLS12_GCM_EXPLICIT_NONCE_LENGTH + DTLS12_AEAD_TAG_LENGTH;
    if record.payload.len() < minimum {
        return Err(Dtls12Error::InvalidRecordLength(record.payload.len()));
    }
    let (explicit_nonce, ciphertext) =
        record.payload.split_at(DTLS12_GCM_EXPLICIT_NONCE_LENGTH);
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(fixed_iv);
    nonce[4..].copy_from_slice(explicit_nonce);
    let plaintext_length = ciphertext.len() - DTLS12_AEAD_TAG_LENGTH;
    let aad = dtls12_record_aad(record, plaintext_length)?;
    aes_gcm_decrypt(key, &nonce, &aad, ciphertext)
}

fn decrypt_dtls12_ccm_record(
    record: &Dtls12Record,
    key: &[u8],
    fixed_iv: &[u8],
    cipher: Dtls12Cipher,
) -> Result<Vec<u8>, Dtls12Error> {
    let tag_length = match cipher {
        Dtls12Cipher::Aes128Ccm => 16,
        Dtls12Cipher::Aes128Ccm8 | Dtls12Cipher::Aes256Ccm8 => 8,
        _ => return Err(Dtls12Error::UnsupportedCipher(format!("{cipher:?}"))),
    };
    let minimum = DTLS12_GCM_EXPLICIT_NONCE_LENGTH + tag_length;
    if record.payload.len() < minimum {
        return Err(Dtls12Error::InvalidRecordLength(record.payload.len()));
    }
    let (explicit_nonce, ciphertext) =
        record.payload.split_at(DTLS12_GCM_EXPLICIT_NONCE_LENGTH);
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(fixed_iv);
    nonce[4..].copy_from_slice(explicit_nonce);
    let plaintext_length = ciphertext.len() - tag_length;
    let aad = dtls12_record_aad(record, plaintext_length)?;
    aes_ccm_decrypt(key, &nonce, &aad, ciphertext, cipher)
}

fn decrypt_dtls12_chacha_record(
    record: &Dtls12Record,
    key: &[u8],
    fixed_iv: &[u8],
) -> Result<Vec<u8>, Dtls12Error> {
    if record.payload.len() < DTLS12_AEAD_TAG_LENGTH {
        return Err(Dtls12Error::InvalidRecordLength(record.payload.len()));
    }
    let plaintext_length = record.payload.len() - DTLS12_AEAD_TAG_LENGTH;
    let aad = dtls12_record_aad(record, plaintext_length)?;
    let nonce = chacha_nonce(fixed_iv, record)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
        Dtls12Error::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        }
    })?;
    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &record.payload,
                aad: &aad,
            },
        )
        .map_err(|_| Dtls12Error::InvalidAuthentication)
}

fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Dtls12Error> {
    macro_rules! encrypt {
        ($cipher:expr) => {
            $cipher.encrypt(
                nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
        };
    }
    let result = match key.len() {
        16 => encrypt!(Aes128Gcm::new_from_slice(key).expect("validated key")),
        32 => encrypt!(Aes256Gcm::new_from_slice(key).expect("validated key")),
        actual => {
            return Err(Dtls12Error::InvalidKeyLength {
                expected: 16,
                actual,
            });
        }
    };
    result.map_err(|_| Dtls12Error::InvalidAuthentication)
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Dtls12Error> {
    macro_rules! decrypt {
        ($cipher:expr) => {
            $cipher.decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
        };
    }
    let result = match key.len() {
        16 => decrypt!(Aes128Gcm::new_from_slice(key).expect("validated key")),
        32 => decrypt!(Aes256Gcm::new_from_slice(key).expect("validated key")),
        actual => {
            return Err(Dtls12Error::InvalidKeyLength {
                expected: 16,
                actual,
            });
        }
    };
    result.map_err(|_| Dtls12Error::InvalidAuthentication)
}

fn aes_ccm_encrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    cipher: Dtls12Cipher,
) -> Result<Vec<u8>, Dtls12Error> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let result = match cipher {
        Dtls12Cipher::Aes128Ccm => Aes128Ccm::new_from_slice(key)
            .expect("validated key")
            .encrypt(nonce.into(), payload),
        Dtls12Cipher::Aes128Ccm8 => Aes128Ccm8::new_from_slice(key)
            .expect("validated key")
            .encrypt(nonce.into(), payload),
        Dtls12Cipher::Aes256Ccm8 => Aes256Ccm8::new_from_slice(key)
            .expect("validated key")
            .encrypt(nonce.into(), payload),
        _ => return Err(Dtls12Error::UnsupportedCipher(format!("{cipher:?}"))),
    };
    result.map_err(|_| Dtls12Error::InvalidAuthentication)
}

fn aes_ccm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    cipher: Dtls12Cipher,
) -> Result<Vec<u8>, Dtls12Error> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let result = match cipher {
        Dtls12Cipher::Aes128Ccm => Aes128Ccm::new_from_slice(key)
            .expect("validated key")
            .decrypt(nonce.into(), payload),
        Dtls12Cipher::Aes128Ccm8 => Aes128Ccm8::new_from_slice(key)
            .expect("validated key")
            .decrypt(nonce.into(), payload),
        Dtls12Cipher::Aes256Ccm8 => Aes256Ccm8::new_from_slice(key)
            .expect("validated key")
            .decrypt(nonce.into(), payload),
        _ => return Err(Dtls12Error::UnsupportedCipher(format!("{cipher:?}"))),
    };
    result.map_err(|_| Dtls12Error::InvalidAuthentication)
}

fn validate_record(record: &Dtls12Record) -> Result<(), Dtls12Error> {
    if record.sequence > DTLS12_MAX_SEQUENCE {
        return Err(Dtls12Error::SequenceOverflow);
    }
    if record.payload.len() > usize::from(u16::MAX) {
        return Err(Dtls12Error::PayloadTooLarge(record.payload.len()));
    }
    Ok(())
}

fn validate_protection(
    key: &[u8],
    mac_key: &[u8],
    fixed_iv: &[u8],
    suite: &Dtls12Suite,
) -> Result<(), Dtls12Error> {
    if key.len() != suite.cipher.key_length() {
        return Err(Dtls12Error::InvalidKeyLength {
            expected: suite.cipher.key_length(),
            actual: key.len(),
        });
    }
    if mac_key.len() != suite.cipher.mac_key_length() {
        return Err(Dtls12Error::InvalidKeyLength {
            expected: suite.cipher.mac_key_length(),
            actual: mac_key.len(),
        });
    }
    if fixed_iv.len() != suite.cipher.fixed_iv_length() {
        return Err(Dtls12Error::InvalidIvLength {
            expected: suite.cipher.fixed_iv_length(),
            actual: fixed_iv.len(),
        });
    }
    Ok(())
}

fn dtls12_cbc_mac(
    record: &Dtls12Record,
    payload: &[u8],
    mac_key: &[u8],
    cipher: Dtls12Cipher,
) -> Result<Vec<u8>, Dtls12Error> {
    let aad = dtls12_record_aad(record, payload.len())?;
    match cipher {
        Dtls12Cipher::Aes128CbcSha1 | Dtls12Cipher::Aes256CbcSha1 => {
            let mut mac =
                <Hmac<Sha1> as hmac13::KeyInit>::new_from_slice(mac_key)
                    .expect("HMAC accepts arbitrary key lengths");
            mac.update(&aad);
            mac.update(payload);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Dtls12Cipher::Aes128CbcSha256 => {
            let mut mac =
                <Hmac<Sha256> as hmac13::KeyInit>::new_from_slice(mac_key)
                    .expect("HMAC accepts arbitrary key lengths");
            mac.update(&aad);
            mac.update(payload);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(Dtls12Error::UnsupportedCipher(format!("{cipher:?}"))),
    }
}

fn dtls12_record_aad(
    record: &Dtls12Record,
    payload_length: usize,
) -> Result<[u8; DTLS12_RECORD_HEADER_LENGTH], Dtls12Error> {
    let payload_length = u16::try_from(payload_length)
        .map_err(|_| Dtls12Error::PayloadTooLarge(payload_length))?;
    let mut aad = [0_u8; DTLS12_RECORD_HEADER_LENGTH];
    aad[0..2].copy_from_slice(&record.epoch.to_be_bytes());
    write_u48(&mut aad[2..8], record.sequence);
    aad[8] = record.content_type;
    aad[9..11].copy_from_slice(&DTLS12_VERSION.to_be_bytes());
    aad[11..13].copy_from_slice(&payload_length.to_be_bytes());
    Ok(aad)
}

fn record_number(record: &Dtls12Record) -> [u8; 8] {
    let mut number = [0_u8; 8];
    number[..2].copy_from_slice(&record.epoch.to_be_bytes());
    write_u48(&mut number[2..], record.sequence);
    number
}

fn chacha_nonce(
    fixed_iv: &[u8],
    record: &Dtls12Record,
) -> Result<[u8; 12], Dtls12Error> {
    if fixed_iv.len() != 12 {
        return Err(Dtls12Error::InvalidIvLength {
            expected: 12,
            actual: fixed_iv.len(),
        });
    }
    let mut nonce: [u8; 12] = fixed_iv.try_into().expect("validated length");
    for (output, input) in nonce[4..].iter_mut().zip(record_number(record)) {
        *output ^= input;
    }
    Ok(nonce)
}

fn crypt_cbc(
    decrypt: bool,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, Dtls12Error> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_cbc(),
        32 => Cipher::aes_256_cbc(),
        actual => {
            return Err(Dtls12Error::InvalidKeyLength {
                expected: 16,
                actual,
            });
        }
    };
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

    fn record() -> Dtls12Record {
        Dtls12Record {
            content_type: 23,
            epoch: 1,
            sequence: 0x0102_0304_0506,
            payload: b"an IP packet".to_vec(),
        }
    }

    #[test]
    fn tls12_prfs_match_pinned_go_vectors() {
        assert_eq!(
            hex::encode(tls12_prf(
                Dtls12PrfHash::Sha256,
                b"secret",
                "test label",
                b"seed",
                48,
            )),
            "bfc72aea54e12f176b7549dc7d0082fecd2be093284636015f9149017f433669e453c27d2993bfb7cd5abd8c655edc7a"
        );
        assert_eq!(
            hex::encode(tls12_prf(
                Dtls12PrfHash::Sha384,
                b"secret",
                "test label",
                b"seed",
                64,
            )),
            "cdd47dc0124953e293a71e0f3fcc02ab44f08334cb2ca2136fafc00d82a403080ec07bb017728d8d7e2ad075878bed7a570ac06c916c38dd683e4a4e7b66d85d"
        );
    }

    #[test]
    fn suite_mapping_matches_pinned_go_and_pion() {
        let cases = [
            ("DHE-RSA-AES128-SHA", 0x0033, false),
            ("DHE-RSA-AES256-SHA", 0x0039, false),
            ("AES128-SHA", 0x002f, false),
            ("AES256-SHA", 0x0035, false),
            ("ECDHE-RSA-AES128-GCM-SHA256", 0xc02f, false),
            ("ECDHE-RSA-AES256-GCM-SHA384", 0xc030, false),
            ("AES128-GCM-SHA256", 0x009c, false),
            ("OC-DTLS1_2-AES128-GCM", 0x009c, false),
            ("AES256-GCM-SHA384", 0x009d, false),
            ("OC-DTLS1_2-AES256-GCM", 0x009d, false),
            ("OC2-DTLS1_2-CHACHA20-POLY1305", 0xccab, true),
            ("TLS_PSK_WITH_AES_128_GCM_SHA256", 0x00a8, true),
            ("TLS_PSK_WITH_AES_128_CCM", 0xc0a4, true),
            ("TLS_PSK_WITH_AES_128_CCM_8", 0xc0a8, true),
            ("TLS_PSK_WITH_AES_256_CCM_8", 0xc0a9, true),
            ("TLS_PSK_WITH_AES_128_CBC_SHA256", 0x00ae, true),
        ];
        for (name, expected_id, expected_psk) in cases {
            let suite = Dtls12Suite::from_name(name, true).unwrap();
            assert_eq!(suite.cipher_suite_id, expected_id, "{name}");
            assert_eq!(suite.psk_cipher, expected_psk, "{name}");
        }
        assert!(matches!(
            Dtls12Suite::from_name("AES128-SHA", false),
            Err(Dtls12Error::RequiresDtls12(_))
        ));
        assert!(matches!(
            Dtls12Suite::from_name("made-up", true),
            Err(Dtls12Error::UnsupportedCipher(_))
        ));
    }

    #[test]
    fn directional_key_schedule_uses_suite_sizes() {
        for name in [
            "AES128-SHA",
            "OC-DTLS1_2-AES256-GCM",
            "OC2-DTLS1_2-CHACHA20-POLY1305",
            "TLS_PSK_WITH_AES_128_CCM",
            "TLS_PSK_WITH_AES_256_CCM_8",
            "TLS_PSK_WITH_AES_128_CBC_SHA256",
        ] {
            let suite = Dtls12Suite::from_name(name, true).unwrap();
            let keys = derive_dtls12_keys(
                &suite,
                &[0x11; 48],
                &[0x22; 32],
                &[0x33; 32],
            );
            assert_eq!(
                keys.client_mac_key.len(),
                suite.cipher.mac_key_length()
            );
            assert_eq!(keys.client_write_key.len(), suite.cipher.key_length());
            assert_eq!(
                keys.client_write_iv.len(),
                suite.cipher.fixed_iv_length()
            );
            assert_ne!(keys.client_write_key, keys.server_write_key);
            assert_ne!(keys.client_write_iv, keys.server_write_iv);
        }
    }

    #[test]
    fn record_header_round_trips_multiple_records() {
        let first = record();
        let second = Dtls12Record {
            content_type: 21,
            epoch: 0,
            sequence: 9,
            payload: b"alert".to_vec(),
        };
        let mut datagram = marshal_dtls12_record(&first).unwrap();
        datagram.extend(marshal_dtls12_record(&second).unwrap());
        assert_eq!(parse_dtls12_records(&datagram).unwrap(), [first, second]);
    }

    #[test]
    fn deterministic_aes128_gcm_record_matches_pinned_go() {
        let suite =
            Dtls12Suite::from_name("OC-DTLS1_2-AES128-GCM", true).unwrap();
        let encoded = encrypt_dtls12_record(
            &record(),
            &[0x11; 16],
            &[],
            &[0x22; 4],
            &suite,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "17fefd0001010203040506002400010102030405068f8061bfb5816b6ecc5f407481bb4bd1ce5f612d5e849ceadd89f5f2"
        );
        let protected = parse_dtls12_records(&encoded).unwrap().remove(0);
        assert_eq!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 16],
                &[],
                &[0x22; 4],
                &suite,
            )
            .unwrap(),
            b"an IP packet"
        );
    }

    #[test]
    fn aes256_gcm_round_trip_rejects_header_tampering() {
        let suite =
            Dtls12Suite::from_name("OC-DTLS1_2-AES256-GCM", true).unwrap();
        let encoded = encrypt_dtls12_record(
            &record(),
            &[0x11; 32],
            &[],
            &[0x22; 4],
            &suite,
        )
        .unwrap();
        let mut protected = parse_dtls12_records(&encoded).unwrap().remove(0);
        assert_eq!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 32],
                &[],
                &[0x22; 4],
                &suite,
            )
            .unwrap(),
            b"an IP packet"
        );
        protected.sequence += 1;
        assert!(matches!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 32],
                &[],
                &[0x22; 4],
                &suite,
            ),
            Err(Dtls12Error::InvalidAuthentication)
        ));
    }

    #[test]
    fn chacha20_poly1305_has_no_explicit_nonce_and_authenticates() {
        let suite =
            Dtls12Suite::from_name("OC2-DTLS1_2-CHACHA20-POLY1305", true)
                .unwrap();
        let encoded = encrypt_dtls12_record(
            &record(),
            &[0x11; 32],
            &[],
            &[0x22; 12],
            &suite,
        )
        .unwrap();
        let mut protected = parse_dtls12_records(&encoded).unwrap().remove(0);
        assert_eq!(
            protected.payload.len(),
            b"an IP packet".len() + DTLS12_AEAD_TAG_LENGTH
        );
        assert_eq!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 32],
                &[],
                &[0x22; 12],
                &suite,
            )
            .unwrap(),
            b"an IP packet"
        );
        protected.payload[0] ^= 1;
        assert!(matches!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 32],
                &[],
                &[0x22; 12],
                &suite,
            ),
            Err(Dtls12Error::InvalidAuthentication)
        ));
    }

    #[test]
    fn psk_ccm_variants_round_trip_and_authenticate() {
        for (name, key_length, tag_length) in [
            ("TLS_PSK_WITH_AES_128_CCM", 16, 16),
            ("TLS_PSK_WITH_AES_128_CCM_8", 16, 8),
            ("TLS_PSK_WITH_AES_256_CCM_8", 32, 8),
        ] {
            let suite = Dtls12Suite::from_name(name, true).unwrap();
            let key = vec![0x11; key_length];
            let encoded =
                encrypt_dtls12_record(&record(), &key, &[], &[0x22; 4], &suite)
                    .unwrap();
            let mut protected =
                parse_dtls12_records(&encoded).unwrap().remove(0);
            assert_eq!(
                protected.payload.len(),
                8 + b"an IP packet".len() + tag_length,
                "{name}"
            );
            assert_eq!(
                decrypt_dtls12_record(
                    &protected,
                    &key,
                    &[],
                    &[0x22; 4],
                    &suite,
                )
                .unwrap(),
                b"an IP packet",
                "{name}"
            );
            protected.payload[8] ^= 1;
            assert!(matches!(
                decrypt_dtls12_record(
                    &protected,
                    &key,
                    &[],
                    &[0x22; 4],
                    &suite,
                ),
                Err(Dtls12Error::InvalidAuthentication)
            ));
        }
    }

    #[test]
    fn psk_aes128_cbc_sha256_round_trips_and_authenticates() {
        let suite =
            Dtls12Suite::from_name("TLS_PSK_WITH_AES_128_CBC_SHA256", true)
                .unwrap();
        let encoded = encrypt_dtls12_cbc_record_with_iv(
            &record(),
            &[0x11; 16],
            &[0x22; 32],
            &[0x44; 16],
            &suite,
            &[0x33; 16],
        )
        .unwrap();
        let mut protected = parse_dtls12_records(&encoded).unwrap().remove(0);
        assert_eq!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 16],
                &[0x22; 32],
                &[0x44; 16],
                &suite,
            )
            .unwrap(),
            b"an IP packet"
        );
        protected.sequence += 1;
        assert!(matches!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 16],
                &[0x22; 32],
                &[0x44; 16],
                &suite,
            ),
            Err(Dtls12Error::InvalidAuthentication)
        ));
    }

    #[test]
    fn deterministic_cbc_record_round_trips_and_authenticates() {
        let suite = Dtls12Suite::from_name("AES128-SHA", true).unwrap();
        let encoded = encrypt_dtls12_cbc_record_with_iv(
            &record(),
            &[0x11; 16],
            &[0x22; 20],
            &[0x44; 16],
            &suite,
            &[0x33; 16],
        )
        .unwrap();
        let mut protected = parse_dtls12_records(&encoded).unwrap().remove(0);
        assert_eq!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 16],
                &[0x22; 20],
                &[0x44; 16],
                &suite,
            )
            .unwrap(),
            b"an IP packet"
        );
        protected.content_type = 22;
        assert!(matches!(
            decrypt_dtls12_record(
                &protected,
                &[0x11; 16],
                &[0x22; 20],
                &[0x44; 16],
                &suite,
            ),
            Err(Dtls12Error::InvalidAuthentication)
        ));
    }

    #[test]
    fn finished_uses_direction_and_suite_hash() {
        let sha256 = Dtls12Suite::from_name("AES128-SHA", true).unwrap();
        let sha384 =
            Dtls12Suite::from_name("OC-DTLS1_2-AES256-GCM", true).unwrap();
        let client = dtls12_finished(&sha256, &[7; 48], b"transcript", true);
        let server = dtls12_finished(&sha256, &[7; 48], b"transcript", false);
        let stronger = dtls12_finished(&sha384, &[7; 48], b"transcript", true);
        assert_eq!(client.len(), 12);
        assert_ne!(client, server);
        assert_ne!(client, stronger);
    }
}
