//! Shared OpenConnect ESP packet protection.
//!
//! This implements the legacy OpenConnect AES-CBC plus truncated-HMAC wire
//! format used by GlobalProtect, Pulse and Network Connect. Socket lifecycle
//! and transport probing live in the endpoint layer.

use std::sync::Mutex;

use aes::{
    Aes128, Aes256,
    cipher::{Block, BlockCipherEncrypt, KeyInit as _},
};
use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit as _,
    block_padding::NoPadding,
};
use hmac13::{Hmac, Mac as _};
use md5::Md5;
use sha1_11::Sha1;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

use super::{
    GlobalProtectEspAuthentication, GlobalProtectEspConfiguration,
    GlobalProtectEspEncryption, GlobalProtectEspKeyMaterial,
};

pub const OPENCONNECT_ESP_FIXED_HEADER_SIZE: usize = 24;
pub const OPENCONNECT_ESP_IPV4_NEXT_HEADER: u8 = 4;
pub const OPENCONNECT_ESP_LZO_NEXT_HEADER: u8 = 5;
pub const OPENCONNECT_ESP_IPV6_NEXT_HEADER: u8 = 41;
const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenConnectEspEncryption {
    Aes128Cbc,
    Aes256Cbc,
}

impl OpenConnectEspEncryption {
    pub const fn key_length(self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenConnectEspAuthentication {
    HmacMd5_96,
    HmacSha1_96,
    HmacSha256_128,
}

impl OpenConnectEspAuthentication {
    pub const fn key_length(self) -> usize {
        match self {
            Self::HmacMd5_96 => 16,
            Self::HmacSha1_96 => 20,
            Self::HmacSha256_128 => 32,
        }
    }

    pub const fn icv_length(self) -> usize {
        match self {
            Self::HmacMd5_96 | Self::HmacSha1_96 => 12,
            Self::HmacSha256_128 => 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct OpenConnectEspKeyMaterial {
    #[zeroize(skip)]
    pub spi: u32,
    pub encryption_key: Vec<u8>,
    pub authentication_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct OpenConnectEspKeySetConfig {
    #[zeroize(skip)]
    pub encryption: OpenConnectEspEncryption,
    #[zeroize(skip)]
    pub authentication: OpenConnectEspAuthentication,
    pub outbound: OpenConnectEspKeyMaterial,
    pub inbound: OpenConnectEspKeyMaterial,
    #[zeroize(skip)]
    pub disable_replay_protection: bool,
}

impl From<&GlobalProtectEspConfiguration> for OpenConnectEspKeySetConfig {
    fn from(configuration: &GlobalProtectEspConfiguration) -> Self {
        Self {
            encryption: match configuration.encryption {
                GlobalProtectEspEncryption::Aes128Cbc => {
                    OpenConnectEspEncryption::Aes128Cbc
                }
                GlobalProtectEspEncryption::Aes256Cbc => {
                    OpenConnectEspEncryption::Aes256Cbc
                }
            },
            authentication: match configuration.authentication {
                GlobalProtectEspAuthentication::HmacMd5_96 => {
                    OpenConnectEspAuthentication::HmacMd5_96
                }
                GlobalProtectEspAuthentication::HmacSha1_96 => {
                    OpenConnectEspAuthentication::HmacSha1_96
                }
                GlobalProtectEspAuthentication::HmacSha256_128 => {
                    OpenConnectEspAuthentication::HmacSha256_128
                }
            },
            outbound: convert_material(&configuration.outbound),
            inbound: convert_material(&configuration.inbound),
            disable_replay_protection: false,
        }
    }
}

fn convert_material(
    material: &GlobalProtectEspKeyMaterial,
) -> OpenConnectEspKeyMaterial {
    OpenConnectEspKeyMaterial {
        spi: material.spi,
        encryption_key: material.encryption_key.clone(),
        authentication_key: material.authentication_key.clone(),
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpenConnectEspError {
    #[error("invalid ESP configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid ESP datagram: {0}")]
    InvalidDatagram(String),
    #[error("ESP authentication failed")]
    AuthenticationFailed,
    #[error("ESP replay rejected")]
    Replay,
    #[error("ESP sequence exhausted")]
    SequenceExhausted,
    #[error("ESP keys are destroyed")]
    KeysDestroyed,
    #[error("generate initial ESP IV: {0}")]
    Random(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenConnectEspReplayWindow {
    missing: u64,
    next_sequence: u64,
}

impl OpenConnectEspReplayWindow {
    pub fn accept(&mut self, sequence: u32) -> bool {
        let sequence = u64::from(sequence);
        if sequence == self.next_sequence {
            self.missing <<= 1;
            self.next_sequence += 1;
            return true;
        }
        if sequence > self.next_sequence {
            let delta = sequence - self.next_sequence;
            match delta {
                64.. => self.missing = u64::MAX,
                63 => self.missing = u64::MAX >> 1,
                _ => {
                    self.missing <<= delta + 1;
                    self.missing |= (1_u64 << delta) - 1;
                }
            }
            self.next_sequence = sequence + 1;
            return true;
        }
        let delta = self.next_sequence - sequence;
        if delta == 1 || delta > 65 {
            return false;
        }
        let mask = 1_u64 << (delta - 2);
        if self.missing & mask == 0 {
            return false;
        }
        self.missing &= !mask;
        true
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

struct SecurityAssociation {
    encryption: OpenConnectEspEncryption,
    authentication: OpenConnectEspAuthentication,
    spi: u32,
    encryption_key: Vec<u8>,
    authentication_key: Vec<u8>,
    sequence: u64,
    replay: OpenConnectEspReplayWindow,
    iv: [u8; AES_BLOCK_SIZE],
    valid: bool,
}

impl SecurityAssociation {
    fn new(
        encryption: OpenConnectEspEncryption,
        authentication: OpenConnectEspAuthentication,
        material: &OpenConnectEspKeyMaterial,
        outbound: bool,
    ) -> Result<Self, OpenConnectEspError> {
        if material.spi == 0 {
            return Err(OpenConnectEspError::InvalidConfiguration(
                "SPI is zero".into(),
            ));
        }
        if material.encryption_key.len() != encryption.key_length() {
            return Err(OpenConnectEspError::InvalidConfiguration(format!(
                "encryption key length is {}, expected {}",
                material.encryption_key.len(),
                encryption.key_length()
            )));
        }
        if material.authentication_key.len() != authentication.key_length() {
            return Err(OpenConnectEspError::InvalidConfiguration(format!(
                "authentication key length is {}, expected {}",
                material.authentication_key.len(),
                authentication.key_length()
            )));
        }
        let mut iv = [0_u8; AES_BLOCK_SIZE];
        if outbound {
            getrandom::fill(&mut iv).map_err(|error| {
                OpenConnectEspError::Random(error.to_string())
            })?;
        }
        Ok(Self {
            encryption,
            authentication,
            spi: material.spi,
            encryption_key: material.encryption_key.clone(),
            authentication_key: material.authentication_key.clone(),
            sequence: 0,
            replay: OpenConnectEspReplayWindow::default(),
            iv,
            valid: true,
        })
    }

    fn destroy(&mut self) {
        self.encryption_key.zeroize();
        self.authentication_key.zeroize();
        self.iv.zeroize();
        self.sequence = 0;
        self.replay = OpenConnectEspReplayWindow::default();
        self.spi = 0;
        self.valid = false;
    }
}

impl Drop for SecurityAssociation {
    fn drop(&mut self) {
        self.destroy();
    }
}

struct InboundAssociations {
    current: SecurityAssociation,
    previous: Option<SecurityAssociation>,
    previous_limit: u64,
    disable_replay_protection: bool,
    destroyed: bool,
}

pub struct OpenConnectEspKeySet {
    outbound: Mutex<SecurityAssociation>,
    inbound: Mutex<InboundAssociations>,
}

impl OpenConnectEspKeySet {
    pub fn new(
        configuration: &OpenConnectEspKeySetConfig,
    ) -> Result<Self, OpenConnectEspError> {
        let outbound = SecurityAssociation::new(
            configuration.encryption,
            configuration.authentication,
            &configuration.outbound,
            true,
        )?;
        let inbound = SecurityAssociation::new(
            configuration.encryption,
            configuration.authentication,
            &configuration.inbound,
            false,
        )?;
        Ok(Self {
            outbound: Mutex::new(outbound),
            inbound: Mutex::new(InboundAssociations {
                current: inbound,
                previous: None,
                previous_limit: 0,
                disable_replay_protection: configuration
                    .disable_replay_protection,
                destroyed: false,
            }),
        })
    }

    pub fn install(
        &self,
        configuration: &OpenConnectEspKeySetConfig,
    ) -> Result<(), OpenConnectEspError> {
        let replacement_outbound = SecurityAssociation::new(
            configuration.encryption,
            configuration.authentication,
            &configuration.outbound,
            true,
        )?;
        let replacement_inbound = SecurityAssociation::new(
            configuration.encryption,
            configuration.authentication,
            &configuration.inbound,
            false,
        )?;
        let mut outbound = self.outbound.lock().map_err(|_| {
            OpenConnectEspError::InvalidConfiguration(
                "outbound key lock poisoned".into(),
            )
        })?;
        let mut inbound = self.inbound.lock().map_err(|_| {
            OpenConnectEspError::InvalidConfiguration(
                "inbound key lock poisoned".into(),
            )
        })?;
        if inbound.destroyed || !outbound.valid {
            return Err(OpenConnectEspError::KeysDestroyed);
        }
        outbound.destroy();
        *outbound = replacement_outbound;
        if let Some(mut previous) = inbound.previous.take() {
            previous.destroy();
        }
        let previous_limit = inbound.current.replay.next_sequence() + 32;
        let previous =
            std::mem::replace(&mut inbound.current, replacement_inbound);
        inbound.previous = Some(previous);
        inbound.previous_limit = previous_limit;
        inbound.disable_replay_protection =
            configuration.disable_replay_protection;
        Ok(())
    }

    pub fn seal(
        &self,
        payload: &[u8],
        next_header: Option<u8>,
    ) -> Result<Vec<u8>, OpenConnectEspError> {
        let mut association = self.outbound.lock().map_err(|_| {
            OpenConnectEspError::InvalidConfiguration(
                "outbound key lock poisoned".into(),
            )
        })?;
        if !association.valid {
            return Err(OpenConnectEspError::KeysDestroyed);
        }
        let next_header = select_next_header(payload, next_header)?;
        if association.sequence > u64::from(u32::MAX) {
            return Err(OpenConnectEspError::SequenceExhausted);
        }
        let padding_length =
            AES_BLOCK_SIZE - 1 - (payload.len() + 1) % AES_BLOCK_SIZE;
        let plaintext_length = payload.len() + padding_length + 2;
        let icv_length = association.authentication.icv_length();
        let mut datagram = Vec::with_capacity(
            OPENCONNECT_ESP_FIXED_HEADER_SIZE + plaintext_length + icv_length,
        );
        datagram.extend_from_slice(&association.spi.to_be_bytes());
        datagram
            .extend_from_slice(&(association.sequence as u32).to_be_bytes());
        association.sequence += 1;
        datagram.extend_from_slice(&association.iv);
        let plaintext_start = datagram.len();
        datagram.extend_from_slice(payload);
        for value in 1..=padding_length {
            datagram.push(value as u8);
        }
        datagram.push(padding_length as u8);
        datagram.push(next_header);
        let ciphertext = encrypt_cbc(
            association.encryption,
            &association.encryption_key,
            &association.iv,
            &datagram[plaintext_start..],
        )?;
        datagram.truncate(plaintext_start);
        datagram.extend_from_slice(&ciphertext);
        let full_icv = calculate_icv(
            association.authentication,
            &association.authentication_key,
            &datagram,
        );
        datagram.extend_from_slice(&full_icv[..icv_length]);
        let mut next_iv_input = [0_u8; AES_BLOCK_SIZE];
        let hmac_tail = &full_icv[full_icv.len() - AES_BLOCK_SIZE..];
        let ciphertext_tail = &ciphertext[ciphertext.len() - AES_BLOCK_SIZE..];
        for index in 0..AES_BLOCK_SIZE {
            next_iv_input[index] = hmac_tail[index] ^ ciphertext_tail[index];
        }
        association.iv = encrypt_aes_block(
            association.encryption,
            &association.encryption_key,
            next_iv_input,
        )?;
        next_iv_input.zeroize();
        Ok(datagram)
    }

    pub fn open(
        &self,
        datagram: &[u8],
    ) -> Result<(Vec<u8>, u8), OpenConnectEspError> {
        if datagram.len() < 8 {
            return Err(invalid_datagram("header is truncated"));
        }
        let spi = u32::from_be_bytes(datagram[..4].try_into().unwrap());
        let sequence = u32::from_be_bytes(datagram[4..8].try_into().unwrap());
        let mut inbound = self.inbound.lock().map_err(|_| {
            OpenConnectEspError::InvalidConfiguration(
                "inbound key lock poisoned".into(),
            )
        })?;
        if inbound.destroyed || !inbound.current.valid {
            return Err(OpenConnectEspError::KeysDestroyed);
        }
        let current_next = inbound.current.replay.next_sequence();
        let previous_limit = inbound.previous_limit;
        let disable_replay_protection = inbound.disable_replay_protection;
        let association = if spi == inbound.current.spi {
            &mut inbound.current
        } else if inbound.previous.as_ref().is_some_and(|previous| {
            previous.valid
                && previous.spi == spi
                && u64::from(sequence) + current_next < previous_limit
        }) {
            inbound.previous.as_mut().expect("checked above")
        } else {
            return Err(invalid_datagram("SPI is unknown or expired"));
        };
        let icv_length = association.authentication.icv_length();
        if datagram.len()
            < OPENCONNECT_ESP_FIXED_HEADER_SIZE + AES_BLOCK_SIZE + icv_length
        {
            return Err(invalid_datagram("ciphertext is truncated"));
        }
        let authenticated_length = datagram.len() - icv_length;
        let ciphertext_length =
            authenticated_length - OPENCONNECT_ESP_FIXED_HEADER_SIZE;
        if !ciphertext_length.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(invalid_datagram("ciphertext is not block aligned"));
        }
        let expected = calculate_icv(
            association.authentication,
            &association.authentication_key,
            &datagram[..authenticated_length],
        );
        if !constant_time_equal(
            &expected[..icv_length],
            &datagram[authenticated_length..],
        ) {
            return Err(OpenConnectEspError::AuthenticationFailed);
        }
        let replay_accepted = association.replay.accept(sequence);
        if !replay_accepted && !disable_replay_protection {
            return Err(OpenConnectEspError::Replay);
        }
        let mut plaintext = decrypt_cbc(
            association.encryption,
            &association.encryption_key,
            &datagram[8..OPENCONNECT_ESP_FIXED_HEADER_SIZE],
            &datagram[OPENCONNECT_ESP_FIXED_HEADER_SIZE..authenticated_length],
        )?;
        if plaintext.len() < 2 {
            plaintext.zeroize();
            return Err(invalid_datagram("plaintext trailer is truncated"));
        }
        let padding_length = usize::from(plaintext[plaintext.len() - 2]);
        if plaintext.len() <= padding_length + 2 {
            plaintext.zeroize();
            return Err(invalid_datagram("padding consumes payload"));
        }
        let payload_length = plaintext.len() - padding_length - 2;
        if plaintext[payload_length..payload_length + padding_length]
            .iter()
            .enumerate()
            .any(|(index, value)| *value != (index + 1) as u8)
        {
            plaintext.zeroize();
            return Err(invalid_datagram("padding is invalid"));
        }
        let next_header = plaintext[plaintext.len() - 1];
        validate_next_header(next_header)?;
        plaintext.truncate(payload_length);
        Ok((plaintext, next_header))
    }

    pub fn destroy(&self) {
        if let Ok(mut outbound) = self.outbound.lock() {
            outbound.destroy();
        }
        if let Ok(mut inbound) = self.inbound.lock() {
            if inbound.destroyed {
                return;
            }
            inbound.destroyed = true;
            inbound.current.destroy();
            if let Some(mut previous) = inbound.previous.take() {
                previous.destroy();
            }
            inbound.previous_limit = 0;
        }
    }
}

impl Drop for OpenConnectEspKeySet {
    fn drop(&mut self) {
        self.destroy();
    }
}

fn select_next_header(
    payload: &[u8],
    requested: Option<u8>,
) -> Result<u8, OpenConnectEspError> {
    let next_header = match requested {
        Some(value) => value,
        None => match payload.first().map(|byte| byte >> 4) {
            Some(4) => OPENCONNECT_ESP_IPV4_NEXT_HEADER,
            Some(6) => OPENCONNECT_ESP_IPV6_NEXT_HEADER,
            Some(_) => {
                return Err(invalid_datagram("unknown inner IP version"));
            }
            None => return Err(invalid_datagram("payload is empty")),
        },
    };
    validate_next_header(next_header)?;
    Ok(next_header)
}

fn validate_next_header(next_header: u8) -> Result<(), OpenConnectEspError> {
    if matches!(
        next_header,
        OPENCONNECT_ESP_IPV4_NEXT_HEADER
            | OPENCONNECT_ESP_IPV6_NEXT_HEADER
            | OPENCONNECT_ESP_LZO_NEXT_HEADER
    ) {
        Ok(())
    } else {
        Err(invalid_datagram("next header is unknown"))
    }
}

fn encrypt_cbc(
    encryption: OpenConnectEspEncryption,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OpenConnectEspError> {
    let ciphertext = match encryption {
        OpenConnectEspEncryption::Aes128Cbc => {
            cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|_| invalid_configuration("invalid AES-128 key/IV"))?
                .encrypt_padded_vec::<NoPadding>(plaintext)
        }
        OpenConnectEspEncryption::Aes256Cbc => {
            cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| invalid_configuration("invalid AES-256 key/IV"))?
                .encrypt_padded_vec::<NoPadding>(plaintext)
        }
    };
    Ok(ciphertext)
}

fn decrypt_cbc(
    encryption: OpenConnectEspEncryption,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, OpenConnectEspError> {
    match encryption {
        OpenConnectEspEncryption::Aes128Cbc => {
            cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|_| invalid_configuration("invalid AES-128 key/IV"))?
                .decrypt_padded_vec::<NoPadding>(ciphertext)
                .map_err(|_| invalid_datagram("AES-128 ciphertext is invalid"))
        }
        OpenConnectEspEncryption::Aes256Cbc => {
            cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| invalid_configuration("invalid AES-256 key/IV"))?
                .decrypt_padded_vec::<NoPadding>(ciphertext)
                .map_err(|_| invalid_datagram("AES-256 ciphertext is invalid"))
        }
    }
}

fn calculate_icv(
    authentication: OpenConnectEspAuthentication,
    key: &[u8],
    datagram: &[u8],
) -> Vec<u8> {
    macro_rules! hmac {
        ($digest:ty) => {{
            let mut mac =
                <Hmac<$digest> as hmac13::KeyInit>::new_from_slice(key)
                    .expect("HMAC accepts arbitrary key lengths");
            mac.update(datagram);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match authentication {
        OpenConnectEspAuthentication::HmacMd5_96 => hmac!(Md5),
        OpenConnectEspAuthentication::HmacSha1_96 => hmac!(Sha1),
        OpenConnectEspAuthentication::HmacSha256_128 => hmac!(Sha256),
    }
}

fn encrypt_aes_block(
    encryption: OpenConnectEspEncryption,
    key: &[u8],
    input: [u8; AES_BLOCK_SIZE],
) -> Result<[u8; AES_BLOCK_SIZE], OpenConnectEspError> {
    let mut block = Block::<Aes128>::from(input);
    match encryption {
        OpenConnectEspEncryption::Aes128Cbc => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| invalid_configuration("invalid AES-128 key"))?;
            cipher.encrypt_block(&mut block);
        }
        OpenConnectEspEncryption::Aes256Cbc => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| invalid_configuration("invalid AES-256 key"))?;
            cipher.encrypt_block(&mut block);
        }
    }
    Ok(block.into())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn invalid_configuration(message: &str) -> OpenConnectEspError {
    OpenConnectEspError::InvalidConfiguration(message.into())
}

fn invalid_datagram(message: &str) -> OpenConnectEspError {
    OpenConnectEspError::InvalidDatagram(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration(
        encryption: OpenConnectEspEncryption,
        authentication: OpenConnectEspAuthentication,
    ) -> (OpenConnectEspKeySetConfig, OpenConnectEspKeySetConfig) {
        let encryption_length = encryption.key_length();
        let authentication_length = authentication.key_length();
        let client_outbound = OpenConnectEspKeyMaterial {
            spi: 0x1122_3344,
            encryption_key: vec![0x11; encryption_length],
            authentication_key: vec![0x22; authentication_length],
        };
        let server_outbound = OpenConnectEspKeyMaterial {
            spi: 0x5566_7788,
            encryption_key: vec![0x33; encryption_length],
            authentication_key: vec![0x44; authentication_length],
        };
        (
            OpenConnectEspKeySetConfig {
                encryption,
                authentication,
                outbound: client_outbound.clone(),
                inbound: server_outbound.clone(),
                disable_replay_protection: false,
            },
            OpenConnectEspKeySetConfig {
                encryption,
                authentication,
                outbound: server_outbound,
                inbound: client_outbound,
                disable_replay_protection: false,
            },
        )
    }

    #[test]
    fn replay_window_matches_openconnect_edges() {
        let mut window = OpenConnectEspReplayWindow::default();
        assert!(window.accept(0));
        assert!(window.accept(2));
        assert!(window.accept(1));
        assert!(!window.accept(1));
        assert!(!window.accept(2));
        assert!(window.accept(100));
        assert!(!window.accept(0));
        assert!(window.accept(99));
        assert!(!window.accept(99));
    }

    #[test]
    fn all_algorithm_pairs_round_trip_and_reject_replay() {
        for encryption in [
            OpenConnectEspEncryption::Aes128Cbc,
            OpenConnectEspEncryption::Aes256Cbc,
        ] {
            for authentication in [
                OpenConnectEspAuthentication::HmacMd5_96,
                OpenConnectEspAuthentication::HmacSha1_96,
                OpenConnectEspAuthentication::HmacSha256_128,
            ] {
                let (client, server) =
                    configuration(encryption, authentication);
                let client = OpenConnectEspKeySet::new(&client).unwrap();
                let server = OpenConnectEspKeySet::new(&server).unwrap();
                let payload = [0x45, 0, 0, 20, 1, 2, 3, 4];
                let datagram = client.seal(&payload, None).unwrap();
                assert_eq!(
                    datagram.len() % AES_BLOCK_SIZE,
                    (OPENCONNECT_ESP_FIXED_HEADER_SIZE
                        + authentication.icv_length())
                        % AES_BLOCK_SIZE
                );
                assert_eq!(
                    server.open(&datagram).unwrap(),
                    (payload.to_vec(), 4)
                );
                assert_eq!(
                    server.open(&datagram).unwrap_err(),
                    OpenConnectEspError::Replay
                );
            }
        }
    }

    #[test]
    fn authentication_precedes_decryption_and_replay_update() {
        let (client_config, server_config) = configuration(
            OpenConnectEspEncryption::Aes128Cbc,
            OpenConnectEspAuthentication::HmacSha256_128,
        );
        let client = OpenConnectEspKeySet::new(&client_config).unwrap();
        let server = OpenConnectEspKeySet::new(&server_config).unwrap();
        let payload = [0x60, 0, 0, 0, 1];
        let datagram = client.seal(&payload, None).unwrap();
        let mut tampered = datagram.clone();
        tampered[OPENCONNECT_ESP_FIXED_HEADER_SIZE] ^= 1;
        assert_eq!(
            server.open(&tampered).unwrap_err(),
            OpenConnectEspError::AuthenticationFailed
        );
        assert_eq!(
            server.open(&datagram).unwrap(),
            (payload.to_vec(), OPENCONNECT_ESP_IPV6_NEXT_HEADER)
        );
    }

    #[test]
    fn rollover_accepts_bounded_previous_spi_then_expires_it() {
        let (first_client, first_server) = configuration(
            OpenConnectEspEncryption::Aes128Cbc,
            OpenConnectEspAuthentication::HmacSha1_96,
        );
        let first_client = OpenConnectEspKeySet::new(&first_client).unwrap();
        let server = OpenConnectEspKeySet::new(&first_server).unwrap();
        let old = first_client.seal(&[0x45, 1], None).unwrap();
        let (mut second_client, mut second_server) = configuration(
            OpenConnectEspEncryption::Aes256Cbc,
            OpenConnectEspAuthentication::HmacSha256_128,
        );
        second_client.outbound.spi = 0x99aa_bbcc;
        second_server.inbound.spi = 0x99aa_bbcc;
        server.install(&second_server).unwrap();
        assert_eq!(server.open(&old).unwrap().0, vec![0x45, 1]);
        let second_client = OpenConnectEspKeySet::new(&second_client).unwrap();
        for _ in 0..33 {
            let packet = second_client.seal(&[0x45, 2], None).unwrap();
            server.open(&packet).unwrap();
        }
        let later_old = first_client.seal(&[0x45, 3], None).unwrap();
        assert!(matches!(
            server.open(&later_old),
            Err(OpenConnectEspError::InvalidDatagram(_))
        ));
    }

    #[test]
    fn destroy_is_idempotent_and_blocks_future_crypto() {
        let (client, _) = configuration(
            OpenConnectEspEncryption::Aes128Cbc,
            OpenConnectEspAuthentication::HmacMd5_96,
        );
        let keys = OpenConnectEspKeySet::new(&client).unwrap();
        keys.destroy();
        keys.destroy();
        assert_eq!(
            keys.seal(&[0x45, 0], None).unwrap_err(),
            OpenConnectEspError::KeysDestroyed
        );
    }
}
