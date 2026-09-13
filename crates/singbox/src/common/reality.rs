//! Protocol primitives shared by the REALITY client and server transports.
//!
//! REALITY authenticates an otherwise ordinary TLS 1.3 ClientHello by placing
//! an AES-GCM sealed metadata block in its 32-byte legacy session ID. The key
//! comes from the ClientHello's X25519 key share and the configured REALITY
//! public key. These helpers deliberately operate on a fully assembled
//! ClientHello so the eventual uTLS shaper and the server listener use the
//! exact bytes covered by the Go implementation's associated data.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use hmac13::{Hmac, Mac as _};
use sha2::{Sha256, Sha512};
use x509_parser::{
    oid_registry::OID_SIG_ED25519,
    prelude::{FromDer, X509Certificate},
};
use x25519_dalek::x25519;
use zeroize::{Zeroize, Zeroizing};

pub const REALITY_PROTOCOL_VERSION: [u8; 3] = [1, 8, 1];
pub const REALITY_SESSION_ID_LEN: usize = 32;
pub const REALITY_SHORT_ID_LEN: usize = 8;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const TLS_EXTENSION_SERVER_NAME: u16 = 0x0000;
const TLS_EXTENSION_KEY_SHARE: u16 = 0x0033;
const TLS_GROUP_X25519: u16 = 0x001d;
const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const TLS_GROUP_X25519_MLKEM768_KEY_EXCHANGE_LEN: usize = 1216;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RealityError {
    #[error("decode {field}: {message}")]
    Decode {
        field: &'static str,
        message: String,
    },
    #[error("invalid {field}: expected {expected} bytes, got {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("short_id must contain at most 8 bytes")]
    ShortIdTooLong,
    #[error("ClientHello session ID range {offset}..{end} exceeds {len} bytes")]
    InvalidSessionIdRange {
        offset: usize,
        end: usize,
        len: usize,
    },
    #[error("REALITY X25519 shared secret is all zero")]
    AllZeroSharedSecret,
    #[error("REALITY key derivation failed")]
    KeyDerivation,
    #[error("REALITY session ID authentication failed")]
    Authentication,
    #[error("invalid REALITY certificate DER")]
    InvalidCertificateDer,
    #[error("invalid REALITY certificate bit string")]
    InvalidCertificateBitString,
    #[error("invalid REALITY Ed25519 public key length {0}")]
    InvalidCertificatePublicKey(usize),
    #[error("REALITY session timestamp is outside the configured tolerance")]
    TimeDifference,
    #[error("REALITY short ID is not allowed")]
    UnknownShortId,
    #[error("invalid REALITY ClientHello: {0}")]
    InvalidClientHello(&'static str),
    #[error("REALITY ClientHello has no X25519-compatible key share")]
    MissingX25519KeyShare,
    #[error("REALITY ClientHello key share does not match its private key")]
    X25519KeyShareMismatch,
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct RealityClientParameters {
    pub server_public_key: [u8; 32],
    pub short_id: [u8; REALITY_SHORT_ID_LEN],
}

impl std::fmt::Debug for RealityClientParameters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealityClientParameters")
            .field("server_public_key", &self.server_public_key)
            .field("short_id", &"<redacted>")
            .finish()
    }
}

impl RealityClientParameters {
    pub fn parse(
        public_key: &str,
        short_id: &str,
    ) -> Result<Self, RealityError> {
        Ok(Self {
            server_public_key: decode_key(public_key, "public_key")?,
            short_id: decode_short_id(short_id)?,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct RealityServerParameters {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; REALITY_SHORT_ID_LEN]>,
    #[zeroize(skip)]
    pub max_time_difference: Duration,
}

impl std::fmt::Debug for RealityServerParameters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealityServerParameters")
            .field("private_key", &"<redacted>")
            .field("short_id_count", &self.short_ids.len())
            .field("max_time_difference", &self.max_time_difference)
            .finish()
    }
}

impl RealityServerParameters {
    pub fn parse(
        private_key: &str,
        short_ids: &[String],
        max_time_difference: Duration,
    ) -> Result<Self, RealityError> {
        let short_ids = if short_ids.is_empty() {
            vec![[0; REALITY_SHORT_ID_LEN]]
        } else {
            short_ids
                .iter()
                .map(|value| decode_short_id(value))
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(Self {
            private_key: decode_key(private_key, "private_key")?,
            short_ids,
            max_time_difference,
        })
    }

    pub fn validate_metadata(
        &self,
        metadata: &RealitySessionMetadata,
        now: SystemTime,
    ) -> Result<(), RealityError> {
        if !self.short_ids.contains(&metadata.short_id) {
            return Err(RealityError::UnknownShortId);
        }
        if !self.max_time_difference.is_zero() {
            let now =
                now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let sent = u64::from(metadata.unix_time);
            if now.abs_diff(sent) > self.max_time_difference.as_secs() {
                return Err(RealityError::TimeDifference);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealitySessionMetadata {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: [u8; REALITY_SHORT_ID_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityClientHelloInfo {
    pub random: [u8; 32],
    pub session_id_offset: usize,
    pub server_name: String,
    pub x25519_public_key: [u8; 32],
    pub x25519_public_key_offset: usize,
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct PreparedRealityClientHello {
    pub client_hello: Vec<u8>,
    pub auth_key: [u8; 32],
    pub session_id: [u8; REALITY_SESSION_ID_LEN],
}

impl std::fmt::Debug for PreparedRealityClientHello {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRealityClientHello")
            .field("client_hello_len", &self.client_hello.len())
            .field("auth_key", &"<redacted>")
            .field("session_id", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityCertificateVerification {
    Verified,
    NotReality,
}

pub fn decode_short_id(
    value: &str,
) -> Result<[u8; REALITY_SHORT_ID_LEN], RealityError> {
    let decoded = hex::decode(value).map_err(|error| RealityError::Decode {
        field: "short_id",
        message: error.to_string(),
    })?;
    if decoded.len() > REALITY_SHORT_ID_LEN {
        return Err(RealityError::ShortIdTooLong);
    }
    let mut short_id = [0; REALITY_SHORT_ID_LEN];
    short_id[..decoded.len()].copy_from_slice(&decoded);
    Ok(short_id)
}

pub fn derive_reality_auth_key(
    shared_secret: &[u8; 32],
    hello_random: &[u8; 32],
) -> Result<[u8; 32], RealityError> {
    if shared_secret.iter().all(|byte| *byte == 0) {
        return Err(RealityError::AllZeroSharedSecret);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared_secret);
    let mut auth_key = [0; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|_| RealityError::KeyDerivation)?;
    Ok(auth_key)
}

pub fn prepare_reality_client_hello(
    local_private_key: [u8; 32],
    parameters: &RealityClientParameters,
    unix_time: u32,
    mut client_hello: Vec<u8>,
) -> Result<PreparedRealityClientHello, RealityError> {
    let hello = parse_reality_client_hello(&client_hello)?;
    let local_private_key = Zeroizing::new(local_private_key);
    let local_public_key =
        x25519(*local_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
    if local_public_key != hello.x25519_public_key {
        return Err(RealityError::X25519KeyShareMismatch);
    }
    let shared_secret = Zeroizing::new(x25519(
        *local_private_key,
        parameters.server_public_key,
    ));
    let auth_key =
        Zeroizing::new(derive_reality_auth_key(&shared_secret, &hello.random)?);
    let metadata = RealitySessionMetadata {
        version: REALITY_PROTOCOL_VERSION,
        unix_time,
        short_id: parameters.short_id,
    };
    let session_id = seal_reality_session_id(
        &auth_key,
        &hello.random,
        hello.session_id_offset,
        metadata,
        &mut client_hello,
    )?;
    Ok(PreparedRealityClientHello {
        client_hello,
        auth_key: *auth_key,
        session_id,
    })
}

/// Parse the fields REALITY binds from a TLS handshake ClientHello.
///
/// The input starts with the one-byte handshake type and three-byte length;
/// it must not include the outer five-byte TLS record header. Both the
/// standard X25519 share and Go 1.24+'s X25519MLKEM768 share are accepted.
pub fn parse_reality_client_hello(
    client_hello: &[u8],
) -> Result<RealityClientHelloInfo, RealityError> {
    let mut cursor = ClientHelloCursor::new(client_hello, 0);
    if cursor.read_u8("missing handshake type")? != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(RealityError::InvalidClientHello(
            "unexpected handshake type",
        ));
    }
    let handshake_len = cursor.read_u24("missing handshake length")?;
    if handshake_len
        != client_hello.len().checked_sub(4).ok_or(
            RealityError::InvalidClientHello("missing handshake header"),
        )?
    {
        return Err(RealityError::InvalidClientHello(
            "handshake length mismatch",
        ));
    }
    cursor.take(2, "missing legacy version")?;
    let mut random = [0; 32];
    random.copy_from_slice(cursor.take(32, "missing random")?);
    let session_id_len =
        usize::from(cursor.read_u8("missing session ID length")?);
    if session_id_len != REALITY_SESSION_ID_LEN {
        return Err(RealityError::InvalidClientHello(
            "legacy session ID is not 32 bytes",
        ));
    }
    let session_id_offset = cursor.absolute_offset();
    cursor.take(session_id_len, "truncated session ID")?;
    let cipher_suites_len =
        usize::from(cursor.read_u16("missing cipher suites length")?);
    if cipher_suites_len % 2 != 0 {
        return Err(RealityError::InvalidClientHello(
            "cipher suites length is not even",
        ));
    }
    cursor.take(cipher_suites_len, "truncated cipher suites")?;
    let compression_len =
        usize::from(cursor.read_u8("missing compression methods length")?);
    cursor.take(compression_len, "truncated compression methods")?;
    let extensions_len =
        usize::from(cursor.read_u16("missing extensions length")?);
    let extensions_offset = cursor.absolute_offset();
    let extensions = cursor.take(extensions_len, "truncated extensions")?;
    if cursor.absolute_offset() != client_hello.len() {
        return Err(RealityError::InvalidClientHello(
            "extensions length mismatch",
        ));
    }

    let mut extensions = ClientHelloCursor::new(extensions, extensions_offset);
    let mut server_name = String::new();
    let mut standard = None;
    let mut hybrid = None;
    while !extensions.is_empty() {
        let extension_type = extensions.read_u16("missing extension type")?;
        let extension_len =
            usize::from(extensions.read_u16("missing extension length")?);
        let extension_offset = extensions.absolute_offset();
        let extension =
            extensions.take(extension_len, "truncated extension")?;
        if extension_type == TLS_EXTENSION_SERVER_NAME {
            server_name = parse_server_name(extension, extension_offset)?;
            continue;
        }
        if extension_type != TLS_EXTENSION_KEY_SHARE {
            continue;
        }
        let mut shares = ClientHelloCursor::new(extension, extension_offset);
        let shares_len =
            usize::from(shares.read_u16("missing key-share vector length")?);
        if shares_len != extension.len().saturating_sub(2) {
            return Err(RealityError::InvalidClientHello(
                "key-share vector length mismatch",
            ));
        }
        while !shares.is_empty() {
            let group = shares.read_u16("missing key-share group")?;
            let share_len =
                usize::from(shares.read_u16("missing key-share length")?);
            let share_offset = shares.absolute_offset();
            let share = shares.take(share_len, "truncated key-share bytes")?;
            match group {
                TLS_GROUP_X25519 if share.len() == 32 => {
                    standard = Some((
                        share.try_into().expect("length checked"),
                        share_offset,
                    ));
                }
                TLS_GROUP_X25519 if share.len() != 32 => {
                    return Err(RealityError::InvalidClientHello(
                        "invalid X25519 key-share length",
                    ));
                }
                TLS_GROUP_X25519_MLKEM768
                    if share.len()
                        == TLS_GROUP_X25519_MLKEM768_KEY_EXCHANGE_LEN =>
                {
                    let offset = share.len() - 32;
                    hybrid = Some((
                        share[offset..].try_into().expect("length checked"),
                        share_offset + offset,
                    ));
                }
                TLS_GROUP_X25519_MLKEM768 => {
                    return Err(RealityError::InvalidClientHello(
                        "invalid X25519MLKEM768 key-share length",
                    ));
                }
                _ => {}
            }
        }
    }
    let (x25519_public_key, x25519_public_key_offset) = standard
        .or(hybrid)
        .ok_or(RealityError::MissingX25519KeyShare)?;
    Ok(RealityClientHelloInfo {
        random,
        session_id_offset,
        server_name,
        x25519_public_key,
        x25519_public_key_offset,
    })
}

fn parse_server_name(
    extension: &[u8],
    extension_offset: usize,
) -> Result<String, RealityError> {
    let mut names = ClientHelloCursor::new(extension, extension_offset);
    let names_len =
        usize::from(names.read_u16("missing server-name list length")?);
    if names_len != extension.len().saturating_sub(2) {
        return Err(RealityError::InvalidClientHello(
            "server-name list length mismatch",
        ));
    }
    while !names.is_empty() {
        let name_type = names.read_u8("missing server-name type")?;
        let name_len =
            usize::from(names.read_u16("missing server-name length")?);
        let name = names.take(name_len, "truncated server name")?;
        if name_type == 0 {
            return std::str::from_utf8(name).map(str::to_owned).map_err(
                |_| RealityError::InvalidClientHello("invalid server name"),
            );
        }
    }
    Ok(String::new())
}

pub fn seal_reality_session_id(
    auth_key: &[u8; 32],
    hello_random: &[u8; 32],
    session_id_offset: usize,
    metadata: RealitySessionMetadata,
    client_hello: &mut [u8],
) -> Result<[u8; REALITY_SESSION_ID_LEN], RealityError> {
    let range = session_id_range(client_hello.len(), session_id_offset)?;
    client_hello[range.clone()].fill(0);

    let mut plaintext = [0; 16];
    plaintext[..3].copy_from_slice(&metadata.version);
    plaintext[4..8].copy_from_slice(&metadata.unix_time.to_be_bytes());
    plaintext[8..].copy_from_slice(&metadata.short_id);

    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| RealityError::KeyDerivation)?;
    let nonce: &[u8; 12] = hello_random[20..]
        .try_into()
        .expect("REALITY nonce has a fixed length");
    let sealed = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: &plaintext,
                aad: client_hello,
            },
        )
        .map_err(|_| RealityError::Authentication)?;
    debug_assert_eq!(sealed.len(), REALITY_SESSION_ID_LEN);
    let mut session_id = [0; REALITY_SESSION_ID_LEN];
    session_id.copy_from_slice(&sealed);
    client_hello[range].copy_from_slice(&session_id);
    plaintext.zeroize();
    Ok(session_id)
}

pub fn open_reality_session_id(
    auth_key: &[u8; 32],
    hello_random: &[u8; 32],
    session_id_offset: usize,
    client_hello: &mut [u8],
) -> Result<RealitySessionMetadata, RealityError> {
    let range = session_id_range(client_hello.len(), session_id_offset)?;
    let sealed = client_hello[range.clone()].to_vec();
    client_hello[range].fill(0);
    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| RealityError::KeyDerivation)?;
    let nonce: &[u8; 12] = hello_random[20..]
        .try_into()
        .expect("REALITY nonce has a fixed length");
    let plaintext = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: &sealed,
                aad: client_hello,
            },
        )
        .map_err(|_| RealityError::Authentication)?;
    if plaintext.len() != 16 {
        return Err(RealityError::Authentication);
    }
    let mut version = [0; 3];
    version.copy_from_slice(&plaintext[..3]);
    let unix_time = u32::from_be_bytes(
        plaintext[4..8]
            .try_into()
            .expect("REALITY timestamp has a fixed length"),
    );
    let mut short_id = [0; REALITY_SHORT_ID_LEN];
    short_id.copy_from_slice(&plaintext[8..]);
    Ok(RealitySessionMetadata {
        version,
        unix_time,
        short_id,
    })
}

pub fn derive_reality_auth_key_from_x25519(
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    hello_random: &[u8; 32],
) -> Result<[u8; 32], RealityError> {
    let private_key = Zeroizing::new(private_key);
    let shared_secret = Zeroizing::new(x25519(*private_key, peer_public_key));
    derive_reality_auth_key(&shared_secret, hello_random)
}

pub fn verify_reality_certificate_binding(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
    certificate_signature: &[u8],
) -> RealityCertificateVerification {
    let mut mac = <HmacSha512 as hmac13::KeyInit>::new_from_slice(auth_key)
        .expect("HMAC accepts every key length");
    mac.update(ed25519_public_key);
    if mac.verify_slice(certificate_signature).is_ok() {
        RealityCertificateVerification::Verified
    } else {
        RealityCertificateVerification::NotReality
    }
}

pub fn verify_reality_certificate_der(
    auth_key: &[u8; 32],
    leaf_der: &[u8],
) -> Result<RealityCertificateVerification, RealityError> {
    let (remaining, certificate) = X509Certificate::from_der(leaf_der)
        .map_err(|_| RealityError::InvalidCertificateDer)?;
    if !remaining.is_empty() {
        return Err(RealityError::InvalidCertificateDer);
    }
    let public_key_info = certificate.public_key();
    if public_key_info.algorithm.algorithm != OID_SIG_ED25519 {
        return Ok(RealityCertificateVerification::NotReality);
    }
    if public_key_info.algorithm.parameters.is_some()
        || certificate.signature_algorithm.parameters.is_some()
    {
        return Err(RealityError::InvalidCertificateDer);
    }
    if public_key_info.subject_public_key.unused_bits != 0
        || certificate.signature_value.unused_bits != 0
    {
        return Err(RealityError::InvalidCertificateBitString);
    }
    let public_key = public_key_info.subject_public_key.data.as_ref();
    let public_key: &[u8; 32] = public_key.try_into().map_err(|_| {
        RealityError::InvalidCertificatePublicKey(public_key.len())
    })?;
    Ok(verify_reality_certificate_binding(
        auth_key,
        public_key,
        certificate.signature_value.data.as_ref(),
    ))
}

fn decode_key(
    value: &str,
    field: &'static str,
) -> Result<[u8; 32], RealityError> {
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        RealityError::Decode {
            field,
            message: error.to_string(),
        }
    })?;
    decoded
        .try_into()
        .map_err(|decoded: Vec<u8>| RealityError::InvalidLength {
            field,
            expected: 32,
            actual: decoded.len(),
        })
}

fn session_id_range(
    len: usize,
    offset: usize,
) -> Result<std::ops::Range<usize>, RealityError> {
    let end = offset.checked_add(REALITY_SESSION_ID_LEN).ok_or(
        RealityError::InvalidSessionIdRange {
            offset,
            end: usize::MAX,
            len,
        },
    )?;
    if end > len {
        return Err(RealityError::InvalidSessionIdRange { offset, end, len });
    }
    Ok(offset..end)
}

struct ClientHelloCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    base: usize,
}

impl<'a> ClientHelloCursor<'a> {
    fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            base,
        }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn absolute_offset(&self) -> usize {
        self.base + self.offset
    }

    fn take(
        &mut self,
        len: usize,
        message: &'static str,
    ) -> Result<&'a [u8], RealityError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RealityError::InvalidClientHello(message))?;
        if end > self.bytes.len() {
            return Err(RealityError::InvalidClientHello(message));
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_u8(&mut self, message: &'static str) -> Result<u8, RealityError> {
        Ok(self.take(1, message)?[0])
    }

    fn read_u16(&mut self, message: &'static str) -> Result<u16, RealityError> {
        let bytes = self.take(2, message)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24(
        &mut self,
        message: &'static str,
    ) -> Result<usize, RealityError> {
        let bytes = self.take(3, message)?;
        Ok((usize::from(bytes[0]) << 16)
            | (usize::from(bytes[1]) << 8)
            | usize::from(bytes[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn client_hello(random: [u8; 32], group: u16, key_share: &[u8]) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&TLS_EXTENSION_KEY_SHARE.to_be_bytes());
        let extension_len = 2 + 2 + 2 + key_share.len();
        extensions.extend_from_slice(&(extension_len as u16).to_be_bytes());
        extensions
            .extend_from_slice(&((extension_len - 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&group.to_be_bytes());
        extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        extensions.extend_from_slice(key_share);

        let mut hello = vec![TLS_HANDSHAKE_CLIENT_HELLO, 0, 0, 0, 0x03, 0x03];
        hello.extend_from_slice(&random);
        hello.push(32);
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let handshake_len = hello.len() - 4;
        hello[1] = ((handshake_len >> 16) & 0xff) as u8;
        hello[2] = ((handshake_len >> 8) & 0xff) as u8;
        hello[3] = (handshake_len & 0xff) as u8;
        hello
    }

    #[test]
    fn session_id_matches_cross_language_oracle() {
        // Generated by Xray-core's REALITY algorithm and independently used by
        // the xray-rust interoperability suite.
        let shared_secret = [7; 32];
        let hello_random = decode_hex(
            "09090909090909090909090909090909090909090b0b0b0b0b0b0b0b0b0b0b0b",
        );
        let auth_key =
            derive_reality_auth_key(&shared_secret, &hello_random).unwrap();
        let mut client_hello = hex::decode(
            "0100004f030309090909090909090909090909090909090909090b0b0b0b0b0b0b0b0b0b0b0b200000000000000000000000000000000000000000000000000000000000000000e0e1e2e3e4e5e6e7e8e9eaeb",
        )
        .unwrap();
        let session_id = seal_reality_session_id(
            &auth_key,
            &hello_random,
            39,
            RealitySessionMetadata {
                version: [0x1a, 0x07, 0x1c],
                unix_time: 1_700_000_000,
                short_id: [2, 3, 4, 5, 0, 0, 0, 0],
            },
            &mut client_hello,
        )
        .unwrap();
        assert_eq!(
            session_id,
            decode_hex(
                "e5779dcf108c612231de7c33b4934e2110b3ef806f544144ab91bf68046b0ecc"
            )
        );
    }

    #[test]
    fn server_opens_client_session_metadata() {
        let private_key = [0x11; 32];
        let peer_private_key = [0x22; 32];
        let public_key =
            x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let peer_public_key =
            x25519(peer_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let random = [0x33; 32];
        let client_auth = derive_reality_auth_key_from_x25519(
            peer_private_key,
            public_key,
            &random,
        )
        .unwrap();
        let server_auth = derive_reality_auth_key_from_x25519(
            private_key,
            peer_public_key,
            &random,
        )
        .unwrap();
        assert_eq!(client_auth, server_auth);

        let mut hello = vec![0xa5; 96];
        let expected = RealitySessionMetadata {
            version: REALITY_PROTOCOL_VERSION,
            unix_time: 1_700_000_123,
            short_id: [1, 2, 3, 0, 0, 0, 0, 0],
        };
        seal_reality_session_id(
            &client_auth,
            &random,
            40,
            expected,
            &mut hello,
        )
        .unwrap();
        let opened =
            open_reality_session_id(&server_auth, &random, 40, &mut hello)
                .unwrap();
        assert_eq!(opened, expected);
        assert_eq!(&hello[40..72], &[0; 32]);
    }

    #[test]
    fn client_hello_parser_finds_standard_x25519_share() {
        let private_key = [0x11; 32];
        let public_key =
            x25519(private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let random = [0x22; 32];
        let hello = client_hello(random, TLS_GROUP_X25519, &public_key);
        let parsed = parse_reality_client_hello(&hello).unwrap();
        assert_eq!(parsed.random, random);
        assert_eq!(parsed.session_id_offset, 39);
        assert_eq!(parsed.x25519_public_key, public_key);
        assert_eq!(
            &hello[parsed.x25519_public_key_offset
                ..parsed.x25519_public_key_offset + 32],
            &public_key
        );
    }

    #[test]
    fn client_hello_parser_uses_hybrid_x25519_suffix() {
        let public_key = [0x71; 32];
        let mut hybrid = vec![0x55; 1184];
        hybrid.extend_from_slice(&public_key);
        let hello =
            client_hello([0x33; 32], TLS_GROUP_X25519_MLKEM768, &hybrid);
        let parsed = parse_reality_client_hello(&hello).unwrap();
        assert_eq!(parsed.x25519_public_key, public_key);
        assert_eq!(
            &hello[parsed.x25519_public_key_offset
                ..parsed.x25519_public_key_offset + 32],
            &public_key
        );
    }

    #[test]
    fn prepared_client_hello_is_opened_by_server_key() {
        let client_private_key = [0x44; 32];
        let client_public_key =
            x25519(client_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let server_private_key = [0x77; 32];
        let server_public_key =
            x25519(server_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let random = [0x88; 32];
        let prepared = prepare_reality_client_hello(
            client_private_key,
            &RealityClientParameters {
                server_public_key,
                short_id: [1, 2, 3, 4, 0, 0, 0, 0],
            },
            1_700_000_456,
            client_hello(random, TLS_GROUP_X25519, &client_public_key),
        )
        .unwrap();
        let server_auth = derive_reality_auth_key_from_x25519(
            server_private_key,
            client_public_key,
            &random,
        )
        .unwrap();
        assert_eq!(prepared.auth_key, server_auth);
        let mut hello = prepared.client_hello.clone();
        let opened =
            open_reality_session_id(&server_auth, &random, 39, &mut hello)
                .unwrap();
        assert_eq!(opened.version, REALITY_PROTOCOL_VERSION);
        assert_eq!(opened.unix_time, 1_700_000_456);
        assert_eq!(opened.short_id, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn malformed_or_mismatched_client_hello_fails_closed() {
        assert!(matches!(
            parse_reality_client_hello(&[1, 0, 0]),
            Err(RealityError::InvalidClientHello(_))
        ));
        let private_key = [0x11; 32];
        let hello = client_hello([0; 32], TLS_GROUP_X25519, &[0x22; 32]);
        assert_eq!(
            prepare_reality_client_hello(
                private_key,
                &RealityClientParameters {
                    server_public_key: [0x33; 32],
                    short_id: [0; 8],
                },
                0,
                hello,
            ),
            Err(RealityError::X25519KeyShareMismatch)
        );
    }

    #[test]
    fn tampered_client_hello_is_rejected() {
        let auth_key = [7; 32];
        let random = [9; 32];
        let mut hello = vec![0; 80];
        seal_reality_session_id(
            &auth_key,
            &random,
            20,
            RealitySessionMetadata {
                version: REALITY_PROTOCOL_VERSION,
                unix_time: 42,
                short_id: [0; 8],
            },
            &mut hello,
        )
        .unwrap();
        hello[79] ^= 1;
        assert_eq!(
            open_reality_session_id(&auth_key, &random, 20, &mut hello),
            Err(RealityError::Authentication)
        );
    }

    #[test]
    fn configuration_parsing_matches_sing_box_padding_rules() {
        let key = URL_SAFE_NO_PAD.encode([7; 32]);
        let client = RealityClientParameters::parse(&key, "012345").unwrap();
        assert_eq!(client.short_id, [1, 0x23, 0x45, 0, 0, 0, 0, 0]);
        let server =
            RealityServerParameters::parse(&key, &[], Duration::ZERO).unwrap();
        assert_eq!(server.short_ids, vec![[0; 8]]);
        assert_eq!(
            decode_short_id("001122334455667788"),
            Err(RealityError::ShortIdTooLong)
        );
        assert!(decode_short_id("0").is_err());
    }

    #[test]
    fn server_validates_short_id_and_timestamp() {
        let key = URL_SAFE_NO_PAD.encode([7; 32]);
        let server = RealityServerParameters::parse(
            &key,
            &["0102".to_owned()],
            Duration::from_secs(30),
        )
        .unwrap();
        let metadata = RealitySessionMetadata {
            version: REALITY_PROTOCOL_VERSION,
            unix_time: 1_000,
            short_id: [1, 2, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            server.validate_metadata(
                &metadata,
                UNIX_EPOCH + Duration::from_secs(1_029)
            ),
            Ok(())
        );
        assert_eq!(
            server.validate_metadata(
                &metadata,
                UNIX_EPOCH + Duration::from_secs(1_031)
            ),
            Err(RealityError::TimeDifference)
        );
        let unknown = RealitySessionMetadata {
            short_id: [9; 8],
            ..metadata
        };
        assert_eq!(
            server.validate_metadata(
                &unknown,
                UNIX_EPOCH + Duration::from_secs(1_000)
            ),
            Err(RealityError::UnknownShortId)
        );
    }

    #[test]
    fn zero_shared_secret_and_invalid_ranges_fail_closed() {
        assert_eq!(
            derive_reality_auth_key(&[0; 32], &[0; 32]),
            Err(RealityError::AllZeroSharedSecret)
        );
        let mut hello = [0u8; 63];
        assert!(matches!(
            seal_reality_session_id(
                &[1; 32],
                &[2; 32],
                32,
                RealitySessionMetadata {
                    version: REALITY_PROTOCOL_VERSION,
                    unix_time: 0,
                    short_id: [0; 8],
                },
                &mut hello,
            ),
            Err(RealityError::InvalidSessionIdRange { .. })
        ));
    }

    #[test]
    fn certificate_binding_uses_hmac_sha512() {
        let auth_key = [0x21; 32];
        let public_key = [0x42; 32];
        let mut mac =
            <HmacSha512 as hmac13::KeyInit>::new_from_slice(&auth_key).unwrap();
        mac.update(&public_key);
        let signature = mac.finalize().into_bytes();
        assert_eq!(
            verify_reality_certificate_binding(
                &auth_key,
                &public_key,
                &signature
            ),
            RealityCertificateVerification::Verified
        );
        assert_eq!(
            verify_reality_certificate_binding(
                &auth_key,
                &public_key,
                &[0; 64]
            ),
            RealityCertificateVerification::NotReality
        );
    }

    #[test]
    fn debug_output_redacts_secret_material() {
        let parameters = RealityClientParameters {
            server_public_key: [7; 32],
            short_id: [9; 8],
        };
        let debug = format!("{parameters:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("9, 9, 9"));
    }
}
