use std::time::Duration;

use super::{DEFAULT_REPLAY_WINDOW_SIZE, DEFAULT_REPLAY_WINDOW_TIME};

pub const TLS_KEY_MATERIAL_LENGTH: usize = 256;

#[derive(Debug, Clone, Copy)]
pub(crate) struct StaticKeySlot<'a> {
    pub cipher_key: &'a [u8],
    pub hmac_key: &'a [u8],
}

pub(crate) fn split_static_key_material(
    material: &[u8],
) -> Option<[StaticKeySlot<'_>; 2]> {
    (material.len() >= TLS_KEY_MATERIAL_LENGTH).then(|| {
        [
            StaticKeySlot {
                cipher_key: &material[..64],
                hmac_key: &material[64..128],
            },
            StaticKeySlot {
                cipher_key: &material[128..192],
                hmac_key: &material[192..256],
            },
        ]
    })
}

pub(crate) fn tls_data_key_slots(
    slots: [StaticKeySlot<'_>; 2],
    server: bool,
) -> (StaticKeySlot<'_>, StaticKeySlot<'_>) {
    if server {
        (slots[1], slots[0])
    } else {
        (slots[0], slots[1])
    }
}

pub(crate) fn data_replay_window_parameters(
    window_size: u32,
    window_time: Duration,
) -> (u32, Duration) {
    (
        if window_size == 0 {
            DEFAULT_REPLAY_WINDOW_SIZE
        } else {
            window_size
        },
        if window_time.is_zero() {
            DEFAULT_REPLAY_WINDOW_TIME
        } else {
            window_time
        },
    )
}

pub trait OpenVpnDataCodec: Send + Sync {
    fn encoded_length(&self, payload_length: usize) -> usize;

    fn encode(
        &self,
        packet_id: u32,
        aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError>;

    fn decode(
        &self,
        aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<(u32, Vec<u8>), OpenVpnDataCodecError>;
}

pub fn new_tls_data_codec(
    key_material: &[u8],
    server: bool,
    cipher_name: &str,
    auth_name: &str,
    replay_window_size: u32,
    replay_window_time: Duration,
) -> Result<Box<dyn OpenVpnDataCodec>, OpenVpnDataCodecError> {
    match cipher_name {
        "AES-128-GCM" | "AES-192-GCM" | "AES-256-GCM" | "CHACHA20-POLY1305" => {
            Ok(Box::new(super::TlsAeadDataCodec::new(
                key_material,
                server,
                cipher_name,
                replay_window_size,
                replay_window_time,
            )?))
        }
        _ if super::openvpn_stream_cipher_spec(cipher_name).is_ok() => {
            Ok(Box::new(super::TlsStreamDataCodec::new(
                key_material,
                server,
                cipher_name,
                auth_name,
                replay_window_size,
                replay_window_time,
            )?))
        }
        _ => Ok(Box::new(super::TlsCbcDataCodec::new(
            key_material,
            server,
            cipher_name,
            auth_name,
            replay_window_size,
            replay_window_time,
        )?)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenVpnDataCodecError {
    #[error("invalid TLS key material: expected at least 256 bytes")]
    InvalidKeyMaterial,
    #[error("unsupported OpenVPN data cipher: {0}")]
    UnsupportedCipher(String),
    #[error("unsupported OpenVPN data authentication digest: {0}")]
    UnsupportedAuth(String),
    #[error("invalid OpenVPN data packet ID")]
    InvalidPacketId,
    #[error("invalid OpenVPN AEAD payload")]
    InvalidAeadPayload,
    #[error("OpenVPN AEAD authentication failed")]
    AuthenticationFailed,
    #[error("OpenVPN data-channel HMAC verification failed")]
    HmacVerificationFailed,
    #[error("invalid OpenVPN encrypted data payload")]
    InvalidEncryptedPayload,
    #[error("invalid OpenVPN data-channel PKCS#7 padding")]
    InvalidPadding,
    #[error("failed to generate OpenVPN initialization vector")]
    RandomFailed,
    #[error("missing OpenVPN static key")]
    MissingStaticKey,
    #[error("invalid OpenVPN static-key end marker")]
    InvalidStaticKeyEndMarker,
    #[error("OpenVPN static key must contain exactly 256 bytes")]
    InvalidStaticKeyLength,
    #[error("OpenVPN static key contains invalid hexadecimal data")]
    InvalidStaticKeyHex,
    #[error("replayed OpenVPN AEAD packet")]
    ReplayedPacket,
}
