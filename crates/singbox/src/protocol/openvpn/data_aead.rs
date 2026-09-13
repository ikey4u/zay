use std::time::Duration;

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit, Payload, consts::U12},
};
use chacha20poly1305::ChaCha20Poly1305;

use super::{
    OpenVpnDataCodec, OpenVpnDataCodecError, ReplayWindow,
    data_replay_window_parameters, split_static_key_material,
    tls_data_key_slots,
};

const AEAD_TAG_SIZE: usize = 16;
const PACKET_ID_SIZE: usize = 4;
const AEAD_OVERHEAD: usize = PACKET_ID_SIZE + AEAD_TAG_SIZE;

type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, U12>;

enum AeadCipher {
    Aes128(Aes128Gcm),
    Aes192(Aes192Gcm),
    Aes256(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadCipher {
    fn new(
        name: &str,
        key_material: &[u8],
    ) -> Result<Self, OpenVpnDataCodecError> {
        let invalid_key = |_| OpenVpnDataCodecError::InvalidKeyMaterial;
        match name {
            "AES-128-GCM" => Aes128Gcm::new_from_slice(&key_material[..16])
                .map(Self::Aes128)
                .map_err(invalid_key),
            "AES-192-GCM" => Aes192Gcm::new_from_slice(&key_material[..24])
                .map(Self::Aes192)
                .map_err(invalid_key),
            "AES-256-GCM" => Aes256Gcm::new_from_slice(&key_material[..32])
                .map(Self::Aes256)
                .map_err(invalid_key),
            "CHACHA20-POLY1305" => {
                ChaCha20Poly1305::new_from_slice(&key_material[..32])
                    .map(Self::ChaCha20Poly1305)
                    .map_err(invalid_key)
            }
            _ => Err(OpenVpnDataCodecError::UnsupportedCipher(name.to_owned())),
        }
    }

    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        macro_rules! encrypt {
            ($cipher:expr) => {
                $cipher.encrypt(
                    &(*nonce).into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
            };
        }
        let result = match self {
            Self::Aes128(cipher) => encrypt!(cipher),
            Self::Aes192(cipher) => encrypt!(cipher),
            Self::Aes256(cipher) => encrypt!(cipher),
            Self::ChaCha20Poly1305(cipher) => encrypt!(cipher),
        };
        result.map_err(|_| OpenVpnDataCodecError::AuthenticationFailed)
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        macro_rules! decrypt {
            ($cipher:expr) => {
                $cipher.decrypt(
                    &(*nonce).into(),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
            };
        }
        let result = match self {
            Self::Aes128(cipher) => decrypt!(cipher),
            Self::Aes192(cipher) => decrypt!(cipher),
            Self::Aes256(cipher) => decrypt!(cipher),
            Self::ChaCha20Poly1305(cipher) => decrypt!(cipher),
        };
        result.map_err(|_| OpenVpnDataCodecError::AuthenticationFailed)
    }
}

/// OpenVPN's AEAD data-channel codec. The wire layout is
/// `packet-id || tag || encrypted-payload`, unlike the postfix-tag layout
/// returned by the underlying RustCrypto primitives.
pub struct TlsAeadDataCodec {
    send_cipher: AeadCipher,
    send_iv_suffix: [u8; 8],
    receive_cipher: AeadCipher,
    receive_iv_suffix: [u8; 8],
    replay_window: ReplayWindow,
}

impl TlsAeadDataCodec {
    pub fn new(
        key_material: &[u8],
        server: bool,
        cipher_name: &str,
        replay_window_size: u32,
        replay_window_time: Duration,
    ) -> Result<Self, OpenVpnDataCodecError> {
        let slots = split_static_key_material(key_material)
            .ok_or(OpenVpnDataCodecError::InvalidKeyMaterial)?;
        let (send_slot, receive_slot) = tls_data_key_slots(slots, server);
        let (replay_window_size, replay_window_time) =
            data_replay_window_parameters(
                replay_window_size,
                replay_window_time,
            );
        Ok(Self {
            send_cipher: AeadCipher::new(cipher_name, send_slot.cipher_key)?,
            send_iv_suffix: send_slot.hmac_key[..8].try_into().unwrap(),
            receive_cipher: AeadCipher::new(
                cipher_name,
                receive_slot.cipher_key,
            )?,
            receive_iv_suffix: receive_slot.hmac_key[..8].try_into().unwrap(),
            replay_window: ReplayWindow::new(
                replay_window_size,
                replay_window_time,
            ),
        })
    }

    fn nonce(packet_id: u32, suffix: [u8; 8]) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&packet_id.to_be_bytes());
        nonce[4..].copy_from_slice(&suffix);
        nonce
    }

    fn aad(aad_prefix: &[u8], packet_id: [u8; 4]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(aad_prefix.len() + PACKET_ID_SIZE);
        aad.extend_from_slice(aad_prefix);
        aad.extend_from_slice(&packet_id);
        aad
    }
}

impl OpenVpnDataCodec for TlsAeadDataCodec {
    fn encoded_length(&self, payload_length: usize) -> usize {
        AEAD_OVERHEAD + payload_length
    }

    fn encode(
        &self,
        packet_id: u32,
        aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        if packet_id == 0 {
            return Err(OpenVpnDataCodecError::InvalidPacketId);
        }
        let packet_id_bytes = packet_id.to_be_bytes();
        let nonce = Self::nonce(packet_id, self.send_iv_suffix);
        let aad = Self::aad(aad_prefix, packet_id_bytes);
        let ciphertext_and_tag =
            self.send_cipher.encrypt(&nonce, &aad, payload)?;
        let encrypted_length = ciphertext_and_tag
            .len()
            .checked_sub(AEAD_TAG_SIZE)
            .ok_or(OpenVpnDataCodecError::InvalidAeadPayload)?;
        let (encrypted_payload, tag) =
            ciphertext_and_tag.split_at(encrypted_length);
        let mut output = Vec::with_capacity(self.encoded_length(payload.len()));
        output.extend_from_slice(&packet_id_bytes);
        output.extend_from_slice(tag);
        output.extend_from_slice(encrypted_payload);
        Ok(output)
    }

    fn decode(
        &self,
        aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<(u32, Vec<u8>), OpenVpnDataCodecError> {
        if payload.len() < AEAD_OVERHEAD {
            return Err(OpenVpnDataCodecError::InvalidAeadPayload);
        }
        let packet_id_bytes: [u8; 4] = payload[..4].try_into().unwrap();
        let packet_id = u32::from_be_bytes(packet_id_bytes);
        let tag = &payload[4..AEAD_OVERHEAD];
        let encrypted_payload = &payload[AEAD_OVERHEAD..];
        let mut ciphertext_and_tag =
            Vec::with_capacity(encrypted_payload.len() + AEAD_TAG_SIZE);
        ciphertext_and_tag.extend_from_slice(encrypted_payload);
        ciphertext_and_tag.extend_from_slice(tag);
        let nonce = Self::nonce(packet_id, self.receive_iv_suffix);
        let aad = Self::aad(aad_prefix, packet_id_bytes);
        let plaintext =
            self.receive_cipher
                .decrypt(&nonce, &aad, &ciphertext_and_tag)?;
        if !self.replay_window.accept(packet_id) {
            return Err(OpenVpnDataCodecError::ReplayedPacket);
        }
        Ok((packet_id, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_material() -> Vec<u8> {
        (0..=u8::MAX).collect()
    }

    #[test]
    fn client_and_server_round_trip_all_aead_ciphers() {
        for cipher in [
            "AES-128-GCM",
            "AES-192-GCM",
            "AES-256-GCM",
            "CHACHA20-POLY1305",
        ] {
            let client = TlsAeadDataCodec::new(
                &key_material(),
                false,
                cipher,
                0,
                Duration::ZERO,
            )
            .unwrap();
            let server = TlsAeadDataCodec::new(
                &key_material(),
                true,
                cipher,
                0,
                Duration::ZERO,
            )
            .unwrap();
            let encoded = client.encode(7, &[0x49, 1, 2, 3], b"hello").unwrap();
            assert_eq!(encoded.len(), client.encoded_length(5));
            assert_eq!(
                server.decode(&[0x49, 1, 2, 3], &encoded).unwrap(),
                (7, b"hello".to_vec())
            );

            let response = server.encode(9, &[], b"world").unwrap();
            assert_eq!(
                client.decode(&[], &response).unwrap(),
                (9, b"world".to_vec())
            );
        }
    }

    #[test]
    fn uses_openvpn_tag_before_ciphertext_wire_layout() {
        let client = TlsAeadDataCodec::new(
            &key_material(),
            false,
            "AES-128-GCM",
            0,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(
            hex::encode(
                client
                    .encode(
                        0x0102_0304,
                        &[0x49, 0xaa, 0xbb, 0xcc],
                        b"sing-openvpn",
                    )
                    .unwrap()
            ),
            "01020304f0287d2199e11adbefe193eece50d056ed24c5b3bfc0a2b359f2afad"
        );
    }

    #[test]
    fn authenticates_aad_and_rejects_replay() {
        let client = TlsAeadDataCodec::new(
            &key_material(),
            false,
            "CHACHA20-POLY1305",
            0,
            Duration::ZERO,
        )
        .unwrap();
        let server = TlsAeadDataCodec::new(
            &key_material(),
            true,
            "CHACHA20-POLY1305",
            0,
            Duration::ZERO,
        )
        .unwrap();
        let encoded = client.encode(1, b"aad", b"payload").unwrap();
        assert_eq!(
            server.decode(b"wrong", &encoded),
            Err(OpenVpnDataCodecError::AuthenticationFailed)
        );
        assert!(server.decode(b"aad", &encoded).is_ok());
        assert_eq!(
            server.decode(b"aad", &encoded),
            Err(OpenVpnDataCodecError::ReplayedPacket)
        );
    }

    #[test]
    fn rejects_invalid_constructor_and_packet_inputs() {
        assert!(matches!(
            TlsAeadDataCodec::new(
                &[0; 255],
                false,
                "AES-128-GCM",
                0,
                Duration::ZERO,
            ),
            Err(OpenVpnDataCodecError::InvalidKeyMaterial)
        ));
        assert!(matches!(
            TlsAeadDataCodec::new(
                &[0; 256],
                false,
                "BF-CBC",
                0,
                Duration::ZERO,
            ),
            Err(OpenVpnDataCodecError::UnsupportedCipher(_))
        ));
        let codec = TlsAeadDataCodec::new(
            &[0; 256],
            false,
            "AES-128-GCM",
            0,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(
            codec.encode(0, &[], &[]),
            Err(OpenVpnDataCodecError::InvalidPacketId)
        );
        assert_eq!(
            codec.decode(&[], &[0; 19]),
            Err(OpenVpnDataCodecError::InvalidAeadPayload)
        );
    }
}
