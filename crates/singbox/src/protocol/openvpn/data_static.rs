use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    OpenVpnAuthDigest, OpenVpnCbcCipher, OpenVpnDataCodec,
    OpenVpnDataCodecError, ReplayWindow, data_replay_window_parameters,
    split_static_key_material,
};

#[derive(Debug, Clone)]
struct StaticDecodeCandidate {
    cipher_key: Vec<u8>,
    hmac_key: Vec<u8>,
}

/// OpenVPN's pre-shared static-key data channel, including bidirectional key
/// slot fallback for unspecified and legacy `key-direction` configurations.
pub struct StaticKeyDataCodec {
    cipher: OpenVpnCbcCipher,
    send_cipher_key: Vec<u8>,
    send_hmac_key: Vec<u8>,
    receive_candidates: Vec<StaticDecodeCandidate>,
    auth: OpenVpnAuthDigest,
    send_timestamp: u32,
    replay_window: ReplayWindow,
}

impl StaticKeyDataCodec {
    pub fn new(
        static_key_material: &[u8],
        key_direction: i8,
        cipher_name: &str,
        auth_name: &str,
        replay_window_size: u32,
        replay_window_time: Duration,
    ) -> Result<Self, OpenVpnDataCodecError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        Self::new_at(
            static_key_material,
            key_direction,
            cipher_name,
            auth_name,
            replay_window_size,
            replay_window_time,
            timestamp,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_at(
        static_key_material: &[u8],
        key_direction: i8,
        cipher_name: &str,
        auth_name: &str,
        replay_window_size: u32,
        replay_window_time: Duration,
        send_timestamp: u32,
    ) -> Result<Self, OpenVpnDataCodecError> {
        let slots = split_static_key_material(static_key_material)
            .ok_or(OpenVpnDataCodecError::InvalidKeyMaterial)?;
        let cipher = OpenVpnCbcCipher::from_name(cipher_name)?;
        let auth = OpenVpnAuthDigest::from_name(auth_name)?;
        let (send_index, receive_index, fallback_index) =
            resolve_static_key_direction(key_direction);
        let key_size = cipher.key_size();
        let hmac_size = auth.output_size();
        let candidate = |index: usize| StaticDecodeCandidate {
            cipher_key: slots[index].cipher_key[..key_size].to_vec(),
            hmac_key: slots[index].hmac_key[..hmac_size].to_vec(),
        };
        let mut receive_candidates = vec![candidate(receive_index)];
        if fallback_index != receive_index {
            receive_candidates.push(candidate(fallback_index));
        }
        let (replay_window_size, replay_window_time) =
            data_replay_window_parameters(
                replay_window_size,
                replay_window_time,
            );
        Ok(Self {
            cipher,
            send_cipher_key: slots[send_index].cipher_key[..key_size].to_vec(),
            send_hmac_key: slots[send_index].hmac_key[..hmac_size].to_vec(),
            receive_candidates,
            auth,
            send_timestamp,
            replay_window: ReplayWindow::new(
                replay_window_size,
                replay_window_time,
            ),
        })
    }

    fn encode_with_iv(
        &self,
        packet_id: u32,
        payload: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        if packet_id == 0 {
            return Err(OpenVpnDataCodecError::InvalidPacketId);
        }
        let mut plaintext = Vec::with_capacity(8 + payload.len());
        plaintext.extend_from_slice(&packet_id.to_be_bytes());
        plaintext.extend_from_slice(&self.send_timestamp.to_be_bytes());
        plaintext.extend_from_slice(payload);
        let protected = if self.cipher == OpenVpnCbcCipher::None {
            plaintext
        } else {
            let ciphertext =
                self.cipher.encrypt(&self.send_cipher_key, iv, &plaintext)?;
            let mut protected = Vec::with_capacity(iv.len() + ciphertext.len());
            protected.extend_from_slice(iv);
            protected.extend_from_slice(&ciphertext);
            protected
        };
        let mut output =
            Vec::with_capacity(self.auth.output_size() + protected.len());
        output.extend_from_slice(
            &self.auth.sign(&self.send_hmac_key, &protected),
        );
        output.extend_from_slice(&protected);
        Ok(output)
    }

    fn decode_candidate(
        &self,
        payload: &[u8],
        candidate: &StaticDecodeCandidate,
    ) -> Result<(u32, u32, Vec<u8>), OpenVpnDataCodecError> {
        let hmac_size = self.auth.output_size();
        if payload.len() < hmac_size {
            return Err(OpenVpnDataCodecError::InvalidEncryptedPayload);
        }
        let (received_hmac, protected) = payload.split_at(hmac_size);
        if !self
            .auth
            .verify(&candidate.hmac_key, protected, received_hmac)
        {
            return Err(OpenVpnDataCodecError::HmacVerificationFailed);
        }
        let plaintext = if self.cipher == OpenVpnCbcCipher::None {
            protected.to_vec()
        } else {
            let block_size = self.cipher.block_size();
            if protected.len() < block_size * 2
                || protected.len() % block_size != 0
            {
                return Err(OpenVpnDataCodecError::InvalidEncryptedPayload);
            }
            let (iv, ciphertext) = protected.split_at(block_size);
            self.cipher.decrypt(&candidate.cipher_key, iv, ciphertext)?
        };
        if plaintext.len() < 8 {
            return Err(OpenVpnDataCodecError::InvalidEncryptedPayload);
        }
        let packet_id = u32::from_be_bytes(plaintext[..4].try_into().unwrap());
        if packet_id == 0 {
            return Err(OpenVpnDataCodecError::InvalidPacketId);
        }
        let timestamp = u32::from_be_bytes(plaintext[4..8].try_into().unwrap());
        Ok((packet_id, timestamp, plaintext[8..].to_vec()))
    }
}

impl OpenVpnDataCodec for StaticKeyDataCodec {
    fn encoded_length(&self, payload_length: usize) -> usize {
        let plaintext_length = 8 + payload_length;
        let block_size = self.cipher.block_size();
        let protected_length = if block_size == 0 {
            plaintext_length
        } else {
            block_size + (plaintext_length / block_size + 1) * block_size
        };
        self.auth.output_size() + protected_length
    }

    fn encode(
        &self,
        packet_id: u32,
        _aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        let mut iv = vec![0; self.cipher.block_size()];
        getrandom::fill(&mut iv)
            .map_err(|_| OpenVpnDataCodecError::RandomFailed)?;
        self.encode_with_iv(packet_id, payload, &iv)
    }

    fn decode(
        &self,
        _aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<(u32, Vec<u8>), OpenVpnDataCodecError> {
        let mut last_error = OpenVpnDataCodecError::InvalidEncryptedPayload;
        for candidate in &self.receive_candidates {
            match self.decode_candidate(payload, candidate) {
                Ok((packet_id, timestamp, plaintext)) => {
                    if !self
                        .replay_window
                        .accept_long_form(packet_id, timestamp)
                    {
                        return Err(OpenVpnDataCodecError::ReplayedPacket);
                    }
                    return Ok((packet_id, plaintext));
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
}

fn resolve_static_key_direction(direction: i8) -> (usize, usize, usize) {
    if matches!(direction, 1 | 2) {
        (1, 0, 1)
    } else if direction < 0 {
        (0, 0, 1)
    } else {
        (0, 1, 0)
    }
}

pub fn parse_openvpn_static_key(
    content: &[u8],
) -> Result<Vec<u8>, OpenVpnDataCodecError> {
    if content.is_empty() {
        return Err(OpenVpnDataCodecError::MissingStaticKey);
    }
    if content.len() == 256 {
        return Ok(content.to_vec());
    }
    const BEGIN: &[u8] = b"-----BEGIN OpenVPN Static key V1-----";
    const END: &[u8] = b"-----END OpenVPN Static key V1-----";
    let mut encoded = content;
    if let Some(begin) = find_bytes(encoded, BEGIN) {
        encoded = &encoded[begin + BEGIN.len()..];
        let end = find_bytes(encoded, END)
            .ok_or(OpenVpnDataCodecError::InvalidStaticKeyEndMarker)?;
        encoded = &encoded[..end];
    }
    let compact: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.len() != 512 {
        return Err(OpenVpnDataCodecError::InvalidStaticKeyLength);
    }
    hex::decode(compact).map_err(|_| OpenVpnDataCodecError::InvalidStaticKeyHex)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_material() -> Vec<u8> {
        (0..=u8::MAX).collect()
    }

    #[test]
    fn parses_raw_and_pem_style_static_keys() {
        let material = key_material();
        assert_eq!(parse_openvpn_static_key(&material).unwrap(), material);
        let hex = hex::encode(&material);
        let wrapped = format!(
            "ignored\n-----BEGIN OpenVPN Static key V1-----\n{}\n{}\n-----END OpenVPN Static key V1-----\n",
            &hex[..256],
            &hex[256..]
        );
        assert_eq!(
            parse_openvpn_static_key(wrapped.as_bytes()).unwrap(),
            material
        );
        assert_eq!(
            parse_openvpn_static_key(b""),
            Err(OpenVpnDataCodecError::MissingStaticKey)
        );
    }

    #[test]
    fn round_trips_static_mode_ciphers_and_direction_pairs() {
        for cipher in [
            "BF-CBC",
            "DES-CBC",
            "DES-EDE-CBC",
            "DES-EDE3-CBC",
            "CAST5-CBC",
            "AES-128-CBC",
            "AES-192-CBC",
            "AES-256-CBC",
            "ARIA-128-CBC",
            "ARIA-192-CBC",
            "ARIA-256-CBC",
            "CAMELLIA-128-CBC",
            "CAMELLIA-192-CBC",
            "CAMELLIA-256-CBC",
            "SEED-CBC",
            "SM4-CBC",
            "NONE",
        ] {
            let direction_zero = StaticKeyDataCodec::new_at(
                &key_material(),
                0,
                cipher,
                "SHA256",
                0,
                Duration::ZERO,
                55,
            )
            .unwrap();
            let direction_one = StaticKeyDataCodec::new_at(
                &key_material(),
                1,
                cipher,
                "SHA256",
                0,
                Duration::ZERO,
                55,
            )
            .unwrap();
            let packet = direction_zero.encode(7, &[], b"static").unwrap();
            assert_eq!(
                direction_one.decode(&[], &packet).unwrap(),
                (7, b"static".to_vec()),
                "{cipher}"
            );
        }
    }

    #[test]
    fn unspecified_direction_accepts_both_key_slots() {
        let unspecified = StaticKeyDataCodec::new_at(
            &key_material(),
            -1,
            "AES-256-CBC",
            "SHA1",
            0,
            Duration::ZERO,
            10,
        )
        .unwrap();
        let direction_one = StaticKeyDataCodec::new_at(
            &key_material(),
            1,
            "AES-256-CBC",
            "SHA1",
            0,
            Duration::ZERO,
            10,
        )
        .unwrap();
        let packet = direction_one.encode(1, &[], b"fallback").unwrap();
        assert_eq!(
            unspecified.decode(&[], &packet).unwrap(),
            (1, b"fallback".to_vec())
        );
    }

    #[test]
    fn matches_go_static_key_wire_vector() {
        let codec = StaticKeyDataCodec::new_at(
            &key_material(),
            0,
            "AES-128-CBC",
            "SHA256",
            0,
            Duration::ZERO,
            0x1122_3344,
        )
        .unwrap();
        let iv: Vec<u8> = (0xa0..=0xaf).collect();
        assert_eq!(
            hex::encode(
                codec
                    .encode_with_iv(0x0102_0304, b"sing-openvpn", &iv)
                    .unwrap()
            ),
            "d66d1c9d384676a862327d583a325bffca9c963fa924be10178aaa483f938dd0a0a1a2a3a4a5a6a7a8a9aaabacadaeafa9c0043c348b01b03f4a6a225f434657c39c0a42ec7367c83396418df977b8b6"
        );
    }
}
