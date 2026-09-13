use std::time::Duration;

use super::{
    OpenVpnAuthDigest, OpenVpnCbcCipher, OpenVpnDataCodec,
    OpenVpnDataCodecError, ReplayWindow, data_replay_window_parameters,
    split_static_key_material, tls_data_key_slots,
};

/// OpenVPN's classic TLS data-channel codec for CBC block ciphers and the
/// compatibility `cipher NONE` mode.
pub struct TlsCbcDataCodec {
    send_cipher: OpenVpnCbcCipher,
    send_cipher_key: Vec<u8>,
    send_hmac_key: Vec<u8>,
    receive_cipher: OpenVpnCbcCipher,
    receive_cipher_key: Vec<u8>,
    receive_hmac_key: Vec<u8>,
    auth: OpenVpnAuthDigest,
    replay_window: ReplayWindow,
}

impl TlsCbcDataCodec {
    pub fn new(
        key_material: &[u8],
        server: bool,
        cipher_name: &str,
        auth_name: &str,
        replay_window_size: u32,
        replay_window_time: Duration,
    ) -> Result<Self, OpenVpnDataCodecError> {
        let slots = split_static_key_material(key_material)
            .ok_or(OpenVpnDataCodecError::InvalidKeyMaterial)?;
        let (send_slot, receive_slot) = tls_data_key_slots(slots, server);
        let cipher = OpenVpnCbcCipher::from_name(cipher_name)?;
        let auth = OpenVpnAuthDigest::from_name(auth_name)?;
        let key_size = cipher.key_size();
        let hmac_size = auth.output_size();
        let (replay_window_size, replay_window_time) =
            data_replay_window_parameters(
                replay_window_size,
                replay_window_time,
            );
        Ok(Self {
            send_cipher: cipher,
            send_cipher_key: send_slot.cipher_key[..key_size].to_vec(),
            send_hmac_key: send_slot.hmac_key[..hmac_size].to_vec(),
            receive_cipher: cipher,
            receive_cipher_key: receive_slot.cipher_key[..key_size].to_vec(),
            receive_hmac_key: receive_slot.hmac_key[..hmac_size].to_vec(),
            auth,
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
        let mut plaintext = Vec::with_capacity(4 + payload.len());
        plaintext.extend_from_slice(&packet_id.to_be_bytes());
        plaintext.extend_from_slice(payload);
        let protected = if self.send_cipher == OpenVpnCbcCipher::None {
            plaintext
        } else {
            let ciphertext = self.send_cipher.encrypt(
                &self.send_cipher_key,
                iv,
                &plaintext,
            )?;
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
}

impl OpenVpnDataCodec for TlsCbcDataCodec {
    fn encoded_length(&self, payload_length: usize) -> usize {
        let plaintext_length = 4 + payload_length;
        let block_size = self.send_cipher.block_size();
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
        let mut iv = vec![0; self.send_cipher.block_size()];
        getrandom::fill(&mut iv)
            .map_err(|_| OpenVpnDataCodecError::RandomFailed)?;
        self.encode_with_iv(packet_id, payload, &iv)
    }

    fn decode(
        &self,
        _aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<(u32, Vec<u8>), OpenVpnDataCodecError> {
        let hmac_size = self.auth.output_size();
        if payload.len() < hmac_size {
            return Err(OpenVpnDataCodecError::InvalidEncryptedPayload);
        }
        let (received_hmac, protected) = payload.split_at(hmac_size);
        if !self
            .auth
            .verify(&self.receive_hmac_key, protected, received_hmac)
        {
            return Err(OpenVpnDataCodecError::HmacVerificationFailed);
        }
        let plaintext = if self.receive_cipher == OpenVpnCbcCipher::None {
            protected.to_vec()
        } else {
            let block_size = self.receive_cipher.block_size();
            if protected.len() < block_size * 2
                || protected.len() % block_size != 0
            {
                return Err(OpenVpnDataCodecError::InvalidEncryptedPayload);
            }
            let (iv, ciphertext) = protected.split_at(block_size);
            self.receive_cipher.decrypt(
                &self.receive_cipher_key,
                iv,
                ciphertext,
            )?
        };
        if plaintext.len() < 4 {
            return Err(OpenVpnDataCodecError::InvalidEncryptedPayload);
        }
        let packet_id = u32::from_be_bytes(plaintext[..4].try_into().unwrap());
        if !self.replay_window.accept(packet_id) {
            return Err(OpenVpnDataCodecError::ReplayedPacket);
        }
        Ok((packet_id, plaintext[4..].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_material() -> Vec<u8> {
        (0..=u8::MAX).collect()
    }

    #[test]
    fn client_and_server_round_trip_every_supported_cbc_cipher() {
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
            let client = TlsCbcDataCodec::new(
                &key_material(),
                false,
                cipher,
                "SHA256",
                0,
                Duration::ZERO,
            )
            .unwrap();
            let server = TlsCbcDataCodec::new(
                &key_material(),
                true,
                cipher,
                "SHA256",
                0,
                Duration::ZERO,
            )
            .unwrap();
            let encoded = client.encode(11, b"ignored", b"payload").unwrap();
            assert_eq!(encoded.len(), client.encoded_length(7), "{cipher}");
            assert_eq!(
                server.decode(b"also ignored", &encoded).unwrap(),
                (11, b"payload".to_vec()),
                "{cipher}"
            );
        }
    }

    #[test]
    fn supports_all_openvpn_auth_digests_and_detects_tampering() {
        for auth in [
            "MD5",
            "SHA1",
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512",
            "RIPEMD160",
            "NONE",
        ] {
            let client = TlsCbcDataCodec::new(
                &key_material(),
                false,
                "AES-128-CBC",
                auth,
                0,
                Duration::ZERO,
            )
            .unwrap();
            let server = TlsCbcDataCodec::new(
                &key_material(),
                true,
                "AES-128-CBC",
                auth,
                0,
                Duration::ZERO,
            )
            .unwrap();
            let mut encoded = client.encode(1, &[], b"test").unwrap();
            let last = encoded.len() - 1;
            encoded[last] ^= 1;
            assert!(server.decode(&[], &encoded).is_err(), "{auth}");
        }
    }

    #[test]
    fn matches_go_aes_cbc_hmac_wire_vector() {
        let client = TlsCbcDataCodec::new(
            &key_material(),
            false,
            "AES-128-CBC",
            "SHA256",
            0,
            Duration::ZERO,
        )
        .unwrap();
        let iv: Vec<u8> = (0xa0..=0xaf).collect();
        assert_eq!(
            hex::encode(
                client
                    .encode_with_iv(0x0102_0304, b"sing-openvpn", &iv)
                    .unwrap()
            ),
            "d8ed4534b52e65b93814d61ea6cfb522bf754ad49aca68d5780acc06ed9e41e6a0a1a2a3a4a5a6a7a8a9aaabacadaeaf479dae89c2058a6051726c9601323eda17e519e1530955596ed3e7063506a54f"
        );
    }
}
