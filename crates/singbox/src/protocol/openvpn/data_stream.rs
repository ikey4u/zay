use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    OpenVpnAuthDigest, OpenVpnCbcCipher, OpenVpnDataCodec,
    OpenVpnDataCodecError, OpenVpnStreamMode, ReplayWindow,
    data_replay_window_parameters, openvpn_stream_cipher_spec,
    split_static_key_material, tls_data_key_slots,
};

/// OpenVPN's retained full-block CFB/OFB data-channel compatibility mode.
pub struct TlsStreamDataCodec {
    mode: OpenVpnStreamMode,
    send_cipher: OpenVpnCbcCipher,
    send_cipher_key: Vec<u8>,
    send_hmac_key: Vec<u8>,
    receive_cipher: OpenVpnCbcCipher,
    receive_cipher_key: Vec<u8>,
    receive_hmac_key: Vec<u8>,
    auth: OpenVpnAuthDigest,
    send_timestamp: u32,
    replay_window: ReplayWindow,
}

impl TlsStreamDataCodec {
    pub fn new(
        key_material: &[u8],
        server: bool,
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
            key_material,
            server,
            cipher_name,
            auth_name,
            replay_window_size,
            replay_window_time,
            timestamp,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_at(
        key_material: &[u8],
        server: bool,
        cipher_name: &str,
        auth_name: &str,
        replay_window_size: u32,
        replay_window_time: Duration,
        send_timestamp: u32,
    ) -> Result<Self, OpenVpnDataCodecError> {
        let slots = split_static_key_material(key_material)
            .ok_or(OpenVpnDataCodecError::InvalidKeyMaterial)?;
        let (send_slot, receive_slot) = tls_data_key_slots(slots, server);
        let (mode, cipher) = openvpn_stream_cipher_spec(cipher_name)?;
        let auth = OpenVpnAuthDigest::from_name(auth_name)?;
        let key_size = cipher.key_size();
        let hmac_size = auth.output_size();
        let (replay_window_size, replay_window_time) =
            data_replay_window_parameters(
                replay_window_size,
                replay_window_time,
            );
        Ok(Self {
            mode,
            send_cipher: cipher,
            send_cipher_key: send_slot.cipher_key[..key_size].to_vec(),
            send_hmac_key: send_slot.hmac_key[..hmac_size].to_vec(),
            receive_cipher: cipher,
            receive_cipher_key: receive_slot.cipher_key[..key_size].to_vec(),
            receive_hmac_key: receive_slot.hmac_key[..hmac_size].to_vec(),
            auth,
            send_timestamp,
            replay_window: ReplayWindow::new(
                replay_window_size,
                replay_window_time,
            ),
        })
    }
}

impl OpenVpnDataCodec for TlsStreamDataCodec {
    fn encoded_length(&self, payload_length: usize) -> usize {
        self.auth.output_size() + self.send_cipher.block_size() + payload_length
    }

    fn encode(
        &self,
        packet_id: u32,
        _aad_prefix: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        if packet_id == 0 {
            return Err(OpenVpnDataCodecError::InvalidPacketId);
        }
        let mut iv = vec![0; self.send_cipher.block_size()];
        iv[..4].copy_from_slice(&packet_id.to_be_bytes());
        iv[4..8].copy_from_slice(&self.send_timestamp.to_be_bytes());
        let ciphertext = self.send_cipher.crypt_stream(
            self.mode,
            &self.send_cipher_key,
            &iv,
            payload,
            true,
        )?;
        let mut protected = Vec::with_capacity(iv.len() + ciphertext.len());
        protected.extend_from_slice(&iv);
        protected.extend_from_slice(&ciphertext);
        let mut output =
            Vec::with_capacity(self.auth.output_size() + protected.len());
        output.extend_from_slice(
            &self.auth.sign(&self.send_hmac_key, &protected),
        );
        output.extend_from_slice(&protected);
        Ok(output)
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
        let block_size = self.receive_cipher.block_size();
        if protected.len() <= block_size {
            return Err(OpenVpnDataCodecError::InvalidEncryptedPayload);
        }
        let (iv, ciphertext) = protected.split_at(block_size);
        let packet_id = u32::from_be_bytes(iv[..4].try_into().unwrap());
        let timestamp = u32::from_be_bytes(iv[4..8].try_into().unwrap());
        let plaintext = self.receive_cipher.crypt_stream(
            self.mode,
            &self.receive_cipher_key,
            iv,
            ciphertext,
            false,
        )?;
        if !self.replay_window.accept_long_form(packet_id, timestamp) {
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
    fn round_trips_every_openvpn_cfb_and_ofb_cipher() {
        for base in [
            "BF",
            "DES",
            "DES-EDE",
            "DES-EDE3",
            "CAST5",
            "AES-128",
            "AES-192",
            "AES-256",
            "ARIA-128",
            "ARIA-192",
            "ARIA-256",
            "CAMELLIA-128",
            "CAMELLIA-192",
            "CAMELLIA-256",
            "SEED",
            "SM4",
        ] {
            for mode in ["CFB", "OFB"] {
                let cipher_name = format!("{base}-{mode}");
                let client = TlsStreamDataCodec::new_at(
                    &key_material(),
                    false,
                    &cipher_name,
                    "SHA1",
                    0,
                    Duration::ZERO,
                    100,
                )
                .unwrap();
                let server = TlsStreamDataCodec::new_at(
                    &key_material(),
                    true,
                    &cipher_name,
                    "SHA1",
                    0,
                    Duration::ZERO,
                    100,
                )
                .unwrap();
                let encoded = client
                    .encode(4, &[], b"stream payload")
                    .unwrap_or_else(|error| panic!("{cipher_name}: {error}"));
                assert_eq!(
                    server.decode(&[], &encoded).unwrap_or_else(
                        |error| panic!("{cipher_name}: {error}")
                    ),
                    (4, b"stream payload".to_vec()),
                    "{cipher_name}"
                );
            }
        }
    }

    #[test]
    fn matches_go_aes_cfb_hmac_wire_vector() {
        let client = TlsStreamDataCodec::new_at(
            &key_material(),
            false,
            "AES-128-CFB",
            "SHA256",
            0,
            Duration::ZERO,
            0x1122_3344,
        )
        .unwrap();
        assert_eq!(
            hex::encode(
                client.encode(0x0102_0304, &[], b"sing-openvpn").unwrap()
            ),
            "06fcb7ae209190cee6e301eda3d303cc3c518addf2978a09a82ede2a458f80580102030411223344000000000000000008ad1e06295e018e2e79834c"
        );
    }

    #[test]
    fn rejects_empty_ciphertext_and_replay() {
        let client = TlsStreamDataCodec::new_at(
            &key_material(),
            false,
            "AES-256-OFB",
            "NONE",
            0,
            Duration::ZERO,
            1,
        )
        .unwrap();
        let server = TlsStreamDataCodec::new_at(
            &key_material(),
            true,
            "AES-256-OFB",
            "NONE",
            0,
            Duration::ZERO,
            1,
        )
        .unwrap();
        assert_eq!(
            server.decode(&[], &[0; 16]),
            Err(OpenVpnDataCodecError::InvalidEncryptedPayload)
        );
        let packet = client.encode(1, &[], b"x").unwrap();
        assert!(server.decode(&[], &packet).is_ok());
        assert_eq!(
            server.decode(&[], &packet),
            Err(OpenVpnDataCodecError::ReplayedPacket)
        );
    }
}
