use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use ctr::cipher::{KeyIvInit, StreamCipher};

use super::{
    DEFAULT_REPLAY_WINDOW_SIZE, DEFAULT_REPLAY_WINDOW_TIME, Opcode,
    OpenVpnAuthDigest, ReplayWindow, parse_openvpn_static_key,
    split_static_key_material,
};

pub const TLS_CONTROL_HEADER_LENGTH: usize = 9;
pub const TLS_CONTROL_PACKET_ID_LENGTH: usize = 8;
pub const TLS_CRYPT_TAG_LENGTH: usize = 32;
pub const TLS_CRYPT_BLOCK_LENGTH: usize = 16;
pub const TLS_CRYPT_V2_CLIENT_PEM_TYPE: &str =
    "OpenVPN tls-crypt-v2 client key";
pub const TLS_CRYPT_V2_SERVER_PEM_TYPE: &str =
    "OpenVPN tls-crypt-v2 server key";
pub const TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH: usize = 256;
pub const TLS_CRYPT_V2_SERVER_KEY_LENGTH: usize = 128;
pub const TLS_CRYPT_KEY_DIRECTION_NORMAL: i8 = 0;
pub const TLS_CRYPT_KEY_DIRECTION_INVERSE: i8 = 1;
pub const TLS_CRYPT_V2_EARLY_NEGOTIATION_START: u32 = 0x0f00_0000;
pub const TLS_CRYPT_V2_TLV_TYPE_EARLY_NEGOTIATION_FLAGS: u16 = 1;
pub const TLS_CRYPT_V2_EARLY_NEGOTIATION_FLAG_RESEND_WKC: u16 = 1;

#[derive(Debug)]
struct PacketIdState {
    next_id: AtomicU32,
    timestamp: AtomicU32,
}

impl Default for PacketIdState {
    fn default() -> Self {
        Self {
            next_id: AtomicU32::new(0),
            timestamp: AtomicU32::new(0),
        }
    }
}

impl PacketIdState {
    fn seed_next_id(&self, next_id: u32) {
        self.next_id.store(next_id, Ordering::SeqCst);
        if self.timestamp.load(Ordering::Relaxed) == 0 {
            self.timestamp.store(unix_timestamp(), Ordering::SeqCst);
        }
    }

    fn next(&self) -> [u8; TLS_CONTROL_PACKET_ID_LENGTH] {
        loop {
            let current = self.next_id.load(Ordering::Relaxed);
            let wraps = current == u32::MAX;
            let next = if wraps { 1 } else { current + 1 };
            if self
                .next_id
                .compare_exchange(
                    current,
                    next,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let now = unix_timestamp();
                let timestamp =
                    if wraps || self.timestamp.load(Ordering::Relaxed) == 0 {
                        self.timestamp.fetch_max(now, Ordering::SeqCst).max(now)
                    } else {
                        self.timestamp.load(Ordering::Relaxed)
                    };
                let mut packet_id = [0; TLS_CONTROL_PACKET_ID_LENGTH];
                packet_id[..4].copy_from_slice(&next.to_be_bytes());
                packet_id[4..].copy_from_slice(&timestamp.to_be_bytes());
                return packet_id;
            }
        }
    }

    #[cfg(test)]
    fn set(&self, next_id: u32, timestamp: u32) {
        self.next_id.store(next_id, Ordering::Relaxed);
        self.timestamp.store(timestamp, Ordering::Relaxed);
    }
}

fn unix_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

#[derive(Debug)]
pub struct ControlAuthCodec {
    send_key: Vec<u8>,
    receive_keys: Vec<Vec<u8>>,
    send_state: PacketIdState,
    receive_state: ReplayWindow,
    auth: OpenVpnAuthDigest,
}

impl ControlAuthCodec {
    pub fn new(
        static_key: &[u8],
        key_direction: i8,
        auth_name: &str,
    ) -> Result<Self, ControlWrapError> {
        let material = parse_openvpn_static_key(static_key)
            .map_err(|error| ControlWrapError::Key(error.to_string()))?;
        let auth = OpenVpnAuthDigest::from_name(auth_name)
            .map_err(|error| ControlWrapError::Key(error.to_string()))?;
        if auth == OpenVpnAuthDigest::None {
            return Err(ControlWrapError::NoneAuth);
        }
        let slots = split_static_key_material(&material).ok_or_else(|| {
            ControlWrapError::Key("invalid key material".into())
        })?;
        let (send, receive, fallback) = resolve_direction(key_direction);
        let digest_size = auth.output_size();
        let mut receive_keys =
            vec![slots[receive].hmac_key[..digest_size].to_vec()];
        if fallback != receive {
            receive_keys.push(slots[fallback].hmac_key[..digest_size].to_vec());
        }
        Ok(Self {
            send_key: slots[send].hmac_key[..digest_size].to_vec(),
            receive_keys,
            send_state: PacketIdState::default(),
            receive_state: ReplayWindow::new(
                DEFAULT_REPLAY_WINDOW_SIZE,
                DEFAULT_REPLAY_WINDOW_TIME,
            ),
            auth,
        })
    }

    pub fn new_session_codec(&self) -> Self {
        Self {
            send_key: self.send_key.clone(),
            receive_keys: self.receive_keys.clone(),
            send_state: PacketIdState::default(),
            receive_state: ReplayWindow::new(
                DEFAULT_REPLAY_WINDOW_SIZE,
                DEFAULT_REPLAY_WINDOW_TIME,
            ),
            auth: self.auth,
        }
    }

    pub fn digest_size(&self) -> usize {
        self.auth.output_size()
    }

    pub fn seed_next_packet_id(&self, next_id: u32) {
        self.send_state.seed_next_id(next_id);
    }

    pub fn encode(&self, raw_packet: &[u8]) -> Vec<u8> {
        if raw_packet.len() < TLS_CONTROL_HEADER_LENGTH {
            return raw_packet.to_vec();
        }
        let packet_id = self.send_state.next();
        let mut auth_input =
            Vec::with_capacity(packet_id.len() + raw_packet.len());
        auth_input.extend_from_slice(&packet_id);
        auth_input.extend_from_slice(raw_packet);
        let digest = self.auth.sign(&self.send_key, &auth_input);
        let mut output = Vec::with_capacity(
            raw_packet.len() + digest.len() + packet_id.len(),
        );
        output.extend_from_slice(&raw_packet[..TLS_CONTROL_HEADER_LENGTH]);
        output.extend_from_slice(&digest);
        output.extend_from_slice(&packet_id);
        output.extend_from_slice(&raw_packet[TLS_CONTROL_HEADER_LENGTH..]);
        output
    }

    pub fn decode(
        &self,
        raw_packet: &[u8],
    ) -> Result<Vec<u8>, ControlWrapError> {
        let digest_size = self.auth.output_size();
        if raw_packet.len()
            < TLS_CONTROL_HEADER_LENGTH
                + digest_size
                + TLS_CONTROL_PACKET_ID_LENGTH
        {
            return Err(ControlWrapError::InvalidPacket);
        }
        let header = &raw_packet[..TLS_CONTROL_HEADER_LENGTH];
        let digest = &raw_packet[TLS_CONTROL_HEADER_LENGTH
            ..TLS_CONTROL_HEADER_LENGTH + digest_size];
        let packet_id_start = TLS_CONTROL_HEADER_LENGTH + digest_size;
        let packet_id = &raw_packet
            [packet_id_start..packet_id_start + TLS_CONTROL_PACKET_ID_LENGTH];
        let body =
            &raw_packet[packet_id_start + TLS_CONTROL_PACKET_ID_LENGTH..];
        let mut auth_input =
            Vec::with_capacity(packet_id.len() + header.len() + body.len());
        auth_input.extend_from_slice(packet_id);
        auth_input.extend_from_slice(header);
        auth_input.extend_from_slice(body);
        for key in &self.receive_keys {
            if !self.auth.verify(key, &auth_input, digest) {
                continue;
            }
            accept_control_packet_id(&self.receive_state, packet_id)?;
            let mut decoded = Vec::with_capacity(header.len() + body.len());
            decoded.extend_from_slice(header);
            decoded.extend_from_slice(body);
            return Ok(decoded);
        }
        Err(ControlWrapError::AuthenticationFailed)
    }
}

#[derive(Debug, Clone)]
struct CryptCandidate {
    encrypt_key: [u8; 32],
    auth_key: [u8; 32],
}

#[derive(Debug)]
pub struct ControlCryptCodec {
    send: CryptCandidate,
    receive_candidates: Vec<CryptCandidate>,
    send_state: PacketIdState,
    receive_state: ReplayWindow,
}

impl ControlCryptCodec {
    pub fn new(
        static_key: &[u8],
        key_direction: i8,
    ) -> Result<Self, ControlWrapError> {
        let material = parse_openvpn_static_key(static_key)
            .map_err(|error| ControlWrapError::Key(error.to_string()))?;
        Self::from_material(&material, key_direction)
    }

    pub fn from_material(
        material: &[u8],
        key_direction: i8,
    ) -> Result<Self, ControlWrapError> {
        let slots = split_static_key_material(material).ok_or_else(|| {
            ControlWrapError::Key("invalid key material".into())
        })?;
        let (send, receive, fallback) = resolve_direction(key_direction);
        let candidate = |index: usize| CryptCandidate {
            encrypt_key: slots[index].cipher_key[..32].try_into().unwrap(),
            auth_key: slots[index].hmac_key[..32].try_into().unwrap(),
        };
        let mut receive_candidates = vec![candidate(receive)];
        if fallback != receive {
            receive_candidates.push(candidate(fallback));
        }
        Ok(Self {
            send: candidate(send),
            receive_candidates,
            send_state: PacketIdState::default(),
            receive_state: ReplayWindow::new(
                DEFAULT_REPLAY_WINDOW_SIZE,
                DEFAULT_REPLAY_WINDOW_TIME,
            ),
        })
    }

    pub fn new_session_codec(&self) -> Self {
        Self {
            send: self.send.clone(),
            receive_candidates: self.receive_candidates.clone(),
            send_state: PacketIdState::default(),
            receive_state: ReplayWindow::new(
                DEFAULT_REPLAY_WINDOW_SIZE,
                DEFAULT_REPLAY_WINDOW_TIME,
            ),
        }
    }

    pub fn seed_next_packet_id(&self, next_id: u32) {
        self.send_state.seed_next_id(next_id);
    }

    pub fn encode(&self, raw_packet: &[u8]) -> Vec<u8> {
        if raw_packet.len() < TLS_CONTROL_HEADER_LENGTH {
            return raw_packet.to_vec();
        }
        let header = &raw_packet[..TLS_CONTROL_HEADER_LENGTH];
        let body = &raw_packet[TLS_CONTROL_HEADER_LENGTH..];
        let packet_id = self.send_state.next();
        let mut authenticated =
            Vec::with_capacity(header.len() + packet_id.len() + body.len());
        authenticated.extend_from_slice(header);
        authenticated.extend_from_slice(&packet_id);
        authenticated.extend_from_slice(body);
        let tag =
            OpenVpnAuthDigest::Sha256.sign(&self.send.auth_key, &authenticated);
        let ciphertext = aes256_ctr(&self.send.encrypt_key, &tag[..16], body);
        let mut output = Vec::with_capacity(
            header.len() + packet_id.len() + tag.len() + ciphertext.len(),
        );
        output.extend_from_slice(header);
        output.extend_from_slice(&packet_id);
        output.extend_from_slice(&tag);
        output.extend_from_slice(&ciphertext);
        output
    }

    pub fn decode(
        &self,
        raw_packet: &[u8],
    ) -> Result<Vec<u8>, ControlWrapError> {
        if raw_packet.len()
            < TLS_CONTROL_HEADER_LENGTH
                + TLS_CONTROL_PACKET_ID_LENGTH
                + TLS_CRYPT_TAG_LENGTH
        {
            return Err(ControlWrapError::InvalidPacket);
        }
        let header = &raw_packet[..TLS_CONTROL_HEADER_LENGTH];
        let packet_id = &raw_packet[TLS_CONTROL_HEADER_LENGTH
            ..TLS_CONTROL_HEADER_LENGTH + TLS_CONTROL_PACKET_ID_LENGTH];
        let tag_start =
            TLS_CONTROL_HEADER_LENGTH + TLS_CONTROL_PACKET_ID_LENGTH;
        let tag = &raw_packet[tag_start..tag_start + TLS_CRYPT_TAG_LENGTH];
        let ciphertext = &raw_packet[tag_start + TLS_CRYPT_TAG_LENGTH..];
        for candidate in &self.receive_candidates {
            let plaintext =
                aes256_ctr(&candidate.encrypt_key, &tag[..16], ciphertext);
            let mut authenticated = Vec::with_capacity(
                header.len() + packet_id.len() + plaintext.len(),
            );
            authenticated.extend_from_slice(header);
            authenticated.extend_from_slice(packet_id);
            authenticated.extend_from_slice(&plaintext);
            if !OpenVpnAuthDigest::Sha256.verify(
                &candidate.auth_key,
                &authenticated,
                tag,
            ) {
                continue;
            }
            accept_control_packet_id(&self.receive_state, packet_id)?;
            let mut decoded =
                Vec::with_capacity(header.len() + plaintext.len());
            decoded.extend_from_slice(header);
            decoded.extend_from_slice(&plaintext);
            return Ok(decoded);
        }
        Err(ControlWrapError::AuthenticationFailed)
    }
}

fn aes256_ctr(key: &[u8; 32], iv: &[u8], input: &[u8]) -> Vec<u8> {
    let mut output = input.to_vec();
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv)
        .expect("fixed AES-256 key and 128-bit IV");
    cipher.apply_keystream(&mut output);
    output
}

fn accept_control_packet_id(
    replay: &ReplayWindow,
    packet_id: &[u8],
) -> Result<(), ControlWrapError> {
    let id = u32::from_be_bytes(packet_id[..4].try_into().unwrap());
    let timestamp = u32::from_be_bytes(packet_id[4..8].try_into().unwrap());
    replay
        .accept_long_form(id, timestamp)
        .then_some(())
        .ok_or(ControlWrapError::ReplayedPacket)
}

fn resolve_direction(direction: i8) -> (usize, usize, usize) {
    if matches!(direction, 1 | 2) {
        (1, 0, 1)
    } else if direction < 0 {
        (0, 0, 1)
    } else {
        (0, 1, 0)
    }
}

#[derive(Debug, Default)]
pub struct TlsControlProtection {
    pub auth: Option<ControlAuthCodec>,
    pub crypt: Option<ControlCryptCodec>,
    pub crypt_v2_server_key: Vec<u8>,
}

impl TlsControlProtection {
    pub fn new_session_protection(&self) -> Self {
        Self {
            auth: self.auth.as_ref().map(ControlAuthCodec::new_session_codec),
            crypt: self
                .crypt
                .as_ref()
                .map(ControlCryptCodec::new_session_codec),
            crypt_v2_server_key: self.crypt_v2_server_key.clone(),
        }
    }

    pub fn control_packet_overhead(&self) -> usize {
        if self.crypt.is_some() || !self.crypt_v2_server_key.is_empty() {
            TLS_CONTROL_PACKET_ID_LENGTH
                + TLS_CRYPT_TAG_LENGTH
                + TLS_CRYPT_BLOCK_LENGTH
        } else if let Some(auth) = &self.auth {
            auth.digest_size() + TLS_CONTROL_PACKET_ID_LENGTH
        } else {
            0
        }
    }

    pub fn encode(&self, raw_packet: &[u8]) -> Vec<u8> {
        if let Some(crypt) = &self.crypt {
            crypt.encode(raw_packet)
        } else if let Some(auth) = &self.auth {
            auth.encode(raw_packet)
        } else {
            raw_packet.to_vec()
        }
    }

    pub fn decode(
        &mut self,
        raw_packet: &[u8],
    ) -> Result<Vec<u8>, ControlWrapError> {
        if raw_packet.len() < TLS_CONTROL_HEADER_LENGTH {
            return Err(ControlWrapError::InvalidPacket);
        }
        let opcode = Opcode::from_wire(raw_packet[0] >> 3);
        let packet = if matches!(
            opcode,
            Opcode::ControlHardResetClientV3 | Opcode::ControlWkcV1
        ) {
            self.extract_tls_crypt_v2_client_key(raw_packet)?
        } else {
            raw_packet.to_vec()
        };
        if let Some(crypt) = &self.crypt {
            crypt.decode(&packet)
        } else if let Some(auth) = &self.auth {
            auth.decode(&packet)
        } else if !self.crypt_v2_server_key.is_empty() {
            Err(ControlWrapError::MissingWrappedClientKey)
        } else {
            Ok(packet)
        }
    }

    fn extract_tls_crypt_v2_client_key(
        &mut self,
        raw_packet: &[u8],
    ) -> Result<Vec<u8>, ControlWrapError> {
        if self.crypt_v2_server_key.is_empty() {
            return Err(ControlWrapError::MissingServerKey);
        }
        if raw_packet.len() < TLS_CONTROL_HEADER_LENGTH + 2 {
            return Err(ControlWrapError::InvalidV2WrappedKey);
        }
        let wrapped_length = u16::from_be_bytes(
            raw_packet[raw_packet.len() - 2..].try_into().unwrap(),
        ) as usize;
        if wrapped_length < TLS_CRYPT_TAG_LENGTH + 2
            || wrapped_length > raw_packet.len() - TLS_CONTROL_HEADER_LENGTH
        {
            return Err(ControlWrapError::InvalidV2WrappedKey);
        }
        let packet_end = raw_packet.len() - wrapped_length;
        if self.crypt.is_none() {
            let material = unwrap_tls_crypt_v2_client_key(
                &raw_packet[packet_end..],
                &self.crypt_v2_server_key,
            )?;
            self.crypt = Some(ControlCryptCodec::from_material(
                &material,
                TLS_CRYPT_KEY_DIRECTION_NORMAL,
            )?);
        }
        Ok(raw_packet[..packet_end].to_vec())
    }
}

pub fn tls_crypt_v2_reset_announces_early_negotiation(
    raw_packet: &[u8],
) -> bool {
    if raw_packet.len() < TLS_CONTROL_HEADER_LENGTH + 4 {
        return false;
    }
    let packet_id = u32::from_be_bytes(
        raw_packet[TLS_CONTROL_HEADER_LENGTH..TLS_CONTROL_HEADER_LENGTH + 4]
            .try_into()
            .unwrap(),
    );
    packet_id & TLS_CRYPT_V2_EARLY_NEGOTIATION_START
        == TLS_CRYPT_V2_EARLY_NEGOTIATION_START
}

pub fn parse_tls_crypt_v2_early_negotiation_flags(
    mut payload: &[u8],
) -> Result<u16, ControlWrapError> {
    let mut flags = 0;
    while !payload.is_empty() {
        if payload.len() < 4 {
            return Err(ControlWrapError::MalformedEarlyNegotiation);
        }
        let kind = u16::from_be_bytes(payload[..2].try_into().unwrap());
        let length =
            u16::from_be_bytes(payload[2..4].try_into().unwrap()) as usize;
        payload = &payload[4..];
        if payload.len() < length {
            return Err(ControlWrapError::MalformedEarlyNegotiation);
        }
        let value = &payload[..length];
        payload = &payload[length..];
        if kind == TLS_CRYPT_V2_TLV_TYPE_EARLY_NEGOTIATION_FLAGS {
            if length != 2 {
                return Err(ControlWrapError::MalformedEarlyNegotiation);
            }
            flags |= u16::from_be_bytes(value.try_into().unwrap());
        }
    }
    Ok(flags)
}

pub fn tls_crypt_v2_server_requests_wrapped_client_key_resend(
    payload: &[u8],
) -> Result<bool, ControlWrapError> {
    Ok(parse_tls_crypt_v2_early_negotiation_flags(payload)?
        & TLS_CRYPT_V2_EARLY_NEGOTIATION_FLAG_RESEND_WKC
        != 0)
}

pub fn append_tls_crypt_v2_wrapped_client_key(
    raw_packet: &[u8],
    wrapped_client_key: &[u8],
    opcode: Opcode,
) -> Vec<u8> {
    let mut output = raw_packet.to_vec();
    if !wrapped_client_key.is_empty()
        && matches!(
            opcode,
            Opcode::ControlHardResetClientV3 | Opcode::ControlWkcV1
        )
    {
        output.extend_from_slice(wrapped_client_key);
    }
    output
}

pub fn load_tls_crypt_v2_client_key(
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ControlWrapError> {
    let key = load_named_pem(input, TLS_CRYPT_V2_CLIENT_PEM_TYPE)?;
    if key.len() < TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH {
        return Err(ControlWrapError::InvalidV2ClientKey);
    }
    let (material, wrapped) = key.split_at(TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH);
    if wrapped.is_empty() {
        return Err(ControlWrapError::MissingWrappedClientKey);
    }
    Ok((material.to_vec(), wrapped.to_vec()))
}

pub fn load_tls_crypt_v2_server_key(
    input: &[u8],
) -> Result<Vec<u8>, ControlWrapError> {
    let key = load_named_pem(input, TLS_CRYPT_V2_SERVER_PEM_TYPE)?;
    if key.len() < TLS_CRYPT_V2_SERVER_KEY_LENGTH {
        return Err(ControlWrapError::InvalidV2ServerKey);
    }
    Ok(key[..TLS_CRYPT_V2_SERVER_KEY_LENGTH].to_vec())
}

fn load_named_pem(
    input: &[u8],
    expected_type: &str,
) -> Result<Vec<u8>, ControlWrapError> {
    let block = pem::parse(input).map_err(|_| ControlWrapError::InvalidPem)?;
    if block.tag() != expected_type {
        return Err(ControlWrapError::InvalidPem);
    }
    Ok(block.contents().to_vec())
}

pub fn unwrap_tls_crypt_v2_client_key(
    wrapped: &[u8],
    server_key: &[u8],
) -> Result<Vec<u8>, ControlWrapError> {
    if server_key.len() < TLS_CRYPT_V2_SERVER_KEY_LENGTH {
        return Err(ControlWrapError::InvalidV2ServerKey);
    }
    if wrapped.len() < TLS_CRYPT_TAG_LENGTH + 2 {
        return Err(ControlWrapError::InvalidV2WrappedKey);
    }
    let net_length =
        u16::from_be_bytes(wrapped[wrapped.len() - 2..].try_into().unwrap())
            as usize;
    if net_length != wrapped.len() {
        return Err(ControlWrapError::InvalidV2WrappedKeyLength);
    }
    let tag = &wrapped[..TLS_CRYPT_TAG_LENGTH];
    let ciphertext = &wrapped[TLS_CRYPT_TAG_LENGTH..wrapped.len() - 2];
    let plaintext = aes256_ctr(
        server_key[..32].try_into().unwrap(),
        &tag[..16],
        ciphertext,
    );
    let length = &wrapped[wrapped.len() - 2..];
    let mut authenticated = Vec::with_capacity(2 + plaintext.len());
    authenticated.extend_from_slice(length);
    authenticated.extend_from_slice(&plaintext);
    if !OpenVpnAuthDigest::Sha256.verify(
        &server_key[64..96],
        &authenticated,
        tag,
    ) {
        return Err(ControlWrapError::AuthenticationFailed);
    }
    if plaintext.len() < TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH {
        return Err(ControlWrapError::V2PlaintextTooShort);
    }
    Ok(plaintext[..TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH].to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlWrapError {
    #[error("invalid OpenVPN control packet")]
    InvalidPacket,
    #[error("OpenVPN control packet authentication failed")]
    AuthenticationFailed,
    #[error("replayed OpenVPN control packet")]
    ReplayedPacket,
    #[error("tls-auth requires a non-NONE auth algorithm")]
    NoneAuth,
    #[error("invalid OpenVPN control key: {0}")]
    Key(String),
    #[error("missing tls-crypt-v2 wrapped client key")]
    MissingWrappedClientKey,
    #[error("peer requested tls-crypt-v2 without a server key")]
    MissingServerKey,
    #[error("invalid tls-crypt-v2 wrapped key")]
    InvalidV2WrappedKey,
    #[error("invalid tls-crypt-v2 wrapped key length")]
    InvalidV2WrappedKeyLength,
    #[error("invalid tls-crypt-v2 client key")]
    InvalidV2ClientKey,
    #[error("invalid tls-crypt-v2 server key")]
    InvalidV2ServerKey,
    #[error("tls-crypt-v2 plaintext is too short")]
    V2PlaintextTooShort,
    #[error("malformed tls-crypt-v2 early negotiation data")]
    MalformedEarlyNegotiation,
    #[error("invalid tls-crypt-v2 PEM content")]
    InvalidPem,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_material() -> Vec<u8> {
        (0..=u8::MAX).collect()
    }

    fn raw_packet(opcode: Opcode) -> Vec<u8> {
        let mut packet = vec![opcode.wire_value() << 3];
        packet.extend_from_slice(b"session1");
        packet.extend_from_slice(b"control body");
        packet
    }

    #[test]
    fn tls_auth_round_trips_directions_and_rejects_replay() {
        let sender =
            ControlAuthCodec::new(&key_material(), 0, "SHA256").unwrap();
        let receiver =
            ControlAuthCodec::new(&key_material(), 1, "SHA256").unwrap();
        let raw = raw_packet(Opcode::ControlV1);
        let encoded = sender.encode(&raw);
        assert_eq!(receiver.decode(&encoded).unwrap(), raw);
        assert_eq!(
            receiver.decode(&encoded),
            Err(ControlWrapError::ReplayedPacket)
        );
    }

    #[test]
    fn tls_crypt_round_trips_directions_and_detects_tampering() {
        let sender = ControlCryptCodec::new(&key_material(), 0).unwrap();
        let receiver = ControlCryptCodec::new(&key_material(), 1).unwrap();
        let raw = raw_packet(Opcode::ControlV1);
        let mut encoded = sender.encode(&raw);
        assert_eq!(receiver.decode(&encoded).unwrap(), raw);
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert_eq!(
            receiver.decode(&encoded),
            Err(ControlWrapError::AuthenticationFailed)
        );
    }

    #[test]
    fn matches_go_tls_auth_and_tls_crypt_wire_vectors() {
        let auth = ControlAuthCodec::new(&key_material(), 0, "SHA256").unwrap();
        auth.send_state.set(0, 0x1122_3344);
        let raw = raw_packet(Opcode::ControlV1);
        assert_eq!(
            hex::encode(auth.encode(&raw)),
            "2073657373696f6e31df6155227e9837ec1c94632f35ce08bb6f48ce33ecca3912305f8d0e5fb604830000000111223344636f6e74726f6c20626f6479"
        );

        let crypt = ControlCryptCodec::new(&key_material(), 0).unwrap();
        crypt.send_state.set(0, 0x1122_3344);
        assert_eq!(
            hex::encode(crypt.encode(&raw)),
            "2073657373696f6e3100000001112233448552343776300ad78944f80c37bf3dff0d445fdba92033c33f6abc0f208d08176249350226a6f5a1f239a759"
        );
    }

    #[test]
    fn packet_id_state_wraps_and_advances_timestamp() {
        let state = PacketIdState::default();
        state.set(u32::MAX - 1, 1);
        let first = state.next();
        assert_eq!(
            u32::from_be_bytes(first[..4].try_into().unwrap()),
            u32::MAX
        );
        let second = state.next();
        assert_eq!(u32::from_be_bytes(second[..4].try_into().unwrap()), 1);
        assert!(u32::from_be_bytes(second[4..].try_into().unwrap()) >= 1);
    }

    #[test]
    fn parses_early_negotiation_tlvs() {
        let payload = [0, 9, 0, 1, 7, 0, 1, 0, 2, 0, 1];
        assert_eq!(parse_tls_crypt_v2_early_negotiation_flags(&payload), Ok(1));
        assert_eq!(
            tls_crypt_v2_server_requests_wrapped_client_key_resend(&payload),
            Ok(true)
        );
        assert_eq!(
            parse_tls_crypt_v2_early_negotiation_flags(&payload[..10]),
            Err(ControlWrapError::MalformedEarlyNegotiation)
        );
    }

    #[test]
    fn loads_v2_pem_keys_and_unwraps_client_material() {
        let material = key_material();
        let mut server_key = vec![0; TLS_CRYPT_V2_SERVER_KEY_LENGTH];
        for (index, byte) in server_key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let metadata = b"metadata";
        let mut plaintext = material.clone();
        plaintext.extend_from_slice(metadata);
        let wrapped_length = TLS_CRYPT_TAG_LENGTH + plaintext.len() + 2;
        let length = (wrapped_length as u16).to_be_bytes();
        let mut authenticated = Vec::new();
        authenticated.extend_from_slice(&length);
        authenticated.extend_from_slice(&plaintext);
        let tag =
            OpenVpnAuthDigest::Sha256.sign(&server_key[64..96], &authenticated);
        let ciphertext = aes256_ctr(
            server_key[..32].try_into().unwrap(),
            &tag[..16],
            &plaintext,
        );
        let mut wrapped = tag;
        wrapped.extend_from_slice(&ciphertext);
        wrapped.extend_from_slice(&length);
        assert_eq!(
            unwrap_tls_crypt_v2_client_key(&wrapped, &server_key).unwrap(),
            material
        );

        let client_pem = pem::encode(&pem::Pem::new(
            TLS_CRYPT_V2_CLIENT_PEM_TYPE,
            [material.as_slice(), wrapped.as_slice()].concat(),
        ));
        let server_pem = pem::encode(&pem::Pem::new(
            TLS_CRYPT_V2_SERVER_PEM_TYPE,
            server_key.clone(),
        ));
        assert_eq!(
            load_tls_crypt_v2_client_key(client_pem.as_bytes())
                .unwrap()
                .0,
            material
        );
        assert_eq!(
            load_tls_crypt_v2_server_key(server_pem.as_bytes()).unwrap(),
            server_key
        );
    }
}
