use std::time::Duration;

use super::{
    Opcode, Packet, PacketError, SessionError, SessionManager,
    TlsControlProtection, append_tls_crypt_v2_wrapped_client_key,
    is_control_or_acknowledgment,
    tls_crypt_v2_server_requests_wrapped_client_key_resend,
};

pub const TLS_HANDSHAKE_RETRY_MAXIMUM: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRetrySchedule {
    current: Duration,
}

impl HandshakeRetrySchedule {
    pub fn new(initial: Duration) -> Self {
        Self { current: initial }
    }

    pub fn current(self) -> Duration {
        self.current
    }

    pub fn advance(&mut self) -> Duration {
        self.current = self
            .current
            .saturating_mul(2)
            .min(TLS_HANDSHAKE_RETRY_MAXIMUM);
        self.current
    }
}

pub fn build_client_hard_reset(
    session: &SessionManager,
    protection: &TlsControlProtection,
    wrapped_client_key: &[u8],
) -> Result<Vec<u8>, ResetError> {
    let opcode = if wrapped_client_key.is_empty() {
        Opcode::ControlHardResetClientV2
    } else {
        Opcode::ControlHardResetClientV3
    };
    let mut packet = Packet::new(opcode, session.current_key_id(), Vec::new());
    packet.local_session_id = session.local_session_id();
    let encoded = protection.encode(&packet.encode()?);
    Ok(append_tls_crypt_v2_wrapped_client_key(
        &encoded,
        wrapped_client_key,
        opcode,
    ))
}

pub fn accept_server_hard_reset(
    session: &SessionManager,
    protection: &mut TlsControlProtection,
    wrapped_client_key_present: bool,
    raw_packet: &[u8],
) -> Result<AcceptedServerReset, ResetError> {
    let packet = decode_handshake_packet(protection, raw_packet)?;
    if !matches!(
        packet.opcode,
        Opcode::ControlHardResetServerV1 | Opcode::ControlHardResetServerV2
    ) {
        return Err(ResetError::InvalidServerOpcode(packet.opcode));
    }
    if packet.key_id != session.current_key_id()
        || !session.validate_incoming_remote_session_id(&packet)
    {
        return Err(ResetError::InvalidServerReset);
    }
    session.set_remote_session_id(packet.local_session_id);
    let resend_wrapped_client_key = if wrapped_client_key_present
        && !packet.payload.is_empty()
    {
        tls_crypt_v2_server_requests_wrapped_client_key_resend(&packet.payload)
            .map_err(|error| ResetError::Protection(error.to_string()))?
    } else {
        false
    };
    Ok(AcceptedServerReset {
        packet,
        resend_wrapped_client_key,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedServerReset {
    pub packet: Packet,
    pub resend_wrapped_client_key: bool,
}

pub fn accept_initial_client_hard_reset(
    static_protection: &TlsControlProtection,
    raw_packet: &[u8],
) -> Result<(Packet, TlsControlProtection), ResetError> {
    let mut session_protection = static_protection.new_session_protection();
    let packet = decode_handshake_packet(&mut session_protection, raw_packet)?;
    validate_initial_client_reset(&packet)?;
    Ok((packet, session_protection))
}

pub fn validate_initial_client_reset(
    packet: &Packet,
) -> Result<(), ResetError> {
    if packet.key_id != 0 {
        return Err(ResetError::InvalidClientKeyId);
    }
    if !matches!(
        packet.opcode,
        Opcode::ControlHardResetClientV2 | Opcode::ControlHardResetClientV3
    ) {
        return Err(ResetError::InvalidClientOpcode(packet.opcode));
    }
    if packet.id != 0
        || !packet.acknowledgment_ids.is_empty()
        || !packet.payload.is_empty()
    {
        return Err(ResetError::InvalidClientState);
    }
    Ok(())
}

pub fn build_server_hard_reset(
    session: &SessionManager,
    protection: &TlsControlProtection,
    client_reset_packet_id: u32,
    early_negotiation_payload: Vec<u8>,
) -> Result<Vec<u8>, ResetError> {
    let mut packet = session
        .new_hard_reset_server_v2_packet(vec![client_reset_packet_id])?;
    packet.payload = early_negotiation_payload;
    Ok(protection.encode(&packet.encode()?))
}

pub fn decode_handshake_packet(
    protection: &mut TlsControlProtection,
    raw_packet: &[u8],
) -> Result<Packet, ResetError> {
    let opcode = raw_packet
        .first()
        .map(|header| Opcode::from_wire(header >> 3))
        .ok_or(ResetError::EmptyPacket)?;
    let decoded = if is_control_or_acknowledgment(opcode) {
        protection
            .decode(raw_packet)
            .map_err(|error| ResetError::Protection(error.to_string()))?
    } else {
        raw_packet.to_vec()
    };
    Ok(Packet::parse(&decoded)?)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResetError {
    #[error("empty OpenVPN TLS reset packet")]
    EmptyPacket,
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("OpenVPN control protection: {0}")]
    Protection(String),
    #[error("invalid OpenVPN server reset opcode: {0}")]
    InvalidServerOpcode(Opcode),
    #[error("invalid OpenVPN server reset session state")]
    InvalidServerReset,
    #[error("invalid initial OpenVPN client reset key-id")]
    InvalidClientKeyId,
    #[error("invalid initial OpenVPN client reset opcode: {0}")]
    InvalidClientOpcode(Opcode),
    #[error("invalid initial OpenVPN client reset state")]
    InvalidClientState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_reset_exchange_establishes_session_ids() {
        let client = SessionManager::with_local_id(*b"clientid");
        let server = SessionManager::with_local_id(*b"serverid");
        let protection = TlsControlProtection::default();

        let client_wire =
            build_client_hard_reset(&client, &protection, &[]).unwrap();
        let (client_reset, server_protection) =
            accept_initial_client_hard_reset(&protection, &client_wire)
                .unwrap();
        assert_eq!(client_reset.opcode, Opcode::ControlHardResetClientV2);
        server.set_remote_session_id(client_reset.local_session_id);
        let server_wire = build_server_hard_reset(
            &server,
            &server_protection,
            client_reset.id,
            Vec::new(),
        )
        .unwrap();
        let accepted = accept_server_hard_reset(
            &client,
            &mut TlsControlProtection::default(),
            false,
            &server_wire,
        )
        .unwrap();
        assert_eq!(accepted.packet.local_session_id, *b"serverid");
        assert_eq!(client.remote_session_id(), Some(*b"serverid"));
    }

    #[test]
    fn validates_initial_reset_shape() {
        let mut packet =
            Packet::new(Opcode::ControlHardResetClientV2, 0, Vec::new());
        assert!(validate_initial_client_reset(&packet).is_ok());
        packet.id = 1;
        assert_eq!(
            validate_initial_client_reset(&packet),
            Err(ResetError::InvalidClientState)
        );
        packet.id = 0;
        packet.key_id = 1;
        assert_eq!(
            validate_initial_client_reset(&packet),
            Err(ResetError::InvalidClientKeyId)
        );
    }

    #[test]
    fn retry_timeout_doubles_with_sixty_second_cap() {
        let mut schedule = HandshakeRetrySchedule::new(Duration::from_secs(5));
        assert_eq!(schedule.current(), Duration::from_secs(5));
        assert_eq!(schedule.advance(), Duration::from_secs(10));
        assert_eq!(schedule.advance(), Duration::from_secs(20));
        assert_eq!(schedule.advance(), Duration::from_secs(40));
        assert_eq!(schedule.advance(), Duration::from_secs(60));
        assert_eq!(schedule.advance(), Duration::from_secs(60));
    }
}
