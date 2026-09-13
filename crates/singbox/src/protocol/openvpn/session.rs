use parking_lot::Mutex;

use super::{Opcode, Packet, PacketId, SessionId};

pub const KEY_ID_MAX_VALUE: u8 = 7;

pub const fn next_key_id(key_id: u8) -> u8 {
    if key_id >= KEY_ID_MAX_VALUE {
        1
    } else {
        key_id + 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NegotiationState {
    Initial = 1,
    PreStart = 2,
    Start = 3,
    ControlReady = 6,
}

#[derive(Debug, Clone)]
struct SessionInner {
    key_id: u8,
    local_session_id: SessionId,
    remote_session_id: Option<SessionId>,
    local_control_packet_id: PacketId,
    local_data_packet_id: PacketId,
    negotiation_state: NegotiationState,
}

#[derive(Debug)]
pub struct SessionManager {
    inner: Mutex<SessionInner>,
}

impl SessionManager {
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut id = [0_u8; 8];
        getrandom::fill(&mut id)?;
        Ok(Self::with_local_id(id))
    }

    pub fn with_local_id(local_session_id: SessionId) -> Self {
        Self {
            inner: Mutex::new(SessionInner {
                key_id: 0,
                local_session_id,
                remote_session_id: None,
                local_control_packet_id: 1,
                local_data_packet_id: 1,
                negotiation_state: NegotiationState::Initial,
            }),
        }
    }

    pub fn local_session_id(&self) -> SessionId {
        self.inner.lock().local_session_id
    }

    pub fn remote_session_id(&self) -> Option<SessionId> {
        self.inner.lock().remote_session_id
    }

    pub fn set_remote_session_id(&self, id: SessionId) {
        self.inner.lock().remote_session_id = Some(id);
    }

    pub fn current_key_id(&self) -> u8 {
        self.inner.lock().key_id
    }

    pub fn negotiation_state(&self) -> NegotiationState {
        self.inner.lock().negotiation_state
    }

    pub fn next_local_control_packet_id(&self) -> PacketId {
        self.inner.lock().local_control_packet_id
    }

    pub fn set_negotiation_state(&self, state: NegotiationState) {
        self.inner.lock().negotiation_state = state;
    }

    pub fn validate_incoming_remote_session_id(&self, packet: &Packet) -> bool {
        packet.acknowledgment_ids.is_empty()
            || (packet.remote_session_id != [0; 8]
                && packet.remote_session_id
                    == self.inner.lock().local_session_id)
    }

    pub fn validate_incoming_local_session_id(&self, packet: &Packet) -> bool {
        self.inner
            .lock()
            .remote_session_id
            .is_some_and(|id| packet.local_session_id == id)
    }

    pub fn renegotiation(&self, key_id: u8) -> Self {
        let inner = self.inner.lock();
        Self {
            inner: Mutex::new(SessionInner {
                key_id,
                local_session_id: inner.local_session_id,
                remote_session_id: inner.remote_session_id,
                local_control_packet_id: 1,
                local_data_packet_id: 1,
                negotiation_state: NegotiationState::Start,
            }),
        }
    }

    pub fn new_soft_reset_packet(&self) -> Result<Packet, SessionError> {
        let inner = self.inner.lock();
        let remote = inner
            .remote_session_id
            .ok_or(SessionError::MissingRemoteSessionId)?;
        let mut packet =
            Packet::new(Opcode::ControlSoftResetV1, inner.key_id, Vec::new());
        packet.local_session_id = inner.local_session_id;
        packet.remote_session_id = remote;
        Ok(packet)
    }

    pub fn new_acknowledgment_packet(
        &self,
        acknowledgment_ids: Vec<PacketId>,
    ) -> Result<Packet, SessionError> {
        let inner = self.inner.lock();
        let remote = inner
            .remote_session_id
            .ok_or(SessionError::MissingRemoteSessionId)?;
        let mut packet =
            Packet::new(Opcode::AcknowledgmentV1, inner.key_id, Vec::new());
        packet.local_session_id = inner.local_session_id;
        packet.remote_session_id = remote;
        packet.acknowledgment_ids = acknowledgment_ids;
        Ok(packet)
    }

    pub fn new_hard_reset_server_v2_packet(
        &self,
        acknowledgment_ids: Vec<PacketId>,
    ) -> Result<Packet, SessionError> {
        let inner = self.inner.lock();
        let mut packet = Packet::new(
            Opcode::ControlHardResetServerV2,
            inner.key_id,
            Vec::new(),
        );
        packet.local_session_id = inner.local_session_id;
        packet.acknowledgment_ids = acknowledgment_ids;
        if !packet.acknowledgment_ids.is_empty() {
            packet.remote_session_id = inner
                .remote_session_id
                .ok_or(SessionError::MissingRemoteSessionId)?;
        }
        Ok(packet)
    }

    pub fn new_control_packet(
        &self,
        opcode: Opcode,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Packet, SessionError> {
        if !opcode.is_control() {
            return Err(SessionError::InvalidOpcode);
        }
        let mut inner = self.inner.lock();
        if inner.local_control_packet_id == u32::MAX {
            return Err(SessionError::PacketIdExpired);
        }
        let id = inner.local_control_packet_id;
        inner.local_control_packet_id += 1;
        let mut packet = Packet::new(opcode, inner.key_id, payload);
        packet.local_session_id = inner.local_session_id;
        packet.remote_session_id = inner.remote_session_id.unwrap_or_default();
        packet.id = id;
        Ok(packet)
    }

    pub fn new_data_packet_ids(
        &self,
        opcode: Opcode,
        count: usize,
    ) -> Result<Vec<PacketId>, SessionError> {
        if !opcode.is_data() {
            return Err(SessionError::InvalidOpcode);
        }
        let mut inner = self.inner.lock();
        let count =
            u32::try_from(count).map_err(|_| SessionError::PacketIdExpired)?;
        let end = inner
            .local_data_packet_id
            .checked_add(count)
            .ok_or(SessionError::PacketIdExpired)?;
        let start = inner.local_data_packet_id;
        inner.local_data_packet_id = end;
        Ok((start..end).collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("missing remote OpenVPN session id")]
    MissingRemoteSessionId,
    #[error("OpenVPN packet id expired")]
    PacketIdExpired,
    #[error("invalid opcode for OpenVPN packet creation")]
    InvalidOpcode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_control_and_data_ids_and_wraps_key_id() {
        let manager = SessionManager::with_local_id(*b"local-id");
        assert_eq!(
            manager
                .new_control_packet(Opcode::ControlV1, [])
                .unwrap()
                .id,
            1
        );
        assert_eq!(
            manager
                .new_control_packet(Opcode::ControlV1, [])
                .unwrap()
                .id,
            2
        );
        assert_eq!(
            manager.new_data_packet_ids(Opcode::DataV2, 3).unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(next_key_id(0), 1);
        assert_eq!(next_key_id(7), 1);
    }

    #[test]
    fn validates_ack_session_ids() {
        let manager = SessionManager::with_local_id(*b"local-id");
        manager.set_remote_session_id(*b"remoteid");
        let mut ack = manager.new_acknowledgment_packet(vec![1]).unwrap();
        ack.remote_session_id = *b"local-id";
        assert!(manager.validate_incoming_remote_session_id(&ack));

        let mut incoming = Packet::new(Opcode::ControlV1, 0, Vec::new());
        incoming.local_session_id = *b"remoteid";
        assert!(manager.validate_incoming_local_session_id(&incoming));
    }
}
