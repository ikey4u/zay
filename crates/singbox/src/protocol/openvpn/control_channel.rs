use std::{sync::Arc, time::Instant};

use super::{
    ACKNOWLEDGMENT_SET_CAPACITY, IncomingReliableState,
    MAXIMUM_ACKNOWLEDGMENTS_PER_PACKET, Opcode, OutgoingReliableState, Packet,
    PacketError, SessionError, SessionManager, TlsControlProtection,
    append_tls_crypt_v2_wrapped_client_key,
};

pub const TLS_CONTROL_PAYLOAD_SIZE: usize = 1024;
pub const TLS_CONTROL_CHANNEL_MTU: usize = 1250;
pub const IPV4_CONTROL_DATAGRAM_OVERHEAD: usize = 28;
pub const IPV6_CONTROL_DATAGRAM_OVERHEAD: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingControlEvent {
    TlsCiphertext(Vec<u8>),
    Data(Packet),
    HardReset(Packet),
    SoftReset(Packet),
}

/// Protocol core for one OpenVPN reliable TLS control key-state.
///
/// Link I/O stays outside this type so the same state machine can drive UDP,
/// TCP framing, injected transports, and deterministic tests.
#[derive(Debug)]
pub struct TlsControlChannelCore {
    session: Arc<SessionManager>,
    protection: TlsControlProtection,
    outgoing: OutgoingReliableState,
    incoming: IncomingReliableState,
    wrapped_client_key: Vec<u8>,
    remote_is_ipv6: bool,
}

impl TlsControlChannelCore {
    pub fn new(
        session: Arc<SessionManager>,
        protection: TlsControlProtection,
        wrapped_client_key: Vec<u8>,
        remote_is_ipv6: bool,
    ) -> Self {
        Self {
            session,
            protection,
            outgoing: OutgoingReliableState::new(),
            incoming: IncomingReliableState::new(),
            wrapped_client_key,
            remote_is_ipv6,
        }
    }

    pub fn session(&self) -> &Arc<SessionManager> {
        &self.session
    }

    pub fn seed_incoming_packet(&self, packet: &Packet) {
        if self.session.validate_incoming_remote_session_id(packet) {
            self.outgoing.on_incoming_packet(packet);
        }
    }

    pub fn ingest_link_packet(
        &mut self,
        raw_packet: &[u8],
    ) -> Result<Vec<IncomingControlEvent>, ControlChannelError> {
        let opcode = raw_packet
            .first()
            .map(|header| Opcode::from_wire(header >> 3))
            .ok_or(ControlChannelError::EmptyPacket)?;
        let decoded = if is_control_or_acknowledgment(opcode) {
            self.protection.decode(raw_packet).map_err(|error| {
                ControlChannelError::Protection(error.to_string())
            })?
        } else {
            raw_packet.to_vec()
        };
        let packet = Packet::parse(&decoded)?;
        if packet.opcode.is_data() {
            return Ok(vec![IncomingControlEvent::Data(packet)]);
        }
        if !self.session.validate_incoming_remote_session_id(&packet) {
            return Ok(Vec::new());
        }
        if is_tls_hard_reset_opcode(packet.opcode) {
            if packet.key_id != 0
                || self.session.current_key_id() != 0
                || !self.session.validate_incoming_local_session_id(&packet)
            {
                return Ok(Vec::new());
            }
            self.outgoing.on_incoming_packet(&packet);
            return Ok(vec![IncomingControlEvent::HardReset(packet)]);
        }
        if packet.opcode == Opcode::ControlSoftResetV1 {
            if !self.session.validate_incoming_local_session_id(&packet) {
                return Ok(Vec::new());
            }
            return Ok(vec![IncomingControlEvent::SoftReset(packet)]);
        }
        if !self.session.validate_incoming_local_session_id(&packet)
            || packet.key_id != self.session.current_key_id()
        {
            return Ok(Vec::new());
        }
        self.outgoing.on_incoming_packet(&packet);
        if packet.opcode == Opcode::AcknowledgmentV1
            || !packet.opcode.is_control()
        {
            return Ok(Vec::new());
        }
        if !self.incoming.try_insert_incoming_packet(packet) {
            return Ok(Vec::new());
        }
        Ok(self
            .incoming
            .next_ordered_sequence()
            .into_iter()
            .filter(|packet| !packet.payload.is_empty())
            .map(|packet| IncomingControlEvent::TlsCiphertext(packet.payload))
            .collect())
    }

    /// Consumes at most one reliable window slot and returns the corresponding
    /// link packet plus the number of TLS bytes consumed.
    pub fn packetize_tls_ciphertext(
        &self,
        ciphertext: &[u8],
    ) -> Result<Option<(Vec<u8>, usize)>, ControlChannelError> {
        if ciphertext.is_empty() {
            return Ok(None);
        }
        let pending = self.outgoing.pending_acknowledgment_count();
        let mut payload_size = TLS_CONTROL_PAYLOAD_SIZE
            .min(TLS_CONTROL_CHANNEL_MTU)
            .saturating_sub(self.control_channel_frame_overhead(pending));
        if self.next_packet_carries_wrapped_client_key() {
            payload_size =
                payload_size.saturating_sub(self.wrapped_client_key.len());
        }
        let consumed = ciphertext.len().min(payload_size);
        let packet = self.outgoing.insert_outgoing_packet(
            MAXIMUM_ACKNOWLEDGMENTS_PER_PACKET,
            |acknowledgment_ids| {
                let mut packet = self.session.new_control_packet(
                    Opcode::ControlV1,
                    ciphertext[..consumed].to_vec(),
                )?;
                packet.acknowledgment_ids = acknowledgment_ids;
                Ok::<_, SessionError>(packet)
            },
        )?;
        packet
            .map(|packet| {
                self.encode_link_packet(&packet).map(|raw| (raw, consumed))
            })
            .transpose()
    }

    pub fn send_initial_soft_reset(
        &self,
    ) -> Result<Vec<u8>, ControlChannelError> {
        let packet = self.outgoing.insert_outgoing_packet(
            MAXIMUM_ACKNOWLEDGMENTS_PER_PACKET,
            |acknowledgment_ids| {
                let mut packet = self.session.new_soft_reset_packet()?;
                packet.acknowledgment_ids = acknowledgment_ids;
                Ok::<_, SessionError>(packet)
            },
        )?;
        let packet = packet.ok_or(ControlChannelError::ReliableWindowFull)?;
        self.encode_link_packet(&packet)
    }

    /// Returns retransmissions followed by a standalone ACK (or a reliable
    /// WKC packet while tls-crypt-v2 packet 1 remains unacknowledged).
    pub fn packets_ready_to_send(
        &self,
        now: Instant,
    ) -> Result<Vec<Vec<u8>>, ControlChannelError> {
        let mut packets = self
            .outgoing
            .packets_ready_to_send(now)
            .iter()
            .map(|packet| self.encode_link_packet(packet))
            .collect::<Result<Vec<_>, _>>()?;
        if self.outgoing.pending_acknowledgment_count() > 0 {
            match self.new_acknowledgment_packet() {
                Ok(packet) => packets.push(packet),
                Err(ControlChannelError::ReliableWindowFull) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(packets)
    }

    pub fn return_failed_acknowledgments(
        &self,
        raw_packet: &[u8],
    ) -> Result<(), ControlChannelError> {
        let packet = Packet::parse(raw_packet)?;
        if packet.opcode == Opcode::AcknowledgmentV1 {
            self.outgoing
                .return_acknowledgment_ids(packet.acknowledgment_ids);
        }
        Ok(())
    }

    pub fn has_in_flight_packets(&self) -> bool {
        self.outgoing.has_in_flight_packets()
    }

    pub fn control_channel_frame_overhead(
        &self,
        acknowledgment_count: usize,
    ) -> usize {
        1 + 8
            + acknowledgment_array_length(acknowledgment_count)
            + 4
            + self.protection.control_packet_overhead()
            + if self.remote_is_ipv6 {
                IPV6_CONTROL_DATAGRAM_OVERHEAD
            } else {
                IPV4_CONTROL_DATAGRAM_OVERHEAD
            }
    }

    fn new_acknowledgment_packet(
        &self,
    ) -> Result<Vec<u8>, ControlChannelError> {
        if self.next_packet_carries_wrapped_client_key() {
            let packet = self.outgoing.insert_outgoing_packet(
                ACKNOWLEDGMENT_SET_CAPACITY,
                |acknowledgment_ids| {
                    let mut packet = self
                        .session
                        .new_control_packet(Opcode::ControlWkcV1, Vec::new())?;
                    packet.acknowledgment_ids = acknowledgment_ids;
                    Ok::<_, SessionError>(packet)
                },
            )?;
            return self.encode_link_packet(
                &packet.ok_or(ControlChannelError::ReliableWindowFull)?,
            );
        }
        let ids = self
            .outgoing
            .take_acknowledgment_ids(ACKNOWLEDGMENT_SET_CAPACITY);
        if ids.is_empty() {
            return Err(ControlChannelError::NoPendingAcknowledgment);
        }
        let packet = match self.session.new_acknowledgment_packet(ids.clone()) {
            Ok(packet) => packet,
            Err(error) => {
                self.outgoing.return_acknowledgment_ids(ids);
                return Err(error.into());
            }
        };
        self.encode_link_packet(&packet)
    }

    fn next_packet_carries_wrapped_client_key(&self) -> bool {
        !self.wrapped_client_key.is_empty()
            && self.session.next_local_control_packet_id() == 1
    }

    fn encode_link_packet(
        &self,
        packet: &Packet,
    ) -> Result<Vec<u8>, ControlChannelError> {
        let should_wrap = !self.wrapped_client_key.is_empty()
            && packet.id == 1
            && matches!(
                packet.opcode,
                Opcode::ControlV1 | Opcode::ControlWkcV1
            );
        let mut outgoing = packet.clone();
        if should_wrap {
            outgoing.opcode = Opcode::ControlWkcV1;
        }
        let raw = outgoing.encode()?;
        let protected = if is_control_or_acknowledgment(outgoing.opcode) {
            self.protection.encode(&raw)
        } else {
            raw
        };
        Ok(if should_wrap {
            append_tls_crypt_v2_wrapped_client_key(
                &protected,
                &self.wrapped_client_key,
                outgoing.opcode,
            )
        } else {
            protected
        })
    }
}

pub fn acknowledgment_array_length(count: usize) -> usize {
    let count = count.min(MAXIMUM_ACKNOWLEDGMENTS_PER_PACKET);
    if count == 0 { 1 } else { 1 + 4 * count + 8 }
}

pub const fn is_control_or_acknowledgment(opcode: Opcode) -> bool {
    opcode.is_control() || matches!(opcode, Opcode::AcknowledgmentV1)
}

pub const fn is_tls_hard_reset_opcode(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::ControlHardResetClientV1
            | Opcode::ControlHardResetServerV1
            | Opcode::ControlHardResetClientV2
            | Opcode::ControlHardResetServerV2
            | Opcode::ControlHardResetClientV3
    )
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlChannelError {
    #[error("empty OpenVPN link packet")]
    EmptyPacket,
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("OpenVPN control protection: {0}")]
    Protection(String),
    #[error("OpenVPN reliable send window is full")]
    ReliableWindowFull,
    #[error("no pending OpenVPN acknowledgment")]
    NoPendingAcknowledgment,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(local: [u8; 8], remote: [u8; 8]) -> TlsControlChannelCore {
        let session = Arc::new(SessionManager::with_local_id(local));
        session.set_remote_session_id(remote);
        TlsControlChannelCore::new(
            session,
            TlsControlProtection::default(),
            Vec::new(),
            false,
        )
    }

    #[test]
    fn packetizes_reorders_and_acknowledges_tls_ciphertext() {
        let local = *b"local-id";
        let remote = *b"remoteid";
        let client = channel(local, remote);
        let mut server = channel(remote, local);

        let (first, first_count) = client
            .packetize_tls_ciphertext(&vec![0x5a; 2000])
            .unwrap()
            .unwrap();
        assert!(first_count < 1024);
        let (second, second_count) = client
            .packetize_tls_ciphertext(&vec![0x5a; 2000 - first_count])
            .unwrap()
            .unwrap();
        assert!(second_count > 0);

        assert!(server.ingest_link_packet(&second).unwrap().is_empty());
        let events = server.ingest_link_packet(&first).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| matches!(
            event,
            IncomingControlEvent::TlsCiphertext(payload) if !payload.is_empty()
        )));
        let outbound = server.packets_ready_to_send(Instant::now()).unwrap();
        assert_eq!(outbound.len(), 1);
        let ack = Packet::parse(&outbound[0]).unwrap();
        assert_eq!(ack.opcode, Opcode::AcknowledgmentV1);
        assert_eq!(ack.acknowledgment_ids, [1, 2]);
    }

    #[test]
    fn ignores_wrong_sessions_and_dispatches_data_and_soft_reset() {
        let mut core = channel(*b"local-id", *b"remoteid");
        let mut wrong = Packet::new(Opcode::ControlV1, 0, b"tls".to_vec());
        wrong.local_session_id = *b"stranger";
        wrong.id = 1;
        assert!(
            core.ingest_link_packet(&wrong.encode().unwrap())
                .unwrap()
                .is_empty()
        );

        let data = Packet::new(Opcode::DataV1, 0, b"ip".to_vec());
        assert!(matches!(
            core.ingest_link_packet(&data.encode().unwrap()).unwrap()[0],
            IncomingControlEvent::Data(_)
        ));

        let mut reset = Packet::new(Opcode::ControlSoftResetV1, 0, Vec::new());
        reset.local_session_id = *b"remoteid";
        reset.remote_session_id = *b"local-id";
        reset.acknowledgment_ids.push(9);
        assert!(matches!(
            core.ingest_link_packet(&reset.encode().unwrap()).unwrap()[0],
            IncomingControlEvent::SoftReset(_)
        ));
    }

    #[test]
    fn computes_exact_frame_overhead_and_honors_six_slot_window() {
        let core = channel(*b"local-id", *b"remoteid");
        assert_eq!(acknowledgment_array_length(0), 1);
        assert_eq!(acknowledgment_array_length(2), 17);
        assert_eq!(core.control_channel_frame_overhead(0), 42);
        for _ in 0..6 {
            assert!(core.packetize_tls_ciphertext(b"x").unwrap().is_some());
        }
        assert!(core.packetize_tls_ciphertext(b"x").unwrap().is_none());
    }
}
