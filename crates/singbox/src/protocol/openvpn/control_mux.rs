use std::{collections::HashMap, time::Instant};

use super::{
    ControlChannelError, IncomingControlEvent, Opcode, Packet,
    TlsControlChannelCore,
};

const MAXIMUM_PENDING_PACKETS_PER_KEY_STATE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedControlEvents {
    pub key_id: u8,
    pub events: Vec<IncomingControlEvent>,
}

/// Packet-level demultiplexer for the primary TLS control channel and the
/// concurrently alive soft-reset channels. An unseen key-id is first offered
/// to the primary channel so a new P_CONTROL_SOFT_RESET_V1 can be discovered.
#[derive(Debug)]
pub struct TlsControlChannelMuxCore {
    primary_key_id: u8,
    channels: HashMap<u8, TlsControlChannelCore>,
    pending: HashMap<u8, Vec<Vec<u8>>>,
}

impl TlsControlChannelMuxCore {
    pub fn new(primary: TlsControlChannelCore) -> Self {
        let primary_key_id = primary.session().current_key_id();
        Self {
            primary_key_id,
            channels: HashMap::from([(primary_key_id, primary)]),
            pending: HashMap::new(),
        }
    }

    pub fn primary_key_id(&self) -> u8 {
        self.primary_key_id
    }

    pub fn contains(&self, key_id: u8) -> bool {
        self.channels.contains_key(&key_id)
    }

    pub fn register_renegotiation_channel(
        &mut self,
        mut channel: TlsControlChannelCore,
        initial_soft_reset: Option<&Packet>,
    ) -> Result<Vec<IncomingControlEvent>, ControlMuxError> {
        let key_id = channel.session().current_key_id();
        if key_id == 0 {
            return Err(ControlMuxError::InvalidRenegotiationKeyId);
        }
        if self.channels.contains_key(&key_id) {
            return Err(ControlMuxError::DuplicateKeyId(key_id));
        }
        if let Some(packet) = initial_soft_reset {
            if packet.key_id != key_id {
                return Err(ControlMuxError::WrongInitialResetKeyId);
            }
            channel.seed_incoming_packet(packet);
        }
        let mut events = Vec::new();
        if let Some(pending) = self.pending.remove(&key_id) {
            for packet in pending {
                events.extend(channel.ingest_link_packet(&packet)?);
            }
        }
        self.channels.insert(key_id, channel);
        Ok(events)
    }

    pub fn promote(&mut self, key_id: u8) -> Result<(), ControlMuxError> {
        if !self.channels.contains_key(&key_id) {
            return Err(ControlMuxError::UnknownKeyId(key_id));
        }
        self.primary_key_id = key_id;
        Ok(())
    }

    pub fn unregister(&mut self, key_id: u8) -> bool {
        if key_id == self.primary_key_id {
            return false;
        }
        self.pending.remove(&key_id);
        self.channels.remove(&key_id).is_some()
    }

    pub fn ingest_link_packet(
        &mut self,
        raw_packet: &[u8],
    ) -> Result<RoutedControlEvents, ControlMuxError> {
        let announced_key_id = raw_packet
            .first()
            .map(|header| header & 0x07)
            .ok_or(ControlMuxError::EmptyPacket)?;
        let opcode = Opcode::from_wire(raw_packet[0] >> 3);
        if !self.channels.contains_key(&announced_key_id)
            && opcode != Opcode::ControlSoftResetV1
        {
            let pending = self.pending.entry(announced_key_id).or_default();
            if pending.len() >= MAXIMUM_PENDING_PACKETS_PER_KEY_STATE {
                pending.remove(0);
            }
            pending.push(raw_packet.to_vec());
            return Ok(RoutedControlEvents {
                key_id: announced_key_id,
                events: Vec::new(),
            });
        }
        let routed_key_id = if self.channels.contains_key(&announced_key_id) {
            announced_key_id
        } else {
            self.primary_key_id
        };
        let events = self
            .channels
            .get_mut(&routed_key_id)
            .ok_or(ControlMuxError::UnknownKeyId(routed_key_id))?
            .ingest_link_packet(raw_packet)?;
        Ok(RoutedControlEvents {
            key_id: routed_key_id,
            events,
        })
    }

    pub fn packetize_tls_ciphertext(
        &self,
        key_id: u8,
        ciphertext: &[u8],
    ) -> Result<Option<(Vec<u8>, usize)>, ControlMuxError> {
        Ok(self
            .channels
            .get(&key_id)
            .ok_or(ControlMuxError::UnknownKeyId(key_id))?
            .packetize_tls_ciphertext(ciphertext)?)
    }

    pub fn send_initial_soft_reset(
        &self,
        key_id: u8,
    ) -> Result<Vec<u8>, ControlMuxError> {
        Ok(self
            .channels
            .get(&key_id)
            .ok_or(ControlMuxError::UnknownKeyId(key_id))?
            .send_initial_soft_reset()?)
    }

    pub fn packets_ready_to_send(
        &self,
        now: Instant,
    ) -> Result<Vec<Vec<u8>>, ControlMuxError> {
        let mut packets = Vec::new();
        for channel in self.channels.values() {
            packets.extend(channel.packets_ready_to_send(now)?);
        }
        Ok(packets)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlMuxError {
    #[error("empty OpenVPN packet")]
    EmptyPacket,
    #[error("invalid zero key-id for OpenVPN soft-reset channel")]
    InvalidRenegotiationKeyId,
    #[error("duplicate OpenVPN TLS control key-id: {0}")]
    DuplicateKeyId(u8),
    #[error("unknown OpenVPN TLS control key-id: {0}")]
    UnknownKeyId(u8),
    #[error("initial OpenVPN soft-reset packet has the wrong key-id")]
    WrongInitialResetKeyId,
    #[error(transparent)]
    Channel(#[from] ControlChannelError),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::protocol::openvpn::{
        Opcode, SessionManager, TlsControlProtection,
    };

    fn channel(
        key_id: u8,
        local: [u8; 8],
        remote: [u8; 8],
    ) -> TlsControlChannelCore {
        let initial = SessionManager::with_local_id(local);
        initial.set_remote_session_id(remote);
        let session = Arc::new(if key_id == 0 {
            initial
        } else {
            initial.renegotiation(key_id)
        });
        TlsControlChannelCore::new(
            session,
            TlsControlProtection::default(),
            Vec::new(),
            false,
        )
    }

    #[test]
    fn discovers_registers_and_routes_a_soft_reset_channel() {
        let local = *b"local-id";
        let remote = *b"remoteid";
        let mut mux = TlsControlChannelMuxCore::new(channel(0, local, remote));
        let peer_rekey = channel(1, remote, local);
        let reset = peer_rekey.send_initial_soft_reset().unwrap();
        let routed = mux.ingest_link_packet(&reset).unwrap();
        assert_eq!(routed.key_id, 0);
        let IncomingControlEvent::SoftReset(reset_packet) = &routed.events[0]
        else {
            panic!("expected soft reset");
        };

        let (early_wire, _) = peer_rekey
            .packetize_tls_ciphertext(b"early tls")
            .unwrap()
            .unwrap();
        let early = mux.ingest_link_packet(&early_wire).unwrap();
        assert_eq!(early.key_id, 1);
        assert!(early.events.is_empty());
        let pending_events = mux
            .register_renegotiation_channel(
                channel(1, local, remote),
                Some(reset_packet),
            )
            .unwrap();
        assert_eq!(
            pending_events,
            [IncomingControlEvent::TlsCiphertext(b"early tls".to_vec())]
        );
        let ready = mux.packets_ready_to_send(Instant::now()).unwrap();
        assert!(ready.iter().any(|raw| {
            Packet::parse(raw).is_ok_and(|packet| {
                packet.opcode == Opcode::AcknowledgmentV1
                    && packet.key_id == 1
                    && packet.acknowledgment_ids.contains(&0)
            })
        }));

        let (wire, _) = peer_rekey
            .packetize_tls_ciphertext(b"new tls")
            .unwrap()
            .unwrap();
        let routed = mux.ingest_link_packet(&wire).unwrap();
        assert_eq!(routed.key_id, 1);
        assert_eq!(
            routed.events,
            [IncomingControlEvent::TlsCiphertext(b"new tls".to_vec())]
        );
        mux.promote(1).unwrap();
        assert_eq!(mux.primary_key_id(), 1);
    }

    #[test]
    fn refuses_duplicate_and_primary_removal() {
        let mut mux = TlsControlChannelMuxCore::new(channel(
            0,
            *b"local-id",
            *b"remoteid",
        ));
        assert!(!mux.unregister(0));
        assert_eq!(
            mux.register_renegotiation_channel(
                channel(0, *b"local-id", *b"remoteid"),
                None,
            ),
            Err(ControlMuxError::InvalidRenegotiationKeyId)
        );
    }

    #[test]
    fn bounds_and_clears_packets_waiting_for_key_state_registration() {
        let mut mux = TlsControlChannelMuxCore::new(channel(
            0,
            *b"local-id",
            *b"remoteid",
        ));
        for id in 0_u8..12 {
            let mut packet =
                vec![(Opcode::ControlV1.wire_value() << 3) | 1, id];
            packet.resize(14, 0);
            mux.ingest_link_packet(&packet).unwrap();
        }
        let pending = mux.pending.get(&1).unwrap();
        assert_eq!(pending.len(), MAXIMUM_PENDING_PACKETS_PER_KEY_STATE);
        assert_eq!(pending.first().unwrap()[1], 4);
        assert_eq!(pending.last().unwrap()[1], 11);

        assert!(!mux.unregister(1));
        assert!(!mux.pending.contains_key(&1));
    }
}
