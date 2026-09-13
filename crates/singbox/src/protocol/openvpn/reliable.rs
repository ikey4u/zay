use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use super::{Opcode, Packet, PacketId};

pub const RELIABLE_SEND_BUFFER_SIZE: usize = 6;
pub const RELIABLE_RECEIVE_BUFFER_SIZE: u32 = 12;
pub const MAXIMUM_ACKNOWLEDGMENTS_PER_PACKET: usize = 4;
pub const ACKNOWLEDGMENT_SET_CAPACITY: usize = 8;
pub const INITIAL_RETRANSMISSION_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAXIMUM_RETRANSMISSION_TIMEOUT: Duration = Duration::from_secs(60);
pub const FAST_RETRANSMISSION_ACK_THRESHOLD: u8 = 3;

#[derive(Debug, Clone)]
struct InFlightPacket {
    packet: Packet,
    retransmission_deadline: Option<Instant>,
    higher_packet_acknowledgments: u8,
    retransmission_count: u32,
}

impl InFlightPacket {
    fn schedule(&mut self, now: Instant) {
        self.retransmission_count = self.retransmission_count.saturating_add(1);
        let shift = self.retransmission_count.saturating_sub(1).min(31);
        let multiplier = 1_u32 << shift;
        let timeout = INITIAL_RETRANSMISSION_TIMEOUT
            .saturating_mul(multiplier)
            .min(MAXIMUM_RETRANSMISSION_TIMEOUT);
        self.retransmission_deadline = Some(now + timeout);
    }
}

#[derive(Debug, Default)]
struct OutgoingInner {
    in_flight: BTreeMap<PacketId, InFlightPacket>,
    pending_acknowledgments: BTreeSet<PacketId>,
}

/// Bounded reliable-control sender matching OpenVPN's six-slot send window.
#[derive(Debug, Default)]
pub struct OutgoingReliableState {
    inner: Mutex<OutgoingInner>,
}

impl OutgoingReliableState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically takes ACKs and creates an outgoing packet. When the send
    /// window is full no ACK or packet-id state is consumed.
    pub fn insert_outgoing_packet<E>(
        &self,
        maximum_acknowledgments: usize,
        create: impl FnOnce(Vec<PacketId>) -> Result<Packet, E>,
    ) -> Result<Option<Packet>, E> {
        let mut inner = self.inner.lock();
        if inner.in_flight.len() >= RELIABLE_SEND_BUFFER_SIZE {
            return Ok(None);
        }
        let ids = take_acknowledgments(&mut inner, maximum_acknowledgments);
        let packet = match create(ids.clone()) {
            Ok(packet) => packet,
            Err(error) => {
                return_acknowledgments(&mut inner, ids);
                return Err(error);
            }
        };
        inner.in_flight.insert(
            packet.id,
            InFlightPacket {
                packet: packet.clone(),
                retransmission_deadline: None,
                higher_packet_acknowledgments: 0,
                retransmission_count: 0,
            },
        );
        Ok(Some(packet))
    }

    pub fn on_incoming_packet(&self, packet: &Packet) {
        let mut inner = self.inner.lock();
        if packet.opcode != Opcode::AcknowledgmentV1
            && inner.pending_acknowledgments.len() < ACKNOWLEDGMENT_SET_CAPACITY
        {
            inner.pending_acknowledgments.insert(packet.id);
        }
        for acknowledged_id in &packet.acknowledgment_ids {
            inner.in_flight.remove(acknowledged_id);
            for (&id, tracked) in &mut inner.in_flight {
                if *acknowledged_id > id {
                    tracked.higher_packet_acknowledgments =
                        tracked.higher_packet_acknowledgments.saturating_add(1);
                }
            }
        }
    }

    pub fn pending_acknowledgment_count(&self) -> usize {
        self.inner.lock().pending_acknowledgments.len()
    }

    pub fn take_acknowledgment_ids(&self, maximum: usize) -> Vec<PacketId> {
        take_acknowledgments(&mut self.inner.lock(), maximum)
    }

    pub fn return_acknowledgment_ids(&self, ids: Vec<PacketId>) {
        return_acknowledgments(&mut self.inner.lock(), ids);
    }

    pub fn has_in_flight_packets(&self) -> bool {
        !self.inner.lock().in_flight.is_empty()
    }

    pub fn packets_ready_to_send(&self, now: Instant) -> Vec<Packet> {
        let mut inner = self.inner.lock();
        inner
            .in_flight
            .values_mut()
            .filter_map(|tracked| {
                let ready = tracked
                    .retransmission_deadline
                    .is_none_or(|deadline| deadline <= now)
                    || tracked.higher_packet_acknowledgments
                        >= FAST_RETRANSMISSION_ACK_THRESHOLD;
                ready.then(|| {
                    tracked.schedule(now);
                    tracked.packet.clone()
                })
            })
            .collect()
    }
}

fn take_acknowledgments(
    inner: &mut OutgoingInner,
    maximum: usize,
) -> Vec<PacketId> {
    let ids: Vec<_> = inner
        .pending_acknowledgments
        .iter()
        .copied()
        .take(maximum)
        .collect();
    for id in &ids {
        inner.pending_acknowledgments.remove(id);
    }
    ids
}

fn return_acknowledgments(inner: &mut OutgoingInner, ids: Vec<PacketId>) {
    for id in ids {
        if inner.pending_acknowledgments.len() >= ACKNOWLEDGMENT_SET_CAPACITY
            && !inner.pending_acknowledgments.contains(&id)
        {
            break;
        }
        inner.pending_acknowledgments.insert(id);
    }
}

#[derive(Debug, Default)]
struct IncomingInner {
    pending: BTreeMap<PacketId, Packet>,
    last_consumed_id: PacketId,
}

/// Reorders the bounded OpenVPN reliable receive window and suppresses
/// duplicates and stale packets.
#[derive(Debug, Default)]
pub struct IncomingReliableState {
    inner: Mutex<IncomingInner>,
}

impl IncomingReliableState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_insert_incoming_packet(&self, packet: Packet) -> bool {
        let mut inner = self.inner.lock();
        if packet.id <= inner.last_consumed_id
            || inner.pending.contains_key(&packet.id)
        {
            return false;
        }
        let next = inner.last_consumed_id.wrapping_add(1);
        if packet.id.wrapping_sub(next) >= RELIABLE_RECEIVE_BUFFER_SIZE
            || inner.pending.len() >= RELIABLE_RECEIVE_BUFFER_SIZE as usize
        {
            return false;
        }
        inner.pending.insert(packet.id, packet);
        true
    }

    pub fn next_ordered_sequence(&self) -> Vec<Packet> {
        let mut inner = self.inner.lock();
        let mut ready = Vec::new();
        loop {
            let next = inner.last_consumed_id.wrapping_add(1);
            let Some(packet) = inner.pending.remove(&next) else {
                break;
            };
            inner.last_consumed_id = next;
            ready.push(packet);
        }
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(id: u32) -> Packet {
        let mut packet = Packet::new(Opcode::ControlV1, 0, Vec::new());
        packet.id = id;
        packet
    }

    #[test]
    fn incoming_window_orders_and_rejects_duplicates() {
        let state = IncomingReliableState::new();
        assert!(state.try_insert_incoming_packet(control(2)));
        assert!(state.next_ordered_sequence().is_empty());
        assert!(state.try_insert_incoming_packet(control(1)));
        assert_eq!(
            state
                .next_ordered_sequence()
                .iter()
                .map(|packet| packet.id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(!state.try_insert_incoming_packet(control(2)));
        assert!(!state.try_insert_incoming_packet(control(15)));
    }

    #[test]
    fn outgoing_window_acks_and_retransmits() {
        let state = OutgoingReliableState::new();
        state.on_incoming_packet(&control(9));
        let packet = state
            .insert_outgoing_packet(4, |acks| -> Result<_, ()> {
                let mut packet = control(1);
                packet.acknowledgment_ids = acks;
                Ok(packet)
            })
            .unwrap()
            .unwrap();
        assert_eq!(packet.acknowledgment_ids, vec![9]);
        let now = Instant::now();
        assert_eq!(state.packets_ready_to_send(now).len(), 1);
        assert!(state.packets_ready_to_send(now).is_empty());

        let mut ack = Packet::new(Opcode::AcknowledgmentV1, 0, Vec::new());
        ack.acknowledgment_ids.push(1);
        state.on_incoming_packet(&ack);
        assert!(!state.has_in_flight_packets());
    }

    #[test]
    fn full_send_window_does_not_consume_pending_acknowledgments() {
        let state = OutgoingReliableState::new();
        state.on_incoming_packet(&control(88));
        for id in 1..=RELIABLE_SEND_BUFFER_SIZE as u32 {
            state
                .insert_outgoing_packet(0, |_| -> Result<_, ()> {
                    Ok(control(id))
                })
                .unwrap()
                .unwrap();
        }
        assert!(
            state
                .insert_outgoing_packet(4, |_| -> Result<_, ()> {
                    Ok(control(7))
                })
                .unwrap()
                .is_none()
        );
        assert_eq!(state.pending_acknowledgment_count(), 1);
    }
}
