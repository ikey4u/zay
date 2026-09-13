use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

const TYPE_WHOLE: u32 = 0;
const TYPE_PARTIAL: u32 = 1;
const TYPE_LAST: u32 = 2;
const TYPE_MASK: u32 = 0x3;
const SEQUENCE_MASK: u32 = 0xff;
const SEQUENCE_SHIFT: u32 = 2;
const ID_MASK: u32 = 0x1f;
const ID_SHIFT: u32 = 10;
const SIZE_MASK: u32 = 0x3fff;
const SIZE_SHIFT: u32 = 15;
const SIZE_ROUND_SHIFT: usize = 2;
pub const FRAGMENT_MAX_PARTS: usize = 32;
pub const FRAGMENT_RECEIVE_WINDOW: i32 = 25;
pub const FRAGMENT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
pub const FRAGMENT_REASSEMBLY_MAX_BYTES: usize = 4 << 20;
pub const FRAGMENT_REASSEMBLY_MAX_PACKET_BYTES: usize = u16::MAX as usize;

#[derive(Debug)]
struct IncomingBuffer {
    max_size: usize,
    last_id: Option<usize>,
    parts: HashMap<usize, Vec<u8>>,
    bytes: usize,
    updated: Instant,
}

#[derive(Debug, Default)]
struct FragmentInner {
    outgoing_sequence: u8,
    incoming_sequence: Option<u8>,
    incoming: HashMap<u8, IncomingBuffer>,
    incoming_bytes: usize,
}

/// OpenVPN `--fragment` framing and bounded out-of-order reassembly.
#[derive(Debug)]
pub struct FragmentCodec {
    inner: Mutex<FragmentInner>,
    reassembly_timeout: Duration,
    reassembly_max_bytes: usize,
    reassembly_max_packet_bytes: usize,
}

impl Default for FragmentCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentCodec {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(FragmentInner::default()),
            reassembly_timeout: FRAGMENT_REASSEMBLY_TIMEOUT,
            reassembly_max_bytes: FRAGMENT_REASSEMBLY_MAX_BYTES,
            reassembly_max_packet_bytes: FRAGMENT_REASSEMBLY_MAX_PACKET_BYTES,
        }
    }

    pub fn with_limits(
        timeout: Duration,
        total_bytes: usize,
        packet_bytes: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(FragmentInner::default()),
            reassembly_timeout: timeout,
            reassembly_max_bytes: total_bytes,
            reassembly_max_packet_bytes: packet_bytes,
        }
    }

    pub fn encode(
        &self,
        payload: &[u8],
        fragment_size: usize,
    ) -> Result<Vec<Vec<u8>>, FragmentError> {
        let fragment_size = fragment_size & !((1 << SIZE_ROUND_SHIFT) - 1);
        if fragment_size == 0 {
            return Err(FragmentError::PacketSizeTooSmall);
        }
        if payload.len() <= fragment_size {
            return Ok(vec![frame(payload, TYPE_WHOLE, 0, 0, 0)]);
        }
        let sequence = {
            let mut inner = self.inner.lock();
            let sequence = inner.outgoing_sequence;
            inner.outgoing_sequence = inner.outgoing_sequence.wrapping_add(1);
            sequence
        };
        let mut fragments =
            Vec::with_capacity(payload.len().div_ceil(fragment_size));
        for (id, chunk) in payload.chunks(fragment_size).enumerate() {
            if id >= FRAGMENT_MAX_PARTS {
                return Err(FragmentError::TooManyFragments);
            }
            let last = (id + 1) * fragment_size >= payload.len();
            fragments.push(frame(
                chunk,
                if last { TYPE_LAST } else { TYPE_PARTIAL },
                sequence,
                id as u8,
                if last {
                    fragment_size >> SIZE_ROUND_SHIFT
                } else {
                    0
                },
            ));
        }
        Ok(fragments)
    }

    pub fn decode(
        &self,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, FragmentError> {
        self.decode_at(payload, Instant::now())
    }

    fn decode_at(
        &self,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, FragmentError> {
        if payload.len() < 4 {
            return Err(FragmentError::HeaderNotFound);
        }
        let flags = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let kind = flags & TYPE_MASK;
        let body = &payload[4..];
        if kind == TYPE_WHOLE {
            if ((flags >> SEQUENCE_SHIFT) & SEQUENCE_MASK) != 0
                || ((flags >> ID_SHIFT) & ID_MASK) != 0
            {
                return Err(FragmentError::SpuriousFlags);
            }
            return Ok(Some(body.to_vec()));
        }
        if !matches!(kind, TYPE_PARTIAL | TYPE_LAST) {
            return Err(FragmentError::UnknownType(kind as u8));
        }
        let sequence = ((flags >> SEQUENCE_SHIFT) & SEQUENCE_MASK) as u8;
        let id = ((flags >> ID_SHIFT) & ID_MASK) as usize;
        let maximum_size =
            (((flags >> SIZE_SHIFT) & SIZE_MASK) as usize) << SIZE_ROUND_SHIFT;
        self.store(sequence, id, maximum_size, kind == TYPE_LAST, body, now)
    }

    fn store(
        &self,
        sequence: u8,
        id: usize,
        maximum_size: usize,
        last: bool,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, FragmentError> {
        let mut inner = self.inner.lock();
        expire(&mut inner, now, self.reassembly_timeout);
        if payload.len() > self.reassembly_max_packet_bytes {
            return Err(FragmentError::PacketTooLarge);
        }
        advance_window(&mut inner, sequence);
        let fragment_size = if maximum_size > 0 {
            maximum_size
        } else {
            payload.len()
        };
        if inner
            .incoming
            .get(&sequence)
            .is_some_and(|buffer| buffer.max_size != fragment_size)
        {
            delete_buffer(&mut inner, sequence);
        }
        inner
            .incoming
            .entry(sequence)
            .or_insert_with(|| IncomingBuffer {
                max_size: fragment_size,
                last_id: None,
                parts: HashMap::new(),
                bytes: 0,
                updated: now,
            });

        let previous_length =
            inner.incoming[&sequence].parts.get(&id).map_or(0, Vec::len);
        let buffer_bytes = inner.incoming[&sequence]
            .bytes
            .saturating_sub(previous_length)
            .saturating_add(payload.len());
        if buffer_bytes > self.reassembly_max_packet_bytes {
            delete_buffer(&mut inner, sequence);
            return Err(FragmentError::PacketTooLarge);
        }
        while inner
            .incoming_bytes
            .saturating_sub(previous_length)
            .saturating_add(payload.len())
            > self.reassembly_max_bytes
        {
            let Some(oldest) = oldest_sequence(&inner, sequence) else {
                delete_buffer(&mut inner, sequence);
                return Err(FragmentError::MemoryLimit);
            };
            delete_buffer(&mut inner, oldest);
        }

        let buffer = inner.incoming.get_mut(&sequence).unwrap();
        if maximum_size > 0 {
            buffer.max_size = maximum_size;
        }
        buffer.parts.insert(id, payload.to_vec());
        buffer.bytes = buffer_bytes;
        buffer.updated = now;
        if last {
            buffer.last_id = Some(id);
        }
        inner.incoming_bytes = inner
            .incoming_bytes
            .saturating_sub(previous_length)
            .saturating_add(payload.len());
        let Some(last_id) = inner.incoming[&sequence].last_id else {
            return Ok(None);
        };
        if !(0..=last_id)
            .all(|part| inner.incoming[&sequence].parts.contains_key(&part))
        {
            return Ok(None);
        }
        let buffer = inner.incoming.remove(&sequence).unwrap();
        inner.incoming_bytes =
            inner.incoming_bytes.saturating_sub(buffer.bytes);
        let mut reassembled = Vec::with_capacity(buffer.bytes);
        for part in 0..=last_id {
            reassembled.extend_from_slice(&buffer.parts[&part]);
        }
        Ok(Some(reassembled))
    }
}

fn frame(
    payload: &[u8],
    kind: u32,
    sequence: u8,
    id: u8,
    maximum_size: usize,
) -> Vec<u8> {
    let mut flags = kind & TYPE_MASK;
    flags |= ((sequence as u32) & SEQUENCE_MASK) << SEQUENCE_SHIFT;
    flags |= ((id as u32) & ID_MASK) << ID_SHIFT;
    if kind == TYPE_LAST {
        flags |= ((maximum_size as u32) & SIZE_MASK) << SIZE_SHIFT;
    }
    let mut output = Vec::with_capacity(4 + payload.len());
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(payload);
    output
}

fn sequence_difference(sequence: u8, reference: u8) -> i32 {
    let direct = sequence as i32 - reference as i32;
    if direct == 0 {
        return 0;
    }
    let wrapped = if sequence > reference {
        direct - 256
    } else {
        direct + 256
    };
    if direct < 0 {
        if -direct <= wrapped { direct } else { wrapped }
    } else if direct <= -wrapped {
        direct
    } else {
        wrapped
    }
}

fn advance_window(inner: &mut FragmentInner, sequence: u8) {
    let Some(current) = inner.incoming_sequence else {
        inner.incoming_sequence = Some(sequence);
        return;
    };
    let difference = sequence_difference(sequence, current);
    if !(-FRAGMENT_RECEIVE_WINDOW..FRAGMENT_RECEIVE_WINDOW)
        .contains(&difference)
    {
        inner.incoming.clear();
        inner.incoming_bytes = 0;
        inner.incoming_sequence = Some(sequence);
        return;
    }
    if difference <= 0 {
        return;
    }
    inner.incoming_sequence = Some(sequence);
    let stale: Vec<_> = inner
        .incoming
        .keys()
        .copied()
        .filter(|buffered| {
            let difference = sequence_difference(*buffered, sequence);
            difference <= -FRAGMENT_RECEIVE_WINDOW || difference > 0
        })
        .collect();
    for sequence in stale {
        delete_buffer(inner, sequence);
    }
}

fn expire(inner: &mut FragmentInner, now: Instant, timeout: Duration) {
    let expired: Vec<_> = inner
        .incoming
        .iter()
        .filter_map(|(&sequence, buffer)| {
            (now.duration_since(buffer.updated) >= timeout).then_some(sequence)
        })
        .collect();
    for sequence in expired {
        delete_buffer(inner, sequence);
    }
}

fn oldest_sequence(inner: &FragmentInner, exclude: u8) -> Option<u8> {
    inner
        .incoming
        .iter()
        .filter(|(sequence, _)| **sequence != exclude)
        .min_by_key(|(_, buffer)| buffer.updated)
        .map(|(&sequence, _)| sequence)
}

fn delete_buffer(inner: &mut FragmentInner, sequence: u8) {
    if let Some(buffer) = inner.incoming.remove(&sequence) {
        inner.incoming_bytes =
            inner.incoming_bytes.saturating_sub(buffer.bytes);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    #[error("fragment packet size is too small for data-channel overhead")]
    PacketSizeTooSmall,
    #[error("too many OpenVPN fragments")]
    TooManyFragments,
    #[error("OpenVPN fragment header not found")]
    HeaderNotFound,
    #[error("spurious OpenVPN fragment header flags")]
    SpuriousFlags,
    #[error("unknown OpenVPN fragment type {0}")]
    UnknownType(u8),
    #[error("fragmented packet exceeds maximum IP packet size")]
    PacketTooLarge,
    #[error("fragment reassembly memory limit exceeded")]
    MemoryLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_and_reassembles_out_of_order() {
        let codec = FragmentCodec::new();
        let payload: Vec<_> =
            (0_u16..1000).flat_map(u16::to_be_bytes).collect();
        let fragments = codec.encode(&payload, 257).unwrap();
        assert_eq!(fragments.len(), 8);
        let mut order: Vec<_> = (0..fragments.len()).collect();
        order.reverse();
        let mut result = None;
        for index in order {
            if let Some(value) = codec.decode(&fragments[index]).unwrap() {
                result = Some(value);
            }
        }
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn whole_packets_and_resource_limits_are_enforced() {
        let codec = FragmentCodec::new();
        let framed = codec.encode(b"hello", 68).unwrap();
        assert_eq!(codec.decode(&framed[0]).unwrap().unwrap(), b"hello");
        assert_eq!(
            codec.encode(b"x", 3),
            Err(FragmentError::PacketSizeTooSmall)
        );

        let tiny = FragmentCodec::with_limits(Duration::from_secs(30), 4, 4);
        let partial = frame(b"12345", TYPE_PARTIAL, 1, 0, 0);
        assert_eq!(tiny.decode(&partial), Err(FragmentError::PacketTooLarge));
    }

    #[test]
    fn rejects_spurious_whole_flags_and_expires_partial_packets() {
        let codec =
            FragmentCodec::with_limits(Duration::from_secs(1), 1024, 1024);
        let mut spurious = frame(b"x", TYPE_WHOLE, 0, 0, 0);
        spurious[3] |= 4;
        assert_eq!(codec.decode(&spurious), Err(FragmentError::SpuriousFlags));

        let start = Instant::now();
        let first = frame(b"old", TYPE_PARTIAL, 1, 0, 0);
        assert_eq!(codec.decode_at(&first, start).unwrap(), None);
        let last = frame(b"new", TYPE_LAST, 1, 1, 1);
        assert_eq!(
            codec
                .decode_at(&last, start + Duration::from_secs(2))
                .unwrap(),
            None
        );
    }
}
