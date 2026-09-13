// Chrome-compatible Initial packet payload shaping.
//
// Ported from github.com/sagernet/quic-go v0.61.0-sing-box-mod.6
// packet_packer_chaos.go (MIT), which mirrors Chromium's QuicChaosProtector.

use bytes::Bytes;
use rand::{seq::SliceRandom, Rng};

use crate::{frame, VarInt};

const MIN_ADDED_CRYPTO_FRAMES: usize = 2;
const MAX_ADDED_CRYPTO_FRAMES: usize = 10;
const MIN_PING_FRAMES: usize = 2;
const MAX_PING_FRAMES: usize = 10;

enum Item {
    Raw(Bytes),
    Crypto(frame::Crypto),
    Padding(usize),
}

/// Scramble a plaintext client Initial payload without changing its length.
/// ACK frames stay at the beginning; CRYPTO frames, other frames, added PINGs,
/// and distributed padding are shuffled behind them.
pub(super) fn protect_initial_payload<R: Rng + ?Sized>(
    buffer: &mut Vec<u8>,
    payload_start: usize,
    rng: &mut R,
) {
    let original = Bytes::copy_from_slice(&buffer[payload_start..]);
    let mut frames = match frame::Iter::new(original.clone()) {
        Ok(frames) => frames,
        Err(_) => return,
    };
    let mut acknowledgements = Vec::new();
    let mut crypto = Vec::new();
    let mut others = Vec::new();
    let mut padding = 0usize;

    while frames.remaining_len() != 0 {
        let before = frames.remaining_len();
        let parsed = match frames.next() {
            Some(Ok(parsed)) => parsed,
            _ => return,
        };
        let after = frames.remaining_len();
        let raw =
            original.slice(original.len() - before..original.len() - after);
        match parsed {
            frame::Frame::Padding => padding += 1,
            frame::Frame::Ack(_) => acknowledgements.push(raw),
            frame::Frame::Crypto(value) => crypto.push(value),
            _ => others.push(raw),
        }
    }

    if crypto.is_empty() || padding == 0 {
        return;
    }

    shred_crypto_frames(&mut crypto, others.len(), &mut padding, rng);

    let mut items =
        Vec::with_capacity(crypto.len() + others.len() + MAX_PING_FRAMES * 2);
    items.extend(crypto.into_iter().map(Item::Crypto));
    items.extend(others.into_iter().map(Item::Raw));

    let ping_count = rng
        .random_range(MIN_PING_FRAMES..=MAX_PING_FRAMES)
        .min(padding);
    items.extend(
        (0..ping_count).map(|_| Item::Raw(Bytes::from_static(&[0x01]))),
    );
    padding -= ping_count;

    for run in spread_padding(items.len(), padding, rng) {
        items.push(Item::Padding(run));
    }
    items.shuffle(rng);

    let expected_len = buffer.len() - payload_start;
    buffer.truncate(payload_start);
    for ack in acknowledgements {
        buffer.extend_from_slice(&ack);
    }
    for item in items {
        match item {
            Item::Raw(raw) => buffer.extend_from_slice(&raw),
            Item::Crypto(value) => value.encode(buffer),
            Item::Padding(len) => buffer.resize(buffer.len() + len, 0),
        }
    }
    debug_assert_eq!(buffer.len() - payload_start, expected_len);
}

fn crypto_header_len(offset: u64, data_len: usize) -> usize {
    1 + VarInt::from_u64(offset).unwrap().size()
        + VarInt::from_u64(data_len as u64).unwrap().size()
}

fn shred_crypto_frames<R: Rng + ?Sized>(
    crypto: &mut Vec<frame::Crypto>,
    other_count: usize,
    padding: &mut usize,
    rng: &mut R,
) {
    let Some(first) = crypto.first() else {
        return;
    };
    let mut low = first.offset;
    let mut high = first.offset + first.data.len() as u64;
    for value in crypto.iter().skip(1) {
        low = low.min(value.offset);
        high = high.max(value.offset + value.data.len() as u64);
    }
    let max_overhead = crypto_header_len(high, (high - low) as usize);
    let attempts =
        rng.random_range(MIN_ADDED_CRYPTO_FRAMES..=MAX_ADDED_CRYPTO_FRAMES);

    for _ in 0..attempts {
        if *padding < max_overhead {
            break;
        }
        let index = rng.random_range(0..crypto.len() + other_count);
        if index >= crypto.len() || crypto[index].data.len() <= 1 {
            continue;
        }
        let value = crypto[index].clone();
        let cut = rng.random_range(1..value.data.len());
        let left = frame::Crypto {
            offset: value.offset,
            data: value.data.slice(..cut),
        };
        let right = frame::Crypto {
            offset: value.offset + cut as u64,
            data: value.data.slice(cut..),
        };
        let old_header = crypto_header_len(value.offset, value.data.len());
        let new_headers = crypto_header_len(left.offset, left.data.len())
            + crypto_header_len(right.offset, right.data.len());
        if old_header + *padding < new_headers {
            break;
        }
        *padding = old_header + *padding - new_headers;
        crypto[index] = left;
        crypto.push(right);
    }
}

fn spread_padding<R: Rng + ?Sized>(
    frame_count: usize,
    mut budget: usize,
    rng: &mut R,
) -> Vec<usize> {
    let mut runs = Vec::with_capacity(frame_count + 1);
    for _ in 0..frame_count {
        if budget == 0 {
            break;
        }
        let len = rng.random_range(0..=budget);
        if len != 0 {
            runs.push(len);
            budget -= len;
        }
    }
    if budget != 0 {
        runs.push(budget);
    }
    runs
}

/// Returns `(head, tail)` lengths for Chrome's first ClientHello packet.
pub(super) fn crypto_split<R: Rng + ?Sized>(
    pending: usize,
    offset: u64,
    available: usize,
    rng: &mut R,
) -> Option<(usize, usize)> {
    if pending == 0 || available == 0 {
        return None;
    }
    let min_frame = crypto_header_len(offset + pending as u64 - 1, pending);
    if available < 2 * min_frame {
        return None;
    }
    let max_first = available - 2 * min_frame;
    let max_other = available - min_frame;
    if pending <= max_first {
        return None;
    }
    let occupied = max_other - max_first;
    let packet_count = (pending + occupied).div_ceil(max_other);
    let other_data = (pending + occupied).div_ceil(packet_count);
    if other_data < occupied {
        return None;
    }
    let first_data = other_data - occupied;
    let head = 55 + rng.random_range(0..32);
    if pending <= head || first_data <= head {
        return None;
    }
    Some((head, first_data - head))
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn chaos_preserves_length_and_crypto_bytes() {
        let mut payload = Vec::new();
        frame::Crypto {
            offset: 0,
            data: Bytes::from_static(&[7; 256]),
        }
        .encode(&mut payload);
        payload.resize(1200, 0);
        let mut rng = StdRng::seed_from_u64(42);
        protect_initial_payload(&mut payload, 0, &mut rng);
        assert_eq!(payload.len(), 1200);

        let mut crypto = Vec::new();
        let mut pings = 0;
        let mut padding = 0;
        for parsed in frame::Iter::new(Bytes::from(payload)).unwrap() {
            match parsed.unwrap() {
                frame::Frame::Crypto(value) => crypto.push(value),
                frame::Frame::Ping => pings += 1,
                frame::Frame::Padding => padding += 1,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        crypto.sort_by_key(|value| value.offset);
        let mut rebuilt = BytesMut::new();
        for value in crypto {
            rebuilt.put_slice(&value.data);
        }
        assert_eq!(&rebuilt[..], &[7; 256]);
        assert!((MIN_PING_FRAMES..=MAX_PING_FRAMES).contains(&pings));
        assert!(padding != 0);
    }

    #[test]
    fn large_client_hello_split_sends_head_and_tail_first() {
        let mut rng = StdRng::seed_from_u64(7);
        let (head, tail) = crypto_split(2400, 0, 1160, &mut rng).unwrap();
        assert!((55..87).contains(&head));
        assert!(tail != 0);
        assert!(head + tail < 2400);
    }
}
