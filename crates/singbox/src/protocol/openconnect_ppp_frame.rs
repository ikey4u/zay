//! PPP carrier framing shared by the Fortinet and F5 OpenConnect flavors.

use thiserror::Error;

pub const PPP_MAXIMUM_PAYLOAD_LENGTH: usize = u16::MAX as usize;
pub const PPP_MAXIMUM_WIRE_FRAME_SIZE: usize =
    2 * PPP_MAXIMUM_PAYLOAD_LENGTH + 6;
pub const PPP_HDLC_CONTROL_ESCAPE_MASK: u32 = u32::MAX;

const F5_MAGIC: u16 = 0xf500;
const FORTINET_MAGIC: u16 = 0x5050;
const HDLC_FLAG: u8 = 0x7e;
const HDLC_ESCAPE: u8 = 0x7d;
const HDLC_INITIAL_FCS: u16 = 0xffff;
const HDLC_GOOD_FCS: u16 = 0xf0b8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppEncapsulation {
    F5,
    F5Hdlc,
    Fortinet,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PppFrameError {
    #[error("PPP receive buffer exceeds maximum wire frame size")]
    ReceiveBufferTooLarge,
    #[error("invalid PPP payload length: {0}")]
    InvalidPayloadLength(usize),
    #[error("PPP payload exceeds frame length field")]
    FrameLengthOverflow,
    #[error("invalid F5 PPP frame magic: {0}")]
    InvalidF5Magic(String),
    #[error("invalid Fortinet PPP frame magic: {0}")]
    InvalidFortinetMagic(String),
    #[error("invalid Fortinet PPP frame length: {0}")]
    InvalidFortinetLength(String),
}

#[derive(Debug, Clone)]
pub struct PppFrameDecoder {
    encapsulation: PppEncapsulation,
    pending: Vec<u8>,
}

impl PppFrameDecoder {
    pub fn new(encapsulation: PppEncapsulation) -> Self {
        Self {
            encapsulation,
            pending: Vec::new(),
        }
    }

    pub fn push(
        &mut self,
        content: &[u8],
    ) -> Result<Vec<Vec<u8>>, PppFrameError> {
        if content.is_empty() {
            return Ok(Vec::new());
        }
        if self.pending.len().saturating_add(content.len())
            > PPP_MAXIMUM_WIRE_FRAME_SIZE
        {
            return Err(PppFrameError::ReceiveBufferTooLarge);
        }
        self.pending.extend_from_slice(content);
        match self.encapsulation {
            PppEncapsulation::F5 => self.decode_f5(),
            PppEncapsulation::F5Hdlc => Ok(self.decode_hdlc()),
            PppEncapsulation::Fortinet => self.decode_fortinet(),
        }
    }

    pub fn discard(&mut self) -> usize {
        let discarded = self.pending.len();
        self.pending.clear();
        self.pending.shrink_to_fit();
        discarded
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn decode_f5(&mut self) -> Result<Vec<Vec<u8>>, PppFrameError> {
        let mut frames = Vec::new();
        let mut consumed = 0;
        while self.pending.len() - consumed >= 4 {
            let frame = &self.pending[consumed..];
            if u16::from_be_bytes([frame[0], frame[1]]) != F5_MAGIC {
                let error = PppFrameError::InvalidF5Magic(preview(frame));
                self.pending.drain(..consumed);
                return Err(error);
            }
            let payload_length =
                usize::from(u16::from_be_bytes([frame[2], frame[3]]));
            let frame_length = 4 + payload_length;
            if frame.len() < frame_length {
                break;
            }
            if payload_length != 0 {
                frames.push(frame[4..frame_length].to_vec());
            }
            consumed += frame_length;
        }
        self.pending.drain(..consumed);
        Ok(frames)
    }

    fn decode_fortinet(&mut self) -> Result<Vec<Vec<u8>>, PppFrameError> {
        let mut frames = Vec::new();
        let mut consumed = 0;
        while self.pending.len() - consumed >= 6 {
            let frame = &self.pending[consumed..];
            let total_length =
                usize::from(u16::from_be_bytes([frame[0], frame[1]]));
            if u16::from_be_bytes([frame[2], frame[3]]) != FORTINET_MAGIC {
                let error = PppFrameError::InvalidFortinetMagic(preview(frame));
                self.pending.drain(..consumed);
                return Err(error);
            }
            let payload_length =
                usize::from(u16::from_be_bytes([frame[4], frame[5]]));
            if total_length != payload_length + 6 {
                let error =
                    PppFrameError::InvalidFortinetLength(preview(frame));
                self.pending.drain(..consumed);
                return Err(error);
            }
            if frame.len() < total_length {
                break;
            }
            if payload_length != 0 {
                frames.push(frame[6..total_length].to_vec());
            }
            consumed += total_length;
        }
        self.pending.drain(..consumed);
        Ok(frames)
    }

    fn decode_hdlc(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut consumed = 0;
        while consumed < self.pending.len() {
            let mut start = consumed;
            if self.pending[start] == HDLC_FLAG {
                while start < self.pending.len()
                    && self.pending[start] == HDLC_FLAG
                {
                    start += 1;
                }
                if start == self.pending.len() {
                    consumed = self.pending.len() - 1;
                    break;
                }
            }
            let Some(end_offset) = self.pending[start..]
                .iter()
                .position(|value| *value == HDLC_FLAG)
            else {
                break;
            };
            let end = start + end_offset;
            if let Some(frame) =
                decode_ppp_hdlc_frame(&self.pending[start..end])
            {
                frames.push(frame);
            }
            consumed = end;
        }
        self.pending.drain(..consumed);
        frames
    }
}

pub fn encode_ppp_frame(
    encapsulation: PppEncapsulation,
    payload: &[u8],
    async_map: u32,
) -> Result<Vec<u8>, PppFrameError> {
    if payload.is_empty() || payload.len() > PPP_MAXIMUM_PAYLOAD_LENGTH {
        return Err(PppFrameError::InvalidPayloadLength(payload.len()));
    }
    match encapsulation {
        PppEncapsulation::F5 => {
            let mut result = Vec::with_capacity(payload.len() + 4);
            result.extend_from_slice(&F5_MAGIC.to_be_bytes());
            result.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            result.extend_from_slice(payload);
            Ok(result)
        }
        PppEncapsulation::F5Hdlc => {
            Ok(encode_ppp_hdlc_frame(payload, async_map))
        }
        PppEncapsulation::Fortinet => {
            if payload.len() > PPP_MAXIMUM_PAYLOAD_LENGTH - 6 {
                return Err(PppFrameError::FrameLengthOverflow);
            }
            let total_length = payload.len() + 6;
            let mut result = Vec::with_capacity(total_length);
            result.extend_from_slice(&(total_length as u16).to_be_bytes());
            result.extend_from_slice(&FORTINET_MAGIC.to_be_bytes());
            result.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            result.extend_from_slice(payload);
            Ok(result)
        }
    }
}

pub fn encode_ppp_hdlc_frame(payload: &[u8], async_map: u32) -> Vec<u8> {
    let mut fcs = HDLC_INITIAL_FCS;
    for value in payload {
        fcs = update_hdlc_fcs(fcs, *value);
    }
    fcs ^= u16::MAX;
    let mut result = Vec::with_capacity(2 * payload.len() + 6);
    result.push(HDLC_FLAG);
    append_hdlc_byte(&mut result, payload, async_map);
    append_hdlc_byte(&mut result, &[fcs as u8, (fcs >> 8) as u8], async_map);
    result.push(HDLC_FLAG);
    result
}

pub fn decode_ppp_hdlc_frame(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut escaped = false;
    for value in encoded {
        if escaped {
            decoded.push(*value ^ 0x20);
            escaped = false;
        } else if *value == HDLC_ESCAPE {
            escaped = true;
        } else {
            decoded.push(*value);
        }
    }
    if escaped || decoded.len() < 3 {
        return None;
    }
    let fcs = decoded
        .iter()
        .fold(HDLC_INITIAL_FCS, |fcs, value| update_hdlc_fcs(fcs, *value));
    if fcs != HDLC_GOOD_FCS {
        return None;
    }
    decoded.truncate(decoded.len() - 2);
    Some(decoded)
}

fn append_hdlc_byte(result: &mut Vec<u8>, values: &[u8], async_map: u32) {
    for value in values {
        let escape = matches!(*value, HDLC_ESCAPE | HDLC_FLAG)
            || (*value < 0x20 && async_map & (1_u32 << *value) != 0);
        if escape {
            result.extend_from_slice(&[HDLC_ESCAPE, *value ^ 0x20]);
        } else {
            result.push(*value);
        }
    }
}

fn update_hdlc_fcs(mut fcs: u16, value: u8) -> u16 {
    fcs ^= u16::from(value);
    for _ in 0..8 {
        fcs = if fcs & 1 != 0 {
            fcs >> 1 ^ 0x8408
        } else {
            fcs >> 1
        };
    }
    fcs
}

fn preview(content: &[u8]) -> String {
    const LIMIT: usize = 64;
    let mut value = hex::encode(&content[..content.len().min(LIMIT)]);
    if content.len() > LIMIT {
        value.push_str("...");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f5_and_fortinet_frames_stream_and_coalesce() {
        for encapsulation in [PppEncapsulation::F5, PppEncapsulation::Fortinet]
        {
            let first = encode_ppp_frame(encapsulation, b"one", 0).unwrap();
            let second = encode_ppp_frame(encapsulation, b"two", 0).unwrap();
            let mut wire = first.clone();
            wire.extend_from_slice(&second);
            let mut decoder = PppFrameDecoder::new(encapsulation);
            assert!(decoder.push(&wire[..2]).unwrap().is_empty());
            assert_eq!(
                decoder.push(&wire[2..]).unwrap(),
                [b"one".to_vec(), b"two".to_vec()]
            );
            assert_eq!(decoder.pending_len(), 0);
        }
    }

    #[test]
    fn hdlc_round_trip_escapes_flags_controls_and_fcs() {
        let payload = [0x00, 0x01, 0x20, 0x7d, 0x7e, 0xff];
        let encoded = encode_ppp_hdlc_frame(&payload, u32::MAX);
        assert_eq!(encoded.first(), Some(&HDLC_FLAG));
        assert_eq!(encoded.last(), Some(&HDLC_FLAG));
        assert_eq!(
            decode_ppp_hdlc_frame(&encoded[1..encoded.len() - 1]),
            Some(payload.to_vec())
        );
        assert!(encoded.windows(2).any(|value| value == [0x7d, 0x5e]));
        assert!(encoded.windows(2).any(|value| value == [0x7d, 0x5d]));
    }

    #[test]
    fn hdlc_decoder_drops_bad_frames_and_preserves_partial_flag() {
        let mut bad = encode_ppp_hdlc_frame(b"bad", 0);
        bad[2] ^= 1;
        let good = encode_ppp_hdlc_frame(b"good", 0);
        bad.extend_from_slice(&good);
        let mut decoder = PppFrameDecoder::new(PppEncapsulation::F5Hdlc);
        assert_eq!(decoder.push(&bad).unwrap(), [b"good".to_vec()]);
        assert_eq!(decoder.pending_len(), 1);
        assert_eq!(decoder.discard(), 1);
    }

    #[test]
    fn rejects_malformed_and_oversized_frames() {
        let mut decoder = PppFrameDecoder::new(PppEncapsulation::Fortinet);
        assert!(matches!(
            decoder.push(&[0, 6, 0, 0, 0, 0]),
            Err(PppFrameError::InvalidFortinetMagic(_))
        ));
        assert!(matches!(
            encode_ppp_frame(
                PppEncapsulation::Fortinet,
                &vec![0; PPP_MAXIMUM_PAYLOAD_LENGTH],
                0
            ),
            Err(PppFrameError::FrameLengthOverflow)
        ));
    }
}
