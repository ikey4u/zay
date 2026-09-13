//! AnyConnect stateless compression codecs.
//!
//! LZS is a direct safe-Rust port of OpenConnect's LGPL-2.1 `lzs.c` algorithm;
//! LZ4 block encoding is delegated to `lz4_flex`.

use super::{CSTP_MAX_PAYLOAD_SIZE, CstpCompression, CstpError};
use flate2::{
    Compress, Compression, Decompress, FlushCompress, FlushDecompress,
};

pub const ANYCONNECT_MINIMUM_COMPRESSION_SIZE: usize = 40;
const LZS_HASH_TABLE_SIZE: usize = 1 << 16;
const LZS_MAXIMUM_HISTORY: usize = 1 << 11;
const LZS_INVALID_OFFSET: u16 = u16::MAX;
const LZS_MAXIMUM_INPUT_SIZE: usize = u16::MAX as usize + 1;
const ANYCONNECT_DEFLATE_WINDOW_BITS: u8 = 12;

/// Stateful CSTP deflate. Compression history and Adler-32 both continue
/// across records, as required by OpenConnect/ocserv.
#[derive(Debug)]
pub struct AnyConnectDeflateState {
    outgoing: Compress,
    outgoing_checksum: u32,
    incoming: Decompress,
    incoming_checksum: u32,
}

impl Default for AnyConnectDeflateState {
    fn default() -> Self {
        Self::new()
    }
}

impl AnyConnectDeflateState {
    pub fn new() -> Self {
        Self {
            outgoing: Compress::new_with_window_bits(
                Compression::default(),
                false,
                ANYCONNECT_DEFLATE_WINDOW_BITS,
            ),
            outgoing_checksum: 1,
            incoming: Decompress::new_with_window_bits(
                false,
                ANYCONNECT_DEFLATE_WINDOW_BITS,
            ),
            incoming_checksum: 1,
        }
    }

    pub fn compress(&mut self, payload: &[u8]) -> Result<Vec<u8>, CstpError> {
        let mut output = Vec::with_capacity(CSTP_MAX_PAYLOAD_SIZE - 4);
        let input_before = self.outgoing.total_in();
        self.outgoing
            .compress_vec(payload, &mut output, FlushCompress::Sync)
            .map_err(|error| {
                CstpError::Protocol(format!("compress deflate packet: {error}"))
            })?;
        let consumed = (self.outgoing.total_in() - input_before) as usize;
        if consumed != payload.len() {
            return Err(CstpError::Protocol(format!(
                "short deflate input: consumed {consumed} of {} bytes",
                payload.len()
            )));
        }
        self.outgoing_checksum =
            update_adler32(self.outgoing_checksum, payload);
        if output.len() + 4 > CSTP_MAX_PAYLOAD_SIZE {
            return Err(CstpError::Protocol(format!(
                "compressed deflate packet exceeds CSTP wire limit: {}",
                output.len() + 4
            )));
        }
        output.extend_from_slice(&self.outgoing_checksum.to_be_bytes());
        Ok(output)
    }

    pub fn decompress(
        &mut self,
        payload: &[u8],
        maximum_payload_size: usize,
    ) -> Result<Vec<u8>, CstpError> {
        if payload.len() < 4 {
            return Err(CstpError::Protocol(
                "deflate packet is missing its Adler-32 checksum".into(),
            ));
        }
        if maximum_payload_size == 0
            || maximum_payload_size > CSTP_MAX_PAYLOAD_SIZE
        {
            return Err(CstpError::InvalidOption(format!(
                "invalid decompressed packet limit: {maximum_payload_size}"
            )));
        }
        let compressed = &payload[..payload.len() - 4];
        let mut output = Vec::with_capacity(maximum_payload_size + 1);
        let input_before = self.incoming.total_in();
        self.incoming
            .decompress_vec(compressed, &mut output, FlushDecompress::Sync)
            .map_err(|error| {
                CstpError::Protocol(format!(
                    "decompress deflate packet: {error}"
                ))
            })?;
        let consumed = (self.incoming.total_in() - input_before) as usize;
        if consumed != compressed.len() {
            return Err(CstpError::Protocol(format!(
                "deflate packet has unconsumed input: {} bytes",
                compressed.len() - consumed
            )));
        }
        if output.is_empty() {
            return Err(CstpError::Protocol(
                "deflate decompressor made no progress".into(),
            ));
        }
        let expected_size =
            anyconnect_ip_packet_size(&output)?.ok_or_else(|| {
                CstpError::Protocol("truncated decompressed IP header".into())
            })?;
        if expected_size > maximum_payload_size {
            return Err(CstpError::Protocol(format!(
                "decompressed deflate packet exceeds receive limit: {expected_size}"
            )));
        }
        if output.len() != expected_size {
            return Err(CstpError::Protocol(format!(
                "decompressed deflate packet length differs from IP length: {} != {expected_size}",
                output.len()
            )));
        }
        self.incoming_checksum =
            update_adler32(self.incoming_checksum, &output);
        let expected_checksum = u32::from_be_bytes(
            payload[payload.len() - 4..]
                .try_into()
                .expect("four-byte checksum slice"),
        );
        if self.incoming_checksum != expected_checksum {
            return Err(CstpError::Protocol(format!(
                "deflate Adler-32 mismatch: expected {expected_checksum}, got {}",
                self.incoming_checksum
            )));
        }
        Ok(output)
    }
}

pub fn update_adler32(mut checksum: u32, mut payload: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let mut low = checksum & 0xffff;
    let mut high = checksum >> 16;
    while !payload.is_empty() {
        let block_size = payload.len().min(5552);
        for value in &payload[..block_size] {
            low += u32::from(*value);
            high += low;
        }
        low %= MODULUS;
        high %= MODULUS;
        payload = &payload[block_size..];
    }
    checksum = high << 16 | low;
    checksum
}

pub fn anyconnect_ip_packet_size(
    payload: &[u8],
) -> Result<Option<usize>, CstpError> {
    let Some(first) = payload.first() else {
        return Ok(None);
    };
    match first >> 4 {
        4 => {
            if payload.len() < 4 {
                return Ok(None);
            }
            let size =
                usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            if size < 20 {
                return Err(CstpError::Protocol(format!(
                    "invalid decompressed IPv4 packet length: {size}"
                )));
            }
            Ok(Some(size))
        }
        6 => {
            if payload.len() < 6 {
                return Ok(None);
            }
            let size =
                40 + usize::from(u16::from_be_bytes([payload[4], payload[5]]));
            Ok(Some(size))
        }
        version => Err(CstpError::Protocol(format!(
            "invalid decompressed IP version: {version}"
        ))),
    }
}

/// Compresses an IP packet using a negotiated stateless AnyConnect codec.
/// `Ok(None)` means the caller must send the original CSTP DATA packet.
pub fn compress_anyconnect_stateless(
    compression: CstpCompression,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CstpError> {
    if payload.len() < ANYCONNECT_MINIMUM_COMPRESSION_SIZE {
        return Ok(None);
    }
    let mut output = match compression {
        CstpCompression::OcLz4 => {
            vec![0_u8; lz4_flex::block::get_maximum_output_size(payload.len())]
        }
        _ => vec![0_u8; payload.len()],
    };
    let written = match compression {
        CstpCompression::OcLz4 => {
            match lz4_flex::block::compress_into(payload, &mut output) {
                Ok(written) => written,
                Err(_) => return Ok(None),
            }
        }
        CstpCompression::Lzs => match compress_lzs_into(&mut output, payload) {
            Ok(written) => written,
            Err(CstpError::Protocol(message))
                if message == "LZS output exceeds destination capacity" =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        },
        CstpCompression::None | CstpCompression::Deflate => return Ok(None),
    };
    if written == 0 || written > payload.len() {
        return Ok(None);
    }
    output.truncate(written);
    Ok(Some(output))
}

pub fn decompress_anyconnect_stateless(
    compression: CstpCompression,
    payload: &[u8],
    maximum_payload_size: usize,
) -> Result<Vec<u8>, CstpError> {
    if maximum_payload_size == 0 || maximum_payload_size > CSTP_MAX_PAYLOAD_SIZE
    {
        return Err(CstpError::InvalidOption(format!(
            "invalid decompressed packet limit: {maximum_payload_size}"
        )));
    }
    let mut output = vec![0_u8; maximum_payload_size];
    let written = match compression {
        CstpCompression::OcLz4 => lz4_flex::block::decompress_into(
            payload,
            &mut output,
        )
        .map_err(|error| {
            CstpError::Protocol(format!("decompress oc-lz4 packet: {error}"))
        })?,
        CstpCompression::Lzs => decompress_lzs_into(&mut output, payload)?,
        CstpCompression::None | CstpCompression::Deflate => {
            return Err(CstpError::InvalidOption(format!(
                "unsupported stateless compression: {compression:?}"
            )));
        }
    };
    if written == 0 {
        return Err(CstpError::Protocol(format!(
            "decompressed {compression:?} packet is empty"
        )));
    }
    output.truncate(written);
    Ok(output)
}

pub fn compress_lzs(payload: &[u8]) -> Result<Vec<u8>, CstpError> {
    if payload.len() > LZS_MAXIMUM_INPUT_SIZE {
        return Err(CstpError::Protocol(
            "LZS input exceeds 65536 bytes".into(),
        ));
    }
    // Literal-only output needs ceil((9*n + 16)/8) bytes. This upper bound is
    // also sufficient when matches replace literals.
    let capacity = (payload.len() * 9 + 16).div_ceil(8);
    let mut output = vec![0_u8; capacity];
    let written = compress_lzs_into(&mut output, payload)?;
    output.truncate(written);
    Ok(output)
}

pub fn decompress_lzs(
    payload: &[u8],
    maximum_payload_size: usize,
) -> Result<Vec<u8>, CstpError> {
    let mut output = vec![0_u8; maximum_payload_size];
    let written = decompress_lzs_into(&mut output, payload)?;
    output.truncate(written);
    Ok(output)
}

fn compress_lzs_into(
    destination: &mut [u8],
    source: &[u8],
) -> Result<usize, CstpError> {
    if source.len() > LZS_MAXIMUM_INPUT_SIZE {
        return Err(CstpError::Protocol(
            "LZS input exceeds 65536 bytes".into(),
        ));
    }
    let mut hash_table = vec![LZS_INVALID_OFFSET; LZS_HASH_TABLE_SIZE];
    let mut hash_chain = [LZS_INVALID_OFFSET; LZS_MAXIMUM_HISTORY];
    let mut writer = LzsBitWriter::new(destination);
    let mut input_position = 0_usize;
    while input_position + 2 < source.len() {
        let hash = usize::from(lzs_hash(source, input_position));
        let mut candidate_offset = hash_table[hash];
        hash_chain[input_position & (LZS_MAXIMUM_HISTORY - 1)] =
            candidate_offset;
        hash_table[hash] = input_position as u16;
        if candidate_offset == LZS_INVALID_OFFSET
            || usize::from(candidate_offset) + LZS_MAXIMUM_HISTORY
                <= input_position
        {
            writer.write(u32::from(source[input_position]), 9)?;
            input_position += 1;
            continue;
        }

        let mut longest_match_length = 2_usize;
        let mut longest_match_position = usize::from(candidate_offset);
        while candidate_offset != LZS_INVALID_OFFSET
            && usize::from(candidate_offset) + LZS_MAXIMUM_HISTORY
                > input_position
        {
            let candidate_position = usize::from(candidate_offset);
            let current_end = input_position + longest_match_length + 1;
            let candidate_end = candidate_position + longest_match_length + 1;
            if current_end <= source.len()
                && candidate_end <= source.len()
                && source[candidate_position + 2..candidate_end]
                    == source[input_position + 2..current_end]
            {
                longest_match_position = candidate_position;
                let mut match_length = longest_match_length + 1;
                while input_position + match_length < source.len()
                    && source[input_position + match_length]
                        == source[candidate_position + match_length]
                {
                    match_length += 1;
                }
                longest_match_length = match_length;
                if input_position + longest_match_length == source.len() {
                    break;
                }
            }
            candidate_offset =
                hash_chain[candidate_position & (LZS_MAXIMUM_HISTORY - 1)];
        }

        write_lzs_match(
            &mut writer,
            input_position - longest_match_position,
            longest_match_length,
        )?;
        if input_position + longest_match_length
            >= source.len().saturating_sub(2)
        {
            input_position += longest_match_length;
            break;
        }
        input_position += 1;
        for _ in 0..longest_match_length - 1 {
            let hash = usize::from(lzs_hash(source, input_position));
            hash_chain[input_position & (LZS_MAXIMUM_HISTORY - 1)] =
                hash_table[hash];
            hash_table[hash] = input_position as u16;
            input_position += 1;
        }
    }

    if input_position + 2 == source.len() {
        let hash = usize::from(lzs_hash(source, input_position));
        let candidate_offset = hash_table[hash];
        if candidate_offset != LZS_INVALID_OFFSET
            && usize::from(candidate_offset) + LZS_MAXIMUM_HISTORY
                > input_position
        {
            write_lzs_match(
                &mut writer,
                input_position - usize::from(candidate_offset),
                2,
            )?;
        } else {
            writer.write(u32::from(source[input_position]), 9)?;
            writer.write(u32::from(source[input_position + 1]), 9)?;
        }
    } else if input_position + 1 == source.len() {
        writer.write(u32::from(source[input_position]), 9)?;
    }
    writer.write(0xc000, 16)?;
    Ok(writer.bytes_written())
}

fn lzs_hash(source: &[u8], position: usize) -> u16 {
    u16::from(source[position]) << 8 | u16::from(source[position + 1])
}

fn write_lzs_match(
    writer: &mut LzsBitWriter<'_>,
    offset: usize,
    length: usize,
) -> Result<(), CstpError> {
    if offset < 0x80 {
        writer.write((0x180 | offset) as u32, 9)?;
    } else {
        writer.write((0x1000 | offset) as u32, 13)?;
    }
    if length < 5 {
        return writer.write((length - 2) as u32, 2);
    }
    if length < 8 {
        return writer.write((length + 7) as u32, 4);
    }
    let mut remaining_length = length + 7;
    while remaining_length >= 30 {
        writer.write(0xff, 8)?;
        remaining_length -= 30;
    }
    if remaining_length >= 15 {
        writer.write((0xf0 + remaining_length - 15) as u32, 8)
    } else {
        writer.write(remaining_length as u32, 4)
    }
}

fn decompress_lzs_into(
    destination: &mut [u8],
    source: &[u8],
) -> Result<usize, CstpError> {
    let mut reader = LzsBitReader::new(source);
    let mut written = 0_usize;
    loop {
        let code = reader.read(9)?;
        if code < 0x100 {
            if written >= destination.len() {
                return Err(output_capacity_error());
            }
            destination[written] = code as u8;
            written += 1;
            continue;
        }
        if code == 0x180 {
            return Ok(written);
        }
        let mut offset = (code & 0x7f) as usize;
        if code < 0x180 {
            offset = offset << 4 | reader.read(4)? as usize;
        }
        if offset == 0 || offset > written {
            return Err(CstpError::Protocol("invalid LZS match offset".into()));
        }

        let mut length_code = reader.read(2)?;
        let mut length = length_code as usize + 2;
        if length_code == 3 {
            length_code = reader.read(2)?;
            length = length_code as usize + 5;
            if length_code == 3 {
                length = 8;
                loop {
                    length_code = reader.read(4)?;
                    let addition = length_code as usize;
                    if addition
                        > destination.len().saturating_sub(written + length)
                    {
                        return Err(output_capacity_error());
                    }
                    length += addition;
                    if length_code != 15 {
                        break;
                    }
                }
            }
        }
        if length > destination.len().saturating_sub(written) {
            return Err(output_capacity_error());
        }
        for _ in 0..length {
            destination[written] = destination[written - offset];
            written += 1;
        }
    }
}

fn output_capacity_error() -> CstpError {
    CstpError::Protocol("LZS output exceeds destination capacity".into())
}

struct LzsBitWriter<'a> {
    destination: &'a mut [u8],
    bit_offset: usize,
}

impl<'a> LzsBitWriter<'a> {
    fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            bit_offset: 0,
        }
    }

    fn write(&mut self, value: u32, bit_count: usize) -> Result<(), CstpError> {
        if bit_count > 32
            || self.bit_offset + bit_count > self.destination.len() * 8
        {
            return Err(output_capacity_error());
        }
        for index in (0..bit_count).rev() {
            let byte_index = self.bit_offset / 8;
            let bit_index = 7 - self.bit_offset % 8;
            let mask = 1_u8 << bit_index;
            if value & (1 << index) != 0 {
                self.destination[byte_index] |= mask;
            } else {
                self.destination[byte_index] &= !mask;
            }
            self.bit_offset += 1;
        }
        Ok(())
    }

    fn bytes_written(&self) -> usize {
        self.bit_offset / 8
    }
}

struct LzsBitReader<'a> {
    source: &'a [u8],
    bit_offset: usize,
}

impl<'a> LzsBitReader<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            bit_offset: 0,
        }
    }

    fn read(&mut self, bit_count: usize) -> Result<u32, CstpError> {
        if bit_count > 32 || self.bit_offset + bit_count > self.source.len() * 8
        {
            return Err(CstpError::Protocol("truncated LZS bitstream".into()));
        }
        let mut value = 0_u32;
        for _ in 0..bit_count {
            let byte_index = self.bit_offset / 8;
            let bit_index = 7 - self.bit_offset % 8;
            value = value << 1
                | u32::from(self.source[byte_index] >> bit_index & 1);
            self.bit_offset += 1;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repetitive_ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 400];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&400_u16.to_be_bytes());
        for byte in &mut packet[20..] {
            *byte = b'A';
        }
        packet
    }

    #[test]
    fn lzs_round_trips_literals_short_and_long_matches() {
        for input in [
            Vec::new(),
            b"x".to_vec(),
            b"xy".to_vec(),
            b"abcabc".to_vec(),
            b"abcabcabcabcabcabcabcabcabcabc".to_vec(),
            (0_u8..=255).cycle().take(5000).collect(),
        ] {
            let compressed = compress_lzs(&input).unwrap();
            let decompressed =
                decompress_lzs(&compressed, input.len().max(1)).unwrap();
            assert_eq!(decompressed, input);
        }
    }

    #[test]
    fn stateless_codecs_round_trip_and_small_packets_fall_back() {
        let packet = repetitive_ipv4_packet();
        for compression in [CstpCompression::OcLz4, CstpCompression::Lzs] {
            let compressed =
                compress_anyconnect_stateless(compression, &packet)
                    .unwrap()
                    .expect("repetitive packet should compress");
            assert!(compressed.len() < packet.len());
            assert_eq!(
                decompress_anyconnect_stateless(compression, &compressed, 400)
                    .unwrap(),
                packet
            );
        }
        assert!(
            compress_anyconnect_stateless(CstpCompression::Lzs, &[0; 39])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn decompression_rejects_truncation_and_limits() {
        assert!(decompress_lzs(&[0], 10).is_err());
        let compressed = compress_lzs(&[7; 100]).unwrap();
        assert!(decompress_lzs(&compressed, 99).is_err());
        assert!(
            decompress_anyconnect_stateless(
                CstpCompression::OcLz4,
                &[1, 2, 3],
                CSTP_MAX_PAYLOAD_SIZE + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn matches_pinned_go_sing_openconnect_vectors() {
        let literal_and_match = b"abcabcabcabcabcabcabcabcabcabc";
        assert_eq!(
            hex::encode(compress_lzs(literal_and_match).unwrap()),
            "30988c783ff4c000"
        );

        let mut ipv4 = vec![0_u8; 100];
        ipv4[..4].copy_from_slice(&[0x45, 0, 0, 100]);
        assert_eq!(
            hex::encode(compress_lzs(&ipv4).unwrap()),
            "228000064c1981ffffffbc00"
        );
        let go_lz4 = hex::decode(
            "5f450000640001003a000200e00000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(
            decompress_anyconnect_stateless(
                CstpCompression::OcLz4,
                &go_lz4,
                100,
            )
            .unwrap(),
            ipv4
        );
    }

    #[test]
    fn stateful_deflate_round_trips_multiple_ip_packets() {
        let mut compressor = AnyConnectDeflateState::new();
        let mut decompressor = AnyConnectDeflateState::new();
        let first = repetitive_ipv4_packet();
        let mut second = first.clone();
        second[20..40].fill(b'B');
        for packet in [first, second] {
            let compressed = compressor.compress(&packet).unwrap();
            assert!(compressed.len() < packet.len());
            assert_eq!(
                decompressor.decompress(&compressed, 400).unwrap(),
                packet
            );
        }
    }

    #[test]
    fn stateful_deflate_validates_ip_length_and_checksum() {
        let mut compressor = AnyConnectDeflateState::new();
        let packet = repetitive_ipv4_packet();
        let mut compressed = compressor.compress(&packet).unwrap();
        *compressed.last_mut().unwrap() ^= 1;
        assert!(
            AnyConnectDeflateState::new()
                .decompress(&compressed, 400)
                .is_err()
        );

        let mut invalid = packet;
        invalid[2..4].copy_from_slice(&399_u16.to_be_bytes());
        let compressed =
            AnyConnectDeflateState::new().compress(&invalid).unwrap();
        assert!(
            AnyConnectDeflateState::new()
                .decompress(&compressed, 400)
                .is_err()
        );
    }

    #[test]
    fn decodes_consecutive_pinned_go_deflate_vectors() {
        let first = repetitive_ipv4_packet();
        let mut second = first.clone();
        second[20..40].fill(b'B');
        let vectors = [
            "7265609cc080061c47c1800100000000ffff1ecb6153",
            "c2161f4e58c0680cd1278600000000ffff7390c2b9",
        ];
        let mut state = AnyConnectDeflateState::new();
        for (index, encoded) in vectors.into_iter().enumerate() {
            let decoded = state
                .decompress(&hex::decode(encoded).unwrap(), 400)
                .unwrap();
            let expected = if index == 0 { &first } else { &second };
            assert_eq!(&decoded, expected);
        }
    }
}
