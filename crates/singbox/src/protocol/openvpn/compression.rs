use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::{FragmentCodec, FragmentError};

pub const OPENVPN_LZO_COMPRESS_BYTE: u8 = 0x66;
pub const OPENVPN_LZ4_COMPRESS_BYTE: u8 = 0x69;
pub const OPENVPN_NO_COMPRESS_BYTE: u8 = 0xfa;
pub const OPENVPN_NO_COMPRESS_BYTE_SWAP: u8 = 0xfb;
pub const OPENVPN_COMPRESS_V2_INDICATOR_BYTE: u8 = 0x50;
pub const OPENVPN_COMPRESS_V2_SUBTYPE_NONE: u8 = 0;
pub const OPENVPN_COMPRESS_V2_SUBTYPE_LZ4: u8 = 1;
pub const OPENVPN_MAX_DECOMPRESSED_SIZE: usize = 1 << 16;
pub const OPENVPN_COMPRESSION_THRESHOLD: usize = 100;

const LZO_ADAPTIVE_SAMPLE_DURATION: Duration = Duration::from_secs(2);
const LZO_ADAPTIVE_OFF_DURATION: Duration = Duration::from_secs(60);
const LZO_ADAPTIVE_MINIMUM_BYTES: usize = 1000;
const LZO_ADAPTIVE_SAVE_PERCENT: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionAlgorithm {
    #[default]
    None,
    Stub,
    Lzo,
    Lz4,
    StubV2,
    Lz4V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompressionSettings {
    pub algorithm: CompressionAlgorithm,
    pub swap: bool,
    pub adaptive: bool,
    pub asymmetric: bool,
}

impl CompressionSettings {
    pub fn apply(
        &mut self,
        directive: CompressionDirective,
    ) -> Result<(), CompressionError> {
        match directive {
            CompressionDirective::Compress(value) => match value.trim() {
                "" | "stub" => {
                    self.algorithm = CompressionAlgorithm::Stub;
                    self.swap = true;
                }
                "stub-v2" => self.algorithm = CompressionAlgorithm::StubV2,
                "lzo" => {
                    self.algorithm = CompressionAlgorithm::Lzo;
                    self.adaptive = false;
                    self.swap = false;
                }
                "lz4" => {
                    self.algorithm = CompressionAlgorithm::Lz4;
                    self.swap = true;
                }
                "lz4-v2" => self.algorithm = CompressionAlgorithm::Lz4V2,
                "migrate" | "none" | "no" | "disabled" | "off" => {
                    *self = Self::default();
                }
                value => {
                    return Err(CompressionError::Unsupported(value.into()));
                }
            },
            CompressionDirective::CompLzo(value) => {
                self.swap = false;
                match value.trim() {
                    "" | "adaptive" => {
                        self.algorithm = CompressionAlgorithm::Lzo;
                        self.adaptive = true;
                        self.asymmetric = false;
                    }
                    "yes" => {
                        self.algorithm = CompressionAlgorithm::Lzo;
                        self.adaptive = false;
                        self.asymmetric = false;
                    }
                    "asym" => {
                        self.algorithm = CompressionAlgorithm::Lzo;
                        self.adaptive = false;
                        self.asymmetric = true;
                    }
                    "no" => {
                        self.algorithm = CompressionAlgorithm::Stub;
                        self.adaptive = false;
                    }
                    "none" | "disabled" | "off" => *self = Self::default(),
                    value => {
                        return Err(CompressionError::Unsupported(
                            value.into(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn framing_enabled(self) -> bool {
        self.algorithm != CompressionAlgorithm::None
    }

    pub fn non_stub_enabled(self) -> bool {
        matches!(
            self.algorithm,
            CompressionAlgorithm::Lzo
                | CompressionAlgorithm::Lz4
                | CompressionAlgorithm::Lz4V2
        )
    }

    pub fn framing_overhead(self) -> usize {
        usize::from(matches!(
            self.algorithm,
            CompressionAlgorithm::Stub
                | CompressionAlgorithm::Lzo
                | CompressionAlgorithm::Lz4
        ))
    }

    pub fn compresses_outbound(self, policy: AllowCompressionPolicy) -> bool {
        self.algorithm == CompressionAlgorithm::Lzo
            && !self.asymmetric
            && policy == AllowCompressionPolicy::Yes
    }
}

pub enum CompressionDirective<'a> {
    Compress(&'a str),
    CompLzo(&'a str),
}

pub fn resolve_compression_settings(
    compression: &str,
    compression_lzo: &str,
) -> Result<CompressionSettings, CompressionError> {
    let mut settings = CompressionSettings::default();
    if !compression.trim().is_empty() {
        settings.apply(CompressionDirective::Compress(compression))?;
    }
    if !compression_lzo.trim().is_empty() {
        settings.apply(CompressionDirective::CompLzo(compression_lzo))?;
    }
    Ok(settings)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowCompressionPolicy {
    StubOnly,
    Asymmetric,
    Yes,
}

pub fn resolve_allow_compression_policy(
    value: &str,
    settings: CompressionSettings,
) -> Result<AllowCompressionPolicy, CompressionError> {
    if value.is_empty() {
        return Ok(if settings.non_stub_enabled() {
            AllowCompressionPolicy::Asymmetric
        } else {
            AllowCompressionPolicy::StubOnly
        });
    }
    let policy = match value {
        "no" => AllowCompressionPolicy::StubOnly,
        "asym" => AllowCompressionPolicy::Asymmetric,
        "yes" => AllowCompressionPolicy::Yes,
        _ => return Err(CompressionError::InvalidAllowPolicy),
    };
    if policy == AllowCompressionPolicy::StubOnly && settings.non_stub_enabled()
    {
        return Err(CompressionError::AllowPolicyConflict);
    }
    Ok(policy)
}

#[derive(Debug, Default)]
struct AdaptiveState {
    disabled: bool,
    next: Option<Instant>,
    total_bytes: usize,
    compressed_bytes: usize,
}

#[derive(Debug)]
pub struct DataChannelFraming {
    compression: CompressionSettings,
    compress_outbound: bool,
    fragment_enabled: bool,
    fragments: FragmentCodec,
    adaptive: Mutex<AdaptiveState>,
}

impl Clone for DataChannelFraming {
    fn clone(&self) -> Self {
        // A cloned endpoint template starts a fresh per-session fragment and
        // adaptive-compression state; carrying sequence/reassembly state
        // across OpenVPN peers would corrupt both wire directions.
        Self {
            compression: self.compression,
            compress_outbound: self.compress_outbound,
            fragment_enabled: self.fragment_enabled,
            fragments: FragmentCodec::new(),
            adaptive: Mutex::new(AdaptiveState::default()),
        }
    }
}

impl DataChannelFraming {
    pub fn new(
        compression: CompressionSettings,
        fragment: u32,
        allow_compression: AllowCompressionPolicy,
    ) -> Option<Self> {
        (compression.framing_enabled() || fragment > 0).then(|| Self {
            compression,
            compress_outbound: compression
                .compresses_outbound(allow_compression),
            fragment_enabled: fragment > 0,
            fragments: FragmentCodec::new(),
            adaptive: Mutex::new(AdaptiveState::default()),
        })
    }

    pub fn payload_overhead(&self) -> usize {
        self.compression.framing_overhead()
            + usize::from(self.fragment_enabled) * 4
    }

    pub fn encode(
        &self,
        payload: &[u8],
        fragment_size: usize,
    ) -> Result<Vec<Vec<u8>>, CompressionError> {
        let framed = match self.compression.algorithm {
            CompressionAlgorithm::None => payload.to_vec(),
            CompressionAlgorithm::Stub => {
                apply_stub_compression_frame(payload, self.compression.swap)
            }
            CompressionAlgorithm::Lz4 => {
                apply_stub_compression_frame(payload, true)
            }
            CompressionAlgorithm::Lzo => {
                self.encode_lzo_frame(payload, Instant::now())
            }
            CompressionAlgorithm::StubV2 | CompressionAlgorithm::Lz4V2 => {
                escape_v2_stub_compression(payload)
            }
        };
        if self.fragment_enabled {
            self.fragments
                .encode(&framed, fragment_size)
                .map_err(Into::into)
        } else {
            Ok(vec![framed])
        }
    }

    pub fn decode(
        &self,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, CompressionError> {
        let framed = if self.fragment_enabled {
            let Some(reassembled) = self.fragments.decode(payload)? else {
                return Ok(None);
            };
            reassembled
        } else {
            payload.to_vec()
        };
        let decoded = match self.compression.algorithm {
            CompressionAlgorithm::None => framed,
            CompressionAlgorithm::Stub => {
                unframe_stub_compression(&framed, self.compression.swap)?
            }
            CompressionAlgorithm::Lzo => decode_lzo_frame(&framed)?,
            CompressionAlgorithm::Lz4 => decode_lz4_v1_frame(&framed)?,
            CompressionAlgorithm::StubV2 | CompressionAlgorithm::Lz4V2 => {
                unwrap_v2_compression(&framed, self.compression.algorithm)?
            }
        };
        Ok(Some(decoded))
    }

    fn encode_lzo_frame(&self, payload: &[u8], now: Instant) -> Vec<u8> {
        if !self.compress_outbound
            || payload.len() < OPENVPN_COMPRESSION_THRESHOLD
            || !self.lzo_compression_enabled(now)
        {
            return prepend(OPENVPN_NO_COMPRESS_BYTE, payload);
        }
        let compressed = lzo1x::compress(payload);
        if self.compression.adaptive {
            let mut state = self.adaptive.lock();
            state.total_bytes += payload.len();
            state.compressed_bytes += compressed.len();
        }
        if compressed.len() >= payload.len() {
            prepend(OPENVPN_NO_COMPRESS_BYTE, payload)
        } else {
            prepend(OPENVPN_LZO_COMPRESS_BYTE, &compressed)
        }
    }

    fn lzo_compression_enabled(&self, now: Instant) -> bool {
        if !self.compression.adaptive {
            return true;
        }
        let mut state = self.adaptive.lock();
        if state.next.is_none_or(|next| now >= next) {
            if state.disabled {
                state.disabled = false;
                state.next = Some(now + LZO_ADAPTIVE_SAMPLE_DURATION);
            } else if state.total_bytes > LZO_ADAPTIVE_MINIMUM_BYTES
                && state.total_bytes - state.compressed_bytes
                    < state.total_bytes / (100 / LZO_ADAPTIVE_SAVE_PERCENT)
            {
                state.disabled = true;
                state.next = Some(now + LZO_ADAPTIVE_OFF_DURATION);
            } else {
                state.next = Some(now + LZO_ADAPTIVE_SAMPLE_DURATION);
            }
            state.total_bytes = 0;
            state.compressed_bytes = 0;
        }
        !state.disabled
    }
}

pub fn apply_stub_compression_frame(payload: &[u8], swap: bool) -> Vec<u8> {
    if !swap {
        return prepend(OPENVPN_NO_COMPRESS_BYTE, payload);
    }
    if payload.is_empty() {
        return vec![OPENVPN_NO_COMPRESS_BYTE_SWAP];
    }
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.push(OPENVPN_NO_COMPRESS_BYTE_SWAP);
    framed.extend_from_slice(&payload[1..]);
    framed.push(payload[0]);
    framed
}

pub fn unframe_stub_compression(
    framed: &[u8],
    swap: bool,
) -> Result<Vec<u8>, CompressionError> {
    let Some(marker) = framed.first() else {
        return Err(CompressionError::MissingMarker);
    };
    let expected = if swap {
        OPENVPN_NO_COMPRESS_BYTE_SWAP
    } else {
        OPENVPN_NO_COMPRESS_BYTE
    };
    if *marker != expected {
        return Err(CompressionError::InvalidMarker);
    }
    Ok(if swap {
        unswap_v1_frame_head(framed)
    } else {
        framed[1..].to_vec()
    })
}

pub fn escape_v2_stub_compression(payload: &[u8]) -> Vec<u8> {
    if payload.first() != Some(&OPENVPN_COMPRESS_V2_INDICATOR_BYTE) {
        return payload.to_vec();
    }
    let mut escaped = Vec::with_capacity(payload.len() + 2);
    escaped.extend_from_slice(&[
        OPENVPN_COMPRESS_V2_INDICATOR_BYTE,
        OPENVPN_COMPRESS_V2_SUBTYPE_NONE,
    ]);
    escaped.extend_from_slice(payload);
    escaped
}

pub fn decode_lzo_frame(framed: &[u8]) -> Result<Vec<u8>, CompressionError> {
    match framed.first() {
        None => Err(CompressionError::MissingMarker),
        Some(&OPENVPN_NO_COMPRESS_BYTE) => Ok(framed[1..].to_vec()),
        Some(&OPENVPN_LZO_COMPRESS_BYTE) => {
            lzo1x::decompress(&framed[1..], OPENVPN_MAX_DECOMPRESSED_SIZE)
                .map_err(|_| CompressionError::DecompressionFailed)
        }
        _ => Err(CompressionError::InvalidMarker),
    }
}

pub fn decode_lz4_v1_frame(framed: &[u8]) -> Result<Vec<u8>, CompressionError> {
    match framed.first() {
        None => Err(CompressionError::MissingMarker),
        Some(&OPENVPN_NO_COMPRESS_BYTE_SWAP) => {
            Ok(unswap_v1_frame_head(framed))
        }
        Some(&OPENVPN_LZ4_COMPRESS_BYTE) => {
            if framed.len() < 2 {
                return Err(CompressionError::TruncatedFrame);
            }
            let mut block = Vec::with_capacity(framed.len() - 1);
            block.push(*framed.last().unwrap());
            block.extend_from_slice(&framed[1..framed.len() - 1]);
            decompress_lz4(&block)
        }
        _ => Err(CompressionError::InvalidMarker),
    }
}

pub fn unwrap_v2_compression(
    payload: &[u8],
    algorithm: CompressionAlgorithm,
) -> Result<Vec<u8>, CompressionError> {
    if payload.first() != Some(&OPENVPN_COMPRESS_V2_INDICATOR_BYTE) {
        return Ok(payload.to_vec());
    }
    if payload.len() < 2 {
        return Err(CompressionError::TruncatedFrame);
    }
    match payload[1] {
        OPENVPN_COMPRESS_V2_SUBTYPE_NONE => Ok(payload[2..].to_vec()),
        OPENVPN_COMPRESS_V2_SUBTYPE_LZ4
            if algorithm == CompressionAlgorithm::Lz4V2 =>
        {
            decompress_lz4(&payload[2..])
        }
        OPENVPN_COMPRESS_V2_SUBTYPE_LZ4 => {
            Err(CompressionError::CompressedV2NotSupported)
        }
        subtype => Err(CompressionError::InvalidV2Subtype(subtype)),
    }
}

fn decompress_lz4(block: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if block.is_empty() {
        return Err(CompressionError::DecompressionFailed);
    }
    let mut output = vec![0; OPENVPN_MAX_DECOMPRESSED_SIZE];
    let length = lz4_flex::block::decompress_into(block, &mut output)
        .map_err(|_| CompressionError::DecompressionFailed)?;
    if length == 0 {
        return Err(CompressionError::DecompressionFailed);
    }
    output.truncate(length);
    Ok(output)
}

fn unswap_v1_frame_head(framed: &[u8]) -> Vec<u8> {
    if framed.len() <= 1 {
        return Vec::new();
    }
    let mut payload = Vec::with_capacity(framed.len() - 1);
    payload.push(*framed.last().unwrap());
    payload.extend_from_slice(&framed[1..framed.len() - 1]);
    payload
}

fn prepend(marker: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len() + 1);
    output.push(marker);
    output.extend_from_slice(payload);
    output
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompressionError {
    #[error("unsupported OpenVPN compression mode: {0}")]
    Unsupported(String),
    #[error("invalid OpenVPN allow-compression policy")]
    InvalidAllowPolicy,
    #[error("allow-compression no conflicts with enabled compression")]
    AllowPolicyConflict,
    #[error("missing OpenVPN compression marker")]
    MissingMarker,
    #[error("invalid OpenVPN compression marker")]
    InvalidMarker,
    #[error("truncated OpenVPN compression frame")]
    TruncatedFrame,
    #[error("invalid OpenVPN compression v2 subtype {0:#x}")]
    InvalidV2Subtype(u8),
    #[error("compressed LZ4 v2 payload is not supported by this framing mode")]
    CompressedV2NotSupported,
    #[error("OpenVPN block decompression failed")]
    DecompressionFailed,
    #[error(transparent)]
    Fragment(#[from] FragmentError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_compression_directive_overrides_algorithm_but_retains_flags() {
        let settings = resolve_compression_settings("lz4", "adaptive").unwrap();
        assert_eq!(settings.algorithm, CompressionAlgorithm::Lzo);
        assert!(settings.adaptive);
        assert!(!settings.swap);
        assert_eq!(
            resolve_allow_compression_policy("", settings),
            Ok(AllowCompressionPolicy::Asymmetric)
        );
        assert_eq!(
            resolve_allow_compression_policy("no", settings),
            Err(CompressionError::AllowPolicyConflict)
        );
    }

    #[test]
    fn stub_v1_swap_and_v2_escape_round_trip() {
        for swap in [false, true] {
            let framed = apply_stub_compression_frame(b"payload", swap);
            assert_eq!(
                unframe_stub_compression(&framed, swap).unwrap(),
                b"payload"
            );
        }
        let escaped = escape_v2_stub_compression(b"Ppayload");
        assert_eq!(
            unwrap_v2_compression(&escaped, CompressionAlgorithm::StubV2)
                .unwrap(),
            b"Ppayload"
        );
    }

    #[test]
    fn decodes_lzo_and_both_lz4_wire_formats() {
        let payload = vec![b'a'; 2048];
        let mut lzo = vec![OPENVPN_LZO_COMPRESS_BYTE];
        lzo.extend_from_slice(&lzo1x::compress(&payload));
        assert_eq!(decode_lzo_frame(&lzo).unwrap(), payload);

        let block = lz4_flex::block::compress(&payload);
        let mut v1 = vec![OPENVPN_LZ4_COMPRESS_BYTE];
        v1.extend_from_slice(&block[1..]);
        v1.push(block[0]);
        assert_eq!(decode_lz4_v1_frame(&v1).unwrap(), payload);

        let mut v2 = vec![
            OPENVPN_COMPRESS_V2_INDICATOR_BYTE,
            OPENVPN_COMPRESS_V2_SUBTYPE_LZ4,
        ];
        v2.extend_from_slice(&block);
        assert_eq!(
            unwrap_v2_compression(&v2, CompressionAlgorithm::Lz4V2).unwrap(),
            payload
        );
    }

    #[test]
    fn framing_combines_compression_and_fragment_reassembly() {
        let settings = resolve_compression_settings("stub-v2", "").unwrap();
        let framing = DataChannelFraming::new(
            settings,
            1,
            AllowCompressionPolicy::StubOnly,
        )
        .unwrap();
        let mut payload = vec![b'P'];
        payload.extend_from_slice(&[9; 200]);
        let fragments = framing.encode(&payload, 64).unwrap();
        assert!(fragments.len() > 1);
        let mut decoded = None;
        for fragment in fragments.into_iter().rev() {
            if let Some(value) = framing.decode(&fragment).unwrap() {
                decoded = Some(value);
            }
        }
        assert_eq!(decoded.unwrap(), payload);
        assert_eq!(framing.payload_overhead(), 4);
    }

    #[test]
    fn lzo_outbound_compression_requires_explicit_legacy_yes() {
        let settings = resolve_compression_settings("", "yes").unwrap();
        let asym = DataChannelFraming::new(
            settings,
            0,
            AllowCompressionPolicy::Asymmetric,
        )
        .unwrap();
        assert_eq!(
            asym.encode(&vec![0; 1000], 0).unwrap()[0][0],
            OPENVPN_NO_COMPRESS_BYTE
        );
        let yes =
            DataChannelFraming::new(settings, 0, AllowCompressionPolicy::Yes)
                .unwrap();
        assert_eq!(
            yes.encode(&vec![0; 1000], 0).unwrap()[0][0],
            OPENVPN_LZO_COMPRESS_BYTE
        );
    }
}
