//! Pulse Secure IF-T, EAP, and AVP wire primitives.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PULSE_VENDOR_TCG: u32 = 0x5597;
pub const PULSE_VENDOR_JUNIPER: u32 = 0x0a4c;
pub const PULSE_VENDOR_JUNIPER2: u32 = 0x0583;

pub const PULSE_IFT_VERSION_REQUEST: u32 = 1;
pub const PULSE_IFT_VERSION_RESPONSE: u32 = 2;
pub const PULSE_IFT_CLIENT_AUTH_CHALLENGE: u32 = 5;
pub const PULSE_IFT_CLIENT_AUTH_RESPONSE: u32 = 6;
pub const PULSE_IFT_CLIENT_AUTH_SUCCESS: u32 = 7;
pub const PULSE_IFT_AUTHENTICATION_JUNIPER: u32 =
    (PULSE_VENDOR_JUNIPER << 8) | 1;

pub const PULSE_EAP_REQUEST: u8 = 1;
pub const PULSE_EAP_RESPONSE: u8 = 2;
pub const PULSE_EAP_SUCCESS: u8 = 3;
pub const PULSE_EAP_FAILURE: u8 = 4;
pub const PULSE_EAP_TYPE_IDENTITY: u8 = 1;
pub const PULSE_EAP_TYPE_GTC: u8 = 6;
pub const PULSE_EAP_TYPE_TLS: u8 = 0x0d;
pub const PULSE_EAP_TYPE_TTLS: u8 = 0x15;
pub const PULSE_EAP_TYPE_EXPANDED: u8 = 0xfe;
pub const PULSE_EAP_EXPANDED_JUNIPER: u32 =
    ((PULSE_EAP_TYPE_EXPANDED as u32) << 24) | PULSE_VENDOR_JUNIPER;
pub const PULSE_AVP_EAP_MESSAGE: u32 = 79;

pub const PULSE_IFT_HEADER_SIZE: usize = 16;
pub const PULSE_AUTHENTICATION_FRAME_LIMIT: usize = 16 * 1024;
pub const PULSE_CONFIGURATION_FRAME_LIMIT: usize = 1024 * 1024;
pub const PULSE_MAXIMUM_AUTHENTICATION_STEPS: usize = 64;

pub const PULSE_AVP_FLAG_VENDOR: u8 = 0x80;
pub const PULSE_AVP_FLAG_MANDATORY: u8 = 0x40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseIftFrame {
    pub vendor: u32,
    pub frame_type: u32,
    pub sequence: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseEapPacket {
    pub code: u8,
    pub identifier: u8,
    pub type_value: u32,
    pub subtype: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseAvp {
    pub code: u32,
    pub vendor: u32,
    pub flags: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PulseIftError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid Pulse IF-T frame limit: {0}")]
    InvalidFrameLimit(usize),
    #[error("invalid Pulse IF-T frame length: {0}")]
    InvalidFrameLength(u32),
    #[error("Pulse IF-T payload is too large: {0}")]
    PayloadTooLarge(usize),
    #[error("EAP packet is shorter than its header")]
    ShortEapHeader,
    #[error("EAP length mismatch: {encoded} != {actual}")]
    EapLengthMismatch { encoded: usize, actual: usize },
    #[error("terminal EAP packet has a payload")]
    TerminalEapPayload,
    #[error("EAP packet omitted its type")]
    MissingEapType,
    #[error("expanded EAP packet is too short")]
    ShortExpandedEap,
    #[error("EAP payload is too large: {0}")]
    EapPayloadTooLarge(usize),
    #[error("unexpected Pulse IF-T authentication frame")]
    UnexpectedAuthenticationFrame,
    #[error("IF-T authentication frame omitted Juniper/1 auth type")]
    MissingJuniperAuthentication,
    #[error("unexpected Pulse EAP code: {0}")]
    UnexpectedEapCode(u8),
    #[error("AVP stream ended inside a header")]
    ShortAvpHeader,
    #[error("invalid Pulse AVP length: {0}")]
    InvalidAvpLength(usize),
    #[error("AVP padding exceeds its packet")]
    InvalidAvpPadding,
    #[error("AVP is too large: {0}")]
    AvpTooLarge(usize),
}

#[derive(Debug, Clone, Default)]
pub struct PulseIftEncoder {
    next_sequence: u32,
}

/// Buffered, sequence-owning IF-T connection used by Pulse authentication and
/// tunnel sessions. All writes are flushed as complete IF-T frames.
pub struct PulseIftConnection<S> {
    stream: S,
    encoder: PulseIftEncoder,
}

impl<S> PulseIftConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            encoder: PulseIftEncoder::default(),
        }
    }

    pub async fn read_frame(
        &mut self,
        maximum_length: usize,
    ) -> Result<PulseIftFrame, PulseIftError> {
        read_pulse_ift_frame(&mut self.stream, maximum_length).await
    }

    pub async fn write_frame(
        &mut self,
        vendor: u32,
        frame_type: u32,
        payload: &[u8],
    ) -> Result<(), PulseIftError> {
        self.encoder
            .write(&mut self.stream, vendor, frame_type, payload)
            .await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub fn next_sequence(&self) -> u32 {
        self.encoder.next_sequence()
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl PulseIftEncoder {
    pub fn with_sequence(sequence: u32) -> Self {
        Self {
            next_sequence: sequence,
        }
    }

    pub fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    pub fn encode(
        &mut self,
        vendor: u32,
        frame_type: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, PulseIftError> {
        let total = PULSE_IFT_HEADER_SIZE
            .checked_add(payload.len())
            .filter(|length| *length <= u32::MAX as usize)
            .ok_or(PulseIftError::PayloadTooLarge(payload.len()))?;
        let mut result = Vec::with_capacity(total);
        result.extend_from_slice(&vendor.to_be_bytes());
        result.extend_from_slice(&frame_type.to_be_bytes());
        result.extend_from_slice(&(total as u32).to_be_bytes());
        result.extend_from_slice(&self.next_sequence.to_be_bytes());
        result.extend_from_slice(payload);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(result)
    }

    pub async fn write<W>(
        &mut self,
        writer: &mut W,
        vendor: u32,
        frame_type: u32,
        payload: &[u8],
    ) -> Result<(), PulseIftError>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        writer
            .write_all(&self.encode(vendor, frame_type, payload)?)
            .await?;
        Ok(())
    }
}

pub async fn read_pulse_ift_frame<R>(
    reader: &mut R,
    maximum_length: usize,
) -> Result<PulseIftFrame, PulseIftError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    if maximum_length < PULSE_IFT_HEADER_SIZE {
        return Err(PulseIftError::InvalidFrameLimit(maximum_length));
    }
    let mut header = [0_u8; PULSE_IFT_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let total_length = u32::from_be_bytes(header[8..12].try_into().unwrap());
    if total_length < PULSE_IFT_HEADER_SIZE as u32
        || total_length as usize > maximum_length
    {
        return Err(PulseIftError::InvalidFrameLength(total_length));
    }
    let mut payload = vec![0_u8; total_length as usize - PULSE_IFT_HEADER_SIZE];
    reader.read_exact(&mut payload).await?;
    Ok(PulseIftFrame {
        vendor: u32::from_be_bytes(header[0..4].try_into().unwrap()),
        frame_type: u32::from_be_bytes(header[4..8].try_into().unwrap()),
        sequence: u32::from_be_bytes(header[12..16].try_into().unwrap()),
        payload,
    })
}

pub fn parse_pulse_eap(
    content: &[u8],
) -> Result<PulseEapPacket, PulseIftError> {
    if content.len() < 4 {
        return Err(PulseIftError::ShortEapHeader);
    }
    let encoded =
        u16::from_be_bytes(content[2..4].try_into().unwrap()) as usize;
    if encoded != content.len() {
        return Err(PulseIftError::EapLengthMismatch {
            encoded,
            actual: content.len(),
        });
    }
    let mut packet = PulseEapPacket {
        code: content[0],
        identifier: content[1],
        type_value: 0,
        subtype: 0,
        payload: Vec::new(),
    };
    if matches!(packet.code, PULSE_EAP_SUCCESS | PULSE_EAP_FAILURE) {
        if content.len() != 4 {
            return Err(PulseIftError::TerminalEapPayload);
        }
        return Ok(packet);
    }
    if content.len() < 5 {
        return Err(PulseIftError::MissingEapType);
    }
    packet.type_value = u32::from(content[4]);
    packet.payload = content[5..].to_vec();
    if content[4] == PULSE_EAP_TYPE_EXPANDED {
        if content.len() < 12 {
            return Err(PulseIftError::ShortExpandedEap);
        }
        packet.type_value =
            u32::from_be_bytes(content[4..8].try_into().unwrap());
        packet.subtype = u32::from_be_bytes(content[8..12].try_into().unwrap());
        packet.payload = content[12..].to_vec();
    }
    Ok(packet)
}

pub fn build_pulse_eap(
    code: u8,
    identifier: u8,
    type_value: u8,
    subtype: u32,
    payload: &[u8],
) -> Result<Vec<u8>, PulseIftError> {
    let header_length: usize = if type_value == PULSE_EAP_TYPE_EXPANDED {
        12
    } else {
        5
    };
    let total = header_length
        .checked_add(payload.len())
        .filter(|length| *length <= u16::MAX as usize)
        .ok_or(PulseIftError::EapPayloadTooLarge(payload.len()))?;
    let mut content = vec![0_u8; total];
    content[0] = code;
    content[1] = identifier;
    content[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    if type_value == PULSE_EAP_TYPE_EXPANDED {
        content[4..8]
            .copy_from_slice(&PULSE_EAP_EXPANDED_JUNIPER.to_be_bytes());
        content[8..12].copy_from_slice(&subtype.to_be_bytes());
    } else {
        content[4] = type_value;
    }
    content[header_length..].copy_from_slice(payload);
    Ok(content)
}

pub fn parse_pulse_authentication_eap(
    frame: &PulseIftFrame,
) -> Result<PulseEapPacket, PulseIftError> {
    if frame.vendor & 0x00ff_ffff != PULSE_VENDOR_TCG
        || frame.frame_type != PULSE_IFT_CLIENT_AUTH_CHALLENGE
    {
        return Err(PulseIftError::UnexpectedAuthenticationFrame);
    }
    if frame.payload.len() < 4
        || u32::from_be_bytes(frame.payload[..4].try_into().unwrap())
            != PULSE_IFT_AUTHENTICATION_JUNIPER
    {
        return Err(PulseIftError::MissingJuniperAuthentication);
    }
    let packet = parse_pulse_eap(&frame.payload[4..])?;
    if packet.code != PULSE_EAP_REQUEST {
        return Err(PulseIftError::UnexpectedEapCode(packet.code));
    }
    Ok(packet)
}

pub fn build_pulse_authentication_payload(packet: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + packet.len());
    payload.extend_from_slice(&PULSE_IFT_AUTHENTICATION_JUNIPER.to_be_bytes());
    payload.extend_from_slice(packet);
    payload
}

pub fn parse_pulse_avps(
    mut content: &[u8],
) -> Result<Vec<PulseAvp>, PulseIftError> {
    let mut attributes = Vec::new();
    while !content.is_empty() {
        if content.len() < 8 {
            return Err(PulseIftError::ShortAvpHeader);
        }
        let code = u32::from_be_bytes(content[0..4].try_into().unwrap());
        let flags = content[4];
        let attribute_length =
            (u32::from_be_bytes(content[4..8].try_into().unwrap())
                & 0x00ff_ffff) as usize;
        let header_length = if flags & PULSE_AVP_FLAG_VENDOR != 0 {
            12
        } else {
            8
        };
        if attribute_length < header_length || attribute_length > content.len()
        {
            return Err(PulseIftError::InvalidAvpLength(attribute_length));
        }
        let aligned_length = (attribute_length + 3) & !3;
        if aligned_length > content.len() {
            return Err(PulseIftError::InvalidAvpPadding);
        }
        let vendor = if header_length == 12 {
            u32::from_be_bytes(content[8..12].try_into().unwrap())
        } else {
            0
        };
        attributes.push(PulseAvp {
            code,
            vendor,
            flags,
            data: content[header_length..attribute_length].to_vec(),
        });
        content = &content[aligned_length..];
    }
    Ok(attributes)
}

pub fn append_pulse_avp(
    destination: &mut Vec<u8>,
    code: u32,
    vendor: u32,
    data: &[u8],
) -> Result<(), PulseIftError> {
    let header_length: usize = if vendor == 0 { 8 } else { 12 };
    let attribute_length = header_length
        .checked_add(data.len())
        .filter(|length| *length <= 0x00ff_ffff)
        .ok_or(PulseIftError::AvpTooLarge(data.len()))?;
    let aligned_length = (attribute_length + 3) & !3;
    let start = destination.len();
    destination.resize(start + aligned_length, 0);
    destination[start..start + 4].copy_from_slice(&code.to_be_bytes());
    let flags = PULSE_AVP_FLAG_MANDATORY
        | if vendor == 0 {
            0
        } else {
            PULSE_AVP_FLAG_VENDOR
        };
    let encoded_length = (u32::from(flags) << 24) | attribute_length as u32;
    destination[start + 4..start + 8]
        .copy_from_slice(&encoded_length.to_be_bytes());
    if vendor != 0 {
        destination[start + 8..start + 12]
            .copy_from_slice(&vendor.to_be_bytes());
    }
    destination[start + header_length..start + attribute_length]
        .copy_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ift_frames_round_trip_and_sequence() {
        let mut encoder = PulseIftEncoder::with_sequence(7);
        let first = encoder.encode(PULSE_VENDOR_TCG, 5, b"abc").unwrap();
        let second = encoder.encode(PULSE_VENDOR_JUNIPER, 6, b"def").unwrap();
        assert_eq!(encoder.next_sequence(), 9);
        let mut wire = first;
        wire.extend_from_slice(&second);
        let mut reader = std::io::Cursor::new(wire);
        let first = read_pulse_ift_frame(&mut reader, 1024).await.unwrap();
        let second = read_pulse_ift_frame(&mut reader, 1024).await.unwrap();
        assert_eq!((first.sequence, first.payload), (7, b"abc".to_vec()));
        assert_eq!((second.sequence, second.payload), (8, b"def".to_vec()));
    }

    #[tokio::test]
    async fn ift_reader_rejects_invalid_lengths() {
        let mut reader = std::io::Cursor::new(vec![0_u8; 16]);
        assert!(matches!(
            read_pulse_ift_frame(&mut reader, 15).await,
            Err(PulseIftError::InvalidFrameLimit(15))
        ));
        let mut wire = vec![0_u8; 16];
        wire[8..12].copy_from_slice(&15_u32.to_be_bytes());
        let mut reader = std::io::Cursor::new(wire);
        assert!(matches!(
            read_pulse_ift_frame(&mut reader, 1024).await,
            Err(PulseIftError::InvalidFrameLength(15))
        ));
    }

    #[test]
    fn ordinary_and_expanded_eap_round_trip() {
        for (kind, subtype) in
            [(PULSE_EAP_TYPE_IDENTITY, 0), (PULSE_EAP_TYPE_EXPANDED, 3)]
        {
            let encoded = build_pulse_eap(
                PULSE_EAP_RESPONSE,
                9,
                kind,
                subtype,
                b"payload",
            )
            .unwrap();
            let parsed = parse_pulse_eap(&encoded).unwrap();
            assert_eq!(parsed.code, PULSE_EAP_RESPONSE);
            assert_eq!(parsed.identifier, 9);
            assert_eq!(parsed.subtype, subtype);
            assert_eq!(parsed.payload, b"payload");
        }
    }

    #[test]
    fn terminal_and_malformed_eap_are_bounded() {
        assert_eq!(
            parse_pulse_eap(&[PULSE_EAP_SUCCESS, 1, 0, 4]).unwrap().code,
            PULSE_EAP_SUCCESS
        );
        assert!(matches!(
            parse_pulse_eap(&[1, 2, 0, 5]),
            Err(PulseIftError::EapLengthMismatch { .. })
        ));
        assert!(matches!(
            parse_pulse_eap(&[PULSE_EAP_FAILURE, 1, 0, 5, 0]),
            Err(PulseIftError::TerminalEapPayload)
        ));
    }

    #[test]
    fn authentication_envelope_validates_vendor_type_and_request() {
        let eap = build_pulse_eap(
            PULSE_EAP_REQUEST,
            2,
            PULSE_EAP_TYPE_GTC,
            0,
            b"token",
        )
        .unwrap();
        let frame = PulseIftFrame {
            vendor: PULSE_VENDOR_TCG,
            frame_type: PULSE_IFT_CLIENT_AUTH_CHALLENGE,
            sequence: 1,
            payload: build_pulse_authentication_payload(&eap),
        };
        assert_eq!(
            parse_pulse_authentication_eap(&frame).unwrap().payload,
            b"token"
        );
        let mut wrong = frame;
        wrong.frame_type = PULSE_IFT_CLIENT_AUTH_RESPONSE;
        assert!(matches!(
            parse_pulse_authentication_eap(&wrong),
            Err(PulseIftError::UnexpectedAuthenticationFrame)
        ));
    }

    #[test]
    fn avps_round_trip_vendor_flags_and_padding() {
        let mut wire = Vec::new();
        append_pulse_avp(&mut wire, PULSE_AVP_EAP_MESSAGE, 0, b"abc").unwrap();
        append_pulse_avp(&mut wire, 7, PULSE_VENDOR_JUNIPER2, b"value")
            .unwrap();
        let parsed = parse_pulse_avps(&wire).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].data, b"abc");
        assert_eq!(parsed[1].vendor, PULSE_VENDOR_JUNIPER2);
        assert_eq!(parsed[1].data, b"value");
        assert_ne!(parsed[1].flags & PULSE_AVP_FLAG_VENDOR, 0);
    }
}
