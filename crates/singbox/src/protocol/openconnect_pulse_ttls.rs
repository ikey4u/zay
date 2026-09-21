//! Pulse EAP-TTLS fragmentation, async transport, and inner EAP-Message AVP.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};

use super::{
    PULSE_AUTHENTICATION_FRAME_LIMIT, PULSE_AVP_EAP_MESSAGE,
    PULSE_CONFIGURATION_FRAME_LIMIT, PULSE_EAP_EXPANDED_JUNIPER,
    PULSE_EAP_REQUEST, PULSE_EAP_RESPONSE, PULSE_EAP_TYPE_TTLS,
    PULSE_IFT_CLIENT_AUTH_RESPONSE, PULSE_VENDOR_TCG, PulseEapPacket,
    PulseIftConnection, PulseIftError, build_pulse_authentication_payload,
    build_pulse_eap, parse_pulse_authentication_eap, parse_pulse_eap,
};

pub const PULSE_TTLS_MAXIMUM_FRAGMENT: usize = 8192;
pub const PULSE_TTLS_FLAG_LENGTH: u8 = 0x80;
pub const PULSE_TTLS_FLAG_MORE: u8 = 0x40;
pub const PULSE_TTLS_FLAG_START: u8 = 0x20;

const PULSE_AVP_FLAG_VENDOR: u8 = 0x80;
const PULSE_AVP_FLAG_MANDATORY: u8 = 0x40;

#[derive(Debug, Error)]
pub enum PulseTtlsError {
    #[error(transparent)]
    Ift(#[from] PulseIftError),
    #[error("unexpected Pulse EAP-TTLS packet")]
    UnexpectedPacket,
    #[error("unsupported Pulse EAP-TTLS flags: {0:#04x}")]
    UnsupportedFlags(u8),
    #[error("continued Pulse EAP-TTLS fragment repeated the length flag")]
    RepeatedLength,
    #[error("invalid continued Pulse EAP-TTLS fragment length: {0}")]
    InvalidContinuedLength(usize),
    #[error("non-final Pulse EAP-TTLS fragment consumed the complete message")]
    NonFinalConsumedMessage,
    #[error("final Pulse EAP-TTLS fragment length mismatch")]
    FinalLengthMismatch,
    #[error(
        "initial fragmented Pulse EAP-TTLS packet omitted its total length"
    )]
    MissingFragmentedLength,
    #[error("invalid Pulse EAP-TTLS fragmented message length: {0}")]
    InvalidFragmentedLength(u32),
    #[error("EAP-TTLS length flag omitted its value")]
    MissingLength,
    #[error("EAP-TTLS unfragmented message length mismatch")]
    UnfragmentedLengthMismatch,
    #[error("empty Pulse EAP-TTLS data packet")]
    EmptyPacket,
    #[error("Pulse EAP-TTLS output exceeds {0} bytes")]
    OutputTooLarge(usize),
    #[error("invalid Pulse EAP-TTLS fragment acknowledgement")]
    InvalidAcknowledgement,
    #[error("inner EAP-Message AVP is too large: {0}")]
    InnerEapTooLarge(usize),
    #[error("unexpected Pulse inner EAP-TTLS AVP")]
    UnexpectedInnerAvp,
    #[error("invalid Pulse inner EAP-Message AVP length: {0}")]
    InvalidInnerAvpLength(usize),
    #[error("Pulse inner EAP-Message AVP is truncated")]
    TruncatedInnerAvp,
    #[error("unexpected Pulse inner EAP packet type")]
    UnexpectedInnerPacket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseTtlsIncomingFragment {
    pub identifier: u8,
    pub fragment: Vec<u8>,
    pub remaining: u32,
    pub acknowledgement_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseTtlsOutboundFragment {
    pub flags: u8,
    pub total_length: Option<u32>,
    pub fragment: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct PulseTtlsReassembler {
    remaining: u32,
    content: Vec<u8>,
}

type PulseTtlsIoFuture = Pin<
    Box<dyn Future<Output = io::Result<PulseTtlsIoResult>> + Send + 'static>,
>;

struct PulseTtlsIoResult {
    identifier: u8,
    fragment: Vec<u8>,
    remaining: u32,
}

/// `AsyncRead`/`AsyncWrite` adapter that carries a TLS client over Pulse's
/// outer EAP-TTLS request/response exchange.
pub struct PulseTtlsTransport<S> {
    outer: Arc<Mutex<PulseIftConnection<S>>>,
    identifier: u8,
    send_buffer: Vec<u8>,
    receive_buffer: Vec<u8>,
    receive_offset: usize,
    message_left: u32,
    io_future: Option<PulseTtlsIoFuture>,
    future_reads: bool,
    closed: bool,
}

impl<S> PulseTtlsTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(
        outer: Arc<Mutex<PulseIftConnection<S>>>,
        identifier: u8,
    ) -> Self {
        Self {
            outer,
            identifier,
            send_buffer: Vec::new(),
            receive_buffer: Vec::new(),
            receive_offset: 0,
            message_left: 0,
            io_future: None,
            future_reads: false,
            closed: false,
        }
    }

    pub fn outer(&self) -> Arc<Mutex<PulseIftConnection<S>>> {
        self.outer.clone()
    }

    fn start_io(&mut self, read_after_flush: bool) {
        let outer = self.outer.clone();
        let identifier = self.identifier;
        let message_left = self.message_left;
        let content = if read_after_flush && self.message_left > 0 {
            Vec::new()
        } else {
            std::mem::take(&mut self.send_buffer)
        };
        self.future_reads = read_after_flush;
        self.io_future = Some(Box::pin(async move {
            pulse_ttls_exchange(
                outer,
                identifier,
                content,
                message_left,
                read_after_flush,
            )
            .await
            .map_err(io::Error::other)
        }));
    }

    fn poll_io(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(future) = &mut self.io_future else {
            return Poll::Ready(Ok(()));
        };
        let result = match future.as_mut().poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.io_future = None;
        match result {
            Ok(result) => {
                self.identifier = result.identifier;
                self.message_left = result.remaining;
                if self.future_reads {
                    self.receive_buffer = result.fragment;
                    self.receive_offset = 0;
                }
                self.future_reads = false;
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<S> AsyncRead for PulseTtlsTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Pulse EAP-TTLS transport is closed",
            )));
        }
        loop {
            if self.receive_offset < self.receive_buffer.len() {
                let available = &self.receive_buffer[self.receive_offset..];
                let count = available.len().min(destination.remaining());
                destination.put_slice(&available[..count]);
                self.receive_offset += count;
                if self.receive_offset == self.receive_buffer.len() {
                    self.receive_buffer.fill(0);
                    self.receive_buffer.clear();
                    self.receive_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if self.io_future.is_none() {
                self.start_io(true);
            }
            match self.poll_io(context) {
                Poll::Ready(Ok(())) => continue,
                result => return result,
            }
        }
    }
}

impl<S> AsyncWrite for PulseTtlsTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        content: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Pulse EAP-TTLS transport is closed",
            )));
        }
        if self.send_buffer.len().saturating_add(content.len())
            > PULSE_CONFIGURATION_FRAME_LIMIT
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Pulse EAP-TTLS pending output exceeds its limit",
            )));
        }
        self.send_buffer.extend_from_slice(content);
        Poll::Ready(Ok(content.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Pulse EAP-TTLS transport is closed",
            )));
        }
        if self.io_future.is_none() {
            if self.send_buffer.is_empty() {
                return Poll::Ready(Ok(()));
            }
            if self.message_left > 0
                || self.receive_offset < self.receive_buffer.len()
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot flush Pulse EAP-TTLS output with pending input",
                )));
            }
            self.start_io(false);
        }
        self.poll_io(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;
        self.io_future = None;
        self.send_buffer.fill(0);
        self.send_buffer.clear();
        self.receive_buffer.fill(0);
        self.receive_buffer.clear();
        self.message_left = 0;
        Poll::Ready(Ok(()))
    }
}

impl PulseTtlsReassembler {
    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    pub fn push(
        &mut self,
        packet: &PulseEapPacket,
    ) -> Result<Option<Vec<u8>>, PulseTtlsError> {
        let parsed = parse_pulse_ttls_fragment(packet, self.remaining)?;
        self.remaining = parsed.remaining;
        self.content.extend_from_slice(&parsed.fragment);
        if self.content.len() > PULSE_CONFIGURATION_FRAME_LIMIT {
            self.clear();
            return Err(PulseTtlsError::OutputTooLarge(
                PULSE_CONFIGURATION_FRAME_LIMIT,
            ));
        }
        if self.remaining == 0 {
            return Ok(Some(std::mem::take(&mut self.content)));
        }
        Ok(None)
    }

    pub fn clear(&mut self) {
        self.remaining = 0;
        self.content.fill(0);
        self.content.clear();
    }
}

pub fn parse_pulse_ttls_fragment(
    packet: &PulseEapPacket,
    message_left: u32,
) -> Result<PulseTtlsIncomingFragment, PulseTtlsError> {
    if packet.type_value != u32::from(PULSE_EAP_TYPE_TTLS)
        || packet.payload.is_empty()
    {
        return Err(PulseTtlsError::UnexpectedPacket);
    }
    let flags = packet.payload[0];
    if flags & 0x3f != 0 {
        return Err(PulseTtlsError::UnsupportedFlags(flags));
    }
    let mut fragment = &packet.payload[1..];
    let continuing = message_left > 0;
    let remaining;
    if continuing {
        if flags & PULSE_TTLS_FLAG_LENGTH != 0 {
            return Err(PulseTtlsError::RepeatedLength);
        }
        if fragment.is_empty() || fragment.len() as u32 > message_left {
            return Err(PulseTtlsError::InvalidContinuedLength(fragment.len()));
        }
        if flags & PULSE_TTLS_FLAG_MORE != 0 {
            if fragment.len() as u32 >= message_left {
                return Err(PulseTtlsError::NonFinalConsumedMessage);
            }
        } else if fragment.len() as u32 != message_left {
            return Err(PulseTtlsError::FinalLengthMismatch);
        }
        remaining = message_left - fragment.len() as u32;
    } else if flags & PULSE_TTLS_FLAG_MORE != 0 {
        if flags & PULSE_TTLS_FLAG_LENGTH == 0 || fragment.len() < 5 {
            return Err(PulseTtlsError::MissingFragmentedLength);
        }
        let total_length =
            u32::from_be_bytes(fragment[..4].try_into().unwrap());
        fragment = &fragment[4..];
        if total_length > PULSE_CONFIGURATION_FRAME_LIMIT as u32
            || total_length <= fragment.len() as u32
            || fragment.is_empty()
        {
            return Err(PulseTtlsError::InvalidFragmentedLength(total_length));
        }
        remaining = total_length - fragment.len() as u32;
    } else if flags & PULSE_TTLS_FLAG_LENGTH != 0 {
        if fragment.len() < 4 {
            return Err(PulseTtlsError::MissingLength);
        }
        let total_length =
            u32::from_be_bytes(fragment[..4].try_into().unwrap());
        fragment = &fragment[4..];
        if total_length > PULSE_CONFIGURATION_FRAME_LIMIT as u32
            || total_length != fragment.len() as u32
            || fragment.is_empty()
        {
            return Err(PulseTtlsError::UnfragmentedLengthMismatch);
        }
        remaining = 0;
    } else {
        if fragment.is_empty() {
            return Err(PulseTtlsError::EmptyPacket);
        }
        remaining = 0;
    }
    Ok(PulseTtlsIncomingFragment {
        identifier: packet.identifier,
        fragment: fragment.to_vec(),
        remaining,
        acknowledgement_required: remaining > 0,
    })
}

pub fn split_pulse_ttls_message(
    content: &[u8],
) -> Result<Vec<PulseTtlsOutboundFragment>, PulseTtlsError> {
    if content.len() > PULSE_CONFIGURATION_FRAME_LIMIT {
        return Err(PulseTtlsError::OutputTooLarge(
            PULSE_CONFIGURATION_FRAME_LIMIT,
        ));
    }
    if content.is_empty() {
        return Ok(Vec::new());
    }
    let total = u32::try_from(content.len()).unwrap();
    let mut remaining = content;
    let mut first = true;
    let mut result = Vec::new();
    while remaining.len() > PULSE_TTLS_MAXIMUM_FRAGMENT {
        let flags = PULSE_TTLS_FLAG_MORE
            | if first { PULSE_TTLS_FLAG_LENGTH } else { 0 };
        result.push(PulseTtlsOutboundFragment {
            flags,
            total_length: first.then_some(total),
            fragment: remaining[..PULSE_TTLS_MAXIMUM_FRAGMENT].to_vec(),
        });
        first = false;
        remaining = &remaining[PULSE_TTLS_MAXIMUM_FRAGMENT..];
    }
    result.push(PulseTtlsOutboundFragment {
        flags: 0,
        total_length: None,
        fragment: remaining.to_vec(),
    });
    Ok(result)
}

pub fn build_pulse_ttls_response(
    identifier: u8,
    fragment: &PulseTtlsOutboundFragment,
) -> Result<Vec<u8>, PulseTtlsError> {
    let mut payload = Vec::with_capacity(5 + fragment.fragment.len());
    payload.push(fragment.flags);
    if fragment.flags & PULSE_TTLS_FLAG_LENGTH != 0 {
        let total_length =
            fragment.total_length.ok_or(PulseTtlsError::MissingLength)?;
        payload.extend_from_slice(&total_length.to_be_bytes());
    }
    payload.extend_from_slice(&fragment.fragment);
    Ok(build_pulse_eap(
        PULSE_EAP_RESPONSE,
        identifier,
        PULSE_EAP_TYPE_TTLS,
        0,
        &payload,
    )?)
}

pub fn validate_pulse_ttls_acknowledgement(
    packet: &PulseEapPacket,
) -> Result<u8, PulseTtlsError> {
    if packet.type_value != u32::from(PULSE_EAP_TYPE_TTLS)
        || packet.payload.as_slice() != [0]
    {
        return Err(PulseTtlsError::InvalidAcknowledgement);
    }
    Ok(packet.identifier)
}

pub fn build_pulse_inner_eap_avp(
    packet: &[u8],
) -> Result<Vec<u8>, PulseTtlsError> {
    let attribute_length = 8_usize
        .checked_add(packet.len())
        .filter(|length| *length <= 0x00ff_ffff)
        .ok_or(PulseTtlsError::InnerEapTooLarge(packet.len()))?;
    let mut content = vec![0_u8; attribute_length];
    content[..4].copy_from_slice(&PULSE_AVP_EAP_MESSAGE.to_be_bytes());
    let encoded =
        (u32::from(PULSE_AVP_FLAG_MANDATORY) << 24) | attribute_length as u32;
    content[4..8].copy_from_slice(&encoded.to_be_bytes());
    content[8..].copy_from_slice(packet);
    Ok(content)
}

pub fn parse_pulse_inner_eap_avp(
    content: &[u8],
) -> Result<PulseEapPacket, PulseTtlsError> {
    if content.len() < 8 {
        return Err(PulseTtlsError::TruncatedInnerAvp);
    }
    if u32::from_be_bytes(content[..4].try_into().unwrap())
        != PULSE_AVP_EAP_MESSAGE
        || content[4] & PULSE_AVP_FLAG_VENDOR != 0
    {
        return Err(PulseTtlsError::UnexpectedInnerAvp);
    }
    let attribute_length =
        (u32::from_be_bytes(content[4..8].try_into().unwrap()) & 0x00ff_ffff)
            as usize;
    if !(8..=PULSE_AUTHENTICATION_FRAME_LIMIT).contains(&attribute_length) {
        return Err(PulseTtlsError::InvalidInnerAvpLength(attribute_length));
    }
    if content.len() < attribute_length {
        return Err(PulseTtlsError::TruncatedInnerAvp);
    }
    let packet = parse_pulse_eap(&content[8..attribute_length])?;
    if packet.code != PULSE_EAP_REQUEST
        || packet.type_value != PULSE_EAP_EXPANDED_JUNIPER
        || packet.subtype != 1
    {
        return Err(PulseTtlsError::UnexpectedInnerPacket);
    }
    Ok(packet)
}

pub async fn write_pulse_inner_eap<W>(
    writer: &mut W,
    packet: &[u8],
) -> Result<(), PulseTtlsError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let content = build_pulse_inner_eap_avp(packet)?;
    writer
        .write_all(&content)
        .await
        .map_err(PulseIftError::Io)?;
    Ok(())
}

pub async fn read_pulse_inner_eap<R>(
    reader: &mut R,
) -> Result<PulseEapPacket, PulseTtlsError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0_u8; 8];
    reader
        .read_exact(&mut header)
        .await
        .map_err(PulseIftError::Io)?;
    if u32::from_be_bytes(header[..4].try_into().unwrap())
        != PULSE_AVP_EAP_MESSAGE
        || header[4] & PULSE_AVP_FLAG_VENDOR != 0
    {
        return Err(PulseTtlsError::UnexpectedInnerAvp);
    }
    let length = (u32::from_be_bytes(header[4..8].try_into().unwrap())
        & 0x00ff_ffff) as usize;
    if !(8..=PULSE_AUTHENTICATION_FRAME_LIMIT).contains(&length) {
        return Err(PulseTtlsError::InvalidInnerAvpLength(length));
    }
    let mut content = vec![0_u8; length - 8];
    reader
        .read_exact(&mut content)
        .await
        .map_err(PulseIftError::Io)?;
    let packet = parse_pulse_eap(&content)?;
    if packet.code != PULSE_EAP_REQUEST
        || packet.type_value != PULSE_EAP_EXPANDED_JUNIPER
        || packet.subtype != 1
    {
        return Err(PulseTtlsError::UnexpectedInnerPacket);
    }
    Ok(packet)
}

async fn pulse_ttls_exchange<S>(
    outer: Arc<Mutex<PulseIftConnection<S>>>,
    mut identifier: u8,
    content: Vec<u8>,
    message_left: u32,
    read_after_flush: bool,
) -> Result<PulseTtlsIoResult, PulseTtlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut outer = outer.lock().await;
    if !content.is_empty() {
        let fragments = split_pulse_ttls_message(&content)?;
        for (index, fragment) in fragments.iter().enumerate() {
            write_ttls_fragment(&mut outer, identifier, fragment).await?;
            if index + 1 < fragments.len() {
                let frame =
                    outer.read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT).await?;
                let packet = parse_pulse_authentication_eap(&frame)?;
                identifier = validate_pulse_ttls_acknowledgement(&packet)?;
            }
        }
    }
    if !read_after_flush {
        return Ok(PulseTtlsIoResult {
            identifier,
            fragment: Vec::new(),
            remaining: message_left,
        });
    }
    if message_left > 0 {
        write_ttls_fragment(
            &mut outer,
            identifier,
            &PulseTtlsOutboundFragment {
                flags: 0,
                total_length: None,
                fragment: Vec::new(),
            },
        )
        .await?;
    }
    let frame = outer.read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT).await?;
    let packet = parse_pulse_authentication_eap(&frame)?;
    let parsed = parse_pulse_ttls_fragment(&packet, message_left)?;
    Ok(PulseTtlsIoResult {
        identifier: parsed.identifier,
        fragment: parsed.fragment,
        remaining: parsed.remaining,
    })
}

async fn write_ttls_fragment<S>(
    outer: &mut PulseIftConnection<S>,
    identifier: u8,
    fragment: &PulseTtlsOutboundFragment,
) -> Result<(), PulseTtlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let packet = build_pulse_ttls_response(identifier, fragment)?;
    let payload = build_pulse_authentication_payload(&packet);
    outer
        .write_frame(PULSE_VENDOR_TCG, PULSE_IFT_CLIENT_AUTH_RESPONSE, &payload)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{super::pulse_ift::PULSE_EAP_TYPE_EXPANDED, *};

    fn ttls_packet(identifier: u8, flags: u8, body: &[u8]) -> PulseEapPacket {
        let mut payload = vec![flags];
        payload.extend_from_slice(body);
        PulseEapPacket {
            code: PULSE_EAP_REQUEST,
            identifier,
            type_value: u32::from(PULSE_EAP_TYPE_TTLS),
            subtype: 0,
            payload,
        }
    }

    #[test]
    fn fragmented_message_reassembles_with_strict_lengths() {
        let mut first = 12_u32.to_be_bytes().to_vec();
        first.extend_from_slice(b"hello");
        let mut reassembler = PulseTtlsReassembler::default();
        assert!(
            reassembler
                .push(&ttls_packet(
                    1,
                    PULSE_TTLS_FLAG_LENGTH | PULSE_TTLS_FLAG_MORE,
                    &first
                ))
                .unwrap()
                .is_none()
        );
        assert_eq!(reassembler.remaining(), 7);
        let message = reassembler
            .push(&ttls_packet(2, 0, b" world!"))
            .unwrap()
            .unwrap();
        assert_eq!(message, b"hello world!");
    }

    #[test]
    fn invalid_continuations_fail_closed() {
        let packet =
            ttls_packet(2, PULSE_TTLS_FLAG_LENGTH, &[0, 0, 0, 1, b'x']);
        assert!(matches!(
            parse_pulse_ttls_fragment(&packet, 3),
            Err(PulseTtlsError::RepeatedLength)
        ));
        assert!(matches!(
            parse_pulse_ttls_fragment(
                &ttls_packet(2, PULSE_TTLS_FLAG_MORE, b"abc"),
                3
            ),
            Err(PulseTtlsError::NonFinalConsumedMessage)
        ));
    }

    #[test]
    fn outgoing_fragmentation_matches_upstream_boundaries() {
        let content = vec![0x5a; PULSE_TTLS_MAXIMUM_FRAGMENT * 2 + 7];
        let fragments = split_pulse_ttls_message(&content).unwrap();
        assert_eq!(fragments.len(), 3);
        assert_eq!(
            fragments[0].flags,
            PULSE_TTLS_FLAG_LENGTH | PULSE_TTLS_FLAG_MORE
        );
        assert_eq!(fragments[0].total_length, Some(content.len() as u32));
        assert_eq!(fragments[1].flags, PULSE_TTLS_FLAG_MORE);
        assert_eq!(fragments[2].flags, 0);
        assert_eq!(fragments[2].fragment.len(), 7);
    }

    #[test]
    fn response_and_acknowledgement_use_server_identifier() {
        let fragment = PulseTtlsOutboundFragment {
            flags: 0,
            total_length: None,
            fragment: b"tls".to_vec(),
        };
        let encoded = build_pulse_ttls_response(44, &fragment).unwrap();
        let parsed = parse_pulse_eap(&encoded).unwrap();
        assert_eq!(parsed.identifier, 44);
        assert_eq!(parsed.payload, b"\0tls");
        assert_eq!(
            validate_pulse_ttls_acknowledgement(&ttls_packet(45, 0, b""))
                .unwrap(),
            45
        );
    }

    #[test]
    fn inner_eap_avp_round_trips_juniper_request() {
        let eap = build_pulse_eap(
            PULSE_EAP_REQUEST,
            7,
            PULSE_EAP_TYPE_EXPANDED,
            1,
            b"challenge",
        )
        .unwrap();
        let avp = build_pulse_inner_eap_avp(&eap).unwrap();
        let parsed = parse_pulse_inner_eap_avp(&avp).unwrap();
        assert_eq!(parsed.identifier, 7);
        assert_eq!(parsed.payload, b"challenge");
        let mut vendor = avp;
        vendor[4] |= PULSE_AVP_FLAG_VENDOR;
        assert!(matches!(
            parse_pulse_inner_eap_avp(&vendor),
            Err(PulseTtlsError::UnexpectedInnerAvp)
        ));
    }

    #[tokio::test]
    async fn async_transport_exchanges_tls_bytes_over_ift() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let outer = Arc::new(Mutex::new(PulseIftConnection::new(client)));
        let server_task = tokio::spawn(async move {
            let mut server = PulseIftConnection::new(server);
            let frame = server
                .read_frame(PULSE_AUTHENTICATION_FRAME_LIMIT)
                .await
                .unwrap();
            let packet = parse_pulse_eap(&frame.payload[4..]).unwrap();
            assert_eq!(packet.identifier, 7);
            assert_eq!(packet.payload, b"\0client hello");
            let response = build_pulse_eap(
                PULSE_EAP_REQUEST,
                8,
                PULSE_EAP_TYPE_TTLS,
                0,
                b"\0server hello",
            )
            .unwrap();
            server
                .write_frame(
                    PULSE_VENDOR_TCG,
                    super::super::PULSE_IFT_CLIENT_AUTH_CHALLENGE,
                    &build_pulse_authentication_payload(&response),
                )
                .await
                .unwrap();
        });
        let mut transport = PulseTtlsTransport::new(outer, 7);
        transport.write_all(b"client hello").await.unwrap();
        transport.flush().await.unwrap();
        let mut response = [0_u8; 12];
        transport.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"server hello");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn async_inner_eap_helpers_are_bounded() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let packet = build_pulse_eap(
            PULSE_EAP_REQUEST,
            3,
            PULSE_EAP_TYPE_EXPANDED,
            1,
            b"request",
        )
        .unwrap();
        let write = tokio::spawn(async move {
            write_pulse_inner_eap(&mut writer, &packet).await.unwrap();
        });
        let parsed = read_pulse_inner_eap(&mut reader).await.unwrap();
        assert_eq!(
            (parsed.identifier, parsed.payload.as_slice()),
            (3, b"request".as_slice())
        );
        write.await.unwrap();
    }
}
