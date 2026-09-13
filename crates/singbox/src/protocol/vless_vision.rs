//! Wire primitives for VLESS `xtls-rprx-vision` padding.
//!
//! Direct TLS splicing is integrated separately because it needs controlled
//! extraction of rustls read-ahead buffers.  Keeping the framing state machine
//! independent makes its byte-level compatibility testable without a socket.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::adapter::{Stream, VisionDirectSwitch};

const UUID_LENGTH: usize = 16;
const HEADER_LENGTH: usize = 5;
const RESHAPE_LIMIT: usize = 8192 - UUID_LENGTH - HEADER_LENGTH;
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const VLESS_RESPONSE: [u8; 2] = [0, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VisionCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for VisionCommand {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::End),
            2 => Ok(Self::Direct),
            _ => Err(invalid_data(format!(
                "unknown VLESS Vision command {value}"
            ))),
        }
    }
}

#[derive(Debug)]
pub(crate) struct VisionPaddingEncoder {
    uuid: [u8; UUID_LENGTH],
    write_uuid: bool,
}

impl VisionPaddingEncoder {
    pub(crate) fn new(uuid: [u8; UUID_LENGTH]) -> Self {
        Self {
            uuid,
            write_uuid: true,
        }
    }

    pub(crate) fn encode(
        &mut self,
        command: VisionCommand,
        content: &[u8],
        is_tls: bool,
    ) -> io::Result<Vec<u8>> {
        let padding_len = if content.len() < 900 && is_tls {
            900 - content.len() + usize::from(random_below(500)?)
        } else {
            usize::from(random_below(256)?)
        };
        self.encode_with_padding(command, content, padding_len)
    }

    fn encode_with_padding(
        &mut self,
        command: VisionCommand,
        content: &[u8],
        padding_len: usize,
    ) -> io::Result<Vec<u8>> {
        let content_len = u16::try_from(content.len()).map_err(|_| {
            invalid_input("VLESS Vision content exceeds 65535 bytes")
        })?;
        let padding_len = u16::try_from(padding_len).map_err(|_| {
            invalid_input("VLESS Vision padding exceeds 65535 bytes")
        })?;
        let prefix_len = if self.write_uuid { UUID_LENGTH } else { 0 };
        let mut output = Vec::with_capacity(
            prefix_len
                + HEADER_LENGTH
                + content.len()
                + usize::from(padding_len),
        );
        if self.write_uuid {
            output.extend_from_slice(&self.uuid);
            self.write_uuid = false;
        }
        output.push(command as u8);
        output.extend_from_slice(&content_len.to_be_bytes());
        output.extend_from_slice(&padding_len.to_be_bytes());
        output.extend_from_slice(content);
        let padding_start = output.len();
        output.resize(padding_start + usize::from(padding_len), 0);
        getrandom::fill(&mut output[padding_start..])
            .map_err(io::Error::other)?;
        Ok(output)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct VisionDecoded {
    pub(crate) data: Vec<u8>,
    pub(crate) transition: Option<VisionCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    Detect,
    Header,
    Content {
        command: VisionCommand,
        remaining: usize,
        padding: usize,
    },
    Padding {
        command: VisionCommand,
        remaining: usize,
    },
    Passthrough,
}

#[derive(Debug)]
pub(crate) struct VisionPaddingDecoder {
    uuid: [u8; UUID_LENGTH],
    pending: Vec<u8>,
    state: DecodeState,
}

impl VisionPaddingDecoder {
    pub(crate) fn new(uuid: [u8; UUID_LENGTH]) -> Self {
        Self {
            uuid,
            pending: Vec::new(),
            state: DecodeState::Detect,
        }
    }

    pub(crate) fn push(&mut self, input: &[u8]) -> io::Result<VisionDecoded> {
        self.pending.extend_from_slice(input);
        let mut decoded = VisionDecoded::default();
        loop {
            match self.state {
                DecodeState::Detect => {
                    let compared = self.pending.len().min(UUID_LENGTH);
                    if self.pending[..compared] != self.uuid[..compared] {
                        self.state = DecodeState::Passthrough;
                        decoded.data.append(&mut self.pending);
                        break;
                    }
                    if self.pending.len() < UUID_LENGTH {
                        break;
                    }
                    self.pending.drain(..UUID_LENGTH);
                    self.state = DecodeState::Header;
                }
                DecodeState::Header => {
                    if self.pending.len() < HEADER_LENGTH {
                        break;
                    }
                    let command = VisionCommand::try_from(self.pending[0])?;
                    let content = usize::from(u16::from_be_bytes([
                        self.pending[1],
                        self.pending[2],
                    ]));
                    let padding = usize::from(u16::from_be_bytes([
                        self.pending[3],
                        self.pending[4],
                    ]));
                    self.pending.drain(..HEADER_LENGTH);
                    self.state = if content == 0 {
                        DecodeState::Padding {
                            command,
                            remaining: padding,
                        }
                    } else {
                        DecodeState::Content {
                            command,
                            remaining: content,
                            padding,
                        }
                    };
                }
                DecodeState::Content {
                    command,
                    remaining,
                    padding,
                } => {
                    let take = remaining.min(self.pending.len());
                    decoded.data.extend(self.pending.drain(..take));
                    let remaining = remaining - take;
                    self.state = if remaining == 0 {
                        DecodeState::Padding {
                            command,
                            remaining: padding,
                        }
                    } else {
                        DecodeState::Content {
                            command,
                            remaining,
                            padding,
                        }
                    };
                    if take == 0 {
                        break;
                    }
                }
                DecodeState::Padding { command, remaining } => {
                    let take = remaining.min(self.pending.len());
                    self.pending.drain(..take);
                    let remaining = remaining - take;
                    if remaining != 0 {
                        self.state =
                            DecodeState::Padding { command, remaining };
                        break;
                    }
                    match command {
                        VisionCommand::Continue => {
                            self.state = DecodeState::Header;
                        }
                        VisionCommand::End | VisionCommand::Direct => {
                            self.state = DecodeState::Passthrough;
                            decoded.transition = Some(command);
                            decoded.data.append(&mut self.pending);
                            break;
                        }
                    }
                }
                DecodeState::Passthrough => {
                    decoded.data.append(&mut self.pending);
                    break;
                }
            }
        }
        Ok(decoded)
    }

    pub(crate) fn finish(self) -> io::Result<Vec<u8>> {
        match self.state {
            DecodeState::Detect | DecodeState::Passthrough => Ok(self.pending),
            _ => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated VLESS Vision padding frame",
            )),
        }
    }
}

#[derive(Debug)]
struct PendingWrite {
    data: Vec<u8>,
    offset: usize,
    switch_after: bool,
}

/// Bidirectional VLESS Vision stream.
///
/// Reads remove Vision padding and independently switch the outer TLS read
/// direction after a Direct command. Writes inspect the proxied TLS records,
/// emit the final padded Direct block through outer TLS, flush it, and only
/// then switch the write direction to the raw transport.
pub(crate) struct VisionStream {
    inner: Stream,
    direct_switch: Arc<dyn VisionDirectSwitch>,
    encoder: VisionPaddingEncoder,
    decoder: Option<VisionPaddingDecoder>,
    filter: VisionTlsFilter,
    write_padding: bool,
    writes: VecDeque<PendingWrite>,
    switch_after_flush: bool,
    write_result: Option<usize>,
    read_pending: Vec<u8>,
    read_offset: usize,
    read_eof: bool,
}

impl VisionStream {
    pub(crate) fn client(
        inner: Stream,
        direct_switch: Arc<dyn VisionDirectSwitch>,
        uuid: [u8; UUID_LENGTH],
    ) -> Self {
        Self::new(inner, direct_switch, uuid, false)
    }

    pub(crate) fn server(
        inner: Stream,
        direct_switch: Arc<dyn VisionDirectSwitch>,
        uuid: [u8; UUID_LENGTH],
    ) -> Self {
        Self::new(inner, direct_switch, uuid, true)
    }

    fn new(
        inner: Stream,
        direct_switch: Arc<dyn VisionDirectSwitch>,
        uuid: [u8; UUID_LENGTH],
        write_response: bool,
    ) -> Self {
        let mut writes = VecDeque::new();
        if write_response {
            writes.push_back(PendingWrite {
                data: VLESS_RESPONSE.to_vec(),
                offset: 0,
                switch_after: false,
            });
        }
        Self {
            inner,
            direct_switch,
            encoder: VisionPaddingEncoder::new(uuid),
            decoder: Some(VisionPaddingDecoder::new(uuid)),
            filter: VisionTlsFilter::default(),
            write_padding: true,
            writes,
            switch_after_flush: false,
            write_result: None,
            read_pending: Vec::new(),
            read_offset: 0,
            read_eof: false,
        }
    }

    fn queue_application(&mut self, data: &[u8]) -> io::Result<()> {
        self.filter.observe(data);
        let (first, second) = reshape(data);
        for chunk in [Some(first), second].into_iter().flatten() {
            if self.write_padding {
                let command = self.filter.command_for(chunk);
                let switch_after = command == VisionCommand::Direct;
                tracing::trace!(
                    ?command,
                    content = chunk.len(),
                    tls = self.filter.is_tls(),
                    "VLESS Vision padding block"
                );
                if command != VisionCommand::Continue {
                    self.write_padding = false;
                }
                let encoded = self.encoder.encode(
                    command,
                    chunk,
                    self.filter.is_tls(),
                )?;
                self.writes.push_back(PendingWrite {
                    data: encoded,
                    offset: 0,
                    switch_after,
                });
            } else {
                self.writes.push_back(PendingWrite {
                    data: chunk.to_vec(),
                    offset: 0,
                    switch_after: false,
                });
            }
        }
        Ok(())
    }

    fn poll_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.switch_after_flush {
                match Pin::new(&mut self.inner).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        self.direct_switch.request_write_direct();
                        self.switch_after_flush = false;
                    }
                }
            }
            let Some(write) = self.writes.front_mut() else {
                return Poll::Ready(Ok(()));
            };
            match Pin::new(&mut self.inner)
                .poll_write(cx, &write.data[write.offset..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write VLESS Vision frame",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    write.offset += written;
                    if write.offset == write.data.len() {
                        let switch_after = write.switch_after;
                        self.writes.pop_front();
                        self.switch_after_flush = switch_after;
                    }
                }
            }
        }
    }

    fn copy_read_pending(&mut self, buffer: &mut ReadBuf<'_>) -> bool {
        if self.read_offset >= self.read_pending.len()
            || buffer.remaining() == 0
        {
            return false;
        }
        let size = buffer
            .remaining()
            .min(self.read_pending.len().saturating_sub(self.read_offset));
        let end = self.read_offset + size;
        buffer.put_slice(&self.read_pending[self.read_offset..end]);
        self.read_offset = end;
        if self.read_offset == self.read_pending.len() {
            self.read_pending.clear();
            self.read_offset = 0;
        }
        true
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.copy_read_pending(buffer) || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            let capacity = buffer.remaining().clamp(8192, 64 * 1024);
            let mut scratch = vec![0_u8; capacity];
            let mut input = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if input.filled().is_empty() => {
                    self.read_eof = true;
                    let decoder = self.decoder.take().expect("Vision decoder");
                    match decoder.finish() {
                        Ok(trailing) => self.read_pending = trailing,
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                    self.copy_read_pending(buffer);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(())) => {}
            }
            let decoded = match self
                .decoder
                .as_mut()
                .expect("Vision decoder")
                .push(input.filled())
            {
                Ok(decoded) => decoded,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if !decoded.data.is_empty() {
                self.filter.observe(&decoded.data);
                self.read_pending = decoded.data;
            }
            if decoded.transition == Some(VisionCommand::Direct) {
                tracing::trace!("VLESS Vision switching read direction to raw");
                self.direct_switch.request_read_direct();
            }
            if self.copy_read_pending(buffer) {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_result.is_some() {
            match self.poll_writes(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(Ok(self.write_result.take().unwrap()));
                }
            }
        }
        match self.poll_writes(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Err(error) = self.queue_application(data) {
            return Poll::Ready(Err(error));
        }
        self.write_result = Some(data.len());
        match self.poll_writes(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                Poll::Ready(Ok(self.write_result.take().unwrap()))
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_writes(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_writes(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
pub(crate) struct VisionTlsFilter {
    packets_remaining: u8,
    is_tls: bool,
    tls12_or_above: bool,
    remaining_server_hello: usize,
    cipher: Option<u16>,
    enable_direct: bool,
}

impl Default for VisionTlsFilter {
    fn default() -> Self {
        Self {
            packets_remaining: 8,
            is_tls: false,
            tls12_or_above: false,
            remaining_server_hello: 0,
            cipher: None,
            enable_direct: false,
        }
    }
}

impl VisionTlsFilter {
    pub(crate) fn observe(&mut self, packet: &[u8]) {
        if self.packets_remaining == 0 {
            return;
        }
        self.packets_remaining -= 1;
        if packet.len() > 6 {
            if packet.starts_with(&TLS_SERVER_HANDSHAKE_START) && packet[5] == 2
            {
                self.is_tls = true;
                self.tls12_or_above = true;
                self.remaining_server_hello =
                    usize::from(u16::from_be_bytes([packet[3], packet[4]])) + 5;
                if packet.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = usize::from(packet[43]);
                    let cipher_offset = 44 + session_id_len;
                    if let Some(cipher) =
                        packet.get(cipher_offset..cipher_offset + 2)
                    {
                        self.cipher =
                            Some(u16::from_be_bytes([cipher[0], cipher[1]]));
                    }
                }
            } else if packet.starts_with(&TLS_CLIENT_HANDSHAKE_START)
                && packet[5] == 1
            {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello != 0 {
            let inspected = self.remaining_server_hello.min(packet.len());
            self.remaining_server_hello -= inspected;
            if packet[..inspected]
                .windows(TLS13_SUPPORTED_VERSIONS.len())
                .any(|window| window == TLS13_SUPPORTED_VERSIONS)
            {
                self.enable_direct = self
                    .cipher
                    .is_some_and(|cipher| matches!(cipher, 0x1301..=0x1304));
                self.packets_remaining = 0;
            } else if self.remaining_server_hello == 0 {
                self.packets_remaining = 0;
            }
        }
    }

    pub(crate) fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub(crate) fn command_for(&self, chunk: &[u8]) -> VisionCommand {
        if self.is_tls && chunk.starts_with(&TLS_APPLICATION_DATA_START) {
            if self.enable_direct {
                VisionCommand::Direct
            } else {
                VisionCommand::End
            }
        } else if !self.tls12_or_above && self.packets_remaining <= 1 {
            VisionCommand::End
        } else {
            VisionCommand::Continue
        }
    }
}

pub(crate) fn reshape(input: &[u8]) -> (&[u8], Option<&[u8]>) {
    if input.len() < RESHAPE_LIMIT {
        return (input, None);
    }
    let split = input
        .windows(TLS_APPLICATION_DATA_START.len())
        .rposition(|window| window == TLS_APPLICATION_DATA_START)
        .filter(|index| *index > 0)
        .unwrap_or(8192 / 2);
    (&input[..split], Some(&input[split..]))
}

fn random_below(upper: u16) -> io::Result<u16> {
    debug_assert!(upper != 0);
    let zone = (u32::from(u16::MAX) + 1) / u32::from(upper) * u32::from(upper);
    loop {
        let mut bytes = [0_u8; 2];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        let value = u32::from(u16::from_be_bytes(bytes));
        if value < zone {
            return Ok((value % u32::from(upper)) as u16);
        }
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn first_padding_block_carries_uuid_and_big_endian_lengths() {
        let mut encoder = VisionPaddingEncoder::new(UUID);
        let encoded = encoder
            .encode_with_padding(VisionCommand::Continue, b"hello", 3)
            .unwrap();
        assert_eq!(&encoded[..16], &UUID);
        assert_eq!(&encoded[16..21], &[0, 0, 5, 0, 3]);
        assert_eq!(&encoded[21..26], b"hello");
        assert_eq!(encoded.len(), 29);

        let second = encoder
            .encode_with_padding(VisionCommand::End, b"world", 0)
            .unwrap();
        assert_eq!(&second[..5], &[1, 0, 5, 0, 0]);
        assert_eq!(&second[5..], b"world");
    }

    #[test]
    fn decoder_handles_every_byte_boundary_and_end_passthrough() {
        let mut encoder = VisionPaddingEncoder::new(UUID);
        let mut wire = encoder
            .encode_with_padding(VisionCommand::Continue, b"first", 7)
            .unwrap();
        wire.extend(
            encoder
                .encode_with_padding(VisionCommand::End, b"second", 2)
                .unwrap(),
        );
        wire.extend_from_slice(b"raw-tail");

        let mut decoder = VisionPaddingDecoder::new(UUID);
        let mut output = Vec::new();
        let mut transition = None;
        for byte in wire {
            let decoded = decoder.push(&[byte]).unwrap();
            output.extend(decoded.data);
            transition = transition.or(decoded.transition);
        }
        assert_eq!(output, b"firstsecondraw-tail");
        assert_eq!(transition, Some(VisionCommand::End));
        assert!(decoder.finish().unwrap().is_empty());
    }

    #[test]
    fn decoder_passes_through_a_non_vision_stream() {
        let mut decoder = VisionPaddingDecoder::new(UUID);
        let mut output = decoder.push(b"ordinary stream").unwrap().data;
        output.extend(decoder.push(b" bytes").unwrap().data);
        assert_eq!(output, b"ordinary stream bytes");
    }

    #[test]
    fn reshape_uses_last_tls_application_record_or_midpoint() {
        let plain = vec![0_u8; RESHAPE_LIMIT];
        let (first, second) = reshape(&plain);
        assert_eq!(first.len(), 4096);
        assert_eq!(second.unwrap().len(), RESHAPE_LIMIT - 4096);

        let mut tls = vec![0_u8; 9000];
        tls[7000..7003].copy_from_slice(&TLS_APPLICATION_DATA_START);
        let (first, second) = reshape(&tls);
        assert_eq!(first.len(), 7000);
        assert_eq!(second.unwrap().len(), 2000);
    }

    #[test]
    fn tls_filter_enables_direct_only_for_supported_tls13_cipher() {
        let mut server_hello = vec![0_u8; 90];
        server_hello[..6].copy_from_slice(&[0x16, 0x03, 0x03, 0, 85, 2]);
        server_hello[43] = 0;
        server_hello[44..46].copy_from_slice(&0x1301_u16.to_be_bytes());
        server_hello[70..76].copy_from_slice(&TLS13_SUPPORTED_VERSIONS);
        let mut filter = VisionTlsFilter::default();
        filter.observe(&server_hello);
        assert!(filter.is_tls());
        assert_eq!(
            filter.command_for(&[0x17, 0x03, 0x03, 0, 1, 0]),
            VisionCommand::Direct,
        );

        server_hello[44..46].copy_from_slice(&0x1305_u16.to_be_bytes());
        let mut ccm8 = VisionTlsFilter::default();
        ccm8.observe(&server_hello);
        assert_eq!(
            ccm8.command_for(&[0x17, 0x03, 0x03, 0, 1, 0]),
            VisionCommand::End,
        );
    }

    #[test]
    fn random_padding_matches_upstream_ranges() {
        let mut encoder = VisionPaddingEncoder::new(UUID);
        let tls = encoder
            .encode(VisionCommand::Continue, b"short", true)
            .unwrap();
        let padding = usize::from(u16::from_be_bytes([tls[19], tls[20]]));
        assert!((895..=1394).contains(&padding));

        let plain = encoder
            .encode(VisionCommand::Continue, b"plain", false)
            .unwrap();
        let padding = usize::from(u16::from_be_bytes([plain[3], plain[4]]));
        assert!(padding <= 255);
    }
}
