//! VLESS version 0 request/response and legacy UDP framing.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf,
        WriteHalf,
    },
    sync::Mutex,
};
use uuid::Uuid;

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::network::SocksAddr,
};

pub const VERSION: u8 = 0;
pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub const COMMAND_MUX: u8 = 3;
pub const FLOW_VISION: &str = "xtls-rprx-vision";
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_IPV6: u8 = 3;
const ADDRESS_DOMAIN: u8 = 2;
const XUDP_STATUS_NEW: u8 = 1;
const XUDP_STATUS_KEEP: u8 = 2;
const XUDP_STATUS_END: u8 = 3;
const XUDP_OPTION_DATA: u8 = 1;
const XUDP_NETWORK_UDP: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
}

impl Command {
    fn byte(self) -> u8 {
        match self {
            Self::Tcp => COMMAND_TCP,
            Self::Udp => COMMAND_UDP,
            Self::Mux => COMMAND_MUX,
        }
    }

    fn parse(value: u8) -> io::Result<Self> {
        match value {
            COMMAND_TCP => Ok(Self::Tcp),
            COMMAND_UDP => Ok(Self::Udp),
            COMMAND_MUX => Ok(Self::Mux),
            value => {
                Err(invalid_data(format!("unknown VLESS command: {value}")))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub uuid: Uuid,
    pub command: Command,
    pub destination: Option<SocksAddr>,
    pub flow: String,
}

pub fn parse_user_id(value: &str) -> Uuid {
    Uuid::parse_str(value)
        .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), value.as_bytes()))
}

pub async fn write_request<S>(
    stream: &mut S,
    uuid: Uuid,
    command: Command,
    destination: Option<&SocksAddr>,
    flow: &str,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_u8(VERSION).await?;
    stream.write_all(uuid.as_bytes()).await?;
    let addons = encode_addons(flow)?;
    stream.write_u8(addons.len() as u8).await?;
    stream.write_all(&addons).await?;
    stream.write_u8(command.byte()).await?;
    if command != Command::Mux {
        write_address(
            stream,
            destination.ok_or_else(|| {
                invalid_input("VLESS TCP/UDP request requires a destination")
            })?,
        )
        .await?;
    }
    stream.flush().await
}

pub async fn read_request<S>(stream: &mut S) -> io::Result<Request>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(invalid_data(format!("unknown VLESS version: {version}")));
    }
    let mut uuid = [0_u8; 16];
    stream.read_exact(&mut uuid).await?;
    let addons_length = stream.read_u8().await? as usize;
    let mut addons = vec![0_u8; addons_length];
    stream.read_exact(&mut addons).await?;
    let flow = decode_addons(&addons)?;
    let command = Command::parse(stream.read_u8().await?)?;
    let destination = if command == Command::Mux {
        None
    } else {
        Some(read_address(stream).await?)
    };
    Ok(Request {
        uuid: Uuid::from_bytes(uuid),
        command,
        destination,
        flow,
    })
}

pub async fn write_response<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(&[VERSION, 0]).await?;
    stream.flush().await
}

pub struct VlessOutbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    uuid: Uuid,
    legacy_udp: bool,
    packet_addr: bool,
    flow: String,
}

impl VlessOutbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        user_id: &str,
        legacy_udp: bool,
        packet_addr: bool,
    ) -> Self {
        Self::new_with_flow(
            upstream,
            server,
            user_id,
            legacy_udp,
            packet_addr,
            "",
        )
        .expect("empty VLESS flow is valid")
    }

    pub fn new_with_flow(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        user_id: &str,
        legacy_udp: bool,
        packet_addr: bool,
        flow: &str,
    ) -> io::Result<Self> {
        if !matches!(flow, "" | FLOW_VISION) {
            return Err(invalid_input(format!(
                "unsupported VLESS flow {flow:?}"
            )));
        }
        Ok(Self {
            upstream,
            server,
            uuid: parse_user_id(user_id),
            legacy_udp,
            packet_addr,
            flow: flow.to_owned(),
        })
    }
}

impl Dialer for VlessOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            if self.flow == FLOW_VISION {
                let mut transport =
                    self.upstream.dial_vision_tcp(&self.server).await?;
                let socket = crate::adapter::stream_socket(&transport.stream);
                write_request(
                    &mut transport.stream,
                    self.uuid,
                    Command::Tcp,
                    Some(destination),
                    &self.flow,
                )
                .await?;
                let stream = Box::new(VlessTcpStream::new(transport.stream));
                return Ok(crate::adapter::preserve_stream_socket(
                    Box::new(
                        crate::protocol::vless_vision::VisionStream::client(
                            stream,
                            transport.direct_switch,
                            *self.uuid.as_bytes(),
                        ),
                    ),
                    socket,
                ));
            }
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            write_request(
                &mut stream,
                self.uuid,
                Command::Tcp,
                Some(destination),
                "",
            )
            .await?;
            Ok(crate::adapter::preserve_stream_socket(
                Box::new(VlessTcpStream::new(stream)) as Stream,
                socket,
            ))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            if self.flow == FLOW_VISION {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "xtls-rprx-vision flow does not support UDP",
                ));
            }
            if !self.legacy_udp {
                let mut stream = self.upstream.dial_tcp(&self.server).await?;
                write_request(&mut stream, self.uuid, Command::Mux, None, "")
                    .await?;
                return Ok(Box::new(XudpPacketConnection::new(
                    Box::new(VlessTcpStream::new(stream)) as Stream,
                    destination.clone(),
                )) as PacketStream);
            }
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            let request_destination = if self.packet_addr {
                if destination.is_domain() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "packetaddr does not support domain destinations",
                    ));
                }
                SocksAddr::new(crate::protocol::packetaddr::MAGIC_ADDRESS, 0)
            } else {
                destination.clone()
            };
            write_request(
                &mut stream,
                self.uuid,
                Command::Udp,
                Some(&request_destination),
                "",
            )
            .await?;
            let packet: PacketStream = Box::new(VlessPacketConnection::new(
                stream,
                request_destination,
            ));
            if self.packet_addr {
                Ok(Box::new(
                    crate::protocol::packetaddr::PacketAddrConnection::new(
                        packet,
                    ),
                ) as PacketStream)
            } else {
                Ok(packet)
            }
        })
    }
}

pub struct XudpPacketConnection {
    reader: Mutex<ReadHalf<Stream>>,
    writer: Mutex<WriteHalf<Stream>>,
    destination: SocksAddr,
    request_written: Mutex<bool>,
}

impl XudpPacketConnection {
    pub fn new(stream: Stream, destination: SocksAddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            destination,
            request_written: Mutex::new(false),
        }
    }
}

impl PacketConnection for XudpPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let mut first = self.request_written.lock().await;
            let status = if *first {
                XUDP_STATUS_KEEP
            } else {
                *first = true;
                XUDP_STATUS_NEW
            };
            let mut writer = self.writer.lock().await;
            write_xudp_frame(&mut *writer, status, destination, data, false)
                .await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            read_xudp_frame(&mut *reader, data, Some(&self.destination)).await
        })
    }
}

pub struct XudpServerPacketConnection {
    reader: Mutex<ReadHalf<Stream>>,
    writer: Mutex<XudpServerWriter>,
}

struct XudpServerWriter {
    inner: WriteHalf<Stream>,
    response_written: bool,
}

impl XudpServerPacketConnection {
    pub fn new(stream: Stream) -> Self {
        Self::with_response_state(stream, false)
    }

    pub fn new_without_response(stream: Stream) -> Self {
        Self::with_response_state(stream, true)
    }

    fn with_response_state(stream: Stream, response_written: bool) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(XudpServerWriter {
                inner: writer,
                response_written,
            }),
        }
    }
}

impl PacketConnection for XudpServerPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let mut writer = self.writer.lock().await;
            if !writer.response_written {
                writer.inner.write_all(&[VERSION, 0]).await?;
                writer.response_written = true;
            }
            write_xudp_frame(
                &mut writer.inner,
                XUDP_STATUS_KEEP,
                destination,
                data,
                false,
            )
            .await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            read_xudp_frame(&mut *reader, data, None).await
        })
    }
}

async fn write_xudp_frame<S>(
    stream: &mut S,
    status: u8,
    destination: &SocksAddr,
    data: &[u8],
    error: bool,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let address_length = socks_address_length(destination)?;
    let frame_length = u16::try_from(5 + address_length)
        .map_err(|_| invalid_input("XUDP frame header is too long"))?;
    let data_length = u16::try_from(data.len())
        .map_err(|_| invalid_input("XUDP packet is longer than 65535 bytes"))?;
    stream.write_u16(frame_length).await?;
    stream.write_u16(0).await?;
    stream.write_u8(status).await?;
    stream
        .write_u8(XUDP_OPTION_DATA | if error { 2 } else { 0 })
        .await?;
    stream.write_u8(XUDP_NETWORK_UDP).await?;
    stream.write_all(&encode_xudp_address(destination)?).await?;
    stream.write_u16(data_length).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

async fn read_xudp_frame<S>(
    stream: &mut S,
    data: &mut [u8],
    fallback: Option<&SocksAddr>,
) -> io::Result<(usize, SocksAddr)>
where
    S: AsyncRead + Unpin + ?Sized,
{
    loop {
        let header_length = stream.read_u16().await? as usize;
        if header_length < 4 {
            return Err(invalid_data(
                "XUDP frame header is shorter than 4 bytes",
            ));
        }
        let session = stream.read_u16().await?;
        if session != 0 {
            return Err(invalid_data(format!(
                "unsupported XUDP session id: {session}"
            )));
        }
        let status = stream.read_u8().await?;
        let option = stream.read_u8().await?;
        if status == XUDP_STATUS_END {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "XUDP session ended",
            ));
        }
        if !matches!(status, XUDP_STATUS_NEW | XUDP_STATUS_KEEP) {
            return Err(invalid_data(format!(
                "unsupported XUDP status: {status}"
            )));
        }
        let destination = if header_length > 4 {
            let mut header = vec![0_u8; header_length - 4];
            stream.read_exact(&mut header).await?;
            let network = header[0];
            if network != XUDP_NETWORK_UDP {
                return Err(invalid_data(format!(
                    "unsupported XUDP network: {network}"
                )));
            }
            decode_xudp_address(&header[1..])?.0
        } else {
            fallback
                .cloned()
                .ok_or_else(|| invalid_data("XUDP frame omitted destination"))?
        };
        if option & 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "XUDP peer closed with error",
            ));
        }
        if option & XUDP_OPTION_DATA == 0 {
            continue;
        }
        let length = stream.read_u16().await? as usize;
        if length > data.len() {
            return Err(invalid_data("XUDP payload exceeds buffer"));
        }
        stream.read_exact(&mut data[..length]).await?;
        return Ok((length, destination));
    }
}

pub(crate) fn socks_address_length(
    destination: &SocksAddr,
) -> io::Result<usize> {
    Ok(match destination {
        SocksAddr::Ip(address) if address.is_ipv4() => 1 + 4 + 2,
        SocksAddr::Ip(_) => 1 + 16 + 2,
        SocksAddr::Domain { host, .. } => {
            u8::try_from(host.len()).map_err(|_| {
                invalid_input("XUDP domain is longer than 255 bytes")
            })?;
            1 + 1 + host.len() + 2
        }
    })
}

pub(crate) fn encode_xudp_address(
    destination: &SocksAddr,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(socks_address_length(destination)?);
    output.extend_from_slice(&destination.port().to_be_bytes());
    match destination {
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(address) => {
                output.push(ADDRESS_IPV4);
                output.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                output.push(ADDRESS_IPV6);
                output.extend_from_slice(&address.octets());
            }
        },
        SocksAddr::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                invalid_input("XUDP domain is longer than 255 bytes")
            })?;
            output.push(ADDRESS_DOMAIN);
            output.push(length);
            output.extend_from_slice(host.as_bytes());
        }
    }
    Ok(output)
}

pub(crate) fn decode_xudp_address(
    input: &[u8],
) -> io::Result<(SocksAddr, usize)> {
    if input.len() < 3 {
        return Err(invalid_data("truncated XUDP address"));
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    match input[2] {
        ADDRESS_IPV4 => {
            let bytes: [u8; 4] = input
                .get(3..7)
                .ok_or_else(|| invalid_data("truncated XUDP IPv4 address"))?
                .try_into()
                .unwrap();
            Ok((SocksAddr::new(Ipv4Addr::from(bytes).to_string(), port), 7))
        }
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = input
                .get(3..19)
                .ok_or_else(|| invalid_data("truncated XUDP IPv6 address"))?
                .try_into()
                .unwrap();
            Ok((SocksAddr::new(Ipv6Addr::from(bytes).to_string(), port), 19))
        }
        ADDRESS_DOMAIN => {
            let length =
                usize::from(*input.get(3).ok_or_else(|| {
                    invalid_data("truncated XUDP domain length")
                })?);
            let end = 4 + length;
            let host = std::str::from_utf8(
                input
                    .get(4..end)
                    .ok_or_else(|| invalid_data("truncated XUDP domain"))?,
            )
            .map_err(|_| invalid_data("XUDP domain is not UTF-8"))?;
            Ok((SocksAddr::new(host, port), end))
        }
        kind => Err(invalid_data(format!(
            "unsupported XUDP address family: {kind}"
        ))),
    }
}

struct VlessTcpStream {
    inner: Stream,
    prefix: [u8; 2],
    prefix_read: usize,
    addons_remaining: Option<usize>,
}

impl VlessTcpStream {
    fn new(inner: Stream) -> Self {
        Self {
            inner,
            prefix: [0; 2],
            prefix_read: 0,
            addons_remaining: None,
        }
    }
}

impl AsyncRead for VlessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.prefix_read < 2 {
            let start = this.prefix_read;
            let mut header = ReadBuf::new(&mut this.prefix[start..]);
            match Pin::new(&mut *this.inner).poll_read(cx, &mut header) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if header.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short VLESS response",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    this.prefix_read += header.filled().len()
                }
            }
        }
        if this.prefix[0] != VERSION {
            return Poll::Ready(Err(invalid_data(format!(
                "unknown VLESS response version: {}",
                this.prefix[0]
            ))));
        }
        if this.addons_remaining.is_none() {
            this.addons_remaining = Some(this.prefix[1] as usize);
        }
        while this.addons_remaining.unwrap_or(0) > 0 {
            let amount = this.addons_remaining.unwrap().min(256);
            let mut scratch = [0_u8; 256];
            let mut skipped = ReadBuf::new(&mut scratch[..amount]);
            match Pin::new(&mut *this.inner).poll_read(cx, &mut skipped) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if skipped.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short VLESS response addons",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    this.addons_remaining = Some(
                        this.addons_remaining.unwrap() - skipped.filled().len(),
                    )
                }
            }
        }
        Pin::new(&mut *this.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for VlessTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, data)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

pub struct VlessPacketConnection {
    reader: Mutex<VlessPacketReader>,
    writer: Mutex<WriteHalf<Stream>>,
    destination: SocksAddr,
}

pub struct VlessServerPacketConnection {
    reader: Mutex<ReadHalf<Stream>>,
    writer: Mutex<VlessServerPacketWriter>,
    destination: SocksAddr,
}

struct VlessServerPacketWriter {
    inner: WriteHalf<Stream>,
    response_written: bool,
}

impl VlessServerPacketConnection {
    pub fn new(stream: Stream, destination: SocksAddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(VlessServerPacketWriter {
                inner: writer,
                response_written: false,
            }),
            destination,
        }
    }
}

impl PacketConnection for VlessServerPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let length = u16::try_from(data.len()).map_err(|_| {
                invalid_input("VLESS UDP packet is longer than 65535 bytes")
            })?;
            let mut writer = self.writer.lock().await;
            if !writer.response_written {
                writer.inner.write_all(&[VERSION, 0]).await?;
                writer.response_written = true;
            }
            writer.inner.write_u16(length).await?;
            writer.inner.write_all(data).await?;
            writer.inner.flush().await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            let length = reader.read_u16().await? as usize;
            if length > data.len() {
                return Err(invalid_data("VLESS UDP payload exceeds buffer"));
            }
            reader.read_exact(&mut data[..length]).await?;
            Ok((length, self.destination.clone()))
        })
    }
}

struct VlessPacketReader {
    inner: ReadHalf<Stream>,
    response_read: bool,
}

impl VlessPacketConnection {
    pub fn new(stream: Stream, destination: SocksAddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(VlessPacketReader {
                inner: reader,
                response_read: false,
            }),
            writer: Mutex::new(writer),
            destination,
        }
    }
}

impl PacketConnection for VlessPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let length = u16::try_from(data.len()).map_err(|_| {
                invalid_input("VLESS UDP packet is longer than 65535 bytes")
            })?;
            let mut writer = self.writer.lock().await;
            writer.write_u16(length).await?;
            writer.write_all(data).await?;
            writer.flush().await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            if !reader.response_read {
                read_response(&mut reader.inner).await?;
                reader.response_read = true;
            }
            let length = reader.inner.read_u16().await? as usize;
            if length > data.len() {
                return Err(invalid_data("VLESS UDP payload exceeds buffer"));
            }
            reader.inner.read_exact(&mut data[..length]).await?;
            Ok((length, self.destination.clone()))
        })
    }
}

async fn read_response<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(invalid_data(format!(
            "unknown VLESS response version: {version}"
        )));
    }
    let length = stream.read_u8().await? as usize;
    let mut addons = vec![0_u8; length];
    stream.read_exact(&mut addons).await?;
    Ok(())
}

async fn write_address<S>(stream: &mut S, address: &SocksAddr) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_u16(address.port()).await?;
    match address {
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => {
                stream.write_u8(ADDRESS_IPV4).await?;
                stream.write_all(&ip.octets()).await
            }
            IpAddr::V6(ip) => {
                stream.write_u8(ADDRESS_IPV6).await?;
                stream.write_all(&ip.octets()).await
            }
        },
        SocksAddr::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                invalid_input("VLESS domain is longer than 255 bytes")
            })?;
            stream.write_u8(ADDRESS_DOMAIN).await?;
            stream.write_u8(length).await?;
            stream.write_all(host.as_bytes()).await
        }
    }
}

async fn read_address<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let port = stream.read_u16().await?;
    let host = match stream.read_u8().await? {
        ADDRESS_IPV4 => {
            let mut value = [0_u8; 4];
            stream.read_exact(&mut value).await?;
            IpAddr::V4(Ipv4Addr::from(value)).to_string()
        }
        ADDRESS_IPV6 => {
            let mut value = [0_u8; 16];
            stream.read_exact(&mut value).await?;
            IpAddr::V6(Ipv6Addr::from(value)).to_string()
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await? as usize;
            let mut value = vec![0_u8; length];
            stream.read_exact(&mut value).await?;
            String::from_utf8(value)
                .map_err(|_| invalid_data("VLESS domain is not UTF-8"))?
        }
        value => {
            return Err(invalid_data(format!(
                "unknown VLESS address type: {value}"
            )));
        }
    };
    Ok(SocksAddr::new(host, port))
}

fn encode_addons(flow: &str) -> io::Result<Vec<u8>> {
    if flow.is_empty() {
        return Ok(Vec::new());
    }
    let length = u8::try_from(flow.len())
        .map_err(|_| invalid_input("VLESS flow is too long"))?;
    let mut addons = Vec::with_capacity(flow.len() + 2);
    addons.push(10);
    addons.push(length);
    addons.extend_from_slice(flow.as_bytes());
    if addons.len() > u8::MAX as usize {
        return Err(invalid_input("VLESS addons are too long"));
    }
    Ok(addons)
}

fn decode_addons(bytes: &[u8]) -> io::Result<String> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    if bytes.len() < 2 || bytes[0] != 10 {
        return Err(invalid_data("unsupported VLESS addons"));
    }
    let length = bytes[1] as usize;
    if bytes.len() != length + 2 {
        return Err(invalid_data("invalid VLESS flow addon length"));
    }
    String::from_utf8(bytes[2..].to_vec())
        .map_err(|_| invalid_data("VLESS flow is not UTF-8"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    use super::{
        ADDRESS_DOMAIN, Command, VlessTcpStream, XUDP_NETWORK_UDP,
        XUDP_OPTION_DATA, XUDP_STATUS_NEW, XudpPacketConnection,
        XudpServerPacketConnection, parse_user_id, read_request,
        read_xudp_frame, write_request, write_xudp_frame,
    };
    use crate::{
        adapter::{PacketConnection, Stream},
        common::network::SocksAddr,
    };

    #[tokio::test]
    async fn request_uses_port_first_vless_address_format() {
        let uuid =
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            uuid,
            Command::Tcp,
            Some(&SocksAddr::new("example.com", 443)),
            "",
        )
        .await
        .unwrap();
        assert_eq!(
            &bytes[..19],
            &[
                0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 1
            ]
        );
        assert_eq!(&bytes[19..22], &[0x01, 0xbb, 2]);
        let request = read_request(&mut bytes.as_slice()).await.unwrap();
        assert_eq!(request.uuid, uuid);
        assert_eq!(
            request.destination,
            Some(SocksAddr::new("example.com", 443))
        );
    }

    #[test]
    fn non_uuid_user_ids_use_nil_namespace_v5() {
        assert_eq!(
            parse_user_id("example"),
            Uuid::new_v5(&Uuid::nil(), b"example")
        );
    }

    #[tokio::test]
    async fn tcp_stream_consumes_response_header_and_addons() {
        let (client, mut server) = tokio::io::duplex(128);
        let task = tokio::spawn(async move {
            server.write_all(&[0, 3, 1, 2, 3]).await.unwrap();
            server.write_all(b"payload").await.unwrap();
        });
        let mut stream = VlessTcpStream::new(Box::new(client) as Stream);
        let mut output = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut output)
            .await
            .unwrap();
        assert_eq!(output, "payload");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn xudp_single_session_frames_dynamic_destinations() {
        let (client, server) = tokio::io::duplex(1024);
        let client = XudpPacketConnection::new(
            Box::new(VlessTcpStream::new(Box::new(client) as Stream)) as Stream,
            SocksAddr::new("fallback.test", 53),
        );
        let server =
            XudpServerPacketConnection::new(Box::new(server) as Stream);
        let destination = SocksAddr::new("dns.example", 53);
        client.send_to(b"query", &destination).await.unwrap();
        let mut buffer = [0_u8; 32];
        let (size, received) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..size], b"query");
        assert_eq!(received, destination);
        server.send_to(b"response", &received).await.unwrap();
        let (size, received) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..size], b"response");
        assert_eq!(received, destination);
    }

    #[tokio::test]
    async fn xudp_frame_matches_go_port_then_address_wire() {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        let destination = SocksAddr::new("dns.example", 53);
        write_xudp_frame(
            &mut writer,
            XUDP_STATUS_NEW,
            &destination,
            b"query",
            false,
        )
        .await
        .unwrap();
        drop(writer);
        let mut wire = Vec::new();
        reader.read_to_end(&mut wire).await.unwrap();
        let mut expected = vec![
            0x00,
            0x14, // header length: fixed 5 + 15-byte address
            0x00,
            0x00, // session id
            XUDP_STATUS_NEW,
            XUDP_OPTION_DATA,
            XUDP_NETWORK_UDP,
            0x00,
            0x35, // port precedes address family in VMess/XUDP
            ADDRESS_DOMAIN,
            0x0b,
        ];
        expected.extend_from_slice(b"dns.example");
        expected.extend_from_slice(&[0x00, 0x05]);
        expected.extend_from_slice(b"query");
        assert_eq!(wire, expected);

        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer.write_all(&expected).await.unwrap();
        drop(writer);
        let mut payload = [0_u8; 16];
        let (size, decoded) = read_xudp_frame(&mut reader, &mut payload, None)
            .await
            .unwrap();
        assert_eq!(decoded, destination);
        assert_eq!(&payload[..size], b"query");
    }
}
