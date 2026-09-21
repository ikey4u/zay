//! TLS ClientHello decoy injection used by sing-box `spoof` options.
//!
//! The ordinary TLS stream remains untouched. Before its first write, this
//! wrapper emits a forged ClientHello in a TCP segment which the real server
//! rejects while a permissive middlebox can still inspect its SNI.

#![cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "macos",
        all(windows, any(target_arch = "x86_64", target_arch = "x86"))
    )),
    allow(dead_code)
)]

use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::adapter::{Stream, stream_local_addr, stream_peer_addr};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
const DEFAULT_TTL: u8 = 64;
const DEFAULT_WINDOW: u16 = u16::MAX;
const TCP_TIMESTAMP_BACKDATE: u32 = 3_600_000;

/// How the forged TCP segment is made unacceptable to the destination.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TlsSpoofMethod {
    /// Put the segment before the server receive window.
    #[default]
    WrongSequence,
    /// Deliberately corrupt its TCP checksum.
    WrongChecksum,
    /// Put its acknowledgement before the server send window.
    WrongAcknowledgment,
    /// Attach an unnegotiated TCP-MD5 option.
    WrongMd5,
    /// Attach a backdated TCP timestamp so PAWS rejects it.
    WrongTimestamp,
}

impl TlsSpoofMethod {
    /// Parse the names accepted by sing-box. Empty selects `wrong-sequence`.
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "" | "wrong-sequence" => Ok(Self::WrongSequence),
            "wrong-checksum" => Ok(Self::WrongChecksum),
            "wrong-ack" => Ok(Self::WrongAcknowledgment),
            "wrong-md5" => Ok(Self::WrongMd5),
            "wrong-timestamp" => Ok(Self::WrongTimestamp),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tls_spoof: unknown method: {value}"),
            )),
        }
    }

    /// Return the canonical sing-box configuration name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongSequence => "wrong-sequence",
            Self::WrongChecksum => "wrong-checksum",
            Self::WrongAcknowledgment => "wrong-ack",
            Self::WrongMd5 => "wrong-md5",
            Self::WrongTimestamp => "wrong-timestamp",
        }
    }
}

/// Whether raw TLS spoof injection is implemented on this build target.
pub const PLATFORM_SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "macos",
    all(windows, any(target_arch = "x86_64", target_arch = "x86"))
));

/// Validate a `spoof`/`spoof_method` pair and return its parsed method.
pub fn parse_options(
    spoof: &str,
    method: &str,
) -> io::Result<Option<TlsSpoofMethod>> {
    if spoof.is_empty() {
        if method.is_empty() {
            return Ok(None);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spoof_method requires spoof",
        ));
    }
    if !PLATFORM_SUPPORTED {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tls_spoof is not supported on this platform",
        ));
    }
    Ok(Some(TlsSpoofMethod::parse(method)?))
}

/// Wrap a connected TCP stream with one-shot TLS ClientHello injection.
///
/// Raw socket setup happens here, before any application bytes are consumed,
/// so privilege and unsupported-stream errors fail the connection cleanly.
pub fn wrap_tls_spoof(
    stream: Stream,
    fake_sni: &str,
    method: TlsSpoofMethod,
) -> io::Result<Stream> {
    if fake_sni.is_empty() {
        return Ok(stream);
    }
    let fake_hello = build_fake_client_hello(fake_sni)?;
    let local = stream_local_addr(&stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_spoof: underlying stream is not a physical TCP connection",
        )
    })?;
    let remote = stream_peer_addr(&stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_spoof: underlying stream has no TCP peer address",
        )
    })?;
    if local.is_ipv4() != remote.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_spoof: local/remote address family mismatch",
        ));
    }
    let spoofer = platform::new_spoofer(&stream, method, local, remote)?;
    Ok(Box::new(TlsSpoofStream {
        inner: stream,
        spoofer: Some(spoofer),
        fake_hello,
        injected: false,
    }))
}

trait RawSpoofer: Send {
    fn inject(&mut self, payload: &[u8]) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct TlsSpoofStream {
    inner: Stream,
    spoofer: Option<Box<dyn RawSpoofer>>,
    fake_hello: Vec<u8>,
    injected: bool,
}

impl TlsSpoofStream {
    fn inject_once(&mut self) -> io::Result<()> {
        if self.injected {
            return Ok(());
        }
        let spoofer = self.spoofer.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tls_spoof: spoofer closed",
            )
        })?;
        spoofer.inject(&self.fake_hello)?;
        self.injected = true;
        Ok(())
    }
}

impl AsyncRead for TlsSpoofStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for TlsSpoofStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.injected
            && let Err(error) = self.inject_once()
        {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut spoofer) = self.spoofer.take() {
            spoofer.close()?;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for TlsSpoofStream {
    fn drop(&mut self) {
        if let Some(mut spoofer) = self.spoofer.take() {
            let _ = spoofer.close();
        }
    }
}

fn build_fake_client_hello(sni: &str) -> io::Result<Vec<u8>> {
    if sni.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty sni"));
    }
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups.retain(|group| {
        matches!(
            group.name().as_str(),
            Some("X25519" | "secp256r1" | "secp384r1")
        )
    });
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ])
        .map_err(io::Error::other)?
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_name =
        ServerName::try_from(sni.to_owned()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid spoof SNI: {error}"),
            )
        })?;
    let mut connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(io::Error::other)?;
    let mut hello = Vec::new();
    while connection.wants_write() {
        connection.write_tls(&mut hello)?;
    }
    if hello.is_empty() {
        return Err(io::Error::other("tls ClientHello not produced"));
    }
    Ok(hello)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpoofPacketInfo {
    sequence: u32,
    acknowledgment: u32,
    corrupt_checksum: bool,
    options: Vec<u8>,
}

fn resolve_packet_info(
    method: TlsSpoofMethod,
    send_next: u32,
    receive_next: u32,
    timestamp: u32,
    mut tcp_options: Vec<u8>,
    payload_len: usize,
) -> SpoofPacketInfo {
    let mut info = SpoofPacketInfo {
        sequence: send_next,
        acknowledgment: receive_next,
        corrupt_checksum: false,
        options: Vec::new(),
    };
    match method {
        TlsSpoofMethod::WrongSequence => {
            info.sequence = send_next.wrapping_sub(payload_len as u32);
        }
        TlsSpoofMethod::WrongChecksum => info.corrupt_checksum = true,
        TlsSpoofMethod::WrongAcknowledgment => {
            info.acknowledgment =
                receive_next.wrapping_sub(u32::from(DEFAULT_WINDOW / 2));
        }
        TlsSpoofMethod::WrongMd5 => {
            info.options = vec![0; 20];
            info.options[0] = 19;
            info.options[1] = 18;
        }
        TlsSpoofMethod::WrongTimestamp => {
            let spoofed = timestamp.saturating_sub(TCP_TIMESTAMP_BACKDATE);
            if rewrite_tcp_timestamp(&mut tcp_options, spoofed) {
                info.options = tcp_options;
            } else {
                info.options = vec![1, 1, 8, 10];
                info.options.extend_from_slice(&spoofed.to_be_bytes());
                info.options.extend_from_slice(&0_u32.to_be_bytes());
            }
        }
    }
    info
}

fn rewrite_tcp_timestamp(options: &mut [u8], timestamp: u32) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => return false,
            1 => {
                offset += 1;
                continue;
            }
            _ => {}
        }
        let Some(&length) = options.get(offset + 1) else {
            return false;
        };
        let length = usize::from(length);
        if length < 2 || offset + length > options.len() {
            return false;
        }
        if options[offset] == 8 && length == 10 {
            options[offset + 2..offset + 6]
                .copy_from_slice(&timestamp.to_be_bytes());
            return true;
        }
        offset += length;
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn build_spoof_frame(
    method: TlsSpoofMethod,
    source: SocketAddr,
    destination: SocketAddr,
    send_next: u32,
    receive_next: u32,
    timestamp: u32,
    tcp_options: Vec<u8>,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_spoof: mixed IPv4/IPv6 address family",
        ));
    }
    let info = resolve_packet_info(
        method,
        send_next,
        receive_next,
        timestamp,
        tcp_options,
        payload.len(),
    );
    let ip_header_len = if source.is_ipv4() {
        IPV4_HEADER_LEN
    } else {
        IPV6_HEADER_LEN
    };
    let tcp_len = TCP_HEADER_LEN + info.options.len() + payload.len();
    let frame_len = ip_header_len + tcp_len;
    let mut frame = vec![0_u8; frame_len];
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            frame[0] = 0x45;
            frame[2..4].copy_from_slice(&(frame_len as u16).to_be_bytes());
            frame[8] = DEFAULT_TTL;
            frame[9] = 6;
            frame[12..16].copy_from_slice(&source.octets());
            frame[16..20].copy_from_slice(&destination.octets());
            let checksum = checksum(&frame[..IPV4_HEADER_LEN]);
            frame[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            frame[0] = 0x60;
            frame[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            frame[6] = 6;
            frame[7] = DEFAULT_TTL;
            frame[8..24].copy_from_slice(&source.octets());
            frame[24..40].copy_from_slice(&destination.octets());
        }
        _ => unreachable!("address families checked above"),
    }
    encode_tcp(
        &mut frame,
        ip_header_len,
        source,
        destination,
        &info,
        payload,
    );
    Ok(frame)
}

#[cfg(target_os = "macos")]
fn build_spoof_tcp_segment(
    method: TlsSpoofMethod,
    source: SocketAddr,
    destination: SocketAddr,
    send_next: u32,
    receive_next: u32,
    timestamp: u32,
    payload: &[u8],
) -> Vec<u8> {
    let info = resolve_packet_info(
        method,
        send_next,
        receive_next,
        timestamp,
        Vec::new(),
        payload.len(),
    );
    let mut segment =
        vec![0_u8; TCP_HEADER_LEN + info.options.len() + payload.len()];
    encode_tcp(&mut segment, 0, source, destination, &info, payload);
    segment
}

fn encode_tcp(
    frame: &mut [u8],
    offset: usize,
    source: SocketAddr,
    destination: SocketAddr,
    info: &SpoofPacketInfo,
    payload: &[u8],
) {
    let tcp = &mut frame[offset..];
    tcp[0..2].copy_from_slice(&source.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&info.sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&info.acknowledgment.to_be_bytes());
    tcp[12] = (((TCP_HEADER_LEN + info.options.len()) / 4) as u8) << 4;
    tcp[13] = 0x18;
    tcp[14..16].copy_from_slice(&DEFAULT_WINDOW.to_be_bytes());
    tcp[TCP_HEADER_LEN..TCP_HEADER_LEN + info.options.len()]
        .copy_from_slice(&info.options);
    tcp[TCP_HEADER_LEN + info.options.len()..].copy_from_slice(payload);
    let mut sum =
        pseudo_header_sum(source.ip(), destination.ip(), tcp.len() as u32);
    sum = checksum_sum(tcp, sum);
    let mut value = finalize_checksum(sum);
    if info.corrupt_checksum {
        value ^= u16::MAX;
    }
    tcp[16..18].copy_from_slice(&value.to_be_bytes());
}

fn pseudo_header_sum(source: IpAddr, destination: IpAddr, tcp_len: u32) -> u32 {
    let mut bytes = Vec::with_capacity(40);
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            bytes.extend_from_slice(&source.octets());
            bytes.extend_from_slice(&destination.octets());
            bytes.extend_from_slice(&[0, 6]);
            bytes.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            bytes.extend_from_slice(&source.octets());
            bytes.extend_from_slice(&destination.octets());
            bytes.extend_from_slice(&tcp_len.to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 6]);
        }
        _ => unreachable!("address families checked by caller"),
    }
    checksum_sum(&bytes, 0)
}

fn checksum(bytes: &[u8]) -> u16 {
    finalize_checksum(checksum_sum(bytes, 0))
}

fn checksum_sum(bytes: &[u8], mut sum: u32) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    #[cfg(target_os = "macos")]
    use std::{ffi::CString, ptr};
    use std::{mem, os::fd::RawFd};

    use super::*;
    use crate::adapter::stream_socket;

    struct UnixSpoofer {
        method: TlsSpoofMethod,
        source: SocketAddr,
        destination: SocketAddr,
        raw_fd: RawFd,
        send_next: u32,
        receive_next: u32,
        timestamp: u32,
    }

    impl Drop for UnixSpoofer {
        fn drop(&mut self) {
            if self.raw_fd >= 0 {
                // SAFETY: raw_fd is exclusively owned by this object.
                unsafe { libc::close(self.raw_fd) };
                self.raw_fd = -1;
            }
        }
    }

    impl RawSpoofer for UnixSpoofer {
        fn inject(&mut self, payload: &[u8]) -> io::Result<()> {
            #[cfg(target_os = "macos")]
            if self.destination.is_ipv6() {
                let segment = build_spoof_tcp_segment(
                    self.method,
                    self.source,
                    self.destination,
                    self.send_next,
                    self.receive_next,
                    self.timestamp,
                    payload,
                );
                return send_raw(self.raw_fd, self.destination, &segment);
            }
            #[allow(unused_mut)]
            let mut frame = build_spoof_frame(
                self.method,
                self.source,
                self.destination,
                self.send_next,
                self.receive_next,
                self.timestamp,
                Vec::new(),
                payload,
            )?;
            #[cfg(target_os = "macos")]
            if self.destination.is_ipv4() {
                // Darwin's IP_HDRINCL API expects these two IPv4 fields in
                // host byte order and swaps them before transmission.
                let total =
                    u16::from_be_bytes([frame[2], frame[3]]).to_ne_bytes();
                frame[2..4].copy_from_slice(&total);
                let fragment =
                    u16::from_be_bytes([frame[6], frame[7]]).to_ne_bytes();
                frame[6..8].copy_from_slice(&fragment);
            }
            send_raw(self.raw_fd, self.destination, &frame)
        }
    }

    pub(super) fn new_spoofer(
        stream: &Stream,
        method: TlsSpoofMethod,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Box<dyn RawSpoofer>> {
        #[cfg(target_os = "macos")]
        if method == TlsSpoofMethod::WrongTimestamp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tls_spoof: wrong-timestamp is not supported on macOS",
            ));
        }
        let tcp_fd = stream_socket(stream).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tls_spoof: underlying stream is not a physical TCP connection",
            )
        })?;
        let raw_fd = open_raw_socket(source, destination)?;
        let sequences =
            load_sequence_numbers(tcp_fd, source, destination, method);
        let (send_next, receive_next, timestamp) = match sequences {
            Ok(value) => value,
            Err(error) => {
                // SAFETY: raw_fd was returned by socket and is still owned here.
                unsafe { libc::close(raw_fd) };
                return Err(error);
            }
        };
        Ok(Box::new(UnixSpoofer {
            method,
            source,
            destination,
            raw_fd,
            send_next,
            receive_next,
            timestamp,
        }))
    }

    fn open_raw_socket(
        _source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<RawFd> {
        let domain = if destination.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        // SAFETY: arguments are valid socket constants.
        let fd =
            unsafe { libc::socket(domain, libc::SOCK_RAW, libc::IPPROTO_TCP) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let option: libc::c_int = 1;
        let setup = if destination.is_ipv4() {
            // SAFETY: option points to an initialized c_int.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    (&option as *const libc::c_int).cast(),
                    mem::size_of_val(&option) as libc::socklen_t,
                )
            }
        } else {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: option points to an initialized c_int.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_HDRINCL,
                        (&option as *const libc::c_int).cast(),
                        mem::size_of_val(&option) as libc::socklen_t,
                    )
                }
            }
            #[cfg(target_os = "macos")]
            {
                let SocketAddr::V6(source) = _source else {
                    unreachable!()
                };
                let address = sockaddr_v6(source);
                // SAFETY: address has the correct sockaddr_in6 layout.
                unsafe {
                    libc::bind(
                        fd,
                        (&address as *const libc::sockaddr_in6).cast(),
                        mem::size_of_val(&address) as libc::socklen_t,
                    )
                }
            }
        };
        if setup != 0 {
            let error = io::Error::last_os_error();
            // SAFETY: fd is owned here.
            unsafe { libc::close(fd) };
            return Err(error);
        }
        Ok(fd)
    }

    fn send_raw(
        fd: RawFd,
        destination: SocketAddr,
        packet: &[u8],
    ) -> io::Result<()> {
        let result = match destination {
            SocketAddr::V4(destination) => {
                let address = sockaddr_v4(destination);
                // SAFETY: address and packet are valid for the duration of sendto.
                unsafe {
                    libc::sendto(
                        fd,
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&address as *const libc::sockaddr_in).cast(),
                        mem::size_of_val(&address) as libc::socklen_t,
                    )
                }
            }
            SocketAddr::V6(destination) => {
                let address = sockaddr_v6(destination);
                // SAFETY: address and packet are valid for the duration of sendto.
                unsafe {
                    libc::sendto(
                        fd,
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&address as *const libc::sockaddr_in6).cast(),
                        mem::size_of_val(&address) as libc::socklen_t,
                    )
                }
            }
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    fn sockaddr_v4(address: std::net::SocketAddrV4) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as _,
            sin_port: address.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            },
            sin_zero: [0; 8],
        }
    }

    #[cfg(target_os = "linux")]
    fn sockaddr_v4(address: std::net::SocketAddrV4) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: address.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            },
            sin_zero: [0; 8],
        }
    }

    #[cfg(target_os = "macos")]
    fn sockaddr_v6(address: std::net::SocketAddrV6) -> libc::sockaddr_in6 {
        libc::sockaddr_in6 {
            sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
            sin6_family: libc::AF_INET6 as _,
            sin6_port: address.port().to_be(),
            sin6_flowinfo: address.flowinfo(),
            sin6_addr: libc::in6_addr {
                s6_addr: address.ip().octets(),
            },
            sin6_scope_id: address.scope_id(),
        }
    }

    #[cfg(target_os = "linux")]
    fn sockaddr_v6(address: std::net::SocketAddrV6) -> libc::sockaddr_in6 {
        libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as _,
            sin6_port: address.port().to_be(),
            sin6_flowinfo: address.flowinfo(),
            sin6_addr: libc::in6_addr {
                s6_addr: address.ip().octets(),
            },
            sin6_scope_id: address.scope_id(),
        }
    }

    #[cfg(target_os = "linux")]
    fn load_sequence_numbers(
        fd: RawFd,
        _source: SocketAddr,
        _destination: SocketAddr,
        method: TlsSpoofMethod,
    ) -> io::Result<(u32, u32, u32)> {
        const TCP_REPAIR: libc::c_int = 19;
        const TCP_REPAIR_QUEUE: libc::c_int = 20;
        const TCP_QUEUE_SEQ: libc::c_int = 21;
        const TCP_TIMESTAMP: libc::c_int = 24;
        const TCP_REPAIR_ON: libc::c_int = 1;
        const TCP_REPAIR_OFF: libc::c_int = 0;
        const TCP_RECV_QUEUE: libc::c_int = 1;
        const TCP_SEND_QUEUE: libc::c_int = 2;

        let timestamp = if method == TlsSpoofMethod::WrongTimestamp {
            get_socket_int(fd, libc::IPPROTO_TCP, TCP_TIMESTAMP)? as u32
        } else {
            0
        };
        set_socket_int(fd, libc::IPPROTO_TCP, TCP_REPAIR, TCP_REPAIR_ON)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("enter TCP_REPAIR (need CAP_NET_ADMIN): {error}"),
                )
            })?;
        let read_result = (|| {
            set_socket_int(
                fd,
                libc::IPPROTO_TCP,
                TCP_REPAIR_QUEUE,
                TCP_SEND_QUEUE,
            )?;
            let send =
                get_socket_int(fd, libc::IPPROTO_TCP, TCP_QUEUE_SEQ)? as u32;
            set_socket_int(
                fd,
                libc::IPPROTO_TCP,
                TCP_REPAIR_QUEUE,
                TCP_RECV_QUEUE,
            )?;
            let receive =
                get_socket_int(fd, libc::IPPROTO_TCP, TCP_QUEUE_SEQ)? as u32;
            Ok((send, receive, timestamp))
        })();
        let leave =
            set_socket_int(fd, libc::IPPROTO_TCP, TCP_REPAIR, TCP_REPAIR_OFF);
        match (read_result, leave) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(io::Error::new(
                error.kind(),
                format!("leave TCP_REPAIR: {error}"),
            )),
        }
    }

    #[cfg(target_os = "linux")]
    fn set_socket_int(
        fd: RawFd,
        level: i32,
        name: i32,
        value: i32,
    ) -> io::Result<()> {
        // SAFETY: value points to an initialized c_int.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&value as *const libc::c_int).cast(),
                mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn get_socket_int(fd: RawFd, level: i32, name: i32) -> io::Result<i32> {
        let mut value = 0_i32;
        let mut length = mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: output pointers are valid and correctly sized.
        let result = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        };
        if result == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "macos")]
    fn load_sequence_numbers(
        _fd: RawFd,
        source: SocketAddr,
        destination: SocketAddr,
        _method: TlsSpoofMethod,
    ) -> io::Result<(u32, u32, u32)> {
        const HEADER: usize = 24;
        const SOCKET_OFFSET: usize = 104;
        const FOREIGN_PORT: usize = 16;
        const LOCAL_PORT: usize = 18;
        const VFLAG: usize = 44;
        const FOREIGN_ADDR: usize = 48;
        const LOCAL_ADDR: usize = 64;
        const IPV4_OFFSET: usize = 12;
        const EXTRA: usize = 208;
        const SND_NXT: usize = 56;
        const RCV_NXT: usize = 80;

        let release = sysctl_raw("kern.osrelease")?;
        let release =
            release.split(|byte| *byte == 0).next().unwrap_or_default();
        let major = std::str::from_utf8(release)
            .ok()
            .and_then(|value| value.split('.').next())
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| {
                io::Error::other("unexpected kern.osrelease format")
            })?;
        let structure = if major >= 22 { 408 } else { 384 };
        let item = structure + EXTRA;
        let list = sysctl_raw("net.inet.tcp.pcblist_n")?;
        for offset in (HEADER..)
            .step_by(item)
            .take_while(|offset| offset + item <= list.len())
        {
            let pcb = &list[offset..offset + SOCKET_OFFSET];
            let tcp = &list[offset + structure..offset + item];
            if u16::from_be_bytes([pcb[LOCAL_PORT], pcb[LOCAL_PORT + 1]])
                != source.port()
                || u16::from_be_bytes([
                    pcb[FOREIGN_PORT],
                    pcb[FOREIGN_PORT + 1],
                ]) != destination.port()
            {
                continue;
            }
            let addresses = if pcb[VFLAG] & 1 != 0 {
                let local = IpAddr::V4(std::net::Ipv4Addr::new(
                    pcb[LOCAL_ADDR + IPV4_OFFSET],
                    pcb[LOCAL_ADDR + IPV4_OFFSET + 1],
                    pcb[LOCAL_ADDR + IPV4_OFFSET + 2],
                    pcb[LOCAL_ADDR + IPV4_OFFSET + 3],
                ));
                let remote = IpAddr::V4(std::net::Ipv4Addr::new(
                    pcb[FOREIGN_ADDR + IPV4_OFFSET],
                    pcb[FOREIGN_ADDR + IPV4_OFFSET + 1],
                    pcb[FOREIGN_ADDR + IPV4_OFFSET + 2],
                    pcb[FOREIGN_ADDR + IPV4_OFFSET + 3],
                ));
                (local, remote)
            } else if pcb[VFLAG] & 2 != 0 {
                let local = IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&pcb[LOCAL_ADDR..LOCAL_ADDR + 16])
                        .expect("fixed slice"),
                ));
                let remote = IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&pcb[FOREIGN_ADDR..FOREIGN_ADDR + 16])
                        .expect("fixed slice"),
                ));
                (local, remote)
            } else {
                continue;
            };
            if addresses != (source.ip(), destination.ip()) {
                continue;
            }
            let send = u32::from_ne_bytes(
                tcp[SND_NXT..SND_NXT + 4].try_into().unwrap(),
            );
            let receive = u32::from_ne_bytes(
                tcp[RCV_NXT..RCV_NXT + 4].try_into().unwrap(),
            );
            return Ok((send, receive, 0));
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "tls_spoof: connection {source}->{destination} not found in pcblist_n"
            ),
        ))
    }

    #[cfg(target_os = "macos")]
    fn sysctl_raw(name: &str) -> io::Result<Vec<u8>> {
        let name = CString::new(name).expect("static sysctl name");
        let mut length = 0_usize;
        // SAFETY: first call queries required output length.
        if unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                ptr::null_mut(),
                &mut length,
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = vec![0_u8; length];
        // SAFETY: bytes has the capacity reported by the kernel.
        if unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        bytes.truncate(length);
        Ok(bytes)
    }
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
mod platform {
    use std::{
        borrow::Cow,
        cell::UnsafeCell,
        sync::{Condvar, Mutex, mpsc},
        time::Duration,
    };

    use windivert::{
        CloseAction, WinDivert, layer,
        packet::WinDivertPacket,
        prelude::{WinDivertFlags, WinDivertShutdownMode},
    };

    use super::*;

    const CLOSE_GRACE_PERIOD: Duration = Duration::from_secs(2);

    struct SharedHandle(UnsafeCell<WinDivert<layer::NetworkLayer>>);

    // SAFETY: WinDivert documents shutdown as callable concurrently with a
    // blocking receive. All send/receive operations remain on the worker;
    // the owner thread only invokes shutdown to wake it during close.
    unsafe impl Send for SharedHandle {}
    unsafe impl Sync for SharedHandle {}

    impl SharedHandle {
        fn recv<'a>(
            &self,
            buffer: Option<&'a mut [u8]>,
        ) -> Result<
            WinDivertPacket<'a, layer::NetworkLayer>,
            windivert::error::WinDivertError,
        > {
            // SAFETY: only the worker invokes recv.
            unsafe { &*self.0.get() }.recv(buffer)
        }

        fn send(
            &self,
            packet: &WinDivertPacket<'_, layer::NetworkLayer>,
        ) -> Result<u32, windivert::error::WinDivertError> {
            // SAFETY: only the worker invokes send.
            unsafe { &*self.0.get() }.send(packet)
        }

        fn shutdown_receive(&self) {
            // SAFETY: shutdown is the one operation allowed concurrently with
            // a blocking receive by the WinDivert API.
            let _ = unsafe { &mut *self.0.get() }
                .shutdown(WinDivertShutdownMode::Recv);
        }

        fn close(&self) {
            // SAFETY: the worker calls close after receive has returned and no
            // further operation touches the handle.
            let _ = unsafe { &mut *self.0.get() }.close(CloseAction::Nothing);
        }
    }

    #[derive(Default)]
    struct WorkerState {
        done: bool,
        error: Option<String>,
    }

    struct WindowsSpoofer {
        fake: Option<mpsc::SyncSender<Vec<u8>>>,
        handle: Arc<SharedHandle>,
        state: Arc<(Mutex<WorkerState>, Condvar)>,
        closed: bool,
    }

    impl RawSpoofer for WindowsSpoofer {
        fn inject(&mut self, payload: &[u8]) -> io::Result<()> {
            if let Some(error) = self.state.0.lock().unwrap().error.clone() {
                return Err(io::Error::other(error));
            }
            self.fake
                .as_ref()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "tls_spoof closed",
                    )
                })?
                .send(payload.to_vec())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "tls_spoof worker closed",
                    )
                })
        }

        fn close(&mut self) -> io::Result<()> {
            if self.closed {
                return worker_result(&self.state);
            }
            self.closed = true;
            self.fake.take();
            let (lock, wake) = &*self.state;
            let state = lock.lock().unwrap();
            let (state, timeout) = wake
                .wait_timeout_while(state, CLOSE_GRACE_PERIOD, |state| {
                    !state.done
                })
                .unwrap();
            if timeout.timed_out() && !state.done {
                drop(state);
                self.handle.shutdown_receive();
                let mut state = lock.lock().unwrap();
                while !state.done {
                    state = wake.wait(state).unwrap();
                }
            }
            worker_result(&self.state)
        }
    }

    fn worker_result(
        state: &Arc<(Mutex<WorkerState>, Condvar)>,
    ) -> io::Result<()> {
        match state.0.lock().unwrap().error.clone() {
            Some(error) => Err(io::Error::other(error)),
            None => Ok(()),
        }
    }

    pub(super) fn new_spoofer(
        _stream: &Stream,
        method: TlsSpoofMethod,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Box<dyn RawSpoofer>> {
        let filter = divert_filter(source, destination);
        let divert = WinDivert::network(&filter, 0, WinDivertFlags::default())
            .map_err(|error| {
                io::Error::other(format!("tls_spoof: open WinDivert: {error}"))
            })?;
        let handle = Arc::new(SharedHandle(UnsafeCell::new(divert)));
        let state =
            Arc::new((Mutex::new(WorkerState::default()), Condvar::new()));
        let (fake_tx, fake_rx) = mpsc::sync_channel(1);
        let worker_handle = handle.clone();
        let worker_state = state.clone();
        std::thread::Builder::new()
            .name("singbox-tls-spoof".into())
            .spawn(move || {
                let result = run_worker(
                    &worker_handle,
                    method,
                    source,
                    destination,
                    fake_rx,
                );
                worker_handle.close();
                let (lock, wake) = &*worker_state;
                let mut state = lock.lock().unwrap();
                state.done = true;
                state.error = result.err().map(|error| error.to_string());
                wake.notify_all();
            })
            .map_err(|error| {
                io::Error::other(format!("start tls_spoof worker: {error}"))
            })?;
        Ok(Box::new(WindowsSpoofer {
            fake: Some(fake_tx),
            handle,
            state,
            closed: false,
        }))
    }

    fn run_worker(
        handle: &SharedHandle,
        method: TlsSpoofMethod,
        source: SocketAddr,
        destination: SocketAddr,
        fake_rx: mpsc::Receiver<Vec<u8>>,
    ) -> io::Result<()> {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let packet = handle.recv(Some(&mut buffer)).map_err(|error| {
                io::Error::other(format!("WinDivert receive: {error}"))
            })?;
            let Some(parsed) = parse_tcp_packet(&packet.data) else {
                handle.send(&packet).map_err(|error| {
                    io::Error::other(format!(
                        "WinDivert re-inject malformed packet: {error}"
                    ))
                })?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WinDivert received malformed packet matching tls_spoof filter",
                ));
            };
            if parsed.payload_len == 0 {
                handle.send(&packet).map_err(|error| {
                    io::Error::other(format!(
                        "WinDivert re-inject empty packet: {error}"
                    ))
                })?;
                continue;
            }
            let Ok(fake) = fake_rx.try_recv() else {
                handle.send(&packet).map_err(|error| {
                    io::Error::other(format!(
                        "WinDivert re-inject early packet: {error}"
                    ))
                })?;
                continue;
            };
            let timestamp = tcp_timestamp(&parsed.options).unwrap_or_default();
            let frame = build_spoof_frame(
                method,
                source,
                destination,
                parsed.sequence,
                parsed.acknowledgment,
                timestamp,
                parsed.options,
                &fake,
            )?;
            let mut fake_packet = WinDivertPacket {
                address: packet.address.clone(),
                data: Cow::Owned(frame),
            };
            // Prevent WinDivert from recalculating an intentionally damaged
            // TCP checksum. The packet builder has already filled both sums.
            fake_packet.address.set_ip_checksum(true);
            fake_packet.address.set_tcp_checksum(true);
            handle.send(&fake_packet).map_err(|error| {
                io::Error::other(format!(
                    "WinDivert inject fake ClientHello: {error}"
                ))
            })?;
            handle.send(&packet).map_err(|error| {
                io::Error::other(format!(
                    "WinDivert release real ClientHello: {error}"
                ))
            })?;
            return Ok(());
        }
    }

    fn divert_filter(source: SocketAddr, destination: SocketAddr) -> String {
        match (source, destination) {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => format!(
                "outbound and tcp and ip.SrcAddr == {} and tcp.SrcPort == {} and ip.DstAddr == {} and tcp.DstPort == {}",
                source.ip(),
                source.port(),
                destination.ip(),
                destination.port()
            ),
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => format!(
                "outbound and tcp and ipv6.SrcAddr == {} and tcp.SrcPort == {} and ipv6.DstAddr == {} and tcp.DstPort == {}",
                source.ip(),
                source.port(),
                destination.ip(),
                destination.port()
            ),
            _ => {
                unreachable!("address families validated before backend setup")
            }
        }
    }

    struct ParsedTcp {
        sequence: u32,
        acknowledgment: u32,
        options: Vec<u8>,
        payload_len: usize,
    }

    fn parse_tcp_packet(packet: &[u8]) -> Option<ParsedTcp> {
        let version = packet.first().map(|byte| byte >> 4)?;
        let (ip_header, total) = match version {
            4 => {
                let header = usize::from(packet.first()? & 0x0f) * 4;
                if header < IPV4_HEADER_LEN
                    || header + TCP_HEADER_LEN > packet.len()
                    || packet[9] != 6
                {
                    return None;
                }
                let declared =
                    usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                (
                    header,
                    if declared == 0 || declared > packet.len() {
                        packet.len()
                    } else {
                        declared
                    },
                )
            }
            6 => {
                if packet.len() < IPV6_HEADER_LEN + TCP_HEADER_LEN
                    || packet[6] != 6
                {
                    return None;
                }
                let declared = IPV6_HEADER_LEN
                    + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
                (
                    IPV6_HEADER_LEN,
                    if declared == IPV6_HEADER_LEN || declared > packet.len() {
                        packet.len()
                    } else {
                        declared
                    },
                )
            }
            _ => return None,
        };
        let tcp = packet.get(ip_header..total)?;
        let tcp_header = usize::from(*tcp.get(12)? >> 4) * 4;
        if tcp_header < TCP_HEADER_LEN || tcp_header > tcp.len() {
            return None;
        }
        Some(ParsedTcp {
            sequence: u32::from_be_bytes(tcp.get(4..8)?.try_into().ok()?),
            acknowledgment: u32::from_be_bytes(
                tcp.get(8..12)?.try_into().ok()?,
            ),
            options: tcp[TCP_HEADER_LEN..tcp_header].to_vec(),
            payload_len: tcp.len() - tcp_header,
        })
    }

    fn tcp_timestamp(options: &[u8]) -> Option<u32> {
        let mut offset = 0;
        while offset < options.len() {
            match options[offset] {
                0 => return None,
                1 => {
                    offset += 1;
                    continue;
                }
                _ => {}
            }
            let length = usize::from(*options.get(offset + 1)?);
            if length < 2 || offset + length > options.len() {
                return None;
            }
            if options[offset] == 8 && length == 10 {
                return Some(u32::from_be_bytes(
                    options.get(offset + 2..offset + 6)?.try_into().ok()?,
                ));
            }
            offset += length;
        }
        None
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    all(windows, any(target_arch = "x86_64", target_arch = "x86"))
)))]
mod platform {
    use super::*;

    pub(super) fn new_spoofer(
        _stream: &Stream,
        _method: TlsSpoofMethod,
        _source: SocketAddr,
        _destination: SocketAddr,
    ) -> io::Result<Box<dyn RawSpoofer>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tls_spoof is not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_match_upstream_names_and_validation() {
        for (name, method) in [
            ("", TlsSpoofMethod::WrongSequence),
            ("wrong-sequence", TlsSpoofMethod::WrongSequence),
            ("wrong-checksum", TlsSpoofMethod::WrongChecksum),
            ("wrong-ack", TlsSpoofMethod::WrongAcknowledgment),
            ("wrong-md5", TlsSpoofMethod::WrongMd5),
            ("wrong-timestamp", TlsSpoofMethod::WrongTimestamp),
        ] {
            assert_eq!(TlsSpoofMethod::parse(name).unwrap(), method);
        }
        assert!(TlsSpoofMethod::parse("ttl").is_err());
        assert!(parse_options("", "wrong-ack").is_err());
    }

    #[test]
    fn generated_client_hello_contains_requested_sni_and_stays_under_one_mss() {
        let hello = build_fake_client_hello("allowed.example").unwrap();
        assert!(
            hello
                .windows(b"allowed.example".len())
                .any(|window| window == b"allowed.example")
        );
        assert!(
            hello.len() < 1460,
            "generated ClientHello is {} bytes",
            hello.len()
        );
    }

    #[test]
    fn packet_methods_apply_expected_tcp_mutations_and_valid_checksums() {
        let source: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let destination: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let payload = b"hello";
        for method in [
            TlsSpoofMethod::WrongSequence,
            TlsSpoofMethod::WrongChecksum,
            TlsSpoofMethod::WrongAcknowledgment,
            TlsSpoofMethod::WrongMd5,
            TlsSpoofMethod::WrongTimestamp,
        ] {
            let frame = build_spoof_frame(
                method,
                source,
                destination,
                100,
                200,
                4_000_000,
                Vec::new(),
                payload,
            )
            .unwrap();
            assert_eq!(checksum(&frame[..20]), 0);
            let tcp = &frame[20..];
            let sum = checksum_sum(
                tcp,
                pseudo_header_sum(
                    source.ip(),
                    destination.ip(),
                    tcp.len() as u32,
                ),
            );
            if method == TlsSpoofMethod::WrongChecksum {
                assert_ne!(finalize_checksum(sum), 0);
            } else {
                assert_eq!(finalize_checksum(sum), 0);
            }
        }
        let wrong_sequence = resolve_packet_info(
            TlsSpoofMethod::WrongSequence,
            100,
            200,
            0,
            Vec::new(),
            payload.len(),
        );
        assert_eq!(wrong_sequence.sequence, 95);
        let wrong_ack = resolve_packet_info(
            TlsSpoofMethod::WrongAcknowledgment,
            100,
            40_000,
            0,
            Vec::new(),
            payload.len(),
        );
        assert_eq!(wrong_ack.acknowledgment, 7_233);
    }

    #[test]
    fn timestamp_rewrite_matches_upstream_option_walker() {
        let mut options = vec![1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9];
        assert!(rewrite_tcp_timestamp(&mut options, 123));
        assert_eq!(&options[4..8], &123_u32.to_be_bytes());
        let info = resolve_packet_info(
            TlsSpoofMethod::WrongTimestamp,
            0,
            0,
            100,
            Vec::new(),
            1,
        );
        assert_eq!(&info.options[4..8], &0_u32.to_be_bytes());
    }
}
