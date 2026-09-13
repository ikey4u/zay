//! Runtime interfaces shared by inbound, outbound, endpoint and route modules.

use std::{
    any::Any,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, rdata::svcb::SvcParamValue},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::common::network::Network;
use crate::common::network::SocksAddr;
use crate::constant::{InterfaceType, NetworkStrategy};

/// Per-connection dial hints produced by route actions.
///
/// Most outbounds intentionally ignore this hint. Direct outbounds and
/// groups which eventually select a direct outbound propagate it, matching
/// sing-box's optional `ParallelInterfaceDialer` behavior.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NetworkDialOptions {
    pub strategy: Option<NetworkStrategy>,
    pub network_type: Vec<InterfaceType>,
    pub fallback_network_type: Vec<InterfaceType>,
    pub fallback_delay: Option<std::time::Duration>,
    pub udp_disable_domain_unmapping: bool,
    pub udp_connect: bool,
    /// Whether this dial originates from a routed user connection.
    ///
    /// Outbound groups use this provenance bit to match sing-box's
    /// interruption semantics: internal protocol connections are always
    /// replaced when group selection changes, while external connections
    /// are preserved unless `interrupt_exist_connections` is enabled.
    pub external_connection: bool,
}

/// Runtime-scoped neighbor table used by local DNS and LAN-aware routing.
///
/// Linux and macOS runtimes create the native resolver when configuration
/// requires it. Embedding applications may override that resolver, and mobile
/// platforms provide their VPN/platform-backed table through this interface.
pub trait NeighborResolver: Send + Sync {
    fn lookup_addresses(&self, hostname: &str) -> Vec<IpAddr>;

    /// Return the link-layer address currently associated with an IP address.
    ///
    /// Implementations that only provide hostname-to-address resolution can
    /// keep the default. Desktop neighbor-table monitors and mobile platform
    /// adapters use this hook to populate `source_mac_address` route metadata.
    fn lookup_mac(&self, _address: IpAddr) -> Option<Vec<u8>> {
        None
    }

    /// Return the DHCP/neighbor hostname currently associated with an IP.
    fn lookup_hostname(&self, _address: IpAddr) -> Option<String> {
        None
    }
}

/// Process ownership information discovered for a local TCP/UDP flow.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub process_name: String,
    pub process_path: String,
    pub package_name: String,
    pub user: String,
    pub user_id: Option<i32>,
}

/// Runtime-scoped connection-owner lookup supplied by an embedding host.
///
/// Mobile platforms normally implement this through their VPN API. Desktop
/// hosts may use socket-diag, sysctl or IP Helper without making the singbox
/// library own a process-global monitor.
pub trait ProcessResolver: Send + Sync {
    fn lookup(
        &self,
        network: Network,
        source: std::net::SocketAddr,
        destination: Option<std::net::SocketAddr>,
    ) -> Option<ProcessInfo>;
}

#[derive(Default)]
pub(crate) struct InterruptGenerations {
    internal: CancellationToken,
    external: CancellationToken,
}

impl InterruptGenerations {
    pub(crate) fn token(&self, external: bool) -> CancellationToken {
        if external {
            self.external.clone()
        } else {
            self.internal.clone()
        }
    }

    pub(crate) fn interrupt(&mut self, include_external: bool) {
        self.internal.cancel();
        self.internal = CancellationToken::new();
        if include_external {
            self.external.cancel();
            self.external = CancellationToken::new();
        }
    }

    pub(crate) fn cancel_all(&self) {
        self.internal.cancel();
        self.external.cancel();
    }
}

impl NetworkDialOptions {
    pub fn is_empty(&self) -> bool {
        self.strategy.is_none()
            && self.network_type.is_empty()
            && self.fallback_network_type.is_empty()
            && self.fallback_delay.is_none_or(|delay| delay.is_zero())
            && !self.udp_disable_domain_unmapping
            && !self.udp_connect
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: AsyncRead + AsyncWrite + Any> AsyncReadWrite for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub type Stream = Box<dyn AsyncReadWrite + Unpin + Send>;

#[cfg(unix)]
pub(crate) type StreamSocket = std::os::fd::RawFd;
#[cfg(windows)]
pub(crate) type StreamSocket = std::os::windows::io::RawSocket;
#[cfg(not(any(unix, windows)))]
pub(crate) type StreamSocket = ();

/// Return the physical TCP descriptor carried by a stream, if any. Protocol
/// and TLS wrappers use `preserve_stream_socket` when replacing the outer I/O
/// type so socket-level controls can still reach the original connection.
#[cfg(unix)]
pub(crate) fn stream_socket(stream: &Stream) -> Option<StreamSocket> {
    if let Some(stream) = stream
        .as_ref()
        .as_any()
        .downcast_ref::<tokio::net::TcpStream>()
    {
        use std::os::fd::AsRawFd as _;
        return Some(stream.as_raw_fd());
    }
    stream
        .as_ref()
        .as_any()
        .downcast_ref::<SocketMetadataStream>()
        .map(|stream| stream.socket)
}

#[cfg(windows)]
pub(crate) fn stream_socket(stream: &Stream) -> Option<StreamSocket> {
    if let Some(stream) = stream
        .as_ref()
        .as_any()
        .downcast_ref::<tokio::net::TcpStream>()
    {
        use std::os::windows::io::AsRawSocket as _;
        return Some(stream.as_raw_socket());
    }
    stream
        .as_ref()
        .as_any()
        .downcast_ref::<SocketMetadataStream>()
        .map(|stream| stream.socket)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn stream_socket(_stream: &Stream) -> Option<StreamSocket> {
    None
}

#[cfg(unix)]
pub(crate) fn tcp_stream_socket(
    stream: &tokio::net::TcpStream,
) -> Option<StreamSocket> {
    use std::os::fd::AsRawFd as _;
    Some(stream.as_raw_fd())
}

#[cfg(windows)]
pub(crate) fn tcp_stream_socket(
    stream: &tokio::net::TcpStream,
) -> Option<StreamSocket> {
    use std::os::windows::io::AsRawSocket as _;
    Some(stream.as_raw_socket())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn tcp_stream_socket(
    _stream: &tokio::net::TcpStream,
) -> Option<StreamSocket> {
    None
}

pub(crate) fn preserve_stream_socket(
    stream: Stream,
    socket: Option<StreamSocket>,
) -> Stream {
    match socket {
        Some(socket) => Box::new(SocketMetadataStream {
            inner: stream,
            socket,
        }),
        None => stream,
    }
}

/// Return the physical local address carried by a TCP stream when the dialer
/// preserved its socket metadata.
pub(crate) fn stream_local_addr(
    stream: &Stream,
) -> io::Result<Option<std::net::SocketAddr>> {
    if let Some(stream) = stream
        .as_ref()
        .as_any()
        .downcast_ref::<tokio::net::TcpStream>()
    {
        return stream.local_addr().map(Some);
    }
    #[cfg(unix)]
    {
        use std::os::fd::BorrowedFd;

        let Some(socket) = stream_socket(stream) else {
            return Ok(None);
        };
        // SAFETY: the descriptor remains owned by `stream` and the borrowed
        // handle cannot outlive this function call.
        let socket = unsafe { BorrowedFd::borrow_raw(socket) };
        socket2::SockRef::from(&socket)
            .local_addr()
            .map(|address| address.as_socket())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::BorrowedSocket;

        let Some(socket) = stream_socket(stream) else {
            return Ok(None);
        };
        // SAFETY: the socket remains owned by `stream` for this borrow.
        let socket = unsafe { BorrowedSocket::borrow_raw(socket) };
        socket2::SockRef::from(&socket)
            .local_addr()
            .map(|address| address.as_socket())
    }
    #[cfg(not(any(unix, windows)))]
    Ok(None)
}

/// Return the physical peer address carried by a TCP stream when the dialer
/// preserved its socket metadata.
pub(crate) fn stream_peer_addr(
    stream: &Stream,
) -> io::Result<Option<std::net::SocketAddr>> {
    if let Some(stream) = stream
        .as_ref()
        .as_any()
        .downcast_ref::<tokio::net::TcpStream>()
    {
        return stream.peer_addr().map(Some);
    }
    #[cfg(unix)]
    {
        use std::os::fd::BorrowedFd;

        let Some(socket) = stream_socket(stream) else {
            return Ok(None);
        };
        // SAFETY: the descriptor remains owned by `stream` for this borrow.
        let socket = unsafe { BorrowedFd::borrow_raw(socket) };
        socket2::SockRef::from(&socket)
            .peer_addr()
            .map(|address| address.as_socket())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::BorrowedSocket;

        let Some(socket) = stream_socket(stream) else {
            return Ok(None);
        };
        // SAFETY: the socket remains owned by `stream` for this borrow.
        let socket = unsafe { BorrowedSocket::borrow_raw(socket) };
        socket2::SockRef::from(&socket)
            .peer_addr()
            .map(|address| address.as_socket())
    }
    #[cfg(not(any(unix, windows)))]
    Ok(None)
}

struct SocketMetadataStream {
    inner: Stream,
    #[cfg_attr(not(unix), allow(dead_code))]
    socket: StreamSocket,
}

impl AsyncRead for SocketMetadataStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for SocketMetadataStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
pub type DialFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Stream>> + Send + 'a>>;
pub type VisionDialFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<VisionTransport>> + Send + 'a>>;
pub type PacketFuture<'a, T> =
    Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// A raw IP packet return path attached to an [`IpPacketPort`].
///
/// Ports call this before delivering a received packet to their own userspace
/// stack. Consumed packets are removed from the returned vector; packets that
/// do not belong to this return path remain available to the port's normal
/// receive path. The weak reference used by [`IpPacketPort::attach_return`]
/// prevents endpoint-to-router reference cycles.
pub trait IpPacketReturn: Send + Sync {
    /// Writable bytes which must precede each IP packet.
    fn return_headroom(&self) -> usize {
        0
    }

    /// Consume matching return packets and return the unconsumed remainder.
    fn return_packets(&self, packets: Vec<Vec<u8>>) -> Vec<Vec<u8>>;
}

/// An L3 packet port exposed by flow-capable outbounds and endpoints.
///
/// This is the Rust counterpart of `sing-tun`'s `Port`: the flow dispatcher
/// applies stateful source NAT before writing packets and reverses that mapping
/// through an attached [`IpPacketReturn`].
pub trait IpPacketPort: Send + Sync {
    /// Primary IPv4 and IPv6 addresses used as the flow-NAT source.
    fn port_addresses(&self) -> (Option<IpAddr>, Option<IpAddr>);

    /// Effective IP MTU, or zero when the port does not impose one.
    fn port_mtu(&self) -> usize;

    /// Optional `(start, count)` source-selector range owned by the port. A
    /// zero count asks the dispatcher to use its normal ephemeral range.
    /// Platform bridges use a reserved range on systems where the kernel NAT
    /// shares the host port namespace.
    fn port_selector_range(&self) -> (u16, u16) {
        (0, 0)
    }

    /// Attach the dispatcher return path. A port may reject multiple live
    /// return paths when its underlying transport can only feed one consumer.
    fn attach_return(
        &self,
        return_path: Weak<dyn IpPacketReturn>,
    ) -> io::Result<()>;

    /// Detach a previously attached dispatcher return path.
    fn detach_return(&self, return_path: &Weak<dyn IpPacketReturn>);

    /// Write raw IPv4/IPv6 packets to this port.
    fn write_packets<'a>(
        &'a self,
        packets: Vec<Vec<u8>>,
    ) -> PacketFuture<'a, ()>;
}

/// Control plane for a TLS stream whose outer record layer can be retired by
/// the authenticated VLESS Vision Direct command.
pub trait VisionDirectSwitch: Send + Sync {
    fn request_read_direct(&self);
    fn request_write_direct(&self);
    fn read_direct_active(&self) -> bool;
    fn write_direct_active(&self) -> bool;
}

/// A byte stream paired with the exact outer-TLS switch that owns its raw
/// transport.  Keeping this capability explicit prevents Vision from silently
/// running in padding-only mode on an incompatible transport wrapper.
pub struct VisionTransport {
    pub stream: Stream,
    pub direct_switch: Arc<dyn VisionDirectSwitch>,
}

pub trait PacketConnection: Send + Sync {
    /// Returns the physical local UDP address when this packet connection owns
    /// one. Tunnel transports may leave it unavailable.
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize>;

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)>;
}

pub type PacketStream = Box<dyn PacketConnection>;

pub(crate) fn apply_udp_connect(
    inner: PacketStream,
    destination: &SocksAddr,
    enabled: bool,
    preserve_response_source: bool,
) -> PacketStream {
    if enabled {
        Box::new(ConnectedPacketConnection {
            inner,
            destination: destination.clone(),
            preserve_response_source,
        })
    } else {
        inner
    }
}

struct ConnectedPacketConnection {
    inner: PacketStream,
    destination: SocksAddr,
    preserve_response_source: bool,
}

impl PacketConnection for ConnectedPacketConnection {
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        self.inner.send_to(data, &self.destination)
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let (size, source) = self.inner.recv_from(data).await?;
            Ok((
                size,
                if self.preserve_response_source {
                    source
                } else {
                    self.destination.clone()
                },
            ))
        })
    }
}

/// Result of an ICMP request forwarded by an outbound. `packet` contains the
/// ICMP message without an IP header; the endpoint router restores the
/// original tunnel addresses when it builds the return packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpResponse {
    pub source: IpAddr,
    pub packet: Vec<u8>,
    pub hop_limit: u8,
}

/// Put bytes consumed during protocol inspection back in front of a stream.
/// Writes always pass directly to the underlying transport.
pub fn replay_stream(inner: Stream, prefix: Vec<u8>) -> Stream {
    if prefix.is_empty() {
        inner
    } else {
        let socket = stream_socket(&inner);
        preserve_stream_socket(
            Box::new(ReplayStream {
                inner,
                prefix,
                offset: 0,
            }),
            socket,
        )
    }
}

struct ReplayStream {
    inner: Stream,
    prefix: Vec<u8>,
    offset: usize,
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buffer.remaining() != 0 {
            let size = buffer
                .remaining()
                .min(self.prefix.len().saturating_sub(self.offset));
            let end = self.offset + size;
            buffer.put_slice(&self.prefix[self.offset..end]);
            self.offset = end;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wrap a stream so a group selection change can interrupt pending I/O.
pub fn interruptible_stream(inner: Stream, token: CancellationToken) -> Stream {
    let socket = stream_socket(&inner);
    preserve_stream_socket(
        Box::new(InterruptibleStream {
            inner,
            cancelled: Box::pin(token.cancelled_owned()),
        }),
        socket,
    )
}

struct InterruptibleStream {
    inner: Stream,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl InterruptibleStream {
    fn poll_cancelled(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.cancelled.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "outbound group selection changed",
            )),
            Poll::Pending => Ok(()),
        }
    }
}

impl AsyncRead for InterruptibleStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for InterruptibleStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let Err(error) = self.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if let Err(error) = self.poll_cancelled(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wrap a packet connection so a group selection change interrupts operations.
pub fn interruptible_packets(
    inner: PacketStream,
    token: CancellationToken,
) -> PacketStream {
    Box::new(InterruptiblePacketConnection { inner, token })
}

struct InterruptiblePacketConnection {
    inner: PacketStream,
    token: CancellationToken,
}

impl PacketConnection for InterruptiblePacketConnection {
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = self.token.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = self.inner.send_to(data, destination) => result,
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = self.token.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "outbound group selection changed",
                )),
                result = self.inner.recv_from(data) => result,
            }
        })
    }
}

pub trait Dialer: Send + Sync {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a>;

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        _options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        self.dial_tcp(destination)
    }

    /// Open a TCP bind request through an outbound that supports it.
    ///
    /// Like sagernet/sing's `BindContext`, the returned stream has consumed
    /// the first bind reply. Protocols such as SOCKS leave their second
    /// peer-connected reply at the front of the returned stream.
    fn bind_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP bind is not supported by this outbound",
            ))
        })
    }

    fn dial_vision_tcp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> VisionDialFuture<'a> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "VLESS Vision requires a switchable outer TLS stream",
            ))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is not supported by this outbound",
            ))
        })
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let packets = self.listen_udp(destination).await?;
            Ok(apply_udp_connect(
                packets,
                destination,
                options.udp_connect,
                options.udp_disable_domain_unmapping,
            ))
        })
    }

    /// Create a UDP packet connection bound to a requested local port.
    /// Outbounds that cannot control their physical bind return Unsupported.
    fn listen_udp_on<'a>(
        &'a self,
        destination: &'a SocksAddr,
        local_port: u16,
    ) -> PacketFuture<'a, PacketStream> {
        if local_port == 0 {
            return self.listen_udp(destination);
        }
        Box::pin(async move {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("binding UDP port {local_port} is not supported"),
            ))
        })
    }

    /// Forward one ICMP message. Most proxy protocols do not expose an IP
    /// packet port and therefore keep the Unsupported default. Direct and
    /// endpoint outbounds can opt in without pretending ICMP is UDP.
    fn exchange_icmp<'a>(
        &'a self,
        _packet: &'a [u8],
        _source: IpAddr,
        _hop_limit: u8,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICMP is not supported by this outbound",
            ))
        })
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        _options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        self.exchange_icmp(packet, source, hop_limit, destination)
    }

    /// Report whether this outbound is preferred for a domain learned from
    /// its live routing configuration. Dynamic VPN endpoints override this
    /// so `preferred_by` rules can follow negotiated split-tunnel policy.
    fn preferred_domain(&self, _domain: &str) -> bool {
        false
    }

    /// Report whether this outbound is preferred for a destination address
    /// learned from its live routing configuration.
    fn preferred_address(&self, _address: IpAddr) -> bool {
        false
    }

    /// Port addresses advertised when this dialer can accept a pre-matched
    /// ICMP flow. Packet-port outbounds inherit their actual L3 source
    /// addresses; direct overrides this with unspecified addresses, matching
    /// sing-box's host ICMP port.
    fn icmp_flow_addresses(&self) -> Option<(Option<IpAddr>, Option<IpAddr>)> {
        self.packet_port().map(|port| port.port_addresses())
    }

    /// Return the L3 packet port when this outbound can receive whole routed
    /// TCP, UDP, and ICMP flows without reconstructing transport sockets.
    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        None
    }
}

impl<T: Dialer + ?Sized> Dialer for Arc<T> {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        (**self).dial_tcp(destination)
    }

    fn dial_tcp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> DialFuture<'a> {
        (**self).dial_tcp_with_options(destination, options)
    }

    fn dial_vision_tcp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> VisionDialFuture<'a> {
        (**self).dial_vision_tcp(destination)
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        (**self).bind_tcp(destination)
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        (**self).listen_udp(destination)
    }

    fn listen_udp_with_options<'a>(
        &'a self,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, PacketStream> {
        (**self).listen_udp_with_options(destination, options)
    }

    fn listen_udp_on<'a>(
        &'a self,
        destination: &'a SocksAddr,
        local_port: u16,
    ) -> PacketFuture<'a, PacketStream> {
        (**self).listen_udp_on(destination, local_port)
    }

    fn exchange_icmp<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, IcmpResponse> {
        (**self).exchange_icmp(packet, source, hop_limit, destination)
    }

    fn exchange_icmp_with_options<'a>(
        &'a self,
        packet: &'a [u8],
        source: IpAddr,
        hop_limit: u8,
        destination: &'a SocksAddr,
        options: &'a NetworkDialOptions,
    ) -> PacketFuture<'a, IcmpResponse> {
        (**self).exchange_icmp_with_options(
            packet,
            source,
            hop_limit,
            destination,
            options,
        )
    }

    fn preferred_domain(&self, domain: &str) -> bool {
        (**self).preferred_domain(domain)
    }

    fn preferred_address(&self, address: IpAddr) -> bool {
        (**self).preferred_address(address)
    }

    fn icmp_flow_addresses(&self) -> Option<(Option<IpAddr>, Option<IpAddr>)> {
        (**self).icmp_flow_addresses()
    }

    fn packet_port(&self) -> Option<Arc<dyn IpPacketPort>> {
        (**self).packet_port()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InboundContext {
    pub inbound: String,
    pub outbound: String,
    pub source: Option<SocksAddr>,
    pub destination: Option<SocksAddr>,
    pub domain: String,
    pub protocol: String,
    pub user: String,
    pub network_type: String,
}

/// Extract addresses that sing-box exposes to DNS response matchers.
///
/// Only successful responses contribute addresses. Besides ordinary A and
/// AAAA answers, HTTPS service-binding IPv4/IPv6 hints are included. IPv4
/// hints remain true [`std::net::Ipv4Addr`] values rather than IPv4-mapped
/// IPv6 addresses, matching Go's `netip.Addr.Unmap` behavior.
pub fn dns_response_addresses(response: &Message) -> Vec<IpAddr> {
    if response.metadata.response_code != ResponseCode::NoError {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    for record in &response.answers {
        match &record.data {
            RData::A(address) => addresses.push(IpAddr::V4(address.0)),
            RData::AAAA(address) => addresses.push(IpAddr::V6(address.0)),
            RData::HTTPS(https) => {
                for (_, value) in &https.0.svc_params {
                    match value {
                        SvcParamValue::Ipv4Hint(hints) => addresses.extend(
                            hints.0.iter().map(|hint| IpAddr::V4(hint.0)),
                        ),
                        SvcParamValue::Ipv6Hint(hints) => addresses.extend(
                            hints.0.iter().map(|hint| IpAddr::V6(hint.0)),
                        ),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use hickory_proto::{
        op::{Message, ResponseCode},
        rr::{
            Name, RData, Record,
            rdata::{
                A, AAAA, HTTPS, SVCB,
                svcb::{IpHint, SvcParamKey, SvcParamValue},
            },
        },
    };

    use super::dns_response_addresses;

    #[test]
    fn dns_response_addresses_unmaps_https_ipv4_hints() {
        let mut response = Message::query();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A::new(
                            1, 1, 1, 1,
                        )])),
                    ),
                    (
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(
                            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
                        )])),
                    ),
                ],
            ))),
        ));
        assert_eq!(
            dns_response_addresses(&response),
            [IpAddr::from([1, 1, 1, 1]), "2001:db8::1".parse().unwrap(),]
        );
        assert!(dns_response_addresses(&response)[0].is_ipv4());

        response.metadata.response_code = ResponseCode::NXDomain;
        assert!(dns_response_addresses(&response).is_empty());
    }
}
