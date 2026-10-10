//! Shared SOCKS listener and direct server, independent of the routing engine.

#[cfg(feature = "full")]
#[path = "socks/routed.rs"]
mod routed;
use std::{
    collections::HashSet,
    future::{Future, pending},
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "full")]
pub use routed::{SocksInbound, SocksTcpInjector};
#[cfg(feature = "full")]
pub(crate) use routed::{
    handle_connection, proxy_packet_connection, restore_fake_ip,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    common::network::SocksAddr,
    option::User,
    protocol::socks::{
        SocksCommand, SocksVersion, decode_udp_packet, encode_udp_packet,
        server_request, write_reply_for_version,
    },
};

#[derive(Clone)]
pub struct SocksServerOptions {
    /// TCP listener address; port zero selects an available port.
    pub listen: SocketAddr,
    /// An empty list allows unauthenticated clients.
    pub users: Vec<User>,
    /// Maximum idle time between UDP packets.
    pub udp_timeout: Duration,
    /// Bounds both authentication/request parsing and destination TCP dialing.
    pub handshake_timeout: Duration,
    /// Concurrent client connections; further clients wait in the backlog.
    pub max_connections: usize,
}

impl Default for SocksServerOptions {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".parse().expect("valid loopback address"),
            users: Vec::new(),
            udp_timeout: Duration::from_secs(300),
            handshake_timeout: Duration::from_secs(10),
            max_connections: 1024,
        }
    }
}

/// Direct TCP/UDP forwarding using the same protocol and listener machinery
/// as the routed SOCKS inbound. Requires only the `socks` Cargo feature.
pub struct SocksServer {
    options: Arc<SocksServerOptions>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    local_addr: Option<SocketAddr>,
}

impl SocksServer {
    pub fn new(options: SocksServerOptions) -> io::Result<Self> {
        if options.udp_timeout.is_zero() || options.handshake_timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS timeouts must be positive",
            ));
        }
        if options.max_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS connection limit must be positive",
            ));
        }
        for user in &options.users {
            if user.username.is_empty()
                || user.username.len() > 255
                || user.password.is_empty()
                || user.password.len() > 255
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS credentials must contain between 1 and 255 bytes",
                ));
            }
        }
        Ok(Self {
            options: Arc::new(options),
            cancellation: CancellationToken::new(),
            task: None,
            local_addr: None,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub async fn start(&mut self) -> io::Result<()> {
        if self.task.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "SOCKS server is already started",
            ));
        }
        let listener = TcpListener::bind(self.options.listen).await?;
        self.local_addr = Some(listener.local_addr()?);
        self.cancellation = CancellationToken::new();
        let cancellation = self.cancellation.clone();
        let options = self.options.clone();
        self.task = Some(tokio::spawn(serve_listener(
            listener,
            cancellation,
            self.options.max_connections,
            move |stream, local_ip, source| {
                let options = options.clone();
                async move {
                    handle_direct(stream, local_ip, source, &options).await
                }
            },
        )));
        Ok(())
    }

    /// Resolves once the listener stops without `close` being called, so
    /// callers can supervise it. Cancelling this future leaves the server
    /// running.
    pub async fn wait(&mut self) -> io::Result<()> {
        let Some(task) = self.task.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SOCKS server is not started",
            ));
        };
        let result = task.await;
        self.task = None;
        self.local_addr = None;
        result.map_err(io::Error::other)?
    }

    pub async fn close(&mut self) -> io::Result<()> {
        self.cancellation.cancel();
        self.local_addr = None;
        if let Some(task) = self.task.take() {
            task.await.map_err(io::Error::other)??;
        }
        Ok(())
    }
}

impl Drop for SocksServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Accepts until cancelled. Accept failures never stop the listener: resource
/// exhaustion (EMFILE, ENFILE, ENOBUFS, ENOMEM) clears once connections
/// close, and exiting would drop the listening socket for good.
async fn serve_listener<F, Fut>(
    listener: TcpListener,
    cancellation: CancellationToken,
    max_connections: usize,
    handle: F,
) -> io::Result<()>
where
    F: Fn(TcpStream, IpAddr, SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let mut connections = JoinSet::new();
    let mut backoff = ACCEPT_BACKOFF_MIN;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            result = listener.accept(), if connections.len() < max_connections => {
                match result {
                    Ok((stream, source)) => {
                        backoff = ACCEPT_BACKOFF_MIN;
                        // A peer that already reset fails only itself.
                        if let Ok(address) = stream.local_addr() {
                            connections.spawn(handle(stream, address.ip(), source));
                        }
                    }
                    // The queued peer went away; the listener is unaffected.
                    Err(error) if is_peer_error(&error) => {}
                    Err(error) => {
                        if backoff == ACCEPT_BACKOFF_MIN {
                            report_accept_error(&error);
                        }
                        // Retrying immediately would spin while descriptors
                        // are exhausted; a finished connection frees some.
                        tokio::select! {
                            _ = cancellation.cancelled() => break,
                            _ = sleep(backoff) => {}
                            Some(_) = connections.join_next(), if !connections.is_empty() => {}
                        }
                        backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                    }
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

fn is_peer_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
    )
}

fn report_accept_error(error: &io::Error) {
    #[cfg(feature = "full")]
    tracing::warn!(%error, "accept SOCKS connection");
    #[cfg(not(feature = "full"))]
    eprintln!("SOCKS accept failed, retrying: {error}");
}

/// Detects peers that vanished without closing, which would otherwise hold a
/// relay and its connection slot forever.
fn enable_keepalive(stream: &TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(20));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// The UDP source a client announced in its ASSOCIATE request, if usable.
/// Datagrams are only accepted from the control connection's address, so an
/// announced address elsewhere (typically a private one behind NAT) could
/// never match and is ignored rather than discarding every datagram.
fn association_client(
    requested: &SocksAddr,
    source: SocketAddr,
) -> Option<SocketAddr> {
    match requested {
        SocksAddr::Ip(address)
            if address.port() != 0
                && address.ip().to_canonical()
                    == source.ip().to_canonical() =>
        {
            Some(SocketAddr::new(source.ip(), address.port()))
        }
        _ => None,
    }
}

async fn handle_direct(
    mut client: TcpStream,
    local_ip: IpAddr,
    source: SocketAddr,
    options: &SocksServerOptions,
) -> io::Result<()> {
    enable_keepalive(&client);
    let request = timeout(
        options.handshake_timeout,
        server_request(&mut client, &options.users),
    )
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out")
    })??;
    match request.command {
        SocksCommand::Connect => {
            let connection = async {
                let addresses = request.destination.resolve().await?;
                TcpStream::connect(addresses.as_slice()).await
            };
            let connection = timeout(options.handshake_timeout, connection)
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "SOCKS destination connection timed out",
                    ))
                });
            let mut remote = match connection {
                Ok(remote) => remote,
                Err(error) => {
                    write_reply_for_version(
                        &mut client,
                        request.version,
                        error_reply(&error),
                        None,
                    )
                    .await?;
                    return Err(error);
                }
            };
            enable_keepalive(&remote);
            write_reply_for_version(
                &mut client,
                request.version,
                0,
                Some(&remote.local_addr()?.into()),
            )
            .await?;
            copy_bidirectional(&mut client, &mut remote).await?;
            Ok(())
        }
        SocksCommand::UdpAssociate if request.version == SocksVersion::V5 => {
            let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
            // A dual-stack listener reports IPv4 clients as IPv4-mapped
            // IPv6, which an IPv4 client cannot send datagrams to.
            let bound = socket.local_addr()?;
            let bound =
                SocketAddr::new(bound.ip().to_canonical(), bound.port());
            write_reply_for_version(
                &mut client,
                request.version,
                0,
                Some(&bound.into()),
            )
            .await?;
            let incoming = SocksUdpAssociation {
                socket,
                source_ip: source.ip(),
                client: Mutex::new(association_client(
                    &request.destination,
                    source,
                )),
            };
            tokio::select! {
                result = forward_direct_udp(&incoming, options.udp_timeout) => result,
                result = wait_for_control_close(&mut client) => result,
            }
        }
        _ => {
            write_reply_for_version(&mut client, request.version, 7, None)
                .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS command is not supported",
            ))
        }
    }
}

async fn receive_udp(
    socket: &Option<UdpSocket>,
    data: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(data).await,
        None => pending().await,
    }
}

/// ICMP errors for earlier datagrams surface on later socket calls; they
/// concern one destination, not the association.
fn is_udp_peer_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::Interrupted
    )
}

fn udp_packet<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(packet) => Ok(Some(packet)),
        Err(error) if is_udp_peer_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn forward_direct_udp(
    incoming: &SocksUdpAssociation,
    udp_timeout: Duration,
) -> io::Result<()> {
    let (mut ipv4, mut ipv6) = (None, None);
    let mut destinations = HashSet::new();
    let (mut request, mut response4, mut response6) =
        (vec![0; 65_535], vec![0; 65_535], vec![0; 65_535]);
    loop {
        timeout(udp_timeout, async {
            let forwarded: io::Result<()> = tokio::select! {
                packet = incoming.recv_from(&mut request) => {
                    let Some((size, destination)) = udp_packet(packet)? else { return Ok(()) };
                    // UDP is lossy: a datagram that cannot be resolved or
                    // sent is dropped without ending the association.
                    let Ok(addresses) = destination.resolve().await else { return Ok(()) };
                    for address in addresses {
                        let socket = if address.is_ipv4() { &mut ipv4 } else { &mut ipv6 };
                        if socket.is_none() {
                            let Ok(bound) = UdpSocket::bind(if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await else { continue };
                            *socket = Some(bound);
                        }
                        if socket.as_ref().expect("socket initialized").send_to(&request[..size], address).await.is_ok() {
                            destinations.insert(address);
                            break;
                        }
                    }
                    Ok(())
                }
                packet = receive_udp(&ipv4, &mut response4) => {
                    let Some((size, source)) = udp_packet(packet)? else { return Ok(()) };
                    if destinations.contains(&source) { udp_packet(incoming.send_to(&response4[..size], &source.into()).await)?; }
                    Ok(())
                }
                packet = receive_udp(&ipv6, &mut response6) => {
                    let Some((size, source)) = udp_packet(packet)? else { return Ok(()) };
                    if destinations.contains(&source) { udp_packet(incoming.send_to(&response6[..size], &source.into()).await)?; }
                    Ok(())
                }
            };
            forwarded
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS UDP session timed out"))??;
    }
}

async fn wait_for_control_close<S: AsyncRead + Unpin>(
    control: &mut S,
) -> io::Result<()> {
    loop {
        match control.read_u8().await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
}

struct SocksUdpAssociation {
    socket: UdpSocket,
    source_ip: IpAddr,
    client: Mutex<Option<SocketAddr>>,
}

impl SocksUdpAssociation {
    async fn send_to(
        &self,
        data: &[u8],
        destination: &SocksAddr,
    ) -> io::Result<usize> {
        let client = self.client.lock().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "SOCKS UDP client is not known",
            )
        })?;
        let packet = encode_udp_packet(destination, data)?;
        self.socket.send_to(&packet, client).await
    }

    async fn recv_from(
        &self,
        data: &mut [u8],
    ) -> io::Result<(usize, SocksAddr)> {
        let mut packet = vec![0_u8; 65_535];
        loop {
            let (size, sender) = self.socket.recv_from(&mut packet).await?;
            if sender.ip() != self.source_ip {
                continue;
            }
            if self
                .client
                .lock()
                .await
                .is_some_and(|expected| expected != sender)
            {
                continue;
            }
            // RFC 1928 requires dropping fragments; malformed datagrams
            // are dropped too, and neither identifies the client.
            let Ok((destination, payload)) = decode_udp_packet(&packet[..size])
            else {
                continue;
            };
            self.client.lock().await.get_or_insert(sender);
            if payload.len() > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS UDP receive buffer is too small",
                ));
            }
            data[..payload.len()].copy_from_slice(payload);
            return Ok((payload.len(), destination));
        }
    }
}

fn error_reply(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::NetworkUnreachable => 3,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => 4,
        io::ErrorKind::ConnectionRefused => 5,
        io::ErrorKind::TimedOut => 6,
        io::ErrorKind::Unsupported => 7,
        _ => 1,
    }
}
