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
    time::timeout,
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
}

impl Default for SocksServerOptions {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".parse().expect("valid loopback address"),
            users: Vec::new(),
            udp_timeout: Duration::from_secs(300),
            handshake_timeout: Duration::from_secs(10),
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
            move |stream, local_ip, source| {
                let options = options.clone();
                async move {
                    handle_direct(stream, local_ip, source, &options).await
                }
            },
        )));
        Ok(())
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

async fn serve_listener<F, Fut>(
    listener: TcpListener,
    cancellation: CancellationToken,
    handle: F,
) -> io::Result<()>
where
    F: Fn(TcpStream, IpAddr, SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = cancellation.cancelled() => break Ok(()),
            result = listener.accept() => {
                let (stream, source) = match result {
                    Ok(connection) => connection,
                    Err(error) => break Err(error),
                };
                let local_ip = match stream.local_addr() {
                    Ok(address) => address.ip(),
                    Err(error) => break Err(error),
                };
                connections.spawn(handle(stream, local_ip, source));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

async fn handle_direct(
    mut client: TcpStream,
    local_ip: IpAddr,
    source: SocketAddr,
    options: &SocksServerOptions,
) -> io::Result<()> {
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
            write_reply_for_version(
                &mut client,
                request.version,
                0,
                Some(&socket.local_addr()?.into()),
            )
            .await?;
            let client_address = match request.destination {
                SocksAddr::Ip(address)
                    if !address.ip().is_unspecified()
                        && address.port() != 0 =>
                {
                    Some(address)
                }
                _ => None,
            };
            let incoming = SocksUdpAssociation {
                socket,
                source_ip: source.ip(),
                client: Mutex::new(client_address),
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
            tokio::select! {
                packet = incoming.recv_from(&mut request) => {
                    let (size, destination) = packet?;
                    let addresses = destination.resolve().await?;
                    let mut last_error = io::Error::new(io::ErrorKind::NotFound, "SOCKS destination has no address");
                    for address in addresses {
                        let socket = if address.is_ipv4() { &mut ipv4 } else { &mut ipv6 };
                        if socket.is_none() {
                            *socket = Some(UdpSocket::bind(if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?);
                        }
                        match socket.as_ref().expect("socket initialized").send_to(&request[..size], address).await {
                            Ok(_) => { destinations.insert(address); return Ok(()); }
                            Err(error) => last_error = error,
                        }
                    }
                    Err(last_error)
                }
                packet = receive_udp(&ipv4, &mut response4) => {
                    let (size, source) = packet?;
                    if destinations.contains(&source) { incoming.send_to(&response4[..size], &source.into()).await?; }
                    Ok(())
                }
                packet = receive_udp(&ipv6, &mut response6) => {
                    let (size, source) = packet?;
                    if destinations.contains(&source) { incoming.send_to(&response6[..size], &source.into()).await?; }
                    Ok(())
                }
            }
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
            let mut client = self.client.lock().await;
            if client.is_some_and(|expected| expected != sender) {
                continue;
            }
            client.get_or_insert(sender);
            drop(client);
            let (destination, payload) = decode_udp_packet(&packet[..size])?;
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
