//! Quinn adapters for UDP packet connections routed through an outbound.

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Dialer, PacketConnection},
    common::network::SocksAddr,
};

struct ReceivedPacket {
    data: Vec<u8>,
    source: SocketAddr,
}

struct OutgoingPacket {
    data: Vec<u8>,
    destination: SocksAddr,
}

pub(crate) struct PacketUdpSocket {
    send: mpsc::UnboundedSender<OutgoingPacket>,
    receive: Mutex<mpsc::UnboundedReceiver<io::Result<ReceivedPacket>>>,
    local_address: SocketAddr,
    fixed_destination: Option<SocksAddr>,
    cancellation: CancellationToken,
}

impl fmt::Debug for PacketUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketUdpSocket")
            .field("local_address", &self.local_address)
            .finish_non_exhaustive()
    }
}

impl PacketUdpSocket {
    pub(crate) async fn connect(
        dialer: Arc<dyn Dialer>,
        destination: &SocksAddr,
    ) -> io::Result<(Arc<dyn AsyncUdpSocket>, SocketAddr)> {
        let remote = match destination {
            SocksAddr::Ip(address) => *address,
            SocksAddr::Domain { port, .. } => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *port)
            }
        };
        let socket = Self::bind_inner(
            dialer,
            destination,
            remote.is_ipv6(),
            Some(destination.clone()),
            remote,
        )
        .await?;
        Ok((socket, remote))
    }

    pub(crate) async fn bind(
        dialer: Arc<dyn Dialer>,
        route_destination: &SocksAddr,
        ipv6: bool,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let fallback_source = if ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        };
        Self::bind_inner(dialer, route_destination, ipv6, None, fallback_source)
            .await
    }

    async fn bind_inner(
        dialer: Arc<dyn Dialer>,
        route_destination: &SocksAddr,
        ipv6: bool,
        fixed_destination: Option<SocksAddr>,
        fallback_source: SocketAddr,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let connection: Arc<dyn PacketConnection> =
            Arc::from(dialer.listen_udp(route_destination).await?);
        let local_address = connection.local_addr()?.unwrap_or_else(|| {
            if ipv6 {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        });
        let (send_tx, mut send_rx) =
            mpsc::unbounded_channel::<OutgoingPacket>();
        let (receive_tx, receive_rx) = mpsc::unbounded_channel();
        let send_error_tx = receive_tx.clone();
        let send_connection = connection.clone();
        let cancellation = CancellationToken::new();
        let send_cancellation = cancellation.clone();
        tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = send_cancellation.cancelled() => break,
                    packet = send_rx.recv() => match packet {
                        Some(packet) => packet,
                        None => break,
                    },
                };
                if let Err(error) = send_connection
                    .send_to(&packet.data, &packet.destination)
                    .await
                {
                    let _ = send_error_tx.send(Err(error));
                    break;
                }
            }
        });
        let receive_cancellation = cancellation.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            loop {
                let result = tokio::select! {
                    _ = receive_cancellation.cancelled() => break,
                    result = connection.recv_from(&mut buffer) => result.map(
                        |(size, source)| ReceivedPacket {
                            data: buffer[..size].to_vec(),
                            source: match source {
                                SocksAddr::Ip(address) => address,
                                SocksAddr::Domain { .. } => fallback_source,
                            },
                        },
                    ),
                };
                let failed = result.is_err();
                if receive_tx.send(result).is_err() || failed {
                    break;
                }
            }
        });
        Ok(Arc::new(Self {
            send: send_tx,
            receive: Mutex::new(receive_rx),
            local_address,
            fixed_destination,
            cancellation,
        }))
    }
}

impl Drop for PacketUdpSocket {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for PacketUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let segment_size =
            transmit.segment_size.unwrap_or(transmit.contents.len());
        for segment in transmit.contents.chunks(segment_size.max(1)) {
            let destination = self
                .fixed_destination
                .clone()
                .unwrap_or(SocksAddr::Ip(transmit.destination));
            self.send
                .send(OutgoingPacket {
                    data: segment.to_vec(),
                    destination,
                })
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "QUIC packet connection is closed",
                    )
                })?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buffer) = buffers.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let mut receive = self
            .receive
            .lock()
            .map_err(|_| io::Error::other("QUIC receive lock poisoned"))?;
        match receive.poll_recv(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC packet connection is closed",
            ))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(Some(Ok(packet))) => {
                if packet.data.len() > buffer.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "QUIC datagram exceeds receive buffer",
                    )));
                }
                buffer[..packet.data.len()].copy_from_slice(&packet.data);
                metadata[0] = RecvMeta {
                    addr: packet.source,
                    len: packet.data.len(),
                    stride: packet.data.len(),
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_address)
    }

    fn may_fragment(&self) -> bool {
        true
    }
}
