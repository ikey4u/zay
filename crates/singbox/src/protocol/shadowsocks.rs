//! Shadowsocks client transport backed by `shadowsocks-rust`.
//!
//! The protocol implementation, cipher suites and replay protection come from
//! the mature `shadowsocks` crate. This module adapts them to singbox's
//! destination-aware stream and packet abstractions, including outbound
//! detours.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::SystemTime,
};

use shadowsocks::{
    ServerConfig,
    config::ServerType,
    context::{Context as ShadowsocksContext, TimeProvider},
    crypto::CipherKind,
    relay::{
        socks5::Address,
        tcprelay::proxy_stream::ProxyClientStream,
        udprelay::{
            DatagramReceive, DatagramSend, DatagramSocket, ProxySocket,
            options::UdpSocketControlData, proxy_socket::UdpSocketType,
        },
    },
};
use tokio::{io::ReadBuf, sync::mpsc};

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
    },
    common::{network::SocksAddr, ntp::NtpClock},
    protocol::shadowsocks_aead192::{Aes192GcmMethod, SALT_LENGTH},
};

pub fn parse_method(method: &str) -> io::Result<CipherKind> {
    let method = CipherKind::from_str(method).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported Shadowsocks method: {method}"),
        )
    })?;
    Ok(method)
}

#[cfg(test)]
mod method_tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use bytes::BytesMut;
    use shadowsocks::{
        config::ServerType,
        context::Context,
        crypto::CipherKind,
        relay::{
            socks5::Address,
            udprelay::{
                crypto_io::{decrypt_client_payload, encrypt_client_payload},
                options::UdpSocketControlData,
            },
        },
    };

    use super::{parse_method, shadowsocks_context_with_clock};
    use crate::common::ntp::{NtpClock, NtpSample};

    #[test]
    fn accepts_the_upstream_extended_aead_cipher() {
        assert!(parse_method("xchacha20-ietf-poly1305").is_ok());
    }

    #[test]
    fn aead_2022_udp_uses_injected_ntp_clock() {
        let clock = NtpClock::default();
        clock.update(NtpSample {
            offset_nanos: 120_000_000_000,
            round_trip_nanos: 1,
            stratum: 1,
        });
        let client = shadowsocks_context_with_clock(
            ServerType::Local,
            Some(clock.clone()),
        );
        let server =
            shadowsocks_context_with_clock(ServerType::Server, Some(clock));
        let method = CipherKind::AEAD2022_BLAKE3_AES_128_GCM;
        let key = [7_u8; 16];
        let address = Address::SocketAddress(SocketAddr::new(
            Ipv4Addr::LOCALHOST.into(),
            443,
        ));
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 11;
        control.packet_id = 1;
        let mut encrypted = BytesMut::new();
        encrypt_client_payload(
            &client,
            method,
            &key,
            &address,
            &control,
            &[],
            b"clock-aware",
            &mut encrypted,
        );

        let mut system_time_packet = encrypted.to_vec();
        assert!(
            decrypt_client_payload(
                &Context::new(ServerType::Server),
                method,
                &key,
                &mut system_time_packet,
                None,
            )
            .is_err()
        );
        let mut corrected_packet = encrypted.to_vec();
        let (size, decoded_address, _) = decrypt_client_payload(
            &server,
            method,
            &key,
            &mut corrected_packet,
            None,
        )
        .expect("matching NTP clocks must accept AEAD-2022 timestamp");
        assert_eq!(decoded_address, address);
        assert_eq!(&corrected_packet[..size], b"clock-aware");
    }
}

pub fn server_config(
    server: &SocksAddr,
    password: &str,
    method: CipherKind,
) -> io::Result<ServerConfig> {
    ServerConfig::new(to_address(server), password, method)
        .map_err(io::Error::other)
}

pub fn to_address(address: &SocksAddr) -> Address {
    match address {
        SocksAddr::Ip(address) => Address::SocketAddress(*address),
        SocksAddr::Domain { host, port } => {
            Address::DomainNameAddress(host.clone(), *port)
        }
    }
}

pub fn from_address(address: Address) -> SocksAddr {
    match address {
        Address::SocketAddress(address) => SocksAddr::Ip(address),
        Address::DomainNameAddress(host, port) => {
            SocksAddr::Domain { host, port }
        }
    }
}

#[derive(Debug)]
struct NtpTimeProvider(NtpClock);

impl TimeProvider for NtpTimeProvider {
    fn now(&self) -> SystemTime {
        self.0.now()
    }
}

pub(crate) fn shadowsocks_context_with_clock(
    server_type: ServerType,
    clock: Option<NtpClock>,
) -> shadowsocks::context::SharedContext {
    let mut context = ShadowsocksContext::new(server_type);
    if let Some(clock) = clock {
        context.set_time_provider(Arc::new(NtpTimeProvider(clock)));
    }
    Arc::new(context)
}

pub struct ShadowsocksOutbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    method: ShadowsocksOutboundMethod,
}

enum ShadowsocksOutboundMethod {
    Library {
        config: Box<ServerConfig>,
        context: shadowsocks::context::SharedContext,
    },
    Aes192(Aes192GcmMethod),
}

impl ShadowsocksOutbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        method: &str,
        password: &str,
    ) -> io::Result<Self> {
        Self::new_with_clock(upstream, server, method, password, None)
    }

    pub fn new_with_clock(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        method: &str,
        password: &str,
        clock: Option<NtpClock>,
    ) -> io::Result<Self> {
        let method = if method.eq_ignore_ascii_case("aes-192-gcm") {
            ShadowsocksOutboundMethod::Aes192(Aes192GcmMethod::new(password)?)
        } else {
            let method = parse_method(method)?;
            let config = server_config(&server, password, method)?;
            ShadowsocksOutboundMethod::Library {
                config: Box::new(config),
                context: shadowsocks_context_with_clock(
                    ServerType::Local,
                    clock,
                ),
            }
        };
        Ok(Self {
            upstream,
            server,
            method,
        })
    }
}

impl Dialer for ShadowsocksOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            let stream = match &self.method {
                ShadowsocksOutboundMethod::Library { config, context } => {
                    let stream = ProxyClientStream::from_stream(
                        context.clone(),
                        stream,
                        config,
                        to_address(destination),
                    );
                    Box::new(stream) as crate::adapter::Stream
                }
                ShadowsocksOutboundMethod::Aes192(method) => {
                    method.wrap_client_stream(stream, destination.clone())
                }
            };
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let packet = self.upstream.listen_udp(&self.server).await?;
            match &self.method {
                ShadowsocksOutboundMethod::Library { config, context } => {
                    let bridge =
                        DatagramBridge::new(packet, self.server.clone());
                    let socket = ProxySocket::from_socket(
                        UdpSocketType::Client,
                        context.clone(),
                        config,
                        bridge,
                    );
                    let mut session_id = [0_u8; 8];
                    getrandom::fill(&mut session_id)
                        .map_err(io::Error::other)?;
                    Ok(Box::new(ShadowsocksPacketConnection {
                        socket,
                        bound_destination: destination.clone(),
                        client_session_id: u64::from_be_bytes(session_id),
                        packet_id: AtomicU64::new(0),
                    }) as PacketStream)
                }
                ShadowsocksOutboundMethod::Aes192(method) => {
                    Ok(Box::new(Aes192PacketConnection {
                        packet,
                        server: self.server.clone(),
                        bound_destination: destination.clone(),
                        method: method.clone(),
                    }) as PacketStream)
                }
            }
        })
    }
}

struct Aes192PacketConnection {
    packet: PacketStream,
    server: SocksAddr,
    bound_destination: SocksAddr,
    method: Aes192GcmMethod,
}

impl PacketConnection for Aes192PacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let destination = if destination.host().is_empty() {
                &self.bound_destination
            } else {
                destination
            };
            let mut salt = [0_u8; SALT_LENGTH];
            getrandom::fill(&mut salt).map_err(io::Error::other)?;
            let packet = self.method.seal_packet(&salt, destination, data)?;
            self.packet.send_to(&packet, &self.server).await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut packet = vec![0_u8; 65_535];
            let (size, _) = self.packet.recv_from(&mut packet).await?;
            let (source, payload) = self.method.open_packet(&packet[..size])?;
            if payload.len() > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks UDP payload exceeds receive buffer",
                ));
            }
            data[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), source))
        })
    }
}

struct ShadowsocksPacketConnection {
    socket: ProxySocket<DatagramBridge>,
    bound_destination: SocksAddr,
    client_session_id: u64,
    packet_id: AtomicU64,
}

impl PacketConnection for ShadowsocksPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let destination = if destination.host().is_empty() {
                &self.bound_destination
            } else {
                destination
            };
            let mut control = UdpSocketControlData::default();
            control.client_session_id = self.client_session_id;
            control.packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
            self.socket
                .send_with_ctrl(&to_address(destination), &control, data)
                .await
                .map(|_| data.len())
                .map_err(io::Error::from)
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut packet = vec![0_u8; 65_535];
            let (size, source, _, control) = self
                .socket
                .recv_with_ctrl(&mut packet)
                .await
                .map_err(io::Error::from)?;
            if control.as_ref().is_some_and(|control| {
                control.client_session_id != self.client_session_id
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks UDP response session mismatch",
                ));
            }
            if size > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks UDP payload exceeds receive buffer",
                ));
            }
            data[..size].copy_from_slice(&packet[..size]);
            Ok((size, from_address(source)))
        })
    }
}

/// Converts the destination-aware packet API into the poll-based connected
/// datagram transport expected by shadowsocks-rust. A background task is used
/// because `PacketConnection` deliberately exposes async borrowed futures.
struct DatagramBridge {
    sends: mpsc::UnboundedSender<Vec<u8>>,
    receives: Mutex<mpsc::UnboundedReceiver<io::Result<Vec<u8>>>>,
}

impl DatagramBridge {
    fn new(packet: PacketStream, server: SocksAddr) -> Self {
        let packet: Arc<dyn PacketConnection> = Arc::from(packet);
        let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (receive_tx, receive_rx) =
            mpsc::unbounded_channel::<io::Result<Vec<u8>>>();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            loop {
                tokio::select! {
                    Some(data) = send_rx.recv() => {
                        if let Err(error) = packet.send_to(&data, &server).await {
                            let _ = receive_tx.send(Err(error));
                            break;
                        }
                    }
                    result = packet.recv_from(&mut buffer) => {
                        match result {
                            Ok((size, _)) => {
                                if receive_tx.send(Ok(buffer[..size].to_vec())).is_err() {
                                    break;
                                }
                            }
                            Err(error) => {
                                let _ = receive_tx.send(Err(error));
                                break;
                            }
                        }
                    }
                    else => break,
                }
            }
        });
        Self {
            sends: send_tx,
            receives: Mutex::new(receive_rx),
        }
    }
}

impl DatagramSocket for DatagramBridge {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }
}

impl DatagramSend for DatagramBridge {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.sends.send(buffer.to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Shadowsocks UDP transport closed",
            )
        })?;
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buffer: &[u8],
        _target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.poll_send(cx, buffer)
    }

    fn poll_send_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl DatagramReceive for DatagramBridge {
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut receives = self.receives.lock().map_err(|_| {
            io::Error::other("Shadowsocks UDP receive lock poisoned")
        })?;
        match receives.poll_recv(cx) {
            Poll::Ready(Some(Ok(packet))) => {
                if packet.len() > buffer.remaining() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Shadowsocks UDP packet exceeds receive buffer",
                    )));
                }
                buffer.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Shadowsocks UDP transport closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        match self.poll_recv(cx, buffer) {
            Poll::Ready(Ok(())) => {
                Poll::Ready(Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_recv_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use shadowsocks::crypto::CipherKind;

    use super::{from_address, parse_method, server_config, to_address};
    use crate::common::network::SocksAddr;

    #[test]
    fn converts_addresses_without_dns_resolution() {
        for address in [
            SocksAddr::new("127.0.0.1", 53),
            SocksAddr::new("example.com", 443),
        ] {
            assert_eq!(from_address(to_address(&address)), address);
        }
    }

    #[test]
    fn accepts_upstream_cipher_set_and_derives_keys() {
        for method in [
            "none",
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "xchacha20-ietf-poly1305",
        ] {
            let kind = parse_method(method).unwrap();
            server_config(&SocksAddr::new("127.0.0.1", 8388), "secret", kind)
                .unwrap();
        }
        assert!(parse_method("rc4-md5").is_err());
        assert!(parse_method("aes-192-gcm").is_err());
        assert_eq!(parse_method("plain").unwrap(), CipherKind::NONE);
    }
}
