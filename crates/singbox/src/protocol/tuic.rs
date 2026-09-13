//! TUIC v5 wire protocol and reusable Quinn client/server sessions.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use n0_watcher::Watcher as _;
use quinn::{
    AsyncUdpSocket, Connection, Endpoint, EndpointConfig, RecvStream,
    SendStream, TokioRuntime,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::Mutex,
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::{
        network::SocksAddr,
        quic::PacketUdpSocket,
        tls::{ClientTlsConfig, ServerTlsConfig},
    },
};

pub const VERSION: u8 = 5;
pub const COMMAND_AUTHENTICATE: u8 = 0;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_PACKET: u8 = 2;
pub const COMMAND_DISSOCIATE: u8 = 3;
pub const COMMAND_HEARTBEAT: u8 = 4;
pub const AUTHENTICATE_LENGTH: usize = 2 + 16 + 32;
pub const DEFAULT_ALPN: &str = "h3";
pub const MAX_UDP_SIZE: usize = u16::MAX as usize;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn encode_address(address: Option<&SocksAddr>) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    match address {
        None => output.push(0xff),
        Some(SocksAddr::Domain { host, port }) => {
            let length = u8::try_from(host.len())
                .map_err(|_| invalid("TUIC domain exceeds u8"))?;
            output.push(0x00);
            output.push(length);
            output.extend_from_slice(host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
        Some(SocksAddr::Ip(address)) if address.is_ipv4() => {
            output.push(0x01);
            let IpAddr::V4(ip) = address.ip() else {
                unreachable!()
            };
            output.extend_from_slice(&ip.octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
        Some(SocksAddr::Ip(address)) => {
            output.push(0x02);
            let IpAddr::V6(ip) = address.ip() else {
                unreachable!()
            };
            output.extend_from_slice(&ip.octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    Ok(output)
}

pub fn decode_address(input: &[u8]) -> io::Result<(Option<SocksAddr>, usize)> {
    let family = *input
        .first()
        .ok_or_else(|| invalid("missing TUIC address"))?;
    match family {
        0xff => Ok((None, 1)),
        0x00 => {
            let length = usize::from(
                *input
                    .get(1)
                    .ok_or_else(|| invalid("missing TUIC domain length"))?,
            );
            let host = input
                .get(2..2 + length)
                .ok_or_else(|| invalid("truncated TUIC domain"))?;
            let port = input
                .get(2 + length..4 + length)
                .ok_or_else(|| invalid("missing TUIC domain port"))?;
            let host = String::from_utf8(host.to_vec())
                .map_err(|_| invalid("TUIC domain is not UTF-8"))?;
            Ok((
                Some(SocksAddr::new(
                    host,
                    u16::from_be_bytes(port.try_into().unwrap()),
                )),
                4 + length,
            ))
        }
        0x01 => {
            let address = input
                .get(1..5)
                .ok_or_else(|| invalid("truncated TUIC IPv4 address"))?;
            let port = input
                .get(5..7)
                .ok_or_else(|| invalid("missing TUIC IPv4 port"))?;
            Ok((
                Some(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(address).unwrap(),
                        )),
                        u16::from_be_bytes(port.try_into().unwrap()),
                    )
                    .into(),
                ),
                7,
            ))
        }
        0x02 => {
            let address = input
                .get(1..17)
                .ok_or_else(|| invalid("truncated TUIC IPv6 address"))?;
            let port = input
                .get(17..19)
                .ok_or_else(|| invalid("missing TUIC IPv6 port"))?;
            Ok((
                Some(
                    SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(address).unwrap(),
                        )),
                        u16::from_be_bytes(port.try_into().unwrap()),
                    )
                    .into(),
                ),
                19,
            ))
        }
        value => {
            Err(invalid(format!("unknown TUIC address family {value:#x}")))
        }
    }
}

pub fn encode_authenticate(
    uuid: Uuid,
    connection: &Connection,
    password: &str,
) -> io::Result<[u8; AUTHENTICATE_LENGTH]> {
    let mut token = [0_u8; 32];
    connection
        .export_keying_material(
            &mut token,
            uuid.as_bytes(),
            password.as_bytes(),
        )
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let mut output = [0_u8; AUTHENTICATE_LENGTH];
    output[0] = VERSION;
    output[1] = COMMAND_AUTHENTICATE;
    output[2..18].copy_from_slice(uuid.as_bytes());
    output[18..].copy_from_slice(&token);
    Ok(output)
}

pub fn encode_connect(destination: &SocksAddr) -> io::Result<Vec<u8>> {
    let mut output = vec![VERSION, COMMAND_CONNECT];
    output.extend_from_slice(&encode_address(Some(destination))?);
    Ok(output)
}

pub fn decode_connect(input: &[u8]) -> io::Result<(SocksAddr, usize)> {
    if input.get(..2) != Some(&[VERSION, COMMAND_CONNECT]) {
        return Err(invalid("invalid TUIC connect command"));
    }
    let (destination, consumed) = decode_address(&input[2..])?;
    Ok((
        destination.ok_or_else(|| invalid("empty TUIC connect destination"))?,
        consumed + 2,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub destination: Option<SocksAddr>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerUdpEvent {
    Packet(UdpMessage, bool),
    Dissociate(u16),
    Heartbeat,
}

impl UdpMessage {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let data_length = u16::try_from(self.data.len())
            .map_err(|_| invalid("TUIC UDP payload exceeds u16"))?;
        let mut output = Vec::with_capacity(32 + self.data.len());
        output.extend_from_slice(&[VERSION, COMMAND_PACKET]);
        output.extend_from_slice(&self.session_id.to_be_bytes());
        output.extend_from_slice(&self.packet_id.to_be_bytes());
        output.push(self.fragment_total);
        output.push(self.fragment_id);
        output.extend_from_slice(&data_length.to_be_bytes());
        output.extend_from_slice(&encode_address(self.destination.as_ref())?);
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<Self> {
        if input.get(..2) != Some(&[VERSION, COMMAND_PACKET]) {
            return Err(invalid("invalid TUIC UDP command"));
        }
        let fixed = input
            .get(2..10)
            .ok_or_else(|| invalid("truncated TUIC UDP header"))?;
        let session_id = u16::from_be_bytes(fixed[0..2].try_into().unwrap());
        let packet_id = u16::from_be_bytes(fixed[2..4].try_into().unwrap());
        let fragment_total = fixed[4];
        let fragment_id = fixed[5];
        let data_length =
            usize::from(u16::from_be_bytes(fixed[6..8].try_into().unwrap()));
        let (destination, address_length) = decode_address(&input[10..])?;
        let data = input
            .get(10 + address_length..)
            .ok_or_else(|| invalid("truncated TUIC UDP payload"))?;
        if data.len() != data_length {
            return Err(invalid("TUIC UDP payload length mismatch"));
        }
        if fragment_total == 0 || fragment_id >= fragment_total {
            return Err(invalid("invalid TUIC UDP fragment index"));
        }
        Ok(Self {
            session_id,
            packet_id,
            fragment_total,
            fragment_id,
            destination,
            data: data.to_vec(),
        })
    }
}

pub fn fragment_udp_message(
    message: UdpMessage,
    max_packet_size: usize,
) -> io::Result<Vec<UdpMessage>> {
    let header_size = 10 + encode_address(message.destination.as_ref())?.len();
    let payload_size = max_packet_size
        .checked_sub(header_size)
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("TUIC datagram MTU is too small"))?;
    if message.data.len() <= payload_size {
        return Ok(vec![message]);
    }
    let count = message.data.len().div_ceil(payload_size);
    let count = u8::try_from(count)
        .map_err(|_| invalid("TUIC UDP fragment count exceeds u8"))?;
    let mut fragments = Vec::with_capacity(usize::from(count));
    for (index, data) in message.data.chunks(payload_size).enumerate() {
        fragments.push(UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            fragment_total: count,
            fragment_id: u8::try_from(index).unwrap(),
            destination: (index == 0)
                .then(|| message.destination.clone())
                .flatten(),
            data: data.to_vec(),
        });
    }
    Ok(fragments)
}

struct FragmentSet {
    updated: Instant,
    fragments: Vec<Option<UdpMessage>>,
}

#[derive(Default)]
pub struct UdpDefragmenter {
    packets: HashMap<u16, FragmentSet>,
}

impl UdpDefragmenter {
    pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
        if message.fragment_total <= 1 {
            return Some(message);
        }
        self.evict();
        let total = usize::from(message.fragment_total);
        let packet_id = message.packet_id;
        let fragment_id = usize::from(message.fragment_id);
        let entry =
            self.packets
                .entry(packet_id)
                .or_insert_with(|| FragmentSet {
                    updated: Instant::now(),
                    fragments: (0..total).map(|_| None).collect(),
                });
        if entry.fragments.len() != total {
            entry.fragments = (0..total).map(|_| None).collect();
        }
        entry.updated = Instant::now();
        if entry.fragments[fragment_id].is_none() {
            entry.fragments[fragment_id] = Some(message);
        }
        if entry.fragments.iter().any(Option::is_none) {
            return None;
        }
        let mut fragments = self.packets.remove(&packet_id)?.fragments;
        let first = fragments.first_mut()?.take()?;
        let destination = first.destination.clone()?;
        let capacity = fragments
            .iter()
            .filter_map(Option::as_ref)
            .fold(first.data.len(), |size, item| size + item.data.len());
        let mut data = Vec::with_capacity(capacity);
        data.extend_from_slice(&first.data);
        for fragment in fragments.into_iter().skip(1).flatten() {
            data.extend_from_slice(&fragment.data);
        }
        Some(UdpMessage {
            destination: Some(destination),
            data,
            fragment_total: 1,
            fragment_id: 0,
            ..first
        })
    }

    fn evict(&mut self) {
        let now = Instant::now();
        self.packets.retain(|_, item| {
            now.duration_since(item.updated) < Duration::from_secs(10)
        });
        while self.packets.len() >= 10 {
            let Some(oldest) = self
                .packets
                .iter()
                .min_by_key(|(_, item)| item.updated)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.packets.remove(&oldest);
        }
    }
}

pub struct TuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(context)
    }
}

pub fn server_endpoint(
    address: SocketAddr,
    tls: ServerTlsConfig,
    transport: Arc<quinn::TransportConfig>,
) -> io::Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls.config)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport);
    Endpoint::server(config, address)
}

pub struct ClientSession {
    endpoint: Endpoint,
    connection: Connection,
    channels: Arc<Mutex<HashMap<u16, tokio::sync::mpsc::Sender<UdpMessage>>>>,
    next_session_id: AtomicU32,
    udp_stream: bool,
    zero_rtt_accepted: bool,
    driver: JoinHandle<()>,
    heartbeat: JoinHandle<()>,
    network_driver: Option<JoinHandle<()>>,
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        remote: SocketAddr,
        server_name: &str,
        uuid: Uuid,
        password: &str,
        tls: ClientTlsConfig,
        transport: Arc<quinn::TransportConfig>,
        udp_stream: bool,
        heartbeat: Duration,
    ) -> io::Result<Self> {
        Self::connect_with_socket(
            remote,
            server_name,
            uuid,
            password,
            tls,
            transport,
            udp_stream,
            heartbeat,
            None,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_socket(
        remote: SocketAddr,
        server_name: &str,
        uuid: Uuid,
        password: &str,
        tls: ClientTlsConfig,
        transport: Arc<quinn::TransportConfig>,
        udp_stream: bool,
        heartbeat: Duration,
        socket: Option<Arc<dyn AsyncUdpSocket>>,
        zero_rtt: bool,
    ) -> io::Result<Self> {
        let mut tls_config =
            tls.config_for_handshake().await.map_err(io::Error::other)?;
        if zero_rtt {
            Arc::make_mut(&mut tls_config).enable_early_data = true;
        }
        let crypto = QuicClientConfig::try_from(tls_config)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport);
        let bind = if remote.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let mut endpoint = if let Some(socket) = socket {
            Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                socket,
                Arc::new(TokioRuntime),
            )?
        } else {
            Endpoint::client(bind)?
        };
        endpoint.set_default_client_config(config);
        let connecting = endpoint
            .connect(remote, server_name)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (connection, early_accepted) = if zero_rtt {
            match connecting.into_0rtt() {
                Ok((connection, accepted)) => (connection, Some(accepted)),
                Err(connecting) => (
                    connecting
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?,
                    None,
                ),
            }
        } else {
            (
                connecting
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?,
                None,
            )
        };
        let zero_rtt_accepted = if let Some(accepted) = early_accepted {
            accepted.await
        } else {
            false
        };
        // TUIC authentication is bound to TLS exporter material, which rustls
        // exposes only after the resumed handshake is accepted. Application
        // streams still benefit from the resumed QUIC connection immediately
        // after this authentication frame is sent.
        send_authentication(&connection, uuid, password).await?;

        let channels = Arc::new(Mutex::new(HashMap::<
            u16,
            tokio::sync::mpsc::Sender<UdpMessage>,
        >::new()));
        let driver_connection = connection.clone();
        let driver_channels = channels.clone();
        let driver = tokio::spawn(async move {
            loop {
                let data = tokio::select! {
                    result = driver_connection.read_datagram() => match result {
                        Ok(data) => data.to_vec(),
                        Err(_) => break,
                    },
                    result = driver_connection.accept_uni() => match result {
                        Ok(mut stream) => match stream.read_to_end(MAX_UDP_SIZE + 300).await {
                            Ok(data) => data,
                            Err(_) => continue,
                        },
                        Err(_) => break,
                    },
                };
                if data == [VERSION, COMMAND_HEARTBEAT] {
                    continue;
                }
                let Ok(message) = UdpMessage::decode(&data) else {
                    continue;
                };
                let sender = driver_channels
                    .lock()
                    .await
                    .get(&message.session_id)
                    .cloned();
                if let Some(sender) = sender {
                    let _ = sender.send(message).await;
                }
            }
        });
        let heartbeat_connection = connection.clone();
        let heartbeat = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(if heartbeat.is_zero() {
                Duration::from_secs(10)
            } else {
                heartbeat
            });
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if heartbeat_connection
                    .send_datagram(bytes::Bytes::from_static(&[
                        VERSION,
                        COMMAND_HEARTBEAT,
                    ]))
                    .is_err()
                {
                    break;
                }
            }
        });
        let network_driver =
            crate::common::network_monitor::NetworkMonitor::new()
                .await
                .ok()
                .map(|monitor| {
                    let connection = connection.clone();
                    tokio::spawn(async move {
                        let mut watcher = monitor.interface_state();
                        let mut previous = watcher.get();
                        while let Ok(current) = watcher.updated().await {
                            let changed = current.is_major_change(&previous);
                            previous = current;
                            if changed {
                                connection
                                    .close(0_u32.into(), b"network changed");
                                break;
                            }
                        }
                    })
                });
        Ok(Self {
            endpoint,
            connection,
            channels,
            next_session_id: AtomicU32::new(0),
            udp_stream,
            zero_rtt_accepted,
            driver,
            heartbeat,
            network_driver,
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn zero_rtt_accepted(&self) -> bool {
        self.zero_rtt_accepted
    }

    pub async fn open_tcp(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<TuicStream> {
        let (mut send, recv) =
            self.connection.open_bi().await.map_err(io::Error::other)?;
        send.write_all(&encode_connect(destination)?)
            .await
            .map_err(io::Error::other)?;
        Ok(TuicStream { send, recv })
    }

    pub async fn open_udp(&self) -> io::Result<TuicPacketConnection> {
        let session_id =
            self.next_session_id.fetch_add(1, Ordering::Relaxed) as u16;
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        self.channels.lock().await.insert(session_id, sender);
        Ok(TuicPacketConnection {
            connection: self.connection.clone(),
            session_id,
            packet_id: AtomicU32::new(0),
            udp_stream: self.udp_stream,
            receiver: Mutex::new(receiver),
            defragmenter: Mutex::new(UdpDefragmenter::default()),
            channels: self.channels.clone(),
        })
    }
}

async fn send_authentication(
    connection: &Connection,
    uuid: Uuid,
    password: &str,
) -> io::Result<()> {
    let mut auth = connection.open_uni().await.map_err(io::Error::other)?;
    auth.write_all(&encode_authenticate(uuid, connection, password)?)
        .await
        .map_err(io::Error::other)?;
    auth.finish().map_err(io::Error::other)
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.driver.abort();
        self.heartbeat.abort();
        if let Some(driver) = self.network_driver.take() {
            driver.abort();
        }
        self.connection.close(0_u32.into(), b"");
        self.endpoint.close(0_u32.into(), b"");
    }
}

pub struct TuicPacketConnection {
    connection: Connection,
    session_id: u16,
    packet_id: AtomicU32,
    udp_stream: bool,
    receiver: Mutex<tokio::sync::mpsc::Receiver<UdpMessage>>,
    defragmenter: Mutex<UdpDefragmenter>,
    channels: Arc<Mutex<HashMap<u16, tokio::sync::mpsc::Sender<UdpMessage>>>>,
}

impl TuicPacketConnection {
    async fn send_message(&self, message: UdpMessage) -> io::Result<()> {
        if self.udp_stream {
            let mut stream =
                self.connection.open_uni().await.map_err(io::Error::other)?;
            stream
                .write_all(&message.encode()?)
                .await
                .map_err(io::Error::other)?;
            stream.finish().map_err(io::Error::other)?;
        } else {
            let mtu = self.connection.max_datagram_size().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "QUIC datagrams unavailable",
                )
            })?;
            for fragment in fragment_udp_message(message, mtu)? {
                self.connection
                    .send_datagram(bytes::Bytes::from(fragment.encode()?))
                    .map_err(io::Error::other)?;
            }
        }
        Ok(())
    }
}

impl PacketConnection for TuicPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            if data.len() > MAX_UDP_SIZE {
                return Err(invalid("TUIC UDP payload exceeds u16"));
            }
            let counter = self
                .packet_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            let packet_id = (counter % u32::from(u16::MAX)) as u16;
            self.send_message(UdpMessage {
                session_id: self.session_id,
                packet_id,
                fragment_total: 1,
                fragment_id: 0,
                destination: Some(destination.clone()),
                data: data.to_vec(),
            })
            .await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            loop {
                let message =
                    self.receiver.lock().await.recv().await.ok_or_else(
                        || {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "TUIC UDP session closed",
                            )
                        },
                    )?;
                let Some(message) =
                    self.defragmenter.lock().await.feed(message)
                else {
                    continue;
                };
                if message.data.len() > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "receive buffer is too small",
                    ));
                }
                data[..message.data.len()].copy_from_slice(&message.data);
                return Ok((
                    message.data.len(),
                    message.destination.ok_or_else(|| {
                        invalid("missing TUIC UDP destination")
                    })?,
                ));
            }
        })
    }
}

impl Drop for TuicPacketConnection {
    fn drop(&mut self) {
        if let Ok(mut channels) = self.channels.try_lock() {
            channels.remove(&self.session_id);
        }
        let connection = self.connection.clone();
        let session_id = self.session_id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let Ok(mut stream) = connection.open_uni().await else {
                    return;
                };
                let _ = stream
                    .write_all(&[
                        VERSION,
                        COMMAND_DISSOCIATE,
                        (session_id >> 8) as u8,
                        session_id as u8,
                    ])
                    .await;
                let _ = stream.finish();
            });
        }
    }
}

pub struct ServerSession {
    connection: Connection,
    pub user: String,
}

impl ServerSession {
    pub async fn authenticate(
        connection: Connection,
        users: &HashMap<Uuid, (String, String)>,
        auth_timeout: Duration,
    ) -> io::Result<Self> {
        let mut stream = tokio::time::timeout(
            if auth_timeout.is_zero() {
                Duration::from_secs(3)
            } else {
                auth_timeout
            },
            connection.accept_uni(),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "TUIC authentication timed out",
            )
        })?
        .map_err(io::Error::other)?;
        let request = stream
            .read_to_end(AUTHENTICATE_LENGTH)
            .await
            .map_err(io::Error::other)?;
        if request.len() != AUTHENTICATE_LENGTH
            || request[..2] != [VERSION, COMMAND_AUTHENTICATE]
        {
            return Err(invalid("invalid TUIC authentication command"));
        }
        let uuid = Uuid::from_slice(&request[2..18])
            .map_err(|_| invalid("invalid TUIC authentication UUID"))?;
        let (user, password) = users.get(&uuid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "unknown TUIC user")
        })?;
        let expected = encode_authenticate(uuid, &connection, password)?;
        let different = expected[18..]
            .iter()
            .zip(&request[18..])
            .fold(0_u8, |value, (left, right)| value | (left ^ right));
        if different != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TUIC authentication token mismatch",
            ));
        }
        Ok(Self {
            connection,
            user: user.clone(),
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn accept_tcp(&self) -> io::Result<(TuicStream, SocksAddr)> {
        let (send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(io::Error::other)?;
        let mut command = [0_u8; 2];
        recv.read_exact(&mut command)
            .await
            .map_err(io::Error::other)?;
        if command != [VERSION, COMMAND_CONNECT] {
            return Err(invalid("invalid TUIC connect command"));
        }
        let destination = read_address(&mut recv)
            .await?
            .ok_or_else(|| invalid("empty TUIC connect destination"))?;
        Ok((TuicStream { send, recv }, destination))
    }

    pub async fn read_udp(&self) -> io::Result<ServerUdpEvent> {
        let data = tokio::select! {
            result = self.connection.read_datagram() => {
                let data = result.map_err(io::Error::other)?;
                (data.to_vec(), false)
            }
            result = self.connection.accept_uni() => {
                let mut stream = result.map_err(io::Error::other)?;
                let data = stream.read_to_end(MAX_UDP_SIZE + 300).await.map_err(io::Error::other)?;
                (data, true)
            }
        };
        if data.0 == [VERSION, COMMAND_HEARTBEAT] {
            return Ok(ServerUdpEvent::Heartbeat);
        }
        if data.0.len() == 4 && data.0[..2] == [VERSION, COMMAND_DISSOCIATE] {
            return Ok(ServerUdpEvent::Dissociate(u16::from_be_bytes([
                data.0[2], data.0[3],
            ])));
        }
        Ok(ServerUdpEvent::Packet(UdpMessage::decode(&data.0)?, data.1))
    }

    pub fn send_heartbeat(&self) -> io::Result<()> {
        self.connection
            .send_datagram(bytes::Bytes::from_static(&[
                VERSION,
                COMMAND_HEARTBEAT,
            ]))
            .map_err(io::Error::other)
    }

    pub async fn send_udp(
        &self,
        message: UdpMessage,
        stream_mode: bool,
    ) -> io::Result<()> {
        if stream_mode {
            let mut stream =
                self.connection.open_uni().await.map_err(io::Error::other)?;
            stream
                .write_all(&message.encode()?)
                .await
                .map_err(io::Error::other)?;
            stream.finish().map_err(io::Error::other)?;
            return Ok(());
        }
        let mtu = self.connection.max_datagram_size().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "QUIC datagrams unavailable",
            )
        })?;
        for fragment in fragment_udp_message(message, mtu)? {
            self.connection
                .send_datagram(bytes::Bytes::from(fragment.encode()?))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

async fn read_address(
    reader: &mut RecvStream,
) -> io::Result<Option<SocksAddr>> {
    let family = reader.read_u8().await.map_err(io::Error::other)?;
    match family {
        0xff => Ok(None),
        0x00 => {
            let length =
                usize::from(reader.read_u8().await.map_err(io::Error::other)?);
            let mut host = vec![0_u8; length];
            reader
                .read_exact(&mut host)
                .await
                .map_err(io::Error::other)?;
            let port = reader.read_u16().await.map_err(io::Error::other)?;
            Ok(Some(SocksAddr::new(
                String::from_utf8(host)
                    .map_err(|_| invalid("TUIC domain is not UTF-8"))?,
                port,
            )))
        }
        0x01 => {
            let mut address = [0_u8; 4];
            reader
                .read_exact(&mut address)
                .await
                .map_err(io::Error::other)?;
            let port = reader.read_u16().await.map_err(io::Error::other)?;
            Ok(Some(
                SocketAddr::new(Ipv4Addr::from(address).into(), port).into(),
            ))
        }
        0x02 => {
            let mut address = [0_u8; 16];
            reader
                .read_exact(&mut address)
                .await
                .map_err(io::Error::other)?;
            let port = reader.read_u16().await.map_err(io::Error::other)?;
            Ok(Some(
                SocketAddr::new(Ipv6Addr::from(address).into(), port).into(),
            ))
        }
        value => {
            Err(invalid(format!("unknown TUIC address family {value:#x}")))
        }
    }
}

pub struct TuicOutbound {
    server: SocksAddr,
    server_name: String,
    uuid: Uuid,
    password: String,
    tls: ClientTlsConfig,
    transport: Arc<quinn::TransportConfig>,
    udp_stream: bool,
    heartbeat: Duration,
    zero_rtt: bool,
    packet_dialer: Option<Arc<dyn Dialer>>,
    state: Mutex<Option<ClientSession>>,
}

impl TuicOutbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: SocksAddr,
        server_name: impl Into<String>,
        uuid: Uuid,
        password: impl Into<String>,
        tls: ClientTlsConfig,
        transport: Arc<quinn::TransportConfig>,
        udp_stream: bool,
        heartbeat: Duration,
    ) -> Self {
        Self {
            server,
            server_name: server_name.into(),
            uuid,
            password: password.into(),
            tls,
            transport,
            udp_stream,
            heartbeat,
            zero_rtt: false,
            packet_dialer: None,
            state: Mutex::new(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_packet_dialer(
        server: SocksAddr,
        server_name: impl Into<String>,
        uuid: Uuid,
        password: impl Into<String>,
        tls: ClientTlsConfig,
        transport: Arc<quinn::TransportConfig>,
        udp_stream: bool,
        heartbeat: Duration,
        packet_dialer: Arc<dyn Dialer>,
        zero_rtt: bool,
    ) -> Self {
        Self {
            server,
            server_name: server_name.into(),
            uuid,
            password: password.into(),
            tls,
            transport,
            udp_stream,
            heartbeat,
            zero_rtt,
            packet_dialer: Some(packet_dialer),
            state: Mutex::new(None),
        }
    }

    async fn ensure_session<'a>(
        &self,
        state: &'a mut Option<ClientSession>,
    ) -> io::Result<&'a ClientSession> {
        let active = state.as_ref().is_some_and(|session| {
            session.connection().close_reason().is_none()
        });
        if !active {
            let (socket, remote) = if let Some(dialer) = &self.packet_dialer {
                let (socket, remote) =
                    PacketUdpSocket::connect(dialer.clone(), &self.server)
                        .await?;
                (Some(socket), remote)
            } else {
                let remote = self
                    .server
                    .resolve()
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "TUIC server resolved to no addresses",
                        )
                    })?;
                (None, remote)
            };
            let tls = self.tls.clone();
            *state = Some(
                ClientSession::connect_with_socket(
                    remote,
                    &self.server_name,
                    self.uuid,
                    &self.password,
                    tls,
                    self.transport.clone(),
                    self.udp_stream,
                    self.heartbeat,
                    socket,
                    self.zero_rtt,
                )
                .await?,
            );
        }
        Ok(state.as_ref().expect("TUIC session initialized"))
    }

    /// Close the cached QUIC session so that the next operation performs a
    /// fresh handshake. Network-interface changes trigger the same behavior
    /// through the session monitor.
    pub async fn reset(&self) {
        self.state.lock().await.take();
    }
}

impl Dialer for TuicOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let stream = self
                .ensure_session(&mut state)
                .await?
                .open_tcp(destination)
                .await?;
            Ok(Box::new(stream) as Stream)
        })
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let connection =
                self.ensure_session(&mut state).await?.open_udp().await?;
            Ok(Box::new(connection) as PacketStream)
        })
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::{
        common::tls::{
            build_client_config, build_server_config_with_default_alpn,
        },
        option::{InboundTlsOptions, OutboundTlsOptions},
    };

    #[test]
    fn connect_and_udp_frames_match_tuic_v5_layout() {
        let domain = SocksAddr::new("example.com", 443);
        assert_eq!(
            hex::encode(encode_connect(&domain).unwrap()),
            "0501000b6578616d706c652e636f6d01bb"
        );
        assert_eq!(
            decode_connect(&encode_connect(&domain).unwrap()).unwrap().0,
            domain
        );
        let ipv4 = SocksAddr::new("1.2.3.4", 53);
        assert_eq!(
            hex::encode(encode_address(Some(&ipv4)).unwrap()),
            "01010203040035"
        );
        let message = UdpMessage {
            session_id: 1,
            packet_id: 2,
            fragment_total: 1,
            fragment_id: 0,
            destination: Some(domain.clone()),
            data: b"ping".to_vec(),
        };
        assert_eq!(
            hex::encode(message.encode().unwrap()),
            "05020001000201000004000b6578616d706c652e636f6d01bb70696e67"
        );
        assert_eq!(
            UdpMessage::decode(&message.encode().unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn udp_fragmentation_restores_destination_out_of_order() {
        let message = UdpMessage {
            session_id: 7,
            packet_id: 9,
            fragment_total: 1,
            fragment_id: 0,
            destination: Some(SocksAddr::new("1.2.3.4", 53)),
            data: (0..100).collect(),
        };
        let fragments = fragment_udp_message(message.clone(), 40).unwrap();
        assert!(fragments.len() > 1);
        assert!(fragments[0].destination.is_some());
        assert!(fragments[1].destination.is_none());
        let mut defrag = UdpDefragmenter::default();
        let mut restored = None;
        for fragment in fragments.into_iter().rev() {
            restored = defrag.feed(fragment).or(restored);
        }
        let restored = restored.unwrap();
        assert_eq!(restored.destination, message.destination);
        assert_eq!(restored.data, message.data);
    }

    async fn exercise_quic_session(udp_stream: bool) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled":true,
            "certificate":cert.pem(),
            "key":key_pair.serialize_pem()
        }))
        .unwrap();
        let server_tls = build_server_config_with_default_alpn(
            &server_options,
            &[DEFAULT_ALPN],
        )
        .unwrap();
        let endpoint = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_tls,
            Arc::new(quinn::TransportConfig::default()),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let user_uuid =
            Uuid::parse_str("059032a9-7d40-4a96-9bb1-36823d848068").unwrap();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let users = HashMap::from([(
                user_uuid,
                ("alice".to_owned(), "secret".to_owned()),
            )]);
            let session = ServerSession::authenticate(
                connection,
                &users,
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            assert_eq!(session.user, "alice");

            let (mut stream, destination) = session.accept_tcp().await.unwrap();
            assert_eq!(destination, SocksAddr::new("example.com", 443));
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();

            let mut defragmenter = UdpDefragmenter::default();
            let (message, received_as_stream) = loop {
                if let ServerUdpEvent::Packet(message, received_as_stream) =
                    session.read_udp().await.unwrap()
                    && let Some(message) = defragmenter.feed(message)
                {
                    break (message, received_as_stream);
                }
            };
            assert_eq!(received_as_stream, udp_stream);
            assert_eq!(message.data.len(), 3000);
            let session_id = message.session_id;
            session.send_udp(message, received_as_stream).await.unwrap();
            assert_eq!(
                session.read_udp().await.unwrap(),
                ServerUdpEvent::Dissociate(session_id)
            );
        });

        let client_tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[DEFAULT_ALPN],
        )
        .unwrap();
        let client = ClientSession::connect(
            address,
            "localhost",
            user_uuid,
            "secret",
            client_tls,
            Arc::new(quinn::TransportConfig::default()),
            udp_stream,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        let mut stream = client
            .open_tcp(&SocksAddr::new("example.com", 443))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        let udp = client.open_udp().await.unwrap();
        let destination = SocksAddr::new("1.2.3.4", 53);
        let packet: Vec<u8> =
            (0..3000).map(|index| (index % 251) as u8).collect();
        udp.send_to(&packet, &destination).await.unwrap();
        let mut response = [0_u8; 4096];
        let (size, source) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], packet);
        assert_eq!(source, destination);
        drop(udp);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_quic_tcp_and_native_udp_interoperate() {
        exercise_quic_session(false).await;
    }

    #[tokio::test]
    async fn authenticated_quic_tcp_and_stream_udp_interoperate() {
        exercise_quic_session(true).await;
    }

    #[tokio::test]
    async fn zero_rtt_resumption_authenticates_and_opens_a_stream() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_options: InboundTlsOptions = serde_json::from_value(json!({
            "enabled":true,
            "certificate":cert.pem(),
            "key":key_pair.serialize_pem()
        }))
        .unwrap();
        let mut server_tls = build_server_config_with_default_alpn(
            &server_options,
            &[DEFAULT_ALPN],
        )
        .unwrap();
        Arc::make_mut(&mut server_tls.config).max_early_data_size = u32::MAX;
        let endpoint = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_tls,
            Arc::new(quinn::TransportConfig::default()),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let user_uuid =
            Uuid::parse_str("059032a9-7d40-4a96-9bb1-36823d848068").unwrap();
        let server = tokio::spawn(async move {
            for expected in [b"one", b"two"] {
                let connection =
                    endpoint.accept().await.unwrap().await.unwrap();
                let users = HashMap::from([(
                    user_uuid,
                    ("alice".to_owned(), "secret".to_owned()),
                )]);
                let session = ServerSession::authenticate(
                    connection,
                    &users,
                    Duration::from_secs(3),
                )
                .await
                .unwrap();
                let (mut stream, _) = session.accept_tcp().await.unwrap();
                let mut payload = [0_u8; 3];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, expected);
                stream.write_all(&payload).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let client_tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[DEFAULT_ALPN],
        )
        .unwrap();
        let tls_config = client_tls.config.clone();
        let tls_server_name = client_tls.server_name.clone();
        let tls_handshake_timeout = client_tls.handshake_timeout;
        let first = ClientSession::connect_with_socket(
            address,
            "localhost",
            user_uuid,
            "secret",
            client_tls,
            Arc::new(quinn::TransportConfig::default()),
            false,
            Duration::from_secs(10),
            None,
            true,
        )
        .await
        .unwrap();
        assert!(!first.zero_rtt_accepted());
        let mut stream = first
            .open_tcp(&SocksAddr::new("example.com", 443))
            .await
            .unwrap();
        stream.write_all(b"one").await.unwrap();
        let mut response = [0_u8; 3];
        stream.read_exact(&mut response).await.unwrap();
        drop(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(first);

        let second = ClientSession::connect_with_socket(
            address,
            "localhost",
            user_uuid,
            "secret",
            ClientTlsConfig {
                config: tls_config,
                server_name: tls_server_name,
                handshake_timeout: tls_handshake_timeout,
                fragment: false,
                record_fragment: false,
                fragment_fallback_delay: Duration::from_millis(500),
                spoof: String::new(),
                spoof_method: crate::common::tls_spoof::TlsSpoofMethod::default(
                ),
                dynamic_ech: None,
                ech_retry: None,
                backend: crate::common::tls::ClientTlsBackend::Rustls,
                kernel_tx: false,
                kernel_rx: false,
            },
            Arc::new(quinn::TransportConfig::default()),
            false,
            Duration::from_secs(10),
            None,
            true,
        )
        .await
        .unwrap();
        assert!(second.zero_rtt_accepted());
        let mut stream = second
            .open_tcp(&SocksAddr::new("example.com", 443))
            .await
            .unwrap();
        stream.write_all(b"two").await.unwrap();
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"two");
        server.await.unwrap();
    }
}
