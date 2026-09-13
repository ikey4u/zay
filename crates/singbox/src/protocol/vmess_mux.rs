//! VMess `CommandMux` server framing shared by VMess and VLESS XUDP.

use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, duplex},
    sync::{Mutex, mpsc},
    task::JoinSet,
};

use crate::{
    adapter::{PacketConnection, PacketFuture, PacketStream, Stream},
    common::network::SocksAddr,
    inbound::{proxy_routed_tcp, socks::proxy_packet_connection},
    outbound::OutboundManager,
    protocol::vless::{
        decode_xudp_address, encode_xudp_address, socks_address_length,
    },
    route::Router,
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_TCP: u8 = 1;
const NETWORK_UDP: u8 = 2;

struct Frame {
    session_id: u16,
    status: u8,
    option: u8,
    network: Option<u8>,
    destination: Option<SocksAddr>,
    data: Vec<u8>,
}

enum SessionSink {
    Tcp(WriteHalf<tokio::io::DuplexStream>),
    Udp(mpsc::Sender<MuxPacket>),
}

struct Session {
    serial: u64,
    destination: SocksAddr,
    sink: SessionSink,
}

struct MuxPacket {
    data: Vec<u8>,
    destination: SocksAddr,
}

struct MuxWriter {
    stream: WriteHalf<Stream>,
    response_prefix: Option<Vec<u8>>,
}

impl MuxWriter {
    async fn prefix(&mut self) -> io::Result<()> {
        if let Some(prefix) = self.response_prefix.take() {
            self.stream.write_all(&prefix).await?;
        }
        Ok(())
    }

    async fn write_tcp(
        &mut self,
        session_id: u16,
        data: &[u8],
    ) -> io::Result<()> {
        let length = u16::try_from(data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess mux TCP frame is too large",
            )
        })?;
        self.prefix().await?;
        self.stream.write_u16(4).await?;
        self.stream.write_u16(session_id).await?;
        self.stream.write_u8(STATUS_KEEP).await?;
        self.stream.write_u8(OPTION_DATA).await?;
        self.stream.write_u16(length).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await
    }

    async fn write_udp(
        &mut self,
        session_id: u16,
        destination: &SocksAddr,
        data: &[u8],
    ) -> io::Result<()> {
        let address = encode_xudp_address(destination)?;
        let header_length = u16::try_from(5 + address.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess mux UDP header is too large",
            )
        })?;
        let data_length = u16::try_from(data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess mux UDP frame is too large",
            )
        })?;
        self.prefix().await?;
        self.stream.write_u16(header_length).await?;
        self.stream.write_u16(session_id).await?;
        self.stream.write_u8(STATUS_KEEP).await?;
        self.stream.write_u8(OPTION_DATA).await?;
        self.stream.write_u8(NETWORK_UDP).await?;
        self.stream.write_all(&address).await?;
        self.stream.write_u16(data_length).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await
    }

    async fn write_end(
        &mut self,
        session_id: u16,
        has_error: bool,
    ) -> io::Result<()> {
        self.prefix().await?;
        self.stream.write_u16(4).await?;
        self.stream.write_u16(session_id).await?;
        self.stream.write_u8(STATUS_END).await?;
        self.stream
            .write_u8(if has_error { OPTION_ERROR } else { 0 })
            .await?;
        self.stream.flush().await
    }
}

struct MuxPacketConnection {
    session_id: u16,
    destination: SocksAddr,
    receiver: Mutex<mpsc::Receiver<MuxPacket>>,
    writer: Arc<Mutex<MuxWriter>>,
}

impl PacketConnection for MuxPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let destination = if destination.host().is_empty() {
                &self.destination
            } else {
                destination
            };
            self.writer
                .lock()
                .await
                .write_udp(self.session_id, destination, data)
                .await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let packet =
                self.receiver.lock().await.recv().await.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "VMess mux UDP session closed",
                    )
                })?;
            if packet.data.len() > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMess mux UDP packet exceeds buffer",
                ));
            }
            data[..packet.data.len()].copy_from_slice(&packet.data);
            Ok((packet.data.len(), packet.destination))
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_routed(
    stream: Stream,
    response_prefix: Option<Vec<u8>>,
    source: SocketAddr,
    tag: String,
    user: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(MuxWriter {
        stream: writer,
        response_prefix,
    }));
    let mut sessions = HashMap::<u16, Session>::new();
    let mut serial = 0_u64;
    let (closed_sender, mut closed_receiver) =
        mpsc::unbounded_channel::<(u16, u64, bool)>();
    let mut tasks = JoinSet::new();
    loop {
        enum Event {
            Frame(io::Result<Frame>),
            Closed(u16, u64, bool),
        }
        let event = tokio::select! {
            frame = read_frame(&mut reader) => Event::Frame(frame),
            Some((id, serial, error)) = closed_receiver.recv() => Event::Closed(id, serial, error),
        };
        match event {
            Event::Closed(id, closed_serial, has_error) => {
                if sessions
                    .get(&id)
                    .is_some_and(|session| session.serial == closed_serial)
                {
                    sessions.remove(&id);
                    writer.lock().await.write_end(id, has_error).await?;
                }
            }
            Event::Frame(Err(error)) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return if error.kind() == io::ErrorKind::UnexpectedEof {
                    Ok(())
                } else {
                    Err(error)
                };
            }
            Event::Frame(Ok(frame)) => {
                handle_frame(
                    frame,
                    &mut sessions,
                    &mut serial,
                    &mut tasks,
                    &closed_sender,
                    writer.clone(),
                    source,
                    &tag,
                    &user,
                    router.clone(),
                    outbounds.clone(),
                    udp_timeout,
                )
                .await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_frame(
    frame: Frame,
    sessions: &mut HashMap<u16, Session>,
    serial: &mut u64,
    tasks: &mut JoinSet<()>,
    closed_sender: &mpsc::UnboundedSender<(u16, u64, bool)>,
    writer: Arc<Mutex<MuxWriter>>,
    source: SocketAddr,
    tag: &str,
    user: &str,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    udp_timeout: std::time::Duration,
) -> io::Result<()> {
    if frame.status == STATUS_KEEP_ALIVE {
        return Ok(());
    }
    if frame.status == STATUS_END {
        sessions.remove(&frame.session_id);
        return Ok(());
    }
    if frame.status == STATUS_NEW {
        let network = frame.network.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess mux NEW frame has no network",
            )
        })?;
        let destination = frame.destination.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess mux NEW frame has no destination",
            )
        })?;
        if !matches!(network, NETWORK_TCP | NETWORK_UDP) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VMess mux network: {network}"),
            ));
        }
        *serial = serial.wrapping_add(1);
        let session_serial = *serial;
        let id = frame.session_id;
        let closed = closed_sender.clone();
        if network == NETWORK_TCP {
            let (application, transport) = duplex(64 * 1024);
            let (response_reader, request_writer) = tokio::io::split(transport);
            sessions.insert(
                id,
                Session {
                    serial: session_serial,
                    destination: destination.clone(),
                    sink: SessionSink::Tcp(request_writer),
                },
            );
            let writer = writer.clone();
            let tag = tag.to_owned();
            let user = user.to_owned();
            tasks.spawn(async move {
                let response = tokio::spawn(copy_tcp_responses(
                    response_reader,
                    writer,
                    id,
                ));
                let result = proxy_routed_tcp(
                    Box::new(application),
                    source,
                    &tag,
                    &user,
                    destination,
                    &router,
                    &outbounds,
                )
                .await;
                let _ = response.await;
                let _ = closed.send((id, session_serial, result.is_err()));
            });
        } else {
            let (sender, receiver) = mpsc::channel(64);
            sessions.insert(
                id,
                Session {
                    serial: session_serial,
                    destination: destination.clone(),
                    sink: SessionSink::Udp(sender),
                },
            );
            let packet: PacketStream = Box::new(MuxPacketConnection {
                session_id: id,
                destination,
                receiver: Mutex::new(receiver),
                writer: writer.clone(),
            });
            let tag = tag.to_owned();
            let user = user.to_owned();
            tasks.spawn(async move {
                let result = proxy_packet_connection(
                    packet,
                    source,
                    &tag,
                    Some(user),
                    &router,
                    &outbounds,
                    udp_timeout,
                )
                .await;
                let _ = closed.send((id, session_serial, result.is_err()));
            });
        }
    } else if frame.status != STATUS_KEEP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VMess mux status: {}", frame.status),
        ));
    }

    let Some(session) = sessions.get_mut(&frame.session_id) else {
        writer
            .lock()
            .await
            .write_end(frame.session_id, true)
            .await?;
        return Ok(());
    };
    if frame.option & OPTION_DATA == 0 || frame.data.is_empty() {
        return Ok(());
    }
    let destination = frame
        .destination
        .unwrap_or_else(|| session.destination.clone());
    let feed = match &mut session.sink {
        SessionSink::Tcp(stream) => stream.write_all(&frame.data).await,
        SessionSink::Udp(sender) => sender
            .send(MuxPacket {
                data: frame.data,
                destination,
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "VMess mux UDP session closed",
                )
            }),
    };
    if feed.is_err() {
        let session = sessions.remove(&frame.session_id).unwrap();
        writer
            .lock()
            .await
            .write_end(frame.session_id, true)
            .await?;
        drop(session);
    }
    Ok(())
}

async fn copy_tcp_responses(
    mut reader: ReadHalf<tokio::io::DuplexStream>,
    writer: Arc<Mutex<MuxWriter>>,
    session_id: u16,
) {
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let size = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(size) => size,
        };
        if writer
            .lock()
            .await
            .write_tcp(session_id, &buffer[..size])
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn read_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let header_length = reader.read_u16().await? as usize;
    if header_length < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess mux header is shorter than 4 bytes",
        ));
    }
    let session_id = reader.read_u16().await?;
    let status = reader.read_u8().await?;
    let option = reader.read_u8().await?;
    let (network, destination) = if header_length > 4 {
        let mut header = vec![0_u8; header_length - 4];
        reader.read_exact(&mut header).await?;
        let network = header[0];
        let (destination, consumed) = decode_xudp_address(&header[1..])?;
        if consumed + 1 > header.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess mux address exceeds frame header",
            ));
        }
        (Some(network), Some(destination))
    } else {
        (None, None)
    };
    let data = if option & OPTION_DATA != 0 {
        let length = reader.read_u16().await? as usize;
        let mut data = vec![0_u8; length];
        reader.read_exact(&mut data).await?;
        data
    } else {
        Vec::new()
    };
    Ok(Frame {
        session_id,
        status,
        option,
        network,
        destination,
        data,
    })
}

pub fn encode_new_frame(
    session_id: u16,
    network: u8,
    destination: &SocksAddr,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    let address = encode_xudp_address(destination)?;
    debug_assert_eq!(address.len(), socks_address_length(destination)?);
    let header_length = u16::try_from(5 + address.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VMess mux header is too large",
        )
    })?;
    let data_length = u16::try_from(data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VMess mux payload is too large",
        )
    })?;
    let mut output = Vec::new();
    output.extend_from_slice(&header_length.to_be_bytes());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.push(STATUS_NEW);
    output.push(OPTION_DATA);
    output.push(network);
    output.extend_from_slice(&address);
    output.extend_from_slice(&data_length.to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        time::timeout,
    };

    use super::*;
    use crate::{option::Options, outbound::OutboundManager, route::Router};

    #[tokio::test]
    async fn multiplexes_nonzero_tcp_and_udp_sessions_on_one_stream() {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_destination = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });

        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut data = [0_u8; 16];
            let (size, source) = udp_target.recv_from(&mut data).await.unwrap();
            udp_target.send_to(&data[..size], source).await.unwrap();
        });

        let outbounds = Arc::new(
            OutboundManager::from_options(&Options::default(), "").unwrap(),
        );
        let router = Arc::new(Router::from_json(&[], "").unwrap());
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(serve_routed(
            Box::new(server),
            Some(vec![0, 0]),
            "127.0.0.1:12345".parse().unwrap(),
            "vless-in".into(),
            "alice".into(),
            router,
            outbounds,
            Duration::from_millis(250),
        ));

        let tcp_frame =
            encode_new_frame(7, NETWORK_TCP, &tcp_destination.into(), b"tcp!")
                .unwrap();
        let udp_frame = encode_new_frame(
            9,
            NETWORK_UDP,
            &udp_destination.into(),
            b"packet",
        )
        .unwrap();
        client.write_all(&tcp_frame).await.unwrap();
        client.write_all(&udp_frame).await.unwrap();
        client.flush().await.unwrap();

        let mut prefix = [0_u8; 2];
        timeout(Duration::from_secs(2), client.read_exact(&mut prefix))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prefix, [0, 0]);

        let mut tcp_response = None;
        let mut udp_response = None;
        for _ in 0..8 {
            let frame =
                timeout(Duration::from_secs(2), read_frame(&mut client))
                    .await
                    .unwrap()
                    .unwrap();
            if frame.status != STATUS_KEEP || frame.option & OPTION_DATA == 0 {
                continue;
            }
            match frame.session_id {
                7 => tcp_response = Some(frame.data),
                9 => {
                    udp_response = Some((frame.destination, frame.data));
                }
                id => panic!("unexpected VMess mux session {id}"),
            }
            if tcp_response.is_some() && udp_response.is_some() {
                break;
            }
        }
        assert_eq!(tcp_response.as_deref(), Some(b"tcp!".as_slice()));
        let (udp_source, udp_data) = udp_response.unwrap();
        assert_eq!(udp_source, Some(udp_destination.into()));
        assert_eq!(udp_data, b"packet");

        drop(client);
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
    }
}
