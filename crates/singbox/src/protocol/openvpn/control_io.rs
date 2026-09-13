use std::{
    collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Dialer, PacketStream, Stream},
    common::network::SocksAddr,
};

use super::{
    IncomingControlEvent, Packet, TlsControlChannelCore,
    TlsControlChannelMuxCore, read_stream_packet, write_stream_packet,
};

#[async_trait]
pub trait OpenVpnPacketTransport: Send + Sync + 'static {
    async fn read_packet(&self) -> io::Result<Vec<u8>>;
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()>;

    /// Read a packet together with its datagram source when the link exposes
    /// one. Connected UDP and stream transports keep the source-less default.
    async fn read_packet_with_source(
        &self,
    ) -> io::Result<(Vec<u8>, Option<SocketAddr>)> {
        self.read_packet().await.map(|packet| (packet, None))
    }

    /// Confirm or reject a source only after the data codec authenticated the
    /// packet. A false verdict drops that packet while keeping the session.
    async fn accept_authenticated_packet_source(
        &self,
        _source: Option<SocketAddr>,
    ) -> io::Result<bool> {
        Ok(true)
    }

    /// OpenVPN treats data decryption failure as fatal on a stream link and
    /// as a dropped datagram on UDP.
    fn connection_oriented(&self) -> bool {
        true
    }
}

pub struct OpenVpnStreamTransport<R, W> {
    reader: Mutex<R>,
    writer: Mutex<W>,
}

impl<R, W> OpenVpnStreamTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl<R, W> OpenVpnPacketTransport for OpenVpnStreamTransport<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        read_stream_packet(&mut *self.reader.lock().await).await
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        write_stream_packet(&mut *self.writer.lock().await, packet).await
    }
}

pub struct OpenVpnDatagramTransport {
    socket: Arc<UdpSocket>,
    maximum_packet_size: usize,
}

pub struct OpenVpnDialerDatagramTransport {
    connection: PacketStream,
    destination: SocksAddr,
    maximum_packet_size: usize,
}

impl OpenVpnDialerDatagramTransport {
    pub fn new(
        connection: PacketStream,
        destination: SocksAddr,
        maximum_packet_size: usize,
    ) -> Self {
        Self {
            connection,
            destination,
            maximum_packet_size: maximum_packet_size.max(1),
        }
    }
}

#[async_trait]
impl OpenVpnPacketTransport for OpenVpnDialerDatagramTransport {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut packet = vec![0; self.maximum_packet_size];
        let (length, _) = self.connection.recv_from(&mut packet).await?;
        packet.truncate(length);
        Ok(packet)
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let written =
            self.connection.send_to(packet, &self.destination).await?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short OpenVPN outbound UDP packet write",
            ));
        }
        Ok(())
    }

    fn connection_oriented(&self) -> bool {
        false
    }
}

pub async fn dial_openvpn_packet_transport(
    dialer: &dyn Dialer,
    destination: &SocksAddr,
    network: &str,
    maximum_packet_size: usize,
) -> io::Result<Arc<dyn OpenVpnPacketTransport>> {
    match network {
        "tcp" => {
            let stream = dialer.dial_tcp(destination).await?;
            Ok(openvpn_stream_transport(stream))
        }
        "udp" => {
            let connection = dialer.listen_udp(destination).await?;
            Ok(Arc::new(OpenVpnDialerDatagramTransport::new(
                connection,
                destination.clone(),
                maximum_packet_size,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported OpenVPN transport network {network:?}"),
        )),
    }
}

pub fn openvpn_stream_transport(
    stream: Stream,
) -> Arc<dyn OpenVpnPacketTransport> {
    let (reader, writer) = tokio::io::split(stream);
    Arc::new(OpenVpnStreamTransport::new(reader, writer))
}

impl OpenVpnDatagramTransport {
    pub fn new(socket: Arc<UdpSocket>, maximum_packet_size: usize) -> Self {
        Self {
            socket,
            maximum_packet_size: maximum_packet_size.max(1),
        }
    }
}

#[async_trait]
impl OpenVpnPacketTransport for OpenVpnDatagramTransport {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut packet = vec![0; self.maximum_packet_size];
        let length = self.socket.recv(&mut packet).await?;
        packet.truncate(length);
        Ok(packet)
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let written = self.socket.send(packet).await?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short OpenVPN UDP packet write",
            ));
        }
        Ok(())
    }

    fn connection_oriented(&self) -> bool {
        false
    }
}

pub struct TlsControlChannelDriver {
    pub stream: DuplexStream,
    pub data_packets: mpsc::Receiver<Packet>,
    pub resets: mpsc::Receiver<IncomingControlEvent>,
    cancellation: CancellationToken,
    task: JoinHandle<io::Result<()>>,
    mux: Arc<Mutex<TlsControlChannelMuxCore>>,
    tls_writers: Arc<Mutex<HashMap<u8, mpsc::Sender<Vec<u8>>>>>,
    transport: Arc<dyn OpenVpnPacketTransport>,
}

impl TlsControlChannelDriver {
    pub fn into_stream_and_handle(
        self,
    ) -> (DuplexStream, TlsControlChannelHandle) {
        let Self {
            stream,
            data_packets,
            resets,
            cancellation,
            task,
            mux,
            tls_writers,
            transport,
        } = self;
        (
            stream,
            TlsControlChannelHandle {
                data_packets,
                resets,
                cancellation,
                task,
                mux,
                tls_writers,
                transport,
            },
        )
    }

    pub async fn shutdown(self) -> io::Result<()> {
        self.cancellation.cancel();
        self.task.await.map_err(io::Error::other)?
    }
}

pub struct TlsControlChannelHandle {
    pub data_packets: mpsc::Receiver<Packet>,
    pub resets: mpsc::Receiver<IncomingControlEvent>,
    cancellation: CancellationToken,
    task: JoinHandle<io::Result<()>>,
    mux: Arc<Mutex<TlsControlChannelMuxCore>>,
    tls_writers: Arc<Mutex<HashMap<u8, mpsc::Sender<Vec<u8>>>>>,
    transport: Arc<dyn OpenVpnPacketTransport>,
}

impl TlsControlChannelHandle {
    pub fn close(&self) {
        self.cancellation.cancel();
    }

    pub fn take_data_packets(&mut self) -> mpsc::Receiver<Packet> {
        let (_sender, receiver) = mpsc::channel(1);
        std::mem::replace(&mut self.data_packets, receiver)
    }

    pub fn take_resets(&mut self) -> mpsc::Receiver<IncomingControlEvent> {
        let (_sender, receiver) = mpsc::channel(1);
        std::mem::replace(&mut self.resets, receiver)
    }

    pub async fn register_renegotiation_channel(
        &self,
        core: TlsControlChannelCore,
        initial_soft_reset: Option<&Packet>,
    ) -> io::Result<TlsRenegotiationChannelDriver> {
        let key_id = core.session().current_key_id();
        let (stream, engine) = tokio::io::duplex(64 * 1024);
        let (mut encrypted_reader, mut encrypted_writer) =
            tokio::io::split(engine);
        let (tls_sender, mut tls_receiver) = mpsc::channel::<Vec<u8>>(64);
        self.tls_writers
            .lock()
            .await
            .insert(key_id, tls_sender.clone());
        let pending_events = match self
            .mux
            .lock()
            .await
            .register_renegotiation_channel(core, initial_soft_reset)
        {
            Ok(events) => events,
            Err(error) => {
                self.tls_writers.lock().await.remove(&key_id);
                return Err(protocol_error(error));
            }
        };
        for event in pending_events {
            match event {
                IncomingControlEvent::TlsCiphertext(ciphertext) => {
                    if tls_sender.send(ciphertext).await.is_err() {
                        self.tls_writers.lock().await.remove(&key_id);
                        self.mux.lock().await.unregister(key_id);
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "OpenVPN TLS key-state stream closed",
                        ));
                    }
                }
                IncomingControlEvent::SoftReset(_) => {
                    // UDP can retransmit the reset before the new key-state is
                    // installed; the first reset already created this state.
                }
                IncomingControlEvent::HardReset(_)
                | IncomingControlEvent::Data(_) => {
                    self.tls_writers.lock().await.remove(&key_id);
                    self.mux.lock().await.unregister(key_id);
                    return Err(protocol_error(
                        "unexpected buffered event during OpenVPN renegotiation",
                    ));
                }
            }
        }

        let cancellation = self.cancellation.child_token();
        let task_cancellation = cancellation.clone();
        let mux = self.mux.clone();
        let task_mux = mux.clone();
        let tls_writers = self.tls_writers.clone();
        let transport = self.transport.clone();
        let driver_transport = transport.clone();
        let task = tokio::spawn(async move {
            let incoming = async move {
                while let Some(ciphertext) = tls_receiver.recv().await {
                    encrypted_writer.write_all(&ciphertext).await?;
                }
                Ok::<_, io::Error>(())
            };
            let outgoing_cancellation = task_cancellation.clone();
            let outgoing = async move {
                let mut buffer = vec![0; 16 * 1024];
                loop {
                    let length = tokio::select! {
                        _ = outgoing_cancellation.cancelled() => return Ok(()),
                        result = encrypted_reader.read(&mut buffer) => result?,
                    };
                    if length == 0 {
                        return Ok(());
                    }
                    let mut consumed = 0;
                    while consumed < length {
                        let packet = task_mux
                            .lock()
                            .await
                            .packetize_tls_ciphertext(
                                key_id,
                                &buffer[consumed..length],
                            )
                            .map_err(protocol_error)?;
                        let Some((packet, packet_consumed)) = packet else {
                            tokio::select! {
                                _ = outgoing_cancellation.cancelled() => return Ok(()),
                                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                            }
                            continue;
                        };
                        transport.write_packet(&packet).await?;
                        consumed += packet_consumed;
                    }
                }
            };
            let result = tokio::select! {
                result = incoming => result,
                result = outgoing => result,
                _ = task_cancellation.cancelled() => Ok(()),
            };
            tls_writers.lock().await.remove(&key_id);
            mux.lock().await.unregister(key_id);
            result
        });
        Ok(TlsRenegotiationChannelDriver {
            stream,
            key_id,
            mux: self.mux.clone(),
            cancellation,
            task,
            transport: driver_transport,
        })
    }

    pub async fn promote_renegotiation_channel(
        &self,
        key_id: u8,
    ) -> io::Result<()> {
        self.mux
            .lock()
            .await
            .promote(key_id)
            .map_err(protocol_error)
    }

    pub async fn shutdown(self) -> io::Result<()> {
        self.cancellation.cancel();
        self.task.await.map_err(io::Error::other)?
    }
}

pub struct TlsRenegotiationChannelDriver {
    pub stream: DuplexStream,
    pub key_id: u8,
    mux: Arc<Mutex<TlsControlChannelMuxCore>>,
    cancellation: CancellationToken,
    task: JoinHandle<io::Result<()>>,
    transport: Arc<dyn OpenVpnPacketTransport>,
}

impl TlsRenegotiationChannelDriver {
    pub fn into_stream_and_handle(
        self,
    ) -> (DuplexStream, TlsRenegotiationChannelHandle) {
        let Self {
            stream,
            key_id,
            mux: _,
            cancellation,
            task,
            transport: _,
        } = self;
        (
            stream,
            TlsRenegotiationChannelHandle {
                key_id,
                cancellation,
                task,
            },
        )
    }

    pub async fn send_initial_soft_reset(&self) -> io::Result<()> {
        let packet = self
            .mux
            .lock()
            .await
            .send_initial_soft_reset(self.key_id)
            .map_err(protocol_error)?;
        self.transport.write_packet(&packet).await
    }

    pub async fn shutdown(self) -> io::Result<()> {
        self.cancellation.cancel();
        self.task.await.map_err(io::Error::other)?
    }
}

pub struct TlsRenegotiationChannelHandle {
    pub key_id: u8,
    cancellation: CancellationToken,
    task: JoinHandle<io::Result<()>>,
}

impl TlsRenegotiationChannelHandle {
    pub async fn shutdown(self) -> io::Result<()> {
        self.cancellation.cancel();
        self.task.await.map_err(io::Error::other)?
    }
}

pub fn spawn_tls_control_channel(
    core: TlsControlChannelCore,
    transport: Arc<dyn OpenVpnPacketTransport>,
) -> TlsControlChannelDriver {
    let primary_key_id = core.session().current_key_id();
    let core = Arc::new(Mutex::new(TlsControlChannelMuxCore::new(core)));
    let (stream, engine) = tokio::io::duplex(64 * 1024);
    let (mut encrypted_reader, mut encrypted_writer) = tokio::io::split(engine);
    let (initial_tls_sender, mut initial_tls_receiver) =
        mpsc::channel::<Vec<u8>>(64);
    let tls_writers = Arc::new(Mutex::new(HashMap::from([(
        primary_key_id,
        initial_tls_sender,
    )])));
    let (data_sender, data_packets) = mpsc::channel(64);
    let (reset_sender, resets) = mpsc::channel(8);
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let handle_transport = transport.clone();
    let handle_core = core.clone();
    let handle_tls_writers = tls_writers.clone();
    let task = tokio::spawn(async move {
        let incoming_core = core.clone();
        let incoming_transport = transport.clone();
        let incoming_cancellation = task_cancellation.clone();
        let incoming = async move {
            loop {
                let (raw, source) = tokio::select! {
                    _ = incoming_cancellation.cancelled() => return Ok(()),
                    result = incoming_transport.read_packet_with_source() => result?,
                };
                let routed = incoming_core
                    .lock()
                    .await
                    .ingest_link_packet(&raw)
                    .map_err(protocol_error)?;
                for event in routed.events {
                    match event {
                        IncomingControlEvent::TlsCiphertext(ciphertext) => {
                            let sender = tls_writers
                                .lock()
                                .await
                                .get(&routed.key_id)
                                .cloned();
                            if let Some(sender) = sender {
                                sender.send(ciphertext).await.map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "OpenVPN TLS key-state stream closed",
                                    )
                                })?;
                            }
                        }
                        IncomingControlEvent::Data(mut packet) => {
                            packet.set_link_source(source);
                            data_sender.send(packet).await.map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "OpenVPN data receiver closed",
                                )
                            })?;
                        }
                        event @ (IncomingControlEvent::HardReset(_)
                        | IncomingControlEvent::SoftReset(_)) => {
                            reset_sender.send(event).await.map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "OpenVPN reset receiver closed",
                                )
                            })?;
                        }
                    }
                }
            }
        };

        let initial_tls_cancellation = task_cancellation.clone();
        let initial_tls = async move {
            loop {
                let ciphertext = tokio::select! {
                    _ = initial_tls_cancellation.cancelled() => return Ok(()),
                    value = initial_tls_receiver.recv() => value,
                };
                let Some(ciphertext) = ciphertext else {
                    return Ok(());
                };
                encrypted_writer.write_all(&ciphertext).await?;
            }
        };

        let outgoing_core = core.clone();
        let outgoing_transport = transport.clone();
        let outgoing_cancellation = task_cancellation.clone();
        let outgoing = async move {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                let length = tokio::select! {
                    _ = outgoing_cancellation.cancelled() => return Ok(()),
                    result = encrypted_reader.read(&mut buffer) => result?,
                };
                if length == 0 {
                    // The data/control owner, rather than the OpenSSL stream,
                    // owns the packet transport lifetime.  Key-method users
                    // may drop the TLS stream after negotiation while the
                    // encrypted data channel and reset mux remain active.
                    outgoing_cancellation.cancelled().await;
                    return Ok(());
                }
                let mut consumed = 0;
                while consumed < length {
                    let packet = outgoing_core
                        .lock()
                        .await
                        .packetize_tls_ciphertext(
                            primary_key_id,
                            &buffer[consumed..length],
                        )
                        .map_err(protocol_error)?;
                    let Some((packet, packet_consumed)) = packet else {
                        tokio::select! {
                            _ = outgoing_cancellation.cancelled() => return Ok(()),
                            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        }
                        continue;
                    };
                    outgoing_transport.write_packet(&packet).await?;
                    consumed += packet_consumed;
                }
            }
        };

        let retransmit_core = core;
        let retransmit_transport = transport;
        let retransmit_cancellation = task_cancellation.clone();
        let retransmit = async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(100));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = retransmit_cancellation.cancelled() => return Ok(()),
                    _ = interval.tick() => {}
                }
                let packets = retransmit_core
                    .lock()
                    .await
                    .packets_ready_to_send(std::time::Instant::now())
                    .map_err(protocol_error)?;
                for packet in packets {
                    retransmit_transport.write_packet(&packet).await?;
                }
            }
        };

        tokio::select! {
            result = incoming => result,
            result = initial_tls => result,
            result = outgoing => result,
            result = retransmit => result,
            _ = task_cancellation.cancelled() => Ok(()),
        }
    });
    TlsControlChannelDriver {
        stream,
        data_packets,
        resets,
        cancellation,
        task,
        mux: handle_core,
        tls_writers: handle_tls_writers,
        transport: handle_transport,
    }
}

fn protocol_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use openssl::ssl::Ssl;
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    };
    use tokio_openssl::SslStream;

    use super::*;
    use crate::protocol::openvpn::{
        OpenVpnTlsContextOptions, OpenVpnTlsRole, SessionManager,
        TlsControlProtection, TlsMaterial, VerifyClientCertMode,
        build_openssl_tls_context,
    };

    struct MemoryPacketTransport {
        receive: Mutex<mpsc::Receiver<Vec<u8>>>,
        send: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl OpenVpnPacketTransport for MemoryPacketTransport {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            self.receive.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "packet link closed",
                )
            })
        }

        async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.send.send(packet.to_vec()).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "packet link closed")
            })
        }
    }

    fn memory_packet_pair() -> (
        Arc<dyn OpenVpnPacketTransport>,
        Arc<dyn OpenVpnPacketTransport>,
    ) {
        let (left_send, right_receive) = mpsc::channel(128);
        let (right_send, left_receive) = mpsc::channel(128);
        (
            Arc::new(MemoryPacketTransport {
                receive: Mutex::new(left_receive),
                send: left_send,
            }),
            Arc::new(MemoryPacketTransport {
                receive: Mutex::new(right_receive),
                send: right_send,
            }),
        )
    }

    #[tokio::test]
    async fn carries_a_real_openssl_handshake_over_reliable_openvpn_packets() {
        let mut certificate_params =
            CertificateParams::new(vec!["vpn.test".into()]).unwrap();
        certificate_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "vpn.test");
        certificate_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        certificate_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key_pair = KeyPair::generate().unwrap();
        let cert = certificate_params.self_signed(&key_pair).unwrap();
        let certificate = cert.pem().into_bytes();
        let server_context =
            build_openssl_tls_context(&OpenVpnTlsContextOptions {
                role: OpenVpnTlsRole::Server,
                certificate: TlsMaterial::from_pem(certificate.clone()),
                key: TlsMaterial::from_pem(key_pair.serialize_pem()),
                verify_client_certificate: VerifyClientCertMode::None,
                ..OpenVpnTlsContextOptions::server()
            })
            .unwrap();
        let client_context =
            build_openssl_tls_context(&OpenVpnTlsContextOptions {
                certificate_authority: TlsMaterial::from_pem(certificate),
                verify_name: "vpn.test".into(),
                verify_name_type: "name".into(),
                remote_certificate_tls: "server".into(),
                ..OpenVpnTlsContextOptions::client()
            })
            .unwrap();

        let client_session =
            Arc::new(SessionManager::with_local_id(*b"clientid"));
        client_session.set_remote_session_id(*b"serverid");
        let server_session =
            Arc::new(SessionManager::with_local_id(*b"serverid"));
        server_session.set_remote_session_id(*b"clientid");
        let (client_transport, server_transport) = memory_packet_pair();
        let client_driver = spawn_tls_control_channel(
            TlsControlChannelCore::new(
                client_session,
                TlsControlProtection::default(),
                Vec::new(),
                false,
            ),
            client_transport,
        );
        let server_driver = spawn_tls_control_channel(
            TlsControlChannelCore::new(
                server_session,
                TlsControlProtection::default(),
                Vec::new(),
                false,
            ),
            server_transport,
        );
        let mut client_tls = SslStream::new(
            Ssl::new(&client_context).unwrap(),
            client_driver.stream,
        )
        .unwrap();
        let mut server_tls = SslStream::new(
            Ssl::new(&server_context).unwrap(),
            server_driver.stream,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                Pin::new(&mut client_tls).connect(),
                Pin::new(&mut server_tls).accept()
            )
            .map_err(io::Error::other)?;
            client_tls.write_all(b"PUSH_REQUEST\0").await?;
            let mut request = [0; 13];
            server_tls.read_exact(&mut request).await?;
            assert_eq!(&request, b"PUSH_REQUEST\0");
            Ok::<_, io::Error>(())
        })
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn dynamically_routes_a_soft_reset_tls_stream_by_key_id() {
        let client_session =
            Arc::new(SessionManager::with_local_id(*b"clientid"));
        client_session.set_remote_session_id(*b"serverid");
        let server_session =
            Arc::new(SessionManager::with_local_id(*b"serverid"));
        server_session.set_remote_session_id(*b"clientid");
        let (client_transport, server_transport) = memory_packet_pair();
        let client_driver = spawn_tls_control_channel(
            TlsControlChannelCore::new(
                client_session.clone(),
                TlsControlProtection::default(),
                Vec::new(),
                false,
            ),
            client_transport,
        );
        let server_driver = spawn_tls_control_channel(
            TlsControlChannelCore::new(
                server_session.clone(),
                TlsControlProtection::default(),
                Vec::new(),
                false,
            ),
            server_transport,
        );
        let (_client_primary_stream, client_handle) =
            client_driver.into_stream_and_handle();
        let (_server_primary_stream, mut server_handle) =
            server_driver.into_stream_and_handle();

        let client_rekey_session = Arc::new(client_session.renegotiation(1));
        let mut client_rekey = client_handle
            .register_renegotiation_channel(
                TlsControlChannelCore::new(
                    client_rekey_session,
                    TlsControlProtection::default(),
                    Vec::new(),
                    false,
                ),
                None,
            )
            .await
            .unwrap();
        client_rekey.send_initial_soft_reset().await.unwrap();

        let reset = tokio::time::timeout(
            Duration::from_secs(2),
            server_handle.resets.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        let IncomingControlEvent::SoftReset(reset) = reset else {
            panic!("expected soft reset");
        };
        let server_rekey_session = Arc::new(server_session.renegotiation(1));
        let mut server_rekey = server_handle
            .register_renegotiation_channel(
                TlsControlChannelCore::new(
                    server_rekey_session,
                    TlsControlProtection::default(),
                    Vec::new(),
                    false,
                ),
                Some(&reset),
            )
            .await
            .unwrap();

        client_rekey
            .stream
            .write_all(b"second TLS stream")
            .await
            .unwrap();
        let mut received = vec![0; 17];
        tokio::time::timeout(
            Duration::from_secs(2),
            server_rekey.stream.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, b"second TLS stream");

        client_rekey.shutdown().await.unwrap();
        server_rekey.shutdown().await.unwrap();
        tokio::try_join!(client_handle.shutdown(), server_handle.shutdown())
            .unwrap();
    }
}
