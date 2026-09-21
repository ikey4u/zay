//! Cloudflare Tunnel QUIC edge transport backed by Quinn.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream,
    TransportConfig, VarInt,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use super::cloudflared::{
    CLOUDFLARED_RPC_STREAM_SIGNATURE, CloudflaredConnectRequest,
    CloudflaredError, CloudflaredIncomingDatagramVersion,
    CloudflaredRegistrationClient, CloudflaredRegistrationOptions,
    CloudflaredRegistrationResult, CloudflaredStreamType,
    cloudflared_registration_rpc, read_cloudflared_connect_request,
    read_cloudflared_stream_signature,
};

pub const CLOUDFLARED_QUIC_HANDSHAKE_IDLE_TIMEOUT: Duration =
    Duration::from_secs(5);
pub const CLOUDFLARED_QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
pub const CLOUDFLARED_QUIC_KEEP_ALIVE_INTERVAL: Duration =
    Duration::from_secs(1);
pub const CLOUDFLARED_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5);

pub const fn cloudflared_quic_initial_packet_size(ip_version: u8) -> u16 {
    if ip_version == 4 { 1232 } else { 1252 }
}

pub fn cloudflared_quic_transport_config(
    ip_version: u8,
) -> Result<TransportConfig, CloudflaredError> {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        CLOUDFLARED_QUIC_MAX_IDLE_TIMEOUT.try_into().map_err(|_| {
            CloudflaredError::Transport(
                "QUIC idle timeout exceeds varint range".into(),
            )
        })?,
    ));
    transport.keep_alive_interval(Some(CLOUDFLARED_QUIC_KEEP_ALIVE_INTERVAL));
    // Quinn replenishes stream credit as streams close. A large finite window
    // avoids the pathological work caused by quic-go's static 1<<60 limit.
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1024));
    transport.max_concurrent_uni_streams(VarInt::from_u32(1024));
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    transport.initial_mtu(cloudflared_quic_initial_packet_size(ip_version));
    Ok(transport)
}

pub struct CloudflaredQuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl CloudflaredQuicStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    pub fn stop(&mut self) {
        let _ = self.recv.stop(VarInt::from_u32(0));
        let _ = self.send.reset(VarInt::from_u32(0));
    }
}

impl AsyncRead for CloudflaredQuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for CloudflaredQuicStream {
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
        AsyncWrite::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), context)
    }
}

pub enum CloudflaredQuicEvent {
    Data {
        stream: CloudflaredQuicStream,
        request: CloudflaredConnectRequest,
    },
    Rpc {
        stream: CloudflaredQuicStream,
    },
    Datagram(Bytes),
}

#[derive(Clone)]
pub struct CloudflaredQuicDatagramSender {
    connection: Connection,
    datagram_version: CloudflaredIncomingDatagramVersion,
}

impl CloudflaredQuicDatagramSender {
    fn new(
        connection: Connection,
        datagram_version: CloudflaredIncomingDatagramVersion,
    ) -> Self {
        Self {
            connection,
            datagram_version,
        }
    }

    pub const fn datagram_version(&self) -> CloudflaredIncomingDatagramVersion {
        self.datagram_version
    }

    pub fn send_datagram(
        &self,
        datagram: Bytes,
    ) -> Result<(), CloudflaredError> {
        self.connection
            .send_datagram(datagram)
            .map_err(|error| CloudflaredError::Transport(error.to_string()))
    }

    pub async fn open_rpc_stream(
        &self,
    ) -> Result<CloudflaredQuicStream, CloudflaredError> {
        open_cloudflared_rpc_stream(&self.connection).await
    }

    pub(crate) fn connection_id(&self) -> usize {
        self.connection.stable_id()
    }

    pub(crate) async fn wait_closed(&self) {
        let _ = self.connection.closed().await;
    }
}

#[async_trait]
pub trait CloudflaredQuicHandler: Send + Sync + 'static {
    async fn handle_data_stream(
        &self,
        stream: CloudflaredQuicStream,
        request: CloudflaredConnectRequest,
        connection_index: u8,
    );

    async fn handle_rpc_stream(
        &self,
        stream: CloudflaredQuicStream,
        connection_index: u8,
        sender: CloudflaredQuicDatagramSender,
    );

    async fn handle_datagram(
        &self,
        datagram: Bytes,
        sender: CloudflaredQuicDatagramSender,
    );
}

async fn open_cloudflared_rpc_stream(
    connection: &Connection,
) -> Result<CloudflaredQuicStream, CloudflaredError> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
    let mut stream = CloudflaredQuicStream::new(send, recv);
    stream
        .write_all(&CLOUDFLARED_RPC_STREAM_SIGNATURE)
        .await
        .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
    Ok(stream)
}

pub struct CloudflaredQuicEdge {
    endpoint: Endpoint,
    connection: Connection,
    datagram_version: CloudflaredIncomingDatagramVersion,
}

impl CloudflaredQuicEdge {
    pub fn from_connection(
        endpoint: Endpoint,
        connection: Connection,
        datagram_version: CloudflaredIncomingDatagramVersion,
    ) -> Self {
        Self {
            endpoint,
            connection,
            datagram_version,
        }
    }

    pub async fn connect(
        bind_address: SocketAddr,
        edge_address: SocketAddr,
        server_name: &str,
        mut client_config: ClientConfig,
        ip_version: u8,
        datagram_version: CloudflaredIncomingDatagramVersion,
    ) -> Result<Self, CloudflaredError> {
        client_config.transport_config(Arc::new(
            cloudflared_quic_transport_config(ip_version)?,
        ));
        let mut endpoint = Endpoint::client(bind_address)
            .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(edge_address, server_name)
            .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
        let connection = tokio::time::timeout(
            CLOUDFLARED_QUIC_HANDSHAKE_IDLE_TIMEOUT,
            connecting,
        )
        .await
        .map_err(|_| {
            CloudflaredError::Transport("QUIC handshake timed out".into())
        })?
        .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
        Ok(Self::from_connection(
            endpoint,
            connection,
            datagram_version,
        ))
    }

    pub fn local_address(&self) -> Result<SocketAddr, CloudflaredError> {
        self.endpoint
            .local_addr()
            .map_err(|error| CloudflaredError::Transport(error.to_string()))
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub const fn datagram_version(&self) -> CloudflaredIncomingDatagramVersion {
        self.datagram_version
    }

    pub async fn next_event(
        &self,
    ) -> Result<CloudflaredQuicEvent, CloudflaredError> {
        tokio::select! {
            stream = self.connection.accept_bi() => {
                let (send, recv) = stream
                    .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
                let mut stream = CloudflaredQuicStream::new(send, recv);
                match read_cloudflared_stream_signature(&mut stream).await {
                    Ok(CloudflaredStreamType::Data) => {
                        let request = read_cloudflared_connect_request(&mut stream).await?;
                        Ok(CloudflaredQuicEvent::Data { stream, request })
                    }
                    Ok(CloudflaredStreamType::Rpc) => {
                        Ok(CloudflaredQuicEvent::Rpc { stream })
                    }
                    Err(error) => {
                        stream.stop();
                        Err(error)
                    }
                }
            }
            datagram = self.connection.read_datagram() => {
                datagram
                    .map(CloudflaredQuicEvent::Datagram)
                    .map_err(|error| CloudflaredError::Transport(error.to_string()))
            }
        }
    }

    pub async fn open_rpc_stream(
        &self,
    ) -> Result<CloudflaredQuicStream, CloudflaredError> {
        open_cloudflared_rpc_stream(&self.connection).await
    }

    /// Register this edge connection on its first client-initiated stream.
    ///
    /// `capnp-rpc` uses local futures, so this method must run inside a Tokio
    /// [`tokio::task::LocalSet`]. The returned session keeps that RPC driver
    /// alive until graceful shutdown or drop.
    pub async fn register(
        self,
        mut options: CloudflaredRegistrationOptions,
        grace_period: Duration,
    ) -> Result<CloudflaredQuicSession, CloudflaredError> {
        options.origin_local_ip = self.local_address()?.ip();
        let (send, recv) =
            self.connection.open_bi().await.map_err(|error| {
                CloudflaredError::Transport(error.to_string())
            })?;
        let stream = CloudflaredQuicStream::new(send, recv);
        let (registration, rpc_system) = cloudflared_registration_rpc(stream);
        let rpc_task = tokio::task::spawn_local(rpc_system);
        let result = match tokio::time::timeout(
            CLOUDFLARED_REGISTRATION_TIMEOUT,
            registration.register_connection(&options),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                rpc_task.abort();
                self.close(b"registration failed");
                return Err(error);
            }
            Err(_) => {
                rpc_task.abort();
                self.close(b"registration timed out");
                return Err(CloudflaredError::Transport(
                    "registration timed out".into(),
                ));
            }
        };
        if !result.tunnel_is_remotely_managed {
            rpc_task.abort();
            self.close(b"non-remote-managed tunnel");
            return Err(CloudflaredError::NonRemoteManagedTunnel);
        }
        Ok(CloudflaredQuicSession {
            edge: Some(self),
            registration,
            registration_result: result,
            rpc_task,
            grace_period,
        })
    }

    pub fn send_datagram(
        &self,
        datagram: Bytes,
    ) -> Result<(), CloudflaredError> {
        self.connection
            .send_datagram(datagram)
            .map_err(|error| CloudflaredError::Transport(error.to_string()))
    }

    pub async fn closed(&self) -> quinn::ConnectionError {
        self.connection.closed().await
    }

    pub fn close(&self, reason: &[u8]) {
        self.connection.close(VarInt::from_u32(0), reason);
        self.endpoint.close(VarInt::from_u32(0), reason);
    }
}

pub struct CloudflaredQuicSession {
    edge: Option<CloudflaredQuicEdge>,
    registration: CloudflaredRegistrationClient,
    registration_result: CloudflaredRegistrationResult,
    rpc_task: tokio::task::JoinHandle<Result<(), capnp::Error>>,
    grace_period: Duration,
}

impl CloudflaredQuicSession {
    pub const fn registration_result(&self) -> &CloudflaredRegistrationResult {
        &self.registration_result
    }

    pub fn edge(&self) -> &CloudflaredQuicEdge {
        self.edge
            .as_ref()
            .expect("registered edge is present until graceful shutdown")
    }

    pub async fn next_event(
        &self,
    ) -> Result<CloudflaredQuicEvent, CloudflaredError> {
        self.edge().next_event().await
    }

    pub fn send_datagram(
        &self,
        datagram: Bytes,
    ) -> Result<(), CloudflaredError> {
        self.edge().send_datagram(datagram)
    }

    pub async fn open_rpc_stream(
        &self,
    ) -> Result<CloudflaredQuicStream, CloudflaredError> {
        self.edge().open_rpc_stream().await
    }

    /// Serve edge streams and datagrams until cancellation or transport loss.
    ///
    /// Each event receives an independent task so a long-lived TCP/WebSocket
    /// stream cannot block new streams or datagrams. On cancellation the
    /// registration is removed first, active handlers retain the configured
    /// grace window, and any tasks still alive afterwards are aborted.
    pub async fn serve(
        self,
        connection_index: u8,
        handler: Arc<dyn CloudflaredQuicHandler>,
        cancellation: CancellationToken,
    ) -> Result<(), CloudflaredError> {
        let sender = CloudflaredQuicDatagramSender::new(
            self.edge().connection.clone(),
            self.edge().datagram_version,
        );
        let mut handlers = JoinSet::new();
        loop {
            tokio::select! {
                () = cancellation.cancelled() => break,
                event = self.next_event() => {
                    let event = match event {
                        Ok(event) => event,
                        Err(error) => {
                            handlers.abort_all();
                            while handlers.join_next().await.is_some() {}
                            self.force_close();
                            return Err(error);
                        }
                    };
                    let handler = Arc::clone(&handler);
                    let event_sender = sender.clone();
                    handlers.spawn_local(async move {
                        match event {
                            CloudflaredQuicEvent::Data { stream, request } => {
                                handler
                                    .handle_data_stream(
                                        stream,
                                        request,
                                        connection_index,
                                    )
                                    .await;
                            }
                            CloudflaredQuicEvent::Rpc { stream } => {
                                handler
                                    .handle_rpc_stream(
                                        stream,
                                        connection_index,
                                        event_sender,
                                    )
                                    .await;
                            }
                            CloudflaredQuicEvent::Datagram(datagram) => {
                                handler
                                    .handle_datagram(datagram, event_sender)
                                    .await;
                            }
                        }
                    });
                }
                Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                    if let Err(error) = result
                        && error.is_panic()
                    {
                        handlers.abort_all();
                        while handlers.join_next().await.is_some() {}
                        self.force_close();
                        return Err(CloudflaredError::Transport(
                            "cloudflared QUIC handler panicked".into(),
                        ));
                    }
                }
            }
        }

        let shutdown_result = self.graceful_shutdown().await;
        handlers.abort_all();
        while handlers.join_next().await.is_some() {}
        shutdown_result
    }

    pub async fn graceful_shutdown(mut self) -> Result<(), CloudflaredError> {
        let unregister = tokio::time::timeout(
            self.grace_period,
            self.registration.unregister_connection(),
        )
        .await;
        self.rpc_task.abort();
        if !self.grace_period.is_zero() {
            tokio::time::sleep(self.grace_period).await;
        }
        if let Some(edge) = self.edge.take() {
            edge.close(b"graceful shutdown");
        }
        match unregister {
            Ok(result) => result,
            Err(_) => {
                Err(CloudflaredError::Transport("unregister timed out".into()))
            }
        }
    }

    pub fn force_close(mut self) {
        self.rpc_task.abort();
        if let Some(edge) = self.edge.take() {
            edge.close(b"connection closed");
        }
    }
}

impl Drop for CloudflaredQuicSession {
    fn drop(&mut self) {
        self.rpc_task.abort();
        if let Some(edge) = self.edge.take() {
            edge.close(b"connection closed");
        }
    }
}

impl Drop for CloudflaredQuicEdge {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(0), b"");
        self.endpoint.close(VarInt::from_u32(0), b"");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use quinn::crypto::rustls::QuicClientConfig;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::io::AsyncReadExt;
    use tokio_util::compat::TokioAsyncReadCompatExt;
    use uuid::Uuid;

    use super::*;
    use crate::{
        cloudflared_quic_metadata_capnp as metadata_capnp,
        cloudflared_tunnelrpc_capnp as tunnelrpc,
        common::tls::{
            build_client_config, build_server_config_with_default_alpn,
        },
        option::{InboundTlsOptions, OutboundTlsOptions},
        protocol::cloudflared::{
            CLOUDFLARED_QUIC_EDGE_ALPN, CloudflaredCredentials,
        },
        transport::quic::server_config,
    };

    struct QuicRegistrationServer {
        registered: Arc<tokio::sync::Notify>,
        unregistered: Arc<AtomicBool>,
    }

    impl tunnelrpc::registration_server::Server for QuicRegistrationServer {
        async fn register_connection(
            self: capnp::capability::Rc<Self>,
            params: tunnelrpc::registration_server::RegisterConnectionParams,
            mut results: tunnelrpc::registration_server::RegisterConnectionResults,
        ) -> Result<(), capnp::Error> {
            let params = params.get()?;
            let options = params.get_options()?;
            assert_eq!(options.get_origin_local_ip()?, &[127, 0, 0, 1]);
            assert_eq!(params.get_conn_index(), 2);

            let response = results.get().init_result();
            let mut details = response.get_result().init_connection_details();
            details.set_uuid(
                Uuid::parse_str("550e8400-e29a-41d4-a716-446655440009")
                    .unwrap()
                    .as_bytes(),
            );
            details.set_location_name("LAX");
            details.set_tunnel_is_remotely_managed(true);
            self.registered.notify_one();
            Ok(())
        }

        async fn unregister_connection(
            self: capnp::capability::Rc<Self>,
            _params: tunnelrpc::registration_server::UnregisterConnectionParams,
            _results: tunnelrpc::registration_server::UnregisterConnectionResults,
        ) -> Result<(), capnp::Error> {
            self.unregistered.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Default)]
    struct QuicServeRecorder {
        data: AtomicBool,
        rpc: AtomicBool,
        datagram: AtomicBool,
        changed: tokio::sync::Notify,
    }

    impl QuicServeRecorder {
        fn complete(&self) -> bool {
            self.data.load(Ordering::SeqCst)
                && self.rpc.load(Ordering::SeqCst)
                && self.datagram.load(Ordering::SeqCst)
        }

        async fn wait_complete(&self) {
            while !self.complete() {
                self.changed.notified().await;
            }
        }

        fn mark(&self, field: &AtomicBool) {
            field.store(true, Ordering::SeqCst);
            self.changed.notify_waiters();
        }
    }

    #[async_trait]
    impl CloudflaredQuicHandler for QuicServeRecorder {
        async fn handle_data_stream(
            &self,
            mut stream: CloudflaredQuicStream,
            request: CloudflaredConnectRequest,
            connection_index: u8,
        ) {
            assert_eq!(connection_index, 2);
            assert_eq!(request.destination, "tcp://192.0.2.22:443");
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"served-data");
            self.mark(&self.data);
        }

        async fn handle_rpc_stream(
            &self,
            mut stream: CloudflaredQuicStream,
            connection_index: u8,
            sender: CloudflaredQuicDatagramSender,
        ) {
            assert_eq!(connection_index, 2);
            assert_eq!(
                sender.datagram_version(),
                CloudflaredIncomingDatagramVersion::V3
            );
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"served-rpc");
            sender
                .send_datagram(Bytes::from_static(b"handler-response"))
                .unwrap();
            self.mark(&self.rpc);
        }

        async fn handle_datagram(
            &self,
            datagram: Bytes,
            _sender: CloudflaredQuicDatagramSender,
        ) {
            assert_eq!(datagram, Bytes::from_static(b"served-datagram"));
            self.mark(&self.datagram);
        }
    }

    fn test_quic_client_config() -> ClientConfig {
        let client_tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &[CLOUDFLARED_QUIC_EDGE_ALPN],
        )
        .unwrap();
        let crypto = QuicClientConfig::try_from(client_tls.config).unwrap();
        ClientConfig::new(Arc::new(crypto))
    }

    #[tokio::test]
    async fn real_quinn_edge_classifies_streams_and_datagrams() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_tls: InboundTlsOptions = serde_json::from_value(json!({
            "enabled": true,
            "certificate": cert.pem(),
            "key": key_pair.serialize_pem()
        }))
        .unwrap();
        let server_tls = build_server_config_with_default_alpn(
            &server_tls,
            &[crate::protocol::cloudflared::CLOUDFLARED_QUIC_EDGE_ALPN],
        )
        .unwrap();
        let mut server_config = server_config(server_tls).unwrap();
        server_config.transport_config(Arc::new(
            cloudflared_quic_transport_config(4).unwrap(),
        ));
        let server_endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .unwrap();
        let server_address = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let connection =
                server_endpoint.accept().await.unwrap().await.unwrap();

            let (mut data_send, _data_recv) =
                connection.open_bi().await.unwrap();
            let mut message = capnp::message::Builder::new_default();
            {
                let mut request = message
                    .init_root::<metadata_capnp::connect_request::Builder<'_>>(
                );
                request.set_dest("tcp://192.0.2.1:443");
                request.set_type(metadata_capnp::ConnectionType::Tcp);
                request.init_metadata(0);
            }
            let mut wire =
                crate::protocol::cloudflared::cloudflared_data_stream_prefix()
                    .to_vec();
            capnp::serialize::write_message(&mut wire, &message).unwrap();
            data_send.write_all(&wire).await.unwrap();
            data_send.write_all(b"data-body").await.unwrap();
            data_send.finish().unwrap();

            let (mut rpc_send, _rpc_recv) = connection.open_bi().await.unwrap();
            rpc_send
                .write_all(&CLOUDFLARED_RPC_STREAM_SIGNATURE)
                .await
                .unwrap();
            rpc_send.write_all(b"rpc-body").await.unwrap();
            rpc_send.finish().unwrap();
            connection
                .send_datagram(Bytes::from_static(b"edge-datagram"))
                .unwrap();

            let (_response_send, mut response_recv) =
                connection.accept_bi().await.unwrap();
            let mut signature = [0_u8; 6];
            response_recv.read_exact(&mut signature).await.unwrap();
            assert_eq!(signature, CLOUDFLARED_RPC_STREAM_SIGNATURE);
            let mut body = [0_u8; 4];
            response_recv.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"pong");
            assert_eq!(
                connection.read_datagram().await.unwrap(),
                Bytes::from_static(b"client-datagram")
            );
        });

        let edge = CloudflaredQuicEdge::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_address,
            "localhost",
            test_quic_client_config(),
            4,
            CloudflaredIncomingDatagramVersion::V3,
        )
        .await
        .unwrap();
        assert_eq!(edge.remote_address(), server_address);
        assert!(edge.local_address().unwrap().ip().is_ipv4());
        assert_eq!(
            edge.datagram_version(),
            CloudflaredIncomingDatagramVersion::V3
        );

        let mut saw_data = false;
        let mut saw_rpc = false;
        let mut saw_datagram = false;
        for _ in 0..3 {
            match tokio::time::timeout(
                Duration::from_secs(3),
                edge.next_event(),
            )
            .await
            .expect("timed out waiting for edge event")
            .unwrap()
            {
                CloudflaredQuicEvent::Data {
                    mut stream,
                    request,
                } => {
                    saw_data = true;
                    assert_eq!(request.destination, "tcp://192.0.2.1:443");
                    assert_eq!(
                        request.connection_type,
                        crate::protocol::cloudflared::CloudflaredConnectionType::Tcp
                    );
                    let mut body = Vec::new();
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        stream.read_to_end(&mut body),
                    )
                    .await
                    .expect("timed out reading data stream body")
                    .unwrap();
                    assert_eq!(body, b"data-body");
                }
                CloudflaredQuicEvent::Rpc { mut stream } => {
                    saw_rpc = true;
                    let mut body = Vec::new();
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        stream.read_to_end(&mut body),
                    )
                    .await
                    .expect("timed out reading RPC stream body")
                    .unwrap();
                    assert_eq!(body, b"rpc-body");
                }
                CloudflaredQuicEvent::Datagram(datagram) => {
                    saw_datagram = true;
                    assert_eq!(datagram, Bytes::from_static(b"edge-datagram"));
                }
            }
        }
        assert!(saw_data && saw_rpc && saw_datagram);

        let mut rpc_stream = edge.open_rpc_stream().await.unwrap();
        rpc_stream.write_all(b"pong").await.unwrap();
        rpc_stream.shutdown().await.unwrap();
        edge.send_datagram(Bytes::from_static(b"client-datagram"))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .expect("timed out waiting for fake edge")
            .unwrap();
        edge.close(b"test complete");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quic_session_registers_and_gracefully_unregisters() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let CertifiedKey { cert, key_pair } =
                    generate_simple_self_signed(vec!["localhost".into()])
                        .unwrap();
                let server_tls: InboundTlsOptions =
                    serde_json::from_value(json!({
                        "enabled": true,
                        "certificate": cert.pem(),
                        "key": key_pair.serialize_pem()
                    }))
                    .unwrap();
                let server_tls = build_server_config_with_default_alpn(
                    &server_tls,
                    &[CLOUDFLARED_QUIC_EDGE_ALPN],
                )
                .unwrap();
                let mut server_config = server_config(server_tls).unwrap();
                server_config.transport_config(Arc::new(
                    cloudflared_quic_transport_config(4).unwrap(),
                ));
                let server_endpoint = Endpoint::server(
                    server_config,
                    "127.0.0.1:0".parse().unwrap(),
                )
                .unwrap();
                let server_address = server_endpoint.local_addr().unwrap();
                let unregistered = Arc::new(AtomicBool::new(false));
                let server_unregistered = Arc::clone(&unregistered);

                let server_task = tokio::task::spawn_local(async move {
                    let connection =
                        server_endpoint.accept().await.unwrap().await.unwrap();
                    let (send, recv) = connection.accept_bi().await.unwrap();
                    let stream = CloudflaredQuicStream::new(send, recv);
                    let bootstrap: tunnelrpc::registration_server::Client =
                        capnp_rpc::new_client(QuicRegistrationServer {
                            registered: Arc::new(tokio::sync::Notify::new()),
                            unregistered: server_unregistered,
                        });
                    let (reader, writer) =
                        futures::io::AsyncReadExt::split(stream.compat());
                    let network =
                        Box::new(capnp_rpc::twoparty::VatNetwork::new(
                            futures::io::BufReader::new(reader),
                            futures::io::BufWriter::new(writer),
                            capnp_rpc::rpc_twoparty_capnp::Side::Server,
                            capnp::message::ReaderOptions::new(),
                        ));
                    let rpc = capnp_rpc::RpcSystem::new(
                        network,
                        Some(bootstrap.client),
                    );
                    let _ = rpc.await;
                });

                let edge = CloudflaredQuicEdge::connect(
                    "127.0.0.1:0".parse().unwrap(),
                    server_address,
                    "localhost",
                    test_quic_client_config(),
                    4,
                    CloudflaredIncomingDatagramVersion::V3,
                )
                .await
                .unwrap();
                let session = edge
                    .register(
                        CloudflaredRegistrationOptions {
                            credentials: CloudflaredCredentials {
                                account_tag: "account123".into(),
                                tunnel_secret: b"secret".to_vec(),
                                tunnel_id: Uuid::parse_str(
                                    "550e8400-e29a-41d4-a716-446655440000",
                                )
                                .unwrap(),
                                endpoint: "fed".into(),
                            },
                            connection_index: 2,
                            client_id: vec![3; 16],
                            client_features: vec!["quic".into()],
                            client_version: "singbox-rust-test".into(),
                            client_arch: "test".into(),
                            origin_local_ip: "192.0.2.10".parse().unwrap(),
                            replace_existing: false,
                            compression_quality: 0,
                            previous_attempts: 0,
                        },
                        // Leave enough time for the unregister RPC when the
                        // full test suite is contending for the current-thread
                        // executor. Ten milliseconds made this assertion
                        // scheduler-dependent on slower hosts.
                        Duration::from_millis(250),
                    )
                    .await
                    .unwrap();
                assert_eq!(session.registration_result().location, "LAX");
                assert!(
                    session.registration_result().tunnel_is_remotely_managed
                );

                tokio::time::timeout(
                    Duration::from_secs(3),
                    session.graceful_shutdown(),
                )
                .await
                .expect("timed out shutting down registered QUIC session")
                .unwrap();
                assert!(unregistered.load(Ordering::SeqCst));
                server_task.abort();
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quic_session_serves_events_concurrently_and_drains_on_cancel() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let CertifiedKey { cert, key_pair } =
                    generate_simple_self_signed(vec!["localhost".into()])
                        .unwrap();
                let server_tls: InboundTlsOptions =
                    serde_json::from_value(json!({
                        "enabled": true,
                        "certificate": cert.pem(),
                        "key": key_pair.serialize_pem()
                    }))
                    .unwrap();
                let server_tls = build_server_config_with_default_alpn(
                    &server_tls,
                    &[CLOUDFLARED_QUIC_EDGE_ALPN],
                )
                .unwrap();
                let mut server_config = server_config(server_tls).unwrap();
                server_config.transport_config(Arc::new(
                    cloudflared_quic_transport_config(4).unwrap(),
                ));
                let server_endpoint = Endpoint::server(
                    server_config,
                    "127.0.0.1:0".parse().unwrap(),
                )
                .unwrap();
                let server_address = server_endpoint.local_addr().unwrap();
                let registered = Arc::new(tokio::sync::Notify::new());
                let server_registered = Arc::clone(&registered);
                let unregistered = Arc::new(AtomicBool::new(false));
                let server_unregistered = Arc::clone(&unregistered);

                let server_task = tokio::task::spawn_local(async move {
                    let connection =
                        server_endpoint.accept().await.unwrap().await.unwrap();
                    let (send, recv) = connection.accept_bi().await.unwrap();
                    let stream = CloudflaredQuicStream::new(send, recv);
                    let bootstrap: tunnelrpc::registration_server::Client =
                        capnp_rpc::new_client(QuicRegistrationServer {
                            registered: server_registered,
                            unregistered: server_unregistered,
                        });
                    let (reader, writer) =
                        futures::io::AsyncReadExt::split(stream.compat());
                    let network = Box::new(
                        capnp_rpc::twoparty::VatNetwork::new(
                            futures::io::BufReader::new(reader),
                            futures::io::BufWriter::new(writer),
                            capnp_rpc::rpc_twoparty_capnp::Side::Server,
                            capnp::message::ReaderOptions::new(),
                        ),
                    );
                    let rpc = capnp_rpc::RpcSystem::new(
                        network,
                        Some(bootstrap.client),
                    );
                    let event_connection = connection.clone();
                    tokio::task::spawn_local(async move {
                        registered.notified().await;

                        let (mut data_send, _data_recv) =
                            event_connection.open_bi().await.unwrap();
                        let mut message = capnp::message::Builder::new_default();
                        {
                            let mut request = message.init_root::<
                                metadata_capnp::connect_request::Builder<'_>,
                            >();
                            request.set_dest("tcp://192.0.2.22:443");
                            request.set_type(metadata_capnp::ConnectionType::Tcp);
                            request.init_metadata(0);
                        }
                        let mut wire = crate::protocol::cloudflared::cloudflared_data_stream_prefix().to_vec();
                        capnp::serialize::write_message(&mut wire, &message)
                            .unwrap();
                        data_send.write_all(&wire).await.unwrap();
                        data_send.write_all(b"served-data").await.unwrap();
                        data_send.finish().unwrap();

                        let (mut rpc_send, _rpc_recv) =
                            event_connection.open_bi().await.unwrap();
                        rpc_send
                            .write_all(&CLOUDFLARED_RPC_STREAM_SIGNATURE)
                            .await
                            .unwrap();
                        rpc_send.write_all(b"served-rpc").await.unwrap();
                        rpc_send.finish().unwrap();
                        event_connection
                            .send_datagram(Bytes::from_static(
                                b"served-datagram",
                            ))
                            .unwrap();
                        assert_eq!(
                            event_connection.read_datagram().await.unwrap(),
                            Bytes::from_static(b"handler-response")
                        );
                    });
                    let _ = rpc.await;
                });

                let edge = CloudflaredQuicEdge::connect(
                    "127.0.0.1:0".parse().unwrap(),
                    server_address,
                    "localhost",
                    test_quic_client_config(),
                    4,
                    CloudflaredIncomingDatagramVersion::V3,
                )
                .await
                .unwrap();
                let session = edge
                    .register(
                        CloudflaredRegistrationOptions {
                            credentials: CloudflaredCredentials {
                                account_tag: "account123".into(),
                                tunnel_secret: b"secret".to_vec(),
                                tunnel_id: Uuid::parse_str(
                                    "550e8400-e29a-41d4-a716-446655440000",
                                )
                                .unwrap(),
                                endpoint: "fed".into(),
                            },
                            connection_index: 2,
                            client_id: vec![3; 16],
                            client_features: vec!["quic".into()],
                            client_version: "singbox-rust-test".into(),
                            client_arch: "test".into(),
                            origin_local_ip: "192.0.2.10".parse().unwrap(),
                            replace_existing: false,
                            compression_quality: 0,
                            previous_attempts: 0,
                        },
                        Duration::from_millis(250),
                    )
                    .await
                    .unwrap();
                let recorder = Arc::new(QuicServeRecorder::default());
                let cancellation = CancellationToken::new();
                let serve_task = tokio::task::spawn_local(session.serve(
                    2,
                    recorder.clone(),
                    cancellation.clone(),
                ));
                tokio::time::timeout(
                    Duration::from_secs(3),
                    recorder.wait_complete(),
                )
                .await
                .expect("timed out waiting for concurrent handlers");
                cancellation.cancel();
                tokio::time::timeout(Duration::from_secs(3), serve_task)
                    .await
                    .expect("timed out stopping QUIC serve supervisor")
                    .unwrap()
                    .unwrap();
                assert!(unregistered.load(Ordering::SeqCst));
                server_task.abort();
            })
            .await;
    }

    #[test]
    fn quic_transport_defaults_match_cloudflared() {
        assert_eq!(cloudflared_quic_initial_packet_size(4), 1232);
        assert_eq!(cloudflared_quic_initial_packet_size(6), 1252);
        assert_eq!(
            CLOUDFLARED_QUIC_HANDSHAKE_IDLE_TIMEOUT,
            Duration::from_secs(5)
        );
        assert_eq!(CLOUDFLARED_QUIC_MAX_IDLE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            CLOUDFLARED_QUIC_KEEP_ALIVE_INTERVAL,
            Duration::from_secs(1)
        );
        assert_eq!(CLOUDFLARED_REGISTRATION_TIMEOUT, Duration::from_secs(5));
    }
}
