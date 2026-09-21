//! V2Ray QUIC transport backed by Quinn.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use n0_watcher::Watcher as _;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{DialFuture, Dialer, Stream},
    common::{
        network::SocksAddr,
        quic::PacketUdpSocket,
        tls::{ClientTlsConfig, ServerTlsConfig},
    },
    dns::Resolver,
    option::DomainStrategy,
};

pub struct QuicDialer {
    server: SocksAddr,
    server_name: String,
    tls: ClientTlsConfig,
    resolver: Option<(Arc<dyn Resolver>, DomainStrategy)>,
    packet_dialer: Option<Arc<dyn Dialer>>,
    state: Arc<Mutex<Option<(Endpoint, Connection)>>>,
    network_monitor_started: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

impl QuicDialer {
    pub fn new(
        server: SocksAddr,
        server_name: impl Into<String>,
        tls: ClientTlsConfig,
    ) -> io::Result<Self> {
        Self::new_inner(server, server_name.into(), tls, None, None)
    }

    pub fn new_with_resolver(
        server: SocksAddr,
        server_name: impl Into<String>,
        tls: ClientTlsConfig,
        resolver: Arc<dyn Resolver>,
        strategy: DomainStrategy,
    ) -> io::Result<Self> {
        Self::new_inner(
            server,
            server_name.into(),
            tls,
            Some((resolver, strategy)),
            None,
        )
    }

    pub fn new_with_packet_dialer(
        server: SocksAddr,
        server_name: impl Into<String>,
        tls: ClientTlsConfig,
        packet_dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        Self::new_inner(
            server,
            server_name.into(),
            tls,
            None,
            Some(packet_dialer),
        )
    }

    fn new_inner(
        server: SocksAddr,
        server_name: String,
        tls: ClientTlsConfig,
        resolver: Option<(Arc<dyn Resolver>, DomainStrategy)>,
        packet_dialer: Option<Arc<dyn Dialer>>,
    ) -> io::Result<Self> {
        Ok(Self {
            server,
            server_name,
            tls,
            resolver,
            packet_dialer,
            state: Arc::new(Mutex::new(None)),
            network_monitor_started: Arc::new(AtomicBool::new(false)),
            cancellation: CancellationToken::new(),
        })
    }

    fn ensure_network_monitor(&self) {
        if self
            .network_monitor_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let state = self.state.clone();
        let cancellation = self.cancellation.clone();
        let started = self.network_monitor_started.clone();
        tokio::spawn(async move {
            let Ok(monitor) =
                crate::common::network_monitor::NetworkMonitor::new().await
            else {
                started.store(false, Ordering::Release);
                return;
            };
            let mut watcher = monitor.interface_state();
            let mut previous = watcher.get();
            loop {
                let current = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    current = watcher.updated() => match current {
                        Ok(current) => current,
                        Err(_) => return,
                    },
                };
                let changed = current.is_major_change(&previous);
                previous = current;
                if changed {
                    close_state(&state, b"network changed").await;
                }
            }
        });
    }

    /// Close the cached QUIC connection. The next stream dial performs a new
    /// handshake and re-resolves the server address.
    pub async fn reset(&self) {
        close_state(&self.state, b"session reset").await;
    }

    async fn connection(&self) -> io::Result<Connection> {
        self.ensure_network_monitor();
        let mut state = self.state.lock().await;
        if let Some((_, connection)) = state.as_ref()
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let (mut endpoint, remote) = if let Some(dialer) = &self.packet_dialer {
            let (socket, remote) =
                PacketUdpSocket::connect(dialer.clone(), &self.server).await?;
            (
                Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )?,
                remote,
            )
        } else {
            let remote =
                resolve_server(&self.server, self.resolver.as_ref()).await?;
            let bind = if remote.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            (Endpoint::client(bind)?, remote)
        };
        let tls_config = self
            .tls
            .config_for_handshake()
            .await
            .map_err(io::Error::other)?;
        let crypto =
            QuicClientConfig::try_from(tls_config).map_err(io::Error::other)?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
        let connection = endpoint
            .connect(remote, &self.server_name)
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        *state = Some((endpoint, connection.clone()));
        Ok(connection)
    }
}

async fn close_state(
    state: &Mutex<Option<(Endpoint, Connection)>>,
    reason: &[u8],
) {
    if let Some((endpoint, connection)) = state.lock().await.take() {
        connection.close(0_u32.into(), reason);
        endpoint.close(0_u32.into(), reason);
    }
}

impl Drop for QuicDialer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.state.try_lock()
            && let Some((endpoint, connection)) = state.take()
        {
            connection.close(0_u32.into(), b"");
            endpoint.close(0_u32.into(), b"");
        }
    }
}

impl Dialer for QuicDialer {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let connection = self.connection().await?;
            let (send, recv) =
                connection.open_bi().await.map_err(io::Error::other)?;
            Ok(Box::new(QuicStream {
                send,
                recv,
                _connection: connection,
            }) as Stream)
        })
    }
}

pub fn server_config(tls: ServerTlsConfig) -> io::Result<ServerConfig> {
    let crypto =
        QuicServerConfig::try_from(tls.config).map_err(io::Error::other)?;
    Ok(ServerConfig::with_crypto(Arc::new(crypto)))
}

pub fn server_endpoint(
    tls: ServerTlsConfig,
    address: SocketAddr,
) -> io::Result<Endpoint> {
    Endpoint::server(server_config(tls)?, address)
}

pub type StreamHandler = Arc<
    dyn Fn(Stream, SocketAddr) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

pub async fn accept_loop(
    endpoint: Endpoint,
    cancellation: CancellationToken,
    handler: StreamHandler,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let handler = handler.clone();
                connections.spawn(async move {
                    let connection = incoming.await.map_err(io::Error::other)?;
                    let source = connection.remote_address();
                    let mut streams = JoinSet::new();
                    while let Ok((send, recv)) = connection.accept_bi().await {
                        let stream = boxed_stream(connection.clone(), send, recv);
                        let handler = handler.clone();
                        streams.spawn(async move { handler(stream, source).await });
                    }
                    streams.abort_all();
                    while streams.join_next().await.is_some() {}
                    Ok::<_, io::Error>(())
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    endpoint.close(0_u32.into(), b"");
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    _connection: Connection,
}

pub fn boxed_stream(
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
) -> Stream {
    Box::new(QuicStream {
        send,
        recv,
        _connection: connection,
    })
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

async fn resolve_server(
    server: &SocksAddr,
    resolver: Option<&(Arc<dyn Resolver>, DomainStrategy)>,
) -> io::Result<SocketAddr> {
    match server {
        SocksAddr::Ip(address) => Ok(*address),
        SocksAddr::Domain { host, port } => {
            if let Some((resolver, strategy)) = resolver {
                return resolver
                    .lookup(host, *strategy)
                    .await?
                    .into_iter()
                    .next()
                    .map(|address| SocketAddr::new(address, *port))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "QUIC server {host:?} resolved to no addresses"
                            ),
                        )
                    });
            }
            tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "QUIC server {host:?} resolved to no addresses"
                        ),
                    )
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        common::tls::{
            build_client_config, build_server_config_with_default_alpn,
        },
        option::{InboundTlsOptions, OutboundTlsOptions},
    };

    #[tokio::test]
    async fn quic_dialer_opens_reusable_bidirectional_streams() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_tls: InboundTlsOptions = serde_json::from_value(json!({
            "enabled":true,
            "certificate":cert.pem(),
            "key":key_pair.serialize_pem()
        }))
        .unwrap();
        let server_tls =
            build_server_config_with_default_alpn(&server_tls, &["h3"])
                .unwrap();
        let endpoint = Endpoint::server(
            server_config(server_tls).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_address = endpoint.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let first = endpoint.accept().await.unwrap().await.unwrap();
            for _ in 0..2 {
                let (mut send, mut recv) = first.accept_bi().await.unwrap();
                let mut request = [0_u8; 4];
                recv.read_exact(&mut request).await.unwrap();
                send.write_all(&request).await.unwrap();
            }
            first.closed().await;

            let second = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = second.accept_bi().await.unwrap();
            let mut request = [0_u8; 4];
            recv.read_exact(&mut request).await.unwrap();
            send.write_all(&request).await.unwrap();
            let _ = done_rx.await;
        });
        let client_tls = build_client_config(
            "localhost",
            &OutboundTlsOptions {
                enabled: true,
                insecure: true,
                ..Default::default()
            },
            &["h3"],
        )
        .unwrap();
        let client =
            QuicDialer::new(server_address.into(), "localhost", client_tls)
                .unwrap();
        for _ in 0..2 {
            let mut stream = client
                .dial_tcp(&SocksAddr::new("unused.example", 1))
                .await
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut response = [0_u8; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ping");
        }
        client.reset().await;
        let mut stream = client
            .dial_tcp(&SocksAddr::new("unused.example", 1))
            .await
            .unwrap();
        stream.write_all(b"next").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"next");
        let _ = done_tx.send(());
        server.await.unwrap();
    }
}
