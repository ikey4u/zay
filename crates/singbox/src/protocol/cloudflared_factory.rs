//! Standard Cloudflare edge connection construction for the HA supervisor.

use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};

use super::{
    cloudflared::{
        CLOUDFLARED_HTTP2_EDGE_SNI, CLOUDFLARED_QUIC_EDGE_ALPN,
        CLOUDFLARED_QUIC_EDGE_SNI, CloudflaredConfigurationApplier,
        CloudflaredError, CloudflaredIncomingDatagramVersion,
        CloudflaredRegistrationOptions, CloudflaredTransportProtocol,
    },
    cloudflared_http2::{CloudflaredHttp2Connection, CloudflaredHttp2Handler},
    cloudflared_quic::{
        CLOUDFLARED_QUIC_HANDSHAKE_IDLE_TIMEOUT, CloudflaredQuicEdge,
        CloudflaredQuicHandler, cloudflared_quic_transport_config,
    },
    cloudflared_supervisor::{
        CloudflaredConnectionAttempt, CloudflaredConnectionFactory,
        CloudflaredManagedConnection, CloudflaredQuicManagedConnection,
    },
};
use crate::{
    adapter::{Dialer, stream_local_addr},
    common::{
        network::SocksAddr,
        quic::PacketUdpSocket,
        tls::{ClientTlsConfig, build_client_config},
    },
    option::{CurvePreference, Listable, OutboundTlsOptions},
};

pub const CLOUDFLARED_EDGE_TLS_HANDSHAKE_TIMEOUT: Duration =
    Duration::from_secs(15);
pub const CLOUDFLARED_POST_QUANTUM_FEATURE: &str = "postquantum";
pub const CLOUDFLARED_ROOT_CA_PEM: &str = include_str!("cloudflare_ca.pem");

/// Supplies the datagram wire version and registration feature list for each
/// new edge connection. Cloudflare's remotely controlled rollout can change
/// this snapshot while existing HA connections remain alive.
pub trait CloudflaredConnectionFeatureSelector: Send + Sync + 'static {
    fn snapshot(&self) -> (CloudflaredIncomingDatagramVersion, Vec<String>);
}

#[derive(Clone)]
pub struct CloudflaredEdgeTlsConfigs {
    pub quic: ClientTlsConfig,
    pub http2: ClientTlsConfig,
}

pub fn cloudflared_edge_tls_configs(
    post_quantum: bool,
) -> Result<CloudflaredEdgeTlsConfigs, CloudflaredError> {
    cloudflared_edge_tls_configs_with_clock(post_quantum, None)
}

fn cloudflared_edge_tls_configs_with_clock(
    post_quantum: bool,
    ntp_clock: Option<crate::common::ntp::NtpClock>,
) -> Result<CloudflaredEdgeTlsConfigs, CloudflaredError> {
    Ok(CloudflaredEdgeTlsConfigs {
        quic: cloudflared_edge_tls_config(
            CLOUDFLARED_QUIC_EDGE_SNI,
            &[CLOUDFLARED_QUIC_EDGE_ALPN],
            post_quantum,
            ntp_clock.clone(),
        )?,
        http2: cloudflared_edge_tls_config(
            CLOUDFLARED_HTTP2_EDGE_SNI,
            &[],
            false,
            ntp_clock,
        )?,
    })
}

fn cloudflared_edge_tls_config(
    server_name: &str,
    alpn: &[&str],
    post_quantum: bool,
    ntp_clock: Option<crate::common::ntp::NtpClock>,
) -> Result<ClientTlsConfig, CloudflaredError> {
    let curve = if post_quantum {
        CurvePreference::X25519MlKem768
    } else {
        CurvePreference::P256
    };
    build_client_config(
        server_name,
        &OutboundTlsOptions {
            enabled: true,
            server_name: server_name.into(),
            certificate: Listable(vec![CLOUDFLARED_ROOT_CA_PEM.into()]),
            curve_preferences: Listable(vec![curve]),
            ntp_clock,
            ..Default::default()
        },
        alpn,
    )
    .map_err(|error| {
        CloudflaredError::Transport(format!(
            "build Cloudflare edge TLS config: {error}"
        ))
    })
}

pub struct CloudflaredEdgeConnectionFactory {
    tunnel_dialer: Arc<dyn Dialer>,
    registration_options: CloudflaredRegistrationOptions,
    grace_period: Duration,
    datagram_version: CloudflaredIncomingDatagramVersion,
    feature_selector: Option<Arc<dyn CloudflaredConnectionFeatureSelector>>,
    tls: CloudflaredEdgeTlsConfigs,
    quic_handler: Arc<dyn CloudflaredQuicHandler>,
    http2_handler: Arc<dyn CloudflaredHttp2Handler>,
    configuration: Arc<dyn CloudflaredConfigurationApplier>,
}

impl CloudflaredEdgeConnectionFactory {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tunnel_dialer: Arc<dyn Dialer>,
        registration_options: CloudflaredRegistrationOptions,
        grace_period: Duration,
        datagram_version: CloudflaredIncomingDatagramVersion,
        post_quantum: bool,
        quic_handler: Arc<dyn CloudflaredQuicHandler>,
        http2_handler: Arc<dyn CloudflaredHttp2Handler>,
        configuration: Arc<dyn CloudflaredConfigurationApplier>,
    ) -> Result<Self, CloudflaredError> {
        Self::new_with_clock(
            tunnel_dialer,
            registration_options,
            grace_period,
            datagram_version,
            post_quantum,
            quic_handler,
            http2_handler,
            configuration,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_clock(
        tunnel_dialer: Arc<dyn Dialer>,
        registration_options: CloudflaredRegistrationOptions,
        grace_period: Duration,
        datagram_version: CloudflaredIncomingDatagramVersion,
        post_quantum: bool,
        quic_handler: Arc<dyn CloudflaredQuicHandler>,
        http2_handler: Arc<dyn CloudflaredHttp2Handler>,
        configuration: Arc<dyn CloudflaredConfigurationApplier>,
        ntp_clock: Option<crate::common::ntp::NtpClock>,
    ) -> Result<Self, CloudflaredError> {
        Ok(Self {
            tunnel_dialer,
            registration_options,
            grace_period,
            datagram_version,
            feature_selector: None,
            tls: cloudflared_edge_tls_configs_with_clock(
                post_quantum,
                ntp_clock,
            )?,
            quic_handler,
            http2_handler,
            configuration,
        })
    }

    pub fn with_feature_selector(
        mut self,
        selector: Arc<dyn CloudflaredConnectionFeatureSelector>,
    ) -> Self {
        self.feature_selector = Some(selector);
        self
    }

    fn registration_snapshot(
        &self,
    ) -> (
        CloudflaredRegistrationOptions,
        CloudflaredIncomingDatagramVersion,
    ) {
        let mut registration_options = self.registration_options.clone();
        let datagram_version = if let Some(selector) = &self.feature_selector {
            let (version, features) = selector.snapshot();
            registration_options.client_features = features;
            version
        } else {
            self.datagram_version
        };
        (registration_options, datagram_version)
    }

    /// Replace production edge trust for a private edge or deterministic test.
    pub fn with_tls_configs(mut self, tls: CloudflaredEdgeTlsConfigs) -> Self {
        self.tls = tls;
        self
    }

    async fn connect_quic(
        &self,
        attempt: CloudflaredConnectionAttempt,
        mut registration_options: CloudflaredRegistrationOptions,
        datagram_version: CloudflaredIncomingDatagramVersion,
    ) -> Result<Box<dyn CloudflaredManagedConnection>, CloudflaredError> {
        let destination = SocksAddr::Ip(attempt.edge.address);
        let (socket, remote) = PacketUdpSocket::connect(
            Arc::clone(&self.tunnel_dialer),
            &destination,
        )
        .await
        .map_err(|error| {
            CloudflaredError::Transport(format!(
                "dial UDP for QUIC edge: {error}"
            ))
        })?;
        let tls_config = self
            .tls
            .quic
            .config_for_handshake()
            .await
            .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
        let crypto = QuicClientConfig::try_from(tls_config)
            .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
        let mut client_config = ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(
            cloudflared_quic_transport_config(attempt.edge.ip_version)?,
        ));
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| CloudflaredError::Transport(error.to_string()))?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(remote, CLOUDFLARED_QUIC_EDGE_SNI)
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
        registration_options.origin_local_ip = endpoint
            .local_addr()
            .map_err(|error| CloudflaredError::Transport(error.to_string()))?
            .ip();
        let edge = CloudflaredQuicEdge::from_connection(
            endpoint,
            connection,
            datagram_version,
        );
        let session = edge
            .register(registration_options, self.grace_period)
            .await?;
        Ok(Box::new(CloudflaredQuicManagedConnection::new(
            session,
            attempt.connection_index,
            Arc::clone(&self.quic_handler),
        )))
    }

    async fn connect_http2(
        &self,
        attempt: CloudflaredConnectionAttempt,
        mut registration_options: CloudflaredRegistrationOptions,
    ) -> Result<Box<dyn CloudflaredManagedConnection>, CloudflaredError> {
        let destination = SocksAddr::Ip(attempt.edge.address);
        let stream = self.tunnel_dialer.dial_tcp(&destination).await.map_err(
            |error| {
                CloudflaredError::Transport(format!(
                    "dial HTTP/2 edge TCP: {error}"
                ))
            },
        )?;
        registration_options.origin_local_ip = stream_local_addr(&stream)
            .map_err(|error| CloudflaredError::Transport(error.to_string()))?
            .map(|address| address.ip())
            .unwrap_or_else(|| {
                if attempt.edge.ip_version == 6 {
                    IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                }
            });
        let stream = self
            .tls
            .http2
            .connect_stream_with_timeout(
                stream,
                Some(CLOUDFLARED_EDGE_TLS_HANDSHAKE_TIMEOUT),
            )
            .await
            .map_err(|error| {
                CloudflaredError::Transport(format!(
                    "HTTP/2 edge TLS handshake: {error}"
                ))
            })?
            .into_stream();
        Ok(Box::new(CloudflaredHttp2Connection::new(
            stream,
            attempt.connection_index,
            registration_options,
            self.grace_period,
            Arc::clone(&self.http2_handler),
            Arc::clone(&self.configuration),
        )))
    }
}

#[async_trait(?Send)]
impl CloudflaredConnectionFactory for CloudflaredEdgeConnectionFactory {
    async fn connect(
        &self,
        attempt: CloudflaredConnectionAttempt,
    ) -> Result<Box<dyn CloudflaredManagedConnection>, CloudflaredError> {
        let (mut registration_options, datagram_version) =
            self.registration_snapshot();
        registration_options.connection_index = attempt.connection_index;
        registration_options.previous_attempts = attempt.previous_attempts;
        match attempt.protocol {
            CloudflaredTransportProtocol::Quic => {
                self.connect_quic(
                    attempt,
                    registration_options,
                    datagram_version,
                )
                .await
            }
            CloudflaredTransportProtocol::Http2 => {
                self.connect_http2(attempt, registration_options).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{Method, Request, StatusCode};
    use http_body_util::{BodyExt as _, Full};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use serde_json::json;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::*;
    use crate::{
        adapter::{DialFuture, Stream},
        common::tls::build_server_config_with_default_alpn,
        option::InboundTlsOptions,
        protocol::{
            cloudflared::{
                CloudflaredConfigurationUpdate, CloudflaredConnectRequest,
                CloudflaredCredentials, CloudflaredMetadata,
            },
            cloudflared_http2::{
                CloudflaredHttp2ResponseWriter, CloudflaredHttp2Stream,
            },
            cloudflared_quic::{
                CloudflaredQuicDatagramSender, CloudflaredQuicStream,
            },
        },
    };

    #[test]
    fn production_tls_configs_pin_edge_names_curves_alpn_and_ca_bundle() {
        let classical = cloudflared_edge_tls_configs(false).unwrap();
        assert_eq!(
            classical.quic.server_name.to_str(),
            CLOUDFLARED_QUIC_EDGE_SNI
        );
        assert_eq!(
            classical.quic.config.alpn_protocols,
            vec![CLOUDFLARED_QUIC_EDGE_ALPN.as_bytes()]
        );
        assert_eq!(
            classical.http2.server_name.to_str(),
            CLOUDFLARED_HTTP2_EDGE_SNI
        );
        assert!(classical.http2.config.alpn_protocols.is_empty());
        assert_eq!(
            CLOUDFLARED_ROOT_CA_PEM.matches("BEGIN CERTIFICATE").count(),
            3
        );

        let post_quantum = cloudflared_edge_tls_configs(true).unwrap();
        assert_eq!(
            post_quantum.quic.config.alpn_protocols,
            vec![CLOUDFLARED_QUIC_EDGE_ALPN.as_bytes()]
        );
    }

    struct LoopbackDialer(std::net::SocketAddr);

    impl Dialer for LoopbackDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                Ok(Box::new(TcpStream::connect(self.0).await?) as Stream)
            })
        }
    }

    #[derive(Default)]
    struct FactoryHandler;

    #[async_trait]
    impl CloudflaredHttp2Handler for FactoryHandler {
        async fn dispatch_request(
            &self,
            _stream: CloudflaredHttp2Stream,
            response: CloudflaredHttp2ResponseWriter,
            _request: CloudflaredConnectRequest,
        ) {
            response
                .write_response(
                    None,
                    &[CloudflaredMetadata {
                        key: "HttpStatus".into(),
                        value: "204".into(),
                    }],
                )
                .unwrap();
        }
    }

    #[async_trait]
    impl CloudflaredQuicHandler for FactoryHandler {
        async fn handle_data_stream(
            &self,
            _stream: CloudflaredQuicStream,
            _request: CloudflaredConnectRequest,
            _connection_index: u8,
        ) {
        }

        async fn handle_rpc_stream(
            &self,
            _stream: CloudflaredQuicStream,
            _connection_index: u8,
            _sender: CloudflaredQuicDatagramSender,
        ) {
        }

        async fn handle_datagram(
            &self,
            _datagram: Bytes,
            _sender: CloudflaredQuicDatagramSender,
        ) {
        }
    }

    impl CloudflaredConfigurationApplier for FactoryHandler {
        fn apply_configuration(
            &self,
            version: i32,
            _configuration: &[u8],
        ) -> CloudflaredConfigurationUpdate {
            CloudflaredConfigurationUpdate {
                latest_applied_version: version,
                error: None,
            }
        }
    }

    fn registration_options() -> CloudflaredRegistrationOptions {
        CloudflaredRegistrationOptions {
            credentials: CloudflaredCredentials {
                account_tag: "account".into(),
                tunnel_secret: vec![1; 32],
                tunnel_id: Uuid::nil(),
                endpoint: String::new(),
            },
            connection_index: 0,
            client_id: vec![2; 16],
            client_features: vec![],
            client_version: "test".into(),
            client_arch: "test".into(),
            origin_local_ip: "0.0.0.0".parse().unwrap(),
            replace_existing: false,
            compression_quality: 0,
            previous_attempts: 0,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn factory_dials_real_tcp_tls_and_serves_http2() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let CertifiedKey { cert, key_pair } =
                    generate_simple_self_signed(vec![
                        CLOUDFLARED_HTTP2_EDGE_SNI.into(),
                    ])
                    .unwrap();
                let server_options: InboundTlsOptions =
                    serde_json::from_value(json!({
                        "enabled": true,
                        "certificate": cert.pem(),
                        "key": key_pair.serialize_pem(),
                    }))
                    .unwrap();
                let server_tls =
                    build_server_config_with_default_alpn(&server_options, &[])
                        .unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let (sender_tx, sender_rx) = tokio::sync::oneshot::channel();
                let edge_task = tokio::spawn(async move {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let tls = TlsAcceptor::from(server_tls.config)
                        .accept(tcp)
                        .await
                        .unwrap();
                    let (sender, connection) =
                        hyper::client::conn::http2::handshake(
                            TokioExecutor::new(),
                            TokioIo::new(tls),
                        )
                        .await
                        .unwrap();
                    sender_tx.send(sender).unwrap();
                    let _ = connection.await;
                });

                let client_tls = build_client_config(
                    CLOUDFLARED_HTTP2_EDGE_SNI,
                    &OutboundTlsOptions {
                        enabled: true,
                        server_name: CLOUDFLARED_HTTP2_EDGE_SNI.into(),
                        certificate: Listable(vec![cert.pem()]),
                        curve_preferences: Listable(vec![
                            CurvePreference::P256,
                        ]),
                        ..Default::default()
                    },
                    &[],
                )
                .unwrap();
                let production_tls =
                    cloudflared_edge_tls_configs(false).unwrap();
                let handler = Arc::new(FactoryHandler);
                let factory = CloudflaredEdgeConnectionFactory::new(
                    Arc::new(LoopbackDialer(address)),
                    registration_options(),
                    Duration::from_secs(1),
                    CloudflaredIncomingDatagramVersion::V2,
                    false,
                    handler.clone(),
                    handler.clone(),
                    handler,
                )
                .unwrap()
                .with_tls_configs(CloudflaredEdgeTlsConfigs {
                    quic: production_tls.quic,
                    http2: client_tls,
                });
                let connection = factory
                    .connect(CloudflaredConnectionAttempt {
                        connection_index: 3,
                        edge:
                            super::super::cloudflared::CloudflaredEdgeAddress {
                                address: "192.0.2.1:7844".parse().unwrap(),
                                ip_version: 4,
                            },
                        protocol: CloudflaredTransportProtocol::Http2,
                        previous_attempts: 2,
                    })
                    .await
                    .unwrap();
                let cancellation = CancellationToken::new();
                let serve_cancellation = cancellation.clone();
                let serve_task = tokio::task::spawn_local(async move {
                    connection
                        .serve(
                            serve_cancellation,
                            Arc::new(tokio::sync::Notify::new()),
                        )
                        .await
                });
                let mut sender = sender_rx.await.unwrap();
                let response = sender
                    .send_request(
                        Request::builder()
                            .method(Method::GET)
                            .uri("https://origin.example/test")
                            .header("host", "origin.example")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
                assert!(
                    response.collect().await.unwrap().to_bytes().is_empty()
                );

                cancellation.cancel();
                serve_task.await.unwrap().unwrap();
                drop(sender);
                edge_task.await.unwrap();
            })
            .await;
    }
}
