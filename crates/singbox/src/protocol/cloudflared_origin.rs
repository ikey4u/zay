//! Cloudflare Tunnel edge requests dispatched into the embedding router.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use async_compression::tokio::bufread::GzipDecoder;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha1::{Digest, Sha1};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite,
    AsyncWriteExt, BufReader, ReadBuf,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};

use super::{
    cloudflared::{
        CLOUDFLARED_METADATA_HTTP_HOST, CLOUDFLARED_METADATA_HTTP_STATUS,
        CloudflaredConnectRequest, CloudflaredConnectionType,
        CloudflaredMetadata, cloudflared_flow_connect_rate_limited_metadata,
        cloudflared_metadata_map, encode_cloudflared_connect_response,
    },
    cloudflared_access::{
        CLOUDFLARED_ACCESS_JWT_ASSERTION_HEADER, CloudflaredAccessValidator,
        cloudflared_access_validator_key,
    },
    cloudflared_datagram::CloudflaredDatagramService,
    cloudflared_http2::{
        CloudflaredHttp2Handler, CloudflaredHttp2ResponseWriter,
        CloudflaredHttp2Stream,
    },
    cloudflared_ingress::{
        CloudflaredConfigManager, CloudflaredIpRulePolicy,
        CloudflaredResolvedService, CloudflaredResolvedServiceKind,
    },
    cloudflared_quic::{
        CloudflaredQuicDatagramSender, CloudflaredQuicHandler,
        CloudflaredQuicStream,
    },
};
use crate::{
    adapter::{Dialer, Stream},
    common::{
        certificate_store::CertificateStore, network::SocksAddr, ntp::NtpClock,
        tls::build_client_config,
    },
    option::OutboundTlsOptions,
};

enum ConnectResponse {
    Quic,
    Http2(CloudflaredHttp2ResponseWriter),
    #[cfg(test)]
    Capture(CapturedResponses),
}

#[cfg(test)]
type CapturedResponses =
    Arc<std::sync::Mutex<Vec<(Option<String>, Vec<CloudflaredMetadata>)>>>;

impl ConnectResponse {
    async fn write<W>(
        &self,
        writer: &mut W,
        response_error: Option<&str>,
        metadata: &[CloudflaredMetadata],
    ) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Self::Quic => {
                writer
                    .write_all(
                        &encode_cloudflared_connect_response(
                            response_error,
                            metadata,
                        )
                        .map_err(io::Error::other)?,
                    )
                    .await
            }
            Self::Http2(response) => response
                .write_response(response_error, metadata)
                .map_err(io::Error::other),
            #[cfg(test)]
            Self::Capture(responses) => {
                responses.lock().expect("response lock poisoned").push((
                    response_error.map(str::to_owned),
                    metadata.to_vec(),
                ));
                Ok(())
            }
        }
    }

    fn add_trailers(&self, trailers: &http::HeaderMap) {
        if let Self::Http2(response) = self {
            for (name, value) in trailers {
                response.add_trailer(name.clone(), value.clone());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        adapter::{DialFuture, Dialer},
        protocol::cloudflared::{
            CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED,
            CLOUDFLARED_METADATA_HTTP_HOST,
        },
    };

    struct MemoryDialer {
        origin: Mutex<Option<tokio::io::DuplexStream>>,
    }

    impl Dialer for MemoryDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                self.origin
                    .lock()
                    .expect("origin lock poisoned")
                    .take()
                    .map(|stream| Box::new(stream) as crate::adapter::Stream)
                    .ok_or_else(|| io::Error::other("origin already dialed"))
            })
        }
    }

    #[tokio::test]
    async fn tcp_dispatch_bridges_both_directions_and_tracks_flow() {
        let (edge_service, mut edge_client) = tokio::io::duplex(4096);
        let (origin_service, mut origin_peer) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let service = Arc::new(CloudflaredOriginService::new(
            Arc::new(CloudflaredConfigManager::new()),
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        ));
        let task = {
            let service = service.clone();
            let responses = responses.clone();
            tokio::spawn(async move {
                service
                    .dispatch(
                        edge_service,
                        ConnectResponse::Capture(responses),
                        CloudflaredConnectRequest {
                            destination: "origin.example:443".into(),
                            connection_type: CloudflaredConnectionType::Tcp,
                            metadata: vec![],
                        },
                    )
                    .await;
            })
        };

        edge_client.write_all(b"from-edge").await.unwrap();
        let mut from_edge = [0; 9];
        origin_peer.read_exact(&mut from_edge).await.unwrap();
        assert_eq!(&from_edge, b"from-edge");
        origin_peer.write_all(b"from-origin").await.unwrap();
        let mut from_origin = [0; 11];
        edge_client.read_exact(&mut from_origin).await.unwrap();
        assert_eq!(&from_origin, b"from-origin");
        assert_eq!(service.active_flows(), 1);

        drop(edge_client);
        drop(origin_peer);
        task.await.unwrap();
        assert_eq!(service.active_flows(), 0);
        let responses = responses.lock().unwrap();
        assert_eq!(responses.as_slice(), &[(None, vec![])]);
    }

    #[tokio::test]
    async fn default_ingress_returns_status_503() {
        let (edge_service, edge_client) = tokio::io::duplex(256);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let service = CloudflaredOriginService::new(
            Arc::new(CloudflaredConfigManager::new()),
            Arc::new(MemoryDialer {
                origin: Mutex::new(None),
            }),
        );
        service
            .dispatch(
                edge_service,
                ConnectResponse::Capture(responses.clone()),
                CloudflaredConnectRequest {
                    destination: "https://example.com/path".into(),
                    connection_type: CloudflaredConnectionType::Http,
                    metadata: vec![CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                        value: "example.com".into(),
                    }],
                },
            )
            .await;
        drop(edge_client);
        let responses = responses.lock().unwrap();
        assert_eq!(responses[0].0, None);
        assert_eq!(responses[0].1[0].key, CLOUDFLARED_METADATA_HTTP_STATUS);
        assert_eq!(responses[0].1[0].value, "503");
    }

    #[tokio::test]
    async fn rate_limit_metadata_is_returned_without_dialing() {
        let config = Arc::new(CloudflaredConfigManager::new());
        config.apply(
            1,
            br#"{"ingress":[{"service":"http_status:503"}],"warp-routing":{"enabled":true,"maxActiveFlows":1}}"#,
        );
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(None),
            }),
        );
        service.active_flows.store(1, Ordering::Release);
        let (edge_service, edge_client) = tokio::io::duplex(256);
        let responses = Arc::new(Mutex::new(Vec::new()));
        service
            .dispatch(
                edge_service,
                ConnectResponse::Capture(responses.clone()),
                CloudflaredConnectRequest {
                    destination: "example.com:443".into(),
                    connection_type: CloudflaredConnectionType::Tcp,
                    metadata: vec![],
                },
            )
            .await;
        drop(edge_client);
        let responses = responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0.as_deref(), Some("too many active flows"));
        assert_eq!(
            responses[0].1[0].key,
            CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED
        );
    }

    #[tokio::test]
    async fn http_origin_streams_request_and_response_through_dialer() {
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        );
        std::io::Write::write_all(&mut encoder, b"pong!").unwrap();
        let compressed_response = encoder.finish().unwrap();
        let config = Arc::new(CloudflaredConfigManager::new());
        let update = config.apply(
            1,
            br#"{"originRequest":{"httpHostHeader":"rewritten.internal"},"ingress":[{"hostname":"public.example","service":"http://origin.test:8080"},{"service":"http_status:404"}]}"#,
        );
        assert_eq!(update.error, None);
        let (origin_service, mut origin_peer) = tokio::io::duplex(4096);
        let origin_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                origin_peer.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let mut body = [0_u8; 4];
            origin_peer.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"ping");
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("POST /api?q=1 HTTP/1.1\r\n"));
            assert!(request.contains("host: rewritten.internal\r\n"));
            assert!(request.contains("x-forwarded-host: public.example\r\n"));
            assert!(request.contains("x-test: edge\r\n"));
            assert!(request.contains("accept-encoding: gzip\r\n"));
            origin_peer
                .write_all(
                    format!(
                        "HTTP/1.1 201 Created\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nX-Origin: yes\r\n\r\n",
                        compressed_response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            origin_peer.write_all(&compressed_response).await.unwrap();
        });
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        );
        let (edge_service, mut edge_client) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://public.example/api?q=1".into(),
                connection_type: CloudflaredConnectionType::Http,
                metadata: vec![
                    CloudflaredMetadata {
                        key: super::super::cloudflared::CLOUDFLARED_METADATA_HTTP_METHOD.into(),
                        value: "POST".into(),
                    },
                    CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                        value: "public.example".into(),
                    },
                    CloudflaredMetadata {
                        key: "HttpHeader:Content-Length".into(),
                        value: "4".into(),
                    },
                    CloudflaredMetadata {
                        key: "HttpHeader:X-Test".into(),
                        value: "edge".into(),
                    },
                ],
            },
        );
        let client = async {
            edge_client.write_all(b"ping").await.unwrap();
            edge_client.shutdown().await.unwrap();
            let mut body = Vec::new();
            edge_client.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"pong!");
        };
        tokio::join!(dispatch, client);
        origin_task.await.unwrap();
        let responses = responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0, None);
        assert!(responses[0].1.iter().any(|entry| {
            entry.key == CLOUDFLARED_METADATA_HTTP_STATUS
                && entry.value == "201"
        }));
        assert!(responses[0].1.iter().any(|entry| {
            entry.key.eq_ignore_ascii_case("HttpHeader:x-origin")
                && entry.value == "yes"
        }));
        assert!(!responses[0].1.iter().any(|entry| {
            entry
                .key
                .eq_ignore_ascii_case("HttpHeader:content-encoding")
                || entry.key.eq_ignore_ascii_case("HttpHeader:content-length")
        }));
    }

    #[tokio::test]
    async fn websocket_origin_upgrades_and_bridges_raw_edge_stream() {
        let config = Arc::new(CloudflaredConfigManager::new());
        let update = config.apply(
            1,
            br#"{"ingress":[{"hostname":"ws.example","service":"ws://origin.test:8080"},{"service":"http_status:404"}]}"#,
        );
        assert_eq!(update.error, None);
        let (origin_service, mut origin_peer) = tokio::io::duplex(4096);
        let origin_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                origin_peer.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /socket HTTP/1.1\r\n"));
            assert!(request.contains("connection: Upgrade\r\n"));
            assert!(request.contains("upgrade: websocket\r\n"));
            origin_peer
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();
            let mut payload = [0_u8; 4];
            origin_peer.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            origin_peer.write_all(b"pong").await.unwrap();
            origin_peer.shutdown().await.unwrap();
        });
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        );
        let (edge_service, mut edge_client) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://ws.example/socket".into(),
                connection_type: CloudflaredConnectionType::Websocket,
                metadata: vec![
                    CloudflaredMetadata {
                        key: super::super::cloudflared::CLOUDFLARED_METADATA_HTTP_METHOD.into(),
                        value: "GET".into(),
                    },
                    CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                        value: "ws.example".into(),
                    },
                ],
            },
        );
        let client = async {
            edge_client.write_all(b"ping").await.unwrap();
            let mut response = [0_u8; 4];
            edge_client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");
            edge_client.shutdown().await.unwrap();
        };
        tokio::join!(dispatch, client);
        origin_task.await.unwrap();
        let responses = responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        assert!(responses[0].1.iter().any(|entry| {
            entry.key == CLOUDFLARED_METADATA_HTTP_STATUS
                && entry.value == "101"
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_http_origin_uses_configured_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("origin.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut origin, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                origin.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with("GET /unix HTTP/1.1\r\n")
            );
            origin
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nunix")
                .await
                .unwrap();
        });
        let config = Arc::new(CloudflaredConfigManager::new());
        let configuration = serde_json::json!({
            "ingress": [
                {
                    "hostname": "unix.example",
                    "service": format!("unix:{}", socket_path.display()),
                },
                { "service": "http_status:404" },
            ],
        });
        assert_eq!(
            config
                .apply(1, &serde_json::to_vec(&configuration).unwrap())
                .error,
            None
        );
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(None),
            }),
        );
        let (edge_service, mut edge_client) = tokio::io::duplex(1024);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://unix.example/unix".into(),
                connection_type: CloudflaredConnectionType::Http,
                metadata: vec![CloudflaredMetadata {
                    key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                    value: "unix.example".into(),
                }],
            },
        );
        let client = async {
            edge_client.shutdown().await.unwrap();
            let mut body = Vec::new();
            edge_client.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"unix");
        };
        tokio::join!(dispatch, client);
        origin_task.await.unwrap();
        assert_eq!(responses.lock().unwrap()[0].0, None);
    }

    #[tokio::test]
    async fn https_origin_negotiates_http2_and_streams_body() {
        use http_body_util::Full;
        use hyper::service::service_fn;
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rustls::{
            ServerConfig,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use tokio_rustls::TlsAcceptor;

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let (origin_service, origin_peer) = tokio::io::duplex(16 * 1024);
        let origin_task =
            tokio::spawn(async move {
                let origin = acceptor.accept(origin_peer).await.unwrap();
                let _ = hyper::server::conn::http2::Builder::new(
                    TokioExecutor::new(),
                )
                .serve_connection(
                    TokioIo::new(origin),
                    service_fn(|request: Request<Incoming>| async move {
                        assert_eq!(request.version(), http::Version::HTTP_2);
                        assert_eq!(request.uri().path(), "/h2");
                        let body = request
                            .into_body()
                            .collect()
                            .await
                            .unwrap()
                            .to_bytes();
                        assert_eq!(body.as_ref(), b"request");
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(202)
                                .header("x-protocol", "h2")
                                .body(Full::new(Bytes::from_static(
                                    b"response",
                                )))
                                .unwrap(),
                        )
                    }),
                )
                .await;
            });
        let config = Arc::new(CloudflaredConfigManager::new());
        assert_eq!(
            config
                .apply(
                    1,
                    br#"{"originRequest":{"noTLSVerify":true,"http2Origin":true},"ingress":[{"hostname":"h2.example","service":"https://localhost:443"},{"service":"http_status:404"}]}"#,
                )
                .error,
            None
        );
        let configured = config.resolve("h2.example", "/h2").unwrap();
        assert!(configured.origin_request.no_tls_verify);
        assert!(configured.origin_request.http2_origin);
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        );
        let (edge_service, mut edge_client) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://h2.example/h2".into(),
                connection_type: CloudflaredConnectionType::Http,
                metadata: vec![
                    CloudflaredMetadata {
                        key: super::super::cloudflared::CLOUDFLARED_METADATA_HTTP_METHOD.into(),
                        value: "POST".into(),
                    },
                    CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                        value: "h2.example".into(),
                    },
                    CloudflaredMetadata {
                        key: "HttpHeader:Content-Length".into(),
                        value: "7".into(),
                    },
                ],
            },
        );
        let client = async {
            edge_client.write_all(b"request").await.unwrap();
            edge_client.shutdown().await.unwrap();
            let mut body = Vec::new();
            edge_client.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"response");
        };
        tokio::join!(dispatch, client);
        origin_task.await.unwrap();
        let responses = responses.lock().unwrap();
        assert!(responses[0].1.iter().any(|entry| {
            entry.key == CLOUDFLARED_METADATA_HTTP_STATUS
                && entry.value == "202"
        }));
        assert!(responses[0].1.iter().any(|entry| {
            entry.key.eq_ignore_ascii_case("HttpHeader:x-protocol")
                && entry.value == "h2"
        }));
    }

    #[tokio::test]
    async fn stream_service_bridges_websocket_frames_to_raw_origin() {
        let config = Arc::new(CloudflaredConfigManager::new());
        assert_eq!(
            config
                .apply(
                    1,
                    br#"{"ingress":[{"hostname":"stream.example","service":"tcp://origin.test:1234"},{"service":"http_status:404"}]}"#,
                )
                .error,
            None
        );
        let (origin_service, mut origin_peer) = tokio::io::duplex(4096);
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        );
        let (edge_service, edge_client) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://stream.example/tunnel".into(),
                connection_type: CloudflaredConnectionType::Websocket,
                metadata: vec![
                    CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                        value: "stream.example".into(),
                    },
                    CloudflaredMetadata {
                        key: "HttpHeader:Sec-WebSocket-Key".into(),
                        value: "dGhlIHNhbXBsZSBub25jZQ==".into(),
                    },
                ],
            },
        );
        let client = async move {
            let mut websocket = WebSocketStream::from_raw_socket(
                edge_client,
                Role::Client,
                None,
            )
            .await;
            websocket
                .send(Message::Binary(b"from-edge".to_vec().into()))
                .await
                .unwrap();
            let mut from_edge = [0_u8; 9];
            origin_peer.read_exact(&mut from_edge).await.unwrap();
            assert_eq!(&from_edge, b"from-edge");
            origin_peer.write_all(b"from-origin").await.unwrap();
            let message = websocket.next().await.unwrap().unwrap();
            assert_eq!(message.into_data(), b"from-origin".as_slice());
            websocket.close(None).await.unwrap();
        };
        tokio::join!(dispatch, client);
        let responses = responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        assert!(responses[0].1.iter().any(|entry| {
            entry
                .key
                .eq_ignore_ascii_case("HttpHeader:Sec-WebSocket-Accept")
                && entry.value == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        }));
    }

    #[tokio::test]
    async fn socks_proxy_service_enforces_policy_and_tunnels_websocket() {
        let config = Arc::new(CloudflaredConfigManager::new());
        assert_eq!(
            config
                .apply(
                    1,
                    br#"{"originRequest":{"ipRules":[{"prefix":"127.0.0.0/8","ports":[53],"allow":true}]},"ingress":[{"hostname":"socks.example","service":"socks-proxy"},{"service":"http_status:404"}]}"#,
                )
                .error,
            None
        );
        let (origin_service, mut origin_peer) = tokio::io::duplex(4096);
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        );
        let (edge_service, edge_client) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://socks.example/".into(),
                connection_type: CloudflaredConnectionType::Websocket,
                metadata: vec![CloudflaredMetadata {
                    key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                    value: "socks.example".into(),
                }],
            },
        );
        let client = async move {
            let mut websocket = WebSocketStream::from_raw_socket(
                edge_client,
                Role::Client,
                None,
            )
            .await;
            websocket
                .send(Message::Binary(vec![5, 1, 0].into()))
                .await
                .unwrap();
            let method_reply =
                websocket.next().await.unwrap().unwrap().into_data();
            assert_eq!(method_reply.as_ref(), &[5, 0]);
            websocket
                .send(Message::Binary(
                    vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 53].into(),
                ))
                .await
                .unwrap();
            let connect_reply =
                websocket.next().await.unwrap().unwrap().into_data();
            assert_eq!(connect_reply.as_ref(), &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            websocket
                .send(Message::Binary(b"query".to_vec().into()))
                .await
                .unwrap();
            let mut query = [0_u8; 5];
            origin_peer.read_exact(&mut query).await.unwrap();
            assert_eq!(&query, b"query");
            origin_peer.write_all(b"answer").await.unwrap();
            assert_eq!(
                websocket.next().await.unwrap().unwrap().into_data(),
                b"answer".as_slice()
            );
            websocket.close(None).await.unwrap();
        };
        tokio::join!(dispatch, client);
        assert_eq!(responses.lock().unwrap().len(), 1);
    }

    #[test]
    fn bastion_destination_accepts_url_and_rejects_missing_header() {
        let request = CloudflaredConnectRequest {
            destination: "https://bastion.example/".into(),
            connection_type: CloudflaredConnectionType::Websocket,
            metadata: vec![CloudflaredMetadata {
                key: "HttpHeader:Cf-Access-Jump-Destination".into(),
                value: "ssh://jump.example:2222/ignored".into(),
            }],
        };
        assert_eq!(
            resolve_bastion_destination(&request).unwrap().to_string(),
            "jump.example:2222"
        );
        assert!(
            resolve_bastion_destination(&CloudflaredConnectRequest {
                metadata: vec![],
                ..request
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn access_assertion_is_validated_before_ingress_service() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use openssl::{
            hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer,
        };

        let key = Rsa::generate(2048).unwrap();
        let jwks = serde_json::to_vec(&serde_json::json!({
            "keys":[{
                "kty":"RSA", "kid":"access-key", "alg":"RS256", "use":"sig",
                "n":URL_SAFE_NO_PAD.encode(key.n().to_vec()),
                "e":URL_SAFE_NO_PAD.encode(key.e().to_vec())
            }]
        }))
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"access-key"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss":"https://team.cloudflareaccess.com",
                "aud":["audience"],
                "exp":now + 3600
            }))
            .unwrap(),
        );
        let signed = format!("{header}.{claims}");
        let key = PKey::from_rsa(key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(signed.as_bytes()).unwrap();
        let token = format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap())
        );

        let config = Arc::new(CloudflaredConfigManager::new());
        assert_eq!(
            config
                .apply(
                    1,
                    br#"{"originRequest":{"access":{"required":true,"teamName":"team","audTag":["audience"]}},"ingress":[{"hostname":"protected.example","service":"http_status:204"},{"service":"http_status:404"}]}"#,
                )
                .error,
            None
        );
        let access = config
            .resolve("protected.example", "/")
            .unwrap()
            .origin_request
            .access;
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(None),
            }),
        );
        service.install_access_jwks(access, &jwks).await.unwrap();

        for (assertion, expected_status) in
            [(token.as_str(), "204"), ("not-a-jwt", "403")]
        {
            let (edge_service, edge_client) = tokio::io::duplex(256);
            let responses = Arc::new(Mutex::new(Vec::new()));
            service
                .dispatch(
                    edge_service,
                    ConnectResponse::Capture(responses.clone()),
                    CloudflaredConnectRequest {
                        destination: "https://protected.example/".into(),
                        connection_type: CloudflaredConnectionType::Http,
                        metadata: vec![
                            CloudflaredMetadata {
                                key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                                value: "protected.example".into(),
                            },
                            CloudflaredMetadata {
                                key: format!(
                                    "HttpHeader:{}",
                                    CLOUDFLARED_ACCESS_JWT_ASSERTION_HEADER
                                ),
                                value: assertion.into(),
                            },
                        ],
                    },
                )
                .await;
            drop(edge_client);
            let responses = responses.lock().unwrap();
            assert!(responses[0].1.iter().any(|entry| {
                entry.key == CLOUDFLARED_METADATA_HTTP_STATUS
                    && entry.value == expected_status
            }));
        }
    }

    #[test]
    fn disable_chunked_encoding_preserves_length_and_removes_chunking() {
        let request = CloudflaredConnectRequest {
            destination: "http://origin.example/upload".into(),
            connection_type: CloudflaredConnectionType::Http,
            metadata: vec![
                CloudflaredMetadata {
                    key: super::super::cloudflared::CLOUDFLARED_METADATA_HTTP_METHOD
                        .into(),
                    value: "POST".into(),
                },
                CloudflaredMetadata {
                    key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                    value: "public.example".into(),
                },
                CloudflaredMetadata {
                    key: "HttpHeader:Transfer-Encoding".into(),
                    value: "chunked".into(),
                },
                CloudflaredMetadata {
                    key: "HttpHeader:Content-Length".into(),
                    value: "7".into(),
                },
                CloudflaredMetadata {
                    key: "HttpHeader:Content-Length".into(),
                    value: "9".into(),
                },
            ],
        };
        assert!(request_has_streaming_body(&request).unwrap());
        let body = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync();
        let output = build_origin_request(
            &request,
            &url::Url::parse(&request.destination).unwrap(),
            &super::super::cloudflared_ingress::CloudflaredOriginRequestConfig {
                disable_chunked_encoding: true,
                ..Default::default()
            },
            body,
        )
        .unwrap();
        assert_eq!(
            output.headers()[http::header::CONTENT_LENGTH],
            HeaderValue::from_static("7")
        );
        assert_eq!(
            output
                .headers()
                .get_all(http::header::CONTENT_LENGTH)
                .iter()
                .count(),
            1
        );
        assert!(
            !output
                .headers()
                .contains_key(http::header::TRANSFER_ENCODING)
        );
    }

    #[test]
    fn streaming_body_detection_matches_upstream_substring_rule() {
        let request = CloudflaredConnectRequest {
            destination: "http://origin.example/upload".into(),
            connection_type: CloudflaredConnectionType::Http,
            metadata: vec![CloudflaredMetadata {
                key: "HttpHeader:Transfer-Encoding".into(),
                value: "gzip,X-Chunked-Experimental".into(),
            }],
        };
        assert!(request_has_streaming_body(&request).unwrap());
    }

    #[test]
    fn origin_automatic_gzip_matches_go_transport_policy() {
        let mut automatic = Request::builder()
            .method(Method::GET)
            .uri("http://origin.example/path")
            .body(())
            .unwrap();
        assert!(add_origin_accept_encoding(&mut automatic));
        assert_eq!(automatic.headers()[http::header::ACCEPT_ENCODING], "gzip");
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("GZip"),
        );
        response_headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("24"),
        );
        assert!(normalize_origin_gzip_response(&mut response_headers, true));
        assert!(!response_headers.contains_key(http::header::CONTENT_ENCODING));
        assert!(!response_headers.contains_key(http::header::CONTENT_LENGTH));

        let mut explicit = Request::builder()
            .method(Method::GET)
            .uri("http://origin.example/path")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .body(())
            .unwrap();
        assert!(!add_origin_accept_encoding(&mut explicit));
        let mut ranged = Request::builder()
            .method(Method::GET)
            .uri("http://origin.example/path")
            .header(http::header::RANGE, "bytes=0-9")
            .body(())
            .unwrap();
        assert!(!add_origin_accept_encoding(&mut ranged));
        let mut head = Request::builder()
            .method(Method::HEAD)
            .uri("http://origin.example/path")
            .body(())
            .unwrap();
        assert!(!add_origin_accept_encoding(&mut head));
    }

    #[tokio::test]
    async fn disable_chunked_encoding_emits_fixed_length_http1_wire() {
        let (origin_service, mut origin_peer) = tokio::io::duplex(4096);
        let origin_task = tokio::spawn(async move {
            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                origin_peer.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            assert!(head.contains("content-length: 7\r\n"));
            assert!(!head.contains("transfer-encoding:"));
            let mut body = [0_u8; 7];
            origin_peer.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"payload");
            origin_peer
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let config = Arc::new(CloudflaredConfigManager::new());
        assert_eq!(
            config
                .apply(
                    1,
                    br#"{"ingress":[{"hostname":"upload.example","service":"http://origin.example","originRequest":{"disableChunkedEncoding":true}},{"service":"http_status:404"}]}"#,
                )
                .error,
            None
        );
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        );
        let (edge_service, mut edge_client) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://upload.example/path".into(),
                connection_type: CloudflaredConnectionType::Http,
                metadata: vec![
                    CloudflaredMetadata {
                        key: super::super::cloudflared::CLOUDFLARED_METADATA_HTTP_METHOD
                            .into(),
                        value: "POST".into(),
                    },
                    CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                        value: "upload.example".into(),
                    },
                    CloudflaredMetadata {
                        key: "HttpHeader:Transfer-Encoding".into(),
                        value: "chunked".into(),
                    },
                    CloudflaredMetadata {
                        key: "HttpHeader:Content-Length".into(),
                        value: "7".into(),
                    },
                ],
            },
        );
        let client = async {
            edge_client.write_all(b"payload").await.unwrap();
            edge_client.shutdown().await.unwrap();
            let mut response = Vec::new();
            edge_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"ok");
        };
        tokio::join!(dispatch, client);
        origin_task.await.unwrap();
        assert!(responses.lock().unwrap()[0].1.iter().any(|entry| {
            entry.key == CLOUDFLARED_METADATA_HTTP_STATUS
                && entry.value == "200"
        }));
    }

    #[tokio::test]
    async fn disable_chunked_encoding_emits_unframed_http1_wire() {
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        );
        std::io::Write::write_all(&mut encoder, b"pong!").unwrap();
        let compressed_response = encoder.finish().unwrap();
        let (origin_service, mut origin_peer) = tokio::io::duplex(4096);
        let origin_task = tokio::spawn(async move {
            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                origin_peer.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            assert!(head.starts_with("post /path http/1.1\r\n"));
            assert!(head.contains("host: upload.example\r\n"));
            assert!(head.contains("connection: keep-alive\r\n"));
            assert!(head.contains("accept-encoding: gzip\r\n"));
            assert!(!head.contains("content-length:"));
            assert!(!head.contains("transfer-encoding:"));
            let mut body = Vec::new();
            origin_peer.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"payload");
            origin_peer.write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nX-Origin: yes\r\n\r\n").await.unwrap();
            let split = compressed_response.len() / 2;
            for chunk in
                [&compressed_response[..split], &compressed_response[split..]]
            {
                origin_peer
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                origin_peer.write_all(chunk).await.unwrap();
                origin_peer.write_all(b"\r\n").await.unwrap();
            }
            origin_peer
                .write_all(b"0\r\nX-Checksum: valid\r\n\r\n")
                .await
                .unwrap();
            origin_peer.shutdown().await.unwrap();
        });
        let config = Arc::new(CloudflaredConfigManager::new());
        assert_eq!(
            config
                .apply(
                    1,
                    br#"{"ingress":[{"hostname":"upload.example","service":"http://origin.example","originRequest":{"disableChunkedEncoding":true}},{"service":"http_status:404"}]}"#,
                )
                .error,
            None
        );
        let service = CloudflaredOriginService::new(
            config,
            Arc::new(MemoryDialer {
                origin: Mutex::new(Some(origin_service)),
            }),
        );
        let (edge_service, mut edge_client) = tokio::io::duplex(4096);
        let responses = Arc::new(Mutex::new(Vec::new()));
        let dispatch = service.dispatch(
            edge_service,
            ConnectResponse::Capture(responses.clone()),
            CloudflaredConnectRequest {
                destination: "https://upload.example/path".into(),
                connection_type: CloudflaredConnectionType::Http,
                metadata: vec![
                    CloudflaredMetadata {
                        key: super::super::cloudflared::CLOUDFLARED_METADATA_HTTP_METHOD
                            .into(),
                        value: "POST".into(),
                    },
                    CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_HOST.into(),
                        value: "upload.example".into(),
                    },
                    CloudflaredMetadata {
                        key: "HttpHeader:Transfer-Encoding".into(),
                        value: "chunked".into(),
                    },
                ],
            },
        );
        let client = async {
            edge_client.write_all(b"payload").await.unwrap();
            edge_client.shutdown().await.unwrap();
            let mut response = Vec::new();
            edge_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"pong!");
        };
        tokio::join!(dispatch, client);
        origin_task.await.unwrap();
        let responses = responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        assert!(responses[0].1.iter().any(|entry| {
            entry.key == CLOUDFLARED_METADATA_HTTP_STATUS
                && entry.value == "200"
        }));
        assert!(responses[0].1.iter().any(|entry| {
            entry.key.eq_ignore_ascii_case("HttpHeader:X-Origin")
                && entry.value == "yes"
        }));
        assert!(!responses[0].1.iter().any(|entry| {
            entry
                .key
                .eq_ignore_ascii_case("HttpHeader:Transfer-Encoding")
                || entry
                    .key
                    .eq_ignore_ascii_case("HttpHeader:Content-Encoding")
        }));
    }
}

struct ActiveFlow<'a>(&'a AtomicU64);

impl Drop for ActiveFlow<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Shared Cloudflare Tunnel request dispatcher for QUIC and HTTP/2 edges.
///
/// The dispatcher deliberately accepts an embedding [`Dialer`]. This keeps
/// route selection, DNS policy and detours under the owning zay runtime while
/// preserving cloudflared's wire behavior.
pub struct CloudflaredOriginService {
    config: Arc<CloudflaredConfigManager>,
    dialer: Arc<dyn Dialer>,
    access_dialer: Arc<dyn Dialer>,
    access_validators:
        tokio::sync::Mutex<HashMap<String, Arc<CloudflaredAccessValidator>>>,
    active_flows: Arc<AtomicU64>,
    datagrams: Arc<CloudflaredDatagramService>,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
}

impl CloudflaredOriginService {
    pub fn new(
        config: Arc<CloudflaredConfigManager>,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self::with_access_dialer(config, dialer.clone(), dialer)
    }

    pub fn with_access_dialer(
        config: Arc<CloudflaredConfigManager>,
        dialer: Arc<dyn Dialer>,
        access_dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self::with_access_dialer_and_runtime_context(
            config,
            dialer,
            access_dialer,
            None,
            None,
        )
    }

    pub(crate) fn with_access_dialer_and_runtime_context(
        config: Arc<CloudflaredConfigManager>,
        dialer: Arc<dyn Dialer>,
        access_dialer: Arc<dyn Dialer>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Self {
        let active_flows = Arc::new(AtomicU64::new(0));
        let datagrams = Arc::new(CloudflaredDatagramService::new(
            config.clone(),
            dialer.clone(),
            active_flows.clone(),
        ));
        Self {
            config,
            dialer,
            access_dialer,
            access_validators: tokio::sync::Mutex::new(HashMap::new()),
            active_flows,
            datagrams,
            ntp_clock,
            certificate_store,
        }
    }

    pub fn config(&self) -> &Arc<CloudflaredConfigManager> {
        &self.config
    }

    pub fn active_flows(&self) -> u64 {
        self.active_flows.load(Ordering::Acquire)
    }

    pub fn datagram_service(&self) -> &Arc<CloudflaredDatagramService> {
        &self.datagrams
    }

    pub async fn close_datagrams(&self) {
        self.datagrams.close().await;
    }

    pub async fn install_access_jwks(
        &self,
        config: super::cloudflared_ingress::CloudflaredAccessConfig,
        jwks: &[u8],
    ) -> io::Result<()> {
        let key = cloudflared_access_validator_key(&config);
        let validator =
            Arc::new(CloudflaredAccessValidator::from_jwks(config, jwks)?);
        self.access_validators.lock().await.insert(key, validator);
        Ok(())
    }

    async fn dispatch<S>(
        &self,
        stream: S,
        response: ConnectResponse,
        request: CloudflaredConnectRequest,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut edge_reader, mut edge_writer) = tokio::io::split(stream);
        let result = match request.connection_type {
            CloudflaredConnectionType::Tcp => {
                self.dispatch_tcp(
                    &mut edge_reader,
                    &mut edge_writer,
                    &response,
                    &request.destination,
                )
                .await
            }
            CloudflaredConnectionType::Http
            | CloudflaredConnectionType::Websocket => {
                self.dispatch_http(
                    edge_reader,
                    &mut edge_writer,
                    &response,
                    &request,
                )
                .await
            }
        };
        if let Err(error) = result {
            let _ = response
                .write(&mut edge_writer, Some(&error.to_string()), &[])
                .await;
        }
        let _ = edge_writer.shutdown().await;
    }

    async fn dispatch_tcp<R, W>(
        &self,
        edge_reader: &mut R,
        edge_writer: &mut W,
        response: &ConnectResponse,
        destination: &str,
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let destination = destination.parse::<SocksAddr>()?;
        let warp = self.config.snapshot().warp_routing;
        let previous = self.active_flows.fetch_add(1, Ordering::AcqRel);
        if warp.max_active_flows != 0 && previous >= warp.max_active_flows {
            self.active_flows.fetch_sub(1, Ordering::AcqRel);
            return response
                .write(
                    edge_writer,
                    Some("too many active flows"),
                    &cloudflared_flow_connect_rate_limited_metadata(),
                )
                .await;
        }
        let _active = ActiveFlow(self.active_flows.as_ref());
        let mut origin = if warp.connect_timeout.is_zero() {
            self.dialer.dial_tcp(&destination).await?
        } else {
            tokio::time::timeout(
                warp.connect_timeout,
                self.dialer.dial_tcp(&destination),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("dial TCP origin {destination} timed out"),
                )
            })??
        };
        response.write(edge_writer, None, &[]).await?;
        let (mut origin_reader, mut origin_writer) =
            tokio::io::split(&mut origin);
        let upstream = tokio::io::copy(edge_reader, &mut origin_writer);
        let downstream = tokio::io::copy(&mut origin_reader, edge_writer);
        let _ = tokio::try_join!(upstream, downstream);
        Ok(())
    }

    async fn dispatch_http<R, W>(
        &self,
        mut edge_reader: R,
        edge_writer: &mut W,
        response: &ConnectResponse,
        request: &CloudflaredConnectRequest,
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin,
    {
        let url = url::Url::parse(&request.destination).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse request URL: {error}"),
            )
        })?;
        let metadata = cloudflared_metadata_map(&request.metadata);
        let host = metadata
            .get(CLOUDFLARED_METADATA_HTTP_HOST)
            .map(String::as_str)
            .or_else(|| url.host_str())
            .unwrap_or_default();
        let service =
            self.config.resolve(host, url.path()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no ingress rule matched request host/path",
                )
            })?;
        if service.origin_request.access.required
            && self.validate_access(request, &service).await.is_err()
        {
            return response
                .write(
                    edge_writer,
                    None,
                    &[CloudflaredMetadata {
                        key: CLOUDFLARED_METADATA_HTTP_STATUS.into(),
                        value: http::StatusCode::FORBIDDEN.as_u16().to_string(),
                    }],
                )
                .await;
        }
        match service.kind {
            CloudflaredResolvedServiceKind::Status => {
                response
                    .write(
                        edge_writer,
                        None,
                        &[CloudflaredMetadata {
                            key: CLOUDFLARED_METADATA_HTTP_STATUS.into(),
                            value: service.status_code.to_string(),
                        }],
                    )
                    .await
            }
            CloudflaredResolvedServiceKind::Stream
            | CloudflaredResolvedServiceKind::Bastion
            | CloudflaredResolvedServiceKind::SocksProxy => {
                if request.connection_type
                    != CloudflaredConnectionType::Websocket
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "cloudflared {:?} service requires websocket request type",
                            service.kind
                        ),
                    ));
                }
                self.dispatch_special_websocket(
                    edge_reader,
                    edge_writer,
                    response,
                    request,
                    &service,
                )
                .await
            }
            CloudflaredResolvedServiceKind::Http
            | CloudflaredResolvedServiceKind::Unix
            | CloudflaredResolvedServiceKind::UnixTls => {
                let origin_url = service
                    .build_request_url(&request.destination)
                    .map_err(io::Error::other)?;
                let origin_url =
                    url::Url::parse(&origin_url).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("parse origin URL: {error}"),
                        )
                    })?;
                let (origin, http2) = match service.kind {
                    CloudflaredResolvedServiceKind::Http => {
                        let destination = service.destination.as_ref().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "HTTP ingress service is missing destination",
                            )
                        })?;
                        self.dial_http_origin(
                            destination,
                            &origin_url,
                            host,
                            &service.origin_request,
                        )
                        .await?
                    }
                    CloudflaredResolvedServiceKind::Unix
                    | CloudflaredResolvedServiceKind::UnixTls => {
                        self.dial_unix_http_origin(
                            &service.unix_path,
                            &origin_url,
                            host,
                            &service.origin_request,
                        )
                        .await?
                    }
                    _ => unreachable!("HTTP origin service kind was matched"),
                };
                let websocket = request.connection_type
                    == CloudflaredConnectionType::Websocket;
                let stream_request_body =
                    !websocket && request_has_streaming_body(request)?;
                let (body_sender, body) = if stream_request_body {
                    let (sender, body) = http_body_util::channel::Channel::<
                        Bytes,
                        io::Error,
                    >::new(16);
                    (Some(sender), body.boxed_unsync())
                } else {
                    (
                        None,
                        Empty::<Bytes>::new()
                            .map_err(|never| match never {})
                            .boxed_unsync(),
                    )
                };
                let mut origin_request = build_origin_request(
                    request,
                    &origin_url,
                    &service.origin_request,
                    body.boxed_unsync(),
                )?;
                let auto_gzip = add_origin_accept_encoding(&mut origin_request);
                let unframed_http1_body = !websocket
                    && !http2
                    && stream_request_body
                    && service.origin_request.disable_chunked_encoding
                    && !origin_request
                        .headers()
                        .contains_key(http::header::CONTENT_LENGTH);
                if unframed_http1_body {
                    return send_unframed_http1_origin_request(
                        origin,
                        origin_request,
                        edge_reader,
                        edge_writer,
                        response,
                        auto_gzip,
                    )
                    .await;
                }
                if websocket {
                    let mut origin_response =
                        send_origin_request(origin, origin_request, http2)
                            .await?;
                    let decompress_gzip = normalize_origin_gzip_response(
                        origin_response.headers_mut(),
                        auto_gzip,
                    );
                    let response_metadata =
                        origin_response_metadata(&origin_response);
                    response
                        .write(edge_writer, None, &response_metadata)
                        .await?;
                    if origin_response.status()
                        == http::StatusCode::SWITCHING_PROTOCOLS
                    {
                        let upgraded = hyper::upgrade::on(&mut origin_response)
                            .await
                            .map_err(io::Error::other)?;
                        let upgraded = TokioIo::new(upgraded);
                        let (mut upgraded_reader, mut upgraded_writer) =
                            tokio::io::split(upgraded);
                        let upstream = tokio::io::copy(
                            &mut edge_reader,
                            &mut upgraded_writer,
                        );
                        let downstream =
                            tokio::io::copy(&mut upgraded_reader, edge_writer);
                        let _ = tokio::try_join!(upstream, downstream);
                    } else {
                        let _ = copy_origin_body(
                            origin_response,
                            edge_writer,
                            response,
                            decompress_gzip,
                        )
                        .await;
                    }
                    return Ok(());
                }

                let request_body = body_sender.map(|body_sender| {
                    tokio::spawn(async move {
                        pump_request_body(&mut edge_reader, body_sender).await
                    })
                });
                let mut origin_response =
                    match send_origin_request(origin, origin_request, http2)
                        .await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            if let Some(request_body) = request_body {
                                request_body.abort();
                            }
                            return Err(error);
                        }
                    };
                let decompress_gzip = normalize_origin_gzip_response(
                    origin_response.headers_mut(),
                    auto_gzip,
                );
                let response_metadata =
                    origin_response_metadata(&origin_response);
                response
                    .write(edge_writer, None, &response_metadata)
                    .await?;
                let copy_result = copy_origin_body(
                    origin_response,
                    edge_writer,
                    response,
                    decompress_gzip,
                )
                .await;
                if let Some(request_body) = request_body {
                    request_body.abort();
                }
                let _ = copy_result;
                Ok(())
            }
        }
    }

    async fn validate_access(
        &self,
        request: &CloudflaredConnectRequest,
        service: &CloudflaredResolvedService,
    ) -> io::Result<()> {
        let config = &service.origin_request.access;
        let key = cloudflared_access_validator_key(config);
        let validator = {
            let mut validators = self.access_validators.lock().await;
            validators
                .entry(key)
                .or_insert_with(|| {
                    Arc::new(
                        CloudflaredAccessValidator::new_with_runtime_context(
                            config.clone(),
                            self.access_dialer.clone(),
                            self.ntp_clock.clone(),
                            self.certificate_store.clone(),
                        ),
                    )
                })
                .clone()
        };
        validator
            .validate(
                request_header(
                    request,
                    CLOUDFLARED_ACCESS_JWT_ASSERTION_HEADER,
                )
                .unwrap_or_default(),
            )
            .await
    }

    async fn dispatch_special_websocket<R, W>(
        &self,
        edge_reader: R,
        edge_writer: &mut W,
        response: &ConnectResponse,
        request: &CloudflaredConnectRequest,
        service: &CloudflaredResolvedService,
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let destination = match service.kind {
            CloudflaredResolvedServiceKind::Stream => {
                if !service.stream_has_port {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "stream service is missing destination port",
                    ));
                }
                service.destination.clone().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "stream service is missing destination",
                    )
                })?
            }
            CloudflaredResolvedServiceKind::Bastion => {
                resolve_bastion_destination(request)?
            }
            CloudflaredResolvedServiceKind::SocksProxy => {
                SocksAddr::new("0.0.0.0", 0)
            }
            _ => unreachable!("special websocket service kind was matched"),
        };
        let mut fixed_target =
            if service.kind == CloudflaredResolvedServiceKind::SocksProxy {
                None
            } else {
                Some(self.dialer.dial_tcp(&destination).await?)
            };
        response
            .write(edge_writer, None, &websocket_response_metadata(request))
            .await?;

        let edge = SplitEdgeIo {
            reader: edge_reader,
            writer: edge_writer,
        };
        let websocket =
            WebSocketStream::from_raw_socket(edge, Role::Server, None).await;
        let (application, bridge) = tokio::io::duplex(32 * 1024);
        let websocket_bridge = bridge_websocket(websocket, bridge);
        let application_service = async {
            if service.kind == CloudflaredResolvedServiceKind::SocksProxy {
                serve_socks_proxy(
                    application,
                    service.socks_policy.as_ref(),
                    &self.dialer,
                )
                .await
            } else if is_socks_proxy_type(&service.origin_request.proxy_type) {
                serve_fixed_socks(
                    application,
                    fixed_target.take().expect("fixed target was dialed"),
                )
                .await
            } else {
                let mut target =
                    fixed_target.take().expect("fixed target was dialed");
                let mut application = application;
                let _ = tokio::io::copy_bidirectional(
                    &mut application,
                    &mut target,
                )
                .await;
                Ok(())
            }
        };
        let (_, service_result) =
            tokio::join!(websocket_bridge, application_service);
        let _ = service_result;
        Ok(())
    }

    async fn dial_http_origin(
        &self,
        destination: &SocksAddr,
        origin_url: &url::Url,
        request_host: &str,
        options: &super::cloudflared_ingress::CloudflaredOriginRequestConfig,
    ) -> io::Result<(Stream, bool)> {
        let dial = self.dialer.dial_tcp(destination);
        let stream = if options.connect_timeout.is_zero() {
            dial.await?
        } else {
            tokio::time::timeout(options.connect_timeout, dial)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("dial HTTP origin {destination} timed out"),
                    )
                })??
        };
        wrap_http_origin_tls(
            stream,
            origin_url,
            request_host,
            options,
            self.ntp_clock.clone(),
            self.certificate_store.clone(),
        )
        .await
    }

    #[cfg(unix)]
    async fn dial_unix_http_origin(
        &self,
        path: &str,
        origin_url: &url::Url,
        request_host: &str,
        options: &super::cloudflared_ingress::CloudflaredOriginRequestConfig,
    ) -> io::Result<(Stream, bool)> {
        let connect = tokio::net::UnixStream::connect(path);
        let stream = if options.connect_timeout.is_zero() {
            connect.await?
        } else {
            tokio::time::timeout(options.connect_timeout, connect)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("dial Unix HTTP origin {path:?} timed out"),
                    )
                })??
        };
        wrap_http_origin_tls(
            Box::new(stream),
            origin_url,
            request_host,
            options,
            self.ntp_clock.clone(),
            self.certificate_store.clone(),
        )
        .await
    }

    #[cfg(not(unix))]
    async fn dial_unix_http_origin(
        &self,
        _path: &str,
        _origin_url: &url::Url,
        _request_host: &str,
        _options: &super::cloudflared_ingress::CloudflaredOriginRequestConfig,
    ) -> io::Result<(Stream, bool)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix ingress services are unavailable on this platform",
        ))
    }
}

async fn wrap_http_origin_tls(
    stream: Stream,
    origin_url: &url::Url,
    request_host: &str,
    options: &super::cloudflared_ingress::CloudflaredOriginRequestConfig,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> io::Result<(Stream, bool)> {
    if origin_url.scheme() != "https" {
        return Ok((stream, false));
    }
    let endpoint_host = origin_url.host_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTPS origin URL is missing hostname",
        )
    })?;
    let effective_host = if options.http_host_header.is_empty() {
        request_host
    } else {
        &options.http_host_header
    };
    let server_name = if !options.origin_server_name.is_empty() {
        options.origin_server_name.clone()
    } else if options.match_sni_to_host {
        strip_http_host_port(effective_host).into()
    } else {
        endpoint_host.into()
    };
    let mut tls_options = OutboundTlsOptions {
        enabled: true,
        server_name,
        insecure: options.no_tls_verify,
        certificate_path: options.ca_pool.clone(),
        ..Default::default()
    };
    tls_options.set_runtime_context(ntp_clock, certificate_store);
    let default_alpn = if options.http2_origin {
        &["h2", "http/1.1"][..]
    } else {
        &["http/1.1"][..]
    };
    let tls = build_client_config(endpoint_host, &tls_options, default_alpn)
        .map_err(io::Error::other)?;
    let handshake_timeout = if options.tls_timeout.is_zero() {
        None
    } else {
        Some(options.tls_timeout)
    };
    let tls_stream = tls
        .connect_stream_with_timeout(stream, handshake_timeout)
        .await?;
    let http2 = tls_stream.negotiated_alpn() == Some(b"h2");
    Ok((tls_stream.into_stream(), http2))
}

struct SplitEdgeIo<'a, R, W> {
    reader: R,
    writer: &'a mut W,
}

impl<R, W> AsyncRead for SplitEdgeIo<'_, R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(context, buffer)
    }
}

impl<R, W> AsyncWrite for SplitEdgeIo<'_, R, W>
where
    R: Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.writer).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.writer).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.writer).poll_shutdown(context)
    }
}

async fn bridge_websocket<S>(
    mut websocket: WebSocketStream<S>,
    bridge: tokio::io::DuplexStream,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge);
    let mut outgoing = vec![0_u8; 16 * 1024];
    loop {
        tokio::select! {
            incoming = websocket.next() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    if bridge_writer.write_all(&data).await.is_err() { break; }
                }
                Some(Ok(Message::Text(data))) => {
                    if bridge_writer.write_all(data.as_bytes()).await.is_err() { break; }
                }
                Some(Ok(Message::Ping(data))) => {
                    if websocket.send(Message::Pong(data)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            read = bridge_reader.read(&mut outgoing) => match read {
                Ok(0) | Err(_) => {
                    let _ = websocket.close(None).await;
                    break;
                }
                Ok(length) => {
                    if websocket
                        .send(Message::Binary(outgoing[..length].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    }
    let _ = bridge_writer.shutdown().await;
}

fn websocket_response_metadata(
    request: &CloudflaredConnectRequest,
) -> Vec<CloudflaredMetadata> {
    let mut metadata = vec![
        CloudflaredMetadata {
            key: CLOUDFLARED_METADATA_HTTP_STATUS.into(),
            value: http::StatusCode::SWITCHING_PROTOCOLS.as_u16().to_string(),
        },
        CloudflaredMetadata {
            key: "HttpHeader:Connection".into(),
            value: "Upgrade".into(),
        },
        CloudflaredMetadata {
            key: "HttpHeader:Upgrade".into(),
            value: "websocket".into(),
        },
    ];
    if let Some(key) = request_header(request, "sec-websocket-key") {
        let mut digest = Sha1::new();
        digest.update(key.as_bytes());
        digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        metadata.push(CloudflaredMetadata {
            key: "HttpHeader:Sec-WebSocket-Accept".into(),
            value: STANDARD.encode(digest.finalize()),
        });
    }
    metadata
}

fn request_header<'a>(
    request: &'a CloudflaredConnectRequest,
    name: &str,
) -> Option<&'a str> {
    request.metadata.iter().find_map(|entry| {
        entry
            .key
            .strip_prefix(
                super::cloudflared::CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX,
            )
            .filter(|header| header.eq_ignore_ascii_case(name))
            .map(|_| entry.value.as_str())
    })
}

fn resolve_bastion_destination(
    request: &CloudflaredConnectRequest,
) -> io::Result<SocksAddr> {
    let raw = request_header(request, "cf-access-jump-destination")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing Cf-Access-Jump-Destination header",
            )
        })?;
    let destination = url::Url::parse(raw)
        .ok()
        .and_then(|url| {
            url.host_str().map(|host| {
                let port = url
                    .port()
                    .map(|port| format!(":{port}"))
                    .unwrap_or_default();
                format!("{host}{port}")
            })
        })
        .unwrap_or_else(|| raw.split('/').next().unwrap_or(raw).to_owned());
    destination.parse()
}

fn is_socks_proxy_type(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "socks" | "socks5"
    )
}

async fn serve_fixed_socks<S>(
    mut client: S,
    mut target: Stream,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = read_socks_handshake(&mut client).await?;
    write_socks_reply(&mut client, 0).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
    Ok(())
}

async fn serve_socks_proxy<S>(
    mut client: S,
    policy: Option<&CloudflaredIpRulePolicy>,
    dialer: &Arc<dyn Dialer>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let destination = read_socks_handshake(&mut client).await?;
    let addresses = destination.resolve().await?;
    let allowed = policy.is_some_and(|policy| {
        addresses.first().is_some_and(|address| {
            policy.allows(address.ip(), destination.port())
        })
    });
    if !allowed {
        write_socks_reply(&mut client, 2).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("connect to {destination} denied by ip_rules"),
        ));
    }
    let mut target = match dialer.dial_tcp(&destination).await {
        Ok(target) => target,
        Err(error) => {
            let reply = socks_reply_for_error(&error);
            let _ = write_socks_reply(&mut client, reply).await;
            return Err(error);
        }
    };
    write_socks_reply(&mut client, 0).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
    Ok(())
}

async fn read_socks_handshake<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS version: {version}"),
        ));
    }
    let method_count = stream.read_u8().await? as usize;
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown authentication type",
        ));
    }
    stream.write_all(&[5, 0]).await?;
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS request version: {}", header[0]),
        ));
    }
    if header[1] != 1 {
        write_socks_reply(stream, 7).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported SOCKS command: {}", header[1]),
        ));
    }
    let host = match header[3] {
        1 => IpAddr::V4(Ipv4Addr::from(stream.read_u32().await?)).to_string(),
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut host = vec![0_u8; length];
            stream.read_exact(&mut host).await?;
            String::from_utf8(host).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS domain is not UTF-8",
                )
            })?
        }
        4 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address).await?;
            IpAddr::V6(Ipv6Addr::from(address)).to_string()
        }
        address_type => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported SOCKS address type: {address_type}"),
            ));
        }
    };
    let port = stream.read_u16().await?;
    Ok(SocksAddr::new(host, port))
}

async fn write_socks_reply<S>(stream: &mut S, reply: u8) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

fn socks_reply_for_error(error: &io::Error) -> u8 {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("refused") {
        5
    } else if message.contains("network is unreachable") {
        3
    } else {
        4
    }
}

type OriginRequestBody = UnsyncBoxBody<Bytes, io::Error>;

fn build_origin_request(
    request: &CloudflaredConnectRequest,
    origin_url: &url::Url,
    options: &super::cloudflared_ingress::CloudflaredOriginRequestConfig,
    body: OriginRequestBody,
) -> io::Result<Request<OriginRequestBody>> {
    let metadata = cloudflared_metadata_map(&request.metadata);
    let method = metadata
        .get(super::cloudflared::CLOUDFLARED_METADATA_HTTP_METHOD)
        .map(String::as_str)
        .unwrap_or("GET")
        .parse::<Method>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse HTTP method: {error}"),
            )
        })?;
    let uri = origin_url.as_str().parse::<http::Uri>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("parse origin URI: {error}"),
        )
    })?;
    let mut output = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .map_err(io::Error::other)?;
    for entry in &request.metadata {
        let Some(name) = entry.key.strip_prefix(
            super::cloudflared::CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX,
        ) else {
            continue;
        };
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse HTTP header name: {error}"),
                )
            })?;
        let value = HeaderValue::from_str(&entry.value).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse HTTP header value: {error}"),
            )
        })?;
        output.headers_mut().append(name, value);
    }
    output.headers_mut().remove(HeaderName::from_static(
        "cf-cloudflared-proxy-connection-upgrade",
    ));
    if let Some(content_length) =
        output.headers().get(http::header::CONTENT_LENGTH).cloned()
    {
        content_length
            .to_str()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse content-length: {error}"),
                )
            })?
            .parse::<u64>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse content-length: {error}"),
                )
            })?;
        // Go stores the first Header.Get value in Request.ContentLength and
        // net/http serializes that single canonical value.
        output
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, content_length);
    }
    let request_host = metadata
        .get(CLOUDFLARED_METADATA_HTTP_HOST)
        .cloned()
        .or_else(|| origin_url.host_str().map(str::to_owned))
        .unwrap_or_default();
    if !options.http_host_header.is_empty() {
        output.headers_mut().insert(
            http::header::HOST,
            HeaderValue::from_str(&options.http_host_header).map_err(
                |error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("parse origin Host header: {error}"),
                    )
                },
            )?,
        );
        output.headers_mut().insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_str(&request_host).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse forwarded Host header: {error}"),
                )
            })?,
        );
    } else if !output.headers().contains_key(http::header::HOST) {
        output.headers_mut().insert(
            http::header::HOST,
            HeaderValue::from_str(&request_host).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse Host header: {error}"),
                )
            })?,
        );
    }
    if !output.headers().contains_key(http::header::USER_AGENT) {
        output
            .headers_mut()
            .insert(http::header::USER_AGENT, HeaderValue::from_static(""));
    }
    if request.connection_type == CloudflaredConnectionType::Websocket {
        output.headers_mut().insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        output.headers_mut().insert(
            http::header::UPGRADE,
            HeaderValue::from_static("websocket"),
        );
        output.headers_mut().insert(
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("13"),
        );
        output.headers_mut().remove(http::header::CONTENT_LENGTH);
    } else {
        if options.disable_chunked_encoding {
            // Go sets Request.TransferEncoding to gzip/deflate solely to
            // suppress net/http's automatic chunk writer. Hyper derives
            // framing from Content-Length/body size; removing the edge's
            // hop-by-hop header produces the same fixed-length wire request.
            output.headers_mut().remove(http::header::TRANSFER_ENCODING);
        }
        output.headers_mut().insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
    }
    Ok(output)
}

fn request_has_streaming_body(
    request: &CloudflaredConnectRequest,
) -> io::Result<bool> {
    let mut content_length = None;
    let mut chunked = false;
    for entry in &request.metadata {
        let Some(name) = entry.key.strip_prefix(
            super::cloudflared::CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX,
        ) else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length")
            && content_length.is_none()
        {
            content_length =
                Some(entry.value.parse::<u64>().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("parse content-length: {error}"),
                    )
                })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && entry.value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }
    Ok(chunked || content_length.is_some_and(|length| length != 0))
}

fn add_origin_accept_encoding<B>(request: &mut Request<B>) -> bool {
    let accepts_encoding = request
        .headers()
        .get(http::header::ACCEPT_ENCODING)
        .is_some_and(|value| !value.is_empty());
    let has_range = request
        .headers()
        .get(http::header::RANGE)
        .is_some_and(|value| !value.is_empty());
    if accepts_encoding || has_range || request.method() == Method::HEAD {
        return false;
    }
    request.headers_mut().insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip"),
    );
    true
}

fn normalize_origin_gzip_response(
    headers: &mut HeaderMap,
    auto_gzip: bool,
) -> bool {
    if !auto_gzip
        || !headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("gzip"))
    {
        return false;
    }
    headers.remove(http::header::CONTENT_ENCODING);
    headers.remove(http::header::CONTENT_LENGTH);
    true
}

const CLOUDFLARED_HTTP1_MAX_HEAD_SIZE: usize = 1024 * 1024;
const CLOUDFLARED_HTTP1_MAX_LINE_SIZE: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http1ResponseBodyKind {
    None,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

struct ParsedHttp1Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Http1ResponseBodyKind,
}

async fn send_unframed_http1_origin_request<R, W>(
    origin: Stream,
    request: Request<OriginRequestBody>,
    mut edge_reader: R,
    edge_writer: &mut W,
    connect_response: &ConnectResponse,
    auto_gzip: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let request_head = encode_unframed_http1_request(&request)?;
    let request_method = request.method().clone();
    let (origin_reader, mut origin_writer) = tokio::io::split(origin);
    let request_body = tokio::spawn(async move {
        origin_writer.write_all(&request_head).await?;
        tokio::io::copy(&mut edge_reader, &mut origin_writer).await?;
        // There is deliberately no HTTP message framing on this compatibility
        // path.  Half-close after the edge body finishes so origins which wait
        // for EOF can complete, while the read half remains available for the
        // response.
        origin_writer.shutdown().await
    });
    let mut origin_reader = BufReader::new(origin_reader);
    let result = async {
        let mut response =
            read_http1_response_head(&mut origin_reader, &request_method)
                .await?;
        let decompress_gzip =
            normalize_origin_gzip_response(&mut response.headers, auto_gzip);
        connect_response
            .write(
                edge_writer,
                None,
                &origin_response_metadata_parts(
                    response.status,
                    &response.headers,
                ),
            )
            .await?;
        copy_http1_response_body(
            &mut origin_reader,
            edge_writer,
            connect_response,
            response.body,
            decompress_gzip,
        )
        .await
    }
    .await;
    request_body.abort();
    let _ = request_body.await;
    result
}

fn encode_unframed_http1_request<B>(
    request: &Request<B>,
) -> io::Result<Vec<u8>> {
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    if target.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP request target contains a control byte",
        ));
    }
    let host = request
        .headers()
        .get(http::header::HOST)
        .map(|value| value.to_str())
        .transpose()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse Host header: {error}"),
            )
        })?
        .or_else(|| request.uri().authority().map(|value| value.as_str()))
        .unwrap_or_default();
    let mut output = Vec::with_capacity(1024);
    output.extend_from_slice(request.method().as_str().as_bytes());
    output.extend_from_slice(b" ");
    output.extend_from_slice(target.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(b"\r\n");

    let mut headers = request
        .headers()
        .iter()
        .filter(|(name, value)| {
            *name != http::header::HOST
                && *name != http::header::CONTENT_LENGTH
                && *name != http::header::TRANSFER_ENCODING
                && !(*name == http::header::USER_AGENT && value.is_empty())
        })
        .collect::<Vec<_>>();
    headers.sort_by(|(left_name, _), (right_name, _)| {
        left_name.as_str().cmp(right_name.as_str())
    });
    for (name, value) in headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Ok(output)
}

async fn read_http1_response_head<R>(
    reader: &mut R,
    method: &Method,
) -> io::Result<ParsedHttp1Response>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let mut encoded = Vec::new();
        loop {
            let remaining = CLOUDFLARED_HTTP1_MAX_HEAD_SIZE
                .checked_sub(encoded.len())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP response headers exceed limit",
                    )
                })?;
            let before = encoded.len();
            let read = reader
                .take((remaining + 1) as u64)
                .read_until(b'\n', &mut encoded)
                .await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "origin closed before a complete HTTP response",
                ));
            }
            if encoded.len() > CLOUDFLARED_HTTP1_MAX_HEAD_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP response headers exceed limit",
                ));
            }
            let line = &encoded[before..];
            if line == b"\n" || line == b"\r\n" {
                break;
            }
        }

        let header_capacity = encoded
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            .saturating_sub(1)
            .max(1);
        let mut raw_headers = vec![httparse::EMPTY_HEADER; header_capacity];
        let mut parsed = httparse::Response::new(&mut raw_headers);
        let parsed_size = match parsed.parse(&encoded).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse HTTP response head: {error}"),
            )
        })? {
            httparse::Status::Complete(size) => size,
            httparse::Status::Partial => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete HTTP response head",
                ));
            }
        };
        if parsed_size != encoded.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response parser did not consume the complete head",
            ));
        }
        if !matches!(parsed.version, Some(0 | 1)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported HTTP response version",
            ));
        }
        let status = StatusCode::from_u16(parsed.code.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response is missing a status code",
            )
        })?)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HTTP response status: {error}"),
            )
        })?;
        let mut headers = HeaderMap::new();
        for header in parsed.headers.iter() {
            let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(
                |error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid HTTP response header name: {error}"),
                    )
                },
            )?;
            let value =
                HeaderValue::from_bytes(header.value).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid HTTP response header value: {error}"),
                    )
                })?;
            headers.append(name, value);
        }
        if status.is_informational()
            && status != StatusCode::SWITCHING_PROTOCOLS
        {
            continue;
        }
        let body = http1_response_body_kind(method, status, &mut headers)?;
        return Ok(ParsedHttp1Response {
            status,
            headers,
            body,
        });
    }
}

fn http1_response_body_kind(
    method: &Method,
    status: StatusCode,
    headers: &mut HeaderMap,
) -> io::Result<Http1ResponseBodyKind> {
    let transfer_encoding = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .collect::<Vec<_>>();
    let chunked = if transfer_encoding.is_empty() {
        false
    } else if transfer_encoding.len() == 1
        && transfer_encoding[0]
            .to_str()
            .is_ok_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        true
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported HTTP response transfer encoding",
        ));
    };
    if chunked {
        headers.remove(http::header::TRANSFER_ENCODING);
        headers.remove(http::header::CONTENT_LENGTH);
    }
    if method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return Ok(Http1ResponseBodyKind::None);
    }
    if chunked {
        headers.remove(http::header::TRAILER);
        return Ok(Http1ResponseBodyKind::Chunked);
    }
    let lengths = headers
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid response content-length: {error}"),
                    )
                })?
                .trim()
                .parse::<u64>()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid response content-length: {error}"),
                    )
                })
        })
        .collect::<io::Result<Vec<_>>>()?;
    if let Some(first) = lengths.first().copied() {
        if lengths.iter().any(|length| *length != first) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "conflicting response content-length headers",
            ));
        }
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&first.to_string())
                .map_err(io::Error::other)?,
        );
        Ok(Http1ResponseBodyKind::ContentLength(first))
    } else {
        Ok(Http1ResponseBodyKind::CloseDelimited)
    }
}

async fn copy_http1_response_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    connect_response: &ConnectResponse,
    body: Http1ResponseBodyKind,
    decompress_gzip: bool,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if decompress_gzip && body != Http1ResponseBodyKind::None {
        let (encoded_reader, mut encoded_writer) = tokio::io::duplex(32 * 1024);
        let source = async move {
            copy_http1_response_body_encoded(
                reader,
                &mut encoded_writer,
                connect_response,
                body,
            )
            .await
        };
        let sink = async move {
            let mut decoder = GzipDecoder::new(BufReader::new(encoded_reader));
            decoder.multiple_members(true);
            tokio::io::copy(&mut decoder, writer).await?;
            Ok::<_, io::Error>(())
        };
        tokio::try_join!(source, sink)?;
        return Ok(());
    }
    copy_http1_response_body_encoded(reader, writer, connect_response, body)
        .await
}

async fn copy_http1_response_body_encoded<R, W>(
    reader: &mut R,
    writer: &mut W,
    connect_response: &ConnectResponse,
    body: Http1ResponseBodyKind,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        Http1ResponseBodyKind::None => Ok(()),
        Http1ResponseBodyKind::ContentLength(length) => {
            copy_exact_http1_body(reader, writer, length).await
        }
        Http1ResponseBodyKind::CloseDelimited => {
            tokio::io::copy(reader, writer).await?;
            Ok(())
        }
        Http1ResponseBodyKind::Chunked => {
            copy_chunked_http1_body(reader, writer, connect_response).await
        }
    }
}

async fn copy_exact_http1_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded by the buffer length");
        let read = reader.read(&mut buffer[..limit]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "origin response ended before content-length bytes arrived",
            ));
        }
        writer.write_all(&buffer[..read]).await?;
        remaining -= read as u64;
    }
    Ok(())
}

async fn copy_chunked_http1_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    connect_response: &ConnectResponse,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let line = read_bounded_http1_line(reader).await?;
        let size_text = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap_or(&line);
        let size_text = size_text
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        let size_text = std::str::from_utf8(size_text).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size")
        })?;
        let size =
            u64::from_str_radix(size_text.trim(), 16).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid HTTP chunk size: {error}"),
                )
            })?;
        if size == 0 {
            let trailers = read_http1_trailers(reader).await?;
            connect_response.add_trailers(&trailers);
            return Ok(());
        }
        copy_exact_http1_body(reader, writer, size).await?;
        let ending = read_bounded_http1_line(reader).await?;
        if ending != b"\r\n" && ending != b"\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP chunk is missing its line ending",
            ));
        }
    }
}

async fn read_http1_trailers<R>(reader: &mut R) -> io::Result<HeaderMap>
where
    R: AsyncBufRead + Unpin,
{
    let mut trailers = HeaderMap::new();
    let mut total_size = 0_usize;
    loop {
        let line = read_bounded_http1_line(reader).await?;
        total_size = total_size.checked_add(line.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response trailers exceed limit",
            )
        })?;
        if total_size > CLOUDFLARED_HTTP1_MAX_HEAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response trailers exceed limit",
            ));
        }
        if line == b"\r\n" || line == b"\n" {
            return Ok(trailers);
        }
        let line = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap_or(&line);
        let separator =
            line.iter().position(|byte| *byte == b':').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTP response trailer",
                )
            })?;
        let name =
            HeaderName::from_bytes(&line[..separator]).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid HTTP response trailer name: {error}"),
                )
            })?;
        if name == http::header::TRANSFER_ENCODING
            || name == http::header::CONTENT_LENGTH
            || name == http::header::TRAILER
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("prohibited HTTP response trailer: {name}"),
            ));
        }
        let value = HeaderValue::from_bytes(
            line[separator + 1..]
                .strip_prefix(b" ")
                .unwrap_or(&line[separator + 1..]),
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HTTP response trailer value: {error}"),
            )
        })?;
        trailers.append(name, value);
    }
}

async fn read_bounded_http1_line<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let read = reader
        .take((CLOUDFLARED_HTTP1_MAX_LINE_SIZE + 1) as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "origin response ended before a complete HTTP line",
        ));
    }
    if line.len() > CLOUDFLARED_HTTP1_MAX_LINE_SIZE || !line.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP response line exceeds limit",
        ));
    }
    Ok(line)
}

async fn send_origin_request(
    origin: Stream,
    mut request: Request<OriginRequestBody>,
    http2: bool,
) -> io::Result<http::Response<Incoming>> {
    let origin = TokioIo::new(origin);
    if http2 {
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<
            _,
            _,
            OriginRequestBody,
        >(TokioExecutor::new(), origin)
        .await
        .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        sender.send_request(request).await.map_err(io::Error::other)
    } else {
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .parse::<http::Uri>()
            .map_err(io::Error::other)?;
        *request.uri_mut() = path_and_query;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(origin)
                .await
                .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        sender.send_request(request).await.map_err(io::Error::other)
    }
}

async fn pump_request_body<R>(
    reader: &mut R,
    mut sender: http_body_util::channel::Sender<Bytes, io::Error>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            return Ok(());
        }
        if sender
            .send_data(Bytes::copy_from_slice(&buffer[..length]))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

fn origin_response_metadata(
    response: &http::Response<Incoming>,
) -> Vec<CloudflaredMetadata> {
    origin_response_metadata_parts(response.status(), response.headers())
}

fn origin_response_metadata_parts(
    status: StatusCode,
    headers: &HeaderMap,
) -> Vec<CloudflaredMetadata> {
    let mut metadata = vec![CloudflaredMetadata {
        key: CLOUDFLARED_METADATA_HTTP_STATUS.into(),
        value: status.as_u16().to_string(),
    }];
    metadata.extend(headers.iter().filter_map(|(name, value)| {
        value.to_str().ok().map(|value| CloudflaredMetadata {
            key: format!(
                "{}{}",
                super::cloudflared::CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX,
                name.as_str()
            ),
            value: value.into(),
        })
    }));
    metadata
}

async fn copy_origin_body<W>(
    response: http::Response<Incoming>,
    writer: &mut W,
    connect_response: &ConnectResponse,
    decompress_gzip: bool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if decompress_gzip {
        let (encoded_reader, mut encoded_writer) = tokio::io::duplex(32 * 1024);
        let source = async move {
            copy_origin_body_encoded(
                response,
                &mut encoded_writer,
                connect_response,
            )
            .await
        };
        let sink = async move {
            let mut decoder = GzipDecoder::new(BufReader::new(encoded_reader));
            decoder.multiple_members(true);
            tokio::io::copy(&mut decoder, writer).await?;
            Ok::<_, io::Error>(())
        };
        tokio::try_join!(source, sink)?;
        return Ok(());
    }
    copy_origin_body_encoded(response, writer, connect_response).await
}

async fn copy_origin_body_encoded<W>(
    mut response: http::Response<Incoming>,
    writer: &mut W,
    connect_response: &ConnectResponse,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = response.frame().await {
        let frame = frame.map_err(io::Error::other)?;
        match frame.into_data() {
            Ok(data) => writer.write_all(&data).await?,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    connect_response.add_trailers(&trailers);
                }
            }
        }
    }
    Ok(())
}

fn strip_http_host_port(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.split_once(']').map(|(host, _)| host))
        .or_else(|| host.rsplit_once(':').map(|(host, _)| host))
        .unwrap_or(host)
}

#[async_trait]
impl CloudflaredHttp2Handler for CloudflaredOriginService {
    async fn dispatch_request(
        &self,
        stream: CloudflaredHttp2Stream,
        response: CloudflaredHttp2ResponseWriter,
        request: CloudflaredConnectRequest,
    ) {
        self.dispatch(stream, ConnectResponse::Http2(response), request)
            .await;
    }
}

#[async_trait]
impl CloudflaredQuicHandler for CloudflaredOriginService {
    async fn handle_data_stream(
        &self,
        stream: CloudflaredQuicStream,
        request: CloudflaredConnectRequest,
        _connection_index: u8,
    ) {
        self.dispatch(stream, ConnectResponse::Quic, request).await;
    }

    async fn handle_rpc_stream(
        &self,
        stream: CloudflaredQuicStream,
        _connection_index: u8,
        sender: CloudflaredQuicDatagramSender,
    ) {
        self.datagrams.serve_rpc_stream(stream, sender).await;
    }

    async fn handle_datagram(
        &self,
        datagram: Bytes,
        sender: CloudflaredQuicDatagramSender,
    ) {
        self.datagrams.handle_datagram(datagram, sender).await;
    }
}
