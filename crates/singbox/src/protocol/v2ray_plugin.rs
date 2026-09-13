//! Built-in SIP003 `v2ray-plugin` compatibility for Shadowsocks.

use std::{io, sync::Arc};

use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    adapter::{DialFuture, Dialer, PacketFuture, PacketStream, Stream},
    common::{
        network::SocksAddr,
        tls::{ClientTlsDialer, build_client_config},
    },
    option::{Listable, OutboundTlsOptions, V2RayWebsocketOptions},
    protocol::simple_obfs::parse_plugin_options,
    transport::{quic::QuicDialer, v2ray::WebsocketDialer},
};

const VMESS_MUX_DESTINATION: &str = "v1.mux.cool";
const VMESS_MUX_PORT: u16 = 666;
const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_TCP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2RayPluginMode {
    Websocket,
    Quic,
}

#[derive(Debug, Clone, PartialEq)]
pub struct V2RayPluginOptions {
    pub mode: V2RayPluginMode,
    pub host: String,
    pub path: String,
    pub mux: i32,
    pub tls: Option<OutboundTlsOptions>,
}

impl V2RayPluginOptions {
    pub fn parse(value: &str) -> io::Result<Self> {
        let values = parse_plugin_options(value)?;
        let first = |key: &str| {
            values
                .get(key)
                .and_then(|values| values.first())
                .map(String::as_str)
        };
        let mode = match first("mode").unwrap_or("websocket") {
            "websocket" => V2RayPluginMode::Websocket,
            "quic" => V2RayPluginMode::Quic,
            value => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("v2ray-plugin: unknown mode: {value}"),
                ));
            }
        };
        let host = first("host").unwrap_or("cloudfront.com").to_owned();
        let path = first("path").unwrap_or("/").to_owned();
        let mux = if mode == V2RayPluginMode::Websocket {
            first("mux")
                .map(str::parse::<i32>)
                .transpose()
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("parse mux value: {error}"),
                    )
                })?
                .unwrap_or(1)
        } else {
            0
        };
        let tls = if values.contains_key("tls") {
            let mut tls = OutboundTlsOptions {
                enabled: true,
                ..OutboundTlsOptions::default()
            };
            if values.contains_key("host") {
                tls.server_name = host.clone();
            }
            if let Some(path) = first("cert") {
                tls.certificate_path = path.to_owned();
            }
            if let Some(raw) = first("certRaw") {
                tls.certificate = Listable(vec![format!(
                    "-----BEGIN CERTIFICATE-----\n{raw}\n-----END CERTIFICATE-----"
                )]);
            }
            Some(tls)
        } else {
            None
        };
        Ok(Self {
            mode,
            host,
            path,
            mux,
            tls,
        })
    }
}

/// A plugin changes only the Shadowsocks TCP path. UDP remains on the original
/// dialer, matching sing-box's `sip003.Plugin` interface.
pub struct V2RayPluginDialer {
    transport: Arc<dyn Dialer>,
    udp_upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    mux: bool,
}

impl V2RayPluginDialer {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        options: V2RayPluginOptions,
    ) -> io::Result<Self> {
        let udp_upstream = upstream.clone();
        let transport: Arc<dyn Dialer> = match options.mode {
            V2RayPluginMode::Websocket => {
                let upstream = if let Some(tls_options) = &options.tls {
                    let tls = build_client_config(
                        &server.host(),
                        tls_options,
                        &["http/1.1"],
                    )
                    .map_err(io::Error::other)?;
                    Arc::new(ClientTlsDialer::new(upstream, tls))
                        as Arc<dyn Dialer>
                } else {
                    upstream
                };
                let mut headers = Map::new();
                headers.insert("Host".into(), Value::String(options.host));
                Arc::new(WebsocketDialer::new(
                    upstream,
                    server.clone(),
                    V2RayWebsocketOptions {
                        path: options.path,
                        headers,
                        ..V2RayWebsocketOptions::default()
                    },
                )?)
            }
            V2RayPluginMode::Quic => {
                let tls_options = options.tls.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "V2Ray QUIC transport requires TLS",
                    )
                })?;
                let server_name = if tls_options.server_name.is_empty() {
                    server.host()
                } else {
                    tls_options.server_name.clone()
                };
                let tls =
                    build_client_config(&server.host(), tls_options, &["h3"])
                        .map_err(io::Error::other)?;
                Arc::new(QuicDialer::new_with_packet_dialer(
                    server.clone(),
                    server_name,
                    tls,
                    upstream,
                )?)
            }
        };
        Ok(Self {
            transport,
            udp_upstream,
            server,
            mux: options.mux > 0,
        })
    }
}

impl Dialer for V2RayPluginDialer {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = self.transport.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            let stream = if self.mux {
                wrap_vmess_mux_client(stream)
            } else {
                stream
            };
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        self.udp_upstream.listen_udp(destination)
    }
}

/// Adapt one byte stream to the legacy VMess mux framing used by the original
/// v2ray-plugin when its (default-on) `mux` option is positive.
pub fn wrap_vmess_mux_client(raw: Stream) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut application_reader, mut application_writer) =
        tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
    tokio::spawn(async move {
        loop {
            let header_length = match raw_reader.read_u16().await {
                Ok(length) if length >= 4 => usize::from(length),
                _ => break,
            };
            let _session_id = match raw_reader.read_u16().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let status = match raw_reader.read_u8().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let option = match raw_reader.read_u8().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let mut extra = vec![0_u8; header_length - 4];
            if raw_reader.read_exact(&mut extra).await.is_err() {
                break;
            }
            match status {
                STATUS_NEW => break,
                STATUS_KEEP | STATUS_KEEP_ALIVE => {}
                STATUS_END => break,
                _ => break,
            }
            if option & OPTION_ERROR != 0 {
                break;
            }
            if option & OPTION_DATA == 0 {
                continue;
            }
            let payload_length = match raw_reader.read_u16().await {
                Ok(value) => usize::from(value),
                Err(_) => break,
            };
            let mut payload = vec![0_u8; payload_length];
            if raw_reader.read_exact(&mut payload).await.is_err()
                || application_writer.write_all(&payload).await.is_err()
            {
                break;
            }
        }
        let _ = application_writer.shutdown().await;
    });
    tokio::spawn(async move {
        let mut request_written = false;
        let mut payload = vec![0_u8; usize::from(u16::MAX)];
        loop {
            let size = match application_reader.read(&mut payload).await {
                Ok(0) | Err(_) => break,
                Ok(size) => size,
            };
            let result = if !request_written {
                request_written = true;
                write_vmess_mux_new(&mut raw_writer, &payload[..size]).await
            } else {
                write_vmess_mux_keep(&mut raw_writer, &payload[..size]).await
            };
            if result.is_err() {
                break;
            }
        }
        let _ = raw_writer.shutdown().await;
    });
    Box::new(application)
}

async fn write_vmess_mux_new<W>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let destination = VMESS_MUX_DESTINATION.as_bytes();
    let address_length = 2 + 1 + 1 + destination.len();
    writer.write_u16((5 + address_length) as u16).await?;
    writer.write_u16(0).await?;
    writer.write_u8(STATUS_NEW).await?;
    writer.write_u8(OPTION_DATA).await?;
    writer.write_u8(NETWORK_TCP).await?;
    writer.write_u16(VMESS_MUX_PORT).await?;
    writer.write_u8(0x02).await?;
    writer.write_u8(destination.len() as u8).await?;
    writer.write_all(destination).await?;
    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

async fn write_vmess_mux_keep<W>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    writer.write_u16(4).await?;
    writer.write_u16(0).await?;
    writer.write_u8(STATUS_KEEP).await?;
    writer.write_u8(OPTION_DATA).await?;
    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use crate::{
        common::tls::build_server_config_with_default_alpn,
        option::{DirectOutboundOptions, InboundTlsOptions},
        protocol::direct::DirectOutbound,
        transport::{quic::server_config, v2ray::accept_websocket},
    };
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use super::*;

    #[test]
    fn parses_upstream_defaults_tls_certificate_and_modes() {
        let defaults = V2RayPluginOptions::parse("").unwrap();
        assert_eq!(defaults.mode, V2RayPluginMode::Websocket);
        assert_eq!(defaults.host, "cloudfront.com");
        assert_eq!(defaults.path, "/");
        assert_eq!(defaults.mux, 1);
        assert!(defaults.tls.is_none());

        let configured = V2RayPluginOptions::parse(
            "tls;host=cover.test;path=/edge;mux=0;certRaw=YWJj",
        )
        .unwrap();
        assert_eq!(configured.path, "/edge");
        assert_eq!(configured.mux, 0);
        let tls = configured.tls.unwrap();
        assert_eq!(tls.server_name, "cover.test");
        assert_eq!(
            tls.certificate.as_slice(),
            ["-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----"]
        );

        let quic = V2RayPluginOptions::parse("mode=quic;mux=9").unwrap();
        assert_eq!(quic.mode, V2RayPluginMode::Quic);
        assert_eq!(quic.mux, 0);
        assert!(V2RayPluginOptions::parse("mode=grpc").is_err());
        assert!(V2RayPluginOptions::parse("mux=bad").is_err());
    }

    #[tokio::test]
    async fn legacy_mux_wrapper_matches_first_keep_and_response_frames() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut mux = wrap_vmess_mux_client(Box::new(client));
        mux.write_all(b"request").await.unwrap();

        assert_eq!(server.read_u16().await.unwrap(), 20);
        assert_eq!(server.read_u16().await.unwrap(), 0);
        assert_eq!(server.read_u8().await.unwrap(), STATUS_NEW);
        assert_eq!(server.read_u8().await.unwrap(), OPTION_DATA);
        assert_eq!(server.read_u8().await.unwrap(), NETWORK_TCP);
        assert_eq!(server.read_u16().await.unwrap(), VMESS_MUX_PORT);
        assert_eq!(server.read_u8().await.unwrap(), 0x02);
        assert_eq!(server.read_u8().await.unwrap(), 11);
        let mut domain = [0_u8; 11];
        server.read_exact(&mut domain).await.unwrap();
        assert_eq!(&domain, VMESS_MUX_DESTINATION.as_bytes());
        assert_eq!(server.read_u16().await.unwrap(), 7);
        let mut request = [0_u8; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        mux.write_all(b"again").await.unwrap();
        assert_eq!(server.read_u16().await.unwrap(), 4);
        assert_eq!(server.read_u16().await.unwrap(), 0);
        assert_eq!(server.read_u8().await.unwrap(), STATUS_KEEP);
        assert_eq!(server.read_u8().await.unwrap(), OPTION_DATA);
        assert_eq!(server.read_u16().await.unwrap(), 5);
        let mut again = [0_u8; 5];
        server.read_exact(&mut again).await.unwrap();
        assert_eq!(&again, b"again");

        server.write_u16(4).await.unwrap();
        server.write_u16(0).await.unwrap();
        server.write_u8(STATUS_KEEP).await.unwrap();
        server.write_u8(OPTION_DATA).await.unwrap();
        server.write_u16(8).await.unwrap();
        server.write_all(b"response").await.unwrap();
        let mut response = [0_u8; 8];
        mux.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
    }

    #[tokio::test]
    async fn websocket_mode_forms_a_real_byte_stream_without_mux() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = accept_websocket(
                Box::new(stream),
                &V2RayWebsocketOptions {
                    path: "/edge".into(),
                    ..V2RayWebsocketOptions::default()
                },
            )
            .await
            .unwrap();
            let mut request = [0_u8; 7];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            stream.write_all(b"response").await.unwrap();
        });

        let options =
            V2RayPluginOptions::parse("host=cover.test;path=/edge;mux=0")
                .unwrap();
        let plugin = V2RayPluginDialer::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            server.into(),
            options,
        )
        .unwrap();
        let mut stream = plugin
            .dial_tcp(&SocksAddr::new("ignored.test", 1))
            .await
            .unwrap();
        stream.write_all(b"request").await.unwrap();
        let mut response = [0_u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        server_task.await.unwrap();
    }

    #[test]
    fn quic_mode_requires_tls_during_construction() {
        let options = V2RayPluginOptions::parse("mode=quic").unwrap();
        let result = V2RayPluginDialer::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            SocksAddr::new("127.0.0.1", 443),
            options,
        );
        let error = match result {
            Ok(_) => panic!("QUIC v2ray-plugin without TLS was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("requires TLS"));
    }

    #[tokio::test]
    async fn quic_mode_uses_cert_raw_and_forms_a_real_byte_stream() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_tls: InboundTlsOptions =
            serde_json::from_value(serde_json::json!({
                "enabled":true,
                "certificate":cert.pem(),
                "key":key_pair.serialize_pem()
            }))
            .unwrap();
        let server_tls =
            build_server_config_with_default_alpn(&server_tls, &["h3"])
                .unwrap();
        let endpoint = quinn::Endpoint::server(
            server_config(server_tls).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server = endpoint.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let mut request = [0_u8; 7];
            receive.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            send.write_all(b"response").await.unwrap();
            send.finish().unwrap();
            let _ = done_rx.await;
        });

        let raw_certificate: String = cert
            .pem()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let options = V2RayPluginOptions::parse(&format!(
            "mode=quic;tls;host=localhost;certRaw={raw_certificate}"
        ))
        .unwrap();
        let plugin = V2RayPluginDialer::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            server.into(),
            options,
        )
        .unwrap();
        let mut stream = plugin
            .dial_tcp(&SocksAddr::new("ignored.test", 1))
            .await
            .unwrap();
        stream.write_all(b"request").await.unwrap();
        let mut response = [0_u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        let _ = done_tx.send(());
        server_task.await.unwrap();
    }
}
