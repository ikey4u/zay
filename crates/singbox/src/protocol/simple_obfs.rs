//! SIP003 `obfs-local` compatibility used by Shadowsocks outbounds.

use std::{collections::HashMap, io, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    adapter::{DialFuture, Dialer, PacketFuture, PacketStream, Stream},
    common::network::SocksAddr,
    protocol::snell::wrap_simple_tls_obfs_client,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleObfsMode {
    Http,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleObfsOptions {
    pub mode: SimpleObfsMode,
    pub host: String,
}

impl SimpleObfsOptions {
    pub fn parse(value: &str) -> io::Result<Self> {
        let values = parse_plugin_options(value)?;
        let mode = match values
            .get("obfs")
            .and_then(|values| values.first())
            .map(String::as_str)
            .unwrap_or("http")
        {
            "http" => SimpleObfsMode::Http,
            "tls" => SimpleObfsMode::Tls,
            value => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown obfs mode {value}"),
                ));
            }
        };
        let host = values
            .get("obfs-host")
            .and_then(|values| values.first())
            .cloned()
            .unwrap_or_default();
        Ok(Self { mode, host })
    }
}

pub struct SimpleObfsDialer {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    options: SimpleObfsOptions,
}

impl SimpleObfsDialer {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        options: SimpleObfsOptions,
    ) -> Self {
        Self {
            upstream,
            server,
            options,
        }
    }
}

impl Dialer for SimpleObfsDialer {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let raw = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&raw);
            let stream = match self.options.mode {
                SimpleObfsMode::Http => wrap_http_client(
                    raw,
                    self.options.host.clone(),
                    self.server.port(),
                ),
                SimpleObfsMode::Tls => {
                    wrap_simple_tls_obfs_client(raw, self.options.host.clone())?
                }
            };
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        self.upstream.listen_udp(destination)
    }
}

fn wrap_http_client(raw: Stream, host: String, port: u16) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut application_reader, mut application_writer) =
        tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
    tokio::spawn(async move {
        let mut matched = 0_usize;
        const TERMINATOR: &[u8] = b"\r\n\r\n";
        while matched < TERMINATOR.len() {
            let value = match raw_reader.read_u8().await {
                Ok(value) => value,
                Err(_) => return,
            };
            matched = if value == TERMINATOR[matched] {
                matched + 1
            } else if value == TERMINATOR[0] {
                1
            } else {
                0
            };
        }
        let _ = tokio::io::copy(&mut raw_reader, &mut application_writer).await;
        let _ = application_writer.shutdown().await;
    });
    tokio::spawn(async move {
        let mut first = vec![0_u8; 64 * 1024];
        let size = match application_reader.read(&mut first).await {
            Ok(0) | Err(_) => {
                let _ = raw_writer.shutdown().await;
                return;
            }
            Ok(size) => size,
        };
        let mut key = [0_u8; 16];
        let mut random = [0_u8; 2];
        if getrandom::fill(&mut key).is_err()
            || getrandom::fill(&mut random).is_err()
        {
            return;
        }
        let host = if port == 80 {
            host
        } else {
            format!("{host}:{port}")
        };
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.{}.{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nContent-Length: {size}\r\n\r\n",
            random[0] % 54,
            random[1] % 2,
            URL_SAFE.encode(key),
        );
        if raw_writer.write_all(request.as_bytes()).await.is_err()
            || raw_writer.write_all(&first[..size]).await.is_err()
        {
            return;
        }
        let _ = tokio::io::copy(&mut application_reader, &mut raw_writer).await;
        let _ = raw_writer.shutdown().await;
    });
    Box::new(application)
}

pub(crate) fn parse_plugin_options(
    value: &str,
) -> io::Result<HashMap<String, Vec<String>>> {
    let mut options = HashMap::<String, Vec<String>>::new();
    let mut index = 0;
    while index < value.len() {
        let (key, consumed, separator) = parse_part(&value[index..], b"=;")?;
        if key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty SIP003 plugin option key",
            ));
        }
        index += consumed;
        if separator != Some(b'=') {
            options.entry(key).or_default().push("1".into());
            if separator.is_some() {
                index += 1;
            }
            continue;
        }
        index += 1;
        let (option_value, consumed, separator) =
            parse_part(&value[index..], b";")?;
        index += consumed;
        options.entry(key).or_default().push(option_value);
        if separator.is_some() {
            index += 1;
        }
    }
    Ok(options)
}

fn parse_part(
    value: &str,
    terminators: &[u8],
) -> io::Result<(String, usize, Option<u8>)> {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if terminators.contains(&byte) {
            return String::from_utf8(output)
                .map(|value| (value, index, Some(byte)))
                .map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error)
                });
        }
        if byte == b'\\' {
            index += 1;
            if index == bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "nothing following final SIP003 escape",
                ));
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(output)
        .map(|value| (value, index, None))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn parses_escaped_sip003_options() {
        let options = parse_plugin_options(
            r"obfs=http;obfs-host=cover\;edge\=one;flag;flag=two",
        )
        .unwrap();
        assert_eq!(options["obfs"], ["http"]);
        assert_eq!(options["obfs-host"], ["cover;edge=one"]);
        assert_eq!(options["flag"], ["1", "two"]);
    }

    #[tokio::test]
    async fn http_obfs_matches_sip003_first_request_and_response() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut obfs =
            wrap_http_client(Box::new(client), "cover.test".into(), 8080);
        obfs.write_all(b"encrypted").await.unwrap();
        let mut received = Vec::new();
        let mut byte = [0_u8; 1];
        while !received.ends_with(b"\r\n\r\nencrypted") {
            server.read_exact(&mut byte).await.unwrap();
            received.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&received);
        assert!(text.starts_with("GET / HTTP/1.1\r\n"));
        assert!(text.contains("Host: cover.test:8080\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        server
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\ndecrypted")
            .await
            .unwrap();
        let mut response = [0_u8; 9];
        obfs.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"decrypted");
    }
}
