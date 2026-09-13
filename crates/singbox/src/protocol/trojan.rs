//! Trojan authentication, request and UDP stream framing.

use std::{io, sync::Arc};

use sha2::{Digest, Sha224};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
    },
    sync::Mutex,
};

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::network::SocksAddr,
    protocol::socks::{read_address, write_address},
};

pub const KEY_LENGTH: usize = 56;
pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 3;
pub const COMMAND_MUX: u8 = 0x7f;
const CRLF: [u8; 2] = [b'\r', b'\n'];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
}

impl Command {
    fn byte(self) -> u8 {
        match self {
            Self::Tcp => COMMAND_TCP,
            Self::Udp => COMMAND_UDP,
            Self::Mux => COMMAND_MUX,
        }
    }

    fn parse(value: u8) -> io::Result<Self> {
        match value {
            COMMAND_TCP => Ok(Self::Tcp),
            COMMAND_UDP => Ok(Self::Udp),
            COMMAND_MUX => Ok(Self::Mux),
            value => {
                Err(invalid_data(format!("unknown Trojan command: {value}")))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub destination: SocksAddr,
    pub user: usize,
}

#[derive(Debug)]
pub enum RequestError {
    Io(io::Error),
    InvalidPassword(Vec<u8>),
}

impl From<io::Error> for RequestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn key(password: &str) -> [u8; KEY_LENGTH] {
    let digest = Sha224::digest(password.as_bytes());
    let encoded = hex::encode(digest);
    let mut key = [0_u8; KEY_LENGTH];
    key.copy_from_slice(encoded.as_bytes());
    key
}

pub async fn write_request<S>(
    stream: &mut S,
    key: &[u8; KEY_LENGTH],
    command: Command,
    destination: &SocksAddr,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(key).await?;
    stream.write_all(&CRLF).await?;
    stream.write_u8(command.byte()).await?;
    write_address(stream, destination).await?;
    stream.write_all(&CRLF).await?;
    stream.flush().await
}

pub async fn read_request<S>(
    stream: &mut S,
    keys: &[[u8; KEY_LENGTH]],
) -> io::Result<Request>
where
    S: AsyncRead + Unpin + ?Sized,
{
    read_request_with_fallback(stream, keys).await.map_err(
        |error| match error {
            RequestError::Io(error) => error,
            RequestError::InvalidPassword(_) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Trojan password",
            ),
        },
    )
}

pub async fn read_request_with_fallback<S>(
    stream: &mut S,
    keys: &[[u8; KEY_LENGTH]],
) -> Result<Request, RequestError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut presented = [0_u8; KEY_LENGTH];
    let size = stream.read(&mut presented).await?;
    if size != KEY_LENGTH {
        return Err(RequestError::InvalidPassword(presented[..size].to_vec()));
    }
    let user = keys
        .iter()
        .position(|candidate| constant_time_equal(candidate, &presented))
        .ok_or_else(|| RequestError::InvalidPassword(presented.to_vec()))?;
    read_crlf(stream, "authentication").await?;
    let command = Command::parse(stream.read_u8().await?)?;
    let destination = read_address(stream).await?;
    read_crlf(stream, "request").await?;
    Ok(Request {
        command,
        destination,
        user,
    })
}

pub struct TrojanOutbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    key: [u8; KEY_LENGTH],
}

impl TrojanOutbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        password: &str,
    ) -> Self {
        Self {
            upstream,
            server,
            key: key(password),
        }
    }
}

impl Dialer for TrojanOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            let socket = crate::adapter::stream_socket(&stream);
            write_request(&mut stream, &self.key, Command::Tcp, destination)
                .await?;
            Ok(crate::adapter::preserve_stream_socket(stream, socket))
        })
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            write_request(&mut stream, &self.key, Command::Udp, destination)
                .await?;
            Ok(Box::new(TrojanPacketConnection::new(stream)) as PacketStream)
        })
    }
}

pub struct TrojanPacketConnection {
    reader: Mutex<ReadHalf<Stream>>,
    writer: Mutex<WriteHalf<Stream>>,
}

impl TrojanPacketConnection {
    pub fn new(stream: Stream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

impl PacketConnection for TrojanPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let length = u16::try_from(data.len()).map_err(|_| {
                invalid_input("Trojan UDP packet is longer than 65535 bytes")
            })?;
            let mut writer = self.writer.lock().await;
            write_address(&mut *writer, destination).await?;
            writer.write_u16(length).await?;
            writer.write_all(&CRLF).await?;
            writer.write_all(data).await?;
            writer.flush().await?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            let destination = read_address(&mut *reader).await?;
            let length = reader.read_u16().await? as usize;
            read_crlf(&mut *reader, "UDP packet").await?;
            if length > data.len() {
                return Err(invalid_data("Trojan UDP payload exceeds buffer"));
            }
            reader.read_exact(&mut data[..length]).await?;
            Ok((length, destination))
        })
    }
}

async fn read_crlf<S>(stream: &mut S, context: &str) -> io::Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut crlf = [0_u8; 2];
    stream.read_exact(&mut crlf).await?;
    if crlf != CRLF {
        return Err(invalid_data(format!(
            "invalid Trojan {context} delimiter"
        )));
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;

    use super::{
        Command, KEY_LENGTH, TrojanPacketConnection, key, read_request,
        write_request,
    };
    use crate::{
        adapter::{PacketConnection, Stream},
        common::network::SocksAddr,
    };

    #[test]
    fn password_key_is_lowercase_sha224_hex() {
        let key = key("password");
        assert_eq!(key.len(), KEY_LENGTH);
        assert_eq!(
            std::str::from_utf8(&key).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[tokio::test]
    async fn request_wire_round_trips_and_authenticates() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let expected = key("secret");
        let destination = SocksAddr::new("example.com", 443);
        let sent = destination.clone();
        let task = tokio::spawn(async move {
            write_request(&mut client, &expected, Command::Tcp, &sent)
                .await
                .unwrap();
        });
        let request = read_request(&mut server, &[key("wrong"), key("secret")])
            .await
            .unwrap();
        assert_eq!(request.command, Command::Tcp);
        assert_eq!(request.destination, destination);
        assert_eq!(request.user, 1);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_frames_round_trip_in_both_directions() {
        let (left, right) = tokio::io::duplex(1024);
        let left = TrojanPacketConnection::new(Box::new(left) as Stream);
        let right =
            Arc::new(TrojanPacketConnection::new(Box::new(right) as Stream));
        let destination = SocksAddr::new("dns.example", 53);
        left.send_to(b"query", &destination).await.unwrap();
        let mut buffer = [0_u8; 32];
        let (size, received) = right.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..size], b"query");
        assert_eq!(received, destination);
        right.send_to(b"response", &received).await.unwrap();
        let (size, received) = left.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..size], b"response");
        assert_eq!(received, destination);
    }

    #[tokio::test]
    async fn rejects_bad_delimiters_and_passwords() {
        let mut bytes = Vec::from(key("secret"));
        bytes.extend_from_slice(b"xx\x01\x01\x7f\x00\x00\x01\x00\x50\r\n");
        assert_eq!(
            read_request(&mut bytes.as_slice(), &[key("secret")])
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let (mut client, mut server) = tokio::io::duplex(128);
        client.write_all(&key("wrong")).await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(
            read_request(&mut server, &[key("secret")])
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
