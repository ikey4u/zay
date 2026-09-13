//! SagerNet UDP-over-TCP framing used by several proxy outbounds.

use std::{io, net::IpAddr};

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
};

pub const VERSION: u8 = 2;
pub const LEGACY_VERSION: u8 = 1;
pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

const ADDRESS_IPV4: u8 = 0;
const ADDRESS_IPV6: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub is_connect: bool,
    pub destination: SocksAddr,
}

pub fn magic_destination(version: u8) -> io::Result<SocksAddr> {
    match version {
        0 | VERSION => Ok(SocksAddr::new(MAGIC_ADDRESS, 0)),
        LEGACY_VERSION => Ok(SocksAddr::new(LEGACY_MAGIC_ADDRESS, 0)),
        version => Err(invalid_input(format!(
            "unknown UDP-over-TCP version: {version}"
        ))),
    }
}

pub fn destination_version(destination: &SocksAddr) -> Option<u8> {
    let SocksAddr::Domain { host, .. } = destination else {
        return None;
    };
    if host.eq_ignore_ascii_case(MAGIC_ADDRESS) {
        Some(VERSION)
    } else if host.eq_ignore_ascii_case(LEGACY_MAGIC_ADDRESS) {
        Some(LEGACY_VERSION)
    } else {
        None
    }
}

pub async fn write_request<S>(
    stream: &mut S,
    request: &Request,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_u8(u8::from(request.is_connect)).await?;
    write_address(stream, &request.destination).await?;
    stream.flush().await
}

pub async fn read_request<S>(stream: &mut S) -> io::Result<Request>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let is_connect = match stream.read_u8().await? {
        0 => false,
        1 => true,
        value => {
            return Err(invalid_data(format!(
                "invalid UDP-over-TCP isConnect value: {value}"
            )));
        }
    };
    Ok(Request {
        is_connect,
        destination: read_address(stream).await?,
    })
}

pub struct UotOutbound<D> {
    upstream: D,
    version: u8,
}

impl<D> UotOutbound<D> {
    pub fn new(upstream: D, version: u8) -> io::Result<Self> {
        magic_destination(version)?;
        Ok(Self { upstream, version })
    }
}

impl<D: Dialer> Dialer for UotOutbound<D> {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        self.upstream.dial_tcp(destination)
    }

    fn listen_udp<'a>(
        &'a self,
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let magic = magic_destination(self.version)?;
            let mut stream = self.upstream.dial_tcp(&magic).await?;
            let request = Request {
                is_connect: false,
                destination: destination.clone(),
            };
            if self.version != LEGACY_VERSION {
                write_request(&mut stream, &request).await?;
            }
            Ok(Box::new(UotPacketConnection::new(stream, request))
                as PacketStream)
        })
    }
}

pub struct UotPacketConnection {
    reader: Mutex<ReadHalf<Stream>>,
    writer: Mutex<WriteHalf<Stream>>,
    request: Request,
}

impl UotPacketConnection {
    pub fn new(stream: Stream, request: Request) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            request,
        }
    }
}

impl PacketConnection for UotPacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let length = u16::try_from(data.len()).map_err(|_| {
                invalid_input("UDP-over-TCP packet is longer than 65535 bytes")
            })?;
            let mut writer = self.writer.lock().await;
            if !self.request.is_connect {
                write_address(&mut *writer, destination).await?;
            }
            writer.write_u16(length).await?;
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
            let destination = if self.request.is_connect {
                self.request.destination.clone()
            } else {
                read_address(&mut *reader).await?
            };
            let length = reader.read_u16().await? as usize;
            if length > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP-over-TCP payload exceeds buffer",
                ));
            }
            reader.read_exact(&mut data[..length]).await?;
            Ok((length, destination))
        })
    }
}

pub async fn accept(
    mut stream: Stream,
    version: u8,
) -> io::Result<UotPacketConnection> {
    let request = match version {
        VERSION => read_request(&mut stream).await?,
        LEGACY_VERSION => Request {
            is_connect: false,
            destination: SocksAddr::new("0.0.0.0", 0),
        },
        version => {
            return Err(invalid_input(format!(
                "unknown UDP-over-TCP version: {version}"
            )));
        }
    };
    Ok(UotPacketConnection::new(stream, request))
}

async fn write_address<S>(stream: &mut S, address: &SocksAddr) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    match address {
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => {
                stream.write_u8(ADDRESS_IPV4).await?;
                stream.write_all(&ip.octets()).await?;
            }
            IpAddr::V6(ip) => {
                stream.write_u8(ADDRESS_IPV6).await?;
                stream.write_all(&ip.octets()).await?;
            }
        },
        SocksAddr::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                invalid_input("UDP-over-TCP domain is longer than 255 bytes")
            })?;
            stream.write_u8(ADDRESS_DOMAIN).await?;
            stream.write_u8(length).await?;
            stream.write_all(host.as_bytes()).await?;
        }
    }
    stream.write_u16(address.port()).await
}

async fn read_address<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let host = match stream.read_u8().await? {
        ADDRESS_IPV4 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        ADDRESS_IPV6 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes).await?;
            std::net::Ipv6Addr::from(bytes).to_string()
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0_u8; length];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes)
                .map_err(|_| invalid_data("UDP-over-TCP domain is not UTF-8"))?
        }
        value => {
            return Err(invalid_data(format!(
                "unknown UDP-over-TCP address type: {value}"
            )));
        }
    };
    Ok(SocksAddr::new(host, stream.read_u16().await?))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::{Request, read_request, write_request};

    #[tokio::test]
    async fn request_wire_format_matches_version_two() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let request = Request {
            is_connect: true,
            destination: "example.com:53".parse().unwrap(),
        };
        let write = tokio::spawn(async move {
            write_request(&mut client, &request).await.unwrap();
        });
        let mut wire = [0_u8; 16];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire, b"\x01\x02\x0bexample.com\0\x35");
        write.await.unwrap();
    }

    #[tokio::test]
    async fn request_codec_round_trips_ipv4_ipv6_and_domain() {
        for destination in [
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:5353".parse().unwrap(),
            "example.com:853".parse().unwrap(),
        ] {
            let (mut client, mut server) = tokio::io::duplex(256);
            let expected = Request {
                is_connect: false,
                destination,
            };
            let sent = expected.clone();
            let write = tokio::spawn(async move {
                write_request(&mut client, &sent).await.unwrap();
            });
            assert_eq!(read_request(&mut server).await.unwrap(), expected);
            write.await.unwrap();
        }
    }

    #[tokio::test]
    async fn packet_connection_round_trips_connect_and_unconnected_frames() {
        for is_connect in [false, true] {
            let (left, right) = tokio::io::duplex(1024);
            let destination: crate::common::network::SocksAddr =
                "example.com:53".parse().unwrap();
            let left = super::UotPacketConnection::new(
                Box::new(left),
                Request {
                    is_connect,
                    destination: destination.clone(),
                },
            );
            let right = super::UotPacketConnection::new(
                Box::new(right),
                Request {
                    is_connect,
                    destination: destination.clone(),
                },
            );
            crate::adapter::PacketConnection::send_to(
                &left,
                b"payload",
                &destination,
            )
            .await
            .unwrap();
            let mut bytes = [0_u8; 32];
            let (size, received_destination) =
                crate::adapter::PacketConnection::recv_from(&right, &mut bytes)
                    .await
                    .unwrap();
            assert_eq!(received_destination, destination);
            assert_eq!(&bytes[..size], b"payload");
        }
    }
}
