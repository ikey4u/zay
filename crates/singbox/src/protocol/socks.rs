//! SOCKS protocol primitives and outbound dialer.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::Mutex,
};

use crate::{
    adapter::{
        DialFuture, Dialer, PacketConnection, PacketFuture, PacketStream,
        Stream,
    },
    common::network::SocksAddr,
    dns::Resolver,
    option::{DomainStrategy, User},
};

const VERSION_4: u8 = 4;
const VERSION_5: u8 = 5;
const METHOD_NONE: u8 = 0;
const METHOD_USERNAME_PASSWORD: u8 = 2;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_BIND: u8 = 2;
const COMMAND_UDP_ASSOCIATE: u8 = 3;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;
const REPLY_4_GRANTED: u8 = 90;
const REPLY_4_REJECTED: u8 = 91;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V4,
    V4a,
    V5,
}

impl SocksVersion {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "4" => Ok(Self::V4),
            "4a" => Ok(Self::V4a),
            "" | "5" => Ok(Self::V5),
            value => {
                Err(invalid_input(format!("unknown SOCKS version: {value}")))
            }
        }
    }
}

pub struct Socks4Outbound {
    upstream: std::sync::Arc<dyn Dialer>,
    resolver: std::sync::Arc<dyn Resolver>,
    strategy: DomainStrategy,
    server: SocksAddr,
    username: String,
    resolve_locally: bool,
}

impl Socks4Outbound {
    pub fn new(
        upstream: std::sync::Arc<dyn Dialer>,
        resolver: std::sync::Arc<dyn Resolver>,
        strategy: DomainStrategy,
        server: SocksAddr,
        username: impl Into<String>,
        resolve_locally: bool,
    ) -> Self {
        Self {
            upstream,
            resolver,
            strategy,
            server,
            username: username.into(),
            resolve_locally,
        }
    }

    async fn dial_one(&self, destination: &SocksAddr) -> io::Result<Stream> {
        let mut stream = self.upstream.dial_tcp(&self.server).await?;
        client_handshake4(&mut stream, destination, &self.username).await?;
        Ok(stream)
    }

    async fn bind_one(&self, destination: &SocksAddr) -> io::Result<Stream> {
        let mut stream = self.upstream.dial_tcp(&self.server).await?;
        client_bind4(&mut stream, destination, &self.username).await?;
        Ok(stream)
    }
}

impl Dialer for Socks4Outbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            if !self.resolve_locally || !destination.is_domain() {
                return self.dial_one(destination).await;
            }
            let host = destination.host();
            let addresses = self.resolver.lookup(&host, self.strategy).await?;
            let mut last_error = None;
            for address in addresses {
                let resolved =
                    SocksAddr::new(address.to_string(), destination.port());
                match self.dial_one(&resolved).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "SOCKS4 destination resolved to no addresses",
                )
            }))
        })
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move { self.bind_one(destination).await })
    }
}

pub struct Socks5Outbound<D> {
    upstream: D,
    server: SocksAddr,
    username: String,
    password: String,
}

impl<D> Socks5Outbound<D> {
    pub fn new(
        upstream: D,
        server: SocksAddr,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            upstream,
            server,
            username: username.into(),
            password: password.into(),
        }
    }
}

impl<D: Dialer> Dialer for Socks5Outbound<D> {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            client_handshake(
                &mut stream,
                destination,
                (!self.username.is_empty()).then_some((
                    self.username.as_str(),
                    self.password.as_str(),
                )),
            )
            .await?;
            Ok(stream)
        })
    }

    fn bind_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            client_bind(
                &mut stream,
                destination,
                (!self.username.is_empty()).then_some((
                    self.username.as_str(),
                    self.password.as_str(),
                )),
            )
            .await?;
            Ok(stream)
        })
    }

    fn listen_udp<'a>(
        &'a self,
        _destination: &'a SocksAddr,
    ) -> PacketFuture<'a, PacketStream> {
        Box::pin(async move {
            let mut control = self.upstream.dial_tcp(&self.server).await?;
            let mut relay = client_command_handshake(
                &mut control,
                &SocksAddr::new("0.0.0.0", 0),
                (!self.username.is_empty()).then_some((
                    self.username.as_str(),
                    self.password.as_str(),
                )),
                COMMAND_UDP_ASSOCIATE,
            )
            .await?;
            if relay
                .host()
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified())
            {
                let server = self
                    .server
                    .resolve()
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "SOCKS server has no address",
                        )
                    })?;
                relay = SocksAddr::new(server.ip().to_string(), relay.port());
            }
            let relay_address =
                relay.resolve().await?.into_iter().next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "SOCKS UDP relay has no address",
                    )
                })?;
            let bind = if relay_address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(relay_address).await?;
            Ok(Box::new(Socks5PacketConnection {
                socket,
                _control: Mutex::new(control),
            }) as PacketStream)
        })
    }
}

pub async fn client_handshake<S>(
    stream: &mut S,
    destination: &SocksAddr,
    credentials: Option<(&str, &str)>,
) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    client_command_handshake(stream, destination, credentials, COMMAND_CONNECT)
        .await
}

pub async fn client_handshake4<S>(
    stream: &mut S,
    destination: &SocksAddr,
    username: &str,
) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    client_command_handshake4(stream, destination, username, COMMAND_CONNECT)
        .await
}

pub async fn client_bind4<S>(
    stream: &mut S,
    destination: &SocksAddr,
    username: &str,
) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    client_command_handshake4(stream, destination, username, COMMAND_BIND).await
}

async fn client_command_handshake4<S>(
    stream: &mut S,
    destination: &SocksAddr,
    username: &str,
    command: u8,
) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if username.len() > u8::MAX as usize {
        return Err(invalid_input("SOCKS4 username is longer than 255 bytes"));
    }
    stream.write_all(&[VERSION_4, command]).await?;
    stream.write_u16(destination.port()).await?;
    match destination {
        SocksAddr::Ip(address) if address.ip().is_ipv4() => {
            let IpAddr::V4(ip) = address.ip() else {
                unreachable!()
            };
            stream.write_all(&ip.octets()).await?;
        }
        _ => stream.write_all(&[0, 0, 0, 1]).await?,
    }
    stream.write_all(username.as_bytes()).await?;
    stream.write_u8(0).await?;
    if !matches!(destination, SocksAddr::Ip(address) if address.ip().is_ipv4())
    {
        let host = destination.host();
        if host.len() > u8::MAX as usize {
            return Err(invalid_input(
                "SOCKS4a destination hostname is longer than 255 bytes",
            ));
        }
        stream.write_all(host.as_bytes()).await?;
        stream.write_u8(0).await?;
    }
    stream.flush().await?;

    read_command_response4(stream).await
}

pub async fn client_accept_bind4<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    read_command_response4(stream).await
}

async fn read_command_response4<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut response = [0_u8; 8];
    stream.read_exact(&mut response).await?;
    if response[0] != 0 {
        return Err(invalid_data("invalid SOCKS4 response version"));
    }
    if response[1] != REPLY_4_GRANTED {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS4 request rejected with reply {}", response[1]),
        ));
    }
    Ok(SocksAddr::new(
        Ipv4Addr::new(response[4], response[5], response[6], response[7])
            .to_string(),
        u16::from_be_bytes([response[2], response[3]]),
    ))
}

pub async fn client_udp_associate<S>(
    stream: &mut S,
    client_address: &SocksAddr,
    credentials: Option<(&str, &str)>,
) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    client_command_handshake(
        stream,
        client_address,
        credentials,
        COMMAND_UDP_ASSOCIATE,
    )
    .await
}

pub async fn client_bind<S>(
    stream: &mut S,
    address: &SocksAddr,
    credentials: Option<(&str, &str)>,
) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    client_command_handshake(stream, address, credentials, COMMAND_BIND).await
}

pub async fn client_accept_bind<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    read_command_response(stream).await
}

async fn client_command_handshake<S>(
    stream: &mut S,
    destination: &SocksAddr,
    credentials: Option<(&str, &str)>,
    command: u8,
) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let methods: &[u8] = if credentials.is_some() {
        &[METHOD_NONE, METHOD_USERNAME_PASSWORD]
    } else {
        &[METHOD_NONE]
    };
    stream.write_all(&[VERSION_5, methods.len() as u8]).await?;
    stream.write_all(methods).await?;
    stream.flush().await?;

    let mut selection = [0_u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != VERSION_5 {
        return Err(invalid_data("invalid SOCKS version in method response"));
    }
    match selection[1] {
        METHOD_NONE => {}
        METHOD_USERNAME_PASSWORD => {
            authenticate(stream, credentials).await?;
        }
        METHOD_UNACCEPTABLE => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no acceptable SOCKS authentication method",
            ));
        }
        method => {
            return Err(invalid_data(format!(
                "unknown SOCKS authentication method: {method}"
            )));
        }
    }

    stream.write_all(&[VERSION_5, command, 0]).await?;
    write_address(stream, destination).await?;
    stream.flush().await?;
    read_command_response(stream).await
}

async fn read_command_response<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut response = [0_u8; 3];
    stream.read_exact(&mut response).await?;
    if response[0] != VERSION_5 || response[2] != 0 {
        return Err(invalid_data("invalid SOCKS command response"));
    }
    if response[1] != 0 {
        return Err(io::Error::new(
            reply_error_kind(response[1]),
            format!("SOCKS command failed with reply {}", response[1]),
        ));
    }
    read_address(stream).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksCommand {
    Connect,
    Bind,
    UdpAssociate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub version: SocksVersion,
    pub command: SocksCommand,
    pub destination: SocksAddr,
    pub user: Option<String>,
}

/// Accept a SOCKS5 CONNECT request and return its destination and authenticated
/// username. The caller sends the final command reply after routing succeeds or
/// fails, matching sing-box's split handshake/connection-handler lifecycle.
pub async fn server_handshake<S>(
    stream: &mut S,
    users: &[User],
) -> io::Result<(SocksAddr, Option<String>)>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let request = server_request(stream, users).await?;
    if request.command != SocksCommand::Connect {
        write_reply(stream, 7, None).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported SOCKS command: {:?}", request.command),
        ));
    }
    Ok((request.destination, request.user))
}

pub async fn server_request<S>(
    stream: &mut S,
    users: &[User],
) -> io::Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let version = stream.read_u8().await?;
    if version == VERSION_4 {
        return server_request4(stream, users).await;
    }
    if version != VERSION_5 {
        return Err(invalid_data(format!(
            "unsupported SOCKS version: {version}"
        )));
    }
    let count = stream.read_u8().await? as usize;
    if count == 0 {
        return Err(invalid_data("SOCKS greeting contains no methods"));
    }
    let mut methods = vec![0_u8; count];
    stream.read_exact(&mut methods).await?;
    let selected = if users.is_empty() && methods.contains(&METHOD_NONE) {
        METHOD_NONE
    } else if !users.is_empty() && methods.contains(&METHOD_USERNAME_PASSWORD) {
        METHOD_USERNAME_PASSWORD
    } else {
        METHOD_UNACCEPTABLE
    };
    stream.write_all(&[VERSION_5, selected]).await?;
    stream.flush().await?;
    if selected == METHOD_UNACCEPTABLE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable SOCKS authentication method",
        ));
    }
    let user = if selected == METHOD_USERNAME_PASSWORD {
        Some(server_authenticate(stream, users).await?)
    } else {
        None
    };

    let mut request = [0_u8; 3];
    stream.read_exact(&mut request).await?;
    if request[0] != VERSION_5 || request[2] != 0 {
        return Err(invalid_data("invalid SOCKS request header"));
    }
    let command = match request[1] {
        COMMAND_CONNECT => SocksCommand::Connect,
        COMMAND_BIND => SocksCommand::Bind,
        COMMAND_UDP_ASSOCIATE => SocksCommand::UdpAssociate,
        command => {
            write_reply(stream, 7, None).await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported SOCKS command: {command}"),
            ));
        }
    };
    Ok(SocksRequest {
        version: SocksVersion::V5,
        command,
        destination: read_address(stream).await?,
        user,
    })
}

async fn server_request4<S>(
    stream: &mut S,
    users: &[User],
) -> io::Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let command_byte = stream.read_u8().await?;
    let port = stream.read_u16().await?;
    let mut ip = [0_u8; 4];
    stream.read_exact(&mut ip).await?;
    let username = read_nul_string(stream, "SOCKS4 username").await?;
    if !users.is_empty()
        && !users.iter().any(|candidate| {
            constant_time_equal(
                candidate.username.as_bytes(),
                username.as_bytes(),
            ) & constant_time_equal(candidate.password.as_bytes(), b"")
        })
    {
        write_reply_for_version(stream, SocksVersion::V4, 2, None).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS4 authentication failed",
        ));
    }
    let is_4a = ip[0..3] == [0, 0, 0] && ip[3] != 0;
    let host = if is_4a {
        read_nul_string(stream, "SOCKS4a hostname").await?
    } else {
        Ipv4Addr::from(ip).to_string()
    };
    if host.is_empty() {
        write_reply_for_version(stream, SocksVersion::V4, 1, None).await?;
        return Err(invalid_data("SOCKS4 destination is empty"));
    }
    let command = match command_byte {
        COMMAND_CONNECT => SocksCommand::Connect,
        COMMAND_BIND => SocksCommand::Bind,
        command => {
            write_reply_for_version(stream, SocksVersion::V4, 7, None).await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported SOCKS4 command: {command}"),
            ));
        }
    };
    Ok(SocksRequest {
        version: if is_4a {
            SocksVersion::V4a
        } else {
            SocksVersion::V4
        },
        command,
        destination: SocksAddr::new(host, port),
        user: Some(username),
    })
}

async fn read_nul_string<S>(stream: &mut S, field: &str) -> io::Result<String>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            break;
        }
        if bytes.len() == u8::MAX as usize {
            return Err(invalid_data(format!(
                "{field} is longer than 255 bytes"
            )));
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes)
        .map_err(|_| invalid_data(format!("{field} is not UTF-8")))
}

struct Socks5PacketConnection {
    socket: UdpSocket,
    _control: Mutex<Stream>,
}

impl PacketConnection for Socks5PacketConnection {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a SocksAddr,
    ) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let packet = encode_udp_packet(destination, data)?;
            let sent = self.socket.send(&packet).await?;
            if sent != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial SOCKS UDP datagram",
                ));
            }
            Ok(data.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        data: &'a mut [u8],
    ) -> PacketFuture<'a, (usize, SocksAddr)> {
        Box::pin(async move {
            let mut packet = vec![0_u8; data.len() + 262];
            let size = self.socket.recv(&mut packet).await?;
            let (source, payload) = decode_udp_packet(&packet[..size])?;
            if payload.len() > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS UDP payload exceeds buffer",
                ));
            }
            data[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), source))
        })
    }
}

pub async fn write_reply<S>(
    stream: &mut S,
    reply: u8,
    bound: Option<&SocksAddr>,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(&[VERSION_5, reply, 0]).await?;
    let fallback = SocksAddr::new("0.0.0.0", 0);
    write_address(stream, bound.unwrap_or(&fallback)).await?;
    stream.flush().await
}

pub async fn write_reply_for_version<S>(
    stream: &mut S,
    version: SocksVersion,
    reply: u8,
    bound: Option<&SocksAddr>,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    match version {
        SocksVersion::V5 => write_reply(stream, reply, bound).await,
        SocksVersion::V4 | SocksVersion::V4a => {
            let code = if reply == 0 {
                REPLY_4_GRANTED
            } else {
                REPLY_4_REJECTED
            };
            let fallback = SocksAddr::new("0.0.0.0", 0);
            let bound = bound.unwrap_or(&fallback);
            let ip = match bound {
                SocksAddr::Ip(address) => match address.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                },
                SocksAddr::Domain { .. } => Ipv4Addr::UNSPECIFIED,
            };
            stream.write_all(&[0, code]).await?;
            stream.write_u16(bound.port()).await?;
            stream.write_all(&ip.octets()).await?;
            stream.flush().await
        }
    }
}

async fn server_authenticate<S>(
    stream: &mut S,
    users: &[User],
) -> io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if stream.read_u8().await? != 1 {
        return Err(invalid_data("invalid SOCKS username/password version"));
    }
    let username_length = stream.read_u8().await? as usize;
    let mut username = vec![0_u8; username_length];
    stream.read_exact(&mut username).await?;
    let password_length = stream.read_u8().await? as usize;
    let mut password = vec![0_u8; password_length];
    stream.read_exact(&mut password).await?;
    let matched = users.iter().find(|candidate| {
        constant_time_equal(candidate.username.as_bytes(), &username)
            & constant_time_equal(candidate.password.as_bytes(), &password)
    });
    let status = u8::from(matched.is_none());
    stream.write_all(&[1, status]).await?;
    stream.flush().await?;
    matched.map(|user| user.username.clone()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS authentication failed",
        )
    })
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

async fn authenticate<S>(
    stream: &mut S,
    credentials: Option<(&str, &str)>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (username, password) = credentials.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS server requires credentials",
        )
    })?;
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(invalid_input(
            "SOCKS username or password is longer than 255 bytes",
        ));
    }
    stream.write_all(&[1, username.len() as u8]).await?;
    stream.write_all(username.as_bytes()).await?;
    stream.write_all(&[password.len() as u8]).await?;
    stream.write_all(password.as_bytes()).await?;
    stream.flush().await?;
    let mut auth = [0_u8; 2];
    stream.read_exact(&mut auth).await?;
    if auth != [1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS authentication failed",
        ));
    }
    Ok(())
}

pub async fn write_address<S>(
    stream: &mut S,
    address: &SocksAddr,
) -> io::Result<()>
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
            if host.len() > u8::MAX as usize {
                return Err(invalid_input(
                    "SOCKS domain is longer than 255 bytes",
                ));
            }
            stream.write_u8(ADDRESS_DOMAIN).await?;
            stream.write_u8(host.len() as u8).await?;
            stream.write_all(host.as_bytes()).await?;
        }
    }
    stream.write_u16(address.port()).await
}

pub async fn read_address<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let address = match stream.read_u8().await? {
        ADDRESS_IPV4 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes)).to_string()
        }
        ADDRESS_IPV6 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes)).to_string()
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0_u8; length];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes)
                .map_err(|_| invalid_data("SOCKS domain is not UTF-8"))?
        }
        address_type => {
            return Err(invalid_data(format!(
                "unknown SOCKS address type: {address_type}"
            )));
        }
    };
    let port = stream.read_u16().await?;
    Ok(SocksAddr::new(address, port))
}

pub fn encode_udp_packet(
    destination: &SocksAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(payload.len() + 22);
    packet.extend_from_slice(&[0, 0, 0]);
    match destination {
        SocksAddr::Ip(address) => match address.ip() {
            IpAddr::V4(ip) => {
                packet.push(ADDRESS_IPV4);
                packet.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                packet.push(ADDRESS_IPV6);
                packet.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                invalid_input("SOCKS domain is longer than 255 bytes")
            })?;
            packet.extend_from_slice(&[ADDRESS_DOMAIN, length]);
            packet.extend_from_slice(host.as_bytes());
        }
    }
    packet.extend_from_slice(&destination.port().to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub fn decode_udp_packet(packet: &[u8]) -> io::Result<(SocksAddr, &[u8])> {
    if packet.len() < 4 || packet[0..2] != [0, 0] {
        return Err(invalid_data("invalid SOCKS UDP reserved field"));
    }
    if packet[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented SOCKS UDP datagrams are not supported",
        ));
    }
    let mut offset = 4;
    let host = match packet[3] {
        ADDRESS_IPV4 => {
            let bytes = packet.get(offset..offset + 4).ok_or_else(|| {
                invalid_data("truncated SOCKS UDP IPv4 address")
            })?;
            offset += 4;
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
                .to_string()
        }
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = packet
                .get(offset..offset + 16)
                .ok_or_else(|| {
                    invalid_data("truncated SOCKS UDP IPv6 address")
                })?
                .try_into()
                .expect("length checked");
            offset += 16;
            IpAddr::V6(Ipv6Addr::from(bytes)).to_string()
        }
        ADDRESS_DOMAIN => {
            let length = *packet.get(offset).ok_or_else(|| {
                invalid_data("truncated SOCKS UDP domain length")
            })? as usize;
            offset += 1;
            let domain = packet
                .get(offset..offset + length)
                .ok_or_else(|| invalid_data("truncated SOCKS UDP domain"))?;
            offset += length;
            std::str::from_utf8(domain)
                .map_err(|_| invalid_data("SOCKS UDP domain is not UTF-8"))?
                .to_owned()
        }
        address_type => {
            return Err(invalid_data(format!(
                "unknown SOCKS UDP address type: {address_type}"
            )));
        }
    };
    let port_bytes: [u8; 2] = packet
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_data("truncated SOCKS UDP port"))?
        .try_into()
        .expect("length checked");
    offset += 2;
    Ok((
        SocksAddr::new(host, u16::from_be_bytes(port_bytes)),
        &packet[offset..],
    ))
}

fn reply_error_kind(reply: u8) -> io::ErrorKind {
    match reply {
        2 => io::ErrorKind::PermissionDenied,
        3 | 4 => io::ErrorKind::NetworkUnreachable,
        5 => io::ErrorKind::ConnectionRefused,
        6 => io::ErrorKind::TimedOut,
        7 => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::Other,
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        COMMAND_UDP_ASSOCIATE, SocksCommand, SocksVersion, client_accept_bind,
        client_accept_bind4, client_bind, client_bind4,
        client_command_handshake, client_handshake, client_handshake4,
        decode_udp_packet, encode_udp_packet, read_address, server_handshake,
        server_request, write_address, write_reply, write_reply_for_version,
    };
    use crate::{common::network::SocksAddr, option::User};

    #[tokio::test]
    async fn address_codec_round_trips_all_forms() {
        for address in [
            "192.0.2.1:53".parse::<SocksAddr>().unwrap(),
            "[2001:db8::1]:853".parse().unwrap(),
            "example.com:443".parse().unwrap(),
        ] {
            let (mut writer, mut reader) = tokio::io::duplex(512);
            let expected = address.clone();
            let write = tokio::spawn(async move {
                write_address(&mut writer, &address).await
            });
            assert_eq!(read_address(&mut reader).await.unwrap(), expected);
            write.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn socks4_client_request_is_wire_exact() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 13];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"\x04\x01\x01\xbb\xc0\x00\x02\x01user\0");
            server
                .write_all(b"\0\x5a\xc3\x50\x7f\0\0\x01")
                .await
                .unwrap();
        });
        let bound = client_handshake4(
            &mut client,
            &"192.0.2.1:443".parse().unwrap(),
            "user",
        )
        .await
        .unwrap();
        assert_eq!(bound.to_string(), "127.0.0.1:50000");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks4a_client_and_server_preserve_domain_and_user_id() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let request = server_request(&mut server, &[]).await.unwrap();
            assert_eq!(request.version, SocksVersion::V4a);
            assert_eq!(request.command, SocksCommand::Connect);
            assert_eq!(request.destination.to_string(), "example.com:443");
            assert_eq!(request.user.as_deref(), Some("alice"));
            write_reply_for_version(
                &mut server,
                request.version,
                0,
                Some(&"127.0.0.1:1234".parse().unwrap()),
            )
            .await
            .unwrap();
        });
        let bound = client_handshake4(
            &mut client,
            &"example.com:443".parse().unwrap(),
            "alice",
        )
        .await
        .unwrap();
        assert_eq!(bound.to_string(), "127.0.0.1:1234");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks4_and_socks5_bind_consume_both_protocol_replies() {
        let (mut client4, mut server4) = tokio::io::duplex(512);
        let server4_task = tokio::spawn(async move {
            let request = server_request(&mut server4, &[]).await.unwrap();
            assert_eq!(request.command, SocksCommand::Bind);
            assert_eq!(request.destination.to_string(), "peer.example:9000");
            write_reply_for_version(
                &mut server4,
                request.version,
                0,
                Some(&"127.0.0.1:41000".parse().unwrap()),
            )
            .await
            .unwrap();
            write_reply_for_version(
                &mut server4,
                request.version,
                0,
                Some(&"192.0.2.20:9000".parse().unwrap()),
            )
            .await
            .unwrap();
        });
        let bound4 = client_bind4(
            &mut client4,
            &"peer.example:9000".parse().unwrap(),
            "alice",
        )
        .await
        .unwrap();
        assert_eq!(bound4.to_string(), "127.0.0.1:41000");
        let peer4 = client_accept_bind4(&mut client4).await.unwrap();
        assert_eq!(peer4.to_string(), "192.0.2.20:9000");
        server4_task.await.unwrap();

        let (mut client5, mut server5) = tokio::io::duplex(512);
        let server5_task = tokio::spawn(async move {
            let request = server_request(&mut server5, &[]).await.unwrap();
            assert_eq!(request.version, SocksVersion::V5);
            assert_eq!(request.command, SocksCommand::Bind);
            assert_eq!(request.destination.to_string(), "peer.example:9000");
            write_reply(
                &mut server5,
                0,
                Some(&"[2001:db8::10]:42000".parse().unwrap()),
            )
            .await
            .unwrap();
            write_reply(
                &mut server5,
                0,
                Some(&"192.0.2.21:9000".parse().unwrap()),
            )
            .await
            .unwrap();
        });
        let bound5 = client_bind(
            &mut client5,
            &"peer.example:9000".parse().unwrap(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(bound5.to_string(), "[2001:db8::10]:42000");
        let peer5 = client_accept_bind(&mut client5).await.unwrap();
        assert_eq!(peer5.to_string(), "192.0.2.21:9000");
        server5_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks4_authentication_matches_user_id_with_empty_password() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let users = [User {
                username: "alice".into(),
                password: String::new(),
            }];
            server_request(&mut server, &users).await.unwrap()
        });
        let client_task = tokio::spawn(async move {
            client
                .write_all(b"\x04\x01\0P\x7f\0\0\x01alice\0")
                .await
                .unwrap();
        });
        let request = server_task.await.unwrap();
        assert_eq!(request.user.as_deref(), Some("alice"));
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn client_connect_handshake_matches_rfc_1928() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0_u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 3];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0]);
            let destination = read_address(&mut server).await.unwrap();
            assert_eq!(destination.to_string(), "example.com:443");
            server.write_all(&[5, 0, 0]).await.unwrap();
            write_address(&mut server, &"127.0.0.1:50000".parse().unwrap())
                .await
                .unwrap();
        });
        let bound = client_handshake(
            &mut client,
            &"example.com:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(bound.to_string(), "127.0.0.1:50000");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn username_password_subnegotiation_is_exact() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0_u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            server.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0_u8; 11];
            server.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x04user\x04pass");
            server.write_all(&[1, 0]).await.unwrap();
            let mut request = [0_u8; 3];
            server.read_exact(&mut request).await.unwrap();
            read_address(&mut server).await.unwrap();
            server.write_all(&[5, 0, 0]).await.unwrap();
            write_address(&mut server, &"0.0.0.0:0".parse().unwrap())
                .await
                .unwrap();
        });
        client_handshake(
            &mut client,
            &"example.com:443".parse().unwrap(),
            Some(("user", "pass")),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn client_and_server_handshakes_interoperate() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let users = [User {
                username: "user".into(),
                password: "pass".into(),
            }];
            let (destination, user) =
                server_handshake(&mut server, &users).await.unwrap();
            assert_eq!(destination.to_string(), "example.com:443");
            assert_eq!(user.as_deref(), Some("user"));
            write_reply(
                &mut server,
                0,
                Some(&"127.0.0.1:1234".parse().unwrap()),
            )
            .await
            .unwrap();
        });
        let bound = client_handshake(
            &mut client,
            &"example.com:443".parse().unwrap(),
            Some(("user", "pass")),
        )
        .await
        .unwrap();
        assert_eq!(bound.to_string(), "127.0.0.1:1234");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn server_rejects_wrong_credentials() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let server_task = tokio::spawn(async move {
            let users = [User {
                username: "user".into(),
                password: "correct".into(),
            }];
            assert!(server_handshake(&mut server, &users).await.is_err());
        });
        let error = client_handshake(
            &mut client,
            &"example.com:443".parse().unwrap(),
            Some(("user", "wrong")),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        server_task.await.unwrap();
    }

    #[test]
    fn udp_datagram_codec_round_trips_and_rejects_fragments() {
        for destination in [
            "192.0.2.1:53".parse::<SocksAddr>().unwrap(),
            "[2001:db8::1]:853".parse().unwrap(),
            "example.com:443".parse().unwrap(),
        ] {
            let encoded = encode_udp_packet(&destination, b"payload").unwrap();
            let (decoded, payload) = decode_udp_packet(&encoded).unwrap();
            assert_eq!(decoded, destination);
            assert_eq!(payload, b"payload");
        }
        let mut fragmented =
            encode_udp_packet(&"example.com:53".parse().unwrap(), b"payload")
                .unwrap();
        fragmented[2] = 1;
        assert_eq!(
            decode_udp_packet(&fragmented).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    #[tokio::test]
    async fn udp_associate_command_round_trips() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let request = server_request(&mut server, &[]).await.unwrap();
            assert_eq!(request.command, SocksCommand::UdpAssociate);
            assert_eq!(request.destination.to_string(), "0.0.0.0:0");
            write_reply(
                &mut server,
                0,
                Some(&"127.0.0.1:53000".parse().unwrap()),
            )
            .await
            .unwrap();
        });
        let relay = client_command_handshake(
            &mut client,
            &"0.0.0.0:0".parse().unwrap(),
            None,
            COMMAND_UDP_ASSOCIATE,
        )
        .await
        .unwrap();
        assert_eq!(relay.to_string(), "127.0.0.1:53000");
        server_task.await.unwrap();
    }
}
