//! Platform original-destination helpers used by redirect and TProxy.

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::{io, net::SocketAddr};

use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
pub fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let remote = stream.peer_addr()?;
    unsafe {
        if remote.is_ipv4() {
            let mut address: libc::sockaddr_in = std::mem::zeroed();
            let mut length =
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                (&raw mut address).cast(),
                &raw mut length,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let ip =
                std::net::Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            Ok(SocketAddr::new(ip.into(), u16::from_be(address.sin_port)))
        } else {
            let mut address: libc::sockaddr_in6 = std::mem::zeroed();
            let mut length =
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IPV6,
                SO_ORIGINAL_DST,
                (&raw mut address).cast(),
                &raw mut length,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::new(
                std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).into(),
                u16::from_be(address.sin6_port),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
pub fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    const PF_OUT: u8 = 0x2;
    const DIOCNATLOOK: libc::c_ulong = 0xc054_4417;

    #[repr(C)]
    struct PfNatLook {
        source: [u8; 16],
        destination: [u8; 16],
        redirected_source: [u8; 16],
        redirected_destination: [u8; 16],
        source_port: [u8; 4],
        destination_port: [u8; 4],
        redirected_source_port: [u8; 4],
        redirected_destination_port: [u8; 4],
        address_family: u8,
        protocol: u8,
        protocol_variant: u8,
        direction: u8,
    }
    const _: () = assert!(std::mem::size_of::<PfNatLook>() == 0x54);

    let local = stream.local_addr()?;
    let remote = stream.peer_addr()?;
    let mut lookup = PfNatLook {
        source: [0; 16],
        destination: [0; 16],
        redirected_source: [0; 16],
        redirected_destination: [0; 16],
        source_port: [0; 4],
        destination_port: [0; 4],
        redirected_source_port: [0; 4],
        redirected_destination_port: [0; 4],
        address_family: 0,
        protocol: libc::IPPROTO_TCP as u8,
        protocol_variant: 0,
        direction: PF_OUT,
    };
    match (remote, local) {
        (SocketAddr::V4(remote), SocketAddr::V4(local)) => {
            lookup.source[..4].copy_from_slice(&remote.ip().octets());
            lookup.destination[..4].copy_from_slice(&local.ip().octets());
            lookup.address_family = libc::AF_INET as u8;
        }
        (SocketAddr::V6(remote), SocketAddr::V6(local)) => {
            lookup.source.copy_from_slice(&remote.ip().octets());
            lookup.destination.copy_from_slice(&local.ip().octets());
            lookup.address_family = libc::AF_INET6 as u8;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirect connection address families do not match",
            ));
        }
    }
    lookup.source_port[..2].copy_from_slice(&remote.port().to_be_bytes());
    lookup.destination_port[..2].copy_from_slice(&local.port().to_be_bytes());

    let path = b"/dev/pf\0";
    let descriptor =
        unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let result =
        unsafe { libc::ioctl(descriptor, DIOCNATLOOK, &raw mut lookup) };
    let error = io::Error::last_os_error();
    unsafe {
        libc::close(descriptor);
    }
    if result != 0 {
        return Err(error);
    }
    let port = u16::from_be_bytes([
        lookup.redirected_destination_port[0],
        lookup.redirected_destination_port[1],
    ]);
    match lookup.address_family as libc::c_int {
        libc::AF_INET => Ok(SocketAddr::new(
            std::net::Ipv4Addr::new(
                lookup.redirected_destination[0],
                lookup.redirected_destination[1],
                lookup.redirected_destination[2],
                lookup.redirected_destination[3],
            )
            .into(),
            port,
        )),
        libc::AF_INET6 => Ok(SocketAddr::new(
            std::net::Ipv6Addr::from(lookup.redirected_destination).into(),
            port,
        )),
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PF returned unknown address family {family}"),
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn original_destination(_stream: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "redirect original-destination lookup is unsupported on this platform",
    ))
}

#[cfg(target_os = "linux")]
pub fn transparent_tcp_listener(
    address: SocketAddr,
) -> io::Result<std::net::TcpListener> {
    use std::os::fd::AsRawFd as _;

    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    set_transparent(socket.as_raw_fd(), address.is_ipv6())?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

#[derive(Debug, Clone, Copy)]
pub struct TransparentUdpPacket {
    pub length: usize,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

#[cfg(target_os = "linux")]
pub struct TransparentUdpSocket {
    socket: tokio::io::unix::AsyncFd<std::net::UdpSocket>,
}

#[cfg(target_os = "linux")]
impl TransparentUdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.get_ref().local_addr()
    }

    pub async fn recv_from(
        &self,
        data: &mut [u8],
    ) -> io::Result<TransparentUdpPacket> {
        loop {
            let mut ready = self.socket.readable().await?;
            match ready.try_io(|socket| {
                recv_transparent_packet(socket.get_ref().as_raw_fd(), data)
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct TransparentUdpSocket;

#[cfg(not(target_os = "linux"))]
impl TransparentUdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TProxy is only supported on Linux",
        ))
    }

    pub async fn recv_from(
        &self,
        _data: &mut [u8],
    ) -> io::Result<TransparentUdpPacket> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TProxy is only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn transparent_udp_socket(
    address: SocketAddr,
) -> io::Result<TransparentUdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    set_transparent(socket.as_raw_fd(), address.is_ipv6())?;
    set_receive_original_destination(socket.as_raw_fd(), address.is_ipv6())?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    let socket: std::net::UdpSocket = socket.into();
    Ok(TransparentUdpSocket {
        socket: tokio::io::unix::AsyncFd::new(socket)?,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn transparent_udp_socket(
    _address: SocketAddr,
) -> io::Result<TransparentUdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TProxy is only supported on Linux",
    ))
}

#[cfg(target_os = "linux")]
pub fn send_transparent_udp(
    source: SocketAddr,
    destination: SocketAddr,
    data: &[u8],
) -> io::Result<usize> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if source.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TProxy UDP source and destination address families differ",
        ));
    }
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    set_transparent(socket.as_raw_fd(), source.is_ipv6())?;
    socket.bind(&source.into())?;
    socket.send_to(data, &destination.into())
}

#[cfg(not(target_os = "linux"))]
pub fn send_transparent_udp(
    _source: SocketAddr,
    _destination: SocketAddr,
    _data: &[u8],
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TProxy is only supported on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn set_transparent(descriptor: libc::c_int, ipv6: bool) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    let set = |level, name| unsafe {
        libc::setsockopt(
            descriptor,
            level,
            name,
            (&raw const enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if set(libc::SOL_SOCKET, libc::SO_REUSEADDR) != 0
        || set(libc::SOL_IP, libc::IP_TRANSPARENT) != 0
        || (ipv6 && set(libc::SOL_IPV6, libc::IPV6_TRANSPARENT) != 0)
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_receive_original_destination(
    descriptor: libc::c_int,
    ipv6: bool,
) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    let set = |level, name| unsafe {
        libc::setsockopt(
            descriptor,
            level,
            name,
            (&raw const enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if set(libc::SOL_IP, libc::IP_RECVORIGDSTADDR) != 0
        || (ipv6 && set(libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) != 0)
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn recv_transparent_packet(
    descriptor: libc::c_int,
    data: &mut [u8],
) -> io::Result<TransparentUdpPacket> {
    let mut source: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut control = [0_u8; 128];
    let mut vector = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = (&raw mut source).cast();
    message.msg_namelen = std::mem::size_of_val(&source) as libc::socklen_t;
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let length = unsafe { libc::recvmsg(descriptor, &raw mut message, 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let source = unsafe {
        socket_addr_from_raw((&raw const source).cast(), message.msg_namelen)?
    };
    let mut destination = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        if current.cmsg_level == libc::SOL_IP
            && current.cmsg_type == libc::IP_ORIGDSTADDR
        {
            destination = Some(unsafe {
                socket_addr_from_raw(
                    libc::CMSG_DATA(header).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )?
            });
            break;
        }
        if current.cmsg_level == libc::SOL_IPV6
            && current.cmsg_type == libc::IPV6_ORIGDSTADDR
        {
            destination = Some(unsafe {
                socket_addr_from_raw(
                    libc::CMSG_DATA(header).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>()
                        as libc::socklen_t,
                )?
            });
            break;
        }
        header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
    }
    Ok(TransparentUdpPacket {
        length: length as usize,
        source,
        destination: destination.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TProxy UDP packet has no original destination",
            )
        })?,
    })
}

#[cfg(target_os = "linux")]
unsafe fn socket_addr_from_raw(
    address: *const libc::sockaddr,
    length: libc::socklen_t,
) -> io::Result<SocketAddr> {
    if address.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing socket address",
        ));
    }
    match unsafe { (*address).sa_family as libc::c_int } {
        libc::AF_INET
            if length as usize >= std::mem::size_of::<libc::sockaddr_in>() =>
        {
            let address = unsafe { &*address.cast::<libc::sockaddr_in>() };
            Ok(SocketAddr::new(
                std::net::Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))
                    .into(),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6
            if length as usize >= std::mem::size_of::<libc::sockaddr_in6>() =>
        {
            let address = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::new(
                std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).into(),
                u16::from_be(address.sin6_port),
            ))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown socket address family {family}"),
        )),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn transparent_tcp_listener(
    _address: SocketAddr,
) -> io::Result<std::net::TcpListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TProxy is only supported on Linux",
    ))
}
