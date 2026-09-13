//! macOS PF_ROUTE backend for TUN routes.

use std::{
    ffi::{CStr, c_char},
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
    process::{Command, Stdio},
};

use async_trait::async_trait;
use ipnet::IpNet;

use super::tun_route::TunRouteBackend;

const ROUTE_HEADER_LEN: usize = 0x5c;
const DARWIN_ROUTE_PADDING: usize = 1024;
const SIOCAIFADDR: libc::c_ulong = 0x8040_691a;
const SIOCAIFADDR_IN6: libc::c_ulong = 2_155_899_162;
const IN6_IFF_NODAD: u32 = 0x0020;
const IN6_IFF_SECURED: u32 = 0x0400;
const ND6_INFINITE_LIFETIME: u32 = u32::MAX;
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const SIOCSIFFLAGS: libc::c_ulong = 0x8020_6910;
const SIOCGIFFLAGS: libc::c_ulong = 0xc020_6911;
const SIOCSIFMTU: libc::c_ulong = 0x8020_6934;

pub(crate) fn flush_dns_cache() {
    let _ = Command::new("dscacheutil")
        .arg("-flushcache")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAliasRequest4 {
    name: [c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in,
    destination: libc::sockaddr_in,
    mask: libc::sockaddr_in,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AddressLifetime6 {
    expire: i64,
    preferred: i64,
    valid_lifetime: u32,
    preferred_lifetime: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAliasRequest6 {
    name: [c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in6,
    destination: libc::sockaddr_in6,
    mask: libc::sockaddr_in6,
    flags: u32,
    lifetime: AddressLifetime6,
}

/// Open an Apple utun control socket without asking `tun-easytier` to
/// configure its IPv4-only alias. This is used for IPv6-only interfaces.
pub(crate) fn open_utun(requested_name: &str) -> io::Result<(OwnedFd, String)> {
    let unit = utun_unit(requested_name)?;
    // SAFETY: socket returns either a uniquely owned descriptor or -1.
    let raw_fd = unsafe {
        libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw_fd is valid and uniquely owned after a successful socket.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut info: libc::ctl_info = unsafe { mem::zeroed() };
    for (output, input) in
        info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.as_bytes())
    {
        *output = *input as c_char;
    }
    // SAFETY: CTLIOCGINFO expects a writable ctl_info value.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let address = libc::sockaddr_ctl {
        sc_len: mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: unit,
        sc_reserved: [0; 5],
    };
    // SAFETY: address has the sockaddr_ctl layout and remains alive for the
    // duration of connect.
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut name = [0_u8; 64];
    let mut name_len = name.len() as libc::socklen_t;
    // SAFETY: name is writable for name_len bytes and getsockopt updates the
    // length without retaining either pointer.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut name_len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returns a NUL-terminated interface name in a
    // zero-initialized buffer.
    let name = unsafe { CStr::from_ptr(name.as_ptr().cast::<c_char>()) }
        .to_str()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .to_owned();
    Ok((fd, name))
}

/// Configure the state normally handled by `tun-easytier::Device::new` when
/// an IPv6-only utun is opened through [`open_utun`].
pub(crate) fn configure_utun_interface(
    interface_name: &str,
    mtu: u16,
) -> io::Result<()> {
    // SAFETY: socket returns either a uniquely owned descriptor or -1.
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw_fd is valid and uniquely owned after a successful socket.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    request.ifr_name = interface_name_bytes(interface_name)?;
    // SAFETY: the request codes operate on the matching ifreq layout.
    unsafe {
        request.ifr_ifru.ifru_mtu = i32::from(mtu);
        if libc::ioctl(fd.as_raw_fd(), SIOCSIFMTU, &request) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::ioctl(fd.as_raw_fd(), SIOCGIFFLAGS, &mut request) < 0 {
            return Err(io::Error::last_os_error());
        }
        request.ifr_ifru.ifru_flags |=
            (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(fd.as_raw_fd(), SIOCSIFFLAGS, &request) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Add every address not already configured by tun-easytier. Its macOS
/// backend currently installs only a primary IPv4 alias; `None` means the
/// raw IPv6-only path and therefore installs every configured address.
pub(crate) fn configure_additional_addresses(
    interface_name: &str,
    addresses: &[IpNet],
    primary_ipv4: Option<IpNet>,
) -> io::Result<()> {
    for address in addresses {
        if Some(*address) == primary_ipv4 {
            continue;
        }
        match address {
            IpNet::V4(address) => execute_alias_ioctl(
                libc::AF_INET,
                SIOCAIFADDR,
                &build_alias_request4(interface_name, *address)?,
            )?,
            IpNet::V6(address) => execute_alias_ioctl(
                libc::AF_INET6,
                SIOCAIFADDR_IN6,
                &build_alias_request6(interface_name, *address)?,
            )?,
        }
    }
    Ok(())
}

fn utun_unit(requested_name: &str) -> io::Result<u32> {
    if requested_name.is_empty() {
        return Ok(0);
    }
    let Some(index) = requested_name.strip_prefix("utun") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macOS TUN interface name must use the utun<N> form",
        ));
    };
    if requested_name.len() >= libc::IFNAMSIZ || index.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid macOS utun interface name",
        ));
    }
    index
        .parse::<u32>()
        .ok()
        .and_then(|index| index.checked_add(1))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid macOS utun interface index",
            )
        })
}

fn execute_alias_ioctl<T>(
    family: libc::c_int,
    request: libc::c_ulong,
    value: &T,
) -> io::Result<()> {
    // SAFETY: socket returns either a new owned descriptor or -1. The
    // descriptor is immediately wrapped and closed exactly once.
    let raw_fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw_fd is valid and uniquely owned after a successful socket.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    // SAFETY: the request code selects the same repr(C) request type as T;
    // value remains alive and immutable for the duration of ioctl.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), request, value) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn build_alias_request4(
    interface_name: &str,
    network: ipnet::Ipv4Net,
) -> io::Result<IfAliasRequest4> {
    Ok(IfAliasRequest4 {
        name: interface_name_bytes(interface_name)?,
        address: sockaddr4(network.addr()),
        destination: sockaddr4(network.addr()),
        mask: sockaddr4(match prefix_mask(IpNet::V4(network)) {
            IpAddr::V4(mask) => mask,
            IpAddr::V6(_) => unreachable!(),
        }),
    })
}

fn build_alias_request6(
    interface_name: &str,
    network: ipnet::Ipv6Net,
) -> io::Result<IfAliasRequest6> {
    let destination = if network.prefix_len() == 128 {
        next_ipv6(network.addr())
            .map(sockaddr6)
            .unwrap_or_else(empty_sockaddr6)
    } else {
        empty_sockaddr6()
    };
    Ok(IfAliasRequest6 {
        name: interface_name_bytes(interface_name)?,
        address: sockaddr6(network.addr()),
        destination,
        mask: sockaddr6(match prefix_mask(IpNet::V6(network)) {
            IpAddr::V6(mask) => mask,
            IpAddr::V4(_) => unreachable!(),
        }),
        flags: IN6_IFF_NODAD | IN6_IFF_SECURED,
        lifetime: AddressLifetime6 {
            expire: 0,
            preferred: 0,
            valid_lifetime: ND6_INFINITE_LIFETIME,
            preferred_lifetime: ND6_INFINITE_LIFETIME,
        },
    })
}

fn interface_name_bytes(
    interface_name: &str,
) -> io::Result<[c_char; libc::IFNAMSIZ]> {
    if interface_name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN interface name is too long",
        ));
    }
    let mut name = [0; libc::IFNAMSIZ];
    for (output, input) in name.iter_mut().zip(interface_name.as_bytes()) {
        *output = *input as c_char;
    }
    Ok(name)
}

fn sockaddr4(address: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    }
}

fn sockaddr6(address: Ipv6Addr) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: address.octets(),
        },
        sin6_scope_id: 0,
    }
}

fn empty_sockaddr6() -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: 0,
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    }
}

fn next_ipv6(address: Ipv6Addr) -> Option<Ipv6Addr> {
    u128::from(address).checked_add(1).map(Ipv6Addr::from)
}

pub(crate) struct DarwinRouteBackend {
    gateway4: Option<IpAddr>,
    gateway6: Option<IpAddr>,
}

impl DarwinRouteBackend {
    pub(crate) fn new(addresses: &[IpNet]) -> Self {
        Self {
            gateway4: addresses
                .iter()
                .find(|network| network.addr().is_ipv4())
                .map(IpNet::addr),
            gateway6: addresses
                .iter()
                .find(|network| network.addr().is_ipv6())
                .map(IpNet::addr),
        }
    }

    fn gateway(&self, route: IpNet) -> io::Result<IpAddr> {
        if route.addr().is_ipv4() {
            self.gateway4
        } else {
            self.gateway6
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no TUN gateway for route {route}"),
            )
        })
    }

    fn execute(&self, message_type: u8, route: IpNet) -> io::Result<()> {
        let message =
            build_route_message(message_type, route, self.gateway(route)?)?;
        // SAFETY: socket returns either a new owned descriptor or -1. The
        // successful descriptor is immediately wrapped in OwnedFd and closed
        // exactly once when this function returns.
        let raw_fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw_fd was created successfully above and ownership has not
        // been transferred elsewhere.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        // SAFETY: message points to `message.len()` initialized bytes and the
        // owned route socket remains valid for the duration of the call.
        let written = unsafe {
            libc::write(fd.as_raw_fd(), message.as_ptr().cast(), message.len())
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != message.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short PF_ROUTE write: wrote {written} of {} bytes",
                    message.len()
                ),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl TunRouteBackend for DarwinRouteBackend {
    async fn add_route(&mut self, route: IpNet) -> io::Result<()> {
        match self.execute(libc::RTM_ADD as u8, route) {
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                self.execute(libc::RTM_DELETE as u8, route).map_err(
                    |delete_error| {
                        io::Error::new(
                            delete_error.kind(),
                            format!(
                                "remove existing route {route}: {delete_error}"
                            ),
                        )
                    },
                )?;
                self.execute(libc::RTM_ADD as u8, route)
                    .map_err(|add_error| {
                        io::Error::new(
                            add_error.kind(),
                            format!("re-add route {route}: {add_error}"),
                        )
                    })
            }
            result => result,
        }
    }

    async fn remove_route(&mut self, route: IpNet) -> io::Result<()> {
        self.execute(libc::RTM_DELETE as u8, route)
    }
}

fn build_route_message(
    message_type: u8,
    route: IpNet,
    gateway: IpAddr,
) -> io::Result<Vec<u8>> {
    if route.addr().is_ipv4() != gateway.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "route {route} and gateway {gateway} use different families"
            ),
        ));
    }

    let destination = sockaddr(route.network());
    let gateway = sockaddr(gateway);
    let netmask = sockaddr(prefix_mask(route));
    let message_len = ROUTE_HEADER_LEN
        + destination.len()
        + gateway.len()
        + netmask.len()
        + DARWIN_ROUTE_PADDING;
    let message_len = u16::try_from(message_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "PF_ROUTE message too large",
        )
    })?;

    let mut message = vec![0_u8; usize::from(message_len)];
    message[0..2].copy_from_slice(&message_len.to_ne_bytes());
    message[2] = libc::RTM_VERSION as u8;
    message[3] = message_type;
    let flags = libc::RTF_STATIC
        | libc::RTF_GATEWAY
        | if message_type == libc::RTM_ADD as u8 {
            libc::RTF_UP
        } else {
            0
        };
    message[8..12].copy_from_slice(&flags.to_ne_bytes());
    let addresses = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
    message[12..16].copy_from_slice(&addresses.to_ne_bytes());
    message[20..24].copy_from_slice(&1_i32.to_ne_bytes());

    let mut offset = ROUTE_HEADER_LEN;
    for address in [&destination, &gateway, &netmask] {
        message[offset..offset + address.len()].copy_from_slice(address);
        offset += address.len();
    }
    Ok(message)
}

fn sockaddr(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => {
            let mut encoded = vec![0_u8; 16];
            encoded[0] = 16;
            encoded[1] = libc::AF_INET as u8;
            encoded[4..8].copy_from_slice(&address.octets());
            encoded
        }
        IpAddr::V6(address) => {
            let mut encoded = vec![0_u8; 28];
            encoded[0] = 28;
            encoded[1] = libc::AF_INET6 as u8;
            encoded[8..24].copy_from_slice(&address.octets());
            encoded
        }
    }
}

fn prefix_mask(route: IpNet) -> IpAddr {
    match route {
        IpNet::V4(route) => IpAddr::V4(
            u32::MAX
                .checked_shl(32 - u32::from(route.prefix_len()))
                .unwrap_or(0)
                .into(),
        ),
        IpNet::V6(route) => IpAddr::V6(
            u128::MAX
                .checked_shl(128 - u32::from(route.prefix_len()))
                .unwrap_or(0)
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{
        DARWIN_ROUTE_PADDING, IfAliasRequest4, IfAliasRequest6,
        ROUTE_HEADER_LEN, build_alias_request4, build_alias_request6,
        build_route_message, prefix_mask, utun_unit,
    };

    #[test]
    fn builds_go_compatible_ipv4_add_message() {
        let message = build_route_message(
            libc::RTM_ADD as u8,
            "203.0.113.0/24".parse().unwrap(),
            "10.14.0.1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            message.len(),
            ROUTE_HEADER_LEN + 3 * 16 + DARWIN_ROUTE_PADDING
        );
        assert_eq!(
            u16::from_ne_bytes(message[0..2].try_into().unwrap()) as usize,
            message.len()
        );
        assert_eq!(message[2], libc::RTM_VERSION as u8);
        assert_eq!(message[3], libc::RTM_ADD as u8);
        assert_eq!(
            i32::from_ne_bytes(message[8..12].try_into().unwrap()),
            libc::RTF_STATIC | libc::RTF_GATEWAY | libc::RTF_UP
        );
        assert_eq!(
            i32::from_ne_bytes(message[12..16].try_into().unwrap()),
            libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK
        );
        assert_eq!(
            &message[ROUTE_HEADER_LEN + 4..ROUTE_HEADER_LEN + 8],
            &[203, 0, 113, 0]
        );
        assert_eq!(
            &message[ROUTE_HEADER_LEN + 20..ROUTE_HEADER_LEN + 24],
            &[10, 14, 0, 1]
        );
        assert_eq!(
            &message[ROUTE_HEADER_LEN + 36..ROUTE_HEADER_LEN + 40],
            &[255, 255, 255, 0]
        );
    }

    #[test]
    fn builds_ipv6_delete_message_and_masks() {
        let message = build_route_message(
            libc::RTM_DELETE as u8,
            "2001:db8::/32".parse().unwrap(),
            "fdfe:dcba::1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            message.len(),
            ROUTE_HEADER_LEN + 3 * 28 + DARWIN_ROUTE_PADDING
        );
        assert_eq!(message[3], libc::RTM_DELETE as u8);
        assert_eq!(
            i32::from_ne_bytes(message[8..12].try_into().unwrap()),
            libc::RTF_STATIC | libc::RTF_GATEWAY
        );
        assert_eq!(
            prefix_mask("::/0".parse().unwrap()),
            "::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            prefix_mask("0.0.0.0/0".parse().unwrap()),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn builds_ipv4_and_ipv6_alias_ioctl_layouts() {
        assert_eq!(std::mem::size_of::<IfAliasRequest4>(), 64);
        assert_eq!(std::mem::size_of::<IfAliasRequest6>(), 128);
        let ipv4 =
            build_alias_request4("utun42", "10.14.0.9/30".parse().unwrap())
                .unwrap();
        assert_eq!(ipv4.address.sin_addr.s_addr.to_ne_bytes(), [10, 14, 0, 9]);
        assert_eq!(
            ipv4.mask.sin_addr.s_addr.to_ne_bytes(),
            [255, 255, 255, 252]
        );

        let ipv6 = build_alias_request6(
            "utun42",
            "fdfe:dcba:9876::1/126".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            ipv6.address.sin6_addr.s6_addr[0..6],
            [0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76]
        );
        assert_eq!(ipv6.destination.sin6_family, 0);
        assert_eq!(ipv6.mask.sin6_addr.s6_addr[0..15], [0xff; 15]);
        assert_eq!(ipv6.mask.sin6_addr.s6_addr[15], 0xfc);
    }

    #[test]
    fn parses_requested_utun_unit_like_the_kernel_control_api() {
        assert_eq!(utun_unit("").unwrap(), 0);
        assert_eq!(utun_unit("utun0").unwrap(), 1);
        assert_eq!(utun_unit("utun42").unwrap(), 43);
        assert!(utun_unit("tun42").is_err());
        assert!(utun_unit("utun").is_err());
        assert!(utun_unit("utun4294967295").is_err());
    }
}
