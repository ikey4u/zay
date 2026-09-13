//! Linux systemd-resolved link DNS discovery.
//!
//! This deliberately uses resolved only when `/etc/resolv.conf` advertises
//! that it is managed by systemd-resolved.  Queries themselves still use the
//! crate's transports rather than the resolved stub, matching upstream's
//! protection against TUN feedback loops and preserving DNS-over-TLS policy.

use std::{
    ffi::CString,
    fs, io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    path::Path,
};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::OwnedObjectPath,
};

const RESOLVED_SERVICE: &str = "org.freedesktop.resolve1";
const RESOLVED_MANAGER_PATH: &str = "/org/freedesktop/resolve1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolvedTlsMode {
    Disabled,
    Opportunistic,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedServerSpecification {
    address: IpAddr,
    interface_index: u32,
    port: u16,
    server_name: String,
}

impl ResolvedServerSpecification {
    pub(super) fn socket_address(&self, tls: bool) -> SocketAddr {
        let port = if self.port != 0 {
            self.port
        } else if tls {
            853
        } else {
            53
        };
        match self.address {
            IpAddr::V4(address) => SocketAddr::new(IpAddr::V4(address), port),
            IpAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
                address,
                port,
                0,
                if address.is_unicast_link_local() {
                    self.interface_index
                } else {
                    0
                },
            )),
        }
    }

    pub(super) fn tls_server_name(&self) -> String {
        if self.server_name.is_empty() {
            self.address.to_string()
        } else {
            self.server_name.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedConfiguration {
    pub(super) servers: Vec<ResolvedServerSpecification>,
    pub(super) tls_mode: ResolvedTlsMode,
    pub(super) signature: String,
}

/// Read the DNS server set for the kernel's current default route link.
///
/// `Ok(None)` means resolved is not the owner of `/etc/resolv.conf`; callers
/// should use the ordinary system configuration path in that case.
pub(super) fn read_configuration() -> io::Result<Option<ResolvedConfiguration>>
{
    if !is_resolved_managed(Path::new("/etc/resolv.conf"))? {
        return Ok(None);
    }
    let (interface_name, interface_index) = default_route_interface()?;
    let connection = Connection::system().map_err(dbus_error)?;
    let peer = Proxy::new(
        &connection,
        RESOLVED_SERVICE,
        RESOLVED_MANAGER_PATH,
        "org.freedesktop.DBus.Peer",
    )
    .map_err(dbus_error)?;
    let _: () = peer.call("Ping", &()).map_err(dbus_error)?;

    let manager = Proxy::new(
        &connection,
        RESOLVED_SERVICE,
        RESOLVED_MANAGER_PATH,
        "org.freedesktop.resolve1.Manager",
    )
    .map_err(dbus_error)?;
    let link_path: OwnedObjectPath = manager
        .call("GetLink", &(interface_index as i32,))
        .map_err(dbus_error)?;
    let link = Proxy::new(
        &connection,
        RESOLVED_SERVICE,
        link_path.as_str(),
        "org.freedesktop.resolve1.Link",
    )
    .map_err(dbus_error)?;

    let tls_mode = match link.get_property::<String>("DNSOverTLS") {
        Ok(value) => parse_tls_mode(&value),
        Err(error) if is_unknown_property(&error) => ResolvedTlsMode::Disabled,
        Err(error) => return Err(dbus_error(error)),
    };
    let extended =
        match link.get_property::<Vec<(i32, Vec<u8>, u16, String)>>("DNSEx") {
            Ok(value) => value,
            Err(error) if is_unknown_property(&error) => Vec::new(),
            Err(error) => return Err(dbus_error(error)),
        };
    let mut servers = if extended.is_empty() {
        link.get_property::<Vec<(i32, Vec<u8>)>>("DNS")
            .map_err(dbus_error)?
            .into_iter()
            .filter_map(|(_, address)| {
                build_server(interface_index, &address, 0, String::new())
            })
            .collect::<Vec<_>>()
    } else {
        extended
            .into_iter()
            .filter_map(|(_, address, port, name)| {
                build_server(interface_index, &address, port, name)
            })
            .collect::<Vec<_>>()
    };
    servers.dedup();
    if servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "systemd-resolved link {interface_name} has no valid DNS servers"
            ),
        ));
    }
    let signature = format!(
        "resolved:{interface_name}:{interface_index}:{tls_mode:?}:{servers:?}"
    );
    Ok(Some(ResolvedConfiguration {
        servers,
        tls_mode,
        signature,
    }))
}

fn dbus_error(error: zbus::Error) -> io::Error {
    io::Error::other(format!("query systemd-resolved over D-Bus: {error}"))
}

fn is_unknown_property(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::MethodError(name, _, _) => {
            name.as_str() == "org.freedesktop.DBus.Error.UnknownProperty"
        }
        zbus::Error::FDO(error) => {
            matches!(error.as_ref(), zbus::fdo::Error::UnknownProperty(_))
        }
        _ => false,
    }
}

fn parse_tls_mode(value: &str) -> ResolvedTlsMode {
    match value {
        "yes" => ResolvedTlsMode::Required,
        "opportunistic" => ResolvedTlsMode::Opportunistic,
        _ => ResolvedTlsMode::Disabled,
    }
}

fn build_server(
    interface_index: u32,
    raw_address: &[u8],
    port: u16,
    server_name: String,
) -> Option<ResolvedServerSpecification> {
    let address = match raw_address {
        [a, b, c, d] => IpAddr::from([*a, *b, *c, *d]),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(ResolvedServerSpecification {
        address,
        interface_index,
        port,
        server_name,
    })
}

fn is_resolved_managed(path: &Path) -> io::Result<bool> {
    let content = fs::read_to_string(path)?;
    Ok(is_resolved_managed_content(&content))
}

fn is_resolved_managed_content(content: &str) -> bool {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('#') {
            return false;
        }
        if line.contains("systemd-resolved") {
            return true;
        }
    }
    false
}

fn default_route_interface() -> io::Result<(String, u32)> {
    let ipv4 = fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|content| parse_ipv4_default_route(&content));
    let selected = ipv4.or_else(|| {
        fs::read_to_string("/proc/net/ipv6_route")
            .ok()
            .and_then(|content| parse_ipv6_default_route(&content))
    });
    let interface_name = selected.map(|(_, name)| name).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "missing default interface")
    })?;
    let c_name = CString::new(interface_name.as_str()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "interface name contains NUL",
        )
    })?;
    // SAFETY: `c_name` is a valid NUL-terminated interface name and the call
    // does not retain its pointer.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((interface_name, index))
}

fn parse_ipv4_default_route(content: &str) -> Option<(u32, String)> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8
                || fields[1] != "00000000"
                || fields[7] != "00000000"
            {
                return None;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            if flags & 1 == 0 {
                return None;
            }
            let metric = fields[6].parse::<u32>().ok()?;
            Some((metric, fields[0].to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
}

fn parse_ipv6_default_route(content: &str) -> Option<(u32, String)> {
    content
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10
                || fields[0] != "00000000000000000000000000000000"
                || fields[1] != "00"
            {
                return None;
            }
            let metric = u32::from_str_radix(fields[5], 16).ok()?;
            Some((metric, fields[9].to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    use super::{
        ResolvedTlsMode, build_server, is_resolved_managed_content,
        parse_ipv4_default_route, parse_ipv6_default_route, parse_tls_mode,
    };

    #[test]
    fn managed_resolv_conf_requires_resolved_header_before_configuration() {
        assert!(is_resolved_managed_content(
            "# This file is managed by systemd-resolved\n# details\nnameserver 127.0.0.53\n"
        ));
        assert!(!is_resolved_managed_content(
            "# generated\nnameserver 127.0.0.53\n# systemd-resolved\n"
        ));
    }

    #[test]
    fn route_parsers_choose_lowest_metric_default() {
        let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 01020304 0003 0 0 100 00000000 0 0 0\nwlan0 00000000 01020304 0003 0 0 50 00000000 0 0 0\n";
        assert_eq!(parse_ipv4_default_route(ipv4), Some((50, "wlan0".into())));
        let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000020 00000000 00000000 00000001 enp0s1\n";
        assert_eq!(parse_ipv6_default_route(ipv6), Some((32, "enp0s1".into())));
    }

    #[test]
    fn server_preserves_extended_port_name_and_link_scope() {
        let server = build_server(
            7,
            &Ipv6Addr::LOCALHOST.octets(),
            8853,
            "resolver.example".into(),
        )
        .unwrap();
        assert_eq!(server.tls_server_name(), "resolver.example");
        assert_eq!(server.socket_address(true).port(), 8853);

        let link_local = build_server(
            9,
            &Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets(),
            0,
            String::new(),
        )
        .unwrap();
        let SocketAddr::V6(link_local) = link_local.socket_address(false)
        else {
            panic!("expected IPv6 server")
        };
        assert_eq!(link_local.scope_id(), 9);
        assert_eq!(link_local.port(), 53);

        let ipv4 = build_server(2, &[1, 1, 1, 1], 0, String::new()).unwrap();
        assert_eq!(
            ipv4.tls_server_name(),
            IpAddr::from([1, 1, 1, 1]).to_string()
        );
        assert_eq!(parse_tls_mode("yes"), ResolvedTlsMode::Required);
        assert_eq!(
            parse_tls_mode("opportunistic"),
            ResolvedTlsMode::Opportunistic
        );
        assert_eq!(parse_tls_mode("no"), ResolvedTlsMode::Disabled);
    }
}
