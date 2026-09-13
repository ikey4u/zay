// Adapted from the copy of spacemeowx2/tokio-smoltcp already maintained in
// this repository under vendor/Easytier. Easytier and this crate are both
// distributed under GPL-3.0-or-later.

//! An asynchronous wrapper for smoltcp.

#![allow(dead_code)]

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicUsize, Ordering},
    },
};

use device::BufferDevice;
use reactor::Reactor;
pub use smoltcp;
use smoltcp::{
    iface::{Config, Interface},
    time::Instant,
    wire::{IpAddress, IpCidr},
};
pub use socket::{IcmpSocket, TcpListener, TcpStream, UdpSocket};
pub use socket_allocator::BufferSize;
use tokio::sync::{Notify, broadcast};
use tokio_util::task::AbortOnDropHandle;

/// The async devices.
pub mod channel_device;
pub mod device;
mod reactor;
mod socket;
mod socket_allocator;

/// A config for a `Net`.
///
/// This is used to configure the `Net`.
#[non_exhaustive]
pub struct NetConfig {
    pub interface_config: Config,
    pub ip_addrs: Vec<IpCidr>,
    pub gateway: Vec<IpAddress>,
    pub buffer_size: BufferSize,
    pub icmp_errors: Option<broadcast::Sender<Vec<u8>>>,
}

impl NetConfig {
    pub fn new(
        interface_config: Config,
        ip_addrs: Vec<IpCidr>,
        gateway: Vec<IpAddress>,
        buffer_size: Option<BufferSize>,
    ) -> Self {
        Self {
            interface_config,
            ip_addrs,
            gateway,
            buffer_size: buffer_size.unwrap_or_default(),
            icmp_errors: None,
        }
    }
}

/// `Net` is the main interface to the network stack.
/// Socket creation and configuration is done through the `Net` interface.
///
/// When `Net` is dropped, all sockets are closed and the network stack is stopped.
pub struct Net {
    reactor: Arc<Reactor>,
    ip_addrs: Vec<IpCidr>,
    from_port: AtomicU16,
    mtu: Arc<AtomicUsize>,
    stopper: Arc<Notify>,
    _fut: AbortOnDropHandle<io::Result<()>>,
    icmp_errors: Option<broadcast::Sender<Vec<u8>>>,
}

impl std::fmt::Debug for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Net")
            .field("ip_addrs", &self.ip_addrs)
            .field("from_port", &self.from_port)
            .finish()
    }
}

impl Net {
    /// Creates a new `Net` instance. It panics if the medium is not supported.
    pub fn new<D: device::AsyncDevice + 'static>(
        device: D,
        config: NetConfig,
    ) -> io::Result<Net> {
        Self::new2(device, config)
    }

    fn new2<D: device::AsyncDevice + 'static>(
        device: D,
        config: NetConfig,
    ) -> io::Result<Net> {
        let mut buffer_device =
            BufferDevice::new(device.capabilities().clone());
        let mtu = buffer_device.mtu_handle();
        let mut iface = Interface::new(
            config.interface_config,
            &mut buffer_device,
            Instant::now(),
        );
        if config.ip_addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one IP address is required",
            ));
        }
        let local_addresses = config.ip_addrs;
        let icmp_errors = config.icmp_errors;
        let mut address_error = None;
        iface.update_ip_addrs(|ip_addrs| {
            for ip_addr in &local_addresses {
                if ip_addrs.push(*ip_addr).is_err() {
                    address_error = Some(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many interface addresses for smoltcp",
                    ));
                    break;
                }
            }
        });
        if let Some(error) = address_error {
            return Err(error);
        }
        for gateway in config.gateway {
            match gateway {
                IpAddress::Ipv4(v4) => {
                    iface.routes_mut().add_default_ipv4_route(v4).map_err(
                        |_| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "cannot add smoltcp IPv4 default route",
                            )
                        },
                    )?;
                }
                IpAddress::Ipv6(v6) => {
                    iface.routes_mut().add_default_ipv6_route(v6).map_err(
                        |_| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "cannot add smoltcp IPv6 default route",
                            )
                        },
                    )?;
                }
                #[allow(unreachable_patterns)]
                _ => panic!("Unsupported address"),
            };
        }

        let stopper = Arc::new(Notify::new());
        let (reactor, fut) = Reactor::new(
            device,
            iface,
            buffer_device,
            config.buffer_size,
            stopper.clone(),
        );

        Ok(Net {
            reactor: Arc::new(reactor),
            ip_addrs: local_addresses,
            from_port: AtomicU16::new(10001),
            mtu,
            stopper,
            _fut: AbortOnDropHandle::new(tokio::spawn(fut)),
            icmp_errors,
        })
    }
    pub fn get_port(&self) -> u16 {
        self.from_port
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                Some(if x > 60000 { 10000 } else { x + 1 })
            })
            .unwrap()
    }

    /// Update the packet MTU consumed by smoltcp on its next reactor poll.
    pub fn set_mtu(&self, mtu: usize) {
        self.mtu.store(mtu, Ordering::Release);
        self.reactor.notify();
    }

    pub fn mtu(&self) -> usize {
        self.mtu.load(Ordering::Acquire)
    }
    /// Creates a new TcpListener, which will be bound to the specified address.
    pub async fn tcp_bind(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        let addr = self.set_address(addr)?;
        TcpListener::new(self.reactor.clone(), socket_addr_to_endpoint(addr))
            .await
    }
    /// Opens a TCP connection to a remote host.
    pub async fn tcp_connect(
        &self,
        addr: SocketAddr,
        local_port: u16,
    ) -> io::Result<TcpStream> {
        TcpStream::connect(
            self.reactor.clone(),
            (self.address_for(addr.ip())?, local_port).into(),
            socket_addr_to_endpoint(addr),
        )
        .await
    }

    /// This function will create a new UDP socket and attempt to bind it to the `addr` provided.
    pub async fn udp_bind(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let addr = self.set_address(addr)?;
        UdpSocket::new(self.reactor.clone(), socket_addr_to_endpoint(addr))
            .await
    }

    /// Opens an ICMP socket using an internally unique identifier.
    pub async fn icmp_bind(&self, identifier: u16) -> io::Result<IcmpSocket> {
        IcmpSocket::new(self.reactor.clone(), identifier).await
    }

    /// Exchange one echo request through the userspace stack. The identifier
    /// is translated to a stack-unique value so concurrent callers that reuse
    /// the same process identifier cannot steal each other's replies.
    pub async fn exchange_icmp(
        &self,
        packet: &[u8],
        source: IpAddr,
        destination: IpAddr,
        hop_limit: u8,
        timeout_duration: std::time::Duration,
    ) -> io::Result<crate::adapter::IcmpResponse> {
        if source.is_ipv4() != destination.is_ipv4() || packet.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ICMP exchange address family or packet",
            ));
        }
        let request_type = if source.is_ipv4() { 8 } else { 128 };
        let response_type = if source.is_ipv4() { 0 } else { 129 };
        if packet[0] != request_type || packet[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only ICMP echo requests can be exchanged",
            ));
        }
        let original_identifier = u16::from_be_bytes([packet[4], packet[5]]);
        let sequence = u16::from_be_bytes([packet[6], packet[7]]);
        let identifier = self.get_port();
        let socket = self.icmp_bind(identifier).await?;
        socket.set_hop_limit(hop_limit);
        let mut icmp_errors =
            self.icmp_errors.as_ref().map(|sender| sender.subscribe());
        let mut request = packet.to_vec();
        request[4..6].copy_from_slice(&identifier.to_be_bytes());
        if source.is_ipv4() {
            request[2..4].fill(0);
            let checksum = internet_checksum(&request);
            request[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        socket.send_to(&request, destination).await?;
        let mut response = vec![0_u8; 65_535];
        tokio::time::timeout(timeout_duration, async {
            loop {
                let received = if let Some(errors) = &mut icmp_errors {
                    tokio::select! {
                        response = socket.recv_from(&mut response) => {
                            response.map(IcmpExchangeInput::Echo)?
                        }
                        error = errors.recv() => match error {
                            Ok(packet) => IcmpExchangeInput::Error(packet),
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => {
                                icmp_errors = None;
                                continue;
                            }
                        }
                    }
                } else {
                    IcmpExchangeInput::Echo(
                        socket.recv_from(&mut response).await?,
                    )
                };
                let IcmpExchangeInput::Echo((length, response_source)) =
                    received
                else {
                    let IcmpExchangeInput::Error(packet) = received else {
                        unreachable!()
                    };
                    if let Some(response) = parse_icmp_error_response(
                        &packet,
                        source,
                        destination,
                        identifier,
                        original_identifier,
                        sequence,
                    ) {
                        return Ok(response);
                    }
                    continue;
                };
                if length < 8
                    || response[0] != response_type
                    || response[1] != 0
                    || u16::from_be_bytes([response[4], response[5]])
                        != identifier
                    || u16::from_be_bytes([response[6], response[7]])
                        != sequence
                {
                    continue;
                }
                response.truncate(length);
                response[4..6]
                    .copy_from_slice(&original_identifier.to_be_bytes());
                if source.is_ipv4() {
                    response[2..4].fill(0);
                    let checksum = internet_checksum(&response);
                    response[2..4].copy_from_slice(&checksum.to_be_bytes());
                }
                return Ok(crate::adapter::IcmpResponse {
                    source: response_source,
                    packet: response,
                    hop_limit: 64,
                });
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("ICMP exchange with {destination} timed out"),
            )
        })?
    }

    fn set_address(&self, mut addr: SocketAddr) -> io::Result<SocketAddr> {
        if addr.ip().is_unspecified() {
            addr.set_ip(match self.address_for(addr.ip())? {
                IpAddress::Ipv4(ip) => ip.into(),
                IpAddress::Ipv6(ip) => ip.into(),
                #[allow(unreachable_patterns)]
                _ => panic!("address must not be unspecified"),
            });
        }
        if addr.port() == 0 {
            addr.set_port(self.get_port());
        }
        Ok(addr)
    }

    fn address_for(&self, address: std::net::IpAddr) -> io::Result<IpAddress> {
        self.ip_addrs
            .iter()
            .map(IpCidr::address)
            .find(|candidate| {
                matches!(
                    (candidate, address),
                    (IpAddress::Ipv4(_), std::net::IpAddr::V4(_))
                        | (IpAddress::Ipv6(_), std::net::IpAddr::V6(_))
                )
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no local address for {address}"),
                )
            })
    }

    /// Enable or disable the AnyIP capability.
    pub fn set_any_ip(&self, any_ip: bool) {
        let iface = self.reactor.iface().clone();
        let mut iface: parking_lot::lock_api::MutexGuard<
            '_,
            parking_lot::RawMutex,
            Interface,
        > = iface.lock();
        iface.set_any_ip(any_ip);
    }
}

enum IcmpExchangeInput {
    Echo((usize, IpAddr)),
    Error(Vec<u8>),
}

fn parse_icmp_error_response(
    packet: &[u8],
    source: IpAddr,
    destination: IpAddr,
    wire_identifier: u16,
    original_identifier: u16,
    sequence: u16,
) -> Option<crate::adapter::IcmpResponse> {
    match (source, destination, packet.first().map(|byte| byte >> 4)) {
        (IpAddr::V4(source), IpAddr::V4(destination), Some(4)) => {
            if packet.len() < 56 || packet[9] != 1 {
                return None;
            }
            let outer_header_len = usize::from(packet[0] & 0x0f) * 4;
            let message = packet.get(outer_header_len..)?;
            if message.len() < 36 || !matches!(message[0], 3 | 11) {
                return None;
            }
            let inner_header_len = usize::from(message[8] & 0x0f) * 4;
            let inner_icmp = 8_usize.checked_add(inner_header_len)?;
            if message.len() < inner_icmp + 8
                || u16::from_be_bytes([
                    message[inner_icmp + 4],
                    message[inner_icmp + 5],
                ]) != wire_identifier
                || u16::from_be_bytes([
                    message[inner_icmp + 6],
                    message[inner_icmp + 7],
                ]) != sequence
            {
                return None;
            }
            let (_, message) = crate::protocol::direct::rewrite_icmpv4_error(
                message,
                source,
                destination,
                original_identifier,
            )?;
            Some(crate::adapter::IcmpResponse {
                source: IpAddr::V4(std::net::Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                packet: message,
                hop_limit: packet[8],
            })
        }
        (IpAddr::V6(source), IpAddr::V6(destination), Some(6)) => {
            if packet.len() < 96 || packet[6] != 58 {
                return None;
            }
            let message = &packet[40..];
            if !matches!(message[0], 1..=4)
                || u16::from_be_bytes([message[52], message[53]])
                    != wire_identifier
                || u16::from_be_bytes([message[54], message[55]]) != sequence
            {
                return None;
            }
            let (_, message) = crate::protocol::direct::rewrite_icmpv6_error(
                message,
                source,
                destination,
                original_identifier,
            )?;
            Some(crate::adapter::IcmpResponse {
                source: IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[8..24]).ok()?,
                )),
                packet: message,
                hop_limit: packet[7],
            })
        }
        _ => None,
    }
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn socket_addr_to_endpoint(addr: SocketAddr) -> smoltcp::wire::IpEndpoint {
    match addr {
        SocketAddr::V4(addr) => addr.into(),
        SocketAddr::V6(addr) => addr.into(),
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.stopper.notify_waiters()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc, time::Duration};

    use smoltcp::{
        iface::Config,
        phy::{DeviceCapabilities, Medium},
        wire::{HardwareAddress, IpAddress, IpCidr},
    };

    use super::{BufferSize, Net, NetConfig, channel_device::ChannelDevice};

    #[tokio::test]
    async fn channel_sideband_delivers_icmp_traceroute_error() {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        let (device, ingress, _egress, mut output, icmp_errors) =
            ChannelDevice::new(capabilities);
        let local: IpAddress = "10.0.0.2".parse().unwrap();
        let gateway: IpAddress = "10.0.0.1".parse().unwrap();
        let mut config = NetConfig::new(
            Config::new(HardwareAddress::Ip),
            vec![IpCidr::new(local, 24)],
            vec![gateway],
            Some(BufferSize::default()),
        );
        config.icmp_errors = Some(icmp_errors);
        let net = Arc::new(Net::new(device, config).unwrap());
        let mut request = b"\x08\x00\x00\x00\x31\x41\x00\x07trace".to_vec();
        let checksum = super::internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        let exchange = {
            let net = net.clone();
            tokio::spawn(async move {
                net.exchange_icmp(
                    &request,
                    "10.0.0.2".parse().unwrap(),
                    "198.51.100.7".parse().unwrap(),
                    1,
                    Duration::from_secs(1),
                )
                .await
            })
        };
        let outbound =
            tokio::time::timeout(Duration::from_secs(1), output.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(outbound[8], 1);
        assert_eq!(outbound[9], 1);

        let mut error = vec![0_u8; 28 + outbound.len()];
        let error_len = error.len() as u16;
        error[0] = 0x45;
        error[2..4].copy_from_slice(&error_len.to_be_bytes());
        error[8] = 62;
        error[9] = 1;
        error[12..16].copy_from_slice(&[192, 0, 2, 1]);
        error[16..20].copy_from_slice(&[10, 0, 0, 2]);
        error[20] = 11;
        error[28..].copy_from_slice(&outbound);
        ingress.send(Ok(error)).await.unwrap();

        let response = exchange.await.unwrap().unwrap();
        assert_eq!(response.source, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(response.hop_limit, 62);
        assert_eq!(response.packet[0], 11);
        let inner_header_len = usize::from(response.packet[8] & 0x0f) * 4;
        let inner_icmp = 8 + inner_header_len;
        assert_eq!(
            &response.packet[inner_icmp + 4..inner_icmp + 8],
            b"\x31\x41\x00\x07"
        );
    }

    #[test]
    fn parses_ipv6_icmp_error_from_channel_sideband() {
        let local: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let target: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        let transit: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut packet = vec![0_u8; 96];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&56_u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = 61;
        packet[8..24].copy_from_slice(&transit.octets());
        packet[24..40].copy_from_slice(&local.octets());
        packet[40] = 3;
        packet[48] = 0x60;
        packet[52..54].copy_from_slice(&8_u16.to_be_bytes());
        packet[54] = 58;
        packet[55] = 1;
        packet[56..72].copy_from_slice(&local.octets());
        packet[72..88].copy_from_slice(&target.octets());
        packet[88] = 128;
        packet[92..94].copy_from_slice(&10001_u16.to_be_bytes());
        packet[94..96].copy_from_slice(&8_u16.to_be_bytes());

        let response = super::parse_icmp_error_response(
            &packet,
            local.into(),
            target.into(),
            10001,
            0x3142,
            8,
        )
        .unwrap();
        assert_eq!(response.source, IpAddr::V6(transit));
        assert_eq!(response.hop_limit, 61);
        assert_eq!(response.packet[0], 3);
        assert_eq!(&response.packet[52..56], b"\x31\x42\x00\x08");
    }
}
