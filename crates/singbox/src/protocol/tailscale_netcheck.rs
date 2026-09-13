//! Tailscale endpoint discovery over the socket shared with disco/WireGuard.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use futures_util::future::join_all;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig as _};

use super::{
    hysteria2_realm::{RealmPortMapping, RealmPortMappingOptions},
    tailscale_control_types::TailscaleNetmapState,
    tailscale_disco_socket::TailscaleDiscoSocketHandle,
};

pub const TAILSCALE_STUN_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const TAILSCALE_STUN_MAXIMUM_SERVERS: usize = 3;
/// Midpoint of upstream's randomized 20–26 second periodic ReSTUN window.
pub const TAILSCALE_RESTUN_INTERVAL: Duration = Duration::from_secs(23);
pub const TAILSCALE_PORT_MAPPING_TIMEOUT: Duration = Duration::from_secs(10);
pub const TAILSCALE_PORT_MAPPING_LIFETIME: Duration =
    Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TailscaleEndpointType {
    Local = 1,
    Stun = 2,
    PortMapped = 3,
    StunIpv4LocalPort = 4,
    Explicit = 5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleDiscoveredEndpoint {
    pub address: SocketAddr,
    pub endpoint_type: TailscaleEndpointType,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleNetcheckReport {
    pub endpoints: Vec<TailscaleDiscoveredEndpoint>,
    pub stun_servers_tried: Vec<SocketAddr>,
    pub stun_failures: Vec<(SocketAddr, String)>,
    pub mapping_varies_by_destination: bool,
}

impl TailscaleNetcheckReport {
    pub fn map_request_values(&self) -> (Vec<String>, Vec<i32>) {
        (
            self.endpoints
                .iter()
                .map(|endpoint| endpoint.address.to_string())
                .collect(),
            self.endpoints
                .iter()
                .map(|endpoint| endpoint.endpoint_type as i32)
                .collect(),
        )
    }

    pub fn add_port_mapped_endpoint(&mut self, address: SocketAddr) {
        if let Some(index) = self
            .endpoints
            .iter()
            .position(|endpoint| endpoint.address == address)
        {
            let mut endpoint = self.endpoints.remove(index);
            endpoint.endpoint_type = TailscaleEndpointType::PortMapped;
            self.endpoints.insert(0, endpoint);
            return;
        }
        self.endpoints.insert(
            0,
            TailscaleDiscoveredEndpoint {
                address,
                endpoint_type: TailscaleEndpointType::PortMapped,
            },
        );
    }
}

/// PCP/NAT-PMP/UPnP lease used by the Tailscale endpoint. The implementation
/// is shared with Hysteria Realm so renewal and explicit gateway cleanup have
/// one audited code path.
#[derive(Debug)]
pub struct TailscalePortMapping {
    inner: RealmPortMapping,
}

impl TailscalePortMapping {
    pub async fn start(internal_port: u16) -> io::Result<Self> {
        RealmPortMapping::start(
            internal_port,
            RealmPortMappingOptions::new(
                Some(TAILSCALE_PORT_MAPPING_TIMEOUT),
                Some(TAILSCALE_PORT_MAPPING_LIFETIME),
            ),
        )
        .await
        .map(|inner| Self { inner })
        .map_err(io::Error::other)
    }

    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.external_addr()
    }

    pub async fn changed(&mut self) -> io::Result<Option<SocketAddr>> {
        self.inner.changed().await.map_err(io::Error::other)
    }

    pub async fn close(self) {
        self.inner.close().await;
    }
}

pub async fn discover_tailscale_endpoints(
    socket: &TailscaleDiscoSocketHandle,
    netmap: &TailscaleNetmapState,
    timeout: Duration,
) -> io::Result<TailscaleNetcheckReport> {
    let local_addrs = socket.local_addrs();
    let local_addr = local_addrs.first().copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "Tailscale UDP socket has no local address",
        )
    })?;
    let servers = stun_servers(netmap, local_addrs);
    let results = join_all(servers.iter().copied().map(|server| {
        let socket = socket.clone();
        async move { (server, socket.stun_binding(server, timeout).await) }
    }))
    .await;

    let mut report = TailscaleNetcheckReport {
        stun_servers_tried: servers,
        ..Default::default()
    };
    let mut public = Vec::new();
    for (server, result) in results {
        match result {
            Ok(address) => public.push(address),
            Err(error) => {
                report.stun_failures.push((server, error.to_string()))
            }
        }
    }
    public.sort_unstable();
    public.dedup();
    report.mapping_varies_by_destination = public
        .first()
        .is_some_and(|first| public.iter().any(|address| address != first));
    for address in &public {
        push_unique(
            &mut report.endpoints,
            TailscaleDiscoveredEndpoint {
                address: *address,
                endpoint_type: TailscaleEndpointType::Stun,
            },
        );
    }
    if report.mapping_varies_by_destination
        && local_addr.port() != 0
        && let Some(address) = public.iter().find(|address| address.is_ipv4())
    {
        push_unique(
            &mut report.endpoints,
            TailscaleDiscoveredEndpoint {
                address: SocketAddr::new(address.ip(), local_addr.port()),
                endpoint_type: TailscaleEndpointType::StunIpv4LocalPort,
            },
        );
    }
    for address in local_endpoints(local_addrs)? {
        push_unique(
            &mut report.endpoints,
            TailscaleDiscoveredEndpoint {
                address,
                endpoint_type: TailscaleEndpointType::Local,
            },
        );
    }
    Ok(report)
}

fn stun_servers(
    netmap: &TailscaleNetmapState,
    local_addrs: &[SocketAddr],
) -> Vec<SocketAddr> {
    let has_ipv4 = local_addrs.iter().any(SocketAddr::is_ipv4);
    let has_ipv6 = local_addrs.iter().any(SocketAddr::is_ipv6);
    let mut servers = netmap
        .derp_map
        .as_ref()
        .and_then(|map| map.regions.as_ref())
        .into_iter()
        .flat_map(|regions| regions.values())
        .flat_map(|region| region.nodes.iter())
        .filter_map(|node| {
            let port = match node.stun_port {
                value if value < 0 || value > i32::from(u16::MAX) => {
                    return None;
                }
                0 => 3478,
                value => value as u16,
            };
            let mut addresses = Vec::with_capacity(2);
            if has_ipv4
                && let Ok(address) = node.ipv4.parse::<IpAddr>()
                && address.is_ipv4()
            {
                addresses.push(SocketAddr::new(address, port));
            }
            if has_ipv6
                && let Ok(address) = node.ipv6.parse::<IpAddr>()
                && address.is_ipv6()
            {
                addresses.push(SocketAddr::new(address, port));
            }
            Some(addresses)
        })
        .flatten()
        .collect::<Vec<_>>();
    servers.sort_unstable();
    servers.dedup();
    let mut ipv4_count = 0;
    let mut ipv6_count = 0;
    servers.retain(|server| {
        let count = if server.is_ipv4() {
            &mut ipv4_count
        } else {
            &mut ipv6_count
        };
        if *count >= TAILSCALE_STUN_MAXIMUM_SERVERS {
            false
        } else {
            *count += 1;
            true
        }
    });
    servers
}

fn local_endpoints(local_addrs: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
    if local_addrs
        .iter()
        .all(|address| !address.ip().is_unspecified())
    {
        return Ok(local_addrs.to_vec());
    }
    let ipv4_port = local_addrs
        .iter()
        .find(|address| address.is_ipv4())
        .map(SocketAddr::port);
    let ipv6_port = local_addrs
        .iter()
        .find(|address| address.is_ipv6())
        .map(SocketAddr::port);
    let mut external = Vec::new();
    let mut loopback = Vec::new();
    for interface in NetworkInterface::show().map_err(io::Error::other)? {
        for address in interface.addr {
            let ip = match address {
                Addr::V4(address) if ipv4_port.is_some() => {
                    IpAddr::V4(address.ip)
                }
                Addr::V6(address) if ipv6_port.is_some() => {
                    IpAddr::V6(address.ip)
                }
                _ => continue,
            };
            if ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            let port = if ip.is_ipv4() {
                ipv4_port.expect("IPv4 port checked")
            } else {
                ipv6_port.expect("IPv6 port checked")
            };
            let endpoint = SocketAddr::new(ip, port);
            if interface.internal || ip.is_loopback() {
                loopback.push(endpoint);
            } else {
                external.push(endpoint);
            }
        }
    }
    if external.is_empty() {
        external = loopback;
    }
    external.sort_unstable();
    external.dedup();
    Ok(external)
}

fn push_unique(
    endpoints: &mut Vec<TailscaleDiscoveredEndpoint>,
    endpoint: TailscaleDiscoveredEndpoint,
) {
    if !endpoints
        .iter()
        .any(|existing| existing.address == endpoint.address)
    {
        endpoints.push(endpoint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tailscale_control_types::{
        TailscaleDerpMap, TailscaleDerpNode, TailscaleDerpRegion,
    };
    use std::collections::BTreeMap;

    #[test]
    fn selects_deduplicated_stun_servers_and_preserves_wire_types() {
        let mut regions = BTreeMap::new();
        regions.insert(
            1,
            TailscaleDerpRegion {
                region_id: 1,
                nodes: vec![
                    TailscaleDerpNode {
                        ipv4: "192.0.2.2".into(),
                        ipv6: "2001:db8::2".into(),
                        stun_port: 0,
                        ..Default::default()
                    },
                    TailscaleDerpNode {
                        ipv4: "192.0.2.2".into(),
                        stun_port: 3478,
                        ..Default::default()
                    },
                    TailscaleDerpNode {
                        ipv4: "192.0.2.3".into(),
                        stun_port: -1,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        let netmap = TailscaleNetmapState {
            derp_map: Some(TailscaleDerpMap {
                regions: Some(regions),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            stun_servers(&netmap, &["0.0.0.0:41641".parse().unwrap()]),
            vec!["192.0.2.2:3478".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            stun_servers(
                &netmap,
                &[
                    "0.0.0.0:41641".parse().unwrap(),
                    "[::]:41641".parse().unwrap(),
                ],
            ),
            vec![
                "192.0.2.2:3478".parse::<SocketAddr>().unwrap(),
                "[2001:db8::2]:3478".parse::<SocketAddr>().unwrap(),
            ]
        );
        let report = TailscaleNetcheckReport {
            endpoints: vec![TailscaleDiscoveredEndpoint {
                address: "198.51.100.7:41641".parse().unwrap(),
                endpoint_type: TailscaleEndpointType::Stun,
            }],
            ..Default::default()
        };
        assert_eq!(
            report.map_request_values(),
            (vec!["198.51.100.7:41641".into()], vec![2])
        );
        let mut report = report;
        report.add_port_mapped_endpoint(
            "203.0.113.7:41641".parse::<SocketAddr>().unwrap(),
        );
        assert_eq!(report.map_request_values().1, vec![3, 2]);
    }
}
