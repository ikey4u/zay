//! Apply streamed DERP maps to the embedded Tailscale transport.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    adapter::Dialer,
    common::{
        network::SocksAddr,
        tls::{ClientTlsDialer, build_client_config},
    },
    option::OutboundTlsOptions,
};

use super::{
    tailscale::{TailscaleDerpConnectOptions, TailscaleDerpError},
    tailscale_control_supervisor::TailscaleNetmapConsumer,
    tailscale_control_types::{
        TailscaleDerpNode, TailscaleDerpRegion, TailscaleNetmapState,
    },
    tailscale_derp_supervisor::{
        TailscaleDerpConnector, TailscaleDerpDialConnector,
    },
    tailscale_wireguard::{TailscaleWireGuardError, TailscaleWireGuardHandle},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleRoutePolicy {
    pub accept_routes: bool,
    pub exit_node: String,
}

impl TailscaleRoutePolicy {
    pub fn apply(&self, netmap: &TailscaleNetmapState) -> TailscaleNetmapState {
        let mut routed = netmap.clone();
        for peer in routed.peers.values_mut() {
            let exit_node = !self.exit_node.is_empty()
                && (peer.stable_id == self.exit_node
                    || peer.name.trim_end_matches('.')
                        == self.exit_node.trim_end_matches('.')
                    || peer.addresses.iter().any(|address| {
                        address.parse::<ipnet::IpNet>().is_ok_and(|prefix| {
                            prefix.addr().to_string() == self.exit_node
                        })
                    }));
            let node_addresses = peer
                .addresses
                .iter()
                .filter_map(|address| address.parse::<ipnet::IpNet>().ok())
                .collect::<Vec<_>>();
            peer.allowed_ips.retain(|allowed| {
                let Ok(prefix) = allowed.parse::<ipnet::IpNet>() else {
                    return false;
                };
                if node_addresses.contains(&prefix) {
                    true
                } else if prefix.prefix_len() == 0 {
                    exit_node
                } else {
                    self.accept_routes
                }
            });
        }
        routed
    }
}

#[derive(Debug, Error)]
pub enum TailscaleDerpMapError {
    #[error("DERP region {region_id} has no usable node")]
    NoUsableNode { region_id: u32 },
    #[error("invalid DERP node in region {region_id}: {message}")]
    InvalidNode { region_id: u32, message: String },
    #[error("configure DERP TLS: {0}")]
    Tls(String),
    #[error(transparent)]
    WireGuard(#[from] TailscaleWireGuardError),
    #[error(transparent)]
    Derp(#[from] TailscaleDerpError),
}

/// Build the production connector for one control-selected DERP node.
pub fn build_tailscale_derp_connector(
    dialer: Arc<dyn Dialer>,
    region: &TailscaleDerpRegion,
    private_key: [u8; 32],
    tls_options: Option<&OutboundTlsOptions>,
) -> Result<Arc<dyn TailscaleDerpConnector>, TailscaleDerpMapError> {
    let region_id = u32::try_from(region.region_id).map_err(|_| {
        TailscaleDerpMapError::InvalidNode {
            region_id: 0,
            message: "negative region ID".into(),
        }
    })?;
    let node = region
        .nodes
        .iter()
        .find(|node| !node.stun_only && !node.host_name.is_empty())
        .ok_or(TailscaleDerpMapError::NoUsableNode { region_id })?;
    build_node_connector(dialer, region_id, node, private_key, tls_options)
}

fn build_node_connector(
    dialer: Arc<dyn Dialer>,
    region_id: u32,
    node: &TailscaleDerpNode,
    private_key: [u8; 32],
    tls_options: Option<&OutboundTlsOptions>,
) -> Result<Arc<dyn TailscaleDerpConnector>, TailscaleDerpMapError> {
    let port = match node.derp_port {
        1..=65535 => node.derp_port as u16,
        0 => 443,
        _ => {
            return Err(TailscaleDerpMapError::InvalidNode {
                region_id,
                message: format!("invalid DERP port {}", node.derp_port),
            });
        }
    };
    let destination_host = preferred_destination_host(node);
    let destination = SocksAddr::new(destination_host, port);
    let authority = authority(&node.host_name, port);
    let stream_dialer: Arc<dyn Dialer> = if port == 80 {
        dialer
    } else {
        let mut options = tls_options.cloned().unwrap_or_default();
        options.enabled = true;
        let certificate_name = if node.cert_name.is_empty() {
            &node.host_name
        } else {
            &node.cert_name
        };
        let tls = build_client_config(certificate_name, &options, &[])
            .map_err(|error| TailscaleDerpMapError::Tls(error.to_string()))?;
        Arc::new(ClientTlsDialer::new(dialer, tls))
    };
    let mut options = TailscaleDerpConnectOptions::new(authority);
    options.ideal_node = (!node.name.is_empty()).then(|| node.name.clone());
    Ok(Arc::new(TailscaleDerpDialConnector {
        dialer: stream_dialer,
        destination,
        private_key,
        options,
    }))
}

/// Netmap consumer that updates both the DERP region set and WireGuard peers.
/// Unchanged regions keep their live supervisor and reverse-route cache.
pub struct TailscaleDerpMapController {
    engine: TailscaleWireGuardHandle,
    dialer: Arc<dyn Dialer>,
    private_key: [u8; 32],
    tls_options: Option<OutboundTlsOptions>,
    route_policy: TailscaleRoutePolicy,
    regions: Mutex<BTreeMap<u32, TailscaleDerpRegion>>,
}

impl TailscaleDerpMapController {
    pub fn new(
        engine: TailscaleWireGuardHandle,
        dialer: Arc<dyn Dialer>,
        private_key: [u8; 32],
        tls_options: Option<OutboundTlsOptions>,
    ) -> Self {
        Self {
            engine,
            dialer,
            private_key,
            tls_options,
            route_policy: TailscaleRoutePolicy::default(),
            regions: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn new_with_route_policy(
        engine: TailscaleWireGuardHandle,
        dialer: Arc<dyn Dialer>,
        private_key: [u8; 32],
        tls_options: Option<OutboundTlsOptions>,
        route_policy: TailscaleRoutePolicy,
    ) -> Self {
        Self {
            engine,
            dialer,
            private_key,
            tls_options,
            route_policy,
            regions: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn routed_netmap(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> TailscaleNetmapState {
        self.route_policy.apply(netmap)
    }

    pub fn configured_regions(&self) -> Vec<u32> {
        self.regions
            .lock()
            .map(|regions| regions.keys().copied().collect())
            .unwrap_or_default()
    }

    async fn apply(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> Result<(), TailscaleDerpMapError> {
        let desired = netmap
            .derp_map
            .as_ref()
            .and_then(|map| map.regions.as_ref())
            .map(|regions| {
                regions
                    .values()
                    .filter_map(|region| {
                        u32::try_from(region.region_id)
                            .ok()
                            .filter(|id| *id != 0)
                            .map(|id| (id, region.clone()))
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let previous = self
            .regions
            .lock()
            .map_err(|_| TailscaleDerpMapError::InvalidNode {
                region_id: 0,
                message: "DERP region lock poisoned".into(),
            })?
            .clone();

        for (region_id, region) in &desired {
            if previous.get(region_id) == Some(region) {
                continue;
            }
            let connector = build_tailscale_derp_connector(
                self.dialer.clone(),
                region,
                self.private_key,
                self.tls_options.as_ref(),
            )?;
            self.engine.set_derp_region(*region_id, connector).await?;
        }
        for region_id in previous.keys() {
            if !desired.contains_key(region_id) {
                self.engine.remove_derp_region(*region_id).await?;
            }
        }
        let home_region = netmap
            .node
            .as_ref()
            .and_then(|node| u32::try_from(node.home_derp).ok())
            .filter(|region| *region != 0);
        self.engine.set_home_derp_region(home_region).await?;
        self.engine.set_netmap(&self.routed_netmap(netmap)).await?;
        *self.regions.lock().map_err(|_| {
            TailscaleDerpMapError::InvalidNode {
                region_id: 0,
                message: "DERP region lock poisoned".into(),
            }
        })? = desired;
        Ok(())
    }
}

#[async_trait]
impl TailscaleNetmapConsumer for TailscaleDerpMapController {
    async fn apply_netmap(
        &self,
        netmap: &TailscaleNetmapState,
    ) -> Result<(), String> {
        self.apply(netmap).await.map_err(|error| error.to_string())
    }
}

fn preferred_destination_host(node: &TailscaleDerpNode) -> String {
    if !node.ipv4.is_empty() && node.ipv4.parse::<IpAddr>().is_ok() {
        node.ipv4.clone()
    } else if !node.ipv6.is_empty() && node.ipv6.parse::<IpAddr>().is_ok() {
        node.ipv6.clone()
    } else {
        node.host_name.clone()
    }
}

fn authority(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        option::DirectOutboundOptions, protocol::direct::DirectOutbound,
    };

    fn region(port: i32) -> TailscaleDerpRegion {
        TailscaleDerpRegion {
            region_id: 7,
            region_code: "test".into(),
            nodes: vec![TailscaleDerpNode {
                name: "7a".into(),
                region_id: 7,
                host_name: "derp.example".into(),
                ipv4: "192.0.2.7".into(),
                derp_port: port,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn builds_plain_and_tls_derp_connectors() {
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        assert!(
            build_tailscale_derp_connector(
                dialer.clone(),
                &region(80),
                [1; 32],
                None,
            )
            .is_ok()
        );
        assert!(
            build_tailscale_derp_connector(
                dialer,
                &region(443),
                [1; 32],
                None,
            )
            .is_ok()
        );
        assert_eq!(authority("2001:db8::1", 444), "[2001:db8::1]:444");
    }

    #[test]
    fn rejects_regions_without_derp_nodes() {
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let mut region = region(443);
        region.nodes[0].stun_only = true;
        assert!(matches!(
            build_tailscale_derp_connector(dialer, &region, [1; 32], None),
            Err(TailscaleDerpMapError::NoUsableNode { region_id: 7 })
        ));
    }

    #[test]
    fn route_policy_keeps_node_addresses_and_gates_subnet_and_exit_routes() {
        use crate::protocol::tailscale_control_types::{
            TailscaleNode, TailscaleNodePublicKey,
        };

        let mut netmap = TailscaleNetmapState::default();
        netmap.peers.insert(
            7,
            TailscaleNode {
                id: 7,
                stable_id: "peer-7".into(),
                name: "exit.example.ts.net.".into(),
                key: TailscaleNodePublicKey::from_bytes([7; 32]),
                addresses: vec!["100.64.0.7/32".into()],
                allowed_ips: vec![
                    "100.64.0.7/32".into(),
                    "10.0.0.0/8".into(),
                    "0.0.0.0/0".into(),
                    "::/0".into(),
                ],
                ..Default::default()
            },
        );
        let default = TailscaleRoutePolicy::default().apply(&netmap);
        assert_eq!(default.peers[&7].allowed_ips, vec!["100.64.0.7/32"]);
        let routes = TailscaleRoutePolicy {
            accept_routes: true,
            ..Default::default()
        }
        .apply(&netmap);
        assert_eq!(
            routes.peers[&7].allowed_ips,
            vec!["100.64.0.7/32", "10.0.0.0/8"]
        );
        let exit = TailscaleRoutePolicy {
            exit_node: "peer-7".into(),
            ..Default::default()
        }
        .apply(&netmap);
        assert_eq!(
            exit.peers[&7].allowed_ips,
            vec!["100.64.0.7/32", "0.0.0.0/0", "::/0"]
        );
    }
}
