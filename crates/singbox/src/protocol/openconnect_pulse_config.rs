//! Pulse Secure tunnel configuration and ESP key negotiation.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rand::{RngCore, rngs::OsRng};
use thiserror::Error;

use super::{
    OPENCONNECT_ESP_IPV4_NEXT_HEADER, OPENCONNECT_ESP_IPV6_NEXT_HEADER,
    OpenConnectEspAuthentication, OpenConnectEspEncryption,
    OpenConnectEspError, OpenConnectEspKeyMaterial, OpenConnectEspKeySet,
    OpenConnectEspKeySetConfig, PULSE_VENDOR_JUNIPER, PulseIftFrame,
    TunnelConfiguration, TunnelRoute,
};

pub const PULSE_DEFAULT_ESP_ATTEMPT_PERIOD: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct PulseTunnelConfiguration {
    pub configuration: TunnelConfiguration,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub assigned_ipv6: Option<Ipv6Addr>,
    pub esp: Option<PulseEspConfiguration>,
}

#[derive(Debug, Clone)]
pub struct PulseEspConfiguration {
    pub remote: SocketAddr,
    pub keys: OpenConnectEspKeySetConfig,
    pub encryption: OpenConnectEspEncryption,
    pub authentication: OpenConnectEspAuthentication,
    pub port: u16,
    pub fallback: Duration,
    pub cross_family: bool,
    pub replay_protection: bool,
    pub probe_next_header: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PulseConfigurationAction {
    Ignored,
    Applied,
    EspResponse(Vec<u8>),
    Complete,
}

#[derive(Debug, Error)]
pub enum PulseConfigurationError {
    #[error("invalid Pulse configuration envelope")]
    InvalidEnvelope,
    #[error("Pulse configuration is truncated: {0}")]
    Truncated(&'static str),
    #[error("invalid Pulse configuration: {0}")]
    Invalid(&'static str),
    #[error("invalid Pulse configuration length: {0}")]
    InvalidLength(usize),
    #[error("unknown Pulse IPv4 route type: {0:#x}")]
    UnknownRouteType(u32),
    #[error("Pulse IPv4 route range is not a CIDR prefix")]
    NonCidrRoute,
    #[error("Pulse IPv4 netmask is not contiguous")]
    NonContiguousNetmask,
    #[error("server returned insufficient Pulse tunnel configuration")]
    InsufficientConfiguration,
    #[error("server did not provide an IPv4 Pulse tunnel address")]
    MissingIpv4Address,
    #[error("Pulse IPv4 configuration omitted its netmask")]
    MissingIpv4Netmask,
    #[error("invalid Pulse tunnel MTU: {0}")]
    InvalidMtu(u32),
    #[error("invalid Pulse ESP configuration frame")]
    InvalidEspFrame,
    #[error("Pulse ESP configuration omitted usable algorithms, keys, or port")]
    IncompleteEspConfiguration,
    #[error("Pulse ESP key lengths exceed the 64-byte secret block")]
    EspKeysTooLarge,
    #[error(transparent)]
    Esp(#[from] OpenConnectEspError),
}

pub struct PulseConfigurationAccumulator {
    configuration: TunnelConfiguration,
    assigned_ipv4: Option<Ipv4Addr>,
    assigned_ipv6: Option<Ipv6Addr>,
    ipv4_netmask: Option<Ipv4Addr>,
    esp_encryption: Option<OpenConnectEspEncryption>,
    esp_authentication: Option<OpenConnectEspAuthentication>,
    esp_port: u16,
    esp_fallback: Duration,
    esp_cross_family: bool,
    esp_replay: bool,
    esp: Option<PulseEspConfiguration>,
    main_seen: bool,
    ipv6_disabled: bool,
    no_udp: bool,
    accepted_address: IpAddr,
}

impl PulseConfigurationAccumulator {
    pub fn new(
        accepted_address: IpAddr,
        authentication_expiration: Option<SystemTime>,
        idle_timeout: Duration,
        ipv6_disabled: bool,
        no_udp: bool,
    ) -> Self {
        Self {
            configuration: empty_configuration(
                accepted_address,
                authentication_expiration,
                idle_timeout,
            ),
            assigned_ipv4: None,
            assigned_ipv6: None,
            ipv4_netmask: None,
            esp_encryption: None,
            esp_authentication: None,
            esp_port: 0,
            esp_fallback: Duration::ZERO,
            esp_cross_family: false,
            esp_replay: false,
            esp: None,
            main_seen: false,
            ipv6_disabled,
            no_udp,
            accepted_address,
        }
    }

    pub fn apply_frame(
        &mut self,
        frame: &PulseIftFrame,
    ) -> Result<PulseConfigurationAction, PulseConfigurationError> {
        if frame.vendor != PULSE_VENDOR_JUNIPER {
            return Ok(PulseConfigurationAction::Ignored);
        }
        if frame.frame_type == 0x8f {
            return Ok(PulseConfigurationAction::Complete);
        }
        if frame.frame_type != 1 || frame.payload.len() < 28 {
            return Ok(PulseConfigurationAction::Ignored);
        }
        if !pulse_configuration_envelope_valid(&frame.payload) {
            return Err(PulseConfigurationError::InvalidEnvelope);
        }
        match u32::from_be_bytes(frame.payload[16..20].try_into().unwrap()) {
            0x2c20f000 | 0x2e20f000 => {
                self.parse_main_configuration(&frame.payload)?;
                Ok(PulseConfigurationAction::Applied)
            }
            0x21202400 if self.no_udp => Ok(PulseConfigurationAction::Ignored),
            0x21202400 => {
                let (configuration, response) =
                    self.parse_esp_configuration(&frame.payload)?;
                self.esp = Some(configuration);
                Ok(PulseConfigurationAction::EspResponse(response))
            }
            _ => Ok(PulseConfigurationAction::Ignored),
        }
    }

    /// Parse a server-initiated ESP rekey using the algorithms and transport
    /// attributes retained from the previous negotiation.
    pub fn parse_esp_rekey(
        payload: &[u8],
        previous: &PulseEspConfiguration,
    ) -> Result<(PulseEspConfiguration, Vec<u8>), PulseConfigurationError> {
        let mut accumulator =
            Self::new(previous.remote.ip(), None, Duration::ZERO, false, false);
        accumulator.esp_encryption = Some(previous.encryption);
        accumulator.esp_authentication = Some(previous.authentication);
        accumulator.esp_port = previous.port;
        accumulator.esp_fallback = previous.fallback;
        accumulator.esp_cross_family = previous.cross_family;
        accumulator.esp_replay = previous.replay_protection;
        accumulator.parse_esp_configuration(payload)
    }

    pub fn finish(
        mut self,
    ) -> Result<PulseTunnelConfiguration, PulseConfigurationError> {
        if !self.main_seen
            || self.configuration.mtu == 0
            || (self.assigned_ipv4.is_none() && self.assigned_ipv6.is_none())
        {
            return Err(PulseConfigurationError::InsufficientConfiguration);
        }
        if self.ipv6_disabled {
            self.assigned_ipv6 = None;
            self.configuration
                .addresses
                .retain(|address| address.addr().is_ipv4());
            if self.assigned_ipv4.is_none() {
                return Err(PulseConfigurationError::MissingIpv4Address);
            }
        }
        let minimum_mtu = if self.assigned_ipv6.is_some() {
            1280
        } else {
            576
        };
        if !(minimum_mtu..=65_535).contains(&self.configuration.mtu) {
            return Err(PulseConfigurationError::InvalidMtu(
                self.configuration.mtu,
            ));
        }
        if let Some(address) = self.assigned_ipv4 {
            let netmask = self
                .ipv4_netmask
                .ok_or(PulseConfigurationError::MissingIpv4Netmask)?;
            self.configuration.addresses.push(IpNet::V4(
                Ipv4Net::new(address, ipv4_prefix_length(netmask)?).map_err(
                    |_| PulseConfigurationError::NonContiguousNetmask,
                )?,
            ));
        }
        normalize_configuration(&mut self.configuration, self.ipv6_disabled);
        Ok(PulseTunnelConfiguration {
            configuration: self.configuration,
            assigned_ipv4: self.assigned_ipv4,
            assigned_ipv6: self.assigned_ipv6,
            esp: self.esp,
        })
    }
}

pub fn pulse_esp_configuration_frame_valid(payload: &[u8]) -> bool {
    payload.len() >= 106
        && pulse_configuration_envelope_valid(payload)
        && u32::from_be_bytes(payload[16..20].try_into().unwrap()) == 0x21202400
        && u32::from_be_bytes(payload[28..32].try_into().unwrap())
            == (payload.len() - 28) as u32
        && u32::from_be_bytes(payload[32..36].try_into().unwrap()) == 0x01000000
        && u16::from_be_bytes(payload[40..42].try_into().unwrap()) == 64
}

pub fn pulse_packet_version(payload: &[u8]) -> u8 {
    payload.first().map_or(0, |byte| byte >> 4)
}

fn empty_configuration(
    accepted_address: IpAddr,
    authentication_expiration: Option<SystemTime>,
    idle_timeout: Duration,
) -> TunnelConfiguration {
    TunnelConfiguration {
        mtu: 0,
        remote_address: Some(accepted_address),
        addresses: Vec::new(),
        routes: Vec::new(),
        excluded_routes: Vec::new(),
        dns: Vec::new(),
        nbns: Vec::new(),
        search_domains: Vec::new(),
        split_dns: Vec::new(),
        split_dns_rules: Vec::new(),
        proxy_auto_config_url: String::new(),
        banner: String::new(),
        tunnel_all_dns: false,
        client_bypass_protocol: false,
        idle_timeout,
        authentication_expiration,
    }
}

fn ipv4_attribute(content: &[u8]) -> Result<Ipv4Addr, PulseConfigurationError> {
    Ok(Ipv4Addr::from(<[u8; 4]>::try_from(content).map_err(
        |_| PulseConfigurationError::Invalid("IPv4 attribute"),
    )?))
}

fn be_u16(
    content: &[u8],
    name: &'static str,
) -> Result<u16, PulseConfigurationError> {
    Ok(u16::from_be_bytes(
        content
            .try_into()
            .map_err(|_| PulseConfigurationError::Invalid(name))?,
    ))
}

fn be_u32(
    content: &[u8],
    name: &'static str,
) -> Result<u32, PulseConfigurationError> {
    Ok(u32::from_be_bytes(
        content
            .try_into()
            .map_err(|_| PulseConfigurationError::Invalid(name))?,
    ))
}

fn ipv4_prefix_length(
    netmask: Ipv4Addr,
) -> Result<u8, PulseConfigurationError> {
    let mask = u32::from(netmask);
    let prefix = mask.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if mask != expected {
        return Err(PulseConfigurationError::NonContiguousNetmask);
    }
    Ok(prefix)
}

fn normalize_configuration(
    configuration: &mut TunnelConfiguration,
    ipv6_disabled: bool,
) {
    if ipv6_disabled {
        configuration
            .addresses
            .retain(|address| address.addr().is_ipv4());
        configuration.dns.retain(IpAddr::is_ipv4);
        configuration.nbns.retain(IpAddr::is_ipv4);
        configuration
            .routes
            .retain(|route| route.prefix.addr().is_ipv4());
        configuration
            .excluded_routes
            .retain(|route| route.prefix.addr().is_ipv4());
    }
    let has_ipv4_address = configuration
        .addresses
        .iter()
        .any(|address| address.addr().is_ipv4());
    let has_ipv6_address = configuration
        .addresses
        .iter()
        .any(|address| address.addr().is_ipv6());
    let has_ipv4_route = configuration
        .routes
        .iter()
        .any(|route| route.prefix.addr().is_ipv4());
    let has_ipv6_route = configuration
        .routes
        .iter()
        .any(|route| route.prefix.addr().is_ipv6());
    if has_ipv4_address && !has_ipv4_route {
        configuration.routes.push(TunnelRoute {
            prefix: IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            gateway: None,
            metric: 0,
        });
    }
    if has_ipv6_address && !has_ipv6_route {
        configuration.routes.push(TunnelRoute {
            prefix: IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()),
            gateway: None,
            metric: 0,
        });
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&kind.to_be_bytes());
        result.extend_from_slice(&(value.len() as u16).to_be_bytes());
        result.extend_from_slice(value);
        result
    }

    fn attribute_block(attributes: &[u8]) -> Vec<u8> {
        let mut result = vec![0_u8; 8];
        let length = result.len() + attributes.len();
        result[..4].copy_from_slice(&(length as u32).to_be_bytes());
        result[4..8].copy_from_slice(&0x03000000_u32.to_be_bytes());
        result.extend_from_slice(attributes);
        result
    }

    fn main_frame(attributes: &[u8], routes: &[[u8; 16]]) -> PulseIftFrame {
        let mut section = Vec::new();
        section.extend_from_slice(&0x2e00_u16.to_be_bytes());
        section.extend_from_slice(
            &(8_u16 + routes.len() as u16 * 16).to_be_bytes(),
        );
        section.push(routes.len() as u8);
        section.extend_from_slice(&[0, 0, 0]);
        for route in routes {
            section.extend_from_slice(route);
        }
        section.extend_from_slice(&attribute_block(attributes));
        let mut payload = vec![0_u8; 28];
        payload[16..20].copy_from_slice(&0x2c20f000_u32.to_be_bytes());
        payload.extend_from_slice(&section);
        let length = payload.len() as u32;
        payload[24..28].copy_from_slice(&length.to_be_bytes());
        PulseIftFrame {
            vendor: PULSE_VENDOR_JUNIPER,
            frame_type: 1,
            sequence: 0,
            payload,
        }
    }

    #[test]
    fn main_configuration_parses_addresses_dns_routes_and_mtu() {
        let mut attributes = Vec::new();
        attributes.extend_from_slice(&attribute(0x0001, &[10, 0, 0, 2]));
        attributes.extend_from_slice(&attribute(0x0002, &[255, 255, 255, 0]));
        attributes.extend_from_slice(&attribute(0x0003, &[10, 0, 0, 53]));
        attributes
            .extend_from_slice(&attribute(0x4005, &1400_u32.to_be_bytes()));
        attributes.extend_from_slice(&attribute(0x4006, b"corp.example\0"));
        let mut route = [0_u8; 16];
        route[..4].copy_from_slice(&0x07000010_u32.to_be_bytes());
        route[4..8].copy_from_slice(&0x0000ffff_u32.to_be_bytes());
        route[8..12].copy_from_slice(
            &u32::from(Ipv4Addr::new(192, 0, 2, 0)).to_be_bytes(),
        );
        route[12..16].copy_from_slice(
            &u32::from(Ipv4Addr::new(192, 0, 2, 255)).to_be_bytes(),
        );
        let mut accumulator = PulseConfigurationAccumulator::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            None,
            Duration::from_secs(30),
            false,
            true,
        );
        assert_eq!(
            accumulator
                .apply_frame(&main_frame(&attributes, &[route]))
                .unwrap(),
            PulseConfigurationAction::Applied
        );
        let configuration = accumulator.finish().unwrap();
        assert_eq!(configuration.configuration.mtu, 1400);
        assert_eq!(
            configuration.configuration.addresses[0].to_string(),
            "10.0.0.2/24"
        );
        assert_eq!(
            configuration.configuration.routes[0].prefix.to_string(),
            "192.0.2.0/24"
        );
        assert_eq!(
            configuration.configuration.dns,
            [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]
        );
    }

    #[test]
    fn rejects_noncontiguous_route_and_netmask() {
        let mut accumulator = PulseConfigurationAccumulator::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            Duration::ZERO,
            false,
            true,
        );
        let mut route = [0_u8; 16];
        route[..4].copy_from_slice(&0x07000010_u32.to_be_bytes());
        route[4..8].copy_from_slice(&0x0000ffff_u32.to_be_bytes());
        route[8..12].copy_from_slice(&1_u32.to_be_bytes());
        route[12..16].copy_from_slice(&3_u32.to_be_bytes());
        assert!(matches!(
            accumulator.parse_ipv4_route(&route),
            Err(PulseConfigurationError::NonCidrRoute)
        ));
        assert!(ipv4_prefix_length(Ipv4Addr::new(255, 0, 255, 0)).is_err());
    }

    #[test]
    fn envelope_and_packet_version_are_strict() {
        let mut payload = vec![0_u8; 28];
        payload[24..28].copy_from_slice(&28_u32.to_be_bytes());
        assert!(pulse_configuration_envelope_valid(&payload));
        payload[0] = 1;
        assert!(!pulse_configuration_envelope_valid(&payload));
        assert_eq!(pulse_packet_version(&[0x60]), 6);
        assert_eq!(pulse_packet_version(&[]), 0);
    }

    #[test]
    fn esp_rekey_inherits_algorithms_and_rotates_key_material() {
        let previous = PulseEspConfiguration {
            remote: "192.0.2.1:4501".parse().unwrap(),
            keys: OpenConnectEspKeySetConfig {
                encryption: OpenConnectEspEncryption::Aes128Cbc,
                authentication: OpenConnectEspAuthentication::HmacSha1_96,
                outbound: OpenConnectEspKeyMaterial {
                    spi: 1,
                    encryption_key: vec![1; 16],
                    authentication_key: vec![2; 20],
                },
                inbound: OpenConnectEspKeyMaterial {
                    spi: 2,
                    encryption_key: vec![3; 16],
                    authentication_key: vec![4; 20],
                },
                disable_replay_protection: false,
            },
            encryption: OpenConnectEspEncryption::Aes128Cbc,
            authentication: OpenConnectEspAuthentication::HmacSha1_96,
            port: 4501,
            fallback: Duration::from_secs(30),
            cross_family: true,
            replay_protection: true,
            probe_next_header: OPENCONNECT_ESP_IPV4_NEXT_HEADER,
        };
        let mut payload = vec![0_u8; 106];
        let payload_length = payload.len();
        payload[16..20].copy_from_slice(&0x21202400_u32.to_be_bytes());
        payload[24..28].copy_from_slice(&(payload_length as u32).to_be_bytes());
        payload[28..32]
            .copy_from_slice(&((payload_length - 28) as u32).to_be_bytes());
        payload[32..36].copy_from_slice(&0x01000000_u32.to_be_bytes());
        payload[36..40].copy_from_slice(&0x10203040_u32.to_le_bytes());
        payload[40..42].copy_from_slice(&64_u16.to_be_bytes());
        payload[42..58].fill(0x11);
        payload[58..78].fill(0x22);

        let (rekeyed, response) =
            PulseConfigurationAccumulator::parse_esp_rekey(&payload, &previous)
                .unwrap();
        assert_eq!(rekeyed.remote, previous.remote);
        assert_eq!(rekeyed.fallback, previous.fallback);
        assert!(rekeyed.cross_family);
        assert_eq!(rekeyed.keys.outbound.spi, 0x10203040);
        assert_eq!(rekeyed.keys.outbound.encryption_key, vec![0x11; 16]);
        assert_eq!(rekeyed.keys.outbound.authentication_key, vec![0x22; 20]);
        assert_ne!(rekeyed.keys.inbound.spi, 0);
        assert_eq!(response.len(), 176);
    }
}

pub fn pulse_configuration_envelope_valid(payload: &[u8]) -> bool {
    payload.len() >= 28
        && u32::from_be_bytes(payload[24..28].try_into().unwrap())
            == payload.len() as u32
        && payload[..16].iter().all(|byte| *byte == 0)
        && u32::from_be_bytes(payload[20..24].try_into().unwrap()) == 0
}

impl PulseConfigurationAccumulator {
    fn parse_main_configuration(
        &mut self,
        payload: &[u8],
    ) -> Result<(), PulseConfigurationError> {
        let identifier =
            u32::from_be_bytes(payload[16..20].try_into().unwrap());
        let section = &payload[28..];
        let mut offset = 0;
        if identifier == 0x2e20f000 {
            loop {
                if section.len().saturating_sub(offset) < 8 {
                    return Err(PulseConfigurationError::Truncated(
                        "leading attributes",
                    ));
                }
                let flag = u16::from_be_bytes(
                    section[offset..offset + 2].try_into().unwrap(),
                );
                let length = u16::from_be_bytes(
                    section[offset + 2..offset + 4].try_into().unwrap(),
                ) as usize;
                if length < 8 || length > section.len() - offset {
                    return Err(PulseConfigurationError::InvalidLength(length));
                }
                self.parse_attribute_block(&section[offset..offset + length])?;
                offset += length;
                if flag == 0x2c00 {
                    break;
                }
            }
        }
        if section.len().saturating_sub(offset) < 8
            || u16::from_be_bytes(
                section[offset..offset + 2].try_into().unwrap(),
            ) != 0x2e00
        {
            return Err(PulseConfigurationError::Invalid(
                "routing block is missing",
            ));
        }
        let routing_length = u16::from_be_bytes(
            section[offset + 2..offset + 4].try_into().unwrap(),
        ) as usize;
        let route_count = usize::from(section[offset + 4]);
        if routing_length != route_count * 16 + 8
            || routing_length > section.len().saturating_sub(offset + 4)
        {
            return Err(PulseConfigurationError::InvalidLength(routing_length));
        }
        for route in
            section[offset + 8..offset + routing_length].chunks_exact(16)
        {
            self.parse_ipv4_route(route)?;
        }
        offset += routing_length;
        if section.len().saturating_sub(offset) < 8 {
            return Err(PulseConfigurationError::Truncated("final attributes"));
        }
        let attribute_length =
            u32::from_be_bytes(section[offset..offset + 4].try_into().unwrap())
                as usize;
        if attribute_length != section.len() - offset {
            return Err(PulseConfigurationError::InvalidLength(
                attribute_length,
            ));
        }
        self.parse_attribute_block(&section[offset..])?;
        self.main_seen = true;
        Ok(())
    }

    fn parse_attribute_block(
        &mut self,
        content: &[u8],
    ) -> Result<(), PulseConfigurationError> {
        if content.len() < 8
            || u32::from_be_bytes(content[4..8].try_into().unwrap())
                != 0x03000000
        {
            return Err(PulseConfigurationError::Invalid(
                "attribute block header",
            ));
        }
        let mut content = &content[8..];
        while !content.is_empty() {
            if content.len() < 4 {
                return Err(PulseConfigurationError::Truncated(
                    "attribute header",
                ));
            }
            let attribute_type =
                u16::from_be_bytes(content[..2].try_into().unwrap());
            let attribute_length =
                u16::from_be_bytes(content[2..4].try_into().unwrap()) as usize;
            if attribute_length > content.len() - 4 {
                return Err(PulseConfigurationError::InvalidLength(
                    attribute_length,
                ));
            }
            self.apply_attribute(
                attribute_type,
                &content[4..4 + attribute_length],
            )?;
            content = &content[4 + attribute_length..];
        }
        Ok(())
    }

    fn apply_attribute(
        &mut self,
        attribute_type: u16,
        content: &[u8],
    ) -> Result<(), PulseConfigurationError> {
        match attribute_type {
            0x0001 => {
                let address = ipv4_attribute(content)?;
                if address.is_unspecified() || address.is_multicast() {
                    return Err(PulseConfigurationError::Invalid(
                        "assigned IPv4 address",
                    ));
                }
                self.assigned_ipv4 = Some(address);
            }
            0x0002 => self.ipv4_netmask = Some(ipv4_attribute(content)?),
            0x0003 | 0x0004 => {
                let address = ipv4_attribute(content)?;
                if address.is_unspecified() {
                    return Err(PulseConfigurationError::Invalid(
                        "unspecified IPv4 name server",
                    ));
                }
                let servers = if attribute_type == 0x0003 {
                    &mut self.configuration.dns
                } else {
                    &mut self.configuration.nbns
                };
                if servers.len() < 3 {
                    servers.push(IpAddr::V4(address));
                }
            }
            0x0008 if !self.ipv6_disabled => {
                if content.len() != 17 || content[16] > 128 {
                    return Err(PulseConfigurationError::Invalid(
                        "IPv6 address attribute",
                    ));
                }
                let address = Ipv6Addr::from(
                    <[u8; 16]>::try_from(&content[..16]).unwrap(),
                );
                if address.is_unspecified()
                    || address.is_multicast()
                    || address.to_ipv4_mapped().is_some()
                {
                    return Err(PulseConfigurationError::Invalid(
                        "assigned IPv6 address",
                    ));
                }
                self.assigned_ipv6 = Some(address);
                self.configuration.addresses.push(IpNet::V6(
                    Ipv6Net::new(address, content[16]).map_err(|_| {
                        PulseConfigurationError::Invalid("IPv6 prefix")
                    })?,
                ));
            }
            0x000a if !self.ipv6_disabled => {
                if content.len() != 16 {
                    return Err(PulseConfigurationError::Invalid(
                        "IPv6 DNS attribute",
                    ));
                }
                let address =
                    Ipv6Addr::from(<[u8; 16]>::try_from(content).unwrap());
                if address.is_unspecified()
                    || address.to_ipv4_mapped().is_some()
                {
                    return Err(PulseConfigurationError::Invalid(
                        "IPv6 DNS server",
                    ));
                }
                if self.configuration.dns.len() < 3 {
                    self.configuration.dns.push(IpAddr::V6(address));
                }
            }
            0x000f | 0x0010 if !self.ipv6_disabled => {
                if content.len() != 17 || content[16] > 128 {
                    return Err(PulseConfigurationError::Invalid(
                        "IPv6 route attribute",
                    ));
                }
                let address = Ipv6Addr::from(
                    <[u8; 16]>::try_from(&content[..16]).unwrap(),
                );
                if address.to_ipv4_mapped().is_some() {
                    return Err(PulseConfigurationError::Invalid("IPv6 route"));
                }
                let route = TunnelRoute {
                    prefix: IpNet::V6(
                        Ipv6Net::new(address, content[16])
                            .map_err(|_| {
                                PulseConfigurationError::Invalid(
                                    "IPv6 route prefix",
                                )
                            })?
                            .trunc(),
                    ),
                    gateway: None,
                    metric: 0,
                };
                if attribute_type == 0x000f {
                    self.configuration.routes.push(route);
                } else {
                    self.configuration.excluded_routes.push(route);
                }
            }
            0x4005 => {
                self.configuration.mtu = be_u32(content, "MTU attribute")?;
            }
            0x4006 => {
                let content = content.strip_suffix(&[0]).unwrap_or(content);
                if !content.is_empty() {
                    self.configuration
                        .search_domains
                        .push(String::from_utf8_lossy(content).into());
                }
            }
            0x4010 => {
                self.esp_encryption = match be_u16(content, "ESP encryption")? {
                    2 => Some(OpenConnectEspEncryption::Aes128Cbc),
                    5 => Some(OpenConnectEspEncryption::Aes256Cbc),
                    _ => None,
                };
            }
            0x4011 => {
                self.esp_authentication =
                    match be_u16(content, "ESP authentication")? {
                        1 => Some(OpenConnectEspAuthentication::HmacMd5_96),
                        2 => Some(OpenConnectEspAuthentication::HmacSha1_96),
                        3 => Some(OpenConnectEspAuthentication::HmacSha256_128),
                        _ => None,
                    };
            }
            0x4012 | 0x4013 => {
                let _ = be_u32(content, "ESP lifetime")?;
            }
            0x4014 => self.esp_replay = be_u32(content, "ESP replay")? != 0,
            0x4016 => self.esp_port = be_u16(content, "ESP port")?,
            0x4017 => {
                self.esp_fallback = Duration::from_secs(u64::from(be_u32(
                    content,
                    "ESP fallback",
                )?));
            }
            0x401a | 0x4024 => {
                if content.len() != 1 {
                    return Err(PulseConfigurationError::Invalid(
                        "ESP flag attribute",
                    ));
                }
                if attribute_type == 0x4024 {
                    self.esp_cross_family = content[0] != 0;
                }
            }
            0x0008 | 0x000a | 0x000f | 0x0010 | 0x4009 | 0x4023 | 0x400b
            | 0x401e => {}
            _ => {}
        }
        Ok(())
    }

    fn parse_ipv4_route(
        &mut self,
        content: &[u8],
    ) -> Result<(), PulseConfigurationError> {
        if content.len() != 16
            || u32::from_be_bytes(content[4..8].try_into().unwrap())
                != 0x0000ffff
        {
            return Err(PulseConfigurationError::Invalid("IPv4 route entry"));
        }
        let start = u32::from_be_bytes(content[8..12].try_into().unwrap());
        let end = u32::from_be_bytes(content[12..16].try_into().unwrap());
        let host_mask = start ^ end;
        let mask = !host_mask;
        let prefix = mask.count_ones() as u8;
        let expected = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        if mask != expected || start & mask != start || start | host_mask != end
        {
            return Err(PulseConfigurationError::NonCidrRoute);
        }
        let route = TunnelRoute {
            prefix: IpNet::V4(
                Ipv4Net::new(Ipv4Addr::from(start), prefix)
                    .map_err(|_| PulseConfigurationError::NonCidrRoute)?,
            ),
            gateway: None,
            metric: 0,
        };
        match u32::from_be_bytes(content[..4].try_into().unwrap()) {
            0x07000010 => self.configuration.routes.push(route),
            0xf1000010 => self.configuration.excluded_routes.push(route),
            kind => {
                return Err(PulseConfigurationError::UnknownRouteType(kind));
            }
        }
        Ok(())
    }

    fn parse_esp_configuration(
        &self,
        payload: &[u8],
    ) -> Result<(PulseEspConfiguration, Vec<u8>), PulseConfigurationError> {
        if !pulse_esp_configuration_frame_valid(payload) {
            return Err(PulseConfigurationError::InvalidEspFrame);
        }
        let encryption = self
            .esp_encryption
            .ok_or(PulseConfigurationError::IncompleteEspConfiguration)?;
        let authentication = self
            .esp_authentication
            .ok_or(PulseConfigurationError::IncompleteEspConfiguration)?;
        if self.esp_port == 0 {
            return Err(PulseConfigurationError::IncompleteEspConfiguration);
        }
        let encryption_length = encryption.key_length();
        let authentication_length = authentication.key_length();
        if encryption_length + authentication_length > 64 {
            return Err(PulseConfigurationError::EspKeysTooLarge);
        }
        let server_spi =
            u32::from_le_bytes(payload[36..40].try_into().unwrap());
        let server_encryption = payload[42..42 + encryption_length].to_vec();
        let server_authentication = payload[42 + encryption_length
            ..42 + encryption_length + authentication_length]
            .to_vec();
        let mut client_encryption = vec![0_u8; encryption_length];
        let mut client_authentication = vec![0_u8; authentication_length];
        OsRng.fill_bytes(&mut client_encryption);
        OsRng.fill_bytes(&mut client_authentication);
        let client_spi = loop {
            let value = OsRng.next_u32();
            if value != 0 {
                break value;
            }
        };
        let keys = OpenConnectEspKeySetConfig {
            encryption,
            authentication,
            disable_replay_protection: !self.esp_replay,
            outbound: OpenConnectEspKeyMaterial {
                spi: server_spi,
                encryption_key: server_encryption,
                authentication_key: server_authentication,
            },
            inbound: OpenConnectEspKeyMaterial {
                spi: client_spi,
                encryption_key: client_encryption.clone(),
                authentication_key: client_authentication.clone(),
            },
        };
        drop(OpenConnectEspKeySet::new(&keys)?);
        let mut response = [0_u8; 0x34 + 2 * (64 + 6)];
        response[0x20..0x24].copy_from_slice(&0x21202400_u32.to_be_bytes());
        let response_length = response.len();
        response[0x28..0x2c]
            .copy_from_slice(&((response_length - 0x10) as u32).to_be_bytes());
        response[0x2c..0x30]
            .copy_from_slice(&((response_length - 0x2c) as u32).to_be_bytes());
        response[0x30..0x34].copy_from_slice(&0x01000000_u32.to_be_bytes());
        response[0x34..0x38].copy_from_slice(&client_spi.to_le_bytes());
        response[0x38..0x3a].copy_from_slice(&64_u16.to_be_bytes());
        response[0x3a..0x3a + encryption_length]
            .copy_from_slice(&client_encryption);
        response[0x3a + encryption_length
            ..0x3a + encryption_length + authentication_length]
            .copy_from_slice(&client_authentication);
        response[0x3a + 64..].copy_from_slice(&payload[0x24..0x24 + 70]);
        let fallback = if self.esp_fallback.is_zero() {
            PULSE_DEFAULT_ESP_ATTEMPT_PERIOD
        } else {
            self.esp_fallback
        };
        Ok((
            PulseEspConfiguration {
                remote: SocketAddr::new(self.accepted_address, self.esp_port),
                keys,
                encryption,
                authentication,
                port: self.esp_port,
                fallback,
                cross_family: self.esp_cross_family,
                replay_protection: self.esp_replay,
                probe_next_header: if self.accepted_address.is_ipv6() {
                    OPENCONNECT_ESP_IPV6_NEXT_HEADER
                } else {
                    OPENCONNECT_ESP_IPV4_NEXT_HEADER
                },
            },
            response[16..].to_vec(),
        ))
    }
}
