//! Transport-independent PPP LCP/IPCP/IP6CP negotiation state machine.
//!
//! The carrier owns asynchronous I/O. This type owns the wire-visible PPP
//! state so Fortinet and F5 sessions can share identical negotiation rules.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;

use super::{
    PPP_CODE_CODE_REJECTION, PPP_CODE_CONFIGURE_ACKNOWLEDGEMENT,
    PPP_CODE_CONFIGURE_NEGATIVE_ACKNOWLEDGEMENT, PPP_CODE_CONFIGURE_REJECTION,
    PPP_CODE_CONFIGURE_REQUEST, PPP_CODE_DISCARD_REQUEST, PPP_CODE_ECHO_REPLY,
    PPP_CODE_ECHO_REQUEST, PPP_CODE_PROTOCOL_REJECTION,
    PPP_CODE_TERMINATE_ACKNOWLEDGEMENT, PPP_CODE_TERMINATE_REQUEST,
    PPP_DEFAULT_MRU, PPP_HDLC_CONTROL_ESCAPE_MASK,
    PPP_IP6CP_OPTION_INTERFACE_ID, PPP_IPCP_OPTION_ADDRESS,
    PPP_IPCP_OPTION_ADDRESSES, PPP_IPCP_OPTION_COMPRESSION,
    PPP_IPCP_OPTION_PRIMARY_DNS, PPP_IPCP_OPTION_PRIMARY_NBNS,
    PPP_IPCP_OPTION_SECONDARY_DNS, PPP_IPCP_OPTION_SECONDARY_NBNS,
    PPP_LCP_OPTION_ADDRESS_COMPRESSION, PPP_LCP_OPTION_ASYNC_MAP,
    PPP_LCP_OPTION_AUTHENTICATION, PPP_LCP_OPTION_MAGIC, PPP_LCP_OPTION_MRU,
    PPP_LCP_OPTION_PROTOCOL_COMPRESSION, PPP_MAXIMUM_PAYLOAD_LENGTH,
    PPP_MINIMUM_MRU, PPP_PROTOCOL_IP6CP, PPP_PROTOCOL_IPCP, PPP_PROTOCOL_IPV4,
    PPP_PROTOCOL_IPV6, PPP_PROTOCOL_LCP, PppControlError, PppEncapsulation,
    TunnelConfiguration, append_ppp_option, append_ppp_option_u16,
    append_ppp_option_u32, build_ppp_control_packet, build_ppp_packet_header,
    encode_ppp_frame, parse_ppp_control_packet, parse_ppp_options,
    parse_ppp_packet, ppp_interface_id, ppp_ipv4_from_bytes,
    ppp_ipv6_from_interface_id, random_ppp_magic,
};

pub const PPP_DEFAULT_TUNNEL_MTU: u32 = 1400;
pub const PPP_DEFAULT_BASE_MTU: u32 = 1406;
pub const PPP_DEFAULT_NEGOTIATION_PERIOD: Duration = Duration::from_secs(3);
pub const PPP_DEFAULT_NEGOTIATION_ATTEMPTS: usize = 10;
pub const PPP_DEFAULT_ECHO_FAILURES: usize = 3;
pub const PPP_MINIMUM_IPV6_MTU: u32 = 1280;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppNegotiatorOptions {
    pub encapsulation: PppEncapsulation,
    pub want_ipv4: bool,
    pub want_ipv6: bool,
    pub ipv4_address: Option<Ipv4Net>,
    pub ipv6_address: Option<Ipv6Net>,
    pub lock_addresses: bool,
    pub mtu: u32,
    pub request_ipv4_name_servers: bool,
    pub negotiation_period: Duration,
    pub negotiation_attempts: usize,
    pub echo_interval: Duration,
    pub echo_failures: usize,
}

impl Default for PppNegotiatorOptions {
    fn default() -> Self {
        Self {
            encapsulation: PppEncapsulation::Fortinet,
            want_ipv4: true,
            want_ipv6: true,
            ipv4_address: None,
            ipv6_address: None,
            lock_addresses: false,
            mtu: PPP_DEFAULT_TUNNEL_MTU,
            request_ipv4_name_servers: false,
            negotiation_period: PPP_DEFAULT_NEGOTIATION_PERIOD,
            negotiation_attempts: PPP_DEFAULT_NEGOTIATION_ATTEMPTS,
            echo_interval: Duration::ZERO,
            echo_failures: PPP_DEFAULT_ECHO_FAILURES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppNegotiationPhase {
    Establishing,
    Network,
    Terminating,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppOutboundPacket {
    pub protocol: u16,
    pub payload: Vec<u8>,
    pub protocol_compression: bool,
    pub address_compression: bool,
    pub async_map: u32,
}

impl PppOutboundPacket {
    pub fn encode(
        &self,
        encapsulation: PppEncapsulation,
    ) -> Result<Vec<u8>, PppNegotiationError> {
        if self.protocol == 0 || self.payload.is_empty() {
            return Err(PppNegotiationError::InvalidOutboundPacket);
        }
        let mut packet = build_ppp_packet_header(
            self.protocol,
            self.protocol_compression,
            self.address_compression,
        );
        packet.extend_from_slice(&self.payload);
        Ok(encode_ppp_frame(encapsulation, &packet, self.async_map)?)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PppNegotiationEvent {
    pub outbound: Vec<PppOutboundPacket>,
    pub delivered: Option<Vec<u8>>,
    pub network_ready: bool,
    pub peer_terminated: bool,
    pub termination_acknowledged: bool,
}

#[derive(Debug, Error)]
pub enum PppNegotiationError {
    #[error("generate PPP magic: {0}")]
    Random(#[from] std::io::Error),
    #[error(transparent)]
    Control(#[from] PppControlError),
    #[error(transparent)]
    Frame(#[from] super::PppFrameError),
    #[error("PPP link requires IPv4 or IPv6")]
    NoNetworkFamily,
    #[error("PPP tunnel MTU is outside the supported range: {0}")]
    InvalidMtu(u32),
    #[error("unsupported PPP control protocol: {0:#06x}")]
    UnsupportedControlProtocol(u16),
    #[error("PPP peer rejected every requested network control protocol")]
    NoNetworkProtocol,
    #[error("PPP peer rejected the IPv4 address negotiation")]
    Ipv4Rejected,
    #[error("PPP peer changed the proposed IPv4 address: {0} -> {1}")]
    Ipv4AddressChanged(Ipv4Addr, Ipv4Addr),
    #[error("PPP peer changed the proposed IPv6 interface identifier")]
    Ipv6AddressChanged,
    #[error("PPP peer returned an invalid IPv4 name server option: {0}")]
    InvalidNameServer(u8),
    #[error("PPP peer Nak/Rejected an unknown LCP option: {0}")]
    UnknownLcpOption(u8),
    #[error("PPP peer Nak/Rejected an unknown IPCP option: {0}")]
    UnknownIpcpOption(u8),
    #[error("PPP peer Nak/Rejected an unknown IP6CP option: {0}")]
    UnknownIp6cpOption(u8),
    #[error("invalid PPP {0} Nak/Reject")]
    InvalidNak(&'static str),
    #[error("PPP control protocol negotiation attempts exhausted: {0:#06x}")]
    AttemptsExhausted(u16),
    #[error("PPP control protocol negotiation timed out: {0:#06x}")]
    NegotiationTimedOut(u16),
    #[error("PPP IPv4 negotiation completed without a local address")]
    MissingIpv4Address,
    #[error("PPP IPv6 negotiation completed without a local address")]
    MissingIpv6Address,
    #[error("PPP echo request/reply arrived on a non-LCP protocol")]
    EchoOnNonLcp,
    #[error("invalid PPP Protocol-Reject packet")]
    InvalidProtocolReject,
    #[error("PPP peer sent Code-Reject")]
    CodeRejected,
    #[error("unsupported PPP control code: {0}")]
    UnsupportedControlCode(u8),
    #[error("PPP peer did not answer LCP echo requests")]
    PeerDead,
    #[error("PPP data channel is not ready")]
    DataChannelNotReady,
    #[error("PPP data packet exceeds negotiated MTU: {0} > {1}")]
    DataPacketTooLarge(usize, usize),
    #[error("PPP data packet is empty or has an invalid IP version")]
    InvalidDataPacket,
    #[error("PPP data packet uses a disabled network family")]
    DisabledNetworkFamily,
    #[error("invalid empty PPP outbound packet")]
    InvalidOutboundPacket,
}

#[derive(Debug, Clone, Default)]
struct ControlState {
    next_identifier: u8,
    request_identifier: u8,
    request_sent: bool,
    request_acknowledged: bool,
    peer_request_acknowledged: bool,
    request_attempts: usize,
    last_request: Option<Instant>,
}

pub struct PppNegotiator {
    options: PppNegotiatorOptions,
    phase: PppNegotiationPhase,
    lcp: ControlState,
    ipcp: ControlState,
    ip6cp: ControlState,
    local_mru: u16,
    peer_mru: u16,
    local_magic: [u8; 4],
    local_magic_enabled: bool,
    request_async_map: bool,
    request_protocol_compression: bool,
    request_address_compression: bool,
    local_async_map: u32,
    outbound_protocol_compression: bool,
    outbound_address_compression: bool,
    request_mru: bool,
    addresses_locked: bool,
    want_ipv4: bool,
    want_ipv6: bool,
    local_ipv4: Option<Ipv4Addr>,
    peer_ipv4: Option<Ipv4Addr>,
    local_ipv6: Option<Ipv6Addr>,
    peer_ipv6: Option<Ipv6Addr>,
    name_server_requests: BTreeMap<u8, Ipv4Addr>,
    configuration: Option<TunnelConfiguration>,
    last_received: Instant,
    pending_echo: bool,
    pending_echo_identifier: u8,
    pending_echo_sent: Instant,
    missed_echo_replies: usize,
}

impl PppNegotiator {
    pub fn new(
        mut options: PppNegotiatorOptions,
        now: Instant,
    ) -> Result<Self, PppNegotiationError> {
        if !options.want_ipv4 && !options.want_ipv6 {
            return Err(PppNegotiationError::NoNetworkFamily);
        }
        if options.mtu == 0 {
            options.mtu = PPP_DEFAULT_TUNNEL_MTU;
        }
        if options.mtu < u32::from(PPP_MINIMUM_MRU)
            || options.mtu > ppp_maximum_tunnel_mtu(options.encapsulation)
        {
            return Err(PppNegotiationError::InvalidMtu(options.mtu));
        }
        if options.negotiation_period.is_zero() {
            options.negotiation_period = PPP_DEFAULT_NEGOTIATION_PERIOD;
        }
        if options.negotiation_attempts == 0 {
            options.negotiation_attempts = PPP_DEFAULT_NEGOTIATION_ATTEMPTS;
        }
        if options.echo_failures == 0 {
            options.echo_failures = PPP_DEFAULT_ECHO_FAILURES;
        }
        let mut name_server_requests = BTreeMap::new();
        if options.request_ipv4_name_servers {
            for kind in [
                PPP_IPCP_OPTION_PRIMARY_DNS,
                PPP_IPCP_OPTION_PRIMARY_NBNS,
                PPP_IPCP_OPTION_SECONDARY_DNS,
                PPP_IPCP_OPTION_SECONDARY_NBNS,
            ] {
                name_server_requests.insert(kind, Ipv4Addr::UNSPECIFIED);
            }
        }
        let fortinet = options.encapsulation == PppEncapsulation::Fortinet;
        Ok(Self {
            local_mru: options.mtu as u16,
            local_magic: random_ppp_magic()?,
            request_async_map: options.encapsulation
                == PppEncapsulation::F5Hdlc,
            request_protocol_compression: !fortinet,
            request_address_compression: !fortinet,
            addresses_locked: options.lock_addresses,
            want_ipv4: options.want_ipv4,
            want_ipv6: options.want_ipv6,
            local_ipv4: options.ipv4_address.map(|prefix| prefix.addr()),
            local_ipv6: options.ipv6_address.map(|prefix| prefix.addr()),
            options,
            phase: PppNegotiationPhase::Establishing,
            lcp: ControlState::default(),
            ipcp: ControlState::default(),
            ip6cp: ControlState::default(),
            peer_mru: PPP_DEFAULT_MRU,
            local_magic_enabled: true,
            local_async_map: 0,
            outbound_protocol_compression: false,
            outbound_address_compression: false,
            request_mru: true,
            peer_ipv4: None,
            peer_ipv6: None,
            name_server_requests,
            configuration: None,
            last_received: now,
            pending_echo: false,
            pending_echo_identifier: 0,
            pending_echo_sent: now,
            missed_echo_replies: 0,
        })
    }

    pub fn phase(&self) -> PppNegotiationPhase {
        self.phase
    }

    pub fn is_ready(&self) -> bool {
        self.phase == PppNegotiationPhase::Network
    }

    pub fn configuration(&self) -> Option<&TunnelConfiguration> {
        self.configuration.as_ref()
    }

    pub fn start(
        &mut self,
        now: Instant,
    ) -> Result<Vec<PppOutboundPacket>, PppNegotiationError> {
        Ok(vec![
            self.build_configuration_request(PPP_PROTOCOL_LCP, now)?,
        ])
    }

    pub fn handle_frame(
        &mut self,
        frame: &[u8],
        now: Instant,
    ) -> Result<PppNegotiationEvent, PppNegotiationError> {
        let packet = parse_ppp_packet(frame)?;
        self.last_received = now;
        self.pending_echo = false;
        self.missed_echo_replies = 0;
        let mut event = match packet.protocol {
            PPP_PROTOCOL_LCP | PPP_PROTOCOL_IPCP | PPP_PROTOCOL_IP6CP => {
                if (packet.protocol == PPP_PROTOCOL_IPCP && !self.want_ipv4)
                    || (packet.protocol == PPP_PROTOCOL_IP6CP
                        && !self.want_ipv6)
                {
                    PppNegotiationEvent {
                        outbound: self.protocol_rejection(
                            packet.protocol,
                            packet.payload,
                        )?,
                        ..Default::default()
                    }
                } else {
                    self.handle_control_packet(
                        packet.protocol,
                        packet.payload,
                        now,
                    )?
                }
            }
            PPP_PROTOCOL_IPV4 | PPP_PROTOCOL_IPV6 => {
                let allowed = (packet.protocol == PPP_PROTOCOL_IPV4
                    && self.want_ipv4)
                    || (packet.protocol == PPP_PROTOCOL_IPV6 && self.want_ipv6);
                PppNegotiationEvent {
                    delivered: (self.phase == PppNegotiationPhase::Network
                        && allowed)
                        .then(|| packet.payload.to_vec()),
                    ..Default::default()
                }
            }
            protocol => PppNegotiationEvent {
                outbound: self.protocol_rejection(protocol, packet.payload)?,
                ..Default::default()
            },
        };
        if self.configuration.is_some()
            && self.phase == PppNegotiationPhase::Establishing
        {
            self.phase = PppNegotiationPhase::Network;
            self.addresses_locked = true;
            event.network_ready = true;
        }
        Ok(event)
    }

    pub fn handle_timer(
        &mut self,
        now: Instant,
    ) -> Result<Vec<PppOutboundPacket>, PppNegotiationError> {
        if self.phase == PppNegotiationPhase::Terminating {
            return Ok(Vec::new());
        }
        let mut outbound = Vec::new();
        for protocol in
            [PPP_PROTOCOL_LCP, PPP_PROTOCOL_IPCP, PPP_PROTOCOL_IP6CP]
        {
            if (protocol == PPP_PROTOCOL_IPCP && !self.want_ipv4)
                || (protocol == PPP_PROTOCOL_IP6CP && !self.want_ipv6)
            {
                continue;
            }
            let state = self.control_state(protocol)?;
            if !state.request_sent || state.request_acknowledged {
                continue;
            }
            let Some(last_request) = state.last_request else {
                continue;
            };
            if now.saturating_duration_since(last_request)
                < self.options.negotiation_period
            {
                continue;
            }
            if state.request_attempts >= self.options.negotiation_attempts {
                return Err(PppNegotiationError::NegotiationTimedOut(protocol));
            }
            outbound.push(self.build_configuration_request(protocol, now)?);
        }
        if self.phase != PppNegotiationPhase::Network
            || self.options.echo_interval.is_zero()
        {
            return Ok(outbound);
        }
        if self.pending_echo {
            if now.saturating_duration_since(self.pending_echo_sent)
                < self.options.echo_interval
            {
                return Ok(outbound);
            }
            self.missed_echo_replies += 1;
            if self.missed_echo_replies >= self.options.echo_failures {
                return Err(PppNegotiationError::PeerDead);
            }
        } else if now.saturating_duration_since(self.last_received)
            < self.options.echo_interval
        {
            return Ok(outbound);
        }
        self.lcp.next_identifier = self.lcp.next_identifier.wrapping_add(1);
        self.pending_echo_identifier = self.lcp.next_identifier;
        self.pending_echo = true;
        self.pending_echo_sent = now;
        let mut payload = [0_u8; 4];
        if self.local_magic_enabled {
            payload = self.local_magic;
        }
        let control = build_ppp_control_packet(
            PPP_CODE_ECHO_REQUEST,
            self.pending_echo_identifier,
            &payload,
        )?;
        outbound.push(self.outbound_packet(PPP_PROTOCOL_LCP, control));
        Ok(outbound)
    }

    pub fn build_data_packet(
        &self,
        payload: &[u8],
    ) -> Result<PppOutboundPacket, PppNegotiationError> {
        if self.phase != PppNegotiationPhase::Network {
            return Err(PppNegotiationError::DataChannelNotReady);
        }
        if payload.is_empty() {
            return Err(PppNegotiationError::InvalidDataPacket);
        }
        let mtu = usize::from(self.local_mru.min(self.peer_mru));
        if payload.len() > mtu {
            return Err(PppNegotiationError::DataPacketTooLarge(
                payload.len(),
                mtu,
            ));
        }
        let protocol = match payload[0] >> 4 {
            4 if self.want_ipv4 => PPP_PROTOCOL_IPV4,
            6 if self.want_ipv6 => PPP_PROTOCOL_IPV6,
            4 | 6 => return Err(PppNegotiationError::DisabledNetworkFamily),
            _ => return Err(PppNegotiationError::InvalidDataPacket),
        };
        Ok(self.outbound_packet(protocol, payload.to_vec()))
    }

    pub fn terminate_request(
        &mut self,
    ) -> Result<PppOutboundPacket, PppNegotiationError> {
        self.phase = PppNegotiationPhase::Terminating;
        self.lcp.next_identifier = self.lcp.next_identifier.wrapping_add(1);
        let control = build_ppp_control_packet(
            PPP_CODE_TERMINATE_REQUEST,
            self.lcp.next_identifier,
            &[],
        )?;
        Ok(self.outbound_packet(PPP_PROTOCOL_LCP, control))
    }

    fn build_configuration_request(
        &mut self,
        protocol: u16,
        now: Instant,
    ) -> Result<PppOutboundPacket, PppNegotiationError> {
        let mut payload = Vec::new();
        match protocol {
            PPP_PROTOCOL_LCP => {
                if self.request_mru {
                    append_ppp_option_u16(
                        &mut payload,
                        PPP_LCP_OPTION_MRU,
                        self.local_mru,
                    )?;
                }
                if self.request_async_map {
                    append_ppp_option_u32(
                        &mut payload,
                        PPP_LCP_OPTION_ASYNC_MAP,
                        self.local_async_map,
                    )?;
                }
                if self.local_magic_enabled {
                    self.local_magic = random_ppp_magic()?;
                    append_ppp_option(
                        &mut payload,
                        PPP_LCP_OPTION_MAGIC,
                        &self.local_magic,
                    )?;
                }
                if self.request_protocol_compression {
                    append_ppp_option(
                        &mut payload,
                        PPP_LCP_OPTION_PROTOCOL_COMPRESSION,
                        &[],
                    )?;
                }
                if self.request_address_compression {
                    append_ppp_option(
                        &mut payload,
                        PPP_LCP_OPTION_ADDRESS_COMPRESSION,
                        &[],
                    )?;
                }
            }
            PPP_PROTOCOL_IPCP => {
                append_ppp_option(
                    &mut payload,
                    PPP_IPCP_OPTION_ADDRESS,
                    &self.local_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED).octets(),
                )?;
                for (kind, address) in &self.name_server_requests {
                    append_ppp_option(&mut payload, *kind, &address.octets())?;
                }
            }
            PPP_PROTOCOL_IP6CP => append_ppp_option(
                &mut payload,
                PPP_IP6CP_OPTION_INTERFACE_ID,
                &self
                    .local_ipv6
                    .map(|address| ppp_interface_id(address.into()))
                    .unwrap_or([0; 8]),
            )?,
            _ => {
                return Err(PppNegotiationError::UnsupportedControlProtocol(
                    protocol,
                ));
            }
        }
        let state = self.control_state_mut(protocol)?;
        state.next_identifier = state.next_identifier.wrapping_add(1);
        state.request_identifier = state.next_identifier;
        state.request_sent = true;
        state.request_acknowledged = false;
        state.request_attempts += 1;
        state.last_request = Some(now);
        let identifier = state.request_identifier;
        let control = build_ppp_control_packet(
            PPP_CODE_CONFIGURE_REQUEST,
            identifier,
            &payload,
        )?;
        Ok(self.outbound_packet(protocol, control))
    }

    fn handle_control_packet(
        &mut self,
        protocol: u16,
        packet: &[u8],
        now: Instant,
    ) -> Result<PppNegotiationEvent, PppNegotiationError> {
        let packet = parse_ppp_control_packet(packet)?;
        let mut event = PppNegotiationEvent::default();
        match packet.code {
            PPP_CODE_CONFIGURE_REQUEST => {
                event.outbound = self.handle_configuration_request(
                    protocol,
                    packet.identifier,
                    &packet.payload,
                    now,
                )?;
            }
            PPP_CODE_CONFIGURE_ACKNOWLEDGEMENT => {
                self.control_state_mut(protocol)?.request_acknowledged = true;
                if protocol == PPP_PROTOCOL_LCP {
                    self.outbound_protocol_compression =
                        self.request_protocol_compression;
                    self.outbound_address_compression =
                        self.request_address_compression;
                }
                event.outbound = self.advance_negotiation(now)?;
            }
            PPP_CODE_CONFIGURE_NEGATIVE_ACKNOWLEDGEMENT
            | PPP_CODE_CONFIGURE_REJECTION => {
                event.outbound = self.handle_configuration_nak_or_reject(
                    protocol,
                    packet.identifier,
                    packet.code,
                    &packet.payload,
                    now,
                )?;
            }
            PPP_CODE_TERMINATE_REQUEST => {
                let control = build_ppp_control_packet(
                    PPP_CODE_TERMINATE_ACKNOWLEDGEMENT,
                    packet.identifier,
                    &[],
                )?;
                event.outbound.push(self.outbound_packet(protocol, control));
                self.phase = PppNegotiationPhase::Terminating;
                event.peer_terminated = true;
            }
            PPP_CODE_TERMINATE_ACKNOWLEDGEMENT => {
                event.termination_acknowledged =
                    self.phase == PppNegotiationPhase::Terminating;
            }
            PPP_CODE_ECHO_REQUEST => {
                if protocol != PPP_PROTOCOL_LCP {
                    return Err(PppNegotiationError::EchoOnNonLcp);
                }
                if !self.lcp.request_acknowledged
                    || !self.lcp.peer_request_acknowledged
                {
                    return Ok(event);
                }
                let mut reply = vec![0; packet.payload.len().max(4)];
                if packet.payload.len() > 4 {
                    reply[4..].copy_from_slice(&packet.payload[4..]);
                }
                if self.local_magic_enabled {
                    reply[..4].copy_from_slice(&self.local_magic);
                }
                let control = build_ppp_control_packet(
                    PPP_CODE_ECHO_REPLY,
                    packet.identifier,
                    &reply,
                )?;
                event.outbound.push(self.outbound_packet(protocol, control));
            }
            PPP_CODE_ECHO_REPLY => {
                if protocol != PPP_PROTOCOL_LCP {
                    return Err(PppNegotiationError::EchoOnNonLcp);
                }
                if self.pending_echo
                    && packet.identifier == self.pending_echo_identifier
                {
                    self.pending_echo = false;
                    self.missed_echo_replies = 0;
                }
            }
            PPP_CODE_DISCARD_REQUEST => {}
            PPP_CODE_PROTOCOL_REJECTION => {
                if protocol != PPP_PROTOCOL_LCP || packet.payload.len() < 2 {
                    return Err(PppNegotiationError::InvalidProtocolReject);
                }
                let rejected =
                    u16::from_be_bytes([packet.payload[0], packet.payload[1]]);
                match rejected {
                    PPP_PROTOCOL_IPCP => self.want_ipv4 = false,
                    PPP_PROTOCOL_IP6CP => self.want_ipv6 = false,
                    _ => return Ok(event),
                }
                event.outbound = self.advance_negotiation(now)?;
            }
            PPP_CODE_CODE_REJECTION => {
                return Err(PppNegotiationError::CodeRejected);
            }
            code => {
                return Err(PppNegotiationError::UnsupportedControlCode(code));
            }
        }
        Ok(event)
    }

    fn handle_configuration_request(
        &mut self,
        protocol: u16,
        identifier: u8,
        payload: &[u8],
        now: Instant,
    ) -> Result<Vec<PppOutboundPacket>, PppNegotiationError> {
        let options = parse_ppp_options(payload)?;
        let mut rejected = Vec::new();
        let mut nak = Vec::new();
        let mut peer_mru = PPP_DEFAULT_MRU;
        let mut peer_magic = [0_u8; 4];
        let mut peer_ipv4 = None;
        let mut peer_ipv6 = None;
        for option in options {
            match protocol {
                PPP_PROTOCOL_LCP => match option.kind {
                    PPP_LCP_OPTION_MRU if option.value.len() == 2 => {
                        let mru = u16::from_be_bytes([
                            option.value[0],
                            option.value[1],
                        ]);
                        if mru < PPP_MINIMUM_MRU {
                            append_ppp_option_u16(
                                &mut nak,
                                option.kind,
                                PPP_MINIMUM_MRU,
                            )?;
                        } else {
                            peer_mru = mru;
                        }
                    }
                    PPP_LCP_OPTION_ASYNC_MAP if option.value.len() == 4 => {}
                    PPP_LCP_OPTION_MAGIC if option.value.len() == 4 => {
                        peer_magic.copy_from_slice(&option.value);
                        if self.local_magic_enabled
                            && peer_magic == self.local_magic
                        {
                            append_ppp_option(
                                &mut nak,
                                option.kind,
                                &random_ppp_magic()?,
                            )?;
                        }
                    }
                    PPP_LCP_OPTION_PROTOCOL_COMPRESSION
                    | PPP_LCP_OPTION_ADDRESS_COMPRESSION
                        if option.value.is_empty() => {}
                    PPP_LCP_OPTION_AUTHENTICATION => {
                        rejected.extend_from_slice(&option.raw)
                    }
                    _ => rejected.extend_from_slice(&option.raw),
                },
                PPP_PROTOCOL_IPCP => match option.kind {
                    PPP_IPCP_OPTION_ADDRESSES if option.value.len() == 8 => {}
                    PPP_IPCP_OPTION_ADDRESS => {
                        match ppp_ipv4_from_bytes(&option.value) {
                            Ok(address) => peer_ipv4 = Some(address),
                            Err(_) => rejected.extend_from_slice(&option.raw),
                        }
                    }
                    PPP_IPCP_OPTION_COMPRESSION => {
                        rejected.extend_from_slice(&option.raw)
                    }
                    _ => rejected.extend_from_slice(&option.raw),
                },
                PPP_PROTOCOL_IP6CP => {
                    if option.kind != PPP_IP6CP_OPTION_INTERFACE_ID {
                        rejected.extend_from_slice(&option.raw);
                    } else {
                        match ppp_ipv6_from_interface_id(&option.value) {
                            Ok(address) => peer_ipv6 = Some(address),
                            Err(_) => rejected.extend_from_slice(&option.raw),
                        }
                    }
                }
                _ => {
                    return Err(
                        PppNegotiationError::UnsupportedControlProtocol(
                            protocol,
                        ),
                    );
                }
            }
        }
        let mut outbound = Vec::new();
        if !rejected.is_empty() {
            let control = build_ppp_control_packet(
                PPP_CODE_CONFIGURE_REJECTION,
                identifier,
                &rejected,
            )?;
            outbound.push(self.outbound_packet(protocol, control));
        }
        if !nak.is_empty() {
            let control = build_ppp_control_packet(
                PPP_CODE_CONFIGURE_NEGATIVE_ACKNOWLEDGEMENT,
                identifier,
                &nak,
            )?;
            outbound.push(self.outbound_packet(protocol, control));
        }
        if rejected.is_empty() && nak.is_empty() {
            let control = build_ppp_control_packet(
                PPP_CODE_CONFIGURE_ACKNOWLEDGEMENT,
                identifier,
                payload,
            )?;
            outbound.push(self.outbound_packet(protocol, control));
            self.control_state_mut(protocol)?.peer_request_acknowledged = true;
            match protocol {
                PPP_PROTOCOL_LCP => self.peer_mru = peer_mru,
                PPP_PROTOCOL_IPCP => self.peer_ipv4 = peer_ipv4,
                PPP_PROTOCOL_IP6CP => self.peer_ipv6 = peer_ipv6,
                _ => unreachable!(),
            }
            outbound.extend(self.advance_negotiation(now)?);
        }
        Ok(outbound)
    }

    fn handle_configuration_nak_or_reject(
        &mut self,
        protocol: u16,
        identifier: u8,
        code: u8,
        payload: &[u8],
        now: Instant,
    ) -> Result<Vec<PppOutboundPacket>, PppNegotiationError> {
        if identifier != self.control_state(protocol)?.request_identifier {
            return Ok(Vec::new());
        }
        let options = parse_ppp_options(payload)?;
        let mut protocol_disabled = false;
        for option in options {
            match protocol {
                PPP_PROTOCOL_LCP => match option.kind {
                    PPP_LCP_OPTION_MRU if option.value.len() == 2 => {
                        self.request_mru = false
                    }
                    PPP_LCP_OPTION_ASYNC_MAP if option.value.len() == 4 => {
                        self.local_async_map = PPP_HDLC_CONTROL_ESCAPE_MASK;
                        self.request_async_map = false;
                    }
                    PPP_LCP_OPTION_MAGIC if option.value.len() == 4 => {
                        if code == PPP_CODE_CONFIGURE_REJECTION {
                            self.local_magic_enabled = false;
                        }
                    }
                    PPP_LCP_OPTION_PROTOCOL_COMPRESSION
                        if option.value.is_empty() =>
                    {
                        self.request_protocol_compression = false;
                        self.outbound_protocol_compression = false;
                    }
                    PPP_LCP_OPTION_ADDRESS_COMPRESSION
                        if option.value.is_empty() =>
                    {
                        self.request_address_compression = false;
                        self.outbound_address_compression = false;
                    }
                    PPP_LCP_OPTION_MRU => {
                        return Err(PppNegotiationError::InvalidNak("LCP MRU"));
                    }
                    PPP_LCP_OPTION_ASYNC_MAP => {
                        return Err(PppNegotiationError::InvalidNak(
                            "LCP async-map",
                        ));
                    }
                    PPP_LCP_OPTION_MAGIC => {
                        return Err(PppNegotiationError::InvalidNak(
                            "LCP magic",
                        ));
                    }
                    PPP_LCP_OPTION_PROTOCOL_COMPRESSION => {
                        return Err(PppNegotiationError::InvalidNak(
                            "LCP protocol-compression",
                        ));
                    }
                    PPP_LCP_OPTION_ADDRESS_COMPRESSION => {
                        return Err(PppNegotiationError::InvalidNak(
                            "LCP address-compression",
                        ));
                    }
                    kind => {
                        return Err(PppNegotiationError::UnknownLcpOption(
                            kind,
                        ));
                    }
                },
                PPP_PROTOCOL_IPCP => match option.kind {
                    PPP_IPCP_OPTION_ADDRESS => {
                        let address = ppp_ipv4_from_bytes(&option.value)?;
                        if code == PPP_CODE_CONFIGURE_REJECTION
                            || address.is_unspecified()
                        {
                            return Err(PppNegotiationError::Ipv4Rejected);
                        }
                        if self.addresses_locked
                            && self.local_ipv4.is_some_and(|old| old != address)
                        {
                            return Err(
                                PppNegotiationError::Ipv4AddressChanged(
                                    self.local_ipv4.expect("checked"),
                                    address,
                                ),
                            );
                        }
                        self.local_ipv4 = Some(address);
                    }
                    PPP_IPCP_OPTION_PRIMARY_DNS
                    | PPP_IPCP_OPTION_PRIMARY_NBNS
                    | PPP_IPCP_OPTION_SECONDARY_DNS
                    | PPP_IPCP_OPTION_SECONDARY_NBNS => {
                        if code == PPP_CODE_CONFIGURE_REJECTION {
                            self.name_server_requests.remove(&option.kind);
                        } else {
                            let address = ppp_ipv4_from_bytes(&option.value)?;
                            if address.is_unspecified() {
                                return Err(
                                    PppNegotiationError::InvalidNameServer(
                                        option.kind,
                                    ),
                                );
                            }
                            self.name_server_requests
                                .insert(option.kind, address);
                        }
                    }
                    kind => {
                        return Err(PppNegotiationError::UnknownIpcpOption(
                            kind,
                        ));
                    }
                },
                PPP_PROTOCOL_IP6CP => {
                    if option.kind != PPP_IP6CP_OPTION_INTERFACE_ID {
                        return Err(PppNegotiationError::UnknownIp6cpOption(
                            option.kind,
                        ));
                    }
                    if code == PPP_CODE_CONFIGURE_REJECTION {
                        self.want_ipv6 = false;
                        protocol_disabled = true;
                        continue;
                    }
                    let address = ppp_ipv6_from_interface_id(&option.value)?;
                    let offered = ppp_interface_id(address.into());
                    if offered == [0; 8] {
                        self.want_ipv6 = false;
                        protocol_disabled = true;
                        continue;
                    }
                    if self.addresses_locked
                        && self.local_ipv6.is_some_and(|current| {
                            ppp_interface_id(current.into()) != offered
                        })
                    {
                        return Err(PppNegotiationError::Ipv6AddressChanged);
                    }
                    let mut local = self.local_ipv6.unwrap_or(address).octets();
                    local[8..].copy_from_slice(&offered);
                    self.local_ipv6 = Some(Ipv6Addr::from(local));
                }
                _ => {
                    return Err(
                        PppNegotiationError::UnsupportedControlProtocol(
                            protocol,
                        ),
                    );
                }
            }
        }
        if protocol_disabled {
            return self.advance_negotiation(now);
        }
        if self.control_state(protocol)?.request_attempts
            >= self.options.negotiation_attempts
        {
            return Err(PppNegotiationError::AttemptsExhausted(protocol));
        }
        Ok(vec![self.build_configuration_request(protocol, now)?])
    }

    fn advance_negotiation(
        &mut self,
        now: Instant,
    ) -> Result<Vec<PppOutboundPacket>, PppNegotiationError> {
        if !self.lcp.request_acknowledged || !self.lcp.peer_request_acknowledged
        {
            return Ok(Vec::new());
        }
        if !self.want_ipv4 && !self.want_ipv6 {
            return Err(PppNegotiationError::NoNetworkProtocol);
        }
        let mut outbound = Vec::new();
        if self.want_ipv4 && !self.ipcp.request_sent {
            outbound.push(
                self.build_configuration_request(PPP_PROTOCOL_IPCP, now)?,
            );
        }
        if self.want_ipv6 && !self.ip6cp.request_sent {
            outbound.push(
                self.build_configuration_request(PPP_PROTOCOL_IP6CP, now)?,
            );
        }
        if self.want_ipv4
            && (!self.ipcp.request_acknowledged
                || !self.ipcp.peer_request_acknowledged)
        {
            return Ok(outbound);
        }
        if self.want_ipv6
            && (!self.ip6cp.request_acknowledged
                || !self.ip6cp.peer_request_acknowledged)
        {
            return Ok(outbound);
        }
        if self.want_ipv4
            && self
                .local_ipv4
                .is_none_or(|address| address.is_unspecified())
        {
            return Err(PppNegotiationError::MissingIpv4Address);
        }
        if self.want_ipv6
            && self.local_ipv6.is_none_or(|address| {
                ppp_interface_id(address.into()) == [0; 8]
            })
        {
            return Err(PppNegotiationError::MissingIpv6Address);
        }
        self.configuration = Some(self.build_configuration());
        Ok(outbound)
    }

    fn protocol_rejection(
        &mut self,
        protocol: u16,
        payload: &[u8],
    ) -> Result<Vec<PppOutboundPacket>, PppNegotiationError> {
        let maximum = (payload.len() + 2)
            .min(usize::from(self.peer_mru.saturating_sub(10)).max(2));
        let mut rejected = vec![0; maximum];
        rejected[..2].copy_from_slice(&protocol.to_be_bytes());
        rejected[2..].copy_from_slice(&payload[..maximum - 2]);
        self.lcp.next_identifier = self.lcp.next_identifier.wrapping_add(1);
        let control = build_ppp_control_packet(
            PPP_CODE_PROTOCOL_REJECTION,
            self.lcp.next_identifier,
            &rejected,
        )?;
        Ok(vec![self.outbound_packet(PPP_PROTOCOL_LCP, control)])
    }

    fn outbound_packet(
        &self,
        protocol: u16,
        payload: Vec<u8>,
    ) -> PppOutboundPacket {
        PppOutboundPacket {
            protocol,
            payload,
            protocol_compression: self.outbound_protocol_compression,
            address_compression: self.outbound_address_compression,
            async_map: if protocol == PPP_PROTOCOL_LCP {
                PPP_HDLC_CONTROL_ESCAPE_MASK
            } else {
                self.local_async_map
            },
        }
    }

    fn control_state(
        &self,
        protocol: u16,
    ) -> Result<&ControlState, PppNegotiationError> {
        match protocol {
            PPP_PROTOCOL_LCP => Ok(&self.lcp),
            PPP_PROTOCOL_IPCP => Ok(&self.ipcp),
            PPP_PROTOCOL_IP6CP => Ok(&self.ip6cp),
            _ => Err(PppNegotiationError::UnsupportedControlProtocol(protocol)),
        }
    }

    fn control_state_mut(
        &mut self,
        protocol: u16,
    ) -> Result<&mut ControlState, PppNegotiationError> {
        match protocol {
            PPP_PROTOCOL_LCP => Ok(&mut self.lcp),
            PPP_PROTOCOL_IPCP => Ok(&mut self.ipcp),
            PPP_PROTOCOL_IP6CP => Ok(&mut self.ip6cp),
            _ => Err(PppNegotiationError::UnsupportedControlProtocol(protocol)),
        }
    }

    fn build_configuration(&self) -> TunnelConfiguration {
        let mut configuration = TunnelConfiguration {
            mtu: u32::from(self.local_mru.min(self.peer_mru)),
            remote_address: None,
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
            idle_timeout: Duration::ZERO,
            authentication_expiration: None,
        };
        if self.want_ipv4 {
            let bits = self
                .options
                .ipv4_address
                .map_or(32, |prefix| prefix.prefix_len());
            configuration.addresses.push(IpNet::V4(
                Ipv4Net::new(self.local_ipv4.expect("validated"), bits)
                    .expect("existing prefix length"),
            ));
        }
        if self.want_ipv6 {
            let bits = self
                .options
                .ipv6_address
                .map_or(64, |prefix| prefix.prefix_len());
            configuration.addresses.push(IpNet::V6(
                Ipv6Net::new(self.local_ipv6.expect("validated"), bits)
                    .expect("existing prefix length"),
            ));
        }
        for kind in [PPP_IPCP_OPTION_PRIMARY_DNS, PPP_IPCP_OPTION_SECONDARY_DNS]
        {
            if let Some(address) = self.name_server_requests.get(&kind)
                && !address.is_unspecified()
            {
                configuration.dns.push(IpAddr::V4(*address));
            }
        }
        for kind in
            [PPP_IPCP_OPTION_PRIMARY_NBNS, PPP_IPCP_OPTION_SECONDARY_NBNS]
        {
            if let Some(address) = self.name_server_requests.get(&kind)
                && !address.is_unspecified()
            {
                configuration.nbns.push(IpAddr::V4(*address));
            }
        }
        configuration
    }
}

pub fn ppp_maximum_tunnel_mtu(encapsulation: PppEncapsulation) -> u32 {
    let mut maximum = PPP_MAXIMUM_PAYLOAD_LENGTH as u32 - 4;
    if encapsulation == PppEncapsulation::Fortinet {
        maximum -= 6;
    }
    maximum
}

pub fn calculate_ppp_tunnel_mtu(
    requested_mtu: u32,
    mut base_mtu: u32,
    outer_ipv6: bool,
    encapsulation: PppEncapsulation,
) -> u32 {
    if base_mtu == 0 {
        base_mtu = PPP_DEFAULT_BASE_MTU;
    }
    base_mtu = base_mtu.max(PPP_MINIMUM_IPV6_MTU);
    let mut mtu = if requested_mtu == 0 {
        base_mtu as i64 - if outer_ipv6 { 40 } else { 20 } - 20
    } else {
        i64::from(requested_mtu)
    };
    mtu -= match encapsulation {
        PppEncapsulation::F5 | PppEncapsulation::F5Hdlc => 10,
        PppEncapsulation::Fortinet => 15,
    };
    if encapsulation == PppEncapsulation::F5Hdlc {
        mtu -= mtu >> 5;
    }
    mtu as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_frame(
        protocol: u16,
        code: u8,
        id: u8,
        options: &[u8],
    ) -> Vec<u8> {
        let mut frame = build_ppp_packet_header(protocol, false, false);
        frame.extend(build_ppp_control_packet(code, id, options).unwrap());
        frame
    }

    fn packet_control(
        packet: &PppOutboundPacket,
    ) -> super::super::PppControlPacket {
        parse_ppp_control_packet(&packet.payload).unwrap()
    }

    #[test]
    fn mtu_calculation_matches_openconnect_carrier_overheads() {
        assert_eq!(
            calculate_ppp_tunnel_mtu(
                0,
                1406,
                false,
                PppEncapsulation::Fortinet
            ),
            1351
        );
        assert_eq!(
            calculate_ppp_tunnel_mtu(1500, 0, true, PppEncapsulation::F5),
            1490
        );
        assert_eq!(
            calculate_ppp_tunnel_mtu(1500, 0, true, PppEncapsulation::F5Hdlc),
            1444
        );
        assert_eq!(ppp_maximum_tunnel_mtu(PppEncapsulation::Fortinet), 65_525);
    }

    #[test]
    fn fortinet_lcp_request_disables_header_compression() {
        let now = Instant::now();
        let mut negotiator = PppNegotiator::new(
            PppNegotiatorOptions {
                want_ipv6: false,
                ..Default::default()
            },
            now,
        )
        .unwrap();
        let request = negotiator.start(now).unwrap().remove(0);
        let control = packet_control(&request);
        let kinds = parse_ppp_options(&control.payload)
            .unwrap()
            .into_iter()
            .map(|option| option.kind)
            .collect::<Vec<_>>();
        assert_eq!(kinds, [PPP_LCP_OPTION_MRU, PPP_LCP_OPTION_MAGIC]);
        assert!(!request.protocol_compression);
        assert!(!request.address_compression);
    }

    #[test]
    fn ipv4_negotiation_accepts_server_address_and_dns() {
        let now = Instant::now();
        let mut negotiator = PppNegotiator::new(
            PppNegotiatorOptions {
                want_ipv6: false,
                request_ipv4_name_servers: true,
                ..Default::default()
            },
            now,
        )
        .unwrap();
        let lcp_request = negotiator.start(now).unwrap().remove(0);
        let lcp_id = packet_control(&lcp_request).identifier;
        let mut peer_lcp = Vec::new();
        append_ppp_option_u16(&mut peer_lcp, PPP_LCP_OPTION_MRU, 1300).unwrap();
        append_ppp_option(&mut peer_lcp, PPP_LCP_OPTION_MAGIC, &[1, 2, 3, 4])
            .unwrap();
        negotiator
            .handle_frame(
                &control_frame(
                    PPP_PROTOCOL_LCP,
                    PPP_CODE_CONFIGURE_REQUEST,
                    9,
                    &peer_lcp,
                ),
                now,
            )
            .unwrap();
        let event = negotiator
            .handle_frame(
                &control_frame(
                    PPP_PROTOCOL_LCP,
                    PPP_CODE_CONFIGURE_ACKNOWLEDGEMENT,
                    lcp_id,
                    &[],
                ),
                now,
            )
            .unwrap();
        let ipcp_request = event
            .outbound
            .iter()
            .find(|packet| packet.protocol == PPP_PROTOCOL_IPCP)
            .unwrap();
        let ipcp_id = packet_control(ipcp_request).identifier;
        let mut offered = Vec::new();
        append_ppp_option(
            &mut offered,
            PPP_IPCP_OPTION_ADDRESS,
            &[10, 0, 0, 2],
        )
        .unwrap();
        append_ppp_option(
            &mut offered,
            PPP_IPCP_OPTION_PRIMARY_DNS,
            &[1, 1, 1, 1],
        )
        .unwrap();
        let event = negotiator
            .handle_frame(
                &control_frame(
                    PPP_PROTOCOL_IPCP,
                    PPP_CODE_CONFIGURE_NEGATIVE_ACKNOWLEDGEMENT,
                    ipcp_id,
                    &offered,
                ),
                now,
            )
            .unwrap();
        let ipcp_request = &event.outbound[0];
        let ipcp_id = packet_control(ipcp_request).identifier;
        negotiator
            .handle_frame(
                &control_frame(
                    PPP_PROTOCOL_IPCP,
                    PPP_CODE_CONFIGURE_REQUEST,
                    4,
                    &offered[..6],
                ),
                now,
            )
            .unwrap();
        let event = negotiator
            .handle_frame(
                &control_frame(
                    PPP_PROTOCOL_IPCP,
                    PPP_CODE_CONFIGURE_ACKNOWLEDGEMENT,
                    ipcp_id,
                    &[],
                ),
                now,
            )
            .unwrap();
        assert!(event.network_ready);
        let configuration = negotiator.configuration().unwrap();
        assert_eq!(configuration.mtu, 1300);
        assert_eq!(configuration.addresses[0].to_string(), "10.0.0.2/32");
        assert_eq!(configuration.dns, [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        assert!(negotiator.build_data_packet(&[0x45, 0, 0, 20]).is_ok());
    }

    #[test]
    fn retries_and_echo_timeout_are_bounded() {
        let now = Instant::now();
        let mut negotiator = PppNegotiator::new(
            PppNegotiatorOptions {
                want_ipv6: false,
                negotiation_period: Duration::from_secs(1),
                negotiation_attempts: 2,
                ..Default::default()
            },
            now,
        )
        .unwrap();
        negotiator.start(now).unwrap();
        assert_eq!(
            negotiator
                .handle_timer(now + Duration::from_secs(1))
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            negotiator.handle_timer(now + Duration::from_secs(2)),
            Err(PppNegotiationError::NegotiationTimedOut(PPP_PROTOCOL_LCP))
        ));
    }
}
