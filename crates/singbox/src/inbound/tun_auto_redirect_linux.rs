//! Native nftables transaction support for Linux TUN auto-redirect.
//!
//! The generated bindings intentionally expose the kernel netlink ABI rather
//! than a policy language.  Keeping the rule plan separate from its encoder
//! makes the exact sing-tun ordering testable without requiring CAP_NET_ADMIN.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use ipnet::IpNet;
use n0_watcher::Watcher as _;
use netlink_bindings::{
    nftables::{
        self, BitwiseOps, LookupFlags, Nfgenmsg, PushExprListAttrs,
        PushRuleAttrs, Registers, RejectTypes, SetElemFlags, SetFlags,
        VerdictCode,
    },
    traits::Pusher,
    utils,
};
use netlink_socket2::NetlinkSocket;
use network_interface::{
    Addr as InterfaceAddr, NetworkInterface, NetworkInterfaceConfig as _,
};
use tokio::{
    net::TcpListener,
    process::Command,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use super::tun_nfqueue_linux::NfQueueLease;
use crate::{
    common::{
        redir::original_destination,
        socket::{AutoRedirectMarkLease, with_network_namespace},
    },
    inbound::tun_route_linux::UidRange,
    outbound::OutboundManager,
    route::Router,
};

const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const HOOK_PREROUTING: u32 = 0;
const HOOK_INPUT: u32 = 1;
const HOOK_FORWARD: u32 = 2;
const HOOK_OUTPUT: u32 = 3;
const HOOK_POSTROUTING: u32 = 4;
const PRIORITY_MANGLE: i32 = -150;
const PRIORITY_DST_NAT: i32 = -100;
const PRIORITY_FILTER: i32 = 0;
const PRIORITY_SOURCE_NAT: i32 = 100;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
const NF_NAT_RANGE_PROTO_SPECIFIED: u32 = 1 << 1;
const NFT_EXTHDR_F_PRESENT: u32 = 1;
const NFT_EXTHDR_OP_TCPOPT: u32 = 1;
const TCP_OPTION_MPTCP: u32 = 30;
const IFNAME_SIZE: usize = libc::IFNAMSIZ;
const NFT_TYPE_ETHER_ADDR: u32 = 9;
const NFT_TYPE_UID: u32 = 24;
const NFT_TYPE_IFNAME: u32 = 41;
const SET_INCLUDE_UID: &str = "include_uid";
const SET_EXCLUDE_UID: &str = "exclude_uid";
const SET_INCLUDE_INTERFACE: &str = "include_interface";
const SET_EXCLUDE_INTERFACE: &str = "exclude_interface";
const SET_INCLUDE_MAC: &str = "include_mac";
const SET_EXCLUDE_MAC: &str = "exclude_mac";
const SET_PREMATCH_PROTOCOL: &str = "prematch_protocol";
const SET_LOCAL_IPV4: &str = "inet4_local_address_set";
const SET_LOCAL_IPV6: &str = "inet6_local_address_set";
const DOCKER_FILTER_TABLE: &str = "filter";
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";
const NFT_TYPE_IPV4_ADDR: u32 = 7;
const NFT_TYPE_IPV6_ADDR: u32 = 8;
const NFT_TYPE_INET_PROTO: u32 = 12;
const NFT_QUEUE_FLAG_BYPASS: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainType {
    Nat,
    Filter,
    Route,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum MetaKey {
    Mark = 3,
    Iifname = 6,
    Oifname = 7,
    Iiftype = 8,
    Skuid = 10,
    Nfproto = 15,
    L4Proto = 16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum CtKey {
    Mark = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Payload {
    LinkLayerHeader = 0,
    NetworkHeader = 1,
    TransportHeader = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum CompareOp {
    Eq = 0,
    Neq = 1,
    Gt = 4,
}

impl ChainType {
    const fn name(self) -> &'static [u8] {
        match self {
            Self::Nat => b"nat",
            Self::Filter => b"filter",
            Self::Route => b"route",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainPlan {
    name: &'static str,
    hook: u32,
    priority: i32,
    chain_type: ChainType,
    rules: Vec<Vec<Expression>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetPlan {
    name: &'static str,
    key_type: u32,
    key_len: u32,
    interval: bool,
    constant: bool,
    elements: Vec<SetElementPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetElementPlan {
    key: Vec<u8>,
    interval_end: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NftPlan {
    sets: Vec<SetPlan>,
    chains: Vec<ChainPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expression {
    MetaLoad(MetaKey),
    MetaStore(MetaKey),
    CtLoad(CtKey),
    CtStore(CtKey),
    PayloadLoad {
        base: Payload,
        offset: u32,
        length: u32,
    },
    BitwiseMask(Vec<u8>),
    Compare {
        operation: CompareOp,
        data: Vec<u8>,
    },
    Immediate(Vec<u8>),
    Counter,
    Return,
    Accept,
    Drop,
    RejectTcpReset,
    Redirect,
    Masquerade,
    FullCone,
    TcpOptionPresent(u32),
    TcpOptionLoad {
        kind: u32,
        offset: u32,
        length: u32,
    },
    TcpOptionStore {
        kind: u32,
        offset: u32,
        length: u32,
    },
    Queue {
        number: u16,
        bypass: bool,
    },
    Lookup {
        set: &'static str,
        invert: bool,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct AutoRedirectNftConfig {
    pub(crate) table: String,
    pub(crate) interface: String,
    pub(crate) redirect_port: u16,
    pub(crate) input_mark: u32,
    pub(crate) output_mark: u32,
    pub(crate) reset_mark: u32,
    pub(crate) nfqueue: Option<u16>,
    pub(crate) enable_ipv4: bool,
    pub(crate) enable_ipv6: bool,
    pub(crate) routes: Vec<IpNet>,
    pub(crate) local_networks: Vec<IpNet>,
    pub(crate) include_uids: Vec<UidRange>,
    pub(crate) exclude_uids: Vec<UidRange>,
    pub(crate) include_interfaces: Vec<String>,
    pub(crate) exclude_interfaces: Vec<String>,
    pub(crate) include_mac_addresses: Vec<String>,
    pub(crate) exclude_mac_addresses: Vec<String>,
    pub(crate) exclude_mptcp: bool,
}

impl AutoRedirectNftConfig {
    fn plan(&self) -> io::Result<NftPlan> {
        if self.table.as_bytes().contains(&0) {
            return Err(invalid("nftables table name contains NUL"));
        }
        if self.interface.as_bytes().contains(&0)
            || self.interface.len() >= IFNAME_SIZE
        {
            return Err(invalid("invalid TUN interface name for nftables"));
        }
        if self.redirect_port == 0 || self.input_mark == 0 {
            return Err(invalid(
                "auto-redirect port and input mark must be non-zero",
            ));
        }
        validate_filter_options(
            &self.include_interfaces,
            &self.exclude_interfaces,
            &self.include_mac_addresses,
            &self.exclude_mac_addresses,
        )?;
        let include_mac = parse_mac_addresses(
            &self.include_mac_addresses,
            "include_mac_address",
        )?;
        let exclude_mac = parse_mac_addresses(
            &self.exclude_mac_addresses,
            "exclude_mac_address",
        )?;

        let mut sets = Vec::new();
        sets.extend(local_address_sets(
            self.enable_ipv4,
            self.enable_ipv6,
            &self.local_networks,
        ));
        if self.nfqueue.is_some() {
            sets.push(SetPlan {
                name: SET_PREMATCH_PROTOCOL,
                key_type: NFT_TYPE_INET_PROTO,
                key_len: 1,
                interval: false,
                constant: true,
                elements: [
                    IPPROTO_TCP,
                    IPPROTO_UDP,
                    IPPROTO_ICMP,
                    IPPROTO_ICMPV6,
                ]
                .into_iter()
                .map(|protocol| SetElementPlan {
                    key: vec![protocol],
                    interval_end: false,
                })
                .collect(),
            });
        }
        if self.include_uids.len() > 1
            || self
                .include_uids
                .first()
                .is_some_and(|range| range.start != range.end)
        {
            sets.push(uid_interval_set(SET_INCLUDE_UID, &self.include_uids));
        }
        if self.exclude_uids.len() > 1
            || self
                .exclude_uids
                .first()
                .is_some_and(|range| range.start != range.end)
        {
            sets.push(uid_interval_set(SET_EXCLUDE_UID, &self.exclude_uids));
        }
        if self.include_interfaces.len() > 1 {
            sets.push(interface_set(
                SET_INCLUDE_INTERFACE,
                &self.include_interfaces,
            )?);
        }
        if self.exclude_interfaces.len() > 1 {
            sets.push(interface_set(
                SET_EXCLUDE_INTERFACE,
                &self.exclude_interfaces,
            )?);
        }
        if include_mac.len() > 1 {
            sets.push(mac_set(SET_INCLUDE_MAC, &include_mac));
        }
        if exclude_mac.len() > 1 {
            sets.push(mac_set(SET_EXCLUDE_MAC, &exclude_mac));
        }

        let skip_output = (!self.include_interfaces.is_empty()
            && !self
                .include_interfaces
                .iter()
                .any(|interface| interface == "lo"))
            || self
                .exclude_interfaces
                .iter()
                .any(|interface| interface == "lo");
        let mut chains = Vec::new();
        if let Some(queue) = self.nfqueue {
            chains.push(self.pre_match_chain(queue, true)?);
            if !skip_output {
                chains.push(self.pre_match_chain(queue, false)?);
            }
        }
        if !skip_output {
            chains.push(self.output_nat_chain()?);
            chains.push(self.output_packet_chain()?);
        }
        chains.push(self.input_chain());
        chains.push(self.prerouting_nat_chain(&include_mac, &exclude_mac)?);
        chains.push(self.prerouting_packet_chain(&include_mac, &exclude_mac)?);
        Ok(NftPlan { sets, chains })
    }

    fn output_nat_chain(&self) -> io::Result<ChainPlan> {
        let mut rules = Vec::new();
        if self.nfqueue.is_some() {
            rules.push(mark_return_rule(self.output_mark, true));
        }
        rules.push(mark_return_rule(self.output_mark, false));
        rules.extend(uid_filter_rules(&self.include_uids, &self.exclude_uids));
        rules.extend(local_return_rules(&self.local_networks));
        rules.push(mptcp_rule(self.exclude_mptcp));
        rules.extend(self.routes.iter().copied().map(|network| {
            let mut rule = destination_match(network);
            rule.extend(l4_protocol_match(IPPROTO_TCP));
            rule.extend(redirect_expressions(self.redirect_port));
            rule
        }));
        Ok(ChainPlan {
            name: "output",
            hook: HOOK_OUTPUT,
            priority: PRIORITY_MANGLE + i32::from(self.nfqueue.is_some()) * 2,
            chain_type: ChainType::Nat,
            rules,
        })
    }

    fn output_packet_chain(&self) -> io::Result<ChainPlan> {
        let mut rules = vec![mark_return_rule(self.output_mark, false)];
        rules.push(mark_return_rule(self.output_mark, true));
        rules.extend(uid_filter_rules(&self.include_uids, &self.exclude_uids));
        rules.extend(local_return_rules(&self.local_networks));
        rules.extend(mark_route_rules(&self.routes, self.input_mark));
        Ok(ChainPlan {
            name: "output_udp_icmp",
            hook: HOOK_OUTPUT,
            priority: PRIORITY_MANGLE + i32::from(self.nfqueue.is_some()) * 2,
            chain_type: ChainType::Route,
            rules,
        })
    }

    fn input_chain(&self) -> ChainPlan {
        let mut rule = l4_protocol_match(IPPROTO_TCP);
        rule.push(Expression::PayloadLoad {
            base: Payload::TransportHeader,
            offset: 2,
            length: 2,
        });
        rule.push(Expression::Compare {
            operation: CompareOp::Eq,
            data: self.redirect_port.to_be_bytes().to_vec(),
        });
        rule.push(Expression::Counter);
        rule.push(Expression::RejectTcpReset);
        ChainPlan {
            name: "input",
            hook: HOOK_INPUT,
            priority: PRIORITY_FILTER,
            chain_type: ChainType::Filter,
            rules: vec![rule],
        }
    }

    fn prerouting_nat_chain(
        &self,
        include_mac: &[[u8; 6]],
        exclude_mac: &[[u8; 6]],
    ) -> io::Result<ChainPlan> {
        let mut rules = Vec::new();
        if self.nfqueue.is_some() {
            rules.push(mark_return_rule(self.output_mark, true));
        }
        rules.extend(prerouting_exclusions(self, include_mac, exclude_mac)?);
        rules.extend(local_return_rules(&self.local_networks));
        rules.push(mptcp_rule(self.exclude_mptcp));
        rules.extend(self.routes.iter().copied().map(|network| {
            let mut rule = destination_match(network);
            rule.extend(l4_protocol_match(IPPROTO_TCP));
            rule.extend(redirect_expressions(self.redirect_port));
            rule
        }));
        Ok(ChainPlan {
            name: "prerouting",
            hook: HOOK_PREROUTING,
            priority: PRIORITY_DST_NAT + 1 + i32::from(self.nfqueue.is_some()),
            chain_type: ChainType::Nat,
            rules,
        })
    }

    fn prerouting_packet_chain(
        &self,
        include_mac: &[[u8; 6]],
        exclude_mac: &[[u8; 6]],
    ) -> io::Result<ChainPlan> {
        let mut rules = prerouting_exclusions(self, include_mac, exclude_mac)?;
        rules.extend(local_return_rules(&self.local_networks));
        if self.exclude_mptcp {
            rules.push(mptcp_rule(true));
        }
        rules.extend(mark_route_rules(&self.routes, self.input_mark));
        Ok(ChainPlan {
            name: "prerouting_udp_icmp",
            hook: HOOK_PREROUTING,
            priority: PRIORITY_DST_NAT + 2 + i32::from(self.nfqueue.is_some()),
            chain_type: ChainType::Filter,
            rules,
        })
    }

    fn pre_match_chain(
        &self,
        queue: u16,
        prerouting: bool,
    ) -> io::Result<ChainPlan> {
        let mut rules = Vec::new();
        if !prerouting {
            rules.push(vec![
                Expression::MetaLoad(MetaKey::Oifname),
                Expression::Compare {
                    operation: CompareOp::Eq,
                    data: interface_key(&self.interface),
                },
                Expression::Return,
            ]);
        }
        if self.enable_ipv4 != self.enable_ipv6 {
            rules.push(vec![
                Expression::MetaLoad(MetaKey::Nfproto),
                Expression::Compare {
                    operation: CompareOp::Eq,
                    data: vec![if self.enable_ipv4 {
                        NFPROTO_IPV6
                    } else {
                        NFPROTO_IPV4
                    }],
                },
                Expression::Return,
            ]);
        }
        rules.push(lookup_return_rule(
            Expression::MetaLoad(MetaKey::L4Proto),
            SET_PREMATCH_PROTOCOL,
            true,
        ));
        rules.push(tcp_non_syn_return_rule());
        rules.push(copy_packet_mark_to_conntrack_rule(self.output_mark));
        rules.push(tcp_reset_mark_rule(self.reset_mark));
        rules.push(mark_return_rule(self.output_mark, true));
        rules.push(mark_return_rule(self.input_mark, true));
        if prerouting {
            let include_mac = parse_mac_addresses(
                &self.include_mac_addresses,
                "include_mac_address",
            )?;
            let exclude_mac = parse_mac_addresses(
                &self.exclude_mac_addresses,
                "exclude_mac_address",
            )?;
            rules.extend(prerouting_exclusions(
                self,
                &include_mac,
                &exclude_mac,
            )?);
        } else {
            rules.extend(uid_filter_rules(
                &self.include_uids,
                &self.exclude_uids,
            ));
        }
        rules.extend(local_return_rules(&self.local_networks));
        rules.push(mptcp_rule(self.exclude_mptcp));
        rules.push(queue_protocol_rule(IPPROTO_TCP, queue, None));
        rules.push(queue_protocol_rule(IPPROTO_UDP, queue, None));
        rules.push(queue_protocol_rule(IPPROTO_ICMP, queue, Some([8, 0])));
        rules.push(queue_protocol_rule(IPPROTO_ICMPV6, queue, Some([128, 0])));
        Ok(ChainPlan {
            name: if prerouting {
                "prerouting_prematch"
            } else {
                "output_prematch"
            },
            hook: if prerouting {
                HOOK_PREROUTING
            } else {
                HOOK_OUTPUT
            },
            priority: if prerouting {
                PRIORITY_DST_NAT - 1
            } else {
                PRIORITY_MANGLE + 1
            },
            chain_type: ChainType::Filter,
            rules,
        })
    }
}

pub(crate) fn validate_filter_options(
    include_interfaces: &[String],
    exclude_interfaces: &[String],
    include_mac_addresses: &[String],
    exclude_mac_addresses: &[String],
) -> io::Result<()> {
    for interface in include_interfaces.iter().chain(exclude_interfaces) {
        validate_interface(interface)?;
    }
    parse_mac_addresses(include_mac_addresses, "include_mac_address")?;
    parse_mac_addresses(exclude_mac_addresses, "exclude_mac_address")?;
    Ok(())
}

fn prerouting_exclusions(
    config: &AutoRedirectNftConfig,
    include_mac: &[[u8; 6]],
    exclude_mac: &[[u8; 6]],
) -> io::Result<Vec<Vec<Expression>>> {
    let mut rules =
        vec![interface_return_rule(&config.interface, CompareOp::Eq)?];
    match config.include_interfaces.as_slice() {
        [] => {}
        [interface] => {
            rules.push(interface_return_rule(interface, CompareOp::Neq)?);
        }
        _ => rules.push(lookup_return_rule(
            Expression::MetaLoad(MetaKey::Iifname),
            SET_INCLUDE_INTERFACE,
            true,
        )),
    }
    match config.exclude_interfaces.as_slice() {
        [] => {}
        [interface] => {
            rules.push(interface_return_rule(interface, CompareOp::Eq)?);
        }
        _ => rules.push(lookup_return_rule(
            Expression::MetaLoad(MetaKey::Iifname),
            SET_EXCLUDE_INTERFACE,
            false,
        )),
    }
    if !include_mac.is_empty() {
        rules.push(vec![
            Expression::MetaLoad(MetaKey::Iiftype),
            Expression::Compare {
                operation: CompareOp::Neq,
                data: (libc::ARPHRD_ETHER as u16).to_ne_bytes().to_vec(),
            },
            Expression::Counter,
            Expression::Return,
        ]);
        rules.push(if include_mac.len() == 1 {
            mac_return_rule(include_mac[0], CompareOp::Neq)
        } else {
            lookup_return_rule(mac_source_load(), SET_INCLUDE_MAC, true)
        });
    }
    match exclude_mac {
        [] => {}
        [mac] => rules.push(mac_return_rule(*mac, CompareOp::Eq)),
        _ => rules.push(lookup_return_rule(
            mac_source_load(),
            SET_EXCLUDE_MAC,
            false,
        )),
    }
    Ok(rules)
}

fn interface_return_rule(
    interface: &str,
    operation: CompareOp,
) -> io::Result<Vec<Expression>> {
    validate_interface(interface)?;
    Ok(vec![
        Expression::MetaLoad(MetaKey::Iifname),
        Expression::Compare {
            operation,
            data: interface_key(interface),
        },
        Expression::Counter,
        Expression::Return,
    ])
}

fn mac_source_load() -> Expression {
    Expression::PayloadLoad {
        base: Payload::LinkLayerHeader,
        offset: 6,
        length: 6,
    }
}

fn mac_return_rule(mac: [u8; 6], operation: CompareOp) -> Vec<Expression> {
    vec![
        mac_source_load(),
        Expression::Compare {
            operation,
            data: mac.to_vec(),
        },
        Expression::Counter,
        Expression::Return,
    ]
}

fn lookup_return_rule(
    load: Expression,
    set: &'static str,
    invert: bool,
) -> Vec<Expression> {
    vec![
        load,
        Expression::Lookup { set, invert },
        Expression::Counter,
        Expression::Return,
    ]
}

fn uid_interval_set(name: &'static str, ranges: &[UidRange]) -> SetPlan {
    let elements = ranges
        .iter()
        .flat_map(|range| {
            [
                SetElementPlan {
                    key: range.start.to_ne_bytes().to_vec(),
                    interval_end: false,
                },
                SetElementPlan {
                    key: range.end.wrapping_add(1).to_ne_bytes().to_vec(),
                    interval_end: true,
                },
            ]
        })
        .collect();
    SetPlan {
        name,
        key_type: NFT_TYPE_UID,
        key_len: 4,
        interval: true,
        constant: true,
        elements,
    }
}

fn ip_interval_set(
    name: &'static str,
    ipv6: bool,
    networks: &[IpNet],
) -> SetPlan {
    let elements = IpNet::aggregate(
        &networks
            .iter()
            .copied()
            .filter(|network| network.addr().is_ipv6() == ipv6)
            .collect::<Vec<_>>(),
    )
    .into_iter()
    .flat_map(|network| {
        let (start, end) = match network {
            IpNet::V4(network) => {
                let start = u32::from(network.network());
                let host_bits = 32 - u32::from(network.prefix_len());
                let end =
                    start | u32::MAX.checked_shr(32 - host_bits).unwrap_or(0);
                (
                    start.to_be_bytes().to_vec(),
                    end.checked_add(1)
                        .map(|value| value.to_be_bytes().to_vec()),
                )
            }
            IpNet::V6(network) => {
                let start = u128::from(network.network());
                let host_bits = 128 - u32::from(network.prefix_len());
                let end =
                    start | u128::MAX.checked_shr(128 - host_bits).unwrap_or(0);
                (
                    start.to_be_bytes().to_vec(),
                    end.checked_add(1)
                        .map(|value| value.to_be_bytes().to_vec()),
                )
            }
        };
        std::iter::once(SetElementPlan {
            key: start,
            interval_end: false,
        })
        .chain(end.map(|key| SetElementPlan {
            key,
            interval_end: true,
        }))
    })
    .collect();
    SetPlan {
        name,
        key_type: if ipv6 {
            NFT_TYPE_IPV6_ADDR
        } else {
            NFT_TYPE_IPV4_ADDR
        },
        key_len: if ipv6 { 16 } else { 4 },
        interval: true,
        constant: false,
        elements,
    }
}

fn local_address_sets(
    enable_ipv4: bool,
    enable_ipv6: bool,
    networks: &[IpNet],
) -> Vec<SetPlan> {
    let mut sets = Vec::with_capacity(2);
    if enable_ipv4 {
        sets.push(ip_interval_set(SET_LOCAL_IPV4, false, networks));
    }
    if enable_ipv6 {
        sets.push(ip_interval_set(SET_LOCAL_IPV6, true, networks));
    }
    sets
}

fn interface_set(
    name: &'static str,
    interfaces: &[String],
) -> io::Result<SetPlan> {
    let elements = interfaces
        .iter()
        .map(|interface| {
            validate_interface(interface)?;
            Ok(SetElementPlan {
                key: interface_key(interface),
                interval_end: false,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(SetPlan {
        name,
        key_type: NFT_TYPE_IFNAME,
        key_len: IFNAME_SIZE as u32,
        interval: false,
        constant: true,
        elements,
    })
}

fn validate_interface(interface: &str) -> io::Result<()> {
    if interface.as_bytes().contains(&0) || interface.len() >= IFNAME_SIZE {
        return Err(invalid("invalid interface filter for nftables"));
    }
    Ok(())
}

fn interface_key(interface: &str) -> Vec<u8> {
    let mut name = vec![0_u8; IFNAME_SIZE];
    name[..interface.len()].copy_from_slice(interface.as_bytes());
    name
}

fn mac_set(name: &'static str, addresses: &[[u8; 6]]) -> SetPlan {
    SetPlan {
        name,
        key_type: NFT_TYPE_ETHER_ADDR,
        key_len: 6,
        interval: false,
        constant: true,
        elements: addresses
            .iter()
            .map(|address| SetElementPlan {
                key: address.to_vec(),
                interval_end: false,
            })
            .collect(),
    }
}

fn parse_mac_addresses(
    values: &[String],
    field: &str,
) -> io::Result<Vec<[u8; 6]>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            parse_mac_address(value).ok_or_else(|| {
                invalid(format!("parse {field}[{index}]: invalid MAC address"))
            })
        })
        .collect()
}

fn parse_mac_address(value: &str) -> Option<[u8; 6]> {
    let hex = if value.len() == 17
        && value
            .as_bytes()
            .get(2)
            .is_some_and(|separator| matches!(separator, b':' | b'-'))
    {
        let separator = value.as_bytes()[2] as char;
        let parts = value.split(separator).collect::<Vec<_>>();
        if parts.len() != 6 || parts.iter().any(|part| part.len() != 2) {
            return None;
        }
        parts.concat()
    } else if value.len() == 14 && value.as_bytes().get(4) == Some(&b'.') {
        let parts = value.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|part| part.len() != 4) {
            return None;
        }
        parts.concat()
    } else if value.len() == 12 {
        value.to_owned()
    } else {
        return None;
    };
    hex::decode(hex).ok()?.try_into().ok()
}

fn local_return_rules(networks: &[IpNet]) -> Vec<Vec<Expression>> {
    let mut rules = Vec::new();
    if networks.iter().any(|network| network.addr().is_ipv4()) {
        rules.push(address_set_return_rule(false, SET_LOCAL_IPV4));
    }
    if networks.iter().any(|network| network.addr().is_ipv6()) {
        rules.push(address_set_return_rule(true, SET_LOCAL_IPV6));
    }
    rules
}

fn address_set_return_rule(ipv6: bool, set: &'static str) -> Vec<Expression> {
    vec![
        Expression::MetaLoad(MetaKey::Nfproto),
        Expression::Compare {
            operation: CompareOp::Eq,
            data: vec![if ipv6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 }],
        },
        Expression::PayloadLoad {
            base: Payload::NetworkHeader,
            offset: if ipv6 { 24 } else { 16 },
            length: if ipv6 { 16 } else { 4 },
        },
        Expression::Lookup { set, invert: false },
        Expression::Counter,
        Expression::Return,
    ]
}

fn uid_filter_rules(
    includes: &[UidRange],
    excludes: &[UidRange],
) -> Vec<Vec<Expression>> {
    let mut rules = Vec::new();
    match includes {
        [] => {}
        [range] if range.start == range.end => rules.push(vec![
            Expression::MetaLoad(MetaKey::Skuid),
            Expression::Compare {
                operation: CompareOp::Neq,
                data: range.start.to_ne_bytes().to_vec(),
            },
            Expression::Counter,
            Expression::Return,
        ]),
        _ => rules.push(lookup_return_rule(
            Expression::MetaLoad(MetaKey::Skuid),
            SET_INCLUDE_UID,
            true,
        )),
    }
    match excludes {
        [] => {}
        [range] if range.start == range.end => rules.push(vec![
            Expression::MetaLoad(MetaKey::Skuid),
            Expression::Compare {
                operation: CompareOp::Eq,
                data: range.start.to_ne_bytes().to_vec(),
            },
            Expression::Counter,
            Expression::Return,
        ]),
        _ => rules.push(lookup_return_rule(
            Expression::MetaLoad(MetaKey::Skuid),
            SET_EXCLUDE_UID,
            false,
        )),
    }
    rules
}

fn mark_route_rules(routes: &[IpNet], input_mark: u32) -> Vec<Vec<Expression>> {
    routes
        .iter()
        .copied()
        .flat_map(|network| {
            let protocols: &[u8] = if network.addr().is_ipv4() {
                &[IPPROTO_UDP, IPPROTO_ICMP]
            } else {
                &[IPPROTO_UDP, IPPROTO_ICMPV6]
            };
            protocols.iter().copied().map(move |protocol| {
                let mut rule = destination_match(network);
                rule.extend(l4_protocol_match(protocol));
                rule.extend(mark_expressions(input_mark));
                rule
            })
        })
        .collect()
}

fn destination_match(network: IpNet) -> Vec<Expression> {
    let (nfproto, offset, address, prefix) = match network {
        IpNet::V4(network) => (
            NFPROTO_IPV4,
            16,
            network.network().octets().to_vec(),
            network.prefix_len(),
        ),
        IpNet::V6(network) => (
            NFPROTO_IPV6,
            24,
            network.network().octets().to_vec(),
            network.prefix_len(),
        ),
    };
    let mut expressions = vec![
        Expression::MetaLoad(MetaKey::Nfproto),
        Expression::Compare {
            operation: CompareOp::Eq,
            data: vec![nfproto],
        },
        Expression::PayloadLoad {
            base: Payload::NetworkHeader,
            offset,
            length: address.len() as u32,
        },
    ];
    if usize::from(prefix) != address.len() * 8 {
        let mut mask = vec![0_u8; address.len()];
        for bit in 0..usize::from(prefix) {
            mask[bit / 8] |= 1 << (7 - bit % 8);
        }
        expressions.push(Expression::BitwiseMask(mask));
    }
    expressions.push(Expression::Compare {
        operation: CompareOp::Eq,
        data: address,
    });
    expressions
}

fn l4_protocol_match(protocol: u8) -> Vec<Expression> {
    vec![
        Expression::MetaLoad(MetaKey::L4Proto),
        Expression::Compare {
            operation: CompareOp::Eq,
            data: vec![protocol],
        },
    ]
}

fn mptcp_rule(exclude: bool) -> Vec<Expression> {
    let mut rule = l4_protocol_match(IPPROTO_TCP);
    rule.push(Expression::TcpOptionPresent(TCP_OPTION_MPTCP));
    rule.push(Expression::Compare {
        operation: CompareOp::Eq,
        data: vec![1],
    });
    rule.push(Expression::Counter);
    rule.push(if exclude {
        Expression::Return
    } else {
        Expression::Drop
    });
    rule
}

fn tcp_non_syn_return_rule() -> Vec<Expression> {
    let mut rule = l4_protocol_match(IPPROTO_TCP);
    rule.extend([
        Expression::PayloadLoad {
            base: Payload::TransportHeader,
            offset: 13,
            length: 1,
        },
        Expression::BitwiseMask(vec![0x12]),
        Expression::Compare {
            operation: CompareOp::Neq,
            data: vec![0x02],
        },
        Expression::Return,
    ]);
    rule
}

fn copy_packet_mark_to_conntrack_rule(mark: u32) -> Vec<Expression> {
    vec![
        Expression::MetaLoad(MetaKey::Mark),
        Expression::Compare {
            operation: CompareOp::Eq,
            data: mark.to_ne_bytes().to_vec(),
        },
        Expression::CtStore(CtKey::Mark),
        Expression::Counter,
        Expression::Return,
    ]
}

fn tcp_reset_mark_rule(mark: u32) -> Vec<Expression> {
    let mut rule = l4_protocol_match(IPPROTO_TCP);
    rule.extend([
        Expression::MetaLoad(MetaKey::Mark),
        Expression::Compare {
            operation: CompareOp::Eq,
            data: mark.to_ne_bytes().to_vec(),
        },
        Expression::Counter,
        Expression::RejectTcpReset,
    ]);
    rule
}

fn queue_protocol_rule(
    protocol: u8,
    queue: u16,
    icmp_type_code: Option<[u8; 2]>,
) -> Vec<Expression> {
    let mut rule = l4_protocol_match(protocol);
    if let Some(type_code) = icmp_type_code {
        rule.extend([
            Expression::PayloadLoad {
                base: Payload::TransportHeader,
                offset: 0,
                length: 2,
            },
            Expression::Compare {
                operation: CompareOp::Eq,
                data: type_code.to_vec(),
            },
        ]);
    }
    rule.extend([
        Expression::Counter,
        Expression::Queue {
            number: queue,
            bypass: true,
        },
    ]);
    rule
}

fn mark_return_rule(mark: u32, conntrack: bool) -> Vec<Expression> {
    vec![
        if conntrack {
            Expression::CtLoad(CtKey::Mark)
        } else {
            Expression::MetaLoad(MetaKey::Mark)
        },
        Expression::Compare {
            operation: CompareOp::Eq,
            data: mark.to_ne_bytes().to_vec(),
        },
        Expression::Counter,
        Expression::Return,
    ]
}

fn mark_expressions(mark: u32) -> Vec<Expression> {
    vec![
        Expression::Immediate(mark.to_ne_bytes().to_vec()),
        Expression::MetaStore(MetaKey::Mark),
        Expression::MetaLoad(MetaKey::Mark),
        Expression::CtStore(CtKey::Mark),
        Expression::Counter,
        Expression::Return,
    ]
}

fn redirect_expressions(port: u16) -> Vec<Expression> {
    vec![
        Expression::Counter,
        Expression::Immediate(port.to_be_bytes().to_vec()),
        Expression::Redirect,
        Expression::Return,
    ]
}

pub(crate) struct NftablesLease {
    table: Option<String>,
    network_namespace: String,
}

/// Minimal native nftables lease used by the bridge outbound. It shares the
/// same generation-ID protected transaction encoder as TUN auto-redirect and
/// therefore does not depend on the `nft` executable.
pub(crate) struct LinuxBridgeNftLease {
    table: String,
    interface: String,
    enable_ipv4: bool,
    enable_ipv6: bool,
    full_cone: bool,
    mtu: u16,
    backend: BridgeFirewallBackend,
    inner: NftablesLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BridgeFirewallBackend {
    Nftables,
    Iptables,
}

impl LinuxBridgeNftLease {
    pub(crate) async fn install(
        table: String,
        interface: String,
        enable_ipv4: bool,
        enable_ipv6: bool,
        mtu: u16,
    ) -> io::Result<Self> {
        if interface.as_bytes().contains(&0) || interface.len() >= IFNAME_SIZE {
            return Err(invalid("invalid bridge TUN interface name"));
        }
        let install_table = table.clone();
        let install_interface = interface.clone();
        let (backend, full_cone, ipv6_active) =
            tokio::task::spawn_blocking(move || -> io::Result<_> {
                if nft_table_exists_sync(
                    "sing-box-bridge-capability-probe",
                    NFPROTO_INET,
                )
                .is_ok()
                {
                    let full_cone = probe_full_cone_sync();
                    let plan = bridge_nft_plan(
                        &install_interface,
                        enable_ipv4,
                        enable_ipv6,
                        mtu,
                        full_cone,
                    );
                    delete_table_sync(&install_table).ok();
                    install_table_sync(&install_table, &plan)?;
                    Ok((
                        BridgeFirewallBackend::Nftables,
                        full_cone,
                        enable_ipv6,
                    ))
                } else {
                    let ipv6_active = install_bridge_iptables(
                        &install_table,
                        &install_interface,
                        enable_ipv4,
                        enable_ipv6,
                        mtu,
                    )?;
                    Ok((BridgeFirewallBackend::Iptables, false, ipv6_active))
                }
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
        Ok(Self {
            table: table.clone(),
            interface,
            enable_ipv4,
            enable_ipv6: ipv6_active,
            full_cone,
            mtu,
            backend,
            inner: NftablesLease {
                table: (backend == BridgeFirewallBackend::Nftables)
                    .then_some(table),
                network_namespace: String::new(),
            },
        })
    }

    pub(crate) fn ipv6_active(&self) -> bool {
        self.enable_ipv6
    }

    pub(crate) async fn update_mtu(&mut self, mtu: u16) -> io::Result<()> {
        if self.mtu == mtu {
            return Ok(());
        }
        let table = self.table.clone();
        let interface = self.interface.clone();
        let enable_ipv4 = self.enable_ipv4;
        let enable_ipv6 = self.enable_ipv6;
        let full_cone = self.full_cone;
        let backend = self.backend;
        tokio::task::spawn_blocking(move || match backend {
            BridgeFirewallBackend::Nftables => {
                let plan = bridge_nft_plan(
                    &interface,
                    enable_ipv4,
                    enable_ipv6,
                    mtu,
                    full_cone,
                );
                replace_table_sync(&table, &plan)
            }
            BridgeFirewallBackend::Iptables => update_bridge_iptables_mss(
                &table,
                &interface,
                enable_ipv4,
                enable_ipv6,
                mtu,
            ),
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))??;
        self.mtu = mtu;
        Ok(())
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        match self.backend {
            BridgeFirewallBackend::Nftables => self.inner.close().await,
            BridgeFirewallBackend::Iptables => {
                let table = self.table.clone();
                tokio::task::spawn_blocking(move || {
                    cleanup_bridge_iptables(&table);
                })
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
                Ok(())
            }
        }
    }
}

fn bridge_nft_plan(
    interface: &str,
    enable_ipv4: bool,
    enable_ipv6: bool,
    mtu: u16,
    full_cone: bool,
) -> NftPlan {
    let mut forward_rules = Vec::new();
    for (enabled, protocol, header_size) in [
        (enable_ipv4, NFPROTO_IPV4, 40u16),
        (enable_ipv6, NFPROTO_IPV6, 60u16),
    ] {
        if !enabled {
            continue;
        }
        let clamp = mtu.saturating_sub(header_size).max(1).to_be_bytes();
        forward_rules.push(vec![
            Expression::MetaLoad(MetaKey::Nfproto),
            Expression::Compare {
                operation: CompareOp::Eq,
                data: vec![protocol],
            },
            Expression::MetaLoad(MetaKey::Iifname),
            Expression::Compare {
                operation: CompareOp::Eq,
                data: interface_key(interface),
            },
            Expression::MetaLoad(MetaKey::L4Proto),
            Expression::Compare {
                operation: CompareOp::Eq,
                data: vec![IPPROTO_TCP],
            },
            Expression::PayloadLoad {
                base: Payload::TransportHeader,
                offset: 13,
                length: 1,
            },
            Expression::BitwiseMask(vec![0x02]),
            Expression::Compare {
                operation: CompareOp::Eq,
                data: vec![0x02],
            },
            Expression::TcpOptionLoad {
                kind: 2,
                offset: 2,
                length: 2,
            },
            Expression::Compare {
                operation: CompareOp::Gt,
                data: clamp.to_vec(),
            },
            Expression::Immediate(clamp.to_vec()),
            Expression::TcpOptionStore {
                kind: 2,
                offset: 2,
                length: 2,
            },
        ]);
    }
    NftPlan {
        sets: Vec::new(),
        chains: vec![
            ChainPlan {
                name: "postrouting",
                hook: HOOK_POSTROUTING,
                priority: PRIORITY_SOURCE_NAT,
                chain_type: ChainType::Nat,
                rules: vec![vec![
                    Expression::MetaLoad(MetaKey::Iifname),
                    Expression::Compare {
                        operation: CompareOp::Eq,
                        data: interface_key(interface),
                    },
                    if full_cone {
                        Expression::FullCone
                    } else {
                        Expression::Masquerade
                    },
                ]],
            },
            ChainPlan {
                name: "forward",
                hook: HOOK_FORWARD,
                priority: PRIORITY_MANGLE,
                chain_type: ChainType::Filter,
                rules: forward_rules,
            },
        ],
    }
}

fn probe_full_cone_sync() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let table = format!("sing-box-fullcone-probe-{}", std::process::id());
        delete_table_sync(&table).ok();
        let plan = NftPlan {
            sets: Vec::new(),
            chains: vec![ChainPlan {
                name: "postrouting",
                hook: HOOK_POSTROUTING,
                priority: PRIORITY_SOURCE_NAT,
                chain_type: ChainType::Nat,
                rules: vec![vec![Expression::FullCone]],
            }],
        };
        let supported = install_table_sync(&table, &plan).is_ok();
        delete_table_sync(&table).ok();
        supported
    })
}

const BRIDGE_IPTABLES_MARK: &str = "0x40000000/0x40000000";

fn install_bridge_iptables(
    table: &str,
    interface: &str,
    enable_ipv4: bool,
    enable_ipv6: bool,
    mtu: u16,
) -> io::Result<bool> {
    cleanup_bridge_iptables(table);
    if enable_ipv4
        && let Err(error) =
            install_bridge_iptables_family("iptables", table, interface)
    {
        cleanup_bridge_iptables(table);
        return Err(error);
    }
    let mut ipv6_active = false;
    if enable_ipv6 {
        ipv6_active =
            install_bridge_iptables_family("ip6tables", table, interface)
                .is_ok();
        if !ipv6_active {
            cleanup_bridge_iptables_family("ip6tables", table);
        }
    }
    if let Err(error) = update_bridge_iptables_mss(
        table,
        interface,
        enable_ipv4,
        ipv6_active,
        mtu,
    ) {
        cleanup_bridge_iptables(table);
        return Err(error);
    }
    Ok(ipv6_active)
}

fn install_bridge_iptables_family(
    binary: &str,
    table: &str,
    interface: &str,
) -> io::Result<()> {
    run_bridge_iptables(binary, &["-t", "nat", "-N", table])?;
    run_bridge_iptables(
        binary,
        &[
            "-t",
            "nat",
            "-A",
            table,
            "-m",
            "mark",
            "--mark",
            BRIDGE_IPTABLES_MARK,
            "-j",
            "MASQUERADE",
        ],
    )?;
    run_bridge_iptables(
        binary,
        &["-t", "nat", "-I", "POSTROUTING", "-j", table],
    )?;
    run_bridge_iptables(binary, &["-t", "mangle", "-N", table])?;
    append_bridge_iptables_mark(binary, table, interface)?;
    run_bridge_iptables(
        binary,
        &["-t", "mangle", "-I", "FORWARD", "-j", table],
    )?;
    run_bridge_iptables(binary, &["-t", "filter", "-N", table])?;
    run_bridge_iptables(
        binary,
        &["-t", "filter", "-A", table, "-i", interface, "-j", "ACCEPT"],
    )?;
    run_bridge_iptables(
        binary,
        &["-t", "filter", "-A", table, "-o", interface, "-j", "ACCEPT"],
    )?;
    run_bridge_iptables(binary, &["-t", "filter", "-I", "FORWARD", "-j", table])
}

fn append_bridge_iptables_mark(
    binary: &str,
    table: &str,
    interface: &str,
) -> io::Result<()> {
    run_bridge_iptables(
        binary,
        &[
            "-t",
            "mangle",
            "-A",
            table,
            "-i",
            interface,
            "-j",
            "MARK",
            "--set-xmark",
            BRIDGE_IPTABLES_MARK,
        ],
    )
}

fn update_bridge_iptables_mss(
    table: &str,
    interface: &str,
    enable_ipv4: bool,
    enable_ipv6: bool,
    mtu: u16,
) -> io::Result<()> {
    for (enabled, binary, header_size) in [
        (enable_ipv4, "iptables", 40u16),
        (enable_ipv6, "ip6tables", 60u16),
    ] {
        if !enabled {
            continue;
        }
        run_bridge_iptables(binary, &["-t", "mangle", "-F", table])?;
        append_bridge_iptables_mark(binary, table, interface)?;
        let mss = mtu.saturating_sub(header_size).max(1).to_string();
        run_bridge_iptables(
            binary,
            &[
                "-t",
                "mangle",
                "-A",
                table,
                "-i",
                interface,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--set-mss",
                &mss,
            ],
        )?;
    }
    Ok(())
}

fn run_bridge_iptables(binary: &str, args: &[&str]) -> io::Result<()> {
    let output = std::process::Command::new(binary).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!(
            "{binary} {} failed with {}{}",
            args.join(" "),
            output.status,
            if detail.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", detail.trim())
            }
        )))
    }
}

fn cleanup_bridge_iptables(table: &str) {
    cleanup_bridge_iptables_family("iptables", table);
    cleanup_bridge_iptables_family("ip6tables", table);
}

fn cleanup_bridge_iptables_family(binary: &str, table: &str) {
    for (iptables_table, hook) in [
        ("nat", "POSTROUTING"),
        ("mangle", "FORWARD"),
        ("filter", "FORWARD"),
    ] {
        let _ = std::process::Command::new(binary)
            .args(["-t", iptables_table, "-D", hook, "-j", table])
            .output();
        let _ = std::process::Command::new(binary)
            .args(["-t", iptables_table, "-F", table])
            .output();
        let _ = std::process::Command::new(binary)
            .args(["-t", iptables_table, "-X", table])
            .output();
    }
}

struct OpenWrtLease {
    rule_path: Option<PathBuf>,
    fw4_path: Option<PathBuf>,
}

#[derive(Clone)]
struct DockerFirewallConfig {
    interface: String,
    enable_ipv4: bool,
    enable_ipv6: bool,
    network_namespace: String,
}

struct DockerRuleInfo {
    handle: u64,
    comment: Option<String>,
}

pub(crate) struct LinuxAutoRedirectLease {
    nfqueue: Option<NfQueueLease>,
    nftables: NftablesLease,
    openwrt: OpenWrtLease,
    output_mark: Option<AutoRedirectMarkLease>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    network_task: Option<JoinHandle<()>>,
    docker_task: Option<JoinHandle<()>>,
    docker: DockerFirewallConfig,
    nft_config: AutoRedirectNftConfig,
    tun_networks: Vec<IpNet>,
}

impl LinuxAutoRedirectLease {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn install(
        table: String,
        interface: String,
        input_mark: u32,
        output_mark_value: u32,
        reset_mark: u32,
        nfqueue_number: u16,
        routes: Vec<IpNet>,
        tun_networks: &[IpNet],
        include_uids: Vec<UidRange>,
        exclude_uids: Vec<UidRange>,
        include_interfaces: Vec<String>,
        exclude_interfaces: Vec<String>,
        include_mac_addresses: Vec<String>,
        exclude_mac_addresses: Vec<String>,
        exclude_mptcp: bool,
        tag: String,
        router: Arc<Router>,
        outbounds: Arc<OutboundManager>,
        network_namespace: &str,
    ) -> io::Result<Self> {
        let listen: SocketAddr =
            if tun_networks.iter().any(|network| network.addr().is_ipv6()) {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            }
            .parse()
            .expect("static auto-redirect listen address");
        let namespace = network_namespace.to_owned();
        let listener = with_network_namespace(&namespace, move || {
            let listener = std::net::TcpListener::bind(listen)?;
            listener.set_nonblocking(true)?;
            Ok(listener)
        })
        .await?;
        let listener = TcpListener::from_std(listener)?;
        let redirect_port = listener.local_addr()?.port();
        let mut local_networks =
            system_local_networks_in(network_namespace).await?;
        local_networks.extend_from_slice(tun_networks);
        local_networks = IpNet::aggregate(&local_networks);
        let enable_ipv4 =
            tun_networks.iter().any(|network| network.addr().is_ipv4());
        let enable_ipv6 =
            tun_networks.iter().any(|network| network.addr().is_ipv6());
        let monitor_table = table.clone();
        let monitor_interface = interface.clone();

        let mut nfqueue = match NfQueueLease::start(
            nfqueue_number,
            output_mark_value,
            reset_mark,
            tag.clone(),
            router.clone(),
            network_namespace,
        )
        .await
        {
            Ok(lease) => Some(lease),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "NFQUEUE unavailable; TUN auto-redirect pre-match disabled"
                );
                None
            }
        };
        let mut output_mark = if network_namespace.is_empty() {
            match AutoRedirectMarkLease::register(output_mark_value) {
                Ok(lease) => Some(lease),
                Err(error) => {
                    if let Some(mut queue) = nfqueue.take() {
                        let _ = queue.close().await;
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        let nft_config = AutoRedirectNftConfig {
            table,
            interface,
            redirect_port,
            input_mark,
            output_mark: output_mark_value,
            reset_mark,
            nfqueue: nfqueue.as_ref().map(|_| nfqueue_number),
            enable_ipv4,
            enable_ipv6,
            routes,
            local_networks: local_networks.clone(),
            include_uids,
            exclude_uids,
            include_interfaces,
            exclude_interfaces,
            include_mac_addresses,
            exclude_mac_addresses,
            exclude_mptcp,
        };
        let mut nftables =
            match NftablesLease::install(nft_config.clone(), network_namespace)
                .await
            {
                Ok(lease) => lease,
                Err(error) => {
                    if let Some(mark) = output_mark.as_mut() {
                        mark.close();
                    }
                    if let Some(mut queue) = nfqueue.take() {
                        let _ = queue.close().await;
                    }
                    return Err(error);
                }
            };
        let openwrt = if network_namespace.is_empty() {
            match OpenWrtLease::install(&monitor_table, &monitor_interface)
                .await
            {
                Ok(lease) => lease,
                Err(error) => {
                    let _ = nftables.close().await;
                    if let Some(mark) = output_mark.as_mut() {
                        mark.close();
                    }
                    if let Some(mut queue) = nfqueue.take() {
                        let _ = queue.close().await;
                    }
                    return Err(error);
                }
            }
        } else {
            OpenWrtLease::disabled()
        };
        let docker = DockerFirewallConfig {
            interface: monitor_interface,
            enable_ipv4,
            enable_ipv6,
            network_namespace: network_namespace.to_owned(),
        };
        let initial_docker = docker.clone();
        match reconcile_docker_firewall(initial_docker, false).await {
            Ok(()) => {}
            Err(error) => {
                tracing::warn!(%error, "configure Docker firewall compatibility");
            }
        }
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(accept_loop(
            listener,
            cancellation.clone(),
            tag,
            router,
            outbounds,
        ));
        let network_task = Some(tokio::spawn(monitor_local_networks(
            monitor_table,
            enable_ipv4,
            enable_ipv6,
            tun_networks.to_vec(),
            local_networks,
            cancellation.clone(),
            network_namespace.to_owned(),
        )));
        let docker_task = Some(tokio::spawn(monitor_docker_firewall(
            docker.clone(),
            cancellation.clone(),
        )));
        Ok(Self {
            nfqueue,
            nftables,
            openwrt,
            output_mark,
            cancellation,
            task: Some(task),
            network_task,
            docker_task,
            docker,
            nft_config,
            tun_networks: tun_networks.to_vec(),
        })
    }

    /// Atomically replace the route-dependent nftables rules after a dynamic
    /// rule-set update. Local interface networks are sampled again so a route
    /// refresh cannot resurrect stale bypass-set elements.
    pub(crate) async fn update_routes(
        &mut self,
        routes: Vec<IpNet>,
    ) -> io::Result<()> {
        if self.nft_config.routes == routes {
            return Ok(());
        }
        let mut local_networks =
            system_local_networks_in(&self.nftables.network_namespace).await?;
        local_networks.extend_from_slice(&self.tun_networks);
        let mut next = self.nft_config.clone();
        next.routes = routes;
        next.local_networks = IpNet::aggregate(&local_networks);
        self.nftables.replace(&next).await?;
        self.nft_config = next;
        Ok(())
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        let mut failures = Vec::new();
        if let Some(mut nfqueue) = self.nfqueue.take()
            && let Err(error) = nfqueue.close().await
        {
            failures.push(format!("close auto-redirect NFQUEUE: {error}"));
        }
        self.cancellation.cancel();
        if let Some(task) = self.network_task.take()
            && let Err(error) = task.await
            && !error.is_cancelled()
        {
            failures
                .push(format!("stop auto-redirect network monitor: {error}"));
        }
        if let Some(task) = self.docker_task.take()
            && let Err(error) = task.await
            && !error.is_cancelled()
        {
            failures.push(format!("stop Docker firewall monitor: {error}"));
        }
        if let Some(task) = self.task.take() {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(error.to_string()),
                Err(error) if error.is_cancelled() => {}
                Err(error) => failures.push(error.to_string()),
            }
        }
        if let Err(error) = self.nftables.close().await {
            failures.push(format!("remove auto-redirect nftables: {error}"));
        }
        if let Err(error) = self.openwrt.close().await {
            failures.push(format!("remove OpenWrt fw4 compatibility: {error}"));
        }
        match reconcile_docker_firewall(self.docker.clone(), true).await {
            Ok(()) => {}
            Err(error) => failures
                .push(format!("remove Docker firewall compatibility: {error}")),
        }
        if let Some(mut output_mark) = self.output_mark.take() {
            output_mark.close();
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    cancellation: CancellationToken,
    tag: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, source) = accepted?;
                let tag = tag.clone();
                let router = router.clone();
                let outbounds = outbounds.clone();
                connections.spawn(async move {
                    let destination = original_destination(&stream)?;
                    super::redirect::handle_connection(
                        stream,
                        source,
                        destination.into(),
                        &tag,
                        &router,
                        &outbounds,
                    )
                    .await
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn monitor_local_networks(
    table: String,
    enable_ipv4: bool,
    enable_ipv6: bool,
    tun_networks: Vec<IpNet>,
    mut current: Vec<IpNet>,
    cancellation: CancellationToken,
    network_namespace: String,
) {
    let monitor = if network_namespace.is_empty() {
        match crate::common::network_monitor::NetworkMonitor::new().await {
            Ok(monitor) => Some(monitor),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "network monitor unavailable; auto-redirect local address set will not refresh"
                );
                return;
            }
        }
    } else {
        None
    };
    let mut watcher = monitor.as_ref().map(|monitor| monitor.interface_state());
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        let triggered = tokio::select! {
            _ = cancellation.cancelled() => return,
            triggered = async {
                if let Some(watcher) = watcher.as_mut() {
                    watcher.updated().await.is_ok()
                } else {
                    interval.tick().await;
                    true
                }
            } => triggered,
        };
        if !triggered {
            return;
        }
        let mut networks = match system_local_networks_in(&network_namespace)
            .await
        {
            Ok(networks) => networks,
            Err(error) => {
                tracing::warn!(%error, "refresh auto-redirect local addresses");
                continue;
            }
        };
        networks.extend_from_slice(&tun_networks);
        let networks = IpNet::aggregate(&networks);
        if networks == current {
            continue;
        }
        let sets = local_address_sets(enable_ipv4, enable_ipv6, &networks);
        let update_table = table.clone();
        let namespace = network_namespace.clone();
        match with_network_namespace(&namespace, move || {
            update_set_elements_sync(&update_table, &sets)
        })
        .await
        {
            Ok(()) => current = networks,
            Err(error) => {
                tracing::warn!(%error, "update auto-redirect local address set");
            }
        }
    }
}

async fn monitor_docker_firewall(
    config: DockerFirewallConfig,
    cancellation: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = interval.tick() => {}
        }
        match reconcile_docker_firewall(config.clone(), false).await {
            Ok(()) => {}
            Err(error) => {
                tracing::warn!(%error, "update Docker firewall compatibility");
            }
        }
    }
}

async fn system_local_networks_in(
    network_namespace: &str,
) -> io::Result<Vec<IpNet>> {
    let namespace = network_namespace.to_owned();
    with_network_namespace(&namespace, system_local_networks).await
}

async fn reconcile_docker_firewall(
    config: DockerFirewallConfig,
    cleanup: bool,
) -> io::Result<()> {
    let namespace = config.network_namespace.clone();
    with_network_namespace(&namespace, move || {
        reconcile_docker_firewall_sync(&config, cleanup)
    })
    .await
}

fn system_local_networks() -> io::Result<Vec<IpNet>> {
    let interfaces = NetworkInterface::show().map_err(io::Error::other)?;
    let mut networks = Vec::new();
    for interface in interfaces {
        for address in interface.addr {
            match address {
                InterfaceAddr::V4(address)
                    if interface.internal
                        || global_unicast(IpAddr::V4(address.ip)) =>
                {
                    let prefix = address
                        .netmask
                        .map_or(32, |mask| u32::from(mask).count_ones() as u8);
                    networks.push(
                        IpNet::new(address.ip.into(), prefix)
                            .map_err(|error| invalid(error.to_string()))?,
                    );
                }
                InterfaceAddr::V6(address)
                    if interface.internal
                        || global_unicast(IpAddr::V6(address.ip)) =>
                {
                    let prefix = address.netmask.map_or(128, |mask| {
                        u128::from(mask).count_ones() as u8
                    });
                    networks.push(
                        IpNet::new(address.ip.into(), prefix)
                            .map_err(|error| invalid(error.to_string()))?,
                    );
                }
                _ => {}
            }
        }
    }
    Ok(networks)
}

fn global_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_link_local()
                && address != std::net::Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

impl NftablesLease {
    pub(crate) async fn install(
        config: AutoRedirectNftConfig,
        network_namespace: &str,
    ) -> io::Result<Self> {
        let table = config.table.clone();
        let plan = config.plan()?;
        let install_table = table.clone();
        let namespace = network_namespace.to_owned();
        with_network_namespace(&namespace, move || {
            delete_table_sync(&install_table).ok();
            install_table_sync(&install_table, &plan)
        })
        .await?;
        Ok(Self {
            table: Some(table),
            network_namespace: network_namespace.to_owned(),
        })
    }

    async fn replace(
        &mut self,
        config: &AutoRedirectNftConfig,
    ) -> io::Result<()> {
        let Some(table) = self.table.as_deref() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "auto-redirect nftables lease is closed",
            ));
        };
        if config.table != table {
            return Err(invalid("cannot rename an active nftables lease"));
        }
        let plan = config.plan()?;
        let table = table.to_owned();
        let namespace = self.network_namespace.clone();
        with_network_namespace(&namespace, move || {
            replace_table_sync(&table, &plan)
        })
        .await
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        let Some(table) = self.table.take() else {
            return Ok(());
        };
        let namespace = self.network_namespace.clone();
        with_network_namespace(&namespace, move || delete_table_sync(&table))
            .await
    }
}

impl OpenWrtLease {
    fn disabled() -> Self {
        Self {
            rule_path: None,
            fw4_path: None,
        }
    }

    async fn install(table: &str, interface: &str) -> io::Result<Self> {
        let has_fw4 = tokio::task::spawn_blocking(|| {
            nft_table_exists_sync("fw4", NFPROTO_INET)
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))??;
        let Some(fw4_path) = has_fw4.then(find_fw4_path).flatten() else {
            return Ok(Self {
                rule_path: None,
                fw4_path: None,
            });
        };
        let rule_path = PathBuf::from(format!(
            "/etc/nftables.d/0-{table}-auto-redirect.nft"
        ));
        let contents = openwrt_rules(table, interface);
        let write_path = rule_path.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::write(write_path, contents)
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))??;
        if let Err(error) = reload_fw4(&fw4_path).await {
            let cleanup_path = rule_path.clone();
            let _ = tokio::task::spawn_blocking(move || {
                std::fs::remove_file(cleanup_path)
            })
            .await;
            let _ = reload_fw4(&fw4_path).await;
            return Err(error);
        }
        Ok(Self {
            rule_path: Some(rule_path),
            fw4_path: Some(fw4_path),
        })
    }

    async fn close(&mut self) -> io::Result<()> {
        let (Some(rule_path), Some(fw4_path)) =
            (self.rule_path.take(), self.fw4_path.take())
        else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || {
            match std::fs::remove_file(rule_path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))??;
        reload_fw4(&fw4_path).await
    }
}

fn find_fw4_path() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("fw4"))
        .find(|candidate| {
            candidate.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

fn openwrt_rules(table: &str, interface: &str) -> Vec<u8> {
    let table = nft_string(table);
    let interface = nft_string(interface);
    format!(
        "chain input {{\n\
         \ttype filter hook input priority filter; policy accept;\n\
         \tiifname \"{interface}\" counter accept comment \"!{table}: Accept traffic from tun\"\n\
         \toifname \"{interface}\" counter accept comment \"!{table}: Accept traffic from tun\"\n\
         }}\n\
         chain forward {{\n\
         \ttype filter hook forward priority filter; policy accept;\n\
         \tiifname \"{interface}\" counter accept comment \"!{table}: Accept traffic from tun\"\n\
         \toifname \"{interface}\" counter accept comment \"!{table}: Accept traffic from tun\"\n\
         }}\n"
    )
    .into_bytes()
}

fn nft_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn reload_fw4(path: &Path) -> io::Result<()> {
    let output = Command::new(path)
        .arg("reload")
        .kill_on_drop(true)
        .output()
        .await?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "fw4 reload failed with {}{}",
        output.status,
        if detail.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", detail.trim())
        }
    )))
}

fn nft_table_exists_sync(table: &str, family: u8) -> io::Result<bool> {
    let mut socket = NetlinkSocket::new();
    let header = Nfgenmsg {
        nfgen_family: family,
        ..Nfgenmsg::new()
    };
    let mut request = nftables::Request::new().op_gettable_do(&header);
    request.encode().push_name_bytes(table.as_bytes());
    let mut replies = socket.request(&request).map_err(io::Error::from)?;
    match replies.recv_one() {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.as_io_error().raw_os_error(),
                Some(libc::ENOENT | libc::ESRCH)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(io::Error::from(error)),
    }
}

fn reconcile_docker_firewall_sync(
    config: &DockerFirewallConfig,
    cleanup: bool,
) -> io::Result<()> {
    let mut failures = Vec::new();
    for (enabled, family) in [
        (config.enable_ipv4, NFPROTO_IPV4),
        (config.enable_ipv6, NFPROTO_IPV6),
    ] {
        if !enabled {
            continue;
        }
        if let Err(error) =
            reconcile_docker_family_sync(family, &config.interface, cleanup)
        {
            failures.push(error.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")))
    }
}

fn reconcile_docker_family_sync(
    family: u8,
    interface: &str,
    cleanup: bool,
) -> io::Result<()> {
    let mut socket = NetlinkSocket::new();
    if !nft_chain_exists_sync(
        &mut socket,
        family,
        DOCKER_FILTER_TABLE,
        DOCKER_USER_CHAIN,
    )? {
        return Ok(());
    }
    let rules = docker_rules_sync(
        &mut socket,
        family,
        DOCKER_FILTER_TABLE,
        DOCKER_USER_CHAIN,
    )?;
    let output_comment = docker_comment("output to tun");
    let input_comment = docker_comment("input from tun");
    let owned = rules
        .iter()
        .filter(|rule| {
            rule.comment.as_deref() == Some(output_comment.as_str())
                || rule.comment.as_deref() == Some(input_comment.as_str())
        })
        .collect::<Vec<_>>();
    if cleanup && owned.is_empty() {
        return Ok(());
    }
    if !cleanup
        && owned.len() == 2
        && owned
            .iter()
            .filter(|rule| {
                rule.comment.as_deref() == Some(output_comment.as_str())
            })
            .count()
            == 1
        && owned
            .iter()
            .filter(|rule| {
                rule.comment.as_deref() == Some(input_comment.as_str())
            })
            .count()
            == 1
    {
        return Ok(());
    }

    let generation = latest_generation(&mut socket)?;
    let mut transaction = nftables::Chained::new(socket.reserve_seq(32));
    transaction
        .request()
        .op_batch_begin_do(&batch_header())
        .encode()
        .push_genid(generation);
    let header = Nfgenmsg {
        nfgen_family: family,
        ..Nfgenmsg::new()
    };
    for rule in &owned {
        transaction
            .request()
            .op_delrule_do(&header)
            .encode()
            .push_table_bytes(DOCKER_FILTER_TABLE.as_bytes())
            .push_chain_bytes(DOCKER_USER_CHAIN.as_bytes())
            .push_handle(rule.handle);
    }
    if !cleanup {
        let position = rules
            .iter()
            .find(|rule| !owned.iter().any(|owned| owned.handle == rule.handle))
            .map(|rule| rule.handle);
        append_docker_rule(
            &mut transaction,
            &header,
            interface,
            MetaKey::Oifname,
            &output_comment,
            position,
        );
        append_docker_rule(
            &mut transaction,
            &header,
            interface,
            MetaKey::Iifname,
            &input_comment,
            position,
        );
    }
    transaction.request().op_batch_end_do(&batch_header());
    socket
        .request_chained(&transaction.finalize())
        .map_err(io::Error::from)?
        .recv_all()
        .map_err(io::Error::from)
}

fn nft_chain_exists_sync(
    socket: &mut NetlinkSocket,
    family: u8,
    table: &str,
    chain: &str,
) -> io::Result<bool> {
    let header = Nfgenmsg {
        nfgen_family: family,
        ..Nfgenmsg::new()
    };
    let mut request = nftables::Request::new().op_getchain_do(&header);
    request
        .encode()
        .push_table_bytes(table.as_bytes())
        .push_name_bytes(chain.as_bytes());
    let mut replies = socket.request(&request).map_err(io::Error::from)?;
    match replies.recv_one() {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.as_io_error().raw_os_error(),
                Some(libc::ENOENT | libc::ESRCH)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(io::Error::from(error)),
    }
}

fn docker_rules_sync(
    socket: &mut NetlinkSocket,
    family: u8,
    table: &str,
    chain: &str,
) -> io::Result<Vec<DockerRuleInfo>> {
    let header = Nfgenmsg {
        nfgen_family: family,
        ..Nfgenmsg::new()
    };
    let mut request = nftables::Request::new().op_getrule_dump(&header);
    request
        .encode()
        .push_table_bytes(table.as_bytes())
        .push_chain_bytes(chain.as_bytes());
    let mut replies = socket.request(&request).map_err(io::Error::from)?;
    let mut rules = Vec::new();
    while let Some((_, attributes)) =
        replies.recv().transpose().map_err(io::Error::from)?
    {
        rules.push(DockerRuleInfo {
            handle: attributes.get_handle().map_err(io::Error::other)?,
            comment: attributes.get_userdata().ok().and_then(parse_nft_comment),
        });
    }
    Ok(rules)
}

fn append_docker_rule(
    transaction: &mut nftables::Chained<'static>,
    header: &Nfgenmsg,
    interface: &str,
    key: MetaKey,
    comment: &str,
    position: Option<u64>,
) {
    let mut request = transaction.request();
    if position.is_none() {
        request = request.set_append();
    }
    let mut operation = request.set_create().op_newrule_do(header);
    let mut attributes = operation
        .encode()
        .push_table_bytes(DOCKER_FILTER_TABLE.as_bytes())
        .push_chain_bytes(DOCKER_USER_CHAIN.as_bytes());
    if let Some(position) = position {
        attributes = attributes.push_position(position);
    }
    let userdata = nft_comment_userdata(comment);
    let mut expressions =
        attributes.push_userdata(&userdata).nested_expressions();
    for expression in [
        Expression::MetaLoad(key),
        Expression::Compare {
            operation: CompareOp::Eq,
            data: interface_key(interface),
        },
        Expression::Counter,
        Expression::Accept,
    ] {
        expressions = encode_expression(expressions, &expression);
    }
    expressions.end_nested();
}

fn docker_comment(kind: &str) -> String {
    format!("!sing-box: {kind}")
}

fn nft_comment_userdata(comment: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(comment.len() + 3);
    data.push(0);
    data.push((comment.len() + 1) as u8);
    data.extend_from_slice(comment.as_bytes());
    data.push(0);
    data
}

fn parse_nft_comment(userdata: &[u8]) -> Option<String> {
    let (&kind, rest) = userdata.split_first()?;
    let (&length, rest) = rest.split_first()?;
    if kind != 0 || length == 0 || rest.len() < usize::from(length) {
        return None;
    }
    let value = &rest[..usize::from(length)];
    let value = value.strip_suffix(&[0]).unwrap_or(value);
    std::str::from_utf8(value).ok().map(str::to_owned)
}

fn update_set_elements_sync(table: &str, sets: &[SetPlan]) -> io::Result<()> {
    let mut socket = NetlinkSocket::new();
    let generation = latest_generation(&mut socket)?;
    let mut transaction = nftables::Chained::new(socket.reserve_seq(64));
    transaction
        .request()
        .op_batch_begin_do(&batch_header())
        .encode()
        .push_genid(generation);
    for set in sets {
        transaction
            .request()
            .op_delsetelem_do(&message_header())
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_set_bytes(set.name.as_bytes());
        append_set_elements(&mut transaction, table, set);
    }
    transaction.request().op_batch_end_do(&batch_header());
    socket
        .request_chained(&transaction.finalize())
        .map_err(io::Error::other)?
        .recv_all()
        .map_err(io::Error::other)
}

fn install_table_sync(table: &str, plan: &NftPlan) -> io::Result<()> {
    let mut socket = NetlinkSocket::new();
    let generation = latest_generation(&mut socket)?;
    let mut transaction = nftables::Chained::new(socket.reserve_seq(4096));
    transaction
        .request()
        .op_batch_begin_do(&batch_header())
        .encode()
        .push_genid(generation);
    append_table(&mut transaction, table, plan);
    transaction.request().op_batch_end_do(&batch_header());
    socket
        .request_chained(&transaction.finalize())
        .map_err(io::Error::other)?
        .recv_all()
        .map_err(io::Error::other)
}

fn replace_table_sync(table: &str, plan: &NftPlan) -> io::Result<()> {
    let mut socket = NetlinkSocket::new();
    let generation = latest_generation(&mut socket)?;
    let mut transaction = nftables::Chained::new(socket.reserve_seq(4096));
    transaction
        .request()
        .op_batch_begin_do(&batch_header())
        .encode()
        .push_genid(generation);
    transaction
        .request()
        .op_deltable_do(&message_header())
        .encode()
        .push_name_bytes(table.as_bytes());
    append_table(&mut transaction, table, plan);
    transaction.request().op_batch_end_do(&batch_header());
    socket
        .request_chained(&transaction.finalize())
        .map_err(io::Error::other)?
        .recv_all()
        .map_err(io::Error::other)
}

fn append_table(
    transaction: &mut nftables::Chained<'static>,
    table: &str,
    plan: &NftPlan,
) {
    transaction
        .request()
        .set_create()
        .op_newtable_do(&message_header())
        .encode()
        .push_name_bytes(table.as_bytes());
    for set in &plan.sets {
        append_set(transaction, table, set);
    }
    for chain in &plan.chains {
        transaction
            .request()
            .set_create()
            .op_newchain_do(&message_header())
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_name_bytes(chain.name.as_bytes())
            .nested_hook()
            .push_num(chain.hook)
            .push_priority(chain.priority)
            .end_nested()
            .push_type_bytes(chain.chain_type.name());
        for rule in &chain.rules {
            append_rule(transaction, table, chain.name, rule);
        }
    }
}

fn append_set(
    transaction: &mut nftables::Chained<'static>,
    table: &str,
    set: &SetPlan,
) {
    let header = message_header();
    let mut flags = if set.constant {
        SetFlags::Constant as u32
    } else {
        0
    };
    if set.interval {
        flags |= SetFlags::Interval as u32;
    }
    let mut operation =
        transaction.request().set_create().op_newset_do(&header);
    let mut attributes = operation
        .encode()
        .push_table_bytes(table.as_bytes())
        .push_name_bytes(set.name.as_bytes())
        .push_flags(flags)
        .push_key_type(set.key_type)
        .push_key_len(set.key_len);
    attributes = attributes
        .nested_desc()
        .push_size(set.elements.len() as u32)
        .end_nested();
    drop(attributes);

    append_set_elements(transaction, table, set);
}

fn append_set_elements(
    transaction: &mut nftables::Chained<'static>,
    table: &str,
    set: &SetPlan,
) {
    if set.elements.is_empty() {
        return;
    }
    let header = message_header();
    let mut operation =
        transaction.request().set_create().op_newsetelem_do(&header);
    let mut elements = operation
        .encode()
        .push_table_bytes(table.as_bytes())
        .push_set_bytes(set.name.as_bytes())
        .nested_elements();
    for element in &set.elements {
        let item = elements
            .nested_elem()
            .nested_key()
            .push_value(&element.key)
            .end_nested();
        let item = if element.interval_end {
            item.push_flags(&(SetElemFlags::IntervalEnd as u32).to_be_bytes())
        } else {
            item
        };
        elements = item.end_nested();
    }
    elements.end_nested();
}

fn delete_table_sync(table: &str) -> io::Result<()> {
    if !nft_table_exists_sync(table, NFPROTO_INET)? {
        return Ok(());
    }
    let mut socket = NetlinkSocket::new();
    let generation = latest_generation(&mut socket)?;
    let mut transaction = nftables::Chained::new(socket.reserve_seq(16));
    transaction
        .request()
        .op_batch_begin_do(&batch_header())
        .encode()
        .push_genid(generation);
    transaction
        .request()
        .op_deltable_do(&message_header())
        .encode()
        .push_name_bytes(table.as_bytes());
    transaction.request().op_batch_end_do(&batch_header());
    let request = transaction.finalize();
    let mut replies =
        socket.request_chained(&request).map_err(io::Error::other)?;
    match replies.recv_all() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.as_io_error().raw_os_error(),
                Some(libc::ENOENT | libc::ESRCH)
            ) =>
        {
            // Another manager may have removed the table between the
            // existence probe and this generation-protected transaction.
            Ok(())
        }
        Err(error) => Err(io::Error::other(error)),
    }
}

fn latest_generation(socket: &mut NetlinkSocket) -> io::Result<u32> {
    let request = nftables::Request::new().op_getgen_do(&Nfgenmsg::new());
    let mut replies = socket.request(&request).map_err(io::Error::other)?;
    let (_, attributes) = replies.recv_one().map_err(io::Error::other)?;
    attributes.get_id().map_err(io::Error::other)
}

type PushExpressions<'a> = PushExprListAttrs<PushRuleAttrs<&'a mut Vec<u8>>>;

fn append_rule(
    transaction: &mut nftables::Chained<'static>,
    table: &str,
    chain: &str,
    expressions: &[Expression],
) {
    let header = message_header();
    let mut operation = transaction
        .request()
        .set_create()
        .set_append()
        .op_newrule_do(&header);
    let mut encoder = operation
        .encode()
        .push_table_bytes(table.as_bytes())
        .push_chain_bytes(chain.as_bytes())
        .nested_expressions();
    for expression in expressions {
        encoder = encode_expression(encoder, expression);
    }
    encoder.end_nested();
}

fn encode_expression<'a>(
    encoder: PushExpressions<'a>,
    expression: &Expression,
) -> PushExpressions<'a> {
    let register = Registers::Reg1 as u32;
    match expression {
        Expression::MetaLoad(key) => encoder
            .nested_elem()
            .nested_data_meta()
            .push_dreg(register)
            .push_key(*key as u32)
            .end_nested()
            .end_nested(),
        Expression::MetaStore(key) => encoder
            .nested_elem()
            .nested_data_meta()
            .push_key(*key as u32)
            .push_sreg(register)
            .end_nested()
            .end_nested(),
        Expression::CtLoad(key) => encoder
            .nested_elem()
            .nested_data_ct()
            .push_dreg(register)
            .push_key(*key as u32)
            .end_nested()
            .end_nested(),
        Expression::CtStore(key) => encoder
            .nested_elem()
            .nested_data_ct()
            .push_key(*key as u32)
            .push_sreg(register)
            .end_nested()
            .end_nested(),
        Expression::PayloadLoad {
            base,
            offset,
            length,
        } => encoder
            .nested_elem()
            .nested_data_payload()
            .push_dreg(register)
            .push_base(*base as u32)
            .push_offset(*offset)
            .push_len(*length)
            .end_nested()
            .end_nested(),
        Expression::BitwiseMask(mask) => encoder
            .nested_elem()
            .nested_data_bitwise()
            .push_sreg(register)
            .push_dreg(register)
            .push_len(mask.len() as u32)
            .push_op(BitwiseOps::MaskXor as u32)
            .nested_mask()
            .push_value(mask)
            .end_nested()
            .nested_xor()
            .push_value(&vec![0; mask.len()])
            .end_nested()
            .end_nested()
            .end_nested(),
        Expression::Compare { operation, data } => encoder
            .nested_elem()
            .nested_data_cmp()
            .push_sreg(register)
            .push_op(*operation as u32)
            .nested_data()
            .push_value(data)
            .end_nested()
            .end_nested()
            .end_nested(),
        Expression::Immediate(data) => encoder
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(register)
            .nested_data()
            .push_value(data)
            .end_nested()
            .end_nested()
            .end_nested(),
        Expression::Counter => encoder
            .nested_elem()
            .nested_data_counter()
            .end_nested()
            .end_nested(),
        Expression::Return => encoder
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(Registers::RegVerdict as u32)
            .nested_data()
            .nested_verdict()
            .push_code(VerdictCode::Return as u32)
            .end_nested()
            .end_nested()
            .end_nested()
            .end_nested(),
        Expression::Accept => encoder
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(Registers::RegVerdict as u32)
            .nested_data()
            .nested_verdict()
            .push_code(VerdictCode::Accept as u32)
            .end_nested()
            .end_nested()
            .end_nested()
            .end_nested(),
        Expression::Drop => encoder
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(Registers::RegVerdict as u32)
            .nested_data()
            .nested_verdict()
            .push_code(VerdictCode::Drop as u32)
            .end_nested()
            .end_nested()
            .end_nested()
            .end_nested(),
        Expression::RejectTcpReset => encoder
            .nested_elem()
            .nested_data_reject()
            .push_type(RejectTypes::TcpRst as u32)
            .end_nested()
            .end_nested(),
        Expression::Redirect => encode_redirect(encoder),
        Expression::Masquerade => encode_masquerade(encoder),
        Expression::FullCone => encode_empty_expression(encoder, b"fullcone"),
        Expression::TcpOptionPresent(kind) => {
            encode_tcp_option_present(encoder, *kind)
        }
        Expression::TcpOptionLoad {
            kind,
            offset,
            length,
        } => encode_tcp_option_access(encoder, false, *kind, *offset, *length),
        Expression::TcpOptionStore {
            kind,
            offset,
            length,
        } => encode_tcp_option_access(encoder, true, *kind, *offset, *length),
        Expression::Queue { number, bypass } => {
            encode_queue(encoder, *number, *bypass)
        }
        Expression::Lookup { set, invert } => {
            let expression = encoder
                .nested_elem()
                .nested_data_lookup()
                .push_set_bytes(set.as_bytes())
                .push_sreg(register);
            if *invert {
                expression
                    .push_flags(LookupFlags::Invert as u32)
                    .end_nested()
                    .end_nested()
            } else {
                expression.end_nested().end_nested()
            }
        }
    }
}

fn encode_queue(
    encoder: PushExpressions<'_>,
    number: u16,
    bypass: bool,
) -> PushExpressions<'_> {
    let mut expression = encoder.nested_elem().push_name_bytes(b"queue");
    let data = utils::push_nested_header(expression.as_vec_mut(), 2);
    utils::push_header(expression.as_vec_mut(), 1, 2);
    expression.as_vec_mut().extend(number.to_be_bytes());
    if bypass {
        utils::push_header(expression.as_vec_mut(), 3, 2);
        expression
            .as_vec_mut()
            .extend(NFT_QUEUE_FLAG_BYPASS.to_be_bytes());
    }
    utils::finalize_nested_header(expression.as_vec_mut(), data);
    expression.end_nested()
}

fn encode_tcp_option_present(
    encoder: PushExpressions<'_>,
    kind: u32,
) -> PushExpressions<'_> {
    let mut expression = encoder.nested_elem().push_name_bytes(b"exthdr");
    let data = utils::push_nested_header(expression.as_vec_mut(), 2);
    for (attribute, value) in [
        (1, Registers::Reg1 as u32),
        (2, kind),
        (3, 0),
        (4, 1),
        (5, NFT_EXTHDR_F_PRESENT),
        (6, NFT_EXTHDR_OP_TCPOPT),
    ] {
        utils::push_header(expression.as_vec_mut(), attribute, 4);
        expression.as_vec_mut().extend(value.to_be_bytes());
    }
    utils::finalize_nested_header(expression.as_vec_mut(), data);
    expression.end_nested()
}

fn encode_tcp_option_access(
    encoder: PushExpressions<'_>,
    store: bool,
    kind: u32,
    offset: u32,
    length: u32,
) -> PushExpressions<'_> {
    let mut expression = encoder.nested_elem().push_name_bytes(b"exthdr");
    let data = utils::push_nested_header(expression.as_vec_mut(), 2);
    let register_attribute = if store { 7 } else { 1 };
    for (attribute, value) in [
        (register_attribute, Registers::Reg1 as u32),
        (2, kind),
        (3, offset),
        (4, length),
        (6, NFT_EXTHDR_OP_TCPOPT),
    ] {
        utils::push_header(expression.as_vec_mut(), attribute, 4);
        expression.as_vec_mut().extend(value.to_be_bytes());
    }
    utils::finalize_nested_header(expression.as_vec_mut(), data);
    expression.end_nested()
}

fn encode_redirect(encoder: PushExpressions<'_>) -> PushExpressions<'_> {
    let mut expression = encoder.nested_elem().push_name_bytes(b"redir");
    let data = utils::push_nested_header(expression.as_vec_mut(), 2);
    utils::push_header(expression.as_vec_mut(), 1, 4);
    expression
        .as_vec_mut()
        .extend((Registers::Reg1 as u32).to_be_bytes());
    utils::push_header(expression.as_vec_mut(), 3, 4);
    expression
        .as_vec_mut()
        .extend(NF_NAT_RANGE_PROTO_SPECIFIED.to_be_bytes());
    utils::finalize_nested_header(expression.as_vec_mut(), data);
    expression.end_nested()
}

fn encode_masquerade(encoder: PushExpressions<'_>) -> PushExpressions<'_> {
    encode_empty_expression(encoder, b"masq")
}

fn encode_empty_expression<'a>(
    encoder: PushExpressions<'a>,
    name: &[u8],
) -> PushExpressions<'a> {
    let mut expression = encoder.nested_elem().push_name_bytes(name);
    let data = utils::push_nested_header(expression.as_vec_mut(), 2);
    utils::finalize_nested_header(expression.as_vec_mut(), data);
    expression.end_nested()
}

fn batch_header() -> Nfgenmsg {
    let mut header = Nfgenmsg::new();
    header.set_res_id(10);
    header
}

fn message_header() -> Nfgenmsg {
    Nfgenmsg {
        nfgen_family: NFPROTO_INET,
        ..Nfgenmsg::new()
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AutoRedirectNftConfig {
        AutoRedirectNftConfig {
            table: "sing-box".into(),
            interface: "tun0".into(),
            redirect_port: 12345,
            input_mark: 0x2023,
            output_mark: 0x2024,
            reset_mark: 0x2025,
            nfqueue: None,
            enable_ipv4: true,
            enable_ipv6: true,
            routes: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            local_networks: vec![
                "127.0.0.0/8".parse().unwrap(),
                "::1/128".parse().unwrap(),
            ],
            include_uids: Vec::new(),
            exclude_uids: Vec::new(),
            include_interfaces: Vec::new(),
            exclude_interfaces: Vec::new(),
            include_mac_addresses: Vec::new(),
            exclude_mac_addresses: Vec::new(),
            exclude_mptcp: false,
        }
    }

    #[test]
    fn default_plan_has_upstream_base_chain_order_and_priorities() {
        let plan = config().plan().unwrap();
        assert_eq!(
            plan.chains
                .iter()
                .map(|chain| chain.name)
                .collect::<Vec<_>>(),
            [
                "output",
                "output_udp_icmp",
                "input",
                "prerouting",
                "prerouting_udp_icmp"
            ]
        );
        assert_eq!(plan.chains[0].priority, -150);
        assert_eq!(plan.chains[3].priority, -99);
        assert_eq!(plan.chains[4].priority, -98);
    }

    #[test]
    fn bridge_plan_clamps_only_oversized_syn_mss_for_active_families() {
        let plan = bridge_nft_plan("bridge0", true, true, 1500, false);
        assert_eq!(plan.chains[0].name, "postrouting");
        assert!(plan.chains[0].rules[0].contains(&Expression::Masquerade));
        let forward = &plan.chains[1];
        assert_eq!(forward.name, "forward");
        assert_eq!(forward.rules.len(), 2);
        for (rule, clamp) in forward
            .rules
            .iter()
            .zip([1460u16.to_be_bytes(), 1440u16.to_be_bytes()])
        {
            assert!(rule.contains(&Expression::Compare {
                operation: CompareOp::Gt,
                data: clamp.to_vec(),
            }));
            assert!(rule.contains(&Expression::TcpOptionLoad {
                kind: 2,
                offset: 2,
                length: 2,
            }));
            assert!(rule.contains(&Expression::TcpOptionStore {
                kind: 2,
                offset: 2,
                length: 2,
            }));
        }
    }

    #[test]
    fn nfqueue_plan_adds_prematch_chains_and_shifts_redirect_priorities() {
        let mut config = config();
        config.nfqueue = Some(8123);
        let plan = config.plan().unwrap();
        assert!(
            plan.sets
                .iter()
                .any(|set| set.name == SET_PREMATCH_PROTOCOL)
        );
        assert_eq!(
            plan.chains
                .iter()
                .map(|chain| (chain.name, chain.priority))
                .collect::<Vec<_>>(),
            [
                ("prerouting_prematch", -101),
                ("output_prematch", -149),
                ("output", -148),
                ("output_udp_icmp", -148),
                ("input", 0),
                ("prerouting", -98),
                ("prerouting_udp_icmp", -97),
            ]
        );
        for name in ["prerouting_prematch", "output_prematch"] {
            let chain =
                plan.chains.iter().find(|chain| chain.name == name).unwrap();
            assert_eq!(
                chain
                    .rules
                    .iter()
                    .filter(|rule| rule.iter().any(|expression| {
                        matches!(
                            expression,
                            Expression::Queue {
                                number: 8123,
                                bypass: true
                            }
                        )
                    }))
                    .count(),
                4
            );
            assert!(chain.rules.iter().any(|rule| {
                rule.contains(&Expression::RejectTcpReset)
                    && rule.contains(&Expression::Compare {
                        operation: CompareOp::Eq,
                        data: 0x2025_u32.to_ne_bytes().to_vec(),
                    })
            }));
        }
    }

    #[test]
    fn route_plan_redirects_tcp_and_marks_udp_and_icmp_per_family() {
        let plan = config().plan().unwrap();
        assert_eq!(
            plan.chains
                .iter()
                .find(|chain| chain.name == "output")
                .unwrap()
                .rules
                .iter()
                .filter(|rule| rule.contains(&Expression::Redirect))
                .count(),
            2
        );
        let packet_chain = plan
            .chains
            .iter()
            .find(|chain| chain.name == "output_udp_icmp")
            .unwrap();
        assert_eq!(
            packet_chain
                .rules
                .iter()
                .filter(
                    |rule| rule.contains(&Expression::MetaStore(MetaKey::Mark))
                )
                .count(),
            4
        );
    }

    #[test]
    fn route_refresh_rebuilds_every_route_dependent_chain() {
        let mut before = config();
        before.routes = vec!["10.20.0.0/16".parse().unwrap()];
        let before = before.plan().unwrap();
        let mut after = config();
        after.routes = vec!["172.24.0.0/16".parse().unwrap()];
        let after = after.plan().unwrap();

        let destination = |octets: [u8; 4]| Expression::Compare {
            operation: CompareOp::Eq,
            data: octets.to_vec(),
        };
        for chain_name in [
            "output",
            "output_udp_icmp",
            "prerouting",
            "prerouting_udp_icmp",
        ] {
            let before_chain = before
                .chains
                .iter()
                .find(|chain| chain.name == chain_name)
                .unwrap();
            let after_chain = after
                .chains
                .iter()
                .find(|chain| chain.name == chain_name)
                .unwrap();
            assert!(
                before_chain
                    .rules
                    .iter()
                    .any(|rule| rule.contains(&destination([10, 20, 0, 0])))
            );
            assert!(
                !after_chain
                    .rules
                    .iter()
                    .any(|rule| rule.contains(&destination([10, 20, 0, 0])))
            );
            assert!(
                after_chain
                    .rules
                    .iter()
                    .any(|rule| rule.contains(&destination([172, 24, 0, 0])))
            );
        }
    }

    #[test]
    fn mptcp_is_dropped_by_nat_or_excluded_when_requested() {
        let plan = config().plan().unwrap();
        for name in ["output", "prerouting"] {
            let chain =
                plan.chains.iter().find(|chain| chain.name == name).unwrap();
            assert!(chain.rules.iter().any(|rule| {
                rule.contains(&Expression::TcpOptionPresent(TCP_OPTION_MPTCP))
                    && rule.contains(&Expression::Drop)
            }));
        }

        let mut config = config();
        config.exclude_mptcp = true;
        let plan = config.plan().unwrap();
        for name in ["output", "prerouting", "prerouting_udp_icmp"] {
            let chain =
                plan.chains.iter().find(|chain| chain.name == name).unwrap();
            assert!(chain.rules.iter().any(|rule| {
                rule.contains(&Expression::TcpOptionPresent(TCP_OPTION_MPTCP))
                    && rule.contains(&Expression::Return)
            }));
        }
    }

    #[test]
    fn output_chain_is_skipped_when_loopback_is_not_selected() {
        let mut config = config();
        config.include_interfaces = vec!["eth0".into()];
        let plan = config.plan().unwrap();
        assert!(!plan.chains.iter().any(|chain| chain.hook == HOOK_OUTPUT));
    }

    #[test]
    fn output_chains_apply_include_and_exclude_uid_interval_sets() {
        let mut config = config();
        config.include_uids = vec![
            UidRange {
                start: 501,
                end: 501,
            },
            UidRange {
                start: 1000,
                end: 2000,
            },
        ];
        config.exclude_uids = vec![UidRange {
            start: 1500,
            end: 1600,
        }];
        let plan = config.plan().unwrap();
        let include = plan
            .sets
            .iter()
            .find(|set| set.name == SET_INCLUDE_UID)
            .unwrap();
        let exclude = plan
            .sets
            .iter()
            .find(|set| set.name == SET_EXCLUDE_UID)
            .unwrap();
        assert!(include.interval);
        assert!(exclude.interval);
        assert_eq!(include.elements.len(), 4);
        assert_eq!(exclude.elements.len(), 2);
        for name in ["output", "output_udp_icmp"] {
            let chain =
                plan.chains.iter().find(|chain| chain.name == name).unwrap();
            for lookup in [
                Expression::Lookup {
                    set: SET_INCLUDE_UID,
                    invert: true,
                },
                Expression::Lookup {
                    set: SET_EXCLUDE_UID,
                    invert: false,
                },
            ] {
                assert!(chain.rules.iter().any(|rule| rule.contains(&lookup)));
            }
        }
    }

    #[test]
    fn multiple_interface_and_mac_filters_use_native_sets() {
        let mut config = config();
        config.include_interfaces = vec!["eth0".into(), "wlan0".into()];
        config.exclude_interfaces = vec!["docker0".into(), "podman0".into()];
        config.include_mac_addresses =
            vec!["00:11:22:33:44:55".into(), "0011.2233.4466".into()];
        config.exclude_mac_addresses =
            vec!["aa-bb-cc-dd-ee-ff".into(), "aabbccddeeff".into()];
        let plan = config.plan().unwrap();
        assert_eq!(
            plan.sets
                .iter()
                .filter(|set| set.constant)
                .map(|set| set.name)
                .collect::<Vec<_>>(),
            [
                SET_INCLUDE_INTERFACE,
                SET_EXCLUDE_INTERFACE,
                SET_INCLUDE_MAC,
                SET_EXCLUDE_MAC,
            ]
        );
        let chain = plan
            .chains
            .iter()
            .find(|chain| chain.name == "prerouting")
            .unwrap();
        for lookup in [
            Expression::Lookup {
                set: SET_INCLUDE_INTERFACE,
                invert: true,
            },
            Expression::Lookup {
                set: SET_EXCLUDE_INTERFACE,
                invert: false,
            },
            Expression::Lookup {
                set: SET_INCLUDE_MAC,
                invert: true,
            },
            Expression::Lookup {
                set: SET_EXCLUDE_MAC,
                invert: false,
            },
        ] {
            assert!(chain.rules.iter().any(|rule| rule.contains(&lookup)));
        }
        assert!(chain.rules.iter().any(|rule| {
            rule.contains(&Expression::MetaLoad(MetaKey::Iiftype))
        }));
    }

    #[test]
    fn local_addresses_use_mutable_family_interval_sets() {
        let mut config = config();
        config.local_networks = vec![
            "10.0.1.0/24".parse().unwrap(),
            "0.0.0.0/0".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ];
        let plan = config.plan().unwrap();
        let ipv4 = plan
            .sets
            .iter()
            .find(|set| set.name == SET_LOCAL_IPV4)
            .unwrap();
        assert!(!ipv4.constant);
        assert!(ipv4.interval);
        assert_eq!(
            ipv4.elements,
            vec![SetElementPlan {
                key: [0_u8; 4].to_vec(),
                interval_end: false,
            }]
        );
        let ipv6 = plan
            .sets
            .iter()
            .find(|set| set.name == SET_LOCAL_IPV6)
            .unwrap();
        assert!(!ipv6.constant);
        assert_eq!(ipv6.elements.len(), 2);
        for name in ["output", "prerouting"] {
            let chain =
                plan.chains.iter().find(|chain| chain.name == name).unwrap();
            for set in [SET_LOCAL_IPV4, SET_LOCAL_IPV6] {
                assert!(chain.rules.iter().any(|rule| {
                    rule.contains(&Expression::Lookup { set, invert: false })
                }));
            }
        }
    }

    #[test]
    fn openwrt_fragment_accepts_both_tun_directions_and_escapes_values() {
        let rules =
            String::from_utf8(openwrt_rules("sing-box", "tun\"0")).unwrap();
        assert!(rules.contains("chain input"));
        assert!(rules.contains("chain forward"));
        assert_eq!(rules.matches("counter accept").count(), 4);
        assert!(rules.contains("iifname \"tun\\\"0\""));
        assert!(rules.contains("!sing-box: Accept traffic from tun"));
    }

    #[test]
    fn docker_rule_comment_uses_libnftables_userdata_tlv() {
        let comment = docker_comment("output to tun");
        let userdata = nft_comment_userdata(&comment);
        assert_eq!(
            parse_nft_comment(&userdata).as_deref(),
            Some(comment.as_str())
        );
        assert_eq!(userdata[0], 0);
        assert_eq!(usize::from(userdata[1]), comment.len() + 1);
        assert_eq!(parse_nft_comment(&[0, 5, b'x']), None);
    }

    #[test]
    fn mac_parser_matches_supported_go_mac48_forms() {
        let expected = [0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc];
        assert_eq!(parse_mac_address("00:11:22:aa:bb:cc"), Some(expected));
        assert_eq!(parse_mac_address("00-11-22-AA-BB-CC"), Some(expected));
        assert_eq!(parse_mac_address("0011.22aa.bbcc"), Some(expected));
        assert_eq!(parse_mac_address("001122aabbcc"), Some(expected));
        assert_eq!(parse_mac_address("00:11"), None);
    }

    #[test]
    fn prefix_match_uses_network_order_mask() {
        let expressions = destination_match("10.20.16.0/20".parse().unwrap());
        assert!(
            expressions.contains(&Expression::BitwiseMask(vec![
                0xff, 0xff, 0xf0, 0x00
            ]))
        );
        assert!(expressions.contains(&Expression::Compare {
            operation: CompareOp::Eq,
            data: vec![10, 20, 16, 0]
        }));
    }
}
