//! Linux rtnetlink backend for TUN addresses, routes, and policy rules.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use futures_util::{StreamExt as _, TryStreamExt as _};
use ipnet::IpNet;
use n0_watcher::Watcher as _;
use rtnetlink::{
    Handle, IpVersion, RouteMessageBuilder, new_connection,
    packet_route::{
        AddressFamily,
        address::{AddressAttribute, AddressMessage},
        link::{LinkAttribute, LinkFlags},
        route::{
            RouteAddress, RouteAttribute, RouteHeader, RouteMessage,
            RouteScope, RouteType,
        },
        rule::{
            RuleAction, RuleAttribute, RuleFlags, RuleMessage, RulePortRange,
            RuleUidRange,
        },
    },
};
use tokio::{process::Command, sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use super::tun_route::{TunRouteBackend, TunRouteLease, TunRoutePlan};
use crate::{
    common::socket::with_network_namespace, option::TunInboundOptions,
};

pub(crate) const DEFAULT_ROUTE_TABLE: u32 = 2022;
pub(crate) const DEFAULT_RULE_PRIORITY: u32 = 9000;
pub(crate) const DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_PRIORITY: u32 = 32768;
const RULE_PRIORITY_SPAN: u32 = 10;
const USER_END: u32 = u32::MAX - 1;
const REDIRECT_ROUTE_RULE_PRIORITY: u32 = 1;

pub(crate) struct LinuxBridgeRouteLease {
    handle: Handle,
    routes: Vec<RouteMessage>,
    rules: Vec<RuleMessage>,
    pinned_table: Option<u32>,
    cancellation: CancellationToken,
    refresh_task: Option<JoinHandle<()>>,
    connection: Option<JoinHandle<()>>,
}

impl LinuxBridgeRouteLease {
    pub(crate) async fn install(
        interface: &str,
        ports: impl IntoIterator<Item = IpAddr>,
        pinned_egress: Option<&str>,
        route_table: u32,
        rule_priority: u32,
    ) -> io::Result<Self> {
        let (connection, handle, _) = new_connection()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let connection = tokio::spawn(connection);
        let interface_index = match find_interface(&handle, interface).await {
            Ok(index) => index,
            Err(error) => {
                connection.abort();
                return Err(error);
            }
        };
        let ports = ports.into_iter().collect::<Vec<_>>();
        let cancellation = CancellationToken::new();
        let mut lease = Self {
            handle,
            routes: Vec::new(),
            rules: Vec::new(),
            pinned_table: pinned_egress.map(|_| route_table),
            cancellation,
            refresh_task: None,
            connection: Some(connection),
        };
        let install_result: io::Result<()> = async {
            for port in &ports {
                let port = *port;
                let scope = if port.is_ipv4() {
                    RouteScope::Link
                } else {
                    RouteScope::Universe
                };
                let route = RouteMessageBuilder::<IpAddr>::new()
                    .destination_prefix(
                        port,
                        if port.is_ipv4() { 32 } else { 128 },
                    )
                    .map_err(|error| io::Error::other(error.to_string()))?
                    .output_interface(interface_index)
                    .table_id(254)
                    .scope(scope)
                    .build();
                lease
                    .handle
                    .route()
                    .add(route.clone())
                    .replace()
                    .execute()
                    .await
                    .map_err(netlink_error)?;
                lease.routes.push(route);

                for rule in bridge_policy_rules(
                    interface,
                    port,
                    route_table,
                    rule_priority,
                ) {
                    let _ =
                        lease.handle.rule().del(rule.clone()).execute().await;
                    let mut request = lease.handle.rule().add();
                    request.message_mut().clone_from(&rule);
                    request.execute().await.map_err(netlink_error)?;
                    lease.rules.push(rule);
                }
            }
            if let Some(egress) = pinned_egress {
                sync_bridge_pinned_routes(
                    &lease.handle,
                    egress,
                    route_table,
                    &ports,
                )
                .await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = install_result {
            let _ = lease.close().await;
            return Err(error);
        }

        if let Some(egress) = pinned_egress {
            let handle = lease.handle.clone();
            let egress = egress.to_owned();
            let ports = ports.clone();
            let cancellation = lease.cancellation.clone();
            lease.refresh_task = Some(tokio::spawn(async move {
                let mut signature = bridge_route_signature(&egress).await;
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(1));
                interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Skip,
                );
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = interval.tick() => {
                            let next_signature = bridge_route_signature(&egress).await;
                            if next_signature == signature {
                                continue;
                            }
                            signature = next_signature;
                            let _ = sync_bridge_pinned_routes(
                                &handle,
                                &egress,
                                route_table,
                                &ports,
                            ).await;
                        }
                    }
                }
            }));
        }
        Ok(lease)
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        self.cancellation.cancel();
        let mut errors = Vec::new();
        if let Some(task) = self.refresh_task.take()
            && let Err(error) = task.await
        {
            errors.push(format!("bridge route refresh task: {error}"));
        }
        if let Some(table) = self.pinned_table.take()
            && let Err(error) =
                flush_bridge_route_table(&self.handle, table).await
        {
            errors.push(format!("flush bridge route table: {error}"));
        }
        for rule in self.rules.drain(..).rev() {
            if let Err(error) = self.handle.rule().del(rule).execute().await
                && netlink_error_kind(&error) != io::ErrorKind::NotFound
            {
                errors.push(netlink_error(error).to_string());
            }
        }
        for route in self.routes.drain(..).rev() {
            if let Err(error) = self.handle.route().del(route).execute().await
                && netlink_error_kind(&error) != io::ErrorKind::NotFound
            {
                errors.push(netlink_error(error).to_string());
            }
        }
        if let Some(connection) = self.connection.take() {
            connection.abort();
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
}

async fn bridge_route_signature(egress: &str) -> Vec<u8> {
    let mut signature = egress.as_bytes().to_vec();
    for path in ["/proc/net/route", "/proc/net/ipv6_route"] {
        if let Ok(content) = tokio::fs::read(path).await {
            signature.extend_from_slice(&content);
        }
    }
    signature
}

fn bridge_policy_rules(
    interface: &str,
    port: IpAddr,
    route_table: u32,
    priority: u32,
) -> [RuleMessage; 2] {
    let address_family = family(port.is_ipv6());
    let mut incoming = rule_for_table(
        address_family,
        priority,
        if route_table == 0 { 254 } else { route_table },
        None,
    );
    incoming
        .attributes
        .push(RuleAttribute::Iifname(interface.into()));

    let mut returning = rule_for_table(address_family, priority + 1, 254, None);
    set_destination(
        &mut returning,
        port,
        if port.is_ipv4() { 32 } else { 128 },
    );
    [incoming, returning]
}

async fn sync_bridge_pinned_routes(
    handle: &Handle,
    egress: &str,
    table: u32,
    ports: &[IpAddr],
) -> io::Result<()> {
    flush_bridge_route_table(handle, table).await?;
    let interface_index = match find_interface(handle, egress).await {
        Ok(index) => index,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            for ipv6 in active_bridge_families(ports) {
                replace_bridge_blackhole(handle, table, ipv6).await?;
            }
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    for ipv6 in active_bridge_families(ports) {
        sync_bridge_pinned_family(handle, interface_index, table, ipv6).await?;
    }
    Ok(())
}

fn active_bridge_families(ports: &[IpAddr]) -> impl Iterator<Item = bool> + '_ {
    [false, true]
        .into_iter()
        .filter(|ipv6| ports.iter().any(|port| port.is_ipv6() == *ipv6))
}

async fn sync_bridge_pinned_family(
    handle: &Handle,
    interface_index: u32,
    table: u32,
    ipv6: bool,
) -> io::Result<()> {
    let request = if ipv6 {
        RouteMessageBuilder::<Ipv6Addr>::new().build()
    } else {
        RouteMessageBuilder::<Ipv4Addr>::new().build()
    };
    let mut stream = handle.route().get(request).execute();
    let mut connected = Vec::new();
    let mut default = None::<RouteMessage>;
    while let Some(route) = match stream.try_next().await {
        Ok(route) => route,
        Err(error) => {
            replace_bridge_blackhole(handle, table, ipv6).await?;
            return Err(netlink_error(error));
        }
    } {
        if route_table(&route) != 254
            || route.header.kind != RouteType::Unicast
            || route_output_interface(&route) != Some(interface_index)
        {
            continue;
        }
        if route.header.destination_prefix_length == 0 {
            let replace = default.as_ref().is_none_or(|current| {
                route_metric(&route) < route_metric(current)
            });
            if replace {
                default = Some(route);
            }
        } else if !route_has_gateway(&route) {
            connected.push(route);
        }
    }
    drop(stream);
    for route in connected {
        replace_bridge_route(handle, set_bridge_route_table(route, table))
            .await?;
    }
    match default {
        Some(route) => {
            replace_bridge_route(handle, set_bridge_route_table(route, table))
                .await
        }
        None => replace_bridge_blackhole(handle, table, ipv6).await,
    }
}

fn route_output_interface(route: &RouteMessage) -> Option<u32> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
}

fn route_has_gateway(route: &RouteMessage) -> bool {
    route.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            RouteAttribute::Gateway(RouteAddress::Inet(_))
                | RouteAttribute::Gateway(RouteAddress::Inet6(_))
        )
    })
}

fn route_metric(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        })
        .unwrap_or(u32::MAX)
}

fn set_bridge_route_table(mut route: RouteMessage, table: u32) -> RouteMessage {
    route
        .attributes
        .retain(|attribute| !matches!(attribute, RouteAttribute::Table(_)));
    if table < 256 {
        route.header.table = table as u8;
    } else {
        route.header.table = RouteHeader::RT_TABLE_UNSPEC;
        route.attributes.push(RouteAttribute::Table(table));
    }
    route
}

async fn replace_bridge_route(
    handle: &Handle,
    route: RouteMessage,
) -> io::Result<()> {
    handle
        .route()
        .add(route)
        .replace()
        .execute()
        .await
        .map_err(netlink_error)
}

async fn replace_bridge_blackhole(
    handle: &Handle,
    table: u32,
    ipv6: bool,
) -> io::Result<()> {
    let route = if ipv6 {
        RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(table)
            .kind(RouteType::BlackHole)
            .build()
    } else {
        RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(table)
            .kind(RouteType::BlackHole)
            .build()
    };
    replace_bridge_route(handle, route).await
}

async fn flush_bridge_route_table(
    handle: &Handle,
    table: u32,
) -> io::Result<()> {
    for request in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let mut stream = handle.route().get(request).execute();
        let mut routes = Vec::new();
        while let Some(route) =
            stream.try_next().await.map_err(netlink_error)?
        {
            if route_table(&route) == table {
                routes.push(route);
            }
        }
        drop(stream);
        for route in routes {
            if let Err(error) = handle.route().del(route).execute().await
                && netlink_error_kind(&error) != io::ErrorKind::NotFound
            {
                return Err(netlink_error(error));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UidRange {
    pub(crate) start: u32,
    pub(crate) end: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct LinuxPolicyOptions {
    pub(crate) include_uids: Vec<UidRange>,
    pub(crate) exclude_uids: Vec<UidRange>,
    pub(crate) excluded_uids: Vec<UidRange>,
    include_interfaces: Vec<String>,
    exclude_interfaces: Vec<String>,
    strict_route: bool,
}

impl LinuxPolicyOptions {
    pub(crate) fn from_options(
        options: &TunInboundOptions,
    ) -> Result<Self, String> {
        let mut includes = options
            .include_uid
            .as_slice()
            .iter()
            .map(|uid| UidRange {
                start: *uid,
                end: *uid,
            })
            .collect::<Vec<_>>();
        includes.extend(parse_uid_ranges(
            options.include_uid_range.as_slice(),
            "include_uid_range",
        )?);
        let mut excludes = options
            .exclude_uid
            .as_slice()
            .iter()
            .map(|uid| UidRange {
                start: *uid,
                end: *uid,
            })
            .collect::<Vec<_>>();
        excludes.extend(parse_uid_ranges(
            options.exclude_uid_range.as_slice(),
            "exclude_uid_range",
        )?);
        let excluded_uids =
            build_excluded_ranges(includes.clone(), excludes.clone());
        Ok(Self {
            include_uids: includes,
            exclude_uids: excludes,
            excluded_uids,
            include_interfaces: options.include_interface.as_slice().to_vec(),
            exclude_interfaces: options.exclude_interface.as_slice().to_vec(),
            strict_route: options.strict_route,
        })
    }
}

pub(crate) struct LinuxTunLease {
    handle: Handle,
    connection_task: JoinHandle<()>,
    routes: TunRouteLease<LinuxRouteBackend>,
    rules: Vec<RuleMessage>,
    addresses: Vec<AddressMessage>,
    redirect_routes: Arc<Mutex<Vec<RouteMessage>>>,
    redirect_rules: Vec<RuleMessage>,
    redirect_table: Option<u32>,
    redirect_cancellation: CancellationToken,
    redirect_task: Option<JoinHandle<()>>,
    dns_interface: Option<String>,
    dns_task: Option<JoinHandle<()>>,
}

impl LinuxTunLease {
    pub(crate) async fn install(
        interface_name: &str,
        addresses: &[IpNet],
        primary_ipv4: Option<IpNet>,
        route_plan: &TunRoutePlan,
        table: u32,
        rule_priority: u32,
        auto_route: bool,
        policy: &LinuxPolicyOptions,
        dns_servers: &[IpAddr],
        auto_redirect: bool,
        auto_redirect_input_mark: u32,
        auto_redirect_output_mark: u32,
        auto_redirect_fallback_rule_priority: u32,
        network_namespace: &str,
    ) -> io::Result<Self> {
        let namespace = network_namespace.to_owned();
        let (connection, handle, _) =
            with_network_namespace(&namespace, new_connection).await?;
        let mut connection_task = tokio::spawn(connection);
        let interface_index =
            match find_interface(&handle, interface_name).await {
                Ok(index) => index,
                Err(error) => {
                    connection_task.abort();
                    let _ = (&mut connection_task).await;
                    return Err(error);
                }
            };
        let rp_filter = rp_filter_path(interface_name)?;
        let _ = with_network_namespace(&namespace, move || {
            std::fs::write(rp_filter, b"2")
        })
        .await;
        let backend = LinuxRouteBackend::new(
            handle.clone(),
            interface_index,
            table,
            addresses,
        );
        let mut lease = Self {
            handle: handle.clone(),
            connection_task,
            routes: TunRouteLease::new(backend),
            rules: Vec::new(),
            addresses: Vec::new(),
            redirect_routes: Arc::new(Mutex::new(Vec::new())),
            redirect_rules: Vec::new(),
            redirect_table: None,
            redirect_cancellation: CancellationToken::new(),
            redirect_task: None,
            dns_interface: None,
            dns_task: None,
        };

        let install_result: io::Result<()> = async {
            lease
                .install_additional_addresses(
                    interface_index,
                    addresses,
                    primary_ipv4,
                )
                .await?;
            if !route_plan.routes().is_empty() {
                lease.routes.install(route_plan).await?;
            }
            if auto_route {
                cleanup_rule_range(
                    &handle,
                    rule_priority,
                    auto_redirect
                        .then_some(auto_redirect_fallback_rule_priority),
                )
                .await?;
                let rules = if auto_redirect {
                    build_auto_redirect_rules(
                        addresses,
                        table,
                        rule_priority,
                        auto_redirect_input_mark,
                        auto_redirect_output_mark,
                        auto_redirect_fallback_rule_priority,
                    )
                } else {
                    build_rules(
                        interface_name,
                        addresses,
                        table,
                        rule_priority,
                        policy,
                    )
                };
                for rule in rules {
                    let mut request = handle.rule().add();
                    request.message_mut().clone_from(&rule);
                    request.execute().await.map_err(netlink_error)?;
                    lease.rules.push(rule);
                }
            } else if addresses.iter().any(|address| address.addr().is_ipv6()) {
                let priority = next_ipv6_rule_priority(&handle).await?;
                let mut rule =
                    rule_for_table(family(true), priority, table, None);
                rule.attributes
                    .push(RuleAttribute::Oifname(interface_name.into()));
                let mut request = handle.rule().add();
                request.message_mut().clone_from(&rule);
                request.execute().await.map_err(netlink_error)?;
                lease.rules.push(rule);
            }
            if auto_redirect {
                lease
                    .install_redirect_routes(
                        interface_name,
                        table,
                        addresses
                            .iter()
                            .any(|address| address.addr().is_ipv4()),
                        addresses
                            .iter()
                            .any(|address| address.addr().is_ipv6()),
                    )
                    .await?;
            }
            if network_namespace.is_empty() && !dns_servers.is_empty() {
                lease.dns_interface = Some(interface_name.to_owned());
                let interface = interface_name.to_owned();
                let servers = dns_servers.to_vec();
                lease.dns_task = Some(tokio::spawn(async move {
                    configure_systemd_resolved(&interface, &servers).await;
                }));
            }
            Ok(())
        }
        .await;

        if let Err(error) = install_result {
            let rollback = lease.close_inner().await.err();
            lease.connection_task.abort();
            let _ = (&mut lease.connection_task).await;
            let mut message = error.to_string();
            if let Some(rollback) = rollback {
                message.push_str(&format!("; rollback: {rollback}"));
            }
            return Err(io::Error::new(error.kind(), message));
        }
        if auto_redirect {
            lease
                .start_redirect_route_monitor(
                    interface_name,
                    addresses.iter().any(|address| address.addr().is_ipv4()),
                    addresses.iter().any(|address| address.addr().is_ipv6()),
                    network_namespace,
                )
                .await;
        }
        Ok(lease)
    }

    async fn install_additional_addresses(
        &mut self,
        interface_index: u32,
        addresses: &[IpNet],
        primary_ipv4: Option<IpNet>,
    ) -> io::Result<()> {
        for address in addresses {
            if Some(*address) == primary_ipv4 {
                continue;
            }
            let mut request = self.handle.address().add(
                interface_index,
                address.addr(),
                address.prefix_len(),
            );
            let message = request.message_mut().clone();
            match request.execute().await {
                Ok(()) => self.addresses.push(message),
                Err(error)
                    if netlink_error_kind(&error)
                        == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(netlink_error(error)),
            }
        }
        Ok(())
    }

    /// Install sing-tun's priority-one local-route table used after nftables
    /// REDIRECT.  A separate local route is required for every active
    /// non-loopback interface so prerouted traffic is delivered locally on
    /// the interface on which it arrived.
    async fn install_redirect_routes(
        &mut self,
        tun_name: &str,
        main_table: u32,
        enable_ipv4: bool,
        enable_ipv6: bool,
    ) -> io::Result<()> {
        let table = choose_redirect_table(&self.handle, main_table).await?;
        let keys = redirect_route_keys(
            &self.handle,
            tun_name,
            enable_ipv4,
            enable_ipv6,
        )
        .await?;

        for key in keys {
            let route = redirect_route_message(table, key)?;
            append_route(&self.handle, route.clone())
                .await
                .map_err(netlink_error)?;
            self.redirect_routes.lock().await.push(route);
        }
        for ipv6 in [false, true] {
            if (ipv6 && !enable_ipv6) || (!ipv6 && !enable_ipv4) {
                continue;
            }
            let rule = rule_for_table(
                family(ipv6),
                REDIRECT_ROUTE_RULE_PRIORITY,
                table,
                None,
            );
            let mut request = self.handle.rule().add();
            request.message_mut().clone_from(&rule);
            request.execute().await.map_err(netlink_error)?;
            self.redirect_rules.push(rule);
        }
        self.redirect_table = Some(table);
        Ok(())
    }

    async fn start_redirect_route_monitor(
        &mut self,
        tun_name: &str,
        enable_ipv4: bool,
        enable_ipv6: bool,
        network_namespace: &str,
    ) {
        let Some(table) = self.redirect_table else {
            return;
        };
        let monitor = if network_namespace.is_empty() {
            match crate::common::network_monitor::NetworkMonitor::new().await {
                Ok(monitor) => Some(monitor),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "network monitor unavailable; auto-redirect routes will not refresh"
                    );
                    return;
                }
            }
        } else {
            None
        };
        let mut watcher =
            monitor.as_ref().map(|monitor| monitor.interface_state());
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(2));
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        let handle = self.handle.clone();
        let tun_name = tun_name.to_owned();
        let routes = self.redirect_routes.clone();
        let cancellation = self.redirect_cancellation.clone();
        self.redirect_task = Some(tokio::spawn(async move {
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
                if let Err(error) = reconcile_redirect_routes(
                    &handle,
                    table,
                    &tun_name,
                    enable_ipv4,
                    enable_ipv6,
                    &routes,
                )
                .await
                {
                    tracing::warn!(%error, "update auto-redirect routes");
                }
            }
        }));
    }

    pub(crate) async fn close(mut self) -> io::Result<()> {
        self.redirect_cancellation.cancel();
        if let Some(task) = self.redirect_task.take() {
            let _ = task.await;
        }
        let result = self.close_inner().await;
        self.connection_task.abort();
        let _ = self.connection_task.await;
        result
    }

    async fn close_inner(&mut self) -> io::Result<()> {
        let mut failures = Vec::new();
        if let Some(mut task) = self.dns_task.take() {
            task.abort();
            let _ = (&mut task).await;
        }
        if let Some(interface) = self.dns_interface.take() {
            revert_systemd_resolved(&interface).await;
        }
        let mut redirect_routes = self.redirect_routes.lock().await;
        while let Some(route) = redirect_routes.pop() {
            if let Err(error) = self.handle.route().del(route).execute().await {
                failures.push(format!("remove auto-redirect route: {error}"));
            }
        }
        drop(redirect_routes);
        while let Some(rule) = self.redirect_rules.pop() {
            if let Err(error) = self.handle.rule().del(rule).execute().await {
                failures.push(format!("remove auto-redirect rule: {error}"));
            }
        }
        self.redirect_table = None;
        while let Some(rule) = self.rules.pop() {
            if let Err(error) = self.handle.rule().del(rule).execute().await {
                failures.push(format!("remove TUN policy rule: {error}"));
            }
        }
        if let Err(error) = self.routes.close().await {
            failures.push(error.to_string());
        }
        while let Some(address) = self.addresses.pop() {
            if let Err(error) =
                self.handle.address().del(address).execute().await
            {
                failures.push(format!("remove TUN address: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }
}

fn rp_filter_path(interface_name: &str) -> io::Result<PathBuf> {
    if interface_name.is_empty()
        || interface_name.contains('/')
        || interface_name.contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Linux interface name",
        ));
    }
    Ok(PathBuf::from("/proc/sys/net/ipv4/conf")
        .join(interface_name)
        .join("rp_filter"))
}

async fn append_route(
    handle: &Handle,
    route: RouteMessage,
) -> Result<(), rtnetlink::Error> {
    use rtnetlink::{
        packet_core::{
            NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_REQUEST,
            NetlinkMessage, NetlinkPayload,
        },
        packet_route::RouteNetlinkMessage,
    };

    let mut request =
        NetlinkMessage::from(RouteNetlinkMessage::NewRoute(route));
    request.header.flags =
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
    let mut handle = handle.clone();
    let mut responses = handle.request(request)?;
    while let Some(message) = responses.next().await {
        if let NetlinkPayload::Error(error) = message.payload {
            return Err(rtnetlink::Error::NetlinkError(error));
        }
    }
    Ok(())
}

async fn configure_systemd_resolved(interface: &str, servers: &[IpAddr]) {
    let commands = [
        vec!["domain".to_owned(), interface.to_owned(), "~.".to_owned()],
        vec![
            "default-route".to_owned(),
            interface.to_owned(),
            "true".to_owned(),
        ],
        std::iter::once("dns".to_owned())
            .chain(std::iter::once(interface.to_owned()))
            .chain(servers.iter().map(ToString::to_string))
            .collect(),
    ];
    for arguments in commands {
        let _ = Command::new("resolvectl")
            .args(arguments)
            .kill_on_drop(true)
            .status()
            .await;
    }
}

async fn revert_systemd_resolved(interface: &str) {
    let _ = Command::new("resolvectl")
        .args(["revert", interface])
        .kill_on_drop(true)
        .status()
        .await;
}

struct LinuxRouteBackend {
    handle: Handle,
    interface_index: u32,
    table: u32,
    gateway4: Option<IpAddr>,
    gateway6: Option<IpAddr>,
}

impl LinuxRouteBackend {
    fn new(
        handle: Handle,
        interface_index: u32,
        table: u32,
        addresses: &[IpNet],
    ) -> Self {
        Self {
            handle,
            interface_index,
            table,
            gateway4: gateway(addresses, false),
            gateway6: gateway(addresses, true),
        }
    }

    fn route_message(&self, route: IpNet) -> io::Result<RouteMessage> {
        let mut builder = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(route.network(), route.prefix_len())
            .map_err(|error| io::Error::other(error.to_string()))?
            .output_interface(self.interface_index)
            .table_id(self.table);
        if let Some(gateway) = if route.addr().is_ipv4() {
            self.gateway4
        } else {
            self.gateway6
        } {
            builder = builder
                .gateway(gateway)
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(builder.build())
    }
}

#[async_trait]
impl TunRouteBackend for LinuxRouteBackend {
    async fn add_route(&mut self, route: IpNet) -> io::Result<()> {
        self.handle
            .route()
            .add(self.route_message(route)?)
            .execute()
            .await
            .map_err(netlink_error)
    }

    async fn remove_route(&mut self, route: IpNet) -> io::Result<()> {
        self.handle
            .route()
            .del(self.route_message(route)?)
            .execute()
            .await
            .map_err(netlink_error)
    }
}

async fn find_interface(handle: &Handle, name: &str) -> io::Result<u32> {
    let mut links = handle.link().get().match_name(name).execute();
    links
        .try_next()
        .await
        .map_err(netlink_error)?
        .map(|link| link.header.index)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("TUN interface {name} was not found"),
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct RedirectRouteKey {
    interface_index: u32,
    ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RedirectInterface {
    index: u32,
    name: String,
    up: bool,
    loopback: bool,
    has_ipv4: bool,
    has_ipv6: bool,
}

fn calculate_redirect_route_keys(
    interfaces: &[RedirectInterface],
    tun_name: &str,
    enable_ipv4: bool,
    enable_ipv6: bool,
) -> Vec<RedirectRouteKey> {
    let mut keys = interfaces
        .iter()
        .filter(|interface| {
            interface.up && !interface.loopback && interface.name != tun_name
        })
        .flat_map(|interface| {
            [
                (enable_ipv4 && interface.has_ipv4).then_some(
                    RedirectRouteKey {
                        interface_index: interface.index,
                        ipv6: false,
                    },
                ),
                (enable_ipv6 && interface.has_ipv6).then_some(
                    RedirectRouteKey {
                        interface_index: interface.index,
                        ipv6: true,
                    },
                ),
            ]
            .into_iter()
            .flatten()
        })
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    keys
}

async fn redirect_route_keys(
    handle: &Handle,
    tun_name: &str,
    enable_ipv4: bool,
    enable_ipv6: bool,
) -> io::Result<Vec<RedirectRouteKey>> {
    let mut links = handle.link().get().execute();
    let mut interfaces = HashMap::<u32, RedirectInterface>::new();
    while let Some(link) = links.try_next().await.map_err(netlink_error)? {
        let name =
            link.attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfName(name) => Some(name.clone()),
                    _ => None,
                });
        let Some(name) = name else {
            continue;
        };
        interfaces.insert(
            link.header.index,
            RedirectInterface {
                index: link.header.index,
                name,
                up: link.header.flags.contains(LinkFlags::Up),
                loopback: link.header.flags.contains(LinkFlags::Loopback),
                has_ipv4: false,
                has_ipv6: false,
            },
        );
    }

    let mut addresses = handle.address().get().execute();
    while let Some(address) =
        addresses.try_next().await.map_err(netlink_error)?
    {
        let Some(interface) = interfaces.get_mut(&address.header.index) else {
            continue;
        };
        for attribute in &address.attributes {
            let ip = match attribute {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    *ip
                }
                _ => continue,
            };
            if ip.is_ipv4() {
                interface.has_ipv4 = true;
            } else {
                interface.has_ipv6 = true;
            }
        }
    }
    Ok(calculate_redirect_route_keys(
        &interfaces.into_values().collect::<Vec<_>>(),
        tun_name,
        enable_ipv4,
        enable_ipv6,
    ))
}

async fn reconcile_redirect_routes(
    handle: &Handle,
    table: u32,
    tun_name: &str,
    enable_ipv4: bool,
    enable_ipv6: bool,
    tracked: &Arc<Mutex<Vec<RouteMessage>>>,
) -> io::Result<()> {
    let desired =
        redirect_route_keys(handle, tun_name, enable_ipv4, enable_ipv6)
            .await?
            .into_iter()
            .collect::<BTreeSet<_>>();
    let current = current_redirect_routes(handle, table).await?;
    let current_keys = current.keys().copied().collect::<BTreeSet<_>>();
    let (to_add, to_delete) = calculate_redirect_route_changes(
        desired.iter().copied(),
        current_keys.iter().copied(),
    );
    for key in desired.intersection(&current_keys) {
        if let Some(routes) = current.get(key) {
            for route in routes.iter().skip(1) {
                if let Err(error) =
                    handle.route().del(route.clone()).execute().await
                    && netlink_error_kind(&error) != io::ErrorKind::NotFound
                {
                    return Err(netlink_error(error));
                }
            }
        }
    }
    for key in to_delete {
        if let Some(routes) = current.get(&key) {
            for route in routes {
                if let Err(error) =
                    handle.route().del(route.clone()).execute().await
                    && netlink_error_kind(&error) != io::ErrorKind::NotFound
                {
                    return Err(netlink_error(error));
                }
            }
        }
    }
    for key in to_add {
        append_route(handle, redirect_route_message(table, key)?)
            .await
            .map_err(netlink_error)?;
    }
    *tracked.lock().await = desired
        .into_iter()
        .map(|key| redirect_route_message(table, key))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(())
}

fn calculate_redirect_route_changes(
    desired: impl IntoIterator<Item = RedirectRouteKey>,
    current: impl IntoIterator<Item = RedirectRouteKey>,
) -> (Vec<RedirectRouteKey>, Vec<RedirectRouteKey>) {
    let desired = desired.into_iter().collect::<BTreeSet<_>>();
    let current = current.into_iter().collect::<BTreeSet<_>>();
    (
        desired.difference(&current).copied().collect(),
        current.difference(&desired).copied().collect(),
    )
}

async fn current_redirect_routes(
    handle: &Handle,
    table: u32,
) -> io::Result<BTreeMap<RedirectRouteKey, Vec<RouteMessage>>> {
    let mut current = BTreeMap::<RedirectRouteKey, Vec<RouteMessage>>::new();
    for request in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let mut routes = handle.route().get(request).execute();
        while let Some(route) =
            routes.try_next().await.map_err(netlink_error)?
        {
            if route_table(&route) != table {
                continue;
            }
            if let Some(key) = redirect_route_key_from_message(&route) {
                current.entry(key).or_default().push(route);
            }
        }
    }
    Ok(current)
}

fn redirect_route_key_from_message(
    route: &RouteMessage,
) -> Option<RedirectRouteKey> {
    if route.header.kind != RouteType::Local
        || route.header.scope != RouteScope::Host
    {
        return None;
    }
    let interface_index = route.attributes.iter().find_map(|attribute| {
        if let RouteAttribute::Oif(index) = attribute {
            Some(*index)
        } else {
            None
        }
    })?;
    let ipv6 =
        route
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Destination(RouteAddress::Inet(address))
                    if route.header.destination_prefix_length == 32
                        && *address == Ipv4Addr::LOCALHOST =>
                {
                    Some(false)
                }
                RouteAttribute::Destination(RouteAddress::Inet6(address))
                    if route.header.destination_prefix_length == 128
                        && *address == Ipv6Addr::LOCALHOST =>
                {
                    Some(true)
                }
                _ => None,
            })?;
    Some(RedirectRouteKey {
        interface_index,
        ipv6,
    })
}

async fn choose_redirect_table(
    handle: &Handle,
    main_table: u32,
) -> io::Result<u32> {
    for _ in 0..64 {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        let table = u32::from_ne_bytes(bytes);
        if table == 0 || table == main_table {
            continue;
        }
        if !route_table_in_use(handle, table).await? {
            return Ok(table);
        }
    }
    Err(io::Error::other(
        "unable to allocate an unused auto-redirect route table",
    ))
}

async fn route_table_in_use(handle: &Handle, table: u32) -> io::Result<bool> {
    let requests = [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ];
    for request in requests {
        let mut routes = handle.route().get(request).execute();
        while let Some(route) =
            routes.try_next().await.map_err(netlink_error)?
        {
            if route_table(&route) == table {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn route_table(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table))
}

fn redirect_route_message(
    table: u32,
    key: RedirectRouteKey,
) -> io::Result<RouteMessage> {
    let (destination, prefix) = if key.ipv6 {
        (IpAddr::V6(Ipv6Addr::LOCALHOST), 128)
    } else {
        (IpAddr::V4(Ipv4Addr::LOCALHOST), 32)
    };
    Ok(RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(destination, prefix)
        .map_err(|error| io::Error::other(error.to_string()))?
        .output_interface(key.interface_index)
        .table_id(table)
        .scope(RouteScope::Host)
        .kind(RouteType::Local)
        .build())
}

fn gateway(addresses: &[IpNet], ipv6: bool) -> Option<IpAddr> {
    let network = addresses
        .iter()
        .find(|network| network.addr().is_ipv6() == ipv6)?;
    let next = match network.addr() {
        IpAddr::V4(address) => u32::from(address)
            .checked_add(1)
            .map(std::net::Ipv4Addr::from)
            .map(IpAddr::V4),
        IpAddr::V6(address) => u128::from(address)
            .checked_add(1)
            .map(std::net::Ipv6Addr::from)
            .map(IpAddr::V6),
    }?;
    network.contains(&next).then_some(next)
}

async fn cleanup_rule_range(
    handle: &Handle,
    rule_priority: u32,
    fallback_priority: Option<u32>,
) -> io::Result<()> {
    for version in [IpVersion::V4, IpVersion::V6] {
        let mut rules = handle.rule().get(version).execute();
        while let Some(rule) = rules.try_next().await.map_err(netlink_error)? {
            let priority = rule.attributes.iter().find_map(|attribute| {
                if let RuleAttribute::Priority(priority) = attribute {
                    Some(*priority)
                } else {
                    None
                }
            });
            if priority.is_some_and(|priority| {
                (rule_priority..=rule_priority + RULE_PRIORITY_SPAN)
                    .contains(&priority)
                    || fallback_priority == Some(priority)
            }) {
                handle
                    .rule()
                    .del(rule)
                    .execute()
                    .await
                    .map_err(netlink_error)?;
            }
        }
    }
    Ok(())
}

fn build_auto_redirect_rules(
    addresses: &[IpNet],
    table: u32,
    rule_start: u32,
    input_mark: u32,
    output_mark: u32,
    fallback_priority: u32,
) -> Vec<RuleMessage> {
    let mut rules = Vec::new();
    for (has_family, family) in [
        (
            addresses.iter().any(|address| address.addr().is_ipv4()),
            family(false),
        ),
        (
            addresses.iter().any(|address| address.addr().is_ipv6()),
            family(true),
        ),
    ] {
        if !has_family {
            continue;
        }
        rules.push(rule_goto_mark(
            family,
            rule_start,
            output_mark,
            rule_start + 2,
        ));
        rules.push(rule_for_table_mark(
            family,
            rule_start + 1,
            table,
            input_mark,
        ));
        rules.push(nop_rule(family, rule_start + 2));
        rules.push(rule_for_table(family, fallback_priority, table, None));
    }
    rules
}

async fn next_ipv6_rule_priority(handle: &Handle) -> io::Result<u32> {
    let mut rules = handle.rule().get(IpVersion::V6).execute();
    let mut minimum = None;
    while let Some(rule) = rules.try_next().await.map_err(netlink_error)? {
        let priority = rule.attributes.iter().find_map(|attribute| {
            if let RuleAttribute::Priority(priority) = attribute {
                Some(*priority)
            } else {
                None
            }
        });
        if let Some(priority) = priority.filter(|priority| *priority > 0) {
            minimum = Some(
                minimum.map_or(priority, |value: u32| value.min(priority)),
            );
        }
    }
    minimum
        .and_then(|priority| priority.checked_sub(1))
        .ok_or_else(|| io::Error::other("no free IPv6 policy rule priority"))
}

fn build_rules(
    interface_name: &str,
    addresses: &[IpNet],
    table: u32,
    rule_start: u32,
    policy: &LinuxPolicyOptions,
) -> Vec<RuleMessage> {
    let mut rules = Vec::new();
    let has_ipv4 = addresses.iter().any(|address| address.addr().is_ipv4());
    let has_ipv6 = addresses.iter().any(|address| address.addr().is_ipv6());
    let nop_priority = rule_start + RULE_PRIORITY_SPAN;
    let mut priority4 = rule_start;
    let mut priority6 = rule_start;

    for uid in &policy.excluded_uids {
        if has_ipv4 {
            rules.push(rule_goto_uid(
                family(false),
                priority4,
                *uid,
                nop_priority,
            ));
        }
        if has_ipv6 {
            rules.push(rule_goto_uid(
                family(true),
                priority6,
                *uid,
                nop_priority,
            ));
        }
    }
    if !policy.excluded_uids.is_empty() {
        priority4 += u32::from(has_ipv4);
        priority6 += u32::from(has_ipv6);
    }

    if !policy.include_interfaces.is_empty() {
        let match4 = priority4 + 2;
        let match6 = priority6 + 2;
        for interface in &policy.include_interfaces {
            if has_ipv4 {
                rules.push(rule_goto_interface(
                    family(false),
                    priority4,
                    interface,
                    match4,
                ));
            }
            if has_ipv6 {
                rules.push(rule_goto_interface(
                    family(true),
                    priority6,
                    interface,
                    match6,
                ));
            }
        }
        if has_ipv4 {
            priority4 += 1;
            rules.push(goto_rule(family(false), priority4, nop_priority));
            priority4 += 1;
            rules.push(nop_rule(family(false), match4));
            priority4 += 1;
        }
        if has_ipv6 {
            priority6 += 1;
            rules.push(goto_rule(family(true), priority6, nop_priority));
            priority6 += 1;
            rules.push(nop_rule(family(true), match6));
            priority6 += 1;
        }
    } else if !policy.exclude_interfaces.is_empty() {
        for interface in &policy.exclude_interfaces {
            if has_ipv4 {
                rules.push(rule_goto_interface(
                    family(false),
                    priority4,
                    interface,
                    nop_priority,
                ));
            }
            if has_ipv6 {
                rules.push(rule_goto_interface(
                    family(true),
                    priority6,
                    interface,
                    nop_priority,
                ));
            }
        }
        priority4 += u32::from(has_ipv4);
        priority6 += u32::from(has_ipv6);
    }

    if policy.strict_route {
        if !has_ipv4 {
            rules.push(unreachable_rule(family(false), priority4));
        }
        if !has_ipv6 {
            rules.push(unreachable_rule(family(true), priority6));
        }
    }

    if has_ipv4 {
        for address in
            addresses.iter().filter(|address| address.addr().is_ipv4())
        {
            rules.push(rule_for_table(
                family(false),
                priority4,
                table,
                Some((address.network(), address.prefix_len(), false)),
            ));
        }
        priority4 += 1;
        rules.push(rule_suppress(family(false), priority4, table));
        priority4 += 1;
        rules.push(rule_main_non_dns(family(false), priority4));
        rules.push(rule_goto_interface(
            family(false),
            priority4,
            interface_name,
            nop_priority,
        ));
        priority4 += 1;
        rules.push(rule_inverted_loopback(family(false), priority4, table));
        rules.push(rule_for_table_with_interface(
            family(false),
            priority4,
            table,
            "lo",
            Some(("0.0.0.0".parse().unwrap(), 32)),
        ));
        for address in
            addresses.iter().filter(|address| address.addr().is_ipv4())
        {
            rules.push(rule_for_table_with_interface(
                family(false),
                priority4,
                table,
                "lo",
                Some((address.network(), address.prefix_len())),
            ));
        }
        rules.push(nop_rule(family(false), nop_priority));
    }

    if has_ipv6 {
        rules.push(rule_suppress(family(true), priority6, table));
        priority6 += 1;
        rules.push(rule_main_non_dns(family(true), priority6));
        rules.push(rule_goto_interface(
            family(true),
            priority6,
            interface_name,
            nop_priority,
        ));
        for (source, prefix) in
            [("::".parse().unwrap(), 1), ("8000::".parse().unwrap(), 1)]
        {
            rules.push(rule_goto_source(
                family(true),
                priority6,
                source,
                prefix,
                "lo",
                nop_priority,
            ));
        }
        priority6 += 1;
        for address in
            addresses.iter().filter(|address| address.addr().is_ipv6())
        {
            rules.push(rule_for_table_with_interface(
                family(true),
                priority6,
                table,
                "lo",
                Some((address.network(), address.prefix_len())),
            ));
        }
        priority6 += 1;
        rules.push(rule_for_table(family(true), priority6, table, None));
        rules.push(nop_rule(family(true), nop_priority));
    }
    rules
}

fn family(ipv6: bool) -> AddressFamily {
    if ipv6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    }
}

fn new_rule(family: AddressFamily, priority: u32) -> RuleMessage {
    let mut rule = RuleMessage::default();
    rule.header.family = family;
    rule.header.table = RouteHeader::RT_TABLE_UNSPEC;
    rule.attributes.push(RuleAttribute::Priority(priority));
    rule
}

fn set_table(rule: &mut RuleMessage, table: u32) {
    rule.header.action = RuleAction::ToTable;
    if table < 256 {
        rule.header.table = table as u8;
    } else {
        rule.attributes.push(RuleAttribute::Table(table));
    }
}

fn set_source(rule: &mut RuleMessage, address: IpAddr, prefix: u8) {
    rule.header.src_len = prefix;
    rule.attributes.push(RuleAttribute::Source(address));
}

fn set_destination(rule: &mut RuleMessage, address: IpAddr, prefix: u8) {
    rule.header.dst_len = prefix;
    rule.attributes.push(RuleAttribute::Destination(address));
}

fn rule_for_table(
    family: AddressFamily,
    priority: u32,
    table: u32,
    network: Option<(IpAddr, u8, bool)>,
) -> RuleMessage {
    let mut rule = new_rule(family, priority);
    set_table(&mut rule, table);
    if let Some((address, prefix, source)) = network {
        if source {
            set_source(&mut rule, address, prefix);
        } else {
            set_destination(&mut rule, address, prefix);
        }
    }
    rule
}

fn rule_suppress(
    family: AddressFamily,
    priority: u32,
    table: u32,
) -> RuleMessage {
    let mut rule = rule_for_table(family, priority, table, None);
    rule.attributes.push(RuleAttribute::SuppressPrefixLen(0));
    rule
}

fn rule_main_non_dns(family: AddressFamily, priority: u32) -> RuleMessage {
    let mut rule =
        rule_suppress(family, priority, u32::from(RouteHeader::RT_TABLE_MAIN));
    rule.header.flags |= RuleFlags::Invert;
    rule.attributes
        .push(RuleAttribute::DestinationPortRange(RulePortRange {
            start: 53,
            end: 53,
        }));
    rule
}

fn rule_goto_interface(
    family: AddressFamily,
    priority: u32,
    interface: &str,
    target: u32,
) -> RuleMessage {
    let mut rule = new_rule(family, priority);
    rule.header.action = RuleAction::Goto;
    rule.attributes
        .push(RuleAttribute::Iifname(interface.into()));
    rule.attributes.push(RuleAttribute::Goto(target));
    rule
}

fn goto_rule(family: AddressFamily, priority: u32, target: u32) -> RuleMessage {
    let mut rule = new_rule(family, priority);
    rule.header.action = RuleAction::Goto;
    rule.attributes.push(RuleAttribute::Goto(target));
    rule
}

fn set_mark(rule: &mut RuleMessage, mark: u32) {
    rule.attributes.push(RuleAttribute::FwMark(mark));
}

fn rule_goto_mark(
    family: AddressFamily,
    priority: u32,
    mark: u32,
    target: u32,
) -> RuleMessage {
    let mut rule = goto_rule(family, priority, target);
    set_mark(&mut rule, mark);
    rule
}

fn rule_for_table_mark(
    family: AddressFamily,
    priority: u32,
    table: u32,
    mark: u32,
) -> RuleMessage {
    let mut rule = rule_for_table(family, priority, table, None);
    set_mark(&mut rule, mark);
    rule
}

fn rule_goto_uid(
    family: AddressFamily,
    priority: u32,
    uid: UidRange,
    target: u32,
) -> RuleMessage {
    let mut rule = goto_rule(family, priority, target);
    rule.attributes.push(RuleAttribute::UidRange(RuleUidRange {
        start: uid.start,
        end: uid.end,
    }));
    rule
}

fn rule_inverted_loopback(
    family: AddressFamily,
    priority: u32,
    table: u32,
) -> RuleMessage {
    let mut rule = rule_for_table(family, priority, table, None);
    rule.header.flags |= RuleFlags::Invert;
    rule.attributes.push(RuleAttribute::Iifname("lo".into()));
    rule
}

fn rule_for_table_with_interface(
    family: AddressFamily,
    priority: u32,
    table: u32,
    interface: &str,
    source: Option<(IpAddr, u8)>,
) -> RuleMessage {
    let mut rule = rule_for_table(family, priority, table, None);
    rule.attributes
        .push(RuleAttribute::Iifname(interface.into()));
    if let Some((source, prefix)) = source {
        set_source(&mut rule, source, prefix);
    }
    rule
}

fn rule_goto_source(
    family: AddressFamily,
    priority: u32,
    source: IpAddr,
    prefix: u8,
    interface: &str,
    target: u32,
) -> RuleMessage {
    let mut rule = rule_goto_interface(family, priority, interface, target);
    set_source(&mut rule, source, prefix);
    rule
}

fn nop_rule(family: AddressFamily, priority: u32) -> RuleMessage {
    let mut rule = new_rule(family, priority);
    rule.header.action = RuleAction::Nop;
    rule
}

fn unreachable_rule(family: AddressFamily, priority: u32) -> RuleMessage {
    let mut rule = new_rule(family, priority);
    rule.header.action = RuleAction::Unreachable;
    rule
}

fn parse_uid_ranges(
    values: &[String],
    field: &str,
) -> Result<Vec<UidRange>, String> {
    values
        .iter()
        .map(|value| {
            let (start, end) = value.split_once(':').ok_or_else(|| {
                format!("parse {field}: missing ':' in range: {value}")
            })?;
            if start.is_empty() {
                return Err(format!(
                    "parse {field}: missing range start: {value}"
                ));
            }
            if end.is_empty() {
                return Err(format!(
                    "parse {field}: missing range end: {value}"
                ));
            }
            Ok(UidRange {
                start: parse_go_uint32(start).map_err(|error| {
                    format!("parse {field}: parse range start: {error}")
                })?,
                end: parse_go_uint32(end).map_err(|error| {
                    format!("parse {field}: parse range end: {error}")
                })?,
            })
        })
        .collect()
}

fn parse_go_uint32(value: &str) -> Result<u32, String> {
    let value = value.strip_prefix('+').unwrap_or(value);
    let (digits, radix) = if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (value, 16)
    } else if let Some(value) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        (value, 2)
    } else if let Some(value) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        (value, 8)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    u32::from_str_radix(digits, radix).map_err(|error| error.to_string())
}

fn build_excluded_ranges(
    includes: Vec<UidRange>,
    excludes: Vec<UidRange>,
) -> Vec<UidRange> {
    if includes.is_empty() {
        return merge_ranges(excludes);
    }
    let included =
        subtract_ranges(merge_ranges(includes), merge_ranges(excludes));
    if included.is_empty() {
        return Vec::new();
    }
    complement_ranges(included, USER_END)
}

fn merge_ranges(mut ranges: Vec<UidRange>) -> Vec<UidRange> {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<UidRange> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end.saturating_add(1)
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn subtract_ranges(
    includes: Vec<UidRange>,
    excludes: Vec<UidRange>,
) -> Vec<UidRange> {
    let mut output = Vec::new();
    for include in includes {
        let mut fragments = vec![include];
        for exclude in &excludes {
            fragments = fragments
                .into_iter()
                .flat_map(|fragment| subtract_uid_range(fragment, *exclude))
                .collect();
        }
        output.extend(fragments);
    }
    merge_ranges(output)
}

fn subtract_uid_range(range: UidRange, excluded: UidRange) -> Vec<UidRange> {
    if excluded.end < range.start || excluded.start > range.end {
        return vec![range];
    }
    let mut output = Vec::new();
    if excluded.start > range.start {
        output.push(UidRange {
            start: range.start,
            end: excluded.start - 1,
        });
    }
    if excluded.end < range.end {
        output.push(UidRange {
            start: excluded.end + 1,
            end: range.end,
        });
    }
    output
}

fn complement_ranges(included: Vec<UidRange>, end: u32) -> Vec<UidRange> {
    let mut output = Vec::new();
    let mut cursor = 0_u32;
    for range in included {
        if range.start > cursor {
            output.push(UidRange {
                start: cursor,
                end: range.start - 1,
            });
        }
        cursor = range.end.saturating_add(1);
        if cursor > end {
            return output;
        }
    }
    if cursor <= end {
        output.push(UidRange { start: cursor, end });
    }
    output
}

fn netlink_error(error: rtnetlink::Error) -> io::Error {
    match error {
        rtnetlink::Error::NetlinkError(message) => message.to_io(),
        error => io::Error::other(error.to_string()),
    }
}

fn netlink_error_kind(error: &rtnetlink::Error) -> io::ErrorKind {
    match error {
        rtnetlink::Error::NetlinkError(message) => message.to_io().kind(),
        _ => io::ErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use rtnetlink::{
        RouteMessageBuilder,
        packet_route::{
            route::{RouteAttribute, RouteHeader},
            rule::{RuleAction, RuleAttribute, RuleFlags},
        },
    };
    use serde_json::json;

    use super::{
        DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_PRIORITY, DEFAULT_ROUTE_TABLE,
        DEFAULT_RULE_PRIORITY, LinuxPolicyOptions, RedirectInterface,
        RedirectRouteKey, USER_END, UidRange, bridge_policy_rules,
        build_auto_redirect_rules, build_rules,
        calculate_redirect_route_changes, calculate_redirect_route_keys,
        gateway, redirect_route_key_from_message, redirect_route_message,
        route_table, rp_filter_path, set_bridge_route_table,
    };
    use crate::option::TunInboundOptions;

    #[test]
    fn rp_filter_path_is_interface_scoped_and_rejects_traversal() {
        assert_eq!(
            rp_filter_path("tun0").unwrap(),
            std::path::Path::new("/proc/sys/net/ipv4/conf/tun0/rp_filter")
        );
        assert!(rp_filter_path("../all").is_err());
        assert!(rp_filter_path("").is_err());
    }

    fn policy(value: serde_json::Value) -> LinuxPolicyOptions {
        LinuxPolicyOptions::from_options(
            &serde_json::from_value::<TunInboundOptions>(value).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn bridge_policy_rules_precede_tun_rules_and_pin_only_forwarded_flows() {
        let port = "192.0.2.1".parse().unwrap();
        let rules = bridge_policy_rules("bridge0", port, 2200, 100);
        assert_eq!(
            rules[0].attributes,
            [
                RuleAttribute::Priority(100),
                RuleAttribute::Table(2200),
                RuleAttribute::Iifname("bridge0".into()),
            ]
        );
        assert_eq!(rules[1].header.table, RouteHeader::RT_TABLE_MAIN);
        assert_eq!(rules[1].header.dst_len, 32);
        assert!(rules[1].attributes.contains(&RuleAttribute::Priority(101)));
        assert!(
            rules[1]
                .attributes
                .contains(&RuleAttribute::Destination(port))
        );

        let automatic = bridge_policy_rules("bridge0", port, 0, 100);
        assert_eq!(automatic[0].header.table, RouteHeader::RT_TABLE_MAIN);
        assert!(
            !automatic[0]
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, RuleAttribute::Table(_)))
        );
    }

    #[test]
    fn bridge_route_copy_uses_extended_table_attribute() {
        let route = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .table_id(254)
            .build();
        let route = set_bridge_route_table(route, 2200);
        assert_eq!(route.header.table, RouteHeader::RT_TABLE_UNSPEC);
        assert!(route.attributes.contains(&RouteAttribute::Table(2200)));
        assert_eq!(route_table(&route), 2200);
    }

    #[test]
    fn builds_upstream_dual_stack_default_policy_shape() {
        let addresses = vec![
            "10.14.14.9/30".parse().unwrap(),
            "fdfe:dcba:9876::1/126".parse().unwrap(),
        ];
        let rules = build_rules(
            "tun0",
            &addresses,
            DEFAULT_ROUTE_TABLE,
            DEFAULT_RULE_PRIORITY,
            &policy(json!({})),
        );
        assert_eq!(rules.len(), 16);
        assert_eq!(rules[0].header.action, RuleAction::ToTable);
        assert!(rules[2].header.flags.contains(RuleFlags::Invert));
        assert!(rules.iter().any(|rule| {
            rule.attributes
                .contains(&RuleAttribute::Goto(DEFAULT_RULE_PRIORITY + 10))
        }));
        assert_eq!(rules.last().unwrap().header.action, RuleAction::Nop);
    }

    #[test]
    fn builds_upstream_auto_redirect_mark_mode_rules() {
        let addresses = vec![
            "10.14.14.9/30".parse().unwrap(),
            "fdfe:dcba:9876::1/126".parse().unwrap(),
        ];
        let rules = build_auto_redirect_rules(
            &addresses,
            DEFAULT_ROUTE_TABLE,
            DEFAULT_RULE_PRIORITY,
            0x2023,
            0x2024,
            DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_PRIORITY,
        );
        assert_eq!(rules.len(), 8);
        for family_rules in rules.chunks_exact(4) {
            assert_eq!(family_rules[0].header.action, RuleAction::Goto);
            assert!(
                family_rules[0]
                    .attributes
                    .contains(&RuleAttribute::Priority(DEFAULT_RULE_PRIORITY))
            );
            assert!(
                family_rules[0]
                    .attributes
                    .contains(&RuleAttribute::FwMark(0x2024))
            );
            assert!(!family_rules[0].attributes.iter().any(
                |attribute| matches!(attribute, RuleAttribute::FwMask(_))
            ));
            assert!(
                family_rules[0]
                    .attributes
                    .contains(&RuleAttribute::Goto(DEFAULT_RULE_PRIORITY + 2))
            );

            assert_eq!(family_rules[1].header.action, RuleAction::ToTable);
            assert!(
                family_rules[1]
                    .attributes
                    .contains(&RuleAttribute::Priority(
                        DEFAULT_RULE_PRIORITY + 1
                    ))
            );
            assert!(
                family_rules[1]
                    .attributes
                    .contains(&RuleAttribute::FwMark(0x2023))
            );
            assert!(!family_rules[1].attributes.iter().any(
                |attribute| matches!(attribute, RuleAttribute::FwMask(_))
            ));

            assert_eq!(family_rules[2].header.action, RuleAction::Nop);
            assert!(
                family_rules[2]
                    .attributes
                    .contains(&RuleAttribute::Priority(
                        DEFAULT_RULE_PRIORITY + 2
                    ))
            );

            assert_eq!(family_rules[3].header.action, RuleAction::ToTable);
            assert!(family_rules[3].attributes.contains(
                &RuleAttribute::Priority(
                    DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_PRIORITY,
                )
            ));
        }
        assert_ne!(rules[0].header.family, rules[4].header.family);
    }

    #[test]
    fn include_and_exclude_uid_ranges_match_upstream_complement() {
        let policy = policy(json!({
            "include_uid":[1000],
            "include_uid_range":["0x3e8:04000"],
            "exclude_uid_range":"1500:1600"
        }));
        assert_eq!(
            policy.excluded_uids,
            [
                UidRange { start: 0, end: 999 },
                UidRange {
                    start: 1500,
                    end: 1600
                },
                UidRange {
                    start: 2049,
                    end: USER_END
                }
            ]
        );
    }

    #[test]
    fn interface_uid_and_strict_rules_preserve_upstream_priority_layout() {
        let addresses = vec!["10.14.14.9/30".parse().unwrap()];
        let policy = policy(json!({
            "exclude_uid": 501,
            "include_interface": ["eth0", "wlan0"],
            "strict_route": true
        }));
        let rules = build_rules(
            "tun0",
            &addresses,
            DEFAULT_ROUTE_TABLE,
            DEFAULT_RULE_PRIORITY,
            &policy,
        );
        assert!(rules.iter().any(|rule| {
            rule.attributes.contains(&RuleAttribute::UidRange(
                rtnetlink::packet_route::rule::RuleUidRange {
                    start: 501,
                    end: 501,
                },
            ))
        }));
        assert!(rules.iter().any(|rule| {
            rule.header.action == RuleAction::Unreachable
                && rule.header.family
                    == rtnetlink::packet_route::AddressFamily::Inet6
        }));
        assert!(rules.iter().any(|rule| {
            rule.attributes
                .contains(&RuleAttribute::Iifname("eth0".into()))
                && rule
                    .attributes
                    .contains(&RuleAttribute::Goto(DEFAULT_RULE_PRIORITY + 3))
        }));
    }

    #[test]
    fn linux_gateway_is_next_address_when_available() {
        let addresses = vec![
            "10.14.14.9/30".parse().unwrap(),
            "fdfe:dcba:9876::1/126".parse().unwrap(),
        ];
        assert_eq!(
            gateway(&addresses, false),
            Some("10.14.14.10".parse().unwrap())
        );
        assert_eq!(
            gateway(&addresses, true),
            Some("fdfe:dcba:9876::2".parse().unwrap())
        );
    }

    #[test]
    fn redirect_routes_cover_each_active_non_tun_address_family() {
        let interfaces = vec![
            RedirectInterface {
                index: 1,
                name: "lo".into(),
                up: true,
                loopback: true,
                has_ipv4: true,
                has_ipv6: true,
            },
            RedirectInterface {
                index: 2,
                name: "eth0".into(),
                up: true,
                loopback: false,
                has_ipv4: true,
                has_ipv6: true,
            },
            RedirectInterface {
                index: 3,
                name: "wlan0".into(),
                up: false,
                loopback: false,
                has_ipv4: true,
                has_ipv6: false,
            },
            RedirectInterface {
                index: 4,
                name: "tun0".into(),
                up: true,
                loopback: false,
                has_ipv4: true,
                has_ipv6: true,
            },
        ];
        assert_eq!(
            calculate_redirect_route_keys(&interfaces, "tun0", true, true),
            [
                RedirectRouteKey {
                    interface_index: 2,
                    ipv6: false,
                },
                RedirectRouteKey {
                    interface_index: 2,
                    ipv6: true,
                },
            ]
        );
    }

    #[test]
    fn redirect_route_is_host_scoped_local_loopback() {
        let route = redirect_route_message(
            0x1020_3040,
            RedirectRouteKey {
                interface_index: 17,
                ipv6: false,
            },
        )
        .unwrap();
        assert_eq!(route_table(&route), 0x1020_3040);
        assert_eq!(
            route.header.scope,
            rtnetlink::packet_route::route::RouteScope::Host
        );
        assert_eq!(
            route.header.kind,
            rtnetlink::packet_route::route::RouteType::Local
        );
        assert!(route.attributes.contains(
            &rtnetlink::packet_route::route::RouteAttribute::Oif(17)
        ));
        assert!(route.attributes.contains(
            &rtnetlink::packet_route::route::RouteAttribute::Destination(
                "127.0.0.1".parse::<std::net::IpAddr>().unwrap().into()
            )
        ));
        assert_eq!(
            redirect_route_key_from_message(&route),
            Some(RedirectRouteKey {
                interface_index: 17,
                ipv6: false,
            })
        );
    }

    #[test]
    fn redirect_route_reconciliation_restores_and_removes_interfaces() {
        let ipv4_eth0 = RedirectRouteKey {
            interface_index: 2,
            ipv6: false,
        };
        let ipv6_eth0 = RedirectRouteKey {
            interface_index: 2,
            ipv6: true,
        };
        let ipv4_removed = RedirectRouteKey {
            interface_index: 9,
            ipv6: false,
        };
        let (to_add, to_delete) = calculate_redirect_route_changes(
            [ipv4_eth0, ipv6_eth0],
            [ipv4_eth0, ipv4_removed],
        );
        assert_eq!(to_add, [ipv6_eth0]);
        assert_eq!(to_delete, [ipv4_removed]);
    }
}
