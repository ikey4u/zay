use std::{io, net::IpAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tun::{AbstractDevice as _, Configuration, Layer};

use super::{BridgeOutbound, BridgeWrite, RunningBridge};
use crate::inbound::{
    tun_auto_redirect_linux::LinuxBridgeNftLease,
    tun_route_linux::LinuxBridgeRouteLease,
};

const BRIDGE_MTU: u16 = u16::MAX;
const DEFAULT_BRIDGE_RULE_INDEX: u32 = 100;
const DEFAULT_BRIDGE_TABLE_INDEX_BASE: u32 = 2200;

pub(crate) struct LinuxBridge {
    cancellation: CancellationToken,
    pump: JoinHandle<io::Result<()>>,
    system: LinuxSystemLease,
}

pub(crate) async fn start(
    bridge: Arc<BridgeOutbound>,
) -> io::Result<RunningBridge> {
    let options = bridge.options();
    if options.iproute2_table_index < 0 || options.iproute2_rule_index < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bridge iproute2 indices must be non-negative",
        ));
    }
    let rule_priority = u32::try_from(options.iproute2_rule_index)
        .ok()
        .filter(|priority| *priority != 0)
        .unwrap_or(DEFAULT_BRIDGE_RULE_INDEX);
    let route_table = (!options.interface.is_empty())
        .then(|| {
            u32::try_from(options.iproute2_table_index)
                .ok()
                .filter(|table| *table != 0)
                .unwrap_or(
                    DEFAULT_BRIDGE_TABLE_INDEX_BASE + bridge._index.0 as u32,
                )
        })
        .unwrap_or(0);
    if matches!(route_table, 253..=255) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bridge route table cannot replace the default, main, or local table",
        ));
    }
    let base_name = if options.bridge_name.is_empty() {
        "bridge"
    } else {
        &options.bridge_name
    };
    let tun_name = format!("{base_name}{}", bridge._index.0);
    if tun_name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bridge TUN interface name is too long",
        ));
    }
    let requested_name = tun_name.clone();
    let device = tokio::task::spawn_blocking(move || {
        let mut configuration = Configuration::default();
        configuration
            .layer(Layer::L3)
            .mtu(BRIDGE_MTU)
            .tun_name(requested_name)
            .up();
        tun::create_as_async(&configuration).map_err(io::Error::from)
    })
    .await
    .map_err(|error| io::Error::other(error.to_string()))??;
    let actual_name = device.tun_name().map_err(io::Error::from)?;
    let ports = vec![bridge.ipv4_port, bridge.ipv6_port];
    let (system, ipv6_active) = LinuxSystemLease::enable(
        &actual_name,
        ports,
        (!options.interface.is_empty()).then_some(options.interface.as_str()),
        route_table,
        rule_priority,
    )
    .await?;
    bridge.set_ipv6_active(ipv6_active);

    let (writes, mut write_rx) = mpsc::channel::<BridgeWrite>(64);
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let pump_bridge = bridge.clone();
    let (mut reader, mut writer) = tokio::io::split(device);
    let pump = tokio::spawn(async move {
        let mut packet = vec![0u8; u16::MAX as usize];
        loop {
            tokio::select! {
                _ = task_cancellation.cancelled() => break,
                result = reader.read(&mut packet) => {
                    let size = result?;
                    if size != 0 {
                        pump_bridge.deliver_return(packet[..size].to_vec());
                    }
                }
                request = write_rx.recv() => {
                    let Some(request) = request else { break };
                    let result = async {
                        for packet in request.packets {
                            writer.write_all(&packet).await?;
                        }
                        Ok(())
                    }.await;
                    let failed = result.is_err();
                    let _ = request.result.send(result);
                    if failed {
                        break;
                    }
                }
            }
        }
        Ok(())
    });
    Ok(RunningBridge {
        writes,
        backend: LinuxBridge {
            cancellation,
            pump,
            system,
        },
    })
}

impl LinuxBridge {
    pub(crate) async fn close(mut self) -> io::Result<()> {
        self.cancellation.cancel();
        let pump_result = match self.pump.await {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(error.to_string())),
        };
        let cleanup_result = self.system.close().await;
        match (pump_result, cleanup_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(pump), Err(cleanup)) => Err(io::Error::other(format!(
                "bridge packet pump: {pump}; bridge system cleanup: {cleanup}"
            ))),
        }
    }
}

struct LinuxSystemLease {
    routes: LinuxBridgeRouteLease,
    nftables: Arc<tokio::sync::Mutex<LinuxBridgeNftLease>>,
    mtu_cancellation: CancellationToken,
    mtu_task: Option<JoinHandle<()>>,
    forwarding: Vec<(String, String)>,
}

impl LinuxSystemLease {
    async fn enable(
        interface: &str,
        ports: Vec<IpAddr>,
        pinned_egress: Option<&str>,
        route_table: u32,
        rule_priority: u32,
    ) -> io::Result<(Self, bool)> {
        let enable_ipv4 = ports.iter().any(IpAddr::is_ipv4);
        let enable_ipv6 = ports.iter().any(IpAddr::is_ipv6);
        let initial_mtu = bridge_egress_mtu(pinned_egress).await;
        let mut nftables = LinuxBridgeNftLease::install(
            format!("sing-box-{interface}"),
            interface.to_owned(),
            enable_ipv4,
            enable_ipv6,
            initial_mtu,
        )
        .await?;
        let ipv6_active = enable_ipv6 && nftables.ipv6_active();
        let active_ports = ports
            .into_iter()
            .filter(|port| port.is_ipv4() || ipv6_active)
            .collect::<Vec<_>>();
        let routes = match LinuxBridgeRouteLease::install(
            interface,
            active_ports,
            pinned_egress,
            route_table,
            rule_priority,
        )
        .await
        {
            Ok(routes) => routes,
            Err(error) => {
                let _ = nftables.close().await;
                return Err(error);
            }
        };
        let nftables = Arc::new(tokio::sync::Mutex::new(nftables));
        let mtu_cancellation = CancellationToken::new();
        let mut lease = Self {
            routes,
            nftables,
            mtu_cancellation,
            mtu_task: None,
            forwarding: Vec::new(),
        };
        if let Err(error) = lease
            .enable_forwarding(interface, enable_ipv4, ipv6_active)
            .await
        {
            let _ = lease.close().await;
            return Err(error);
        }
        lease.start_mtu_monitor(pinned_egress.map(str::to_owned));
        Ok((lease, ipv6_active))
    }

    fn start_mtu_monitor(&mut self, pinned_egress: Option<String>) {
        let nftables = self.nftables.clone();
        let cancellation = self.mtu_cancellation.clone();
        self.mtu_task = Some(tokio::spawn(async move {
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
                        let mtu = bridge_egress_mtu(pinned_egress.as_deref()).await;
                        let _ = nftables.lock().await.update_mtu(mtu).await;
                    }
                }
            }
        }));
    }

    async fn enable_forwarding(
        &mut self,
        interface: &str,
        enable_ipv4: bool,
        enable_ipv6: bool,
    ) -> io::Result<()> {
        let mut paths = Vec::new();
        if enable_ipv4 {
            paths.push("/proc/sys/net/ipv4/ip_forward".to_owned());
            paths
                .push(format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter"));
        }
        if enable_ipv6 {
            paths.push("/proc/sys/net/ipv6/conf/all/forwarding".to_owned());
        }
        let mut enabled_ipv6_forwarding = false;
        for path in paths {
            let Ok(old) = tokio::fs::read_to_string(&path).await else {
                continue;
            };
            let old = old.trim().to_owned();
            let next = if path.ends_with("rp_filter") {
                "2"
            } else {
                "1"
            };
            if old != next && tokio::fs::write(&path, next).await.is_err() {
                continue;
            }
            if path.ends_with("/ipv6/conf/all/forwarding") && old != "1" {
                enabled_ipv6_forwarding = true;
            }
            self.forwarding.push((path, old));
        }
        if enabled_ipv6_forwarding {
            self.overrule_accept_ra().await;
        }
        Ok(())
    }

    async fn overrule_accept_ra(&mut self) {
        let Ok(mut entries) =
            tokio::fs::read_dir("/proc/sys/net/ipv6/conf").await
        else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_name() == "all" {
                continue;
            }
            let path = entry.path().join("accept_ra");
            let Ok(old) = tokio::fs::read_to_string(&path).await else {
                continue;
            };
            let old = old.trim().to_owned();
            if old != "1" || tokio::fs::write(&path, "2").await.is_err() {
                continue;
            }
            self.forwarding
                .push((path.to_string_lossy().into_owned(), old));
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        let mut errors = Vec::new();
        self.mtu_cancellation.cancel();
        if let Some(task) = self.mtu_task.take()
            && let Err(error) = task.await
        {
            errors.push(format!("bridge MTU monitor: {error}"));
        }
        if let Err(error) = self.nftables.lock().await.close().await {
            errors.push(format!("remove bridge nftables: {error}"));
        }
        if let Err(error) = self.routes.close().await {
            errors.push(format!("remove bridge routes: {error}"));
        }
        for (path, value) in self.forwarding.drain(..).rev() {
            if let Err(error) = tokio::fs::write(&path, value).await {
                errors.push(format!("restore {path}: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
}

async fn bridge_egress_mtu(pinned_egress: Option<&str>) -> u16 {
    let interface = match pinned_egress {
        Some(interface) => Some(interface.to_owned()),
        None => default_route_interface().await,
    };
    let Some(interface) = interface else {
        return BRIDGE_MTU;
    };
    if interface.is_empty()
        || interface.as_bytes().contains(&0)
        || interface.contains('/')
    {
        return BRIDGE_MTU;
    }
    tokio::fs::read_to_string(format!("/sys/class/net/{interface}/mtu"))
        .await
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|mtu| (576..=u32::from(BRIDGE_MTU)).contains(mtu))
        .map(|mtu| mtu as u16)
        .unwrap_or(BRIDGE_MTU)
}

async fn default_route_interface() -> Option<String> {
    if let Ok(routes) = tokio::fs::read_to_string("/proc/net/route").await
        && let Some(interface) = parse_ipv4_default_interface(&routes)
    {
        return Some(interface);
    }
    tokio::fs::read_to_string("/proc/net/ipv6_route")
        .await
        .ok()
        .and_then(|routes| parse_ipv6_default_interface(&routes))
}

fn parse_ipv4_default_interface(routes: &str) -> Option<String> {
    routes
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
            Some((fields[6].parse::<u32>().ok()?, fields[0].to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, interface)| interface)
}

fn parse_ipv6_default_interface(routes: &str) -> Option<String> {
    routes
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10
                || fields[0] != "00000000000000000000000000000000"
                || fields[1] != "00"
            {
                return None;
            }
            let flags = u32::from_str_radix(fields[8], 16).ok()?;
            if flags & 1 == 0 {
                return None;
            }
            Some((
                u32::from_str_radix(fields[5], 16).ok()?,
                fields[9].to_owned(),
            ))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, interface)| interface)
}

#[cfg(test)]
mod tests {
    use super::{parse_ipv4_default_interface, parse_ipv6_default_interface};

    #[test]
    fn default_route_parsers_choose_the_lowest_metric_active_interface() {
        let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 01020304 0003 0 0 100 00000000\nwlan0 00000000 01020304 0003 0 0 50 00000000\n";
        assert_eq!(
            parse_ipv4_default_interface(ipv4).as_deref(),
            Some("wlan0")
        );
        let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000040 00000000 00000000 00000001 eth0\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000020 00000000 00000000 00000001 wlan0\n";
        assert_eq!(
            parse_ipv6_default_interface(ipv6).as_deref(),
            Some("wlan0")
        );
    }
}
