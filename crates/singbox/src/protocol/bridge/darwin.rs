use std::{
    collections::{BTreeSet, HashMap},
    ffi::CStr,
    io,
    net::IpAddr,
    process::Stdio,
    sync::Arc,
};

use ipnet::IpNet;
use network_interface::{
    Addr as InterfaceAddr, NetworkInterface, NetworkInterfaceConfig as _,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::Command,
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tun::{AbstractDevice as _, Configuration, Layer};

use super::{BridgeOutbound, BridgeWrite, RunningBridge};

const BRIDGE_MTU: u16 = 2016;
const IPV4_LOCAL_BASE: u32 = u32::from_be_bytes([198, 51, 100, 1]);
const IPV6_LOCAL_BASE: u128 = u128::from_be_bytes([
    0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

pub(crate) struct DarwinBridge {
    cancellation: CancellationToken,
    pump: JoinHandle<io::Result<()>>,
    system: DarwinSystemLease,
}

pub(crate) async fn start(
    bridge: Arc<BridgeOutbound>,
) -> io::Result<RunningBridge> {
    let index = bridge._index.0;
    let ipv4_local = IpAddr::V4((IPV4_LOCAL_BASE + index as u32).into());
    let ipv6_local = IpAddr::V6((IPV6_LOCAL_BASE + index as u128).into());
    let ipv4_port = bridge.ipv4_port;
    let ipv6_port = bridge.ipv6_port;
    let requested_name = bridge.options().bridge_name.clone();

    let device = tokio::task::spawn_blocking(move || {
        let mut configuration = Configuration::default();
        configuration
            .layer(Layer::L3)
            .mtu(BRIDGE_MTU)
            .up()
            .address(ipv4_local)
            .destination(ipv4_port)
            .netmask("255.255.255.255");
        if requested_name.starts_with("utun") {
            configuration.tun_name(requested_name);
        }
        tun::create_as_async(&configuration).map_err(io::Error::from)
    })
    .await
    .map_err(|error| io::Error::other(error.to_string()))??;
    let tun_name = device.tun_name().map_err(io::Error::from)?;

    let ipv6_active = configure_ipv6(&tun_name, ipv6_local, ipv6_port)
        .await
        .is_ok();
    bridge.set_ipv6_active(ipv6_active);
    let egress = resolve_egress(&bridge.options().interface).await?;
    let mut system = DarwinSystemLease::enable(
        &tun_name,
        &egress,
        &bridge.options().interface,
        ipv4_port,
        ipv6_active.then_some(ipv6_port),
    )
    .await?;

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
    system.armed = true;
    Ok(RunningBridge {
        writes,
        backend: DarwinBridge {
            cancellation,
            pump,
            system,
        },
    })
}

impl DarwinBridge {
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

struct DarwinSystemLease {
    anchor: String,
    pf_token: Option<String>,
    forwarding: Vec<(&'static str, String)>,
    monitor_cancellation: CancellationToken,
    monitor_task: Option<JoinHandle<()>>,
    armed: bool,
}

impl DarwinSystemLease {
    async fn enable(
        tun_name: &str,
        egress: &Egress,
        requested_interface: &str,
        ipv4_port: IpAddr,
        ipv6_port: Option<IpAddr>,
    ) -> io::Result<Self> {
        let mut lease = Self {
            anchor: format!("com.apple/sing-box-{tun_name}"),
            pf_token: None,
            forwarding: Vec::new(),
            monitor_cancellation: CancellationToken::new(),
            monitor_task: None,
            armed: false,
        };
        let result = async {
            lease.enable_forwarding("net.inet.ip.forwarding").await?;
            if ipv6_port.is_some() {
                lease.enable_forwarding("net.inet6.ip6.forwarding").await?;
            }
            lease.pf_token = Some(enable_pf().await?);
            let rules = build_rules(tun_name, egress, ipv4_port, ipv6_port)?;
            load_anchor(&lease.anchor, &rules).await?;
            lease.start_monitor(
                tun_name.to_owned(),
                requested_interface.to_owned(),
                ipv4_port,
                ipv6_port,
                rules,
            );
            Ok(())
        }
        .await;
        if let Err(error) = result {
            let _ = lease.close().await;
            return Err(error);
        }
        Ok(lease)
    }

    fn start_monitor(
        &mut self,
        tun_name: String,
        requested_interface: String,
        ipv4_port: IpAddr,
        ipv6_port: Option<IpAddr>,
        mut current_rules: String,
    ) {
        let cancellation = self.monitor_cancellation.clone();
        let anchor = self.anchor.clone();
        self.monitor_task = Some(tokio::spawn(async move {
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
                        let rules = match resolve_egress(&requested_interface).await
                            .and_then(|egress| build_rules(
                                &tun_name,
                                &egress,
                                ipv4_port,
                                ipv6_port,
                            ))
                        {
                            Ok(rules) => rules,
                            Err(_) => build_drop_rules(
                                &tun_name,
                                ipv4_port,
                                ipv6_port,
                            ),
                        };
                        if rules == current_rules {
                            continue;
                        }
                        if load_anchor(&anchor, &rules).await.is_ok() {
                            current_rules = rules;
                        }
                    }
                }
            }
        }));
    }

    async fn enable_forwarding(&mut self, key: &'static str) -> io::Result<()> {
        let old = command_output("/usr/sbin/sysctl", &["-n", key]).await?;
        let old = old.trim().to_owned();
        if old != "1" {
            command_ok("/usr/sbin/sysctl", &["-w", &format!("{key}=1")])
                .await?;
        }
        self.forwarding.push((key, old));
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        let mut errors = Vec::new();
        self.monitor_cancellation.cancel();
        if let Some(task) = self.monitor_task.take()
            && let Err(error) = task.await
        {
            errors.push(format!("stop PF egress monitor: {error}"));
        }
        if !self.anchor.is_empty()
            && let Err(error) = load_anchor(&self.anchor, "").await
        {
            errors.push(format!("flush PF anchor: {error}"));
        }
        if let Some(token) = self.pf_token.take()
            && let Err(error) = command_ok("/sbin/pfctl", &["-X", &token]).await
        {
            errors.push(format!("release PF reference: {error}"));
        }
        for (key, value) in self.forwarding.drain(..).rev() {
            if value != "1"
                && let Err(error) = command_ok(
                    "/usr/sbin/sysctl",
                    &["-w", &format!("{key}={value}")],
                )
                .await
            {
                errors.push(format!("restore {key}: {error}"));
            }
        }
        self.armed = false;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
}

impl Drop for DarwinSystemLease {
    fn drop(&mut self) {
        debug_assert!(
            !self.armed,
            "Darwin bridge system lease dropped without asynchronous close"
        );
    }
}

struct Egress {
    interface: String,
    ipv4_gateway: Option<String>,
    ipv6_gateway: Option<String>,
    mtu: u16,
    pinned: bool,
    cellular: bool,
    broadcast: bool,
    loopback: bool,
    point_to_point: bool,
}

async fn resolve_egress(requested: &str) -> io::Result<Egress> {
    let ipv4 = route_get(false, requested).await.ok();
    let ipv6 = route_get(true, requested).await.ok();
    let interface = if requested.is_empty() {
        ipv4.as_deref()
            .and_then(|output| field(output, "interface"))
            .or_else(|| {
                ipv6.as_deref()
                    .and_then(|output| field(output, "interface"))
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no default egress interface",
                )
            })?
    } else {
        requested.to_owned()
    };
    let ipv4_gateway =
        ipv4.as_deref().and_then(|output| field(output, "gateway"));
    let ipv6_gateway = if requested.is_empty() {
        ipv6.as_deref()
            .filter(|output| {
                field(output, "interface").as_deref()
                    == Some(interface.as_str())
            })
            .and_then(|output| field(output, "gateway"))
    } else {
        ipv6.as_deref().and_then(|output| field(output, "gateway"))
    };
    let details = command_output("/sbin/ifconfig", &[&interface]).await?;
    let (mtu, broadcast, loopback, point_to_point) =
        parse_interface_details(&details);
    Ok(Egress {
        cellular: interface.starts_with("pdp_ip"),
        interface,
        ipv4_gateway,
        ipv6_gateway,
        mtu,
        pinned: !requested.is_empty(),
        broadcast,
        loopback,
        point_to_point,
    })
}

fn parse_interface_details(output: &str) -> (u16, bool, bool, bool) {
    let first = output.lines().next().unwrap_or_default();
    let mtu = first
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|fields| {
            (fields[0] == "mtu").then(|| fields[1].parse::<u32>().ok())?
        })
        .filter(|mtu| (576..=u32::from(BRIDGE_MTU)).contains(mtu))
        .map(|mtu| mtu as u16)
        .unwrap_or(BRIDGE_MTU);
    (
        mtu,
        first.contains("BROADCAST"),
        first.contains("LOOPBACK"),
        first.contains("POINTOPOINT"),
    )
}

async fn route_get(ipv6: bool, interface: &str) -> io::Result<String> {
    let mut args = vec!["-n", "get"];
    if ipv6 {
        args.push("-inet6");
    } else {
        args.push("-inet");
    }
    args.push("default");
    if !interface.is_empty() {
        args.extend(["-ifscope", interface]);
    }
    command_output("/sbin/route", &args).await
}

fn field(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then(|| value.trim().to_owned())
    })
}

async fn configure_ipv6(
    tun_name: &str,
    local: IpAddr,
    peer: IpAddr,
) -> io::Result<()> {
    command_ok(
        "/sbin/ifconfig",
        &[
            tun_name,
            "inet6",
            &local.to_string(),
            &peer.to_string(),
            "prefixlen",
            "128",
            "alias",
        ],
    )
    .await
}

fn build_rules(
    tun_name: &str,
    egress: &Egress,
    ipv4_port: IpAddr,
    ipv6_port: Option<IpAddr>,
) -> io::Result<String> {
    if !egress.pinned
        && !egress.cellular
        && (!egress.broadcast || egress.loopback || egress.point_to_point)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "bridge egress {} is not a physical or cellular interface",
                egress.interface
            ),
        ));
    }
    let mut rules = drop_rule_lines(tun_name, ipv4_port, ipv6_port);
    let (local_segments, ipv4_interfaces, ipv6_interfaces) =
        collect_local_segments(
            &egress.interface,
            egress.pinned,
            true,
            ipv6_port.is_some(),
        );
    append_family_rules(
        &mut rules,
        tun_name,
        egress,
        "inet",
        ipv4_port,
        egress.ipv4_gateway.as_deref(),
        egress.mtu - 40,
    );
    for interface in ipv4_interfaces {
        rules.push(format!(
            "nat on {interface} inet from {ipv4_port} to any -> ({interface})"
        ));
    }
    if let Some(ipv6_port) = ipv6_port {
        append_family_rules(
            &mut rules,
            tun_name,
            egress,
            "inet6",
            ipv6_port,
            egress.ipv6_gateway.as_deref(),
            egress.mtu - 60,
        );
        for interface in ipv6_interfaces {
            rules.push(format!(
                "nat on {interface} inet6 from {ipv6_port} to any -> ({interface})"
            ));
        }
    }
    for segment in local_segments {
        let (family, port) = if segment.addr().is_ipv4() {
            ("inet", ipv4_port)
        } else if let Some(ipv6_port) = ipv6_port {
            ("inet6", ipv6_port)
        } else {
            continue;
        };
        rules.push(format!(
            "pass in on {tun_name} {family} from {port} to {segment} keep state"
        ));
    }
    Ok(rules.join("\n") + "\n")
}

fn build_drop_rules(
    tun_name: &str,
    ipv4_port: IpAddr,
    ipv6_port: Option<IpAddr>,
) -> String {
    drop_rule_lines(tun_name, ipv4_port, ipv6_port).join("\n") + "\n"
}

fn drop_rule_lines(
    tun_name: &str,
    ipv4_port: IpAddr,
    ipv6_port: Option<IpAddr>,
) -> Vec<String> {
    let mut rules = vec![format!(
        "block drop in on {tun_name} inet from {ipv4_port} to any"
    )];
    if let Some(port) = ipv6_port {
        rules.push(format!(
            "block drop in on {tun_name} inet6 from {port} to any"
        ));
    }
    rules
}

fn append_family_rules(
    rules: &mut Vec<String>,
    tun_name: &str,
    egress: &Egress,
    family: &str,
    port: IpAddr,
    gateway: Option<&str>,
    max_mss: u16,
) {
    rules.push(format!(
        "scrub out on {} {family} proto tcp from {port} to any max-mss {max_mss}",
        egress.interface
    ));
    rules.push(format!(
        "nat on {} {family} from {port} to any -> ({})",
        egress.interface, egress.interface
    ));
    if let Some(route_to) = gateway
        .map(|gateway| format!("({} {gateway})", egress.interface))
        .or_else(|| {
            (egress.cellular || egress.pinned && egress.point_to_point)
                .then(|| format!("({})", egress.interface))
        })
    {
        let tag = format!("sing-box-{tun_name}");
        rules.push(format!(
            "pass in on {tun_name} {family} from {port} to any route-to {route_to} keep state tag {tag}"
        ));
        rules.push(format!(
            "pass out on {} {family} tagged {tag} reply-to ({tun_name} {port}) keep state",
            egress.interface
        ));
    }
}

fn collect_local_segments(
    egress: &str,
    pinned: bool,
    enable_ipv4: bool,
    enable_ipv6: bool,
) -> (Vec<IpNet>, Vec<String>, Vec<String>) {
    let Ok(interfaces) = NetworkInterface::show() else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let flags = interface_flags();
    let mut segments = BTreeSet::new();
    let mut ipv4_interfaces = BTreeSet::new();
    let mut ipv6_interfaces = BTreeSet::new();
    for interface in interfaces {
        if pinned && interface.name != egress {
            continue;
        }
        let flags = flags.get(&interface.name).copied().unwrap_or_default();
        if flags & libc::IFF_UP as u32 == 0
            || flags & libc::IFF_BROADCAST as u32 == 0
            || flags & libc::IFF_LOOPBACK as u32 != 0
            || flags & libc::IFF_POINTOPOINT as u32 != 0
        {
            continue;
        }
        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        for address in interface.addr {
            let network = match address {
                InterfaceAddr::V4(address)
                    if enable_ipv4 && !address.ip.is_link_local() =>
                {
                    has_ipv4 = true;
                    let prefix = address
                        .netmask
                        .map_or(32, |mask| u32::from(mask).count_ones() as u8);
                    IpNet::new(address.ip.into(), prefix).ok()
                }
                InterfaceAddr::V6(address)
                    if enable_ipv6 && !address.ip.is_unicast_link_local() =>
                {
                    has_ipv6 = true;
                    let prefix = address.netmask.map_or(128, |mask| {
                        u128::from(mask).count_ones() as u8
                    });
                    IpNet::new(address.ip.into(), prefix).ok()
                }
                _ => None,
            };
            if let Some(network) = network {
                segments.insert(network.trunc());
            }
        }
        if interface.name != egress {
            if has_ipv4 {
                ipv4_interfaces.insert(interface.name.clone());
            }
            if has_ipv6 {
                ipv6_interfaces.insert(interface.name);
            }
        }
    }
    (
        segments.into_iter().collect(),
        ipv4_interfaces.into_iter().collect(),
        ipv6_interfaces.into_iter().collect(),
    )
}

fn interface_flags() -> HashMap<String, u32> {
    let mut result = HashMap::new();
    let mut addresses = std::ptr::null_mut::<libc::ifaddrs>();
    // SAFETY: `getifaddrs` initializes a linked list owned by the caller. The
    // list remains valid until the single matching `freeifaddrs` below.
    if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
        return result;
    }
    let head = addresses;
    while !addresses.is_null() {
        // SAFETY: every node is part of the live list returned by getifaddrs.
        let address = unsafe { &*addresses };
        if !address.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated string for the node lifetime.
            if let Ok(name) =
                unsafe { CStr::from_ptr(address.ifa_name) }.to_str()
            {
                result
                    .entry(name.to_owned())
                    .and_modify(|flags| *flags |= address.ifa_flags)
                    .or_insert(address.ifa_flags);
            }
        }
        addresses = address.ifa_next;
    }
    // SAFETY: `head` is the original pointer returned by getifaddrs and has
    // not been freed or modified.
    unsafe { libc::freeifaddrs(head) };
    result
}

async fn enable_pf() -> io::Result<String> {
    let output = command_output("/sbin/pfctl", &["-E"]).await?;
    output
        .split_whitespace()
        .rev()
        .find(|word| word.chars().all(|character| character.is_ascii_digit()))
        .map(str::to_owned)
        .ok_or_else(|| {
            io::Error::other("pfctl did not return a reference token")
        })
}

async fn load_anchor(anchor: &str, rules: &str) -> io::Result<()> {
    let mut child = Command::new("/sbin/pfctl")
        .args(["-a", anchor, "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("pfctl stdin unavailable"))?
        .write_all(rules.as_bytes())
        .await?;
    let output = child.wait_with_output().await?;
    output_result("pfctl", output)
}

async fn command_ok(program: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(program).args(args).output().await?;
    output_result(program, output)
}

async fn command_output(program: &str, args: &[&str]) -> io::Result<String> {
    let output = Command::new(program).args(args).output().await?;
    if !output.status.success() {
        return Err(command_error(program, &output));
    }
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

fn output_result(
    program: &str,
    output: std::process::Output,
) -> io::Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, &output))
    }
}

fn command_error(program: &str, output: &std::process::Output) -> io::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    io::Error::other(format!(
        "{program} exited with {}: {}{}",
        output.status,
        stderr.trim(),
        stdout.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_pin_and_masquerade_both_families() {
        let rules = build_rules(
            "utun7",
            &Egress {
                interface: "en0".into(),
                ipv4_gateway: Some("192.168.1.1".into()),
                ipv6_gateway: Some("fe80::1%en0".into()),
                mtu: 1500,
                pinned: true,
                cellular: false,
                broadcast: true,
                loopback: false,
                point_to_point: false,
            },
            "192.0.2.1".parse().unwrap(),
            Some("2001:db8::1".parse().unwrap()),
        )
        .unwrap();
        assert!(rules.contains("nat on en0 inet from 192.0.2.1"));
        assert!(rules.contains("route-to (en0 192.168.1.1)"));
        assert!(rules.contains("nat on en0 inet6 from 2001:db8::1"));
        assert!(rules.contains("max-mss 1460"));
        assert!(rules.contains("tag sing-box-utun7"));
        assert!(rules.contains("reply-to (utun7 192.0.2.1)"));
        assert!(rules.starts_with("block drop in on utun7 inet"));
    }

    #[test]
    fn parses_ifconfig_flags_and_bounds_mtu() {
        assert_eq!(
            parse_interface_details(
                "en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500"
            ),
            (1500, true, false, false)
        );
        assert_eq!(
            parse_interface_details(
                "utun0: flags=8051<UP,POINTOPOINT,RUNNING> mtu 9000"
            ),
            (2016, false, false, true)
        );
    }
}
