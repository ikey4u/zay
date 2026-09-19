//! iOS Simulator data-plane probe.
//!
//! CoreSimulator does not provide the Network Extension preference daemon, so
//! `NETunnelProviderManager` fails before it can launch a Packet Tunnel.  This
//! probe still executes the exact iOS Rust runtime and TUN boundary in the
//! simulator process: a datagram socketpair replaces the unavailable kernel
//! packet flow and a second smoltcp stack behaves as the device-side client.

use std::{
    ffi::c_char,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::{FromRawFd as _, IntoRawFd as _, OwnedFd},
    os::unix::net::UnixDatagram as StdUnixDatagram,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::json;
use singbox::{
    Options, PlatformNetworkInterface, PlatformNetworkProvider, PlatformSocket,
    Runtime, TunDeviceRequest, TunFileDescriptorProvider,
    endpoint::tokio_smoltcp::{
        Net, NetConfig,
        channel_device::ChannelDevice,
        smoltcp::{
            iface::Config as InterfaceConfig,
            phy::{DeviceCapabilities, Medium},
            wire::{HardwareAddress, IpAddress, IpCidr},
        },
    },
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::error::{clear_error, set_error, to_cstring};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

struct ProbeTunProvider {
    engine_fd: Mutex<Option<OwnedFd>>,
    request: Mutex<Option<TunDeviceRequest>>,
}

impl TunFileDescriptorProvider for ProbeTunProvider {
    fn open_tun(&self, request: &TunDeviceRequest) -> io::Result<OwnedFd> {
        *self.request.lock().map_err(poisoned)? = Some(request.clone());
        self.engine_fd
            .lock()
            .map_err(poisoned)?
            .take()
            .ok_or_else(|| {
                io::Error::other("simulator probe TUN already opened")
            })
    }
}

struct UnusedNetworkProvider;

impl PlatformNetworkProvider for UnusedNetworkProvider {
    fn network_interfaces(&self) -> io::Result<Vec<PlatformNetworkInterface>> {
        Ok(Vec::new())
    }

    fn bind_socket(
        &self,
        _socket: PlatformSocket,
        _interface: &PlatformNetworkInterface,
    ) -> io::Result<()> {
        Ok(())
    }
}

fn poisoned<T>(_error: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("simulator probe state poisoned")
}

fn owned_fd(socket: StdUnixDatagram) -> OwnedFd {
    let raw = socket.into_raw_fd();
    // SAFETY: into_raw_fd transferred the only ownership into `raw`.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn probe_config(socks_port: u16) -> String {
    json!({
        "log": {"level": "debug", "timestamp": true},
        "dns": {
            "servers": [
                {"type": "hosts", "tag": "fallback"},
                {
                    "type": "fakeip",
                    "tag": "fake-ip",
                    "inet4_range": "198.18.0.0/15"
                }
            ],
            "rules": [{
                "query_type": ["A", "AAAA"],
                "action": "route",
                "server": "fake-ip"
            }],
            "final": "fallback",
            "reverse_mapping": true
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-probe",
            "address": ["172.19.0.1/29"],
            "mtu": 1500,
            "auto_route": false,
            "stack": "system"
        }],
        "outbounds": [{
            "type": "socks",
            "tag": "probe-socks",
            "server": "127.0.0.1",
            "server_port": socks_port,
            "version": "5"
        }],
        "route": {
            "rules": [
                {"port": 53, "action": "hijack-dns"},
                {"protocol": "dns", "action": "hijack-dns"}
            ],
            "final": "probe-socks"
        }
    })
    .to_string()
}

fn dns_query(domain: &str, id: u16) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid probe DNS name",
            ));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

fn skip_dns_name(packet: &[u8], offset: &mut usize) -> io::Result<()> {
    loop {
        let length = *packet
            .get(*offset)
            .ok_or_else(|| io::Error::other("truncated DNS name"))?;
        *offset += 1;
        if length == 0 {
            return Ok(());
        }
        if length & 0xc0 == 0xc0 {
            *offset = offset
                .checked_add(1)
                .filter(|next| *next <= packet.len())
                .ok_or_else(|| io::Error::other("truncated DNS pointer"))?;
            return Ok(());
        }
        if length & 0xc0 != 0 {
            return Err(io::Error::other("invalid DNS label"));
        }
        *offset = offset
            .checked_add(usize::from(length))
            .filter(|next| *next <= packet.len())
            .ok_or_else(|| io::Error::other("truncated DNS label"))?;
    }
}

fn read_u16(packet: &[u8], offset: &mut usize) -> io::Result<u16> {
    let bytes: [u8; 2] = packet
        .get(*offset..*offset + 2)
        .ok_or_else(|| io::Error::other("truncated DNS field"))?
        .try_into()
        .expect("two-byte slice");
    *offset += 2;
    Ok(u16::from_be_bytes(bytes))
}

fn parse_fake_ipv4(packet: &[u8], expected_id: u16) -> io::Result<Ipv4Addr> {
    if packet.len() < 12
        || u16::from_be_bytes([packet[0], packet[1]]) != expected_id
    {
        return Err(io::Error::other("invalid DNS response header"));
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    let mut offset = 12;
    for _ in 0..questions {
        skip_dns_name(packet, &mut offset)?;
        offset = offset
            .checked_add(4)
            .filter(|next| *next <= packet.len())
            .ok_or_else(|| io::Error::other("truncated DNS question"))?;
    }
    for _ in 0..answers {
        skip_dns_name(packet, &mut offset)?;
        let record_type = read_u16(packet, &mut offset)?;
        let class = read_u16(packet, &mut offset)?;
        offset = offset
            .checked_add(4)
            .filter(|next| *next <= packet.len())
            .ok_or_else(|| io::Error::other("truncated DNS TTL"))?;
        let length = usize::from(read_u16(packet, &mut offset)?);
        let data = packet
            .get(offset..offset + length)
            .ok_or_else(|| io::Error::other("truncated DNS answer"))?;
        if record_type == 1 && class == 1 && data.len() == 4 {
            return Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        offset += length;
    }
    Err(io::Error::other("DNS response has no IPv4 answer"))
}

async fn exchange_domain(
    net: &Net,
    dns_server: IpAddr,
    domain: &str,
    index: u16,
) -> io::Result<serde_json::Value> {
    let id = 0x7a00_u16.wrapping_add(index);
    let udp = net
        .udp_bind(SocketAddr::new(
            "172.19.0.3".parse().unwrap(),
            53_000 + index,
        ))
        .await?;
    let query = dns_query(domain, id)?;
    udp.send_to(&query, SocketAddr::new(dns_server, 53)).await?;
    let mut response = vec![0_u8; 4096];
    let (length, _) =
        tokio::time::timeout(PROBE_TIMEOUT, udp.recv_from(&mut response))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS probe timed out")
            })??;
    let fake_ip = parse_fake_ipv4(&response[..length], id)?;
    let fake_range = Ipv4Addr::new(198, 18, 0, 0).to_bits()
        ..=Ipv4Addr::new(198, 19, 255, 255).to_bits();
    if !fake_range.contains(&fake_ip.to_bits()) {
        return Err(io::Error::other(format!(
            "DNS returned non-FakeIP address {fake_ip}"
        )));
    }

    let mut stream = tokio::time::timeout(
        PROBE_TIMEOUT,
        net.tcp_connect(SocketAddr::new(fake_ip.into(), 80), 40_000 + index),
    )
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "TCP probe timed out")
    })??;
    let request = format!(
        "GET /probe/{index} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut body = Vec::new();
    tokio::time::timeout(PROBE_TIMEOUT, stream.read_to_end(&mut body))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "HTTP probe timed out")
        })??;
    let response_text = String::from_utf8_lossy(&body);
    if !response_text.starts_with("HTTP/1.1 200")
        || !response_text.contains(domain)
    {
        return Err(io::Error::other(format!(
            "unexpected HTTP probe response: {}",
            response_text.chars().take(200).collect::<String>()
        )));
    }
    Ok(json!({
        "domain": domain,
        "fake_ip": fake_ip,
        "http_200": true
    }))
}

async fn run_probe_async(socks_port: u16) -> Result<String, String> {
    let (engine_socket, client_socket) =
        StdUnixDatagram::pair().map_err(|error| error.to_string())?;
    client_socket
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let provider = Arc::new(ProbeTunProvider {
        engine_fd: Mutex::new(Some(owned_fd(engine_socket))),
        request: Mutex::new(None),
    });
    let options: Options = serde_json::from_str(&probe_config(socks_port))
        .map_err(|error| format!("decode simulator probe config: {error}"))?;
    let mut runtime = Runtime::from_options_in_with_mobile_platform(
        options,
        Path::new("."),
        None,
        provider.clone(),
        Arc::new(UnusedNetworkProvider),
    )
    .map_err(|error| format!("configure simulator probe runtime: {error}"))?;
    runtime
        .start()
        .await
        .map_err(|error| format!("start simulator probe runtime: {error}"))?;

    let outcome = async {
        let request = provider
            .request
            .lock()
            .map_err(poisoned)?
            .clone()
            .ok_or_else(|| io::Error::other("TUN provider was not opened"))?;
        let dns_server = request
            .dns_servers
            .iter()
            .copied()
            .find(IpAddr::is_ipv4)
            .ok_or_else(|| io::Error::other("probe TUN has no IPv4 DNS server"))?;

        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = usize::from(request.mtu);
        let (device, ingress, _egress, mut output, icmp_errors) =
            ChannelDevice::new(capabilities);
        let client = tokio::net::UnixDatagram::from_std(client_socket)?;
        let bridge = tokio::spawn(async move {
            let mut packet = vec![0_u8; 65_535];
            loop {
                tokio::select! {
                    received = client.recv(&mut packet) => {
                        let length = received?;
                        if ingress.send(Ok(packet[..length].to_vec())).await.is_err() {
                            return Ok::<(), io::Error>(());
                        }
                    }
                    outgoing = output.recv() => match outgoing {
                        Some(outgoing) => { client.send(&outgoing).await?; }
                        None => return Ok(()),
                    }
                }
            }
        });

        let mut net_config = NetConfig::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            vec!["172.19.0.3/29"
                .parse::<IpCidr>()
                .map_err(|()| io::Error::other("invalid client CIDR"))?],
            vec![IpAddress::Ipv4(Ipv4Addr::new(172, 19, 0, 1))],
            None,
        );
        net_config.icmp_errors = Some(icmp_errors);
        let net = Net::new(device, net_config)?;
        let mut exchanges = Vec::new();
        for (index, domain) in ["alpha.zay.test", "beta.zay.test"]
            .into_iter()
            .enumerate()
        {
            exchanges.push(
                exchange_domain(&net, dns_server, domain, index as u16).await?,
            );
        }
        drop(net);
        bridge.abort();
        Ok::<_, io::Error>(json!({
            "ok": true,
            "dns_server": dns_server,
            "exchanges": exchanges
        }))
    }
    .await;

    let close_result = runtime.close().await;
    let result = outcome.map_err(|error| error.to_string())?;
    close_result
        .map_err(|error| format!("close simulator probe runtime: {error}"))?;
    serde_json::to_string(&result).map_err(|error| error.to_string())
}

fn run_probe(socks_port: u16) -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| format!("create simulator probe executor: {error}"))?;
    runtime.block_on(run_probe_async(socks_port))
}

/// Run the deterministic simulator TUN/DNS/SOCKS probe.
///
/// The returned JSON string is owned by the caller and must be released with
/// `zay_ios_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn zay_ios_run_simulator_tun_probe(
    socks_port: u16,
) -> *mut c_char {
    clear_error();
    match run_probe(socks_port).and_then(to_cstring) {
        Ok(result) => result,
        Err(error) => {
            set_error(error);
            std::ptr::null_mut()
        }
    }
}
