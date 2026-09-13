//! Async UDP lifecycle for OpenConnect ESP packets.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex as SyncMutex;
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{Dialer, PacketConnection},
    common::network::SocksAddr,
};

use super::{
    GlobalProtectEspProbe, OPENCONNECT_ESP_LZO_NEXT_HEADER,
    OpenConnectEspError, OpenConnectEspKeySet,
};

const ESP_CHANNEL_TIMER_RESOLUTION: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenConnectEspProbe {
    GlobalProtect(GlobalProtectEspProbe),
    Pulse,
}

impl From<GlobalProtectEspProbe> for OpenConnectEspProbe {
    fn from(probe: GlobalProtectEspProbe) -> Self {
        Self::GlobalProtect(probe)
    }
}

impl OpenConnectEspProbe {
    fn build(self, sequence: u16) -> Result<Vec<u8>, String> {
        match self {
            Self::GlobalProtect(probe) => {
                probe.build(sequence).map_err(|error| error.to_string())
            }
            Self::Pulse => Ok(vec![0]),
        }
    }

    fn matches(self, payload: &[u8]) -> bool {
        match self {
            Self::GlobalProtect(probe) => probe.matches(payload),
            Self::Pulse => payload == [0],
        }
    }
}

#[derive(Clone)]
pub struct OpenConnectEspSessionOptions {
    pub remote: SocketAddr,
    pub keys: Arc<OpenConnectEspKeySet>,
    pub mtu: usize,
    pub dpd: Duration,
    pub probe: OpenConnectEspProbe,
    /// Explicit IP protocol number for non-IP probes. Zero lets the ESP codec
    /// infer IPv4/IPv6 from the packet, as used by GlobalProtect.
    pub probe_next_header: u8,
    pub accept_lzo: bool,
    pub queue_length: usize,
}

#[derive(Debug, Error)]
pub enum OpenConnectEspChannelError {
    #[error(transparent)]
    Crypto(#[from] OpenConnectEspError),
    #[error("ESP UDP transport: {0}")]
    Io(#[source] io::Error),
    #[error("invalid ESP channel configuration: {0}")]
    InvalidConfiguration(String),
    #[error("ESP data channel is not established")]
    NotReady,
    #[error("ESP channel closed")]
    Closed,
    #[error("received unsupported LZO-compressed ESP payload")]
    LzoUnsupported,
    #[error("decompress ESP LZO1X payload: {0}")]
    Lzo(String),
    #[error("ESP probe window expired")]
    ProbeTimeout,
    #[error("ESP dead peer detection expired after {0:?}")]
    DeadPeer(Duration),
}

struct EspActivity {
    last_received: Instant,
    last_dpd: Option<Instant>,
}

pub struct OpenConnectEspSession {
    connection: Arc<dyn PacketConnection>,
    remote: SocksAddr,
    keys: Arc<OpenConnectEspKeySet>,
    mtu: usize,
    probe: OpenConnectEspProbe,
    probe_next_header: u8,
    probe_sequence: Arc<AtomicU16>,
    incoming: mpsc::Receiver<Result<Vec<u8>, OpenConnectEspChannelError>>,
    established: watch::Receiver<bool>,
    ready: Arc<AtomicBool>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl OpenConnectEspSession {
    pub async fn connect(
        dialer: Arc<dyn Dialer>,
        options: OpenConnectEspSessionOptions,
    ) -> Result<Self, OpenConnectEspChannelError> {
        if options.remote.port() == 0 {
            return Err(invalid_configuration("remote port is zero"));
        }
        if options.mtu == 0 || options.mtu > usize::from(u16::MAX) {
            return Err(invalid_configuration("MTU is outside 1..=65535"));
        }
        if options.dpd > Duration::from_secs(i64::MAX as u64 / 2) {
            return Err(invalid_configuration("DPD interval is too large"));
        }
        if let OpenConnectEspProbe::GlobalProtect(probe) = options.probe
            && !matches!(
                (probe.assigned, probe.magic),
                (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                    | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
            )
        {
            return Err(invalid_configuration(
                "probe address families do not match",
            ));
        }
        let remote = SocksAddr::new(
            options.remote.ip().to_string(),
            options.remote.port(),
        );
        let connection: Arc<dyn PacketConnection> = dialer
            .listen_udp(&remote)
            .await
            .map(Arc::from)
            .map_err(OpenConnectEspChannelError::Io)?;
        let cancellation = CancellationToken::new();
        let ready = Arc::new(AtomicBool::new(false));
        let (established_tx, established) = watch::channel(false);
        let (incoming_tx, incoming) =
            mpsc::channel(options.queue_length.max(1));
        let activity = Arc::new(SyncMutex::new(EspActivity {
            last_received: Instant::now(),
            last_dpd: None,
        }));
        let probe_sequence = Arc::new(AtomicU16::new(0));
        let read_task = tokio::spawn(read_loop(ReadLoop {
            connection: connection.clone(),
            remote: remote.clone(),
            keys: options.keys.clone(),
            probe: options.probe,
            accept_lzo: options.accept_lzo,
            mtu: options.mtu,
            ready: ready.clone(),
            established: established_tx,
            activity: activity.clone(),
            incoming: incoming_tx.clone(),
            cancellation: cancellation.clone(),
        }));
        let mut tasks = vec![read_task];
        if !options.dpd.is_zero() {
            tasks.push(tokio::spawn(timer_loop(TimerLoop {
                connection: connection.clone(),
                remote: remote.clone(),
                keys: options.keys.clone(),
                probe: options.probe,
                probe_next_header: options.probe_next_header,
                probe_sequence: probe_sequence.clone(),
                dpd: options.dpd,
                ready: ready.clone(),
                activity,
                incoming: incoming_tx,
                cancellation: cancellation.clone(),
            })));
        }
        Ok(Self {
            connection,
            remote,
            keys: options.keys,
            mtu: options.mtu,
            probe: options.probe,
            probe_next_header: options.probe_next_header,
            probe_sequence,
            incoming,
            established,
            ready,
            cancellation,
            tasks,
        })
    }

    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn install_keys(
        &self,
        configuration: &super::OpenConnectEspKeySetConfig,
    ) -> Result<(), OpenConnectEspChannelError> {
        self.keys.install(configuration).map_err(Into::into)
    }

    pub async fn establish(
        &mut self,
    ) -> Result<(), OpenConnectEspChannelError> {
        if self.ready() {
            return Ok(());
        }
        for _ in 0..5 {
            self.send_probe().await?;
            let established = tokio::time::timeout(
                Duration::from_secs(1),
                self.wait_established(),
            )
            .await;
            match established {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
        Err(OpenConnectEspChannelError::ProbeTimeout)
    }

    pub async fn send_probe(&self) -> Result<(), OpenConnectEspChannelError> {
        let sequence = self.probe_sequence.fetch_add(1, Ordering::AcqRel);
        let payload = self
            .probe
            .build(sequence)
            .map_err(|error| invalid_configuration(&error.to_string()))?;
        send_protected(
            &self.connection,
            &self.remote,
            &self.keys,
            &payload,
            false,
            self.probe_next_header,
        )
        .await
    }

    pub async fn write_data_packet(
        &self,
        payload: &[u8],
    ) -> Result<(), OpenConnectEspChannelError> {
        if !self.ready() {
            return Err(OpenConnectEspChannelError::NotReady);
        }
        if payload.len() > self.mtu {
            return Err(invalid_configuration(&format!(
                "data packet exceeds negotiated MTU: {} > {}",
                payload.len(),
                self.mtu
            )));
        }
        send_protected(
            &self.connection,
            &self.remote,
            &self.keys,
            payload,
            true,
            0,
        )
        .await
    }

    pub async fn read_data_packet(
        &mut self,
    ) -> Result<Option<Vec<u8>>, OpenConnectEspChannelError> {
        match self.incoming.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    pub async fn close(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.ready.store(false, Ordering::Release);
        self.keys.destroy();
    }

    async fn wait_established(
        &mut self,
    ) -> Result<(), OpenConnectEspChannelError> {
        loop {
            if *self.established.borrow() {
                return Ok(());
            }
            self.established
                .changed()
                .await
                .map_err(|_| OpenConnectEspChannelError::Closed)?;
        }
    }
}

impl Drop for OpenConnectEspSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
        self.keys.destroy();
    }
}

struct ReadLoop {
    connection: Arc<dyn PacketConnection>,
    remote: SocksAddr,
    keys: Arc<OpenConnectEspKeySet>,
    probe: OpenConnectEspProbe,
    accept_lzo: bool,
    mtu: usize,
    ready: Arc<AtomicBool>,
    established: watch::Sender<bool>,
    activity: Arc<SyncMutex<EspActivity>>,
    incoming: mpsc::Sender<Result<Vec<u8>, OpenConnectEspChannelError>>,
    cancellation: CancellationToken,
}

async fn read_loop(context: ReadLoop) {
    let mut buffer = vec![0_u8; (context.mtu + 256).max(2048)];
    loop {
        let received = tokio::select! {
            _ = context.cancellation.cancelled() => return,
            result = context.connection.recv_from(&mut buffer) => result,
        };
        let (length, source) = match received {
            Ok(received) => received,
            Err(error) => {
                send_error(&context, OpenConnectEspChannelError::Io(error))
                    .await;
                return;
            }
        };
        if length == 0 || source != context.remote {
            continue;
        }
        let (mut payload, next_header) =
            match context.keys.open(&buffer[..length]) {
                Ok(packet) => packet,
                Err(OpenConnectEspError::KeysDestroyed) => {
                    send_error(
                        &context,
                        OpenConnectEspChannelError::Crypto(
                            OpenConnectEspError::KeysDestroyed,
                        ),
                    )
                    .await;
                    return;
                }
                Err(_) => continue,
            };
        context.activity.lock().last_received = Instant::now();
        if context.probe.matches(&payload) {
            if !context.ready.swap(true, Ordering::AcqRel) {
                let _ = context.established.send(true);
            }
            continue;
        }
        if next_header == OPENCONNECT_ESP_LZO_NEXT_HEADER {
            if !context.accept_lzo {
                send_error(
                    &context,
                    OpenConnectEspChannelError::LzoUnsupported,
                )
                .await;
                return;
            }
            payload = match lzo1x::decompress(&payload, context.mtu) {
                Ok(payload) => payload,
                Err(error) => {
                    let _ = error;
                    continue;
                }
            };
        }
        if context.ready.load(Ordering::Acquire)
            && context.incoming.send(Ok(payload)).await.is_err()
        {
            context.cancellation.cancel();
            return;
        }
    }
}

struct TimerLoop {
    connection: Arc<dyn PacketConnection>,
    remote: SocksAddr,
    keys: Arc<OpenConnectEspKeySet>,
    probe: OpenConnectEspProbe,
    probe_next_header: u8,
    probe_sequence: Arc<AtomicU16>,
    dpd: Duration,
    ready: Arc<AtomicBool>,
    activity: Arc<SyncMutex<EspActivity>>,
    incoming: mpsc::Sender<Result<Vec<u8>, OpenConnectEspChannelError>>,
    cancellation: CancellationToken,
}

async fn timer_loop(context: TimerLoop) {
    let mut interval = tokio::time::interval(ESP_CHANNEL_TIMER_RESOLUTION);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = context.cancellation.cancelled() => return,
            _ = interval.tick() => {}
        }
        if !context.ready.load(Ordering::Acquire) {
            continue;
        }
        let now = Instant::now();
        enum TimerAction {
            None,
            Probe,
            DeadPeer,
        }
        let action = {
            let mut activity = context.activity.lock();
            if now.duration_since(activity.last_received) > context.dpd * 2 {
                TimerAction::DeadPeer
            } else {
                let due = activity.last_dpd.map_or(
                    activity.last_received + context.dpd,
                    |last_dpd| {
                        if last_dpd > activity.last_received {
                            last_dpd + context.dpd / 2
                        } else {
                            activity.last_received + context.dpd
                        }
                    },
                );
                if now >= due {
                    activity.last_dpd = Some(now);
                    TimerAction::Probe
                } else {
                    TimerAction::None
                }
            }
        };
        if matches!(action, TimerAction::DeadPeer) {
            let _ = context
                .incoming
                .send(Err(OpenConnectEspChannelError::DeadPeer(
                    context.dpd * 2,
                )))
                .await;
            context.cancellation.cancel();
            return;
        }
        if matches!(action, TimerAction::Probe) {
            let sequence =
                context.probe_sequence.fetch_add(1, Ordering::AcqRel);
            let payload = match context.probe.build(sequence) {
                Ok(payload) => payload,
                Err(error) => {
                    let _ = context
                        .incoming
                        .send(Err(invalid_configuration(&error.to_string())))
                        .await;
                    context.cancellation.cancel();
                    return;
                }
            };
            if let Err(error) = send_protected(
                &context.connection,
                &context.remote,
                &context.keys,
                &payload,
                false,
                context.probe_next_header,
            )
            .await
            {
                let _ = context.incoming.send(Err(error)).await;
                context.cancellation.cancel();
                return;
            }
        }
    }
}

async fn send_protected(
    connection: &Arc<dyn PacketConnection>,
    remote: &SocksAddr,
    keys: &Arc<OpenConnectEspKeySet>,
    payload: &[u8],
    require_nonempty: bool,
    next_header: u8,
) -> Result<(), OpenConnectEspChannelError> {
    if require_nonempty && payload.is_empty() {
        return Err(invalid_configuration("data packet is empty"));
    }
    let datagram =
        keys.seal(payload, (next_header != 0).then_some(next_header))?;
    let written = connection
        .send_to(&datagram, remote)
        .await
        .map_err(OpenConnectEspChannelError::Io)?;
    if written != datagram.len() {
        return Err(OpenConnectEspChannelError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "short ESP UDP write: wrote {written} of {} bytes",
                datagram.len()
            ),
        )));
    }
    Ok(())
}

async fn send_error(context: &ReadLoop, error: OpenConnectEspChannelError) {
    let _ = context.incoming.send(Err(error)).await;
    context.cancellation.cancel();
}

fn invalid_configuration(message: &str) -> OpenConnectEspChannelError {
    OpenConnectEspChannelError::InvalidConfiguration(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter::{DialFuture, PacketFuture, PacketStream},
        protocol::openconnect::{
            OpenConnectEspAuthentication, OpenConnectEspEncryption,
            OpenConnectEspKeyMaterial, OpenConnectEspKeySetConfig,
        },
    };
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    struct MemoryPacketConnection {
        incoming: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocksAddr)>>,
        outgoing: mpsc::Sender<(Vec<u8>, SocksAddr)>,
    }

    impl PacketConnection for MemoryPacketConnection {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                self.outgoing
                    .send((data.to_vec(), destination.clone()))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "closed")
                    })?;
                Ok(data.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(async move {
                let (packet, source) = self
                    .incoming
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "closed")
                    })?;
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), source))
            })
        }
    }

    struct MemoryDialer {
        connection: Mutex<Option<PacketStream>>,
    }

    impl Dialer for MemoryDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(io::Error::new(io::ErrorKind::Unsupported, "TCP"))
            })
        }

        fn listen_udp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, PacketStream> {
            Box::pin(async move {
                self.connection
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| io::Error::other("already taken"))
            })
        }
    }

    fn key_configs() -> (OpenConnectEspKeySetConfig, OpenConnectEspKeySetConfig)
    {
        let client = OpenConnectEspKeyMaterial {
            spi: 1,
            encryption_key: vec![1; 16],
            authentication_key: vec![2; 20],
        };
        let server = OpenConnectEspKeyMaterial {
            spi: 2,
            encryption_key: vec![3; 16],
            authentication_key: vec![4; 20],
        };
        (
            OpenConnectEspKeySetConfig {
                encryption: OpenConnectEspEncryption::Aes128Cbc,
                authentication: OpenConnectEspAuthentication::HmacSha1_96,
                outbound: client.clone(),
                inbound: server.clone(),
                disable_replay_protection: false,
            },
            OpenConnectEspKeySetConfig {
                encryption: OpenConnectEspEncryption::Aes128Cbc,
                authentication: OpenConnectEspAuthentication::HmacSha1_96,
                outbound: server,
                inbound: client,
                disable_replay_protection: false,
            },
        )
    }

    #[tokio::test]
    async fn probes_establish_and_data_flows_after_reply() {
        let remote = SocketAddr::from(([192, 0, 2, 1], 4501));
        let remote_socks = SocksAddr::new("192.0.2.1", 4501);
        let (to_client_tx, to_client_rx) = mpsc::channel(8);
        let (from_client_tx, mut from_client_rx) = mpsc::channel(8);
        let connection: PacketStream = Box::new(MemoryPacketConnection {
            incoming: tokio::sync::Mutex::new(to_client_rx),
            outgoing: from_client_tx,
        });
        let dialer = Arc::new(MemoryDialer {
            connection: Mutex::new(Some(connection)),
        });
        let (client_config, server_config) = key_configs();
        let client_keys =
            Arc::new(OpenConnectEspKeySet::new(&client_config).unwrap());
        let server_keys = OpenConnectEspKeySet::new(&server_config).unwrap();
        let probe = OpenConnectEspProbe::GlobalProtect(GlobalProtectEspProbe {
            assigned: "10.0.0.2".parse().unwrap(),
            magic: "10.0.0.1".parse().unwrap(),
        });
        let server_probe = probe;
        let server = tokio::spawn(async move {
            let (datagram, destination) = from_client_rx.recv().await.unwrap();
            assert_eq!(destination, remote_socks);
            let (mut request, _) = server_keys.open(&datagram).unwrap();
            request[12..16].copy_from_slice(&[10, 0, 0, 1]);
            request[16..20].copy_from_slice(&[10, 0, 0, 2]);
            request[20] = 0;
            assert!(server_probe.matches(&request));
            let reply = server_keys.seal(&request, None).unwrap();
            to_client_tx
                .send((reply, destination.clone()))
                .await
                .unwrap();
            let payload = [0x45, 0, 0, 20, 9];
            let packet = server_keys.seal(&payload, None).unwrap();
            to_client_tx.send((packet, destination)).await.unwrap();
        });
        let mut session = OpenConnectEspSession::connect(
            dialer,
            OpenConnectEspSessionOptions {
                remote,
                keys: client_keys,
                mtu: 1400,
                dpd: Duration::ZERO,
                probe,
                probe_next_header: 0,
                accept_lzo: false,
                queue_length: 4,
            },
        )
        .await
        .unwrap();
        session.establish().await.unwrap();
        assert!(session.ready());
        assert_eq!(
            session.read_data_packet().await.unwrap().unwrap(),
            vec![0x45, 0, 0, 20, 9]
        );
        session.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pulse_zero_probe_uses_negotiated_next_header() {
        let remote: SocketAddr = "[2001:db8::1]:4501".parse().unwrap();
        let remote_socks = SocksAddr::new("2001:db8::1", 4501);
        let (to_client_tx, to_client_rx) = mpsc::channel(8);
        let (from_client_tx, mut from_client_rx) = mpsc::channel(8);
        let connection: PacketStream = Box::new(MemoryPacketConnection {
            incoming: tokio::sync::Mutex::new(to_client_rx),
            outgoing: from_client_tx,
        });
        let dialer = Arc::new(MemoryDialer {
            connection: Mutex::new(Some(connection)),
        });
        let (client_config, server_config) = key_configs();
        let client_keys =
            Arc::new(OpenConnectEspKeySet::new(&client_config).unwrap());
        let server_keys = OpenConnectEspKeySet::new(&server_config).unwrap();
        let server = tokio::spawn(async move {
            let (datagram, destination) = from_client_rx.recv().await.unwrap();
            assert_eq!(destination, remote_socks);
            let (request, next_header) = server_keys.open(&datagram).unwrap();
            assert_eq!(request, [0]);
            assert_eq!(
                next_header,
                super::super::OPENCONNECT_ESP_IPV6_NEXT_HEADER
            );
            let reply = server_keys
                .seal(
                    &[0],
                    Some(super::super::OPENCONNECT_ESP_IPV6_NEXT_HEADER),
                )
                .unwrap();
            to_client_tx.send((reply, destination)).await.unwrap();
        });
        let mut session = OpenConnectEspSession::connect(
            dialer,
            OpenConnectEspSessionOptions {
                remote,
                keys: client_keys,
                mtu: 1400,
                dpd: Duration::ZERO,
                probe: OpenConnectEspProbe::Pulse,
                probe_next_header:
                    super::super::OPENCONNECT_ESP_IPV6_NEXT_HEADER,
                accept_lzo: true,
                queue_length: 4,
            },
        )
        .await
        .unwrap();
        session.establish().await.unwrap();
        assert!(session.ready());
        session.close().await;
        server.await.unwrap();
    }
}
