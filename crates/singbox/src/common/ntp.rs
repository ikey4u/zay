//! RFC 5905 NTP client and offset clock for embedded runtimes.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::{RngCore as _, rngs::OsRng};
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Dialer,
    common::{
        lifecycle::{Lifecycle, LifecycleError, LifecycleFuture, StartStage},
        network::SocksAddr,
    },
};

const NTP_PACKET_LEN: usize = 48;
const NTP_UNIX_EPOCH_DELTA: i128 = 2_208_988_800;
const NTP_ERA_SECONDS: i128 = 1_i128 << 32;
const NTP_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpSample {
    /// Signed server offset relative to the local wall clock.
    pub offset_nanos: i64,
    /// Network delay after removing time spent inside the NTP server.
    pub round_trip_nanos: u64,
    pub stratum: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtpStatus {
    pub synchronized: bool,
    pub sample: Option<NtpSample>,
    pub last_update_unix_millis: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct ClockState {
    offset_nanos: AtomicI64,
    synchronized: AtomicBool,
    status: watch::Sender<NtpStatus>,
}

impl Default for ClockState {
    fn default() -> Self {
        let (status, _) = watch::channel(NtpStatus::default());
        Self {
            offset_nanos: AtomicI64::new(0),
            synchronized: AtomicBool::new(false),
            status,
        }
    }
}

/// Cloneable wall clock corrected by the most recent NTP response.
///
/// NTP itself is not cryptographically authenticated. The selected sing-box
/// dialer and route determine where the query is sent, matching upstream.
#[derive(Debug, Clone, Default)]
pub struct NtpClock {
    state: Arc<ClockState>,
}

impl PartialEq for NtpClock {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

impl Eq for NtpClock {}

impl NtpClock {
    pub fn is_synchronized(&self) -> bool {
        self.state.synchronized.load(Ordering::Acquire)
    }

    pub fn offset_nanos(&self) -> i64 {
        self.state.offset_nanos.load(Ordering::Acquire)
    }

    pub fn now(&self) -> SystemTime {
        apply_offset(SystemTime::now(), self.offset_nanos())
    }

    pub fn unix_time_millis(&self) -> i64 {
        system_time_unix_nanos(self.now())
            .div_euclid(1_000_000)
            .clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }

    pub fn update(&self, sample: NtpSample) {
        self.state
            .offset_nanos
            .store(sample.offset_nanos, Ordering::Release);
        self.state.synchronized.store(true, Ordering::Release);
        self.state.status.send_replace(NtpStatus {
            synchronized: true,
            sample: Some(sample),
            last_update_unix_millis: Some(self.unix_time_millis()),
            last_error: None,
        });
    }

    pub fn subscribe(&self) -> watch::Receiver<NtpStatus> {
        self.state.status.subscribe()
    }

    fn update_error(&self, error: &io::Error) {
        let previous = self.state.status.borrow().clone();
        self.state.status.send_replace(NtpStatus {
            last_error: Some(error.to_string()),
            ..previous
        });
    }
}

/// One-shot NTP client. Lifecycle scheduling is kept separate so zay can use
/// the same primitive outside the configuration-driven runtime.
#[derive(Clone)]
pub struct NtpClient {
    dialer: Arc<dyn Dialer>,
    server: SocksAddr,
    timeout: Duration,
}

/// Privileged host integration used by `ntp.write_to_system`.
///
/// The singbox crate deliberately does not acquire privileges or mutate the
/// host clock itself. Embedding applications such as zay can implement this
/// narrow callback with their platform-specific privileged helper.
pub trait SystemClockWriter: Send + Sync {
    fn set_system_time(&self, time: SystemTime) -> io::Result<()>;
}

/// Staged lifecycle wrapper that refreshes an [`NtpClock`] in the background.
pub struct NtpService {
    client: NtpClient,
    clock: NtpClock,
    interval: Duration,
    system_clock_writer: Option<Arc<dyn SystemClockWriter>>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl NtpService {
    pub fn new(client: NtpClient, interval: Duration) -> Self {
        Self::new_with_clock(client, interval, NtpClock::default())
    }

    pub fn new_with_clock(
        client: NtpClient,
        interval: Duration,
        clock: NtpClock,
    ) -> Self {
        Self {
            client,
            clock,
            interval: if interval.is_zero() {
                Duration::from_secs(30 * 60)
            } else {
                interval
            },
            system_clock_writer: None,
            cancellation: CancellationToken::new(),
            task: None,
        }
    }

    pub fn clock(&self) -> NtpClock {
        self.clock.clone()
    }

    pub fn with_system_clock_writer(
        mut self,
        writer: Arc<dyn SystemClockWriter>,
    ) -> Self {
        self.system_clock_writer = Some(writer);
        self
    }
}

impl Lifecycle for NtpService {
    fn name(&self) -> &str {
        "ntp"
    }

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
        Box::pin(async move {
            if stage != StartStage::Start || self.task.is_some() {
                return Ok(());
            }
            let client = self.client.clone();
            let clock = self.clock.clone();
            let interval = self.interval;
            let system_clock_writer = self.system_clock_writer.clone();
            let cancellation = self.cancellation.clone();
            refresh_clock(&client, &clock, system_clock_writer.as_ref()).await;
            self.task = Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {}
                    }
                    refresh_clock(
                        &client,
                        &clock,
                        system_clock_writer.as_ref(),
                    )
                    .await;
                }
            }));
            Ok(())
        })
    }

    fn close(&mut self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            self.cancellation.cancel();
            if let Some(task) = self.task.take()
                && let Err(error) = task.await
                && !error.is_cancelled()
            {
                return Err(LifecycleError::Close {
                    component: self.name().into(),
                    message: error.to_string(),
                });
            }
            Ok(())
        })
    }
}

impl NtpClient {
    pub fn new(dialer: Arc<dyn Dialer>, server: SocksAddr) -> Self {
        Self {
            dialer,
            server,
            timeout: NTP_QUERY_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn query(&self) -> io::Result<NtpSample> {
        let connection = self.dialer.listen_udp(&self.server).await?;
        let mut request = [0_u8; NTP_PACKET_LEN];
        request[0] = (3 << 6) | (4 << 3) | 3;
        let mut transmit = [0_u8; 8];
        let sent_at = if OsRng.try_fill_bytes(&mut transmit).is_ok() {
            SystemTime::now()
        } else {
            let sent_at = SystemTime::now();
            transmit = encode_ntp_timestamp(sent_at)?;
            sent_at
        };
        request[40..48].copy_from_slice(&transmit);
        let sent = connection.send_to(&request, &self.server).await?;
        if sent != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short NTP request: sent {sent} of {} bytes",
                    request.len()
                ),
            ));
        }
        let mut response = [0_u8; 512];
        let (size, _) = tokio::time::timeout(
            self.timeout,
            connection.recv_from(&mut response),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "NTP query timed out")
        })??;
        let received_at = SystemTime::now();
        parse_response(&response[..size], sent_at, received_at)
    }

    pub async fn query_and_update(
        &self,
        clock: &NtpClock,
    ) -> io::Result<NtpSample> {
        let sample = self.query().await?;
        clock.update(sample);
        Ok(sample)
    }
}

async fn refresh_clock(
    client: &NtpClient,
    clock: &NtpClock,
    system_clock_writer: Option<&Arc<dyn SystemClockWriter>>,
) {
    match client.query_and_update(clock).await {
        Ok(_) => {
            if let Some(writer) = system_clock_writer
                && let Err(error) = writer.set_system_time(clock.now())
            {
                clock.update_error(&error);
            }
        }
        Err(error) => clock.update_error(&error),
    }
}

fn parse_response(
    packet: &[u8],
    sent_at: SystemTime,
    received_at: SystemTime,
) -> io::Result<NtpSample> {
    if packet.len() < NTP_PACKET_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("short NTP response: {} bytes", packet.len()),
        ));
    }
    let stratum = packet[1];
    let reference = system_time_unix_nanos(received_at);
    let t1 = system_time_unix_nanos(sent_at);
    let t2 = decode_ntp_timestamp(&packet[32..40], reference)?;
    let t3 = decode_ntp_timestamp(&packet[40..48], reference)?;
    let t4 = system_time_unix_nanos(received_at);
    let offset = ((t2 - t1) + (t3 - t4)) / 2;
    let delay = ((t4 - t1) - (t3 - t2)).max(0);
    Ok(NtpSample {
        offset_nanos: i64::try_from(offset).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "NTP offset exceeds i64")
        })?,
        round_trip_nanos: u64::try_from(delay).unwrap_or(u64::MAX),
        stratum,
    })
}

fn encode_ntp_timestamp(time: SystemTime) -> io::Result<[u8; 8]> {
    let unix_nanos = system_time_unix_nanos(time);
    let ntp_nanos = unix_nanos
        .checked_add(NTP_UNIX_EPOCH_DELTA * 1_000_000_000)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "NTP timestamp overflow",
            )
        })?;
    if ntp_nanos < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "time predates the NTP epoch",
        ));
    }
    let seconds = ntp_nanos.div_euclid(1_000_000_000) as u32;
    let nanos = ntp_nanos.rem_euclid(1_000_000_000);
    let fraction = ((nanos << 32) / 1_000_000_000) as u32;
    let mut encoded = [0_u8; 8];
    encoded[..4].copy_from_slice(&seconds.to_be_bytes());
    encoded[4..].copy_from_slice(&fraction.to_be_bytes());
    Ok(encoded)
}

fn decode_ntp_timestamp(
    encoded: &[u8],
    reference_unix_nanos: i128,
) -> io::Result<i128> {
    let encoded: [u8; 8] = encoded.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid NTP timestamp length",
        )
    })?;
    let seconds =
        u32::from_be_bytes(encoded[..4].try_into().expect("four bytes"));
    let fraction =
        u32::from_be_bytes(encoded[4..].try_into().expect("four bytes"));
    let reference_ntp_seconds =
        reference_unix_nanos.div_euclid(1_000_000_000) + NTP_UNIX_EPOCH_DELTA;
    let reference_era = reference_ntp_seconds.div_euclid(NTP_ERA_SECONDS);
    let seconds = i128::from(seconds);
    let full_seconds = [reference_era - 1, reference_era, reference_era + 1]
        .into_iter()
        .map(|era| era * NTP_ERA_SECONDS + seconds)
        .min_by_key(|candidate| (candidate - reference_ntp_seconds).abs())
        .expect("three NTP era candidates");
    let fractional_nanos = (i128::from(fraction) * 1_000_000_000) >> 32;
    Ok(
        (full_seconds - NTP_UNIX_EPOCH_DELTA) * 1_000_000_000
            + fractional_nanos,
    )
}

fn system_time_unix_nanos(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            i128::try_from(duration.as_nanos()).unwrap_or(i128::MAX)
        }
        Err(error) => {
            -i128::try_from(error.duration().as_nanos()).unwrap_or(i128::MAX)
        }
    }
}

fn apply_offset(time: SystemTime, offset_nanos: i64) -> SystemTime {
    if offset_nanos >= 0 {
        time.checked_add(Duration::from_nanos(offset_nanos as u64))
            .unwrap_or(time)
    } else {
        time.checked_sub(Duration::from_nanos(offset_nanos.unsigned_abs()))
            .unwrap_or(time)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime},
    };

    use tokio::net::UdpSocket;

    use super::{
        NtpClient, NtpClock, NtpService, SystemClockWriter,
        encode_ntp_timestamp, parse_response,
    };
    use crate::{
        adapter::Dialer,
        common::{
            lifecycle::{Lifecycle, StartStage},
            network::SocksAddr,
        },
        option::DirectOutboundOptions,
        protocol::direct::DirectOutbound,
    };

    #[test]
    fn computes_rfc_four_timestamp_offset_and_delay() {
        let base = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let sent = base;
        let received = base + Duration::from_millis(120);
        let mut packet = [0_u8; 48];
        packet[0] = (4 << 3) | 4;
        packet[1] = 2;
        packet[32..40].copy_from_slice(
            &encode_ntp_timestamp(base + Duration::from_millis(70)).unwrap(),
        );
        packet[40..48].copy_from_slice(
            &encode_ntp_timestamp(base + Duration::from_millis(80)).unwrap(),
        );
        let sample = parse_response(&packet, sent, received).unwrap();
        assert!((sample.offset_nanos - 15_000_000).abs() <= 1);
        assert!((sample.round_trip_nanos as i64 - 110_000_000).abs() <= 1);
        assert_eq!(sample.stratum, 2);
    }

    #[test]
    fn response_acceptance_matches_pinned_sing_ntp_exchange() {
        let now = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let transmit = encode_ntp_timestamp(now).unwrap();
        let mut packet = [0_u8; 48];
        packet[0] = (3 << 6) | (1 << 3) | 7;
        packet[1] = 0;
        packet[32..40].copy_from_slice(&transmit);
        packet[40..48].copy_from_slice(&transmit);
        let sample = parse_response(&packet, now, now).unwrap();
        assert_eq!(sample.stratum, 0);
    }

    #[test]
    fn corrected_clock_tracks_signed_offset() {
        let clock = NtpClock::default();
        assert!(!clock.is_synchronized());
        clock.update(super::NtpSample {
            offset_nanos: -2_000_000_000,
            round_trip_nanos: 1,
            stratum: 1,
        });
        assert!(clock.is_synchronized());
        assert_eq!(clock.offset_nanos(), -2_000_000_000);
        let delta = SystemTime::now()
            .duration_since(clock.now())
            .unwrap_or_default();
        assert!(delta >= Duration::from_millis(1900));
        assert!(delta <= Duration::from_millis(2100));
    }

    #[tokio::test]
    async fn queries_real_udp_server_through_selected_dialer() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request = [0_u8; 512];
            let (size, peer) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 48);
            assert_eq!(request[0], (3 << 6) | (4 << 3) | 3);
            let mut response = [0_u8; 48];
            response[0] = (4 << 3) | 4;
            response[1] = 1;
            response[24..32].copy_from_slice(&request[40..48]);
            let server_now = SystemTime::now() + Duration::from_secs(2);
            let receive = encode_ntp_timestamp(server_now).unwrap();
            let transmit =
                encode_ntp_timestamp(server_now + Duration::from_millis(1))
                    .unwrap();
            response[32..40].copy_from_slice(&receive);
            response[40..48].copy_from_slice(&transmit);
            server.send_to(&response, peer).await.unwrap();
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client = NtpClient::new(dialer, SocksAddr::from(address));
        let sample = client.query().await.unwrap();
        assert!(sample.offset_nanos >= 1_800_000_000);
        assert!(sample.offset_nanos <= 2_200_000_000);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn service_invokes_explicit_system_clock_writer_after_sync() {
        #[derive(Default)]
        struct RecordingWriter {
            values: Mutex<Vec<SystemTime>>,
        }

        impl SystemClockWriter for RecordingWriter {
            fn set_system_time(&self, time: SystemTime) -> io::Result<()> {
                self.values.lock().unwrap().push(time);
                Ok(())
            }
        }

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request = [0_u8; 512];
            let (size, peer) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 48);
            let mut response = [0_u8; 48];
            response[0] = (4 << 3) | 4;
            response[1] = 1;
            response[24..32].copy_from_slice(&request[40..48]);
            let server_now = SystemTime::now() + Duration::from_secs(2);
            response[32..40]
                .copy_from_slice(&encode_ntp_timestamp(server_now).unwrap());
            response[40..48].copy_from_slice(
                &encode_ntp_timestamp(server_now + Duration::from_millis(1))
                    .unwrap(),
            );
            server.send_to(&response, peer).await.unwrap();
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client = NtpClient::new(dialer, SocksAddr::from(address));
        let writer = Arc::new(RecordingWriter::default());
        let mut service = NtpService::new(client, Duration::from_secs(3600))
            .with_system_clock_writer(writer.clone());
        service.start(StartStage::Start).await.unwrap();
        assert_eq!(writer.values.lock().unwrap().len(), 1);
        service.close().await.unwrap();
        {
            let values = writer.values.lock().unwrap();
            assert_eq!(values.len(), 1);
            assert!(values[0] > SystemTime::now() + Duration::from_secs(1));
        }
        task.await.unwrap();
    }
}
