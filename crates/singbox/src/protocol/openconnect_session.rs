//! Asynchronous CSTP data-channel lifecycle.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex as SyncMutex;
use tokio::{
    io::{AsyncWriteExt, WriteHalf},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{
    AnyConnectDeflateState, CSTP_MAX_PAYLOAD_SIZE, CstpCompression, CstpError,
    CstpPacketType, CstpRekeyMethod, compress_anyconnect_stateless,
    decompress_anyconnect_stateless, read_cstp_packet, write_cstp_disconnect,
    write_cstp_packet,
};
use crate::adapter::Stream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpSessionOptions {
    pub mtu: usize,
    pub compression: CstpCompression,
    pub dpd: Duration,
    pub keepalive: Duration,
    pub rekey: Duration,
    pub rekey_method: CstpRekeyMethod,
    pub queue_length: usize,
}

impl Default for CstpSessionOptions {
    fn default() -> Self {
        Self {
            mtu: 1406,
            compression: CstpCompression::None,
            dpd: Duration::ZERO,
            keepalive: Duration::ZERO,
            rekey: Duration::ZERO,
            rekey_method: CstpRekeyMethod::None,
            queue_length: 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CstpTimerAction {
    None,
    Dpd,
    DeadPeer,
    Keepalive,
    Rekey,
}

/// Deterministic form of OpenConnect's `keepalive_action` state machine.
#[derive(Debug, Clone)]
pub struct CstpKeepaliveState {
    dpd: Duration,
    keepalive: Duration,
    rekey: Duration,
    rekey_method: CstpRekeyMethod,
    last_rekey: Duration,
    last_transmit: Duration,
    last_receive: Duration,
    last_dpd: Duration,
}

impl CstpKeepaliveState {
    pub fn new(
        dpd: Duration,
        keepalive: Duration,
        rekey: Duration,
        rekey_method: CstpRekeyMethod,
    ) -> Self {
        Self {
            dpd,
            keepalive,
            rekey,
            rekey_method,
            last_rekey: Duration::ZERO,
            last_transmit: Duration::ZERO,
            last_receive: Duration::ZERO,
            last_dpd: Duration::ZERO,
        }
    }

    pub fn mark_received(&mut self, elapsed: Duration) {
        self.last_receive = elapsed;
    }

    pub fn mark_transmitted(&mut self, elapsed: Duration) {
        self.last_transmit = elapsed;
    }

    pub fn action(&mut self, elapsed: Duration) -> CstpTimerAction {
        if self.rekey_method != CstpRekeyMethod::None
            && !self.rekey.is_zero()
            && elapsed >= self.last_rekey.saturating_add(self.rekey)
        {
            self.last_rekey = elapsed;
            return CstpTimerAction::Rekey;
        }
        if !self.dpd.is_zero() {
            if elapsed
                > self.last_receive.saturating_add(self.dpd.saturating_mul(2))
            {
                return CstpTimerAction::DeadPeer;
            }
            let mut due = self.last_receive.saturating_add(self.dpd);
            if self.last_dpd > self.last_receive {
                due = self.last_dpd.saturating_add(self.dpd / 2);
            }
            if elapsed >= due {
                self.last_dpd = elapsed;
                return CstpTimerAction::Dpd;
            }
        }
        if !self.keepalive.is_zero()
            && elapsed >= self.last_transmit.saturating_add(self.keepalive)
        {
            return CstpTimerAction::Keepalive;
        }
        CstpTimerAction::None
    }

    pub fn next_delay(&self, elapsed: Duration) -> Duration {
        let mut next: Option<Duration> = None;
        let mut include = |deadline: Duration| {
            next = Some(next.map_or(deadline, |current| current.min(deadline)));
        };
        if self.rekey_method != CstpRekeyMethod::None && !self.rekey.is_zero() {
            include(self.last_rekey.saturating_add(self.rekey));
        }
        if !self.dpd.is_zero() {
            let dpd_deadline = if self.last_dpd > self.last_receive {
                self.last_dpd.saturating_add(self.dpd / 2)
            } else {
                self.last_receive.saturating_add(self.dpd)
            };
            include(dpd_deadline);
            include(
                self.last_receive.saturating_add(self.dpd.saturating_mul(2)),
            );
        }
        if !self.keepalive.is_zero() {
            include(self.last_transmit.saturating_add(self.keepalive));
        }
        match next {
            None => Duration::from_secs(3600),
            Some(deadline) if deadline <= elapsed => Duration::from_millis(1),
            Some(deadline) => deadline - elapsed,
        }
    }
}

struct CstpActivity {
    origin: Instant,
    keepalive: SyncMutex<CstpKeepaliveState>,
    last_receive_nanos: AtomicU64,
    last_transmit_nanos: AtomicU64,
}

impl CstpActivity {
    fn new(options: &CstpSessionOptions) -> Self {
        Self {
            origin: Instant::now(),
            keepalive: SyncMutex::new(CstpKeepaliveState::new(
                options.dpd,
                options.keepalive,
                options.rekey,
                options.rekey_method,
            )),
            last_receive_nanos: AtomicU64::new(0),
            last_transmit_nanos: AtomicU64::new(0),
        }
    }

    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }

    fn mark_received(&self) {
        let elapsed = self.elapsed();
        self.last_receive_nanos
            .store(duration_to_nanos(elapsed), Ordering::Relaxed);
        self.keepalive.lock().mark_received(elapsed);
    }

    fn mark_transmitted(&self) {
        let elapsed = self.elapsed();
        self.last_transmit_nanos
            .store(duration_to_nanos(elapsed), Ordering::Relaxed);
        self.keepalive.lock().mark_transmitted(elapsed);
    }
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

struct CstpSessionWriter {
    writer: WriteHalf<Stream>,
    mtu: usize,
    compression: CstpCompression,
    deflate: Option<AnyConnectDeflateState>,
    activity: Arc<CstpActivity>,
}

impl CstpSessionWriter {
    async fn write_control(
        &mut self,
        packet_type: CstpPacketType,
    ) -> Result<(), CstpError> {
        write_cstp_packet(&mut self.writer, packet_type, &[]).await?;
        self.activity.mark_transmitted();
        Ok(())
    }

    async fn write_data(&mut self, payload: &[u8]) -> Result<(), CstpError> {
        if payload.len() > self.mtu {
            return Err(CstpError::InvalidOption(format!(
                "data packet exceeds negotiated MTU: {} > {}",
                payload.len(),
                self.mtu
            )));
        }
        let mut encoded = None;
        match self.compression {
            CstpCompression::OcLz4 | CstpCompression::Lzs => {
                encoded =
                    compress_anyconnect_stateless(self.compression, payload)?;
            }
            CstpCompression::Deflate => {
                match self
                    .deflate
                    .as_mut()
                    .expect("deflate state is configured")
                    .compress(payload)
                {
                    Ok(payload) => encoded = Some(payload),
                    // Upstream keeps the channel alive and disables only
                    // outgoing deflate after a compressor failure.
                    Err(_) => {
                        self.compression = CstpCompression::None;
                        self.deflate = None;
                    }
                }
            }
            CstpCompression::None => {}
        }
        let (packet_type, payload) = match encoded.as_deref() {
            Some(payload) => (CstpPacketType::Compressed, payload),
            None => (CstpPacketType::Data, payload),
        };
        write_cstp_packet(&mut self.writer, packet_type, payload).await?;
        self.activity.mark_transmitted();
        Ok(())
    }
}

type SharedWriter = Arc<Mutex<Option<CstpSessionWriter>>>;

/// Running CSTP TCP data channel. DTLS can later replace its data writes while
/// this channel remains the control/fallback path.
pub struct CstpSession {
    writer: SharedWriter,
    incoming: mpsc::Receiver<Result<Vec<u8>, CstpError>>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl CstpSession {
    pub fn start(
        stream: Stream,
        options: CstpSessionOptions,
    ) -> Result<Self, CstpError> {
        if options.mtu == 0 || options.mtu > CSTP_MAX_PAYLOAD_SIZE {
            return Err(CstpError::InvalidOption(format!(
                "invalid CSTP session MTU: {}",
                options.mtu
            )));
        }
        let (reader, writer) = tokio::io::split(stream);
        let activity = Arc::new(CstpActivity::new(&options));
        let writer = Arc::new(Mutex::new(Some(CstpSessionWriter {
            writer,
            mtu: options.mtu,
            compression: options.compression,
            deflate: (options.compression == CstpCompression::Deflate)
                .then(AnyConnectDeflateState::new),
            activity: activity.clone(),
        })));
        let (incoming_tx, incoming) =
            mpsc::channel(options.queue_length.max(1));
        let cancel = CancellationToken::new();
        let read_task = tokio::spawn(read_loop(
            reader,
            writer.clone(),
            activity.clone(),
            options.mtu,
            options.compression,
            incoming_tx.clone(),
            cancel.clone(),
        ));
        let timer_task = tokio::spawn(timer_loop(
            writer.clone(),
            activity,
            incoming_tx,
            cancel.clone(),
        ));
        Ok(Self {
            writer,
            incoming,
            cancel,
            tasks: vec![read_task, timer_task],
        })
    }

    pub async fn write_data_packet(
        &self,
        payload: &[u8],
    ) -> Result<(), CstpError> {
        let mut writer = self.writer.lock().await;
        writer
            .as_mut()
            .ok_or_else(|| {
                CstpError::Protocol("data channel is not ready".into())
            })?
            .write_data(payload)
            .await
    }

    pub async fn read_data_packet(
        &mut self,
    ) -> Result<Option<Vec<u8>>, CstpError> {
        match self.incoming.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    pub async fn close(&mut self) -> Result<(), CstpError> {
        let disconnect_result = if self.cancel.is_cancelled() {
            Ok(())
        } else {
            let mut writer = self.writer.lock().await;
            if let Some(writer) = writer.as_mut() {
                let result = write_cstp_disconnect(
                    &mut writer.writer,
                    "Client disconnect",
                )
                .await;
                let _ = writer.writer.shutdown().await;
                result
            } else {
                Ok(())
            }
        };
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.writer.lock().await.take();
        disconnect_result
    }
}

impl Drop for CstpSession {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn read_loop(
    mut reader: tokio::io::ReadHalf<Stream>,
    writer: SharedWriter,
    activity: Arc<CstpActivity>,
    mtu: usize,
    compression: CstpCompression,
    incoming: mpsc::Sender<Result<Vec<u8>, CstpError>>,
    cancel: CancellationToken,
) {
    let maximum_payload_size = mtu.max(16_384);
    let maximum_wire_payload_size = if compression == CstpCompression::Deflate {
        CSTP_MAX_PAYLOAD_SIZE
    } else {
        maximum_payload_size
    };
    let mut deflate = (compression == CstpCompression::Deflate)
        .then(AnyConnectDeflateState::new);
    loop {
        let packet = tokio::select! {
            _ = cancel.cancelled() => return,
            result = read_cstp_packet(&mut reader, maximum_wire_payload_size) => result,
        };
        let packet = match packet {
            Ok(packet) => packet,
            Err(CstpError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                cancel.cancel();
                return;
            }
            Err(error) => {
                let _ = incoming.send(Err(error)).await;
                cancel.cancel();
                return;
            }
        };
        activity.mark_received();
        match packet.packet_type {
            CstpPacketType::DpdRequest => {
                let result = async {
                    let mut guard = writer.lock().await;
                    guard
                        .as_mut()
                        .ok_or_else(|| {
                            CstpError::Protocol(
                                "data channel is not ready".into(),
                            )
                        })?
                        .write_control(CstpPacketType::DpdResponse)
                        .await
                }
                .await;
                if let Err(error) = result {
                    let _ = incoming.send(Err(error)).await;
                    cancel.cancel();
                    return;
                }
            }
            CstpPacketType::DpdResponse | CstpPacketType::Keepalive => {}
            CstpPacketType::Data => {
                if incoming.send(Ok(packet.payload)).await.is_err() {
                    cancel.cancel();
                    return;
                }
            }
            CstpPacketType::Compressed => {
                if compression == CstpCompression::None {
                    let _ = incoming
                        .send(Err(CstpError::Protocol(
                            "received compressed packet without negotiated compression".into(),
                        )))
                        .await;
                    cancel.cancel();
                    return;
                }
                let decompressed = if compression == CstpCompression::Deflate {
                    deflate
                        .as_mut()
                        .expect("deflate state is configured")
                        .decompress(&packet.payload, maximum_payload_size)
                } else {
                    decompress_anyconnect_stateless(
                        compression,
                        &packet.payload,
                        maximum_payload_size,
                    )
                };
                match decompressed {
                    Ok(packet) => {
                        if incoming.send(Ok(packet)).await.is_err() {
                            cancel.cancel();
                            return;
                        }
                    }
                    // Upstream drops malformed stateless packets, but a broken
                    // stateful stream is terminal because history is now lost.
                    Err(_) if compression != CstpCompression::Deflate => {}
                    Err(error) => {
                        let _ = incoming.send(Err(error)).await;
                        cancel.cancel();
                        return;
                    }
                }
            }
            CstpPacketType::Disconnect | CstpPacketType::Terminate => {
                let reason = render_cstp_disconnect_reason(&packet.payload);
                let _ = incoming
                    .send(Err(CstpError::Protocol(format!(
                        "server disconnected session: {reason}"
                    ))))
                    .await;
                cancel.cancel();
                return;
            }
            CstpPacketType::Unknown(value) => {
                let _ = incoming
                    .send(Err(CstpError::Protocol(format!(
                        "received unknown packet type: {value}"
                    ))))
                    .await;
                cancel.cancel();
                return;
            }
        }
    }
}

async fn timer_loop(
    writer: SharedWriter,
    activity: Arc<CstpActivity>,
    incoming: mpsc::Sender<Result<Vec<u8>, CstpError>>,
    cancel: CancellationToken,
) {
    loop {
        let delay = {
            let elapsed = activity.elapsed();
            activity.keepalive.lock().next_delay(elapsed)
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        let action = {
            let elapsed = activity.elapsed();
            activity.keepalive.lock().action(elapsed)
        };
        let result = match action {
            CstpTimerAction::Dpd => {
                write_control(&writer, CstpPacketType::DpdRequest).await
            }
            CstpTimerAction::Keepalive => {
                write_control(&writer, CstpPacketType::Keepalive).await
            }
            CstpTimerAction::DeadPeer => {
                Err(CstpError::Protocol("dead peer detection expired".into()))
            }
            CstpTimerAction::Rekey => Err(CstpError::Protocol(
                "CSTP rekey requires a new tunnel".into(),
            )),
            CstpTimerAction::None => continue,
        };
        if let Err(error) = result {
            let _ = incoming.send(Err(error)).await;
            cancel.cancel();
            return;
        }
    }
}

async fn write_control(
    writer: &SharedWriter,
    packet_type: CstpPacketType,
) -> Result<(), CstpError> {
    let mut writer = writer.lock().await;
    writer
        .as_mut()
        .ok_or_else(|| CstpError::Protocol("data channel is not ready".into()))?
        .write_control(packet_type)
        .await
}

pub fn render_cstp_disconnect_reason(payload: &[u8]) -> String {
    let Some((code, content)) = payload.split_first() else {
        return "unspecified".into();
    };
    let reason: String = content
        .iter()
        .map(|byte| {
            let character = char::from(*byte);
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '.'
            }
        })
        .collect();
    if reason.is_empty() {
        format!("code 0x{code:x}")
    } else {
        format!("code 0x{code:x} {reason}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(size: usize, fill: u8) -> Vec<u8> {
        let mut packet = vec![fill; size];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        packet
    }

    #[test]
    fn keepalive_state_matches_dpd_retry_dead_peer_and_rekey_order() {
        let mut state = CstpKeepaliveState::new(
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(60),
            CstpRekeyMethod::Tls,
        );
        assert_eq!(state.next_delay(Duration::ZERO), Duration::from_secs(10));
        assert_eq!(state.action(Duration::from_secs(10)), CstpTimerAction::Dpd);
        assert_eq!(
            state.next_delay(Duration::from_secs(10)),
            Duration::from_secs(5)
        );
        assert_eq!(state.action(Duration::from_secs(15)), CstpTimerAction::Dpd);
        assert_eq!(
            state.action(Duration::from_secs(21)),
            CstpTimerAction::DeadPeer
        );
        state.mark_received(Duration::from_secs(55));
        assert_eq!(
            state.action(Duration::from_secs(60)),
            CstpTimerAction::Rekey
        );
    }

    #[tokio::test]
    async fn session_answers_dpd_and_exchanges_compressed_data() {
        let (client, mut server) = tokio::io::duplex(4096);
        let stream: Stream = Box::new(client);
        let mut session = CstpSession::start(
            stream,
            CstpSessionOptions {
                mtu: 400,
                compression: CstpCompression::Lzs,
                ..Default::default()
            },
        )
        .unwrap();

        write_cstp_packet(&mut server, CstpPacketType::DpdRequest, &[])
            .await
            .unwrap();
        assert_eq!(
            read_cstp_packet(&mut server, 400)
                .await
                .unwrap()
                .packet_type,
            CstpPacketType::DpdResponse
        );

        let outbound = ipv4_packet(200, b'A');
        session.write_data_packet(&outbound).await.unwrap();
        let encoded = read_cstp_packet(&mut server, 400).await.unwrap();
        assert_eq!(encoded.packet_type, CstpPacketType::Compressed);
        assert_eq!(
            decompress_anyconnect_stateless(
                CstpCompression::Lzs,
                &encoded.payload,
                400
            )
            .unwrap(),
            outbound
        );

        let inbound = ipv4_packet(240, b'B');
        let compressed =
            compress_anyconnect_stateless(CstpCompression::Lzs, &inbound)
                .unwrap()
                .unwrap();
        write_cstp_packet(&mut server, CstpPacketType::Compressed, &compressed)
            .await
            .unwrap();
        assert_eq!(session.read_data_packet().await.unwrap().unwrap(), inbound);

        write_cstp_disconnect(&mut server, "maintenance")
            .await
            .unwrap();
        let error = session.read_data_packet().await.unwrap_err();
        assert!(error.to_string().contains("code 0xb0 maintenance"));
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_rejects_mtu_and_unnegotiated_compression() {
        let (client, mut server) = tokio::io::duplex(4096);
        let stream: Stream = Box::new(client);
        let mut session = CstpSession::start(
            stream,
            CstpSessionOptions {
                mtu: 100,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(session.write_data_packet(&[0; 101]).await.is_err());
        write_cstp_packet(&mut server, CstpPacketType::Compressed, b"bad")
            .await
            .unwrap();
        assert!(
            session
                .read_data_packet()
                .await
                .unwrap_err()
                .to_string()
                .contains("without negotiated")
        );
    }

    #[test]
    fn disconnect_reason_sanitizes_control_bytes() {
        assert_eq!(render_cstp_disconnect_reason(&[]), "unspecified");
        assert_eq!(render_cstp_disconnect_reason(&[0xb0]), "code 0xb0");
        assert_eq!(
            render_cstp_disconnect_reason(&[1, b'o', b'k', 0]),
            "code 0x1 ok."
        );
    }
}
