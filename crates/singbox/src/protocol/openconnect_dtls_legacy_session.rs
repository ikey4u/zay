//! Asynchronous Cisco DTLS 0.9 application-data channel.

use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use openssl::memcmp;
use thiserror::Error;
use tokio::{
    sync::Mutex,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

use super::{
    CstpPacketType, LEGACY_DTLS_CONTENT_ALERT,
    LEGACY_DTLS_CONTENT_APPLICATION_DATA,
    LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC, LEGACY_DTLS_CONTENT_HANDSHAKE,
    LEGACY_DTLS_MAX_SEQUENCE, LegacyDtlsError, LegacyDtlsKeys,
    LegacyDtlsReplayWindow, LegacyDtlsSuite, decrypt_legacy_dtls_record,
    encrypt_legacy_dtls_record, parse_legacy_dtls_records,
};
use crate::{adapter::PacketStream, common::network::SocksAddr};

const LEGACY_DTLS_READ_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum LegacyDtlsChannelError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Record(#[from] LegacyDtlsError),
    #[error("Cisco DTLS 0.9 channel is closed")]
    Closed,
    #[error("Cisco DTLS 0.9 record sequence exhausted")]
    SequenceExhausted,
    #[error(
        "Cisco DTLS 0.9 datagram write was short: wrote {actual} of {expected} bytes"
    )]
    ShortWrite { actual: usize, expected: usize },
    #[error("Cisco DTLS 0.9 record is {actual} bytes for MTU {mtu}")]
    MtuExceeded { actual: usize, mtu: usize },
    #[error("Cisco DTLS 0.9 peer sent alert {0:?}")]
    PeerAlert(Option<u8>),
    #[error("unknown Cisco DTLS 0.9 record type: {0}")]
    UnknownRecord(u8),
    #[error("Cisco DTLS 0.9 MTU probe was cancelled")]
    Cancelled,
}

struct LegacyDtlsReadState {
    queue: VecDeque<Vec<u8>>,
    replay: LegacyDtlsReplayWindow,
    buffer: Vec<u8>,
}

impl Default for LegacyDtlsReadState {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            replay: LegacyDtlsReplayWindow::default(),
            buffer: vec![0; LEGACY_DTLS_READ_BUFFER_SIZE],
        }
    }
}

/// A packet-oriented legacy DTLS channel over an arbitrary singbox UDP dialer.
///
/// The handshake driver supplies directional keys and the authenticated final
/// flight.  `receive` returns one decrypted IP/CSTP payload per call even when
/// a UDP datagram carried multiple DTLS records.
pub struct LegacyDtlsSession {
    packet: PacketStream,
    destination: SocksAddr,
    suite: LegacyDtlsSuite,
    keys: Mutex<Option<LegacyDtlsKeys>>,
    read: Mutex<LegacyDtlsReadState>,
    write: Mutex<()>,
    write_sequence: AtomicU64,
    mtu: AtomicUsize,
    strict: bool,
    close_alert: bool,
    final_flight: Vec<Vec<u8>>,
    server_finished: Vec<u8>,
    closed: AtomicBool,
}

impl LegacyDtlsSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet: PacketStream,
        destination: SocksAddr,
        suite: LegacyDtlsSuite,
        keys: LegacyDtlsKeys,
        mtu: usize,
        strict: bool,
        close_alert: bool,
        final_flight: Vec<Vec<u8>>,
        server_finished: Vec<u8>,
    ) -> Self {
        Self {
            packet,
            destination,
            suite,
            keys: Mutex::new(Some(keys)),
            read: Mutex::new(LegacyDtlsReadState::default()),
            write: Mutex::new(()),
            write_sequence: AtomicU64::new(1),
            mtu: AtomicUsize::new(mtu),
            strict,
            close_alert,
            final_flight,
            server_finished,
            closed: AtomicBool::new(false),
        }
    }

    pub fn mtu(&self) -> usize {
        self.mtu.load(Ordering::Acquire)
    }

    pub fn set_mtu(&self, mtu: usize) {
        self.mtu.store(mtu, Ordering::Release);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub async fn send(
        &self,
        payload: &[u8],
    ) -> Result<usize, LegacyDtlsChannelError> {
        let _write = self.write.lock().await;
        if self.is_closed() {
            return Err(LegacyDtlsChannelError::Closed);
        }
        let sequence = self.write_sequence.load(Ordering::Relaxed);
        if sequence > LEGACY_DTLS_MAX_SEQUENCE {
            return Err(LegacyDtlsChannelError::SequenceExhausted);
        }
        let encoded = {
            let keys = self.keys.lock().await;
            let keys = keys.as_ref().ok_or(LegacyDtlsChannelError::Closed)?;
            encrypt_legacy_dtls_record(
                &super::LegacyDtlsRecord {
                    content_type: LEGACY_DTLS_CONTENT_APPLICATION_DATA,
                    epoch: 1,
                    sequence,
                    payload: payload.to_vec(),
                },
                &keys.client_key,
                &keys.client_mac_key,
                &self.suite,
            )?
        };
        let mtu = self.mtu();
        if mtu != 0 && encoded.len() > mtu {
            return Err(LegacyDtlsChannelError::MtuExceeded {
                actual: encoded.len(),
                mtu,
            });
        }
        self.send_datagram(&encoded).await?;
        self.write_sequence.fetch_add(1, Ordering::Relaxed);
        Ok(payload.len())
    }

    pub async fn receive(&self) -> Result<Vec<u8>, LegacyDtlsChannelError> {
        let mut state = self.read.lock().await;
        loop {
            if let Some(payload) = state.queue.pop_front() {
                return Ok(payload);
            }
            if self.is_closed() {
                return Err(LegacyDtlsChannelError::Closed);
            }
            let (size, source) =
                self.packet.recv_from(&mut state.buffer).await?;
            if source != self.destination {
                continue;
            }
            let records = match parse_legacy_dtls_records(
                &state.buffer[..size],
                &self.suite,
            ) {
                Ok(records) => records,
                Err(error) if !self.strict => {
                    let _ = error;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            for record in records {
                match record.content_type {
                    LEGACY_DTLS_CONTENT_APPLICATION_DATA => {
                        let plaintext = match self.decrypt(&record).await {
                            Ok(plaintext) => plaintext,
                            Err(error) if !self.strict => {
                                let _ = error;
                                continue;
                            }
                            Err(error) => return Err(error),
                        };
                        if state.replay.accept(record.sequence) {
                            state.queue.push_back(plaintext);
                        }
                    }
                    LEGACY_DTLS_CONTENT_HANDSHAKE if record.epoch == 1 => {
                        let Ok(plaintext) = self.decrypt(&record).await else {
                            continue;
                        };
                        let duplicate_finished =
                            memcmp::eq(&plaintext, &self.server_finished);
                        if duplicate_finished {
                            let _write = self.write.lock().await;
                            for datagram in &self.final_flight {
                                self.send_datagram(datagram).await?;
                            }
                        }
                    }
                    LEGACY_DTLS_CONTENT_ALERT => {
                        if self.strict {
                            if record.epoch == 1 {
                                self.decrypt(&record).await?;
                            }
                            return Err(LegacyDtlsChannelError::PeerAlert(
                                None,
                            ));
                        }
                        if record.epoch != 1 {
                            continue;
                        }
                        let Ok(plaintext) = self.decrypt(&record).await else {
                            continue;
                        };
                        let description =
                            (plaintext.len() == 2).then_some(plaintext[1]);
                        if description == Some(0) {
                            self.closed.store(true, Ordering::Release);
                            return Err(LegacyDtlsChannelError::Closed);
                        }
                        return Err(LegacyDtlsChannelError::PeerAlert(
                            description,
                        ));
                    }
                    LEGACY_DTLS_CONTENT_CHANGE_CIPHER_SPEC => {}
                    value if self.strict => {
                        return Err(LegacyDtlsChannelError::UnknownRecord(
                            value,
                        ));
                    }
                    _ => {}
                }
            }
        }
    }

    pub async fn close(&self) -> Result<(), LegacyDtlsChannelError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _write = self.write.lock().await;
        let mut first_error = None;
        if self.close_alert {
            let sequence = self.write_sequence.load(Ordering::Relaxed);
            let alert = {
                let keys = self.keys.lock().await;
                let keys =
                    keys.as_ref().ok_or(LegacyDtlsChannelError::Closed)?;
                encrypt_legacy_dtls_record(
                    &super::LegacyDtlsRecord {
                        content_type: LEGACY_DTLS_CONTENT_ALERT,
                        epoch: 1,
                        sequence,
                        payload: vec![1, 0],
                    },
                    &keys.client_key,
                    &keys.client_mac_key,
                    &self.suite,
                )?
            };
            if let Err(error) = self.send_datagram(&alert).await {
                first_error = Some(error);
            }
        }
        self.keys.lock().await.take();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn decrypt(
        &self,
        record: &super::LegacyDtlsRecord,
    ) -> Result<Vec<u8>, LegacyDtlsChannelError> {
        let keys = self.keys.lock().await;
        let keys = keys.as_ref().ok_or(LegacyDtlsChannelError::Closed)?;
        Ok(decrypt_legacy_dtls_record(
            record,
            &keys.server_key,
            &keys.server_mac_key,
            &self.suite,
        )?)
    }

    async fn send_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<(), LegacyDtlsChannelError> {
        let actual = self.packet.send_to(datagram, &self.destination).await?;
        if actual != datagram.len() {
            return Err(LegacyDtlsChannelError::ShortWrite {
                actual,
                expected: datagram.len(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDtlsMtuProbeOptions {
    pub interval: Duration,
    pub timeout: Duration,
    pub retries: usize,
}

impl Default for LegacyDtlsMtuProbeOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(50),
            timeout: Duration::from_secs(10),
            retries: 6,
        }
    }
}

/// Binary-search the largest payload echoed by the peer's DTLS DPD handler.
pub async fn detect_legacy_dtls_mtu(
    session: &LegacyDtlsSession,
    minimum: usize,
    maximum: usize,
    cancellation: &CancellationToken,
    options: &LegacyDtlsMtuProbeOptions,
) -> Result<Option<usize>, LegacyDtlsChannelError> {
    if minimum == 0 || maximum <= minimum {
        return Ok(None);
    }
    let deadline = Instant::now() + options.timeout;
    let mut lower = minimum;
    let mut upper = maximum;
    let mut candidate = maximum;
    while lower < upper && Instant::now() < deadline {
        if cancellation.is_cancelled() {
            return Err(LegacyDtlsChannelError::Cancelled);
        }
        let successful = probe_candidate(
            session,
            candidate,
            cancellation,
            options,
            deadline,
        )
        .await?;
        if successful {
            lower = candidate;
        } else {
            upper = candidate - 1;
        }
        if lower >= upper {
            break;
        }
        candidate = (lower + upper).div_ceil(2);
    }
    Ok(Some(lower))
}

async fn probe_candidate(
    session: &LegacyDtlsSession,
    candidate: usize,
    cancellation: &CancellationToken,
    options: &LegacyDtlsMtuProbeOptions,
    probe_deadline: Instant,
) -> Result<bool, LegacyDtlsChannelError> {
    let mut payload = vec![0x5a; candidate + 1];
    payload[0] = CstpPacketType::DpdRequest.wire_value();
    for _ in 0..options.retries {
        if cancellation.is_cancelled() {
            return Err(LegacyDtlsChannelError::Cancelled);
        }
        let attempt_deadline =
            (Instant::now() + options.interval).min(probe_deadline);
        match session.send(&payload).await {
            Ok(_) => {}
            Err(LegacyDtlsChannelError::MtuExceeded { .. }) => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        loop {
            let response = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(LegacyDtlsChannelError::Cancelled);
                }
                result = timeout_at(attempt_deadline, session.receive()) => result,
            };
            let Ok(response) = response else {
                break;
            };
            let response = response?;
            if response.len() == payload.len()
                && response.first()
                    == Some(&CstpPacketType::DpdResponse.wire_value())
            {
                return Ok(true);
            }
            if response.first()
                == Some(&CstpPacketType::DpdRequest.wire_value())
            {
                session
                    .send(&[CstpPacketType::DpdResponse.wire_value()])
                    .await?;
            }
        }
    }
    Ok(false)
}

pub type SharedLegacyDtlsSession = Arc<LegacyDtlsSession>;

#[async_trait]
impl super::PppDatagramCarrier for LegacyDtlsSession {
    async fn send(&self, content: &[u8]) -> io::Result<usize> {
        LegacyDtlsSession::send(self, content)
            .await
            .map_err(legacy_dtls_io_error)
    }

    async fn receive(&self, content: &mut [u8]) -> io::Result<usize> {
        let packet = LegacyDtlsSession::receive(self)
            .await
            .map_err(legacy_dtls_io_error)?;
        if packet.len() > content.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy DTLS datagram exceeds receive buffer",
            ));
        }
        content[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    async fn close(&self) -> io::Result<()> {
        LegacyDtlsSession::close(self)
            .await
            .map_err(legacy_dtls_io_error)
    }
}

fn legacy_dtls_io_error(error: LegacyDtlsChannelError) -> io::Error {
    let kind = match error {
        LegacyDtlsChannelError::Closed => io::ErrorKind::BrokenPipe,
        LegacyDtlsChannelError::Cancelled => io::ErrorKind::Interrupted,
        LegacyDtlsChannelError::MtuExceeded { .. } => {
            io::ErrorKind::InvalidData
        }
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use tokio::sync::{Mutex as TokioMutex, mpsc};

    use super::*;
    use crate::{
        adapter::{PacketConnection, PacketFuture},
        protocol::openconnect::{
            LegacyDtlsCipher, LegacyDtlsRecord, derive_legacy_dtls_keys,
            encrypt_legacy_dtls_record, parse_legacy_dtls_records,
        },
    };

    struct MemoryPacket {
        sent: mpsc::UnboundedSender<Vec<u8>>,
        received: TokioMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        peer: SocksAddr,
    }

    impl PacketConnection for MemoryPacket {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                self.sent.send(data.to_vec()).map_err(|_| {
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
                let packet = self
                    .received
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "closed")
                    })?;
                data[..packet.len()].copy_from_slice(&packet);
                Ok((packet.len(), self.peer.clone()))
            })
        }
    }

    fn channel(
        mtu: usize,
    ) -> (
        LegacyDtlsSession,
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedSender<Vec<u8>>,
        LegacyDtlsSuite,
        LegacyDtlsKeys,
    ) {
        let destination = SocksAddr::new("vpn.test", 443);
        let (sent_tx, sent_rx) = mpsc::unbounded_channel();
        let (receive_tx, receive_rx) = mpsc::unbounded_channel();
        let suite = LegacyDtlsSuite::cisco(LegacyDtlsCipher::Aes128);
        let keys = derive_legacy_dtls_keys(
            &suite,
            &[0x11; 48],
            &[0x22; 32],
            &[0x33; 32],
        );
        let packet = Box::new(MemoryPacket {
            sent: sent_tx,
            received: TokioMutex::new(receive_rx),
            peer: destination.clone(),
        });
        (
            LegacyDtlsSession::new(
                packet,
                destination,
                suite.clone(),
                keys.clone(),
                mtu,
                false,
                true,
                Vec::new(),
                Vec::new(),
            ),
            sent_rx,
            receive_tx,
            suite,
            keys,
        )
    }

    #[tokio::test]
    async fn application_records_round_trip_and_replays_are_dropped() {
        let (session, mut sent, receive, suite, keys) = channel(0);
        assert_eq!(session.send(b"client packet").await.unwrap(), 13);
        let outbound = sent.recv().await.unwrap();
        let outbound = parse_legacy_dtls_records(&outbound, &suite)
            .unwrap()
            .remove(0);
        assert_eq!(outbound.sequence, 1);
        assert_eq!(
            super::decrypt_legacy_dtls_record(
                &outbound,
                &keys.client_key,
                &keys.client_mac_key,
                &suite,
            )
            .unwrap(),
            b"client packet"
        );

        let server = encrypt_legacy_dtls_record(
            &LegacyDtlsRecord {
                content_type: LEGACY_DTLS_CONTENT_APPLICATION_DATA,
                epoch: 1,
                sequence: 9,
                payload: b"server packet".to_vec(),
            },
            &keys.server_key,
            &keys.server_mac_key,
            &suite,
        )
        .unwrap();
        receive.send(server.clone()).unwrap();
        assert_eq!(session.receive().await.unwrap(), b"server packet");
        receive.send(server).unwrap();
        let next = encrypt_legacy_dtls_record(
            &LegacyDtlsRecord {
                content_type: LEGACY_DTLS_CONTENT_APPLICATION_DATA,
                epoch: 1,
                sequence: 10,
                payload: b"next".to_vec(),
            },
            &keys.server_key,
            &keys.server_mac_key,
            &suite,
        )
        .unwrap();
        receive.send(next).unwrap();
        assert_eq!(session.receive().await.unwrap(), b"next");
    }

    #[tokio::test]
    async fn mtu_limit_and_close_alert_are_enforced() {
        let (session, mut sent, _receive, suite, keys) = channel(20);
        assert!(matches!(
            session.send(b"too large").await,
            Err(LegacyDtlsChannelError::MtuExceeded { .. })
        ));
        session.set_mtu(0);
        session.close().await.unwrap();
        let alert = sent.recv().await.unwrap();
        let alert =
            parse_legacy_dtls_records(&alert, &suite).unwrap().remove(0);
        assert_eq!(
            super::decrypt_legacy_dtls_record(
                &alert,
                &keys.client_key,
                &keys.client_mac_key,
                &suite,
            )
            .unwrap(),
            [1, 0]
        );
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn mtu_probe_binary_searches_dpd_echo_size() {
        let (session, mut sent, receive, suite, keys) = channel(0);
        let responder = tokio::spawn(async move {
            let mut sequence = 1_u64;
            while let Some(datagram) = sent.recv().await {
                let record = parse_legacy_dtls_records(&datagram, &suite)
                    .unwrap()
                    .remove(0);
                let request = super::decrypt_legacy_dtls_record(
                    &record,
                    &keys.client_key,
                    &keys.client_mac_key,
                    &suite,
                )
                .unwrap();
                if request.len() <= 151 {
                    let mut response = request;
                    response[0] = CstpPacketType::DpdResponse.wire_value();
                    receive
                        .send(
                            encrypt_legacy_dtls_record(
                                &LegacyDtlsRecord {
                                    content_type:
                                        LEGACY_DTLS_CONTENT_APPLICATION_DATA,
                                    epoch: 1,
                                    sequence,
                                    payload: response,
                                },
                                &keys.server_key,
                                &keys.server_mac_key,
                                &suite,
                            )
                            .unwrap(),
                        )
                        .unwrap();
                    sequence += 1;
                }
            }
        });
        assert_eq!(
            detect_legacy_dtls_mtu(
                &session,
                100,
                200,
                &CancellationToken::new(),
                &LegacyDtlsMtuProbeOptions {
                    interval: Duration::from_millis(5),
                    timeout: Duration::from_secs(1),
                    retries: 1,
                },
            )
            .await
            .unwrap(),
            Some(150)
        );
        responder.abort();
    }
}
