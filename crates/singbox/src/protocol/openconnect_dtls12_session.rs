//! Packet-oriented DTLS 1.2 session for the AnyConnect data channel.

use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use openssl::memcmp;
use thiserror::Error;
use tokio::{
    sync::Mutex,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

use super::{
    CstpPacketType, DTLS12_MAX_SEQUENCE, Dtls12Error, Dtls12Keys, Dtls12Record,
    Dtls12Suite, LegacyDtlsReplayWindow, decrypt_dtls12_record,
    encrypt_dtls12_record, parse_dtls12_records,
};
use crate::{adapter::PacketStream, common::network::SocksAddr};

const DTLS12_READ_BUFFER_SIZE: usize = 64 * 1024;
const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

#[derive(Debug, Error)]
pub enum Dtls12ChannelError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Record(#[from] Dtls12Error),
    #[error("DTLS 1.2 channel is closed")]
    Closed,
    #[error("DTLS 1.2 record sequence exhausted")]
    SequenceExhausted,
    #[error(
        "DTLS 1.2 datagram write was short: wrote {actual} of {expected} bytes"
    )]
    ShortWrite { actual: usize, expected: usize },
    #[error("DTLS 1.2 record is {actual} bytes for MTU {mtu}")]
    MtuExceeded { actual: usize, mtu: usize },
    #[error("DTLS 1.2 peer sent alert {0:?}")]
    PeerAlert(Option<u8>),
    #[error("unknown DTLS 1.2 record type: {0}")]
    UnknownRecord(u8),
    #[error("DTLS 1.2 MTU probe was cancelled")]
    Cancelled,
}

struct Dtls12ReadState {
    queue: VecDeque<Vec<u8>>,
    replay: LegacyDtlsReplayWindow,
    buffer: Vec<u8>,
}

impl Default for Dtls12ReadState {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            replay: LegacyDtlsReplayWindow::default(),
            buffer: vec![0; DTLS12_READ_BUFFER_SIZE],
        }
    }
}

/// An encrypted DTLS 1.2 packet channel over an arbitrary singbox UDP dialer.
pub struct Dtls12Session {
    packet: PacketStream,
    destination: SocksAddr,
    suite: Dtls12Suite,
    keys: Mutex<Option<Dtls12Keys>>,
    read: Mutex<Dtls12ReadState>,
    write: Mutex<()>,
    write_sequence: AtomicU64,
    mtu: AtomicUsize,
    strict: bool,
    close_alert: bool,
    final_flight: Vec<Vec<u8>>,
    server_finished: Vec<u8>,
    closed: AtomicBool,
}

impl Dtls12Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet: PacketStream,
        destination: SocksAddr,
        suite: Dtls12Suite,
        keys: Dtls12Keys,
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
            read: Mutex::new(Dtls12ReadState::default()),
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
    ) -> Result<usize, Dtls12ChannelError> {
        let _write = self.write.lock().await;
        if self.is_closed() {
            return Err(Dtls12ChannelError::Closed);
        }
        let sequence = self.write_sequence.load(Ordering::Relaxed);
        if sequence > DTLS12_MAX_SEQUENCE {
            return Err(Dtls12ChannelError::SequenceExhausted);
        }
        let encoded = {
            let keys = self.keys.lock().await;
            let keys = keys.as_ref().ok_or(Dtls12ChannelError::Closed)?;
            encrypt_dtls12_record(
                &Dtls12Record {
                    content_type: CONTENT_APPLICATION_DATA,
                    epoch: 1,
                    sequence,
                    payload: payload.to_vec(),
                },
                &keys.client_write_key,
                &keys.client_mac_key,
                &keys.client_write_iv,
                &self.suite,
            )?
        };
        let mtu = self.mtu();
        if mtu != 0 && encoded.len() > mtu {
            return Err(Dtls12ChannelError::MtuExceeded {
                actual: encoded.len(),
                mtu,
            });
        }
        self.send_datagram(&encoded).await?;
        self.write_sequence.fetch_add(1, Ordering::Relaxed);
        Ok(payload.len())
    }

    pub async fn receive(&self) -> Result<Vec<u8>, Dtls12ChannelError> {
        let mut state = self.read.lock().await;
        loop {
            if let Some(payload) = state.queue.pop_front() {
                return Ok(payload);
            }
            if self.is_closed() {
                return Err(Dtls12ChannelError::Closed);
            }
            let (size, source) =
                self.packet.recv_from(&mut state.buffer).await?;
            if source != self.destination {
                continue;
            }
            let records = match parse_dtls12_records(&state.buffer[..size]) {
                Ok(records) => records,
                Err(error) if !self.strict => {
                    let _ = error;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            for record in records {
                match record.content_type {
                    CONTENT_APPLICATION_DATA if record.epoch == 1 => {
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
                    CONTENT_HANDSHAKE if record.epoch == 1 => {
                        let Ok(plaintext) = self.decrypt(&record).await else {
                            continue;
                        };
                        if memcmp::eq(&plaintext, &self.server_finished) {
                            let _write = self.write.lock().await;
                            for datagram in &self.final_flight {
                                self.send_datagram(datagram).await?;
                            }
                        }
                    }
                    CONTENT_ALERT if record.epoch == 1 => {
                        let plaintext = match self.decrypt(&record).await {
                            Ok(plaintext) => plaintext,
                            Err(error) if !self.strict => {
                                let _ = error;
                                continue;
                            }
                            Err(error) => return Err(error),
                        };
                        let description =
                            (plaintext.len() == 2).then_some(plaintext[1]);
                        if description == Some(0) {
                            self.closed.store(true, Ordering::Release);
                            return Err(Dtls12ChannelError::Closed);
                        }
                        return Err(Dtls12ChannelError::PeerAlert(description));
                    }
                    CONTENT_CHANGE_CIPHER_SPEC => {}
                    value if self.strict => {
                        return Err(Dtls12ChannelError::UnknownRecord(value));
                    }
                    _ => {}
                }
            }
        }
    }

    pub async fn close(&self) -> Result<(), Dtls12ChannelError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _write = self.write.lock().await;
        let mut first_error = None;
        if self.close_alert {
            let sequence = self.write_sequence.load(Ordering::Relaxed);
            let alert = {
                let keys = self.keys.lock().await;
                let keys = keys.as_ref().ok_or(Dtls12ChannelError::Closed)?;
                encrypt_dtls12_record(
                    &Dtls12Record {
                        content_type: CONTENT_ALERT,
                        epoch: 1,
                        sequence,
                        payload: vec![1, 0],
                    },
                    &keys.client_write_key,
                    &keys.client_mac_key,
                    &keys.client_write_iv,
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
        record: &Dtls12Record,
    ) -> Result<Vec<u8>, Dtls12ChannelError> {
        let keys = self.keys.lock().await;
        let keys = keys.as_ref().ok_or(Dtls12ChannelError::Closed)?;
        Ok(decrypt_dtls12_record(
            record,
            &keys.server_write_key,
            &keys.server_mac_key,
            &keys.server_write_iv,
            &self.suite,
        )?)
    }

    async fn send_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<(), Dtls12ChannelError> {
        let actual = self.packet.send_to(datagram, &self.destination).await?;
        if actual != datagram.len() {
            return Err(Dtls12ChannelError::ShortWrite {
                actual,
                expected: datagram.len(),
            });
        }
        Ok(())
    }
}

pub type SharedDtls12Session = Arc<Dtls12Session>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dtls12MtuProbeOptions {
    pub interval: Duration,
    pub timeout: Duration,
    pub retries: usize,
}

impl Default for Dtls12MtuProbeOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(50),
            timeout: Duration::from_secs(10),
            retries: 6,
        }
    }
}

/// Binary-search the largest packet echoed by the peer's encrypted DPD path.
pub async fn detect_dtls12_mtu(
    session: &Dtls12Session,
    minimum: usize,
    maximum: usize,
    cancellation: &CancellationToken,
    options: &Dtls12MtuProbeOptions,
) -> Result<Option<usize>, Dtls12ChannelError> {
    if minimum == 0 || maximum <= minimum {
        return Ok(None);
    }
    let deadline = Instant::now() + options.timeout;
    let mut lower = minimum;
    let mut upper = maximum;
    let mut candidate = maximum;
    while lower < upper && Instant::now() < deadline {
        if cancellation.is_cancelled() {
            return Err(Dtls12ChannelError::Cancelled);
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
    session: &Dtls12Session,
    candidate: usize,
    cancellation: &CancellationToken,
    options: &Dtls12MtuProbeOptions,
    probe_deadline: Instant,
) -> Result<bool, Dtls12ChannelError> {
    let mut payload = vec![0x5a; candidate + 1];
    payload[0] = CstpPacketType::DpdRequest.wire_value();
    for _ in 0..options.retries {
        if cancellation.is_cancelled() {
            return Err(Dtls12ChannelError::Cancelled);
        }
        let attempt_deadline =
            (Instant::now() + options.interval).min(probe_deadline);
        match session.send(&payload).await {
            Ok(_) => {}
            Err(Dtls12ChannelError::MtuExceeded { .. }) => return Ok(false),
            Err(error) => return Err(error),
        }
        loop {
            let response = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(Dtls12ChannelError::Cancelled);
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

#[cfg(test)]
mod tests {
    use tokio::sync::{Mutex as TokioMutex, mpsc};

    use super::*;
    use crate::adapter::{PacketConnection, PacketFuture};
    use crate::protocol::openconnect::{
        Dtls12Record, derive_dtls12_keys, encrypt_dtls12_record,
        parse_dtls12_records,
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
        Dtls12Session,
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedSender<Vec<u8>>,
        Dtls12Suite,
        Dtls12Keys,
    ) {
        let destination = SocksAddr::new("vpn.test", 443);
        let (sent_tx, sent_rx) = mpsc::unbounded_channel();
        let (receive_tx, receive_rx) = mpsc::unbounded_channel();
        let suite =
            Dtls12Suite::from_name("OC-DTLS1_2-AES128-GCM", true).unwrap();
        let keys =
            derive_dtls12_keys(&suite, &[0x11; 48], &[0x22; 32], &[0x33; 32]);
        let packet = Box::new(MemoryPacket {
            sent: sent_tx,
            received: TokioMutex::new(receive_rx),
            peer: destination.clone(),
        });
        (
            Dtls12Session::new(
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
        let outbound = parse_dtls12_records(&outbound).unwrap().remove(0);
        assert_eq!(outbound.sequence, 1);
        assert_eq!(
            decrypt_dtls12_record(
                &outbound,
                &keys.client_write_key,
                &keys.client_mac_key,
                &keys.client_write_iv,
                &suite,
            )
            .unwrap(),
            b"client packet"
        );

        let server = encrypt_dtls12_record(
            &Dtls12Record {
                content_type: CONTENT_APPLICATION_DATA,
                epoch: 1,
                sequence: 9,
                payload: b"server packet".to_vec(),
            },
            &keys.server_write_key,
            &keys.server_mac_key,
            &keys.server_write_iv,
            &suite,
        )
        .unwrap();
        receive.send(server.clone()).unwrap();
        assert_eq!(session.receive().await.unwrap(), b"server packet");
        receive.send(server).unwrap();
        receive
            .send(
                encrypt_dtls12_record(
                    &Dtls12Record {
                        content_type: CONTENT_APPLICATION_DATA,
                        epoch: 1,
                        sequence: 10,
                        payload: b"next".to_vec(),
                    },
                    &keys.server_write_key,
                    &keys.server_mac_key,
                    &keys.server_write_iv,
                    &suite,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(session.receive().await.unwrap(), b"next");
    }

    #[tokio::test]
    async fn mtu_limit_and_close_alert_are_enforced() {
        let (session, mut sent, _receive, suite, keys) = channel(20);
        assert!(matches!(
            session.send(b"too large").await,
            Err(Dtls12ChannelError::MtuExceeded { .. })
        ));
        session.set_mtu(0);
        session.close().await.unwrap();
        let alert = sent.recv().await.unwrap();
        let alert = parse_dtls12_records(&alert).unwrap().remove(0);
        assert_eq!(
            decrypt_dtls12_record(
                &alert,
                &keys.client_write_key,
                &keys.client_mac_key,
                &keys.client_write_iv,
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
                let record = parse_dtls12_records(&datagram).unwrap().remove(0);
                let request = decrypt_dtls12_record(
                    &record,
                    &keys.client_write_key,
                    &keys.client_mac_key,
                    &keys.client_write_iv,
                    &suite,
                )
                .unwrap();
                if request.len() <= 151 {
                    let mut response = request;
                    response[0] = CstpPacketType::DpdResponse.wire_value();
                    receive
                        .send(
                            encrypt_dtls12_record(
                                &Dtls12Record {
                                    content_type: CONTENT_APPLICATION_DATA,
                                    epoch: 1,
                                    sequence,
                                    payload: response,
                                },
                                &keys.server_write_key,
                                &keys.server_mac_key,
                                &keys.server_write_iv,
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
            detect_dtls12_mtu(
                &session,
                100,
                200,
                &CancellationToken::new(),
                &Dtls12MtuProbeOptions {
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
