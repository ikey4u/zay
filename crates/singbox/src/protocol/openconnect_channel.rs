//! Unified AnyConnect DTLS data-channel selection and packet policy.

use std::{sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;

use super::{
    AnyConnectCstpConnection, AnyConnectDeflateState, AnyConnectDtlsPsk,
    AnyConnectPskDtlsError, AnyConnectPskDtlsOptions, AnyConnectPskDtlsSession,
    CSTP_MAX_PAYLOAD_SIZE, CstpCompression, CstpDtlsNegotiation, CstpError,
    CstpKeepaliveState, CstpNegotiatedState, CstpPacket, CstpPacketType,
    CstpRekeyMethod, CstpSession, CstpTimerAction, Dtls12ChannelError,
    Dtls12ConnectError, Dtls12ConnectOptions, Dtls12Error,
    Dtls12MtuProbeOptions, Dtls12Session, LegacyDtlsChannelError,
    LegacyDtlsConnectError, LegacyDtlsConnectOptions, LegacyDtlsError,
    LegacyDtlsMtuProbeOptions, LegacyDtlsSession,
    compress_anyconnect_stateless, connect_dtls12_resumption,
    connect_legacy_dtls, decompress_anyconnect_stateless, detect_dtls12_mtu,
    detect_legacy_dtls_mtu, dial_anyconnect_psk_dtls,
};
use crate::adapter::Dialer;

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_FLIGHT_INTERVAL: Duration = Duration::from_millis(250);
const DEFAULT_RETRIES: usize = 6;
const DTLS_RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const DTLS_RETRY_MAXIMUM_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum AnyConnectDtlsChannelError {
    #[error("standard PSK DTLS negotiation did not provide an exporter secret")]
    MissingPsk,
    #[error(transparent)]
    Cstp(#[from] CstpError),
    #[error(transparent)]
    LegacyConnect(#[from] LegacyDtlsConnectError),
    #[error(transparent)]
    Dtls12Connect(#[from] Dtls12ConnectError),
    #[error(transparent)]
    PskConnect(#[from] AnyConnectPskDtlsError),
    #[error(transparent)]
    LegacyChannel(#[from] LegacyDtlsChannelError),
    #[error(transparent)]
    Dtls12Channel(#[from] Dtls12ChannelError),
    #[error("AnyConnect DTLS peer is dead")]
    DeadPeer,
    #[error("AnyConnect DTLS channel requires tunnel rekey via {0:?}")]
    Rekey(CstpRekeyMethod),
    #[error("AnyConnect DTLS peer closed the data channel with {0:?}")]
    PeerClosed(CstpPacketType),
    #[error("AnyConnect DTLS transport returned a short datagram write")]
    ShortWrite,
}

#[derive(Debug, Error)]
pub enum AnyConnectDataChannelError {
    #[error(transparent)]
    Cstp(#[from] CstpError),
    #[error(transparent)]
    Dtls(#[from] AnyConnectDtlsChannelError),
    #[error("AnyConnect CSTP control channel closed")]
    CstpClosed,
}

impl AnyConnectDataChannelError {
    /// Whether the pinned Go client treats this failure as a configuration or
    /// protocol incompatibility rather than a transient transport outage.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Dtls(error) if dtls_error_is_terminal(error))
    }
}

/// An event produced by the AnyConnect data plane.
///
/// State changes are exposed separately so an embedding endpoint can publish
/// DTLS fallback/recovery immediately, even when no tunnel packet is flowing.
pub enum AnyConnectDataChannelEvent {
    Data(Vec<u8>),
    TransportStateChanged,
}

/// Established flavor-specific transport behind one packet API.
pub enum AnyConnectDtlsTransport {
    Legacy(LegacyDtlsSession),
    InjectedDtls12(Dtls12Session),
    Psk(AnyConnectPskDtlsSession),
}

struct AnyConnectDtlsAttempt {
    transport: AnyConnectDtlsTransport,
    negotiation: CstpDtlsNegotiation,
    detected_mtu: Option<usize>,
}

struct AnyConnectDtlsRetryState {
    dialer: Arc<dyn Dialer>,
    negotiation: CstpDtlsNegotiation,
    psk: Option<AnyConnectDtlsPsk>,
    minimum_mtu: usize,
    cancellation: CancellationToken,
    next_attempt: Instant,
    retry_delay: Duration,
    attempt: Option<
        JoinHandle<Result<AnyConnectDtlsAttempt, AnyConnectDtlsChannelError>>,
    >,
}

impl AnyConnectDtlsRetryState {
    fn new(
        dialer: Arc<dyn Dialer>,
        negotiation: CstpDtlsNegotiation,
        psk: Option<AnyConnectDtlsPsk>,
        minimum_mtu: usize,
        parent_cancellation: &CancellationToken,
    ) -> Self {
        Self {
            dialer,
            negotiation,
            psk,
            minimum_mtu,
            cancellation: parent_cancellation.child_token(),
            next_attempt: Instant::now(),
            retry_delay: DTLS_RETRY_INITIAL_BACKOFF,
            attempt: None,
        }
    }

    fn schedule(&mut self, immediate: bool) {
        if immediate {
            self.next_attempt = Instant::now();
            self.retry_delay = DTLS_RETRY_INITIAL_BACKOFF;
        } else {
            self.next_attempt = Instant::now() + self.retry_delay;
            self.retry_delay = self
                .retry_delay
                .saturating_mul(2)
                .min(DTLS_RETRY_MAXIMUM_BACKOFF);
        }
    }

    fn restored(&mut self, negotiation: CstpDtlsNegotiation) {
        self.negotiation = negotiation;
        self.retry_delay = DTLS_RETRY_INITIAL_BACKOFF;
        self.next_attempt = Instant::now();
    }

    fn start_if_due(&mut self) {
        if self.attempt.is_some()
            || self.cancellation.is_cancelled()
            || Instant::now() < self.next_attempt
        {
            return;
        }
        let dialer = self.dialer.clone();
        let negotiation = self.negotiation.clone();
        let psk = self.psk.clone();
        let minimum_mtu = self.minimum_mtu;
        let cancellation = self.cancellation.clone();
        self.attempt = Some(tokio::spawn(async move {
            establish_anyconnect_dtls_attempt(
                dialer,
                negotiation,
                psk,
                minimum_mtu,
                &cancellation,
            )
            .await
        }));
    }

    fn cancel(&mut self) {
        self.cancellation.cancel();
        if let Some(attempt) = self.attempt.take() {
            attempt.abort();
        }
    }
}

impl AnyConnectDtlsTransport {
    async fn detect_mtu(
        &self,
        minimum: usize,
        maximum: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<usize>, AnyConnectDtlsChannelError> {
        match self {
            Self::Legacy(session) => Ok(detect_legacy_dtls_mtu(
                session,
                minimum,
                maximum,
                cancellation,
                &LegacyDtlsMtuProbeOptions::default(),
            )
            .await?),
            Self::InjectedDtls12(session) => Ok(detect_dtls12_mtu(
                session,
                minimum,
                maximum,
                cancellation,
                &Dtls12MtuProbeOptions::default(),
            )
            .await?),
            Self::Psk(session) => {
                Ok(session.detect_mtu(minimum, maximum, cancellation).await?)
            }
        }
    }

    pub async fn send(
        &self,
        payload: &[u8],
    ) -> Result<(), AnyConnectDtlsChannelError> {
        let written = match self {
            Self::Legacy(session) => session.send(payload).await?,
            Self::InjectedDtls12(session) => session.send(payload).await?,
            Self::Psk(session) => session.send(payload).await?,
        };
        if written != payload.len() {
            return Err(AnyConnectDtlsChannelError::ShortWrite);
        }
        Ok(())
    }

    pub async fn receive(&self) -> Result<Vec<u8>, AnyConnectDtlsChannelError> {
        match self {
            Self::Legacy(session) => Ok(session.receive().await?),
            Self::InjectedDtls12(session) => Ok(session.receive().await?),
            Self::Psk(session) => {
                let mut buffer = vec![0; CSTP_MAX_PAYLOAD_SIZE + 1];
                let size = session.receive(&mut buffer).await?;
                buffer.truncate(size);
                Ok(buffer)
            }
        }
    }

    pub async fn close(&self) -> Result<(), AnyConnectDtlsChannelError> {
        match self {
            Self::Legacy(session) => Ok(session.close().await?),
            Self::InjectedDtls12(session) => Ok(session.close().await?),
            Self::Psk(session) => Ok(session.close().await?),
        }
    }
}

/// Dial the flavor selected by the ordered CSTP response headers.
pub async fn dial_anyconnect_dtls(
    dialer: Arc<dyn Dialer>,
    negotiation: &CstpDtlsNegotiation,
    psk: Option<AnyConnectDtlsPsk>,
    cancellation: &CancellationToken,
) -> Result<AnyConnectDtlsTransport, AnyConnectDtlsChannelError> {
    if negotiation.cipher_suite == "PSK-NEGOTIATE" {
        let psk = psk.ok_or(AnyConnectDtlsChannelError::MissingPsk)?;
        return Ok(AnyConnectDtlsTransport::Psk(
            dial_anyconnect_psk_dtls(
                dialer,
                negotiation,
                psk,
                AnyConnectPskDtlsOptions {
                    // The common AnyConnect channel enforces tunnel payload
                    // MTU. Keep the record layer unbounded so DPD probing can
                    // observe the actual UDP path limit including overhead.
                    mtu: 0,
                    ..Default::default()
                },
            )
            .await?,
        ));
    }

    let destination = crate::common::network::SocksAddr::new(
        &negotiation.host,
        negotiation.port,
    );
    let packet = dialer
        .listen_udp(&destination)
        .await
        .map_err(CstpError::from)?;
    if negotiation.dtls12 {
        Ok(AnyConnectDtlsTransport::InjectedDtls12(
            connect_dtls12_resumption(
                packet,
                destination,
                &Dtls12ConnectOptions {
                    session_id: negotiation.session_id.clone(),
                    master_secret: negotiation.master_secret.clone(),
                    cipher_suite: negotiation.cipher_suite.clone(),
                    mtu: 0,
                    strict: true,
                    close_alert: false,
                    handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
                    initial_retry_interval: DEFAULT_FLIGHT_INTERVAL,
                    retries: DEFAULT_RETRIES,
                },
                cancellation,
            )
            .await?,
        ))
    } else {
        Ok(AnyConnectDtlsTransport::Legacy(
            connect_legacy_dtls(
                packet,
                destination,
                &LegacyDtlsConnectOptions {
                    session_id: negotiation.session_id.clone(),
                    master_secret: negotiation.master_secret.clone(),
                    cipher_suite: negotiation.cipher_suite.clone(),
                    allow_insecure_crypto: negotiation.allow_insecure_crypto,
                    mtu: 0,
                    strict: true,
                    close_alert: false,
                    handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
                    initial_retry_interval: DEFAULT_FLIGHT_INTERVAL,
                    retries: DEFAULT_RETRIES,
                },
                cancellation,
            )
            .await?,
        ))
    }
}

async fn establish_anyconnect_dtls_attempt(
    dialer: Arc<dyn Dialer>,
    mut negotiation: CstpDtlsNegotiation,
    psk: Option<AnyConnectDtlsPsk>,
    minimum_mtu: usize,
    cancellation: &CancellationToken,
) -> Result<AnyConnectDtlsAttempt, AnyConnectDtlsChannelError> {
    let transport =
        dial_anyconnect_dtls(dialer, &negotiation, psk, cancellation).await?;
    let detected_mtu = transport
        .detect_mtu(minimum_mtu, negotiation.mtu as usize, cancellation)
        .await?;
    if let Some(detected) = detected_mtu.and_then(|mtu| u32::try_from(mtu).ok())
        && detected != 0
        && detected < negotiation.mtu
    {
        negotiation.mtu = detected;
    }
    Ok(AnyConnectDtlsAttempt {
        transport,
        negotiation,
        detected_mtu,
    })
}

/// Packet-type, compression and liveness policy shared by all DTLS flavors.
pub struct AnyConnectDtlsChannel {
    transport: AnyConnectDtlsTransport,
    mtu: usize,
    outgoing_compression: CstpCompression,
    incoming_compression: CstpCompression,
    outgoing_deflate: Option<AnyConnectDeflateState>,
    incoming_deflate: Option<AnyConnectDeflateState>,
    origin: Instant,
    keepalive: CstpKeepaliveState,
    rekey_method: CstpRekeyMethod,
}

impl AnyConnectDtlsChannel {
    pub fn new(
        transport: AnyConnectDtlsTransport,
        negotiation: &CstpDtlsNegotiation,
    ) -> Self {
        Self {
            transport,
            mtu: negotiation.mtu as usize,
            outgoing_compression: negotiation.compression,
            incoming_compression: negotiation.compression,
            outgoing_deflate: (negotiation.compression
                == CstpCompression::Deflate)
                .then(AnyConnectDeflateState::new),
            incoming_deflate: (negotiation.compression
                == CstpCompression::Deflate)
                .then(AnyConnectDeflateState::new),
            origin: Instant::now(),
            keepalive: CstpKeepaliveState::new(
                negotiation.dpd,
                negotiation.keepalive,
                negotiation.rekey,
                negotiation.rekey_method,
            ),
            rekey_method: negotiation.rekey_method,
        }
    }

    pub async fn send_data(
        &mut self,
        payload: &[u8],
    ) -> Result<(), AnyConnectDtlsChannelError> {
        let packet = self.encode_data(payload)?;
        self.transport.send(&packet).await?;
        self.keepalive.mark_transmitted(self.origin.elapsed());
        Ok(())
    }

    pub async fn receive_data(
        &mut self,
    ) -> Result<Vec<u8>, AnyConnectDtlsChannelError> {
        loop {
            let elapsed = self.origin.elapsed();
            let delay = self.keepalive.next_delay(elapsed);
            tokio::select! {
                result = self.transport.receive() => {
                    let packet = result?;
                    self.keepalive.mark_received(self.origin.elapsed());
                    let Some(packet) = self.decode_packet(&packet)? else {
                        continue;
                    };
                    match packet.packet_type {
                        CstpPacketType::Data => return Ok(packet.payload),
                        CstpPacketType::DpdRequest => {
                            self.send_control(CstpPacketType::DpdResponse).await?;
                        }
                        CstpPacketType::DpdResponse | CstpPacketType::Keepalive => {}
                        CstpPacketType::Disconnect | CstpPacketType::Terminate => {
                            return Err(AnyConnectDtlsChannelError::PeerClosed(
                                packet.packet_type,
                            ));
                        }
                        CstpPacketType::Compressed => unreachable!("decoded to data"),
                        CstpPacketType::Unknown(_) => {
                            return Err(CstpError::Protocol(
                                "unknown AnyConnect DTLS packet type".into(),
                            ).into());
                        }
                    }
                }
                _ = tokio::time::sleep(delay) => {
                    match self.keepalive.action(self.origin.elapsed()) {
                        CstpTimerAction::Dpd => {
                            self.send_control(CstpPacketType::DpdRequest).await?;
                        }
                        CstpTimerAction::Keepalive => {
                            self.send_control(CstpPacketType::Keepalive).await?;
                        }
                        CstpTimerAction::DeadPeer => {
                            return Err(AnyConnectDtlsChannelError::DeadPeer);
                        }
                        CstpTimerAction::Rekey => {
                            return Err(AnyConnectDtlsChannelError::Rekey(
                                self.rekey_method,
                            ));
                        }
                        CstpTimerAction::None => {}
                    }
                }
            }
        }
    }

    pub async fn close(&self) -> Result<(), AnyConnectDtlsChannelError> {
        self.transport.close().await
    }

    fn encode_data(&mut self, payload: &[u8]) -> Result<Vec<u8>, CstpError> {
        if payload.len() > self.mtu {
            return Err(CstpError::InvalidOption(format!(
                "DTLS data packet exceeds negotiated MTU: {} > {}",
                payload.len(),
                self.mtu
            )));
        }
        let encoded = match self.outgoing_compression {
            CstpCompression::OcLz4 | CstpCompression::Lzs => {
                compress_anyconnect_stateless(
                    self.outgoing_compression,
                    payload,
                )?
            }
            CstpCompression::Deflate => match self
                .outgoing_deflate
                .as_mut()
                .expect("deflate state is configured")
                .compress(payload)
            {
                Ok(payload) => Some(payload),
                Err(_) => {
                    // Match upstream: a compressor failure disables only the
                    // outgoing direction. Incoming state remains usable.
                    self.outgoing_compression = CstpCompression::None;
                    self.outgoing_deflate = None;
                    None
                }
            },
            CstpCompression::None => None,
        };
        let (packet_type, body) = encoded
            .as_deref()
            .map_or((CstpPacketType::Data, payload), |encoded| {
                (CstpPacketType::Compressed, encoded)
            });
        let mut packet = Vec::with_capacity(body.len() + 1);
        packet.push(packet_type.wire_value());
        packet.extend_from_slice(body);
        Ok(packet)
    }

    fn decode_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<CstpPacket>, CstpError> {
        let Some((&packet_type, payload)) = packet.split_first() else {
            return Err(CstpError::Protocol(
                "empty AnyConnect DTLS packet".into(),
            ));
        };
        let packet_type = CstpPacketType::from(packet_type);
        if packet_type != CstpPacketType::Compressed {
            if packet_type == CstpPacketType::Data && payload.len() > self.mtu {
                return Err(CstpError::Protocol(format!(
                    "received DTLS data packet over MTU: {} > {}",
                    payload.len(),
                    self.mtu
                )));
            }
            return Ok(Some(CstpPacket {
                packet_type,
                payload: payload.to_vec(),
            }));
        }
        if self.incoming_compression == CstpCompression::None {
            return Err(CstpError::Protocol(
                "received compressed DTLS packet without negotiation".into(),
            ));
        }
        let decoded = if self.incoming_compression == CstpCompression::Deflate {
            self.incoming_deflate
                .as_mut()
                .expect("deflate state is configured")
                .decompress(payload, self.mtu)?
        } else {
            match decompress_anyconnect_stateless(
                self.incoming_compression,
                payload,
                self.mtu,
            ) {
                Ok(decoded) => decoded,
                Err(_) => return Ok(None),
            }
        };
        Ok(Some(CstpPacket {
            packet_type: CstpPacketType::Data,
            payload: decoded,
        }))
    }

    async fn send_control(
        &mut self,
        packet_type: CstpPacketType,
    ) -> Result<(), AnyConnectDtlsChannelError> {
        self.transport.send(&[packet_type.wire_value()]).await?;
        self.keepalive.mark_transmitted(self.origin.elapsed());
        Ok(())
    }
}

/// Live AnyConnect data path with CSTP as the permanent control/fallback
/// channel and DTLS as an optional fast path.
pub struct AnyConnectDataChannel {
    negotiated: CstpNegotiatedState,
    cstp: CstpSession,
    dtls: Option<AnyConnectDtlsChannel>,
    dtls_retry: Option<AnyConnectDtlsRetryState>,
    last_dtls_error: Option<String>,
}

impl AnyConnectDataChannel {
    /// Attempt the negotiated DTLS mode without making a failed UDP fast path
    /// fatal to the already-established CSTP tunnel.
    pub async fn establish(
        dialer: Arc<dyn Dialer>,
        connection: AnyConnectCstpConnection,
        cancellation: &CancellationToken,
    ) -> Result<Self, AnyConnectDataChannelError> {
        let AnyConnectCstpConnection {
            mut negotiated,
            dtls,
            dtls_psk,
            session,
        } = connection;
        let minimum_mtu = if negotiated
            .configuration
            .addresses
            .iter()
            .any(|address| address.addr().is_ipv6())
        {
            1280
        } else {
            576
        };
        let (dtls, dtls_retry, last_dtls_error) = match dtls {
            Some(negotiation) => {
                let mut retry = AnyConnectDtlsRetryState::new(
                    dialer,
                    negotiation,
                    dtls_psk,
                    minimum_mtu,
                    cancellation,
                );
                let attempt = establish_anyconnect_dtls_attempt(
                    retry.dialer.clone(),
                    retry.negotiation.clone(),
                    retry.psk.clone(),
                    minimum_mtu,
                    &retry.cancellation,
                )
                .await;
                match attempt {
                    Ok(attempt) => {
                        let AnyConnectDtlsAttempt {
                            transport,
                            mut negotiation,
                            detected_mtu,
                        } = attempt;
                        apply_detected_dtls_mtu(
                            &mut negotiated,
                            &mut negotiation,
                            detected_mtu,
                        );
                        retry.restored(negotiation.clone());
                        (
                            Some(AnyConnectDtlsChannel::new(
                                transport,
                                &negotiation,
                            )),
                            Some(retry),
                            None,
                        )
                    }
                    Err(error) if dtls_error_is_terminal(&error) => {
                        return Err(error.into());
                    }
                    Err(error) => {
                        retry.schedule(false);
                        (None, Some(retry), Some(error.to_string()))
                    }
                }
            }
            None => (None, None, None),
        };
        Ok(Self {
            negotiated,
            cstp: session,
            dtls,
            dtls_retry,
            last_dtls_error,
        })
    }

    pub fn negotiated(&self) -> &CstpNegotiatedState {
        &self.negotiated
    }

    pub fn dtls_active(&self) -> bool {
        self.dtls.is_some()
    }

    /// Most recent reason the optional DTLS path could not be established or
    /// had to fall back to CSTP.
    pub fn last_dtls_error(&self) -> Option<&str> {
        self.last_dtls_error.as_deref()
    }

    fn restore_dtls(&mut self, attempt: AnyConnectDtlsAttempt) {
        let AnyConnectDtlsAttempt {
            transport,
            mut negotiation,
            detected_mtu,
        } = attempt;
        apply_detected_dtls_mtu(
            &mut self.negotiated,
            &mut negotiation,
            detected_mtu,
        );
        if let Some(retry) = self.dtls_retry.as_mut() {
            retry.restored(negotiation.clone());
        }
        self.dtls = Some(AnyConnectDtlsChannel::new(transport, &negotiation));
        self.last_dtls_error = None;
    }

    fn fail_dtls_retry(&mut self, error: impl ToString) {
        self.last_dtls_error = Some(error.to_string());
        if let Some(retry) = self.dtls_retry.as_mut() {
            retry.attempt.take();
            retry.schedule(false);
        }
    }

    async fn receive_cstp_while_retrying_dtls(
        &mut self,
    ) -> Result<Option<Vec<u8>>, AnyConnectDataChannelError> {
        enum FallbackEvent {
            Cstp(Result<Option<Vec<u8>>, CstpError>),
            Retry(
                Box<
                    Result<
                        Result<
                            AnyConnectDtlsAttempt,
                            AnyConnectDtlsChannelError,
                        >,
                        tokio::task::JoinError,
                    >,
                >,
            ),
            Wake,
        }

        let Some(retry) = self.dtls_retry.as_mut() else {
            return self
                .cstp
                .read_data_packet()
                .await?
                .ok_or(AnyConnectDataChannelError::CstpClosed)
                .map(Some);
        };
        retry.start_if_due();
        let event = if let Some(attempt) = retry.attempt.as_mut() {
            tokio::select! {
                packet = self.cstp.read_data_packet() => {
                    FallbackEvent::Cstp(packet)
                }
                result = attempt => FallbackEvent::Retry(Box::new(result)),
            }
        } else {
            let next_attempt = retry.next_attempt;
            tokio::select! {
                packet = self.cstp.read_data_packet() => {
                    FallbackEvent::Cstp(packet)
                }
                _ = tokio::time::sleep_until(next_attempt) => {
                    FallbackEvent::Wake
                }
            }
        };
        match event {
            FallbackEvent::Cstp(Ok(Some(packet))) => Ok(Some(packet)),
            FallbackEvent::Cstp(Ok(None)) => {
                Err(AnyConnectDataChannelError::CstpClosed)
            }
            FallbackEvent::Cstp(Err(error)) => Err(error.into()),
            FallbackEvent::Retry(result) => match *result {
                Ok(Ok(attempt)) => {
                    if let Some(retry) = self.dtls_retry.as_mut() {
                        retry.attempt.take();
                    }
                    self.restore_dtls(attempt);
                    Ok(None)
                }
                Ok(Err(error)) => {
                    if dtls_error_is_terminal(&error) {
                        if let Some(retry) = self.dtls_retry.as_mut() {
                            retry.attempt.take();
                        }
                        return Err(error.into());
                    }
                    self.fail_dtls_retry(error);
                    Ok(None)
                }
                Err(error) => {
                    self.fail_dtls_retry(format!(
                        "AnyConnect DTLS retry task failed: {error}"
                    ));
                    Ok(None)
                }
            },
            FallbackEvent::Wake => Ok(None),
        }
    }

    pub async fn send_data(
        &mut self,
        payload: &[u8],
    ) -> Result<(), AnyConnectDataChannelError> {
        if let Some(dtls) = self.dtls.as_mut()
            && let Err(error) = dtls.send_data(payload).await
        {
            self.disable_dtls(error).await;
        }
        if self.dtls.is_some() {
            return Ok(());
        }
        self.cstp.write_data_packet(payload).await?;
        Ok(())
    }

    pub async fn receive_event(
        &mut self,
    ) -> Result<AnyConnectDataChannelEvent, AnyConnectDataChannelError> {
        enum Received {
            Cstp(Result<Option<Vec<u8>>, CstpError>),
            Dtls(Result<Vec<u8>, AnyConnectDtlsChannelError>),
        }

        let Some(dtls) = self.dtls.as_mut() else {
            if let Some(packet) =
                self.receive_cstp_while_retrying_dtls().await?
            {
                return Ok(AnyConnectDataChannelEvent::Data(packet));
            }
            return Ok(AnyConnectDataChannelEvent::TransportStateChanged);
        };
        let received = tokio::select! {
            packet = self.cstp.read_data_packet() => Received::Cstp(packet),
            packet = dtls.receive_data() => Received::Dtls(packet),
        };
        match received {
            Received::Cstp(Ok(Some(packet))) | Received::Dtls(Ok(packet)) => {
                Ok(AnyConnectDataChannelEvent::Data(packet))
            }
            Received::Cstp(Ok(None)) => {
                Err(AnyConnectDataChannelError::CstpClosed)
            }
            Received::Cstp(Err(error)) => Err(error.into()),
            Received::Dtls(Err(error))
                if dtls_error_requires_tunnel_reconnect(&error) =>
            {
                Err(error.into())
            }
            Received::Dtls(Err(error)) => {
                self.disable_dtls(error).await;
                Ok(AnyConnectDataChannelEvent::TransportStateChanged)
            }
        }
    }

    pub async fn receive_data(
        &mut self,
    ) -> Result<Vec<u8>, AnyConnectDataChannelError> {
        loop {
            match self.receive_event().await? {
                AnyConnectDataChannelEvent::Data(packet) => return Ok(packet),
                AnyConnectDataChannelEvent::TransportStateChanged => {}
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), AnyConnectDataChannelError> {
        if let Some(retry) = self.dtls_retry.as_mut() {
            retry.cancel();
        }
        let dtls_error = if let Some(dtls) = self.dtls.take() {
            dtls.close().await.err()
        } else {
            None
        };
        let cstp_result = self.cstp.close().await;
        if let Some(error) = dtls_error {
            return Err(error.into());
        }
        cstp_result?;
        Ok(())
    }

    async fn disable_dtls(&mut self, error: AnyConnectDtlsChannelError) {
        let immediate = matches!(
            error,
            AnyConnectDtlsChannelError::Rekey(CstpRekeyMethod::Tls)
        );
        self.last_dtls_error = Some(error.to_string());
        if let Some(dtls) = self.dtls.take() {
            let _ = dtls.close().await;
        }
        if let Some(retry) = self.dtls_retry.as_mut() {
            retry.schedule(immediate);
        }
    }
}

impl Drop for AnyConnectDataChannel {
    fn drop(&mut self) {
        if let Some(retry) = self.dtls_retry.as_mut() {
            retry.cancel();
        }
    }
}

fn dtls_error_requires_tunnel_reconnect(
    error: &AnyConnectDtlsChannelError,
) -> bool {
    matches!(
        error,
        AnyConnectDtlsChannelError::Rekey(CstpRekeyMethod::NewTunnel)
    )
}

fn dtls_error_is_terminal(error: &AnyConnectDtlsChannelError) -> bool {
    match error {
        AnyConnectDtlsChannelError::MissingPsk => true,
        AnyConnectDtlsChannelError::LegacyConnect(error) => match error {
            LegacyDtlsConnectError::InvalidSessionId(_)
            | LegacyDtlsConnectError::InvalidMasterSecret(_) => true,
            LegacyDtlsConnectError::Record(error) => {
                legacy_dtls_error_is_terminal(error)
            }
            _ => false,
        },
        AnyConnectDtlsChannelError::Dtls12Connect(error) => match error {
            Dtls12ConnectError::InvalidSessionId(_)
            | Dtls12ConnectError::InvalidMasterSecret(_) => true,
            Dtls12ConnectError::Record(error) => {
                dtls12_error_is_terminal(error)
            }
            _ => false,
        },
        AnyConnectDtlsChannelError::PskConnect(error) => match error {
            AnyConnectPskDtlsError::WrongNegotiation(_)
            | AnyConnectPskDtlsError::AppIdTooLong(_)
            | AnyConnectPskDtlsError::AppIdUnsupported
            | AnyConnectPskDtlsError::UnsupportedCipher(_) => true,
            AnyConnectPskDtlsError::Record(error) => {
                dtls12_error_is_terminal(error)
            }
            AnyConnectPskDtlsError::Channel(Dtls12ChannelError::Record(
                error,
            )) => dtls12_error_is_terminal(error),
            _ => false,
        },
        AnyConnectDtlsChannelError::LegacyChannel(
            LegacyDtlsChannelError::Record(error),
        ) => legacy_dtls_error_is_terminal(error),
        AnyConnectDtlsChannelError::Dtls12Channel(
            Dtls12ChannelError::Record(error),
        ) => dtls12_error_is_terminal(error),
        AnyConnectDtlsChannelError::Cstp(CstpError::Protocol(message)) => {
            message == "received compressed DTLS packet without negotiation"
        }
        _ => false,
    }
}

fn legacy_dtls_error_is_terminal(error: &LegacyDtlsError) -> bool {
    matches!(
        error,
        LegacyDtlsError::UnsupportedCipher(_)
            | LegacyDtlsError::DeprecatedCipher(_)
    )
}

fn dtls12_error_is_terminal(error: &Dtls12Error) -> bool {
    matches!(
        error,
        Dtls12Error::UnsupportedCipher(_) | Dtls12Error::RequiresDtls12(_)
    )
}

fn apply_detected_dtls_mtu(
    negotiated: &mut CstpNegotiatedState,
    negotiation: &mut CstpDtlsNegotiation,
    detected: Option<usize>,
) {
    let Some(detected) = detected.and_then(|mtu| u32::try_from(mtu).ok())
    else {
        return;
    };
    if detected == 0 || detected >= negotiated.configuration.mtu {
        return;
    }
    negotiated.configuration.mtu = detected;
    negotiation.mtu = detected;
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use tokio::io::{AsyncReadExt as _, duplex};

    use super::*;
    use crate::{
        adapter::{DialFuture, Dialer, PacketConnection, PacketFuture, Stream},
        common::network::SocksAddr,
        option::DirectOutboundOptions,
        protocol::{direct::DirectOutbound, openconnect::write_cstp_packet},
    };

    struct UnusedPacket;

    struct FailingDialer;

    impl Dialer for FailingDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "mock transport unavailable",
                ))
            })
        }
    }

    impl PacketConnection for UnusedPacket {
        fn send_to<'a>(
            &'a self,
            _data: &'a [u8],
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, usize> {
            Box::pin(std::future::pending())
        }

        fn recv_from<'a>(
            &'a self,
            _data: &'a mut [u8],
        ) -> PacketFuture<'a, (usize, SocksAddr)> {
            Box::pin(std::future::pending())
        }
    }

    fn negotiation(compression: CstpCompression) -> CstpDtlsNegotiation {
        CstpDtlsNegotiation {
            host: "127.0.0.1".into(),
            port: 443,
            cipher_suite: "PSK-NEGOTIATE".into(),
            dtls12: true,
            session_id: Vec::new(),
            app_id: vec![1],
            master_secret: Vec::new(),
            mtu: 1406,
            compression,
            dpd: Duration::ZERO,
            keepalive: Duration::ZERO,
            rekey: Duration::ZERO,
            rekey_method: CstpRekeyMethod::None,
            allow_insecure_crypto: false,
        }
    }

    #[test]
    fn packet_codec_round_trips_stateless_compression_and_control() {
        let mut channel = codec_only(CstpCompression::Lzs);
        let mut payload = vec![b'A'; 800];
        payload[0] = 0x45;
        let encoded = channel.encode_data(&payload).unwrap();
        assert_eq!(encoded[0], CstpPacketType::Compressed.wire_value());
        assert_eq!(
            channel.decode_packet(&encoded).unwrap().unwrap(),
            CstpPacket {
                packet_type: CstpPacketType::Data,
                payload,
            }
        );
        assert_eq!(
            channel.decode_packet(&[3]).unwrap().unwrap().packet_type,
            CstpPacketType::DpdRequest
        );
    }

    #[test]
    fn packet_codec_enforces_mtu_and_compression_negotiation() {
        let mut channel = codec_only(CstpCompression::None);
        assert!(channel.encode_data(&vec![0; 1407]).is_err());
        assert!(channel.decode_packet(&[8, 1, 2, 3]).is_err());
        assert!(channel.decode_packet(&[]).is_err());
    }

    #[test]
    fn packet_codec_round_trips_all_negotiated_compression_modes() {
        for compression in [
            CstpCompression::OcLz4,
            CstpCompression::Lzs,
            CstpCompression::Deflate,
        ] {
            let mut channel = codec_only(compression);
            let mut payload = vec![0x5a; 1_024];
            payload[0] = 0x45;
            payload[2..4].copy_from_slice(&1_024u16.to_be_bytes());
            let encoded = channel.encode_data(&payload).unwrap();
            assert_eq!(encoded[0], CstpPacketType::Compressed.wire_value());
            assert_eq!(
                channel.decode_packet(&encoded).unwrap().unwrap(),
                CstpPacket {
                    packet_type: CstpPacketType::Data,
                    payload,
                },
                "failed {compression:?} round trip"
            );
        }
    }

    #[tokio::test]
    async fn retryable_dtls_failure_falls_back_to_live_cstp_channel() {
        let (client, mut peer) = duplex(4_096);
        let stream: Stream = Box::new(client);
        let session = CstpSession::start(
            stream,
            super::super::CstpSessionOptions {
                mtu: 1_406,
                compression: CstpCompression::None,
                ..Default::default()
            },
        )
        .unwrap();
        let connection = AnyConnectCstpConnection {
            negotiated: negotiated_state(),
            dtls: Some(negotiation(CstpCompression::None)),
            dtls_psk: Some(AnyConnectDtlsPsk::from_bytes([7; 32])),
            session,
        };
        let dialer: Arc<dyn Dialer> = Arc::new(FailingDialer);
        let mut channel = AnyConnectDataChannel::establish(
            dialer,
            connection,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!channel.dtls_active());
        assert!(
            channel
                .last_dtls_error()
                .unwrap()
                .contains("UDP is not supported")
        );

        let outgoing = [0x45, 0, 0, 4];
        channel.send_data(&outgoing).await.unwrap();
        let mut frame = [0_u8; 12];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..4], b"STF\x01");
        assert_eq!(&frame[4..6], &4_u16.to_be_bytes());
        assert_eq!(frame[6], CstpPacketType::Data.wire_value());
        assert_eq!(&frame[8..], &outgoing);

        let incoming = [0x60, 0, 0, 0, 0, 0];
        write_cstp_packet(&mut peer, CstpPacketType::Data, &incoming)
            .await
            .unwrap();
        assert_eq!(channel.receive_data().await.unwrap(), incoming);

        channel.dtls_retry.as_mut().unwrap().next_attempt = Instant::now();
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(1),
                channel.receive_event()
            )
            .await
            .unwrap()
            .unwrap(),
            AnyConnectDataChannelEvent::TransportStateChanged
        ));
        assert!(!channel.dtls_active());
        assert!(
            channel
                .last_dtls_error()
                .unwrap()
                .contains("UDP is not supported")
        );
    }

    #[tokio::test]
    async fn protocol_unsupported_missing_psk_is_terminal() {
        let (client, _peer) = duplex(4_096);
        let session = CstpSession::start(
            Box::new(client),
            super::super::CstpSessionOptions {
                mtu: 1_406,
                compression: CstpCompression::None,
                ..Default::default()
            },
        )
        .unwrap();
        let result = AnyConnectDataChannel::establish(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            AnyConnectCstpConnection {
                negotiated: negotiated_state(),
                dtls: Some(negotiation(CstpCompression::None)),
                dtls_psk: None,
                session,
            },
            &CancellationToken::new(),
        )
        .await;
        let Err(error) = result else {
            panic!("missing PSK unexpectedly established AnyConnect DTLS")
        };
        assert!(matches!(
            error,
            AnyConnectDataChannelError::Dtls(
                AnyConnectDtlsChannelError::MissingPsk
            )
        ));
    }

    #[test]
    fn detected_dtls_mtu_only_lowers_published_tunnel_configuration() {
        let mut negotiated = negotiated_state();
        let mut dtls = negotiation(CstpCompression::None);

        apply_detected_dtls_mtu(&mut negotiated, &mut dtls, Some(1300));
        assert_eq!(negotiated.configuration.mtu, 1300);
        assert_eq!(dtls.mtu, 1300);

        apply_detected_dtls_mtu(&mut negotiated, &mut dtls, Some(1350));
        assert_eq!(negotiated.configuration.mtu, 1300);
        assert_eq!(dtls.mtu, 1300);

        apply_detected_dtls_mtu(&mut negotiated, &mut dtls, None);
        assert_eq!(negotiated.configuration.mtu, 1300);
    }

    #[test]
    fn only_new_tunnel_dtls_rekey_restarts_the_cstp_tunnel() {
        assert!(dtls_error_requires_tunnel_reconnect(
            &AnyConnectDtlsChannelError::Rekey(CstpRekeyMethod::NewTunnel)
        ));
        assert!(!dtls_error_requires_tunnel_reconnect(
            &AnyConnectDtlsChannelError::Rekey(CstpRekeyMethod::Tls)
        ));
        assert!(dtls_error_is_terminal(
            &AnyConnectDtlsChannelError::MissingPsk
        ));
        assert!(dtls_error_is_terminal(
            &AnyConnectDtlsChannelError::LegacyConnect(
                LegacyDtlsConnectError::Record(
                    LegacyDtlsError::DeprecatedCipher("DES-CBC-SHA".into())
                )
            )
        ));
        assert!(dtls_error_is_terminal(
            &AnyConnectDtlsChannelError::Dtls12Connect(
                Dtls12ConnectError::InvalidSessionId(3)
            )
        ));
        assert!(!dtls_error_is_terminal(
            &AnyConnectDtlsChannelError::DeadPeer
        ));
        assert!(!dtls_error_requires_tunnel_reconnect(
            &AnyConnectDtlsChannelError::PeerClosed(CstpPacketType::Disconnect)
        ));
    }

    #[test]
    fn dtls_retry_backoff_resets_caps_and_ssl_rekey_is_immediate() {
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let cancellation = CancellationToken::new();
        let mut retry = AnyConnectDtlsRetryState::new(
            dialer,
            negotiation(CstpCompression::None),
            None,
            576,
            &cancellation,
        );

        retry.schedule(false);
        assert_eq!(retry.retry_delay, Duration::from_secs(2));
        for _ in 0..10 {
            retry.schedule(false);
        }
        assert_eq!(retry.retry_delay, DTLS_RETRY_MAXIMUM_BACKOFF);

        retry.schedule(true);
        assert_eq!(retry.retry_delay, DTLS_RETRY_INITIAL_BACKOFF);
        assert!(retry.next_attempt <= Instant::now());

        let updated = negotiation(CstpCompression::Deflate);
        retry.restored(updated.clone());
        assert_eq!(retry.negotiation, updated);
        assert_eq!(retry.retry_delay, DTLS_RETRY_INITIAL_BACKOFF);
    }

    fn negotiated_state() -> CstpNegotiatedState {
        CstpNegotiatedState {
            configuration: super::super::TunnelConfiguration {
                mtu: 1_406,
                remote_address: Some(IpAddr::from([127, 0, 0, 1])),
                addresses: vec!["10.0.0.2/24".parse().unwrap()],
                routes: Vec::new(),
                excluded_routes: Vec::new(),
                dns: Vec::new(),
                nbns: Vec::new(),
                search_domains: Vec::new(),
                split_dns: Vec::new(),
                split_dns_rules: Vec::new(),
                proxy_auto_config_url: String::new(),
                banner: String::new(),
                tunnel_all_dns: false,
                client_bypass_protocol: false,
                idle_timeout: Duration::ZERO,
                authentication_expiration: None,
            },
            dynamic_dns: false,
            dpd: Duration::ZERO,
            keepalive: Duration::ZERO,
            rekey: Duration::ZERO,
            rekey_method: CstpRekeyMethod::None,
            compression: CstpCompression::None,
        }
    }

    fn codec_only(compression: CstpCompression) -> AnyConnectDtlsChannel {
        let negotiation = negotiation(compression);
        let packet = Box::new(UnusedPacket);
        let suite =
            super::super::LegacyDtlsSuite::from_name("AES128-SHA", false)
                .unwrap();
        let keys = super::super::derive_legacy_dtls_keys(
            &suite, &[0; 48], &[1; 32], &[2; 32],
        );
        AnyConnectDtlsChannel::new(
            AnyConnectDtlsTransport::Legacy(LegacyDtlsSession::new(
                packet,
                crate::common::network::SocksAddr::new("127.0.0.1", 443),
                suite,
                keys,
                1406,
                true,
                false,
                Vec::new(),
                Vec::new(),
            )),
            &negotiation,
        )
    }
}
