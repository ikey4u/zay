use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use parking_lot::{Mutex, RwLock};
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use super::{
    DataKeyRingError, DataPlaneError, DataRenegotiationBudget,
    IncomingControlEvent, IncomingDataEvent,
    NegotiatedOpenVpnClientRenegotiation, NegotiatedOpenVpnClientSession,
    NegotiatedOpenVpnServerRenegotiation, NegotiatedOpenVpnServerSession,
    OPENVPN_DATA_CHANNEL_PING_PAYLOAD, OPENVPN_TLS_KEY_SCAN_SIZE,
    OpenVpnDataKeyRing, OpenVpnPacketTransport, OpenVpnTlsRenegotiationSession,
    OpenVpnTlsSession, Packet, RenegotiationDirection, TlsDataPlane,
    openvpn_data_channel_exit_notify_payload,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataWriteOutcome {
    pub packet_count: usize,
    pub renegotiation_required: bool,
}

/// A negotiated OpenVPN data link independent of a platform TUN. Multiple
/// tasks may concurrently read and write IP packets; the reliable TLS driver
/// remains owned until `shutdown`.
pub struct OpenVpnActiveDataSession {
    tls_session: OpenVpnTlsSession,
    data_planes: RwLock<OpenVpnDataKeyRing<Arc<TlsDataPlane>>>,
    transport: Arc<dyn OpenVpnPacketTransport>,
    incoming: AsyncMutex<mpsc::Receiver<Packet>>,
    resets: AsyncMutex<mpsc::Receiver<IncomingControlEvent>>,
    renegotiation_budget: Mutex<DataRenegotiationBudget>,
    renegotiation_requested: AtomicBool,
    renegotiations: Mutex<Vec<OpenVpnTlsRenegotiationSession>>,
    fragment_size: usize,
}

impl OpenVpnActiveDataSession {
    pub fn from_client(
        transport: Arc<dyn OpenVpnPacketTransport>,
        mut negotiated: NegotiatedOpenVpnClientSession,
        fragment_size: usize,
    ) -> Self {
        let incoming = negotiated.session.control.take_data_packets();
        let resets = negotiated.session.control.take_resets();
        let data_plane = Arc::new(negotiated.data_plane);
        let data_planes = OpenVpnDataKeyRing::new(
            data_plane.session().current_key_id(),
            data_plane.session().clone(),
            data_plane,
        );
        Self {
            tls_session: negotiated.session,
            data_planes: RwLock::new(data_planes),
            transport,
            incoming: AsyncMutex::new(incoming),
            resets: AsyncMutex::new(resets),
            renegotiation_budget: Mutex::new(negotiated.renegotiation_budget),
            renegotiation_requested: AtomicBool::new(false),
            renegotiations: Mutex::new(Vec::new()),
            fragment_size,
        }
    }

    pub fn from_server(
        transport: Arc<dyn OpenVpnPacketTransport>,
        mut negotiated: NegotiatedOpenVpnServerSession,
        fragment_size: usize,
    ) -> Self {
        let incoming = negotiated.session.control.take_data_packets();
        let resets = negotiated.session.control.take_resets();
        let data_plane = Arc::new(negotiated.data_plane);
        let data_planes = OpenVpnDataKeyRing::new(
            data_plane.session().current_key_id(),
            data_plane.session().clone(),
            data_plane,
        );
        Self {
            tls_session: negotiated.session,
            data_planes: RwLock::new(data_planes),
            transport,
            incoming: AsyncMutex::new(incoming),
            resets: AsyncMutex::new(resets),
            renegotiation_budget: Mutex::new(negotiated.renegotiation_budget),
            renegotiation_requested: AtomicBool::new(false),
            renegotiations: Mutex::new(Vec::new()),
            fragment_size,
        }
    }

    pub fn tls_session(&self) -> &OpenVpnTlsSession {
        &self.tls_session
    }

    pub fn close(&self) {
        self.tls_session.control.close();
    }

    pub fn data_plane(&self) -> Arc<TlsDataPlane> {
        self.data_planes
            .read()
            .current_send()
            .expect("an active OpenVPN data key always exists")
            .value
            .clone()
    }

    /// Stages a newly negotiated key for inbound data before promotion.
    pub fn stage_data_key_state(
        &self,
        sequence: u64,
        data_plane: TlsDataPlane,
        now: Instant,
    ) -> Result<(), DataKeyRingError> {
        let data_plane = Arc::new(data_plane);
        self.data_planes.write().stage(
            data_plane.session().current_key_id(),
            sequence,
            data_plane.session().clone(),
            data_plane,
            now,
        )
    }

    /// Promotes a staged key for outbound data and leaves the prior key
    /// receive-capable for the OpenVPN transition window.
    pub fn promote_data_key_state(
        &self,
        key_id: u8,
        sequence: u64,
        now: Instant,
    ) -> Result<bool, DataKeyRingError> {
        let promoted =
            self.data_planes.write().promote(key_id, sequence, now)?;
        if promoted {
            self.renegotiation_budget.lock().reset(key_id);
        }
        Ok(promoted)
    }

    pub async fn install_client_renegotiation(
        &self,
        sequence: u64,
        negotiated: NegotiatedOpenVpnClientRenegotiation,
        now: Instant,
    ) -> Result<bool, ActiveDataSessionError> {
        self.install_renegotiation(
            sequence,
            negotiated.session,
            negotiated.data_plane,
            now,
        )
        .await
    }

    pub async fn install_server_renegotiation(
        &self,
        sequence: u64,
        negotiated: NegotiatedOpenVpnServerRenegotiation,
        now: Instant,
    ) -> Result<bool, ActiveDataSessionError> {
        self.install_renegotiation(
            sequence,
            negotiated.session,
            negotiated.data_plane,
            now,
        )
        .await
    }

    /// Returns and clears a pending soft-reset request caused by transfer,
    /// packet-ID, or AEAD usage limits.
    pub fn take_renegotiation_request(&self) -> bool {
        self.renegotiation_requested.swap(false, Ordering::AcqRel)
    }

    pub async fn next_reset_event(
        &self,
    ) -> Result<IncomingControlEvent, ActiveDataSessionError> {
        self.resets
            .lock()
            .await
            .recv()
            .await
            .ok_or(ActiveDataSessionError::Closed)
    }

    pub async fn write_data_packet(
        &self,
        payload: &[u8],
    ) -> Result<DataWriteOutcome, ActiveDataSessionError> {
        self.write_data_payload(payload, true).await
    }

    pub async fn send_ping(
        &self,
    ) -> Result<DataWriteOutcome, ActiveDataSessionError> {
        self.write_data_payload(&OPENVPN_DATA_CHANNEL_PING_PAYLOAD, false)
            .await
    }

    pub async fn send_exit_notification(
        &self,
    ) -> Result<DataWriteOutcome, ActiveDataSessionError> {
        self.write_data_payload(
            &openvpn_data_channel_exit_notify_payload(),
            false,
        )
        .await
    }

    pub async fn read_data_packet(
        &self,
    ) -> Result<Vec<u8>, ActiveDataSessionError> {
        loop {
            let packet = self
                .incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or(ActiveDataSessionError::Closed)?;
            let Some(data_plane) = self
                .data_planes
                .write()
                .select_receive(packet.key_id, Instant::now())
                .map(|entry| entry.value.clone())
            else {
                // tls_pre_decrypt discards packets for unavailable key states
                // on both datagram and connection-oriented transports.
                continue;
            };
            let decoded = match data_plane.decode_packet_with_metadata(&packet)
            {
                Ok(decoded) => decoded,
                Err(
                    DataPlaneError::WrongKeyState | DataPlaneError::WrongPeerId,
                )
                | Err(DataPlaneError::Framing(_)) => continue,
                Err(_) if !self.transport.connection_oriented() => continue,
                Err(error) => return Err(error.into()),
            };
            if !self
                .transport
                .accept_authenticated_packet_source(packet.link_source())
                .await?
            {
                continue;
            }
            let renegotiation_required = {
                let mut budget = self.renegotiation_budget.lock();
                budget.consume_transfer(decoded.key_id, decoded.accounted_bytes)
                    | budget.consume_usage(
                        decoded.key_id,
                        RenegotiationDirection::Receive,
                        decoded.packet_id,
                        decoded.aead_plaintext_bytes,
                    )
            };
            if renegotiation_required {
                self.renegotiation_requested.store(true, Ordering::Release);
            }
            match decoded.event {
                IncomingDataEvent::Payload(payload) => return Ok(payload),
                IncomingDataEvent::OccResponse(response) => {
                    self.write_data_payload(&response, false).await?;
                }
                IncomingDataEvent::Ping
                | IncomingDataEvent::FragmentPending => {}
                IncomingDataEvent::Exit => {
                    return Err(ActiveDataSessionError::PeerExit);
                }
            }
        }
    }

    pub async fn shutdown(self) -> io::Result<()> {
        for renegotiation in self.renegotiations.into_inner() {
            let OpenVpnTlsRenegotiationSession { tls, control, .. } =
                renegotiation;
            drop(tls);
            control.shutdown().await?;
        }
        self.tls_session.control.shutdown().await
    }

    async fn install_renegotiation(
        &self,
        sequence: u64,
        session: OpenVpnTlsRenegotiationSession,
        data_plane: TlsDataPlane,
        now: Instant,
    ) -> Result<bool, ActiveDataSessionError> {
        let key_id = session.session.current_key_id();
        self.stage_data_key_state(sequence, data_plane, now)?;
        self.tls_session
            .control
            .promote_renegotiation_channel(key_id)
            .await?;
        let promoted = self.promote_data_key_state(key_id, sequence, now)?;
        if promoted {
            let retired = {
                let mut sessions = self.renegotiations.lock();
                sessions.push(session);
                (sessions.len() > OPENVPN_TLS_KEY_SCAN_SIZE)
                    .then(|| sessions.remove(0))
            };
            if let Some(retired) = retired {
                let OpenVpnTlsRenegotiationSession { tls, control, .. } =
                    retired;
                drop(tls);
                control.shutdown().await?;
            }
        } else {
            let OpenVpnTlsRenegotiationSession { tls, control, .. } = session;
            drop(tls);
            control.shutdown().await?;
        }
        Ok(promoted)
    }

    async fn write_data_payload(
        &self,
        payload: &[u8],
        _account_application_payload: bool,
    ) -> Result<DataWriteOutcome, ActiveDataSessionError> {
        let data_plane = self.data_plane();
        let packets = data_plane
            .encode_payload_with_metadata(payload, self.fragment_size)?;
        for packet in &packets {
            self.transport.write_packet(&packet.raw_packet).await?;
        }
        let renegotiation_required = {
            let mut budget = self.renegotiation_budget.lock();
            packets.iter().fold(false, |required, packet| {
                required
                    | budget
                        .consume_transfer(packet.key_id, packet.accounted_bytes)
                    | budget.consume_usage(
                        packet.key_id,
                        RenegotiationDirection::Send,
                        packet.packet_id,
                        packet.aead_block_bytes,
                    )
            })
        };
        if renegotiation_required {
            self.renegotiation_requested.store(true, Ordering::Release);
        }
        Ok(DataWriteOutcome {
            packet_count: packets.len(),
            renegotiation_required,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActiveDataSessionError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    DataPlane(#[from] DataPlaneError),
    #[error(transparent)]
    KeyRing(#[from] DataKeyRingError),
    #[error("OpenVPN data channel closed")]
    Closed,
    #[error("OpenVPN peer sent an explicit exit notification")]
    PeerExit,
}
