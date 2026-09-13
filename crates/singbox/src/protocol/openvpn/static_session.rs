use std::{
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::{
    CompressionError, DataChannelFraming, MssClamp,
    OPENVPN_DATA_CHANNEL_PING_PAYLOAD, OpenVpnDataCodec, OpenVpnDataCodecError,
    OpenVpnPacketTransport, StaticKeyDataCodec, calculate_data_payload_budget,
    calculate_mss_clamp, openvpn_outer_transport_overhead,
};

/// Runtime options for OpenVPN's legacy pre-shared `--secret` data link.
pub struct OpenVpnStaticDataSessionOptions {
    pub static_key_material: Vec<u8>,
    pub key_direction: i8,
    pub cipher: String,
    pub auth: String,
    pub replay_window_size: u32,
    pub replay_window_time: Duration,
    pub framing: Option<DataChannelFraming>,
    /// Complete on-wire packet size requested by `--fragment`.
    pub fragment: u32,
    pub mss_fix: u32,
    pub mss_fix_mode: String,
    pub transport_network: String,
    pub remote_ip: Option<IpAddr>,
    pub ping_interval: Duration,
    pub ping_restart: Duration,
}

/// A fully usable OpenVPN static-key data link, independent of a system TUN.
///
/// Static mode has no reliable control channel or OpenVPN opcode header: each
/// packet transport frame is the CBC/HMAC protected data payload itself.
pub struct OpenVpnStaticDataSession {
    transport: Arc<dyn OpenVpnPacketTransport>,
    codec: StaticKeyDataCodec,
    framing: Option<DataChannelFraming>,
    next_packet_id: AtomicU32,
    fragment_size: usize,
    mss_clamp: MssClamp,
    ping_interval: Duration,
    ping_restart: Duration,
    activity: Mutex<StaticSessionActivity>,
    cancellation: CancellationToken,
}

#[derive(Debug, Clone, Copy)]
struct StaticSessionActivity {
    inbound: Instant,
    outbound: Instant,
}

impl OpenVpnStaticDataSession {
    pub fn new(
        transport: Arc<dyn OpenVpnPacketTransport>,
        options: OpenVpnStaticDataSessionOptions,
    ) -> Result<Self, StaticDataSessionError> {
        let codec = StaticKeyDataCodec::new(
            &options.static_key_material,
            options.key_direction,
            &options.cipher,
            &options.auth,
            options.replay_window_size,
            options.replay_window_time,
        )?;
        let packet_header_size = 0;
        let fragment_size = if options.fragment == 0 {
            0
        } else {
            calculate_data_payload_budget(
                options.fragment as isize,
                &codec,
                packet_header_size,
                4,
            )
            .try_into()
            .map_err(|_| StaticDataSessionError::FragmentBudget)?
        };
        let mss_clamp = calculate_mss_clamp(
            options.mss_fix,
            &options.mss_fix_mode,
            options.framing.as_ref(),
            &codec,
            packet_header_size,
            openvpn_outer_transport_overhead(
                &options.transport_network,
                options.remote_ip,
            ),
        );
        let now = Instant::now();
        Ok(Self {
            transport,
            codec,
            framing: options.framing,
            next_packet_id: AtomicU32::new(1),
            fragment_size,
            mss_clamp,
            ping_interval: options.ping_interval,
            ping_restart: options.ping_restart,
            activity: Mutex::new(StaticSessionActivity {
                inbound: now,
                outbound: now,
            }),
            cancellation: CancellationToken::new(),
        })
    }

    pub fn close(&self) {
        self.cancellation.cancel();
    }

    pub fn connection_oriented(&self) -> bool {
        self.transport.connection_oriented()
    }

    pub async fn write_data_packet(
        &self,
        payload: &[u8],
    ) -> Result<usize, StaticDataSessionError> {
        self.write_payload(payload, true).await
    }

    pub async fn send_ping(&self) -> Result<usize, StaticDataSessionError> {
        self.write_payload(&OPENVPN_DATA_CHANNEL_PING_PAYLOAD, false)
            .await
    }

    pub async fn read_data_packet(
        &self,
    ) -> Result<Vec<u8>, StaticDataSessionError> {
        loop {
            self.check_keepalive().await?;
            let (raw, source) = tokio::select! {
                _ = self.cancellation.cancelled() => {
                    return Err(StaticDataSessionError::Closed);
                }
                result = self.transport.read_packet_with_source() => result?,
                _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
            };
            let decoded = match self.codec.decode(&[], &raw) {
                Ok((_, decoded)) => decoded,
                Err(_) if !self.transport.connection_oriented() => continue,
                Err(error) => return Err(error.into()),
            };
            if !self
                .transport
                .accept_authenticated_packet_source(source)
                .await?
            {
                continue;
            }
            self.activity.lock().inbound = Instant::now();
            let payload = match &self.framing {
                Some(framing) => match framing.decode(&decoded) {
                    Ok(Some(payload)) => payload,
                    Ok(None) | Err(_) => continue,
                },
                None => decoded,
            };
            if payload.is_empty()
                || payload == OPENVPN_DATA_CHANNEL_PING_PAYLOAD
            {
                continue;
            }
            return Ok(self.mss_clamp.apply(&payload));
        }
    }

    async fn check_keepalive(&self) -> Result<(), StaticDataSessionError> {
        let now = Instant::now();
        let activity = *self.activity.lock();
        if !self.ping_restart.is_zero()
            && now.duration_since(activity.inbound) >= self.ping_restart
        {
            return Err(StaticDataSessionError::PingRestartTimeout);
        }
        if !self.ping_interval.is_zero()
            && now.duration_since(activity.outbound) >= self.ping_interval
        {
            self.send_ping().await?;
        }
        Ok(())
    }

    async fn write_payload(
        &self,
        payload: &[u8],
        clamp_mss: bool,
    ) -> Result<usize, StaticDataSessionError> {
        if self.cancellation.is_cancelled() {
            return Err(StaticDataSessionError::Closed);
        }
        let payload = if clamp_mss {
            self.mss_clamp.apply(payload)
        } else {
            payload.to_vec()
        };
        let payloads = match &self.framing {
            Some(framing) => match framing.encode(&payload, self.fragment_size)
            {
                Ok(payloads) => payloads,
                // OpenVPN's fragment/compression path drops only the packet
                // that could not be framed; the static session stays alive.
                Err(_) => return Ok(0),
            },
            None => vec![payload],
        };
        for payload in &payloads {
            let packet_id = self.next_packet_id()?;
            let encoded = self.codec.encode(packet_id, &[], payload)?;
            self.transport.write_packet(&encoded).await?;
        }
        if !payloads.is_empty() {
            self.activity.lock().outbound = Instant::now();
        }
        Ok(payloads.len())
    }

    fn next_packet_id(&self) -> Result<u32, StaticDataSessionError> {
        self.next_packet_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |packet_id| {
                packet_id.checked_add(1)
            })
            .map_err(|_| StaticDataSessionError::PacketIdExpired)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StaticDataSessionError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Codec(#[from] OpenVpnDataCodecError),
    #[error(transparent)]
    Framing(#[from] CompressionError),
    #[error("OpenVPN static-key fragment packet size cannot carry data")]
    FragmentBudget,
    #[error("OpenVPN static-key data channel closed")]
    Closed,
    #[error("OpenVPN static-key ping-restart timeout")]
    PingRestartTimeout,
    #[error("OpenVPN static-key packet id expired")]
    PacketIdExpired,
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc};

    use async_trait::async_trait;
    use tokio::sync::Mutex as AsyncMutex;

    use super::*;

    struct MemoryTransport {
        incoming: AsyncMutex<VecDeque<Vec<u8>>>,
        peer: AsyncMutex<Option<Arc<MemoryTransport>>>,
        connection_oriented: bool,
    }

    impl MemoryTransport {
        fn new(connection_oriented: bool) -> Arc<Self> {
            Arc::new(Self {
                incoming: AsyncMutex::new(VecDeque::new()),
                peer: AsyncMutex::new(None),
                connection_oriented,
            })
        }
    }

    #[async_trait]
    impl OpenVpnPacketTransport for MemoryTransport {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            loop {
                if let Some(packet) = self.incoming.lock().await.pop_front() {
                    return Ok(packet);
                }
                tokio::task::yield_now().await;
            }
        }

        async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.peer
                .lock()
                .await
                .as_ref()
                .unwrap()
                .incoming
                .lock()
                .await
                .push_back(packet.to_vec());
            Ok(())
        }

        fn connection_oriented(&self) -> bool {
            self.connection_oriented
        }
    }

    fn options(direction: i8) -> OpenVpnStaticDataSessionOptions {
        OpenVpnStaticDataSessionOptions {
            static_key_material: (0..=u8::MAX).collect(),
            key_direction: direction,
            cipher: "AES-256-CBC".into(),
            auth: "SHA256".into(),
            replay_window_size: 64,
            replay_window_time: Duration::from_secs(15),
            framing: None,
            fragment: 0,
            mss_fix: 0,
            mss_fix_mode: String::new(),
            transport_network: "udp".into(),
            remote_ip: None,
            ping_interval: Duration::ZERO,
            ping_restart: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn static_sessions_exchange_raw_protected_payloads() {
        let client_transport = MemoryTransport::new(false);
        let server_transport = MemoryTransport::new(false);
        *client_transport.peer.lock().await = Some(server_transport.clone());
        *server_transport.peer.lock().await = Some(client_transport.clone());
        let client =
            OpenVpnStaticDataSession::new(client_transport, options(1))
                .unwrap();
        let server =
            OpenVpnStaticDataSession::new(server_transport, options(0))
                .unwrap();

        assert_eq!(
            client.write_data_packet(b"client packet").await.unwrap(),
            1
        );
        assert_eq!(server.read_data_packet().await.unwrap(), b"client packet");
        assert_eq!(
            server.write_data_packet(b"server packet").await.unwrap(),
            1
        );
        assert_eq!(client.read_data_packet().await.unwrap(), b"server packet");
    }

    #[tokio::test]
    async fn udp_drops_bad_packet_but_tcp_fails() {
        let udp = MemoryTransport::new(false);
        udp.incoming.lock().await.push_back(vec![1, 2, 3]);
        let udp_session = Arc::new(
            OpenVpnStaticDataSession::new(udp.clone(), options(1)).unwrap(),
        );
        let read = tokio::spawn({
            let session = udp_session.clone();
            async move { session.read_data_packet().await }
        });
        tokio::task::yield_now().await;
        udp_session.close();
        assert!(matches!(
            read.await.unwrap(),
            Err(StaticDataSessionError::Closed)
        ));

        let tcp = MemoryTransport::new(true);
        tcp.incoming.lock().await.push_back(vec![1, 2, 3]);
        let tcp_session =
            OpenVpnStaticDataSession::new(tcp, options(1)).unwrap();
        assert!(matches!(
            tcp_session.read_data_packet().await,
            Err(StaticDataSessionError::Codec(_))
        ));
    }
}
