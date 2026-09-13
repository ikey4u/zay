//! GlobalProtect SSL tunnel (GPST) framing and handshake.

use std::{
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex as SyncMutex;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{
    CstpKeepaliveState, CstpRekeyMethod, CstpTimerAction,
    GLOBALPROTECT_DEFAULT_DPD_INTERVAL, GlobalProtectFailureClass,
    GlobalProtectTunnelOperation, classify_globalprotect_tunnel_http_status,
    filter_globalprotect_opaque_query,
};
use crate::adapter::Stream;

pub const GPST_FRAME_HEADER_SIZE: usize = 16;
pub const GPST_FRAME_MAGIC: u32 = 0x1a2b_3c4d;
pub const GPST_IPV4_ETHERTYPE: u16 = 0x0800;
pub const GPST_IPV6_ETHERTYPE: u16 = 0x86dd;
pub const GPST_START_MARKER: [u8; 12] = *b"START_TUNNEL";
pub const GPST_MAXIMUM_STATUS_LINE: usize = 1024;
pub const GPST_MINIMUM_RECEIVE_BUFFER: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpstPacketKind {
    Keepalive,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpstPacket {
    pub kind: GpstPacketKind,
    pub payload: Vec<u8>,
    /// The little-endian trailer is normally `(1, 0)` for data and `(0, 0)`
    /// for keepalive frames. OpenConnect accepts non-standard values.
    pub trailer: (u32, u32),
}

#[derive(Debug, Error)]
pub enum GpstError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("GPST protocol error: {0}")]
    Protocol(String),
    #[error("GPST endpoint returned HTTP {status} ({class:?})")]
    HttpStatus {
        status: u16,
        class: GlobalProtectFailureClass,
    },
}

/// Build the deliberately headerless GPST GET request.
pub fn build_gpst_request(tunnel_path: &str, opaque_query: &str) -> Vec<u8> {
    let query = filter_globalprotect_opaque_query(
        opaque_query,
        &["user", "authcookie"],
        true,
    );
    format!("GET {tunnel_path}?{query} HTTP/1.1\r\n\r\n").into_bytes()
}

pub fn encode_gpst_keepalive() -> [u8; GPST_FRAME_HEADER_SIZE] {
    let mut frame = [0_u8; GPST_FRAME_HEADER_SIZE];
    frame[..4].copy_from_slice(&GPST_FRAME_MAGIC.to_be_bytes());
    frame
}

pub fn encode_gpst_data(
    payload: &[u8],
    mtu: usize,
) -> Result<Vec<u8>, GpstError> {
    if payload.is_empty() {
        return Err(GpstError::Protocol("data packet is empty".into()));
    }
    if payload.len() > mtu {
        return Err(GpstError::Protocol(format!(
            "data packet exceeds negotiated MTU: {} > {mtu}",
            payload.len()
        )));
    }
    let ether_type = match payload[0] >> 4 {
        4 => GPST_IPV4_ETHERTYPE,
        6 => GPST_IPV6_ETHERTYPE,
        _ => {
            return Err(GpstError::Protocol(
                "data packet has an unknown IP version".into(),
            ));
        }
    };
    let payload_length = u16::try_from(payload.len()).map_err(|_| {
        GpstError::Protocol("data packet exceeds GPST wire length".into())
    })?;
    let mut frame = vec![0; GPST_FRAME_HEADER_SIZE + payload.len()];
    frame[..4].copy_from_slice(&GPST_FRAME_MAGIC.to_be_bytes());
    frame[4..6].copy_from_slice(&ether_type.to_be_bytes());
    frame[6..8].copy_from_slice(&payload_length.to_be_bytes());
    frame[8..12].copy_from_slice(&1_u32.to_le_bytes());
    frame[GPST_FRAME_HEADER_SIZE..].copy_from_slice(payload);
    Ok(frame)
}

pub async fn write_gpst_data<W>(
    writer: &mut W,
    payload: &[u8],
    mtu: usize,
) -> Result<(), GpstError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_gpst_data(payload, mtu)?).await?;
    Ok(())
}

pub async fn write_gpst_keepalive<W>(writer: &mut W) -> Result<(), GpstError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_gpst_keepalive()).await?;
    Ok(())
}

pub async fn read_gpst_packet<R>(
    reader: &mut R,
    negotiated_mtu: usize,
) -> Result<GpstPacket, GpstError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; GPST_FRAME_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    if u32::from_be_bytes(header[..4].try_into().expect("fixed range"))
        != GPST_FRAME_MAGIC
    {
        return Err(GpstError::Protocol("unknown frame magic".into()));
    }
    let ether_type = u16::from_be_bytes([header[4], header[5]]);
    let payload_length =
        usize::from(u16::from_be_bytes([header[6], header[7]]));
    let maximum = negotiated_mtu.max(GPST_MINIMUM_RECEIVE_BUFFER);
    if payload_length > maximum {
        return Err(GpstError::Protocol(format!(
            "frame exceeds receive limit: {payload_length} > {maximum}"
        )));
    }
    let trailer = (
        u32::from_le_bytes(header[8..12].try_into().expect("fixed range")),
        u32::from_le_bytes(header[12..16].try_into().expect("fixed range")),
    );
    let kind = match ether_type {
        0 => GpstPacketKind::Keepalive,
        GPST_IPV4_ETHERTYPE => GpstPacketKind::Ipv4,
        GPST_IPV6_ETHERTYPE => GpstPacketKind::Ipv6,
        value => {
            return Err(GpstError::Protocol(format!(
                "unknown EtherType: {value:x}"
            )));
        }
    };
    let mut payload = vec![0; payload_length];
    reader.read_exact(&mut payload).await?;
    Ok(GpstPacket {
        kind,
        payload,
        trailer,
    })
}

/// Send the GPST request and require either the exact marker or classify the
/// HTTP status returned in its place.
pub async fn establish_gpst<S>(
    stream: &mut S,
    tunnel_path: &str,
    opaque_query: &str,
) -> Result<(), GpstError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&build_gpst_request(tunnel_path, opaque_query))
        .await?;
    stream.flush().await?;
    let mut prefix = [0_u8; GPST_START_MARKER.len()];
    stream.read_exact(&mut prefix).await?;
    if prefix == GPST_START_MARKER {
        return Ok(());
    }
    let status = read_gpst_http_status(stream, &prefix).await?;
    let class = classify_globalprotect_tunnel_http_status(
        status,
        GlobalProtectTunnelOperation::Gpst,
    )
    .unwrap_or(GlobalProtectFailureClass::ProtocolUnsupported);
    Err(GpstError::HttpStatus { status, class })
}

pub async fn read_gpst_http_status<R>(
    reader: &mut R,
    prefix: &[u8],
) -> Result<u16, GpstError>
where
    R: AsyncRead + Unpin,
{
    let mut line = prefix.to_vec();
    while line.len() < GPST_MAXIMUM_STATUS_LINE
        && line.last().copied() != Some(b'\n')
    {
        line.push(reader.read_u8().await?);
    }
    if line.last().copied() != Some(b'\n') {
        return Err(GpstError::Protocol("HTTP status line is too long".into()));
    }
    let line = std::str::from_utf8(&line)
        .map_err(|_| GpstError::Protocol("HTTP status is not UTF-8".into()))?;
    let mut fields = line.split_ascii_whitespace();
    let protocol = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if !protocol.starts_with("HTTP/") {
        return Err(GpstError::Protocol("unexpected tunnel marker".into()));
    }
    let status = status
        .parse::<u16>()
        .ok()
        .filter(|status| (100..=999).contains(status))
        .ok_or_else(|| GpstError::Protocol("invalid HTTP status".into()))?;
    Ok(status)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpstSessionOptions {
    pub mtu: usize,
    pub dpd: Duration,
    pub keepalive: Duration,
    pub queue_length: usize,
}

impl Default for GpstSessionOptions {
    fn default() -> Self {
        Self {
            mtu: 1406,
            dpd: GLOBALPROTECT_DEFAULT_DPD_INTERVAL,
            keepalive: GLOBALPROTECT_DEFAULT_DPD_INTERVAL,
            queue_length: 64,
        }
    }
}

struct GpstActivity {
    origin: Instant,
    keepalive: SyncMutex<CstpKeepaliveState>,
}

impl GpstActivity {
    fn new(options: &GpstSessionOptions) -> Self {
        Self {
            origin: Instant::now(),
            keepalive: SyncMutex::new(CstpKeepaliveState::new(
                options.dpd,
                options.keepalive,
                Duration::ZERO,
                CstpRekeyMethod::None,
            )),
        }
    }

    fn mark_received(&self) {
        self.keepalive.lock().mark_received(self.origin.elapsed());
    }

    fn mark_transmitted(&self) {
        self.keepalive
            .lock()
            .mark_transmitted(self.origin.elapsed());
    }
}

type SharedGpstWriter = Arc<Mutex<Option<WriteHalf<Stream>>>>;

/// Running GPST channel with bounded packet queues and OpenConnect-compatible
/// DPD/keepalive behavior. The TLS handshake and `START_TUNNEL` exchange must
/// be completed before passing the stream to `start`.
pub struct GpstSession {
    writer: SharedGpstWriter,
    incoming: mpsc::Receiver<Result<Vec<u8>, GpstError>>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    mtu: usize,
    activity: Arc<GpstActivity>,
}

impl GpstSession {
    pub fn start(
        stream: Stream,
        options: GpstSessionOptions,
    ) -> Result<Self, GpstError> {
        if options.mtu == 0 || options.mtu > usize::from(u16::MAX) {
            return Err(GpstError::Protocol(format!(
                "invalid session MTU: {}",
                options.mtu
            )));
        }
        let mtu = options.mtu;
        let activity = Arc::new(GpstActivity::new(&options));
        let (reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(Some(writer)));
        let (incoming_tx, incoming) =
            mpsc::channel(options.queue_length.max(1));
        let cancellation = CancellationToken::new();
        let read_task = tokio::spawn(gpst_read_loop(
            reader,
            mtu,
            incoming_tx.clone(),
            activity.clone(),
            cancellation.clone(),
        ));
        let timer_task = tokio::spawn(gpst_timer_loop(
            writer.clone(),
            incoming_tx,
            activity.clone(),
            cancellation.clone(),
        ));
        Ok(Self {
            writer,
            incoming,
            cancellation,
            tasks: vec![read_task, timer_task],
            mtu,
            activity,
        })
    }

    pub async fn write_data_packet(
        &self,
        payload: &[u8],
    ) -> Result<(), GpstError> {
        let frame = encode_gpst_data(payload, self.mtu)?;
        let mut writer = self.writer.lock().await;
        let writer = writer.as_mut().ok_or_else(|| {
            GpstError::Protocol("data channel is not ready".into())
        })?;
        writer.write_all(&frame).await?;
        self.activity.mark_transmitted();
        Ok(())
    }

    pub async fn read_data_packet(
        &mut self,
    ) -> Result<Option<Vec<u8>>, GpstError> {
        match self.incoming.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    pub async fn close(&mut self) -> Result<(), GpstError> {
        self.cancellation.cancel();
        let shutdown = {
            let mut writer = self.writer.lock().await;
            match writer.as_mut() {
                Some(writer) => writer.shutdown().await,
                None => Ok(()),
            }
        };
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.writer.lock().await.take();
        shutdown.map_err(GpstError::Io)
    }
}

impl Drop for GpstSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn gpst_read_loop(
    mut reader: tokio::io::ReadHalf<Stream>,
    mtu: usize,
    incoming: mpsc::Sender<Result<Vec<u8>, GpstError>>,
    activity: Arc<GpstActivity>,
    cancellation: CancellationToken,
) {
    loop {
        let packet = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = read_gpst_packet(&mut reader, mtu) => result,
        };
        let packet = match packet {
            Ok(packet) => packet,
            Err(GpstError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                cancellation.cancel();
                return;
            }
            Err(error) => {
                let _ = incoming.send(Err(error)).await;
                cancellation.cancel();
                return;
            }
        };
        activity.mark_received();
        match packet.kind {
            GpstPacketKind::Keepalive => {}
            GpstPacketKind::Ipv4 | GpstPacketKind::Ipv6 => {
                if incoming.send(Ok(packet.payload)).await.is_err() {
                    cancellation.cancel();
                    return;
                }
            }
        }
    }
}

async fn gpst_timer_loop(
    writer: SharedGpstWriter,
    incoming: mpsc::Sender<Result<Vec<u8>, GpstError>>,
    activity: Arc<GpstActivity>,
    cancellation: CancellationToken,
) {
    loop {
        let delay = {
            let elapsed = activity.origin.elapsed();
            activity.keepalive.lock().next_delay(elapsed)
        };
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        let action = {
            let elapsed = activity.origin.elapsed();
            activity.keepalive.lock().action(elapsed)
        };
        let result = match action {
            CstpTimerAction::Dpd | CstpTimerAction::Keepalive => {
                gpst_write_keepalive(&writer, &activity).await
            }
            CstpTimerAction::DeadPeer => {
                Err(GpstError::Protocol("dead peer detection expired".into()))
            }
            CstpTimerAction::None => continue,
            CstpTimerAction::Rekey => unreachable!("GPST timer has no rekey"),
        };
        if let Err(error) = result {
            let _ = incoming.send(Err(error)).await;
            cancellation.cancel();
            return;
        }
    }
}

async fn gpst_write_keepalive(
    writer: &SharedGpstWriter,
    activity: &GpstActivity,
) -> Result<(), GpstError> {
    let mut writer = writer.lock().await;
    let writer = writer.as_mut().ok_or_else(|| {
        GpstError::Protocol("data channel is not ready".into())
    })?;
    writer.write_all(&encode_gpst_keepalive()).await?;
    activity.mark_transmitted();
    Ok(())
}

/// Validate that a packet delivered by a GPST frame matches its EtherType.
/// The Go implementation accepts the frame trailer but the IP family remains
/// useful for rejecting corrupt data before passing it to the network stack.
pub fn validate_gpst_packet_family(
    packet: &GpstPacket,
) -> Result<(), GpstError> {
    if packet.kind == GpstPacketKind::Keepalive {
        return if packet.payload.is_empty() {
            Ok(())
        } else {
            Err(GpstError::Protocol(
                "keepalive frame contains a payload".into(),
            ))
        };
    }
    let expected = match packet.kind {
        GpstPacketKind::Ipv4 => 4,
        GpstPacketKind::Ipv6 => 6,
        GpstPacketKind::Keepalive => unreachable!(),
    };
    if packet.payload.first().map(|byte| byte >> 4) != Some(expected) {
        return Err(GpstError::Protocol(format!(
            "EtherType does not match IP version {expected}"
        )));
    }
    Ok(())
}

pub fn globalprotect_gateway_socket(
    address: IpAddr,
    port: u16,
) -> Result<std::net::SocketAddr, GpstError> {
    if port == 0 {
        return Err(GpstError::Protocol("gateway port is zero".into()));
    }
    Ok(std::net::SocketAddr::new(address, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_only_forwards_user_and_authcookie_verbatim() {
        assert_eq!(
            build_gpst_request(
                "/ssl-tunnel-connect.sslvpn",
                "portal=p&user=alice%40example&authcookie=a%2fb&preferred-ip=10.0.0.2"
            ),
            b"GET /ssl-tunnel-connect.sslvpn?user=alice%40example&authcookie=a%2fb HTTP/1.1\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn frame_round_trip_preserves_wire_trailer() {
        let payload = [0x45, 0, 0, 20];
        let encoded = encode_gpst_data(&payload, 1400).unwrap();
        assert_eq!(&encoded[..4], &GPST_FRAME_MAGIC.to_be_bytes());
        assert_eq!(&encoded[4..6], &GPST_IPV4_ETHERTYPE.to_be_bytes());
        assert_eq!(&encoded[8..12], &1_u32.to_le_bytes());
        let mut input = encoded.as_slice();
        let packet = read_gpst_packet(&mut input, 1400).await.unwrap();
        assert_eq!(packet.kind, GpstPacketKind::Ipv4);
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.trailer, (1, 0));
        validate_gpst_packet_family(&packet).unwrap();
    }

    #[tokio::test]
    async fn handshake_writes_headerless_request_and_accepts_marker() {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let server_task = tokio::spawn(async move {
            let mut request = vec![0; 1024];
            let read = server.read(&mut request).await.unwrap();
            request.truncate(read);
            server.write_all(&GPST_START_MARKER).await.unwrap();
            request
        });
        establish_gpst(&mut client, "/tunnel", "user=a&x=y&authcookie=b")
            .await
            .unwrap();
        assert_eq!(
            server_task.await.unwrap(),
            b"GET /tunnel?user=a&authcookie=b HTTP/1.1\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn handshake_classifies_http_instead_of_marker() {
        let (mut client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut request = [0; 256];
            let _ = server.read(&mut request).await.unwrap();
            server
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n")
                .await
                .unwrap();
        });
        let error = establish_gpst(&mut client, "/tunnel", "user=a")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GpstError::HttpStatus {
                status: 502,
                class: GlobalProtectFailureClass::SessionRejected
            }
        ));
    }

    #[tokio::test]
    async fn rejects_unknown_magic_ether_type_and_oversized_payload() {
        let mut bad_magic = [0_u8; GPST_FRAME_HEADER_SIZE].as_slice();
        assert!(read_gpst_packet(&mut bad_magic, 1400).await.is_err());

        let mut unknown = encode_gpst_keepalive();
        unknown[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        let mut unknown = unknown.as_slice();
        assert!(read_gpst_packet(&mut unknown, 1400).await.is_err());

        let mut oversized = encode_gpst_keepalive();
        oversized[6..8].copy_from_slice(&20_000_u16.to_be_bytes());
        let mut oversized = oversized.as_slice();
        assert!(read_gpst_packet(&mut oversized, 1400).await.is_err());
    }

    #[tokio::test]
    async fn running_session_exchanges_data_and_ignores_keepalive() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut session = GpstSession::start(
            Box::new(client),
            GpstSessionOptions {
                mtu: 1400,
                dpd: Duration::ZERO,
                keepalive: Duration::ZERO,
                queue_length: 4,
            },
        )
        .unwrap();
        server.write_all(&encode_gpst_keepalive()).await.unwrap();
        server
            .write_all(&encode_gpst_data(&[0x60, 0, 0, 0], 1400).unwrap())
            .await
            .unwrap();
        assert_eq!(
            session.read_data_packet().await.unwrap().unwrap(),
            [0x60, 0, 0, 0]
        );

        session.write_data_packet(&[0x45, 0, 0, 4]).await.unwrap();
        let packet = read_gpst_packet(&mut server, 1400).await.unwrap();
        assert_eq!(packet.kind, GpstPacketKind::Ipv4);
        assert_eq!(packet.payload, [0x45, 0, 0, 4]);
        session.close().await.unwrap();
    }
}
