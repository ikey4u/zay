//! Tailscale SSH session-recorder transport and asciinema v2 wire format.

use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use futures_util::{StreamExt as _, TryStreamExt as _};
use http_body_util::{BodyExt as _, Empty, StreamBody};
use hyper::{
    Method, Request, StatusCode, Version,
    body::{Frame, Incoming},
    client::conn::http2,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use tokio::{
    io::{
        AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWriteExt as _,
        BufReader,
    },
    sync::{Mutex, mpsc, watch},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::{io::StreamReader, sync::CancellationToken};

use crate::{adapter::Dialer, common::network::SocksAddr};

pub const TAILSCALE_SSH_RECORDER_DIAL_TIMEOUT: Duration =
    Duration::from_secs(5);
pub const TAILSCALE_SSH_RECORDER_V2_PROBE_TIMEOUT: Duration =
    Duration::from_secs(10);
pub const TAILSCALE_SSH_RECORDER_ALL_ATTEMPTS_TIMEOUT: Duration =
    Duration::from_secs(30);
pub const TAILSCALE_SSH_RECORDER_ACK_TIMEOUT: Duration =
    Duration::from_secs(30);
const MAXIMUM_HTTP_HEADER_SIZE: usize = 64 << 10;

/// Header line of the asciinema v2 stream accepted by `tsrecorder`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshCastHeader {
    pub version: u8,
    pub width: u16,
    pub height: u16,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub command: String,
    #[serde(rename = "srcNode")]
    pub source_node: String,
    #[serde(rename = "srcNodeID")]
    pub source_node_id: String,
    #[serde(
        rename = "srcNodeTags",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub source_node_tags: Vec<String>,
    #[serde(rename = "srcNodeUserID", skip_serializing_if = "Option::is_none")]
    pub source_node_user_id: Option<i64>,
    #[serde(
        rename = "srcNodeUser",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub source_node_user: String,
    pub env: std::collections::BTreeMap<String, String>,
    #[serde(rename = "sshUser")]
    pub ssh_user: String,
    #[serde(rename = "localUser")]
    pub local_user: String,
    #[serde(rename = "connectionID")]
    pub connection_id: String,
}

impl TailscaleSshCastHeader {
    pub fn new(timestamp: SystemTime) -> Self {
        Self {
            version: 2,
            width: 0,
            height: 0,
            timestamp: timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .min(i64::MAX as u64) as i64,
            command: String::new(),
            source_node: String::new(),
            source_node_id: String::new(),
            source_node_tags: Vec::new(),
            source_node_user_id: None,
            source_node_user: String::new(),
            env: std::collections::BTreeMap::new(),
            ssh_user: String::new(),
            local_user: String::new(),
            connection_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshRecordingAttempt {
    #[serde(rename = "Recorder")]
    pub recorder: String,
    #[serde(rename = "FailureMessage", default)]
    pub failure_message: String,
}

/// Event values used by Tailscale's SSH recording failure callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TailscaleSshRecordingEventType {
    Rejected = 1,
    Terminated = 2,
    Failed = 3,
}

impl Serialize for TailscaleSshRecordingEventType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for TailscaleSshRecordingEventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(Self::Rejected),
            2 => Ok(Self::Terminated),
            3 => Ok(Self::Failed),
            value => Err(de::Error::custom(format_args!(
                "invalid Tailscale SSH recording event type {value}"
            ))),
        }
    }
}

/// Exact JSON payload sent to an SSH policy's `NotifyURL`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSshRecordingNotification {
    #[serde(rename = "EventType")]
    pub event_type: TailscaleSshRecordingEventType,
    #[serde(rename = "ConnectionID")]
    pub connection_id: String,
    #[serde(rename = "CapVersion")]
    pub cap_version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "SrcNode")]
    pub src_node: i64,
    #[serde(rename = "SSHUser")]
    pub ssh_user: String,
    #[serde(rename = "LocalUser")]
    pub local_user: String,
    #[serde(rename = "RecordingAttempts")]
    pub recording_attempts: Vec<TailscaleSshRecordingAttempt>,
}

#[derive(Debug, Error)]
pub enum TailscaleSshRecordingError {
    #[error("no SSH session recorders configured")]
    NoRecorders,
    #[error("all SSH session recorders failed: {0}")]
    AllRecordersFailed(String),
    #[error("SSH session recording upload failed: {0}")]
    Upload(String),
    #[error("SSH session recording was cancelled")]
    Cancelled,
}

/// An established recorder upload. Clones share one ordered body stream.
#[derive(Debug, Clone)]
pub struct TailscaleSshRecordingUpload {
    sender: Arc<Mutex<Option<mpsc::Sender<Bytes>>>>,
    result: watch::Receiver<Option<Result<(), String>>>,
}

/// Per-session asciinema encoder layered over an established recorder upload.
/// Input is intentionally never accepted, preventing password capture.
#[derive(Debug)]
pub struct TailscaleSshOutputRecording {
    upload: TailscaleSshRecordingUpload,
    started: tokio::time::Instant,
    fail_open: bool,
    failed_open: AtomicBool,
}

impl TailscaleSshOutputRecording {
    pub async fn start(
        upload: TailscaleSshRecordingUpload,
        header: &TailscaleSshCastHeader,
        fail_open: bool,
    ) -> io::Result<Self> {
        let mut header =
            serde_json::to_vec(header).map_err(io::Error::other)?;
        header.push(b'\n');
        upload.write(header).await?;
        Ok(Self {
            upload,
            started: tokio::time::Instant::now(),
            fail_open,
            failed_open: AtomicBool::new(false),
        })
    }

    pub async fn record_output(&self, data: &[u8]) -> io::Result<()> {
        if self.failed_open.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut line = serde_json::to_vec(&(
            self.started.elapsed().as_secs_f64(),
            "o",
            String::from_utf8_lossy(data),
        ))
        .map_err(io::Error::other)?;
        line.push(b'\n');
        if let Err(error) = self.upload.write(line).await {
            if !self.fail_open {
                return Err(error);
            }
            self.failed_open.store(true, Ordering::Release);
        }
        Ok(())
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<Result<(), String>>> {
        self.upload.subscribe()
    }

    pub async fn close(&self) -> Result<(), TailscaleSshRecordingError> {
        self.upload.close().await
    }
}

impl TailscaleSshRecordingUpload {
    pub async fn write(&self, data: impl Into<Bytes>) -> io::Result<()> {
        if let Some(Err(error)) = self.result.borrow().as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                error.clone(),
            ));
        }
        let sender = self.sender.lock().await.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "recording is closed")
        })?;
        sender.send(data.into()).await.map_err(|_| {
            let message = self
                .result
                .borrow()
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .cloned()
                .unwrap_or_else(|| "recording upload ended".into());
            io::Error::new(io::ErrorKind::BrokenPipe, message)
        })
    }

    /// Finish the request body and wait for the recorder's final result.
    pub async fn close(&self) -> Result<(), TailscaleSshRecordingError> {
        self.sender.lock().await.take();
        let mut result = self.result.clone();
        loop {
            if let Some(result) = result.borrow().clone() {
                return result.map_err(TailscaleSshRecordingError::Upload);
            }
            result.changed().await.map_err(|_| {
                TailscaleSshRecordingError::Upload(
                    "recording result channel closed".into(),
                )
            })?;
        }
    }

    /// Observe asynchronous upload failure without taking ownership.
    pub fn subscribe(&self) -> watch::Receiver<Option<Result<(), String>>> {
        self.result.clone()
    }
}

/// Try recorders in policy order, probing h2c v2 before the legacy HTTP/1 API.
pub async fn connect_tailscale_ssh_recorder(
    dialer: Arc<dyn Dialer>,
    recorders: &[String],
    cancellation: CancellationToken,
) -> Result<
    (
        TailscaleSshRecordingUpload,
        Vec<TailscaleSshRecordingAttempt>,
    ),
    (
        TailscaleSshRecordingError,
        Vec<TailscaleSshRecordingAttempt>,
    ),
> {
    if recorders.is_empty() {
        return Err((TailscaleSshRecordingError::NoRecorders, Vec::new()));
    }
    let observed_attempts = Arc::new(std::sync::Mutex::new(Vec::<
        TailscaleSshRecordingAttempt,
    >::new()));
    let result = tokio::time::timeout(
        TAILSCALE_SSH_RECORDER_ALL_ATTEMPTS_TIMEOUT,
        connect_tailscale_ssh_recorder_inner(
            dialer,
            recorders,
            cancellation.clone(),
            observed_attempts.clone(),
        ),
    );
    tokio::select! {
        _ = cancellation.cancelled() => Err((
            TailscaleSshRecordingError::Cancelled,
            observed_attempts.lock().unwrap().clone(),
        )),
        result = result => match result {
            Ok(result) => result,
            Err(_) => Err((
                TailscaleSshRecordingError::AllRecordersFailed(
                    "recorder attempts exceeded 30 seconds".into(),
                ),
                observed_attempts.lock().unwrap().clone(),
            )),
        },
    }
}

async fn connect_tailscale_ssh_recorder_inner(
    dialer: Arc<dyn Dialer>,
    recorders: &[String],
    cancellation: CancellationToken,
    observed_attempts: Arc<std::sync::Mutex<Vec<TailscaleSshRecordingAttempt>>>,
) -> Result<
    (
        TailscaleSshRecordingUpload,
        Vec<TailscaleSshRecordingAttempt>,
    ),
    (
        TailscaleSshRecordingError,
        Vec<TailscaleSshRecordingAttempt>,
    ),
> {
    let mut attempts = Vec::with_capacity(recorders.len());
    let mut failures = Vec::with_capacity(recorders.len());
    for recorder in recorders {
        let mut attempt = TailscaleSshRecordingAttempt {
            recorder: recorder.clone(),
            failure_message: String::new(),
        };
        observed_attempts.lock().unwrap().push(attempt.clone());
        let address = match recorder.parse::<SocketAddr>() {
            Ok(address) => address,
            Err(error) => {
                attempt.failure_message =
                    format!("invalid recorder address: {error}");
                if let Some(observed) =
                    observed_attempts.lock().unwrap().last_mut()
                {
                    *observed = attempt.clone();
                }
                failures.push(attempt.failure_message.clone());
                attempts.push(attempt);
                continue;
            }
        };
        let v2 = supports_recorder_v2(dialer.clone(), address).await;
        let connected = if v2 {
            connect_recorder_v2(
                dialer.clone(),
                address,
                cancellation.child_token(),
            )
            .await
        } else {
            connect_recorder_v1(
                dialer.clone(),
                address,
                cancellation.child_token(),
            )
            .await
        };
        match connected {
            Ok(upload) => {
                attempts.push(attempt);
                return Ok((upload, attempts));
            }
            Err(error) => {
                attempt.failure_message = format!(
                    "recording: error starting recording on {recorder:?}: {error}"
                );
                if let Some(observed) =
                    observed_attempts.lock().unwrap().last_mut()
                {
                    *observed = attempt.clone();
                }
                failures.push(attempt.failure_message.clone());
                attempts.push(attempt);
            }
        }
    }
    Err((
        TailscaleSshRecordingError::AllRecordersFailed(failures.join("; ")),
        attempts,
    ))
}

async fn dial_recorder(
    dialer: &Arc<dyn Dialer>,
    address: SocketAddr,
) -> io::Result<crate::adapter::Stream> {
    tokio::time::timeout(
        TAILSCALE_SSH_RECORDER_DIAL_TIMEOUT,
        dialer.dial_tcp(&SocksAddr::Ip(address)),
    )
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "recorder dial timed out")
    })?
}

async fn supports_recorder_v2(
    dialer: Arc<dyn Dialer>,
    address: SocketAddr,
) -> bool {
    let probe = async {
        let stream = dial_recorder(&dialer, address).await?;
        let (mut sender, connection) =
            http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
                .await
                .map_err(io::Error::other)?;
        let driver = tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::HEAD)
            .uri("/v2/record")
            .header("host", address.to_string())
            .body(Empty::new())
            .map_err(io::Error::other)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;
        let supported = response.status() == StatusCode::OK
            && response.version() == Version::HTTP_2;
        driver.abort();
        Ok::<_, io::Error>(supported)
    };
    tokio::time::timeout(TAILSCALE_SSH_RECORDER_V2_PROBE_TIMEOUT, probe)
        .await
        .is_ok_and(|result| result.unwrap_or(false))
}

async fn connect_recorder_v2(
    dialer: Arc<dyn Dialer>,
    address: SocketAddr,
    cancellation: CancellationToken,
) -> io::Result<TailscaleSshRecordingUpload> {
    let stream = dial_recorder(&dialer, address).await?;
    let (body_tx, body_rx) = mpsc::channel::<Bytes>(32);
    let body = StreamBody::new(
        ReceiverStream::new(body_rx)
            .map(|data| Ok::<_, Infallible>(Frame::data(data))),
    );
    let (mut sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    let driver = tokio::spawn(connection);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v2/record")
        .header("host", address.to_string())
        .body(body)
        .map_err(io::Error::other)?;
    let response = match sender.send_request(request).await {
        Ok(response) if response.status() == StatusCode::OK => response,
        Ok(response) => {
            driver.abort();
            return Err(io::Error::other(format!(
                "unexpected recorder status: {}",
                response.status()
            )));
        }
        Err(error) => {
            driver.abort();
            return Err(io::Error::other(error));
        }
    };
    let (result_tx, result_rx) = watch::channel(None);
    tokio::spawn(async move {
        let result = monitor_recorder_v2(response.into_body(), cancellation)
            .await
            .map_err(|error| error.to_string());
        driver.abort();
        let _ = result_tx.send(Some(result));
    });
    Ok(TailscaleSshRecordingUpload {
        sender: Arc::new(Mutex::new(Some(body_tx))),
        result: result_rx,
    })
}

#[derive(Debug, Deserialize)]
struct TailscaleSshRecorderV2Frame {
    #[allow(dead_code)]
    #[serde(default)]
    ack: u64,
    #[serde(default)]
    error: String,
}

async fn monitor_recorder_v2(
    body: Incoming,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let stream = body
        .into_data_stream()
        .map_err(|error| io::Error::other(error.to_string()));
    let mut lines = BufReader::new(StreamReader::new(stream)).lines();
    loop {
        let line = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "recording cancelled"));
            }
            line = tokio::time::timeout(
                TAILSCALE_SSH_RECORDER_ACK_TIMEOUT,
                lines.next_line(),
            ) => line.map_err(|_| io::Error::new(
                io::ErrorKind::TimedOut,
                "did not receive ack frames from the recorder in 30s",
            ))??,
        };
        let Some(line) = line else {
            return Ok(());
        };
        if line.len() > MAXIMUM_HTTP_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recorder ack frame is too large",
            ));
        }
        let frame: TailscaleSshRecorderV2Frame =
            serde_json::from_str(&line).map_err(io::Error::other)?;
        if !frame.error.is_empty() {
            return Err(io::Error::other(format!(
                "recorder returned error: {:?}",
                frame.error
            )));
        }
    }
}

async fn connect_recorder_v1(
    dialer: Arc<dyn Dialer>,
    address: SocketAddr,
    cancellation: CancellationToken,
) -> io::Result<TailscaleSshRecordingUpload> {
    let mut stream = dial_recorder(&dialer, address).await?;
    let request = format!(
        "POST /record HTTP/1.1\r\nHost: {address}\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let (header, buffered) = read_http_header(&mut stream, Vec::new()).await?;
    if parse_http_status(&header)? != 100 {
        return Err(io::Error::other(
            "legacy recorder did not return 100 Continue",
        ));
    }
    let (body_tx, mut body_rx) = mpsc::channel::<Bytes>(32);
    let (result_tx, result_rx) = watch::channel(None);
    tokio::spawn(async move {
        let result = async {
            loop {
                let data = tokio::select! {
                    _ = cancellation.cancelled() => {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "recording cancelled"));
                    }
                    data = body_rx.recv() => data,
                };
                let Some(data) = data else {
                    break;
                };
                stream
                    .write_all(format!("{:x}\r\n", data.len()).as_bytes())
                    .await?;
                stream.write_all(&data).await?;
                stream.write_all(b"\r\n").await?;
            }
            stream.write_all(b"0\r\n\r\n").await?;
            stream.flush().await?;
            let (header, _) = read_http_header(&mut stream, buffered).await?;
            let status = parse_http_status(&header)?;
            if status != 200 {
                return Err(io::Error::other(format!(
                    "unexpected recorder status: {status}"
                )));
            }
            Ok(())
        }
        .await
        .map_err(|error| error.to_string());
        let _ = result_tx.send(Some(result));
    });
    Ok(TailscaleSshRecordingUpload {
        sender: Arc::new(Mutex::new(Some(body_tx))),
        result: result_rx,
    })
}

async fn read_http_header<S>(
    stream: &mut S,
    mut buffered: Vec<u8>,
) -> io::Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(end) =
            buffered.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let split = end + 4;
            let remaining = buffered.split_off(split);
            return Ok((buffered, remaining));
        }
        if buffered.len() >= MAXIMUM_HTTP_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recorder HTTP header is too large",
            ));
        }
        let mut chunk = [0_u8; 1024];
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "recorder closed before an HTTP response header",
            ));
        }
        buffered.extend_from_slice(&chunk[..length]);
    }
}

fn parse_http_status(header: &[u8]) -> io::Result<u16> {
    let line = header
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTP status line",
            )
        })?;
    line.trim_end_matches('\r')
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status")
        })?
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        option::DirectOutboundOptions, protocol::direct::DirectOutbound,
    };
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::{Response, server::conn::http2 as server_http2};
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    struct HangingDialer;

    impl Dialer for HangingDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> crate::adapter::DialFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    #[test]
    fn cast_header_uses_tailscale_asciinema_field_names() {
        let mut header = TailscaleSshCastHeader::new(UNIX_EPOCH);
        header.width = 80;
        header.height = 24;
        header.source_node = "source.example.ts.net".into();
        header.source_node_id = "node-stable".into();
        header.ssh_user = "remote".into();
        header.local_user = "local".into();
        header.connection_id = "ssh-conn-test".into();
        let value = serde_json::to_value(header).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["srcNode"], "source.example.ts.net");
        assert_eq!(value["srcNodeID"], "node-stable");
        assert_eq!(value["sshUser"], "remote");
        assert_eq!(value["localUser"], "local");
        assert_eq!(value["connectionID"], "ssh-conn-test");
        assert!(value.get("source_node").is_none());
    }

    #[test]
    fn notification_uses_numeric_event_and_go_field_names() {
        let notification = TailscaleSshRecordingNotification {
            event_type: TailscaleSshRecordingEventType::Terminated,
            connection_id: "ssh-conn-test".into(),
            cap_version: 142,
            node_key: "nodekey:abc".into(),
            src_node: 42,
            ssh_user: "remote".into(),
            local_user: "local".into(),
            recording_attempts: vec![TailscaleSshRecordingAttempt {
                recorder: "100.64.0.9:443".into(),
                failure_message: "upload ended".into(),
            }],
        };
        let value = serde_json::to_value(&notification).unwrap();
        assert_eq!(value["EventType"], 2);
        assert_eq!(value["ConnectionID"], "ssh-conn-test");
        assert_eq!(value["CapVersion"], 142);
        assert_eq!(value["NodeKey"], "nodekey:abc");
        assert_eq!(value["SrcNode"], 42);
        assert_eq!(value["RecordingAttempts"][0]["Recorder"], "100.64.0.9:443");
        assert!(value.get("event_type").is_none());
        assert_eq!(
            serde_json::from_value::<TailscaleSshRecordingNotification>(value)
                .unwrap(),
            notification
        );
    }

    #[tokio::test]
    async fn cancellation_preserves_attempts_for_failure_notification() {
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            trigger.cancel();
        });
        let (error, attempts) = connect_tailscale_ssh_recorder(
            Arc::new(HangingDialer),
            &["127.0.0.1:443".into()],
            cancellation,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, TailscaleSshRecordingError::Cancelled));
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].recorder, "127.0.0.1:443");
    }

    #[tokio::test]
    async fn falls_back_to_v1_and_waits_for_continue_before_uploading() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(StdMutex::new(Vec::new()));
        let server_received = received.clone();
        let server = tokio::spawn(async move {
            let (probe, _) = listener.accept().await.unwrap();
            drop(probe);
            let (mut stream, _) = listener.accept().await.unwrap();
            let (header, _) =
                read_http_header(&mut stream, Vec::new()).await.unwrap();
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with("POST /record HTTP/1.1\r\n"));
            assert!(header.contains("Expect: 100-continue\r\n"));
            stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            loop {
                let mut length = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    length.push(byte);
                    if length.ends_with(b"\r\n") {
                        break;
                    }
                }
                let length = usize::from_str_radix(
                    std::str::from_utf8(&length[..length.len() - 2]).unwrap(),
                    16,
                )
                .unwrap();
                if length == 0 {
                    let mut ending = [0_u8; 2];
                    stream.read_exact(&mut ending).await.unwrap();
                    break;
                }
                let mut data = vec![0; length];
                stream.read_exact(&mut data).await.unwrap();
                let mut ending = [0_u8; 2];
                stream.read_exact(&mut ending).await.unwrap();
                server_received.lock().unwrap().extend(data);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let (upload, attempts) = connect_tailscale_ssh_recorder(
            dialer,
            &[address.to_string()],
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(attempts.len(), 1);
        upload.write("header\n").await.unwrap();
        upload.write("output\n").await.unwrap();
        upload.close().await.unwrap();
        server.await.unwrap();
        assert_eq!(&*received.lock().unwrap(), b"header\noutput\n");
    }

    #[tokio::test]
    async fn uploads_v2_and_consumes_ack_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(StdMutex::new(Vec::new()));
        let server_received = received.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let received = server_received.clone();
                server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: Request<Incoming>| {
                            let received = received.clone();
                            async move {
                                if request.method() == Method::HEAD {
                                    return Ok::<_, Infallible>(Response::new(
                                        Full::new(Bytes::new()).boxed_unsync(),
                                    ));
                                }
                                assert_eq!(request.uri().path(), "/v2/record");
                                let (mut ack_tx, ack_body) =
                                    http_body_util::channel::Channel::<
                                        Bytes,
                                        Infallible,
                                    >::new(
                                        2
                                    );
                                tokio::spawn(async move {
                                    let mut body = request.into_body();
                                    let mut count = 0_u64;
                                    while let Some(frame) = body.frame().await {
                                        let frame = frame.unwrap();
                                        if let Ok(data) = frame.into_data() {
                                            count += data.len() as u64;
                                            received
                                                .lock()
                                                .unwrap()
                                                .extend_from_slice(&data);
                                            ack_tx
                                                .send_data(Bytes::from(
                                                    format!(
                                                        "{{\"ack\":{count}}}\n"
                                                    ),
                                                ))
                                                .await
                                                .unwrap();
                                        }
                                    }
                                });
                                Ok(Response::new(ack_body.boxed_unsync()))
                            }
                        }),
                    )
                    .await
                    .unwrap();
            }
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let (upload, attempts) = connect_tailscale_ssh_recorder(
            dialer,
            &[address.to_string()],
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(attempts.len(), 1);
        upload.write("header\n").await.unwrap();
        upload.write("output\n").await.unwrap();
        upload.close().await.unwrap();
        server.await.unwrap();
        assert_eq!(&*received.lock().unwrap(), b"header\noutput\n");
    }
}
