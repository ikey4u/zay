//! AnyTLS v2 authentication and multiplex session wire protocol.

use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, RwLock as StdRwLock, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
    },
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::{DialFuture, Dialer, Stream},
    common::network::SocksAddr,
    protocol::socks::{read_address, write_address},
};

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYN_ACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

type SharedWriter = Arc<Mutex<WriteHalf<Stream>>>;
type SharedClientWriter = Arc<Mutex<ClientWriter>>;
pub type ServerStreamFuture =
    Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;
pub type ServerStreamHandler = Arc<
    dyn Fn(Stream, SocksAddr, String, ServerHandshake) -> ServerStreamFuture
        + Send
        + Sync,
>;

/// Reports the result of establishing the routed connection for an AnyTLS
/// logical stream. AnyTLS v2 sends exactly one SYNACK after routing succeeds or
/// fails; v1 peers do not receive this extension frame.
#[derive(Clone)]
pub struct ServerHandshake {
    writer: SharedWriter,
    stream_id: u32,
    peer_version: u8,
    reported: Arc<AtomicBool>,
}

impl ServerHandshake {
    async fn report(&self, error: Option<&io::Error>) -> io::Result<()> {
        if self.peer_version < 2 || self.reported.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let message = error.map(ToString::to_string).unwrap_or_default();
        write_locked(
            &self.writer,
            CMD_SYN_ACK,
            self.stream_id,
            message.as_bytes(),
        )
        .await
    }

    pub async fn success(&self) -> io::Result<()> {
        self.report(None).await
    }

    pub async fn failure(&self, error: &io::Error) -> io::Result<()> {
        self.report(Some(error)).await
    }
}

#[derive(Clone)]
pub struct AnyTlsOutbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    password_hash: [u8; 32],
    client_metadata: String,
    pool: Arc<ClientPool>,
    padding: Arc<StdRwLock<PaddingFactory>>,
}

struct ClientSession {
    sequence: u64,
    writer: SharedClientWriter,
    streams: Arc<Mutex<HashMap<u32, WriteHalf<tokio::io::DuplexStream>>>>,
    next_stream_id: AtomicU32,
    cancellation: CancellationToken,
}

struct ClientPool {
    state: Mutex<ClientPoolState>,
    next_sequence: AtomicU64,
    cleanup_started: AtomicBool,
    cleanup_interval: Duration,
    idle_timeout: Duration,
    min_idle_sessions: usize,
    cancellation: CancellationToken,
}

#[derive(Default)]
struct ClientPoolState {
    sessions: HashMap<u64, Arc<ClientSession>>,
    idle: Vec<IdleSession>,
}

struct IdleSession {
    session: Arc<ClientSession>,
    since: Instant,
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Drop for ClientPool {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl AnyTlsOutbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        password: &str,
        client_metadata: String,
    ) -> Self {
        Self::new_with_session_policy(
            upstream,
            server,
            password,
            client_metadata,
            Duration::ZERO,
            Duration::ZERO,
            0,
        )
    }

    pub fn new_with_session_policy(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        password: &str,
        client_metadata: String,
        cleanup_interval: Duration,
        idle_timeout: Duration,
        min_idle_sessions: i32,
    ) -> Self {
        let cleanup_interval = if cleanup_interval <= Duration::from_secs(5) {
            Duration::from_secs(30)
        } else {
            cleanup_interval
        };
        let idle_timeout = if idle_timeout <= Duration::from_secs(5) {
            Duration::from_secs(30)
        } else {
            idle_timeout
        };
        Self {
            upstream,
            server,
            password_hash: Sha256::digest(password.as_bytes()).into(),
            client_metadata,
            pool: Arc::new(ClientPool {
                state: Mutex::new(ClientPoolState::default()),
                next_sequence: AtomicU64::new(0),
                cleanup_started: AtomicBool::new(false),
                cleanup_interval,
                idle_timeout,
                min_idle_sessions: min_idle_sessions.max(0) as usize,
                cancellation: CancellationToken::new(),
            }),
            padding: Arc::new(StdRwLock::new(
                PaddingFactory::new(DEFAULT_PADDING_SCHEME.as_bytes())
                    .expect("default AnyTLS padding scheme is valid"),
            )),
        }
    }

    async fn create_session(&self) -> io::Result<Arc<ClientSession>> {
        let mut connection = self.upstream.dial_tcp(&self.server).await?;
        connection.write_all(&self.password_hash).await?;
        let initial_padding = self
            .padding
            .read()
            .expect("AnyTLS padding lock poisoned")
            .generate(0)?
            .first()
            .copied()
            .and_then(|value| match value {
                PaddingSize::Exact(size) => Some(size),
                PaddingSize::Range(_, _) | PaddingSize::Check => None,
            })
            .unwrap_or(0);
        connection.write_u16(initial_padding as u16).await?;
        connection.write_all(&vec![0_u8; initial_padding]).await?;
        let metadata = &self.client_metadata;
        let padding_md5 = self
            .padding
            .read()
            .expect("AnyTLS padding lock poisoned")
            .md5
            .clone();
        let settings =
            format!("v=2\nclient={metadata}\npadding-md5={padding_md5}");
        let (reader, writer) = tokio::io::split(connection);
        let writer = Arc::new(Mutex::new(ClientWriter {
            writer,
            padding: self.padding.clone(),
            packet_counter: 0,
            send_padding: true,
            buffering: true,
            buffer: Vec::new(),
        }));
        write_client_locked(&writer, CMD_SETTINGS, 0, settings.as_bytes())
            .await?;
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = self.pool.cancellation.child_token();
        let sequence =
            self.pool.next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let session = Arc::new(ClientSession {
            sequence,
            writer,
            streams,
            next_stream_id: AtomicU32::new(0),
            cancellation,
        });
        self.pool.register(session.clone()).await;
        tokio::spawn(client_receive_loop(
            reader,
            session.writer.clone(),
            session.streams.clone(),
            self.padding.clone(),
            session.cancellation.clone(),
            Arc::downgrade(&self.pool),
            sequence,
        ));
        Ok(session)
    }

    async fn create_stream(
        &self,
        destination: &SocksAddr,
    ) -> io::Result<Stream> {
        self.pool.start_cleanup();
        let session = match self.pool.checkout().await {
            Some(session) => session,
            None => self.create_session().await?,
        };
        match session
            .open_stream(destination, Arc::downgrade(&self.pool))
            .await
        {
            Ok(stream) => Ok(stream),
            Err(error) => {
                session.cancellation.cancel();
                self.pool.remove(session.sequence).await;
                Err(error)
            }
        }
    }
}

impl ClientPool {
    fn start_cleanup(self: &Arc<Self>) {
        if self
            .cleanup_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let pool = Arc::downgrade(self);
        let cancellation = self.cancellation.clone();
        let interval = self.cleanup_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => return,
                    _ = ticker.tick() => {
                        let Some(pool) = pool.upgrade() else { return };
                        pool.cleanup(Instant::now()).await;
                    }
                }
            }
        });
    }

    async fn register(&self, session: Arc<ClientSession>) {
        self.state
            .lock()
            .await
            .sessions
            .insert(session.sequence, session);
    }

    async fn checkout(&self) -> Option<Arc<ClientSession>> {
        let mut state = self.state.lock().await;
        loop {
            let index = state
                .idle
                .iter()
                .enumerate()
                .max_by_key(|(_, idle)| idle.session.sequence)
                .map(|(index, _)| index)?;
            let session = state.idle.swap_remove(index).session;
            if !session.cancellation.is_cancelled() {
                return Some(session);
            }
            state.sessions.remove(&session.sequence);
        }
    }

    async fn return_idle(&self, session: Arc<ClientSession>) {
        if self.cancellation.is_cancelled()
            || session.cancellation.is_cancelled()
        {
            return;
        }
        let mut state = self.state.lock().await;
        if state.sessions.contains_key(&session.sequence)
            && !state
                .idle
                .iter()
                .any(|idle| idle.session.sequence == session.sequence)
        {
            state.idle.push(IdleSession {
                session,
                since: Instant::now(),
            });
        }
    }

    async fn remove(&self, sequence: u64) {
        let mut state = self.state.lock().await;
        state.sessions.remove(&sequence);
        state.idle.retain(|idle| idle.session.sequence != sequence);
    }

    async fn cleanup(&self, now: Instant) {
        let mut state = self.state.lock().await;
        state
            .idle
            .sort_by_key(|idle| std::cmp::Reverse(idle.session.sequence));
        let mut active = 0_usize;
        let mut retained = Vec::with_capacity(state.idle.len());
        for mut idle in std::mem::take(&mut state.idle) {
            if idle.session.cancellation.is_cancelled() {
                state.sessions.remove(&idle.session.sequence);
                continue;
            }
            if now.saturating_duration_since(idle.since) < self.idle_timeout {
                active += 1;
                retained.push(idle);
            } else if active < self.min_idle_sessions {
                idle.since = now;
                active += 1;
                retained.push(idle);
            } else {
                idle.session.cancellation.cancel();
                state.sessions.remove(&idle.session.sequence);
            }
        }
        state.idle = retained;
    }

    #[cfg(test)]
    async fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().await;
        (state.sessions.len(), state.idle.len())
    }
}

impl ClientSession {
    async fn open_stream(
        self: &Arc<Self>,
        destination: &SocksAddr,
        pool: Weak<ClientPool>,
    ) -> io::Result<Stream> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS session is closed",
            ));
        }
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (application, session) = tokio::io::duplex(64 * 1024);
        let (session_reader, session_writer) = tokio::io::split(session);
        self.streams.lock().await.insert(stream_id, session_writer);
        write_client_locked(&self.writer, CMD_SYN, stream_id, &[]).await?;
        let (mut address_reader, mut address_writer) = tokio::io::duplex(512);
        write_address(&mut address_writer, destination).await?;
        address_writer.shutdown().await?;
        let mut address = Vec::new();
        address_reader.read_to_end(&mut address).await?;
        self.writer.lock().await.buffering = false;
        write_client_locked(&self.writer, CMD_PSH, stream_id, &address).await?;
        spawn_client_outgoing_stream(
            session_reader,
            self.writer.clone(),
            stream_id,
            self.cancellation.clone(),
            self.clone(),
            pool,
        );
        Ok(Box::new(application))
    }
}

impl Dialer for AnyTlsOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move { self.create_stream(destination).await })
    }
}

pub fn password_hash(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

pub async fn serve_connection(
    mut connection: Stream,
    users: Arc<HashMap<[u8; 32], String>>,
    padding_scheme: Arc<Vec<u8>>,
    handler: ServerStreamHandler,
) -> io::Result<()> {
    let mut supplied_hash = [0_u8; 32];
    connection.read_exact(&mut supplied_hash).await?;
    let user = users.get(&supplied_hash).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown AnyTLS password",
        )
    })?;
    let padding_length = connection.read_u16().await? as usize;
    if padding_length > 0 {
        let mut padding = vec![0_u8; padding_length];
        connection.read_exact(&mut padding).await?;
    }

    let (mut reader, writer) = tokio::io::split(connection);
    let writer = Arc::new(Mutex::new(writer));
    let mut streams: HashMap<u32, WriteHalf<tokio::io::DuplexStream>> =
        HashMap::new();
    let mut received_settings = false;
    let mut peer_version = 0;
    loop {
        let frame = read_frame(&mut reader).await?;
        match frame.command {
            CMD_SETTINGS => {
                received_settings = true;
                let settings = parse_settings(&frame.data);
                let scheme_md5 = hex::encode(Md5::digest(&*padding_scheme));
                if settings.get("padding-md5") != Some(&scheme_md5) {
                    write_locked(
                        &writer,
                        CMD_UPDATE_PADDING_SCHEME,
                        0,
                        &padding_scheme,
                    )
                    .await?;
                }
                if settings
                    .get("v")
                    .and_then(|value| value.parse::<u8>().ok())
                    .is_some_and(|version| version >= 2)
                {
                    peer_version = 2;
                    write_locked(&writer, CMD_SERVER_SETTINGS, 0, b"v=2")
                        .await?;
                }
            }
            CMD_SYN => {
                if !received_settings {
                    write_locked(
                        &writer,
                        CMD_ALERT,
                        0,
                        b"client did not send its settings",
                    )
                    .await?;
                    return Err(invalid_data("AnyTLS SYN before settings"));
                }
                if streams.contains_key(&frame.stream_id) {
                    continue;
                }
                let (application, session) = tokio::io::duplex(64 * 1024);
                let (session_reader, session_writer) =
                    tokio::io::split(session);
                streams.insert(frame.stream_id, session_writer);
                spawn_outgoing_stream(
                    session_reader,
                    writer.clone(),
                    frame.stream_id,
                );
                let handler = handler.clone();
                let user = user.clone();
                let writer = writer.clone();
                let stream_id = frame.stream_id;
                let handshake = ServerHandshake {
                    writer: writer.clone(),
                    stream_id,
                    peer_version,
                    reported: Arc::new(AtomicBool::new(false)),
                };
                tokio::spawn(async move {
                    let mut application: Stream = Box::new(application);
                    if let Ok(destination) =
                        read_address(&mut application).await
                    {
                        let result = handler(
                            application,
                            destination,
                            user,
                            handshake.clone(),
                        )
                        .await;
                        match result {
                            Ok(()) => {
                                let _ = handshake.success().await;
                            }
                            Err(error) => {
                                let _ = handshake.failure(&error).await;
                            }
                        }
                    }
                });
            }
            CMD_PSH => {
                if let Some(stream) = streams.get_mut(&frame.stream_id) {
                    stream.write_all(&frame.data).await?;
                }
            }
            CMD_FIN => {
                if let Some(mut stream) = streams.remove(&frame.stream_id) {
                    let _ = stream.shutdown().await;
                }
            }
            CMD_WASTE
            | CMD_HEART_RESPONSE
            | CMD_SERVER_SETTINGS
            | CMD_UPDATE_PADDING_SCHEME => {}
            CMD_HEART_REQUEST => {
                write_locked(&writer, CMD_HEART_RESPONSE, frame.stream_id, &[])
                    .await?;
            }
            CMD_ALERT => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    String::from_utf8_lossy(&frame.data).into_owned(),
                ));
            }
            _ => {}
        }
    }
}

pub fn validate_padding_scheme(scheme: &[u8]) -> io::Result<()> {
    PaddingFactory::new(scheme).map(|_| ())
}

pub fn default_padding_scheme() -> Vec<u8> {
    DEFAULT_PADDING_SCHEME.as_bytes().to_vec()
}

struct Frame {
    command: u8,
    stream_id: u32,
    data: Vec<u8>,
}

#[derive(Clone)]
struct PaddingFactory {
    rules: HashMap<u32, Vec<PaddingSize>>,
    stop: u32,
    md5: String,
}

#[derive(Clone, Copy)]
enum PaddingSize {
    Exact(usize),
    Range(usize, usize),
    Check,
}

impl PaddingFactory {
    fn new(raw: &[u8]) -> io::Result<Self> {
        let settings = parse_settings(raw);
        if settings.is_empty() {
            return Err(invalid_data("empty AnyTLS padding scheme"));
        }
        let stop = settings
            .get("stop")
            .ok_or_else(|| {
                invalid_data("AnyTLS padding scheme has no stop value")
            })?
            .parse::<u32>()
            .map_err(|_| {
                invalid_data("invalid AnyTLS padding scheme stop value")
            })?;
        let mut rules = HashMap::new();
        for (packet, value) in settings {
            let Ok(packet) = packet.parse::<u32>() else {
                continue;
            };
            let mut sizes = Vec::new();
            for item in value.split(',') {
                if item == "c" {
                    sizes.push(PaddingSize::Check);
                    continue;
                }
                let Some((minimum, maximum)) = item.split_once('-') else {
                    continue;
                };
                let (Ok(mut minimum), Ok(mut maximum)) =
                    (minimum.parse::<usize>(), maximum.parse::<usize>())
                else {
                    continue;
                };
                if minimum == 0 || maximum == 0 {
                    continue;
                }
                if minimum > maximum {
                    std::mem::swap(&mut minimum, &mut maximum);
                }
                let size = if minimum == maximum {
                    PaddingSize::Exact(minimum)
                } else {
                    PaddingSize::Range(minimum, maximum)
                };
                sizes.push(size);
            }
            rules.insert(packet, sizes);
        }
        Ok(Self {
            rules,
            stop,
            md5: hex::encode(Md5::digest(raw)),
        })
    }

    fn generate(&self, packet: u32) -> io::Result<Vec<PaddingSize>> {
        self.rules
            .get(&packet)
            .into_iter()
            .flatten()
            .map(|size| match *size {
                PaddingSize::Range(minimum, maximum) => Ok(PaddingSize::Exact(
                    minimum + random_below(maximum - minimum)?,
                )),
                value => Ok(value),
            })
            .collect()
    }
}

fn random_below(limit: usize) -> io::Result<usize> {
    debug_assert!(limit > 0);
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok((u64::from_ne_bytes(bytes) % limit as u64) as usize)
}

struct ClientWriter {
    writer: WriteHalf<Stream>,
    padding: Arc<StdRwLock<PaddingFactory>>,
    packet_counter: u32,
    send_padding: bool,
    buffering: bool,
    buffer: Vec<u8>,
}

impl ClientWriter {
    async fn write_payload(&mut self, mut data: Vec<u8>) -> io::Result<()> {
        if self.buffering {
            self.buffer.extend_from_slice(&data);
            return Ok(());
        }
        if !self.buffer.is_empty() {
            self.buffer.extend_from_slice(&data);
            data = std::mem::take(&mut self.buffer);
        }
        if !self.send_padding {
            return self.writer.write_all(&data).await;
        }
        self.packet_counter += 1;
        let padding = self
            .padding
            .read()
            .expect("AnyTLS padding lock poisoned")
            .clone();
        if self.packet_counter >= padding.stop {
            self.send_padding = false;
            return self.writer.write_all(&data).await;
        }

        let mut offset = 0;
        for size in padding.generate(self.packet_counter)? {
            let remaining = data.len() - offset;
            match size {
                PaddingSize::Check if remaining == 0 => break,
                PaddingSize::Check => continue,
                PaddingSize::Range(_, _) => unreachable!("range was resolved"),
                PaddingSize::Exact(size) if remaining > size => {
                    self.writer.write_all(&data[offset..offset + size]).await?;
                    offset += size;
                }
                PaddingSize::Exact(size) if remaining > 0 => {
                    let padding_length = size
                        .saturating_sub(remaining + 7)
                        .min(u16::MAX as usize);
                    let mut record = Vec::with_capacity(
                        remaining
                            + usize::from(padding_length > 0) * 7
                            + padding_length,
                    );
                    record.extend_from_slice(&data[offset..]);
                    if padding_length > 0 {
                        record.push(CMD_WASTE);
                        record.extend_from_slice(&0_u32.to_be_bytes());
                        record.extend_from_slice(
                            &(padding_length as u16).to_be_bytes(),
                        );
                        record.resize(record.len() + padding_length, 0);
                    }
                    self.writer.write_all(&record).await?;
                    offset = data.len();
                }
                PaddingSize::Exact(size) => {
                    let padding_length = size.min(u16::MAX as usize);
                    write_frame(
                        &mut self.writer,
                        CMD_WASTE,
                        0,
                        &vec![0_u8; padding_length],
                    )
                    .await?;
                }
            }
        }
        if offset < data.len() {
            self.writer.write_all(&data[offset..]).await?;
        }
        Ok(())
    }
}

async fn read_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let command = reader.read_u8().await?;
    let stream_id = reader.read_u32().await?;
    let length = reader.read_u16().await? as usize;
    let mut data = vec![0_u8; length];
    reader.read_exact(&mut data).await?;
    Ok(Frame {
        command,
        stream_id,
        data,
    })
}

async fn write_frame<W>(
    writer: &mut W,
    command: u8,
    stream_id: u32,
    data: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if data.is_empty() {
        writer.write_u8(command).await?;
        writer.write_u32(stream_id).await?;
        writer.write_u16(0).await?;
        return Ok(());
    }
    for chunk in data.chunks(u16::MAX as usize) {
        writer.write_u8(command).await?;
        writer.write_u32(stream_id).await?;
        writer.write_u16(chunk.len() as u16).await?;
        writer.write_all(chunk).await?;
    }
    Ok(())
}

async fn write_locked(
    writer: &SharedWriter,
    command: u8,
    stream_id: u32,
    data: &[u8],
) -> io::Result<()> {
    let mut writer = writer.lock().await;
    write_frame(&mut *writer, command, stream_id, data).await?;
    writer.flush().await
}

async fn write_client_locked(
    writer: &SharedClientWriter,
    command: u8,
    stream_id: u32,
    data: &[u8],
) -> io::Result<()> {
    let mut writer = writer.lock().await;
    if data.is_empty() {
        let mut frame = Vec::with_capacity(7);
        frame.push(command);
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(&0_u16.to_be_bytes());
        writer.write_payload(frame).await?;
    } else {
        for chunk in data.chunks(u16::MAX as usize) {
            let mut frame = Vec::with_capacity(chunk.len() + 7);
            frame.push(command);
            frame.extend_from_slice(&stream_id.to_be_bytes());
            frame.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            frame.extend_from_slice(chunk);
            writer.write_payload(frame).await?;
        }
    }
    writer.writer.flush().await
}

fn parse_settings(data: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(data)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn spawn_outgoing_stream(
    mut reader: ReadHalf<tokio::io::DuplexStream>,
    writer: SharedWriter,
    stream_id: u32,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ =
                        write_locked(&writer, CMD_FIN, stream_id, &[]).await;
                    return;
                }
                Ok(length) => {
                    if write_locked(
                        &writer,
                        CMD_PSH,
                        stream_id,
                        &buffer[..length],
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
}

fn spawn_client_outgoing_stream(
    mut reader: ReadHalf<tokio::io::DuplexStream>,
    writer: SharedClientWriter,
    stream_id: u32,
    cancellation: CancellationToken,
    session: Arc<ClientSession>,
    pool: Weak<ClientPool>,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let result = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = reader.read(&mut buffer) => result,
            };
            match result {
                Ok(0) | Err(_) => {
                    if write_client_locked(&writer, CMD_FIN, stream_id, &[])
                        .await
                        .is_ok()
                        && !session.cancellation.is_cancelled()
                        && let Some(pool) = pool.upgrade()
                    {
                        pool.return_idle(session).await;
                    }
                    return;
                }
                Ok(length) => {
                    if write_client_locked(
                        &writer,
                        CMD_PSH,
                        stream_id,
                        &buffer[..length],
                    )
                    .await
                    .is_err()
                    {
                        session.cancellation.cancel();
                        if let Some(pool) = pool.upgrade() {
                            pool.remove(session.sequence).await;
                        }
                        return;
                    }
                }
            }
        }
    });
}

async fn client_receive_loop(
    mut reader: ReadHalf<Stream>,
    writer: SharedClientWriter,
    streams: Arc<Mutex<HashMap<u32, WriteHalf<tokio::io::DuplexStream>>>>,
    padding: Arc<StdRwLock<PaddingFactory>>,
    cancellation: CancellationToken,
    pool: Weak<ClientPool>,
    sequence: u64,
) {
    loop {
        let frame = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = read_frame(&mut reader) => result,
        };
        let Ok(frame) = frame else {
            break;
        };
        match frame.command {
            CMD_PSH => {
                let failed =
                    match streams.lock().await.get_mut(&frame.stream_id) {
                        Some(writer) => {
                            writer.write_all(&frame.data).await.is_err()
                        }
                        None => false,
                    };
                if failed {
                    break;
                }
            }
            CMD_FIN => {
                if let Some(mut writer) =
                    streams.lock().await.remove(&frame.stream_id)
                {
                    let _ = writer.shutdown().await;
                }
            }
            CMD_SYN_ACK if !frame.data.is_empty() => {
                if let Some(mut writer) =
                    streams.lock().await.remove(&frame.stream_id)
                {
                    let _ = writer.shutdown().await;
                }
            }
            CMD_HEART_REQUEST => {
                if write_client_locked(
                    &writer,
                    CMD_HEART_RESPONSE,
                    frame.stream_id,
                    &[],
                )
                .await
                .is_err()
                {
                    break;
                }
            }
            CMD_UPDATE_PADDING_SCHEME => {
                if let Ok(updated) = PaddingFactory::new(&frame.data) {
                    *padding.write().expect("AnyTLS padding lock poisoned") =
                        updated;
                }
            }
            CMD_ALERT => break,
            CMD_WASTE | CMD_SETTINGS | CMD_HEART_RESPONSE
            | CMD_SERVER_SETTINGS | CMD_SYN_ACK => {}
            _ => {}
        }
    }
    cancellation.cancel();
    streams.lock().await.clear();
    if let Some(pool) = pool.upgrade() {
        pool.remove(sequence).await;
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_and_default_padding_hashes_match_go() {
        assert_eq!(
            hex::encode(password_hash("password")),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
        assert_eq!(
            hex::encode(Md5::digest(DEFAULT_PADDING_SCHEME.as_bytes())),
            "75cff2ad89aadf5e257059ee571ebe11"
        );
    }

    #[tokio::test]
    async fn client_and_server_session_proxy_a_stream() {
        const SERVER_PADDING: &[u8] =
            b"stop=4\n0=30-30\n1=50-50,c,60-60\n2=40-40";
        let (client_side, server_side) = tokio::io::duplex(128 * 1024);
        let upstream = Arc::new(DuplexDialer {
            streams: Mutex::new(vec![client_side]),
        });
        let outbound = AnyTlsOutbound::new(
            upstream,
            SocksAddr::new("server.test", 443),
            "secret",
            String::new(),
        );
        let users = Arc::new(HashMap::from([(
            password_hash("secret"),
            "alice".into(),
        )]));
        let handler: ServerStreamHandler =
            Arc::new(|mut stream, destination, user, handshake| {
                Box::pin(async move {
                    assert_eq!(destination, SocksAddr::new("target.test", 80));
                    assert_eq!(user, "alice");
                    handshake.success().await?;
                    let mut data = [0_u8; 4];
                    stream.read_exact(&mut data).await?;
                    stream.write_all(&data).await
                })
            });
        tokio::spawn(async move {
            let _ = serve_connection(
                Box::new(server_side),
                users,
                Arc::new(SERVER_PADDING.to_vec()),
                handler,
            )
            .await;
        });
        let mut stream = outbound
            .dial_tcp(&SocksAddr::new("target.test", 80))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let expected = hex::encode(Md5::digest(SERVER_PADDING));
            loop {
                if outbound
                    .padding
                    .read()
                    .expect("AnyTLS padding lock poisoned")
                    .md5
                    == expected
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(stream);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if outbound.pool.counts().await == (1, 1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let mut second = outbound
            .dial_tcp(&SocksAddr::new("target.test", 80))
            .await
            .unwrap();
        assert_eq!(outbound.pool.counts().await, (1, 0));
        second.write_all(b"next").await.unwrap();
        second.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"next");
    }

    #[tokio::test]
    async fn server_reports_routing_failure_in_v2_synack() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let users = Arc::new(HashMap::from([(
            password_hash("secret"),
            "alice".into(),
        )]));
        let handler: ServerStreamHandler =
            Arc::new(|_stream, destination, user, handshake| {
                Box::pin(async move {
                    assert_eq!(destination, SocksAddr::new("target.test", 80));
                    assert_eq!(user, "alice");
                    let error = io::Error::other("dial failed");
                    handshake.failure(&error).await?;
                    Err(error)
                })
            });
        tokio::spawn(async move {
            let _ = serve_connection(
                Box::new(server),
                users,
                Arc::new(DEFAULT_PADDING_SCHEME.as_bytes().to_vec()),
                handler,
            )
            .await;
        });

        client.write_all(&password_hash("secret")).await.unwrap();
        client.write_u16(0).await.unwrap();
        let settings = format!(
            "v=2\npadding-md5={}",
            hex::encode(Md5::digest(DEFAULT_PADDING_SCHEME.as_bytes()))
        );
        write_frame(&mut client, CMD_SETTINGS, 0, settings.as_bytes())
            .await
            .unwrap();
        write_frame(&mut client, CMD_SYN, 1, &[]).await.unwrap();
        let mut address = vec![3, 11];
        address.extend_from_slice(b"target.test");
        address.extend_from_slice(&80_u16.to_be_bytes());
        write_frame(&mut client, CMD_PSH, 1, &address)
            .await
            .unwrap();
        client.flush().await.unwrap();

        let server_settings = read_frame(&mut client).await.unwrap();
        assert_eq!(server_settings.command, CMD_SERVER_SETTINGS);
        let synack = read_frame(&mut client).await.unwrap();
        assert_eq!(synack.command, CMD_SYN_ACK);
        assert_eq!(synack.stream_id, 1);
        assert_eq!(synack.data, b"dial failed");
    }

    #[tokio::test]
    async fn busy_sessions_scale_out_then_return_to_the_idle_pool() {
        let mut clients = Vec::new();
        for _ in 0..2 {
            let (client, server) = tokio::io::duplex(128 * 1024);
            clients.push(client);
            spawn_test_server(server);
        }
        let upstream = Arc::new(DuplexDialer {
            streams: Mutex::new(clients),
        });
        let outbound = AnyTlsOutbound::new_with_session_policy(
            upstream,
            SocksAddr::new("server.test", 443),
            "secret",
            String::new(),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            1,
        );

        let mut first = outbound
            .dial_tcp(&SocksAddr::new("target.test", 80))
            .await
            .unwrap();
        let mut second = outbound
            .dial_tcp(&SocksAddr::new("target.test", 80))
            .await
            .unwrap();
        assert_eq!(outbound.pool.counts().await, (2, 0));
        first.write_all(b"one!").await.unwrap();
        second.write_all(b"two!").await.unwrap();
        let mut echoed = [0_u8; 4];
        first.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"one!");
        second.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"two!");
        drop(first);
        drop(second);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if outbound.pool.counts().await == (2, 2) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut reused = outbound
            .dial_tcp(&SocksAddr::new("target.test", 80))
            .await
            .unwrap();
        assert_eq!(outbound.pool.counts().await, (2, 1));
        reused.write_all(b"idle").await.unwrap();
        reused.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"idle");
        drop(reused);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if outbound.pool.counts().await == (2, 2) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        outbound
            .pool
            .cleanup(Instant::now() + std::time::Duration::from_secs(61))
            .await;
        assert_eq!(outbound.pool.counts().await, (1, 1));
    }

    fn spawn_test_server(server: tokio::io::DuplexStream) {
        let users = Arc::new(HashMap::from([(
            password_hash("secret"),
            "alice".into(),
        )]));
        let handler: ServerStreamHandler =
            Arc::new(|mut stream, _, _, handshake| {
                Box::pin(async move {
                    handshake.success().await?;
                    let mut data = [0_u8; 4];
                    stream.read_exact(&mut data).await?;
                    stream.write_all(&data).await
                })
            });
        tokio::spawn(async move {
            let _ = serve_connection(
                Box::new(server),
                users,
                Arc::new(DEFAULT_PADDING_SCHEME.as_bytes().to_vec()),
                handler,
            )
            .await;
        });
    }

    struct DuplexDialer {
        streams: Mutex<Vec<tokio::io::DuplexStream>>,
    }

    impl Dialer for DuplexDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async move {
                self.streams
                    .lock()
                    .await
                    .pop()
                    .map(|stream| Box::new(stream) as Stream)
                    .ok_or_else(|| io::Error::other("already dialed"))
            })
        }
    }
}
