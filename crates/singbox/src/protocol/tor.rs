//! Tor outbound implemented with native Arti and a C Tor compatibility path.
//!
//! Arti normally opens its relay connections directly.  sing-box instead
//! routes those connections through the outbound's configured dialer.  The
//! custom `NetStreamProvider` below preserves that behaviour without spawning
//! a Tor process or exposing an intermediate SOCKS listener. Configurations
//! which explicitly select the legacy Tor executable/options use a supervised
//! process and a loopback-only authenticated SOCKS bridge, matching the Go
//! implementation's bootstrap detour semantics.

use std::{
    collections::HashMap,
    ffi::OsString,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use arti_client::{
    BootstrapBehavior, TorClient, TorClientConfig,
    config::TorClientConfigBuilder,
};
use async_trait::async_trait;
use futures::{
    AsyncRead, AsyncWrite,
    stream::{self, Empty},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    task::JoinHandle,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use tor_rtcompat::{
    CompoundRuntime, NetStreamListener, NetStreamProvider, PreferredRuntime,
    RuntimeSubstExt, StreamOps,
};

use crate::{
    adapter::{DialFuture, Dialer, Stream},
    common::network::SocksAddr,
    option::User,
    protocol::socks::{client_handshake, server_handshake, write_reply},
};

const CONTROL_PORT_TIMEOUT: Duration = Duration::from_secs(60);

type ArtiRuntime = CompoundRuntime<
    PreferredRuntime,
    PreferredRuntime,
    PreferredRuntime,
    DetourTcpProvider,
    PreferredRuntime,
    PreferredRuntime,
    PreferredRuntime,
>;

/// A reusable, lazily bootstrapped native Tor client.
pub struct TorOutbound {
    upstream: Arc<dyn Dialer>,
    data_directory: Option<PathBuf>,
    client: tokio::sync::OnceCell<TorClient<ArtiRuntime>>,
}

impl TorOutbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        data_directory: Option<&Path>,
    ) -> Self {
        Self {
            upstream,
            data_directory: data_directory.map(Path::to_path_buf),
            client: tokio::sync::OnceCell::new(),
        }
    }

    async fn client(&self) -> io::Result<&TorClient<ArtiRuntime>> {
        self.client
            .get_or_try_init(|| async {
                let config = client_config(self.data_directory.as_deref())?;
                create_client(self.upstream.clone(), config)
            })
            .await
    }
}

fn create_client(
    upstream: Arc<dyn Dialer>,
    config: TorClientConfig,
) -> io::Result<TorClient<ArtiRuntime>> {
    // Arti's rustls backend uses the process default.  This workspace also
    // enables aws-lc-rs for certificate generation, so rustls cannot infer a
    // provider from Cargo features alone.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let preferred = PreferredRuntime::current().map_err(other)?;
    let runtime = preferred.with_tcp_provider(DetourTcpProvider { upstream });
    let client = TorClient::with_runtime(runtime)
        .config(config)
        .bootstrap_behavior(BootstrapBehavior::OnDemand)
        .create_unbootstrapped()
        .map_err(other)?;
    Ok(client)
}

impl Dialer for TorOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let host = destination.host();
            let stream = self
                .client()
                .await?
                .connect((host.as_str(), destination.port()))
                .await
                .map_err(other)?;
            Ok(Box::new(stream) as Stream)
        })
    }
}

/// Configuration for the upstream-compatible external Tor backend.
#[derive(Debug, Clone)]
pub struct ExternalTorConfig {
    pub executable_path: String,
    pub extra_args: Vec<String>,
    pub data_directory: Option<PathBuf>,
    pub torrc: HashMap<String, String>,
}

/// A lazily started and process-owned C Tor outbound.
///
/// This backend is selected only when a configuration uses one of the legacy
/// process settings. Dropping the final `Arc` cancels the bootstrap bridge and
/// terminates the child process; no global daemon or CLI lifecycle is needed.
pub struct ExternalTorOutbound {
    upstream: Arc<dyn Dialer>,
    config: ExternalTorConfig,
    state: tokio::sync::OnceCell<ExternalTorState>,
}

impl ExternalTorOutbound {
    pub fn new(upstream: Arc<dyn Dialer>, config: ExternalTorConfig) -> Self {
        Self {
            upstream,
            config,
            state: tokio::sync::OnceCell::new(),
        }
    }

    async fn state(&self) -> io::Result<&ExternalTorState> {
        self.state
            .get_or_try_init(|| {
                start_external_tor(self.upstream.clone(), &self.config)
            })
            .await
    }
}

impl Dialer for ExternalTorOutbound {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let state = self.state().await?;
            let mut stream = TcpStream::connect(state.socks_address).await?;
            client_handshake(&mut stream, destination, None).await?;
            Ok(Box::new(stream) as Stream)
        })
    }
}

struct ExternalTorState {
    socks_address: SocketAddr,
    process: TorProcessSupervisor,
    bridge: UpstreamSocksBridge,
    _temporary_directory: Option<tempfile::TempDir>,
}

impl Drop for ExternalTorState {
    fn drop(&mut self) {
        self.process.cancel.cancel();
        self.bridge.cancel.cancel();
        self.bridge.task.abort();
    }
}

struct TorProcessSupervisor {
    cancel: CancellationToken,
    _task: JoinHandle<()>,
}

fn supervise_tor_process(mut child: Child) -> TorProcessSupervisor {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = task_cancel.cancelled() => {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            _ = child.wait() => {}
        }
    });
    TorProcessSupervisor {
        cancel,
        _task: task,
    }
}

impl Drop for TorProcessSupervisor {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct UpstreamSocksBridge {
    address: SocketAddr,
    username: String,
    password: String,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for UpstreamSocksBridge {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

async fn start_upstream_bridge(
    upstream: Arc<dyn Dialer>,
) -> io::Result<UpstreamSocksBridge> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let username = uuid::Uuid::new_v4().simple().to_string();
    let password = uuid::Uuid::new_v4().simple().to_string();
    let users = Arc::new(vec![User {
        username: username.clone(),
        password: password.clone(),
    }]);
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = task_cancel.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else { break };
            let upstream = upstream.clone();
            let users = users.clone();
            tokio::spawn(async move {
                let _ =
                    serve_upstream_connection(stream, upstream, &users).await;
            });
        }
    });
    Ok(UpstreamSocksBridge {
        address,
        username,
        password,
        cancel,
        task,
    })
}

async fn serve_upstream_connection(
    mut client: TcpStream,
    upstream: Arc<dyn Dialer>,
    users: &[User],
) -> io::Result<()> {
    let (destination, _) = server_handshake(&mut client, users).await?;
    let mut remote = match upstream.dial_tcp(&destination).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = write_reply(&mut client, 1, None).await;
            return Err(error);
        }
    };
    write_reply(&mut client, 0, None).await?;
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn start_external_tor(
    upstream: Arc<dyn Dialer>,
    config: &ExternalTorConfig,
) -> io::Result<ExternalTorState> {
    let bridge = start_upstream_bridge(upstream).await?;
    match start_external_tor_with_bridge(config, bridge).await {
        Ok(state) => Ok(state),
        Err((error, bridge)) => {
            bridge.cancel.cancel();
            bridge.task.abort();
            Err(error)
        }
    }
}

async fn start_external_tor_with_bridge(
    config: &ExternalTorConfig,
    bridge: UpstreamSocksBridge,
) -> Result<ExternalTorState, (io::Error, UpstreamSocksBridge)> {
    let prepared = match prepare_external_directory(config).await {
        Ok(prepared) => prepared,
        Err(error) => return Err((error, bridge)),
    };
    let control_file = prepared.directory.join("control-port");
    let control_cookie = prepared.directory.join("control-auth-cookie");
    // A stale endpoint must never be mistaken for the newly launched child.
    match tokio::fs::remove_file(&control_file).await {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err((error, bridge)),
    }

    let mut command = Command::new(if config.executable_path.is_empty() {
        OsString::from("tor")
    } else {
        OsString::from(&config.executable_path)
    });
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.arg("-f").arg(&prepared.torrc_file);
    command.args(external_tor_arguments(
        config,
        &prepared.directory,
        &control_file,
        &control_cookie,
    ));
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Err((error, bridge)),
    };

    let result = async {
        let control_address =
            wait_for_control_address(&mut child, &control_file).await?;
        let cookie =
            wait_for_control_cookie(&mut child, &control_cookie).await?;
        configure_external_tor(
            control_address,
            bridge.address,
            &bridge.username,
            &bridge.password,
            &config.torrc,
            &hex::encode(cookie),
        )
        .await
    }
    .await;
    match result {
        Ok(socks_address) => Ok(ExternalTorState {
            socks_address,
            process: supervise_tor_process(child),
            bridge,
            _temporary_directory: prepared.temporary_directory,
        }),
        Err(error) => {
            let _ = child.start_kill();
            Err((error, bridge))
        }
    }
}

struct PreparedExternalDirectory {
    directory: PathBuf,
    torrc_file: PathBuf,
    temporary_directory: Option<tempfile::TempDir>,
}

async fn prepare_external_directory(
    config: &ExternalTorConfig,
) -> io::Result<PreparedExternalDirectory> {
    let (directory, temporary_directory) = match &config.data_directory {
        Some(directory) => {
            tokio::fs::create_dir_all(directory).await?;
            (directory.clone(), None)
        }
        None => {
            let temporary =
                tempfile::Builder::new().prefix("singbox-tor-").tempdir()?;
            (temporary.path().to_owned(), Some(temporary))
        }
    };
    let torrc_file = directory.join("torrc");
    match tokio::fs::metadata(&torrc_file).await {
        Ok(metadata) if metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Tor configuration path is a directory: {torrc_file:?}"
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            tokio::fs::write(&torrc_file, []).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                tokio::fs::set_permissions(
                    &torrc_file,
                    std::fs::Permissions::from_mode(0o600),
                )
                .await?;
            }
        }
        Err(error) => return Err(error),
    }
    Ok(PreparedExternalDirectory {
        directory,
        torrc_file,
        temporary_directory,
    })
}

fn external_tor_arguments(
    config: &ExternalTorConfig,
    data_directory: &Path,
    control_file: &Path,
    control_cookie: &Path,
) -> Vec<OsString> {
    let mut arguments: Vec<OsString> =
        config.extra_args.iter().map(Into::into).collect();
    let has_geoip =
        config.extra_args.iter().any(|value| value == "--GeoIPFile");
    let has_geoip6 = config
        .extra_args
        .iter()
        .any(|value| value == "--GeoIPv6File");
    let geoip_directory = data_directory
        .canonicalize()
        .unwrap_or_else(|_| data_directory.to_owned());
    for (name, option, configured) in [
        ("geoip", "--GeoIPFile", has_geoip),
        ("geoip6", "--GeoIPv6File", has_geoip6),
    ] {
        let path = geoip_directory.join(name);
        if !configured && path.is_file() {
            arguments.push(option.into());
            arguments.push(path.into_os_string());
        }
    }
    arguments.extend([
        "--DataDirectory".into(),
        data_directory.as_os_str().into(),
        "--ControlPort".into(),
        "auto".into(),
        "--ControlPortWriteToFile".into(),
        control_file.as_os_str().into(),
        "--CookieAuthentication".into(),
        "1".into(),
        "--CookieAuthFile".into(),
        control_cookie.as_os_str().into(),
        "--DisableNetwork".into(),
        "1".into(),
        "--hush".into(),
        "--SocksPort".into(),
        "auto".into(),
    ]);
    arguments
}

async fn wait_for_control_address(
    child: &mut Child,
    control_file: &Path,
) -> io::Result<SocketAddr> {
    tokio::time::timeout(CONTROL_PORT_TIMEOUT, async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "Tor process exited before publishing its control port: {status}"
                )));
            }
            match tokio::fs::read_to_string(control_file).await {
                Ok(value) => return parse_control_address(&value),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for Tor control port"))?
}

async fn wait_for_control_cookie(
    child: &mut Child,
    cookie_file: &Path,
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(CONTROL_PORT_TIMEOUT, async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "Tor process exited before publishing its control cookie: {status}"
                )));
            }
            match tokio::fs::read(cookie_file).await {
                Ok(cookie) if cookie.len() == 32 => return Ok(cookie),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for Tor control cookie",
        )
    })?
}

fn parse_control_address(value: &str) -> io::Result<SocketAddr> {
    value
        .trim()
        .strip_prefix("PORT=")
        .unwrap_or(value.trim())
        .trim_matches('"')
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

async fn configure_external_tor(
    control_address: SocketAddr,
    bridge_address: SocketAddr,
    username: &str,
    password: &str,
    torrc: &HashMap<String, String>,
    authentication: &str,
) -> io::Result<SocketAddr> {
    let stream = TcpStream::connect(control_address).await?;
    let mut control = BufReader::new(stream);
    control_command(&mut control, &format!("AUTHENTICATE {authentication}"))
        .await?;
    control_command(
        &mut control,
        &format!(
            "RESETCONF Socks5Proxy={} Socks5ProxyUsername={} Socks5ProxyPassword={}",
            control_quote(&bridge_address.to_string()),
            control_quote(username),
            control_quote(password),
        ),
    )
    .await?;
    for (key, value) in torrc {
        if matches!(
            key.as_str(),
            "Socks5Proxy" | "Socks5ProxyUsername" | "Socks5ProxyPassword"
        ) {
            continue;
        }
        validate_control_key(key)?;
        control_command(
            &mut control,
            &format!("SETCONF {key}={}", control_quote(value)),
        )
        .await?;
    }
    control_command(&mut control, "SETCONF DisableNetwork=0").await?;
    let reply =
        control_command(&mut control, "GETINFO net/listeners/socks").await?;
    let _ = control_command(&mut control, "QUIT").await;
    parse_socks_listener(&reply)
}

async fn control_command(
    control: &mut BufReader<TcpStream>,
    command: &str,
) -> io::Result<Vec<String>> {
    control.get_mut().write_all(command.as_bytes()).await?;
    control.get_mut().write_all(b"\r\n").await?;
    control.get_mut().flush().await?;
    let mut reply = Vec::new();
    loop {
        let mut line = String::new();
        if control.read_line(&mut line).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Tor control connection closed",
            ));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_owned();
        let code = line.get(..3).and_then(|value| value.parse::<u16>().ok());
        if code.is_some_and(|code| code >= 400) {
            return Err(io::Error::other(format!("Tor control error: {line}")));
        }
        let complete = line.starts_with("250 ");
        reply.push(line);
        if complete {
            return Ok(reply);
        }
    }
}

fn validate_control_key(key: &str) -> io::Result<()> {
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Tor control option name: {key:?}"),
        ));
    }
    Ok(())
}

fn control_quote(value: &str) -> String {
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\r' => quoted.push_str("\\r"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

fn parse_socks_listener(reply: &[String]) -> io::Result<SocketAddr> {
    let value = reply
        .iter()
        .find_map(|line| line.strip_prefix("250-net/listeners/socks="))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Tor did not report a SOCKS listener",
            )
        })?;
    let first = value.split_whitespace().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Tor reported an empty SOCKS listener",
        )
    })?;
    let address: SocketAddr = first
        .trim_matches('"')
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(if address.ip().is_unspecified() {
        SocketAddr::new(
            if address.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            },
            address.port(),
        )
    } else {
        address
    })
}

fn client_config(data_directory: Option<&Path>) -> io::Result<TorClientConfig> {
    match data_directory {
        Some(directory) => TorClientConfigBuilder::from_directories(
            directory.join("state"),
            directory.join("cache"),
        )
        .build()
        .map_err(other),
        None => Ok(TorClientConfig::default()),
    }
}

/// Expand `$NAME` and `${NAME}` using the same missing-variable semantics as
/// Go's `os.ExpandEnv`, without invoking a shell.
pub fn expand_data_directory(path: &str) -> PathBuf {
    let mut output = String::new();
    let mut chars = path.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '$' {
            output.push(character);
            continue;
        }
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }
        let mut name = String::new();
        while let Some(next) = chars.peek().copied() {
            let ended = if braced {
                next == '}'
            } else {
                next != '_' && !next.is_ascii_alphanumeric()
            };
            if ended {
                break;
            }
            name.push(next);
            chars.next();
        }
        if braced && chars.peek() == Some(&'}') {
            chars.next();
        }
        if let Ok(value) = std::env::var(name) {
            output.push_str(&value);
        }
    }
    PathBuf::from(output)
}

#[derive(Clone)]
struct DetourTcpProvider {
    upstream: Arc<dyn Dialer>,
}

/// Arti requires its network streams to be `Sync`, whereas the sing-box
/// stream abstraction only promises `Send`.  A mutex provides the additional
/// shared-reference guarantee; polling still uses exclusive `&mut self`, so it
/// never locks on the data path.
struct DetourTcpStream {
    inner: Mutex<Compat<Stream>>,
}

impl DetourTcpStream {
    fn new(stream: Stream) -> Self {
        Self {
            inner: Mutex::new(stream.compat()),
        }
    }

    fn inner_mut(&mut self) -> &mut Compat<Stream> {
        self.inner
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl AsyncRead for DetourTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.inner_mut()).poll_read(context, buffer)
    }
}

impl AsyncWrite for DetourTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.inner_mut()).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.inner_mut()).poll_flush(context)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.inner_mut()).poll_close(context)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.inner_mut()).poll_write_vectored(context, buffers)
    }
}

impl StreamOps for DetourTcpStream {}

struct UnsupportedTcpListener;

impl NetStreamListener for UnsupportedTcpListener {
    type Stream = DetourTcpStream;
    type Incoming = Empty<io::Result<(Self::Stream, SocketAddr)>>;

    fn incoming(self) -> Self::Incoming {
        stream::empty()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Tor's detour TCP provider does not accept inbound connections",
        ))
    }
}

#[async_trait]
impl NetStreamProvider for DetourTcpProvider {
    type Stream = DetourTcpStream;
    type Listener = UnsupportedTcpListener;

    async fn connect(&self, address: &SocketAddr) -> io::Result<Self::Stream> {
        self.upstream
            .dial_tcp(&SocksAddr::Ip(*address))
            .await
            .map(DetourTcpStream::new)
    }

    async fn listen(
        &self,
        _address: &SocketAddr,
    ) -> io::Result<Self::Listener> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Tor's detour TCP provider does not accept inbound connections",
        ))
    }
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap, ffi::OsString, net::SocketAddr, sync::Arc,
    };

    use tokio::io::{
        AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader,
    };
    use tor_rtcompat::NetStreamProvider;

    use super::{
        DetourTcpProvider, ExternalTorConfig, TorOutbound,
        configure_external_tor, control_quote, expand_data_directory,
        external_tor_arguments, parse_control_address, parse_socks_listener,
        prepare_external_directory, start_upstream_bridge,
        validate_control_key,
    };
    use crate::{
        adapter::{DialFuture, Dialer, Stream},
        common::network::SocksAddr,
    };

    struct MemoryDialer;

    impl Dialer for MemoryDialer {
        fn dial_tcp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            Box::pin(async {
                let (client, mut server) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut request = [0_u8; 4];
                    server.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request, b"ping");
                    server.write_all(b"pong").await.unwrap();
                });
                Ok(Box::new(client) as Stream)
            })
        }
    }

    #[tokio::test]
    async fn arti_tcp_provider_uses_singbox_dialer() {
        let provider = DetourTcpProvider {
            upstream: Arc::new(MemoryDialer),
        };
        let mut stream = provider
            .connect(&"192.0.2.1:9001".parse().unwrap())
            .await
            .unwrap();
        futures::AsyncWriteExt::write_all(&mut stream, b"ping")
            .await
            .unwrap();
        futures::AsyncWriteExt::flush(&mut stream).await.unwrap();
        let mut response = [0_u8; 4];
        futures::AsyncReadExt::read_exact(&mut stream, &mut response)
            .await
            .unwrap();
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn external_tor_bootstrap_bridge_uses_singbox_dialer() {
        let bridge =
            start_upstream_bridge(Arc::new(MemoryDialer)).await.unwrap();
        let mut stream = tokio::net::TcpStream::connect(bridge.address)
            .await
            .unwrap();
        crate::protocol::socks::client_handshake(
            &mut stream,
            &SocksAddr::new("relay.example", 9001),
            Some((&bridge.username, &bridge.password)),
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn creates_unbootstrapped_client_without_network_access() {
        let directory = tempfile::tempdir().unwrap();
        let outbound =
            TorOutbound::new(Arc::new(MemoryDialer), Some(directory.path()));
        outbound.client().await.unwrap();
    }

    #[test]
    fn expands_data_directory_environment() {
        // HOME is expected on all supported desktop platforms and avoids
        // mutating the process environment from a parallel test.
        let home = std::env::var("HOME").unwrap();
        assert_eq!(
            expand_data_directory("$HOME/tor"),
            std::path::PathBuf::from(home).join("tor")
        );
    }

    #[tokio::test]
    async fn prepares_external_torrc_and_geoip_arguments() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("geoip"), b"v4").unwrap();
        std::fs::write(directory.path().join("geoip6"), b"v6").unwrap();
        let config = ExternalTorConfig {
            executable_path: "/usr/bin/tor".into(),
            extra_args: vec!["--UseBridges".into(), "0".into()],
            data_directory: Some(directory.path().to_owned()),
            torrc: HashMap::new(),
        };
        let prepared = prepare_external_directory(&config).await.unwrap();
        assert_eq!(std::fs::read(&prepared.torrc_file).unwrap(), b"");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&prepared.torrc_file)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let control_file = directory.path().join("control-port");
        let control_cookie = directory.path().join("control-auth-cookie");
        let arguments = external_tor_arguments(
            &config,
            directory.path(),
            &control_file,
            &control_cookie,
        );
        let canonical_directory = directory.path().canonicalize().unwrap();
        for expected in [
            OsString::from("--UseBridges"),
            OsString::from("--GeoIPFile"),
            canonical_directory.join("geoip").into_os_string(),
            OsString::from("--GeoIPv6File"),
            canonical_directory.join("geoip6").into_os_string(),
            OsString::from("--ControlPortWriteToFile"),
            control_file.into_os_string(),
            OsString::from("--CookieAuthFile"),
            control_cookie.into_os_string(),
        ] {
            assert!(arguments.contains(&expected), "missing {expected:?}");
        }
    }

    #[test]
    fn parses_and_escapes_tor_control_values() {
        assert_eq!(
            parse_control_address("PORT=127.0.0.1:19051\n").unwrap(),
            "127.0.0.1:19051".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(control_quote("a\\b\n\"c"), "\"a\\\\b\\n\\\"c\"");
        assert!(validate_control_key("NewCircuitPeriod").is_ok());
        assert!(validate_control_key("bad\r\nGETINFO version").is_err());
        assert_eq!(
            parse_socks_listener(&[
                "250-net/listeners/socks=\"0.0.0.0:19050\"".into(),
                "250 OK".into(),
            ])
            .unwrap(),
            "127.0.0.1:19050".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn configures_external_tor_through_control_protocol() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            for expected in [
                "AUTHENTICATE 0123456789abcdef",
                "RESETCONF Socks5Proxy=",
                "SETCONF NewCircuitPeriod=\"30\"",
                "SETCONF DisableNetwork=0",
                "GETINFO net/listeners/socks",
                "QUIT",
            ] {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert!(
                    line.starts_with(expected),
                    "unexpected command: {line:?}"
                );
                if expected.starts_with("GETINFO") {
                    stream
                        .get_mut()
                        .write_all(
                            b"250-net/listeners/socks=\"127.0.0.1:19050\"\r\n250 OK\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    stream.get_mut().write_all(b"250 OK\r\n").await.unwrap();
                }
            }
        });
        let socks_address = configure_external_tor(
            address,
            "127.0.0.1:19080".parse().unwrap(),
            "user",
            "password",
            &HashMap::from([("NewCircuitPeriod".into(), "30".into())]),
            "0123456789abcdef",
        )
        .await
        .unwrap();
        assert_eq!(
            socks_address,
            "127.0.0.1:19050".parse::<SocketAddr>().unwrap()
        );
        server.await.unwrap();
    }
}
