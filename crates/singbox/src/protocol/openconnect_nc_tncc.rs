//! Network Connect TNCC message framing and conservative built-in policy reply.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::Duration,
};
#[cfg(unix)]
use std::{io, os::fd::OwnedFd, path::PathBuf, process::Stdio};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::read::ZlibDecoder;
use http::{Method, StatusCode};
use openssl::{nid::Nid, x509::X509};
use scraper::{Html, Selector};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
#[cfg(unix)]
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::unix::{OwnedReadHalf, OwnedWriteHalf},
    process::{Child, Command},
};
use url::Url;

use super::{AnyConnectAuthHttpClient, AnyConnectAuthHttpRequest};

pub const NETWORK_CONNECT_TNCC_MAXIMUM_HTTP_BODY: usize = 8 * 1024 * 1024;
pub const NETWORK_CONNECT_TNCC_MAXIMUM_DECODED_MESSAGE: usize = 8 * 1024 * 1024;
pub const NETWORK_CONNECT_TNCC_MAXIMUM_PACKET_COUNT: usize = 4096;
pub const NETWORK_CONNECT_TNCC_MAXIMUM_NESTING: usize = 16;
pub const NETWORK_CONNECT_TNCC_POLICY_MESSAGE: u32 = 0x58316;
pub const NETWORK_CONNECT_TNCC_FUNK_PLATFORM_MESSAGE: u32 = 0x58301;
pub const NETWORK_CONNECT_TNCC_FUNK_MESSAGE: u32 = 0xa4c01;
pub const NETWORK_CONNECT_TNCC_COMMAND_MESSAGE: u32 = 0x0013;
pub const NETWORK_CONNECT_TNCC_COMMAND_COMPRESSED: u32 = 0x0016;
pub const NETWORK_CONNECT_TNCC_COMMAND_ENCAPSULATION: u32 = 0x0ce4;
pub const NETWORK_CONNECT_TNCC_COMMAND_STRING_WITH_ID: u32 = 0x0ce7;
pub const NETWORK_CONNECT_TNCC_COMMAND_NESTED: u32 = 0x0cf0;
pub const NETWORK_CONNECT_TNCC_PACKET_CONSTANT: u32 = 0x583;
pub const NETWORK_CONNECT_TNCC_DEFAULT_USER_AGENT: &str = "Neoteris HC Http";
pub const NETWORK_CONNECT_TNCC_WRAPPER_MAXIMUM_LINE: usize = 1024;
pub const NETWORK_CONNECT_TNCC_WRAPPER_OPERATION_TIMEOUT: Duration =
    Duration::from_secs(30);
pub const NETWORK_CONNECT_TNCC_WRAPPER_EXIT_TIMEOUT: Duration =
    Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectTnccString {
    pub identifier: u32,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConnectTnccIdentity {
    pub machine_identification: bool,
    pub platform: String,
    pub hostname: String,
    pub mac_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkConnectTnccCertificate {
    certificate: X509,
    pem_content: String,
}

impl NetworkConnectTnccCertificate {
    pub fn from_pem_bundle(
        content: &[u8],
    ) -> Result<Vec<Self>, NetworkConnectTnccError> {
        let certificates = X509::stack_from_pem(content).map_err(|error| {
            invalid(format!("parse TNCC certificate PEM: {error}"))
        })?;
        if certificates.is_empty() {
            return Err(invalid(
                "TNCC certificate material contains no certificates",
            ));
        }
        certificates
            .into_iter()
            .map(|certificate| {
                let pem_content = String::from_utf8(
                    certificate.to_pem().map_err(|error| {
                        invalid(format!("encode TNCC certificate PEM: {error}"))
                    })?,
                )
                .map_err(|error| {
                    invalid(format!("TNCC PEM is not UTF-8: {error}"))
                })?;
                Ok(Self {
                    certificate,
                    pem_content,
                })
            })
            .collect()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkConnectTnccError {
    #[error("invalid Network Connect TNCC message: {0}")]
    Invalid(String),
    #[error("Network Connect TNCC message exceeds {0} bytes")]
    TooLarge(usize),
    #[error(
        "TNCC requested unmodeled mandatory policy {0}; configure an external TNCC wrapper"
    )]
    UnmodeledMandatoryPolicy(String),
    #[error("decompress Network Connect TNCC message: {0}")]
    Decompression(String),
    #[error("Network Connect TNCC HTTP operation failed: {0}")]
    Http(String),
    #[error("Network Connect TNCC returned HTTP {0}")]
    UnexpectedStatus(StatusCode),
    #[error("Network Connect TNCC response omitted {0}")]
    MissingResponseField(&'static str),
    #[error("invalid Network Connect TNCC base64 message: {0}")]
    Base64(String),
    #[error("invalid Network Connect TNCC interval: {0}")]
    InvalidInterval(String),
    #[error("Network Connect TNCC wrapper failed: {0}")]
    Wrapper(String),
}

/// Stateful built-in TNCC emulator used by Juniper Network Connect.
///
/// The HTTP transport is injected, so callers retain singbox dialer, TLS and
/// address-pinning behavior. The runner keeps its private cookie jar across
/// the initial and periodic posture exchanges.
pub struct NetworkConnectBuiltInTnccRunner {
    http: AnyConnectAuthHttpClient,
    server_url: Url,
    device_id: String,
    identity: NetworkConnectTnccIdentity,
    certificates: Vec<NetworkConnectTnccCertificate>,
    interval: Duration,
}

impl NetworkConnectBuiltInTnccRunner {
    pub fn new(
        mut http: AnyConnectAuthHttpClient,
        server_url: Url,
        cookies: &[(String, String)],
        device_id: impl Into<String>,
        identity: NetworkConnectTnccIdentity,
        certificates: Vec<NetworkConnectTnccCertificate>,
    ) -> Result<Self, NetworkConnectTnccError> {
        if server_url.scheme() != "https" || server_url.host_str().is_none() {
            return Err(NetworkConnectTnccError::Http(
                "built-in TNCC requires an HTTPS gateway URL".into(),
            ));
        }
        for (name, value) in cookies {
            http.set_cookie(&server_url, name, value).map_err(|error| {
                NetworkConnectTnccError::Http(error.to_string())
            })?;
        }
        Ok(Self {
            http,
            server_url,
            device_id: device_id.into(),
            identity,
            certificates,
            interval: Duration::ZERO,
        })
    }

    pub const fn interval(&self) -> Duration {
        self.interval
    }

    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.http.cookie_value(&self.server_url, name)
    }

    pub async fn start(
        &mut self,
        preauthentication_cookie: &str,
        sign_in_url: &str,
    ) -> Result<String, NetworkConnectTnccError> {
        self.set_cookie("DSPREAUTH", preauthentication_cookie)?;
        if !sign_in_url.is_empty() && sign_in_url != "null" {
            self.set_cookie("DSSIGNIN", sign_in_url)?;
        }
        self.exchange().await
    }

    pub async fn refresh(&mut self) -> Result<String, NetworkConnectTnccError> {
        if self.cookie_value("DSPREAUTH").is_none() {
            return Err(NetworkConnectTnccError::MissingResponseField(
                "DSPREAUTH cookie",
            ));
        }
        self.exchange().await
    }

    async fn exchange(&mut self) -> Result<String, NetworkConnectTnccError> {
        let request_message =
            build_network_connect_tncc_initial_message(&self.identity)?;
        let mut first_body = format!(
            "connID=0;timestamp=0;msg={};firsttime=1;",
            STANDARD.encode(request_message)
        );
        if !self.device_id.is_empty() {
            first_body.push_str("deviceid=");
            first_body.push_str(&self.device_id);
            first_body.push(';');
        }
        let first = self.post(first_body.into_bytes()).await?;
        let values = parse_network_connect_tncc_http_response(&first);
        let encoded = values
            .get("msg")
            .filter(|value| !value.is_empty())
            .ok_or(NetworkConnectTnccError::MissingResponseField("msg"))?;
        let message = STANDARD.decode(encoded).map_err(|error| {
            NetworkConnectTnccError::Base64(error.to_string())
        })?;
        let strings = decode_network_connect_tncc_message(&message)?;
        let response_inner = build_network_connect_tncc_response(
            &strings,
            &self.identity,
            &self.certificates,
        )?;
        let mut envelope = encode_network_connect_tncc_packet(
            NETWORK_CONNECT_TNCC_COMMAND_ENCAPSULATION,
            &response_inner,
        )?;
        envelope.extend_from_slice(&encode_network_connect_tncc_packet(
            0x0ce5,
            b"Accept-Language: en",
        )?);
        let response_message = encode_network_connect_tncc_packet(
            NETWORK_CONNECT_TNCC_COMMAND_MESSAGE,
            &envelope,
        )?;
        let second_body = format!(
            "connID=1;msg={};firsttime=1;",
            STANDARD.encode(response_message)
        );
        self.post(second_body.into_bytes()).await?;

        if let Some(interval) = values.get("interval") {
            let minutes = interval.trim().parse::<u64>().map_err(|error| {
                NetworkConnectTnccError::InvalidInterval(error.to_string())
            })?;
            let candidate = Duration::from_secs(minutes.saturating_mul(60));
            if !candidate.is_zero()
                && (self.interval.is_zero() || candidate < self.interval)
            {
                self.interval = candidate;
            }
        }
        self.cookie_value("DSPREAUTH")
            .filter(|value| !value.is_empty())
            .ok_or(NetworkConnectTnccError::MissingResponseField(
                "DSPREAUTH cookie",
            ))
    }

    async fn post(
        &mut self,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, NetworkConnectTnccError> {
        let mut url = self.server_url.clone();
        url.set_path("/dana-na/hc/tnchcupdate.cgi");
        url.set_query(None);
        url.set_fragment(None);
        let response = self
            .http
            .execute(AnyConnectAuthHttpRequest {
                method: Method::POST,
                url,
                content_type: Some("application/x-www-form-urlencoded".into()),
                body,
                xml_post: false,
                xml_post_probe: false,
                authentication_headers: false,
                preserve_cookie_jar_on_redirect: true,
                follow_redirects: false,
            })
            .await
            .map_err(|error| {
                NetworkConnectTnccError::Http(error.to_string())
            })?;
        if response.body.len() > NETWORK_CONNECT_TNCC_MAXIMUM_HTTP_BODY {
            return Err(NetworkConnectTnccError::TooLarge(response.body.len()));
        }
        if !response.status.is_success() {
            return Err(NetworkConnectTnccError::UnexpectedStatus(
                response.status,
            ));
        }
        Ok(response.body)
    }

    fn set_cookie(
        &mut self,
        name: &str,
        value: &str,
    ) -> Result<(), NetworkConnectTnccError> {
        self.http
            .set_cookie(&self.server_url, name, value)
            .map_err(|error| NetworkConnectTnccError::Http(error.to_string()))
    }
}

/// Runtime TNCC implementation selected from the endpoint options.
pub enum NetworkConnectTnccRunner {
    BuiltIn(NetworkConnectBuiltInTnccRunner),
    #[cfg(unix)]
    External(NetworkConnectExternalTnccRunner),
}

impl NetworkConnectTnccRunner {
    pub fn external(
        wrapper_path: impl Into<std::path::PathBuf>,
        gateway_hostname: impl Into<String>,
        local_hostname: impl Into<String>,
        peer_certificate_der: &[u8],
    ) -> Result<Self, NetworkConnectTnccError> {
        #[cfg(unix)]
        {
            NetworkConnectExternalTnccRunner::new(
                wrapper_path,
                gateway_hostname,
                local_hostname,
                peer_certificate_der,
            )
            .map(Self::External)
        }
        #[cfg(not(unix))]
        {
            let _ = (
                wrapper_path,
                gateway_hostname,
                local_hostname,
                peer_certificate_der,
            );
            Err(NetworkConnectTnccError::Wrapper(
                "external TNCC wrapper is unsupported on this platform".into(),
            ))
        }
    }

    pub const fn interval(&self) -> Duration {
        match self {
            Self::BuiltIn(runner) => runner.interval(),
            #[cfg(unix)]
            Self::External(runner) => runner.interval(),
        }
    }

    pub async fn start(
        &mut self,
        preauthentication_cookie: &str,
        sign_in_url: &str,
    ) -> Result<String, NetworkConnectTnccError> {
        match self {
            Self::BuiltIn(runner) => {
                runner.start(preauthentication_cookie, sign_in_url).await
            }
            #[cfg(unix)]
            Self::External(runner) => {
                runner.start(preauthentication_cookie, sign_in_url).await
            }
        }
    }

    pub async fn refresh(&mut self) -> Result<(), NetworkConnectTnccError> {
        match self {
            Self::BuiltIn(runner) => runner.refresh().await.map(|_| ()),
            #[cfg(unix)]
            Self::External(runner) => runner.refresh().await,
        }
    }

    pub fn replace_preauthentication_cookie(
        &mut self,
        cookie: &str,
    ) -> Result<(), NetworkConnectTnccError> {
        match self {
            Self::BuiltIn(runner) => runner.set_cookie("DSPREAUTH", cookie),
            #[cfg(unix)]
            Self::External(runner) => {
                runner.preauthentication_cookie.clear();
                runner.preauthentication_cookie.push_str(cookie);
                Ok(())
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), NetworkConnectTnccError> {
        match self {
            Self::BuiltIn(_) => Ok(()),
            #[cfg(unix)]
            Self::External(runner) => runner.close().await,
        }
    }
}

#[cfg(unix)]
pub struct NetworkConnectExternalTnccRunner {
    wrapper_path: PathBuf,
    gateway_hostname: String,
    local_hostname: String,
    certificate_hash: String,
    reader: Option<BufReader<OwnedReadHalf>>,
    writer: Option<OwnedWriteHalf>,
    child: Option<Child>,
    interval: Duration,
    preauthentication_cookie: String,
    started: bool,
}

#[cfg(unix)]
impl NetworkConnectExternalTnccRunner {
    pub fn new(
        wrapper_path: impl Into<PathBuf>,
        gateway_hostname: impl Into<String>,
        local_hostname: impl Into<String>,
        peer_certificate_der: &[u8],
    ) -> Result<Self, NetworkConnectTnccError> {
        let certificate =
            X509::from_der(peer_certificate_der).map_err(|error| {
                NetworkConnectTnccError::Wrapper(format!(
                    "parse accepted TLS peer certificate: {error}"
                ))
            })?;
        let spki = certificate
            .public_key()
            .and_then(|key| key.public_key_to_der())
            .map_err(|error| {
                NetworkConnectTnccError::Wrapper(format!(
                    "encode accepted TLS peer public key: {error}"
                ))
            })?;
        let certificate_hash = STANDARD.encode(Sha256::digest(spki));
        let wrapper_path = wrapper_path.into();
        if wrapper_path.as_os_str().is_empty() {
            return Err(NetworkConnectTnccError::Wrapper(
                "wrapper path is empty".into(),
            ));
        }
        let gateway_hostname = gateway_hostname.into();
        if gateway_hostname.is_empty() {
            return Err(NetworkConnectTnccError::Wrapper(
                "gateway hostname is empty".into(),
            ));
        }
        Ok(Self {
            wrapper_path,
            gateway_hostname,
            local_hostname: local_hostname.into(),
            certificate_hash,
            reader: None,
            writer: None,
            child: None,
            interval: Duration::ZERO,
            preauthentication_cookie: String::new(),
            started: false,
        })
    }

    pub const fn interval(&self) -> Duration {
        self.interval
    }

    pub async fn start(
        &mut self,
        preauthentication_cookie: &str,
        sign_in_url: &str,
    ) -> Result<String, NetworkConnectTnccError> {
        if self.started {
            return Err(NetworkConnectTnccError::Wrapper(
                "wrapper is already started".into(),
            ));
        }
        self.start_process().await?;
        self.started = true;
        let command = format!(
            "start\nIC={}\nCookie={}\nDSSIGNIN={}\n",
            self.gateway_hostname, preauthentication_cookie, sign_in_url
        );
        self.write_command(command.as_bytes()).await?;
        let status = self.read_line().await?;
        if status != "200" {
            return Err(NetworkConnectTnccError::Wrapper(format!(
                "wrapper returned status {status}"
            )));
        }
        let _message = self.read_line().await?;
        let cookie = self.read_line().await?;
        if cookie.is_empty() {
            return Err(NetworkConnectTnccError::Wrapper(
                "wrapper returned an empty DSPREAUTH cookie".into(),
            ));
        }
        self.preauthentication_cookie.clone_from(&cookie);
        let interval = self.read_line().await?;
        if !interval.is_empty() {
            let seconds = interval.trim().parse::<u64>().map_err(|error| {
                NetworkConnectTnccError::InvalidInterval(error.to_string())
            })?;
            self.interval = Duration::from_secs(seconds);
        }
        for line_number in 0..=10 {
            let line = self.read_line().await?;
            if line.is_empty() {
                return Ok(cookie);
            }
            if line_number == 10 {
                return Err(NetworkConnectTnccError::Wrapper(
                    "wrapper returned too many response lines".into(),
                ));
            }
        }
        unreachable!("bounded response loop returns")
    }

    pub async fn refresh(&mut self) -> Result<(), NetworkConnectTnccError> {
        if !self.started {
            return Err(NetworkConnectTnccError::Wrapper(
                "wrapper is not started".into(),
            ));
        }
        if self.preauthentication_cookie.is_empty() {
            return Err(NetworkConnectTnccError::Wrapper(
                "periodic refresh requires a DSPREAUTH cookie".into(),
            ));
        }
        let cookie = self.preauthentication_cookie.clone();
        self.set_cookie(&cookie).await
    }

    pub async fn set_cookie(
        &mut self,
        preauthentication_cookie: &str,
    ) -> Result<(), NetworkConnectTnccError> {
        if !self.started {
            return Err(NetworkConnectTnccError::Wrapper(
                "wrapper is not started".into(),
            ));
        }
        self.write_command(
            format!("setcookie\nCookie={preauthentication_cookie}\n")
                .as_bytes(),
        )
        .await?;
        self.preauthentication_cookie.clear();
        self.preauthentication_cookie
            .push_str(preauthentication_cookie);
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), NetworkConnectTnccError> {
        self.reader.take();
        if let Some(mut writer) = self.writer.take() {
            let _ = writer.shutdown().await;
        }
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        match tokio::time::timeout(
            NETWORK_CONNECT_TNCC_WRAPPER_EXIT_TIMEOUT,
            child.wait(),
        )
        .await
        {
            Ok(result) => result.map(|_| ()).map_err(|error| {
                NetworkConnectTnccError::Wrapper(format!(
                    "wait for wrapper: {error}"
                ))
            }),
            Err(_) => {
                child.kill().await.map_err(|error| {
                    NetworkConnectTnccError::Wrapper(format!(
                        "kill wrapper: {error}"
                    ))
                })?;
                child.wait().await.map(|_| ()).map_err(|error| {
                    NetworkConnectTnccError::Wrapper(format!(
                        "reap wrapper: {error}"
                    ))
                })
            }
        }
    }

    async fn start_process(&mut self) -> Result<(), NetworkConnectTnccError> {
        let (parent, child_socket) = tokio::net::UnixStream::pair()
            .map_err(wrapper_io("create wrapper socket pair"))?;
        let child_socket = child_socket
            .into_std()
            .map_err(wrapper_io("convert wrapper child socket"))?;
        // Tokio sockets are non-blocking.  The external TNCC wrapper receives
        // this endpoint as fd 0 and commonly uses a POSIX shell `read` loop;
        // leaving O_NONBLOCK set makes that loop observe EAGAIN between
        // commands as if stdin had ended.
        child_socket
            .set_nonblocking(false)
            .map_err(wrapper_io("prepare wrapper child socket"))?;
        let child_fd = OwnedFd::from(child_socket);
        let mut command = Command::new(&self.wrapper_path);
        command
            .arg(&self.gateway_hostname)
            .stdin(Stdio::from(child_fd))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("TNCC_SHA256")
            .env_remove("TNCC_HOSTNAME")
            .env_remove("TNCC_INTERVAL")
            .env("TNCC_SHA256", &self.certificate_hash)
            .env("TNCC_HOSTNAME", &self.local_hostname)
            .env("TNCC_INTERVAL", "0")
            .kill_on_drop(true);
        let child = command
            .spawn()
            .map_err(wrapper_io("start external TNCC wrapper"))?;
        let (reader, writer) = parent.into_split();
        self.reader = Some(BufReader::new(reader));
        self.writer = Some(writer);
        self.child = Some(child);
        Ok(())
    }

    fn ensure_running(&mut self) -> Result<(), NetworkConnectTnccError> {
        if let Some(child) = self.child.as_mut()
            && let Some(status) = child
                .try_wait()
                .map_err(wrapper_io("inspect external TNCC wrapper"))?
        {
            return Err(NetworkConnectTnccError::Wrapper(format!(
                "wrapper exited unexpectedly with {status}"
            )));
        }
        Ok(())
    }

    async fn write_command(
        &mut self,
        command: &[u8],
    ) -> Result<(), NetworkConnectTnccError> {
        self.ensure_running()?;
        let writer = self.writer.as_mut().ok_or_else(|| {
            NetworkConnectTnccError::Wrapper("wrapper socket is absent".into())
        })?;
        tokio::time::timeout(
            NETWORK_CONNECT_TNCC_WRAPPER_OPERATION_TIMEOUT,
            async {
                writer.write_all(command).await?;
                writer.flush().await
            },
        )
        .await
        .map_err(|_| {
            NetworkConnectTnccError::Wrapper(
                "wrapper command write timed out".into(),
            )
        })?
        .map_err(wrapper_io("write external TNCC wrapper command"))
    }

    async fn read_line(&mut self) -> Result<String, NetworkConnectTnccError> {
        self.ensure_running()?;
        let reader = self.reader.as_mut().ok_or_else(|| {
            NetworkConnectTnccError::Wrapper("wrapper socket is absent".into())
        })?;
        let mut line = Vec::new();
        let length = tokio::time::timeout(
            NETWORK_CONNECT_TNCC_WRAPPER_OPERATION_TIMEOUT,
            reader.read_until(b'\n', &mut line),
        )
        .await
        .map_err(|_| {
            NetworkConnectTnccError::Wrapper(
                "wrapper response read timed out".into(),
            )
        })?
        .map_err(wrapper_io("read external TNCC wrapper response"))?;
        if length == 0 {
            return Err(NetworkConnectTnccError::Wrapper(
                "wrapper response ended unexpectedly".into(),
            ));
        }
        if line.len() > NETWORK_CONNECT_TNCC_WRAPPER_MAXIMUM_LINE {
            return Err(NetworkConnectTnccError::Wrapper(format!(
                "wrapper response line exceeds {NETWORK_CONNECT_TNCC_WRAPPER_MAXIMUM_LINE} bytes"
            )));
        }
        if line.ends_with(b"\n") {
            line.pop();
        }
        if line.ends_with(b"\r") {
            line.pop();
        }
        String::from_utf8(line).map_err(|error| {
            NetworkConnectTnccError::Wrapper(format!(
                "wrapper response is not UTF-8: {error}"
            ))
        })
    }
}

#[cfg(unix)]
fn wrapper_io(
    operation: &'static str,
) -> impl FnOnce(io::Error) -> NetworkConnectTnccError {
    move |error| {
        NetworkConnectTnccError::Wrapper(format!("{operation}: {error}"))
    }
}

/// Parse the line-oriented response emitted by `tnchcupdate.cgi`. A wrapped
/// base64 `msg` value is concatenated in the same way as the upstream client.
pub fn parse_network_connect_tncc_http_response(
    content: &[u8],
) -> BTreeMap<String, String> {
    let normalized = String::from_utf8_lossy(content).replace("\r\n", "\n");
    let mut values = BTreeMap::new();
    let mut last_key = String::new();
    for line in normalized.lines() {
        let line = line.trim();
        if line.is_empty() {
            last_key.clear();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                values.insert(key.to_owned(), value.trim().to_owned());
                last_key = key.to_owned();
            }
        } else if last_key == "msg" {
            values
                .entry(last_key.clone())
                .and_modify(|value| value.push_str(line));
        }
    }
    values
}

pub fn encode_network_connect_tncc_packet(
    command: u32,
    payload: &[u8],
) -> Result<Vec<u8>, NetworkConnectTnccError> {
    let packet_length = 12_usize
        .checked_add(payload.len())
        .ok_or_else(|| too_large(usize::MAX))?;
    if packet_length > u16::MAX as usize {
        return Err(too_large(packet_length));
    }
    let padded_length = packet_length
        .checked_add(3)
        .map(|length| length & !3)
        .ok_or_else(|| too_large(packet_length))?;
    let mut packet = vec![0; padded_length];
    packet[..4].copy_from_slice(&command.to_be_bytes());
    packet[4] = 0xc0;
    packet[6..8].copy_from_slice(&(packet_length as u16).to_be_bytes());
    packet[8..12]
        .copy_from_slice(&NETWORK_CONNECT_TNCC_PACKET_CONSTANT.to_be_bytes());
    packet[12..packet_length].copy_from_slice(payload);
    Ok(packet)
}

pub fn encode_network_connect_tncc_string(
    identifier: u32,
    content: &[u8],
) -> Result<Vec<u8>, NetworkConnectTnccError> {
    let mut payload = Vec::with_capacity(content.len() + 6);
    payload.extend_from_slice(&identifier.to_be_bytes());
    payload.extend_from_slice(content);
    payload.extend_from_slice(&[0, 0]);
    encode_network_connect_tncc_packet(
        NETWORK_CONNECT_TNCC_COMMAND_STRING_WITH_ID,
        &payload,
    )
}

pub fn build_network_connect_tncc_initial_message(
    identity: &NetworkConnectTnccIdentity,
) -> Result<Vec<u8>, NetworkConnectTnccError> {
    let policy_request = concat!(
        "<parameter name=\"policy_request\" value=\"message_version=3;\">",
        "<parameter name=\"esap\" value=\"esap_version=NOT_AVAILABLE;fileinfo=NOT_AVAILABLE;has_file_versions=YES;needs_exact_sdk=YES;opswat_sdk_version=3;\">",
        "<parameter name=\"system_info\" value=\"os_version=2.6.2;sp_version=0;hc_mode=userMode;\">"
    );
    let mut inner =
        encode_network_connect_tncc_string(0xa4c18, policy_request.as_bytes())?;
    inner.extend_from_slice(&encode_network_connect_tncc_string(
        NETWORK_CONNECT_TNCC_POLICY_MESSAGE,
        b"policy request\0v4",
    )?);
    if identity.machine_identification {
        inner.extend_from_slice(&encode_network_connect_tncc_string(
            NETWORK_CONNECT_TNCC_FUNK_PLATFORM_MESSAGE,
            funk_platform_document(identity).as_bytes(),
        )?);
        inner.extend_from_slice(&encode_network_connect_tncc_string(
            NETWORK_CONNECT_TNCC_FUNK_MESSAGE,
            funk_present_document(identity).as_bytes(),
        )?);
    }
    let mut outer = encode_network_connect_tncc_packet(
        NETWORK_CONNECT_TNCC_COMMAND_ENCAPSULATION,
        &inner,
    )?;
    outer.extend_from_slice(&encode_network_connect_tncc_packet(
        0x0ce5,
        b"Accept-Language: en",
    )?);
    outer.extend_from_slice(&encode_network_connect_tncc_packet(
        NETWORK_CONNECT_TNCC_COMMAND_MESSAGE,
        &1_u32.to_le_bytes(),
    )?);
    encode_network_connect_tncc_packet(
        NETWORK_CONNECT_TNCC_COMMAND_MESSAGE,
        &outer,
    )
}

pub fn decode_network_connect_tncc_message(
    content: &[u8],
) -> Result<Vec<NetworkConnectTnccString>, NetworkConnectTnccError> {
    let mut state = DecodeState::default();
    decode_packets(content, 0, &mut state)?;
    Ok(state.strings)
}

/// Build the policy part of a built-in TNCC response. The emulator only
/// models explicit deny/unsupported policies; every unknown mandatory policy
/// fails closed and requires the external wrapper.
pub fn build_network_connect_tncc_policy_response(
    strings: &[NetworkConnectTnccString],
) -> Result<Vec<u8>, NetworkConnectTnccError> {
    let mut policies = BTreeSet::new();
    for item in strings {
        if item.identifier == NETWORK_CONNECT_TNCC_POLICY_MESSAGE {
            policies.extend(parse_policy_names(&item.content)?);
        }
    }
    let mut response = String::new();
    for policy in policies {
        response.push_str("\npolicy:");
        response.push_str(&policy);
        response.push_str("\nstatus:");
        if policy.contains("Unsupported") || policy.contains("Deny") {
            response.push_str("NOTOK\nerror:Unknown error");
        } else {
            return Err(NetworkConnectTnccError::UnmodeledMandatoryPolicy(
                policy,
            ));
        }
    }
    encode_network_connect_tncc_string(
        NETWORK_CONNECT_TNCC_POLICY_MESSAGE,
        response.as_bytes(),
    )
}

/// Build a complete built-in TNCC reply, including requested Funk machine
/// certificates and the policy result.
pub fn build_network_connect_tncc_response(
    strings: &[NetworkConnectTnccString],
    identity: &NetworkConnectTnccIdentity,
    certificates: &[NetworkConnectTnccCertificate],
) -> Result<Vec<u8>, NetworkConnectTnccError> {
    let mut response = Vec::new();
    let mut requests = BTreeMap::<String, BTreeMap<String, String>>::new();
    for item in strings {
        if item.identifier == NETWORK_CONNECT_TNCC_FUNK_MESSAGE {
            requests.extend(parse_funk_certificate_requests(&item.content)?);
        }
    }
    if !requests.is_empty() {
        if !identity.machine_identification {
            return Err(NetworkConnectTnccError::UnmodeledMandatoryPolicy(
                "machine certificate request (machine identification disabled)"
                    .into(),
            ));
        }
        let document =
            funk_certificate_response(identity, certificates, &requests)?;
        response.extend_from_slice(&encode_network_connect_tncc_string(
            NETWORK_CONNECT_TNCC_FUNK_MESSAGE,
            document.as_bytes(),
        )?);
    }
    response.extend_from_slice(&build_network_connect_tncc_policy_response(
        strings,
    )?);
    Ok(response)
}

fn parse_funk_certificate_requests(
    content: &[u8],
) -> Result<BTreeMap<String, BTreeMap<String, String>>, NetworkConnectTnccError>
{
    if !content
        .windows("AttributeRequest".len())
        .any(|window| window.eq_ignore_ascii_case(b"AttributeRequest"))
    {
        return Ok(BTreeMap::new());
    }
    let document = Html::parse_fragment(&String::from_utf8_lossy(content));
    let certificate_selector =
        Selector::parse("certdata").map_err(|error| {
            invalid(format!("TNCC certificate selector: {error}"))
        })?;
    let attribute_selector = Selector::parse("attribute").map_err(|error| {
        invalid(format!("TNCC attribute selector: {error}"))
    })?;
    let mut requests = BTreeMap::new();
    for certificate in document.select(&certificate_selector) {
        let identifier = certificate
            .value()
            .attr("id")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("TNCC certificate request has no ID"))?;
        let mut issuer = BTreeMap::new();
        for attribute in certificate.select(&attribute_selector) {
            let name = attribute.value().attr("name").unwrap_or_default();
            let kind = attribute.value().attr("type").unwrap_or_default();
            if name != "IssuerDN" || kind != "DN" {
                return Err(NetworkConnectTnccError::UnmodeledMandatoryPolicy(
                    format!("certificate attribute {name}/{kind}"),
                ));
            }
            for component in attribute
                .value()
                .attr("value")
                .unwrap_or_default()
                .split(',')
            {
                let (name, value) = component
                    .trim()
                    .split_once('=')
                    .filter(|(name, value)| {
                        !name.is_empty() && !value.is_empty()
                    })
                    .ok_or_else(|| {
                        invalid("TNCC certificate issuer request is malformed")
                    })?;
                issuer.insert(name.to_owned(), value.to_owned());
            }
        }
        requests.insert(identifier.to_owned(), issuer);
    }
    Ok(requests)
}

fn funk_certificate_response(
    identity: &NetworkConnectTnccIdentity,
    certificates: &[NetworkConnectTnccCertificate],
    requests: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<String, NetworkConnectTnccError> {
    let mut matched = BTreeMap::new();
    for (identifier, issuer) in requests {
        let certificate = certificates
            .iter()
            .find(|certificate| certificate_matches_issuer(certificate, issuer))
            .ok_or_else(|| {
                NetworkConnectTnccError::UnmodeledMandatoryPolicy(format!(
                    "unsatisfied certificate request {identifier}"
                ))
            })?;
        matched.insert(identifier, certificate);
    }
    let platform = escape_xml_attribute(&identity.platform);
    let mut document = format!(
        "<FunkMessage VendorID='2636' ProductID='1' Version='1' Platform='{platform}' ClientType='Agentless'> <ClientAttributes SequenceID='0'> <Attribute Name='Platform' Value='{platform}' />"
    );
    for (identifier, certificate) in matched {
        for _ in 0..2 {
            document.push_str(" <Attribute Name='");
            document.push_str(&escape_xml_attribute(identifier));
            document.push_str("' Value='");
            document.push_str(&escape_xml_attribute(
                certificate.pem_content.trim(),
            ));
            document.push_str("' />");
        }
    }
    document.push_str("</ClientAttributes>  </FunkMessage>");
    Ok(document)
}

fn certificate_matches_issuer(
    certificate: &NetworkConnectTnccCertificate,
    expected: &BTreeMap<String, String>,
) -> bool {
    expected.iter().all(|(expected_name, expected_value)| {
        certificate
            .certificate
            .issuer_name()
            .entries()
            .any(|entry| {
                let nid = entry.object().nid();
                let name_matches = nid_oid(nid) == Some(expected_name.as_str())
                    || nid.short_name().is_ok_and(|name| name == expected_name)
                    || nid.long_name().is_ok_and(|name| name == expected_name);
                name_matches
                    && entry
                        .data()
                        .to_string()
                        .is_ok_and(|value| value == *expected_value)
            })
    })
}

const fn nid_oid(nid: Nid) -> Option<&'static str> {
    match nid {
        Nid::COMMONNAME => Some("2.5.4.3"),
        Nid::COUNTRYNAME => Some("2.5.4.6"),
        Nid::LOCALITYNAME => Some("2.5.4.7"),
        Nid::STATEORPROVINCENAME => Some("2.5.4.8"),
        Nid::ORGANIZATIONNAME => Some("2.5.4.10"),
        Nid::ORGANIZATIONALUNITNAME => Some("2.5.4.11"),
        Nid::PKCS9_EMAILADDRESS => Some("1.2.840.113549.1.9.1"),
        _ => None,
    }
}

#[derive(Default)]
struct DecodeState {
    strings: Vec<NetworkConnectTnccString>,
    packet_count: usize,
}

fn decode_packets(
    content: &[u8],
    depth: usize,
    state: &mut DecodeState,
) -> Result<(), NetworkConnectTnccError> {
    if depth > NETWORK_CONNECT_TNCC_MAXIMUM_NESTING {
        return Err(invalid(format!(
            "nesting exceeds {NETWORK_CONNECT_TNCC_MAXIMUM_NESTING}"
        )));
    }
    let mut position = 0;
    while position < content.len() {
        if content.len() - position < 12 {
            if content[position..].iter().any(|byte| *byte != 0) {
                return Err(invalid("truncated packet header"));
            }
            return Ok(());
        }
        state.packet_count += 1;
        if state.packet_count > NETWORK_CONNECT_TNCC_MAXIMUM_PACKET_COUNT {
            return Err(invalid("message contains too many packets"));
        }
        let command = u32::from_be_bytes(
            content[position..position + 4].try_into().unwrap(),
        );
        let packet_length = usize::from(u16::from_be_bytes([
            content[position + 6],
            content[position + 7],
        ]));
        if packet_length < 12 || packet_length > content.len() - position {
            return Err(invalid(format!(
                "packet has an invalid length: {packet_length}"
            )));
        }
        let padded_length = (packet_length + 3) & !3;
        if padded_length > content.len() - position {
            return Err(invalid("packet padding exceeds its container"));
        }
        let payload = &content[position + 12..position + packet_length];
        match command {
            NETWORK_CONNECT_TNCC_COMMAND_MESSAGE => {
                if payload.len() >= 12 {
                    decode_packets(payload, depth + 1, state)?;
                }
            }
            NETWORK_CONNECT_TNCC_COMMAND_ENCAPSULATION
            | NETWORK_CONNECT_TNCC_COMMAND_NESTED => {
                decode_packets(payload, depth + 1, state)?;
            }
            NETWORK_CONNECT_TNCC_COMMAND_COMPRESSED => {
                if payload.len() < 4 {
                    return Err(invalid("compressed packet is too short"));
                }
                let decoded = decompress(&payload[4..])?;
                decode_packets(&decoded, depth + 1, state)?;
            }
            NETWORK_CONNECT_TNCC_COMMAND_STRING_WITH_ID => {
                if payload.len() < 4 {
                    return Err(invalid("identified string is too short"));
                }
                let identifier =
                    u32::from_be_bytes(payload[..4].try_into().unwrap());
                let mut string_content = trim_zero(&payload[4..]).to_vec();
                if string_content.starts_with(b"COMPRESSED:") {
                    let mut parts =
                        string_content.splitn(3, |byte| *byte == b':');
                    let _ = parts.next();
                    let _ = parts.next();
                    let compressed = parts.next().ok_or_else(|| {
                        invalid("compressed string has no payload")
                    })?;
                    string_content = decompress(compressed)?;
                }
                state.strings.push(NetworkConnectTnccString {
                    identifier,
                    content: string_content,
                });
            }
            _ => {}
        }
        position += padded_length;
    }
    Ok(())
}

fn decompress(content: &[u8]) -> Result<Vec<u8>, NetworkConnectTnccError> {
    let mut decoder = ZlibDecoder::new(content);
    let mut decoded = Vec::new();
    decoder
        .by_ref()
        .take((NETWORK_CONNECT_TNCC_MAXIMUM_DECODED_MESSAGE + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|error| {
            NetworkConnectTnccError::Decompression(error.to_string())
        })?;
    if decoded.len() > NETWORK_CONNECT_TNCC_MAXIMUM_DECODED_MESSAGE {
        return Err(too_large(decoded.len()));
    }
    Ok(decoded)
}

fn parse_policy_names(
    content: &[u8],
) -> Result<BTreeSet<String>, NetworkConnectTnccError> {
    let lower = content
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if !lower.windows(6).any(|window| window == b"<param") {
        return Ok(BTreeSet::new());
    }
    let document = Html::parse_document(&String::from_utf8_lossy(content));
    let selector = Selector::parse("param")
        .map_err(|error| invalid(format!("policy selector: {error}")))?;
    let mut policies = BTreeSet::new();
    for node in document.select(&selector) {
        let value = node.value().attr("value").unwrap_or_default();
        for field in value.split(';') {
            let Some((name, value)) = field.trim().split_once('=') else {
                continue;
            };
            let value = value.trim();
            if name == "policy" && !value.is_empty() {
                policies.insert(value.to_owned());
            }
        }
    }
    Ok(policies)
}

fn funk_platform_document(identity: &NetworkConnectTnccIdentity) -> String {
    let platform = escape_xml_attribute(&identity.platform);
    let mut document = format!(
        "<FunkMessage VendorID='2636' ProductID='1' Version='1' Platform='{platform}' ClientType='Agentless'> <ClientAttributes SequenceID='-1'> <Attribute Name='Platform' Value='{platform}' />"
    );
    if !identity.hostname.is_empty() {
        document.push_str(" <Attribute Name='");
        document.push_str(&escape_xml_attribute(&identity.hostname));
        document.push_str("' Value='NETBIOSName' />");
    }
    for address in &identity.mac_addresses {
        document.push_str(" <Attribute Name='");
        document.push_str(&escape_xml_attribute(address));
        document.push_str("' Value='MACAddress' />");
    }
    document.push_str("</ClientAttributes>  </FunkMessage>");
    document
}

fn funk_present_document(identity: &NetworkConnectTnccIdentity) -> String {
    format!(
        "<FunkMessage VendorID='2636' ProductID='1' Version='1' Platform='{}' ClientType='Agentless'> <Present SequenceID='0'></Present>  </FunkMessage>",
        escape_xml_attribute(&identity.platform)
    )
}

fn escape_xml_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

fn trim_zero(content: &[u8]) -> &[u8] {
    let end = content
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    &content[..end]
}

fn invalid(message: impl Into<String>) -> NetworkConnectTnccError {
    NetworkConnectTnccError::Invalid(message.into())
}

fn too_large(size: usize) -> NetworkConnectTnccError {
    NetworkConnectTnccError::TooLarge(size)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use flate2::{Compression, write::ZlibEncoder};
    use http::{HeaderMap, HeaderValue, Request, header::SET_COOKIE};

    use super::*;
    use crate::protocol::openconnect::{
        AnyConnectAuthHttpTransport, AnyConnectAuthRawHttpResponse,
    };

    struct TnccTransport {
        responses: Mutex<Vec<AnyConnectAuthRawHttpResponse>>,
        requests: Mutex<Vec<Request<Vec<u8>>>>,
    }

    #[async_trait]
    impl AnyConnectAuthHttpTransport for TnccTransport {
        async fn execute(
            &self,
            request: Request<Vec<u8>>,
        ) -> io::Result<AnyConnectAuthRawHttpResponse> {
            self.requests.lock().unwrap().push(request);
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no TNCC response",
                ));
            }
            Ok(responses.remove(0))
        }
    }

    #[test]
    fn packet_and_identified_string_match_wire_layout() {
        let packet =
            encode_network_connect_tncc_string(0x0102_0304, b"ok").unwrap();
        assert_eq!(&packet[..4], &0x0ce7_u32.to_be_bytes());
        assert_eq!(packet[4], 0xc0);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 20);
        assert_eq!(&packet[8..12], &0x583_u32.to_be_bytes());
        assert_eq!(&packet[12..16], &0x0102_0304_u32.to_be_bytes());
        assert_eq!(&packet[16..18], b"ok");
        assert_eq!(
            decode_network_connect_tncc_message(&packet).unwrap(),
            [NetworkConnectTnccString {
                identifier: 0x0102_0304,
                content: b"ok".to_vec(),
            }]
        );
    }

    #[test]
    fn decodes_nested_and_compressed_packets() {
        let inner =
            encode_network_connect_tncc_string(7, b"compressed").unwrap();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&inner).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut payload = vec![0, 0, 0, 0];
        payload.extend_from_slice(&compressed);
        let packet = encode_network_connect_tncc_packet(
            NETWORK_CONNECT_TNCC_COMMAND_COMPRESSED,
            &payload,
        )
        .unwrap();
        let outer = encode_network_connect_tncc_packet(
            NETWORK_CONNECT_TNCC_COMMAND_ENCAPSULATION,
            &packet,
        )
        .unwrap();
        assert_eq!(
            decode_network_connect_tncc_message(&outer).unwrap()[0].content,
            b"compressed"
        );
    }

    #[test]
    fn parses_wrapped_http_message_and_interval() {
        let values = parse_network_connect_tncc_http_response(
            b"msg=YWJj\r\n ZGVm\r\ninterval=5\r\n",
        );
        assert_eq!(values["msg"], "YWJjZGVm");
        assert_eq!(values["interval"], "5");
    }

    #[test]
    fn initial_message_contains_machine_identity_when_enabled() {
        let message = build_network_connect_tncc_initial_message(
            &NetworkConnectTnccIdentity {
                machine_identification: true,
                platform: "mac<&>".to_owned(),
                hostname: "zay-host".to_owned(),
                mac_addresses: vec!["00:11:22:33:44:55".to_owned()],
            },
        )
        .unwrap();
        let decoded = decode_network_connect_tncc_message(&message).unwrap();
        assert!(decoded.iter().any(|value| {
            value.identifier == NETWORK_CONNECT_TNCC_FUNK_PLATFORM_MESSAGE
                && String::from_utf8_lossy(&value.content)
                    .contains("Platform='mac&lt;&amp;&gt;'")
        }));
    }

    #[test]
    fn built_in_policy_response_fails_closed() {
        let denied = NetworkConnectTnccString {
            identifier: NETWORK_CONNECT_TNCC_POLICY_MESSAGE,
            content: br#"<param value="policy=Unsupported Antivirus;">"#
                .to_vec(),
        };
        let response =
            build_network_connect_tncc_policy_response(&[denied]).unwrap();
        let decoded = decode_network_connect_tncc_message(&response).unwrap();
        assert!(String::from_utf8_lossy(&decoded[0].content).contains("NOTOK"));

        let required = NetworkConnectTnccString {
            identifier: NETWORK_CONNECT_TNCC_POLICY_MESSAGE,
            content: br#"<param value="policy=Require Antivirus;">"#.to_vec(),
        };
        assert!(matches!(
            build_network_connect_tncc_policy_response(&[required]),
            Err(NetworkConnectTnccError::UnmodeledMandatoryPolicy(_))
        ));
    }

    #[test]
    fn built_in_response_satisfies_funk_certificate_request() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut parameters = rcgen::CertificateParams::default();
        parameters.distinguished_name = rcgen::DistinguishedName::new();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        let certificate = parameters.self_signed(&key).unwrap();
        let certificates = NetworkConnectTnccCertificate::from_pem_bundle(
            certificate.pem().as_bytes(),
        )
        .unwrap();
        let request = NetworkConnectTnccString {
            identifier: NETWORK_CONNECT_TNCC_FUNK_MESSAGE,
            content: br#"<FunkMessage><AttributeRequest><CertData Id='cert-1'><Attribute Name='IssuerDN' Type='DN' Value='2.5.4.3=Example CA'/></CertData></AttributeRequest></FunkMessage>"#.to_vec(),
        };
        let response = build_network_connect_tncc_response(
            &[request],
            &NetworkConnectTnccIdentity {
                machine_identification: true,
                platform: "linux".into(),
                ..Default::default()
            },
            &certificates,
        )
        .unwrap();
        let decoded = decode_network_connect_tncc_message(&response).unwrap();
        let funk = decoded
            .iter()
            .find(|item| item.identifier == NETWORK_CONNECT_TNCC_FUNK_MESSAGE)
            .unwrap();
        let document = String::from_utf8_lossy(&funk.content);
        assert_eq!(document.matches("Name='cert-1'").count(), 2);
        assert!(document.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn built_in_runner_performs_two_posts_and_tracks_cookie_interval() {
        let request_string =
            encode_network_connect_tncc_string(0x1122, b"hello").unwrap();
        let first_body =
            format!("msg={}\ninterval=2\n", STANDARD.encode(request_string))
                .into_bytes();
        let mut second_headers = HeaderMap::new();
        second_headers.insert(
            SET_COOKIE,
            HeaderValue::from_static(
                "DSPREAUTH=refreshed; Path=/; Secure; HttpOnly",
            ),
        );
        let transport = Arc::new(TnccTransport {
            responses: Mutex::new(vec![
                AnyConnectAuthRawHttpResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: first_body,
                    authenticated_address: Some("192.0.2.10".parse().unwrap()),
                    peer_certificate_der: None,
                },
                AnyConnectAuthRawHttpResponse {
                    status: StatusCode::OK,
                    headers: second_headers,
                    body: Vec::new(),
                    authenticated_address: Some("192.0.2.10".parse().unwrap()),
                    peer_certificate_der: None,
                },
            ]),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(
            transport.clone(),
            NETWORK_CONNECT_TNCC_DEFAULT_USER_AGENT,
        );
        let mut runner = NetworkConnectBuiltInTnccRunner::new(
            http,
            Url::parse("https://vpn.example/login").unwrap(),
            &[("existing".into(), "cookie".into())],
            "device-1",
            NetworkConnectTnccIdentity::default(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            runner.start("initial", "/signin").await.unwrap(),
            "refreshed"
        );
        assert_eq!(runner.interval(), Duration::from_secs(120));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].uri().path(), "/dana-na/hc/tnchcupdate.cgi");
        let initial = String::from_utf8_lossy(requests[0].body());
        assert!(initial.starts_with("connID=0;timestamp=0;msg="));
        assert!(initial.ends_with(";firsttime=1;deviceid=device-1;"));
        let response = String::from_utf8_lossy(requests[1].body());
        assert!(response.starts_with("connID=1;msg="));
        assert!(response.ends_with(";firsttime=1;"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn external_runner_uses_full_duplex_fd_zero_protocol() {
        use std::{fs, os::unix::fs::PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let wrapper = directory.path().join("tncc-wrapper.sh");
        fs::write(
            &wrapper,
            concat!(
                "#!/bin/sh\n",
                "IFS= read -r command\n",
                "IFS= read -r gateway\n",
                "IFS= read -r cookie\n",
                "IFS= read -r signin\n",
                "test \"$command\" = start || exit 2\n",
                "test \"$gateway\" = IC=vpn.example || exit 3\n",
                "printf '200\\nmessage\\nupdated-cookie\\n7\\n\\n' >&0\n",
                "IFS= read -r command\n",
                "IFS= read -r cookie\n",
                "test \"$command\" = setcookie || exit 4\n",
                "test \"$cookie\" = Cookie=periodic-cookie || exit 5\n",
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&wrapper, permissions).unwrap();

        let certified =
            rcgen::generate_simple_self_signed(vec!["vpn.example".into()])
                .unwrap();
        let mut runner = NetworkConnectExternalTnccRunner::new(
            wrapper,
            "vpn.example",
            "zay-host",
            certified.cert.der().as_ref(),
        )
        .unwrap();
        assert_eq!(
            runner.start("initial-cookie", "/signin").await.unwrap(),
            "updated-cookie"
        );
        assert_eq!(runner.interval(), Duration::from_secs(7));
        runner.set_cookie("periodic-cookie").await.unwrap();
        runner.close().await.unwrap();
    }
}
