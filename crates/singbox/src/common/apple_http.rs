//! Apple `NSURLSession` HTTP engine backed by the selected sing-box dialer.

use std::{
    ffi::{CStr, CString, c_char},
    io,
    net::{Ipv4Addr, SocketAddr},
    ptr::NonNull,
    sync::Arc,
};

use bytes::Bytes;
use hyper::{HeaderMap, Method, StatusCode};
use rustls::pki_types::CertificateDer;
use tokio::{io::copy_bidirectional, net::TcpListener, sync::Mutex};
use tokio_util::sync::CancellationToken;

use crate::{
    adapter::Dialer,
    common::ntp::NtpClock,
    option::{HttpClientOptions, User},
    protocol::socks::{SocksCommand, server_request, write_reply_for_version},
};

use super::http::DownloadResponse;

#[repr(C)]
struct NativeSession {
    _private: [u8; 0],
}

#[repr(C)]
struct NativeTask {
    _private: [u8; 0],
}

#[repr(C)]
struct NativeSessionConfig {
    proxy_host: *const c_char,
    proxy_port: i32,
    proxy_username: *const c_char,
    proxy_password: *const c_char,
    min_tls_version: u16,
    max_tls_version: u16,
    insecure: bool,
    anchor_certificates: *const *const u8,
    anchor_certificate_lengths: *const usize,
    anchor_certificate_count: usize,
    anchor_only: bool,
    pinned_public_key_sha256: *const u8,
    pinned_public_key_sha256_len: usize,
}

#[repr(C)]
struct NativeRequest {
    method: *const c_char,
    url: *const c_char,
    header_keys: *const *const c_char,
    header_values: *const *const c_char,
    header_count: usize,
    body: *const u8,
    body_len: usize,
    has_verify_time: bool,
    verify_time_unix_millis: i64,
}

#[repr(C)]
struct NativeResponse {
    status_code: i32,
    header_keys: *const *const c_char,
    header_values: *const *const c_char,
    header_count: usize,
    body: *const u8,
    body_len: usize,
}

unsafe extern "C" {
    fn singbox_apple_http_session_create(
        config: *const NativeSessionConfig,
        error: *mut *mut c_char,
    ) -> *mut NativeSession;
    fn singbox_apple_http_session_close(session: *mut NativeSession);
    fn singbox_apple_http_session_send_async(
        session: *mut NativeSession,
        request: *const NativeRequest,
        error: *mut *mut c_char,
    ) -> *mut NativeTask;
    fn singbox_apple_http_task_wait(
        task: *mut NativeTask,
        error: *mut *mut c_char,
    ) -> *mut NativeResponse;
    fn singbox_apple_http_task_cancel(task: *mut NativeTask);
    fn singbox_apple_http_task_close(task: *mut NativeTask);
    fn singbox_apple_http_response_free(response: *mut NativeResponse);
}

pub(crate) struct AppleHttpClient {
    dialer: Arc<dyn Dialer>,
    options: HttpClientOptions,
    state: Mutex<Option<(Option<u64>, Arc<AppleSession>)>>,
    clock: Option<NtpClock>,
}

impl AppleHttpClient {
    pub(crate) fn new(
        dialer: Arc<dyn Dialer>,
        options: HttpClientOptions,
        clock: Option<NtpClock>,
    ) -> Self {
        Self {
            dialer,
            options,
            state: Mutex::new(None),
            clock,
        }
    }

    pub(crate) async fn reset(&self) {
        self.state.lock().await.take();
    }

    pub(crate) async fn request(
        &self,
        method: Method,
        url: &url::Url,
        headers: HeaderMap,
        body: Bytes,
    ) -> io::Result<DownloadResponse> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported HTTP URL scheme {:?}", url.scheme()),
            ));
        }
        if url.scheme() == "https"
            && self.options.tls.as_ref().is_some_and(|tls| {
                !tls.server_name.is_empty()
                    && !tls.server_name.eq_ignore_ascii_case(
                        url.host_str().unwrap_or_default(),
                    )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tls.server_name is unsupported in Apple HTTP engine unless it matches request host",
            ));
        }
        let session = {
            let store_generation = self
                .options
                .tls
                .as_ref()
                .and_then(|tls| tls.certificate_store.as_ref())
                .map(|store| store.generation());
            let mut state = self.state.lock().await;
            if state
                .as_ref()
                .is_some_and(|(generation, _)| *generation != store_generation)
            {
                state.take();
            }
            if state.is_none() {
                *state = Some((
                    store_generation,
                    Arc::new(
                        AppleSession::new(self.dialer.clone(), &self.options)
                            .await?,
                    ),
                ));
            }
            state.as_ref().expect("Apple session inserted").1.clone()
        };
        let task = session.start(
            method,
            url.as_str(),
            headers,
            body,
            self.clock.as_ref().map(NtpClock::unix_time_millis),
        )?;
        let mut cancel_guard = AppleTaskCancelGuard::new(task.clone());
        match tokio::task::spawn_blocking(move || task.wait()).await {
            Ok(result) => {
                cancel_guard.disarm();
                result
            }
            Err(error) => Err(io::Error::other(error)),
        }
    }
}

struct AppleSession {
    raw: NonNull<NativeSession>,
    _bridge: DialerSocksBridge,
}

// NSURLSession is documented as safe to use from multiple threads. All
// ownership-changing operations stay behind the Rust Arc and native session.
unsafe impl Send for AppleSession {}
unsafe impl Sync for AppleSession {}

impl AppleSession {
    async fn new(
        dialer: Arc<dyn Dialer>,
        options: &HttpClientOptions,
    ) -> io::Result<Self> {
        let bridge = DialerSocksBridge::new(dialer).await?;
        let tls = options.tls.clone().unwrap_or_default();
        let (anchors, anchor_only) = load_anchors(&tls)?;
        let anchor_pointers: Vec<*const u8> =
            anchors.iter().map(|anchor| anchor.as_ptr()).collect();
        let anchor_lengths: Vec<usize> = anchors.iter().map(Vec::len).collect();
        let pins: Vec<u8> = tls
            .certificate_public_key_sha256
            .as_slice()
            .iter()
            .flat_map(|pin| pin.0.iter().copied())
            .collect();
        let proxy_host =
            c_string(bridge.address.ip().to_string(), "proxy host")?;
        let username = c_string(&bridge.username, "proxy username")?;
        let password = c_string(&bridge.password, "proxy password")?;
        let config = NativeSessionConfig {
            proxy_host: proxy_host.as_ptr(),
            proxy_port: i32::from(bridge.address.port()),
            proxy_username: username.as_ptr(),
            proxy_password: password.as_ptr(),
            min_tls_version: tls_version(&tls.min_version),
            max_tls_version: tls_version(&tls.max_version),
            insecure: tls.insecure || !pins.is_empty(),
            anchor_certificates: anchor_pointers.as_ptr(),
            anchor_certificate_lengths: anchor_lengths.as_ptr(),
            anchor_certificate_count: anchors.len(),
            anchor_only,
            pinned_public_key_sha256: pins.as_ptr(),
            pinned_public_key_sha256_len: pins.len(),
        };
        let mut error = std::ptr::null_mut();
        // SAFETY: every pointer in `config` remains valid for the duration of
        // the call; the Objective-C implementation copies all supplied data.
        let raw =
            unsafe { singbox_apple_http_session_create(&config, &mut error) };
        let raw = NonNull::new(raw)
            .ok_or_else(|| native_error(error, "create Apple HTTP session"))?;
        Ok(Self {
            raw,
            _bridge: bridge,
        })
    }

    fn start(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Bytes,
        verify_time_unix_millis: Option<i64>,
    ) -> io::Result<Arc<AppleTask>> {
        let method = c_string(method.as_str(), "HTTP method")?;
        let url = c_string(url, "HTTP URL")?;
        let mut header_keys = Vec::new();
        let mut header_values = Vec::new();
        for (name, value) in &headers {
            header_keys.push(c_string(name.as_str(), "HTTP header name")?);
            header_values.push(c_string(
                value.to_str().map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error)
                })?,
                "HTTP header value",
            )?);
        }
        let key_pointers: Vec<*const c_char> =
            header_keys.iter().map(|value| value.as_ptr()).collect();
        let value_pointers: Vec<*const c_char> =
            header_values.iter().map(|value| value.as_ptr()).collect();
        let request = NativeRequest {
            method: method.as_ptr(),
            url: url.as_ptr(),
            header_keys: key_pointers.as_ptr(),
            header_values: value_pointers.as_ptr(),
            header_count: key_pointers.len(),
            body: body.as_ptr(),
            body_len: body.len(),
            has_verify_time: verify_time_unix_millis.is_some(),
            verify_time_unix_millis: verify_time_unix_millis
                .unwrap_or_default(),
        };
        let mut error = std::ptr::null_mut();
        // SAFETY: request buffers live until task creation returns and the
        // native implementation copies them into NSMutableURLRequest.
        let task = unsafe {
            singbox_apple_http_session_send_async(
                self.raw.as_ptr(),
                &request,
                &mut error,
            )
        };
        let task = NonNull::new(task)
            .ok_or_else(|| native_error(error, "create Apple HTTP request"))?;
        Ok(Arc::new(AppleTask { raw: task }))
    }
}

impl Drop for AppleSession {
    fn drop(&mut self) {
        // SAFETY: Arc guarantees this is the final owner of the native handle.
        unsafe { singbox_apple_http_session_close(self.raw.as_ptr()) };
    }
}

struct AppleTask {
    raw: NonNull<NativeTask>,
}

// The native task and dispatch semaphore are thread-safe NSURLSession objects;
// ownership remains with this Arc until the blocking wait has returned.
unsafe impl Send for AppleTask {}
unsafe impl Sync for AppleTask {}

impl AppleTask {
    fn wait(&self) -> io::Result<DownloadResponse> {
        let mut error = std::ptr::null_mut();
        // SAFETY: the Arc keeps the native task alive through this wait.
        let response = unsafe {
            singbox_apple_http_task_wait(self.raw.as_ptr(), &mut error)
        };
        let result = NonNull::new(response).map_or_else(
            || Err(native_error(error, "Apple HTTP request failed")),
            parse_response,
        );
        // SAFETY: response contents have been copied and this response handle
        // is released exactly once after the wait completes.
        unsafe {
            if let Some(response) = NonNull::new(response) {
                singbox_apple_http_response_free(response.as_ptr());
            }
        }
        result
    }

    fn cancel(&self) {
        // SAFETY: cancellation is idempotent and the Arc keeps the task alive.
        unsafe { singbox_apple_http_task_cancel(self.raw.as_ptr()) };
    }
}

impl Drop for AppleTask {
    fn drop(&mut self) {
        // SAFETY: this is the final Arc owner and no waiter still uses the task.
        unsafe { singbox_apple_http_task_close(self.raw.as_ptr()) };
    }
}

struct AppleTaskCancelGuard {
    task: Option<Arc<AppleTask>>,
}

impl AppleTaskCancelGuard {
    fn new(task: Arc<AppleTask>) -> Self {
        Self { task: Some(task) }
    }

    fn disarm(&mut self) {
        self.task.take();
    }
}

impl Drop for AppleTaskCancelGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.cancel();
        }
    }
}

struct DialerSocksBridge {
    address: SocketAddr,
    username: String,
    password: String,
    cancellation: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl DialerSocksBridge {
    async fn new(dialer: Arc<dyn Dialer>) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let mut credential = [0_u8; 24];
        getrandom::fill(&mut credential).map_err(io::Error::other)?;
        let username = hex::encode(&credential[..12]);
        let password = hex::encode(&credential[12..]);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task_username = username.clone();
        let task_password = password.clone();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = task_cancellation.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let dialer = dialer.clone();
                let username = task_username.clone();
                let password = task_password.clone();
                tokio::spawn(async move {
                    let _ = serve_bridge_connection(
                        stream, dialer, username, password,
                    )
                    .await;
                });
            }
        });
        Ok(Self {
            address,
            username,
            password,
            cancellation,
            task,
        })
    }
}

impl Drop for DialerSocksBridge {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.task.abort();
    }
}

async fn serve_bridge_connection(
    mut inbound: tokio::net::TcpStream,
    dialer: Arc<dyn Dialer>,
    username: String,
    password: String,
) -> io::Result<()> {
    let users = [User { username, password }];
    let request = server_request(&mut inbound, &users).await?;
    if request.command != SocksCommand::Connect {
        write_reply_for_version(&mut inbound, request.version, 7, None).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Apple HTTP SOCKS bridge only supports CONNECT",
        ));
    }
    let mut outbound = match dialer.dial_tcp(&request.destination).await {
        Ok(outbound) => outbound,
        Err(error) => {
            let code = match error.kind() {
                io::ErrorKind::PermissionDenied => 2,
                io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable => 4,
                io::ErrorKind::ConnectionRefused => 5,
                io::ErrorKind::TimedOut => 6,
                _ => 1,
            };
            let _ = write_reply_for_version(
                &mut inbound,
                request.version,
                code,
                None,
            )
            .await;
            return Err(error);
        }
    };
    write_reply_for_version(&mut inbound, request.version, 0, None).await?;
    copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

pub(crate) fn load_anchors(
    tls: &crate::option::OutboundTlsOptions,
) -> io::Result<(Vec<Vec<u8>>, bool)> {
    let mut anchors = Vec::new();
    for certificate in tls.certificate.as_slice() {
        parse_anchor_pem(certificate.as_bytes(), &mut anchors)?;
    }
    if !tls.certificate_path.is_empty() {
        let content = std::fs::read(&tls.certificate_path)?;
        parse_anchor_pem(&content, &mut anchors)?;
    }
    if !anchors.is_empty() {
        return Ok((anchors, true));
    }
    if tls.system_trust_disabled {
        return Ok((anchors, true));
    }
    if let Some(store) = &tls.certificate_store {
        let anchors = store
            .apple_anchors()
            .map_err(io::Error::other)?
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect();
        return Ok((anchors, store.exclusive_anchors()));
    }
    Ok((anchors, false))
}

fn parse_anchor_pem(
    content: &[u8],
    anchors: &mut Vec<Vec<u8>>,
) -> io::Result<()> {
    let original_count = anchors.len();
    let mut reader = std::io::BufReader::new(content);
    for certificate in rustls_pemfile::certs(&mut reader) {
        anchors.push(certificate.map_err(io::Error::other)?.to_vec());
    }
    if anchors.len() == original_count && !content.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Apple HTTP trust anchor contains no certificate",
        ));
    }
    Ok(())
}

pub(crate) fn tls_version(value: &str) -> u16 {
    match value {
        "1.0" => 0x0301,
        "1.1" => 0x0302,
        "1.2" => 0x0303,
        "1.3" => 0x0304,
        _ => 0,
    }
}

fn parse_response(
    response: NonNull<NativeResponse>,
) -> io::Result<DownloadResponse> {
    // SAFETY: the native response remains owned by the caller for this entire
    // copy and all pointer/count pairs originate from the Objective-C shim.
    let response = unsafe { response.as_ref() };
    let status = StatusCode::from_u16(
        u16::try_from(response.status_code).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Apple HTTP status",
            )
        })?,
    )
    .map_err(io::Error::other)?;
    let keys: &[*const c_char] = if response.header_count == 0 {
        &[]
    } else {
        unsafe {
            std::slice::from_raw_parts(
                response.header_keys,
                response.header_count,
            )
        }
    };
    let values: &[*const c_char] = if response.header_count == 0 {
        &[]
    } else {
        unsafe {
            std::slice::from_raw_parts(
                response.header_values,
                response.header_count,
            )
        }
    };
    let mut headers = HeaderMap::new();
    for (&key, &value) in keys.iter().zip(values) {
        if key.is_null() || value.is_null() {
            continue;
        }
        let key = unsafe { CStr::from_ptr(key) }.to_str().map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, error)
        })?;
        let value =
            unsafe { CStr::from_ptr(value) }.to_str().map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, error)
            })?;
        headers.append(
            hyper::header::HeaderName::try_from(key)
                .map_err(io::Error::other)?,
            hyper::header::HeaderValue::try_from(value)
                .map_err(io::Error::other)?,
        );
    }
    let body = if response.body_len == 0 {
        Bytes::new()
    } else {
        Bytes::copy_from_slice(unsafe {
            std::slice::from_raw_parts(response.body, response.body_len)
        })
    };
    Ok(DownloadResponse {
        status,
        headers,
        body,
    })
}

pub(crate) fn native_error(error: *mut c_char, context: &str) -> io::Error {
    if error.is_null() {
        return io::Error::other(context.to_owned());
    }
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    unsafe { libc::free(error.cast()) };
    io::Error::other(format!("{context}: {message}"))
}

pub(crate) fn c_string(
    value: impl AsRef<str>,
    field: &str,
) -> io::Result<CString> {
    CString::new(value.as_ref()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} contains NUL"),
        )
    })
}

#[unsafe(no_mangle)]
extern "C" fn singbox_apple_http_verify_public_key_sha256(
    known_hash_values: *const u8,
    known_hash_values_len: usize,
    leaf_cert: *const u8,
    leaf_cert_len: usize,
) -> *mut c_char {
    let result = (|| {
        if known_hash_values.is_null() || leaf_cert.is_null() {
            return Err("missing Apple HTTP certificate pin input".to_owned());
        }
        if !known_hash_values_len.is_multiple_of(32) {
            return Err("invalid pinned public key list".to_owned());
        }
        let hashes = unsafe {
            std::slice::from_raw_parts(known_hash_values, known_hash_values_len)
        }
        .chunks_exact(32)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
        let certificate = CertificateDer::from(unsafe {
            std::slice::from_raw_parts(leaf_cert, leaf_cert_len)
        });
        super::tls::verify_public_key_sha256(&hashes, &certificate)
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(error) => CString::new(error)
            .unwrap_or_else(|_| CString::new("certificate pin failed").unwrap())
            .into_raw(),
    }
}

#[cfg(test)]
mod tests {
    use super::DialerSocksBridge;
    use crate::{
        adapter::Dialer,
        common::network::SocksAddr,
        option::DirectOutboundOptions,
        protocol::{direct::DirectOutbound, socks::Socks5Outbound},
    };
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn authenticated_bridge_returns_connections_to_selected_dialer() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = echo.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let direct: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let bridge = DialerSocksBridge::new(direct.clone()).await.unwrap();
        let proxy = Socks5Outbound::new(
            direct,
            SocksAddr::from(bridge.address),
            &bridge.username,
            &bridge.password,
        );
        let mut stream =
            proxy.dial_tcp(&SocksAddr::from(destination)).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }
}
