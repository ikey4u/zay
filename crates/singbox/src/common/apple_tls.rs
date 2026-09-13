//! Apple Network.framework raw TLS over an existing fd-backed stream.

use std::{
    ffi::{CStr, c_char, c_void},
    future::Future as _,
    io,
    os::fd::{FromRawFd as _, IntoRawFd as _, OwnedFd},
    pin::Pin,
    ptr::NonNull,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use openssl::x509::X509;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};

use crate::{
    adapter::{Stream, stream_socket},
    common::{apple_http, ntp::NtpClock},
    option::OutboundTlsOptions,
};

type AppleTlsState = (Option<Vec<u8>>, Vec<Vec<u8>>);

#[repr(C)]
struct NativeClient {
    _private: [u8; 0],
}

#[repr(C)]
struct NativeState {
    version: u16,
    cipher_suite: u16,
    alpn: *mut c_char,
    server_name: *mut c_char,
    peer_cert_chain: *mut u8,
    peer_cert_chain_len: usize,
}

unsafe extern "C" {
    fn singbox_apple_tls_client_create_with_der_anchors(
        connected_socket: i32,
        server_name: *const c_char,
        alpn: *const c_char,
        alpn_len: usize,
        min_version: u16,
        max_version: u16,
        insecure: bool,
        anchor_certificates: *const *const u8,
        anchor_certificate_lengths: *const usize,
        anchor_certificate_count: usize,
        anchor_only: bool,
        has_verify_time: bool,
        verify_time_unix_millis: i64,
        error: *mut *mut c_char,
    ) -> *mut NativeClient;
    fn box_apple_tls_client_wait_ready(
        client: *mut NativeClient,
        timeout_msec: i32,
        error: *mut *mut c_char,
    ) -> i32;
    fn box_apple_tls_client_cancel(client: *mut NativeClient);
    fn box_apple_tls_client_free(client: *mut NativeClient);
    fn box_apple_tls_client_read(
        client: *mut NativeClient,
        buffer: *mut c_void,
        buffer_len: usize,
        timeout_msec: i32,
        eof: *mut bool,
        error: *mut *mut c_char,
    ) -> isize;
    fn box_apple_tls_client_write(
        client: *mut NativeClient,
        buffer: *const c_void,
        buffer_len: usize,
        timeout_msec: i32,
        error: *mut *mut c_char,
    ) -> isize;
    fn box_apple_tls_client_copy_state(
        client: *mut NativeClient,
        state: *mut NativeState,
        error: *mut *mut c_char,
    ) -> bool;
    fn box_apple_tls_state_free(state: *mut NativeState);
}

pub(crate) struct AppleTlsBackend {
    endpoint_host: String,
    default_alpn: Vec<String>,
    options: OutboundTlsOptions,
    clock: Option<NtpClock>,
}

impl AppleTlsBackend {
    pub(crate) fn new(
        endpoint_host: &str,
        default_alpn: &[&str],
        options: OutboundTlsOptions,
        clock: Option<NtpClock>,
    ) -> Self {
        Self {
            endpoint_host: endpoint_host.to_owned(),
            default_alpn: default_alpn
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            options,
            clock,
        }
    }

    pub(crate) async fn connect(
        &self,
        transport: Stream,
        handshake_timeout: Option<Duration>,
    ) -> io::Result<AppleTlsEstablished> {
        let socket = stream_socket(&transport).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Apple TLS requires an fd-backed TCP stream",
            )
        })?;
        // Network.framework takes ownership of the duplicate. The original
        // stream remains alive to preserve the embedding dialer's lifecycle.
        let duplicate = unsafe { libc::dup(socket) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
        let server_name = if self.options.server_name.is_empty() {
            &self.endpoint_host
        } else {
            &self.options.server_name
        };
        let server_name = apple_http::c_string(server_name, "TLS server name")?;
        let alpn = if self.options.alpn.as_slice().is_empty() {
            self.default_alpn.join("\n")
        } else {
            self.options.alpn.as_slice().join("\n")
        };
        let alpn = apple_http::c_string(&alpn, "TLS ALPN")?;
        let (anchors, anchor_only) = apple_http::load_anchors(&self.options)?;
        let pins = self
            .options
            .certificate_public_key_sha256
            .as_slice()
            .iter()
            .map(|pin| pin.0.clone())
            .collect::<Vec<_>>();
        let verify_time_unix_millis =
            self.clock.as_ref().map(NtpClock::unix_time_millis);
        let client = create_native_client(
            duplicate,
            &server_name,
            &alpn,
            &anchors,
            anchor_only,
            self.options.insecure || !pins.is_empty(),
            apple_http::tls_version(&self.options.min_version),
            apple_http::tls_version(&self.options.max_version),
            verify_time_unix_millis,
        )?;
        let handle = Arc::new(AppleTlsHandle { raw: client });
        let mut cancel_guard = AppleHandshakeCancelGuard(Some(handle.clone()));
        let timeout_millis = handshake_timeout.map_or(-1, duration_millis);
        let wait_handle = handle.clone();
        tokio::task::spawn_blocking(move || {
            wait_handle.wait_ready(timeout_millis)
        })
        .await
        .map_err(io::Error::other)??;
        let (negotiated_alpn, peer_certificates) = handle.state()?;
        if !pins.is_empty() {
            verify_spki_pins(&pins, &peer_certificates)?;
        }
        cancel_guard.0.take();
        Ok(AppleTlsEstablished {
            stream: AppleTlsStream {
                handle,
                _raw_transport: transport,
                read: None,
                write: None,
                read_eof: false,
                shutdown: false,
            },
            negotiated_alpn,
            peer_certificates,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn create_native_client(
    duplicate: OwnedFd,
    server_name: &CStr,
    alpn: &CStr,
    anchors: &[Vec<u8>],
    anchor_only: bool,
    insecure: bool,
    min_version: u16,
    max_version: u16,
    verify_time_unix_millis: Option<i64>,
) -> io::Result<NonNull<NativeClient>> {
    let anchor_pointers: Vec<*const u8> =
        anchors.iter().map(Vec::as_ptr).collect();
    let anchor_lengths: Vec<usize> = anchors.iter().map(Vec::len).collect();
    let mut error = std::ptr::null_mut();
    let client = unsafe {
        singbox_apple_tls_client_create_with_der_anchors(
            duplicate.into_raw_fd(),
            server_name.as_ptr(),
            alpn.as_ptr(),
            alpn.to_bytes().len(),
            min_version,
            max_version,
            insecure,
            anchor_pointers.as_ptr(),
            anchor_lengths.as_ptr(),
            anchors.len(),
            anchor_only,
            verify_time_unix_millis.is_some(),
            verify_time_unix_millis.unwrap_or_default(),
            &mut error,
        )
    };
    NonNull::new(client).ok_or_else(|| {
        apple_http::native_error(error, "create Apple TLS client")
    })
}

pub(crate) struct AppleTlsEstablished {
    pub(crate) stream: AppleTlsStream,
    pub(crate) negotiated_alpn: Option<Vec<u8>>,
    pub(crate) peer_certificates: Vec<Vec<u8>>,
}

struct AppleTlsHandle {
    raw: NonNull<NativeClient>,
}

unsafe impl Send for AppleTlsHandle {}
unsafe impl Sync for AppleTlsHandle {}

impl AppleTlsHandle {
    fn cancel(&self) {
        unsafe { box_apple_tls_client_cancel(self.raw.as_ptr()) };
    }

    fn wait_ready(&self, timeout_millis: i32) -> io::Result<()> {
        let mut error = std::ptr::null_mut();
        let result = unsafe {
            box_apple_tls_client_wait_ready(
                self.raw.as_ptr(),
                timeout_millis,
                &mut error,
            )
        };
        match result {
            1 => Ok(()),
            -2 => {
                self.cancel();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Apple TLS handshake timed out",
                ))
            }
            _ => Err(apple_http::native_error(
                error,
                "Apple TLS handshake failed",
            )),
        }
    }

    fn state(&self) -> io::Result<AppleTlsState> {
        let mut state = NativeState {
            version: 0,
            cipher_suite: 0,
            alpn: std::ptr::null_mut(),
            server_name: std::ptr::null_mut(),
            peer_cert_chain: std::ptr::null_mut(),
            peer_cert_chain_len: 0,
        };
        let mut error = std::ptr::null_mut();
        let copied = unsafe {
            box_apple_tls_client_copy_state(
                self.raw.as_ptr(),
                &mut state,
                &mut error,
            )
        };
        if !copied {
            return Err(apple_http::native_error(
                error,
                "read Apple TLS metadata",
            ));
        }
        let result = parse_state(&state);
        unsafe { box_apple_tls_state_free(&mut state) };
        result
    }

    fn read(&self, maximum: usize) -> io::Result<(Vec<u8>, bool)> {
        let mut output = vec![0_u8; maximum];
        let mut eof = false;
        let mut error = std::ptr::null_mut();
        let read = unsafe {
            box_apple_tls_client_read(
                self.raw.as_ptr(),
                output.as_mut_ptr().cast(),
                output.len(),
                -1,
                &mut eof,
                &mut error,
            )
        };
        if read < 0 {
            return Err(apple_http::native_error(error, "read Apple TLS"));
        }
        output.truncate(read as usize);
        Ok((output, eof))
    }

    fn write(&self, input: Vec<u8>) -> io::Result<usize> {
        let mut error = std::ptr::null_mut();
        let written = unsafe {
            box_apple_tls_client_write(
                self.raw.as_ptr(),
                input.as_ptr().cast(),
                input.len(),
                -1,
                &mut error,
            )
        };
        if written < 0 {
            return Err(apple_http::native_error(error, "write Apple TLS"));
        }
        Ok(written as usize)
    }
}

impl Drop for AppleTlsHandle {
    fn drop(&mut self) {
        unsafe { box_apple_tls_client_free(self.raw.as_ptr()) };
    }
}

struct AppleHandshakeCancelGuard(Option<Arc<AppleTlsHandle>>);

impl Drop for AppleHandshakeCancelGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.cancel();
        }
    }
}

type ReadTask = JoinHandle<io::Result<(Vec<u8>, bool)>>;
type WriteTask = JoinHandle<io::Result<usize>>;

pub(crate) struct AppleTlsStream {
    handle: Arc<AppleTlsHandle>,
    _raw_transport: Stream,
    read: Option<ReadTask>,
    write: Option<(WriteTask, usize)>,
    read_eof: bool,
    shutdown: bool,
}

impl AsyncRead for AppleTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 || self.read_eof {
            return Poll::Ready(Ok(()));
        }
        if self.read.is_none() {
            let handle = self.handle.clone();
            let maximum = buffer.remaining();
            self.read =
                Some(tokio::task::spawn_blocking(move || handle.read(maximum)));
        }
        let result = match Pin::new(self.read.as_mut().expect("read task"))
            .poll(context)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.read.take();
        let (bytes, eof) = result.map_err(io::Error::other)??;
        self.read_eof = eof;
        if bytes.is_empty() && !eof {
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        buffer.put_slice(&bytes);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AppleTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Apple TLS stream is shut down",
            )));
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write.is_none() {
            let length = buffer.len().min(32 * 1024);
            let input = buffer[..length].to_vec();
            let handle = self.handle.clone();
            self.write = Some((
                tokio::task::spawn_blocking(move || handle.write(input)),
                length,
            ));
        }
        let (task, expected) = self.write.as_mut().expect("write task");
        let result = match Pin::new(task).poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        let expected = *expected;
        self.write.take();
        let written = result.map_err(io::Error::other)??;
        if written != expected {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Apple TLS write was short",
            )));
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some((task, expected)) = self.write.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = match Pin::new(task).poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        let expected = *expected;
        self.write.take();
        let written = result.map_err(io::Error::other)??;
        if written != expected {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Apple TLS write was short",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if !self.shutdown {
            self.shutdown = true;
            self.handle.cancel();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for AppleTlsStream {
    fn drop(&mut self) {
        self.handle.cancel();
    }
}

fn parse_state(state: &NativeState) -> io::Result<AppleTlsState> {
    let negotiated_alpn = if state.alpn.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(state.alpn) }.to_bytes().to_vec())
    };
    let bytes = if state.peer_cert_chain_len == 0 {
        &[][..]
    } else if state.peer_cert_chain.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Apple TLS returned a null certificate chain",
        ));
    } else {
        unsafe {
            std::slice::from_raw_parts(
                state.peer_cert_chain,
                state.peer_cert_chain_len,
            )
        }
    };
    let mut certificates = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Apple TLS returned a truncated certificate length",
            ));
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4].try_into().expect("four bytes"),
        ) as usize;
        offset += 4;
        if length > bytes.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Apple TLS returned a truncated certificate",
            ));
        }
        certificates.push(bytes[offset..offset + length].to_vec());
        offset += length;
    }
    Ok((negotiated_alpn, certificates))
}

fn verify_spki_pins(
    pins: &[Vec<u8>],
    certificates: &[Vec<u8>],
) -> io::Result<()> {
    let certificate = certificates.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Apple TLS peer returned no certificate",
        )
    })?;
    let certificate = X509::from_der(certificate).map_err(io::Error::other)?;
    let public_key = certificate
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(io::Error::other)?;
    let digest = Sha256::digest(public_key);
    let matched = pins.iter().any(|pin| {
        pin.len() == digest.len()
            && pin
                .iter()
                .zip(digest.iter())
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0
    });
    if matched {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Apple TLS peer public key does not match any configured SHA-256 pin",
        ))
    }
}

fn duration_millis(duration: Duration) -> i32 {
    let millis = duration.as_millis().max(1);
    i32::try_from(millis).unwrap_or(i32::MAX)
}
