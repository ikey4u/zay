//! Windows Schannel TLS over the library's existing asynchronous stream.

use std::{
    future::poll_fn,
    io::{self, Read as _, Write as _},
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use openssl::{
    stack::Stack,
    x509::{
        X509, X509StoreContext, store::X509StoreBuilder,
        verify::X509VerifyParam,
    },
};
use rustls::pki_types::CertificateDer;
use schannel::{
    cert_context::CertContext,
    cert_store::{CertAdd, Memory},
    schannel_cred::{Direction, Protocol, SchannelCred},
    tls_stream::{
        Builder as SchannelStreamBuilder, HandshakeError,
        MidHandshakeTlsStream, TlsStream,
    },
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    adapter::Stream, common::ntp::NtpClock, option::OutboundTlsOptions,
};

pub(crate) struct WindowsTlsBackend {
    endpoint_host: String,
    default_alpn: Vec<String>,
    options: OutboundTlsOptions,
    clock: Option<NtpClock>,
}

impl WindowsTlsBackend {
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
    ) -> io::Result<WindowsTlsEstablished> {
        let server_name = if self.options.server_name.is_empty() {
            &self.endpoint_host
        } else {
            &self.options.server_name
        };
        let (anchors, exclusive) = load_anchors(&self.options)?;
        let captured_chain = Arc::new(Mutex::new(Vec::new()));
        let mut stream_builder = SchannelStreamBuilder::new();
        stream_builder.domain(server_name);
        let alpn = if self.options.alpn.as_slice().is_empty() {
            &self.default_alpn
        } else {
            self.options.alpn.as_slice()
        };
        if !alpn.is_empty() {
            let alpn = alpn
                .iter()
                .map(|protocol| protocol.as_bytes())
                .collect::<Vec<_>>();
            stream_builder.request_application_protocols(&alpn);
        }
        if !anchors.is_empty() {
            let mut store = Memory::new()?.into_store();
            for anchor in &anchors {
                let certificate = CertContext::new(anchor)?;
                store.add_cert(&certificate, CertAdd::ReplaceExisting)?;
            }
            stream_builder.cert_store(store);
        }
        let capture = captured_chain.clone();
        stream_builder.verify_callback(move |validation| {
            if let Some(chain) = validation.chain() {
                let certificates = chain
                    .certificates()
                    .map(|certificate| certificate.to_der().to_vec())
                    .collect::<Vec<_>>();
                *capture.lock().map_err(|_| {
                    io::Error::other("Schannel chain lock poisoned")
                })? = certificates;
            }
            // The pinned Go implementation also performs trust verification
            // after SSPI has completed. This permits NTP-corrected time and
            // exact exclusive-root semantics while retaining Schannel on wire.
            Ok(())
        });

        let credential = schannel_credential(
            &self.options.min_version,
            &self.options.max_version,
        )?;
        let handshake = connect_schannel(stream_builder, credential, transport);
        let stream = if let Some(handshake_timeout) = handshake_timeout {
            tokio::time::timeout(handshake_timeout, handshake)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Windows TLS handshake timed out",
                    )
                })??
        } else {
            handshake.await?
        };
        let negotiated_alpn = stream.negotiated_application_protocol()?;
        let mut peer_certificates = captured_chain
            .lock()
            .map_err(|_| io::Error::other("Schannel chain lock poisoned"))?
            .clone();
        if peer_certificates.is_empty() {
            let leaf = stream.peer_certificate()?;
            peer_certificates.push(leaf.to_der().to_vec());
            if let Some(store) = leaf.cert_store() {
                for certificate in store.certs() {
                    let certificate = certificate.to_der().to_vec();
                    if !peer_certificates.contains(&certificate) {
                        peer_certificates.push(certificate);
                    }
                }
            }
        }
        self.verify_peer(server_name, &anchors, exclusive, &peer_certificates)?;
        Ok(WindowsTlsEstablished {
            stream: WindowsTlsStream(stream),
            negotiated_alpn,
            peer_certificates,
        })
    }

    fn verify_peer(
        &self,
        server_name: &str,
        anchors: &[Vec<u8>],
        exclusive: bool,
        peer_certificates: &[Vec<u8>],
    ) -> io::Result<()> {
        if !self.options.server_certificate_fingerprints.is_empty() {
            let leaf = peer_certificates.first().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows TLS peer returned no certificate",
                )
            })?;
            return crate::common::tls::verify_certificate_fingerprints(
                &self.options.server_certificate_fingerprints,
                &CertificateDer::from(leaf.as_slice()),
            )
            .map_err(io::Error::other);
        }
        let pins = self
            .options
            .certificate_public_key_sha256
            .as_slice()
            .iter()
            .map(|pin| pin.0.clone())
            .collect::<Vec<_>>();
        if !pins.is_empty() {
            let leaf = peer_certificates.first().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows TLS peer returned no certificate",
                )
            })?;
            return crate::common::tls::verify_public_key_sha256(
                &pins,
                &CertificateDer::from(leaf.as_slice()),
            )
            .map_err(io::Error::other);
        }
        if self.options.insecure {
            return Ok(());
        }
        verify_chain(
            server_name,
            anchors,
            exclusive,
            peer_certificates,
            self.clock.as_ref().map(NtpClock::unix_time_millis),
        )
    }
}

pub(crate) struct WindowsTlsEstablished {
    pub(crate) stream: WindowsTlsStream,
    pub(crate) negotiated_alpn: Option<Vec<u8>>,
    pub(crate) peer_certificates: Vec<Vec<u8>>,
}

fn load_anchors(
    options: &OutboundTlsOptions,
) -> io::Result<(Vec<Vec<u8>>, bool)> {
    let mut anchors = Vec::new();
    for certificate in options.certificate.as_slice() {
        parse_anchor_pem(certificate.as_bytes(), &mut anchors)?;
    }
    if !options.certificate_path.is_empty() {
        let content = std::fs::read(&options.certificate_path)?;
        parse_anchor_pem(&content, &mut anchors)?;
    }
    if !anchors.is_empty() || options.system_trust_disabled {
        return Ok((anchors, true));
    }
    if let Some(store) = &options.certificate_store {
        let anchors = store
            .apple_anchors()
            .map_err(io::Error::other)?
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect();
        return Ok((anchors, store.exclusive_anchors()));
    }
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() && !native.errors.is_empty() {
        return Err(io::Error::other(format!(
            "load Windows certificate roots: {:?}",
            native.errors
        )));
    }
    Ok((
        native
            .certs
            .into_iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect(),
        true,
    ))
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
            "Windows TLS trust anchor contains no certificate",
        ));
    }
    Ok(())
}

fn schannel_credential(
    minimum: &str,
    maximum: &str,
) -> io::Result<SchannelCred> {
    fn index(value: &str) -> io::Result<Option<usize>> {
        match value {
            "" => Ok(None),
            "1.0" => Ok(Some(0)),
            "1.1" => Ok(Some(1)),
            "1.2" => Ok(Some(2)),
            "1.3" => Ok(Some(3)),
            value => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid Windows TLS version {value:?}"),
            )),
        }
    }
    let minimum = index(minimum)?;
    let maximum = index(maximum)?;
    if minimum.is_none() && maximum.is_none() {
        return SchannelCred::builder().acquire(Direction::Outbound);
    }
    let minimum = minimum.unwrap_or(0);
    let maximum = maximum.unwrap_or(3);
    if minimum > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "minimum Windows TLS version exceeds maximum",
        ));
    }
    let protocols = [
        Protocol::Tls10,
        Protocol::Tls11,
        Protocol::Tls12,
        Protocol::Tls13,
    ];
    SchannelCred::builder()
        .enabled_protocols(&protocols[minimum..=maximum])
        .acquire(Direction::Outbound)
}

fn verify_chain(
    server_name: &str,
    anchors: &[Vec<u8>],
    exclusive: bool,
    peer_certificates: &[Vec<u8>],
    verify_time_unix_millis: Option<i64>,
) -> io::Result<()> {
    let leaf = X509::from_der(peer_certificates.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows TLS peer returned no certificate",
        )
    })?)
    .map_err(io::Error::other)?;
    let mut store = X509StoreBuilder::new().map_err(io::Error::other)?;
    if !exclusive {
        store.set_default_paths().map_err(io::Error::other)?;
    }
    for anchor in anchors {
        store
            .add_cert(X509::from_der(anchor).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    let mut parameters = X509VerifyParam::new().map_err(io::Error::other)?;
    if let Ok(ip) = server_name.parse::<IpAddr>() {
        parameters.set_ip(ip).map_err(io::Error::other)?;
    } else {
        parameters.set_host(server_name).map_err(io::Error::other)?;
    }
    if let Some(milliseconds) = verify_time_unix_millis {
        let seconds = milliseconds.div_euclid(1000);
        parameters.set_time(seconds);
    }
    store.set_param(&parameters).map_err(io::Error::other)?;
    let store = store.build();
    let mut intermediates = Stack::new().map_err(io::Error::other)?;
    for certificate in peer_certificates.iter().skip(1) {
        intermediates
            .push(X509::from_der(certificate).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    let mut context = X509StoreContext::new().map_err(io::Error::other)?;
    let verified = context
        .init(&store, &leaf, &intermediates, |context| {
            context.verify_cert()
        })
        .map_err(io::Error::other)?;
    if verified {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Windows TLS certificate verification failed: {}",
                context.error()
            ),
        ))
    }
}

struct AllowStd<S> {
    inner: S,
    context: *mut (),
}

unsafe impl<S: Send> Send for AllowStd<S> {}
unsafe impl<S: Sync> Sync for AllowStd<S> {}

impl<S: AsyncRead + Unpin> std::io::Read for AllowStd<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read_buffer = ReadBuf::new(buffer);
        self.with_context(|context, stream| {
            stream.poll_read(context, &mut read_buffer)
        })?;
        Ok(read_buffer.filled().len())
    }
}

impl<S: AsyncWrite + Unpin> std::io::Write for AllowStd<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.with_context(|context, stream| stream.poll_write(context, buffer))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.with_context(|context, stream| stream.poll_flush(context))
    }
}

impl<S: Unpin> AllowStd<S> {
    fn with_context<T>(
        &mut self,
        operation: impl FnOnce(&mut Context<'_>, Pin<&mut S>) -> Poll<io::Result<T>>,
    ) -> io::Result<T> {
        assert!(!self.context.is_null());
        let context = unsafe { &mut *(self.context.cast::<Context<'_>>()) };
        match operation(context, Pin::new(&mut self.inner)) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

enum HandshakeState {
    Initial(Option<(SchannelStreamBuilder, SchannelCred, Stream)>),
    Mid(Option<MidHandshakeTlsStream<AllowStd<Stream>>>),
}

async fn connect_schannel(
    builder: SchannelStreamBuilder,
    credential: SchannelCred,
    transport: Stream,
) -> io::Result<TlsStream<AllowStd<Stream>>> {
    let mut state =
        HandshakeState::Initial(Some((builder, credential, transport)));
    poll_fn(move |context| {
        let result = match &mut state {
            HandshakeState::Initial(initial) => {
                let (mut builder, credential, transport) = initial
                    .take()
                    .expect("Windows TLS handshake polled after completion");
                builder.connect(
                    credential,
                    AllowStd {
                        inner: transport,
                        context: context as *mut _ as *mut (),
                    },
                )
            }
            HandshakeState::Mid(mid) => {
                let mut mid = mid
                    .take()
                    .expect("Windows TLS handshake polled after completion");
                mid.get_mut().context = context as *mut _ as *mut ();
                mid.handshake()
            }
        };
        match result {
            Ok(mut stream) => {
                stream.get_mut().context = std::ptr::null_mut();
                Poll::Ready(Ok(stream))
            }
            Err(HandshakeError::Interrupted(mut mid)) => {
                mid.get_mut().context = std::ptr::null_mut();
                state = HandshakeState::Mid(Some(mid));
                Poll::Pending
            }
            Err(HandshakeError::Failure(error)) => Poll::Ready(Err(error)),
        }
    })
    .await
}

pub(crate) struct WindowsTlsStream(TlsStream<AllowStd<Stream>>);

impl WindowsTlsStream {
    fn with_context<T>(
        &mut self,
        context: &mut Context<'_>,
        operation: impl FnOnce(&mut TlsStream<AllowStd<Stream>>) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        self.0.get_mut().context = context as *mut _ as *mut ();
        let result = operation(&mut self.0);
        self.0.get_mut().context = std::ptr::null_mut();
        match result {
            Ok(value) => Poll::Ready(Ok(value)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncRead for WindowsTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(context, |stream| {
            let read = stream.read(buffer.initialize_unfilled())?;
            buffer.advance(read);
            Ok(())
        })
    }
}

impl AsyncWrite for WindowsTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(context, |stream| stream.write(buffer))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(context, |stream| stream.flush())
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(context, TlsStream::shutdown)
    }
}
