//! ShadowTLS protocol primitives.
//!
//! Version 1 relays a real TLS 1.2 handshake to a decoy server and then
//! reuses the underlying TCP connection as a plaintext proxy tunnel.  The TLS
//! state is intentionally discarded after both directions observe
//! ChangeCipherSpec followed by the encrypted Finished record.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use hmac::{Hmac, Mac as _};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsConnector;

use crate::{
    adapter::{DialFuture, Dialer, Stream},
    common::{network::SocksAddr, tls::ClientTlsConfig},
};

const TLS_HEADER_SIZE: usize = 5;
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
const TLS_MAX_PLAINTEXT: usize = 16 * 1024;
const TLS_RANDOM_SIZE: usize = 32;
const TLS_SESSION_ID_SIZE: usize = 32;
const V3_HMAC_SIZE: usize = 4;
const CLIENT_HELLO_SESSION_ID_LENGTH_INDEX: usize =
    TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
const CLIENT_HELLO_SESSION_ID_START: usize =
    CLIENT_HELLO_SESSION_ID_LENGTH_INDEX + 1;
const SERVER_HELLO_RANDOM_START: usize = TLS_HEADER_SIZE + 1 + 3 + 2;

/// Complete a real TLS handshake and recover the raw transport beneath
/// rustls. ShadowTLS v1 uses TLS 1.2; its caller is responsible for applying
/// the same min/max-version restriction as the Go adapter.
pub async fn client_handshake_v1(
    raw: Stream,
    tls: &ClientTlsConfig,
) -> io::Result<Stream> {
    let config = tls.config_for_handshake().await.map_err(io::Error::other)?;
    let handshake =
        TlsConnector::from(config).connect(tls.server_name.clone(), raw);
    let stream = if let Some(handshake_timeout) = tls.handshake_timeout {
        tokio::time::timeout(handshake_timeout, handshake)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ShadowTLS handshake timed out",
                )
            })?
    } else {
        handshake.await
    }
    .map_err(io::Error::other)?;
    let (raw, _) = stream.into_inner();
    Ok(raw)
}

struct HashReadStream {
    inner: Stream,
    hash: Hmac<Sha1>,
}

impl HashReadStream {
    fn new(inner: Stream, password: &[u8]) -> io::Result<Self> {
        Ok(Self {
            inner,
            hash: Hmac::<Sha1>::new_from_slice(password)
                .map_err(|error| io::Error::other(error.to_string()))?,
        })
    }

    fn sum(&self) -> [u8; 8] {
        self.hash.clone().finalize().into_bytes()[..8]
            .try_into()
            .expect("eight-byte HMAC prefix")
    }
}

impl AsyncRead for HashReadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                self.hash.update(&buffer.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for HashReadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// ShadowTLS v2 client handshake. The first tunneled application record is
/// authenticated with the first eight bytes of HMAC-SHA1(password,
/// server-handshake-bytes), exactly as `sing-shadowtls`.
pub async fn client_handshake_v2(
    raw: Stream,
    password: &[u8],
    tls: &ClientTlsConfig,
) -> io::Result<Stream> {
    let hashed = HashReadStream::new(raw, password)?;
    let config = tls.config_for_handshake().await.map_err(io::Error::other)?;
    let handshake =
        TlsConnector::from(config).connect(tls.server_name.clone(), hashed);
    let stream = if let Some(handshake_timeout) = tls.handshake_timeout {
        tokio::time::timeout(handshake_timeout, handshake)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ShadowTLS handshake timed out",
                )
            })?
    } else {
        handshake.await
    }
    .map_err(io::Error::other)?;
    let (hashed, _) = stream.into_inner();
    let authentication = hashed.sum();
    Ok(spawn_v2_tunnel(
        hashed.inner,
        Some(authentication.to_vec()),
        Vec::new(),
    ))
}

#[derive(Clone)]
struct V3HandshakeDecoder {
    hmac: Hmac<Sha1>,
    key: [u8; 32],
}

struct V3HandshakeEncoder {
    hmac: Hmac<Sha1>,
    key: [u8; 32],
}

impl V3HandshakeEncoder {
    fn new(
        password: &[u8],
        server_random: &[u8; TLS_RANDOM_SIZE],
    ) -> io::Result<Self> {
        let mut hmac = Hmac::<Sha1>::new_from_slice(password)
            .map_err(|error| io::Error::other(error.to_string()))?;
        hmac.update(server_random);
        Ok(Self {
            hmac,
            key: v3_kdf(password, server_random),
        })
    }

    fn encode(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        if frame.len() < TLS_HEADER_SIZE
            || frame[0] != TLS_RECORD_APPLICATION_DATA
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TLS application record",
            ));
        }
        let encrypted = &frame[TLS_HEADER_SIZE..];
        let mut disguised = Vec::with_capacity(encrypted.len());
        disguised.extend(
            encrypted
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()]),
        );
        self.hmac.update(&disguised);
        let tag = self.hmac.clone().finalize().into_bytes();
        let mut output = Vec::with_capacity(frame.len() + V3_HMAC_SIZE);
        output.extend_from_slice(&frame[..TLS_HEADER_SIZE]);
        output[3..5].copy_from_slice(
            &((disguised.len() + V3_HMAC_SIZE) as u16).to_be_bytes(),
        );
        output.extend_from_slice(&tag[..V3_HMAC_SIZE]);
        output.extend_from_slice(&disguised);
        Ok(output)
    }
}

impl V3HandshakeDecoder {
    fn new(
        password: &[u8],
        server_random: &[u8; TLS_RANDOM_SIZE],
    ) -> io::Result<Self> {
        let mut hmac = Hmac::<Sha1>::new_from_slice(password)
            .map_err(|error| io::Error::other(error.to_string()))?;
        hmac.update(server_random);
        Ok(Self {
            hmac,
            key: v3_kdf(password, server_random),
        })
    }

    fn decode(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        if frame.len() <= TLS_HEADER_SIZE + V3_HMAC_SIZE
            || frame[0] != TLS_RECORD_APPLICATION_DATA
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ShadowTLS v3 handshake record",
            ));
        }
        let tag = &frame[TLS_HEADER_SIZE..TLS_HEADER_SIZE + V3_HMAC_SIZE];
        let encrypted = &frame[TLS_HEADER_SIZE + V3_HMAC_SIZE..];
        let mut trial = self.hmac.clone();
        trial.update(encrypted);
        let expected = trial.clone().finalize().into_bytes();
        if !constant_time_equal(tag, &expected[..V3_HMAC_SIZE]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS v3 handshake HMAC mismatch",
            ));
        }
        self.hmac = trial;
        let mut output = Vec::with_capacity(frame.len() - V3_HMAC_SIZE);
        output.extend_from_slice(&frame[..TLS_HEADER_SIZE]);
        output[3..5].copy_from_slice(&(encrypted.len() as u16).to_be_bytes());
        output.extend(
            encrypted
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()]),
        );
        Ok(output)
    }
}

#[derive(Default)]
struct V3ClientHandshakeStatus {
    server_random: Option<[u8; TLS_RANDOM_SIZE]>,
    is_tls13: bool,
    authorized: bool,
}

#[derive(Debug)]
struct ShadowTlsSessionIdFinalizer {
    password: Vec<u8>,
}

impl rustls::client::FinalizesClientHello for ShadowTlsSessionIdFinalizer {
    fn finalize_client_hello(
        &self,
        client_hello: &mut Vec<u8>,
    ) -> Result<(), rustls::Error> {
        const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;
        if client_hello.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
            return Err(rustls::Error::General(
                "ShadowTLS v3 truncated ClientHello".into(),
            ));
        }
        let session_id = &mut client_hello
            [SESSION_ID_START..SESSION_ID_START + TLS_SESSION_ID_SIZE];
        session_id.fill(0);
        getrandom::fill(&mut session_id[..TLS_SESSION_ID_SIZE - V3_HMAC_SIZE])
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        let mut hmac = Hmac::<Sha1>::new_from_slice(&self.password)
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        hmac.update(client_hello);
        let tag = hmac.finalize().into_bytes();
        client_hello[SESSION_ID_START + TLS_SESSION_ID_SIZE - V3_HMAC_SIZE
            ..SESSION_ID_START + TLS_SESSION_ID_SIZE]
            .copy_from_slice(&tag[..V3_HMAC_SIZE]);
        Ok(())
    }
}

#[derive(Debug)]
struct ShadowTlsClientHelloCustomizer {
    finalizer: Arc<ShadowTlsSessionIdFinalizer>,
}

impl rustls::client::ClientHelloCustomizer for ShadowTlsClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: rustls::client::ClientHelloContext<'_>,
    ) -> Result<Option<rustls::client::ClientHelloPlan>, rustls::Error> {
        Ok(Some(
            rustls::client::ClientHelloPlan::new()
                .with_finalizer(self.finalizer.clone()),
        ))
    }
}

/// Complete a ShadowTLS v3 handshake by authenticating rustls' ClientHello
/// session ID and reversing the server's authenticated camouflage records.
pub async fn client_handshake_v3(
    raw: Stream,
    password: &[u8],
    tls: &ClientTlsConfig,
    strict: bool,
) -> io::Result<Stream> {
    let handshake_done = Arc::new(AtomicBool::new(false));
    let status =
        Arc::new(std::sync::Mutex::new(V3ClientHandshakeStatus::default()));
    let shim = spawn_v3_client_handshake_bridge(
        raw,
        password.to_vec(),
        handshake_done.clone(),
        status.clone(),
    );
    let mut config =
        (*tls.config_for_handshake().await.map_err(io::Error::other)?).clone();
    config.resumption = rustls::client::Resumption::disabled();
    config.client_hello_customizer =
        Some(Arc::new(ShadowTlsClientHelloCustomizer {
            finalizer: Arc::new(ShadowTlsSessionIdFinalizer {
                password: password.to_vec(),
            }),
        }));
    let handshake = TlsConnector::from(Arc::new(config))
        .connect(tls.server_name.clone(), shim);
    let stream = if let Some(handshake_timeout) = tls.handshake_timeout {
        tokio::time::timeout(handshake_timeout, handshake)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ShadowTLS v3 handshake timed out",
                )
            })?
    } else {
        handshake.await
    }
    .map_err(io::Error::other)?;
    let (shim, _) = stream.into_inner();
    handshake_done.store(true, Ordering::Release);
    let status = status.lock().map_err(|_| {
        io::Error::other("ShadowTLS v3 handshake state lock poisoned")
    })?;
    let server_random = status.server_random.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowTLS v3 server random was not received",
        )
    })?;
    if strict && !status.is_tls13 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowTLS v3 strict mode requires TLS 1.3",
        ));
    }
    if !status.authorized {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ShadowTLS v3 traffic was not authenticated",
        ));
    }
    drop(status);
    Ok(spawn_v3_tunnel(
        shim,
        V3RecordCodec::new(password, &server_random, b'C')?,
        V3RecordCodec::new(password, &server_random, b'S')?,
        Vec::new(),
    ))
}

fn spawn_v3_client_handshake_bridge(
    raw: Stream,
    password: Vec<u8>,
    handshake_done: Arc<AtomicBool>,
    status: Arc<std::sync::Mutex<V3ClientHandshakeStatus>>,
) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
    tokio::spawn(async move {
        let mut decoder: Option<V3HandshakeDecoder> = None;
        loop {
            tokio::select! {
                frame = read_tls_frame(&mut app_reader) => {
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(_) => return,
                    };
                    if raw_writer.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                frame = read_tls_frame(&mut raw_reader) => {
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(_) => return,
                    };
                    if handshake_done.load(Ordering::Acquire) {
                        if frame[0] == TLS_RECORD_APPLICATION_DATA
                            && let Some(active) = decoder.as_mut()
                            && active.decode(&frame).is_ok()
                        {
                            continue;
                        }
                        if app_writer.write_all(&frame).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    if let Some(random) = extract_v3_server_random(&frame) {
                        let tls13 = v3_server_hello_supports_tls13(&frame);
                        decoder = V3HandshakeDecoder::new(&password, &random).ok();
                        let mut shared = match status.lock() {
                            Ok(shared) => shared,
                            Err(_) => return,
                        };
                        shared.server_random = Some(random);
                        shared.is_tls13 = tls13;
                        shared.authorized = !tls13;
                    }
                    let output = if frame[0] == TLS_RECORD_APPLICATION_DATA {
                        let active = match decoder.as_mut() {
                            Some(active) => active,
                            None => return,
                        };
                        let output = match active.decode(&frame) {
                            Ok(output) => output,
                            Err(_) => return,
                        };
                        let mut shared = match status.lock() {
                            Ok(shared) => shared,
                            Err(_) => return,
                        };
                        shared.authorized = true;
                        output
                    } else {
                        frame
                    };
                    if app_writer.write_all(&output).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Box::new(application)
}

fn extract_v3_server_random(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    if frame.len() < SERVER_HELLO_RANDOM_START + TLS_RANDOM_SIZE
        || frame[0] != TLS_RECORD_HANDSHAKE
        || frame[TLS_HEADER_SIZE] != 2
    {
        return None;
    }
    frame
        [SERVER_HELLO_RANDOM_START..SERVER_HELLO_RANDOM_START + TLS_RANDOM_SIZE]
        .try_into()
        .ok()
}

fn v3_server_hello_supports_tls13(frame: &[u8]) -> bool {
    if extract_v3_server_random(frame).is_none()
        || frame.len() <= CLIENT_HELLO_SESSION_ID_LENGTH_INDEX
    {
        return false;
    }
    let mut cursor = CLIENT_HELLO_SESSION_ID_LENGTH_INDEX;
    let session_id_length = usize::from(frame[cursor]);
    cursor += 1 + session_id_length;
    if cursor + 5 > frame.len() {
        return false;
    }
    cursor += 3;
    let extensions_length =
        usize::from(u16::from_be_bytes([frame[cursor], frame[cursor + 1]]));
    cursor += 2;
    let extensions_end = match cursor.checked_add(extensions_length) {
        Some(end) if end <= frame.len() => end,
        _ => return false,
    };
    while cursor + 4 <= extensions_end {
        let extension_type =
            u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
        let extension_length = usize::from(u16::from_be_bytes([
            frame[cursor + 2],
            frame[cursor + 3],
        ]));
        cursor += 4;
        if cursor + extension_length > extensions_end {
            return false;
        }
        if extension_type == 43 {
            return extension_length == 2
                && frame[cursor..cursor + 2] == [0x03, 0x04];
        }
        cursor += extension_length;
    }
    false
}

/// Authenticate a ShadowTLS v3 client while relaying its real TLS handshake
/// to `decoy`, then return an authenticated proxy stream and the matched user.
pub async fn server_handshake_v3(
    mut client: Stream,
    decoy: Stream,
    users: &[V3User],
    strict: bool,
) -> io::Result<(Stream, V3User)> {
    let client_hello = read_tls_frame(&mut client).await?;
    let user = authenticate_v3_client_hello(&client_hello, users)?.clone();
    server_handshake_v3_authenticated(client, decoy, client_hello, user, strict)
        .await
}

/// Continue a v3 handshake after the caller has inspected and authenticated
/// the first ClientHello (for example to select an SNI-specific decoy).
pub async fn server_handshake_v3_authenticated(
    mut client: Stream,
    mut decoy: Stream,
    client_hello: Vec<u8>,
    user: V3User,
    strict: bool,
) -> io::Result<(Stream, V3User)> {
    decoy.write_all(&client_hello).await?;

    let server_random = loop {
        let frame = read_tls_frame(&mut decoy).await?;
        let random = extract_v3_server_random(&frame);
        client.write_all(&frame).await?;
        if let Some(random) = random {
            if strict && !v3_server_hello_supports_tls13(&frame) {
                tokio::io::copy_bidirectional(&mut client, &mut decoy).await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ShadowTLS v3 strict mode requires TLS 1.3",
                ));
            }
            break random;
        }
    };

    let (mut client_reader, client_writer) = tokio::io::split(client);
    let (mut decoy_reader, mut decoy_writer) = tokio::io::split(decoy);
    let mut client_writer = client_writer;
    let mut handshake_encoder =
        V3HandshakeEncoder::new(user.password.as_bytes(), &server_random)?;
    let initial_verify =
        V3RecordCodec::new(user.password.as_bytes(), &server_random, b'C')?;
    let (early_payload, verify) = loop {
        tokio::select! {
            frame = read_tls_frame(&mut client_reader) => {
                let frame = frame?;
                if frame[0] == TLS_RECORD_APPLICATION_DATA {
                    let mut candidate = initial_verify.clone();
                    if let Ok(payload) = candidate.decode(&frame) {
                        break (payload, candidate);
                    }
                }
                decoy_writer.write_all(&frame).await?;
            }
            frame = read_tls_frame(&mut decoy_reader) => {
                let frame = frame?;
                let output = if frame[0] == TLS_RECORD_APPLICATION_DATA {
                    handshake_encoder.encode(&frame)?
                } else {
                    frame
                };
                client_writer.write_all(&output).await?;
            }
        }
    };
    drop(decoy_reader);
    drop(decoy_writer);
    let client = client_reader.unsplit(client_writer);
    let add =
        V3RecordCodec::new(user.password.as_bytes(), &server_random, b'S')?;
    Ok((spawn_v3_tunnel(client, add, verify, early_payload), user))
}

/// Relay and authenticate a ShadowTLS v2 handshake. Authentication failures
/// are forwarded to the decoy for two application records before rejection,
/// preserving the upstream fallback boundary.
pub async fn server_handshake_v2(
    client: Stream,
    decoy: Stream,
    password: &[u8],
) -> io::Result<Stream> {
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut decoy_reader, mut decoy_writer) = tokio::io::split(decoy);
    let mut hash = Hmac::<Sha1>::new_from_slice(password)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut current_sum: Option<[u8; 8]> = None;
    let mut last_sum: Option<[u8; 8]> = None;
    let mut application_records = 0_usize;
    let early_payload = loop {
        tokio::select! {
            frame = read_tls_frame(&mut decoy_reader) => {
                let frame = frame?;
                if current_sum.is_some() {
                    last_sum = current_sum;
                }
                hash.update(&frame);
                current_sum = Some(hash.clone().finalize().into_bytes()[..8]
                    .try_into().expect("eight-byte HMAC prefix"));
                client_writer.write_all(&frame).await?;
                client_writer.flush().await?;
            }
            frame = read_tls_frame(&mut client_reader) => {
                let frame = frame?;
                let payload = &frame[TLS_HEADER_SIZE..];
                if frame[0] == TLS_RECORD_APPLICATION_DATA && payload.len() >= 8 {
                    let presented: [u8; 8] = payload[..8].try_into().unwrap();
                    if current_sum == Some(presented) || last_sum == Some(presented) {
                        break payload[8..].to_vec();
                    }
                }
                if frame[0] == TLS_RECORD_APPLICATION_DATA {
                    application_records += 1;
                }
                decoy_writer.write_all(&frame).await?;
                decoy_writer.flush().await?;
                if application_records > 2 {
                    let mut client = client_reader.unsplit(client_writer);
                    let mut decoy = decoy_reader.unsplit(decoy_writer);
                    tokio::io::copy_bidirectional(&mut client, &mut decoy)
                        .await?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "ShadowTLS v2 authentication failed",
                    ));
                }
            }
        }
    };
    drop(decoy_reader);
    drop(decoy_writer);
    let raw = client_reader.unsplit(client_writer);
    Ok(spawn_v2_tunnel(raw, None, early_payload))
}

async fn read_tls_frame<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0_u8; TLS_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + length);
    frame.extend_from_slice(&header);
    frame.resize(TLS_HEADER_SIZE + length, 0);
    reader.read_exact(&mut frame[TLS_HEADER_SIZE..]).await?;
    Ok(frame)
}

pub async fn read_first_tls_frame<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    read_tls_frame(reader).await
}

fn spawn_v2_tunnel(
    raw: Stream,
    first_write_prefix: Option<Vec<u8>>,
    early_read: Vec<u8>,
) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
    tokio::spawn(async move {
        let mut prefix = first_write_prefix;
        let mut buffer = vec![0_u8; TLS_MAX_PLAINTEXT];
        loop {
            let size = match app_reader.read(&mut buffer).await {
                Ok(size) => size,
                Err(_) => return,
            };
            if size == 0 {
                let _ = raw_writer.shutdown().await;
                return;
            }
            let prefix_len = prefix.as_ref().map_or(0, Vec::len);
            let mut payload = Vec::with_capacity(prefix_len + size);
            if let Some(prefix) = prefix.take() {
                payload.extend_from_slice(&prefix);
            }
            payload.extend_from_slice(&buffer[..size]);
            for chunk in payload.chunks(TLS_MAX_PLAINTEXT) {
                let mut header = [0_u8; TLS_HEADER_SIZE];
                header[0] = TLS_RECORD_APPLICATION_DATA;
                header[1..3].copy_from_slice(&[0x03, 0x03]);
                header[3..5]
                    .copy_from_slice(&(chunk.len() as u16).to_be_bytes());
                if raw_writer.write_all(&header).await.is_err()
                    || raw_writer.write_all(chunk).await.is_err()
                {
                    return;
                }
            }
        }
    });
    tokio::spawn(async move {
        if !early_read.is_empty()
            && app_writer.write_all(&early_read).await.is_err()
        {
            return;
        }
        loop {
            let frame = match read_tls_frame(&mut raw_reader).await {
                Ok(frame) => frame,
                Err(_) => {
                    let _ = app_writer.shutdown().await;
                    return;
                }
            };
            if frame[0] != TLS_RECORD_APPLICATION_DATA {
                let _ = app_writer.shutdown().await;
                return;
            }
            if app_writer
                .write_all(&frame[TLS_HEADER_SIZE..])
                .await
                .is_err()
            {
                return;
            }
        }
    });
    Box::new(application)
}

/// Relay exactly the visible TLS handshake between a client and decoy, then
/// return the original client transport positioned at the first proxy byte.
pub async fn server_handshake_v1(
    client: Stream,
    decoy: Stream,
) -> io::Result<Stream> {
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut decoy_reader, mut decoy_writer) = tokio::io::split(decoy);
    let (client_result, server_result) = tokio::join!(
        copy_until_handshake_finished(&mut decoy_writer, &mut client_reader),
        copy_until_handshake_finished(&mut client_writer, &mut decoy_reader),
    );
    client_result?;
    server_result?;
    drop(decoy_reader);
    drop(decoy_writer);
    Ok(client_reader.unsplit(client_writer))
}

/// Version-1 outbound adapter. ShadowTLS transports an inner protocol, so the
/// destination passed by that protocol is intentionally not written here.
pub struct ShadowTlsV1Outbound {
    upstream: Arc<dyn Dialer>,
    server: SocksAddr,
    tls: ClientTlsConfig,
    version: u8,
    password: Vec<u8>,
}

impl ShadowTlsV1Outbound {
    pub fn new(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        tls: ClientTlsConfig,
    ) -> Self {
        Self {
            upstream,
            server,
            tls,
            version: 1,
            password: Vec::new(),
        }
    }

    pub fn new_v2(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        password: impl Into<Vec<u8>>,
        tls: ClientTlsConfig,
    ) -> Self {
        Self {
            upstream,
            server,
            tls,
            version: 2,
            password: password.into(),
        }
    }

    pub fn new_v3(
        upstream: Arc<dyn Dialer>,
        server: SocksAddr,
        password: impl Into<Vec<u8>>,
        tls: ClientTlsConfig,
    ) -> Self {
        Self {
            upstream,
            server,
            tls,
            version: 3,
            password: password.into(),
        }
    }
}

impl Dialer for ShadowTlsV1Outbound {
    fn dial_tcp<'a>(&'a self, _destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let raw = self.upstream.dial_tcp(&self.server).await?;
            match self.version {
                1 => client_handshake_v1(raw, &self.tls).await,
                2 => client_handshake_v2(raw, &self.password, &self.tls).await,
                3 => {
                    client_handshake_v3(raw, &self.password, &self.tls, false)
                        .await
                }
                _ => unreachable!("validated ShadowTLS outbound version"),
            }
        })
    }
}

async fn copy_until_handshake_finished<R, W>(
    destination: &mut W,
    source: &mut R,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut saw_change_cipher_spec = false;
    loop {
        let mut header = [0_u8; TLS_HEADER_SIZE];
        source.read_exact(&mut header).await?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        destination.write_all(&header).await?;
        let mut payload = vec![0_u8; length];
        source.read_exact(&mut payload).await?;
        destination.write_all(&payload).await?;
        destination.flush().await?;

        if header[0] != TLS_RECORD_HANDSHAKE {
            if header[0] != TLS_RECORD_CHANGE_CIPHER_SPEC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected TLS record type: {}", header[0]),
                ));
            }
            if !saw_change_cipher_spec {
                saw_change_cipher_spec = true;
                continue;
            }
        }
        if saw_change_cipher_spec {
            return Ok(());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3User {
    pub name: String,
    pub password: String,
}

/// Replace a TLS ClientHello's 32-byte legacy session ID with 28 random bytes
/// and a four-byte authentication tag. `random_prefix` is injectable so Go
/// and Rust implementations can be compared with a stable vector.
pub fn patch_v3_client_hello_session_id(
    frame: &mut [u8],
    password: &[u8],
    random_prefix: [u8; TLS_SESSION_ID_SIZE - V3_HMAC_SIZE],
) -> io::Result<()> {
    validate_v3_client_hello(frame)?;
    let hmac_index =
        CLIENT_HELLO_SESSION_ID_START + TLS_SESSION_ID_SIZE - V3_HMAC_SIZE;
    frame[CLIENT_HELLO_SESSION_ID_START..hmac_index]
        .copy_from_slice(&random_prefix);
    frame[hmac_index..hmac_index + V3_HMAC_SIZE].fill(0);
    let tag = v3_client_hello_tag(frame, password)?;
    frame[hmac_index..hmac_index + V3_HMAC_SIZE].copy_from_slice(&tag);
    Ok(())
}

pub fn authenticate_v3_client_hello<'a>(
    frame: &[u8],
    users: &'a [V3User],
) -> io::Result<&'a V3User> {
    validate_v3_client_hello(frame)?;
    let hmac_index =
        CLIENT_HELLO_SESSION_ID_START + TLS_SESSION_ID_SIZE - V3_HMAC_SIZE;
    users
        .iter()
        .find(|user| {
            v3_client_hello_tag(frame, user.password.as_bytes()).is_ok_and(
                |expected| {
                    constant_time_equal(
                        &expected,
                        &frame[hmac_index..hmac_index + V3_HMAC_SIZE],
                    )
                },
            )
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ShadowTLS v3 ClientHello HMAC mismatch",
            )
        })
}

fn validate_v3_client_hello(frame: &[u8]) -> io::Result<()> {
    let minimum = CLIENT_HELLO_SESSION_ID_START + TLS_SESSION_ID_SIZE;
    if frame.len() < minimum {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "ShadowTLS v3 truncated ClientHello",
        ));
    }
    if frame[0] != TLS_RECORD_HANDSHAKE || frame[TLS_HEADER_SIZE] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowTLS v3 expected ClientHello",
        ));
    }
    if usize::from(frame[CLIENT_HELLO_SESSION_ID_LENGTH_INDEX])
        != TLS_SESSION_ID_SIZE
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ShadowTLS v3 ClientHello session ID must be 32 bytes",
        ));
    }
    Ok(())
}

fn v3_client_hello_tag(
    frame: &[u8],
    password: &[u8],
) -> io::Result<[u8; V3_HMAC_SIZE]> {
    let hmac_index =
        CLIENT_HELLO_SESSION_ID_START + TLS_SESSION_ID_SIZE - V3_HMAC_SIZE;
    let mut hmac = Hmac::<Sha1>::new_from_slice(password)
        .map_err(|error| io::Error::other(error.to_string()))?;
    hmac.update(&frame[TLS_HEADER_SIZE..hmac_index]);
    hmac.update(&[0_u8; V3_HMAC_SIZE]);
    hmac.update(&frame[hmac_index + V3_HMAC_SIZE..]);
    Ok(hmac.finalize().into_bytes()[..V3_HMAC_SIZE]
        .try_into()
        .expect("four-byte HMAC prefix"))
}

pub fn v3_kdf(
    password: &[u8],
    server_random: &[u8; TLS_RANDOM_SIZE],
) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hash = sha2::Sha256::new();
    hash.update(password);
    hash.update(server_random);
    hash.finalize().into()
}

/// Directional rolling HMAC used by authenticated ShadowTLS v3 tunnel
/// records. Each successfully emitted/accepted tag is fed back into the chain.
#[derive(Clone)]
pub struct V3RecordCodec {
    hmac: Hmac<Sha1>,
}

impl V3RecordCodec {
    pub fn new(
        password: &[u8],
        server_random: &[u8; TLS_RANDOM_SIZE],
        direction: u8,
    ) -> io::Result<Self> {
        if !matches!(direction, b'C' | b'S') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowTLS v3 direction must be C or S",
            ));
        }
        let mut hmac = Hmac::<Sha1>::new_from_slice(password)
            .map_err(|error| io::Error::other(error.to_string()))?;
        hmac.update(server_random);
        hmac.update(&[direction]);
        Ok(Self { hmac })
    }

    pub fn encode(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > TLS_MAX_PLAINTEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowTLS v3 record payload exceeds 16384 bytes",
            ));
        }
        self.hmac.update(payload);
        let tag: [u8; V3_HMAC_SIZE] = self.hmac.clone().finalize().into_bytes()
            [..V3_HMAC_SIZE]
            .try_into()
            .expect("four-byte HMAC prefix");
        self.hmac.update(&tag);
        let mut frame =
            Vec::with_capacity(TLS_HEADER_SIZE + V3_HMAC_SIZE + payload.len());
        frame.extend_from_slice(&[
            TLS_RECORD_APPLICATION_DATA,
            3,
            3,
            (((payload.len() + V3_HMAC_SIZE) >> 8) & 0xff) as u8,
            ((payload.len() + V3_HMAC_SIZE) & 0xff) as u8,
        ]);
        frame.extend_from_slice(&tag);
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    pub fn decode(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        if frame.len() < TLS_HEADER_SIZE + V3_HMAC_SIZE
            || frame[0] != TLS_RECORD_APPLICATION_DATA
            || frame[1..3] != [3, 3]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ShadowTLS v3 application record",
            ));
        }
        let declared = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
        if declared + TLS_HEADER_SIZE != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ShadowTLS v3 record length",
            ));
        }
        let tag = &frame[TLS_HEADER_SIZE..TLS_HEADER_SIZE + V3_HMAC_SIZE];
        let payload = &frame[TLS_HEADER_SIZE + V3_HMAC_SIZE..];
        self.hmac.update(payload);
        let expected = self.hmac.clone().finalize().into_bytes();
        if !constant_time_equal(tag, &expected[..V3_HMAC_SIZE]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS v3 application record HMAC mismatch",
            ));
        }
        self.hmac.update(tag);
        Ok(payload.to_vec())
    }
}

/// Wrap a raw transport with ShadowTLS v3 authenticated application records.
/// The directional codecs must be initialized with `C`/`S` from the local
/// endpoint's perspective. Any bytes extracted from the first authenticated
/// record can be supplied through `early_read`.
pub fn spawn_v3_tunnel(
    raw: Stream,
    mut add: V3RecordCodec,
    mut verify: V3RecordCodec,
    early_read: Vec<u8>,
) -> Stream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    let (mut app_reader, mut app_writer) = tokio::io::split(bridge);
    let (mut raw_reader, mut raw_writer) = tokio::io::split(raw);
    tokio::spawn(async move {
        if !early_read.is_empty()
            && app_writer.write_all(&early_read).await.is_err()
        {
            return;
        }
        let mut buffer = vec![0_u8; TLS_MAX_PLAINTEXT];
        loop {
            tokio::select! {
                read = app_reader.read(&mut buffer) => {
                    let size = match read {
                        Ok(size) => size,
                        Err(_) => return,
                    };
                    if size == 0 {
                        let _ = raw_writer.shutdown().await;
                        return;
                    }
                    let frame = match add.encode(&buffer[..size]) {
                        Ok(frame) => frame,
                        Err(_) => return,
                    };
                    if raw_writer.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                frame = read_tls_frame(&mut raw_reader) => {
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(_) => {
                            let _ = app_writer.shutdown().await;
                            return;
                        }
                    };
                    if frame[0] == 0x15 {
                        let _ = app_writer.shutdown().await;
                        return;
                    }
                    let payload = match verify.decode(&frame) {
                        Ok(payload) => payload,
                        Err(_) => {
                            let mut alert = [0_u8; 31];
                            alert[..5].copy_from_slice(&[0x15, 3, 3, 0, 26]);
                            if getrandom::fill(&mut alert[5..]).is_ok() {
                                let _ = raw_writer.write_all(&alert).await;
                            }
                            let _ = app_writer.shutdown().await;
                            return;
                        }
                    };
                    if app_writer.write_all(&payload).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Box::new(application)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0)
                ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::{
        common::{keygen::generate_tls_keypair, tls},
        option::{InboundTlsOptions, Listable, OutboundTlsOptions},
    };

    #[tokio::test]
    async fn v1_relays_tls12_handshake_then_exposes_raw_tunnel() {
        let pair = generate_tls_keypair("decoy.example", 1).unwrap();
        let server_options = InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![pair.certificate_pem.clone()]),
            key: Listable(vec![pair.private_key_pem]),
            min_version: "1.2".into(),
            max_version: "1.2".into(),
            ..Default::default()
        };
        let client_options = OutboundTlsOptions {
            enabled: true,
            server_name: "decoy.example".into(),
            certificate: Listable(vec![pair.certificate_pem]),
            min_version: "1.2".into(),
            max_version: "1.2".into(),
            ..Default::default()
        };
        let server_tls = tls::build_server_config(&server_options).unwrap();
        let client_tls =
            tls::build_client_config("decoy.example", &client_options, &[])
                .unwrap();

        let (client_raw, shadow_server_raw) = tokio::io::duplex(64 * 1024);
        let (shadow_decoy_raw, decoy_raw) = tokio::io::duplex(64 * 1024);
        let decoy = tokio::spawn(async move {
            let stream = TlsAcceptor::from(server_tls.config)
                .accept(decoy_raw)
                .await
                .unwrap();
            let (raw, _) = stream.into_inner();
            raw
        });
        let shadow = tokio::spawn(async move {
            server_handshake_v1(
                Box::new(shadow_server_raw),
                Box::new(shadow_decoy_raw),
            )
            .await
            .unwrap()
        });
        let mut client = client_handshake_v1(Box::new(client_raw), &client_tls)
            .await
            .unwrap();
        let _ = decoy.await.unwrap();
        let mut server = shadow.await.unwrap();

        client.write_all(b"proxy payload").await.unwrap();
        let mut payload = [0_u8; 13];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"proxy payload");
        server.write_all(b"response").await.unwrap();
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
    }

    #[tokio::test]
    async fn v2_authenticates_then_frames_application_data() {
        let pair = generate_tls_keypair("decoy.example", 1).unwrap();
        let server_options = InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![pair.certificate_pem.clone()]),
            key: Listable(vec![pair.private_key_pem]),
            min_version: "1.2".into(),
            max_version: "1.2".into(),
            ..Default::default()
        };
        let client_options = OutboundTlsOptions {
            enabled: true,
            server_name: "decoy.example".into(),
            certificate: Listable(vec![pair.certificate_pem]),
            min_version: "1.2".into(),
            max_version: "1.2".into(),
            ..Default::default()
        };
        let server_tls = tls::build_server_config(&server_options).unwrap();
        let client_tls =
            tls::build_client_config("decoy.example", &client_options, &[])
                .unwrap();

        let (client_raw, shadow_server_raw) = tokio::io::duplex(64 * 1024);
        let (shadow_decoy_raw, decoy_raw) = tokio::io::duplex(64 * 1024);
        let decoy = tokio::spawn(async move {
            let _stream = TlsAcceptor::from(server_tls.config)
                .accept(decoy_raw)
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let shadow = tokio::spawn(async move {
            server_handshake_v2(
                Box::new(shadow_server_raw),
                Box::new(shadow_decoy_raw),
                b"password",
            )
            .await
            .unwrap()
        });
        let mut client =
            client_handshake_v2(Box::new(client_raw), b"password", &client_tls)
                .await
                .unwrap();
        client.write_all(b"proxy payload").await.unwrap();
        client.flush().await.unwrap();
        let mut server = shadow.await.unwrap();
        let mut payload = [0_u8; 13];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"proxy payload");
        server.write_all(b"response").await.unwrap();
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        decoy.abort();
    }

    #[tokio::test]
    async fn relay_rejects_non_handshake_records_before_ccs() {
        let (mut source, destination) = tokio::io::duplex(64);
        let (mut relay_output, _sink) = tokio::io::duplex(64);
        let mut destination = destination;
        source
            .write_all(&[0x17, 0x03, 0x03, 0, 1, 0])
            .await
            .unwrap();
        let error =
            copy_until_handshake_finished(&mut relay_output, &mut destination)
                .await
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn v3_client_hello_authentication_matches_session_id_contract() {
        let mut hello = vec![0_u8; 96];
        hello[0] = TLS_RECORD_HANDSHAKE;
        hello[1..3].copy_from_slice(&[3, 1]);
        hello[3..5].copy_from_slice(&91_u16.to_be_bytes());
        hello[5] = 1;
        hello[CLIENT_HELLO_SESSION_ID_LENGTH_INDEX] = TLS_SESSION_ID_SIZE as u8;
        for (index, byte) in hello.iter_mut().enumerate().skip(6) {
            if index != CLIENT_HELLO_SESSION_ID_LENGTH_INDEX {
                *byte = index as u8;
            }
        }
        patch_v3_client_hello_session_id(
            &mut hello,
            b"right password",
            [0x42; 28],
        )
        .unwrap();

        let users = [
            V3User {
                name: "wrong".into(),
                password: "wrong password".into(),
            },
            V3User {
                name: "right".into(),
                password: "right password".into(),
            },
        ];
        assert_eq!(
            authenticate_v3_client_hello(&hello, &users).unwrap().name,
            "right"
        );

        hello[95] ^= 1;
        assert_eq!(
            authenticate_v3_client_hello(&hello, &users)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn v3_record_codec_matches_rolling_hmac_vectors() {
        let random: [u8; TLS_RANDOM_SIZE] =
            std::array::from_fn(|index| index as u8);
        assert_eq!(
            hex::encode(v3_kdf(b"secret", &random)),
            "ec4896ad884da7eb9ee3535f3cf6aabee49e926c581ee98f1afe14e711bf1fbf"
        );
        let mut sender = V3RecordCodec::new(b"secret", &random, b'C').unwrap();
        let mut receiver =
            V3RecordCodec::new(b"secret", &random, b'C').unwrap();

        let first = sender.encode(b"hello").unwrap();
        assert_eq!(&first[5..9], &[0x55, 0x21, 0xd8, 0x8f]);
        assert_eq!(receiver.decode(&first).unwrap(), b"hello");
        let second = sender.encode(b"world").unwrap();
        assert_eq!(&second[5..9], &[0x53, 0x2a, 0x6f, 0x1f]);
        assert_eq!(receiver.decode(&second).unwrap(), b"world");

        let mut altered = sender.encode(b"tamper").unwrap();
        *altered.last_mut().unwrap() ^= 1;
        assert_eq!(
            receiver.decode(&altered).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn v3_tunnel_transports_bidirectional_stream_data() {
        let random = [7_u8; TLS_RANDOM_SIZE];
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let mut client = spawn_v3_tunnel(
            Box::new(client_raw),
            V3RecordCodec::new(b"password", &random, b'C').unwrap(),
            V3RecordCodec::new(b"password", &random, b'S').unwrap(),
            Vec::new(),
        );
        let mut server = spawn_v3_tunnel(
            Box::new(server_raw),
            V3RecordCodec::new(b"password", &random, b'S').unwrap(),
            V3RecordCodec::new(b"password", &random, b'C').unwrap(),
            b"early".to_vec(),
        );

        let mut early = [0_u8; 5];
        server.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");
        client.write_all(b"request").await.unwrap();
        let mut request = [0_u8; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        server.write_all(b"response").await.unwrap();
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
    }

    #[tokio::test]
    async fn v3_real_tls_handshake_switches_to_authenticated_tunnel() {
        let pair = generate_tls_keypair("decoy.example", 1).unwrap();
        let server_options = InboundTlsOptions {
            enabled: true,
            certificate: Listable(vec![pair.certificate_pem.clone()]),
            key: Listable(vec![pair.private_key_pem]),
            min_version: "1.3".into(),
            max_version: "1.3".into(),
            ..Default::default()
        };
        let client_options = OutboundTlsOptions {
            enabled: true,
            server_name: "decoy.example".into(),
            certificate: Listable(vec![pair.certificate_pem]),
            min_version: "1.3".into(),
            max_version: "1.3".into(),
            ..Default::default()
        };
        let server_tls = tls::build_server_config(&server_options).unwrap();
        let client_tls =
            tls::build_client_config("decoy.example", &client_options, &[])
                .unwrap();
        let users = vec![V3User {
            name: "alice".into(),
            password: "password".into(),
        }];

        let (client_raw, shadow_server_raw) = tokio::io::duplex(64 * 1024);
        let (shadow_decoy_raw, decoy_raw) = tokio::io::duplex(64 * 1024);
        let decoy = tokio::spawn(async move {
            let _stream = TlsAcceptor::from(server_tls.config)
                .accept(decoy_raw)
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let shadow = tokio::spawn(async move {
            server_handshake_v3(
                Box::new(shadow_server_raw),
                Box::new(shadow_decoy_raw),
                &users,
                true,
            )
            .await
            .unwrap()
        });
        let mut client = client_handshake_v3(
            Box::new(client_raw),
            b"password",
            &client_tls,
            true,
        )
        .await
        .unwrap();
        client.write_all(b"proxy payload").await.unwrap();
        client.flush().await.unwrap();
        let (mut server, user) = shadow.await.unwrap();
        assert_eq!(user.name, "alice");
        let mut payload = [0_u8; 13];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"proxy payload");
        server.write_all(b"response").await.unwrap();
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        decoy.abort();
    }
}
