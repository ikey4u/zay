//! Linux kernel TLS record-layer integration.
//!
//! rustls performs and verifies the TLS 1.3 handshake. The resulting traffic
//! secrets and post-handshake state are then handed to Linux kTLS. Either
//! direction can remain in userspace, matching sing-box's independent
//! `kernel_tx` / `kernel_rx` switches.

use std::{
    collections::VecDeque,
    ffi::CStr,
    io, mem,
    os::fd::{BorrowedFd, RawFd},
    pin::Pin,
    process::Command,
    sync::OnceLock,
    task::{Context, Poll},
};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit as _, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use nix::sys::socket::{
    setsockopt,
    sockopt::{TcpTlsRx, TcpTlsTx, TcpUlp, TlsCryptoInfo},
};
use rustls::{
    ConnectionTrafficSecrets, ExtractedSecrets, ProtocolVersion,
    client::ClientConnectionData, kernel::KernelConnection,
    server::ServerConnectionData,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::adapter::Stream;
use crate::adapter::VisionDirectSwitch;

const RECORD_APPLICATION_DATA: u8 = 23;
const RECORD_ALERT: u8 = 21;
const RECORD_HANDSHAKE: u8 = 22;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const HANDSHAKE_KEY_UPDATE: u8 = 24;
const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_USER_CANCELED: u8 = 90;
const MAX_PLAINTEXT: usize = 16 * 1024;
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
const MAX_HANDSHAKE: usize = 64 * 1024;
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const TLS_GET_RECORD_TYPE: libc::c_int = 2;
const TLS_TX_ZEROCOPY_RO: libc::c_int = 3;
const TLS_RX_EXPECT_NO_PAD: libc::c_int = 4;

#[derive(Clone, Copy)]
struct KernelSupport {
    tls13_rx: bool,
    tx_zerocopy: bool,
    rx_no_padding: bool,
    tls13_key_update: bool,
}

static KERNEL_SUPPORT: OnceLock<Result<KernelSupport, String>> =
    OnceLock::new();

#[derive(Debug, Default)]
pub(crate) struct KtlsVisionSwitch {
    read_requested: std::sync::atomic::AtomicBool,
    write_requested: std::sync::atomic::AtomicBool,
    read_active: std::sync::atomic::AtomicBool,
    write_active: std::sync::atomic::AtomicBool,
}

impl KtlsVisionSwitch {
    fn read_requested(&self) -> bool {
        self.read_requested
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn write_requested(&self) -> bool {
        self.write_requested
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn activate_read(&self) {
        self.read_active
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn activate_write(&self) {
        self.write_active
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

impl VisionDirectSwitch for KtlsVisionSwitch {
    fn request_read_direct(&self) {
        self.read_requested
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn request_write_direct(&self) {
        self.write_requested
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn read_direct_active(&self) -> bool {
        self.read_active.load(std::sync::atomic::Ordering::Acquire)
    }

    fn write_direct_active(&self) -> bool {
        self.write_active.load(std::sync::atomic::Ordering::Acquire)
    }
}

pub(crate) fn load() -> io::Result<()> {
    kernel_support().map(|_| ())
}

fn kernel_support() -> io::Result<KernelSupport> {
    KERNEL_SUPPORT
        .get_or_init(detect_kernel_support)
        .as_ref()
        .copied()
        .map_err(|message| {
            io::Error::new(io::ErrorKind::Unsupported, message.clone())
        })
}

fn detect_kernel_support() -> Result<KernelSupport, String> {
    let mut information: libc::utsname = unsafe { mem::zeroed() };
    if unsafe { libc::uname(&mut information) } != 0 {
        return Err(format!(
            "read Linux kernel version: {}",
            io::Error::last_os_error()
        ));
    }
    let release = unsafe { CStr::from_ptr(information.release.as_ptr()) }
        .to_string_lossy();
    let version = parse_kernel_version(&release).ok_or_else(|| {
        format!("cannot parse Linux kernel release {release:?}")
    })?;
    if version < (5, 1) {
        return Err(format!(
            "Linux kernel {release} does not support TLS 1.3 kTLS"
        ));
    }
    if !std::path::Path::new("/sys/module/tls").exists() {
        if unsafe { libc::geteuid() } != 0 {
            return Err("Linux kernel TLS module is not loaded".into());
        }
        let output = Command::new("modprobe")
            .arg("tls")
            .output()
            .map_err(|error| format!("run modprobe tls: {error}"))?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr);
            return Err(format!("modprobe tls failed: {}", message.trim()));
        }
    }
    Ok(KernelSupport {
        tls13_rx: version >= (6, 0),
        tx_zerocopy: version >= (5, 19),
        rx_no_padding: version >= (6, 0),
        tls13_key_update: version >= (6, 14),
    })
}

fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut components = release.split('.');
    Some((
        components.next()?.parse().ok()?,
        components.next()?.parse().ok()?,
    ))
}

enum ExternalState {
    Client(KernelConnection<ClientConnectionData>),
    Server(KernelConnection<ServerConnectionData>),
}

impl ExternalState {
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> io::Result<()> {
        match self {
            Self::Client(state) => state
                .export_keying_material(output, label, context)
                .map(|_| ())
                .map_err(io::Error::other),
            Self::Server(state) => state
                .export_keying_material(output, label, context)
                .map(|_| ())
                .map_err(io::Error::other),
        }
    }

    fn update_tx_secret(
        &mut self,
    ) -> io::Result<(u64, ConnectionTrafficSecrets)> {
        match self {
            Self::Client(state) => state.update_tx_secret(),
            Self::Server(state) => state.update_tx_secret(),
        }
        .map_err(io::Error::other)
    }

    fn update_rx_secret(
        &mut self,
    ) -> io::Result<(u64, ConnectionTrafficSecrets)> {
        match self {
            Self::Client(state) => state.update_rx_secret(),
            Self::Server(state) => state.update_rx_secret(),
        }
        .map_err(io::Error::other)
    }

    fn handle_new_session_ticket(&mut self, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Client(state) => state
                .handle_new_session_ticket(payload)
                .map_err(io::Error::other),
            Self::Server(_) => Err(invalid_data(
                "TLS server received an unexpected NewSessionTicket",
            )),
        }
    }
}

enum SoftwareCipher {
    Aes128(Box<Aes128Gcm>, [u8; 12]),
    Aes256(Box<Aes256Gcm>, [u8; 12]),
    ChaCha20(Box<ChaCha20Poly1305>, [u8; 12]),
}

impl SoftwareCipher {
    fn new(secret: ConnectionTrafficSecrets) -> io::Result<Self> {
        match secret {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                let cipher =
                    Aes128Gcm::new_from_slice(key.as_ref()).map_err(|_| {
                        invalid_data("invalid AES-128-GCM traffic key")
                    })?;
                Ok(Self::Aes128(Box::new(cipher), copy_iv(&iv)?))
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                let cipher =
                    Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| {
                        invalid_data("invalid AES-256-GCM traffic key")
                    })?;
                Ok(Self::Aes256(Box::new(cipher), copy_iv(&iv)?))
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
                    .map_err(|_| {
                        invalid_data("invalid ChaCha20-Poly1305 traffic key")
                    })?;
                Ok(Self::ChaCha20(Box::new(cipher), copy_iv(&iv)?))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kTLS does not support the negotiated cipher suite",
            )),
        }
    }

    fn seal(&self, sequence: u64, typ: u8, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(data.len() + 1);
        plaintext.extend_from_slice(data);
        plaintext.push(typ);
        let payload_len = plaintext
            .len()
            .checked_add(16)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or_else(|| invalid_data("TLS record is too large"))?;
        let header = [23, 3, 3, (payload_len >> 8) as u8, payload_len as u8];
        let nonce = self.nonce(sequence);
        let payload = Payload {
            msg: &plaintext,
            aad: &header,
        };
        let encrypted = match self {
            Self::Aes128(cipher, _) => cipher.encrypt(&nonce.into(), payload),
            Self::Aes256(cipher, _) => cipher.encrypt(&nonce.into(), payload),
            Self::ChaCha20(cipher, _) => cipher.encrypt(&nonce.into(), payload),
        }
        .map_err(|_| invalid_data("TLS record encryption failed"))?;
        let mut record = Vec::with_capacity(header.len() + encrypted.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&encrypted);
        Ok(record)
    }

    fn open(
        &self,
        sequence: u64,
        header: &[u8; 5],
        ciphertext: &[u8],
    ) -> io::Result<(u8, Vec<u8>)> {
        let nonce = self.nonce(sequence);
        let payload = Payload {
            msg: ciphertext,
            aad: header,
        };
        let mut plaintext = match self {
            Self::Aes128(cipher, _) => cipher.decrypt(&nonce.into(), payload),
            Self::Aes256(cipher, _) => cipher.decrypt(&nonce.into(), payload),
            Self::ChaCha20(cipher, _) => cipher.decrypt(&nonce.into(), payload),
        }
        .map_err(|_| invalid_data("TLS record authentication failed"))?;
        let content = plaintext
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or_else(|| {
                invalid_data("TLS 1.3 record has no content type")
            })?;
        let typ = plaintext[content];
        plaintext.truncate(content);
        Ok((typ, plaintext))
    }

    fn nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = match self {
            Self::Aes128(_, iv)
            | Self::Aes256(_, iv)
            | Self::ChaCha20(_, iv) => *iv,
        };
        for (left, right) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *left ^= right;
        }
        nonce
    }
}

enum PendingWrite {
    Bytes {
        data: Vec<u8>,
        offset: usize,
    },
    KernelRecord {
        typ: u8,
        data: Vec<u8>,
        offset: usize,
        rekey: Option<(TlsCryptoInfo, u64)>,
    },
}

/// An asynchronous TLS 1.3 stream whose requested record directions have
/// been moved into Linux kTLS.
pub(crate) struct KtlsStream {
    transport: Stream,
    socket: RawFd,
    state: ExternalState,
    kernel_tx: bool,
    kernel_rx: bool,
    tx_cipher: Option<SoftwareCipher>,
    rx_cipher: Option<SoftwareCipher>,
    tx_sequence: u64,
    tx_confidentiality_limit: u64,
    rx_sequence: u64,
    raw_input: Vec<u8>,
    plaintext: VecDeque<u8>,
    handshake: Vec<u8>,
    pending_write: VecDeque<PendingWrite>,
    peer_closed: bool,
    shutdown_started: bool,
    vision_switch: Option<std::sync::Arc<KtlsVisionSwitch>>,
}

impl KtlsStream {
    pub(crate) fn new_client(
        stream: tokio_rustls::client::TlsStream<Stream>,
        socket: RawFd,
        kernel_tx: bool,
        kernel_rx: bool,
    ) -> io::Result<Self> {
        let (transport, connection) = stream.into_inner();
        if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kTLS requires TLS 1.3",
            ));
        }
        let (secrets, state) = connection
            .dangerous_into_kernel_connection()
            .map_err(io::Error::other)?;
        Self::new(
            transport,
            socket,
            ExternalState::Client(state),
            secrets,
            kernel_tx,
            kernel_rx,
        )
    }

    pub(crate) fn new_server(
        stream: tokio_rustls::server::TlsStream<Stream>,
        socket: RawFd,
        kernel_tx: bool,
        kernel_rx: bool,
    ) -> io::Result<Self> {
        let (transport, connection) = stream.into_inner();
        if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kTLS requires TLS 1.3",
            ));
        }
        let (secrets, state) = connection
            .dangerous_into_kernel_connection()
            .map_err(io::Error::other)?;
        Self::new(
            transport,
            socket,
            ExternalState::Server(state),
            secrets,
            kernel_tx,
            kernel_rx,
        )
    }

    fn new(
        transport: Stream,
        socket: RawFd,
        state: ExternalState,
        secrets: ExtractedSecrets,
        kernel_tx: bool,
        kernel_rx: bool,
    ) -> io::Result<Self> {
        if !kernel_tx && !kernel_rx {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "kTLS requires kernel_tx or kernel_rx",
            ));
        }
        let support = kernel_support()?;
        if kernel_rx && !support.tls13_rx {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS 1.3 kTLS RX requires Linux 6.0 or later",
            ));
        }
        let borrowed = unsafe { BorrowedFd::borrow_raw(socket) };
        setsockopt(&borrowed, TcpUlp::default(), b"tls")
            .map_err(socket_error("enable TCP TLS ULP"))?;

        let (tx_sequence, tx_secret) = secrets.tx;
        let (rx_sequence, rx_secret) = secrets.rx;
        let tx_cipher = if kernel_tx {
            let crypto = kernel_crypto(tx_secret, tx_sequence)?;
            setsockopt(&borrowed, TcpTlsTx, &crypto)
                .map_err(socket_error("install kTLS TX key"))?;
            if support.tx_zerocopy {
                enable_integer(socket, TLS_TX_ZEROCOPY_RO)?;
            }
            None
        } else {
            Some(SoftwareCipher::new(tx_secret)?)
        };
        let rx_cipher = if kernel_rx {
            let crypto = kernel_crypto(rx_secret, rx_sequence)?;
            setsockopt(&borrowed, TcpTlsRx, &crypto)
                .map_err(socket_error("install kTLS RX key"))?;
            if support.rx_no_padding {
                enable_integer(socket, TLS_RX_EXPECT_NO_PAD)?;
            }
            None
        } else {
            Some(SoftwareCipher::new(rx_secret)?)
        };

        let tx_confidentiality_limit = match &state {
            ExternalState::Client(state) => state.confidentiality_limit(),
            ExternalState::Server(state) => state.confidentiality_limit(),
        };
        Ok(Self {
            transport,
            socket,
            state,
            kernel_tx,
            kernel_rx,
            tx_cipher,
            rx_cipher,
            tx_sequence,
            tx_confidentiality_limit,
            rx_sequence,
            raw_input: Vec::new(),
            plaintext: VecDeque::new(),
            handshake: Vec::new(),
            pending_write: VecDeque::new(),
            peer_closed: false,
            shutdown_started: false,
            vision_switch: None,
        })
    }

    pub(crate) fn enable_vision(
        &mut self,
        vision_switch: std::sync::Arc<KtlsVisionSwitch>,
    ) {
        self.vision_switch = Some(vision_switch);
    }

    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> io::Result<()> {
        self.state.export_keying_material(output, label, context)
    }

    fn queue_record(&mut self, typ: u8, data: &[u8]) -> io::Result<()> {
        if self.kernel_tx {
            self.pending_write.push_back(PendingWrite::KernelRecord {
                typ,
                data: data.to_vec(),
                offset: 0,
                rekey: None,
            });
        } else {
            self.check_tx_confidentiality_limit()?;
            let cipher = self
                .tx_cipher
                .as_ref()
                .ok_or_else(|| invalid_data("missing userspace TX cipher"))?;
            let record = cipher.seal(self.tx_sequence, typ, data)?;
            self.tx_sequence = self
                .tx_sequence
                .checked_add(1)
                .ok_or_else(|| invalid_data("TLS TX sequence exhausted"))?;
            self.pending_write.push_back(PendingWrite::Bytes {
                data: record,
                offset: 0,
            });
        }
        Ok(())
    }

    fn queue_key_update_response(&mut self) -> io::Result<()> {
        const RESPONSE: &[u8] = &[HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0];
        if self.kernel_tx {
            let (sequence, secret) = self.state.update_tx_secret()?;
            let rekey = kernel_crypto(secret, sequence)?;
            self.pending_write.push_back(PendingWrite::KernelRecord {
                typ: RECORD_HANDSHAKE,
                data: RESPONSE.to_vec(),
                offset: 0,
                rekey: Some((rekey, sequence)),
            });
        } else {
            self.queue_record(RECORD_HANDSHAKE, RESPONSE)?;
            let (sequence, secret) = self.state.update_tx_secret()?;
            self.tx_cipher = Some(SoftwareCipher::new(secret)?);
            self.tx_sequence = sequence;
        }
        Ok(())
    }

    fn check_tx_confidentiality_limit(&self) -> io::Result<()> {
        if self.tx_sequence >= self.tx_confidentiality_limit {
            Err(io::Error::other(
                "TLS cipher suite confidentiality limit reached",
            ))
        } else {
            Ok(())
        }
    }

    fn process_record(&mut self, typ: u8, data: Vec<u8>) -> io::Result<()> {
        match typ {
            RECORD_APPLICATION_DATA => self.plaintext.extend(data),
            RECORD_ALERT => {
                if data.len() != 2 {
                    return Err(invalid_data("malformed TLS alert"));
                }
                match data[1] {
                    ALERT_CLOSE_NOTIFY => self.peer_closed = true,
                    ALERT_USER_CANCELED => {}
                    description => {
                        return Err(invalid_data(format!(
                            "peer sent TLS alert {description}"
                        )));
                    }
                }
            }
            RECORD_HANDSHAKE => {
                self.handshake.extend_from_slice(&data);
                self.process_handshake_messages()?;
            }
            _ => {
                return Err(invalid_data(format!(
                    "unexpected post-handshake TLS record type {typ}"
                )));
            }
        }
        Ok(())
    }

    fn process_handshake_messages(&mut self) -> io::Result<()> {
        loop {
            if self.handshake.len() < 4 {
                return Ok(());
            }
            let length = (usize::from(self.handshake[1]) << 16)
                | (usize::from(self.handshake[2]) << 8)
                | usize::from(self.handshake[3]);
            if length > MAX_HANDSHAKE {
                return Err(invalid_data(
                    "post-handshake TLS message is too large",
                ));
            }
            if self.handshake.len() < 4 + length {
                return Ok(());
            }
            let message =
                self.handshake.drain(..4 + length).collect::<Vec<_>>();
            match message[0] {
                HANDSHAKE_NEW_SESSION_TICKET => {
                    self.state.handle_new_session_ticket(&message[4..])?;
                }
                HANDSHAKE_KEY_UPDATE => {
                    if message[4..].len() != 1 || message[4] > 1 {
                        return Err(invalid_data("malformed TLS KeyUpdate"));
                    }
                    let support = kernel_support()?;
                    if self.kernel_rx && !support.tls13_key_update {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "TLS 1.3 kTLS RX rekey requires Linux 6.14 or later",
                        ));
                    }
                    if message[4] == 1
                        && self.kernel_tx
                        && !support.tls13_key_update
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "TLS 1.3 kTLS TX rekey requires Linux 6.14 or later",
                        ));
                    }
                    let (sequence, secret) = self.state.update_rx_secret()?;
                    if self.kernel_rx {
                        let crypto = kernel_crypto(secret, sequence)?;
                        let borrowed =
                            unsafe { BorrowedFd::borrow_raw(self.socket) };
                        setsockopt(&borrowed, TcpTlsRx, &crypto)
                            .map_err(socket_error("replace kTLS RX key"))?;
                    } else {
                        self.rx_cipher = Some(SoftwareCipher::new(secret)?);
                        self.rx_sequence = sequence;
                    }
                    if message[4] == 1 {
                        self.queue_key_update_response()?;
                    }
                }
                message_type => {
                    return Err(invalid_data(format!(
                        "unexpected post-handshake message type {message_type}"
                    )));
                }
            }
        }
    }

    fn process_userspace_records(&mut self) -> io::Result<bool> {
        let mut progressed = false;
        loop {
            if self.raw_input.len() < 5 {
                return Ok(progressed);
            }
            let header: [u8; 5] = self.raw_input[..5]
                .try_into()
                .expect("TLS record header length checked");
            if header[0] != RECORD_APPLICATION_DATA || header[1..3] != [3, 3] {
                return Err(invalid_data(
                    "invalid TLS 1.3 outer record header",
                ));
            }
            let length =
                usize::from(u16::from_be_bytes([header[3], header[4]]));
            if length > MAX_CIPHERTEXT {
                return Err(invalid_data("oversized TLS 1.3 record"));
            }
            if self.raw_input.len() < 5 + length {
                return Ok(progressed);
            }
            let ciphertext = self.raw_input[5..5 + length].to_vec();
            self.raw_input.drain(..5 + length);
            let cipher = self
                .rx_cipher
                .as_ref()
                .ok_or_else(|| invalid_data("missing userspace RX cipher"))?;
            let (typ, plaintext) =
                cipher.open(self.rx_sequence, &header, &ciphertext)?;
            self.rx_sequence = self
                .rx_sequence
                .checked_add(1)
                .ok_or_else(|| invalid_data("TLS RX sequence exhausted"))?;
            self.process_record(typ, plaintext)?;
            progressed = true;
            if !self.plaintext.is_empty() || self.peer_closed {
                return Ok(true);
            }
        }
    }

    fn receive_kernel_record(&mut self) -> io::Result<()> {
        let mut data = vec![0_u8; MAX_PLAINTEXT];
        let mut control = [0_usize; 8];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = mem::size_of_val(&control);
        let size = unsafe {
            libc::recvmsg(self.socket, &mut message, libc::MSG_DONTWAIT)
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            self.peer_closed = true;
            return Ok(());
        }
        if message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(invalid_data("truncated kTLS control message"));
        }
        data.truncate(size as usize);
        let mut typ = RECORD_APPLICATION_DATA;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if !header.is_null()
            && unsafe { (*header).cmsg_level } == libc::SOL_TLS
            && unsafe { (*header).cmsg_type } == TLS_GET_RECORD_TYPE
        {
            typ = unsafe { *libc::CMSG_DATA(header).cast::<u8>() };
        }
        self.process_record(typ, data)
    }

    fn copy_plaintext(&mut self, output: &mut ReadBuf<'_>) -> bool {
        if self.plaintext.is_empty() || output.remaining() == 0 {
            return false;
        }
        let size = output.remaining().min(self.plaintext.len());
        let (first, second) = self.plaintext.as_slices();
        let first_size = size.min(first.len());
        output.put_slice(&first[..first_size]);
        if first_size < size {
            output.put_slice(&second[..size - first_size]);
        }
        self.plaintext.drain(..size);
        true
    }

    fn poll_drain_pending(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let Some(mut pending) = self.pending_write.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            match &mut pending {
                PendingWrite::Bytes { data, offset } => {
                    match Pin::new(&mut self.transport)
                        .poll_write(cx, &data[*offset..])
                    {
                        Poll::Pending => {
                            self.pending_write.push_front(pending);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(
                                io::ErrorKind::WriteZero.into()
                            ));
                        }
                        Poll::Ready(Ok(size)) => *offset += size,
                    }
                    if *offset < data.len() {
                        self.pending_write.push_front(pending);
                        continue;
                    }
                }
                PendingWrite::KernelRecord {
                    typ,
                    data,
                    offset,
                    rekey,
                } => {
                    if let Err(error) = self.check_tx_confidentiality_limit() {
                        return Poll::Ready(Err(error));
                    }
                    match send_kernel_record(
                        self.socket,
                        *typ,
                        &data[*offset..],
                    ) {
                        Ok(0) => {
                            return Poll::Ready(Err(
                                io::ErrorKind::WriteZero.into()
                            ));
                        }
                        Ok(size) => {
                            *offset += size;
                            self.tx_sequence =
                                match self.tx_sequence.checked_add(1) {
                                    Some(sequence) => sequence,
                                    None => {
                                        return Poll::Ready(Err(invalid_data(
                                            "TLS TX sequence exhausted",
                                        )));
                                    }
                                };
                            if *offset < data.len() {
                                self.pending_write.push_front(pending);
                                continue;
                            }
                            if let Some((crypto, sequence)) = rekey.take() {
                                let borrowed = unsafe {
                                    BorrowedFd::borrow_raw(self.socket)
                                };
                                if let Err(error) =
                                    setsockopt(&borrowed, TcpTlsTx, &crypto)
                                        .map_err(socket_error(
                                            "replace kTLS TX key",
                                        ))
                                {
                                    return Poll::Ready(Err(error));
                                }
                                self.tx_sequence = sequence;
                            }
                        }
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock =>
                        {
                            self.pending_write.push_front(pending);
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
            }
        }
    }
}

impl AsyncRead for KtlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || self.copy_plaintext(output) {
            return Poll::Ready(Ok(()));
        }
        if self.peer_closed {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(vision_switch) = &self.vision_switch
                && vision_switch.read_requested()
            {
                vision_switch.activate_read();
                if !self.kernel_rx {
                    if !self.raw_input.is_empty() {
                        let size = output.remaining().min(self.raw_input.len());
                        output.put_slice(&self.raw_input[..size]);
                        self.raw_input.drain(..size);
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut self.transport).poll_read(cx, output);
                }
            }
            if self.kernel_rx {
                let before = output.filled().len();
                match Pin::new(&mut self.transport).poll_read(cx, output) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(error))
                        if error.raw_os_error() == Some(libc::EINVAL) =>
                    {
                        match self.receive_kernel_record() {
                            Ok(()) => {}
                            Err(error)
                                if error.kind()
                                    == io::ErrorKind::WouldBlock =>
                            {
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                            Err(error) => return Poll::Ready(Err(error)),
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                }
                if output.filled().len() != before
                    || self.copy_plaintext(output)
                    || self.peer_closed
                {
                    return Poll::Ready(Ok(()));
                }
            } else {
                if let Err(error) = self.process_userspace_records() {
                    return Poll::Ready(Err(error));
                }
                if self.copy_plaintext(output) || self.peer_closed {
                    return Poll::Ready(Ok(()));
                }
                let mut scratch = [0_u8; 8192];
                let mut input = ReadBuf::new(&mut scratch);
                match Pin::new(&mut self.transport).poll_read(cx, &mut input) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if input.filled().is_empty() => {
                        self.peer_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(())) => {
                        self.raw_input.extend_from_slice(input.filled());
                    }
                }
            }
        }
    }
}

impl AsyncWrite for KtlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.poll_drain_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if self.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS connection is shut down",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(vision_switch) = &self.vision_switch
            && vision_switch.write_requested()
        {
            vision_switch.activate_write();
            if !self.kernel_tx {
                return Pin::new(&mut self.transport).poll_write(cx, data);
            }
        }
        if self.kernel_tx {
            if let Err(error) = self.check_tx_confidentiality_limit() {
                return Poll::Ready(Err(error));
            }
            let size = data.len().min(MAX_PLAINTEXT);
            return match Pin::new(&mut self.transport)
                .poll_write(cx, &data[..size])
            {
                Poll::Ready(Ok(written)) if written > 0 => {
                    self.tx_sequence = match self.tx_sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => {
                            return Poll::Ready(Err(invalid_data(
                                "TLS TX sequence exhausted",
                            )));
                        }
                    };
                    Poll::Ready(Ok(written))
                }
                result => result,
            };
        }
        let size = data.len().min(MAX_PLAINTEXT);
        if let Err(error) =
            self.queue_record(RECORD_APPLICATION_DATA, &data[..size])
        {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(size))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_drain_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.transport).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.shutdown_started {
            self.shutdown_started = true;
            if let Err(error) =
                self.queue_record(RECORD_ALERT, &[1, ALERT_CLOSE_NOTIFY])
            {
                return Poll::Ready(Err(error));
            }
        }
        match self.poll_drain_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                Pin::new(&mut self.transport).poll_shutdown(cx)
            }
        }
    }
}

fn copy_iv(iv: &rustls::crypto::cipher::Iv) -> io::Result<[u8; 12]> {
    iv.as_ref()
        .try_into()
        .map_err(|_| invalid_data("invalid TLS traffic IV"))
}

fn kernel_crypto(
    secret: ConnectionTrafficSecrets,
    sequence: u64,
) -> io::Result<TlsCryptoInfo> {
    let rec_seq = sequence.to_be_bytes();
    match secret {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let iv = copy_iv(&iv)?;
            Ok(TlsCryptoInfo::Aes128Gcm(
                libc::tls12_crypto_info_aes_gcm_128 {
                    info: libc::tls_crypto_info {
                        version: libc::TLS_1_3_VERSION,
                        cipher_type: libc::TLS_CIPHER_AES_GCM_128,
                    },
                    iv: iv[4..].try_into().expect("8-byte AES IV"),
                    key: key.as_ref().try_into().map_err(|_| {
                        invalid_data("invalid AES-128-GCM traffic key")
                    })?,
                    salt: iv[..4].try_into().expect("4-byte AES salt"),
                    rec_seq,
                },
            ))
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let iv = copy_iv(&iv)?;
            Ok(TlsCryptoInfo::Aes256Gcm(
                libc::tls12_crypto_info_aes_gcm_256 {
                    info: libc::tls_crypto_info {
                        version: libc::TLS_1_3_VERSION,
                        cipher_type: libc::TLS_CIPHER_AES_GCM_256,
                    },
                    iv: iv[4..].try_into().expect("8-byte AES IV"),
                    key: key.as_ref().try_into().map_err(|_| {
                        invalid_data("invalid AES-256-GCM traffic key")
                    })?,
                    salt: iv[..4].try_into().expect("4-byte AES salt"),
                    rec_seq,
                },
            ))
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            Ok(TlsCryptoInfo::Chacha20Poly1305(
                libc::tls12_crypto_info_chacha20_poly1305 {
                    info: libc::tls_crypto_info {
                        version: libc::TLS_1_3_VERSION,
                        cipher_type: libc::TLS_CIPHER_CHACHA20_POLY1305,
                    },
                    iv: copy_iv(&iv)?,
                    key: key.as_ref().try_into().map_err(|_| {
                        invalid_data("invalid ChaCha20-Poly1305 traffic key")
                    })?,
                    salt: [],
                    rec_seq,
                },
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kTLS does not support the negotiated cipher suite",
        )),
    }
}

fn send_kernel_record(
    socket: RawFd,
    typ: u8,
    data: &[u8],
) -> io::Result<usize> {
    let mut control = [0_usize; 4];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(1) as usize };
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(invalid_data("failed to allocate kTLS control message"));
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_TLS;
        (*header).cmsg_type = TLS_SET_RECORD_TYPE;
        (*header).cmsg_len = libc::CMSG_LEN(1) as usize;
        *libc::CMSG_DATA(header).cast::<u8>() = typ;
    }
    let size = unsafe { libc::sendmsg(socket, &message, libc::MSG_DONTWAIT) };
    if size < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(size as usize)
    }
}

fn enable_integer(socket: RawFd, name: libc::c_int) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_TLS,
            name,
            (&enabled as *const libc::c_int).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn socket_error(
    operation: &'static str,
) -> impl FnOnce(nix::Error) -> io::Error {
    move |error| io::Error::other(format!("{operation}: {error}"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_round_trip(cipher: SoftwareCipher) {
        let record = cipher
            .seal(42, RECORD_HANDSHAKE, b"ticket")
            .expect("seal TLS 1.3 record");
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let (typ, plaintext) = cipher
            .open(42, &header, &record[5..])
            .expect("open TLS 1.3 record");
        assert_eq!(typ, RECORD_HANDSHAKE);
        assert_eq!(plaintext, b"ticket");
    }

    #[test]
    fn tls13_nonce_xors_big_endian_sequence_into_iv_tail() {
        let cipher = SoftwareCipher::Aes128(
            Box::new(Aes128Gcm::new_from_slice(&[0_u8; 16]).unwrap()),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        );
        assert_eq!(
            cipher.nonce(0x0102_0304_0506_0708),
            [0, 1, 2, 3, 5, 7, 5, 3, 13, 15, 13, 3]
        );
    }

    #[test]
    fn userspace_tls13_record_round_trip_covers_kernel_cipher_set() {
        assert_round_trip(SoftwareCipher::Aes128(
            Box::new(Aes128Gcm::new_from_slice(&[7_u8; 16]).unwrap()),
            [9_u8; 12],
        ));
        assert_round_trip(SoftwareCipher::Aes256(
            Box::new(Aes256Gcm::new_from_slice(&[8_u8; 32]).unwrap()),
            [10_u8; 12],
        ));
        assert_round_trip(SoftwareCipher::ChaCha20(
            Box::new(ChaCha20Poly1305::new_from_slice(&[11_u8; 32]).unwrap()),
            [12_u8; 12],
        ));
    }

    #[test]
    fn userspace_tls13_record_rejects_tampering_and_oversize() {
        let cipher = SoftwareCipher::Aes128(
            Box::new(Aes128Gcm::new_from_slice(&[7_u8; 16]).unwrap()),
            [9_u8; 12],
        );
        let mut record = cipher.seal(42, RECORD_HANDSHAKE, b"ticket").unwrap();
        let header: [u8; 5] = record[..5].try_into().unwrap();
        *record.last_mut().unwrap() ^= 1;
        assert!(cipher.open(42, &header, &record[5..]).is_err());
        assert!(
            cipher
                .seal(
                    0,
                    RECORD_APPLICATION_DATA,
                    &vec![0; usize::from(u16::MAX)]
                )
                .is_err()
        );
    }

    #[test]
    fn parses_distribution_kernel_release_suffixes() {
        assert_eq!(parse_kernel_version("6.14.0-1018-aws"), Some((6, 14)));
        assert_eq!(parse_kernel_version("5.15.0-1092-azure"), Some((5, 15)));
        assert_eq!(parse_kernel_version("invalid"), None);
    }
}
