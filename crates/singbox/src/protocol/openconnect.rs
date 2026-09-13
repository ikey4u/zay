//! Native AnyConnect CSTP wire format and tunnel negotiation primitives.
//!
//! This module intentionally exposes protocol building blocks instead of a
//! process-oriented client.  `zay` can compose them with singbox dialers and
//! TLS streams without spawning an `openconnect` or `sing-box` binary.

#[path = "openconnect_auth.rs"]
mod auth;
#[path = "openconnect_auth_continuation.rs"]
mod auth_continuation;
#[path = "openconnect_auth_driver.rs"]
mod auth_driver;
#[path = "openconnect_auth_http.rs"]
mod auth_http;
#[path = "openconnect_auth_mca.rs"]
mod auth_mca;
#[path = "openconnect_certificate_dtls.rs"]
mod certificate_dtls;
#[path = "openconnect_certificate_dtls_legacy.rs"]
mod certificate_dtls_legacy;
#[path = "openconnect_certificate_dtls_legacy_crypto.rs"]
mod certificate_dtls_legacy_crypto;
#[path = "openconnect_certificate_dtls_legacy_wire.rs"]
mod certificate_dtls_legacy_wire;
#[path = "openconnect_channel.rs"]
mod channel;
#[path = "openconnect_compression.rs"]
mod compression;
#[path = "openconnect_connector.rs"]
mod connector;
#[path = "openconnect_dtls12.rs"]
mod dtls12;
#[path = "openconnect_dtls12_handshake.rs"]
mod dtls12_handshake;
#[path = "openconnect_dtls12_session.rs"]
mod dtls12_session;
#[path = "openconnect_dtls_legacy.rs"]
mod dtls_legacy;
#[path = "openconnect_dtls_legacy_handshake.rs"]
mod dtls_legacy_handshake;
#[path = "openconnect_dtls_legacy_session.rs"]
mod dtls_legacy_session;
#[path = "openconnect_dtls_psk.rs"]
mod dtls_psk;
#[path = "openconnect_esp.rs"]
mod esp;
#[path = "openconnect_esp_channel.rs"]
mod esp_channel;
#[path = "openconnect_f5_auth_driver.rs"]
mod f5_auth_driver;
#[path = "openconnect_f5_config.rs"]
mod f5_config;
#[path = "openconnect_f5_form.rs"]
mod f5_form;
#[path = "openconnect_f5_tunnel.rs"]
mod f5_tunnel;
#[path = "openconnect_fortinet_auth_driver.rs"]
mod fortinet_auth_driver;
#[path = "openconnect_fortinet_config.rs"]
mod fortinet_config;
#[path = "openconnect_fortinet_form.rs"]
mod fortinet_form;
#[path = "openconnect_fortinet_tunnel.rs"]
mod fortinet_tunnel;
#[path = "openconnect_gp_auth.rs"]
mod gp_auth;
#[path = "openconnect_gp_auth_driver.rs"]
mod gp_auth_driver;
#[path = "openconnect_gp_config.rs"]
mod gp_config;
#[path = "openconnect_gp_form.rs"]
mod gp_form;
#[path = "openconnect_gp_hip.rs"]
mod gp_hip;
#[path = "openconnect_gp_probe.rs"]
mod gp_probe;
#[path = "openconnect_gpst.rs"]
mod gpst;
#[path = "openconnect_host_scan.rs"]
mod host_scan;
#[path = "openconnect_nc_auth_driver.rs"]
mod nc_auth_driver;
#[path = "openconnect_nc_form.rs"]
mod nc_form;
#[path = "openconnect_nc_oncp.rs"]
mod nc_oncp;
#[path = "openconnect_nc_tncc.rs"]
mod nc_tncc;
#[path = "openconnect_ppp_control.rs"]
mod ppp_control;
#[path = "openconnect_ppp_datagram_session.rs"]
mod ppp_datagram_session;
#[path = "openconnect_ppp_frame.rs"]
mod ppp_frame;
#[path = "openconnect_ppp_negotiation.rs"]
mod ppp_negotiation;
#[path = "openconnect_ppp_session.rs"]
mod ppp_session;
#[path = "openconnect_pulse_auth.rs"]
mod pulse_auth;
#[path = "openconnect_pulse_config.rs"]
mod pulse_config;
#[path = "openconnect_pulse_form.rs"]
mod pulse_form;
#[path = "openconnect_pulse_ift.rs"]
mod pulse_ift;
#[path = "openconnect_pulse_ttls.rs"]
mod pulse_ttls;
#[path = "openconnect_pulse_tunnel.rs"]
mod pulse_tunnel;
#[path = "openconnect_session.rs"]
mod session;
#[path = "openconnect_stoken.rs"]
mod stoken;
#[path = "openconnect_token.rs"]
mod token;

pub use auth::*;
pub use auth_continuation::*;
pub use auth_driver::*;
pub use auth_http::*;
pub use auth_mca::*;
pub use certificate_dtls::*;
pub use certificate_dtls_legacy::*;
pub use certificate_dtls_legacy_crypto::*;
pub use certificate_dtls_legacy_wire::*;
pub use channel::*;
pub use compression::*;
pub use connector::*;
pub use dtls_legacy::*;
pub use dtls_legacy_handshake::*;
pub use dtls_legacy_session::*;
pub use dtls_psk::*;
pub use dtls12::*;
pub use dtls12_handshake::*;
pub use dtls12_session::*;
pub use esp::*;
pub use esp_channel::*;
pub use f5_auth_driver::*;
pub use f5_config::*;
pub use f5_form::*;
pub use f5_tunnel::*;
pub use fortinet_auth_driver::*;
pub use fortinet_config::*;
pub use fortinet_form::*;
pub use fortinet_tunnel::*;
pub use gp_auth::*;
pub use gp_auth_driver::*;
pub use gp_config::*;
pub use gp_form::*;
pub use gp_hip::*;
pub use gp_probe::*;
pub use gpst::*;
pub use host_scan::*;
pub use nc_auth_driver::*;
pub use nc_form::*;
pub use nc_oncp::*;
pub use nc_tncc::*;
pub use ppp_control::*;
pub use ppp_datagram_session::*;
pub use ppp_frame::*;
pub use ppp_negotiation::*;
pub use ppp_session::*;
pub use pulse_auth::*;
pub use pulse_config::*;
pub use pulse_form::*;
pub use pulse_ift::*;
pub use pulse_ttls::*;
pub use pulse_tunnel::*;
pub use session::*;
pub use stoken::*;
pub use token::*;

/// Default tunnel MTU used by sing-box when an OpenConnect server leaves the
/// negotiated value unset.
pub const OPENCONNECT_DEFAULT_MTU: u32 = 1500;

use std::{
    fmt::Write as _,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::{Duration, SystemTime},
};

use http::{HeaderMap, HeaderName, HeaderValue};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite,
    AsyncWriteExt,
};

const CSTP_MAGIC: [u8; 4] = *b"STF\x01";
const CSTP_HEADER_SIZE: usize = 8;
pub const CSTP_MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;
pub const CSTP_DEFAULT_BASE_MTU: u32 = 1406;
pub const CSTP_MAX_MTU: u32 = CSTP_MAX_PAYLOAD_SIZE as u32;
const CSTP_DTLS_OVERHEAD: u32 = 82;
// Go: (math.MaxInt64) / (2 * time.Second).
const CSTP_MAX_TIMER_SECONDS: u64 = (i64::MAX as u64) / 2_000_000_000;
pub const CSTP_MAX_STATUS_LINE_SIZE: usize = 8192;
pub const CSTP_MAX_HEADER_SIZE: usize = 1024 * 1024;

const DEFAULT_DTLS_CIPHER_SUITES: &str = "PSK-NEGOTIATE:OC2-DTLS1_2-CHACHA20-POLY1305:OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA";
const DEFAULT_DTLS12_CIPHER_SUITES: &str = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA";

#[derive(Debug, Error)]
pub enum CstpError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("CSTP protocol error: {0}")]
    Protocol(String),
    #[error("invalid CSTP option: {0}")]
    InvalidOption(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CstpPacketType {
    Data,
    DpdRequest,
    DpdResponse,
    Disconnect,
    Keepalive,
    Compressed,
    Terminate,
    Unknown(u8),
}

impl CstpPacketType {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::DpdRequest => 3,
            Self::DpdResponse => 4,
            Self::Disconnect => 5,
            Self::Keepalive => 7,
            Self::Compressed => 8,
            Self::Terminate => 9,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for CstpPacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Data,
            3 => Self::DpdRequest,
            4 => Self::DpdResponse,
            5 => Self::Disconnect,
            7 => Self::Keepalive,
            8 => Self::Compressed,
            9 => Self::Terminate,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpPacket {
    pub packet_type: CstpPacketType,
    pub payload: Vec<u8>,
}

pub async fn write_cstp_packet<W>(
    writer: &mut W,
    packet_type: CstpPacketType,
    payload: &[u8],
) -> Result<(), CstpError>
where
    W: AsyncWrite + Unpin,
{
    let payload_size = u16::try_from(payload.len()).map_err(|_| {
        CstpError::Protocol(format!(
            "payload exceeds {CSTP_MAX_PAYLOAD_SIZE} bytes: {}",
            payload.len()
        ))
    })?;
    let mut header = [0_u8; CSTP_HEADER_SIZE];
    header[..4].copy_from_slice(&CSTP_MAGIC);
    header[4..6].copy_from_slice(&payload_size.to_be_bytes());
    header[6] = packet_type.wire_value();
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    Ok(())
}

pub async fn write_cstp_disconnect<W>(
    writer: &mut W,
    reason: &str,
) -> Result<(), CstpError>
where
    W: AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(reason.len() + 1);
    payload.push(0xb0);
    payload.extend_from_slice(reason.as_bytes());
    write_cstp_packet(writer, CstpPacketType::Disconnect, &payload).await
}

pub async fn read_cstp_packet<R>(
    reader: &mut R,
    maximum_payload_size: usize,
) -> Result<CstpPacket, CstpError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; CSTP_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    if header[..4] != CSTP_MAGIC || header[7] != 0 {
        return Err(CstpError::Protocol("invalid packet header".into()));
    }
    let payload_size = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if maximum_payload_size > 0 && payload_size > maximum_payload_size {
        return Err(CstpError::Protocol(format!(
            "payload exceeds receive limit: {payload_size}"
        )));
    }
    let mut payload = vec![0; payload_size];
    reader.read_exact(&mut payload).await?;
    Ok(CstpPacket {
        packet_type: header[6].into(),
        payload,
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CstpCompressionMode {
    #[default]
    Stateless,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpMobileIdentity {
    pub client_version: String,
    pub platform: String,
    pub platform_version: String,
    pub device_type: String,
    pub device_unique_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpConnectOptions {
    pub server: String,
    pub user_agent: String,
    pub local_hostname: String,
    pub cookie: String,
    pub mobile: Option<CstpMobileIdentity>,
    pub compression_disabled: bool,
    pub compression_mode: CstpCompressionMode,
    pub base_mtu: u32,
    pub tunnel_mtu: u32,
    pub remote_is_ipv6: bool,
    pub ipv6_disabled: bool,
    pub previous_addresses: Vec<IpNet>,
    pub no_udp: bool,
    pub dtls_master_secret: Vec<u8>,
    pub dtls_cipher_suites: Option<String>,
    pub dtls12_cipher_suites: Option<String>,
    pub allow_insecure_crypto: bool,
}

impl Default for CstpConnectOptions {
    fn default() -> Self {
        Self {
            server: String::new(),
            user_agent: String::new(),
            local_hostname: String::new(),
            cookie: String::new(),
            mobile: None,
            compression_disabled: false,
            compression_mode: CstpCompressionMode::Stateless,
            base_mtu: 0,
            tunnel_mtu: 0,
            remote_is_ipv6: false,
            ipv6_disabled: false,
            previous_addresses: Vec::new(),
            no_udp: false,
            dtls_master_secret: Vec::new(),
            dtls_cipher_suites: None,
            dtls12_cipher_suites: None,
            allow_insecure_crypto: false,
        }
    }
}

pub fn calculate_cstp_request_mtu(
    requested_base_mtu: u32,
    requested_tunnel_mtu: u32,
    remote_is_ipv6: bool,
) -> (u32, u32) {
    let base_mtu = if requested_base_mtu == 0 {
        CSTP_DEFAULT_BASE_MTU
    } else {
        requested_base_mtu.max(1280)
    };
    if requested_tunnel_mtu != 0 {
        return (base_mtu, requested_tunnel_mtu);
    }
    let ip_header_size = if remote_is_ipv6 { 40 } else { 20 };
    let overhead = ip_header_size + 8 + CSTP_DTLS_OVERHEAD;
    (base_mtu, base_mtu.saturating_sub(overhead).max(1))
}

pub fn build_cstp_connect_request(
    options: &CstpConnectOptions,
) -> Result<Vec<u8>, CstpError> {
    validate_header_value("server", &options.server)?;
    validate_header_value("user agent", &options.user_agent)?;
    validate_header_value("local hostname", &options.local_hostname)?;
    validate_header_value("webvpn cookie", &options.cookie)?;
    if let Some(mobile) = &options.mobile {
        validate_header_value("mobile client version", &mobile.client_version)?;
        validate_header_value("mobile platform", &mobile.platform)?;
        validate_header_value(
            "mobile platform version",
            &mobile.platform_version,
        )?;
        validate_header_value("mobile device type", &mobile.device_type)?;
        validate_header_value("mobile device ID", &mobile.device_unique_id)?;
    }
    for (name, value) in [
        ("DTLS cipher suites", options.dtls_cipher_suites.as_deref()),
        (
            "DTLS 1.2 cipher suites",
            options.dtls12_cipher_suites.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            validate_header_value(name, value)?;
        }
    }

    let (base_mtu, tunnel_mtu) = calculate_cstp_request_mtu(
        options.base_mtu,
        options.tunnel_mtu,
        options.remote_is_ipv6,
    );
    let mut request = String::new();
    write!(
        request,
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nCookie: webvpn={}\r\nX-CSTP-Version: 1\r\nX-CSTP-Hostname: {}\r\nX-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.\r\n",
        options.server, options.user_agent, options.cookie, options.local_hostname
    )
    .expect("String writes cannot fail");
    if let Some(mobile) = &options.mobile {
        write!(
            request,
            "X-AnyConnect-Identifier-ClientVersion: {}\r\nX-AnyConnect-Identifier-Platform: {}\r\nX-AnyConnect-Identifier-PlatformVersion: {}\r\nX-AnyConnect-Identifier-DeviceType: {}\r\nX-AnyConnect-Identifier-Device-UniqueID: {}\r\n",
            mobile.client_version,
            mobile.platform,
            mobile.platform_version,
            mobile.device_type,
            mobile.device_unique_id
        )
        .expect("String writes cannot fail");
    }
    if !options.compression_disabled {
        request.push_str("X-CSTP-Accept-Encoding: oc-lz4,lzs");
        if options.compression_mode == CstpCompressionMode::All {
            request.push_str(",deflate");
        }
        request.push_str("\r\n");
    }
    write!(
        request,
        "X-CSTP-Base-MTU: {base_mtu}\r\nX-CSTP-MTU: {tunnel_mtu}\r\n"
    )
    .expect("String writes cannot fail");
    if options.ipv6_disabled {
        request.push_str("X-CSTP-Address-Type: IPv4\r\n");
    } else {
        request.push_str(
            "X-CSTP-Address-Type: IPv6,IPv4\r\nX-CSTP-Full-IPv6-Capability: true\r\n",
        );
    }
    for address in &options.previous_addresses {
        if options.ipv6_disabled && address.addr().is_ipv6() {
            continue;
        }
        writeln!(request, "X-CSTP-Address: {}\r", address.addr())
            .expect("String writes cannot fail");
    }
    if !options.no_udp {
        request.push_str("X-DTLS-Master-Secret: ");
        for byte in &options.dtls_master_secret {
            write!(request, "{byte:02X}").expect("String writes cannot fail");
        }
        request.push_str("\r\n");
        let custom_suites = options.dtls_cipher_suites.is_some()
            || options.dtls12_cipher_suites.is_some();
        if custom_suites {
            if let Some(suites) = &options.dtls_cipher_suites {
                writeln!(request, "X-DTLS-CipherSuite: {suites}\r")
                    .expect("String writes cannot fail");
            }
            if let Some(suites) = &options.dtls12_cipher_suites {
                writeln!(request, "X-DTLS12-CipherSuite: {suites}\r")
                    .expect("String writes cannot fail");
            }
        } else {
            write!(request, "X-DTLS-CipherSuite: {DEFAULT_DTLS_CIPHER_SUITES}")
                .expect("String writes cannot fail");
            if options.allow_insecure_crypto {
                request.push_str(":DES-CBC3-SHA:DES-CBC-SHA");
            }
            write!(
                request,
                "\r\nX-DTLS12-CipherSuite: {DEFAULT_DTLS12_CIPHER_SUITES}\r\n"
            )
            .expect("String writes cannot fail");
        }
        if !options.compression_disabled {
            request.push_str("X-DTLS-Accept-Encoding: oc-lz4,lzs\r\n");
        }
    }
    request.push_str("\r\n");
    Ok(request.into_bytes())
}

fn validate_header_value(name: &str, value: &str) -> Result<(), CstpError> {
    if value.contains(['\r', '\n']) {
        Err(CstpError::InvalidOption(format!(
            "{name} contains a line break"
        )))
    } else {
        Ok(())
    }
}

pub fn parse_cstp_status_line(line: &str) -> Result<u16, CstpError> {
    let mut fields = line.split_ascii_whitespace();
    let version = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(CstpError::Protocol(format!(
            "invalid HTTP status line: {}",
            line.trim()
        )));
    }
    status.parse::<u16>().map_err(|_| {
        CstpError::Protocol(format!("invalid HTTP status code: {status}"))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpDtlsOption {
    pub suffix: String,
    pub value: String,
    pub dtls12: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpDtlsNegotiationOptions {
    pub server_host: String,
    pub server_port: u16,
    pub authenticated_address: Option<IpAddr>,
    pub master_secret: Vec<u8>,
    pub mtu: u32,
    pub compression_disabled: bool,
    pub compression_mode: CstpCompressionMode,
    pub dpd_override: Option<Duration>,
    pub allow_insecure_crypto: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpDtlsNegotiation {
    pub host: String,
    pub port: u16,
    pub cipher_suite: String,
    pub dtls12: bool,
    pub session_id: Vec<u8>,
    pub app_id: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub mtu: u32,
    pub compression: CstpCompression,
    pub dpd: Duration,
    pub keepalive: Duration,
    pub rekey: Duration,
    pub rekey_method: CstpRekeyMethod,
    pub allow_insecure_crypto: bool,
}

/// Selects a DTLS offer using the exact server header order captured by
/// [`read_cstp_http_response`].  A response without a cipher suite means that
/// the gateway declined UDP and is represented as `Ok(None)`.
pub fn parse_cstp_dtls_negotiation(
    dtls_options: &[CstpDtlsOption],
    options: &CstpDtlsNegotiationOptions,
) -> Result<Option<CstpDtlsNegotiation>, CstpError> {
    if options.server_port == 0 {
        return Err(CstpError::InvalidOption(
            "DTLS server port must not be zero".into(),
        ));
    }
    if options.mtu == 0 || options.mtu > CSTP_MAX_MTU {
        return Err(CstpError::InvalidOption(format!(
            "invalid DTLS MTU: {}",
            options.mtu
        )));
    }
    let mut result = CstpDtlsNegotiation {
        host: options.authenticated_address.map_or_else(
            || options.server_host.clone(),
            |address| address.to_string(),
        ),
        port: options.server_port,
        cipher_suite: String::new(),
        dtls12: false,
        session_id: Vec::new(),
        app_id: Vec::new(),
        master_secret: options.master_secret.clone(),
        mtu: options.mtu,
        compression: CstpCompression::None,
        dpd: Duration::ZERO,
        keepalive: Duration::ZERO,
        rekey: Duration::ZERO,
        rekey_method: CstpRekeyMethod::None,
        allow_insecure_crypto: options.allow_insecure_crypto,
    };
    for option in dtls_options {
        let header_name = if option.dtls12 {
            format!("X-DTLS12-{}", option.suffix)
        } else {
            format!("X-DTLS-{}", option.suffix)
        };
        match option.suffix.to_ascii_lowercase().as_str() {
            "ciphersuite" => {
                result.cipher_suite = option.value.clone();
                result.dtls12 = option.dtls12;
            }
            "session-id" => {
                result.session_id =
                    decode_hex_header(&option.value, &header_name)?;
                if result.session_id.len() != 32 {
                    return Err(CstpError::Protocol(format!(
                        "{header_name} must contain 32 bytes, got {}",
                        result.session_id.len()
                    )));
                }
            }
            "app-id" => {
                result.app_id = decode_hex_header(&option.value, &header_name)?;
                if result.app_id.is_empty() {
                    return Err(CstpError::Protocol(format!(
                        "{header_name} must not be empty"
                    )));
                }
            }
            "content-encoding" => {
                result.compression = parse_compression(
                    &option.value,
                    options.compression_disabled,
                    options.compression_mode,
                    false,
                )?;
            }
            "port" => {
                result.port =
                    option.value.trim().parse::<u16>().map_err(|_| {
                        CstpError::Protocol(format!(
                            "invalid {header_name}: {}",
                            option.value
                        ))
                    })?;
                if result.port == 0 {
                    return Err(CstpError::Protocol(format!(
                        "invalid {header_name}: {}",
                        option.value
                    )));
                }
            }
            "keepalive" => {
                result.keepalive = parse_duration(&option.value, &header_name)?;
            }
            "dpd" => {
                let dpd = parse_duration(&option.value, &header_name)?;
                if !dpd.is_zero() && result.dpd.is_zero() {
                    result.dpd = dpd;
                }
            }
            "rekey-time" => {
                result.rekey = parse_duration(&option.value, &header_name)?;
            }
            "rekey-method" => {
                result.rekey_method = parse_rekey_method(&option.value)?;
            }
            _ => {}
        }
    }
    if result.cipher_suite.is_empty() {
        return Ok(None);
    }
    if let Some(dpd) = options.dpd_override {
        result.dpd = dpd;
    }
    if result.rekey.is_zero() {
        result.rekey_method = CstpRekeyMethod::None;
    }
    Ok(Some(result))
}

fn decode_hex_header(value: &str, name: &str) -> Result<Vec<u8>, CstpError> {
    hex::decode(value.trim())
        .map_err(|error| CstpError::Protocol(format!("decode {name}: {error}")))
}

#[derive(Debug, Clone)]
pub struct CstpHttpResponse {
    pub status_code: u16,
    pub headers: HeaderMap,
    /// DTLS headers in their original wire order.  Order matters because an
    /// AnyConnect gateway may advertise several mutually exclusive suites.
    pub dtls_options: Vec<CstpDtlsOption>,
}

/// Reads the HTTP/1 response prefix that switches a TLS stream into CSTP.
/// The reader remains positioned at the first CSTP record.
pub async fn read_cstp_http_response<R>(
    reader: &mut R,
) -> Result<CstpHttpResponse, CstpError>
where
    R: AsyncBufRead + Unpin,
{
    let status_line =
        read_limited_line(reader, CSTP_MAX_STATUS_LINE_SIZE).await?;
    if status_line.is_empty() {
        return Err(CstpError::Protocol("empty HTTP status line".into()));
    }
    let status_code = parse_cstp_status_line(&status_line)?;
    let mut total_header_size = 0_usize;
    let mut logical_headers: Vec<(String, String)> = Vec::new();
    loop {
        let remaining = CSTP_MAX_HEADER_SIZE
            .checked_sub(total_header_size)
            .ok_or_else(|| {
                CstpError::Protocol("HTTP headers exceed limit".into())
            })?;
        let line = read_limited_line(reader, remaining).await?;
        total_header_size += line.len();
        if line == "\n" || line == "\r\n" {
            break;
        }
        let content = line.trim_end_matches(['\r', '\n']);
        if content.starts_with([' ', '\t']) {
            let Some((_, value)) = logical_headers.last_mut() else {
                return Err(CstpError::Protocol(
                    "HTTP header continuation has no preceding field".into(),
                ));
            };
            value.push(' ');
            value.push_str(content.trim());
            continue;
        }
        let (name, value) = content.split_once(':').ok_or_else(|| {
            CstpError::Protocol(format!(
                "invalid HTTP header line: {content:?}"
            ))
        })?;
        logical_headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let mut headers = HeaderMap::new();
    let mut dtls_options = Vec::new();
    for (name, value) in logical_headers {
        let header_name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                CstpError::Protocol(format!(
                    "invalid HTTP header name {name:?}: {error}"
                ))
            })?;
        let header_value = HeaderValue::from_str(&value).map_err(|error| {
            CstpError::Protocol(format!(
                "invalid HTTP header value for {name}: {error}"
            ))
        })?;
        let lower_name = name.to_ascii_lowercase();
        let dtls = if let Some(suffix) = lower_name.strip_prefix("x-dtls-") {
            Some((suffix, false))
        } else {
            lower_name
                .strip_prefix("x-dtls12-")
                .map(|suffix| (suffix, true))
        };
        if let Some((suffix, dtls12)) = dtls {
            dtls_options.push(CstpDtlsOption {
                suffix: suffix.to_owned(),
                value: value.clone(),
                dtls12,
            });
        }
        headers.append(header_name, header_value);
    }
    Ok(CstpHttpResponse {
        status_code,
        headers,
        dtls_options,
    })
}

async fn read_limited_line<R>(
    reader: &mut R,
    maximum_size: usize,
) -> Result<String, CstpError>
where
    R: AsyncBufRead + Unpin,
{
    let mut encoded = Vec::new();
    let read = reader.read_until(b'\n', &mut encoded).await?;
    if read == 0 {
        return Err(CstpError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "CSTP HTTP response ended before a complete line",
        )));
    }
    if encoded.len() > maximum_size {
        return Err(CstpError::Protocol(format!(
            "HTTP line exceeds {maximum_size} bytes"
        )));
    }
    String::from_utf8(encoded).map_err(|_| {
        CstpError::Protocol("HTTP response contains invalid UTF-8".into())
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CstpCompression {
    #[default]
    None,
    OcLz4,
    Lzs,
    Deflate,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CstpRekeyMethod {
    #[default]
    None,
    NewTunnel,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRoute {
    pub prefix: IpNet,
    pub gateway: Option<IpAddr>,
    pub metric: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSplitDnsRule {
    pub domains: Vec<String>,
    pub servers: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfiguration {
    pub mtu: u32,
    pub remote_address: Option<IpAddr>,
    pub addresses: Vec<IpNet>,
    pub routes: Vec<TunnelRoute>,
    pub excluded_routes: Vec<TunnelRoute>,
    pub dns: Vec<IpAddr>,
    pub nbns: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub split_dns: Vec<String>,
    pub split_dns_rules: Vec<TunnelSplitDnsRule>,
    pub proxy_auto_config_url: String,
    pub banner: String,
    pub tunnel_all_dns: bool,
    pub client_bypass_protocol: bool,
    pub idle_timeout: Duration,
    pub authentication_expiration: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpNegotiatedState {
    pub configuration: TunnelConfiguration,
    pub dynamic_dns: bool,
    pub dpd: Duration,
    pub keepalive: Duration,
    pub rekey: Duration,
    pub rekey_method: CstpRekeyMethod,
    pub compression: CstpCompression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpResponseOptions {
    pub ipv6_disabled: bool,
    pub no_udp: bool,
    pub compression_disabled: bool,
    pub compression_mode: CstpCompressionMode,
    pub dpd_override: Option<Duration>,
    pub authenticated_address: Option<IpAddr>,
}

impl Default for CstpResponseOptions {
    fn default() -> Self {
        Self {
            ipv6_disabled: false,
            no_udp: false,
            compression_disabled: false,
            compression_mode: CstpCompressionMode::Stateless,
            dpd_override: None,
            authenticated_address: None,
        }
    }
}

pub fn parse_cstp_response(
    headers: &HeaderMap,
    options: &CstpResponseOptions,
    now: SystemTime,
) -> Result<CstpNegotiatedState, CstpError> {
    let mut mtu = parse_positive_integer(
        first_header(headers, "x-cstp-mtu")?,
        "X-CSTP-MTU",
    )?;
    for name in ["x-dtls-mtu", "x-dtls12-mtu"] {
        for value in header_values(headers, name)? {
            mtu = mtu.max(parse_positive_integer(&value, "X-DTLS-MTU")?);
        }
    }
    if mtu == 0 {
        return Err(CstpError::Protocol(
            "server did not provide a valid MTU".into(),
        ));
    }
    if mtu > CSTP_MAX_MTU {
        return Err(CstpError::Protocol(format!(
            "MTU exceeds wire limit: {mtu} > {CSTP_MAX_MTU}"
        )));
    }

    let mut addresses = parse_cstp_addresses(headers)?;
    if options.ipv6_disabled {
        addresses.retain(|prefix| prefix.addr().is_ipv4());
    }
    if addresses.is_empty() {
        let message = if options.ipv6_disabled {
            "server did not provide an IPv4 tunnel address"
        } else {
            "server did not provide a tunnel address"
        };
        return Err(CstpError::Protocol(message.into()));
    }

    let mut routes = parse_routes(
        header_values(headers, "x-cstp-split-include")?,
        header_values(headers, "x-cstp-split-include-ip6")?,
    )?;
    let mut excluded_routes = parse_routes(
        header_values(headers, "x-cstp-split-exclude")?,
        header_values(headers, "x-cstp-split-exclude-ip6")?,
    )?;
    let mut dns = parse_addresses_without_prefix(
        header_values(headers, "x-cstp-dns")?,
        header_values(headers, "x-cstp-dns-ip6")?,
        "DNS",
    )?;
    let mut nbns = parse_addresses_without_prefix(
        header_values(headers, "x-cstp-nbns")?,
        Vec::new(),
        "NBNS",
    )?;
    if options.ipv6_disabled {
        routes.retain(|route| route.prefix.addr().is_ipv4());
        excluded_routes.retain(|route| route.prefix.addr().is_ipv4());
        dns.retain(IpAddr::is_ipv4);
        nbns.retain(IpAddr::is_ipv4);
    }
    add_default_routes(&addresses, &mut routes)?;

    let search_domains = header_values(headers, "x-cstp-default-domain")?
        .into_iter()
        .flat_map(|value| {
            value
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    let split_dns = header_values(headers, "x-cstp-split-dns")?
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect();

    let mut dpd =
        parse_duration(first_header(headers, "x-cstp-dpd")?, "X-CSTP-DPD")?;
    if let Some(value) = options.dpd_override {
        dpd = value;
    }
    let keepalive = parse_duration(
        first_header(headers, "x-cstp-keepalive")?,
        "X-CSTP-Keepalive",
    )?;
    let rekey = parse_duration(
        first_header(headers, "x-cstp-rekey-time")?,
        "X-CSTP-Rekey-Time",
    )?;
    let mut rekey_method =
        parse_rekey_method(first_header(headers, "x-cstp-rekey-method")?)?;
    if rekey.is_zero() {
        rekey_method = CstpRekeyMethod::None;
    }
    let idle_timeout = parse_duration(
        first_header(headers, "x-cstp-idle-timeout")?,
        "X-CSTP-Idle-Timeout",
    )?;
    let mut authentication_expiration = None;
    for name in [
        "x-cstp-lease-duration",
        "x-cstp-session-timeout",
        "x-cstp-session-timeout-remaining",
    ] {
        let duration = parse_duration(first_header(headers, name)?, name)?;
        if !duration.is_zero() {
            let expiration = now.checked_add(duration).ok_or_else(|| {
                CstpError::Protocol(format!("{name} expiration overflows"))
            })?;
            if authentication_expiration
                .is_none_or(|current| expiration < current)
            {
                authentication_expiration = Some(expiration);
            }
        }
    }
    let compression = parse_compression(
        first_header(headers, "x-cstp-content-encoding")?,
        options.compression_disabled,
        options.compression_mode,
        true,
    )?;

    Ok(CstpNegotiatedState {
        configuration: TunnelConfiguration {
            mtu,
            remote_address: options.authenticated_address,
            addresses,
            routes,
            excluded_routes,
            dns,
            nbns,
            search_domains,
            split_dns,
            split_dns_rules: Vec::new(),
            proxy_auto_config_url: first_header(
                headers,
                "x-cstp-msie-proxy-pac-url",
            )?
            .to_owned(),
            banner: first_header(headers, "x-cstp-banner")?.to_owned(),
            tunnel_all_dns: first_header(headers, "x-cstp-tunnel-all-dns")?
                == "true",
            client_bypass_protocol: first_header(
                headers,
                "x-cstp-client-bypass-protocol",
            )? == "true",
            idle_timeout,
            authentication_expiration,
        },
        dynamic_dns: first_header(headers, "x-cstp-dyndns")? == "true",
        dpd,
        keepalive,
        rekey,
        rekey_method,
        compression,
    })
}

fn first_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<&'a str, CstpError> {
    match headers.get(name) {
        Some(value) => value.to_str().map_err(|_| {
            CstpError::Protocol(format!("{name} contains non-ASCII bytes"))
        }),
        None => Ok(""),
    }
}

fn header_values(
    headers: &HeaderMap,
    name: &str,
) -> Result<Vec<String>, CstpError> {
    headers
        .get_all(name)
        .iter()
        .map(|value| {
            value.to_str().map(str::to_owned).map_err(|_| {
                CstpError::Protocol(format!("{name} contains non-ASCII bytes"))
            })
        })
        .collect()
}

fn parse_positive_integer(value: &str, name: &str) -> Result<u32, CstpError> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(0);
    }
    value
        .parse::<u32>()
        .map_err(|_| CstpError::Protocol(format!("invalid {name}: {value}")))
}

fn parse_duration(value: &str, name: &str) -> Result<Duration, CstpError> {
    let seconds = u64::from(parse_positive_integer(value, name)?);
    if seconds > CSTP_MAX_TIMER_SECONDS {
        return Err(CstpError::Protocol(format!(
            "{name} exceeds safe timer limit: {seconds} seconds"
        )));
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_rekey_method(value: &str) -> Result<CstpRekeyMethod, CstpError> {
    match value.trim() {
        "" | "none" => Ok(CstpRekeyMethod::None),
        "new-tunnel" => Ok(CstpRekeyMethod::NewTunnel),
        "ssl" => Ok(CstpRekeyMethod::Tls),
        value => Err(CstpError::Protocol(format!(
            "invalid CSTP rekey method: {value}"
        ))),
    }
}

fn parse_compression(
    value: &str,
    disabled: bool,
    mode: CstpCompressionMode,
    stateful_allowed: bool,
) -> Result<CstpCompression, CstpError> {
    let compression = match value.trim().to_ascii_lowercase().as_str() {
        "" => return Ok(CstpCompression::None),
        "oc-lz4" => CstpCompression::OcLz4,
        "lzs" => CstpCompression::Lzs,
        "deflate" => CstpCompression::Deflate,
        value => {
            return Err(CstpError::Protocol(format!(
                "unsupported CSTP compression: {value}"
            )));
        }
    };
    if disabled {
        return Err(CstpError::Protocol(
            "server selected compression while compression is disabled".into(),
        ));
    }
    if compression == CstpCompression::Deflate
        && mode != CstpCompressionMode::All
    {
        return Err(CstpError::Protocol(
            "server selected deflate outside compression_mode=all".into(),
        ));
    }
    if !stateful_allowed && compression == CstpCompression::Deflate {
        return Err(CstpError::Protocol(
            "stateful deflate is not valid for this channel".into(),
        ));
    }
    Ok(compression)
}

fn parse_cstp_addresses(headers: &HeaderMap) -> Result<Vec<IpNet>, CstpError> {
    let ipv6_metadata = header_values(headers, "x-cstp-address-ip6")?
        .into_iter()
        .map(|value| parse_prefix(&value, "X-CSTP-Address-IP6"))
        .collect::<Result<Vec<_>, _>>()?;
    let netmasks = header_values(headers, "x-cstp-netmask")?;
    let mut result = Vec::new();
    let mut has_ipv6_address = false;
    for value in header_values(headers, "x-cstp-address")? {
        let address = IpAddr::from_str(value.trim()).map_err(|error| {
            CstpError::Protocol(format!(
                "parse X-CSTP-Address {value:?}: {error}"
            ))
        })?;
        match address {
            IpAddr::V4(address) => {
                let bits = netmasks
                    .iter()
                    .find(|value| !value.contains(':'))
                    .map(|value| parse_ipv4_netmask_bits(value))
                    .transpose()?
                    .unwrap_or(32);
                result.push(IpNet::V4(Ipv4Net::new(address, bits).map_err(
                    |error| {
                        CstpError::Protocol(format!(
                            "invalid IPv4 prefix: {error}"
                        ))
                    },
                )?));
            }
            IpAddr::V6(address) => {
                has_ipv6_address = true;
                let mut bits =
                    ipv6_metadata.first().map_or(128, IpNet::prefix_len);
                if let Some(mask) =
                    netmasks.iter().find(|value| value.contains(':'))
                {
                    bits = if mask.contains('/') {
                        parse_prefix(mask, "IPv6 X-CSTP-Netmask")?.prefix_len()
                    } else {
                        parse_ipv6_netmask_bits(mask)?
                    };
                }
                result.push(IpNet::V6(Ipv6Net::new(address, bits).map_err(
                    |error| {
                        CstpError::Protocol(format!(
                            "invalid IPv6 prefix: {error}"
                        ))
                    },
                )?));
            }
        }
    }
    if !has_ipv6_address {
        result.extend(ipv6_metadata);
    }
    Ok(result)
}

fn parse_routes(
    ipv4_values: Vec<String>,
    ipv6_values: Vec<String>,
) -> Result<Vec<TunnelRoute>, CstpError> {
    ipv4_values
        .into_iter()
        .chain(ipv6_values)
        .map(|value| {
            Ok(TunnelRoute {
                prefix: parse_prefix(&value, "CSTP split route")?.trunc(),
                gateway: None,
                metric: 0,
            })
        })
        .collect()
}

fn parse_prefix(value: &str, name: &str) -> Result<IpNet, CstpError> {
    let value = value.trim();
    if let Ok(prefix) = IpNet::from_str(value) {
        return Ok(prefix);
    }
    let Some((address, mask)) = value.split_once('/') else {
        let address = IpAddr::from_str(value).map_err(|error| {
            CstpError::Protocol(format!("parse {name} {value:?}: {error}"))
        })?;
        return IpNet::new(address, if address.is_ipv4() { 32 } else { 128 })
            .map_err(|error| {
                CstpError::Protocol(format!("parse {name}: {error}"))
            });
    };
    let address = Ipv4Addr::from_str(address).map_err(|error| {
        CstpError::Protocol(format!("parse {name} {value:?}: {error}"))
    })?;
    let bits = parse_ipv4_netmask_bits(mask)?;
    Ipv4Net::new(address, bits)
        .map(IpNet::V4)
        .map_err(|error| CstpError::Protocol(format!("parse {name}: {error}")))
}

fn parse_ipv4_netmask_bits(value: &str) -> Result<u8, CstpError> {
    let value = value.trim();
    if let Ok(bits) = value.parse::<u8>() {
        return (bits <= 32).then_some(bits).ok_or_else(|| {
            CstpError::Protocol(format!("invalid IPv4 prefix length: {value}"))
        });
    }
    let octets = Ipv4Addr::from_str(value)
        .map_err(|_| {
            CstpError::Protocol(format!("invalid IPv4 netmask: {value}"))
        })?
        .octets();
    contiguous_prefix_bits(&octets).ok_or_else(|| {
        CstpError::Protocol(format!("non-contiguous IPv4 netmask: {value}"))
    })
}

fn parse_ipv6_netmask_bits(value: &str) -> Result<u8, CstpError> {
    let octets = Ipv6Addr::from_str(value.trim())
        .map_err(|_| {
            CstpError::Protocol(format!("invalid IPv6 netmask: {value}"))
        })?
        .octets();
    contiguous_prefix_bits(&octets).ok_or_else(|| {
        CstpError::Protocol(format!("non-contiguous IPv6 netmask: {value}"))
    })
}

fn contiguous_prefix_bits(bytes: &[u8]) -> Option<u8> {
    let mut ones = 0_u8;
    let mut saw_zero = false;
    for byte in bytes {
        for bit in (0..8).rev() {
            let set = byte & (1 << bit) != 0;
            if saw_zero && set {
                return None;
            }
            if set {
                ones += 1;
            } else {
                saw_zero = true;
            }
        }
    }
    Some(ones)
}

fn parse_addresses_without_prefix(
    primary: Vec<String>,
    secondary: Vec<String>,
    name: &str,
) -> Result<Vec<IpAddr>, CstpError> {
    primary
        .into_iter()
        .chain(secondary)
        .map(|value| {
            IpAddr::from_str(value.trim()).map_err(|error| {
                CstpError::Protocol(format!(
                    "parse CSTP {name} address {value:?}: {error}"
                ))
            })
        })
        .collect()
}

fn add_default_routes(
    addresses: &[IpNet],
    routes: &mut Vec<TunnelRoute>,
) -> Result<(), CstpError> {
    let has_ipv4_address =
        addresses.iter().any(|prefix| prefix.addr().is_ipv4());
    let has_ipv6_address =
        addresses.iter().any(|prefix| prefix.addr().is_ipv6());
    let has_ipv4_route =
        routes.iter().any(|route| route.prefix.addr().is_ipv4());
    let has_ipv6_route =
        routes.iter().any(|route| route.prefix.addr().is_ipv6());
    if has_ipv4_address && !has_ipv4_route {
        routes.push(TunnelRoute {
            prefix: IpNet::from_str("0.0.0.0/0").map_err(|error| {
                CstpError::Protocol(format!(
                    "invalid built-in IPv4 route: {error}"
                ))
            })?,
            gateway: None,
            metric: 0,
        });
    }
    if has_ipv6_address && !has_ipv6_route {
        routes.push(TunnelRoute {
            prefix: IpNet::from_str("::/0").map_err(|error| {
                CstpError::Protocol(format!(
                    "invalid built-in IPv6 route: {error}"
                ))
            })?,
            gateway: None,
            metric: 0,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    fn append(
        headers: &mut HeaderMap,
        name: &'static str,
        value: &'static str,
    ) {
        headers.append(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }

    #[tokio::test]
    async fn cstp_packet_matches_go_wire_format() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            write_cstp_packet(&mut writer, CstpPacketType::DpdRequest, b"ping")
                .await
                .unwrap();
        });
        let mut encoded = [0_u8; 12];
        reader.read_exact(&mut encoded).await.unwrap();
        write.await.unwrap();
        assert_eq!(encoded, *b"STF\x01\x00\x04\x03\x00ping");

        let mut source = &encoded[..];
        let decoded = read_cstp_packet(&mut source, CSTP_MAX_PAYLOAD_SIZE)
            .await
            .unwrap();
        assert_eq!(decoded.packet_type, CstpPacketType::DpdRequest);
        assert_eq!(decoded.payload, b"ping");
    }

    #[tokio::test]
    async fn cstp_packet_rejects_bad_header_and_receive_limit() {
        let mut bad = &b"BAD!\x00\x00\x00\x00"[..];
        assert!(matches!(
            read_cstp_packet(&mut bad, 100).await,
            Err(CstpError::Protocol(_))
        ));
        let mut limited = &b"STF\x01\x00\x04\x00\x00test"[..];
        assert!(read_cstp_packet(&mut limited, 3).await.is_err());
    }

    #[tokio::test]
    async fn disconnect_has_cisco_reason_prefix() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            write_cstp_disconnect(&mut writer, "bye").await.unwrap();
        });
        let packet = read_cstp_packet(&mut reader, 64).await.unwrap();
        write.await.unwrap();
        assert_eq!(packet.packet_type, CstpPacketType::Disconnect);
        assert_eq!(packet.payload, b"\xb0bye");
    }

    #[test]
    fn connect_request_matches_anyconnect_headers_and_mtu() {
        let request = String::from_utf8(
            build_cstp_connect_request(&CstpConnectOptions {
                server: "vpn.example:443".into(),
                user_agent: "Open AnyConnect VPN Agent v9.12".into(),
                local_hostname: "zay".into(),
                cookie: "cookie".into(),
                compression_mode: CstpCompressionMode::All,
                remote_is_ipv6: true,
                previous_addresses: vec!["10.0.0.2/24".parse().unwrap()],
                dtls_master_secret: vec![0x0a, 0xff],
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        assert!(request.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"));
        assert!(request.contains("Cookie: webvpn=cookie\r\n"));
        assert!(
            request.contains("X-CSTP-Accept-Encoding: oc-lz4,lzs,deflate\r\n")
        );
        assert!(
            request.contains("X-CSTP-Base-MTU: 1406\r\nX-CSTP-MTU: 1276\r\n")
        );
        assert!(request.contains("X-CSTP-Address: 10.0.0.2\r\n"));
        assert!(request.contains("X-DTLS-Master-Secret: 0AFF\r\n"));
        assert!(request.contains(DEFAULT_DTLS_CIPHER_SUITES));
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn connect_request_rejects_header_injection_and_clamps_mtu() {
        let options = CstpConnectOptions {
            server: "vpn.example\r\nInjected: true".into(),
            ..Default::default()
        };
        assert!(matches!(
            build_cstp_connect_request(&options),
            Err(CstpError::InvalidOption(_))
        ));
        assert_eq!(calculate_cstp_request_mtu(1000, 0, false), (1280, 1170));
        assert_eq!(calculate_cstp_request_mtu(1500, 1300, true), (1500, 1300));
    }

    #[test]
    fn parses_complete_cstp_tunnel_configuration() {
        let mut headers = HeaderMap::new();
        append(&mut headers, "x-cstp-mtu", "1300");
        append(&mut headers, "x-dtls12-mtu", "1350");
        append(&mut headers, "x-cstp-address", "10.8.0.2");
        append(&mut headers, "x-cstp-netmask", "255.255.255.0");
        append(&mut headers, "x-cstp-address-ip6", "2001:db8::2/64");
        append(&mut headers, "x-cstp-split-include", "10.0.0.0/8");
        append(&mut headers, "x-cstp-split-exclude", "10.9.0.0/16");
        append(&mut headers, "x-cstp-dns", "10.8.0.1");
        append(&mut headers, "x-cstp-dns-ip6", "2001:4860:4860::8888");
        append(&mut headers, "x-cstp-nbns", "10.8.0.3");
        append(
            &mut headers,
            "x-cstp-default-domain",
            "corp.example dev.example",
        );
        append(&mut headers, "x-cstp-split-dns", "internal.example");
        append(&mut headers, "x-cstp-banner", "Welcome");
        append(&mut headers, "x-cstp-tunnel-all-dns", "true");
        append(&mut headers, "x-cstp-dyndns", "true");
        append(&mut headers, "x-cstp-dpd", "30");
        append(&mut headers, "x-cstp-keepalive", "20");
        append(&mut headers, "x-cstp-rekey-time", "3600");
        append(&mut headers, "x-cstp-rekey-method", "new-tunnel");
        append(&mut headers, "x-cstp-idle-timeout", "900");
        append(&mut headers, "x-cstp-lease-duration", "7200");
        append(&mut headers, "x-cstp-session-timeout", "3600");
        append(&mut headers, "x-cstp-content-encoding", "oc-lz4");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let state = parse_cstp_response(
            &headers,
            &CstpResponseOptions {
                authenticated_address: Some("192.0.2.1".parse().unwrap()),
                ..Default::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(state.configuration.mtu, 1350);
        assert_eq!(state.configuration.addresses.len(), 2);
        assert_eq!(state.configuration.routes.len(), 2);
        assert_eq!(state.configuration.excluded_routes.len(), 1);
        assert_eq!(state.configuration.dns.len(), 2);
        assert_eq!(state.configuration.search_domains.len(), 2);
        assert_eq!(state.dpd, Duration::from_secs(30));
        assert_eq!(state.rekey_method, CstpRekeyMethod::NewTunnel);
        assert_eq!(state.compression, CstpCompression::OcLz4);
        assert_eq!(
            state.configuration.authentication_expiration,
            Some(now + Duration::from_secs(3600))
        );
    }

    #[test]
    fn rejects_non_contiguous_masks_and_missing_addresses() {
        assert!(parse_ipv4_netmask_bits("255.0.255.0").is_err());
        assert!(parse_ipv6_netmask_bits("ffff:0fff::").is_err());
        let mut headers = HeaderMap::new();
        append(&mut headers, "x-cstp-mtu", "1300");
        assert!(
            parse_cstp_response(
                &headers,
                &CstpResponseOptions::default(),
                SystemTime::UNIX_EPOCH,
            )
            .is_err()
        );
    }

    #[test]
    fn status_line_requires_http_one() {
        assert_eq!(parse_cstp_status_line("HTTP/1.1 200 OK\r\n").unwrap(), 200);
        assert!(parse_cstp_status_line("HTTP/2 200").is_err());
        assert!(parse_cstp_status_line("HTTP/1.1 nope").is_err());
    }

    #[tokio::test]
    async fn reads_http_prefix_and_preserves_dtls_order() {
        let encoded = b"HTTP/1.1 200 OK\r\nX-DTLS-CipherSuite: legacy\r\nX-CSTP-DNS: 10.0.0.1\r\nX-DTLS12-CipherSuite: modern\r\nX-CSTP-Default-Domain: corp.\r\n example\r\n\r\nSTF\x01";
        let mut reader = BufReader::new(&encoded[..]);
        let response = read_cstp_http_response(&mut reader).await.unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.headers["x-cstp-default-domain"], "corp. example");
        assert_eq!(response.dtls_options.len(), 2);
        assert_eq!(response.dtls_options[0].value, "legacy");
        assert!(!response.dtls_options[0].dtls12);
        assert_eq!(response.dtls_options[1].value, "modern");
        assert!(response.dtls_options[1].dtls12);
        let mut magic = [0_u8; 4];
        reader.read_exact(&mut magic).await.unwrap();
        assert_eq!(magic, CSTP_MAGIC);
    }

    #[test]
    fn parses_ordered_dtls_negotiation() {
        let session_id = "00".repeat(32);
        let options = vec![
            CstpDtlsOption {
                suffix: "CipherSuite".into(),
                value: "AES256-SHA".into(),
                dtls12: false,
            },
            CstpDtlsOption {
                suffix: "CipherSuite".into(),
                value: "PSK-NEGOTIATE".into(),
                dtls12: true,
            },
            CstpDtlsOption {
                suffix: "Session-ID".into(),
                value: session_id,
                dtls12: true,
            },
            CstpDtlsOption {
                suffix: "App-ID".into(),
                value: "CAFE".into(),
                dtls12: true,
            },
            CstpDtlsOption {
                suffix: "Port".into(),
                value: "4443".into(),
                dtls12: true,
            },
            CstpDtlsOption {
                suffix: "DPD".into(),
                value: "30".into(),
                dtls12: true,
            },
            CstpDtlsOption {
                suffix: "Rekey-Time".into(),
                value: "600".into(),
                dtls12: true,
            },
            CstpDtlsOption {
                suffix: "Rekey-Method".into(),
                value: "ssl".into(),
                dtls12: true,
            },
        ];
        let result = parse_cstp_dtls_negotiation(
            &options,
            &CstpDtlsNegotiationOptions {
                server_host: "vpn.example".into(),
                server_port: 443,
                authenticated_address: Some("192.0.2.4".parse().unwrap()),
                master_secret: vec![7; 48],
                mtu: 1300,
                compression_disabled: false,
                compression_mode: CstpCompressionMode::Stateless,
                dpd_override: None,
                allow_insecure_crypto: false,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.host, "192.0.2.4");
        assert_eq!(result.port, 4443);
        assert_eq!(result.cipher_suite, "PSK-NEGOTIATE");
        assert!(result.dtls12);
        assert_eq!(result.session_id.len(), 32);
        assert_eq!(result.app_id, [0xca, 0xfe]);
        assert_eq!(result.rekey_method, CstpRekeyMethod::Tls);
    }

    #[test]
    fn dtls_negotiation_decline_and_invalid_session_id() {
        let base = CstpDtlsNegotiationOptions {
            server_host: "vpn.example".into(),
            server_port: 443,
            authenticated_address: None,
            master_secret: Vec::new(),
            mtu: 1300,
            compression_disabled: false,
            compression_mode: CstpCompressionMode::Stateless,
            dpd_override: None,
            allow_insecure_crypto: false,
        };
        assert!(parse_cstp_dtls_negotiation(&[], &base).unwrap().is_none());
        let invalid = [
            CstpDtlsOption {
                suffix: "CipherSuite".into(),
                value: "AES128-SHA".into(),
                dtls12: false,
            },
            CstpDtlsOption {
                suffix: "Session-ID".into(),
                value: "00".into(),
                dtls12: false,
            },
        ];
        assert!(parse_cstp_dtls_negotiation(&invalid, &base).is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_or_oversized_http_prefix() {
        let mut missing_colon =
            BufReader::new(&b"HTTP/1.1 200 OK\r\nBad\r\n\r\n"[..]);
        assert!(read_cstp_http_response(&mut missing_colon).await.is_err());

        let oversized =
            format!("HTTP/1.1 200 {}\n", "x".repeat(CSTP_MAX_STATUS_LINE_SIZE));
        let mut oversized = BufReader::new(oversized.as_bytes());
        assert!(read_cstp_http_response(&mut oversized).await.is_err());
    }

    #[tokio::test]
    async fn packet_writer_handles_backpressure() {
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            write_cstp_packet(&mut writer, CstpPacketType::Data, b"payload")
                .await
                .unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut encoded = Vec::new();
        reader.read_to_end(&mut encoded).await.unwrap();
        task.await.unwrap();
        assert_eq!(&encoded[8..], b"payload");
    }
}
