//! Juniper Network Connect oNCP record, KMP and configuration wire format.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use http::{HeaderMap, HeaderName, HeaderValue};
use ipnet::{IpNet, Ipv4Net};
use thiserror::Error;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use url::{Host, Url};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    OpenConnectEspAuthentication, OpenConnectEspEncryption,
    OpenConnectEspKeyMaterial, OpenConnectEspKeySetConfig, TunnelConfiguration,
    TunnelRoute,
};

pub const NETWORK_CONNECT_ONCP_MAXIMUM_KMP_PAYLOAD: usize = u16::MAX as usize;
pub const NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE: usize = 20;
pub const NETWORK_CONNECT_ONCP_KMP_DATA: u16 = 300;
pub const NETWORK_CONNECT_ONCP_KMP_CONFIGURATION: u16 = 301;
pub const NETWORK_CONNECT_ONCP_KMP_ESP: u16 = 302;
pub const NETWORK_CONNECT_ONCP_KMP_CONTROL: u16 = 303;
pub const NETWORK_CONNECT_DEFAULT_ESP_DPD: Duration = Duration::from_secs(60);
pub const NETWORK_CONNECT_ONCP_MAXIMUM_INITIAL_PENDING: usize = 1024 * 1024;
pub const NETWORK_CONNECT_ONCP_MAXIMUM_INITIAL_RECORDS: usize = 4096;
pub const NETWORK_CONNECT_ONCP_MAXIMUM_HTTP_STATUS_LINE: usize = 8 * 1024;
pub const NETWORK_CONNECT_ONCP_MAXIMUM_HTTP_HEADERS: usize = 64 * 1024;

const AUTHENTICATION_HEAD: [u8; 5] = [0x00, 0x04, 0x00, 0x00, 0x00];
const AUTHENTICATION_TAIL: [u8; 6] = [0xbb, 0x01, 0, 0, 0, 0];
const KMP_HEAD: [u8; 6] = [0; 6];
const KMP_TAIL: [u8; 10] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const KMP_TAIL_OUTGOING: [u8; 10] = [1, 0, 0, 0, 1, 0, 0, 0, 0, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConnectOncpKmpHeader {
    pub message_type: u16,
    pub payload_length: usize,
}

#[derive(Debug, Clone)]
pub struct NetworkConnectTunnelConfiguration {
    pub configuration: TunnelConfiguration,
    pub assigned_ipv4: Ipv4Addr,
    pub esp: Option<NetworkConnectEspConfiguration>,
}

#[derive(Debug, Clone)]
pub struct NetworkConnectEspConfiguration {
    pub remote: SocketAddr,
    pub keys: OpenConnectEspKeySetConfig,
    pub encryption: OpenConnectEspEncryption,
    pub authentication: OpenConnectEspAuthentication,
    pub compression: bool,
    pub replay_protection: bool,
    pub port: u16,
    pub dpd: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NetworkConnectEspParameters {
    #[zeroize(skip)]
    pub encryption: Option<OpenConnectEspEncryption>,
    #[zeroize(skip)]
    pub authentication: Option<OpenConnectEspAuthentication>,
    #[zeroize(skip)]
    pub compression: u8,
    #[zeroize(skip)]
    pub replay_protection: bool,
    #[zeroize(skip)]
    pub port: u16,
    #[zeroize(skip)]
    pub dpd: Duration,
    #[zeroize(skip)]
    pub server_spi: u32,
    pub server_secret: Vec<u8>,
}

impl Default for NetworkConnectEspParameters {
    fn default() -> Self {
        Self {
            encryption: None,
            authentication: None,
            compression: 0,
            replay_protection: false,
            port: 0,
            dpd: Duration::ZERO,
            server_spi: 0,
            server_secret: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectParsedConfiguration {
    pub configuration: TunnelConfiguration,
    pub assigned_ipv4: Ipv4Addr,
    pub esp_parameters: NetworkConnectEspParameters,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkConnectOncpError {
    #[error("invalid Network Connect oNCP wire: {0}")]
    Invalid(String),
    #[error("Network Connect oNCP value is too large: {0}")]
    TooLarge(String),
    #[error("generate Network Connect ESP key material: {0}")]
    Random(String),
    #[error("Network Connect oNCP I/O: {0}")]
    Io(String),
}

#[derive(Debug, Default)]
pub struct NetworkConnectOncpKmpDecoder {
    pending: Vec<u8>,
}

impl NetworkConnectOncpKmpDecoder {
    pub fn push_record(
        &mut self,
        record: &[u8],
    ) -> Result<(), NetworkConnectOncpError> {
        let new_length = self
            .pending
            .len()
            .checked_add(record.len())
            .ok_or_else(|| too_large(usize::MAX.to_string()))?;
        if new_length > NETWORK_CONNECT_ONCP_MAXIMUM_INITIAL_PENDING {
            return Err(too_large(format!("pending KMP bytes ({new_length})")));
        }
        self.pending.extend_from_slice(record);
        Ok(())
    }

    pub fn next_message(
        &mut self,
    ) -> Result<Option<(u16, Vec<u8>)>, NetworkConnectOncpError> {
        if self.pending.len() < NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE {
            return Ok(None);
        }
        let header =
            parse_network_connect_oncp_kmp_header(&self.pending, false)?;
        let total_length = NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE
            .checked_add(header.payload_length)
            .ok_or_else(|| invalid("KMP length overflow"))?;
        if self.pending.len() < total_length {
            return Ok(None);
        }
        let payload = self.pending
            [NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE..total_length]
            .to_vec();
        self.pending.drain(..total_length);
        Ok(Some((header.message_type, payload)))
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

pub struct NetworkConnectOncpReader<R> {
    reader: BufReader<R>,
    decoder: NetworkConnectOncpKmpDecoder,
}

impl<R> NetworkConnectOncpReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            decoder: NetworkConnectOncpKmpDecoder::default(),
        }
    }

    pub async fn read_http_response_header(
        &mut self,
    ) -> Result<(u16, HeaderMap), NetworkConnectOncpError> {
        let status_line = self
            .read_http_line(NETWORK_CONNECT_ONCP_MAXIMUM_HTTP_STATUS_LINE)
            .await?;
        let fields: Vec<_> = status_line.split_ascii_whitespace().collect();
        if fields.len() < 2 || !fields[0].starts_with("HTTP/") {
            return Err(invalid("HTTP status line is invalid"));
        }
        let status = fields[1]
            .parse::<u16>()
            .ok()
            .filter(|status| (100..=999).contains(status))
            .ok_or_else(|| invalid("HTTP status code is invalid"))?;
        let mut headers = HeaderMap::new();
        let mut total = 0_usize;
        loop {
            let remaining = NETWORK_CONNECT_ONCP_MAXIMUM_HTTP_HEADERS
                .checked_sub(total)
                .ok_or_else(|| invalid("HTTP headers are too large"))?;
            if remaining == 0 {
                return Err(invalid("HTTP headers are too large"));
            }
            let line = self.read_http_line(remaining).await?;
            total += line.len() + 2;
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("HTTP header has no colon"))?;
            let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(
                |error| invalid(format!("HTTP header name: {error}")),
            )?;
            let value =
                HeaderValue::from_str(value.trim()).map_err(|error| {
                    invalid(format!("HTTP header value: {error}"))
                })?;
            headers.append(name, value);
        }
        Ok((status, headers))
    }

    pub async fn read_initial_configuration(
        &mut self,
    ) -> Result<Vec<u8>, NetworkConnectOncpError> {
        let first = self.read_record().await?;
        let Some((&result, remainder)) = first.split_first() else {
            return Err(invalid("hostname response is empty"));
        };
        if result != 0 {
            return Err(invalid(format!(
                "hostname response returned error {result}"
            )));
        }
        let mut configuration = remainder.to_vec();
        for record_number in 1..=NETWORK_CONNECT_ONCP_MAXIMUM_INITIAL_RECORDS {
            if configuration.len() >= NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE {
                let header = parse_network_connect_oncp_kmp_header(
                    &configuration,
                    false,
                )?;
                if header.message_type != NETWORK_CONNECT_ONCP_KMP_CONFIGURATION
                {
                    return Err(invalid(format!(
                        "expected KMP 301, received {}",
                        header.message_type
                    )));
                }
                let total = NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE
                    + header.payload_length;
                if configuration.len() >= total {
                    if configuration.len() > total {
                        self.decoder.push_record(&configuration[total..])?;
                    }
                    configuration.truncate(total);
                    return Ok(configuration);
                }
            }
            if record_number == NETWORK_CONNECT_ONCP_MAXIMUM_INITIAL_RECORDS {
                return Err(invalid(
                    "initial configuration used too many records",
                ));
            }
            let record = self.read_record().await?;
            if network_connect_oncp_standalone_data_record(&record) {
                self.decoder.push_record(&record)?;
            } else {
                let length = configuration
                    .len()
                    .checked_add(record.len())
                    .ok_or_else(|| too_large(usize::MAX.to_string()))?;
                if length
                    > NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE
                        + NETWORK_CONNECT_ONCP_MAXIMUM_KMP_PAYLOAD
                {
                    return Err(too_large(format!(
                        "initial configuration ({length})"
                    )));
                }
                configuration.extend_from_slice(&record);
            }
        }
        unreachable!("bounded initial record loop returns")
    }

    pub async fn read_kmp(
        &mut self,
    ) -> Result<(u16, Vec<u8>), NetworkConnectOncpError> {
        loop {
            if let Some(message) = self.decoder.next_message()? {
                return Ok(message);
            }
            let record = self.read_record().await?;
            self.decoder.push_record(&record)?;
        }
    }

    pub async fn read_record(
        &mut self,
    ) -> Result<Vec<u8>, NetworkConnectOncpError> {
        let length = self.reader.read_u16_le().await.map_err(io_error)?;
        if length == 0 {
            let reason = self.reader.read_u8().await.map_err(io_error)?;
            return Err(invalid(format!(
                "server terminated the session with reason {reason}"
            )));
        }
        let mut record = vec![0; usize::from(length)];
        self.reader
            .read_exact(&mut record)
            .await
            .map_err(io_error)?;
        Ok(record)
    }

    async fn read_http_line(
        &mut self,
        maximum: usize,
    ) -> Result<String, NetworkConnectOncpError> {
        let mut bytes = Vec::new();
        loop {
            let byte = self.reader.read_u8().await.map_err(io_error)?;
            bytes.push(byte);
            if bytes.len() > maximum {
                return Err(invalid("HTTP line is too long"));
            }
            if byte == b'\n' {
                break;
            }
        }
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
        String::from_utf8(bytes).map_err(|error| {
            invalid(format!("HTTP line is not UTF-8: {error}"))
        })
    }
}

pub struct NetworkConnectOncpWriter<W> {
    writer: W,
}

impl<W> NetworkConnectOncpWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub async fn write_bytes(
        &mut self,
        content: &[u8],
    ) -> Result<(), NetworkConnectOncpError> {
        self.writer.write_all(content).await.map_err(io_error)
    }

    pub async fn write_record(
        &mut self,
        content: &[u8],
    ) -> Result<(), NetworkConnectOncpError> {
        let record = encode_network_connect_oncp_record(content)?;
        self.writer.write_all(&record).await.map_err(io_error)
    }

    pub async fn write_kmp(
        &mut self,
        message_type: u16,
        payload: &[u8],
    ) -> Result<(), NetworkConnectOncpError> {
        let message = encode_network_connect_oncp_kmp(message_type, payload)?;
        self.write_record(&message).await
    }

    pub async fn flush(&mut self) -> Result<(), NetworkConnectOncpError> {
        self.writer.flush().await.map_err(io_error)
    }

    pub async fn shutdown(&mut self) -> Result<(), NetworkConnectOncpError> {
        self.writer.shutdown().await.map_err(io_error)
    }
}

/// Build the bodyless HTTP/1.1 request which switches a pinned TLS stream to
/// oNCP. `Content-Length: 256` is intentionally sent without a body.
pub fn build_network_connect_oncp_request(
    server_url: &Url,
    user_agent: &str,
    cookies: &[(String, String)],
    dsid: &str,
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    if server_url.scheme() != "https"
        || server_url.host_str().is_none()
        || !server_url.username().is_empty()
        || server_url.password().is_some()
    {
        return Err(invalid("oNCP server URL is not a plain HTTPS URL"));
    }
    if contains_line_delimiter(user_agent) {
        return Err(invalid("oNCP user agent contains a line delimiter"));
    }
    let mut encoded_cookies = Vec::with_capacity(cookies.len() + 1);
    let mut has_dsid = false;
    for (name, value) in cookies {
        validate_cookie(name, value)?;
        if name == "DSID" {
            has_dsid = true;
        }
        encoded_cookies.push(format!("{name}={value}"));
    }
    if !has_dsid {
        validate_cookie("DSID", dsid)?;
        encoded_cookies.push(format!("DSID={dsid}"));
    }
    if encoded_cookies.is_empty() {
        return Err(invalid("oNCP request has no cookies"));
    }
    let host = match server_url.host().expect("validated host") {
        Host::Ipv6(address) => format!("[{address}]"),
        Host::Ipv4(address) => address.to_string(),
        Host::Domain(domain) => domain.to_owned(),
    };
    let authority = match server_url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok(format!(
        "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\nConnection: close\r\nHost: {authority}\r\nUser-Agent: {user_agent}\r\nCookie: {}\r\nNCP-Version: 3\r\nContent-Length: 256\r\n\r\n",
        encoded_cookies.join("; ")
    )
    .into_bytes())
}

pub fn encode_network_connect_oncp_authentication_packet(
    local_hostname: &str,
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    let payload_length = AUTHENTICATION_HEAD.len()
        + 2
        + local_hostname.len()
        + AUTHENTICATION_TAIL.len();
    if payload_length > NETWORK_CONNECT_ONCP_MAXIMUM_KMP_PAYLOAD
        || local_hostname.len() > NETWORK_CONNECT_ONCP_MAXIMUM_KMP_PAYLOAD
    {
        return Err(too_large("local hostname"));
    }
    let mut packet = Vec::with_capacity(payload_length + 2);
    packet.extend_from_slice(&(payload_length as u16).to_le_bytes());
    packet.extend_from_slice(&AUTHENTICATION_HEAD);
    packet.extend_from_slice(&(local_hostname.len() as u16).to_le_bytes());
    packet.extend_from_slice(local_hostname.as_bytes());
    packet.extend_from_slice(&AUTHENTICATION_TAIL);
    Ok(packet)
}

pub fn encode_network_connect_oncp_record(
    content: &[u8],
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    if content.is_empty()
        || content.len() > NETWORK_CONNECT_ONCP_MAXIMUM_KMP_PAYLOAD
    {
        return Err(invalid(format!(
            "record has invalid length: {}",
            content.len()
        )));
    }
    let mut record = Vec::with_capacity(content.len() + 2);
    record.extend_from_slice(&(content.len() as u16).to_le_bytes());
    record.extend_from_slice(content);
    Ok(record)
}

/// Decode one length-prefixed oNCP record and return `(payload, consumed)`.
pub fn decode_network_connect_oncp_record(
    content: &[u8],
) -> Result<(Vec<u8>, usize), NetworkConnectOncpError> {
    if content.len() < 2 {
        return Err(invalid("truncated record length"));
    }
    let length = usize::from(u16::from_le_bytes([content[0], content[1]]));
    if length == 0 {
        if content.len() < 3 {
            return Err(invalid("truncated termination reason"));
        }
        return Err(invalid(format!(
            "server terminated the session with reason {}",
            content[2]
        )));
    }
    let end = 2_usize
        .checked_add(length)
        .ok_or_else(|| invalid("record length overflow"))?;
    if content.len() < end {
        return Err(invalid("truncated record"));
    }
    Ok((content[2..end].to_vec(), end))
}

pub fn parse_network_connect_oncp_kmp_header(
    header: &[u8],
    outgoing: bool,
) -> Result<NetworkConnectOncpKmpHeader, NetworkConnectOncpError> {
    if header.len() < NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE
        || header[..6] != KMP_HEAD
    {
        return Err(invalid("KMP header is invalid"));
    }
    let message_type = u16::from_be_bytes([header[6], header[7]]);
    let expected_tail = if outgoing {
        &KMP_TAIL_OUTGOING
    } else {
        &KMP_TAIL
    };
    if header[8..18] != *expected_tail {
        let legacy_data_tail = message_type == NETWORK_CONNECT_ONCP_KMP_DATA
            && header[8] == 0
            && header[9..18] == KMP_TAIL[1..];
        if !legacy_data_tail {
            return Err(invalid("KMP constants are invalid"));
        }
    }
    Ok(NetworkConnectOncpKmpHeader {
        message_type,
        payload_length: usize::from(u16::from_be_bytes([
            header[18], header[19],
        ])),
    })
}

pub fn encode_network_connect_oncp_kmp(
    message_type: u16,
    payload: &[u8],
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    if payload.len() > NETWORK_CONNECT_ONCP_MAXIMUM_KMP_PAYLOAD {
        return Err(too_large("KMP payload"));
    }
    let mut message = Vec::with_capacity(
        NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE + payload.len(),
    );
    message.extend_from_slice(&KMP_HEAD);
    message.extend_from_slice(&message_type.to_be_bytes());
    message.extend_from_slice(&KMP_TAIL_OUTGOING);
    message.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

pub fn parse_network_connect_oncp_kmp(
    message: &[u8],
    outgoing: bool,
) -> Result<(NetworkConnectOncpKmpHeader, &[u8]), NetworkConnectOncpError> {
    let header = parse_network_connect_oncp_kmp_header(message, outgoing)?;
    let expected = NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE
        .checked_add(header.payload_length)
        .ok_or_else(|| invalid("KMP length overflow"))?;
    if message.len() != expected {
        return Err(invalid(format!(
            "KMP length is {}, expected {expected}",
            message.len()
        )));
    }
    Ok((header, &message[NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE..]))
}

pub fn encode_network_connect_oncp_tlv(
    identifier: u16,
    content: &[u8],
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    let length =
        u32::try_from(content.len()).map_err(|_| too_large("TLV content"))?;
    let mut encoded = Vec::with_capacity(content.len() + 6);
    encoded.extend_from_slice(&identifier.to_be_bytes());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(content);
    Ok(encoded)
}

pub fn parse_network_connect_oncp_configuration_payload(
    payload: &[u8],
    accepted_address: IpAddr,
) -> Result<NetworkConnectParsedConfiguration, NetworkConnectOncpError> {
    let mut configuration = empty_configuration(accepted_address);
    let mut parameters = NetworkConnectEspParameters::default();
    let mut assigned_ipv4 = None;
    let mut netmask = None;
    parse_groups(
        payload,
        false,
        &mut configuration,
        &mut parameters,
        &mut assigned_ipv4,
        &mut netmask,
    )?;
    let assigned_ipv4 = assigned_ipv4.ok_or_else(|| {
        invalid("server returned insufficient IPv4 tunnel configuration")
    })?;
    let netmask = netmask.ok_or_else(|| {
        invalid("server returned insufficient IPv4 tunnel configuration")
    })?;
    if !(576..=65_535).contains(&configuration.mtu) {
        return Err(invalid(
            "server returned insufficient IPv4 tunnel configuration",
        ));
    }
    let prefix = ipv4_prefix(assigned_ipv4, netmask)?;
    configuration.addresses = vec![IpNet::V4(
        Ipv4Net::new(assigned_ipv4, prefix)
            .map_err(|error| invalid(error.to_string()))?,
    )];
    if configuration.routes.is_empty() {
        configuration.routes.push(route(Ipv4Addr::UNSPECIFIED, 0)?);
    }
    Ok(NetworkConnectParsedConfiguration {
        configuration,
        assigned_ipv4,
        esp_parameters: parameters,
    })
}

pub fn parse_network_connect_oncp_esp_rekey(
    payload: &[u8],
    previous: NetworkConnectEspParameters,
) -> Result<NetworkConnectEspParameters, NetworkConnectOncpError> {
    let mut parameters = previous;
    let mut configuration =
        empty_configuration(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let mut assigned_ipv4 = None;
    let mut netmask = None;
    parse_groups(
        payload,
        true,
        &mut configuration,
        &mut parameters,
        &mut assigned_ipv4,
        &mut netmask,
    )?;
    Ok(parameters)
}

pub fn prepare_network_connect_esp(
    accepted_address: IpAddr,
    parameters: &NetworkConnectEspParameters,
) -> Result<(NetworkConnectEspConfiguration, Vec<u8>), NetworkConnectOncpError>
{
    let IpAddr::V4(remote_address) = accepted_address else {
        return Err(invalid("Network Connect ESP supports IPv4 only"));
    };
    let encryption = parameters
        .encryption
        .ok_or_else(|| invalid("ESP parameters use an unknown encryption"))?;
    let authentication = parameters.authentication.ok_or_else(|| {
        invalid("ESP parameters use an unknown authentication")
    })?;
    if parameters.port == 0
        || parameters.server_spi == 0
        || parameters.server_secret.len() != 64
    {
        return Err(invalid("ESP parameters are incomplete"));
    }
    if parameters.compression > 1 {
        return Err(invalid(format!(
            "ESP compression type is {}",
            parameters.compression
        )));
    }
    let encryption_length = encryption.key_length();
    let authentication_length = authentication.key_length();
    if encryption_length + authentication_length
        > parameters.server_secret.len()
    {
        return Err(invalid("ESP secret block is too short"));
    }
    let mut client_encryption_key = vec![0; encryption_length];
    let mut client_authentication_key = vec![0; authentication_length];
    getrandom::fill(&mut client_encryption_key)
        .map_err(|error| NetworkConnectOncpError::Random(error.to_string()))?;
    getrandom::fill(&mut client_authentication_key)
        .map_err(|error| NetworkConnectOncpError::Random(error.to_string()))?;
    let client_spi = loop {
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).map_err(|error| {
            NetworkConnectOncpError::Random(error.to_string())
        })?;
        let spi = u32::from_be_bytes(bytes);
        if spi != 0 {
            break spi;
        }
    };
    let keys = OpenConnectEspKeySetConfig {
        encryption,
        authentication,
        disable_replay_protection: !parameters.replay_protection,
        outbound: OpenConnectEspKeyMaterial {
            spi: parameters.server_spi,
            encryption_key: parameters.server_secret[..encryption_length]
                .to_vec(),
            authentication_key: parameters.server_secret
                [encryption_length..encryption_length + authentication_length]
                .to_vec(),
        },
        inbound: OpenConnectEspKeyMaterial {
            spi: client_spi,
            encryption_key: client_encryption_key.clone(),
            authentication_key: client_authentication_key.clone(),
        },
    };
    let response = encode_esp_response(
        client_spi,
        &client_encryption_key,
        &client_authentication_key,
    )?;
    client_encryption_key.zeroize();
    client_authentication_key.zeroize();
    let dpd = if parameters.dpd.is_zero() {
        NETWORK_CONNECT_DEFAULT_ESP_DPD
    } else {
        parameters.dpd
    };
    Ok((
        NetworkConnectEspConfiguration {
            remote: SocketAddr::new(
                IpAddr::V4(remote_address),
                parameters.port,
            ),
            keys,
            encryption,
            authentication,
            compression: parameters.compression == 1,
            replay_protection: parameters.replay_protection,
            port: parameters.port,
            dpd,
        },
        response,
    ))
}

pub fn encode_network_connect_oncp_mtu_control(
    mtu: u32,
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    let attribute = encode_network_connect_oncp_tlv(2, &mtu.to_be_bytes())?;
    let payload = encode_network_connect_oncp_tlv(6, &attribute)?;
    encode_network_connect_oncp_kmp(NETWORK_CONNECT_ONCP_KMP_CONTROL, &payload)
}

pub fn encode_network_connect_oncp_esp_control(
    enabled: bool,
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    let attribute = encode_network_connect_oncp_tlv(1, &[u8::from(enabled)])?;
    let payload = encode_network_connect_oncp_tlv(6, &attribute)?;
    encode_network_connect_oncp_kmp(NETWORK_CONNECT_ONCP_KMP_CONTROL, &payload)
}

pub fn parse_network_connect_oncp_esp_control(
    payload: &[u8],
) -> Result<bool, NetworkConnectOncpError> {
    if payload.len() != 13
        || u16::from_be_bytes(payload[0..2].try_into().unwrap()) != 6
        || u32::from_be_bytes(payload[2..6].try_into().unwrap()) != 7
        || u16::from_be_bytes(payload[6..8].try_into().unwrap()) != 1
        || u32::from_be_bytes(payload[8..12].try_into().unwrap()) != 1
        || payload[12] > 1
    {
        return Err(invalid("ESP KMP 303 control payload is invalid"));
    }
    Ok(payload[12] != 0)
}

pub fn validate_network_connect_ipv4_packet(
    payload: &[u8],
    exact: bool,
) -> Result<usize, NetworkConnectOncpError> {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return Err(invalid("oNCP supports IPv4 packets only"));
    }
    let header_length = usize::from(payload[0] & 0x0f) * 4;
    let packet_length =
        usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if header_length < 20
        || packet_length < header_length
        || packet_length > payload.len()
    {
        return Err(invalid("IPv4 packet length is invalid"));
    }
    if exact && packet_length != payload.len() {
        return Err(invalid("ESP IPv4 packet has trailing bytes"));
    }
    Ok(packet_length)
}

pub fn network_connect_oncp_standalone_data_record(record: &[u8]) -> bool {
    if record.len() < NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE + 20 {
        return false;
    }
    parse_network_connect_oncp_kmp_header(record, false).is_ok_and(|header| {
        header.message_type == NETWORK_CONNECT_ONCP_KMP_DATA
            && header.payload_length + NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE
                == record.len()
            && record[NETWORK_CONNECT_ONCP_KMP_HEADER_SIZE] >> 4 == 4
    })
}

fn parse_groups(
    payload: &[u8],
    esp_only: bool,
    configuration: &mut TunnelConfiguration,
    parameters: &mut NetworkConnectEspParameters,
    assigned_ipv4: &mut Option<Ipv4Addr>,
    netmask: &mut Option<Ipv4Addr>,
) -> Result<(), NetworkConnectOncpError> {
    let mut offset = 0;
    while offset < payload.len() {
        if payload.len() - offset < 6 {
            return Err(invalid("configuration has a truncated group"));
        }
        let group = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let group_length = u32::from_be_bytes(
            payload[offset + 2..offset + 6].try_into().unwrap(),
        ) as usize;
        offset += 6;
        if (esp_only && !matches!(group, 7 | 8))
            || group_length > payload.len() - offset
        {
            return Err(invalid(
                "configuration group length or type is invalid",
            ));
        }
        let end = offset + group_length;
        while offset < end {
            if end - offset < 6 {
                return Err(invalid("configuration has a truncated attribute"));
            }
            let attribute =
                u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let length = u32::from_be_bytes(
                payload[offset + 2..offset + 6].try_into().unwrap(),
            ) as usize;
            offset += 6;
            if length > end - offset {
                return Err(invalid(
                    "configuration attribute length is invalid",
                ));
            }
            apply_attribute(
                configuration,
                parameters,
                assigned_ipv4,
                netmask,
                group,
                attribute,
                &payload[offset..offset + length],
            )?;
            offset += length;
        }
    }
    Ok(())
}

fn apply_attribute(
    configuration: &mut TunnelConfiguration,
    parameters: &mut NetworkConnectEspParameters,
    assigned_ipv4: &mut Option<Ipv4Addr>,
    netmask: &mut Option<Ipv4Addr>,
    group: u16,
    attribute: u16,
    content: &[u8],
) -> Result<(), NetworkConnectOncpError> {
    match (group, attribute) {
        (1, 1) => *assigned_ipv4 = Some(ipv4(content, "assigned IPv4")?),
        (1, 2) => *netmask = Some(ipv4(content, "IPv4 netmask")?),
        (2, 1) => {
            let address = ipv4(content, "DNS server")?;
            if configuration.dns.len() < 3 {
                configuration.dns.push(IpAddr::V4(address));
            }
        }
        (2, 2) => {
            let domain = String::from_utf8_lossy(content).trim().to_owned();
            if !domain.is_empty() {
                configuration.search_domains.push(domain);
            }
        }
        (3, 3) | (3, 4) => {
            if content.len() != 8 {
                return Err(invalid("IPv4 route has invalid length"));
            }
            let address = ipv4(&content[..4], "IPv4 route address")?;
            let mask = ipv4(&content[4..], "IPv4 route netmask")?;
            let prefix = ipv4_prefix(address, mask)?;
            let route = route(address, prefix)?;
            if attribute == 3 {
                configuration.routes.push(route);
            } else {
                configuration.excluded_routes.push(route);
            }
        }
        (4, 1) => {
            let address = ipv4(content, "NBNS server")?;
            if configuration.nbns.len() < 3 {
                configuration.nbns.push(IpAddr::V4(address));
            }
        }
        (6, 2) => configuration.mtu = be_u32(content, "MTU")?,
        (7, 1) => parameters.server_spi = be_u32(content, "ESP SPI")?,
        (7, 2) => {
            if content.len() != 64 {
                return Err(invalid("ESP secret attribute has invalid length"));
            }
            parameters.server_secret.zeroize();
            parameters.server_secret.extend_from_slice(content);
        }
        (8, 1) => {
            let value = byte(content, "ESP encryption")?;
            parameters.encryption = match value {
                2 => Some(OpenConnectEspEncryption::Aes128Cbc),
                5 => Some(OpenConnectEspEncryption::Aes256Cbc),
                _ => None,
            };
        }
        (8, 2) => {
            let value = byte(content, "ESP authentication")?;
            parameters.authentication = match value {
                1 => Some(OpenConnectEspAuthentication::HmacMd5_96),
                2 => Some(OpenConnectEspAuthentication::HmacSha1_96),
                3 => Some(OpenConnectEspAuthentication::HmacSha256_128),
                _ => None,
            };
        }
        (8, 3) => parameters.compression = byte(content, "ESP compression")?,
        (8, 4) => parameters.port = be_u16(content, "ESP port")?,
        (8, 9) => {
            parameters.dpd = Duration::from_secs(u64::from(be_u32(
                content,
                "ESP fallback",
            )?));
        }
        (8, 10) => {
            parameters.replay_protection =
                be_u32(content, "ESP replay protection")? != 0;
        }
        _ => {}
    }
    Ok(())
}

fn encode_esp_response(
    client_spi: u32,
    encryption_key: &[u8],
    authentication_key: &[u8],
) -> Result<Vec<u8>, NetworkConnectOncpError> {
    let mut secret = vec![0; 64];
    secret[..encryption_key.len()].copy_from_slice(encryption_key);
    secret
        [encryption_key.len()..encryption_key.len() + authentication_key.len()]
        .copy_from_slice(authentication_key);
    let mut attributes =
        encode_network_connect_oncp_tlv(1, &client_spi.to_be_bytes())?;
    attributes.extend_from_slice(&encode_network_connect_oncp_tlv(2, &secret)?);
    secret.zeroize();
    let payload = encode_network_connect_oncp_tlv(7, &attributes)?;
    attributes.zeroize();
    encode_network_connect_oncp_kmp(NETWORK_CONNECT_ONCP_KMP_ESP, &payload)
}

fn empty_configuration(accepted_address: IpAddr) -> TunnelConfiguration {
    TunnelConfiguration {
        mtu: 0,
        remote_address: Some(accepted_address),
        addresses: Vec::new(),
        routes: Vec::new(),
        excluded_routes: Vec::new(),
        dns: Vec::new(),
        nbns: Vec::new(),
        search_domains: Vec::new(),
        split_dns: Vec::new(),
        split_dns_rules: Vec::new(),
        proxy_auto_config_url: String::new(),
        banner: String::new(),
        tunnel_all_dns: false,
        client_bypass_protocol: false,
        idle_timeout: Duration::ZERO,
        authentication_expiration: None,
    }
}

fn route(
    address: Ipv4Addr,
    prefix: u8,
) -> Result<TunnelRoute, NetworkConnectOncpError> {
    Ok(TunnelRoute {
        prefix: IpNet::V4(
            Ipv4Net::new(address, prefix)
                .map_err(|error| invalid(error.to_string()))?
                .trunc(),
        ),
        gateway: None,
        metric: 0,
    })
}

fn ipv4(
    content: &[u8],
    name: &str,
) -> Result<Ipv4Addr, NetworkConnectOncpError> {
    let bytes: [u8; 4] = content
        .try_into()
        .map_err(|_| invalid(format!("{name} attribute has invalid length")))?;
    Ok(Ipv4Addr::from(bytes))
}

fn ipv4_prefix(
    _address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<u8, NetworkConnectOncpError> {
    let mask = u32::from(netmask);
    let prefix = mask.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if mask != expected {
        return Err(invalid("IPv4 netmask is not contiguous"));
    }
    Ok(prefix)
}

fn byte(content: &[u8], name: &str) -> Result<u8, NetworkConnectOncpError> {
    content
        .first()
        .copied()
        .filter(|_| content.len() == 1)
        .ok_or_else(|| invalid(format!("{name} attribute has invalid length")))
}

fn be_u16(content: &[u8], name: &str) -> Result<u16, NetworkConnectOncpError> {
    Ok(u16::from_be_bytes(content.try_into().map_err(|_| {
        invalid(format!("{name} attribute has invalid length"))
    })?))
}

fn be_u32(content: &[u8], name: &str) -> Result<u32, NetworkConnectOncpError> {
    Ok(u32::from_be_bytes(content.try_into().map_err(|_| {
        invalid(format!("{name} attribute has invalid length"))
    })?))
}

fn invalid(message: impl Into<String>) -> NetworkConnectOncpError {
    NetworkConnectOncpError::Invalid(message.into())
}

fn too_large(message: impl Into<String>) -> NetworkConnectOncpError {
    NetworkConnectOncpError::TooLarge(message.into())
}

fn io_error(error: std::io::Error) -> NetworkConnectOncpError {
    NetworkConnectOncpError::Io(error.to_string())
}

fn contains_line_delimiter(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

fn validate_cookie(
    name: &str,
    value: &str,
) -> Result<(), NetworkConnectOncpError> {
    if name.is_empty()
        || name.bytes().any(|byte| {
            !(0x21..0x7f).contains(&byte)
                || matches!(
                    byte,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
        || value.bytes().any(|byte| {
            !(0x20..0x7f).contains(&byte)
                || matches!(byte, b';' | b',' | b'\\' | b'"')
        })
    {
        return Err(invalid(format!("invalid oNCP cookie {name}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(identifier: u16, content: &[u8]) -> Vec<u8> {
        encode_network_connect_oncp_tlv(identifier, content).unwrap()
    }

    fn group(identifier: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<_> = attributes.iter().flatten().copied().collect();
        tlv(identifier, &content)
    }

    #[test]
    fn authentication_record_matches_little_endian_wire() {
        assert_eq!(
            encode_network_connect_oncp_authentication_packet("zay").unwrap(),
            vec![
                16, 0, 0, 4, 0, 0, 0, 3, 0, b'z', b'a', b'y', 0xbb, 1, 0, 0, 0,
                0,
            ]
        );
    }

    #[test]
    fn tunnel_request_preserves_host_and_appends_missing_dsid() {
        let request = build_network_connect_oncp_request(
            &Url::parse("https://[2001:db8::1]:4443/login").unwrap(),
            "zay-test",
            &[("DSPREAUTH".into(), "preauth".into())],
            "session",
        )
        .unwrap();
        assert_eq!(
            request,
            b"POST /dana/js?prot=1&svc=4 HTTP/1.1\r\nConnection: close\r\nHost: [2001:db8::1]:4443\r\nUser-Agent: zay-test\r\nCookie: DSPREAUTH=preauth; DSID=session\r\nNCP-Version: 3\r\nContent-Length: 256\r\n\r\n"
        );
        assert!(
            build_network_connect_oncp_request(
                &Url::parse("https://vpn.example").unwrap(),
                "bad\r\nheader",
                &[],
                "session",
            )
            .is_err()
        );
    }

    #[test]
    fn kmp_and_record_codecs_are_strict_and_round_trip() {
        let message = encode_network_connect_oncp_kmp(
            NETWORK_CONNECT_ONCP_KMP_DATA,
            b"packet",
        )
        .unwrap();
        let (header, payload) =
            parse_network_connect_oncp_kmp(&message, true).unwrap();
        assert_eq!(header.message_type, NETWORK_CONNECT_ONCP_KMP_DATA);
        assert_eq!(payload, b"packet");
        let record = encode_network_connect_oncp_record(&message).unwrap();
        assert_eq!(
            decode_network_connect_oncp_record(&record).unwrap(),
            (message, record.len())
        );
        let mut malformed = encode_network_connect_oncp_kmp(300, b"x").unwrap();
        malformed[8] = 9;
        assert!(parse_network_connect_oncp_kmp(&malformed, true).is_err());

        let mut first = encode_network_connect_oncp_kmp(300, b"one").unwrap();
        first[8..18].copy_from_slice(&KMP_TAIL);
        let mut second = encode_network_connect_oncp_kmp(303, b"two").unwrap();
        second[8..18].copy_from_slice(&KMP_TAIL);
        let mut decoder = NetworkConnectOncpKmpDecoder::default();
        decoder.push_record(&first[..7]).unwrap();
        assert!(decoder.next_message().unwrap().is_none());
        let mut rest = first[7..].to_vec();
        rest.extend_from_slice(&second);
        decoder.push_record(&rest).unwrap();
        assert_eq!(
            decoder.next_message().unwrap(),
            Some((300, b"one".to_vec()))
        );
        assert_eq!(
            decoder.next_message().unwrap(),
            Some((303, b"two".to_vec()))
        );
        assert_eq!(decoder.pending_len(), 0);
    }

    #[test]
    fn parses_configuration_and_prepares_esp_response() {
        let payload: Vec<u8> = [
            group(1, &[tlv(1, &[10, 7, 0, 9]), tlv(2, &[255, 255, 255, 0])]),
            group(2, &[tlv(1, &[1, 1, 1, 1]), tlv(2, b"corp.example")]),
            group(3, &[tlv(3, &[10, 0, 0, 0, 255, 0, 0, 0])]),
            group(4, &[tlv(1, &[10, 0, 0, 10])]),
            group(6, &[tlv(2, &1400_u32.to_be_bytes())]),
            group(
                7,
                &[tlv(1, &0x1020_3040_u32.to_be_bytes()), tlv(2, &[0x55; 64])],
            ),
            group(
                8,
                &[
                    tlv(1, &[2]),
                    tlv(2, &[2]),
                    tlv(3, &[1]),
                    tlv(4, &4500_u16.to_be_bytes()),
                    tlv(9, &30_u32.to_be_bytes()),
                    tlv(10, &1_u32.to_be_bytes()),
                ],
            ),
        ]
        .into_iter()
        .flatten()
        .collect();
        let parsed = parse_network_connect_oncp_configuration_payload(
            &payload,
            "192.0.2.9".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.assigned_ipv4, Ipv4Addr::new(10, 7, 0, 9));
        assert_eq!(parsed.configuration.mtu, 1400);
        assert_eq!(
            parsed.configuration.addresses[0].to_string(),
            "10.7.0.9/24"
        );
        assert_eq!(
            parsed.configuration.routes[0].prefix.to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            parsed.configuration.dns,
            ["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(parsed.esp_parameters.port, 4500);
        let (esp, response) = prepare_network_connect_esp(
            "192.0.2.9".parse().unwrap(),
            &parsed.esp_parameters,
        )
        .unwrap();
        assert_eq!(esp.remote, "192.0.2.9:4500".parse::<SocketAddr>().unwrap());
        assert_eq!(esp.keys.outbound.spi, 0x1020_3040);
        assert_ne!(esp.keys.inbound.spi, 0);
        assert_eq!(esp.keys.outbound.encryption_key, vec![0x55; 16]);
        assert_eq!(esp.keys.outbound.authentication_key, vec![0x55; 20]);
        let (header, _) =
            parse_network_connect_oncp_kmp(&response, true).unwrap();
        assert_eq!(header.message_type, NETWORK_CONNECT_ONCP_KMP_ESP);
    }

    #[test]
    fn rejects_non_contiguous_mask_and_invalid_ipv4_packets() {
        let payload =
            group(1, &[tlv(1, &[10, 0, 0, 1]), tlv(2, &[255, 0, 255, 0])]);
        assert!(
            parse_network_connect_oncp_configuration_payload(
                &payload,
                "192.0.2.1".parse().unwrap(),
            )
            .is_err()
        );
        assert!(
            validate_network_connect_ipv4_packet(&[0x60; 20], true).is_err()
        );
        let mut packet = vec![0_u8; 21];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        assert_eq!(
            validate_network_connect_ipv4_packet(&packet, false),
            Ok(20)
        );
        assert!(validate_network_connect_ipv4_packet(&packet, true).is_err());
    }

    #[tokio::test]
    async fn async_stream_reads_http_fragmented_config_and_pending_data() {
        let mut configuration_payload =
            group(1, &[tlv(1, &[10, 0, 0, 2]), tlv(2, &[255, 255, 255, 0])]);
        configuration_payload
            .extend_from_slice(&group(6, &[tlv(2, &1400_u32.to_be_bytes())]));
        let mut configuration = encode_network_connect_oncp_kmp(
            NETWORK_CONNECT_ONCP_KMP_CONFIGURATION,
            &configuration_payload,
        )
        .unwrap();
        configuration[8..18].copy_from_slice(&KMP_TAIL);
        let split = 17;
        let mut first_payload = vec![0];
        first_payload.extend_from_slice(&configuration[..split]);
        let first = encode_network_connect_oncp_record(&first_payload).unwrap();

        let mut data = encode_network_connect_oncp_kmp(
            NETWORK_CONNECT_ONCP_KMP_DATA,
            &[
                0x45, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
        .unwrap();
        data[8..18].copy_from_slice(&KMP_TAIL);
        let data_record = encode_network_connect_oncp_record(&data).unwrap();
        let remaining =
            encode_network_connect_oncp_record(&configuration[split..])
                .unwrap();
        let mut stream =
            b"HTTP/1.1 200 OK\r\nSet-Cookie: DSID=x\r\nX-Test: yes\r\n\r\n"
                .to_vec();
        stream.extend_from_slice(&first);
        stream.extend_from_slice(&data_record);
        stream.extend_from_slice(&remaining);

        let (mut sender, receiver) = tokio::io::duplex(stream.len());
        tokio::spawn(async move {
            sender.write_all(&stream).await.unwrap();
        });
        let mut reader = NetworkConnectOncpReader::new(receiver);
        let (status, headers) =
            reader.read_http_response_header().await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers["set-cookie"], "DSID=x");
        assert_eq!(
            reader.read_initial_configuration().await.unwrap(),
            configuration
        );
        assert_eq!(
            reader.read_kmp().await.unwrap(),
            (NETWORK_CONNECT_ONCP_KMP_DATA, data[20..].to_vec())
        );
    }

    #[tokio::test]
    async fn async_writer_wraps_kmp_in_little_endian_record() {
        let (writer, mut receiver) = tokio::io::duplex(128);
        let mut writer = NetworkConnectOncpWriter::new(writer);
        writer
            .write_kmp(NETWORK_CONNECT_ONCP_KMP_CONTROL, b"control")
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let mut output = vec![0; 29];
        receiver.read_exact(&mut output).await.unwrap();
        assert_eq!(u16::from_le_bytes([output[0], output[1]]), 27);
        let (header, payload) =
            parse_network_connect_oncp_kmp(&output[2..], true).unwrap();
        assert_eq!(header.message_type, NETWORK_CONNECT_ONCP_KMP_CONTROL);
        assert_eq!(payload, b"control");
    }
}
