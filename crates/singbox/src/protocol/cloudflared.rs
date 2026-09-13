//! Cloudflare Tunnel wire-independent control primitives.
//!
//! The transport uses mature Rust QUIC/HTTP2 implementations elsewhere in
//! this crate.  This module owns the Cloudflare-specific token, protocol
//! selection, feature rollout and edge-discovery contracts.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use http::HeaderMap;
use serde::Deserialize;
use thiserror::Error;
use tokio_util::compat::TokioAsyncReadCompatExt;
use uuid::Uuid;

use crate::{
    cloudflared_quic_metadata_capnp as quic_metadata,
    cloudflared_tunnelrpc_capnp as tunnelrpc,
};

pub const CLOUDFLARED_EDGE_SRV_SERVICE: &str = "v2-origintunneld";
pub const CLOUDFLARED_EDGE_SRV_PROTOCOL: &str = "tcp";
pub const CLOUDFLARED_EDGE_SRV_NAME: &str = "argotunnel.com";
pub const CLOUDFLARED_QUIC_EDGE_SNI: &str = "quic.cftunnel.com";
pub const CLOUDFLARED_QUIC_EDGE_ALPN: &str = "argotunnel";
pub const CLOUDFLARED_HTTP2_EDGE_SNI: &str = "h2.cftunnel.com";
pub const CLOUDFLARED_DEFAULT_DATAGRAM_VERSION: &str = "v2";
pub const CLOUDFLARED_DEFAULT_HA_CONNECTIONS: usize = 4;
pub const CLOUDFLARED_DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(30);
pub const CLOUDFLARED_DATA_STREAM_SIGNATURE: [u8; 6] =
    [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E];
pub const CLOUDFLARED_RPC_STREAM_SIGNATURE: [u8; 6] =
    [0x52, 0xBB, 0x82, 0x5C, 0xDB, 0x65];
pub const CLOUDFLARED_PROTOCOL_VERSION: [u8; 2] = *b"01";
pub const CLOUDFLARED_H2_HEADER_UPGRADE: &str =
    "cf-cloudflared-proxy-connection-upgrade";
pub const CLOUDFLARED_H2_HEADER_TCP_SOURCE: &str = "cf-cloudflared-proxy-src";
pub const CLOUDFLARED_H2_HEADER_RESPONSE_META: &str =
    "cf-cloudflared-response-meta";
pub const CLOUDFLARED_H2_HEADER_RESPONSE_USER: &str =
    "cf-cloudflared-response-headers";
pub const CLOUDFLARED_H2_UPGRADE_CONTROL_STREAM: &str = "control-stream";
pub const CLOUDFLARED_H2_UPGRADE_WEBSOCKET: &str = "websocket";
pub const CLOUDFLARED_H2_UPGRADE_CONFIGURATION: &str = "update-configuration";
pub const CLOUDFLARED_H2_RESPONSE_META_ORIGIN: &str = r#"{"src":"origin"}"#;
pub const CLOUDFLARED_MAX_V3_UDP_PAYLOAD: usize = 1280;
pub const CLOUDFLARED_V3_DEFAULT_IDLE_TIMEOUT: Duration =
    Duration::from_secs(210);

#[derive(Debug, Error)]
pub enum CloudflaredError {
    #[error("missing token")]
    MissingToken,
    #[error("decode token: {0}")]
    TokenBase64(String),
    #[error("unmarshal token: {0}")]
    TokenJson(String),
    #[error("invalid tunnel ID: {0}")]
    TunnelId(String),
    #[error("decode tunnel secret: {0}")]
    TunnelSecret(String),
    #[error("unsupported protocol: {0}, expected auto, quic, http2 or h2mux")]
    UnsupportedProtocol(String),
    #[error("post-quantum is only supported with quic transport")]
    PostQuantumRequiresQuic,
    #[error("edge discovery: {0}")]
    EdgeDiscovery(String),
    #[error("unknown stream signature")]
    UnknownStreamSignature,
    #[error("cloudflared frame is too short")]
    FrameTooShort,
    #[error("unknown cloudflared datagram type: {0}")]
    UnknownDatagramType(u8),
    #[error(
        "cloudflared v3 payload exceeds {CLOUDFLARED_MAX_V3_UDP_PAYLOAD} bytes"
    )]
    DatagramPayloadTooLarge,
    #[error("cloudflared datagram error message exceeds 65535 bytes")]
    DatagramErrorMessageTooLarge,
    #[error("invalid cloudflared v3 registration destination")]
    InvalidRegistrationDestination,
    #[error("cloudflared Cap'n Proto: {0}")]
    Capnp(String),
    #[error("cloudflared transport: {0}")]
    Transport(String),
    #[error("unknown cloudflared connection type")]
    UnknownConnectionType,
    #[error("cloudflared registration failed: {cause}")]
    Registration {
        cause: String,
        retry_after: Duration,
        should_retry: bool,
    },
    #[error("cloudflared registration returned invalid connection UUID")]
    InvalidConnectionId,
    #[error("cloudflared only supports remote-managed tunnels")]
    NonRemoteManagedTunnel,
}

impl From<capnp::Error> for CloudflaredError {
    fn from(error: capnp::Error) -> Self {
        Self::Capnp(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflaredStreamType {
    Data,
    Rpc,
}

pub fn parse_cloudflared_stream_signature(
    input: &[u8],
) -> Result<(CloudflaredStreamType, &[u8]), CloudflaredError> {
    let Some(signature) = input.get(..6) else {
        return Err(CloudflaredError::FrameTooShort);
    };
    let stream_type = if signature == CLOUDFLARED_DATA_STREAM_SIGNATURE {
        CloudflaredStreamType::Data
    } else if signature == CLOUDFLARED_RPC_STREAM_SIGNATURE {
        CloudflaredStreamType::Rpc
    } else {
        return Err(CloudflaredError::UnknownStreamSignature);
    };
    Ok((stream_type, &input[6..]))
}

pub async fn read_cloudflared_stream_signature<R>(
    reader: &mut R,
) -> Result<CloudflaredStreamType, CloudflaredError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut signature = [0_u8; 6];
    tokio::io::AsyncReadExt::read_exact(reader, &mut signature)
        .await
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    parse_cloudflared_stream_signature(&signature).map(|(kind, _)| kind)
}

pub fn cloudflared_data_stream_prefix() -> [u8; 8] {
    let mut prefix = [0_u8; 8];
    prefix[..6].copy_from_slice(&CLOUDFLARED_DATA_STREAM_SIGNATURE);
    prefix[6..].copy_from_slice(&CLOUDFLARED_PROTOCOL_VERSION);
    prefix
}

pub fn serialize_cloudflared_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{}",
                STANDARD_NO_PAD.encode(name.as_str().as_bytes()),
                STANDARD_NO_PAD.encode(value.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

pub fn is_cloudflared_control_response_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with(':')
        || name.starts_with("cf-int-")
        || name.starts_with("cf-cloudflared-")
        || name.starts_with("cf-proxy-")
}

pub fn is_cloudflared_websocket_client_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sec-websocket-accept" | "connection" | "upgrade"
    )
}

pub const CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED: &str =
    "FlowConnectRateLimited";
pub const CLOUDFLARED_METADATA_HTTP_METHOD: &str = "HttpMethod";
pub const CLOUDFLARED_METADATA_HTTP_HOST: &str = "HttpHost";
pub const CLOUDFLARED_METADATA_HTTP_HEADER: &str = "HttpHeader";
pub const CLOUDFLARED_METADATA_HTTP_HEADER_PREFIX: &str = "HttpHeader:";
pub const CLOUDFLARED_METADATA_HTTP_STATUS: &str = "HttpStatus";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredMetadata {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflaredConnectionType {
    Http,
    Websocket,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredConnectRequest {
    pub destination: String,
    pub connection_type: CloudflaredConnectionType,
    pub metadata: Vec<CloudflaredMetadata>,
}

pub fn decode_cloudflared_connect_request(
    input: &[u8],
) -> Result<CloudflaredConnectRequest, CloudflaredError> {
    let message = input.get(2..).ok_or(CloudflaredError::FrameTooShort)?;
    let reader = capnp::serialize::read_message(
        &mut std::io::Cursor::new(message),
        capnp::message::ReaderOptions::new(),
    )
    .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    let request = reader
        .get_root::<quic_metadata::connect_request::Reader<'_>>()
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    decode_cloudflared_connect_request_reader(request)
}

pub async fn read_cloudflared_connect_request<R>(
    reader: &mut R,
) -> Result<CloudflaredConnectRequest, CloudflaredError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut version = [0_u8; 2];
    tokio::io::AsyncReadExt::read_exact(reader, &mut version)
        .await
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    // The Go implementation consumes but intentionally does not validate the
    // two version bytes, preserving forward compatibility.
    let reader = capnp_futures::serialize::read_message(
        reader.compat(),
        capnp::message::ReaderOptions::new(),
    )
    .await
    .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    let request = reader
        .get_root::<quic_metadata::connect_request::Reader<'_>>()
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    decode_cloudflared_connect_request_reader(request)
}

fn decode_cloudflared_connect_request_reader(
    request: quic_metadata::connect_request::Reader<'_>,
) -> Result<CloudflaredConnectRequest, CloudflaredError> {
    let connection_type = match request
        .get_type()
        .map_err(|_| CloudflaredError::UnknownConnectionType)?
    {
        quic_metadata::ConnectionType::Http => CloudflaredConnectionType::Http,
        quic_metadata::ConnectionType::Websocket => {
            CloudflaredConnectionType::Websocket
        }
        quic_metadata::ConnectionType::Tcp => CloudflaredConnectionType::Tcp,
    };
    let destination = request
        .get_dest()
        .and_then(|value| {
            value
                .to_str()
                .map_err(|error| capnp::Error::failed(error.to_string()))
        })
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))?
        .into();
    let metadata_reader = request
        .get_metadata()
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    let mut metadata = Vec::with_capacity(metadata_reader.len() as usize);
    for entry in metadata_reader {
        let key = entry
            .get_key()
            .and_then(|value| {
                value
                    .to_str()
                    .map_err(|error| capnp::Error::failed(error.to_string()))
            })
            .map_err(|error| CloudflaredError::Capnp(error.to_string()))?
            .into();
        let value = entry
            .get_val()
            .and_then(|value| {
                value
                    .to_str()
                    .map_err(|error| capnp::Error::failed(error.to_string()))
            })
            .map_err(|error| CloudflaredError::Capnp(error.to_string()))?
            .into();
        metadata.push(CloudflaredMetadata { key, value });
    }
    Ok(CloudflaredConnectRequest {
        destination,
        connection_type,
        metadata,
    })
}

pub fn encode_cloudflared_connect_response(
    response_error: Option<&str>,
    metadata: &[CloudflaredMetadata],
) -> Result<Vec<u8>, CloudflaredError> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut response =
            message.init_root::<quic_metadata::connect_response::Builder<'_>>();
        response.set_error(response_error.unwrap_or(""));
        let mut entries = response.reborrow().init_metadata(
            u32::try_from(metadata.len()).map_err(|_| {
                CloudflaredError::Capnp("too many metadata entries".into())
            })?,
        );
        for (index, entry) in metadata.iter().enumerate() {
            let mut destination = entries.reborrow().get(index as u32);
            destination.set_key(entry.key.as_str());
            destination.set_val(entry.value.as_str());
        }
    }
    let mut output = cloudflared_data_stream_prefix().to_vec();
    capnp::serialize::write_message(&mut output, &message)
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
    Ok(output)
}

pub fn cloudflared_metadata_map(
    metadata: &[CloudflaredMetadata],
) -> HashMap<String, String> {
    metadata
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect()
}

pub fn cloudflared_flow_connect_rate_limited_metadata()
-> Vec<CloudflaredMetadata> {
    vec![CloudflaredMetadata {
        key: CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED.into(),
        value: "true".into(),
    }]
}

pub fn cloudflared_has_flow_connect_rate_limited(
    metadata: &[CloudflaredMetadata],
) -> bool {
    metadata.iter().any(|entry| {
        entry.key == CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED
            && entry.value == "true"
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloudflaredDatagramV2Type {
    Udp = 0,
    Ip = 1,
    IpWithTrace = 2,
    TracingSpan = 3,
}

impl TryFrom<u8> for CloudflaredDatagramV2Type {
    type Error = CloudflaredError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Udp),
            1 => Ok(Self::Ip),
            2 => Ok(Self::IpWithTrace),
            3 => Ok(Self::TracingSpan),
            value => Err(CloudflaredError::UnknownDatagramType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredDatagramV2<'a> {
    pub datagram_type: CloudflaredDatagramV2Type,
    pub payload: &'a [u8],
}

pub fn decode_cloudflared_datagram_v2(
    frame: &[u8],
) -> Result<CloudflaredDatagramV2<'_>, CloudflaredError> {
    let (&datagram_type, payload) =
        frame.split_last().ok_or(CloudflaredError::FrameTooShort)?;
    Ok(CloudflaredDatagramV2 {
        datagram_type: datagram_type.try_into()?,
        payload,
    })
}

pub fn encode_cloudflared_datagram_v2_udp(
    session_id: Uuid,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 17);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(session_id.as_bytes());
    frame.push(CloudflaredDatagramV2Type::Udp as u8);
    frame
}

pub fn decode_cloudflared_datagram_v2_udp(
    payload: &[u8],
) -> Result<(Uuid, &[u8]), CloudflaredError> {
    let session_start = payload
        .len()
        .checked_sub(16)
        .ok_or(CloudflaredError::FrameTooShort)?;
    let session_id = Uuid::from_slice(&payload[session_start..])
        .map_err(|_| CloudflaredError::FrameTooShort)?;
    Ok((session_id, &payload[..session_start]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloudflaredDatagramV3Type {
    Registration = 0,
    Payload = 1,
    Icmp = 2,
    RegistrationResponse = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredDatagramV3Registration<'a> {
    pub request_id: [u8; 16],
    pub destination: std::net::SocketAddr,
    pub close_after_idle: Duration,
    pub traced: bool,
    pub bundled_payload: &'a [u8],
}

pub fn decode_cloudflared_datagram_v3_registration(
    frame: &[u8],
) -> Result<CloudflaredDatagramV3Registration<'_>, CloudflaredError> {
    if frame.first().copied()
        != Some(CloudflaredDatagramV3Type::Registration as u8)
    {
        return Err(CloudflaredError::UnknownDatagramType(
            frame.first().copied().unwrap_or(u8::MAX),
        ));
    }
    let body = frame.get(1..).ok_or(CloudflaredError::FrameTooShort)?;
    let header = body.get(..21).ok_or(CloudflaredError::FrameTooShort)?;
    let flags = header[0];
    let port = u16::from_be_bytes([header[1], header[2]]);
    let idle_seconds = u16::from_be_bytes([header[3], header[4]]);
    let request_id = header[5..21].try_into().expect("fixed request ID slice");
    let address_length = if flags & 0x01 != 0 { 16 } else { 4 };
    let address_bytes = body
        .get(21..21 + address_length)
        .ok_or(CloudflaredError::FrameTooShort)?;
    let address = if address_length == 16 {
        IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(address_bytes).expect("fixed IPv6 slice"),
        ))
    } else {
        IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(address_bytes).expect("fixed IPv4 slice"),
        ))
    };
    if address.is_unspecified() || port == 0 {
        return Err(CloudflaredError::InvalidRegistrationDestination);
    }
    Ok(CloudflaredDatagramV3Registration {
        request_id,
        destination: std::net::SocketAddr::new(address, port),
        close_after_idle: if idle_seconds == 0 {
            CLOUDFLARED_V3_DEFAULT_IDLE_TIMEOUT
        } else {
            Duration::from_secs(u64::from(idle_seconds))
        },
        traced: flags & 0x02 != 0,
        bundled_payload: if flags & 0x04 != 0 {
            &body[21 + address_length..]
        } else {
            &[]
        },
    })
}

pub fn encode_cloudflared_datagram_v3_payload(
    request_id: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, CloudflaredError> {
    if payload.len() > CLOUDFLARED_MAX_V3_UDP_PAYLOAD {
        return Err(CloudflaredError::DatagramPayloadTooLarge);
    }
    let mut frame = Vec::with_capacity(payload.len() + 17);
    frame.push(CloudflaredDatagramV3Type::Payload as u8);
    frame.extend_from_slice(&request_id);
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_cloudflared_datagram_v3_payload(
    frame: &[u8],
) -> Result<([u8; 16], &[u8]), CloudflaredError> {
    if frame.first().copied() != Some(CloudflaredDatagramV3Type::Payload as u8)
    {
        return Err(CloudflaredError::UnknownDatagramType(
            frame.first().copied().unwrap_or(u8::MAX),
        ));
    }
    let request_id: [u8; 16] = frame
        .get(1..17)
        .ok_or(CloudflaredError::FrameTooShort)?
        .try_into()
        .expect("fixed request ID slice");
    let payload = &frame[17..];
    if payload.len() > CLOUDFLARED_MAX_V3_UDP_PAYLOAD {
        return Err(CloudflaredError::DatagramPayloadTooLarge);
    }
    Ok((request_id, payload))
}

pub fn encode_cloudflared_datagram_v3_registration_response(
    request_id: [u8; 16],
    response_type: u8,
    error_message: &str,
) -> Result<Vec<u8>, CloudflaredError> {
    let error_length = u16::try_from(error_message.len())
        .map_err(|_| CloudflaredError::DatagramErrorMessageTooLarge)?;
    let mut frame = Vec::with_capacity(20 + error_message.len());
    frame.push(CloudflaredDatagramV3Type::RegistrationResponse as u8);
    frame.push(response_type);
    frame.extend_from_slice(&request_id);
    frame.extend_from_slice(&error_length.to_be_bytes());
    frame.extend_from_slice(error_message.as_bytes());
    Ok(frame)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredCredentials {
    pub account_tag: String,
    pub tunnel_secret: Vec<u8>,
    pub tunnel_id: Uuid,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredRegistrationOptions {
    pub credentials: CloudflaredCredentials,
    pub connection_index: u8,
    pub client_id: Vec<u8>,
    pub client_features: Vec<String>,
    pub client_version: String,
    pub client_arch: String,
    pub origin_local_ip: IpAddr,
    pub replace_existing: bool,
    pub compression_quality: u8,
    pub previous_attempts: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredRegistrationResult {
    pub connection_id: Uuid,
    pub location: String,
    pub tunnel_is_remotely_managed: bool,
}

#[derive(Clone)]
pub struct CloudflaredRegistrationClient {
    client: tunnelrpc::registration_server::Client,
}

pub type CloudflaredRpcSystem =
    capnp_rpc::RpcSystem<capnp_rpc::rpc_twoparty_capnp::Side>;

pub const CLOUDFLARED_V3_UDP_REGISTRATION_UNSUPPORTED: &str =
    "datagram v3 does not support RegisterUdpSession RPC";
pub const CLOUDFLARED_V3_UDP_UNREGISTRATION_UNSUPPORTED: &str =
    "datagram v3 does not support UnregisterUdpSession RPC";

pub fn cloudflared_registration_rpc<S>(
    stream: S,
) -> (CloudflaredRegistrationClient, CloudflaredRpcSystem)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = futures::io::AsyncReadExt::split(stream.compat());
    let network = Box::new(capnp_rpc::twoparty::VatNetwork::new(
        futures::io::BufReader::new(reader),
        futures::io::BufWriter::new(writer),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        capnp::message::ReaderOptions::new(),
    ));
    let mut rpc_system = capnp_rpc::RpcSystem::new(network, None);
    let client = rpc_system
        .bootstrap::<tunnelrpc::registration_server::Client>(
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
        );
    (CloudflaredRegistrationClient { client }, rpc_system)
}

impl CloudflaredRegistrationClient {
    pub async fn register_connection(
        &self,
        options: &CloudflaredRegistrationOptions,
    ) -> Result<CloudflaredRegistrationResult, CloudflaredError> {
        let mut request = self.client.register_connection_request();
        {
            let mut params = request.get();
            {
                let mut auth = params.reborrow().init_auth();
                auth.set_account_tag(options.credentials.account_tag.as_str());
                auth.set_tunnel_secret(&options.credentials.tunnel_secret);
            }
            params.set_tunnel_id(options.credentials.tunnel_id.as_bytes());
            params.set_conn_index(options.connection_index);
            let mut connection = params.init_options();
            let origin_local_ip = match options.origin_local_ip {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            };
            connection.set_origin_local_ip(&origin_local_ip);
            connection.set_replace_existing(options.replace_existing);
            connection.set_compression_quality(options.compression_quality);
            connection.set_num_previous_attempts(options.previous_attempts);
            let mut client = connection.init_client();
            client.set_client_id(&options.client_id);
            client.set_version(options.client_version.as_str());
            client.set_arch(options.client_arch.as_str());
            let mut features = client.init_features(
                u32::try_from(options.client_features.len()).map_err(|_| {
                    CloudflaredError::Capnp("too many client features".into())
                })?,
            );
            for (index, feature) in options.client_features.iter().enumerate() {
                features.set(index as u32, feature.as_str());
            }
        }
        let response = request
            .send()
            .promise
            .await
            .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
        let response = response
            .get()
            .and_then(|results| results.get_result())
            .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
        match response
            .get_result()
            .which()
            .map_err(|error| CloudflaredError::Capnp(error.to_string()))?
        {
            tunnelrpc::connection_response::result::Error(error) => {
                let error = error.map_err(|error| {
                    CloudflaredError::Capnp(error.to_string())
                })?;
                let cause = capnp_text(error.get_cause()?)?;
                let retry_after_nanos = error.get_retry_after().max(0) as u64;
                Err(CloudflaredError::Registration {
                    cause,
                    retry_after: Duration::from_nanos(retry_after_nanos),
                    should_retry: error.get_should_retry(),
                })
            }
            tunnelrpc::connection_response::result::ConnectionDetails(
                details,
            ) => {
                let details = details.map_err(|error| {
                    CloudflaredError::Capnp(error.to_string())
                })?;
                let connection_id = Uuid::from_slice(details.get_uuid()?)
                    .map_err(|_| CloudflaredError::InvalidConnectionId)?;
                Ok(CloudflaredRegistrationResult {
                    connection_id,
                    location: capnp_text(details.get_location_name()?)?,
                    tunnel_is_remotely_managed: details
                        .get_tunnel_is_remotely_managed(),
                })
            }
        }
    }

    pub async fn unregister_connection(&self) -> Result<(), CloudflaredError> {
        self.client
            .unregister_connection_request()
            .send()
            .promise
            .await
            .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
        Ok(())
    }

    pub async fn update_local_configuration(
        &self,
        configuration: &[u8],
    ) -> Result<(), CloudflaredError> {
        let mut request = self.client.update_local_configuration_request();
        request.get().set_config(configuration);
        request
            .send()
            .promise
            .await
            .map_err(|error| CloudflaredError::Capnp(error.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflaredIncomingDatagramVersion {
    V2,
    V3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredConfigurationUpdate {
    pub latest_applied_version: i32,
    pub error: Option<String>,
}

pub trait CloudflaredConfigurationApplier: Send + Sync + 'static {
    fn apply_configuration(
        &self,
        version: i32,
        configuration: &[u8],
    ) -> CloudflaredConfigurationUpdate;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredUdpRegistration {
    pub session_id: Uuid,
    pub destination: SocketAddr,
    /// Signed nanoseconds, matching Go's `time.Duration` wire conversion.
    pub close_after_idle_nanos: i64,
    pub trace_context: String,
}

#[async_trait]
pub trait CloudflaredUdpSessionHandler: Send + Sync + 'static {
    async fn register_udp_session(
        &self,
        registration: CloudflaredUdpRegistration,
    ) -> Result<Vec<u8>, String>;

    async fn unregister_udp_session(&self, session_id: Uuid, message: &str);
}

pub struct CloudflaredIncomingRpcServer {
    datagram_version: CloudflaredIncomingDatagramVersion,
    configuration_applier: Arc<dyn CloudflaredConfigurationApplier>,
    udp_sessions: Option<Arc<dyn CloudflaredUdpSessionHandler>>,
}

impl CloudflaredIncomingRpcServer {
    pub fn datagram_v2(
        configuration_applier: Arc<dyn CloudflaredConfigurationApplier>,
        udp_sessions: Arc<dyn CloudflaredUdpSessionHandler>,
    ) -> Self {
        Self {
            datagram_version: CloudflaredIncomingDatagramVersion::V2,
            configuration_applier,
            udp_sessions: Some(udp_sessions),
        }
    }

    pub fn datagram_v3(
        configuration_applier: Arc<dyn CloudflaredConfigurationApplier>,
    ) -> Self {
        Self {
            datagram_version: CloudflaredIncomingDatagramVersion::V3,
            configuration_applier,
            udp_sessions: None,
        }
    }
}

pub fn cloudflared_incoming_rpc<S>(
    stream: S,
    server: CloudflaredIncomingRpcServer,
) -> CloudflaredRpcSystem
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let bootstrap: tunnelrpc::cloudflared_server::Client =
        capnp_rpc::new_client(server);
    let (reader, writer) = futures::io::AsyncReadExt::split(stream.compat());
    let network = Box::new(capnp_rpc::twoparty::VatNetwork::new(
        futures::io::BufReader::new(reader),
        futures::io::BufWriter::new(writer),
        capnp_rpc::rpc_twoparty_capnp::Side::Server,
        capnp::message::ReaderOptions::new(),
    ));
    capnp_rpc::RpcSystem::new(network, Some(bootstrap.client))
}

impl tunnelrpc::session_manager::Server for CloudflaredIncomingRpcServer {
    async fn register_udp_session(
        self: capnp::capability::Rc<Self>,
        params: tunnelrpc::session_manager::RegisterUdpSessionParams,
        mut results: tunnelrpc::session_manager::RegisterUdpSessionResults,
    ) -> Result<(), capnp::Error> {
        if self.datagram_version == CloudflaredIncomingDatagramVersion::V3 {
            let mut result = results.get().init_result();
            result.set_err(CLOUDFLARED_V3_UDP_REGISTRATION_UNSUPPORTED);
            result.set_spans(&[]);
            return Ok(());
        }

        let params = params.get()?;
        let session_id = Uuid::from_slice(params.get_session_id()?)
            .map_err(|error| capnp::Error::failed(error.to_string()))?;
        let destination_ip = params.get_dst_ip()?;
        let registration_result = if destination_ip.is_empty() {
            Err("missing destination IP".to_owned())
        } else {
            let destination_ip = match destination_ip.len() {
                4 => IpAddr::from(
                    <[u8; 4]>::try_from(destination_ip)
                        .expect("length checked"),
                ),
                16 => IpAddr::from(
                    <[u8; 16]>::try_from(destination_ip)
                        .expect("length checked"),
                ),
                _ => {
                    let mut result = results.get().init_result();
                    result.set_err("invalid destination IP");
                    result.set_spans(&[]);
                    return Ok(());
                }
            };
            let trace_context = params
                .get_trace_context()?
                .to_str()
                .map_err(|error| capnp::Error::failed(error.to_string()))?
                .to_owned();
            let registration = CloudflaredUdpRegistration {
                session_id,
                destination: SocketAddr::new(
                    destination_ip,
                    params.get_dst_port(),
                ),
                close_after_idle_nanos: params.get_close_after_idle_hint(),
                trace_context,
            };
            self.udp_sessions
                .as_ref()
                .expect("v2 server always has a UDP session handler")
                .register_udp_session(registration)
                .await
        };

        let mut result = results.get().init_result();
        match registration_result {
            Ok(spans) => {
                result.set_err("");
                result.set_spans(&spans);
            }
            Err(error) => {
                result.set_err(error.as_str());
                result.set_spans(&[]);
            }
        }
        Ok(())
    }

    async fn unregister_udp_session(
        self: capnp::capability::Rc<Self>,
        params: tunnelrpc::session_manager::UnregisterUdpSessionParams,
        _results: tunnelrpc::session_manager::UnregisterUdpSessionResults,
    ) -> Result<(), capnp::Error> {
        if self.datagram_version == CloudflaredIncomingDatagramVersion::V3 {
            return Err(capnp::Error::failed(
                CLOUDFLARED_V3_UDP_UNREGISTRATION_UNSUPPORTED.to_owned(),
            ));
        }
        let params = params.get()?;
        let session_id = Uuid::from_slice(params.get_session_id()?)
            .map_err(|error| capnp::Error::failed(error.to_string()))?;
        let message = params
            .get_message()?
            .to_str()
            .map_err(|error| capnp::Error::failed(error.to_string()))?;
        self.udp_sessions
            .as_ref()
            .expect("v2 server always has a UDP session handler")
            .unregister_udp_session(session_id, message)
            .await;
        Ok(())
    }
}

impl tunnelrpc::configuration_manager::Server for CloudflaredIncomingRpcServer {
    async fn update_configuration(
        self: capnp::capability::Rc<Self>,
        params: tunnelrpc::configuration_manager::UpdateConfigurationParams,
        mut results: tunnelrpc::configuration_manager::UpdateConfigurationResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let update = self
            .configuration_applier
            .apply_configuration(params.get_version(), params.get_config()?);
        let mut result = results.get().init_result();
        result.set_latest_applied_version(update.latest_applied_version);
        result.set_err(update.error.as_deref().unwrap_or(""));
        Ok(())
    }
}

impl tunnelrpc::cloudflared_server::Server for CloudflaredIncomingRpcServer {}

fn capnp_text(
    value: capnp::text::Reader<'_>,
) -> Result<String, CloudflaredError> {
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|error| CloudflaredError::Capnp(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct CloudflaredTunnelToken {
    #[serde(default, rename = "a")]
    account_tag: String,
    #[serde(default, rename = "s")]
    tunnel_secret: String,
    #[serde(default, rename = "t")]
    tunnel_id: Option<String>,
    #[serde(default, rename = "e")]
    endpoint: String,
}

pub fn parse_cloudflared_token(
    token: &str,
) -> Result<CloudflaredCredentials, CloudflaredError> {
    if token.is_empty() {
        return Err(CloudflaredError::MissingToken);
    }
    let decoded = STANDARD
        .decode(token)
        .map_err(|error| CloudflaredError::TokenBase64(error.to_string()))?;
    let token: CloudflaredTunnelToken = serde_json::from_slice(&decoded)
        .map_err(|error| CloudflaredError::TokenJson(error.to_string()))?;
    let tunnel_id = match token.tunnel_id {
        Some(value) => Uuid::parse_str(&value)
            .map_err(|error| CloudflaredError::TunnelId(error.to_string()))?,
        None => Uuid::nil(),
    };
    let tunnel_secret = if token.tunnel_secret.is_empty() {
        Vec::new()
    } else {
        STANDARD.decode(&token.tunnel_secret).map_err(|error| {
            CloudflaredError::TunnelSecret(error.to_string())
        })?
    };
    Ok(CloudflaredCredentials {
        account_tag: token.account_tag,
        tunnel_secret,
        tunnel_id,
        endpoint: token.endpoint,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflaredTransportProtocol {
    Quic,
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudflaredProtocolSelection {
    pub current: CloudflaredTransportProtocol,
    pub fallback: Option<CloudflaredTransportProtocol>,
    pub h2mux_compatibility_alias: bool,
}

impl CloudflaredProtocolSelection {
    pub fn new(
        protocol: &str,
        post_quantum: bool,
    ) -> Result<Self, CloudflaredError> {
        let normalized = match protocol {
            "" | "auto" => "",
            "quic" => "quic",
            "http2" => "http2",
            "h2mux" => "http2",
            value => {
                return Err(CloudflaredError::UnsupportedProtocol(
                    value.into(),
                ));
            }
        };
        if post_quantum && normalized == "http2" {
            return Err(CloudflaredError::PostQuantumRequiresQuic);
        }
        Ok(match normalized {
            "" if post_quantum => Self {
                current: CloudflaredTransportProtocol::Quic,
                fallback: None,
                h2mux_compatibility_alias: false,
            },
            "" => Self {
                current: CloudflaredTransportProtocol::Quic,
                fallback: Some(CloudflaredTransportProtocol::Http2),
                h2mux_compatibility_alias: false,
            },
            "quic" => Self {
                current: CloudflaredTransportProtocol::Quic,
                fallback: None,
                h2mux_compatibility_alias: false,
            },
            "http2" => Self {
                current: CloudflaredTransportProtocol::Http2,
                fallback: None,
                h2mux_compatibility_alias: protocol == "h2mux",
            },
            _ => unreachable!("protocol was normalized"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredSrvRecord {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudflaredEdgeAddress {
    pub address: std::net::SocketAddr,
    pub ip_version: u8,
}

#[async_trait]
pub trait CloudflaredEdgeResolver: Send + Sync {
    async fn lookup_srv(
        &self,
        service: &str,
        protocol: &str,
        name: &str,
    ) -> Result<Vec<CloudflaredSrvRecord>, CloudflaredError>;

    async fn lookup_ip(
        &self,
        host: &str,
    ) -> Result<Vec<IpAddr>, CloudflaredError>;
}

pub fn cloudflared_regional_service_name(region: &str) -> String {
    if region.is_empty() {
        CLOUDFLARED_EDGE_SRV_SERVICE.into()
    } else {
        format!("{region}-{CLOUDFLARED_EDGE_SRV_SERVICE}")
    }
}

pub async fn discover_cloudflared_edges(
    resolver: &dyn CloudflaredEdgeResolver,
    region: &str,
    ip_version: i32,
) -> Result<Vec<Vec<CloudflaredEdgeAddress>>, CloudflaredError> {
    if !matches!(ip_version, 0 | 4 | 6) {
        return Err(CloudflaredError::EdgeDiscovery(format!(
            "unsupported IP version {ip_version}"
        )));
    }
    let mut records = resolver
        .lookup_srv(
            &cloudflared_regional_service_name(region),
            CLOUDFLARED_EDGE_SRV_PROTOCOL,
            CLOUDFLARED_EDGE_SRV_NAME,
        )
        .await?;
    records.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| right.weight.cmp(&left.weight))
    });
    let mut regions = Vec::new();
    for record in records {
        let addresses = resolver.lookup_ip(&record.target).await?;
        let region = addresses
            .into_iter()
            .filter(|address| {
                ip_version == 0
                    || (ip_version == 4 && address.is_ipv4())
                    || (ip_version == 6 && address.is_ipv6())
            })
            .map(|address| CloudflaredEdgeAddress {
                address: std::net::SocketAddr::new(address, record.port),
                ip_version: if address.is_ipv4() { 4 } else { 6 },
            })
            .collect::<Vec<_>>();
        if !region.is_empty() {
            regions.push(region);
        }
    }
    if regions.is_empty() {
        return Err(CloudflaredError::EdgeDiscovery(
            "no edge addresses found".into(),
        ));
    }
    Ok(regions)
}

pub fn cloudflared_effective_ha_connections(
    requested: usize,
    available: usize,
) -> usize {
    requested.min(available)
}

pub fn cloudflared_account_enabled(account_tag: &str, percentage: u32) -> bool {
    if percentage == 0 {
        return false;
    }
    let hash = account_tag
        .as_bytes()
        .iter()
        .fold(2_166_136_261_u32, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
        });
    percentage > hash % 100
}

pub fn cloudflared_remote_datagram_version(
    account_tag: &str,
    txt_record: &[u8],
) -> Result<&'static str, CloudflaredError> {
    #[derive(Deserialize)]
    struct Features {
        #[serde(default, rename = "dv3_2")]
        datagram_v3_percentage: u32,
    }
    let features: Features = serde_json::from_slice(txt_record)
        .map_err(|error| CloudflaredError::TokenJson(error.to_string()))?;
    Ok(
        if cloudflared_account_enabled(
            account_tag,
            features.datagram_v3_percentage,
        ) {
            "v3"
        } else {
            CLOUDFLARED_DEFAULT_DATAGRAM_VERSION
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use http::{HeaderMap, HeaderValue};

    use super::*;

    const TOKEN: &str = "eyJhIjoiYWNjb3VudDEyMyIsInQiOiI1NTBlODQwMC1lMjlhLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJzIjoiYzJWamNtVjBMVE15TFdKNWRHVnpMV3h2Ym1jdGVIZz0iLCJlIjoiZmVkIn0=";

    #[test]
    fn token_protocol_and_feature_selection_match_go_contract() {
        let credentials = parse_cloudflared_token(TOKEN).unwrap();
        assert_eq!(credentials.account_tag, "account123");
        assert_eq!(
            credentials.tunnel_id,
            Uuid::parse_str("550e8400-e29a-41d4-a716-446655440000").unwrap()
        );
        assert_eq!(credentials.tunnel_secret, b"secret-32-bytes-long-xx");
        assert_eq!(credentials.endpoint, "fed");
        assert!(parse_cloudflared_token("").is_err());
        assert!(parse_cloudflared_token("not-base64").is_err());

        assert_eq!(
            CloudflaredProtocolSelection::new("auto", false).unwrap(),
            CloudflaredProtocolSelection {
                current: CloudflaredTransportProtocol::Quic,
                fallback: Some(CloudflaredTransportProtocol::Http2),
                h2mux_compatibility_alias: false,
            }
        );
        assert!(CloudflaredProtocolSelection::new("http2", true).is_err());
        assert_eq!(
            CloudflaredProtocolSelection::new("h2mux", false)
                .unwrap()
                .current,
            CloudflaredTransportProtocol::Http2
        );
        assert_eq!(
            cloudflared_remote_datagram_version(
                "account123",
                br#"{"dv3_2":100}"#
            )
            .unwrap(),
            "v3"
        );
        assert_eq!(
            cloudflared_remote_datagram_version(
                "account123",
                br#"{"dv3_2":0}"#
            )
            .unwrap(),
            "v2"
        );
        assert_eq!(cloudflared_effective_ha_connections(4, 2), 2);
    }

    struct Resolver {
        calls: Mutex<Vec<(String, String, String)>>,
        addresses: HashMap<String, Vec<IpAddr>>,
    }

    #[async_trait]
    impl CloudflaredEdgeResolver for Resolver {
        async fn lookup_srv(
            &self,
            service: &str,
            protocol: &str,
            name: &str,
        ) -> Result<Vec<CloudflaredSrvRecord>, CloudflaredError> {
            self.calls.lock().unwrap().push((
                service.into(),
                protocol.into(),
                name.into(),
            ));
            Ok(vec![
                CloudflaredSrvRecord {
                    target: "second.example".into(),
                    port: 7844,
                    priority: 2,
                    weight: 1,
                },
                CloudflaredSrvRecord {
                    target: "first.example".into(),
                    port: 7844,
                    priority: 1,
                    weight: 10,
                },
            ])
        }

        async fn lookup_ip(
            &self,
            host: &str,
        ) -> Result<Vec<IpAddr>, CloudflaredError> {
            Ok(self.addresses.get(host).cloned().unwrap_or_default())
        }
    }

    #[tokio::test]
    async fn edge_discovery_sorts_srv_and_filters_address_family() {
        let resolver = Resolver {
            calls: Mutex::new(Vec::new()),
            addresses: HashMap::from([
                (
                    "first.example".into(),
                    vec![
                        "192.0.2.1".parse().unwrap(),
                        "2001:db8::1".parse().unwrap(),
                    ],
                ),
                ("second.example".into(), vec!["192.0.2.2".parse().unwrap()]),
            ]),
        };
        let regions = discover_cloudflared_edges(&resolver, "fed", 6)
            .await
            .unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(
            regions[0][0].address,
            "[2001:db8::1]:7844"
                .parse::<std::net::SocketAddr>()
                .unwrap()
        );
        assert_eq!(
            resolver.calls.lock().unwrap().as_slice(),
            &[(
                "fed-v2-origintunneld".into(),
                "tcp".into(),
                "argotunnel.com".into(),
            )]
        );
    }

    #[test]
    fn stream_header_and_metadata_helpers_match_go_contract() {
        let prefix = cloudflared_data_stream_prefix();
        assert_eq!(
            parse_cloudflared_stream_signature(&prefix).unwrap(),
            (
                CloudflaredStreamType::Data,
                CLOUDFLARED_PROTOCOL_VERSION.as_slice()
            )
        );
        assert_eq!(
            parse_cloudflared_stream_signature(
                &CLOUDFLARED_RPC_STREAM_SIGNATURE
            )
            .unwrap()
            .0,
            CloudflaredStreamType::Rpc
        );
        assert!(parse_cloudflared_stream_signature(&[0_u8; 6]).is_err());

        let mut headers = HeaderMap::new();
        headers.insert("x-name", HeaderValue::from_static("hello world"));
        assert_eq!(
            serialize_cloudflared_headers(&headers),
            "eC1uYW1l:aGVsbG8gd29ybGQ"
        );
        assert!(is_cloudflared_control_response_header(
            "Cf-Cloudflared-Test"
        ));
        assert!(is_cloudflared_websocket_client_header("Upgrade"));
        assert!(!is_cloudflared_websocket_client_header("host"));

        let metadata = cloudflared_flow_connect_rate_limited_metadata();
        assert!(cloudflared_has_flow_connect_rate_limited(&metadata));
        assert_eq!(
            cloudflared_metadata_map(&metadata)
                [CLOUDFLARED_METADATA_FLOW_CONNECT_RATE_LIMITED],
            "true"
        );
    }

    #[test]
    fn capnp_connect_request_and_response_use_upstream_schema() {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut request = message
                .init_root::<quic_metadata::connect_request::Builder<'_>>();
            request.set_dest("https://example.com/test");
            request.set_type(quic_metadata::ConnectionType::Http);
            let mut metadata = request.reborrow().init_metadata(2);
            let mut method = metadata.reborrow().get(0);
            method.set_key(CLOUDFLARED_METADATA_HTTP_METHOD);
            method.set_val("GET");
            let mut host = metadata.reborrow().get(1);
            host.set_key(CLOUDFLARED_METADATA_HTTP_HOST);
            host.set_val("example.com");
        }
        let mut encoded = CLOUDFLARED_PROTOCOL_VERSION.to_vec();
        capnp::serialize::write_message(&mut encoded, &message).unwrap();
        let decoded = decode_cloudflared_connect_request(&encoded).unwrap();
        assert_eq!(decoded.destination, "https://example.com/test");
        assert_eq!(decoded.connection_type, CloudflaredConnectionType::Http);
        assert_eq!(
            cloudflared_metadata_map(&decoded.metadata)
                [CLOUDFLARED_METADATA_HTTP_METHOD],
            "GET"
        );

        let response = encode_cloudflared_connect_response(
            Some("denied"),
            &[CloudflaredMetadata {
                key: CLOUDFLARED_METADATA_HTTP_STATUS.into(),
                value: "403".into(),
            }],
        )
        .unwrap();
        assert_eq!(&response[..8], &cloudflared_data_stream_prefix());
        let reader = capnp::serialize::read_message(
            &mut std::io::Cursor::new(&response[8..]),
            capnp::message::ReaderOptions::new(),
        )
        .unwrap();
        let response = reader
            .get_root::<quic_metadata::connect_response::Reader<'_>>()
            .unwrap();
        assert_eq!(response.get_error().unwrap().to_str().unwrap(), "denied");
        let metadata = response.get_metadata().unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(
            metadata.get(0).get_key().unwrap().to_str().unwrap(),
            CLOUDFLARED_METADATA_HTTP_STATUS
        );
        assert_eq!(metadata.get(0).get_val().unwrap().to_str().unwrap(), "403");
    }

    #[tokio::test]
    async fn async_stream_reader_handles_fragmented_quic_metadata() {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut request = message
                .init_root::<quic_metadata::connect_request::Builder<'_>>();
            request.set_dest("tcp://192.0.2.10:443");
            request.set_type(quic_metadata::ConnectionType::Tcp);
            let mut metadata = request.reborrow().init_metadata(1);
            let mut source = metadata.reborrow().get(0);
            source.set_key(CLOUDFLARED_METADATA_HTTP_HOST);
            source.set_val("edge.example");
        }
        let mut wire = CLOUDFLARED_DATA_STREAM_SIGNATURE.to_vec();
        // Unknown version is accepted exactly like the upstream reader.
        wire.extend_from_slice(b"99");
        capnp::serialize::write_message(&mut wire, &message).unwrap();

        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let writer_task = tokio::spawn(async move {
            for byte in wire {
                tokio::io::AsyncWriteExt::write_all(&mut writer, &[byte])
                    .await
                    .unwrap();
            }
        });
        assert_eq!(
            read_cloudflared_stream_signature(&mut reader)
                .await
                .unwrap(),
            CloudflaredStreamType::Data
        );
        let request =
            read_cloudflared_connect_request(&mut reader).await.unwrap();
        assert_eq!(request.destination, "tcp://192.0.2.10:443");
        assert_eq!(request.connection_type, CloudflaredConnectionType::Tcp);
        assert_eq!(request.metadata[0].value, "edge.example");
        writer_task.await.unwrap();
    }

    struct RegistrationServer;

    impl tunnelrpc::registration_server::Server for RegistrationServer {
        async fn register_connection(
            self: capnp::capability::Rc<Self>,
            params: tunnelrpc::registration_server::RegisterConnectionParams,
            mut results: tunnelrpc::registration_server::RegisterConnectionResults,
        ) -> Result<(), capnp::Error> {
            let params = params.get()?;
            let auth = params.get_auth()?;
            assert_eq!(auth.get_account_tag()?.to_str()?, "account123");
            assert_eq!(auth.get_tunnel_secret()?, b"secret-32-bytes-long-xx");
            assert_eq!(
                params.get_tunnel_id()?,
                Uuid::parse_str("550e8400-e29a-41d4-a716-446655440000")
                    .unwrap()
                    .as_bytes()
            );
            assert_eq!(params.get_conn_index(), 3);
            let options = params.get_options()?;
            assert_eq!(options.get_origin_local_ip()?, &[192, 0, 2, 9]);
            assert!(options.get_replace_existing());
            assert_eq!(options.get_compression_quality(), 3);
            assert_eq!(options.get_num_previous_attempts(), 2);
            let client = options.get_client()?;
            assert_eq!(client.get_client_id()?, &[8; 16]);
            assert_eq!(client.get_version()?.to_str()?, "singbox-rust-test");
            assert_eq!(client.get_arch()?.to_str()?, "darwin_amd64");
            let features = client.get_features()?;
            assert_eq!(features.len(), 2);
            assert_eq!(features.get(0)?.to_str()?, "quic");
            assert_eq!(features.get(1)?.to_str()?, "datagramv3");

            let response = results.get().init_result();
            let mut details = response.get_result().init_connection_details();
            details.set_uuid(
                Uuid::parse_str("550e8400-e29a-41d4-a716-446655440001")
                    .unwrap()
                    .as_bytes(),
            );
            details.set_location_name("SJC");
            details.set_tunnel_is_remotely_managed(true);
            Ok(())
        }
    }

    #[tokio::test]
    async fn registration_rpc_maps_all_modern_cloudflare_fields() {
        let credentials = parse_cloudflared_token(TOKEN).unwrap();
        let client = CloudflaredRegistrationClient {
            client: capnp_rpc::new_client(RegistrationServer),
        };
        let result = client
            .register_connection(&CloudflaredRegistrationOptions {
                credentials,
                connection_index: 3,
                client_id: vec![8; 16],
                client_features: vec!["quic".into(), "datagramv3".into()],
                client_version: "singbox-rust-test".into(),
                client_arch: "darwin_amd64".into(),
                origin_local_ip: "192.0.2.9".parse().unwrap(),
                replace_existing: true,
                compression_quality: 3,
                previous_attempts: 2,
            })
            .await
            .unwrap();
        assert_eq!(
            result.connection_id,
            Uuid::parse_str("550e8400-e29a-41d4-a716-446655440001").unwrap()
        );
        assert_eq!(result.location, "SJC");
        assert!(result.tunnel_is_remotely_managed);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registration_rpc_runs_over_two_party_stream_transport() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (client_stream, server_stream) =
                    tokio::io::duplex(64 * 1024);
                let (client, client_rpc) =
                    cloudflared_registration_rpc(client_stream);

                let bootstrap: tunnelrpc::registration_server::Client =
                    capnp_rpc::new_client(RegistrationServer);
                let (server_reader, server_writer) =
                    futures::io::AsyncReadExt::split(server_stream.compat());
                let server_network =
                    Box::new(capnp_rpc::twoparty::VatNetwork::new(
                        futures::io::BufReader::new(server_reader),
                        futures::io::BufWriter::new(server_writer),
                        capnp_rpc::rpc_twoparty_capnp::Side::Server,
                        capnp::message::ReaderOptions::new(),
                    ));
                let server_rpc = capnp_rpc::RpcSystem::new(
                    server_network,
                    Some(bootstrap.client),
                );
                let client_task = tokio::task::spawn_local(client_rpc);
                let server_task = tokio::task::spawn_local(server_rpc);

                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    client.register_connection(
                        &CloudflaredRegistrationOptions {
                            credentials: parse_cloudflared_token(TOKEN)
                                .unwrap(),
                            connection_index: 3,
                            client_id: vec![8; 16],
                            client_features: vec![
                                "quic".into(),
                                "datagramv3".into(),
                            ],
                            client_version: "singbox-rust-test".into(),
                            client_arch: "darwin_amd64".into(),
                            origin_local_ip: "192.0.2.9".parse().unwrap(),
                            replace_existing: true,
                            compression_quality: 3,
                            previous_attempts: 2,
                        },
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(result.location, "SJC");
                client_task.abort();
                server_task.abort();
            })
            .await;
    }

    #[derive(Default)]
    struct IncomingRecorder {
        configurations: Mutex<Vec<(i32, Vec<u8>)>>,
        registrations: Mutex<Vec<CloudflaredUdpRegistration>>,
        unregistrations: Mutex<Vec<(Uuid, String)>>,
    }

    impl CloudflaredConfigurationApplier for IncomingRecorder {
        fn apply_configuration(
            &self,
            version: i32,
            configuration: &[u8],
        ) -> CloudflaredConfigurationUpdate {
            self.configurations
                .lock()
                .unwrap()
                .push((version, configuration.to_vec()));
            CloudflaredConfigurationUpdate {
                latest_applied_version: version - 1,
                error: Some("stale configuration".into()),
            }
        }
    }

    #[async_trait]
    impl CloudflaredUdpSessionHandler for IncomingRecorder {
        async fn register_udp_session(
            &self,
            registration: CloudflaredUdpRegistration,
        ) -> Result<Vec<u8>, String> {
            self.registrations.lock().unwrap().push(registration);
            Ok(vec![1, 2, 3])
        }

        async fn unregister_udp_session(
            &self,
            session_id: Uuid,
            message: &str,
        ) {
            self.unregistrations
                .lock()
                .unwrap()
                .push((session_id, message.to_owned()));
        }
    }

    #[tokio::test]
    async fn incoming_rpc_maps_v2_udp_and_configuration_fields() {
        let recorder = Arc::new(IncomingRecorder::default());
        let bootstrap: tunnelrpc::cloudflared_server::Client =
            capnp_rpc::new_client(CloudflaredIncomingRpcServer::datagram_v2(
                recorder.clone(),
                recorder.clone(),
            ));
        let session = tunnelrpc::session_manager::Client {
            client: bootstrap.client.clone(),
        };
        let configuration = tunnelrpc::configuration_manager::Client {
            client: bootstrap.client,
        };
        let session_id =
            Uuid::parse_str("550e8400-e29a-41d4-a716-446655440009").unwrap();

        let mut request = session.register_udp_session_request();
        {
            let mut params = request.get();
            params.set_session_id(session_id.as_bytes());
            params.set_dst_ip(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]);
            params.set_dst_port(53);
            params.set_close_after_idle_hint(-7);
            params.set_trace_context("traceparent=test");
        }
        let response = request.send().promise.await.unwrap();
        let response = response.get().unwrap().get_result().unwrap();
        assert_eq!(response.get_err().unwrap().to_str().unwrap(), "");
        assert_eq!(response.get_spans().unwrap(), &[1, 2, 3]);

        {
            let registrations = recorder.registrations.lock().unwrap();
            assert_eq!(registrations.len(), 1);
            assert_eq!(registrations[0].session_id, session_id);
            assert_eq!(
                registrations[0].destination.to_string(),
                "[2001:db8::1]:53"
            );
            assert_eq!(registrations[0].close_after_idle_nanos, -7);
            assert_eq!(registrations[0].trace_context, "traceparent=test");
        }

        let mut request = session.unregister_udp_session_request();
        request.get().set_session_id(session_id.as_bytes());
        request.get().set_message("edge close");
        request.send().promise.await.unwrap();
        assert_eq!(
            recorder.unregistrations.lock().unwrap().as_slice(),
            &[(session_id, "edge close".into())]
        );

        let mut request = configuration.update_configuration_request();
        request.get().set_version(9);
        request.get().set_config(br#"{"ingress":[]}"#);
        let response = request.send().promise.await.unwrap();
        let response = response.get().unwrap().get_result().unwrap();
        assert_eq!(response.get_latest_applied_version(), 8);
        assert_eq!(
            response.get_err().unwrap().to_str().unwrap(),
            "stale configuration"
        );
        assert_eq!(
            recorder.configurations.lock().unwrap().as_slice(),
            &[(9, br#"{"ingress":[]}"#.to_vec())]
        );
    }

    #[tokio::test]
    async fn incoming_rpc_preserves_v3_unsupported_session_semantics() {
        let recorder = Arc::new(IncomingRecorder::default());
        let bootstrap: tunnelrpc::cloudflared_server::Client =
            capnp_rpc::new_client(CloudflaredIncomingRpcServer::datagram_v3(
                recorder.clone(),
            ));
        let session = tunnelrpc::session_manager::Client {
            client: bootstrap.client,
        };

        let response = session
            .register_udp_session_request()
            .send()
            .promise
            .await
            .unwrap();
        let response = response.get().unwrap().get_result().unwrap();
        assert_eq!(
            response.get_err().unwrap().to_str().unwrap(),
            CLOUDFLARED_V3_UDP_REGISTRATION_UNSUPPORTED
        );
        assert!(response.get_spans().unwrap().is_empty());

        let error = match session
            .unregister_udp_session_request()
            .send()
            .promise
            .await
        {
            Ok(_) => {
                panic!("datagram v3 UDP unregistration unexpectedly succeeded")
            }
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains(CLOUDFLARED_V3_UDP_UNREGISTRATION_UNSUPPORTED)
        );
        assert!(recorder.registrations.lock().unwrap().is_empty());
        assert!(recorder.unregistrations.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn incoming_rpc_runs_over_two_party_stream_transport() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let recorder = Arc::new(IncomingRecorder::default());
                let (client_stream, server_stream) =
                    tokio::io::duplex(64 * 1024);
                let server_rpc = cloudflared_incoming_rpc(
                    server_stream,
                    CloudflaredIncomingRpcServer::datagram_v3(recorder.clone()),
                );

                let (client_reader, client_writer) =
                    futures::io::AsyncReadExt::split(client_stream.compat());
                let client_network =
                    Box::new(capnp_rpc::twoparty::VatNetwork::new(
                        futures::io::BufReader::new(client_reader),
                        futures::io::BufWriter::new(client_writer),
                        capnp_rpc::rpc_twoparty_capnp::Side::Client,
                        capnp::message::ReaderOptions::new(),
                    ));
                let mut client_rpc =
                    capnp_rpc::RpcSystem::new(client_network, None);
                let bootstrap = client_rpc
                    .bootstrap::<tunnelrpc::cloudflared_server::Client>(
                        capnp_rpc::rpc_twoparty_capnp::Side::Server,
                    );
                let configuration = tunnelrpc::configuration_manager::Client {
                    client: bootstrap.client,
                };
                let server_task = tokio::task::spawn_local(server_rpc);
                let client_task = tokio::task::spawn_local(client_rpc);

                let mut request = configuration.update_configuration_request();
                request.get().set_version(11);
                request.get().set_config(b"remote-config");
                let response = tokio::time::timeout(
                    Duration::from_secs(2),
                    request.send().promise,
                )
                .await
                .unwrap()
                .unwrap();
                let response = response.get().unwrap().get_result().unwrap();
                assert_eq!(response.get_latest_applied_version(), 10);
                assert_eq!(
                    recorder.configurations.lock().unwrap().as_slice(),
                    &[(11, b"remote-config".to_vec())]
                );
                server_task.abort();
                client_task.abort();
            })
            .await;
    }

    #[test]
    fn datagram_v2_udp_codec_matches_suffix_wire_layout() {
        let session_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000009").unwrap();
        let frame = encode_cloudflared_datagram_v2_udp(session_id, b"hello");
        assert_eq!(&frame[..5], b"hello");
        assert_eq!(frame.last().copied(), Some(0));
        let datagram = decode_cloudflared_datagram_v2(&frame).unwrap();
        assert_eq!(datagram.datagram_type, CloudflaredDatagramV2Type::Udp);
        let (decoded_id, payload) =
            decode_cloudflared_datagram_v2_udp(datagram.payload).unwrap();
        assert_eq!(decoded_id, session_id);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn datagram_v3_registration_payload_and_response_match_wire_layout() {
        let request_id = [0x7a; 16];
        let mut registration = vec![0_u8];
        registration.push(0x04);
        registration.extend_from_slice(&53_u16.to_be_bytes());
        registration.extend_from_slice(&0_u16.to_be_bytes());
        registration.extend_from_slice(&request_id);
        registration.extend_from_slice(&[192, 0, 2, 1]);
        registration.extend_from_slice(b"dns");
        let decoded =
            decode_cloudflared_datagram_v3_registration(&registration).unwrap();
        assert_eq!(decoded.request_id, request_id);
        assert_eq!(decoded.destination.to_string(), "192.0.2.1:53");
        assert_eq!(
            decoded.close_after_idle,
            CLOUDFLARED_V3_DEFAULT_IDLE_TIMEOUT
        );
        assert_eq!(decoded.bundled_payload, b"dns");

        let payload =
            encode_cloudflared_datagram_v3_payload(request_id, b"response")
                .unwrap();
        assert_eq!(
            decode_cloudflared_datagram_v3_payload(&payload).unwrap(),
            (request_id, b"response".as_slice())
        );
        assert!(
            encode_cloudflared_datagram_v3_payload(
                request_id,
                &[0_u8; CLOUDFLARED_MAX_V3_UDP_PAYLOAD + 1]
            )
            .is_err()
        );

        let response = encode_cloudflared_datagram_v3_registration_response(
            request_id, 0xff, "failed",
        )
        .unwrap();
        assert_eq!(response[0], 3);
        assert_eq!(response[1], 0xff);
        assert_eq!(&response[2..18], &request_id);
        assert_eq!(&response[18..20], &6_u16.to_be_bytes());
        assert_eq!(&response[20..], b"failed");
    }
}
