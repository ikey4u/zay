//! Apple system DNS through the mDNSResponder IPC protocol.
//!
//! `getaddrinfo` cannot answer arbitrary DNS record types and parsing only
//! `/etc/resolv.conf` loses macOS supplemental/scoped resolver selection. The
//! protocol below follows Apple's open-source `dnssd_ipc.h` and
//! `dnssd_clientstub.c`. A connection is deliberately scoped to one query:
//! dropping the future closes the stream and therefore cancels the operation
//! without leaving a process-global callback or run loop behind.

use std::{
    borrow::Cow, io, net::IpAddr, path::PathBuf, str::FromStr, time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::Record,
    serialize::binary::{BinDecodable, BinDecoder},
};
use hickory_resolver::config::{
    NameServerConfig, ResolverConfig, ResolverOpts,
};
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{FromVoid, ItemRef, TCFType},
        dictionary::CFDictionary,
        number::CFNumber,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const DEFAULT_SOCKET_PATH: &str = "/var/run/mDNSResponder";
const SOCKET_PATH_ENV: &str = "DNSSD_UDS_PATH";
const VERSION: u32 = 1;
const HEADER_LENGTH: usize = 28;
const CONNECTION_REQUEST: u32 = 1;
const QUERY_REQUEST: u32 = 8;
const QUERY_REPLY: u32 = 68;
const ASYNC_ERROR_REPLY: u32 = 73;

const FLAG_MORE_COMING: u32 = 0x1;
const FLAG_ADD: u32 = 0x2;
const FLAG_RETURN_INTERMEDIATES: u32 = 0x1000;
const FLAG_SHARE_CONNECTION: u32 = 0x4000;
const FLAG_TIMEOUT: u32 = 0x10000;
const IPC_FLAG_NO_ERROR_SOCKET: u32 = 0x4;

const ERROR_NONE: i32 = 0;
const ERROR_NO_SUCH_NAME: i32 = -65538;
const ERROR_NO_SUCH_RECORD: i32 = -65554;
const ERROR_TIMEOUT: i32 = -65568;
const MAX_REPLY_LENGTH: usize = 1 << 20;
const QUERY_CONTEXT: u64 = 1;

/// Select the DNS dictionary for the primary network service. Hickory reads
/// only `State:/Network/Global/DNS`; Apple keeps interface-scoped VPN and
/// service resolver state under `State:/Network/Service/<id>/DNS`.
pub(crate) fn read_primary_service_configuration()
-> io::Result<Option<(ResolverConfig, ResolverOpts)>> {
    let Some(store) = SCDynamicStoreBuilder::new("singbox-rust").build() else {
        return Ok(None);
    };
    for global_key in
        ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"]
    {
        let Some(global) = store
            .get(global_key)
            .and_then(|value| value.downcast_into::<CFDictionary>())
        else {
            continue;
        };
        let Some(service_id) = dictionary_string(&global, "PrimaryService")
        else {
            continue;
        };
        let dns_key = format!("State:/Network/Service/{service_id}/DNS");
        let Some(dns) = store
            .get(dns_key.as_str())
            .and_then(|value| value.downcast_into::<CFDictionary>())
        else {
            continue;
        };
        if let Some(configuration) = parse_dns_dictionary(&dns)? {
            return Ok(Some(configuration));
        }
    }
    Ok(None)
}

fn parse_dns_dictionary(
    dictionary: &CFDictionary,
) -> io::Result<Option<(ResolverConfig, ResolverOpts)>> {
    let Some(addresses) = dictionary_array(dictionary, "ServerAddresses")
    else {
        return Ok(None);
    };
    let server_port = dictionary_number(dictionary, "ServerPort")
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value != 0)
        .unwrap_or(53);
    let mut nameservers = Vec::with_capacity(addresses.len() as usize);
    for address in &*addresses {
        let address =
            IpAddr::from_str(&Cow::from(&*address)).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Apple scoped DNS server address: {error}"),
                )
            })?;
        let mut nameserver = NameServerConfig::udp_and_tcp(address);
        for connection in &mut nameserver.connections {
            connection.port = server_port;
        }
        nameservers.push(nameserver);
    }
    if nameservers.is_empty() {
        return Ok(None);
    }

    let search = dictionary_array(dictionary, "SearchDomains")
        .map(|values| {
            (&*values)
                .into_iter()
                .map(|value| {
                    hickory_proto::rr::Name::from_str(&Cow::from(&*value))
                        .map_err(|error| {
                            io::Error::new(io::ErrorKind::InvalidData, error)
                        })
                })
                .collect::<io::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mut options = ResolverOpts::default();
    options.ndots = 1;
    options.attempts = 2;
    options.timeout = dictionary_number(dictionary, "ServerTimeout")
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(5));
    Ok(Some((
        ResolverConfig::from_parts(None, search, nameservers),
        options,
    )))
}

fn dictionary_string(
    dictionary: &CFDictionary,
    key: &'static str,
) -> Option<String> {
    let raw =
        dictionary.find(CFString::from_static_string(key).as_CFTypeRef())?;
    // Apple documents this property as CFString.
    let value: ItemRef<'_, CFString> = unsafe { CFString::from_void(*raw) };
    Some(Cow::from(&*value).into_owned())
}

fn dictionary_array<'a>(
    dictionary: &'a CFDictionary,
    key: &'static str,
) -> Option<ItemRef<'a, CFArray<CFString>>> {
    let raw =
        dictionary.find(CFString::from_static_string(key).as_CFTypeRef())?;
    // Apple documents ServerAddresses/SearchDomains as CFArray<CFString>.
    Some(unsafe { CFArray::from_void(*raw) })
}

fn dictionary_number(
    dictionary: &CFDictionary,
    key: &'static str,
) -> Option<i64> {
    let raw =
        dictionary.find(CFString::from_static_string(key).as_CFTypeRef())?;
    // Apple documents ServerTimeout as CFNumber.
    let value: ItemRef<'_, CFNumber> = unsafe { CFNumber::from_void(*raw) };
    value.to_i64()
}

pub(crate) struct DarwinSystemResolver {
    socket_path: PathBuf,
}

impl DarwinSystemResolver {
    pub(crate) fn new() -> Self {
        Self {
            socket_path: std::env::var_os(SOCKET_PATH_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
        }
    }

    #[cfg(test)]
    fn with_socket_path(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub(crate) async fn exchange(
        &self,
        request: &Message,
    ) -> io::Result<Message> {
        timeout(Duration::from_secs(30), self.exchange_inner(request))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mDNSResponder query timed out",
                )
            })?
    }

    async fn exchange_inner(&self, request: &Message) -> io::Result<Message> {
        let [query] = request.queries.as_slice() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Apple system DNS requires exactly one question",
            ));
        };
        let name = query.name().to_utf8();
        if name.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS name contains NUL",
            ));
        }
        let mut stream =
            UnixStream::connect(&self.socket_path)
                .await
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("connect mDNSResponder: {error}"),
                    )
                })?;
        stream
            .write_all(&append_header(CONNECTION_REQUEST, 0, 0, 0))
            .await?;
        let status = stream.read_i32().await?;
        if status != ERROR_NONE {
            return Err(responder_error(&name, status));
        }
        stream
            .write_all(&build_query_request(
                QUERY_CONTEXT,
                &name,
                u16::from(query.query_type()),
                u16::from(query.query_class()),
            ))
            .await?;

        let mut answers = Vec::new();
        let query_type = u16::from(query.query_type());
        let mut has_final_answer = false;
        loop {
            let (operation, context, payload) = read_reply(&mut stream).await?;
            if context != QUERY_CONTEXT {
                continue;
            }
            match operation {
                QUERY_REPLY => {
                    let reply = parse_query_reply(&payload)?;
                    if reply.error_code != ERROR_NONE {
                        if !answers.is_empty() {
                            return Ok(response(
                                request,
                                answers,
                                ResponseCode::NoError,
                            ));
                        }
                        return status_response(
                            request,
                            responder_response_code(&name, reply.error_code)?,
                        );
                    }
                    if reply.flags & FLAG_ADD != 0
                        && !reply.rdata.is_empty()
                        && let Ok(record) = build_record(&reply)
                    {
                        has_final_answer |= reply.rr_type == query_type;
                        answers.push(record);
                    }
                    if has_final_answer
                        && reply.rr_type == query_type
                        && reply.flags & FLAG_MORE_COMING == 0
                    {
                        return Ok(response(
                            request,
                            answers,
                            ResponseCode::NoError,
                        ));
                    }
                }
                ASYNC_ERROR_REPLY if payload.len() >= 12 => {
                    let flags =
                        u32::from_be_bytes(payload[0..4].try_into().unwrap());
                    let error_code =
                        i32::from_be_bytes(payload[8..12].try_into().unwrap());
                    if !answers.is_empty() {
                        return Ok(response(
                            request,
                            answers,
                            ResponseCode::NoError,
                        ));
                    }
                    let code = responder_response_code(&name, error_code)?;
                    if flags & FLAG_MORE_COMING == 0 {
                        return status_response(request, code);
                    }
                }
                _ => {}
            }
        }
    }
}

fn append_header(
    operation: u32,
    data_length: usize,
    client_context: u64,
    ipc_flags: u32,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(HEADER_LENGTH);
    buffer.extend_from_slice(&VERSION.to_be_bytes());
    buffer.extend_from_slice(&(data_length as u32).to_be_bytes());
    buffer.extend_from_slice(&ipc_flags.to_be_bytes());
    buffer.extend_from_slice(&operation.to_be_bytes());
    buffer.extend_from_slice(&client_context.to_be_bytes());
    buffer.extend_from_slice(&0_u32.to_be_bytes());
    buffer
}

fn build_query_request(
    query_context: u64,
    name: &str,
    query_type: u16,
    query_class: u16,
) -> Vec<u8> {
    let payload_length = 4 + 4 + name.len() + 1 + 2 + 2;
    let mut message = append_header(
        QUERY_REQUEST,
        payload_length,
        query_context,
        IPC_FLAG_NO_ERROR_SOCKET,
    );
    message.extend_from_slice(
        &(FLAG_SHARE_CONNECTION | FLAG_RETURN_INTERMEDIATES | FLAG_TIMEOUT)
            .to_be_bytes(),
    );
    message.extend_from_slice(&0_u32.to_be_bytes());
    message.extend_from_slice(name.as_bytes());
    message.push(0);
    message.extend_from_slice(&query_type.to_be_bytes());
    message.extend_from_slice(&query_class.to_be_bytes());
    message
}

async fn read_reply(
    stream: &mut UnixStream,
) -> io::Result<(u32, u64, Vec<u8>)> {
    let mut header = [0_u8; HEADER_LENGTH];
    stream.read_exact(&mut header).await?;
    let version = u32::from_be_bytes(header[0..4].try_into().unwrap());
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported mDNSResponder IPC version {version}"),
        ));
    }
    let data_length =
        u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if data_length > MAX_REPLY_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("oversized mDNSResponder reply: {data_length}"),
        ));
    }
    let operation = u32::from_be_bytes(header[12..16].try_into().unwrap());
    let context = u64::from_be_bytes(header[16..24].try_into().unwrap());
    let mut payload = vec![0_u8; data_length];
    stream.read_exact(&mut payload).await?;
    Ok((operation, context, payload))
}

#[derive(Debug, Eq, PartialEq)]
struct QueryReply {
    flags: u32,
    error_code: i32,
    name: String,
    rr_type: u16,
    rr_class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

fn parse_query_reply(payload: &[u8]) -> io::Result<QueryReply> {
    let mut reader = ReplyReader::new(payload);
    let flags = reader.read_u32()?;
    let _interface_index = reader.read_u32()?;
    let error_code = reader.read_i32()?;
    let name = reader.read_c_string()?;
    let rr_type = reader.read_u16()?;
    let rr_class = reader.read_u16()?;
    let rdata_length = usize::from(reader.read_u16()?);
    let rdata = reader.read_bytes(rdata_length)?.to_vec();
    let ttl = reader.read_u32()?;
    Ok(QueryReply {
        flags,
        error_code,
        name,
        rr_type,
        rr_class,
        ttl,
        rdata,
    })
}

fn build_record(reply: &QueryReply) -> io::Result<Record> {
    let name = hickory_proto::rr::Name::from_ascii(&reply.name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut wire =
        Vec::with_capacity(reply.name.len() + 16 + reply.rdata.len());
    {
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
        name.emit(&mut BinEncoder::new(&mut wire))
            .map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, error)
            })?;
    }
    wire.extend_from_slice(&reply.rr_type.to_be_bytes());
    wire.extend_from_slice(&reply.rr_class.to_be_bytes());
    wire.extend_from_slice(&reply.ttl.to_be_bytes());
    let rdata_length = u16::try_from(reply.rdata.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "DNS RDATA is too large")
    })?;
    wire.extend_from_slice(&rdata_length.to_be_bytes());
    wire.extend_from_slice(&reply.rdata);
    Record::read(&mut BinDecoder::new(&wire))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn response(
    request: &Message,
    answers: Vec<Record>,
    code: ResponseCode,
) -> Message {
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    response.queries = request.queries.clone();
    response.answers = answers;
    response
}

fn status_response(
    request: &Message,
    code: ResponseCode,
) -> io::Result<Message> {
    Ok(response(request, Vec::new(), code))
}

fn responder_response_code(
    name: &str,
    error_code: i32,
) -> io::Result<ResponseCode> {
    match error_code {
        ERROR_NO_SUCH_RECORD => Ok(ResponseCode::NoError),
        ERROR_NO_SUCH_NAME => Ok(ResponseCode::NXDomain),
        ERROR_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("mDNSResponder query timed out for {name}"),
        )),
        _ => Err(responder_error(name, error_code)),
    }
}

fn responder_error(name: &str, error_code: i32) -> io::Error {
    io::Error::other(format!(
        "mDNSResponder query failed for {name}: error {error_code}"
    ))
}

struct ReplyReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ReplyReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_i32(&mut self) -> io::Result<i32> {
        Ok(i32::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        Ok(bytes.try_into().unwrap())
    }

    fn read_bytes(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(truncated)?;
        let bytes = self.data.get(self.offset..end).ok_or_else(truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_c_string(&mut self) -> io::Result<String> {
        let remaining = self.data.get(self.offset..).ok_or_else(truncated)?;
        let length = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(truncated)?;
        let value = std::str::from_utf8(&remaining[..length])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .to_owned();
        self.offset += length + 1;
        Ok(value)
    }
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "truncated mDNSResponder reply",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RData, RecordType};
    use system_configuration::core_foundation::base::TCFType;

    #[test]
    fn scoped_dns_dictionary_preserves_servers_search_and_timeout() {
        let addresses = CFArray::from_CFTypes(&[
            CFString::new("192.0.2.53"),
            CFString::new("2001:db8::53"),
        ]);
        let search = CFArray::from_CFTypes(&[
            CFString::new("corp.example"),
            CFString::new("vpn.example"),
        ]);
        let dictionary = CFDictionary::from_CFType_pairs(&[
            (
                CFString::new("ServerAddresses").as_CFType(),
                addresses.as_CFType(),
            ),
            (
                CFString::new("SearchDomains").as_CFType(),
                search.as_CFType(),
            ),
            (
                CFString::new("ServerTimeout").as_CFType(),
                CFNumber::from(7).as_CFType(),
            ),
            (
                CFString::new("ServerPort").as_CFType(),
                CFNumber::from(5353).as_CFType(),
            ),
        ])
        .to_untyped();
        let (config, options) =
            parse_dns_dictionary(&dictionary).unwrap().unwrap();
        assert_eq!(
            config
                .name_servers()
                .iter()
                .map(|server| server.ip)
                .collect::<Vec<_>>(),
            [
                "192.0.2.53".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(
            config
                .search()
                .iter()
                .map(|name| name.to_utf8())
                .collect::<Vec<_>>(),
            ["corp.example", "vpn.example"]
        );
        assert_eq!(options.ndots, 1);
        assert_eq!(options.attempts, 2);
        assert_eq!(options.timeout, Duration::from_secs(7));
        assert!(config.name_servers().iter().all(|server| {
            server
                .connections
                .iter()
                .all(|connection| connection.port == 5353)
        }));
    }

    #[test]
    fn query_request_matches_apple_ipc_wire() {
        let request =
            build_query_request(0x0102_0304_0506_0708, "example.com.", 1, 1);
        assert_eq!(u32::from_be_bytes(request[0..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_be_bytes(request[12..16].try_into().unwrap()),
            QUERY_REQUEST
        );
        assert_eq!(
            u64::from_be_bytes(request[16..24].try_into().unwrap()),
            0x0102_0304_0506_0708
        );
        assert_eq!(
            u32::from_be_bytes(request[28..32].try_into().unwrap()),
            FLAG_SHARE_CONNECTION | FLAG_RETURN_INTERMEDIATES | FLAG_TIMEOUT
        );
        assert_eq!(&request[36..49], b"example.com.\0");
        assert_eq!(&request[49..], &[0, 1, 0, 1]);
    }

    #[test]
    fn reply_parser_and_record_decoder_preserve_rdata() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&FLAG_ADD.to_be_bytes());
        payload.extend_from_slice(&7_u32.to_be_bytes());
        payload.extend_from_slice(&ERROR_NONE.to_be_bytes());
        payload.extend_from_slice(b"example.com.\0");
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&4_u16.to_be_bytes());
        payload.extend_from_slice(&[192, 0, 2, 7]);
        payload.extend_from_slice(&90_u32.to_be_bytes());
        let reply = parse_query_reply(&payload).unwrap();
        assert_eq!(reply.name, "example.com.");
        assert_eq!(reply.ttl, 90);
        let record = build_record(&reply).unwrap();
        assert_eq!(record.record_type(), RecordType::A);
        assert!(
            matches!(&record.data, RData::A(address) if address.0.octets() == [192, 0, 2, 7])
        );
    }

    #[tokio::test]
    async fn exchange_handles_nodata_and_nxdomain() {
        for (error_code, expected) in [
            (ERROR_NO_SUCH_RECORD, ResponseCode::NoError),
            (ERROR_NO_SUCH_NAME, ResponseCode::NXDomain),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let socket_path = directory.path().join("mdns-responder.sock");
            let listener =
                tokio::net::UnixListener::bind(&socket_path).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut connection = [0_u8; HEADER_LENGTH];
                stream.read_exact(&mut connection).await.unwrap();
                stream.write_all(&ERROR_NONE.to_be_bytes()).await.unwrap();
                let mut query_header = [0_u8; HEADER_LENGTH];
                stream.read_exact(&mut query_header).await.unwrap();
                let query_length =
                    u32::from_be_bytes(query_header[4..8].try_into().unwrap())
                        as usize;
                let mut query = vec![0_u8; query_length];
                stream.read_exact(&mut query).await.unwrap();
                let mut payload = Vec::new();
                payload.extend_from_slice(&0_u32.to_be_bytes());
                payload.extend_from_slice(&0_u32.to_be_bytes());
                payload.extend_from_slice(&error_code.to_be_bytes());
                payload.extend_from_slice(b"missing.example.\0");
                payload.extend_from_slice(&1_u16.to_be_bytes());
                payload.extend_from_slice(&1_u16.to_be_bytes());
                payload.extend_from_slice(&0_u16.to_be_bytes());
                payload.extend_from_slice(&0_u32.to_be_bytes());
                stream
                    .write_all(&append_header(
                        QUERY_REPLY,
                        payload.len(),
                        QUERY_CONTEXT,
                        0,
                    ))
                    .await
                    .unwrap();
                stream.write_all(&payload).await.unwrap();
            });
            let mut request = Message::new(
                91,
                MessageType::Query,
                hickory_proto::op::OpCode::Query,
            );
            request.add_query(hickory_proto::op::Query::query(
                "missing.example.".parse().unwrap(),
                RecordType::A,
            ));
            let response = DarwinSystemResolver::with_socket_path(&socket_path)
                .exchange(&request)
                .await
                .unwrap();
            assert_eq!(response.metadata.id, 91);
            assert_eq!(response.metadata.response_code, expected);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires the host macOS mDNSResponder daemon"]
    async fn live_macos_responder_answers_localhost() {
        let mut request = Message::new(
            92,
            MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        request.add_query(hickory_proto::op::Query::query(
            "localhost.".parse().unwrap(),
            RecordType::A,
        ));
        let response = DarwinSystemResolver::new()
            .exchange(&request)
            .await
            .unwrap();
        assert_eq!(response.metadata.id, 92);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.iter().any(|record| {
            matches!(&record.data, RData::A(address) if address.0.is_loopback())
        }));
    }
}
