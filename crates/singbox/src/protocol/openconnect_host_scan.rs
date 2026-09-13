//! Cisco Secure Desktop / AnyConnect host-scan compatibility.
//!
//! The built-in path mirrors OpenConnect's `csd-post.sh`: it fetches a scan
//! token and optional requested fields, submits a locally produced endpoint
//! report, then polls the gateway. It never downloads or executes the Cisco
//! stub.

use std::{
    collections::BTreeSet,
    env, fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc32fast::Hasher;
use http::{Method, StatusCode};
use md5::{Digest as _, Md5};
use network_interface::{NetworkInterface, NetworkInterfaceConfig as _};
use openssl::x509::X509;
use quick_xml::{Reader, events::Event};
use regex::Regex;
use sysinfo::System;
use thiserror::Error;
use url::Url;

use super::{
    AnyConnectAuthHttpClient, AnyConnectAuthHttpError,
    AnyConnectAuthHttpRequest, AnyConnectHostScan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyConnectHostScanOptions {
    pub disabled: bool,
    pub local_hostname: String,
    pub poll_interval: Duration,
    /// Optional OpenConnect-compatible CSD wrapper executable.
    pub wrapper_path: PathBuf,
    /// Authentication state used only by the external wrapper contract.
    pub wrapper_selected_group: String,
    pub wrapper_authenticated_address: Option<IpAddr>,
    pub wrapper_server_certificate_der: Option<Vec<u8>>,
    pub wrapper_client_certificate_der: Option<Vec<u8>>,
}

impl Default for AnyConnectHostScanOptions {
    fn default() -> Self {
        Self {
            disabled: false,
            local_hostname: String::new(),
            poll_interval: Duration::from_secs(1),
            wrapper_path: PathBuf::new(),
            wrapper_selected_group: String::new(),
            wrapper_authenticated_address: None,
            wrapper_server_certificate_der: None,
            wrapper_client_certificate_der: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectHostScanInventory {
    pub os_version: String,
    pub os_architecture: String,
    pub os_service_pack: String,
    pub hostname: String,
    pub mac_addresses: Vec<String>,
    pub tcp4_listening_ports: BTreeSet<u16>,
    pub tcp6_listening_ports: BTreeSet<u16>,
    pub process_names: BTreeSet<String>,
}

impl AnyConnectHostScanInventory {
    pub fn collect(local_hostname: &str) -> io::Result<Self> {
        let mut mac_addresses = NetworkInterface::show()
            .map_err(io::Error::other)?
            .into_iter()
            .filter_map(|interface| interface.mac_addr)
            .filter_map(|address| format_anyconnect_host_scan_mac(&address))
            .collect::<Vec<_>>();
        mac_addresses.sort();
        mac_addresses.dedup();

        let system = System::new_all();
        let process_names = system
            .processes()
            .values()
            .flat_map(|process| {
                let mut names = Vec::new();
                if let Some(name) = process.name().to_str() {
                    names.push(name.to_owned());
                }
                if let Some(path) = process.exe()
                    && let Some(name) =
                        path.file_name().and_then(|name| name.to_str())
                {
                    names.push(name.to_owned());
                }
                names
            })
            .collect();
        Ok(Self {
            os_version: System::name()
                .unwrap_or_else(|| env::consts::OS.into()),
            os_architecture: env::consts::ARCH.into(),
            os_service_pack: System::kernel_version().unwrap_or_default(),
            hostname: if local_hostname.is_empty() {
                System::host_name().unwrap_or_default()
            } else {
                local_hostname.into()
            },
            mac_addresses,
            tcp4_listening_ports: read_anyconnect_host_scan_listening_ports(
                Path::new("/proc/net/tcp"),
            ),
            tcp6_listening_ports: read_anyconnect_host_scan_listening_ports(
                Path::new("/proc/net/tcp6"),
            ),
            process_names,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyConnectHostScanRequestedField {
    pub kind: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectHostScanResult {
    pub authenticated_address: Option<std::net::IpAddr>,
}

#[derive(Debug, Error)]
pub enum AnyConnectHostScanError {
    #[error(transparent)]
    Http(#[from] AnyConnectAuthHttpError),
    #[error("invalid AnyConnect CSD URL: {0}")]
    InvalidUrl(String),
    #[error("CSD token request returned HTTP {0}")]
    TokenStatus(StatusCode),
    #[error("CSD token response is invalid: {0}")]
    InvalidToken(String),
    #[error("CSD scan submission returned HTTP {0}")]
    ScanStatus(StatusCode),
    #[error("CSD wait request returned HTTP {0}")]
    WaitStatus(StatusCode),
    #[error("CSD wait endpoint returned neither XML nor an HTML refresh page")]
    InvalidWaitResponse,
    #[error("inspect local endpoint for CSD: {0}")]
    Inventory(#[source] io::Error),
    #[error(
        "external CSD wrapper requires the authenticated TLS peer certificate"
    )]
    MissingWrapperCertificate,
    #[error("invalid external CSD wrapper certificate: {0}")]
    InvalidWrapperCertificate(String),
    #[error("start external CSD wrapper: {0}")]
    StartWrapper(#[source] io::Error),
    #[error("external CSD wrapper terminated abnormally: {0}")]
    WrapperTerminated(String),
}

/// Execute the built-in AnyConnect host scan with an isolated RFC 6265 jar.
pub async fn run_anyconnect_host_scan(
    http: &mut AnyConnectAuthHttpClient,
    authentication_url: &Url,
    state: &AnyConnectHostScan,
    options: &AnyConnectHostScanOptions,
) -> Result<AnyConnectHostScanResult, AnyConnectHostScanError> {
    resolve_anyconnect_host_scan_url(authentication_url, &state.base_url)?;
    let wait_url =
        resolve_anyconnect_host_scan_url(authentication_url, &state.wait_url)?;
    if !state.stub_url.is_empty() {
        resolve_anyconnect_host_scan_url(authentication_url, &state.stub_url)?;
    }

    let mut latest_address = options.wrapper_authenticated_address;
    if !options.wrapper_path.as_os_str().is_empty() {
        run_external_anyconnect_host_scan_wrapper(
            authentication_url,
            &resolve_anyconnect_host_scan_url(
                authentication_url,
                &state.base_url,
            )?,
            state,
            options,
        )
        .await?;
    } else {
        let token_url = host_scan_endpoint(
            authentication_url,
            "/+CSCOE+/sdesktop/token.xml",
            &[("ticket", state.ticket.as_str()), ("stub", "0")],
        );
        let token_response =
            host_scan_request(http, Method::GET, token_url, None, vec![])
                .await?;
        latest_address =
            token_response.authenticated_address.or(latest_address);
        if token_response.status != StatusCode::OK {
            return Err(AnyConnectHostScanError::TokenStatus(
                token_response.status,
            ));
        }
        let scan_token = parse_host_scan_token(&token_response.body)?;

        let data_url = host_scan_endpoint(
            authentication_url,
            "/CACHE/sdesktop/data.xml",
            &[],
        );
        let requested_fields =
            match host_scan_request(http, Method::GET, data_url, None, vec![])
                .await
            {
                Ok(response) if response.status == StatusCode::OK => {
                    latest_address =
                        response.authenticated_address.or(latest_address);
                    parse_host_scan_data(&response.body).unwrap_or_default()
                }
                _ => Vec::new(),
            };
        let inventory =
            AnyConnectHostScanInventory::collect(&options.local_hostname)
                .map_err(AnyConnectHostScanError::Inventory)?;
        let report =
            build_anyconnect_host_scan_report(&requested_fields, &inventory);
        let scan_url = host_scan_endpoint(
            authentication_url,
            "/+CSCOE+/sdesktop/scan.xml",
            &[("reusebrowser", "1")],
        );
        http.set_cookie(&scan_url, "sdesktop", &scan_token)?;
        let scan_response = host_scan_request(
            http,
            Method::POST,
            scan_url,
            Some("text/xml"),
            report,
        )
        .await?;
        latest_address = scan_response.authenticated_address.or(latest_address);
        if !scan_response.status.is_success()
            && !scan_response.status.is_redirection()
        {
            return Err(AnyConnectHostScanError::ScanStatus(
                scan_response.status,
            ));
        }
    }

    http.set_cookie(&wait_url, "sdesktop", &state.token)?;
    loop {
        let response = host_scan_request(
            http,
            Method::GET,
            wait_url.clone(),
            None,
            vec![],
        )
        .await?;
        latest_address = response.authenticated_address.or(latest_address);
        if response.status != StatusCode::OK {
            return Err(AnyConnectHostScanError::WaitStatus(response.status));
        }
        match classify_host_scan_wait_response(&response.body)? {
            AnyConnectHostScanWait::Complete => break,
            AnyConnectHostScanWait::Refresh => {
                tokio::time::sleep(options.poll_interval).await
            }
        }
    }
    Ok(AnyConnectHostScanResult {
        authenticated_address: latest_address,
    })
}

/// Run the external wrapper using OpenConnect's `run_csd_script` argv and
/// environment contract. A normally exited non-zero status is deliberately
/// ignored, as upstream continues authentication in that case.
pub async fn run_external_anyconnect_host_scan_wrapper(
    authentication_url: &Url,
    base_url: &Url,
    state: &AnyConnectHostScan,
    options: &AnyConnectHostScanOptions,
) -> Result<(), AnyConnectHostScanError> {
    let server_der = options
        .wrapper_server_certificate_der
        .as_deref()
        .ok_or(AnyConnectHostScanError::MissingWrapperCertificate)?;
    let certificate = X509::from_der(server_der).map_err(|error| {
        AnyConnectHostScanError::InvalidWrapperCertificate(error.to_string())
    })?;
    let spki = certificate
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|error| {
            AnyConnectHostScanError::InvalidWrapperCertificate(
                error.to_string(),
            )
        })?;
    let server_md5 = hex::encode_upper(Md5::digest(server_der));
    let client_md5 = options
        .wrapper_client_certificate_der
        .as_deref()
        .map(|certificate| hex::encode_upper(Md5::digest(certificate)))
        .unwrap_or_default();

    let mut wrapper_url = base_url.clone();
    if let Some(address) = options.wrapper_authenticated_address {
        wrapper_url
            .set_host(Some(&address.to_string()))
            .map_err(|_| {
                AnyConnectHostScanError::InvalidUrl(wrapper_url.to_string())
            })?;
    }
    let wrapper_authority =
        url_authority(if options.wrapper_authenticated_address.is_some() {
            &wrapper_url
        } else {
            authentication_url
        })?;
    let quote = |value: &str| format!("{value:?}");
    let mut command = tokio::process::Command::new(&options.wrapper_path);
    command
        .arg("")
        .args(["-ticket", &quote(&state.ticket)])
        .args(["-stub", &quote("0")])
        .args(["-group", &quote(&options.wrapper_selected_group)])
        .args(["-certhash", &quote(&format!("{server_md5}:{client_md5}"))])
        .args(["-url", &quote(wrapper_url.as_str())])
        .arg("-langselen")
        .env_remove("CSD_SHA256")
        .env_remove("CSD_TOKEN")
        .env_remove("CSD_HOSTNAME")
        .env("CSD_SHA256", STANDARD.encode(sha2::Sha256::digest(spki)))
        .env("CSD_TOKEN", &state.token)
        .env("CSD_HOSTNAME", wrapper_authority)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = command
        .status()
        .await
        .map_err(AnyConnectHostScanError::StartWrapper)?;
    if status.code().is_some() {
        // OpenConnect intentionally ignores both zero and non-zero normal
        // exits, allowing the gateway wait endpoint to decide compliance.
        Ok(())
    } else {
        Err(AnyConnectHostScanError::WrapperTerminated(
            status.to_string(),
        ))
    }
}

fn url_authority(url: &Url) -> Result<String, AnyConnectHostScanError> {
    let host = url
        .host_str()
        .ok_or_else(|| AnyConnectHostScanError::InvalidUrl(url.to_string()))?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(url
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

async fn host_scan_request(
    http: &mut AnyConnectAuthHttpClient,
    method: Method,
    url: Url,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> Result<super::AnyConnectAuthHttpResponse, AnyConnectHostScanError> {
    Ok(http
        .execute(AnyConnectAuthHttpRequest {
            method,
            url,
            content_type: content_type.map(str::to_owned),
            body,
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: true,
            follow_redirects: true,
        })
        .await?)
}

pub fn resolve_anyconnect_host_scan_url(
    base: &Url,
    reference: &str,
) -> Result<Url, AnyConnectHostScanError> {
    let result = base.join(reference).map_err(|error| {
        AnyConnectHostScanError::InvalidUrl(error.to_string())
    })?;
    if result.scheme() != "https" || result.host_str().is_none() {
        return Err(AnyConnectHostScanError::InvalidUrl(result.to_string()));
    }
    Ok(result)
}

fn host_scan_endpoint(base: &Url, path: &str, query: &[(&str, &str)]) -> Url {
    let mut result = base.clone();
    result
        .set_username("")
        .expect("clearing URL username cannot fail");
    result
        .set_password(None)
        .expect("clearing URL password cannot fail");
    result.set_path(path);
    result.set_query(None);
    result.set_fragment(None);
    if !query.is_empty() {
        result.query_pairs_mut().extend_pairs(query.iter().copied());
    }
    result
}

pub fn parse_anyconnect_host_scan_requested_field(
    value: &str,
) -> Result<AnyConnectHostScanRequestedField, AnyConnectHostScanError> {
    let bytes = value.as_bytes();
    let mut position = 0;
    let mut parts = Vec::with_capacity(3);
    for part_index in 0..3 {
        while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        if bytes.get(position) != Some(&b'\'') {
            return Err(AnyConnectHostScanError::InvalidToken(format!(
                "invalid field tuple: {value}"
            )));
        }
        position += 1;
        let mut part = String::new();
        let mut closed = false;
        while let Some(&character) = bytes.get(position) {
            position += 1;
            if character == b'\\' {
                let escaped = bytes.get(position).ok_or_else(|| {
                    AnyConnectHostScanError::InvalidToken(format!(
                        "unterminated field tuple: {value}"
                    ))
                })?;
                part.push(char::from(*escaped));
                position += 1;
            } else if character == b'\'' {
                if bytes.get(position) == Some(&b'\'') {
                    part.push('\'');
                    position += 1;
                } else {
                    closed = true;
                    break;
                }
            } else {
                part.push(char::from(character));
            }
        }
        if !closed {
            return Err(AnyConnectHostScanError::InvalidToken(format!(
                "unterminated field tuple: {value}"
            )));
        }
        parts.push(part);
        while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        if part_index < 2 {
            if bytes.get(position) != Some(&b',') {
                return Err(AnyConnectHostScanError::InvalidToken(format!(
                    "invalid field tuple separator: {value}"
                )));
            }
            position += 1;
        }
    }
    if !value[position..].trim().is_empty() {
        return Err(AnyConnectHostScanError::InvalidToken(format!(
            "trailing field tuple data: {value}"
        )));
    }
    Ok(AnyConnectHostScanRequestedField {
        kind: parts.remove(0),
        name: parts.remove(0),
        value: parts.remove(0),
    })
}

fn parse_host_scan_token(
    content: &[u8],
) -> Result<String, AnyConnectHostScanError> {
    let mut reader = Reader::from_reader(content);
    let mut root = None;
    let mut in_token = false;
    let mut token = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name =
                    String::from_utf8_lossy(start.name().as_ref()).into_owned();
                if root.is_none() {
                    root = Some(name.clone());
                }
                in_token = name == "token";
            }
            Ok(Event::Text(text)) if in_token => {
                token.push_str(&text.decode().map_err(|error| {
                    AnyConnectHostScanError::InvalidToken(error.to_string())
                })?);
            }
            Ok(Event::End(end)) if end.name().as_ref() == b"token" => {
                in_token = false
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(AnyConnectHostScanError::InvalidToken(
                    error.to_string(),
                ));
            }
            _ => {}
        }
    }
    if root.as_deref() != Some("hostscan") {
        return Err(AnyConnectHostScanError::InvalidToken(format!(
            "unexpected XML root: {}",
            root.unwrap_or_default()
        )));
    }
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(AnyConnectHostScanError::InvalidToken(
            "token omitted".into(),
        ));
    }
    Ok(token)
}

fn parse_host_scan_data(
    content: &[u8],
) -> Result<Vec<AnyConnectHostScanRequestedField>, ()> {
    let mut reader = Reader::from_reader(content);
    let mut fields = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Empty(start)) | Ok(Event::Start(start))
                if start.name().as_ref() == b"field" =>
            {
                for attribute in start.attributes().flatten() {
                    if attribute.key.as_ref() == b"value"
                        && let Ok(value) =
                            std::str::from_utf8(attribute.value.as_ref())
                        && let Ok(field) =
                            parse_anyconnect_host_scan_requested_field(value)
                    {
                        fields.push(field);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(()),
            _ => {}
        }
    }
    Ok(fields)
}

pub fn build_anyconnect_host_scan_report(
    requested_fields: &[AnyConnectHostScanRequestedField],
    inventory: &AnyConnectHostScanInventory,
) -> Vec<u8> {
    let mut report = String::new();
    append_report_value(
        &mut report,
        "endpoint.os.version",
        &inventory.os_version,
    );
    append_report_value(
        &mut report,
        "endpoint.os.architecture",
        &inventory.os_architecture,
    );
    if !inventory.os_service_pack.is_empty() {
        append_report_value(
            &mut report,
            "endpoint.os.servicepack",
            &inventory.os_service_pack,
        );
    }
    append_report_value(
        &mut report,
        "endpoint.device.hostname",
        &inventory.hostname,
    );
    let mut mac_addresses = inventory.mac_addresses.clone();
    mac_addresses.sort();
    for address in mac_addresses {
        append_report_value(
            &mut report,
            &format!("endpoint.device.MAC[{}]", go_quote_ascii(&address)),
            "true",
        );
    }
    let ports = inventory
        .tcp4_listening_ports
        .union(&inventory.tcp6_listening_ports)
        .copied()
        .collect::<BTreeSet<_>>();
    for port in ports {
        let quoted = go_quote_ascii(&port.to_string());
        append_report_value(
            &mut report,
            &format!("endpoint.device.port[{quoted}]"),
            "true",
        );
        if inventory.tcp4_listening_ports.contains(&port) {
            append_report_value(
                &mut report,
                &format!("endpoint.device.tcp4port[{quoted}]"),
                "true",
            );
        }
        if inventory.tcp6_listening_ports.contains(&port) {
            append_report_value(
                &mut report,
                &format!("endpoint.device.tcp6port[{quoted}]"),
                "true",
            );
        }
    }
    for field in requested_fields {
        match field.kind.as_str() {
            "File" => append_file_report(&mut report, field),
            "Process" => {
                let prefix = format!(
                    "endpoint.process[{}]",
                    go_quote_ascii(&field.name)
                );
                report.push_str(&prefix);
                report.push_str("={};\n");
                append_report_value(
                    &mut report,
                    &format!("{prefix}.name"),
                    &field.value,
                );
                let target = Path::new(&field.value)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(&field.value);
                append_report_value(
                    &mut report,
                    &format!("{prefix}.exists"),
                    if inventory.process_names.contains(target) {
                        "true"
                    } else {
                        "false"
                    },
                );
            }
            _ => {}
        }
    }
    report.into_bytes()
}

fn append_file_report(
    report: &mut String,
    field: &AnyConnectHostScanRequestedField,
) {
    let path = Path::new(&field.value);
    let prefix = format!("endpoint.file[{}]", go_quote_ascii(&field.name));
    report.push_str(&prefix);
    report.push_str("={};\n");
    append_report_value(report, &format!("{prefix}.path"), &field.value);
    append_report_value(
        report,
        &format!("{prefix}.name"),
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(""),
    );
    let Ok(metadata) = fs::metadata(path) else {
        append_report_value(report, &format!("{prefix}.exists"), "false");
        return;
    };
    append_report_value(report, &format!("{prefix}.exists"), "true");
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |value| value.as_secs());
    append_report_value(
        report,
        &format!("{prefix}.timestamp"),
        &modified.to_string(),
    );
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH + Duration::from_secs(modified))
        .map_or(0, |value| value.as_secs());
    append_report_value(
        report,
        &format!("{prefix}.lastmodified"),
        &age.to_string(),
    );
    if metadata.is_file()
        && let Ok(content) = fs::read(path)
    {
        let mut checksum = Hasher::new();
        checksum.update(&content);
        append_report_value(
            report,
            &format!("{prefix}.crc32"),
            &format!("0x{:08x}", checksum.finalize()),
        );
    }
}

fn append_report_value(report: &mut String, name: &str, value: &str) {
    report.push_str(name);
    report.push('=');
    report.push_str(&go_quote_ascii(value));
    report.push_str(";\n");
}

fn go_quote_ascii(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\u{08}' => result.push_str("\\b"),
            '\u{0c}' => result.push_str("\\f"),
            character if character.is_ascii_graphic() || character == ' ' => {
                result.push(character)
            }
            character if (character as u32) <= 0xffff => {
                result.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => {
                let value = character as u32 - 0x1_0000;
                result.push_str(&format!(
                    "\\u{:04x}\\u{:04x}",
                    0xd800 + (value >> 10),
                    0xdc00 + (value & 0x3ff)
                ));
            }
        }
    }
    result.push('"');
    result
}

pub fn format_anyconnect_host_scan_mac(value: &str) -> Option<String> {
    let hexadecimal = value
        .bytes()
        .filter(|value| value.is_ascii_hexdigit())
        .map(char::from)
        .collect::<String>()
        .to_ascii_uppercase();
    if hexadecimal.len() != 12 || hexadecimal == "000000000000" {
        return None;
    }
    Some(format!(
        "{}.{}.{}",
        &hexadecimal[..4],
        &hexadecimal[4..8],
        &hexadecimal[8..]
    ))
}

pub fn read_anyconnect_host_scan_listening_ports(path: &Path) -> BTreeSet<u16> {
    fs::read_to_string(path)
        .ok()
        .into_iter()
        .flat_map(|content| {
            content.lines().map(str::to_owned).collect::<Vec<_>>()
        })
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 || fields[3] != "0A" {
                return None;
            }
            let port = fields[1].rsplit_once(':')?.1;
            u16::from_str_radix(port, 16).ok().filter(|port| *port > 0)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyConnectHostScanWait {
    Complete,
    Refresh,
}

pub fn classify_host_scan_wait_response(
    content: &[u8],
) -> Result<AnyConnectHostScanWait, AnyConnectHostScanError> {
    let trimmed = String::from_utf8_lossy(content);
    let trimmed = trimmed.trim();
    if trimmed.starts_with("<?xml") {
        return Ok(AnyConnectHostScanWait::Complete);
    }
    let refresh = Regex::new(r#"(?i)http-equiv\s*=\s*["']\s*refresh\s*["']"#)
        .expect("fixed CSD refresh regex");
    if refresh.is_match(trimmed) {
        Ok(AnyConnectHostScanWait::Refresh)
    } else {
        Err(AnyConnectHostScanError::InvalidWaitResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requested_tuple_escaping() {
        assert_eq!(
            parse_anyconnect_host_scan_requested_field(
                " 'File', 'agent''s config', '/tmp/a\\ b' "
            )
            .unwrap(),
            AnyConnectHostScanRequestedField {
                kind: "File".into(),
                name: "agent's config".into(),
                value: "/tmp/a b".into(),
            }
        );
        assert!(
            parse_anyconnect_host_scan_requested_field("'File','x'").is_err()
        );
    }

    #[test]
    fn report_matches_csd_assignment_shape_and_order() {
        let inventory = AnyConnectHostScanInventory {
            os_version: "Linux".into(),
            os_architecture: "x86_64".into(),
            os_service_pack: "6.8".into(),
            hostname: "vpn-测试".into(),
            mac_addresses: vec!["AABB.CCDD.EEFF".into()],
            tcp4_listening_ports: BTreeSet::from([22, 443]),
            tcp6_listening_ports: BTreeSet::from([443]),
            process_names: BTreeSet::from(["agent".into()]),
        };
        let report = String::from_utf8(build_anyconnect_host_scan_report(
            &[AnyConnectHostScanRequestedField {
                kind: "Process".into(),
                name: "vpn".into(),
                value: "/usr/bin/agent".into(),
            }],
            &inventory,
        ))
        .unwrap();
        assert!(
            report.contains("endpoint.device.hostname=\"vpn-\\u6d4b\\u8bd5\";")
        );
        assert!(report.contains("endpoint.device.tcp4port[\"443\"]=\"true\";"));
        assert!(report.contains("endpoint.device.tcp6port[\"443\"]=\"true\";"));
        assert!(report.contains("endpoint.process[\"vpn\"].exists=\"true\";"));
    }

    #[test]
    fn parses_listening_ports_and_formats_mac() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tcp");
        fs::write(
            &path,
            "  sl  local_address rem_address st\n0: 0100007F:01BB 00000000:0000 0A\n1: 0100007F:0050 00000000:0000 01\n",
        )
        .unwrap();
        assert_eq!(
            read_anyconnect_host_scan_listening_ports(&path),
            [443].into()
        );
        assert_eq!(
            format_anyconnect_host_scan_mac("aa:bb:cc:dd:ee:ff").as_deref(),
            Some("AABB.CCDD.EEFF")
        );
        assert_eq!(format_anyconnect_host_scan_mac("00:00:00:00:00:00"), None);
    }

    #[test]
    fn classifies_wait_responses() {
        assert_eq!(
            classify_host_scan_wait_response(
                b" \n<?xml version='1.0'?><done/>"
            )
            .unwrap(),
            AnyConnectHostScanWait::Complete
        );
        assert_eq!(
            classify_host_scan_wait_response(
                br#"<meta content="1" HTTP-EQUIV = ' refresh '>"#
            )
            .unwrap(),
            AnyConnectHostScanWait::Refresh
        );
        assert!(classify_host_scan_wait_response(b"ready").is_err());
    }

    #[test]
    fn url_resolution_requires_https() {
        let base = Url::parse("https://vpn.example/auth").unwrap();
        assert_eq!(
            resolve_anyconnect_host_scan_url(&base, "/wait")
                .unwrap()
                .as_str(),
            "https://vpn.example/wait"
        );
        assert!(
            resolve_anyconnect_host_scan_url(&base, "http://evil/").is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn external_wrapper_matches_openconnect_argv_and_environment() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("wrapper-output");
        let wrapper = directory.path().join("csd-wrapper.sh");
        let output_path = output.to_string_lossy().replace('\'', "'\\''");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\n{{\nprintf 'sha=%s\\n' \"$CSD_SHA256\"\nprintf 'token=%s\\n' \"$CSD_TOKEN\"\nprintf 'host=%s\\n' \"$CSD_HOSTNAME\"\nfor value in \"$@\"; do printf 'arg=<%s>\\n' \"$value\"; done\n}} > '{output_path}'\nexit 7\n"
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&wrapper, permissions).unwrap();

        let certificate =
            rcgen::generate_simple_self_signed(["vpn.example".into()]).unwrap();
        let server_der = certificate.cert.der().to_vec();
        let server_x509 = X509::from_der(&server_der).unwrap();
        let spki = server_x509
            .public_key()
            .unwrap()
            .public_key_to_der()
            .unwrap();
        let client_der = vec![1, 2, 3, 4];
        let options = AnyConnectHostScanOptions {
            wrapper_path: wrapper,
            wrapper_selected_group: "staff".into(),
            wrapper_authenticated_address: Some("127.0.0.2".parse().unwrap()),
            wrapper_server_certificate_der: Some(server_der.clone()),
            wrapper_client_certificate_der: Some(client_der.clone()),
            ..Default::default()
        };
        run_external_anyconnect_host_scan_wrapper(
            &Url::parse("https://vpn.example:8443/auth").unwrap(),
            &Url::parse("https://vpn.example:8443/+CSCOE+/sdesktop/").unwrap(),
            &AnyConnectHostScan {
                ticket: "ticket-1".into(),
                token: "token-1".into(),
                ..Default::default()
            },
            &options,
        )
        .await
        .unwrap();

        let output = fs::read_to_string(output).unwrap();
        assert!(output.contains(&format!(
            "sha={}\n",
            STANDARD.encode(sha2::Sha256::digest(spki))
        )));
        assert!(output.contains("token=token-1\nhost=127.0.0.2:8443\n"));
        assert!(output.contains(&format!(
            "arg=<-certhash>\narg=<\"{}:{}\">\n",
            hex::encode_upper(Md5::digest(server_der)),
            hex::encode_upper(Md5::digest(client_der))
        )));
        assert!(output.contains(
            "arg=<>\narg=<-ticket>\narg=<\"ticket-1\">\narg=<-stub>\narg=<\"0\">\narg=<-group>\narg=<\"staff\">\n"
        ));
        assert!(output.contains(
            "arg=<-url>\narg=<\"https://127.0.0.2:8443/+CSCOE+/sdesktop/\">\narg=<-langselen>\n"
        ));
    }
}
