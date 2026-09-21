//! GlobalProtect Host Information Profile (HIP) check and report protocol.
//!
//! The built-in report mirrors OpenConnect's conservative inventory: host
//! identity and network-interface MAC addresses are reported, while security
//! product categories are present but empty. An optional external wrapper uses
//! the same bounded stdout and environment contract as OpenConnect.

use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    process::Stdio,
    time::Duration,
};

use http::{Method, StatusCode};
use md5::{Digest as _, Md5};
use network_interface::{NetworkInterface, NetworkInterfaceConfig as _};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tokio::io::AsyncReadExt as _;
use url::Url;

use super::{
    AnyConnectAuthHttpClient, AnyConnectAuthHttpError,
    AnyConnectAuthHttpRequest, GlobalProtectFailureClass,
    encode_globalprotect_form_component,
    gp_config::{XmlNode, parse_xml},
};

pub const GLOBALPROTECT_HIP_CHECK_PATH: &str = "/ssl-vpn/hipreportcheck.esp";
pub const GLOBALPROTECT_HIP_REPORT_PATH: &str = "/ssl-vpn/hipreport.esp";
pub const GLOBALPROTECT_HIP_DEFAULT_INTERVAL: Duration =
    Duration::from_secs(60 * 60);
pub const GLOBALPROTECT_HIP_MAXIMUM_RESPONSE_BODY: usize = 8 * 1024 * 1024;
pub const GLOBALPROTECT_HIP_MAXIMUM_REPORT_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalProtectHipCookieIdentity {
    pub user: String,
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectHipToken {
    pub md5: String,
    pub identity: GlobalProtectHipCookieIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectHipInterface {
    pub name: String,
    pub mac_address: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalProtectHipInventory {
    pub hostname: String,
    pub interfaces: Vec<GlobalProtectHipInterface>,
}

impl GlobalProtectHipInventory {
    pub fn collect(local_hostname: &str) -> io::Result<Self> {
        let mut interfaces = NetworkInterface::show()
            .map_err(io::Error::other)?
            .into_iter()
            .filter_map(|interface| {
                let mac_address = interface.mac_addr?;
                let mac_address = format_globalprotect_hip_mac(&mac_address)?;
                Some(GlobalProtectHipInterface {
                    name: interface.name,
                    mac_address,
                })
            })
            .collect::<Vec<_>>();
        interfaces.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.mac_address.cmp(&right.mac_address))
        });
        interfaces.dedup();
        Ok(Self {
            hostname: if local_hostname.is_empty() {
                sysinfo::System::host_name().unwrap_or_default()
            } else {
                local_hostname.into()
            },
            interfaces,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectHipRunnerOptions {
    pub server_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub opaque_query: String,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub assigned_ipv6: Option<Ipv6Addr>,
    pub app_version: String,
    pub reported_os: String,
    pub local_hostname: String,
    pub interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectHipCheckResult {
    pub report_needed: bool,
    pub report_submitted: bool,
    pub next_check: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalProtectHipResponse {
    pub report_needed: Option<bool>,
}

#[derive(Debug, Error)]
pub enum GlobalProtectHipError {
    #[error(transparent)]
    Http(#[from] AnyConnectAuthHttpError),
    #[error("invalid GlobalProtect HIP configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid GlobalProtect HIP XML: {0}")]
    InvalidXml(String),
    #[error("GlobalProtect HIP {operation} response exceeds {maximum} bytes")]
    BodyTooLarge {
        operation: &'static str,
        maximum: usize,
    },
    #[error("GlobalProtect HIP {operation} returned HTTP {status} ({class:?})")]
    HttpStatus {
        operation: &'static str,
        status: StatusCode,
        class: GlobalProtectFailureClass,
    },
    #[error(
        "GlobalProtect HIP {operation} response error ({class:?}): {message}"
    )]
    Response {
        operation: &'static str,
        message: String,
        class: GlobalProtectFailureClass,
    },
    #[error(
        "GlobalProtect HIP {0} response omitted a valid hip-report-needed value"
    )]
    MissingReportDecision(&'static str),
    #[error("collect GlobalProtect HIP inventory: {0}")]
    Inventory(#[source] io::Error),
    #[error("GlobalProtect HIP report exceeds {0} bytes")]
    ReportTooLarge(usize),
    #[error("start GlobalProtect HIP wrapper: {0}")]
    WrapperStart(#[source] io::Error),
    #[error("wait for GlobalProtect HIP wrapper: {0}")]
    WrapperWait(#[source] io::Error),
    #[error("GlobalProtect HIP wrapper returned non-zero status: {0}")]
    WrapperStatus(i32),
    #[error("GlobalProtect HIP wrapper returned an empty report")]
    WrapperEmpty,
}

pub struct GlobalProtectHipRunner {
    http: AnyConnectAuthHttpClient,
    options: GlobalProtectHipRunnerOptions,
    token: GlobalProtectHipToken,
    check_url: Url,
    report_url: Url,
    wrapper_path: Option<PathBuf>,
}

impl GlobalProtectHipRunner {
    pub fn new(
        http: AnyConnectAuthHttpClient,
        mut options: GlobalProtectHipRunnerOptions,
    ) -> Result<Self, GlobalProtectHipError> {
        validate_hip_options(&options)?;
        if options.interval.is_zero() {
            options.interval = GLOBALPROTECT_HIP_DEFAULT_INTERVAL;
        }
        let token = build_globalprotect_hip_token(&options.opaque_query)?;
        let check_url =
            hip_url(&options.server_url, GLOBALPROTECT_HIP_CHECK_PATH);
        let report_url =
            hip_url(&options.server_url, GLOBALPROTECT_HIP_REPORT_PATH);
        Ok(Self {
            http,
            options,
            token,
            check_url,
            report_url,
            wrapper_path: None,
        })
    }

    pub fn set_wrapper_path(&mut self, path: impl Into<PathBuf>) {
        self.wrapper_path = Some(path.into());
    }

    pub fn interval(&self) -> Duration {
        self.options.interval
    }

    pub async fn check(
        &mut self,
    ) -> Result<GlobalProtectHipCheckResult, GlobalProtectHipError> {
        let check_body = build_globalprotect_hip_check_body(
            &self.options.opaque_query,
            self.options.assigned_ipv4,
            self.options.assigned_ipv6,
            &self.token.md5,
        );
        let check_url = self.check_url.clone();
        let response = self.post(check_url, check_body, "check").await?;
        let response = parse_globalprotect_hip_response(
            &response,
            "check",
            &self.options.opaque_query,
        )?;
        let report_needed = response
            .report_needed
            .ok_or(GlobalProtectHipError::MissingReportDecision("check"))?;
        if !report_needed {
            return Ok(GlobalProtectHipCheckResult {
                report_needed: false,
                report_submitted: false,
                next_check: self.options.interval,
            });
        }
        let report = if let Some(wrapper_path) = self.wrapper_path.as_ref() {
            run_globalprotect_hip_wrapper(
                wrapper_path,
                &self.options,
                &self.token.md5,
            )
            .await?
        } else {
            let inventory = GlobalProtectHipInventory::collect(
                &self.options.local_hostname,
            )
            .map_err(GlobalProtectHipError::Inventory)?;
            build_globalprotect_hip_report(&GlobalProtectHipReportOptions {
                token: self.token.clone(),
                assigned_ipv4: self.options.assigned_ipv4,
                assigned_ipv6: self.options.assigned_ipv6,
                app_version: self.options.app_version.clone(),
                inventory,
                generated_at: local_now(),
            })?
        };
        let report_body = build_globalprotect_hip_report_body(
            &self.options.opaque_query,
            self.options.assigned_ipv4,
            self.options.assigned_ipv6,
            &report,
        );
        let report_url = self.report_url.clone();
        let response = self
            .post(report_url, report_body, "report submission")
            .await?;
        parse_globalprotect_hip_response(
            &response,
            "report submission",
            &self.options.opaque_query,
        )?;
        Ok(GlobalProtectHipCheckResult {
            report_needed: true,
            report_submitted: true,
            next_check: self.options.interval,
        })
    }

    async fn post(
        &mut self,
        url: Url,
        body: String,
        operation: &'static str,
    ) -> Result<Vec<u8>, GlobalProtectHipError> {
        let response = self
            .http
            .execute(AnyConnectAuthHttpRequest {
                method: Method::POST,
                url,
                content_type: Some("application/x-www-form-urlencoded".into()),
                body: body.into_bytes(),
                xml_post: false,
                xml_post_probe: false,
                authentication_headers: false,
                preserve_cookie_jar_on_redirect: false,
                follow_redirects: false,
            })
            .await?;
        if response.body.len() > GLOBALPROTECT_HIP_MAXIMUM_RESPONSE_BODY {
            return Err(GlobalProtectHipError::BodyTooLarge {
                operation,
                maximum: GLOBALPROTECT_HIP_MAXIMUM_RESPONSE_BODY,
            });
        }
        if !response.status.is_success() {
            return Err(GlobalProtectHipError::HttpStatus {
                operation,
                status: response.status,
                class: classify_globalprotect_hip_http_status(
                    response.status.as_u16(),
                ),
            });
        }
        Ok(response.body)
    }
}

async fn run_globalprotect_hip_wrapper(
    wrapper_path: &std::path::Path,
    options: &GlobalProtectHipRunnerOptions,
    md5: &str,
) -> Result<Vec<u8>, GlobalProtectHipError> {
    let mut command = tokio::process::Command::new(wrapper_path);
    command.arg("--cookie").arg(&options.opaque_query);
    if let Some(address) = options.assigned_ipv4 {
        command.arg("--client-ip").arg(address.to_string());
    }
    if let Some(address) = options.assigned_ipv6 {
        command.arg("--client-ipv6").arg(address.to_string());
    }
    command
        .arg("--md5")
        .arg(md5)
        .arg("--client-os")
        .arg(&options.reported_os)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (name, value) in env::vars_os() {
        if !name.to_string_lossy().eq_ignore_ascii_case("APP_VERSION") {
            command.env(name, value);
        }
    }
    if !options.app_version.is_empty() {
        command.env("APP_VERSION", &options.app_version);
    }
    let mut child = command
        .spawn()
        .map_err(GlobalProtectHipError::WrapperStart)?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        GlobalProtectHipError::WrapperStart(io::Error::other(
            "HIP wrapper stdout pipe is unavailable",
        ))
    })?;
    let read_report = async move {
        let mut report =
            Vec::with_capacity(GLOBALPROTECT_HIP_MAXIMUM_REPORT_BODY);
        let mut buffer = [0_u8; 8 * 1024];
        let mut exceeded = false;
        loop {
            let read = stdout.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            let remaining = GLOBALPROTECT_HIP_MAXIMUM_REPORT_BODY
                .saturating_sub(report.len());
            let retained = read.min(remaining);
            report.extend_from_slice(&buffer[..retained]);
            exceeded |= retained != read;
        }
        Ok::<_, io::Error>((report, exceeded))
    };
    let (status, (report, exceeded)) =
        tokio::try_join!(child.wait(), read_report)
            .map_err(GlobalProtectHipError::WrapperWait)?;
    if !status.success() {
        return Err(GlobalProtectHipError::WrapperStatus(
            status.code().unwrap_or(-1),
        ));
    }
    if exceeded {
        return Err(GlobalProtectHipError::ReportTooLarge(
            GLOBALPROTECT_HIP_MAXIMUM_REPORT_BODY,
        ));
    }
    if report.is_empty() {
        return Err(GlobalProtectHipError::WrapperEmpty);
    }
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectHipReportOptions {
    pub token: GlobalProtectHipToken,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub assigned_ipv6: Option<Ipv6Addr>,
    pub app_version: String,
    pub inventory: GlobalProtectHipInventory,
    pub generated_at: OffsetDateTime,
}

pub fn build_globalprotect_hip_token(
    cookie: &str,
) -> Result<GlobalProtectHipToken, GlobalProtectHipError> {
    if cookie.is_empty() {
        return Err(GlobalProtectHipError::InvalidConfiguration(
            "authentication cookie is empty".into(),
        ));
    }
    let mut identity = GlobalProtectHipCookieIdentity::default();
    let mut filtered = Vec::new();
    for segment in cookie.split('&').filter(|segment| !segment.is_empty()) {
        let (name, value) = segment.split_once('=').unwrap_or((segment, ""));
        if name == "user" && identity.user.is_empty() {
            identity.user = decode_query_component(value)?;
        } else if name == "domain" && identity.domain.is_empty() {
            identity.domain = decode_query_component(value)?;
        }
        if !matches!(name, "authcookie" | "preferred-ip" | "preferred-ipv6") {
            filtered.push(segment);
        }
    }
    Ok(GlobalProtectHipToken {
        md5: hex::encode(Md5::digest(filtered.join("&").as_bytes())),
        identity,
    })
}

pub fn build_globalprotect_hip_check_body(
    opaque_query: &str,
    assigned_ipv4: Option<Ipv4Addr>,
    assigned_ipv6: Option<Ipv6Addr>,
    md5: &str,
) -> String {
    let mut body = format!("client-role=global-protect-full&{opaque_query}");
    append_form_option(
        &mut body,
        "client-ip",
        assigned_ipv4.map(|value| value.to_string()).as_deref(),
    );
    append_form_option(
        &mut body,
        "client-ipv6",
        assigned_ipv6.map(|value| value.to_string()).as_deref(),
    );
    append_form_option(&mut body, "md5", Some(md5));
    body
}

pub fn build_globalprotect_hip_report_body(
    opaque_query: &str,
    assigned_ipv4: Option<Ipv4Addr>,
    assigned_ipv6: Option<Ipv6Addr>,
    report: &[u8],
) -> String {
    let mut body = format!("client-role=global-protect-full&{opaque_query}");
    append_form_option(
        &mut body,
        "client-ip",
        assigned_ipv4.map(|value| value.to_string()).as_deref(),
    );
    append_form_option(
        &mut body,
        "client-ipv6",
        assigned_ipv6.map(|value| value.to_string()).as_deref(),
    );
    append_form_option(
        &mut body,
        "report",
        Some(&String::from_utf8_lossy(report)),
    );
    body
}

pub fn build_globalprotect_hip_report(
    options: &GlobalProtectHipReportOptions,
) -> Result<Vec<u8>, GlobalProtectHipError> {
    let (operating_system, vendor) = local_globalprotect_hip_os();
    let timestamp = format_hip_time(options.generated_at);
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<hip-report name=\"hip-report\">\n",
    );
    element(&mut xml, 1, "md5-sum", &options.token.md5);
    element(&mut xml, 1, "user-name", &options.token.identity.user);
    element(&mut xml, 1, "domain", &options.token.identity.domain);
    element(&mut xml, 1, "host-name", &options.inventory.hostname);
    if let Some(address) = options.assigned_ipv4 {
        element(&mut xml, 1, "ip-address", &address.to_string());
    }
    if let Some(address) = options.assigned_ipv6 {
        element(&mut xml, 1, "ipv6-address", &address.to_string());
    }
    element(&mut xml, 1, "generate-time", &timestamp);
    element(&mut xml, 1, "hip-report-version", "4");
    xml.push_str("\t<categories>\n\t\t<entry name=\"host-info\">\n");
    element(&mut xml, 3, "client-version", &options.app_version);
    element(&mut xml, 3, "os", &operating_system);
    element(&mut xml, 3, "os-vendor", &vendor);
    element(&mut xml, 3, "domain", &options.token.identity.domain);
    element(&mut xml, 3, "host-name", &options.inventory.hostname);
    xml.push_str("\t\t\t<network-interface>\n");
    for interface in &options.inventory.interfaces {
        xml.push_str("\t\t\t\t<entry name=\"");
        xml.push_str(&escape_xml(&interface.name));
        xml.push_str("\">\n");
        element(&mut xml, 5, "mac-address", &interface.mac_address);
        xml.push_str("\t\t\t\t</entry>\n");
    }
    xml.push_str("\t\t\t</network-interface>\n\t\t</entry>\n");
    for category in [
        "antivirus",
        "anti-malware",
        "anti-spyware",
        "disk-backup",
        "disk-encryption",
        "firewall",
    ] {
        xml.push_str("\t\t<entry name=\"");
        xml.push_str(category);
        xml.push_str("\">\n\t\t\t<list></list>\n\t\t</entry>\n");
    }
    xml.push_str(
        "\t\t<entry name=\"patch-management\">\n\t\t\t<list></list>\n\t\t\t<missing-patches></missing-patches>\n\t\t</entry>\n",
    );
    xml.push_str(
        "\t\t<entry name=\"data-loss-prevention\">\n\t\t\t<list></list>\n\t\t</entry>\n\t</categories>\n</hip-report>\n",
    );
    if xml.len() > GLOBALPROTECT_HIP_MAXIMUM_REPORT_BODY {
        return Err(GlobalProtectHipError::ReportTooLarge(
            GLOBALPROTECT_HIP_MAXIMUM_REPORT_BODY,
        ));
    }
    Ok(xml.into_bytes())
}

pub fn classify_globalprotect_hip_http_status(
    status: u16,
) -> GlobalProtectFailureClass {
    match status {
        401 | 403 | 512 => GlobalProtectFailureClass::SessionRejected,
        513 => GlobalProtectFailureClass::AuthenticationFailed,
        408 | 425 | 429 => GlobalProtectFailureClass::Retryable,
        500..=599 => GlobalProtectFailureClass::Retryable,
        _ => GlobalProtectFailureClass::Terminal,
    }
}

pub fn parse_globalprotect_hip_response(
    content: &[u8],
    operation: &'static str,
    opaque_query: &str,
) -> Result<GlobalProtectHipResponse, GlobalProtectHipError> {
    let root = parse_xml(content).map_err(|error| {
        GlobalProtectHipError::InvalidXml(error.to_string())
    })?;
    if root.name != "response" {
        return Err(GlobalProtectHipError::InvalidXml(format!(
            "unexpected {operation} root: {}",
            root.name
        )));
    }
    let status_error = root
        .attribute("status")
        .is_some_and(|status| status.trim().eq_ignore_ascii_case("error"));
    let message = child_text(&root, "error").trim();
    if status_error || !message.is_empty() {
        let message = if message.is_empty() {
            "unspecified server error".into()
        } else {
            redact_hip_cookie(message, opaque_query)
        };
        let class = match child_text(&root, "error").trim() {
            "Invalid authentication cookie" | "Portal name not found" => {
                GlobalProtectFailureClass::SessionRejected
            }
            "Valid client certificate is required"
            | "Allow Automatic Restoration of SSL VPN is disabled" => {
                GlobalProtectFailureClass::AuthenticationFailed
            }
            _ => GlobalProtectFailureClass::Terminal,
        };
        return Err(GlobalProtectHipError::Response {
            operation,
            message,
            class,
        });
    }
    let report_needed = match child_text(&root, "hip-report-needed").trim() {
        "" => None,
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    };
    Ok(GlobalProtectHipResponse { report_needed })
}

fn validate_hip_options(
    options: &GlobalProtectHipRunnerOptions,
) -> Result<(), GlobalProtectHipError> {
    if options.server_url.scheme() != "https"
        || options.server_url.host_str().is_none()
        || !options.server_url.username().is_empty()
        || options.server_url.password().is_some()
    {
        return Err(GlobalProtectHipError::InvalidConfiguration(
            "server must be an HTTPS host URL without user information".into(),
        ));
    }
    if options.server_url.port() == Some(0) {
        return Err(GlobalProtectHipError::InvalidConfiguration(
            "server port is zero".into(),
        ));
    }
    if options.opaque_query.is_empty() {
        return Err(GlobalProtectHipError::InvalidConfiguration(
            "authentication cookie is empty".into(),
        ));
    }
    if options.assigned_ipv4.is_none() && options.assigned_ipv6.is_none() {
        return Err(GlobalProtectHipError::InvalidConfiguration(
            "an assigned IP address is required".into(),
        ));
    }
    if options.reported_os.is_empty() {
        return Err(GlobalProtectHipError::InvalidConfiguration(
            "reported GlobalProtect OS is empty".into(),
        ));
    }
    Ok(())
}

fn hip_url(server: &Url, path: &str) -> Url {
    let mut url = server.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn append_form_option(body: &mut String, name: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    body.push('&');
    body.push_str(&encode_globalprotect_form_component(name));
    body.push('=');
    body.push_str(&encode_globalprotect_form_component(value));
}

fn decode_query_component(
    value: &str,
) -> Result<String, GlobalProtectHipError> {
    percent_encoding::percent_decode_str(&value.replace('+', " "))
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|error| {
            GlobalProtectHipError::InvalidConfiguration(format!(
                "cookie identity is not UTF-8: {error}"
            ))
        })
}

fn child_text<'a>(root: &'a XmlNode, name: &str) -> &'a str {
    root.child_text(name).unwrap_or_default()
}

fn redact_hip_cookie(message: &str, opaque_query: &str) -> String {
    let mut safe =
        message.replace(opaque_query, "[redacted authentication cookie]");
    for segment in opaque_query.split('&') {
        let Some(("authcookie", value)) = segment.split_once('=') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        safe = safe.replace(value, "[redacted authcookie]");
        if let Ok(decoded) = decode_query_component(value) {
            safe = safe.replace(&decoded, "[redacted authcookie]");
        }
    }
    safe
}

fn format_globalprotect_hip_mac(value: &str) -> Option<String> {
    let normalized = value.replace(':', "-").to_ascii_uppercase();
    let bytes = normalized
        .split('-')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!bytes.is_empty() && bytes.iter().any(|byte| *byte != 0))
        .then_some(normalized)
}

fn local_globalprotect_hip_os() -> (String, String) {
    let arch = env::consts::ARCH;
    match env::consts::OS {
        "macos" => (format!("Apple macOS {arch}"), "Apple".into()),
        "windows" => (format!("Microsoft Windows {arch}"), "Microsoft".into()),
        "linux" => (format!("Linux {arch}"), "Linux".into()),
        operating_system => (
            format!("{operating_system} {arch}"),
            operating_system.into(),
        ),
    }
}

fn format_hip_time(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(format_description!(
            "[month]/[day]/[year] [hour]:[minute]:[second]"
        ))
        .unwrap_or_default()
}

fn local_now() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    UtcOffset::current_local_offset()
        .map_or(now, |offset| now.to_offset(offset))
}

fn element(xml: &mut String, depth: usize, name: &str, value: &str) {
    for _ in 0..depth {
        xml.push('\t');
    }
    xml.push('<');
    xml.push_str(name);
    xml.push('>');
    xml.push_str(&escape_xml(value));
    xml.push_str("</");
    xml.push_str(name);
    xml.push_str(">\n");
}

fn escape_xml(value: &str) -> String {
    quick_xml::escape::escape(value).into_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use http::{HeaderMap, Request};
    use time::macros::datetime;

    use super::*;
    use crate::protocol::openconnect::{
        AnyConnectAuthHttpTransport, AnyConnectAuthRawHttpResponse,
    };

    #[test]
    fn token_filters_only_upstream_cookie_fields() {
        let token = build_globalprotect_hip_token(
            "authcookie=s%2Fecret&user=alice%20smith&domain=EXAMPLE&preferred-ip=10.0.0.2&x=%2F",
        )
        .unwrap();
        assert_eq!(token.identity.user, "alice smith");
        assert_eq!(token.identity.domain, "EXAMPLE");
        assert_eq!(
            token.md5,
            hex::encode(Md5::digest(
                b"user=alice%20smith&domain=EXAMPLE&x=%2F"
            ))
        );
    }

    #[test]
    fn check_form_preserves_cookie_and_lowercase_rfc3986_encoding() {
        let body = build_globalprotect_hip_check_body(
            "authcookie=a+b&user=u",
            Some("10.0.0.2".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap()),
            "deadbeef",
        );
        assert_eq!(
            body,
            "client-role=global-protect-full&authcookie=a+b&user=u&client-ip=10.0.0.2&client-ipv6=2001%3adb8%3a%3a2&md5=deadbeef"
        );
    }

    #[test]
    fn built_in_report_has_stable_categories_and_escapes_inventory() {
        let report =
            build_globalprotect_hip_report(&GlobalProtectHipReportOptions {
                token: GlobalProtectHipToken {
                    md5: "abcd".into(),
                    identity: GlobalProtectHipCookieIdentity {
                        user: "a&b".into(),
                        domain: "example".into(),
                    },
                },
                assigned_ipv4: Some("10.0.0.2".parse().unwrap()),
                assigned_ipv6: None,
                app_version: "6.3.0-33".into(),
                inventory: GlobalProtectHipInventory {
                    hostname: "host<1>".into(),
                    interfaces: vec![GlobalProtectHipInterface {
                        name: "en&0".into(),
                        mac_address: "00-11-22-33-44-55".into(),
                    }],
                },
                generated_at: datetime!(2026-09-08 12:34:56 UTC),
            })
            .unwrap();
        let report = String::from_utf8(report).unwrap();
        assert!(report.contains("<user-name>a&amp;b</user-name>"));
        assert!(report.contains("name=\"en&amp;0\""));
        assert!(
            report
                .contains("<generate-time>09/08/2026 12:34:56</generate-time>")
        );
        assert_eq!(report.matches("<entry name=").count(), 10);
        assert!(report.ends_with("</hip-report>\n"));
    }

    #[test]
    fn response_classifies_and_redacts_authentication_failures() {
        let error = parse_globalprotect_hip_response(
            br#"<response status="error"><error>cookie secret rejected</error></response>"#,
            "check",
            "authcookie=secret&user=a",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(!text.contains("secret"));
        assert!(text.contains("[redacted authcookie]"));
        assert_eq!(
            classify_globalprotect_hip_http_status(512),
            GlobalProtectFailureClass::SessionRejected
        );
        assert_eq!(
            classify_globalprotect_hip_http_status(503),
            GlobalProtectFailureClass::Retryable
        );
    }

    #[derive(Default)]
    struct MockTransport {
        requests: Mutex<Vec<Request<Vec<u8>>>>,
        responses: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl AnyConnectAuthHttpTransport for MockTransport {
        async fn execute(
            &self,
            request: Request<Vec<u8>>,
        ) -> io::Result<AnyConnectAuthRawHttpResponse> {
            self.requests.lock().unwrap().push(request);
            let body = self.responses.lock().unwrap().remove(0);
            Ok(AnyConnectAuthRawHttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body,
                authenticated_address: Some("192.0.2.1".parse().unwrap()),
                peer_certificate_der: None,
            })
        }
    }

    #[tokio::test]
    async fn runner_submits_report_only_when_requested() {
        let transport = Arc::new(MockTransport {
            responses: Mutex::new(vec![
                br#"<response status="success"><hip-report-needed>yes</hip-report-needed></response>"#.to_vec(),
                br#"<response status="success"/>"#.to_vec(),
            ]),
            ..Default::default()
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut runner = GlobalProtectHipRunner::new(
            http,
            GlobalProtectHipRunnerOptions {
                server_url: Url::parse("https://vpn.example/old?q=1").unwrap(),
                authenticated_address: Some("192.0.2.1".parse().unwrap()),
                opaque_query: "authcookie=secret&user=alice&domain=example"
                    .into(),
                assigned_ipv4: Some("10.0.0.2".parse().unwrap()),
                assigned_ipv6: None,
                app_version: "6.3.0-33".into(),
                reported_os: "linux-64".into(),
                local_hostname: "host".into(),
                interval: Duration::from_secs(30),
            },
        )
        .unwrap();
        let result = runner.check().await.unwrap();
        assert!(result.report_needed);
        assert!(result.report_submitted);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].uri().path(), GLOBALPROTECT_HIP_CHECK_PATH);
        assert_eq!(requests[1].uri().path(), GLOBALPROTECT_HIP_REPORT_PATH);
        assert!(
            std::str::from_utf8(requests[1].body())
                .unwrap()
                .contains("report=%3c%3fxml")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_executes_bounded_external_wrapper_contract() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let wrapper = directory.path().join("hip-wrapper.sh");
        std::fs::write(
            &wrapper,
            r#"#!/bin/sh
[ "$1" = "--cookie" ] || exit 10
[ "$2" = "authcookie=secret&user=alice" ] || exit 11
[ "$3" = "--client-ip" ] || exit 12
[ "$4" = "10.0.0.2" ] || exit 13
[ "$5" = "--md5" ] || exit 14
[ "$7" = "--client-os" ] || exit 15
[ "$8" = "linux-64" ] || exit 16
[ "$APP_VERSION" = "6.3.0-33" ] || exit 17
printf '<external-report/>'
"#,
        )
        .unwrap();
        let mut permissions =
            std::fs::metadata(&wrapper).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&wrapper, permissions).unwrap();
        let transport = Arc::new(MockTransport {
            responses: Mutex::new(vec![
                br#"<response status="success"><hip-report-needed>yes</hip-report-needed></response>"#.to_vec(),
                br#"<response status="success"/>"#.to_vec(),
            ]),
            ..Default::default()
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut runner = GlobalProtectHipRunner::new(
            http,
            GlobalProtectHipRunnerOptions {
                server_url: Url::parse("https://vpn.example/").unwrap(),
                authenticated_address: Some("192.0.2.1".parse().unwrap()),
                opaque_query: "authcookie=secret&user=alice".into(),
                assigned_ipv4: Some("10.0.0.2".parse().unwrap()),
                assigned_ipv6: None,
                app_version: "6.3.0-33".into(),
                reported_os: "linux-64".into(),
                local_hostname: "ignored".into(),
                interval: Duration::from_secs(30),
            },
        )
        .unwrap();
        runner.set_wrapper_path(wrapper);
        runner.check().await.unwrap();
        let requests = transport.requests.lock().unwrap();
        assert!(
            std::str::from_utf8(requests[1].body())
                .unwrap()
                .contains("report=%3cexternal-report%2f%3e")
        );
    }
}
