//! Stateful AnyConnect authentication HTTP transport.
//!
//! Redirect and cookie handling intentionally live above the injected
//! transport. This preserves OpenConnect's authentication behavior while the
//! actual TCP/TLS connection can be created by any singbox `Dialer`.

use std::{io, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use cookie_store::{CookieStore, RawCookie};
use http::{
    HeaderMap, HeaderValue, Method, Request, StatusCode,
    header::{
        ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_TYPE,
        COOKIE, HOST, LOCATION, SET_COOKIE, USER_AGENT, WWW_AUTHENTICATE,
    },
};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use url::Url;

use crate::{
    adapter::{Dialer, stream_peer_addr},
    common::{network::SocksAddr, tls::build_client_config},
    option::OutboundTlsOptions,
};

const MAX_REDIRECTS: usize = 10;
const XMLPOST_PROBE_MAX_REQUESTS: usize = 3;

#[derive(Debug, Error)]
pub enum AnyConnectAuthHttpError {
    #[error("send AnyConnect authentication request: {0}")]
    Transport(#[source] io::Error),
    #[error("invalid AnyConnect authentication URL: {0}")]
    InvalidUrl(String),
    #[error("invalid AnyConnect authentication header: {0}")]
    InvalidHeader(String),
    #[error("authentication redirected to a non-HTTPS URL: {0}")]
    InsecureRedirect(String),
    #[error("XMLPOST probe requires legacy authentication fallback")]
    XmlPostFallback,
    #[error("authentication exceeded {0} redirect requests")]
    TooManyRedirects(usize),
    #[error("authentication exceeded {0} wire requests")]
    TooManyWireRequests(usize),
    #[error("invalid authentication cookie: {0}")]
    InvalidCookie(String),
}

#[derive(Debug, Clone)]
pub struct AnyConnectAuthHttpRequest {
    pub method: Method,
    pub url: Url,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    /// Whether this authentication stage uses XMLPOST and therefore sends
    /// `X-Aggregate-Auth: 1`.
    pub xml_post: bool,
    /// Probe requests use the stricter three-request redirect/fallback policy.
    pub xml_post_probe: bool,
    /// Add the AnyConnect authentication-only X-Transcend/Aggregate headers.
    pub authentication_headers: bool,
    /// Keep RFC 6265 cookies when a redirect changes host or port.
    pub preserve_cookie_jar_on_redirect: bool,
    /// Follow HTTP redirects. GlobalProtect login submission disables this.
    pub follow_redirects: bool,
}

#[derive(Debug, Clone)]
pub struct AnyConnectAuthRawHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct AnyConnectAuthHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub final_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
}

#[async_trait]
pub trait AnyConnectAuthHttpTransport: Send + Sync {
    /// Execute exactly one request without automatic redirect or cookie logic.
    async fn execute(
        &self,
        request: Request<Vec<u8>>,
    ) -> io::Result<AnyConnectAuthRawHttpResponse>;
}

/// HTTP/1.1 authentication transport over an arbitrary singbox TCP dialer.
///
/// Redirects and cookies remain owned by [`AnyConnectAuthHttpClient`]. HTTP/1.1
/// connections are reused per authority unless keep-alive is explicitly
/// disabled, matching OpenConnect's `HTTPKeepAliveDisabled` behavior.
pub struct DialerAnyConnectAuthHttpTransport {
    dialer: Arc<dyn Dialer>,
    tls: OutboundTlsOptions,
    pinned_address: Option<IpAddr>,
    keep_alive_disabled: bool,
    pool: tokio::sync::Mutex<Option<PooledHttp1Connection>>,
}

struct PooledHttp1Connection {
    key: String,
    sender: http1::SendRequest<Full<Bytes>>,
    authenticated_address: Option<IpAddr>,
    peer_certificate_der: Option<Vec<u8>>,
}

impl DialerAnyConnectAuthHttpTransport {
    pub fn new(dialer: Arc<dyn Dialer>, tls: OutboundTlsOptions) -> Self {
        Self {
            dialer,
            tls,
            pinned_address: None,
            keep_alive_disabled: false,
            pool: tokio::sync::Mutex::new(None),
        }
    }

    /// Dial a previously authenticated gateway address while preserving the
    /// original URL host for TLS SNI and the HTTP Host header.
    pub fn with_pinned_address(mut self, address: IpAddr) -> Self {
        self.pinned_address = Some(address);
        self
    }

    pub fn with_keep_alive_disabled(mut self, disabled: bool) -> Self {
        self.keep_alive_disabled = disabled;
        self
    }

    #[cfg(test)]
    pub(crate) const fn keep_alive_disabled(&self) -> bool {
        self.keep_alive_disabled
    }

    async fn connect(
        &self,
        key: String,
        host: &str,
        dial_host: String,
        port: u16,
    ) -> io::Result<PooledHttp1Connection> {
        let stream = self
            .dialer
            .dial_tcp(&SocksAddr::new(dial_host, port))
            .await?;
        let authenticated_address = stream_peer_addr(&stream)
            .ok()
            .flatten()
            .map(|address| address.ip())
            .or(self.pinned_address);
        let mut tls_options = self.tls.clone();
        tls_options.enabled = true;
        let tls = build_client_config(host, &tls_options, &["http/1.1"])
            .map_err(io::Error::other)?;
        let stream = tls.connect_stream(stream).await?;
        let peer_certificate_der = stream.peer_certificates().first().cloned();
        let stream = stream.into_stream();
        let (sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(PooledHttp1Connection {
            key,
            sender,
            authenticated_address,
            peer_certificate_der,
        })
    }
}

#[async_trait]
impl AnyConnectAuthHttpTransport for DialerAnyConnectAuthHttpTransport {
    async fn execute(
        &self,
        request: Request<Vec<u8>>,
    ) -> io::Result<AnyConnectAuthRawHttpResponse> {
        let url = Url::parse(&request.uri().to_string()).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        })?;
        if url.scheme() != "https" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyConnect authentication transport requires HTTPS",
            ));
        }
        let host = url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no host")
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no port")
        })?;
        let dial_host = self
            .pinned_address
            .map_or_else(|| host.to_owned(), |address| address.to_string());
        let (mut parts, body) = request.into_parts();
        let mut target = url.path().to_owned();
        if target.is_empty() {
            target.push('/');
        }
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        parts.uri = target.parse().map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        })?;
        if !parts.headers.contains_key(HOST) {
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            let authority = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            };
            parts.headers.insert(
                HOST,
                HeaderValue::from_str(&authority).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error)
                })?,
            );
        }
        if self.keep_alive_disabled {
            parts
                .headers
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
        let request = Request::from_parts(parts, Full::new(Bytes::from(body)));
        let key = format!("{host}\0{dial_host}\0{port}");
        let mut pool = self.pool.lock().await;
        if pool.as_ref().is_some_and(|connection| {
            connection.key != key || connection.sender.is_closed()
        }) {
            *pool = None;
        }
        if pool.is_none() {
            *pool = Some(self.connect(key, host, dial_host, port).await?);
        }
        let connection = pool.as_mut().expect("HTTP/1 connection initialized");
        let authenticated_address = connection.authenticated_address;
        let peer_certificate_der = connection.peer_certificate_der.clone();
        let response = match connection.sender.send_request(request).await {
            Ok(response) => response,
            Err(error) => {
                *pool = None;
                return Err(io::Error::other(error));
            }
        };
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes()
            .to_vec();
        let should_close =
            self.keep_alive_disabled || connection.sender.is_closed();
        if should_close {
            *pool = None;
        }
        Ok(AnyConnectAuthRawHttpResponse {
            status,
            headers,
            body,
            // The generic Stream trait intentionally does not expose a peer
            // socket address. Custom transports may fill this field.
            authenticated_address,
            peer_certificate_der,
        })
    }
}

pub struct AnyConnectAuthHttpClient {
    transport: Arc<dyn AnyConnectAuthHttpTransport>,
    cookies: CookieStore,
    user_agent: String,
    bearer_token: Option<String>,
    wire_requests: usize,
    maximum_wire_requests: Option<usize>,
}

impl AnyConnectAuthHttpClient {
    pub fn new(
        transport: Arc<dyn AnyConnectAuthHttpTransport>,
        user_agent: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            cookies: CookieStore::default(),
            user_agent: user_agent.into(),
            bearer_token: None,
            wire_requests: 0,
            maximum_wire_requests: None,
        }
    }

    /// Configure an OIDC access token. It is sent only after the server
    /// answers with a Bearer `WWW-Authenticate` challenge, matching
    /// OpenConnect's challenge-first behavior.
    pub fn set_bearer_token(&mut self, token: impl Into<String>) {
        self.bearer_token = Some(token.into());
    }

    /// Bound actual transport executions across redirects and authentication
    /// stages. A Bearer challenge retry also consumes one wire request.
    pub fn set_maximum_wire_requests(&mut self, maximum: Option<usize>) {
        self.maximum_wire_requests = maximum;
    }

    pub const fn wire_request_count(&self) -> usize {
        self.wire_requests
    }

    pub fn clear_cookies(&mut self) {
        self.cookies.clear();
    }

    /// Create a client over the same transport with a fresh cookie jar.
    pub fn isolated(&self) -> Self {
        let mut isolated =
            Self::new(self.transport.clone(), self.user_agent.clone());
        isolated.bearer_token.clone_from(&self.bearer_token);
        isolated.maximum_wire_requests = self.maximum_wire_requests;
        isolated
    }

    pub fn set_cookie(
        &mut self,
        url: &Url,
        name: &str,
        value: &str,
    ) -> Result<(), AnyConnectAuthHttpError> {
        validate_cookie_pair(name, value)?;
        let cookie = format!("{name}={value}; Path=/; Secure; HttpOnly");
        self.cookies.parse(&cookie, url).map_err(|error| {
            AnyConnectAuthHttpError::InvalidCookie(error.to_string())
        })?;
        Ok(())
    }

    pub fn remove_cookie(
        &mut self,
        url: &Url,
        name: &str,
    ) -> Result<(), AnyConnectAuthHttpError> {
        validate_cookie_pair(name, "")?;
        let host = url.host_str().ok_or_else(|| {
            AnyConnectAuthHttpError::InvalidUrl(url.to_string())
        })?;
        self.cookies.remove(host, "/", name);
        Ok(())
    }

    pub fn cookie_value(&self, url: &Url, name: &str) -> Option<String> {
        self.cookies
            .get_request_values(url)
            .find_map(|(cookie_name, value)| {
                (cookie_name == name).then(|| value.to_owned())
            })
    }

    /// Snapshot request cookies in the exact order emitted by the cookie
    /// store. PPP-based OpenConnect flavors reuse this set for their raw
    /// tunnel-upgrade request after HTTP authentication completes.
    pub fn cookie_pairs(&self, url: &Url) -> Vec<(String, String)> {
        self.cookies
            .get_request_values(url)
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect()
    }

    pub async fn execute(
        &mut self,
        request: AnyConnectAuthHttpRequest,
    ) -> Result<AnyConnectAuthHttpResponse, AnyConnectAuthHttpError> {
        validate_https_url(&request.url)?;
        let maximum_requests = if !request.follow_redirects {
            1
        } else if request.xml_post_probe {
            XMLPOST_PROBE_MAX_REQUESTS
        } else {
            MAX_REDIRECTS
        };
        let mut current_url = request.url;

        for _ in 0..maximum_requests {
            let wire_request = self.build_request(
                request.method.clone(),
                &current_url,
                request.content_type.as_deref(),
                &request.body,
                request.xml_post,
                request.authentication_headers,
            )?;
            let mut response = self.execute_wire(wire_request).await?;
            if response.status == StatusCode::UNAUTHORIZED
                && has_bearer_challenge(&response.headers)
                && let Some(token) = self.bearer_token.as_deref()
            {
                let mut retry = self.build_request(
                    request.method.clone(),
                    &current_url,
                    request.content_type.as_deref(),
                    &request.body,
                    request.xml_post,
                    request.authentication_headers,
                )?;
                retry.headers_mut().insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {token}")).map_err(
                        |error| {
                            AnyConnectAuthHttpError::InvalidHeader(
                                error.to_string(),
                            )
                        },
                    )?,
                );
                response = self.execute_wire(retry).await?;
            }
            self.store_response_cookies(&current_url, &response.headers);

            let location = response
                .headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok());
            if !request.follow_redirects
                || !is_redirect(response.status)
                || location.is_none()
            {
                return Ok(AnyConnectAuthHttpResponse {
                    status: response.status,
                    headers: response.headers,
                    body: response.body,
                    final_url: current_url,
                    authenticated_address: response.authenticated_address,
                    peer_certificate_der: response.peer_certificate_der,
                });
            }
            let location = current_url
                .join(location.expect("checked above"))
                .map_err(|error| {
                AnyConnectAuthHttpError::InvalidUrl(error.to_string())
            })?;
            validate_https_url(&location).map_err(|_| {
                AnyConnectAuthHttpError::InsecureRedirect(location.to_string())
            })?;
            let same_endpoint = equal_url_endpoint(&current_url, &location);
            if request.xml_post_probe && same_endpoint {
                return Err(AnyConnectAuthHttpError::XmlPostFallback);
            }
            if !same_endpoint && !request.preserve_cookie_jar_on_redirect {
                // OpenConnect discards the entire authentication jar, rather
                // than only cookies which would fail ordinary domain matching.
                self.cookies.clear();
            }
            current_url = location;
        }

        if request.xml_post_probe {
            Err(AnyConnectAuthHttpError::XmlPostFallback)
        } else {
            Err(AnyConnectAuthHttpError::TooManyRedirects(maximum_requests))
        }
    }

    async fn execute_wire(
        &mut self,
        request: Request<Vec<u8>>,
    ) -> Result<AnyConnectAuthRawHttpResponse, AnyConnectAuthHttpError> {
        if let Some(maximum) = self.maximum_wire_requests
            && self.wire_requests >= maximum
        {
            return Err(AnyConnectAuthHttpError::TooManyWireRequests(maximum));
        }
        self.wire_requests += 1;
        self.transport
            .execute(request)
            .await
            .map_err(AnyConnectAuthHttpError::Transport)
    }

    fn build_request(
        &self,
        method: Method,
        url: &Url,
        content_type: Option<&str>,
        body: &[u8],
        xml_post: bool,
        authentication_headers: bool,
    ) -> Result<Request<Vec<u8>>, AnyConnectAuthHttpError> {
        let mut request = Request::builder()
            .method(method)
            .uri(url.as_str())
            .body(body.to_vec())
            .map_err(|error| {
                AnyConnectAuthHttpError::InvalidUrl(error.to_string())
            })?;
        let headers = request.headers_mut();
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        if authentication_headers {
            headers
                .insert("x-transcend-version", HeaderValue::from_static("1"));
            if xml_post {
                headers
                    .insert("x-aggregate-auth", HeaderValue::from_static("1"));
            }
        }
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent).map_err(|error| {
                AnyConnectAuthHttpError::InvalidHeader(error.to_string())
            })?,
        );
        if let Some(content_type) = content_type {
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_str(content_type).map_err(|error| {
                    AnyConnectAuthHttpError::InvalidHeader(error.to_string())
                })?,
            );
            let padding_length = 64 * (1 + body.len() / 64) - body.len();
            headers.insert(
                "x-pad",
                HeaderValue::from_str(&"0".repeat(padding_length)).map_err(
                    |error| {
                        AnyConnectAuthHttpError::InvalidHeader(
                            error.to_string(),
                        )
                    },
                )?,
            );
        }
        let cookie = self
            .cookies
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if !cookie.is_empty() {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&cookie).map_err(|error| {
                    AnyConnectAuthHttpError::InvalidHeader(error.to_string())
                })?,
            );
        }
        Ok(request)
    }

    fn store_response_cookies(&mut self, url: &Url, headers: &HeaderMap) {
        let cookies = headers.get_all(SET_COOKIE).iter().filter_map(|value| {
            RawCookie::parse(value.to_str().ok()?.to_owned())
                .ok()
                .map(RawCookie::into_owned)
        });
        self.cookies.store_response_cookies(cookies, url);
    }
}

fn validate_cookie_pair(
    name: &str,
    value: &str,
) -> Result<(), AnyConnectAuthHttpError> {
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
        return Err(AnyConnectAuthHttpError::InvalidCookie(name.into()));
    }
    Ok(())
}

fn validate_https_url(url: &Url) -> Result<(), AnyConnectAuthHttpError> {
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(AnyConnectAuthHttpError::InvalidUrl(url.to_string()));
    }
    Ok(())
}

fn equal_url_endpoint(left: &Url, right: &Url) -> bool {
    left.host_str()
        .zip(right.host_str())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
        && left.port_or_known_default().unwrap_or(443)
            == right.port_or_known_default().unwrap_or(443)
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn has_bearer_challenge(headers: &HeaderMap) -> bool {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(header_has_bearer_challenge)
}

fn header_has_bearer_challenge(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        while position < bytes.len()
            && matches!(bytes[position], b' ' | b'\t' | b',')
        {
            position += 1;
        }
        let scheme_start = position;
        while position < bytes.len() && is_auth_token_byte(bytes[position]) {
            position += 1;
        }
        if scheme_start == position {
            break;
        }
        if value[scheme_start..position].eq_ignore_ascii_case("bearer") {
            return true;
        }
        let mut quoted = false;
        let mut escaped = false;
        while position < bytes.len() {
            let byte = bytes[position];
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
                position += 1;
                continue;
            }
            if byte == b'"' {
                quoted = true;
                position += 1;
                continue;
            }
            if byte != b',' {
                position += 1;
                continue;
            }
            let mut candidate = position + 1;
            while candidate < bytes.len()
                && matches!(bytes[candidate], b' ' | b'\t')
            {
                candidate += 1;
            }
            let mut candidate_end = candidate;
            while candidate_end < bytes.len()
                && is_auth_token_byte(bytes[candidate_end])
            {
                candidate_end += 1;
            }
            let mut after = candidate_end;
            while after < bytes.len() && matches!(bytes[after], b' ' | b'\t') {
                after += 1;
            }
            if candidate_end > candidate
                && (after == bytes.len() || bytes[after] != b'=')
            {
                position = candidate;
                break;
            }
            position = candidate_end;
        }
    }
    false
}

fn is_auth_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, convert::Infallible, sync::Mutex};

    use http_body_util::Full;
    use hyper::{Response, service::service_fn};
    use hyper_util::rt::TokioIo;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::{
        adapter::Dialer, option::DirectOutboundOptions,
        protocol::direct::DirectOutbound,
    };

    #[derive(Default)]
    struct FakeTransport {
        requests: Mutex<Vec<Request<Vec<u8>>>>,
        responses: Mutex<VecDeque<AnyConnectAuthRawHttpResponse>>,
    }

    impl FakeTransport {
        fn with_responses(
            responses: Vec<AnyConnectAuthRawHttpResponse>,
        ) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }
    }

    #[async_trait]
    impl AnyConnectAuthHttpTransport for FakeTransport {
        async fn execute(
            &self,
            request: Request<Vec<u8>>,
        ) -> io::Result<AnyConnectAuthRawHttpResponse> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| io::Error::other("no fake response"))
        }
    }

    fn response(
        status: StatusCode,
        headers: &[(&str, &str)],
    ) -> AnyConnectAuthRawHttpResponse {
        let mut header_map = HeaderMap::new();
        for (name, value) in headers {
            header_map.append(
                name.parse::<http::HeaderName>().unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        AnyConnectAuthRawHttpResponse {
            status,
            headers: header_map,
            body: b"response".to_vec(),
            authenticated_address: Some("192.0.2.1".parse().unwrap()),
            peer_certificate_der: Some(vec![1, 2, 3]),
        }
    }

    fn request(url: &str, probe: bool) -> AnyConnectAuthHttpRequest {
        AnyConnectAuthHttpRequest {
            method: Method::POST,
            url: Url::parse(url).unwrap(),
            content_type: Some("application/xml; charset=utf-8".into()),
            body: vec![b'x'; 64],
            xml_post: true,
            xml_post_probe: probe,
            authentication_headers: true,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: true,
        }
    }

    #[tokio::test]
    async fn emits_exact_auth_headers_padding_and_cookies() {
        let transport =
            Arc::new(FakeTransport::with_responses(vec![response(
                StatusCode::OK,
                &[],
            )]));
        let mut client =
            AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let url = Url::parse("https://vpn.example/auth").unwrap();
        client.set_cookie(&url, "webvpn", "secret").unwrap();
        client.execute(request(url.as_str(), false)).await.unwrap();

        let requests = transport.requests.lock().unwrap();
        let request = &requests[0];
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.headers()[ACCEPT], "*/*");
        assert_eq!(request.headers()[ACCEPT_ENCODING], "identity");
        assert_eq!(request.headers()["x-transcend-version"], "1");
        assert_eq!(request.headers()["x-aggregate-auth"], "1");
        assert_eq!(request.headers()[USER_AGENT], "agent");
        assert_eq!(request.headers()[COOKIE], "webvpn=secret");
        assert_eq!(request.headers()["x-pad"].as_bytes().len(), 64);
    }

    #[tokio::test]
    async fn oidc_bearer_token_is_sent_only_after_challenge() {
        let transport = Arc::new(FakeTransport::with_responses(vec![
            response(
                StatusCode::UNAUTHORIZED,
                &[(
                    "www-authenticate",
                    "Digest realm=\"vpn,edge\", Bearer realm=\"vpn\"",
                )],
            ),
            response(StatusCode::OK, &[]),
        ]));
        let mut client =
            AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        client.set_bearer_token("access-token");
        let result = client
            .execute(request("https://vpn.example/auth", false))
            .await
            .unwrap();
        assert_eq!(result.status, StatusCode::OK);

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].headers().contains_key(AUTHORIZATION));
        assert_eq!(requests[1].headers()[AUTHORIZATION], "Bearer access-token");
        assert_eq!(requests[0].body(), requests[1].body());
    }

    #[test]
    fn bearer_challenge_parser_ignores_auth_parameters() {
        assert!(!header_has_bearer_challenge(
            "Digest realm=\"Bearer\", token=Bearer"
        ));
        assert!(header_has_bearer_challenge(
            "Basic realm=\"vpn\", Bearer error=\"invalid_token\""
        ));
        assert!(header_has_bearer_challenge("bearer"));
    }

    #[tokio::test]
    async fn follows_redirects_and_clears_all_cookies_across_endpoints() {
        let transport = Arc::new(FakeTransport::with_responses(vec![
            response(
                StatusCode::FOUND,
                &[
                    ("location", "https://id.example/login"),
                    ("set-cookie", "first=one; Path=/; Secure"),
                ],
            ),
            response(
                StatusCode::OK,
                &[("set-cookie", "webvpn=final; Path=/; Secure")],
            ),
        ]));
        let mut client =
            AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let original = Url::parse("https://vpn.example/auth").unwrap();
        client.set_cookie(&original, "existing", "value").unwrap();
        let result = client
            .execute(request(original.as_str(), false))
            .await
            .unwrap();
        assert_eq!(result.final_url.as_str(), "https://id.example/login");
        assert_eq!(
            result.authenticated_address,
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(result.peer_certificate_der, Some(vec![1, 2, 3]));
        assert_eq!(
            client.cookie_value(&result.final_url, "webvpn"),
            Some("final".into())
        );
        assert_eq!(client.cookie_value(&original, "existing"), None);

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].headers().get(COOKIE).is_none());
        assert_eq!(requests[1].method(), Method::POST);
        assert_eq!(requests[1].body(), &vec![b'x'; 64]);
    }

    #[tokio::test]
    async fn xmlpost_same_endpoint_redirect_requests_legacy_fallback() {
        let transport =
            Arc::new(FakeTransport::with_responses(vec![response(
                StatusCode::FOUND,
                &[("location", "/legacy")],
            )]));
        let mut client = AnyConnectAuthHttpClient::new(transport, "agent");
        assert!(matches!(
            client
                .execute(request("https://vpn.example/auth", true))
                .await,
            Err(AnyConnectAuthHttpError::XmlPostFallback)
        ));
    }

    #[tokio::test]
    async fn rejects_insecure_redirect_and_enforces_redirect_budget() {
        let insecure = Arc::new(FakeTransport::with_responses(vec![response(
            StatusCode::FOUND,
            &[("location", "http://vpn.example/auth")],
        )]));
        let mut client = AnyConnectAuthHttpClient::new(insecure, "agent");
        assert!(matches!(
            client
                .execute(request("https://vpn.example/auth", false))
                .await,
            Err(AnyConnectAuthHttpError::InsecureRedirect(_))
        ));

        let redirects = (0..MAX_REDIRECTS)
            .map(|index| {
                response(
                    StatusCode::FOUND,
                    &[("location", &format!("/redirect/{index}"))],
                )
            })
            .collect();
        let transport = Arc::new(FakeTransport::with_responses(redirects));
        let mut client = AnyConnectAuthHttpClient::new(transport, "agent");
        assert!(matches!(
            client
                .execute(request("https://vpn.example/auth", false))
                .await,
            Err(AnyConnectAuthHttpError::TooManyRedirects(MAX_REDIRECTS))
        ));
    }

    #[tokio::test]
    async fn wire_request_budget_counts_redirects_and_bearer_retries() {
        let transport = Arc::new(FakeTransport::with_responses(vec![
            response(
                StatusCode::UNAUTHORIZED,
                &[("www-authenticate", "Bearer realm=\"vpn\"")],
            ),
            response(StatusCode::FOUND, &[("location", "/next")]),
            response(StatusCode::OK, &[]),
        ]));
        let mut client =
            AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        client.set_bearer_token("token");
        client.set_maximum_wire_requests(Some(2));
        assert!(matches!(
            client
                .execute(request("https://vpn.example/auth", false))
                .await,
            Err(AnyConnectAuthHttpError::TooManyWireRequests(2))
        ));
        assert_eq!(client.wire_request_count(), 2);
        assert_eq!(transport.requests.lock().unwrap().len(), 2);
    }

    #[test]
    fn removes_and_validates_programmatic_cookies() {
        let transport = Arc::new(FakeTransport::default());
        let mut client = AnyConnectAuthHttpClient::new(transport, "agent");
        let url = Url::parse("https://vpn.example/").unwrap();
        client.set_cookie(&url, "webvpn", "secret").unwrap();
        assert_eq!(client.cookie_value(&url, "webvpn"), Some("secret".into()));
        client.remove_cookie(&url, "webvpn").unwrap();
        assert_eq!(client.cookie_value(&url, "webvpn"), None);
        assert!(client.set_cookie(&url, "bad name", "value").is_err());
    }

    #[tokio::test]
    async fn dialer_transport_runs_real_tls_http1_and_exposes_certificate() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let expected_certificate = cert.der().as_ref().to_vec();
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let disabled_acceptor = acceptor.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request| async move {
                        assert_eq!(request.method(), Method::POST);
                        assert_eq!(request.uri(), "/auth?q=1");
                        assert_eq!(
                            request.headers()["x-transcend-version"],
                            "1"
                        );
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(
                                    SET_COOKIE,
                                    "webvpn=server; Path=/; Secure",
                                )
                                .body(Full::new(Bytes::from_static(
                                    b"auth-response",
                                )))
                                .unwrap(),
                        )
                    }),
                )
                .await
                .unwrap();
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let transport = DialerAnyConnectAuthHttpTransport::new(
            dialer,
            OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
        );
        let response = transport
            .execute(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("https://{address}/auth?q=1"))
                    .header("x-transcend-version", "1")
                    .body(b"request".to_vec())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"auth-response");
        assert_eq!(
            response.peer_certificate_der,
            Some(expected_certificate.clone())
        );
        let reused = transport
            .execute(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("https://{address}/auth?q=1"))
                    .header("x-transcend-version", "1")
                    .body(b"second-request".to_vec())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reused.status, StatusCode::OK);
        assert_eq!(reused.body, b"auth-response");
        assert_eq!(reused.peer_certificate_der, Some(expected_certificate));
        drop(transport);
        server.await.unwrap();

        let disabled_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let disabled_address = disabled_listener.local_addr().unwrap();
        let disabled_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = disabled_listener.accept().await.unwrap();
                let stream = disabled_acceptor.accept(stream).await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|request| async move {
                            assert_eq!(request.headers()[CONNECTION], "close");
                            Ok::<_, Infallible>(Response::new(Full::new(
                                Bytes::from_static(b"closed"),
                            )))
                        }),
                    )
                    .await
                    .unwrap();
            }
        });
        let disabled = DialerAnyConnectAuthHttpTransport::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            },
        )
        .with_keep_alive_disabled(true);
        for _ in 0..2 {
            let response = disabled
                .execute(
                    Request::builder()
                        .uri(format!("https://{disabled_address}/"))
                        .body(Vec::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.body, b"closed");
        }
        disabled_server.await.unwrap();
    }
}
