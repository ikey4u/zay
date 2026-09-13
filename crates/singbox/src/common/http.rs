//! Minimal HTTP downloader over a sing-box dialer.

use std::{
    collections::HashMap,
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Buf as _, Bytes};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, StatusCode,
    client::conn::{http1, http2},
    header::{AUTHORIZATION, HeaderMap, LOCATION},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Endpoint, EndpointConfig, TokioRuntime, VarInt};
use tokio::sync::Mutex;

#[cfg(target_vendor = "apple")]
use crate::common::apple_http::AppleHttpClient;
use crate::{
    adapter::{Dialer, Stream},
    common::{
        network::SocksAddr, ntp::NtpClock, quic::PacketUdpSocket,
        tls::build_client_config_with_clock,
    },
    option::HttpClientOptions,
};

pub(crate) struct DownloadResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

type H3RequestStream =
    h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub(crate) struct StreamingResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    body: StreamingBody,
}

enum StreamingBody {
    Hyper(hyper::body::Incoming),
    Http3(Box<H3RequestStream>),
}

impl StreamingResponse {
    pub(crate) async fn chunk(&mut self) -> io::Result<Option<Bytes>> {
        match &mut self.body {
            StreamingBody::Hyper(body) => loop {
                let Some(frame) = body.frame().await else {
                    return Ok(None);
                };
                let frame = frame.map_err(io::Error::other)?;
                if let Ok(data) = frame.into_data() {
                    return Ok(Some(data));
                }
            },
            StreamingBody::Http3(stream) => stream
                .recv_data()
                .await
                .map_err(io::Error::other)
                .map(|chunk| {
                    chunk
                        .map(|mut chunk| chunk.copy_to_bytes(chunk.remaining()))
                }),
        }
    }

    pub(crate) async fn collect(mut self, limit: usize) -> io::Result<Bytes> {
        let mut body = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            if body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > limit)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("HTTP response body exceeds {limit} bytes"),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(body))
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct DownloadOptions {
    pub client: HttpClientOptions,
}

/// Reusable HTTP downloader backed by a sing-box `Dialer`.
///
/// HTTP/1.1, HTTP/2 and HTTP/3 connections are pooled by authority. Calling
/// [`DownloadClient::reset`] drops every transport path so the next request
/// redials through the current network.
pub(crate) struct DownloadClient {
    dialer: Arc<dyn Dialer>,
    options: DownloadOptions,
    pool: Mutex<HashMap<PoolKey, PooledSender>>,
    http3_pool: Mutex<HashMap<PoolKey, Http3Session>>,
    http3_broken: Mutex<HashMap<AuthorityKey, Http3BrokenEntry>>,
    clock: Option<NtpClock>,
    #[cfg(target_vendor = "apple")]
    apple: Option<AppleHttpClient>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AuthorityKey {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Copy)]
struct Http3BrokenEntry {
    until: Instant,
    backoff: Duration,
}

const HTTP3_BROKEN_INITIAL_BACKOFF: Duration = Duration::from_secs(5 * 60);
const HTTP3_BROKEN_MAX_BACKOFF: Duration = Duration::from_secs(48 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    scheme: String,
    host: String,
    port: u16,
    version: u8,
}

enum PooledSender {
    Http1(http1::SendRequest<Full<Bytes>>),
    Http2(http2::SendRequest<Full<Bytes>>),
}

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct Http3Session {
    endpoint: Endpoint,
    sender: H3SendRequest,
    driver: tokio::task::JoinHandle<h3::error::ConnectionError>,
}

impl Drop for Http3Session {
    fn drop(&mut self) {
        self.driver.abort();
        self.endpoint.close(0_u32.into(), b"");
    }
}

impl PooledSender {
    async fn send(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, hyper::Error> {
        match self {
            Self::Http1(sender) => {
                sender.ready().await?;
                sender.send_request(request).await
            }
            Self::Http2(sender) => {
                sender.ready().await?;
                sender.send_request(request).await
            }
        }
    }
}

impl DownloadClient {
    pub(crate) fn new(
        dialer: Arc<dyn Dialer>,
        options: DownloadOptions,
    ) -> io::Result<Self> {
        Self::new_with_clock(dialer, options, None)
    }

    pub(crate) fn new_with_clock(
        dialer: Arc<dyn Dialer>,
        options: DownloadOptions,
        clock: Option<NtpClock>,
    ) -> io::Result<Self> {
        validate_options(&options.client)?;
        #[cfg(target_vendor = "apple")]
        let apple = (options.client.engine == "apple").then(|| {
            AppleHttpClient::new(
                dialer.clone(),
                options.client.clone(),
                clock.clone(),
            )
        });
        Ok(Self {
            dialer,
            options,
            pool: Mutex::new(HashMap::new()),
            http3_pool: Mutex::new(HashMap::new()),
            http3_broken: Mutex::new(HashMap::new()),
            clock,
            #[cfg(target_vendor = "apple")]
            apple,
        })
    }

    pub(crate) async fn download(
        &self,
        source: &str,
        headers: &HeaderMap,
    ) -> io::Result<DownloadResponse> {
        self.request(Method::GET, source, headers, Bytes::new())
            .await
    }

    /// Send a request without collecting its response body.  Realm SSE uses
    /// this path so long-lived events retain backpressure while still dialing
    /// through the same outbound-aware H1/H2/H3 transport as rule downloads.
    pub(crate) async fn request_stream(
        &self,
        method: Method,
        source: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> io::Result<StreamingResponse> {
        if self.options.client.engine == "apple" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "streaming Apple HTTP engine is unavailable",
            ));
        }
        let mut url = url::Url::parse(source).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        })?;
        let mut request_headers = headers.clone();
        for _ in 0..10 {
            let configured_version = if self.options.client.version == 0 {
                2
            } else {
                self.options.client.version
            };
            let mut response = if url.scheme() == "https"
                && configured_version == 3
            {
                match self
                    .request_http3_stream(
                        method.clone(),
                        &url,
                        &request_headers,
                        body.clone(),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(error)
                        if !self.options.client.disable_version_fallback =>
                    {
                        let _ = error;
                        self.request_tcp_stream(
                            method.clone(),
                            &url,
                            &request_headers,
                            body.clone(),
                            2,
                        )
                        .await?
                    }
                    Err(error) => return Err(error),
                }
            } else {
                self.request_tcp_stream(
                    method.clone(),
                    &url,
                    &request_headers,
                    body.clone(),
                    configured_version,
                )
                .await?
            };
            if response.status.is_redirection() {
                let location = response
                    .headers
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "HTTP redirect has no location",
                        )
                    })?;
                let next = url.join(location).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error)
                })?;
                while response.chunk().await?.is_some() {}
                if url.origin() != next.origin() {
                    // Match Go/reqwest redirect safety: a Realm bearer token
                    // must never be forwarded to a different authority.
                    request_headers.remove(AUTHORIZATION);
                }
                url = next;
                continue;
            }
            return Ok(response);
        }
        Err(io::Error::other("too many HTTP redirects"))
    }

    async fn request_tcp_stream(
        &self,
        method: Method,
        url: &url::Url,
        headers: &HeaderMap,
        body: Bytes,
        configured_version: u8,
    ) -> io::Result<StreamingResponse> {
        // A response such as Realm SSE may remain open for the lifetime of the
        // control session.  Do not reserve the authority's sole HTTP/1 sender
        // in the ordinary download pool, otherwise heartbeat/connect requests
        // would wait behind that never-ending body. HTTP/2 remains correct
        // with a dedicated multiplexed connection; H3 has its own pool below.
        let request =
            build_request(method, url, headers, body, &self.options.client)?;
        let mut sender = self.connect_sender(url, configured_version).await?;
        let response = sender.send(request).await.map_err(io::Error::other)?;
        let status = response.status();
        let headers = response.headers().clone();
        Ok(StreamingResponse {
            status,
            headers,
            body: StreamingBody::Hyper(response.into_body()),
        })
    }

    async fn request_http3_stream(
        &self,
        method: Method,
        url: &url::Url,
        headers: &HeaderMap,
        body: Bytes,
    ) -> io::Result<StreamingResponse> {
        let key = pool_key(url, 3)?;
        let mut last_error = None;
        for _ in 0..2 {
            let request = build_http3_request(
                method.clone(),
                url,
                headers,
                &self.options.client,
            )?;
            let stream = {
                let mut pool = self.http3_pool.lock().await;
                if pool
                    .get(&key)
                    .is_some_and(|session| session.driver.is_finished())
                {
                    pool.remove(&key);
                }
                if !pool.contains_key(&key) {
                    let session = connect_http3_session(
                        self.dialer.clone(),
                        url,
                        &self.options.client,
                        self.clock.clone(),
                    )
                    .await?;
                    pool.insert(key.clone(), session);
                }
                match pool
                    .get_mut(&key)
                    .expect("HTTP/3 session inserted")
                    .sender
                    .send_request(request)
                    .await
                {
                    Ok(stream) => Some(stream),
                    Err(error) => {
                        pool.remove(&key);
                        last_error = Some(error);
                        None
                    }
                }
            };
            let Some(mut stream) = stream else {
                continue;
            };
            if !body.is_empty() {
                stream
                    .send_data(body.clone())
                    .await
                    .map_err(io::Error::other)?;
            }
            stream.finish().await.map_err(io::Error::other)?;
            let response =
                stream.recv_response().await.map_err(io::Error::other)?;
            return Ok(StreamingResponse {
                status: response.status(),
                headers: response.headers().clone(),
                body: StreamingBody::Http3(Box::new(stream)),
            });
        }
        Err(io::Error::other(
            last_error.expect("two HTTP/3 attempts always record an error"),
        ))
    }

    /// Drop all reusable H1/H2 senders and H3 sessions. In-flight requests
    /// retain their own stream, while the next request opens a fresh path.
    pub(crate) async fn reset(&self) {
        self.pool.lock().await.clear();
        self.http3_pool.lock().await.clear();
        self.http3_broken.lock().await.clear();
        #[cfg(target_vendor = "apple")]
        if let Some(apple) = &self.apple {
            apple.reset().await;
        }
    }

    async fn request(
        &self,
        method: Method,
        source: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> io::Result<DownloadResponse> {
        let mut url = url::Url::parse(source).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        })?;
        for _ in 0..10 {
            #[cfg(target_vendor = "apple")]
            if let Some(apple) = &self.apple {
                let response = apple
                    .request(
                        method.clone(),
                        &url,
                        apple_request_headers(headers, &self.options.client)?,
                        body.clone(),
                    )
                    .await?;
                if let Some(next) = redirect_url(&url, &response)? {
                    url = next;
                    continue;
                }
                return Ok(response);
            }
            let configured_version = if self.options.client.version == 0 {
                2
            } else {
                self.options.client.version
            };
            if url.scheme() == "https" && configured_version == 3 {
                let response = if self.options.client.disable_version_fallback {
                    self.request_http3_pooled(
                        method.clone(),
                        &url,
                        headers,
                        body.clone(),
                    )
                    .await?
                } else {
                    self.request_http3_with_fallback(
                        method.clone(),
                        &url,
                        headers,
                        body.clone(),
                    )
                    .await?
                };
                if let Some(next) = redirect_url(&url, &response)? {
                    url = next;
                    continue;
                }
                return Ok(response);
            }
            let response = self
                .send_pooled(
                    method.clone(),
                    &url,
                    headers,
                    body.clone(),
                    configured_version,
                )
                .await?;
            let status = response.status();
            let response_headers = response.headers().clone();
            let response_body = response
                .into_body()
                .collect()
                .await
                .map(|body| body.to_bytes())
                .map_err(io::Error::other)?;
            let response = DownloadResponse {
                status,
                headers: response_headers,
                body: response_body,
            };
            if let Some(next) = redirect_url(&url, &response)? {
                url = next;
                continue;
            }
            return Ok(response);
        }
        Err(io::Error::other("too many HTTP redirects"))
    }

    async fn send_pooled(
        &self,
        method: Method,
        url: &url::Url,
        headers: &HeaderMap,
        body: Bytes,
        configured_version: u8,
    ) -> io::Result<hyper::Response<hyper::body::Incoming>> {
        let host = url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no host")
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no port")
        })?;
        let key = PoolKey {
            scheme: url.scheme().to_owned(),
            host: host.to_owned(),
            port,
            version: configured_version,
        };
        let mut last_error = None;
        for _ in 0..2 {
            let mut pool = self.pool.lock().await;
            if !pool.contains_key(&key) {
                let sender =
                    self.connect_sender(url, configured_version).await?;
                pool.insert(key.clone(), sender);
            }
            let request = build_request(
                method.clone(),
                url,
                headers,
                body.clone(),
                &self.options.client,
            )?;
            let result = pool
                .get_mut(&key)
                .expect("pooled sender inserted")
                .send(request)
                .await;
            match result {
                Ok(response) => return Ok(response),
                Err(error) => {
                    pool.remove(&key);
                    last_error = Some(error);
                }
            }
        }
        Err(io::Error::other(
            last_error.expect("two pooled attempts always record an error"),
        ))
    }

    async fn request_http3_pooled(
        &self,
        method: Method,
        url: &url::Url,
        headers: &HeaderMap,
        body: Bytes,
    ) -> io::Result<DownloadResponse> {
        let host = url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no host")
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no port")
        })?;
        let key = PoolKey {
            scheme: url.scheme().to_owned(),
            host: host.to_owned(),
            port,
            version: 3,
        };
        let mut last_error = None;
        for _ in 0..2 {
            let request = build_http3_request(
                method.clone(),
                url,
                headers,
                &self.options.client,
            )?;
            let stream = {
                let mut pool = self.http3_pool.lock().await;
                if pool
                    .get(&key)
                    .is_some_and(|session| session.driver.is_finished())
                {
                    pool.remove(&key);
                }
                if !pool.contains_key(&key) {
                    let session = connect_http3_session(
                        self.dialer.clone(),
                        url,
                        &self.options.client,
                        self.clock.clone(),
                    )
                    .await?;
                    pool.insert(key.clone(), session);
                }
                let result = pool
                    .get_mut(&key)
                    .expect("HTTP/3 session inserted")
                    .sender
                    .send_request(request)
                    .await;
                match result {
                    Ok(stream) => Some(stream),
                    Err(error) => {
                        pool.remove(&key);
                        last_error = Some(error);
                        None
                    }
                }
            };
            let Some(mut stream) = stream else {
                continue;
            };
            if !body.is_empty() {
                stream
                    .send_data(body.clone())
                    .await
                    .map_err(io::Error::other)?;
            }
            stream.finish().await.map_err(io::Error::other)?;
            let response =
                stream.recv_response().await.map_err(io::Error::other)?;
            let status = response.status();
            let headers = response.headers().clone();
            let mut response_body = Vec::new();
            while let Some(mut chunk) =
                stream.recv_data().await.map_err(io::Error::other)?
            {
                response_body
                    .extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            return Ok(DownloadResponse {
                status,
                headers,
                body: Bytes::from(response_body),
            });
        }
        Err(io::Error::other(
            last_error.expect("two HTTP/3 attempts always record an error"),
        ))
    }

    async fn request_http3_cached(
        &self,
        method: Method,
        url: &url::Url,
        headers: &HeaderMap,
        body: Bytes,
    ) -> io::Result<Option<DownloadResponse>> {
        let key = pool_key(url, 3)?;
        let request =
            build_http3_request(method, url, headers, &self.options.client)?;
        let stream = {
            let mut pool = self.http3_pool.lock().await;
            if pool
                .get(&key)
                .is_some_and(|session| session.driver.is_finished())
            {
                pool.remove(&key);
            }
            let Some(session) = pool.get_mut(&key) else {
                return Ok(None);
            };
            match session.sender.send_request(request).await {
                Ok(stream) => stream,
                Err(error) => {
                    pool.remove(&key);
                    return Err(io::Error::other(error));
                }
            }
        };
        let mut stream = stream;
        if !body.is_empty() {
            stream.send_data(body).await.map_err(io::Error::other)?;
        }
        stream.finish().await.map_err(io::Error::other)?;
        let response =
            stream.recv_response().await.map_err(io::Error::other)?;
        let status = response.status();
        let headers = response.headers().clone();
        let mut response_body = Vec::new();
        while let Some(mut chunk) =
            stream.recv_data().await.map_err(io::Error::other)?
        {
            response_body
                .extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        Ok(Some(DownloadResponse {
            status,
            headers,
            body: Bytes::from(response_body),
        }))
    }

    async fn request_http3_with_fallback(
        &self,
        method: Method,
        url: &url::Url,
        headers: &HeaderMap,
        body: Bytes,
    ) -> io::Result<DownloadResponse> {
        let authority = authority_key(url)?;
        if self.http3_is_broken(&authority).await {
            return self.request_fallback(method, url, headers, body).await;
        }

        match self
            .request_http3_cached(method.clone(), url, headers, body.clone())
            .await
        {
            Ok(Some(response)) => {
                self.clear_http3_broken(&authority).await;
                return Ok(response);
            }
            Ok(None) => {}
            Err(_) => {
                self.mark_http3_broken(authority).await;
                return self.request_fallback(method, url, headers, body).await;
            }
        }

        let fallback_delay = self
            .options
            .client
            .dialer
            .abstract_options
            .fallback_delay
            .as_std()
            .filter(|delay| !delay.is_zero())
            .unwrap_or(Duration::from_millis(300));
        let h3 = self.request_http3_pooled(
            method.clone(),
            url,
            headers,
            body.clone(),
        );
        tokio::pin!(h3);
        match tokio::time::timeout(fallback_delay, &mut h3).await {
            Ok(Ok(response)) => {
                self.clear_http3_broken(&authority).await;
                return Ok(response);
            }
            Ok(Err(h3_error)) => {
                self.mark_http3_broken(authority).await;
                return self
                    .request_fallback(method, url, headers, body)
                    .await
                    .map_err(|fallback_error| {
                        combined_transport_error(h3_error, fallback_error)
                    });
            }
            Err(_) => {}
        }

        let fallback = self.request_fallback(method, url, headers, body);
        tokio::pin!(fallback);
        tokio::select! {
            h3_result = &mut h3 => match h3_result {
                Ok(response) => {
                    self.clear_http3_broken(&authority).await;
                    Ok(response)
                }
                Err(h3_error) => {
                    self.mark_http3_broken(authority).await;
                    fallback.await.map_err(|fallback_error| {
                        combined_transport_error(h3_error, fallback_error)
                    })
                }
            },
            fallback_result = &mut fallback => match fallback_result {
                Ok(response) => Ok(response),
                Err(fallback_error) => match h3.await {
                    Ok(response) => {
                        self.clear_http3_broken(&authority).await;
                        Ok(response)
                    }
                    Err(h3_error) => {
                        self.mark_http3_broken(authority).await;
                        Err(combined_transport_error(h3_error, fallback_error))
                    }
                }
            },
        }
    }

    async fn request_fallback(
        &self,
        method: Method,
        url: &url::Url,
        headers: &HeaderMap,
        body: Bytes,
    ) -> io::Result<DownloadResponse> {
        let response = self.send_pooled(method, url, headers, body, 2).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map(|body| body.to_bytes())
            .map_err(io::Error::other)?;
        Ok(DownloadResponse {
            status,
            headers,
            body,
        })
    }

    async fn http3_is_broken(&self, authority: &AuthorityKey) -> bool {
        let mut broken = self.http3_broken.lock().await;
        let Some(entry) = broken.get(authority) else {
            return false;
        };
        if Instant::now() >= entry.until {
            broken.remove(authority);
            return false;
        }
        true
    }

    async fn clear_http3_broken(&self, authority: &AuthorityKey) {
        self.http3_broken.lock().await.remove(authority);
    }

    async fn mark_http3_broken(&self, authority: AuthorityKey) {
        let mut broken = self.http3_broken.lock().await;
        let backoff = broken
            .get(&authority)
            .map(|entry| {
                entry
                    .backoff
                    .saturating_mul(2)
                    .min(HTTP3_BROKEN_MAX_BACKOFF)
            })
            .unwrap_or(HTTP3_BROKEN_INITIAL_BACKOFF);
        broken.insert(
            authority,
            Http3BrokenEntry {
                until: Instant::now() + backoff,
                backoff,
            },
        );
    }

    async fn connect_sender(
        &self,
        url: &url::Url,
        configured_version: u8,
    ) -> io::Result<PooledSender> {
        let host = url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no host")
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no port")
        })?;
        let stream = self.dialer.dial_tcp(&SocksAddr::new(host, port)).await?;
        let (stream, negotiated_h2): (Stream, bool) = match url.scheme() {
            "http" => (stream, false),
            "https" => {
                let alpn: &[&str] = match configured_version {
                    1 => &["http/1.1"],
                    2 if self.options.client.disable_version_fallback => {
                        &["h2"]
                    }
                    2 => &["h2", "http/1.1"],
                    3 => unreachable!("HTTP/3 is handled before TCP dialing"),
                    _ => unreachable!("validated HTTP client version"),
                };
                let mut tls_options =
                    self.options.client.tls.clone().unwrap_or_default();
                tls_options.enabled = true;
                let tls = build_client_config_with_clock(
                    host,
                    &tls_options,
                    alpn,
                    self.clock.clone(),
                )
                .map_err(io::Error::other)?;
                let stream = tls.connect_stream(stream).await?;
                let negotiated_h2 = stream.negotiated_alpn() == Some(b"h2");
                if configured_version == 2
                    && self.options.client.disable_version_fallback
                    && !negotiated_h2
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "server did not negotiate required HTTP/2",
                    ));
                }
                (stream.into_stream(), negotiated_h2)
            }
            scheme => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported HTTP URL scheme {scheme:?}"),
                ));
            }
        };
        if negotiated_h2 {
            let (sender, connection) =
                http2::Builder::new(TokioExecutor::new())
                    .handshake(TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(PooledSender::Http2(sender))
        } else {
            let (sender, connection) = http1::handshake(TokioIo::new(stream))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(PooledSender::Http1(sender))
        }
    }
}

pub(crate) async fn download(
    dialer: Arc<dyn Dialer>,
    source: &str,
    headers: &HeaderMap,
) -> io::Result<DownloadResponse> {
    download_with_options(dialer, source, headers, &DownloadOptions::default())
        .await
}

pub(crate) async fn download_with_options(
    dialer: Arc<dyn Dialer>,
    source: &str,
    headers: &HeaderMap,
    options: &DownloadOptions,
) -> io::Result<DownloadResponse> {
    request_with_options(
        dialer,
        Method::GET,
        source,
        headers,
        Bytes::new(),
        options,
    )
    .await
}

pub(crate) async fn request_with_options(
    dialer: Arc<dyn Dialer>,
    method: Method,
    source: &str,
    headers: &HeaderMap,
    body: Bytes,
    options: &DownloadOptions,
) -> io::Result<DownloadResponse> {
    request_with_options_and_clock(
        dialer, method, source, headers, body, options, None,
    )
    .await
}

pub(crate) async fn request_with_options_and_clock(
    dialer: Arc<dyn Dialer>,
    method: Method,
    source: &str,
    headers: &HeaderMap,
    body: Bytes,
    options: &DownloadOptions,
    clock: Option<NtpClock>,
) -> io::Result<DownloadResponse> {
    validate_options(&options.client)?;
    if options.client.engine == "apple" || clock.is_some() {
        return DownloadClient::new_with_clock(dialer, options.clone(), clock)?
            .request(method, source, headers, body)
            .await;
    }
    let mut url = url::Url::parse(source)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    for _ in 0..10 {
        let host = url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no host")
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL has no port")
        })?;
        let configured_version = if options.client.version == 0 {
            2
        } else {
            options.client.version
        };
        if url.scheme() == "https" && configured_version == 3 {
            return DownloadClient::new(dialer, options.clone())?
                .request(method, source, headers, body)
                .await;
        }
        let stream = dialer.dial_tcp(&SocksAddr::new(host, port)).await?;
        let (stream, negotiated_h2): (Stream, bool) = match url.scheme() {
            "http" => (stream, false),
            "https" => {
                let alpn: &[&str] = match configured_version {
                    1 => &["http/1.1"],
                    2 if options.client.disable_version_fallback => &["h2"],
                    2 => &["h2", "http/1.1"],
                    3 => unreachable!("HTTP/3 is handled before TCP dialing"),
                    _ => unreachable!("validated HTTP client version"),
                };
                let mut tls_options =
                    options.client.tls.clone().unwrap_or_default();
                tls_options.enabled = true;
                let tls = build_client_config_with_clock(
                    host,
                    &tls_options,
                    alpn,
                    None,
                )
                .map_err(io::Error::other)?;
                let stream = tls.connect_stream(stream).await?;
                let negotiated_h2 = stream.negotiated_alpn() == Some(b"h2");
                if configured_version == 2
                    && options.client.disable_version_fallback
                    && !negotiated_h2
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "server did not negotiate required HTTP/2",
                    ));
                }
                (stream.into_stream(), negotiated_h2)
            }
            scheme => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported HTTP URL scheme {scheme:?}"),
                ));
            }
        };
        let target = &url[url::Position::BeforePath..];
        let host_header = host_header(&url)?;
        let mut request = Request::builder()
            .method(method.clone())
            .uri(if target.is_empty() { "/" } else { target })
            .header("host", host_header)
            .header(
                "user-agent",
                concat!("sing-box/", env!("CARGO_PKG_VERSION")),
            )
            .body(Full::new(body.clone()))
            .expect("valid HTTP download request");
        extend_headers(request.headers_mut(), &options.client.headers)?;
        request.headers_mut().extend(headers.clone());
        let response = if negotiated_h2 {
            let (mut sender, connection) =
                http2::Builder::new(TokioExecutor::new())
                    .handshake(TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            sender
                .send_request(request)
                .await
                .map_err(io::Error::other)?
        } else {
            let (mut sender, connection) =
                http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            sender
                .send_request(request)
                .await
                .map_err(io::Error::other)?
        };
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP redirect has no location",
                    )
                })?;
            url = url.join(location).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, error)
            })?;
            continue;
        }
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map(|body| body.to_bytes())
            .map_err(io::Error::other)?;
        return Ok(DownloadResponse {
            status,
            headers,
            body,
        });
    }
    Err(io::Error::other("too many HTTP redirects"))
}

fn authority_key(url: &url::Url) -> io::Result<AuthorityKey> {
    let host = url.host_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "URL has no host")
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "URL has no port")
    })?;
    Ok(AuthorityKey {
        host: host.to_owned(),
        port,
    })
}

fn host_header(url: &url::Url) -> io::Result<String> {
    let host = match url.host() {
        Some(url::Host::Domain(host)) => host.to_owned(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "URL has no host",
            ));
        }
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn pool_key(url: &url::Url, version: u8) -> io::Result<PoolKey> {
    let authority = authority_key(url)?;
    Ok(PoolKey {
        scheme: url.scheme().to_owned(),
        host: authority.host,
        port: authority.port,
        version,
    })
}

fn combined_transport_error(
    primary: io::Error,
    fallback: io::Error,
) -> io::Error {
    io::Error::other(format!(
        "HTTP/3 request failed: {primary}; HTTP/2 fallback failed: {fallback}"
    ))
}

fn redirect_url(
    current: &url::Url,
    response: &DownloadResponse,
) -> io::Result<Option<url::Url>> {
    if !response.status.is_redirection() {
        return Ok(None);
    }
    let location = response
        .headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP redirect has no location",
            )
        })?;
    current
        .join(location)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn build_request(
    method: Method,
    url: &url::Url,
    extra_headers: &HeaderMap,
    body: Bytes,
    options: &HttpClientOptions,
) -> io::Result<Request<Full<Bytes>>> {
    let target = &url[url::Position::BeforePath..];
    let host_header = host_header(url)?;
    let mut request = Request::builder()
        .method(method)
        .uri(if target.is_empty() { "/" } else { target })
        .header("host", host_header)
        .header(
            "user-agent",
            concat!("sing-box/", env!("CARGO_PKG_VERSION")),
        )
        .body(Full::new(body))
        .map_err(io::Error::other)?;
    extend_headers(request.headers_mut(), &options.headers)?;
    request.headers_mut().extend(extra_headers.clone());
    Ok(request)
}

#[cfg(target_vendor = "apple")]
fn apple_request_headers(
    extra_headers: &HeaderMap,
    options: &HttpClientOptions,
) -> io::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::USER_AGENT,
        concat!("sing-box/", env!("CARGO_PKG_VERSION"))
            .parse()
            .expect("static user agent"),
    );
    extend_headers(&mut headers, &options.headers)?;
    headers.extend(extra_headers.clone());
    Ok(headers)
}

fn build_http3_request(
    method: Method,
    url: &url::Url,
    extra_headers: &HeaderMap,
    options: &HttpClientOptions,
) -> io::Result<Request<()>> {
    let mut request = Request::builder()
        .method(method)
        .uri(url.as_str())
        .header(
            "user-agent",
            concat!("sing-box/", env!("CARGO_PKG_VERSION")),
        )
        .body(())
        .map_err(io::Error::other)?;
    extend_headers(request.headers_mut(), &options.headers)?;
    request.headers_mut().extend(extra_headers.clone());
    Ok(request)
}

async fn connect_http3_session(
    dialer: Arc<dyn Dialer>,
    url: &url::Url,
    options: &HttpClientOptions,
    clock: Option<NtpClock>,
) -> io::Result<Http3Session> {
    let host = url.host_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "URL has no host")
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "URL has no port")
    })?;
    let mut tls_options = options.tls.clone().unwrap_or_default();
    tls_options.enabled = true;
    let server_name = if tls_options.server_name.is_empty() {
        host.to_owned()
    } else {
        tls_options.server_name.clone()
    };
    let tls =
        build_client_config_with_clock(host, &tls_options, &["h3"], clock)
            .map_err(io::Error::other)?;
    let crypto = QuicClientConfig::try_from(
        tls.config_for_handshake().await.map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    let mut transport = quinn::TransportConfig::default();
    if let Some(timeout) = options
        .idle_timeout
        .as_std()
        .filter(|timeout| !timeout.is_zero())
    {
        transport.max_idle_timeout(Some(timeout.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP/3 idle_timeout exceeds QUIC varint range",
            )
        })?));
    }
    if let Some(period) = options
        .keep_alive_period
        .as_std()
        .filter(|period| !period.is_zero())
    {
        transport.keep_alive_interval(Some(period));
    }
    if options.stream_receive_window.0 != 0 {
        transport.stream_receive_window(
            VarInt::from_u64(options.stream_receive_window.0)
                .map_err(io::Error::other)?,
        );
    }
    if options.connection_receive_window.0 != 0 {
        transport.receive_window(
            VarInt::from_u64(options.connection_receive_window.0)
                .map_err(io::Error::other)?,
        );
    }
    if options.max_concurrent_streams > 0 {
        transport.max_concurrent_bidi_streams(
            VarInt::from_u64(options.max_concurrent_streams as u64)
                .map_err(io::Error::other)?,
        );
    }
    if options.initial_packet_size > 0 {
        transport.initial_mtu(
            u16::try_from(options.initial_packet_size).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HTTP/3 initial_packet_size exceeds u16",
                )
            })?,
        );
    }
    if options.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(transport));
    let destination = SocksAddr::new(host, port);
    let (socket, remote) =
        PacketUdpSocket::connect(dialer, &destination).await?;
    let runtime = Arc::new(TokioRuntime);
    let mut endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socket,
        runtime,
    )?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(remote, &server_name)
        .map_err(io::Error::other)?
        .await
        .map_err(io::Error::other)?;
    let (mut driver, sender) =
        h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(io::Error::other)?;
    let driver = tokio::spawn(async move {
        futures_util::future::poll_fn(|context| driver.poll_close(context))
            .await
    });
    Ok(Http3Session {
        endpoint,
        sender,
        driver,
    })
}

fn validate_options(options: &HttpClientOptions) -> io::Result<()> {
    options
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    match options.engine.as_str() {
        "" | "go" => Ok(()),
        "apple" => {
            #[cfg(target_vendor = "apple")]
            {
                Ok(())
            }
            #[cfg(not(target_vendor = "apple"))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Apple HTTP client engine is only available on Apple platforms",
                ))
            }
        }
        _ => unreachable!("HTTP client engine was validated"),
    }
}

fn extend_headers(
    destination: &mut HeaderMap,
    source: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<()> {
    for (name, value) in source {
        let name = hyper::header::HeaderName::try_from(name.as_str()).map_err(
            |error| io::Error::new(io::ErrorKind::InvalidInput, error),
        )?;
        let values: Vec<&str> = match value {
            serde_json::Value::String(value) => vec![value],
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    value.as_str().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "HTTP header {name} contains a non-string value"
                            ),
                        )
                    })
                })
                .collect::<io::Result<_>>()?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "HTTP header {name} must be a string or string array"
                    ),
                ));
            }
        };
        destination.remove(&name);
        for value in values {
            destination.append(
                name.clone(),
                hyper::header::HeaderValue::try_from(value).map_err(
                    |error| io::Error::new(io::ErrorKind::InvalidInput, error),
                )?,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{Response, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    #[cfg(target_vendor = "apple")]
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ServerConfig as RustlsServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::{
        AuthorityKey, DownloadClient, DownloadOptions,
        HTTP3_BROKEN_INITIAL_BACKOFF, HTTP3_BROKEN_MAX_BACKOFF, authority_key,
        build_request, download_with_options, host_header,
    };
    use crate::{
        adapter::{DialFuture, Dialer, PacketFuture, PacketStream},
        common::network::SocksAddr,
        option::{
            DirectOutboundOptions, HttpClientOptions, OutboundTlsOptions,
        },
        protocol::direct::DirectOutbound,
    };

    struct FailingUdpDialer {
        direct: DirectOutbound,
        udp_attempts: Arc<AtomicUsize>,
    }

    #[test]
    fn request_authority_and_host_header_cover_upstream_cases() {
        let cases = [
            ("https://example.com/foo", "example.com:443", "example.com"),
            ("http://example.com/foo", "example.com:80", "example.com"),
            (
                "https://example.com:8443/foo",
                "example.com:8443",
                "example.com:8443",
            ),
            ("https://EXAMPLE.COM/foo", "example.com:443", "example.com"),
            (
                "https://[2001:db8::1]/foo",
                "[2001:db8::1]:443",
                "[2001:db8::1]",
            ),
            (
                "https://[2001:db8::1]:8443/foo",
                "[2001:db8::1]:8443",
                "[2001:db8::1]:8443",
            ),
            ("https://192.0.2.1/foo", "192.0.2.1:443", "192.0.2.1"),
        ];
        for (source, expected_authority, expected_host) in cases {
            let url = url::Url::parse(source).unwrap();
            let authority = authority_key(&url).unwrap();
            let rendered_authority =
                match authority.host.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V6(address)) => {
                        format!("[{address}]:{}", authority.port)
                    }
                    _ => format!("{}:{}", authority.host, authority.port),
                };
            assert_eq!(rendered_authority, expected_authority, "{source}");
            assert_eq!(host_header(&url).unwrap(), expected_host, "{source}");
            let request = build_request(
                hyper::Method::GET,
                &url,
                &hyper::HeaderMap::new(),
                Bytes::new(),
                &HttpClientOptions::default(),
            )
            .unwrap();
            assert_eq!(request.headers()[hyper::header::HOST], expected_host);
        }
    }

    impl Dialer for FailingUdpDialer {
        fn dial_tcp<'a>(
            &'a self,
            destination: &'a SocksAddr,
        ) -> DialFuture<'a> {
            self.direct.dial_tcp(destination)
        }

        fn listen_udp<'a>(
            &'a self,
            _destination: &'a SocksAddr,
        ) -> PacketFuture<'a, PacketStream> {
            self.udp_attempts.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "test dialer rejects QUIC",
                ))
            })
        }
    }

    #[tokio::test]
    async fn streaming_redirect_does_not_leak_authorization_cross_origin() {
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let destination_server = tokio::spawn(async move {
            let (stream, _) = destination.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request| async move {
                        assert!(
                            request
                                .headers()
                                .get(hyper::header::AUTHORIZATION)
                                .is_none(),
                            "cross-origin redirect leaked authorization"
                        );
                        Ok::<_, std::convert::Infallible>(Response::new(
                            Full::new(Bytes::from_static(b"safe")),
                        ))
                    }),
                )
                .await
                .unwrap();
        });

        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_address = source.local_addr().unwrap();
        let source_server = tokio::spawn(async move {
            let (stream, _) = source.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request| async move {
                        assert_eq!(
                            request.headers()[hyper::header::AUTHORIZATION],
                            "Bearer realm-token"
                        );
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(hyper::StatusCode::FOUND)
                                .header(
                                    hyper::header::LOCATION,
                                    format!(
                                        "http://{destination_address}/events"
                                    ),
                                )
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }),
                )
                .await
                .unwrap();
        });

        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client =
            DownloadClient::new(dialer, DownloadOptions::default()).unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            "Bearer realm-token".parse().unwrap(),
        );
        let response = client
            .request_stream(
                hyper::Method::GET,
                &format!("http://{source_address}/events"),
                &headers,
                Bytes::new(),
            )
            .await
            .unwrap();
        assert_eq!(response.collect(16).await.unwrap(), b"safe"[..]);
        source_server.await.unwrap();
        destination_server.await.unwrap();
    }

    #[tokio::test]
    async fn http3_broken_authority_backoff_isolated_capped_and_reset() {
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client =
            DownloadClient::new(dialer, DownloadOptions::default()).unwrap();
        let first = AuthorityKey {
            host: "a.example".into(),
            port: 443,
        };
        let second = AuthorityKey {
            host: "b.example".into(),
            port: 443,
        };

        client.mark_http3_broken(first.clone()).await;
        assert_eq!(
            client.http3_broken.lock().await[&first].backoff,
            HTTP3_BROKEN_INITIAL_BACKOFF
        );
        client.mark_http3_broken(first.clone()).await;
        assert_eq!(
            client.http3_broken.lock().await[&first].backoff,
            HTTP3_BROKEN_INITIAL_BACKOFF * 2
        );
        assert!(!client.http3_is_broken(&second).await);

        client.http3_broken.lock().await.insert(
            first.clone(),
            super::Http3BrokenEntry {
                until: std::time::Instant::now(),
                backoff: HTTP3_BROKEN_MAX_BACKOFF,
            },
        );
        assert!(!client.http3_is_broken(&first).await);
        client.http3_broken.lock().await.insert(
            first.clone(),
            super::Http3BrokenEntry {
                until: std::time::Instant::now() + HTTP3_BROKEN_MAX_BACKOFF,
                backoff: HTTP3_BROKEN_MAX_BACKOFF,
            },
        );
        client.mark_http3_broken(first.clone()).await;
        assert_eq!(
            client.http3_broken.lock().await[&first].backoff,
            HTTP3_BROKEN_MAX_BACKOFF
        );
        client.reset().await;
        assert!(client.http3_broken.lock().await.is_empty());
    }

    #[tokio::test]
    async fn http3_failure_falls_back_and_suppresses_retries_until_reset() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = RustlsServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
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
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                connections.push(tokio::spawn(async move {
                    let stream = acceptor.accept(stream).await.unwrap();
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|request| async move {
                                assert_eq!(
                                    request.uri().path(),
                                    "/fallback.srs"
                                );
                                Ok::<_, std::convert::Infallible>(
                                    Response::new(Full::new(
                                        Bytes::from_static(b"fallback-rules"),
                                    )),
                                )
                            }),
                        )
                        .await;
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });
        let udp_attempts = Arc::new(AtomicUsize::new(0));
        let dialer: Arc<dyn Dialer> = Arc::new(FailingUdpDialer {
            direct: DirectOutbound::new(DirectOutboundOptions::default()),
            udp_attempts: udp_attempts.clone(),
        });
        let client = DownloadClient::new(
            dialer,
            DownloadOptions {
                client: HttpClientOptions {
                    version: 3,
                    tls: Some(OutboundTlsOptions {
                        insecure: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            },
        )
        .unwrap();
        let url = format!("https://localhost:{}/fallback.srs", address.port());

        for _ in 0..2 {
            assert_eq!(
                client
                    .download(&url, &hyper::HeaderMap::new())
                    .await
                    .unwrap()
                    .body,
                Bytes::from_static(b"fallback-rules")
            );
        }
        assert_eq!(udp_attempts.load(Ordering::Relaxed), 1);
        client.reset().await;
        assert_eq!(
            client
                .download(&url, &hyper::HeaderMap::new())
                .await
                .unwrap()
                .body,
            Bytes::from_static(b"fallback-rules")
        );
        assert_eq!(udp_attempts.load(Ordering::Relaxed), 2);
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pooled_downloader_reuses_connection_and_reset_redials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = accepted.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                server_accepted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|request| async move {
                                assert_eq!(request.uri().path(), "/rules.json");
                                Ok::<_, std::convert::Infallible>(
                                    Response::new(Full::new(
                                        Bytes::from_static(b"rules"),
                                    )),
                                )
                            }),
                        )
                        .await
                        .unwrap();
                });
            }
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client =
            DownloadClient::new(dialer, DownloadOptions::default()).unwrap();
        let url = format!("http://{address}/rules.json");
        for _ in 0..2 {
            assert_eq!(
                client
                    .download(&url, &hyper::HeaderMap::new())
                    .await
                    .unwrap()
                    .body,
                Bytes::from_static(b"rules")
            );
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        client.reset().await;
        assert_eq!(
            client
                .download(&url, &hyper::HeaderMap::new())
                .await
                .unwrap()
                .body,
            Bytes::from_static(b"rules")
        );
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        server.await.unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn apple_engine_uses_url_session_bridge_and_reset_redials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = accepted.clone();
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                server_accepted.fetch_add(1, Ordering::Relaxed);
                connections.push(tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|request| async move {
                                assert_eq!(request.uri().path(), "/rules.json");
                                assert_eq!(
                                    request.headers()["x-client"],
                                    "apple"
                                );
                                Ok::<_, std::convert::Infallible>(
                                    Response::new(Full::new(
                                        Bytes::from_static(b"apple-rules"),
                                    )),
                                )
                            }),
                        )
                        .await;
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });
        let mut options = HttpClientOptions {
            engine: "apple".into(),
            version: 2,
            ..Default::default()
        };
        options
            .headers
            .insert("X-Client".into(), serde_json::json!("apple"));
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client =
            DownloadClient::new(dialer, DownloadOptions { client: options })
                .unwrap();
        let url = format!("http://{address}/rules.json");
        for _ in 0..2 {
            assert_eq!(
                client
                    .download(&url, &hyper::HeaderMap::new())
                    .await
                    .unwrap()
                    .body,
                Bytes::from_static(b"apple-rules")
            );
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        client.reset().await;
        assert_eq!(
            client
                .download(&url, &hyper::HeaderMap::new())
                .await
                .unwrap()
                .body,
            Bytes::from_static(b"apple-rules")
        );
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        drop(client);
        server.await.unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn apple_engine_verifies_configured_spki_sha256_pin() {
        use sha2::{Digest as _, Sha256};

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.der().clone();
        let parsed =
            rustls::server::ParsedCertificate::try_from(&certificate).unwrap();
        let pin =
            Sha256::digest(parsed.subject_public_key_info().as_ref()).to_vec();
        let server_config = RustlsServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request| async move {
                        assert_eq!(request.uri().path(), "/pinned.srs");
                        Ok::<_, std::convert::Infallible>(Response::new(
                            Full::new(Bytes::from_static(b"pinned-rules")),
                        ))
                    }),
                )
                .await
                .unwrap();
        });
        let options = HttpClientOptions {
            engine: "apple".into(),
            version: 2,
            tls: Some(OutboundTlsOptions {
                certificate_public_key_sha256: crate::option::Listable(vec![
                    crate::option::Base64Bytes(pin),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let response = download_with_options(
            dialer,
            &format!("https://localhost:{}/pinned.srs", address.port()),
            &hyper::HeaderMap::new(),
            &DownloadOptions { client: options },
        )
        .await
        .unwrap();
        assert_eq!(response.body, Bytes::from_static(b"pinned-rules"));
        server.await.unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn apple_engine_rejects_mismatched_spki_sha256_pin() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = RustlsServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
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
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert!(acceptor.accept(stream).await.is_err());
        });
        let options = HttpClientOptions {
            engine: "apple".into(),
            version: 2,
            tls: Some(OutboundTlsOptions {
                certificate_public_key_sha256: crate::option::Listable(vec![
                    crate::option::Base64Bytes(vec![0xA5; 32]),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let result = download_with_options(
            dialer,
            &format!("https://localhost:{}/rejected.srs", address.port()),
            &hyper::HeaderMap::new(),
            &DownloadOptions { client: options },
        )
        .await;
        assert!(result.is_err());
        server.await.unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn apple_engine_uses_ntp_clock_for_certificate_validity() {
        let mut ca_parameters = CertificateParams::default();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap();
        ca_parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_893_456_000).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
        let mut parameters =
            CertificateParams::new(vec!["localhost".into()]).unwrap();
        parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(1_609_459_200).unwrap();
        parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(1_640_995_200).unwrap();
        parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        parameters.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key_pair = KeyPair::generate().unwrap();
        let certificate = parameters
            .signed_by(&key_pair, &ca_certificate, &ca_key)
            .unwrap();
        let server_config = RustlsServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone(), ca_certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key_pair.serialize_der(),
            )),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|_| async move {
                        Ok::<_, std::convert::Infallible>(Response::new(
                            Full::new(Bytes::from_static(b"ntp-time")),
                        ))
                    }),
                )
                .await
                .unwrap();
        });
        let clock = crate::common::ntp::NtpClock::default();
        let system_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        let target_unix_nanos = 1_625_097_600_i128 * 1_000_000_000;
        clock.update(crate::common::ntp::NtpSample {
            offset_nanos: i64::try_from(target_unix_nanos - system_unix_nanos)
                .unwrap(),
            round_trip_nanos: 1,
            stratum: 1,
        });
        let options = HttpClientOptions {
            engine: "apple".into(),
            version: 2,
            tls: Some(OutboundTlsOptions {
                certificate: crate::option::Listable(vec![
                    ca_certificate.pem(),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client = DownloadClient::new_with_clock(
            dialer,
            DownloadOptions { client: options },
            Some(clock),
        )
        .unwrap();
        let response = client
            .download(
                &format!("https://localhost:{}/ntp.srs", address.port()),
                &hyper::HeaderMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(response.body, Bytes::from_static(b"ntp-time"));
        drop(client);
        server.await.unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn cancelling_apple_request_cancels_native_url_session_task() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt as _;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = accepted_tx.send(());
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            let _ = closed_tx.send(());
        });
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client = Arc::new(
            DownloadClient::new(
                dialer,
                DownloadOptions {
                    client: HttpClientOptions {
                        engine: "apple".into(),
                        version: 2,
                        ..Default::default()
                    },
                },
            )
            .unwrap(),
        );
        let url = format!("http://{address}/wait");
        let request_client = client.clone();
        let request = tokio::spawn(async move {
            request_client
                .download(&url, &hyper::HeaderMap::new())
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .unwrap()
            .unwrap();
        request.abort();
        let request_result = request.await;
        assert!(matches!(request_result, Err(error) if error.is_cancelled()));
        tokio::time::timeout(Duration::from_secs(2), closed_rx)
            .await
            .unwrap()
            .unwrap();
        client.reset().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn downloads_over_negotiated_http2_with_custom_headers() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = RustlsServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
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
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request| async move {
                        assert_eq!(request.uri().path(), "/rules.srs");
                        assert_eq!(request.headers()["x-client"], "rust-h2");
                        Ok::<_, std::convert::Infallible>(Response::new(
                            Full::new(Bytes::from_static(b"rule-set")),
                        ))
                    }),
                )
                .await
                .unwrap();
        });
        let mut options = HttpClientOptions {
            version: 2,
            disable_version_fallback: true,
            tls: Some(OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        options
            .headers
            .insert("X-Client".into(), serde_json::json!("rust-h2"));
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let response = download_with_options(
            dialer,
            &format!("https://{address}/rules.srs"),
            &hyper::HeaderMap::new(),
            &DownloadOptions { client: options },
        )
        .await
        .unwrap();
        assert_eq!(response.body, Bytes::from_static(b"rule-set"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn streams_http3_response_through_packet_dialer() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = RustlsServerConfig::builder_with_provider(Arc::new(
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
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut http3 = h3::server::Connection::new(
                h3_quinn::Connection::new(connection),
            )
            .await
            .unwrap();
            let resolver = http3.accept().await.unwrap().unwrap();
            let (request, mut stream) =
                resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), hyper::Method::GET);
            assert_eq!(request.uri().path(), "/rules.srs");
            assert_eq!(request.headers()["x-client"], "rust-h3");
            stream
                .send_response(
                    Response::builder()
                        .status(hyper::StatusCode::OK)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream
                .send_data(Bytes::from_static(b"rule-set-h3"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let _ = done_rx.await;
        });
        let mut options = HttpClientOptions {
            version: 3,
            disable_version_fallback: true,
            tls: Some(OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        options
            .headers
            .insert("X-Client".into(), serde_json::json!("rust-h3"));
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client =
            DownloadClient::new(dialer, DownloadOptions { client: options })
                .unwrap();
        let mut response = client
            .request_stream(
                hyper::Method::GET,
                &format!("https://{address}/rules.srs"),
                &hyper::HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.chunk().await.unwrap(),
            Some(Bytes::from_static(b"rule-set-h3"))
        );
        assert_eq!(response.chunk().await.unwrap(), None);
        let _ = done_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pooled_downloader_reuses_http3_session_and_reset_redials() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = RustlsServerConfig::builder_with_provider(Arc::new(
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
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_accepted = accepted.clone();
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..2 {
                let connection =
                    endpoint.accept().await.unwrap().await.unwrap();
                server_accepted.fetch_add(1, Ordering::Relaxed);
                connections.push(tokio::spawn(async move {
                    let mut http3 = h3::server::Connection::new(
                        h3_quinn::Connection::new(connection),
                    )
                    .await
                    .unwrap();
                    while let Ok(Some(resolver)) = http3.accept().await {
                        let (request, mut stream) =
                            resolver.resolve_request().await.unwrap();
                        assert_eq!(request.method(), hyper::Method::GET);
                        assert_eq!(request.uri().path(), "/rules.srs");
                        stream
                            .send_response(
                                Response::builder()
                                    .status(hyper::StatusCode::OK)
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        stream
                            .send_data(Bytes::from_static(
                                b"pooled-rule-set-h3",
                            ))
                            .await
                            .unwrap();
                        stream.finish().await.unwrap();
                    }
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });
        let options = HttpClientOptions {
            version: 3,
            disable_version_fallback: true,
            tls: Some(OutboundTlsOptions {
                insecure: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let dialer: Arc<dyn Dialer> =
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
        let client =
            DownloadClient::new(dialer, DownloadOptions { client: options })
                .unwrap();
        let url = format!("https://{address}/rules.srs");
        for _ in 0..2 {
            assert_eq!(
                client
                    .download(&url, &hyper::HeaderMap::new())
                    .await
                    .unwrap()
                    .body,
                Bytes::from_static(b"pooled-rule-set-h3")
            );
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        client.reset().await;
        assert_eq!(
            client
                .download(&url, &hyper::HeaderMap::new())
                .await
                .unwrap()
                .body,
            Bytes::from_static(b"pooled-rule-set-h3")
        );
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
        drop(client);
        server.await.unwrap();
    }
}
