//! Certificate-provider HTTP client backed by a sing-box outbound dialer.

use std::{future::Future, pin::Pin, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};

use crate::{
    adapter::Dialer,
    common::{
        http::{DownloadOptions, request_with_options_and_clock},
        ntp::NtpClock,
    },
    option::HttpClientOptions,
};

/// Shared HTTP transport for certificate providers.
///
/// In addition to the direct request helper used by Cloudflare Origin CA,
/// this implements `instant_acme::HttpClient` so ACME directory, account and
/// order traffic follows the same tagged/inline HTTP-client and outbound
/// routing rules as every other managed download.
#[derive(Clone)]
pub(super) struct CertificateHttpClient {
    dialer: Arc<dyn Dialer>,
    options: DownloadOptions,
    clock: Option<NtpClock>,
}

impl CertificateHttpClient {
    #[cfg(test)]
    pub(super) fn new(
        dialer: Arc<dyn Dialer>,
        client: HttpClientOptions,
    ) -> Self {
        Self::new_with_clock(dialer, client, None)
    }

    pub(super) fn new_with_clock(
        dialer: Arc<dyn Dialer>,
        client: HttpClientOptions,
        clock: Option<NtpClock>,
    ) -> Self {
        Self {
            dialer,
            options: DownloadOptions { client },
            clock,
        }
    }

    pub(super) async fn request(
        &self,
        method: http::Method,
        source: &str,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> std::io::Result<crate::common::http::DownloadResponse> {
        request_with_options_and_clock(
            self.dialer.clone(),
            method,
            source,
            headers,
            body,
            &self.options,
            self.clock.clone(),
        )
        .await
    }
}

impl instant_acme::HttpClient for CertificateHttpClient {
    fn request(
        &self,
        request: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        instant_acme::BytesResponse,
                        instant_acme::Error,
                    >,
                > + Send,
        >,
    > {
        let client = self.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let body = body
                .collect()
                .await
                .expect("instant-acme Bytes request body is infallible")
                .to_bytes();
            let response = client
                .request(
                    parts.method,
                    &parts.uri.to_string(),
                    &parts.headers,
                    body,
                )
                .await
                .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
            let mut translated = http::Response::builder()
                .status(response.status)
                .body(Full::new(response.body))
                .expect("valid certificate HTTP response");
            *translated.headers_mut() = response.headers;
            Ok(instant_acme::BytesResponse::from(translated))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Arc};

    use crate::{
        option::{DirectOutboundOptions, HttpClientOptions},
        protocol::direct::DirectOutbound,
    };
    use http_body_util::{BodyExt as _, Full};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;

    use super::CertificateHttpClient;

    #[tokio::test]
    async fn translates_instant_acme_requests_through_the_shared_dialer() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request: Request<Incoming>| async move {
                        assert_eq!(request.method(), http::Method::POST);
                        assert_eq!(request.uri(), "/new-account?attempt=1");
                        assert_eq!(request.headers()["x-acme-test"], "present");
                        let body = request.into_body().collect().await.unwrap();
                        assert_eq!(body.to_bytes(), "signed-payload");
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(http::StatusCode::CREATED)
                                .header("replay-nonce", "nonce-1")
                                .body(Full::new(bytes::Bytes::from_static(
                                    b"response-body",
                                )))
                                .unwrap(),
                        )
                    }),
                )
                .await
                .unwrap();
        });
        let client = CertificateHttpClient::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            HttpClientOptions::default(),
        );
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{address}/new-account?attempt=1"))
            .header("x-acme-test", "present")
            .body(instant_acme::BodyWrapper::from(b"signed-payload".to_vec()))
            .unwrap();
        let mut response = instant_acme::HttpClient::request(&client, request)
            .await
            .unwrap();
        assert_eq!(response.parts.status, http::StatusCode::CREATED);
        assert_eq!(response.parts.headers["replay-nonce"], "nonce-1");
        assert_eq!(response.body.into_bytes().await.unwrap(), "response-body");
        server.await.unwrap();
    }
}
