//! Minimal RFC 8555 transport used when the configured account key is not
//! supported by `instant-acme`.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, header};
use serde_json::{Value, json};

use super::{CertificateHttpClient, acme_signer::AcmeAccountSigner};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

pub(super) struct AcmeResponse {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Bytes,
}

impl AcmeResponse {
    pub(super) fn json(&self) -> Result<Value, BoxError> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub(super) fn location(&self) -> Result<String, BoxError> {
        Ok(self
            .headers
            .get(header::LOCATION)
            .ok_or("ACME response is missing Location")?
            .to_str()?
            .to_owned())
    }

    pub(super) fn ensure_success(
        self,
        operation: &str,
    ) -> Result<Self, BoxError> {
        if self.status.is_success() {
            return Ok(self);
        }
        let problem = serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|value| {
                value
                    .get("detail")
                    .and_then(Value::as_str)
                    .or_else(|| value.get("type").and_then(Value::as_str))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&self.body).into());
        Err(
            format!("{operation} failed with HTTP {}: {problem}", self.status)
                .into(),
        )
    }

    pub(super) fn retry_delay(&self) -> Duration {
        self.headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(1))
            .min(Duration::from_secs(10))
    }
}

pub(super) struct AcmeSession {
    http: CertificateHttpClient,
    directory: Directory,
    signer: AcmeAccountSigner,
    account_url: Option<String>,
    nonce: Option<String>,
}

impl AcmeSession {
    pub(super) async fn connect(
        http: CertificateHttpClient,
        directory_url: &str,
        signer: AcmeAccountSigner,
    ) -> Result<Self, BoxError> {
        let response = http
            .request(
                Method::GET,
                directory_url,
                &HeaderMap::new(),
                Bytes::new(),
            )
            .await?;
        if !response.status.is_success() {
            return Err(format!(
                "fetch ACME directory failed with HTTP {}",
                response.status
            )
            .into());
        }
        Ok(Self {
            http,
            directory: serde_json::from_slice(&response.body)?,
            signer,
            account_url: None,
            nonce: response
                .headers
                .get("replay-nonce")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        })
    }

    pub(super) fn set_account_url(&mut self, account_url: String) {
        self.account_url = Some(account_url);
    }

    pub(super) fn new_order_url(&self) -> &str {
        &self.directory.new_order
    }

    pub(super) fn thumbprint(&self) -> &str {
        self.signer.thumbprint()
    }

    pub(super) async fn lookup_existing_account(
        &mut self,
    ) -> Result<String, BoxError> {
        let url = self.directory.new_account.clone();
        let response = self
            .signed_post(&url, Some(&json!({"onlyReturnExisting": true})), true)
            .await?
            .ensure_success("look up ACME account")?;
        let location = response.location()?;
        self.account_url = Some(location.clone());
        Ok(location)
    }

    pub(super) async fn post(
        &mut self,
        url: &str,
        payload: Option<&Value>,
    ) -> Result<AcmeResponse, BoxError> {
        if self.account_url.is_none() {
            return Err("ACME account URL is not initialized".into());
        }
        self.signed_post(url, payload, false).await
    }

    async fn signed_post(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        use_jwk: bool,
    ) -> Result<AcmeResponse, BoxError> {
        for _ in 0..3 {
            let nonce = match self.nonce.take() {
                Some(nonce) => nonce,
                None => self.fetch_nonce().await?,
            };
            let mut protected = json!({
                "alg": self.signer.algorithm(),
                "nonce": nonce,
                "url": url,
            });
            if use_jwk {
                protected["jwk"] = self.signer.jwk().clone();
            } else {
                protected["kid"] = Value::String(
                    self.account_url
                        .as_ref()
                        .expect("checked account URL")
                        .clone(),
                );
            }
            let protected =
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
            let payload = match payload {
                Some(payload) => {
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?)
                }
                None => String::new(),
            };
            let signing_input = format!("{protected}.{payload}");
            let signature = URL_SAFE_NO_PAD
                .encode(self.signer.sign(signing_input.as_bytes())?);
            let body = serde_json::to_vec(&json!({
                "protected": protected,
                "payload": payload,
                "signature": signature,
            }))?;
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/jose+json"),
            );
            let response = self
                .http
                .request(Method::POST, url, &headers, Bytes::from(body))
                .await?;
            self.nonce = response
                .headers
                .get("replay-nonce")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let response = AcmeResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            };
            if response.status != StatusCode::BAD_REQUEST
                || !is_bad_nonce(&response.body)
            {
                return Ok(response);
            }
        }
        Err("ACME server rejected three consecutive nonces".into())
    }

    async fn fetch_nonce(&self) -> Result<String, BoxError> {
        let response = self
            .http
            .request(
                Method::HEAD,
                &self.directory.new_nonce,
                &HeaderMap::new(),
                Bytes::new(),
            )
            .await?;
        if !response.status.is_success() {
            return Err(format!(
                "fetch ACME nonce failed with HTTP {}",
                response.status
            )
            .into());
        }
        Ok(response
            .headers
            .get("replay-nonce")
            .ok_or("ACME nonce response is missing Replay-Nonce")?
            .to_str()?
            .to_owned())
    }
}

fn is_bad_nonce(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("type")?.as_str().map(str::to_owned))
        .is_some_and(|kind| kind == "urn:ietf:params:acme:error:badNonce")
}
