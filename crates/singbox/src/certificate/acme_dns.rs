//! DNS-01 record provisioning for managed ACME certificates.

use std::{collections::BTreeMap, io, net::IpAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData,
};
use hmac13::{Hmac, Mac as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::option::{AcmeDns01ChallengeOptions, AcmeDns01CommonOptions};

use super::{CertificateHttpClient, CertificateProviderError};

const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";
const ALIDNS_API: &str = "https://alidns.aliyuncs.com/";
const ALIDNS_API_VERSION: &str = "2015-01-09";
const DEFAULT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROPAGATION_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(super) struct Dns01Solver {
    options: AcmeDns01ChallengeOptions,
    http: CertificateHttpClient,
    cloudflare_api: Arc<str>,
    alidns_api: Arc<str>,
}

pub(super) enum ProvisionedRecord {
    Cloudflare { zone_id: String, record_id: String },
    AliDns { record_id: String },
    AcmeDns,
}

impl Dns01Solver {
    pub(super) fn new(
        options: AcmeDns01ChallengeOptions,
        http: CertificateHttpClient,
    ) -> Result<Self, CertificateProviderError> {
        validate_options(&options)?;
        Ok(Self {
            options,
            http,
            cloudflare_api: CLOUDFLARE_API.into(),
            alidns_api: ALIDNS_API.into(),
        })
    }

    pub(super) fn record_name(&self, domain: &str) -> String {
        let common = self.options.common();
        if !common.override_domain.is_empty() {
            common.override_domain.trim_end_matches('.').to_owned()
        } else {
            format!(
                "_acme-challenge.{}",
                domain.trim_start_matches("*.").trim_end_matches('.')
            )
        }
    }

    pub(super) async fn present(
        &self,
        name: &str,
        value: &str,
    ) -> Result<ProvisionedRecord, BoxError> {
        match &self.options {
            AcmeDns01ChallengeOptions::Cloudflare {
                api_token,
                zone_token,
                common,
            } => {
                self.present_cloudflare(
                    name, value, api_token, zone_token, common,
                )
                .await
            }
            AcmeDns01ChallengeOptions::AcmeDns {
                username,
                password,
                subdomain,
                server_url,
                ..
            } => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "subdomain": subdomain,
                    "txt": value,
                }))?;
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    "x-api-user",
                    http::HeaderValue::from_str(username)?,
                );
                headers.insert(
                    "x-api-key",
                    http::HeaderValue::from_str(password)?,
                );
                headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
                let endpoint =
                    format!("{}/update", server_url.trim_end_matches('/'));
                let response = self
                    .http
                    .request(
                        http::Method::POST,
                        &endpoint,
                        &headers,
                        Bytes::from(body),
                    )
                    .await?;
                if response.status != http::StatusCode::OK {
                    return Err(format!(
                        "update ACME-DNS record: HTTP {}",
                        response.status
                    )
                    .into());
                }
                Ok(ProvisionedRecord::AcmeDns)
            }
            AcmeDns01ChallengeOptions::AliDns {
                access_key_id,
                access_key_secret,
                security_token,
                common,
                ..
            } => {
                self.present_alidns(
                    name,
                    value,
                    access_key_id,
                    access_key_secret,
                    security_token,
                    common,
                )
                .await
            }
        }
    }

    pub(super) async fn wait(
        &self,
        name: &str,
        value: &str,
    ) -> Result<(), BoxError> {
        let common = self.options.common();
        if let Some(delay) = positive_duration(common.propagation_delay) {
            tokio::time::sleep(delay).await;
        }
        if common.propagation_timeout.as_nanos() == -1 {
            return Ok(());
        }
        let timeout = positive_duration(common.propagation_timeout)
            .unwrap_or(DEFAULT_PROPAGATION_TIMEOUT);
        let resolver = propagation_resolver(common)?;
        tokio::time::timeout(timeout, async {
            loop {
                if let Ok(records) = resolver.txt_lookup(name).await
                    && records.answers().iter().any(|record| {
                        let RData::TXT(record) = &record.data else {
                            return false;
                        };
                        let bytes = record
                            .txt_data
                            .iter()
                            .flat_map(|part| part.iter().copied())
                            .collect::<Vec<_>>();
                        bytes == value.as_bytes()
                    })
                {
                    return;
                }
                tokio::time::sleep(PROPAGATION_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| {
            format!("timed out waiting for DNS-01 record {name:?} to propagate")
        })?;
        Ok(())
    }

    pub(super) async fn cleanup(
        &self,
        record: ProvisionedRecord,
    ) -> Result<(), BoxError> {
        match record {
            ProvisionedRecord::Cloudflare { zone_id, record_id } => {
                let api_token = match &self.options {
                    AcmeDns01ChallengeOptions::Cloudflare {
                        api_token, ..
                    } => api_token,
                    _ => unreachable!(
                        "Cloudflare cleanup has Cloudflare options"
                    ),
                };
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    http::header::AUTHORIZATION,
                    http::HeaderValue::from_str(&format!(
                        "Bearer {api_token}"
                    ))?,
                );
                let endpoint = format!(
                    "{}/zones/{zone_id}/dns_records/{record_id}",
                    self.cloudflare_api
                );
                let response = self
                    .http
                    .request(
                        http::Method::DELETE,
                        &endpoint,
                        &headers,
                        Bytes::new(),
                    )
                    .await?;
                decode_cloudflare::<serde_json::Value>(response)?;
            }
            ProvisionedRecord::AliDns { record_id } => {
                let (access_key_id, access_key_secret, security_token) =
                    match &self.options {
                        AcmeDns01ChallengeOptions::AliDns {
                            access_key_id,
                            access_key_secret,
                            security_token,
                            ..
                        } => (
                            access_key_id.as_str(),
                            access_key_secret.as_str(),
                            security_token.as_str(),
                        ),
                        _ => unreachable!("AliDNS cleanup has AliDNS options"),
                    };
                let response = self
                    .alidns_request(
                        "DeleteDomainRecord",
                        BTreeMap::from([("RecordId", record_id.as_str())]),
                        access_key_id,
                        access_key_secret,
                        security_token,
                    )
                    .await?;
                decode_alidns(response)?;
            }
            ProvisionedRecord::AcmeDns => {}
        }
        Ok(())
    }

    async fn present_alidns(
        &self,
        name: &str,
        value: &str,
        access_key_id: &str,
        access_key_secret: &str,
        security_token: &str,
        common: &AcmeDns01CommonOptions,
    ) -> Result<ProvisionedRecord, BoxError> {
        let zone = self
            .find_alidns_zone(
                name,
                access_key_id,
                access_key_secret,
                security_token,
            )
            .await?;
        let suffix = format!(".{}", zone.domain_name);
        let relative_name = name
            .trim_end_matches('.')
            .strip_suffix(&suffix)
            .filter(|value| !value.is_empty())
            .unwrap_or("@");
        let requested_ttl = positive_duration(common.ttl)
            .map_or(0, |duration| duration.as_secs());
        let ttl = if requested_ttl == 0 {
            600
        } else if zone.enterprise {
            requested_ttl
        } else {
            requested_ttl.max(600)
        };
        let ttl = ttl.to_string();
        let response = self
            .alidns_request(
                "AddDomainRecord",
                BTreeMap::from([
                    ("DomainName", zone.domain_name.as_str()),
                    ("RR", relative_name),
                    ("TTL", ttl.as_str()),
                    ("Type", "TXT"),
                    ("Value", value),
                ]),
                access_key_id,
                access_key_secret,
                security_token,
            )
            .await?;
        let result = decode_alidns(response)?;
        if result.record_id.is_empty() {
            return Err("AliDNS response is missing RecordId".into());
        }
        Ok(ProvisionedRecord::AliDns {
            record_id: result.record_id,
        })
    }

    async fn find_alidns_zone(
        &self,
        name: &str,
        access_key_id: &str,
        access_key_secret: &str,
        security_token: &str,
    ) -> Result<AliDnsZone, BoxError> {
        let labels = name.trim_end_matches('.').split('.').collect::<Vec<_>>();
        for offset in 0..labels.len().saturating_sub(1) {
            let candidate = labels[offset..].join(".");
            let response = self
                .alidns_request(
                    "DescribeDomains",
                    BTreeMap::from([
                        ("KeyWord", candidate.as_str()),
                        ("SearchMode", "EXACT"),
                    ]),
                    access_key_id,
                    access_key_secret,
                    security_token,
                )
                .await?;
            let result = decode_alidns(response)?;
            if let Some(domain) = result.domains.domain.into_iter().next() {
                return Ok(AliDnsZone {
                    domain_name: domain.domain_name,
                    enterprise: matches!(
                        domain.version_code.as_str(),
                        "enterprise_advanced"
                            | "version_enterprise_advanced"
                            | "enterprise_basic"
                            | "version_enterprise_basic"
                    ),
                });
            }
        }
        Err(format!("could not determine AliDNS zone for {name:?}").into())
    }

    async fn alidns_request(
        &self,
        action: &str,
        parameters: BTreeMap<&str, &str>,
        access_key_id: &str,
        access_key_secret: &str,
        security_token: &str,
    ) -> Result<crate::common::http::DownloadResponse, BoxError> {
        let endpoint = url::Url::parse(&self.alidns_api)?;
        let body = form_body(&parameters);
        let content_hash = sha256_hex(body.as_bytes());
        let host = match endpoint.port() {
            Some(port) => format!(
                "{}:{port}",
                endpoint
                    .host_str()
                    .ok_or("AliDNS endpoint is missing a host")?
            ),
            None => endpoint
                .host_str()
                .ok_or("AliDNS endpoint is missing a host")?
                .to_owned(),
        };
        let mut signed_headers = BTreeMap::from([
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("host", host),
            ("x-acs-action", action.to_owned()),
            ("x-acs-content-sha256", content_hash.clone()),
            (
                "x-acs-date",
                OffsetDateTime::now_utc()
                    .replace_nanosecond(0)?
                    .format(&Rfc3339)?,
            ),
            ("x-acs-signature-nonce", uuid::Uuid::new_v4().to_string()),
            ("x-acs-version", ALIDNS_API_VERSION.to_owned()),
        ]);
        if !security_token.is_empty() {
            signed_headers
                .insert("x-acs-security-token", security_token.to_owned());
        }
        let signed_header_names =
            signed_headers.keys().copied().collect::<Vec<_>>().join(";");
        let canonical_headers = signed_headers
            .iter()
            .map(|(key, value)| format!("{key}:{value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let canonical_request = format!(
            "POST\n{}\n\n{canonical_headers}\n\n{signed_header_names}\n{content_hash}",
            endpoint.path()
        );
        let string_to_sign =
            format!("ACS3-HMAC-SHA256\n{}", sha256_hex(canonical_request));
        let mut mac = <Hmac<Sha256> as hmac13::KeyInit>::new_from_slice(
            access_key_secret.as_bytes(),
        )?;
        mac.update(string_to_sign.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let authorization = format!(
            "ACS3-HMAC-SHA256 Credential={access_key_id},SignedHeaders={signed_header_names},Signature={signature}"
        );
        let mut headers = http::HeaderMap::new();
        for (key, value) in signed_headers {
            headers.insert(
                http::HeaderName::from_bytes(key.as_bytes())?,
                http::HeaderValue::from_str(&value)?,
            );
        }
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&authorization)?,
        );
        self.http
            .request(
                http::Method::POST,
                endpoint.as_str(),
                &headers,
                Bytes::from(body),
            )
            .await
            .map_err(Into::into)
    }

    async fn present_cloudflare(
        &self,
        name: &str,
        value: &str,
        api_token: &str,
        zone_token: &str,
        common: &AcmeDns01CommonOptions,
    ) -> Result<ProvisionedRecord, BoxError> {
        let zone = self
            .find_cloudflare_zone(
                name,
                if zone_token.is_empty() {
                    api_token
                } else {
                    zone_token
                },
            )
            .await?;
        let mut body = serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": format!("\"{value}\""),
        });
        if let Some(ttl) = positive_duration(common.ttl) {
            body["ttl"] = serde_json::Value::from(ttl.as_secs());
        }
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {api_token}"))?,
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        let endpoint =
            format!("{}/zones/{}/dns_records", self.cloudflare_api, zone.id);
        let response = self
            .http
            .request(
                http::Method::POST,
                &endpoint,
                &headers,
                Bytes::from(serde_json::to_vec(&body)?),
            )
            .await?;
        let record: CloudflareRecord = decode_cloudflare(response)?;
        if record.id.is_empty() {
            return Err("Cloudflare DNS response is missing record id".into());
        }
        Ok(ProvisionedRecord::Cloudflare {
            zone_id: zone.id,
            record_id: record.id,
        })
    }

    async fn find_cloudflare_zone(
        &self,
        name: &str,
        token: &str,
    ) -> Result<CloudflareZone, BoxError> {
        let labels = name.trim_end_matches('.').split('.').collect::<Vec<_>>();
        for offset in 0..labels.len().saturating_sub(1) {
            let candidate = labels[offset..].join(".");
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("name", &candidate)
                .finish();
            let endpoint = format!("{}/zones?{query}", self.cloudflare_api);
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_str(&format!("Bearer {token}"))?,
            );
            let response = self
                .http
                .request(http::Method::GET, &endpoint, &headers, Bytes::new())
                .await?;
            let zones: Vec<CloudflareZone> = decode_cloudflare(response)?;
            if zones.len() == 1 {
                return Ok(zones.into_iter().next().expect("one zone"));
            }
        }
        Err(format!("could not determine Cloudflare zone for {name:?}").into())
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Deserialize)]
struct CloudflareEnvelope<T> {
    #[serde(default)]
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

#[derive(Deserialize)]
struct CloudflareError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct CloudflareZone {
    id: String,
}

#[derive(Deserialize)]
struct CloudflareRecord {
    id: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliDnsResult {
    #[serde(default, rename = "RecordId")]
    record_id: String,
    #[serde(default)]
    domains: AliDnsDomains,
    #[serde(default, rename = "Code")]
    code: String,
    #[serde(default, rename = "Message")]
    message: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliDnsDomains {
    #[serde(default)]
    domain: Vec<AliDnsDomain>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliDnsDomain {
    domain_name: String,
    #[serde(default)]
    version_code: String,
}

struct AliDnsZone {
    domain_name: String,
    enterprise: bool,
}

fn decode_cloudflare<T: serde::de::DeserializeOwned>(
    response: crate::common::http::DownloadResponse,
) -> Result<T, BoxError> {
    let envelope: CloudflareEnvelope<T> =
        serde_json::from_slice(&response.body)?;
    if !response.status.is_success() || !envelope.success {
        let details = envelope
            .errors
            .iter()
            .map(|error| {
                if error.code == 0 {
                    error.message.clone()
                } else {
                    format!("{} (code {})", error.message, error.code)
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "Cloudflare DNS API returned HTTP {}{}{}",
            response.status,
            if details.is_empty() { "" } else { ": " },
            details
        )
        .into());
    }
    envelope
        .result
        .ok_or_else(|| "Cloudflare DNS API response is missing result".into())
}

fn decode_alidns(
    response: crate::common::http::DownloadResponse,
) -> Result<AliDnsResult, BoxError> {
    let result: AliDnsResult = serde_json::from_slice(&response.body)?;
    if response.status != http::StatusCode::OK || !result.code.is_empty() {
        return Err(format!(
            "AliDNS API returned HTTP {}{}{}",
            response.status,
            if result.message.is_empty() { "" } else { ": " },
            result.message
        )
        .into());
    }
    Ok(result)
}

fn form_body(parameters: &BTreeMap<&str, &str>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .extend_pairs(parameters.iter().map(|(key, value)| (*key, *value)));
    serializer.finish()
}

fn sha256_hex(value: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(value.as_ref()))
}

fn positive_duration(value: crate::option::Duration) -> Option<Duration> {
    value.as_std().filter(|duration| !duration.is_zero())
}

fn propagation_resolver(
    common: &AcmeDns01CommonOptions,
) -> Result<TokioResolver, BoxError> {
    if common.resolvers.as_slice().is_empty() {
        return TokioResolver::builder_tokio()
            .map_err(|error| io::Error::other(error.to_string()))?
            .build()
            .map_err(|error| io::Error::other(error.to_string()).into());
    }
    let mut name_servers = Vec::new();
    for value in common.resolvers.as_slice() {
        let (ip, port) = match value.parse::<std::net::SocketAddr>() {
            Ok(address) => (address.ip(), address.port()),
            Err(_) => (value.parse::<IpAddr>()?, 53),
        };
        let mut udp = ConnectionConfig::udp();
        udp.port = port;
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = port;
        name_servers.push(NameServerConfig::new(ip, true, vec![udp, tcp]));
    }
    let mut config = ResolverConfig::default();
    config.name_servers = name_servers;
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|error| io::Error::other(error.to_string()).into())
}

fn validate_options(
    options: &AcmeDns01ChallengeOptions,
) -> Result<(), CertificateProviderError> {
    let common = options.common();
    if common.ttl.as_nanos() < 0 {
        return Err(CertificateProviderError::InvalidAcme(format!(
            "invalid ACME DNS01 ttl: {}",
            common.ttl
        )));
    }
    if common.propagation_delay.as_nanos() < 0 {
        return Err(CertificateProviderError::InvalidAcme(format!(
            "invalid ACME DNS01 propagation_delay: {}",
            common.propagation_delay
        )));
    }
    if common.propagation_timeout.as_nanos() < -1 {
        return Err(CertificateProviderError::InvalidAcme(format!(
            "invalid ACME DNS01 propagation_timeout: {}",
            common.propagation_timeout
        )));
    }
    match options {
        AcmeDns01ChallengeOptions::Cloudflare { api_token, .. }
            if api_token.is_empty() =>
        {
            Err(CertificateProviderError::InvalidAcme(
                "Cloudflare DNS-01 api_token cannot be empty".into(),
            ))
        }
        AcmeDns01ChallengeOptions::AcmeDns {
            username,
            password,
            subdomain,
            server_url,
            ..
        } if username.is_empty()
            || password.is_empty()
            || subdomain.is_empty()
            || server_url.is_empty() =>
        {
            Err(CertificateProviderError::InvalidAcme(
                "ACME-DNS username, password, subdomain and server_url cannot be empty"
                    .into(),
            ))
        }
        AcmeDns01ChallengeOptions::AliDns {
            access_key_id,
            access_key_secret,
            ..
        } if access_key_id.is_empty() || access_key_secret.is_empty() => {
            Err(CertificateProviderError::InvalidAcme(
                "AliDNS DNS-01 access_key_id and access_key_secret cannot be empty"
                    .into(),
            ))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http_body_util::{BodyExt as _, Full};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;

    use crate::option::{AcmeDns01ChallengeOptions, AcmeDns01CommonOptions};

    use super::{Dns01Solver, ProvisionedRecord};

    #[test]
    fn builds_wildcard_and_override_record_names() {
        let solver = Dns01Solver {
            options: AcmeDns01ChallengeOptions::Cloudflare {
                common: AcmeDns01CommonOptions::default(),
                api_token: "token".into(),
                zone_token: String::new(),
            },
            http: direct_http_client(),
            cloudflare_api: "http://invalid".into(),
            alidns_api: "http://invalid".into(),
        };
        assert_eq!(
            solver.record_name("*.service.example.com"),
            "_acme-challenge.service.example.com"
        );
        let mut overridden = solver;
        if let AcmeDns01ChallengeOptions::Cloudflare { common, .. } =
            &mut overridden.options
        {
            common.override_domain = "delegated.example.net.".into();
        }
        assert_eq!(
            overridden.record_name("service.example.com"),
            "delegated.example.net"
        );
    }

    #[tokio::test]
    async fn updates_acme_dns_with_upstream_headers_and_body() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request: Request<Incoming>| async move {
                        assert_eq!(request.uri(), "/update");
                        assert_eq!(request.headers()["x-api-user"], "user");
                        assert_eq!(request.headers()["x-api-key"], "pass");
                        let body = request.into_body().collect().await.unwrap();
                        let body: serde_json::Value =
                            serde_json::from_slice(&body.to_bytes()).unwrap();
                        assert_eq!(body["subdomain"], "assigned");
                        assert_eq!(body["txt"], "dns-value");
                        Ok::<_, Infallible>(Response::new(Full::new(
                            bytes::Bytes::new(),
                        )))
                    }),
                )
                .await
                .unwrap();
        });
        let solver = Dns01Solver::new(
            AcmeDns01ChallengeOptions::AcmeDns {
                common: AcmeDns01CommonOptions::default(),
                username: "user".into(),
                password: "pass".into(),
                subdomain: "assigned".into(),
                server_url: format!("http://{address}"),
            },
            direct_http_client(),
        )
        .unwrap();
        let record = solver
            .present("_acme-challenge.example.com", "dns-value")
            .await
            .unwrap();
        assert!(matches!(record, ProvisionedRecord::AcmeDns));
        solver.cleanup(record).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn creates_and_deletes_alidns_txt_record_with_acs3() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..5 {
                let (stream, _) = listener.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|request: Request<Incoming>| async move {
                            assert_eq!(request.method(), http::Method::POST);
                            assert_eq!(request.uri(), "/");
                            assert_eq!(
                                request.headers()["x-acs-version"],
                                "2015-01-09"
                            );
                            assert_eq!(
                                request.headers()["x-acs-security-token"],
                                "session-token"
                            );
                            let authorization = request.headers()
                                [http::header::AUTHORIZATION]
                                .to_str()
                                .unwrap();
                            assert!(authorization.starts_with(
                                "ACS3-HMAC-SHA256 Credential=access-id,"
                            ));
                            assert!(authorization.contains(
                                "SignedHeaders=content-type;host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version"
                            ));
                            let action = request.headers()["x-acs-action"]
                                .to_str()
                                .unwrap()
                                .to_owned();
                            let expected_hash = request.headers()
                                ["x-acs-content-sha256"]
                                .to_str()
                                .unwrap()
                                .to_owned();
                            let body = request
                                .into_body()
                                .collect()
                                .await
                                .unwrap()
                                .to_bytes();
                            assert_eq!(
                                expected_hash,
                                super::sha256_hex(body.as_ref())
                            );
                            let form =
                                url::form_urlencoded::parse(body.as_ref())
                                    .into_owned()
                                    .collect::<std::collections::HashMap<_, _>>();
                            let response = match action.as_str() {
                                "DescribeDomains" => {
                                    if form["KeyWord"] == "example.com" {
                                        serde_json::json!({
                                            "Domains": {"Domain": [{
                                                "DomainName": "example.com",
                                                "VersionCode": "mianfei"
                                            }]}
                                        })
                                    } else {
                                        serde_json::json!({
                                            "Domains": {"Domain": []}
                                        })
                                    }
                                }
                                "AddDomainRecord" => {
                                    assert_eq!(form["DomainName"], "example.com");
                                    assert_eq!(
                                        form["RR"],
                                        "_acme-challenge.service"
                                    );
                                    assert_eq!(form["Type"], "TXT");
                                    assert_eq!(form["Value"], "dns-value");
                                    assert_eq!(form["TTL"], "600");
                                    serde_json::json!({"RecordId":"record-id"})
                                }
                                "DeleteDomainRecord" => {
                                    assert_eq!(form["RecordId"], "record-id");
                                    serde_json::json!({"RecordId":"record-id"})
                                }
                                _ => panic!("unexpected AliDNS action {action}"),
                            };
                            Ok::<_, Infallible>(Response::new(Full::new(
                                bytes::Bytes::from(
                                    serde_json::to_vec(&response).unwrap(),
                                ),
                            )))
                        }),
                    )
                    .await
                    .unwrap();
            }
        });
        let common = AcmeDns01CommonOptions {
            ttl: crate::option::Duration::from_nanos(120_000_000_000),
            ..Default::default()
        };
        let mut solver = Dns01Solver::new(
            AcmeDns01ChallengeOptions::AliDns {
                common,
                access_key_id: "access-id".into(),
                access_key_secret: "access-secret".into(),
                region_id: "cn-hangzhou".into(),
                security_token: "session-token".into(),
            },
            direct_http_client(),
        )
        .unwrap();
        solver.alidns_api = format!("http://{address}/").into();
        let record = solver
            .present("_acme-challenge.service.example.com", "dns-value")
            .await
            .unwrap();
        solver.cleanup(record).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn observes_dns01_txt_record_through_configured_resolver() {
        use hickory_proto::{
            op::{Message, MessageType, OpCode},
            rr::{RData, Record, rdata::TXT},
            serialize::binary::{
                BinDecodable as _, BinDecoder, BinEncodable as _, BinEncoder,
            },
        };
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0_u8; 1024];
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request =
                Message::read(&mut BinDecoder::new(&bytes[..size])).unwrap();
            let mut response =
                Message::new(request.id, MessageType::Response, OpCode::Query);
            response.queries = request.queries.clone();
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                30,
                RData::TXT(TXT::new(vec!["dns-value".into()])),
            ));
            let mut output = Vec::new();
            response.emit(&mut BinEncoder::new(&mut output)).unwrap();
            socket.send_to(&output, peer).await.unwrap();
        });
        let common = AcmeDns01CommonOptions {
            propagation_timeout: crate::option::Duration::from_nanos(
                5_000_000_000,
            ),
            resolvers: crate::option::Listable(vec![
                resolver_address.to_string(),
            ]),
            ..Default::default()
        };
        let solver = Dns01Solver::new(
            AcmeDns01ChallengeOptions::Cloudflare {
                common,
                api_token: "token".into(),
                zone_token: String::new(),
            },
            direct_http_client(),
        )
        .unwrap();
        solver
            .wait("_acme-challenge.example.com", "dns-value")
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn creates_and_deletes_cloudflare_txt_record() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..5 {
                let (stream, _) = listener.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|request: Request<Incoming>| async move {
                            let method = request.method().clone();
                            let uri = request.uri().to_string();
                            let authorization = request.headers()
                                [http::header::AUTHORIZATION]
                                .to_str()
                                .unwrap()
                                .to_owned();
                            let body = request
                                .into_body()
                                .collect()
                                .await
                                .unwrap()
                                .to_bytes();
                            let result = if uri.starts_with("/zones?") {
                                assert_eq!(authorization, "Bearer zone-token");
                                if uri.contains("name=example.com") {
                                    serde_json::json!([{"id":"zone-id"}])
                                } else {
                                    serde_json::json!([])
                                }
                            } else if method == http::Method::POST {
                                assert_eq!(authorization, "Bearer dns-token");
                                let body: serde_json::Value =
                                    serde_json::from_slice(&body).unwrap();
                                assert_eq!(body["type"], "TXT");
                                assert_eq!(
                                    body["name"],
                                    "_acme-challenge.service.example.com"
                                );
                                assert_eq!(body["content"], "\"dns-value\"");
                                assert_eq!(body["ttl"], 120);
                                serde_json::json!({"id":"record-id"})
                            } else {
                                assert_eq!(method, http::Method::DELETE);
                                assert_eq!(authorization, "Bearer dns-token");
                                assert_eq!(
                                    uri,
                                    "/zones/zone-id/dns_records/record-id"
                                );
                                serde_json::json!({})
                            };
                            let response =
                                serde_json::to_vec(&serde_json::json!({
                                    "success": true,
                                    "errors": [],
                                    "result": result,
                                }))
                                .unwrap();
                            Ok::<_, Infallible>(Response::new(Full::new(
                                bytes::Bytes::from(response),
                            )))
                        }),
                    )
                    .await
                    .unwrap();
            }
        });
        let common = AcmeDns01CommonOptions {
            ttl: crate::option::Duration::from_nanos(120_000_000_000),
            ..Default::default()
        };
        let mut solver = Dns01Solver::new(
            AcmeDns01ChallengeOptions::Cloudflare {
                common,
                api_token: "dns-token".into(),
                zone_token: "zone-token".into(),
            },
            direct_http_client(),
        )
        .unwrap();
        solver.cloudflare_api = format!("http://{address}").into();
        let record = solver
            .present("_acme-challenge.service.example.com", "dns-value")
            .await
            .unwrap();
        solver.cleanup(record).await.unwrap();
        server.await.unwrap();
    }

    fn direct_http_client() -> super::CertificateHttpClient {
        use std::sync::Arc;

        use crate::{
            option::{DirectOutboundOptions, HttpClientOptions},
            protocol::direct::DirectOutbound,
        };

        super::CertificateHttpClient::new(
            Arc::new(DirectOutbound::new(DirectOutboundOptions::default())),
            HttpClientOptions::default(),
        )
    }
}
