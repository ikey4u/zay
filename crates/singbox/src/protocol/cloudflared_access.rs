//! Cloudflare Access OIDC assertion validation for tunnel ingress rules.

use std::{
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::signature::{
    RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderMap;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::{
    adapter::Dialer,
    common::{
        certificate_store::CertificateStore,
        http::{DownloadOptions, request_with_options_and_clock},
        ntp::NtpClock,
    },
    option::{HttpClientOptions, OutboundTlsOptions},
};

use super::cloudflared_ingress::CloudflaredAccessConfig;

pub const CLOUDFLARED_ACCESS_JWT_ASSERTION_HEADER: &str =
    "Cf-Access-Jwt-Assertion";
pub const CLOUDFLARED_ACCESS_JWKS_PATH: &str = "/cdn-cgi/access/certs";
pub const CLOUDFLARED_ACCESS_MAX_JWKS_SIZE: usize = 1024 * 1024;

#[derive(Clone)]
struct RsaJwk {
    kid: String,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

#[derive(Default, Deserialize)]
struct JwkSet {
    #[serde(default)]
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    alg: String,
    #[serde(default, rename = "use")]
    usage: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn values(&self) -> &[String] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
}

#[derive(Deserialize)]
struct JwtClaims {
    iss: String,
    aud: Audience,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
}

struct ParsedJwt<'a> {
    signed: &'a [u8],
    header: JwtHeader,
    claims: JwtClaims,
    signature: Vec<u8>,
}

/// Cached RS256 OIDC validator matching cloudflared's production verifier.
pub struct CloudflaredAccessValidator {
    config: CloudflaredAccessConfig,
    issuer: String,
    dialer: Option<Arc<dyn Dialer>>,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
    keys: Mutex<Vec<RsaJwk>>,
}

impl CloudflaredAccessValidator {
    pub fn new(
        config: CloudflaredAccessConfig,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        Self::new_with_runtime_context(config, dialer, None, None)
    }

    pub(crate) fn new_with_runtime_context(
        config: CloudflaredAccessConfig,
        dialer: Arc<dyn Dialer>,
        ntp_clock: Option<NtpClock>,
        certificate_store: Option<CertificateStore>,
    ) -> Self {
        let issuer = cloudflared_access_issuer_url(
            &config.team_name,
            &config.environment,
        );
        Self {
            config,
            issuer,
            dialer: Some(dialer),
            ntp_clock,
            certificate_store,
            keys: Mutex::new(Vec::new()),
        }
    }

    /// Construct a deterministic validator from an already obtained JWKS.
    /// This is useful to embedders that pin or distribute Access keys.
    pub fn from_jwks(
        config: CloudflaredAccessConfig,
        jwks: &[u8],
    ) -> io::Result<Self> {
        let issuer = cloudflared_access_issuer_url(
            &config.team_name,
            &config.environment,
        );
        Ok(Self {
            config,
            issuer,
            dialer: None,
            ntp_clock: None,
            certificate_store: None,
            keys: Mutex::new(parse_jwks(jwks)?),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub async fn validate(&self, assertion: &str) -> io::Result<()> {
        if assertion.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "missing access jwt assertion",
            ));
        }
        let parsed = parse_jwt(assertion)?;
        if parsed.header.alg != "RS256" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "unsupported access JWT signing algorithm: {}",
                    parsed.header.alg
                ),
            ));
        }
        let mut keys = self.keys.lock().await;
        let mut verified = verify_with_keys(&parsed, &keys);
        if verified.is_err()
            && let Some(dialer) = &self.dialer
        {
            *keys = fetch_jwks(
                dialer.clone(),
                &self.issuer,
                self.ntp_clock.clone(),
                self.certificate_store.clone(),
            )
            .await?;
            verified = verify_with_keys(&parsed, &keys);
        }
        verified?;
        validate_claims(&parsed.claims, &self.issuer, &self.config.aud_tag)
    }
}

pub fn cloudflared_access_issuer_url(
    team_name: &str,
    environment: &str,
) -> String {
    if environment.eq_ignore_ascii_case("fed")
        || environment.eq_ignore_ascii_case("fips")
    {
        format!("https://{team_name}.fed.cloudflareaccess.com")
    } else {
        format!("https://{team_name}.cloudflareaccess.com")
    }
}

pub fn cloudflared_access_validator_key(
    config: &CloudflaredAccessConfig,
) -> String {
    format!(
        "{}|{}|{}",
        config.team_name,
        config.environment,
        config.aud_tag.join(",")
    )
}

async fn fetch_jwks(
    dialer: Arc<dyn Dialer>,
    issuer: &str,
    ntp_clock: Option<NtpClock>,
    certificate_store: Option<CertificateStore>,
) -> io::Result<Vec<RsaJwk>> {
    let mut tls = OutboundTlsOptions::default();
    tls.set_runtime_context(ntp_clock.clone(), certificate_store);
    let options = DownloadOptions {
        client: HttpClientOptions {
            tls: Some(tls),
            ..Default::default()
        },
    };
    let response = request_with_options_and_clock(
        dialer,
        http::Method::GET,
        &format!("{issuer}{CLOUDFLARED_ACCESS_JWKS_PATH}"),
        &HeaderMap::new(),
        bytes::Bytes::new(),
        &options,
        ntp_clock,
    )
    .await?;
    if response.status != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "Access JWKS endpoint returned {}",
            response.status
        )));
    }
    if response.body.len() > CLOUDFLARED_ACCESS_MAX_JWKS_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Access JWKS response is too large",
        ));
    }
    parse_jwks(&response.body)
}

fn parse_jwks(input: &[u8]) -> io::Result<Vec<RsaJwk>> {
    if input.len() > CLOUDFLARED_ACCESS_MAX_JWKS_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Access JWKS response is too large",
        ));
    }
    let set: JwkSet = serde_json::from_slice(input).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode Access JWKS: {error}"),
        )
    })?;
    let keys = set
        .keys
        .into_iter()
        .filter(|key| {
            key.kty == "RSA"
                && (key.alg.is_empty() || key.alg == "RS256")
                && (key.usage.is_empty() || key.usage == "sig")
                && !key.kid.is_empty()
        })
        .map(|key| {
            Ok(RsaJwk {
                kid: key.kid,
                modulus: URL_SAFE_NO_PAD.decode(key.n).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("decode Access JWK modulus: {error}"),
                    )
                })?,
                exponent: URL_SAFE_NO_PAD.decode(key.e).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("decode Access JWK exponent: {error}"),
                    )
                })?,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    if keys.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Access JWKS contains no usable RS256 keys",
        ));
    }
    Ok(keys)
}

fn parse_jwt(assertion: &str) -> io::Result<ParsedJwt<'_>> {
    let mut parts = assertion.split('.');
    let encoded_header = parts.next().unwrap_or_default();
    let encoded_claims = parts.next().unwrap_or_default();
    let encoded_signature = parts.next().unwrap_or_default();
    if encoded_header.is_empty()
        || encoded_claims.is_empty()
        || encoded_signature.is_empty()
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "malformed access JWT assertion",
        ));
    }
    let header = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(encoded_header).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "decode access JWT header",
            )
        })?,
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "decode access JWT header",
        )
    })?;
    let claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(encoded_claims).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "decode access JWT claims",
            )
        })?,
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "decode access JWT claims",
        )
    })?;
    let signature =
        URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "decode access JWT signature",
            )
        })?;
    let signed_length = encoded_header.len() + 1 + encoded_claims.len();
    Ok(ParsedJwt {
        signed: &assertion.as_bytes()[..signed_length],
        header,
        claims,
        signature,
    })
}

fn verify_with_keys(token: &ParsedJwt<'_>, keys: &[RsaJwk]) -> io::Result<()> {
    let key = keys
        .iter()
        .find(|key| key.kid == token.header.kid)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "access JWT signing key is unknown",
            )
        })?;
    RsaPublicKeyComponents {
        n: &key.modulus,
        e: &key.exponent,
    }
    .verify(&RSA_PKCS1_2048_8192_SHA256, token.signed, &token.signature)
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access JWT signature verification failed",
        )
    })
}

fn validate_claims(
    claims: &JwtClaims,
    issuer: &str,
    configured_audiences: &[String],
) -> io::Result<()> {
    if claims.iss != issuer {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access JWT issuer does not match configured team",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs() as i64;
    if claims.exp <= now {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access JWT is expired",
        ));
    }
    // coreos/go-oidc applies a five-minute future leeway to nbf.
    if claims
        .nbf
        .is_some_and(|not_before| not_before > now.saturating_add(300))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access JWT is not valid yet",
        ));
    }
    if !claims.aud.values().iter().any(|token_audience| {
        configured_audiences
            .iter()
            .any(|configured| configured == token_audience)
    }) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access token audience does not match configured aud_tag",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        rsa::KeySize,
        signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair},
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn signed_token(
        key: &RsaKeyPair,
        issuer: &str,
        audiences: serde_json::Value,
        expiry: i64,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg":"RS256", "kid":"key-1", "typ":"JWT"
            }))
            .unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss":issuer, "sub":"subject", "aud":audiences,
                "exp":expiry, "iat":expiry - 3600
            }))
            .unwrap(),
        );
        let signed = format!("{header}.{claims}");
        let mut signature = vec![0_u8; key.public_modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signed.as_bytes(),
            &mut signature,
        )
        .unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    #[tokio::test]
    async fn validates_rs256_issuer_expiry_and_audience() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let public = openssl::rsa::Rsa::public_key_from_der_pkcs1(
            key.public_key().as_ref(),
        )
        .unwrap();
        let jwks = serde_json::to_vec(&serde_json::json!({
            "keys":[{
                "kty":"RSA", "kid":"key-1", "use":"sig", "alg":"RS256",
                "n":URL_SAFE_NO_PAD.encode(public.n().to_vec()),
                "e":URL_SAFE_NO_PAD.encode(public.e().to_vec())
            }]
        }))
        .unwrap();
        let config = CloudflaredAccessConfig {
            required: true,
            team_name: "team".into(),
            aud_tag: vec!["aud-1".into()],
            environment: String::new(),
        };
        let validator =
            CloudflaredAccessValidator::from_jwks(config, &jwks).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let valid = signed_token(
            &key,
            validator.issuer(),
            serde_json::json!(["aud-1", "other"]),
            now + 3600,
        );
        validator.validate(&valid).await.unwrap();

        let wrong_audience = signed_token(
            &key,
            validator.issuer(),
            serde_json::json!("aud-2"),
            now + 3600,
        );
        assert!(validator.validate(&wrong_audience).await.is_err());
        let expired = signed_token(
            &key,
            validator.issuer(),
            serde_json::json!("aud-1"),
            now - 1,
        );
        assert!(validator.validate(&expired).await.is_err());
    }

    #[test]
    fn issuer_and_cache_key_match_upstream() {
        assert_eq!(
            cloudflared_access_issuer_url("team", "FiPs"),
            "https://team.fed.cloudflareaccess.com"
        );
        let config = CloudflaredAccessConfig {
            required: true,
            team_name: "team".into(),
            aud_tag: vec!["one".into(), "two".into()],
            environment: "fed".into(),
        };
        assert_eq!(
            cloudflared_access_validator_key(&config),
            "team|fed|one,two"
        );
    }
}
