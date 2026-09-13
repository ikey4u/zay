//! OATH software-token generation used by OpenConnect authentication.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use data_encoding::BASE32_NOPAD;
use hmac13::{Hmac, Mac};
use sha1_11::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use url::Url;

pub trait AnyConnectSoftwareTokenGenerator: Send {
    fn token_type(&self) -> &'static str;
    fn can_generate(&self, message: &str) -> bool;
    fn generate(&mut self, message: &str) -> Result<String, OathTokenError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OathTokenError {
    #[error("unsupported OpenConnect OATH token mode: {0}")]
    UnsupportedMode(String),
    #[error("OATH software token requires a base32 secret")]
    MissingSecret,
    #[error("invalid OATH base32 secret: {0}")]
    InvalidSecret(String),
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error(
        "otpauth token type {actual} does not match configured mode {expected}"
    )]
    ModeMismatch { actual: String, expected: String },
    #[error("unsupported otpauth HMAC algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("unsupported otpauth token digit count: {0}")]
    UnsupportedDigits(u32),
    #[error("otpauth token period must be positive")]
    InvalidPeriod,
    #[error("invalid otpauth parameter {name}: {value}")]
    InvalidParameter { name: &'static str, value: String },
    #[error("automatic software token attempt limit reached")]
    AttemptLimit,
    #[error("software token clock is before the Unix epoch")]
    InvalidClock,
    #[error("software token time range is exhausted")]
    TimeExhausted,
    #[error("HOTP counter is exhausted")]
    CounterExhausted,
    #[error("RSA SecurID software token: {0}")]
    SecurId(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OathMode {
    Totp,
    Hotp,
}

impl OathMode {
    fn parse(mode: &str) -> Result<Self, OathTokenError> {
        match mode {
            "totp" => Ok(Self::Totp),
            "hotp" => Ok(Self::Hotp),
            other => Err(OathTokenError::UnsupportedMode(other.into())),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OathAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug)]
struct OathConfiguration {
    mode: OathMode,
    secret: Vec<u8>,
    algorithm: OathAlgorithm,
    digits: u32,
    period: u64,
}

/// Parsed token configuration whose HOTP counter survives authentication
/// retries and tunnel reauthentication.
#[derive(Debug, Clone)]
pub struct OpenConnectOathTokenFactory {
    configuration: Arc<OathConfiguration>,
    counter: Arc<AtomicU64>,
}

impl OpenConnectOathTokenFactory {
    pub fn new(
        mode: &str,
        secret: &str,
        configured_counter: u64,
    ) -> Result<Self, OathTokenError> {
        let mode = OathMode::parse(mode)?;
        let (configuration, uri_counter) = parse_configuration(mode, secret)?;
        let counter = if configured_counter == 0 {
            uri_counter.unwrap_or(0)
        } else {
            configured_counter
        };
        Ok(Self {
            configuration: Arc::new(configuration),
            counter: Arc::new(AtomicU64::new(counter)),
        })
    }

    pub fn generator(&self) -> OpenConnectOathTokenGenerator {
        OpenConnectOathTokenGenerator {
            configuration: self.configuration.clone(),
            counter: self.counter.clone(),
            attempts: 0,
            first_generation_time: 0,
        }
    }

    pub fn current_counter(&self) -> u64 {
        self.counter.load(Ordering::Acquire)
    }
}

pub struct OpenConnectOathTokenGenerator {
    configuration: Arc<OathConfiguration>,
    counter: Arc<AtomicU64>,
    attempts: u8,
    first_generation_time: u64,
}

impl AnyConnectSoftwareTokenGenerator for OpenConnectOathTokenGenerator {
    fn token_type(&self) -> &'static str {
        self.configuration.mode.as_str()
    }

    fn can_generate(&self, _message: &str) -> bool {
        self.attempts < 2
    }

    fn generate(&mut self, message: &str) -> Result<String, OathTokenError> {
        if !self.can_generate(message) {
            return Err(OathTokenError::AttemptLimit);
        }
        let code = match self.configuration.mode {
            OathMode::Totp => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| OathTokenError::InvalidClock)?
                    .as_secs();
                let generation_time = if self.attempts == 0 {
                    self.first_generation_time = now;
                    now
                } else {
                    self.first_generation_time
                        .checked_add(self.configuration.period)
                        .ok_or(OathTokenError::TimeExhausted)?
                };
                generate_code(
                    &self.configuration,
                    generation_time / self.configuration.period,
                )?
            }
            OathMode::Hotp => loop {
                let counter = self.counter.load(Ordering::Acquire);
                if counter == u64::MAX {
                    return Err(OathTokenError::CounterExhausted);
                }
                let code = generate_code(&self.configuration, counter)?;
                if self
                    .counter
                    .compare_exchange(
                        counter,
                        counter + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    break code;
                }
            },
        };
        self.attempts += 1;
        Ok(code)
    }
}

fn parse_configuration(
    mode: OathMode,
    secret: &str,
) -> Result<(OathConfiguration, Option<u64>), OathTokenError> {
    let trimmed = secret.trim();
    if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        return parse_otpauth(mode, trimmed);
    }
    Ok((
        OathConfiguration {
            mode,
            secret: decode_secret(trimmed)?,
            algorithm: OathAlgorithm::Sha1,
            digits: 6,
            period: 30,
        },
        None,
    ))
}

fn parse_otpauth(
    mode: OathMode,
    value: &str,
) -> Result<(OathConfiguration, Option<u64>), OathTokenError> {
    let uri = Url::parse(value)
        .map_err(|error| OathTokenError::InvalidUri(error.to_string()))?;
    let actual_mode = uri.host_str().unwrap_or_default().to_ascii_lowercase();
    if actual_mode != mode.as_str() {
        return Err(OathTokenError::ModeMismatch {
            actual: actual_mode,
            expected: mode.as_str().into(),
        });
    }
    let parameter = |name: &str| {
        uri.query_pairs()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.into_owned())
    };
    let secret = decode_secret(parameter("secret").as_deref().unwrap_or(""))?;
    let algorithm = match parameter("algorithm")
        .unwrap_or_else(|| "SHA1".into())
        .to_ascii_uppercase()
        .as_str()
    {
        "SHA1" => OathAlgorithm::Sha1,
        "SHA256" => OathAlgorithm::Sha256,
        "SHA512" => OathAlgorithm::Sha512,
        other => {
            return Err(OathTokenError::UnsupportedAlgorithm(other.into()));
        }
    };
    let digits =
        parse_u32_parameter(parameter("digits"), "digits")?.unwrap_or(6);
    if !matches!(digits, 6 | 8) {
        return Err(OathTokenError::UnsupportedDigits(digits));
    }
    let period =
        parse_u64_parameter(parameter("period"), "period")?.unwrap_or(30);
    if period == 0 {
        return Err(OathTokenError::InvalidPeriod);
    }
    let counter = parse_u64_parameter(parameter("counter"), "counter")?;
    Ok((
        OathConfiguration {
            mode,
            secret,
            algorithm,
            digits,
            period,
        },
        counter,
    ))
}

fn parse_u32_parameter(
    value: Option<String>,
    name: &'static str,
) -> Result<Option<u32>, OathTokenError> {
    value
        .map(|value| {
            value
                .parse()
                .map_err(|_| OathTokenError::InvalidParameter { name, value })
        })
        .transpose()
}

fn parse_u64_parameter(
    value: Option<String>,
    name: &'static str,
) -> Result<Option<u64>, OathTokenError> {
    value
        .map(|value| {
            value
                .parse()
                .map_err(|_| OathTokenError::InvalidParameter { name, value })
        })
        .transpose()
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, OathTokenError> {
    let mut normalized = secret.trim();
    if normalized
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("base32:"))
    {
        normalized = &normalized[7..];
    }
    let normalized =
        normalized.trim().trim_end_matches('=').to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(OathTokenError::MissingSecret);
    }
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|error| OathTokenError::InvalidSecret(error.to_string()))
}

fn generate_code(
    configuration: &OathConfiguration,
    counter: u64,
) -> Result<String, OathTokenError> {
    let message = counter.to_be_bytes();
    let digest = match configuration.algorithm {
        OathAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as hmac13::KeyInit>::new_from_slice(
                &configuration.secret,
            )
            .map_err(|error| {
                OathTokenError::InvalidSecret(error.to_string())
            })?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        OathAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as hmac13::KeyInit>::new_from_slice(
                &configuration.secret,
            )
            .map_err(|error| {
                OathTokenError::InvalidSecret(error.to_string())
            })?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        OathAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as hmac13::KeyInit>::new_from_slice(
                &configuration.secret,
            )
            .map_err(|error| {
                OathTokenError::InvalidSecret(error.to_string())
            })?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .expect("HMAC dynamic truncation always has four bytes"),
    ) & 0x7fff_ffff;
    let modulus = 10_u32.pow(configuration.digits);
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = configuration.digits as usize
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4226_hotp_vectors_and_counter_persistence() {
        let factory = OpenConnectOathTokenFactory::new(
            "hotp",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            0,
        )
        .unwrap();
        let mut generator = factory.generator();
        assert_eq!(generator.generate("").unwrap(), "755224");
        assert_eq!(generator.generate("").unwrap(), "287082");
        assert_eq!(factory.current_counter(), 2);
        assert_eq!(
            generator.generate("").unwrap_err(),
            OathTokenError::AttemptLimit
        );
        assert_eq!(factory.generator().generate("").unwrap(), "359152");
    }

    #[test]
    fn rfc_6238_totp_sha1_vector() {
        let (configuration, _) = parse_configuration(
            OathMode::Totp,
            "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30",
        )
        .unwrap();
        assert_eq!(generate_code(&configuration, 59 / 30).unwrap(), "94287082");
    }

    #[test]
    fn otpauth_mode_and_parameters_are_validated() {
        let mismatch = OpenConnectOathTokenFactory::new(
            "totp",
            "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=7",
            0,
        )
        .unwrap_err();
        assert!(matches!(mismatch, OathTokenError::ModeMismatch { .. }));
        assert!(
            OpenConnectOathTokenFactory::new(
                "totp",
                "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=7",
                0,
            )
            .is_err()
        );
    }
}
