//! Pulse Secure user-facing authentication forms and response encoding.

use std::{collections::BTreeMap, time::SystemTime};

use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    OpenConnectAuthPromptChoice, OpenConnectAuthPromptField,
    OpenConnectAuthPromptForm, OpenConnectAuthPromptKind,
    PULSE_AVP_EAP_MESSAGE, PULSE_EAP_RESPONSE, PULSE_EAP_TYPE_EXPANDED,
    PULSE_EAP_TYPE_GTC, PULSE_VENDOR_JUNIPER2, PulseIftError, append_pulse_avp,
    build_pulse_eap, parse_pulse_avps,
};

pub const PULSE_PROMPT_PRIMARY: u32 = 1;
pub const PULSE_PROMPT_USERNAME: u32 = 2;
pub const PULSE_PROMPT_PASSWORD: u32 = 4;
pub const PULSE_PROMPT_GTC_NEXT: u32 = 0x10000;
pub const PULSE_PROMPT_JUNIPER_2021: u32 = 0x20000;

pub const PULSE_JUNIPER_PASSWORD_CHANGE: u8 = 0x43;
pub const PULSE_JUNIPER_PASSWORD_REQUEST: u8 = 0x01;
pub const PULSE_JUNIPER_PASSWORD_RETRY: u8 = 0x81;
pub const PULSE_JUNIPER_PASSWORD_FAILURE: u8 = 0xc5;

pub const PULSE_REALM_SUBMISSION_KEY: &str = "pulse:realm";
pub const PULSE_REALM_CHOICE_SUBMISSION_KEY: &str = "pulse:realm-choice";
pub const PULSE_REGION_CHOICE_SUBMISSION_KEY: &str = "pulse:region-choice";
pub const PULSE_SESSION_SUBMISSION_KEY: &str = "pulse:session";
pub const PULSE_USERNAME_SUBMISSION_KEY: &str = "pulse:username";
pub const PULSE_PASSWORD_SUBMISSION_KEY: &str = "pulse:password";
pub const PULSE_OLD_PASSWORD_SUBMISSION_KEY: &str = "pulse:old-password";
pub const PULSE_NEW_PASSWORD_SUBMISSION_KEY: &str = "pulse:new-password";
pub const PULSE_VERIFY_PASSWORD_SUBMISSION_KEY: &str = "pulse:verify-password";
pub const PULSE_TOKEN_SUBMISSION_KEY: &str = "pulse:token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PulseChallengeKind {
    Unknown,
    RealmEntry,
    RealmChoice,
    RegionChoice,
    Password,
    PasswordChange,
    Gtc,
    Session,
    SignIn,
    Cookie,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseSessionChoice {
    pub identifier: String,
    pub source: String,
    pub created_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseAuthenticationChallenge {
    pub kind: PulseChallengeKind,
    pub outer_identifier: u8,
    pub inner_identifier: u8,
    pub prompt_flags: u32,
    pub user_prompt: String,
    pub password_prompt: String,
    pub gtc_prompt: String,
    pub gtc_next: bool,
    pub realm_choices: Vec<String>,
    pub region_choices: Vec<String>,
    pub sessions: Vec<PulseSessionChoice>,
    pub password_request_code: u8,
    pub error_message: String,
}

impl Default for PulseAuthenticationChallenge {
    fn default() -> Self {
        Self {
            kind: PulseChallengeKind::Unknown,
            outer_identifier: 0,
            inner_identifier: 0,
            prompt_flags: 0,
            user_prompt: String::new(),
            password_prompt: String::new(),
            gtc_prompt: String::new(),
            gtc_next: false,
            realm_choices: Vec::new(),
            region_choices: Vec::new(),
            sessions: Vec::new(),
            password_request_code: 0,
            error_message: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulseEncodedAuthenticationResponse {
    pub content: Vec<u8>,
    pub retry_message: Option<String>,
}

#[derive(Debug, Error)]
pub enum PulseFormError {
    #[error(transparent)]
    Wire(#[from] PulseIftError),
    #[error("Pulse authentication challenge has no user form")]
    NoUserForm,
    #[error("Pulse authentication challenge does not accept a form response")]
    ResponseNotAccepted,
    #[error("Pulse authentication response omitted {0}")]
    MissingResponse(&'static str),
    #[error("Pulse session timestamp has invalid length")]
    InvalidSessionTimestamp,
    #[error("Pulse session timestamp exceeds the supported range")]
    SessionTimestampOutOfRange,
    #[error("Pulse session choice omitted required fields")]
    IncompleteSessionChoice,
}

impl PulseAuthenticationChallenge {
    pub fn prompt_form(
        &self,
        token_can_generate: bool,
    ) -> Result<OpenConnectAuthPromptForm, PulseFormError> {
        match self.kind {
            PulseChallengeKind::RealmEntry => Ok(form(vec![field(
                PULSE_REALM_SUBMISSION_KEY,
                "realm",
                "Realm:",
                OpenConnectAuthPromptKind::Text,
            )])),
            PulseChallengeKind::RealmChoice => Ok(choice_form(
                PULSE_REALM_CHOICE_SUBMISSION_KEY,
                "realm_choice",
                "Realm:",
                &self.realm_choices,
            )),
            PulseChallengeKind::RegionChoice => Ok(choice_form(
                PULSE_REGION_CHOICE_SUBMISSION_KEY,
                "region_choice",
                "Region:",
                &self.region_choices,
            )),
            PulseChallengeKind::Session => {
                let options = self
                    .sessions
                    .iter()
                    .map(|session| OpenConnectAuthPromptChoice {
                        value: session.identifier.clone(),
                        label: format!(
                            "{} from {} at {:?}",
                            session.identifier,
                            session.source,
                            session.created_at
                        ),
                    })
                    .collect();
                Ok(form(vec![OpenConnectAuthPromptField {
                    submission_key: PULSE_SESSION_SUBMISSION_KEY.to_owned(),
                    name: "session_choice".to_owned(),
                    label: "Session:".to_owned(),
                    kind: OpenConnectAuthPromptKind::Select,
                    value: String::new(),
                    options,
                }]))
            }
            PulseChallengeKind::Password => Ok(self.password_form()),
            PulseChallengeKind::PasswordChange => {
                Ok(self.password_change_form())
            }
            PulseChallengeKind::Gtc => Ok(self.gtc_form(token_can_generate)),
            _ => Err(PulseFormError::NoUserForm),
        }
    }

    pub fn build_response(
        &self,
        values: &BTreeMap<String, String>,
    ) -> Result<PulseEncodedAuthenticationResponse, PulseFormError> {
        match self.kind {
            PulseChallengeKind::RealmEntry => {
                string_response(values, PULSE_REALM_SUBMISSION_KEY, 0xd50)
            }
            PulseChallengeKind::RealmChoice => string_response(
                values,
                PULSE_REALM_CHOICE_SUBMISSION_KEY,
                0xd50,
            ),
            PulseChallengeKind::RegionChoice => string_response(
                values,
                PULSE_REGION_CHOICE_SUBMISSION_KEY,
                0xd52,
            ),
            PulseChallengeKind::Session => {
                string_response(values, PULSE_SESSION_SUBMISSION_KEY, 0xd69)
            }
            PulseChallengeKind::Password => self.password_response(values),
            PulseChallengeKind::PasswordChange => {
                self.password_change_response(values)
            }
            PulseChallengeKind::Gtc => self.gtc_response(values),
            _ => Err(PulseFormError::ResponseNotAccepted),
        }
    }

    fn password_form(&self) -> OpenConnectAuthPromptForm {
        let primary = self.prompt_flags & PULSE_PROMPT_PRIMARY != 0;
        let mut fields = Vec::new();
        if self.prompt_flags & PULSE_PROMPT_USERNAME != 0 {
            let label = if self.user_prompt.is_empty() {
                if primary {
                    "Username:"
                } else {
                    "Secondary username:"
                }
            } else {
                &self.user_prompt
            };
            fields.push(field(
                PULSE_USERNAME_SUBMISSION_KEY,
                "username",
                label,
                OpenConnectAuthPromptKind::Text,
            ));
        }
        if self.prompt_flags & PULSE_PROMPT_PASSWORD != 0 {
            let label = if self.password_prompt.is_empty() {
                if primary {
                    "Password:"
                } else {
                    "Secondary password:"
                }
            } else {
                &self.password_prompt
            };
            fields.push(field(
                PULSE_PASSWORD_SUBMISSION_KEY,
                "password",
                label,
                OpenConnectAuthPromptKind::Password,
            ));
        }
        form(fields)
    }

    fn password_change_form(&self) -> OpenConnectAuthPromptForm {
        form(vec![
            field(
                PULSE_OLD_PASSWORD_SUBMISSION_KEY,
                "oldpass",
                "Current password:",
                OpenConnectAuthPromptKind::Password,
            ),
            field(
                PULSE_NEW_PASSWORD_SUBMISSION_KEY,
                "newpass1",
                "New password:",
                OpenConnectAuthPromptKind::Password,
            ),
            field(
                PULSE_VERIFY_PASSWORD_SUBMISSION_KEY,
                "newpass2",
                "Verify new password:",
                OpenConnectAuthPromptKind::Password,
            ),
        ])
    }

    fn gtc_form(&self, _token_can_generate: bool) -> OpenConnectAuthPromptForm {
        let primary = self.prompt_flags & PULSE_PROMPT_PRIMARY != 0;
        let mut fields = Vec::new();
        if self.prompt_flags & PULSE_PROMPT_USERNAME != 0 {
            let label = if self.user_prompt.is_empty() {
                if primary {
                    "Username:"
                } else {
                    "Secondary username:"
                }
            } else {
                &self.user_prompt
            };
            fields.push(field(
                PULSE_USERNAME_SUBMISSION_KEY,
                "username",
                label,
                OpenConnectAuthPromptKind::Text,
            ));
        }
        let label = if self.gtc_next {
            "Please enter response:"
        } else if !self.password_prompt.is_empty() {
            &self.password_prompt
        } else if primary {
            "Please enter your passcode:"
        } else {
            "Please enter your secondary token information:"
        };
        fields.push(field(
            PULSE_TOKEN_SUBMISSION_KEY,
            "tokencode",
            label,
            OpenConnectAuthPromptKind::Password,
        ));
        form(fields)
    }

    fn password_response(
        &self,
        values: &BTreeMap<String, String>,
    ) -> Result<PulseEncodedAuthenticationResponse, PulseFormError> {
        let mut content = Vec::new();
        if self.prompt_flags & PULSE_PROMPT_USERNAME != 0 {
            let username = required(values, PULSE_USERNAME_SUBMISSION_KEY)?;
            append_pulse_avp(
                &mut content,
                0xd6d,
                PULSE_VENDOR_JUNIPER2,
                username.as_bytes(),
            )?;
        }
        let password = if self.prompt_flags & PULSE_PROMPT_PASSWORD != 0 {
            required(values, PULSE_PASSWORD_SUBMISSION_KEY)?
        } else {
            ""
        };
        let password = Zeroizing::new(password.as_bytes().to_vec());
        let inner = if self.prompt_flags & PULSE_PROMPT_JUNIPER_2021 != 0 {
            let mut payload = Zeroizing::new(vec![0_u8; 19]);
            payload[0] = 1;
            let copied = password.len().min(18);
            payload[1..1 + copied].copy_from_slice(&password[..copied]);
            build_pulse_eap(
                PULSE_EAP_RESPONSE,
                self.inner_identifier,
                PULSE_EAP_TYPE_EXPANDED,
                5,
                &payload,
            )?
        } else {
            if password.len() > 253 {
                return Ok(retry("Password exceeds the Pulse 253-byte limit."));
            }
            let mut payload =
                Zeroizing::new(Vec::with_capacity(3 + password.len()));
            payload.extend_from_slice(&[2, 2, (password.len() + 2) as u8]);
            payload.extend_from_slice(&password);
            build_pulse_eap(
                PULSE_EAP_RESPONSE,
                self.inner_identifier,
                PULSE_EAP_TYPE_EXPANDED,
                2,
                &payload,
            )?
        };
        append_pulse_avp(&mut content, PULSE_AVP_EAP_MESSAGE, 0, &inner)?;
        Ok(encoded(content))
    }

    fn password_change_response(
        &self,
        values: &BTreeMap<String, String>,
    ) -> Result<PulseEncodedAuthenticationResponse, PulseFormError> {
        let old = Zeroizing::new(
            required(values, PULSE_OLD_PASSWORD_SUBMISSION_KEY)?
                .as_bytes()
                .to_vec(),
        );
        let new = Zeroizing::new(
            required(values, PULSE_NEW_PASSWORD_SUBMISSION_KEY)?
                .as_bytes()
                .to_vec(),
        );
        let verify = required(values, PULSE_VERIFY_PASSWORD_SUBMISSION_KEY)?;
        if new.as_slice() != verify.as_bytes() {
            return Ok(retry("New passwords do not match."));
        }
        if old.len() > 253 {
            return Ok(retry(
                "Current password exceeds the Pulse 253-byte limit.",
            ));
        }
        if new.len() > 253 {
            return Ok(retry("New password exceeds the Pulse 253-byte limit."));
        }
        let mut payload =
            Zeroizing::new(Vec::with_capacity(old.len() + new.len() + 5));
        payload.extend_from_slice(&[2, 2, (old.len() + 2) as u8]);
        payload.extend_from_slice(&old);
        payload.extend_from_slice(&[3, (new.len() + 2) as u8]);
        payload.extend_from_slice(&new);
        let inner = build_pulse_eap(
            PULSE_EAP_RESPONSE,
            self.inner_identifier,
            PULSE_EAP_TYPE_EXPANDED,
            2,
            &payload,
        )?;
        let mut content = Vec::new();
        append_pulse_avp(&mut content, PULSE_AVP_EAP_MESSAGE, 0, &inner)?;
        Ok(encoded(content))
    }

    fn gtc_response(
        &self,
        values: &BTreeMap<String, String>,
    ) -> Result<PulseEncodedAuthenticationResponse, PulseFormError> {
        let mut content = Vec::new();
        if self.prompt_flags & PULSE_PROMPT_USERNAME != 0 {
            let username = required(values, PULSE_USERNAME_SUBMISSION_KEY)?;
            append_pulse_avp(
                &mut content,
                0xd6d,
                PULSE_VENDOR_JUNIPER2,
                username.as_bytes(),
            )?;
        }
        let token = Zeroizing::new(
            required(values, PULSE_TOKEN_SUBMISSION_KEY)?
                .as_bytes()
                .to_vec(),
        );
        if token.len() > 253 {
            return Ok(retry("Token code exceeds the Pulse 253-byte limit."));
        }
        let inner = build_pulse_eap(
            PULSE_EAP_RESPONSE,
            self.inner_identifier,
            PULSE_EAP_TYPE_GTC,
            0,
            &token,
        )?;
        append_pulse_avp(&mut content, PULSE_AVP_EAP_MESSAGE, 0, &inner)?;
        Ok(encoded(content))
    }
}

pub fn parse_pulse_session_choice(
    content: &[u8],
) -> Result<PulseSessionChoice, PulseFormError> {
    let attributes = parse_pulse_avps(content)?;
    let mut identifier: Option<String> = None;
    let mut source: Option<String> = None;
    let mut created_at = None;
    for attribute in attributes {
        if attribute.vendor != PULSE_VENDOR_JUNIPER2 {
            continue;
        }
        match attribute.code {
            0xd66 => {
                identifier =
                    Some(String::from_utf8_lossy(&attribute.data).into())
            }
            0xd67 => {
                source = Some(String::from_utf8_lossy(&attribute.data).into())
            }
            0xd68 => {
                let seconds =
                    u64::from_be_bytes(
                        attribute.data.as_slice().try_into().map_err(|_| {
                            PulseFormError::InvalidSessionTimestamp
                        })?,
                    );
                created_at = Some(
                    SystemTime::UNIX_EPOCH
                        .checked_add(std::time::Duration::from_secs(seconds))
                        .ok_or(PulseFormError::SessionTimestampOutOfRange)?,
                );
            }
            _ => {}
        }
    }
    let (Some(identifier), Some(source), Some(created_at)) =
        (identifier, source, created_at)
    else {
        return Err(PulseFormError::IncompleteSessionChoice);
    };
    if identifier.is_empty() || source.is_empty() {
        return Err(PulseFormError::IncompleteSessionChoice);
    }
    Ok(PulseSessionChoice {
        identifier,
        source,
        created_at,
    })
}

pub fn normalize_pulse_prompt(content: &[u8]) -> String {
    if content.is_empty() {
        return String::new();
    }
    let mut prompt = String::from_utf8_lossy(content).into_owned();
    if !prompt.ends_with(':') {
        prompt.push(':');
    }
    prompt
}

fn form(fields: Vec<OpenConnectAuthPromptField>) -> OpenConnectAuthPromptForm {
    OpenConnectAuthPromptForm { fields }
}

fn field(
    submission_key: &str,
    name: &str,
    label: &str,
    kind: OpenConnectAuthPromptKind,
) -> OpenConnectAuthPromptField {
    OpenConnectAuthPromptField {
        submission_key: submission_key.to_owned(),
        name: name.to_owned(),
        label: label.to_owned(),
        kind,
        value: String::new(),
        options: Vec::new(),
    }
}

fn choice_form(
    submission_key: &str,
    name: &str,
    label: &str,
    values: &[String],
) -> OpenConnectAuthPromptForm {
    form(vec![OpenConnectAuthPromptField {
        submission_key: submission_key.to_owned(),
        name: name.to_owned(),
        label: label.to_owned(),
        kind: OpenConnectAuthPromptKind::Select,
        value: values.first().cloned().unwrap_or_default(),
        options: values
            .iter()
            .map(|value| OpenConnectAuthPromptChoice {
                value: value.clone(),
                label: value.clone(),
            })
            .collect(),
    }])
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    key: &'static str,
) -> Result<&'a str, PulseFormError> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or(PulseFormError::MissingResponse(key))
}

fn string_response(
    values: &BTreeMap<String, String>,
    key: &'static str,
    code: u32,
) -> Result<PulseEncodedAuthenticationResponse, PulseFormError> {
    let value = required(values, key)?;
    if value.is_empty() {
        return Err(PulseFormError::MissingResponse(key));
    }
    let mut content = Vec::new();
    append_pulse_avp(
        &mut content,
        code,
        PULSE_VENDOR_JUNIPER2,
        value.as_bytes(),
    )?;
    Ok(encoded(content))
}

fn encoded(content: Vec<u8>) -> PulseEncodedAuthenticationResponse {
    PulseEncodedAuthenticationResponse {
        content,
        retry_message: None,
    }
}

fn retry(message: &str) -> PulseEncodedAuthenticationResponse {
    PulseEncodedAuthenticationResponse {
        content: Vec::new(),
        retry_message: Some(message.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_and_region_choices_preserve_wire_codes() {
        for (kind, key, code) in [
            (
                PulseChallengeKind::RealmEntry,
                PULSE_REALM_SUBMISSION_KEY,
                0xd50,
            ),
            (
                PulseChallengeKind::RealmChoice,
                PULSE_REALM_CHOICE_SUBMISSION_KEY,
                0xd50,
            ),
            (
                PulseChallengeKind::RegionChoice,
                PULSE_REGION_CHOICE_SUBMISSION_KEY,
                0xd52,
            ),
            (
                PulseChallengeKind::Session,
                PULSE_SESSION_SUBMISSION_KEY,
                0xd69,
            ),
        ] {
            let challenge = PulseAuthenticationChallenge {
                kind,
                ..Default::default()
            };
            let values =
                BTreeMap::from([(key.to_owned(), "choice".to_owned())]);
            let response = challenge.build_response(&values).unwrap();
            let avps = parse_pulse_avps(&response.content).unwrap();
            assert_eq!(
                (avps[0].code, avps[0].vendor),
                (code, PULSE_VENDOR_JUNIPER2)
            );
            assert_eq!(avps[0].data, b"choice");
        }
    }

    #[test]
    fn password_response_matches_legacy_juniper_shape() {
        let challenge = PulseAuthenticationChallenge {
            kind: PulseChallengeKind::Password,
            inner_identifier: 9,
            prompt_flags: PULSE_PROMPT_PRIMARY
                | PULSE_PROMPT_USERNAME
                | PULSE_PROMPT_PASSWORD,
            ..Default::default()
        };
        let values = BTreeMap::from([
            (PULSE_USERNAME_SUBMISSION_KEY.to_owned(), "alice".to_owned()),
            (
                PULSE_PASSWORD_SUBMISSION_KEY.to_owned(),
                "secret".to_owned(),
            ),
        ]);
        let response = challenge.build_response(&values).unwrap();
        let avps = parse_pulse_avps(&response.content).unwrap();
        assert_eq!(avps.len(), 2);
        assert_eq!(
            (avps[0].code, avps[0].vendor),
            (0xd6d, PULSE_VENDOR_JUNIPER2)
        );
        let inner =
            super::super::pulse_ift::parse_pulse_eap(&avps[1].data).unwrap();
        assert_eq!((inner.identifier, inner.subtype), (9, 2));
        assert_eq!(inner.payload, b"\x02\x02\x08secret");
    }

    #[test]
    fn password_change_retries_without_emitting_wire_data() {
        let challenge = PulseAuthenticationChallenge {
            kind: PulseChallengeKind::PasswordChange,
            inner_identifier: 4,
            ..Default::default()
        };
        let values = BTreeMap::from([
            (
                PULSE_OLD_PASSWORD_SUBMISSION_KEY.to_owned(),
                "old".to_owned(),
            ),
            (
                PULSE_NEW_PASSWORD_SUBMISSION_KEY.to_owned(),
                "new".to_owned(),
            ),
            (
                PULSE_VERIFY_PASSWORD_SUBMISSION_KEY.to_owned(),
                "different".to_owned(),
            ),
        ]);
        let response = challenge.build_response(&values).unwrap();
        assert!(response.content.is_empty());
        assert_eq!(
            response.retry_message.as_deref(),
            Some("New passwords do not match.")
        );
    }

    #[test]
    fn gtc_form_uses_secret_prompt_kind() {
        let challenge = PulseAuthenticationChallenge {
            kind: PulseChallengeKind::Gtc,
            prompt_flags: PULSE_PROMPT_PRIMARY | PULSE_PROMPT_USERNAME,
            ..Default::default()
        };
        let form = challenge.prompt_form(true).unwrap();
        assert_eq!(form.fields.len(), 2);
        assert_eq!(form.fields[1].kind, OpenConnectAuthPromptKind::Password);
    }

    #[test]
    fn session_choice_requires_identifier_source_and_timestamp() {
        let mut content = Vec::new();
        append_pulse_avp(
            &mut content,
            0xd66,
            PULSE_VENDOR_JUNIPER2,
            b"session-1",
        )
        .unwrap();
        append_pulse_avp(
            &mut content,
            0xd67,
            PULSE_VENDOR_JUNIPER2,
            b"198.51.100.7",
        )
        .unwrap();
        append_pulse_avp(
            &mut content,
            0xd68,
            PULSE_VENDOR_JUNIPER2,
            &123_u64.to_be_bytes(),
        )
        .unwrap();
        let choice = parse_pulse_session_choice(&content).unwrap();
        assert_eq!(choice.identifier, "session-1");
        content.truncate(16);
        assert!(parse_pulse_session_choice(&content).is_err());
    }

    #[test]
    fn prompt_normalization_adds_only_a_missing_colon() {
        assert_eq!(normalize_pulse_prompt(b"User name"), "User name:");
        assert_eq!(normalize_pulse_prompt(b"Password:"), "Password:");
        assert_eq!(normalize_pulse_prompt(b""), "");
    }
}
