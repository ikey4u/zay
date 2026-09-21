//! Pulse Secure authentication challenge state and wire validation.

use std::time::{Duration, SystemTime};

use thiserror::Error;

use super::{
    PULSE_AVP_EAP_MESSAGE, PULSE_AVP_FLAG_MANDATORY,
    PULSE_EAP_EXPANDED_JUNIPER, PULSE_EAP_REQUEST, PULSE_EAP_SUCCESS,
    PULSE_EAP_TYPE_EXPANDED, PULSE_EAP_TYPE_GTC, PULSE_EAP_TYPE_TLS,
    PULSE_IFT_AUTHENTICATION_JUNIPER, PULSE_IFT_CLIENT_AUTH_CHALLENGE,
    PULSE_IFT_CLIENT_AUTH_SUCCESS, PULSE_IFT_VERSION_RESPONSE,
    PULSE_JUNIPER_PASSWORD_CHANGE, PULSE_JUNIPER_PASSWORD_FAILURE,
    PULSE_JUNIPER_PASSWORD_REQUEST, PULSE_JUNIPER_PASSWORD_RETRY,
    PULSE_PROMPT_GTC_NEXT, PULSE_PROMPT_JUNIPER_2021, PULSE_PROMPT_PASSWORD,
    PULSE_PROMPT_PRIMARY, PULSE_PROMPT_USERNAME, PULSE_VENDOR_JUNIPER2,
    PULSE_VENDOR_TCG, PulseAuthenticationChallenge, PulseChallengeKind,
    PulseEapPacket, PulseFormError, PulseIftError, PulseIftFrame,
    append_pulse_avp, build_pulse_eap, normalize_pulse_prompt,
    parse_pulse_avps, parse_pulse_eap, parse_pulse_session_choice,
};

#[derive(Debug, Error)]
pub enum PulseAuthenticationError {
    #[error(transparent)]
    Wire(#[from] PulseIftError),
    #[error(transparent)]
    Form(#[from] PulseFormError),
    #[error("unexpected Pulse IF-T version response")]
    UnexpectedVersionResponse,
    #[error("unexpected initial Pulse authentication challenge")]
    UnexpectedInitialChallenge,
    #[error("unexpected Pulse IF-T authentication success frame")]
    UnexpectedSuccessFrame,
    #[error("server did not complete Pulse EAP authentication")]
    AuthenticationNotCompleted,
    #[error("unexpected Pulse EAP authentication type")]
    UnexpectedAuthenticationType,
    #[error("Pulse authentication failure code has invalid length")]
    InvalidFailureCode,
    #[error("Pulse authentication failed with code {code:#x}")]
    AuthenticationFailed { code: u32, reconnect: bool },
    #[error("Pulse prompt flags have invalid length")]
    InvalidPromptFlags,
    #[error("Pulse authentication expiration has invalid length")]
    InvalidAuthenticationExpiration,
    #[error("Pulse idle timeout has invalid length")]
    InvalidIdleTimeout,
    #[error("Pulse authentication returned an empty cookie")]
    EmptyCookie,
    #[error("unsupported mandatory Pulse AVP: {0:#x}")]
    UnsupportedMandatoryAvp(u32),
    #[error("unsupported mandatory Pulse AVP vendor: {0:#x}")]
    UnsupportedMandatoryVendor(u32),
    #[error("unexpected nested Pulse EAP code")]
    UnexpectedNestedEapCode,
    #[error("server requested Pulse Host Checker; use the nc flavor")]
    HostCheckerRequiresNc,
    #[error("server requested EAP-TLS without a client certificate")]
    EapTlsCertificateRequired,
    #[error("unsupported Pulse nested EAP type: {0:#x}")]
    UnsupportedNestedEap(u32),
    #[error("unsupported Pulse expanded EAP subtype: {0}")]
    UnsupportedExpandedSubtype(u32),
    #[error("Pulse authentication packet mixed or omitted request categories")]
    MixedOrMissingCategory,
    #[error("Pulse authentication packet omitted its request category")]
    MissingCategory,
    #[error("Pulse password challenge omitted its request code")]
    MissingPasswordRequestCode,
    #[error("Pulse password request has unexpected payload")]
    InvalidPasswordRequest,
    #[error("invalid Pulse password-change failure payload")]
    InvalidPasswordChangeFailure,
    #[error("Pulse password change failed: {0}")]
    PasswordChangeFailed(String),
    #[error("unknown Pulse password request code: {0:#04x}")]
    UnknownPasswordRequestCode(u8),
    #[error("unexpected Pulse Juniper/5 password request")]
    InvalidJuniper2021Request,
    #[error("Pulse timestamp exceeds the supported range")]
    TimestampOutOfRange,
}

#[derive(Debug, Clone)]
pub struct PulseChallengeParser {
    prompt_flags: u32,
    user_prompt: String,
    password_prompt: String,
    secondary_user_prompt: String,
    secondary_password_prompt: String,
    previous_gtc: bool,
    cookie: Option<Vec<u8>>,
    authentication_expires_at: Option<SystemTime>,
    idle_timeout: Duration,
    certificate_md5: Option<Vec<u8>>,
}

impl Default for PulseChallengeParser {
    fn default() -> Self {
        Self {
            prompt_flags: PULSE_PROMPT_PRIMARY
                | PULSE_PROMPT_USERNAME
                | PULSE_PROMPT_PASSWORD,
            user_prompt: String::new(),
            password_prompt: String::new(),
            secondary_user_prompt: String::new(),
            secondary_password_prompt: String::new(),
            previous_gtc: false,
            cookie: None,
            authentication_expires_at: None,
            idle_timeout: Duration::ZERO,
            certificate_md5: None,
        }
    }
}

impl PulseChallengeParser {
    pub fn set_cookie(&mut self, cookie: Vec<u8>) {
        self.cookie = (!cookie.is_empty()).then_some(cookie);
    }

    pub fn cookie(&self) -> Option<&[u8]> {
        self.cookie.as_deref()
    }

    pub fn authentication_expires_at(&self) -> Option<SystemTime> {
        self.authentication_expires_at
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn certificate_md5(&self) -> Option<&[u8]> {
        self.certificate_md5.as_deref()
    }

    pub fn parse_challenge(
        &mut self,
        packet: &PulseEapPacket,
        reconnecting: bool,
        client_certificate_configured: bool,
        now: SystemTime,
    ) -> Result<PulseAuthenticationChallenge, PulseAuthenticationError> {
        if packet.code != PULSE_EAP_REQUEST
            || packet.type_value != PULSE_EAP_EXPANDED_JUNIPER
            || packet.subtype != 1
        {
            return Err(PulseAuthenticationError::UnexpectedAuthenticationType);
        }
        let attributes = parse_pulse_avps(&packet.payload)?;
        let mut challenge = PulseAuthenticationChallenge {
            outer_identifier: packet.identifier,
            prompt_flags: if self.previous_gtc {
                self.prompt_flags | PULSE_PROMPT_GTC_NEXT
            } else {
                self.prompt_flags & !PULSE_PROMPT_GTC_NEXT
            },
            ..Default::default()
        };
        let mut realm_entry = false;
        let mut sign_in = false;
        let mut cookie_received = false;
        for attribute in attributes {
            if attribute.vendor == PULSE_VENDOR_JUNIPER2 {
                match attribute.code {
                    0xd55 => self.certificate_md5 = Some(attribute.data),
                    0xd65 => challenge
                        .sessions
                        .push(parse_pulse_session_choice(&attribute.data)?),
                    0xd60 => {
                        return Err(
                            PulseAuthenticationError::AuthenticationFailed {
                                code: authentication_failure_code(
                                    &attribute.data,
                                )?,
                                reconnect: reconnecting,
                            },
                        );
                    }
                    0xd80 => {
                        self.user_prompt =
                            normalize_pulse_prompt(&attribute.data)
                    }
                    0xd81 => {
                        self.password_prompt =
                            normalize_pulse_prompt(&attribute.data)
                    }
                    0xd82 => {
                        self.secondary_user_prompt =
                            normalize_pulse_prompt(&attribute.data)
                    }
                    0xd83 => {
                        self.secondary_password_prompt =
                            normalize_pulse_prompt(&attribute.data)
                    }
                    0xd73 => {
                        let value = u32::from_be_bytes(
                            attribute.data.as_slice().try_into().map_err(
                                |_| {
                                    PulseAuthenticationError::InvalidPromptFlags
                                },
                            )?,
                        );
                        challenge.prompt_flags = match value {
                            1 => PULSE_PROMPT_USERNAME | PULSE_PROMPT_PASSWORD,
                            3 | 15 => PULSE_PROMPT_PASSWORD,
                            5 => PULSE_PROMPT_USERNAME,
                            _ => PULSE_PROMPT_USERNAME | PULSE_PROMPT_PASSWORD,
                        };
                    }
                    0xd7b => sign_in = true,
                    0xd4e => challenge
                        .realm_choices
                        .push(String::from_utf8_lossy(&attribute.data).into()),
                    0xd4f => realm_entry = true,
                    0xd51 => challenge
                        .region_choices
                        .push(String::from_utf8_lossy(&attribute.data).into()),
                    0xd5c => {
                        let seconds = u32::from_be_bytes(
                            attribute.data.as_slice().try_into().map_err(|_| {
                                PulseAuthenticationError::InvalidAuthenticationExpiration
                            })?,
                        );
                        self.authentication_expires_at = if seconds == 0 {
                            None
                        } else {
                            Some(
                                now.checked_add(Duration::from_secs(u64::from(seconds)))
                                    .ok_or(PulseAuthenticationError::TimestampOutOfRange)?,
                            )
                        };
                    }
                    0xd75 => {
                        let seconds = u32::from_be_bytes(
                            attribute.data.as_slice().try_into().map_err(
                                |_| {
                                    PulseAuthenticationError::InvalidIdleTimeout
                                },
                            )?,
                        );
                        self.idle_timeout =
                            Duration::from_secs(u64::from(seconds));
                    }
                    0xd53 => {
                        if attribute.data.is_empty() {
                            return Err(PulseAuthenticationError::EmptyCookie);
                        }
                        self.cookie = Some(attribute.data);
                        cookie_received = true;
                    }
                    _ if attribute.flags & PULSE_AVP_FLAG_MANDATORY != 0 => {
                        return Err(
                            PulseAuthenticationError::UnsupportedMandatoryAvp(
                                attribute.code,
                            ),
                        );
                    }
                    _ => {}
                }
                continue;
            }
            if attribute.vendor == 0 && attribute.code == PULSE_AVP_EAP_MESSAGE
            {
                let inner = parse_pulse_eap(&attribute.data)?;
                if inner.code != PULSE_EAP_REQUEST {
                    return Err(
                        PulseAuthenticationError::UnexpectedNestedEapCode,
                    );
                }
                challenge.inner_identifier = inner.identifier;
                if inner.type_value == u32::from(PULSE_EAP_TYPE_GTC) {
                    challenge.kind = PulseChallengeKind::Gtc;
                    challenge.gtc_prompt =
                        String::from_utf8_lossy(&inner.payload).into();
                    challenge.gtc_next =
                        challenge.prompt_flags & PULSE_PROMPT_GTC_NEXT != 0;
                    continue;
                }
                if inner.type_value == PULSE_EAP_EXPANDED_JUNIPER {
                    match inner.subtype {
                        2 => parse_password_challenge(&mut challenge, &inner.payload)?,
                        3 => return Err(PulseAuthenticationError::HostCheckerRequiresNc),
                        5 => parse_juniper_2021_challenge(
                            &mut challenge,
                            &inner.payload,
                        )?,
                        subtype => {
                            return Err(
                                PulseAuthenticationError::UnsupportedExpandedSubtype(
                                    subtype,
                                ),
                            )
                        }
                    }
                    continue;
                }
                if inner.type_value == u32::from(PULSE_EAP_TYPE_TLS)
                    && !client_certificate_configured
                {
                    return Err(
                        PulseAuthenticationError::EapTlsCertificateRequired,
                    );
                }
                return Err(PulseAuthenticationError::UnsupportedNestedEap(
                    inner.type_value,
                ));
            }
            if attribute.flags & PULSE_AVP_FLAG_MANDATORY != 0 {
                return Err(
                    PulseAuthenticationError::UnsupportedMandatoryVendor(
                        attribute.vendor,
                    ),
                );
            }
        }
        let request_kind = challenge.kind;
        let category_count = usize::from(realm_entry)
            + usize::from(!challenge.realm_choices.is_empty())
            + usize::from(!challenge.region_choices.is_empty())
            + usize::from(!challenge.sessions.is_empty())
            + usize::from(matches!(
                request_kind,
                PulseChallengeKind::Password
                    | PulseChallengeKind::PasswordChange
                    | PulseChallengeKind::Gtc
            ))
            + usize::from(cookie_received);
        if category_count != 1 && !sign_in {
            return Err(PulseAuthenticationError::MixedOrMissingCategory);
        }
        challenge.kind = if cookie_received {
            PulseChallengeKind::Cookie
        } else if realm_entry {
            PulseChallengeKind::RealmEntry
        } else if !challenge.realm_choices.is_empty() {
            PulseChallengeKind::RealmChoice
        } else if !challenge.region_choices.is_empty() {
            PulseChallengeKind::RegionChoice
        } else if matches!(
            request_kind,
            PulseChallengeKind::Password
                | PulseChallengeKind::PasswordChange
                | PulseChallengeKind::Gtc
        ) {
            request_kind
        } else if !challenge.sessions.is_empty() {
            PulseChallengeKind::Session
        } else if sign_in {
            PulseChallengeKind::SignIn
        } else {
            return Err(PulseAuthenticationError::MissingCategory);
        };
        let primary = challenge.prompt_flags & PULSE_PROMPT_PRIMARY != 0;
        if primary {
            challenge.user_prompt.clone_from(&self.user_prompt);
            challenge.password_prompt.clone_from(&self.password_prompt);
        } else {
            challenge
                .user_prompt
                .clone_from(&self.secondary_user_prompt);
            challenge
                .password_prompt
                .clone_from(&self.secondary_password_prompt);
        }
        self.prompt_flags = challenge.prompt_flags;
        self.previous_gtc = challenge.kind == PulseChallengeKind::Gtc;
        Ok(challenge)
    }
}

pub fn validate_pulse_version_response(
    frame: &PulseIftFrame,
) -> Result<(), PulseAuthenticationError> {
    if frame.vendor & 0x00ff_ffff != PULSE_VENDOR_TCG
        || frame.frame_type != PULSE_IFT_VERSION_RESPONSE
        || frame.payload.len() != 4
    {
        return Err(PulseAuthenticationError::UnexpectedVersionResponse);
    }
    Ok(())
}

pub fn validate_pulse_initial_challenge(
    frame: &PulseIftFrame,
) -> Result<(), PulseAuthenticationError> {
    if frame.vendor & 0x00ff_ffff != PULSE_VENDOR_TCG
        || frame.frame_type != PULSE_IFT_CLIENT_AUTH_CHALLENGE
        || frame.payload.as_slice()
            != PULSE_IFT_AUTHENTICATION_JUNIPER.to_be_bytes()
    {
        return Err(PulseAuthenticationError::UnexpectedInitialChallenge);
    }
    Ok(())
}

pub fn validate_pulse_authentication_success(
    frame: &PulseIftFrame,
) -> Result<(), PulseAuthenticationError> {
    if frame.vendor & 0x00ff_ffff != PULSE_VENDOR_TCG
        || frame.frame_type != PULSE_IFT_CLIENT_AUTH_SUCCESS
        || frame.payload.len() != 8
        || frame.payload[..4] != PULSE_IFT_AUTHENTICATION_JUNIPER.to_be_bytes()
    {
        return Err(PulseAuthenticationError::UnexpectedSuccessFrame);
    }
    if parse_pulse_eap(&frame.payload[4..])?.code != PULSE_EAP_SUCCESS {
        return Err(PulseAuthenticationError::AuthenticationNotCompleted);
    }
    Ok(())
}

pub fn build_pulse_sign_in_response()
-> Result<Vec<u8>, PulseAuthenticationError> {
    let mut content = Vec::new();
    append_pulse_avp(
        &mut content,
        0xd7c,
        PULSE_VENDOR_JUNIPER2,
        &1_u32.to_be_bytes(),
    )?;
    Ok(content)
}

pub fn build_pulse_authentication_client_avps(
    reported_os: &str,
    user_agent: &str,
    ipv6_disabled: bool,
    cookie: Option<&[u8]>,
) -> Result<Vec<u8>, PulseAuthenticationError> {
    let mut content = Vec::new();
    append_pulse_avp(
        &mut content,
        0xd5e,
        PULSE_VENDOR_JUNIPER2,
        reported_os.as_bytes(),
    )?;
    let wrapped;
    let user_agent =
        if !ipv6_disabled && !user_agent.starts_with("Pulse-Secure/") {
            wrapped = format!("Pulse-Secure/22.2.1.1295 ({user_agent})");
            &wrapped
        } else {
            user_agent
        };
    append_pulse_avp(
        &mut content,
        0xd70,
        PULSE_VENDOR_JUNIPER2,
        user_agent.as_bytes(),
    )?;
    if let Some(cookie) = cookie.filter(|cookie| !cookie.is_empty()) {
        append_pulse_avp(&mut content, 0xd53, PULSE_VENDOR_JUNIPER2, cookie)?;
    }
    Ok(content)
}

pub fn build_pulse_expanded_response(
    identifier: u8,
    content: &[u8],
) -> Result<Vec<u8>, PulseAuthenticationError> {
    Ok(build_pulse_eap(
        2,
        identifier,
        PULSE_EAP_TYPE_EXPANDED,
        1,
        content,
    )?)
}

fn authentication_failure_code(
    content: &[u8],
) -> Result<u32, PulseAuthenticationError> {
    Ok(u32::from_be_bytes(content.try_into().map_err(|_| {
        PulseAuthenticationError::InvalidFailureCode
    })?))
}

fn parse_password_challenge(
    challenge: &mut PulseAuthenticationChallenge,
    payload: &[u8],
) -> Result<(), PulseAuthenticationError> {
    let Some(&request_code) = payload.first() else {
        return Err(PulseAuthenticationError::MissingPasswordRequestCode);
    };
    challenge.password_request_code = request_code;
    match request_code {
        PULSE_JUNIPER_PASSWORD_REQUEST | PULSE_JUNIPER_PASSWORD_RETRY => {
            if payload.len() != 1 {
                return Err(PulseAuthenticationError::InvalidPasswordRequest);
            }
            challenge.kind = PulseChallengeKind::Password;
            if request_code == PULSE_JUNIPER_PASSWORD_RETRY {
                challenge.error_message =
                    "rejected the previous credentials.".to_owned();
            }
        }
        PULSE_JUNIPER_PASSWORD_CHANGE => {
            if payload.len() != 1 {
                return Err(PulseAuthenticationError::InvalidPasswordRequest);
            }
            challenge.kind = PulseChallengeKind::PasswordChange;
        }
        PULSE_JUNIPER_PASSWORD_FAILURE => {
            if payload.len() <= 3
                || payload[1] != 1
                || usize::from(payload[2]) != payload.len() - 1
            {
                return Err(
                    PulseAuthenticationError::InvalidPasswordChangeFailure,
                );
            }
            return Err(PulseAuthenticationError::PasswordChangeFailed(
                String::from_utf8_lossy(&payload[3..])
                    .trim_end_matches('\0')
                    .to_owned(),
            ));
        }
        code => {
            return Err(PulseAuthenticationError::UnknownPasswordRequestCode(
                code,
            ));
        }
    }
    Ok(())
}

fn parse_juniper_2021_challenge(
    challenge: &mut PulseAuthenticationChallenge,
    payload: &[u8],
) -> Result<(), PulseAuthenticationError> {
    if payload.len() != 6 || payload[0] != PULSE_JUNIPER_PASSWORD_REQUEST {
        return Err(PulseAuthenticationError::InvalidJuniper2021Request);
    }
    challenge.kind = PulseChallengeKind::Password;
    challenge.password_request_code = payload[0];
    challenge.prompt_flags |= PULSE_PROMPT_JUNIPER_2021;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        super::{PULSE_EAP_FAILURE, PULSE_IFT_VERSION_REQUEST},
        *,
    };

    fn expanded_packet(content: Vec<u8>) -> PulseEapPacket {
        PulseEapPacket {
            code: PULSE_EAP_REQUEST,
            identifier: 8,
            type_value: PULSE_EAP_EXPANDED_JUNIPER,
            subtype: 1,
            payload: content,
        }
    }

    #[test]
    fn validates_handshake_envelopes() {
        let version = PulseIftFrame {
            vendor: PULSE_VENDOR_TCG,
            frame_type: PULSE_IFT_VERSION_RESPONSE,
            sequence: 0,
            payload: vec![0, 1, 2, 2],
        };
        validate_pulse_version_response(&version).unwrap();
        assert!(
            validate_pulse_version_response(&PulseIftFrame {
                frame_type: PULSE_IFT_VERSION_REQUEST,
                ..version
            })
            .is_err()
        );
    }

    #[test]
    fn parses_realm_and_cookie_categories() {
        let mut parser = PulseChallengeParser::default();
        let mut realm = Vec::new();
        append_pulse_avp(&mut realm, 0xd4e, PULSE_VENDOR_JUNIPER2, b"Users")
            .unwrap();
        let challenge = parser
            .parse_challenge(
                &expanded_packet(realm),
                false,
                false,
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        assert_eq!(challenge.kind, PulseChallengeKind::RealmChoice);

        let mut cookie = Vec::new();
        append_pulse_avp(&mut cookie, 0xd53, PULSE_VENDOR_JUNIPER2, b"session")
            .unwrap();
        let challenge = parser
            .parse_challenge(
                &expanded_packet(cookie),
                false,
                false,
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        assert_eq!(challenge.kind, PulseChallengeKind::Cookie);
        assert_eq!(parser.cookie(), Some(b"session".as_slice()));
    }

    #[test]
    fn parses_nested_password_and_gtc_requests() {
        let mut parser = PulseChallengeParser::default();
        let inner = build_pulse_eap(
            PULSE_EAP_REQUEST,
            3,
            PULSE_EAP_TYPE_EXPANDED,
            2,
            &[PULSE_JUNIPER_PASSWORD_RETRY],
        )
        .unwrap();
        let mut content = Vec::new();
        append_pulse_avp(&mut content, PULSE_AVP_EAP_MESSAGE, 0, &inner)
            .unwrap();
        let challenge = parser
            .parse_challenge(
                &expanded_packet(content),
                false,
                false,
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        assert_eq!(challenge.kind, PulseChallengeKind::Password);
        assert_eq!(challenge.inner_identifier, 3);

        let inner = build_pulse_eap(
            PULSE_EAP_REQUEST,
            4,
            PULSE_EAP_TYPE_GTC,
            0,
            b"OTP",
        )
        .unwrap();
        let mut content = Vec::new();
        append_pulse_avp(&mut content, PULSE_AVP_EAP_MESSAGE, 0, &inner)
            .unwrap();
        let challenge = parser
            .parse_challenge(
                &expanded_packet(content),
                false,
                false,
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        assert_eq!(challenge.kind, PulseChallengeKind::Gtc);
        assert_eq!(challenge.gtc_prompt, "OTP");
    }

    #[test]
    fn rejects_mixed_categories_and_mandatory_unknowns() {
        let mut parser = PulseChallengeParser::default();
        let mut content = Vec::new();
        append_pulse_avp(&mut content, 0xd4f, PULSE_VENDOR_JUNIPER2, b"")
            .unwrap();
        append_pulse_avp(&mut content, 0xd51, PULSE_VENDOR_JUNIPER2, b"Region")
            .unwrap();
        assert!(matches!(
            parser.parse_challenge(
                &expanded_packet(content),
                false,
                false,
                SystemTime::UNIX_EPOCH,
            ),
            Err(PulseAuthenticationError::MixedOrMissingCategory)
        ));

        let mut content = Vec::new();
        append_pulse_avp(&mut content, 0xffff, PULSE_VENDOR_JUNIPER2, b"x")
            .unwrap();
        assert!(matches!(
            parser.parse_challenge(
                &expanded_packet(content),
                false,
                false,
                SystemTime::UNIX_EPOCH,
            ),
            Err(PulseAuthenticationError::UnsupportedMandatoryAvp(0xffff))
        ));
    }

    #[test]
    fn builds_dual_stack_client_avps() {
        let content = build_pulse_authentication_client_avps(
            "linux-64",
            "OpenConnect/1.0",
            false,
            Some(b"cookie"),
        )
        .unwrap();
        let avps = parse_pulse_avps(&content).unwrap();
        assert_eq!(avps.len(), 3);
        assert_eq!(avps[1].data, b"Pulse-Secure/22.2.1.1295 (OpenConnect/1.0)");
        assert_eq!(avps[2].data, b"cookie");
    }

    #[test]
    fn validates_success_eap() {
        let frame = PulseIftFrame {
            vendor: PULSE_VENDOR_TCG,
            frame_type: PULSE_IFT_CLIENT_AUTH_SUCCESS,
            sequence: 5,
            payload: {
                let mut payload =
                    PULSE_IFT_AUTHENTICATION_JUNIPER.to_be_bytes().to_vec();
                payload.extend_from_slice(&[PULSE_EAP_SUCCESS, 7, 0, 4]);
                payload
            },
        };
        validate_pulse_authentication_success(&frame).unwrap();
        let mut failure = frame;
        failure.payload[4] = PULSE_EAP_FAILURE;
        assert!(matches!(
            validate_pulse_authentication_success(&failure),
            Err(PulseAuthenticationError::AuthenticationNotCompleted)
        ));
    }
}
