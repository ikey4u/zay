use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::normalize_control_payload;

pub const AUTH_FAILED_PAYLOAD: &str = "AUTH_FAILED";
pub const AUTH_PENDING_PAYLOAD: &str = "AUTH_PENDING";

pub fn auth_pending_extension(
    hand_window: Duration,
    renegotiation_interval: Duration,
    control_record: &[u8],
) -> Duration {
    let maximum = hand_window.max(renegotiation_interval / 2);
    let extension = parse_auth_pending_timeout(control_record)
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
        .unwrap_or(hand_window);
    extension.min(maximum)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StagedCredentials {
    pub defined: bool,
    pub interactive: bool,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthenticationState {
    staged: StagedCredentials,
    sent_interactive_credentials: bool,
}

impl AuthenticationState {
    pub fn staged(&self) -> &StagedCredentials {
        &self.staged
    }

    pub fn stage(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
        interactive: bool,
    ) {
        self.staged = StagedCredentials {
            defined: true,
            interactive,
            username: username.into(),
            password: password.into(),
        };
    }

    pub fn purge(&mut self) {
        self.staged = StagedCredentials::default();
    }

    pub fn note_sent(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
        interactive: bool,
    ) -> (String, String) {
        self.sent_interactive_credentials = interactive;
        (username.into(), password.into())
    }

    pub fn last_sent_interactive(&self) -> bool {
        self.sent_interactive_credentials
    }
}

pub fn resolve_auth_token_credentials(
    configured_username: &str,
    auth_token: &str,
    encoded_auth_token_user: &str,
    staged_username: &str,
) -> Option<(String, String)> {
    if auth_token.is_empty() {
        return None;
    }
    if !encoded_auth_token_user.is_empty() {
        let username = decode_auth_token_username(encoded_auth_token_user)?;
        return Some((username, auth_token.to_owned()));
    }
    let username = if configured_username.is_empty() {
        staged_username
    } else {
        configured_username
    };
    (!username.is_empty()).then(|| (username.to_owned(), auth_token.to_owned()))
}

pub fn decode_auth_token_username(encoded: &str) -> Option<String> {
    let mut decoded = STANDARD.decode(encoded).ok()?;
    if decoded.is_empty() {
        return None;
    }
    if let Some(index) = decoded.iter().position(|byte| *byte == 0) {
        decoded.truncate(index);
    }
    Some(String::from_utf8_lossy(&decoded).into_owned())
}

pub fn is_auth_failed_payload(payload: &[u8]) -> bool {
    let payload = normalize_control_payload(payload);
    !payload.is_empty()
        && (payload.eq_ignore_ascii_case(AUTH_FAILED_PAYLOAD)
            || payload.to_ascii_uppercase().starts_with("AUTH_FAILED,"))
}

pub fn build_auth_failed_payload(reason: &str) -> Vec<u8> {
    let reason = reason.trim();
    if reason.is_empty() {
        AUTH_FAILED_PAYLOAD.as_bytes().to_vec()
    } else {
        format!("{AUTH_FAILED_PAYLOAD},{reason}").into_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthFailedAdvance {
    #[default]
    NextAddress,
    NextRemote,
    Stay,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthFailedInfo {
    pub failed: bool,
    pub temporary: bool,
    pub reason: String,
    pub backoff_seconds: u32,
    pub advance: AuthFailedAdvance,
}

pub fn parse_auth_failed_payload(payload: &[u8]) -> AuthFailedInfo {
    let normalized = normalize_control_payload(payload);
    if normalized.is_empty()
        || !normalized
            .to_ascii_uppercase()
            .starts_with(AUTH_FAILED_PAYLOAD)
    {
        return AuthFailedInfo::default();
    }
    // Keep the case-sensitive TrimPrefix behavior of sing-openvpn/OpenVPN.
    let suffix = normalized
        .strip_prefix(AUTH_FAILED_PAYLOAD)
        .unwrap_or(&normalized);
    if suffix.is_empty() {
        return AuthFailedInfo {
            failed: true,
            ..AuthFailedInfo::default()
        };
    }
    let Some(mut suffix) = suffix.strip_prefix(',') else {
        return AuthFailedInfo::default();
    };
    let mut info = AuthFailedInfo {
        failed: true,
        ..AuthFailedInfo::default()
    };
    if !suffix.to_ascii_uppercase().starts_with("TEMP") {
        info.reason = suffix.trim().to_owned();
        return info;
    }
    info.temporary = true;
    suffix = suffix.strip_prefix("TEMP").unwrap_or(suffix);
    if let Some(bracket) = suffix.strip_prefix('[')
        && let Some(end) = bracket.find(']')
    {
        apply_auth_failed_temporary_flags(&mut info, &bracket[..end]);
        suffix = &bracket[end + 1..];
    }
    suffix = suffix.strip_prefix(':').unwrap_or(suffix);
    info.reason = suffix.trim().to_owned();
    info
}

pub fn apply_auth_failed_temporary_flags(
    info: &mut AuthFailedInfo,
    content: &str,
) {
    for entry in content.split(',') {
        let entry = entry.trim();
        let Some((keyword, value)) = entry.split_once(' ') else {
            continue;
        };
        let value = value.trim();
        match keyword.to_ascii_lowercase().as_str() {
            "backoff" => {
                if let Ok(backoff) = value.parse() {
                    info.backoff_seconds = backoff;
                }
            }
            "advance" => {
                info.advance = match value.to_ascii_lowercase().as_str() {
                    "no" => AuthFailedAdvance::Stay,
                    "remote" => AuthFailedAdvance::NextRemote,
                    "addr" => AuthFailedAdvance::NextAddress,
                    _ => info.advance,
                };
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRetryMode {
    None,
    NoInteract,
    Interact,
}

pub fn resolve_auth_retry_mode(value: &str) -> AuthRetryMode {
    match value {
        "nointeract" => AuthRetryMode::NoInteract,
        "interact" => AuthRetryMode::Interact,
        _ => AuthRetryMode::None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    DynamicChallenge(Crv1Challenge),
    Temporary {
        backoff_seconds: u32,
        advance: AuthFailedAdvance,
        reason: String,
    },
    Terminal {
        reason: String,
    },
    Retryable,
}

pub fn auth_failure_from_payload(
    payload: &[u8],
    auth_retry: &str,
) -> AuthFailure {
    if let Some(challenge) = extract_crv1_from_auth_failed(payload) {
        return AuthFailure::DynamicChallenge(challenge);
    }
    let info = parse_auth_failed_payload(payload);
    if !info.failed {
        return if resolve_auth_retry_mode(auth_retry) == AuthRetryMode::None {
            AuthFailure::Terminal {
                reason: String::new(),
            }
        } else {
            AuthFailure::Retryable
        };
    }
    if info.temporary {
        return AuthFailure::Temporary {
            backoff_seconds: info.backoff_seconds,
            advance: info.advance,
            reason: info.reason,
        };
    }
    if resolve_auth_retry_mode(auth_retry) == AuthRetryMode::None {
        AuthFailure::Terminal {
            reason: info.reason,
        }
    } else {
        AuthFailure::Retryable
    }
}

pub fn parse_auth_pending_timeout(payload: &[u8]) -> Option<u32> {
    let normalized = normalize_control_payload(payload);
    if normalized.is_empty()
        || !normalized
            .to_ascii_uppercase()
            .starts_with(AUTH_PENDING_PAYLOAD)
    {
        return None;
    }
    let suffix = normalized
        .strip_prefix(AUTH_PENDING_PAYLOAD)
        .unwrap_or(&normalized)
        .strip_prefix(',')?;
    for entry in suffix.split(',') {
        let entry = entry.trim();
        if !entry.to_ascii_lowercase().starts_with("timeout") {
            continue;
        }
        let value = entry
            .strip_prefix("timeout")
            .unwrap_or(entry)
            .trim()
            .strip_prefix('=')
            .unwrap_or_else(|| {
                entry.strip_prefix("timeout").unwrap_or(entry).trim()
            })
            .trim();
        if let Ok(timeout) = value.parse() {
            return Some(timeout);
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crv1Challenge {
    pub state_id: String,
    pub username: String,
    pub challenge_text: String,
    pub echo: bool,
}

pub fn parse_crv1_challenge(challenge: &str) -> Option<Crv1Challenge> {
    let fields: Vec<_> = challenge.splitn(5, ':').collect();
    if fields.len() < 4
        || fields[0] != "CRV1"
        || (fields.len() == 4 && fields[3].is_empty())
    {
        return None;
    }
    let username = STANDARD.decode(fields[3]).unwrap_or_default();
    Some(Crv1Challenge {
        state_id: fields[2].to_owned(),
        username: String::from_utf8_lossy(&username).into_owned(),
        challenge_text: fields.get(4).copied().unwrap_or_default().to_owned(),
        echo: fields[1].contains('E'),
    })
}

pub fn extract_crv1_from_auth_failed(payload: &[u8]) -> Option<Crv1Challenge> {
    let normalized = normalize_control_payload(payload);
    if !normalized.to_ascii_uppercase().starts_with("AUTH_FAILED,") {
        return None;
    }
    parse_crv1_challenge(&normalized[AUTH_FAILED_PAYLOAD.len() + 1..])
}

pub fn pack_static_challenge_password(password: &str, answer: &str) -> String {
    format!(
        "SCRV1:{}:{}",
        STANDARD.encode(password),
        STANDARD.encode(answer)
    )
}

pub fn pack_dynamic_challenge_response(state_id: &str, answer: &str) -> String {
    format!("CRV1::{state_id}::{answer}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_token_username_and_staged_fallback() {
        assert_eq!(
            resolve_auth_token_credentials(
                "configured",
                "token",
                "dXNlcgB0cmFpbA==",
                "staged"
            ),
            Some(("user".into(), "token".into()))
        );
        assert_eq!(
            resolve_auth_token_credentials("", "token", "", "staged"),
            Some(("staged".into(), "token".into()))
        );
        assert!(resolve_auth_token_credentials("", "token", "", "").is_none());
        assert!(decode_auth_token_username("!!!").is_none());
    }

    #[test]
    fn parses_temporary_and_terminal_auth_failures() {
        let info = parse_auth_failed_payload(
            b"AUTH_FAILED,TEMP[backoff 12,advance remote]: maintenance\0",
        );
        assert!(info.failed && info.temporary);
        assert_eq!(info.backoff_seconds, 12);
        assert_eq!(info.advance, AuthFailedAdvance::NextRemote);
        assert_eq!(info.reason, "maintenance");
        assert_eq!(
            auth_failure_from_payload(b"AUTH_FAILED,bad password", "none"),
            AuthFailure::Terminal {
                reason: "bad password".into()
            }
        );
        assert_eq!(
            auth_failure_from_payload(b"AUTH_FAILED,bad password", "interact"),
            AuthFailure::Retryable
        );
        assert!(is_auth_failed_payload(b"auth_failed,reason"));
        assert!(!parse_auth_failed_payload(b"auth_failed,reason").failed);
    }

    #[test]
    fn parses_pending_timeout_and_caps_extension() {
        assert_eq!(
            parse_auth_pending_timeout(b"AUTH_PENDING,foo, timeout=90,bar"),
            Some(90)
        );
        assert_eq!(
            parse_auth_pending_timeout(b"AUTH_PENDING,timeout 17"),
            Some(17)
        );
        assert_eq!(
            auth_pending_extension(
                Duration::from_secs(60),
                Duration::from_secs(100),
                b"AUTH_PENDING,timeout 90"
            ),
            Duration::from_secs(60)
        );
        assert_eq!(
            auth_pending_extension(
                Duration::from_secs(20),
                Duration::from_secs(200),
                b"AUTH_PENDING,timeout 90"
            ),
            Duration::from_secs(90)
        );
    }

    #[test]
    fn parses_crv1_and_packs_static_and_dynamic_answers() {
        let challenge =
            parse_crv1_challenge("CRV1:ER:state:dXNlcg==:OTP: now").unwrap();
        assert_eq!(challenge.state_id, "state");
        assert_eq!(challenge.username, "user");
        assert_eq!(challenge.challenge_text, "OTP: now");
        assert!(challenge.echo);
        assert_eq!(
            extract_crv1_from_auth_failed(
                b"AUTH_FAILED,CRV1:R:s:dXNlcg==:code"
            )
            .unwrap()
            .challenge_text,
            "code"
        );
        assert_eq!(
            pack_static_challenge_password("pass", "123456"),
            "SCRV1:cGFzcw==:MTIzNDU2"
        );
        assert_eq!(
            pack_dynamic_challenge_response("state", "123456"),
            "CRV1::state::123456"
        );
    }

    #[test]
    fn crv1_accepts_empty_reached_fields_like_openvpn() {
        assert!(parse_crv1_challenge("CRV1:::user").is_some());
        assert!(parse_crv1_challenge("CRV1:::").is_none());
        assert_eq!(
            parse_crv1_challenge("CRV1:E:s:not-base64:text")
                .unwrap()
                .username,
            ""
        );
    }

    #[test]
    fn credential_state_survives_send_until_explicit_purge() {
        let mut state = AuthenticationState::default();
        state.stage("user", "password", true);
        assert!(state.staged().defined);
        assert_eq!(
            state.note_sent("user", "password", true),
            ("user".into(), "password".into())
        );
        assert!(state.last_sent_interactive());
        assert!(state.staged().defined);
        state.purge();
        assert!(!state.staged().defined);
    }

    #[test]
    fn builds_auth_failed_wire_payload() {
        assert_eq!(build_auth_failed_payload(""), b"AUTH_FAILED");
        assert_eq!(
            build_auth_failed_payload(" denied "),
            b"AUTH_FAILED,denied"
        );
    }
}
