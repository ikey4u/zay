use super::normalize_tls_control_message;

pub const TLS_PROTOCOL_FLAG_CC_EXIT: &str = "cc-exit";
pub const TLS_PROTOCOL_FLAG_KEY_MATERIAL_EXPORT: &str = "tls-ekm";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsControlDirective {
    Unknown,
    AuthFailed,
    AuthPending,
    PushReply,
    Restart,
    Halt,
    Exit,
    InfoPre,
    Info,
    ChallengeResponse,
}

/// Classify plaintext records from the TLS control channel with the same
/// ordering as OpenVPN (`INFO_PRE` must be checked before `INFO`).
pub fn classify_tls_control_directive(payload: &[u8]) -> TlsControlDirective {
    let normalized = normalize_tls_control_message(payload);
    if normalized.is_empty() {
        return TlsControlDirective::Unknown;
    }
    let upper = normalized.to_ascii_uppercase();
    if exact_or_parameter(&upper, "AUTH_FAILED") {
        TlsControlDirective::AuthFailed
    } else if exact_or_parameter(&upper, "AUTH_PENDING") {
        TlsControlDirective::AuthPending
    } else if upper.starts_with("PUSH_") {
        TlsControlDirective::PushReply
    } else if exact_or_parameter(&upper, "RESTART") {
        TlsControlDirective::Restart
    } else if exact_or_parameter(&upper, "HALT") {
        TlsControlDirective::Halt
    } else if exact_or_parameter(&upper, "INFO_PRE") {
        TlsControlDirective::InfoPre
    } else if exact_or_parameter(&upper, "INFO") {
        TlsControlDirective::Info
    } else if exact_or_parameter(&upper, "CR_RESPONSE") {
        TlsControlDirective::ChallengeResponse
    } else if exact_or_parameter(&upper, "EXIT") {
        TlsControlDirective::Exit
    } else {
        TlsControlDirective::Unknown
    }
}

pub fn tls_control_string_payload(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len() + 1);
    output.extend_from_slice(payload);
    if output.last() != Some(&0) {
        output.push(0);
    }
    output
}

pub fn should_send_control_channel_exit(protocol_flags: &[String]) -> bool {
    contains_flag(protocol_flags, TLS_PROTOCOL_FLAG_CC_EXIT)
}

pub fn tunnel_uses_key_material_export(
    key_derivation: &str,
    protocol_flags: &[String],
) -> bool {
    key_derivation
        .trim()
        .eq_ignore_ascii_case(TLS_PROTOCOL_FLAG_KEY_MATERIAL_EXPORT)
        || contains_flag(protocol_flags, TLS_PROTOCOL_FLAG_KEY_MATERIAL_EXPORT)
}

fn exact_or_parameter(input: &str, command: &str) -> bool {
    input == command
        || input
            .strip_prefix(command)
            .is_some_and(|remaining| remaining.starts_with(','))
}

fn contains_flag(flags: &[String], expected: &str) -> bool {
    flags
        .iter()
        .any(|flag| flag.trim().eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_case_insensitive_control_records() {
        assert_eq!(
            classify_tls_control_directive(b" AUTH_FAILED,temporary\0ignored"),
            TlsControlDirective::AuthFailed
        );
        assert_eq!(
            classify_tls_control_directive(b"info_pre,challenge"),
            TlsControlDirective::InfoPre
        );
        assert_eq!(
            classify_tls_control_directive(b"INFO,message"),
            TlsControlDirective::Info
        );
        assert_eq!(
            classify_tls_control_directive(b"PUSH_REPLY,route 10.0.0.0"),
            TlsControlDirective::PushReply
        );
        assert_eq!(
            classify_tls_control_directive(b"AUTH_FAILEDX"),
            TlsControlDirective::Unknown
        );
    }

    #[test]
    fn handles_control_terminators_and_protocol_flags() {
        assert_eq!(tls_control_string_payload(b"EXIT"), b"EXIT\0");
        assert_eq!(tls_control_string_payload(b"EXIT\0"), b"EXIT\0");
        let flags = vec![" tls-ekm ".into(), "CC-EXIT".into()];
        assert!(should_send_control_channel_exit(&flags));
        assert!(tunnel_uses_key_material_export("", &flags));
        assert!(tunnel_uses_key_material_export("TLS-EKM", &[]));
    }
}
