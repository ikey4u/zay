//! Fortinet login, token-info, and HTML challenge form primitives.

use std::collections::HashMap;

use scraper::{Html, Selector};
use thiserror::Error;
use url::Url;

pub const FORTINET_MAXIMUM_TOKEN_INFO_FIELDS: usize = 64;
pub const FORTINET_MAXIMUM_TOKEN_INFO_FIELD: usize = 8192;
pub const FORTINET_MAXIMUM_SAML_SESSION_ID: usize = 1023;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FortinetAuthenticationFieldKind {
    Hidden,
    Text,
    Password,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortinetAuthenticationField {
    pub submission_key: String,
    pub name: String,
    pub label: String,
    pub kind: FortinetAuthenticationFieldKind,
    pub value: String,
    pub raw_pair: String,
    pub magic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortinetAuthenticationForm {
    pub id: String,
    pub action: String,
    pub message: String,
    pub fields: Vec<FortinetAuthenticationField>,
    pub token_info: bool,
    pub ftm_push: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortinetEncodedAuthenticationResponse {
    pub body: String,
    pub code: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FortinetFormError {
    #[error("invalid Fortinet authentication form: {0}")]
    Invalid(String),
    #[error("Fortinet authentication response omitted field {0}")]
    MissingResponseField(String),
}

pub fn static_fortinet_authentication_form() -> FortinetAuthenticationForm {
    let id = "_login".to_owned();
    FortinetAuthenticationForm {
        fields: vec![
            field(
                &id,
                0,
                "username",
                "Username: ",
                FortinetAuthenticationFieldKind::Text,
            ),
            field(
                &id,
                1,
                "credential",
                "Password: ",
                FortinetAuthenticationFieldKind::Password,
            ),
        ],
        id,
        action: String::new(),
        message: String::new(),
        token_info: false,
        ftm_push: false,
    }
}

pub fn parse_fortinet_authentication_result(
    content: &[u8],
) -> Result<Option<u32>, FortinetFormError> {
    let content = std::str::from_utf8(content)
        .map_err(|error| {
            invalid(format!("authentication result is not UTF-8: {error}"))
        })?
        .trim();
    let Some(result) = content.strip_prefix("ret=") else {
        return Ok(None);
    };
    let result = result
        .split([',', '&', '\r', '\n'])
        .next()
        .unwrap_or_default()
        .trim();
    if result.is_empty() || result.len() > FORTINET_MAXIMUM_TOKEN_INFO_FIELD {
        return Err(invalid("authentication result is invalid"));
    }
    let result = result.parse::<u32>().map_err(|error| {
        invalid(format!("parse authentication result: {error}"))
    })?;
    if result > i32::MAX as u32 {
        return Err(invalid("authentication result exceeds 31 bits"));
    }
    Ok(Some(result))
}

pub fn parse_fortinet_token_info(
    content: &[u8],
    username: &str,
) -> Result<FortinetAuthenticationForm, FortinetFormError> {
    let content = std::str::from_utf8(content)
        .map_err(|error| invalid(format!("tokeninfo is not UTF-8: {error}")))?
        .trim();
    if !content.starts_with("ret=") {
        return Err(invalid("tokeninfo response does not begin with ret"));
    }
    let segments = content.split(',').collect::<Vec<_>>();
    if segments.len() > FORTINET_MAXIMUM_TOKEN_INFO_FIELDS {
        return Err(invalid("tokeninfo response has too many fields"));
    }
    let mut values = HashMap::with_capacity(segments.len());
    let mut raw_pairs = HashMap::with_capacity(segments.len());
    let mut ordered_opaque_names = Vec::new();
    for segment in segments {
        if segment.len() > FORTINET_MAXIMUM_TOKEN_INFO_FIELD {
            return Err(invalid("tokeninfo field exceeds 8192 bytes"));
        }
        let Some((name, value)) = segment.split_once('=') else {
            return Err(invalid("malformed tokeninfo field"));
        };
        if name.is_empty() {
            return Err(invalid("malformed tokeninfo field"));
        }
        if values.insert(name, value).is_some() {
            return Err(invalid(format!("duplicate tokeninfo field: {name}")));
        }
        raw_pairs.insert(name, segment);
        if matches!(
            name,
            "reqid" | "polid" | "grp" | "portal" | "peer" | "magic"
        ) {
            ordered_opaque_names.push(name);
        }
    }
    let token_info = values
        .get("tokeninfo")
        .ok_or_else(|| invalid("challenge omitted tokeninfo"))?;
    let id = "_challenge".to_owned();
    let mut fields = vec![
        FortinetAuthenticationField {
            submission_key: submission_key(&id, 0),
            name: "username".into(),
            label: String::new(),
            kind: FortinetAuthenticationFieldKind::Hidden,
            value: username.into(),
            raw_pair: String::new(),
            magic: false,
        },
        field(
            &id,
            1,
            "code",
            "Code: ",
            FortinetAuthenticationFieldKind::Password,
        ),
    ];
    for name in ordered_opaque_names {
        if name == "magic" {
            continue;
        }
        fields.push(FortinetAuthenticationField {
            submission_key: submission_key(&id, fields.len()),
            name: name.into(),
            label: String::new(),
            kind: FortinetAuthenticationFieldKind::Hidden,
            value: values[name].into(),
            raw_pair: raw_pairs[name].into(),
            magic: false,
        });
    }
    if let Some(raw_pair) = raw_pairs.get("magic") {
        fields.push(FortinetAuthenticationField {
            submission_key: submission_key(&id, fields.len()),
            name: "magic".into(),
            label: String::new(),
            kind: FortinetAuthenticationFieldKind::Hidden,
            value: values["magic"].into(),
            raw_pair: (*raw_pair).into(),
            magic: true,
        });
    }
    Ok(FortinetAuthenticationForm {
        id,
        action: String::new(),
        message: values.get("chal_msg").copied().unwrap_or_default().into(),
        fields,
        token_info: true,
        ftm_push: *token_info == "ftm_push",
    })
}

pub fn parse_fortinet_html_challenge(
    content: &[u8],
) -> Result<FortinetAuthenticationForm, FortinetFormError> {
    let content = std::str::from_utf8(content).map_err(|error| {
        invalid(format!("HTML challenge is not UTF-8: {error}"))
    })?;
    let document = Html::parse_document(content);
    let form_selector = selector("form")?;
    let form = document
        .select(&form_selector)
        .next()
        .ok_or_else(|| invalid("HTTP 401 response has no HTML form"))?;
    if !attribute(&form, "method")
        .trim()
        .eq_ignore_ascii_case("POST")
    {
        return Err(invalid("HTML challenge form is not POST"));
    }
    let id = match attribute(&form, "id").trim() {
        "" => "_challenge".to_owned(),
        id => id.to_owned(),
    };
    let bold_selector = selector("b")?;
    let input_selector = selector("input")?;
    let message = form
        .select(&bold_selector)
        .next()
        .map(|element| normalize_text(element.text()))
        .unwrap_or_default();
    let mut fields = Vec::new();
    for input in form.select(&input_selector) {
        let field_type =
            match attribute(&input, "type").trim().to_ascii_lowercase() {
                value if value.is_empty() => "text".to_owned(),
                value => value,
            };
        let mut kind = match field_type.as_str() {
            "hidden" => FortinetAuthenticationFieldKind::Hidden,
            "password" => FortinetAuthenticationFieldKind::Password,
            "text" | "email" => FortinetAuthenticationFieldKind::Text,
            "submit" | "button" | "reset" | "image" => continue,
            value => {
                return Err(invalid(format!(
                    "unsupported HTML challenge input type: {value}"
                )));
            }
        };
        if attribute(&input, "style") == "display: none;" {
            kind = FortinetAuthenticationFieldKind::Hidden;
        }
        let name = attribute(&input, "name").trim();
        if name.is_empty() {
            return Err(invalid("HTML challenge input has no name"));
        }
        fields.push(FortinetAuthenticationField {
            submission_key: submission_key(&id, fields.len()),
            name: name.into(),
            label: format!("{name}: "),
            kind,
            value: attribute(&input, "value").into(),
            raw_pair: String::new(),
            magic: false,
        });
    }
    if !fields.iter().any(|field| {
        field.name == "username"
            && field.kind == FortinetAuthenticationFieldKind::Hidden
    }) || !fields.iter().any(|field| {
        field.name == "credential"
            && field.kind == FortinetAuthenticationFieldKind::Password
    }) {
        return Err(invalid(
            "HTML challenge omitted hidden username or credential input",
        ));
    }
    Ok(FortinetAuthenticationForm {
        id,
        action: attribute(&form, "action").trim().into(),
        message,
        fields,
        token_info: false,
        ftm_push: false,
    })
}

pub fn parse_fortinet_host_check_action(
    content: &[u8],
) -> Result<Option<String>, FortinetFormError> {
    let content = std::str::from_utf8(content).map_err(|error| {
        invalid(format!("host-check HTML is not UTF-8: {error}"))
    })?;
    let document = Html::parse_document(content);
    let selector = selector("form")?;
    let base = Url::parse("https://fortinet.invalid/").expect("constant URL");
    let mut result = None;
    for form in document.select(&selector) {
        let candidate = attribute(&form, "action").trim();
        if candidate.is_empty() {
            continue;
        }
        let parsed = match base.join(candidate) {
            Ok(parsed) => parsed,
            Err(error)
                if candidate.to_ascii_lowercase().contains("hostcheck") =>
            {
                return Err(invalid(format!(
                    "parse host-check form action: {error}"
                )));
            }
            Err(_) => continue,
        };
        if parsed.path() != "/remote/hostcheck_validate" {
            continue;
        }
        let method = attribute(&form, "method").trim();
        if !method.is_empty() && !method.eq_ignore_ascii_case("POST") {
            return Err(invalid("host-check validation form is not POST"));
        }
        if result.is_some() {
            return Err(invalid("host-check response has multiple forms"));
        }
        result = Some(candidate.to_owned());
    }
    Ok(result)
}

pub fn is_fortinet_html_response(content_type: &str, body: &[u8]) -> bool {
    if content_type.to_ascii_lowercase().starts_with("text/html") {
        return true;
    }
    let lower = String::from_utf8_lossy(body).trim().to_ascii_lowercase();
    lower.starts_with("<!doctype html")
        || lower.starts_with("<html")
        || lower.contains("/remote/saml/")
}

pub fn parse_fortinet_top_location(
    content: &[u8],
) -> Result<Option<String>, FortinetFormError> {
    const MARKER: &[u8] = b"top.location=\"";
    let Some(marker) = content
        .windows(MARKER.len())
        .position(|window| window == MARKER)
    else {
        return Ok(None);
    };
    let start = marker + MARKER.len();
    let mut escaped = false;
    for position in start..content.len() {
        let value = content[position];
        if escaped {
            escaped = false;
        } else if value == b'\\' {
            escaped = true;
        } else if value == b'"' {
            let mut quoted = Vec::with_capacity(position - start + 2);
            quoted.push(b'"');
            quoted.extend_from_slice(&content[start..position]);
            quoted.push(b'"');
            let location =
                serde_json::from_slice::<String>(&quoted).map_err(|error| {
                    invalid(format!("decode JavaScript redirect: {error}"))
                })?;
            if location.is_empty() {
                return Err(invalid("JavaScript redirect is empty"));
            }
            return Ok(Some(location));
        }
    }
    Err(invalid("unterminated JavaScript redirect"))
}

pub fn parse_fortinet_saml_callback(
    callback: &str,
) -> Result<String, FortinetFormError> {
    let callback_url = Url::parse(callback).map_err(|error| {
        invalid(format!("parse SAML callback URL: {error}"))
    })?;
    let authority = callback
        .split_once("://")
        .map(|(_, suffix)| suffix)
        .and_then(|suffix| suffix.split(['/', '?', '#']).next())
        .unwrap_or_default();
    let explicit_port = authority.rsplit_once(':').is_some_and(|(_, port)| {
        !port.is_empty() && port.bytes().all(|value| value.is_ascii_digit())
    });
    if !callback_url.scheme().eq_ignore_ascii_case("http")
        || !callback_url.username().is_empty()
        || callback_url.password().is_some()
        || callback_url.host_str() != Some("127.0.0.1")
        || !explicit_port
        || callback_url.path() != "/"
        || callback_url.fragment().is_some()
    {
        return Err(invalid("SAML callback URL is invalid"));
    }
    authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("SAML callback port is invalid"))?;
    let raw_query = callback_url
        .query()
        .ok_or_else(|| invalid("SAML callback omitted its sole session id"))?;
    validate_percent_encoding(raw_query)?;
    let values =
        url::form_urlencoded::parse(raw_query.as_bytes()).collect::<Vec<_>>();
    if values.len() != 1 || values[0].0 != "id" {
        return Err(invalid("SAML callback omitted its sole session id"));
    }
    let session_id = values[0].1.as_ref();
    if session_id.is_empty()
        || session_id.len() > FORTINET_MAXIMUM_SAML_SESSION_ID
        || !session_id
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'-')
    {
        return Err(invalid(
            "SAML callback session id has an invalid length or character",
        ));
    }
    Ok(session_id.to_owned())
}

pub fn encode_fortinet_authentication_response(
    form: &FortinetAuthenticationForm,
    response: &HashMap<String, String>,
    realm: &str,
    initial: bool,
) -> Result<FortinetEncodedAuthenticationResponse, FortinetFormError> {
    let mut code = String::new();
    let mut form_fields = Vec::with_capacity(form.fields.len() + 3);
    let mut opaque_fields = Vec::new();
    let mut magic_field = None;
    for field in &form.fields {
        let value = response.get(&field.submission_key).ok_or_else(|| {
            FortinetFormError::MissingResponseField(field.name.clone())
        })?;
        if field.name == "code" {
            code.clone_from(value);
        }
        let encoded = if !field.raw_pair.is_empty() && value == &field.value {
            field.raw_pair.clone()
        } else {
            format!("{}={}", query_escape(&field.name), query_escape(value))
        };
        if field.magic {
            magic_field = Some(encoded);
        } else if form.token_info && !field.raw_pair.is_empty() {
            opaque_fields.push(encoded);
        } else {
            form_fields.push(encoded);
        }
    }
    form_fields.push(format!("realm={}", query_escape(realm)));
    if initial {
        form_fields.extend(["ajax=1".into(), "just_logged_in=1".into()]);
    } else {
        form_fields.extend(opaque_fields);
        if form.ftm_push && code.is_empty() {
            form_fields.push("ftmpush=1".into());
        } else if let Some(magic) = magic_field {
            form_fields.push(magic);
        }
    }
    Ok(FortinetEncodedAuthenticationResponse {
        body: form_fields.join("&"),
        code,
    })
}

fn field(
    form_id: &str,
    index: usize,
    name: &str,
    label: &str,
    kind: FortinetAuthenticationFieldKind,
) -> FortinetAuthenticationField {
    FortinetAuthenticationField {
        submission_key: submission_key(form_id, index),
        name: name.into(),
        label: label.into(),
        kind,
        value: String::new(),
        raw_pair: String::new(),
        magic: false,
    }
}

fn submission_key(form_id: &str, index: usize) -> String {
    format!("{form_id}:{index}")
}

fn query_escape(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn selector(value: &str) -> Result<Selector, FortinetFormError> {
    Selector::parse(value).map_err(|error| invalid(error.to_string()))
}

fn attribute<'a>(element: &'a scraper::ElementRef<'a>, name: &str) -> &'a str {
    element.value().attr(name).unwrap_or_default()
}

fn normalize_text<'a>(text: impl Iterator<Item = &'a str>) -> String {
    text.flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_percent_encoding(value: &str) -> Result<(), FortinetFormError> {
    let value = value.as_bytes();
    let mut position = 0;
    while position < value.len() {
        if value[position] == b'%' {
            if position + 2 >= value.len()
                || !value[position + 1].is_ascii_hexdigit()
                || !value[position + 2].is_ascii_hexdigit()
            {
                return Err(invalid(
                    "SAML callback query has invalid escaping",
                ));
            }
            position += 3;
        } else {
            position += 1;
        }
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> FortinetFormError {
    FortinetFormError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_result_and_token_info_in_wire_order() {
        assert_eq!(
            parse_fortinet_authentication_result(b" ret=1,foo=bar ").unwrap(),
            Some(1)
        );
        assert_eq!(
            parse_fortinet_authentication_result(b"html").unwrap(),
            None
        );
        let form = parse_fortinet_token_info(
            b"ret=2,tokeninfo=ftm_push,reqid=r%2F1,grp=g,magic=m%2B1,chal_msg=Approve",
            "alice",
        )
        .unwrap();
        assert!(form.ftm_push);
        assert_eq!(form.message, "Approve");
        assert_eq!(form.fields[2].raw_pair, "reqid=r%2F1");
        assert_eq!(form.fields[3].raw_pair, "grp=g");
        assert!(form.fields[4].magic);
    }

    #[test]
    fn parses_html_challenge_and_host_check() {
        let html = br#"<html><form id="challenge" method="post" action="/remote/logincheck"><b>Enter <i>OTP</i> now</b><input type="hidden" name="username" value="alice"><input type="password" name="credential"><input type="submit"></form></html>"#;
        let form = parse_fortinet_html_challenge(html).unwrap();
        assert_eq!(form.id, "challenge");
        assert_eq!(form.message, "Enter OTP now");
        assert_eq!(form.fields.len(), 2);
        assert_eq!(form.fields[0].submission_key, "challenge:0");

        let action = parse_fortinet_host_check_action(
            br#"<form method="POST" action="/remote/hostcheck_validate?x=1"></form>"#,
        )
        .unwrap();
        assert_eq!(action.as_deref(), Some("/remote/hostcheck_validate?x=1"));
    }

    #[test]
    fn encodes_initial_and_push_challenge_exactly() {
        let login = static_fortinet_authentication_form();
        let response = HashMap::from([
            ("_login:0".into(), "alice smith".into()),
            ("_login:1".into(), "p+a s/s".into()),
        ]);
        let encoded = encode_fortinet_authentication_response(
            &login,
            &response,
            "staff realm",
            true,
        )
        .unwrap();
        assert_eq!(
            encoded.body,
            "username=alice+smith&credential=p%2Ba+s%2Fs&realm=staff+realm&ajax=1&just_logged_in=1"
        );

        let push = parse_fortinet_token_info(
            b"ret=2,tokeninfo=ftm_push,reqid=r%2F1,magic=m%2B1",
            "alice",
        )
        .unwrap();
        let response = push
            .fields
            .iter()
            .map(|field| (field.submission_key.clone(), field.value.clone()))
            .collect();
        let encoded = encode_fortinet_authentication_response(
            &push, &response, "", false,
        )
        .unwrap();
        assert_eq!(
            encoded.body,
            "username=alice&code=&realm=&reqid=r%2F1&ftmpush=1"
        );
    }

    #[test]
    fn rejects_duplicate_token_fields_and_ambiguous_host_check() {
        assert!(
            parse_fortinet_token_info(b"ret=2,tokeninfo=x,tokeninfo=y", "a")
                .is_err()
        );
        assert!(
            parse_fortinet_host_check_action(
                br#"<form action="/remote/hostcheck_validate"></form><form action="/remote/hostcheck_validate"></form>"#,
            )
            .is_err()
        );
    }

    #[test]
    fn parses_javascript_redirect_and_detects_html() {
        assert_eq!(
            parse_fortinet_top_location(
                br#"<script>top.location="/remote/login?realm=staff";</script>"#,
            )
            .unwrap()
            .as_deref(),
            Some("/remote/login?realm=staff")
        );
        assert_eq!(
            parse_fortinet_top_location(br#"top.location="a\"b""#)
                .unwrap()
                .as_deref(),
            Some("a\"b")
        );
        assert!(is_fortinet_html_response("text/html; charset=utf-8", b"x"));
        assert!(is_fortinet_html_response("", b" <!DOCTYPE HTML><p>x"));
        assert!(is_fortinet_html_response("", b"go /remote/saml/start"));
    }

    #[test]
    fn validates_saml_callback_exactly() {
        assert_eq!(
            parse_fortinet_saml_callback("http://127.0.0.1:8020/?id=abc-123")
                .unwrap(),
            "abc-123"
        );
        for invalid in [
            "https://127.0.0.1:8020/?id=x",
            "http://localhost:8020/?id=x",
            "http://127.0.0.1/?id=x",
            "http://127.0.0.1:8020/path?id=x",
            "http://127.0.0.1:8020/?id=x&id=y",
            "http://127.0.0.1:8020/?id=bad_underscore",
            "http://127.0.0.1:8020/?id=%zz",
        ] {
            assert!(
                parse_fortinet_saml_callback(invalid).is_err(),
                "{invalid}"
            );
        }
    }
}
