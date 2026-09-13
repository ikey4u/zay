//! GlobalProtect prelogin, portal, gateway-login and challenge forms.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;

use super::{
    GlobalProtectFailureClass, classify_globalprotect_response_error,
    encode_globalprotect_form_component,
    gp_config::{XmlNode, parse_xml},
};

pub const GLOBALPROTECT_DEFAULT_CLIENT_VERSION: &str = "6.3.0-33";
pub const GLOBALPROTECT_AUTHENTICATION_FORM_ID: &str = "_login";
pub const GLOBALPROTECT_CHALLENGE_FORM_ID: &str = "_challenge";
pub const GLOBALPROTECT_PORTAL_FORM_ID: &str = "_portal";

const LOGIN_ARGUMENT_AUTH_COOKIE: usize = 1;
const LOGIN_ARGUMENT_PORTAL: usize = 3;
const LOGIN_ARGUMENT_USER: usize = 4;
const LOGIN_ARGUMENT_DOMAIN: usize = 7;
const LOGIN_ARGUMENT_CONNECTION_TYPE: usize = 12;
const LOGIN_ARGUMENT_CLIENT_VERSION: usize = 14;
const LOGIN_ARGUMENT_PREFERRED_IP: usize = 15;
const LOGIN_ARGUMENT_PREFERRED_IPV6: usize = 18;
const LOGIN_KNOWN_ARGUMENT_COUNT: usize = 21;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GlobalProtectFormError {
    #[error("invalid GlobalProtect response: {0}")]
    InvalidResponse(String),
    #[error("GlobalProtect response error ({class:?}): {message}")]
    Response {
        class: GlobalProtectFailureClass,
        message: String,
    },
    #[error("invalid GlobalProtect XML: {0}")]
    InvalidXml(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalProtectChallenge {
    pub message: String,
    pub input_string: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalProtectPreloginForm {
    pub message: String,
    pub username_label: String,
    pub password_label: String,
    pub region: String,
    pub saml_method: String,
    pub saml_request: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectPortalGateway {
    pub name: String,
    pub label: String,
    pub priority: i64,
    pub form_value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalProtectPortalConfiguration {
    pub gateways: Vec<GlobalProtectPortalGateway>,
    pub portal_user_auth_cookie: String,
    pub portal_prelogon_user_auth_cookie: String,
    pub hip_report_interval: Duration,
    pub client_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalProtectPortalResponse {
    Configuration(GlobalProtectPortalConfiguration),
    Challenge(GlobalProtectChallenge),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalProtectLoginResponse {
    OpaqueQuery(String),
    Challenge(GlobalProtectChallenge),
}

pub fn parse_globalprotect_prelogin_response(
    content: &[u8],
) -> Result<GlobalProtectPreloginForm, GlobalProtectFormError> {
    if inspect_response(content)?.is_some() {
        return Err(GlobalProtectFormError::InvalidResponse(
            "prelogin returned an authentication challenge".into(),
        ));
    }
    let root = parse_form_xml(content)?;
    if root.name != "prelogin-response" {
        return Err(invalid(format!(
            "prelogin returned unexpected XML root: {}",
            root.name
        )));
    }
    if root.child_text("status").unwrap_or_default().trim() != "Success" {
        return Err(invalid(format!(
            "prelogin failed: {}",
            root.child_text("msg").unwrap_or_default().trim()
        )));
    }
    Ok(GlobalProtectPreloginForm {
        message: text(&root, "authentication-message"),
        username_label: text(&root, "username-label"),
        password_label: text(&root, "password-label"),
        region: text(&root, "region"),
        saml_method: text(&root, "saml-auth-method"),
        saml_request: text(&root, "saml-request"),
    })
}

pub fn parse_globalprotect_portal_response(
    content: &[u8],
    region: &str,
) -> Result<GlobalProtectPortalResponse, GlobalProtectFormError> {
    if let Some(challenge) = inspect_response(content)? {
        return Ok(GlobalProtectPortalResponse::Challenge(challenge));
    }
    let root = parse_form_xml(content)?;
    if root.name != "policy" {
        return Err(invalid(format!(
            "portal returned unexpected XML root: {}",
            root.name
        )));
    }
    let mut configuration = GlobalProtectPortalConfiguration {
        portal_user_auth_cookie: normalize_portal_cookie(text(
            &root,
            "portal-userauthcookie",
        )),
        portal_prelogon_user_auth_cookie: normalize_portal_cookie(text(
            &root,
            "portal-prelogonuserauthcookie",
        )),
        hip_report_interval: parse_globalprotect_hip_report_interval(
            find_path(&root, &["hip-collection", "hip-report-interval"])
                .map(|node| node.text.trim())
                .unwrap_or_default(),
        )?,
        client_version: text(&root, "version"),
        gateways: Vec::new(),
    };
    let entries = find_path(&root, &["gateways", "external", "list"])
        .map(|list| {
            list.children
                .iter()
                .filter(|node| node.name == "entry")
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (index, entry) in entries.into_iter().enumerate() {
        let name = entry.attribute("name").unwrap_or_default().trim();
        if name.is_empty() {
            return Err(invalid(
                "portal returned a gateway without an endpoint name",
            ));
        }
        let description = text(entry, "description");
        let priority = portal_gateway_priority(entry, region)?;
        configuration.gateways.push(GlobalProtectPortalGateway {
            name: name.into(),
            label: if description.is_empty() {
                name.into()
            } else {
                description
            },
            priority,
            form_value: format!("{name}#{index}"),
        });
    }
    if configuration.gateways.is_empty() {
        return Err(invalid("portal configuration lists no gateway servers"));
    }
    configuration
        .gateways
        .sort_by_key(|gateway| gateway.priority);
    Ok(GlobalProtectPortalResponse::Configuration(configuration))
}

pub fn parse_globalprotect_login_response(
    content: &[u8],
    local_hostname: &str,
) -> Result<GlobalProtectLoginResponse, GlobalProtectFormError> {
    if let Some(challenge) = inspect_response(content)? {
        return Ok(GlobalProtectLoginResponse::Challenge(challenge));
    }
    let root = parse_form_xml(content)?;
    if root.name != "jnlp" {
        return Err(invalid(format!(
            "gateway login returned unexpected XML root: {}",
            root.name
        )));
    }
    let application = root
        .children
        .iter()
        .find(|node| node.name == "application-desc")
        .ok_or_else(|| invalid("gateway login omitted application-desc"))?;
    if let Some(unexpected) = application
        .children
        .iter()
        .find(|node| node.name != "argument")
    {
        return Err(invalid(format!(
            "gateway login returned unexpected JNLP element: {}",
            unexpected.name
        )));
    }
    let mut arguments = application
        .children
        .iter()
        .filter(|node| node.name == "argument")
        .map(|node| node.text.clone())
        .collect::<Vec<_>>();
    arguments.resize(LOGIN_KNOWN_ARGUMENT_COUNT, String::new());
    let argument = |index: usize| -> &str {
        normalize_login_argument(arguments[index].as_str())
    };
    if argument(LOGIN_ARGUMENT_AUTH_COOKIE).is_empty() {
        return Err(invalid("gateway login omitted authcookie"));
    }
    if argument(LOGIN_ARGUMENT_USER).is_empty() {
        return Err(invalid("gateway login omitted user"));
    }
    if argument(LOGIN_ARGUMENT_CONNECTION_TYPE) != "tunnel" {
        return Err(invalid(format!(
            "gateway login returned connection-type {}, expected tunnel",
            argument(LOGIN_ARGUMENT_CONNECTION_TYPE)
        )));
    }
    if argument(LOGIN_ARGUMENT_CLIENT_VERSION) != "4100" {
        return Err(invalid(format!(
            "gateway login returned clientVer {}, expected 4100",
            argument(LOGIN_ARGUMENT_CLIENT_VERSION)
        )));
    }
    let mut parameters = Vec::new();
    for (name, index) in [
        ("authcookie", LOGIN_ARGUMENT_AUTH_COOKIE),
        ("portal", LOGIN_ARGUMENT_PORTAL),
        ("user", LOGIN_ARGUMENT_USER),
        ("domain", LOGIN_ARGUMENT_DOMAIN),
        ("preferred-ip", LOGIN_ARGUMENT_PREFERRED_IP),
        ("preferred-ipv6", LOGIN_ARGUMENT_PREFERRED_IPV6),
    ] {
        let value = argument(index);
        if !value.is_empty() {
            parameters.push(format!(
                "{}={}",
                encode_globalprotect_form_component(name),
                encode_globalprotect_form_component(
                    &decode_globalprotect_form_component(value)
                )
            ));
        }
    }
    parameters.push(format!(
        "computer={}",
        encode_globalprotect_form_component(local_hostname)
    ));
    Ok(GlobalProtectLoginResponse::OpaqueQuery(
        parameters.join("&"),
    ))
}

pub fn parse_globalprotect_logout_response(
    content: &[u8],
) -> Result<(), GlobalProtectFormError> {
    if inspect_response(content)?.is_some() {
        return Err(invalid(
            "logout unexpectedly returned an authentication challenge",
        ));
    }
    let root = parse_form_xml(content)?;
    if root.name != "response"
        || root.attribute("status").unwrap_or_default() != "success"
    {
        return Err(invalid("logout did not return a successful response"));
    }
    Ok(())
}

pub fn decode_globalprotect_saml_url(
    method: &str,
    request: &str,
) -> Result<String, GlobalProtectFormError> {
    match method {
        "REDIRECT" => {
            let decoded = STANDARD.decode(request).map_err(|error| {
                invalid(format!("decode SAML REDIRECT request: {error}"))
            })?;
            if decoded.is_empty() {
                return Err(invalid("SAML REDIRECT request is empty"));
            }
            String::from_utf8(decoded)
                .map_err(|_| invalid("SAML REDIRECT request is not UTF-8"))
        }
        "POST" if !request.is_empty() => {
            Ok(format!("data:text/html;base64,{request}"))
        }
        "POST" => Err(invalid("SAML POST request is empty")),
        _ => Err(invalid(format!(
            "unsupported SAML authentication method: {method}"
        ))),
    }
}

pub fn decode_globalprotect_form_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'+' {
            decoded.push(b' ');
        } else if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push(high << 4 | low);
                index += 2;
            } else {
                decoded.push(bytes[index]);
            }
        } else {
            decoded.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

pub fn parse_globalprotect_hip_report_interval(
    value: &str,
) -> Result<Duration, GlobalProtectFormError> {
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return Ok(Duration::ZERO);
    }
    let seconds = value.parse::<i64>().map_err(|_| {
        invalid(format!("invalid HIP report interval: {value}"))
    })?;
    if seconds < 0 || seconds as u64 > i64::MAX as u64 / 1_000_000_000 {
        return Err(invalid(format!("invalid HIP report interval: {seconds}")));
    }
    let interval = Duration::from_secs(seconds as u64);
    if interval > Duration::from_secs(60) {
        Ok(interval - Duration::from_secs(60))
    } else {
        Ok((interval / 2).max(Duration::from_secs(1)))
    }
}

fn inspect_response(
    content: &[u8],
) -> Result<Option<GlobalProtectChallenge>, GlobalProtectFormError> {
    let response = std::str::from_utf8(content)
        .map_err(|_| invalid("server response is not UTF-8"))?
        .trim();
    if response.is_empty() {
        return Err(invalid("server returned an empty response"));
    }
    if response.starts_with("var respStatus") {
        return parse_javascript_challenge(response).map(Some);
    }
    let root = parse_form_xml(content)?;
    match root.name.as_str() {
        "challenge" => {
            let message = root
                .child_text("respmsg")
                .ok_or_else(|| invalid("XML challenge omitted respmsg"))?;
            let input_string = root
                .child_text("inputstr")
                .ok_or_else(|| invalid("XML challenge omitted inputstr"))?;
            Ok(Some(GlobalProtectChallenge {
                message: message.into(),
                input_string: input_string.into(),
            }))
        }
        "html" => parse_javascript_challenge(
            root.child_text("body").unwrap_or_default().trim(),
        )
        .map(Some),
        "response"
            if root.attribute("status") == Some("error")
                || root.child_text("status") == Some("error") =>
        {
            Err(response_error(root.child_text("error").unwrap_or_default()))
        }
        "prelogin-response"
            if root.child_text("status").unwrap_or_default().trim()
                != "Success" =>
        {
            Err(response_error(root.child_text("msg").unwrap_or_default()))
        }
        _ => Ok(None),
    }
}

fn parse_javascript_challenge(
    response: &str,
) -> Result<GlobalProtectChallenge, GlobalProtectFormError> {
    let (status, remaining) =
        consume_javascript_assignment(response.trim(), "var respStatus = ")
            .ok_or_else(|| {
                invalid("failed to parse JavaScript challenge status")
            })?;
    let (message, remaining) =
        consume_javascript_assignment(remaining, "var respMsg = ").ok_or_else(
            || invalid("failed to parse JavaScript challenge message"),
        )?;
    let (input_string, remaining) =
        consume_javascript_assignment(remaining, "thisForm.inputStr.value = ")
            .ok_or_else(|| {
                invalid("failed to parse JavaScript challenge inputStr")
            })?;
    if !remaining
        .trim_matches([';', ' ', '\t', '\r', '\n'])
        .is_empty()
    {
        return Err(invalid(
            "JavaScript challenge contains unexpected trailing input",
        ));
    }
    let decoded_message = decode_javascript_string(message);
    if status.starts_with("Error") {
        return Err(invalid(format!(
            "authentication failed: {decoded_message}"
        )));
    }
    if !status.starts_with("Challenge") {
        return Err(invalid(format!(
            "JavaScript response returned unknown status: {status}"
        )));
    }
    Ok(GlobalProtectChallenge {
        message: decoded_message,
        input_string: input_string.into(),
    })
}

fn consume_javascript_assignment<'a>(
    input: &'a str,
    prefix: &str,
) -> Option<(&'a str, &'a str)> {
    let input = input.trim_start_matches([';', ' ', '\t', '\r', '\n']);
    let quoted = input.strip_prefix(prefix)?;
    if !quoted.starts_with('"') {
        return None;
    }
    let bytes = quoted.as_bytes();
    let mut escaped = false;
    for index in 1..bytes.len() {
        if bytes[index] == b'\\' {
            escaped = !escaped;
        } else {
            if bytes[index] == b'"' && !escaped {
                return Some((&quoted[1..index], &quoted[index + 1..]));
            }
            escaped = false;
        }
    }
    None
}

fn decode_javascript_string(value: &str) -> String {
    let value = value.replace("\\'", "'");
    serde_json::from_str::<String>(&format!("\"{value}\"")).unwrap_or(value)
}

fn portal_gateway_priority(
    entry: &XmlNode,
    region: &str,
) -> Result<i64, GlobalProtectFormError> {
    let Some(rules) = find_path(entry, &["priority-rule"]) else {
        return Ok(i64::MAX);
    };
    let mut priority = i64::MAX;
    for rule in rules.children.iter().filter(|node| node.name == "entry") {
        let name = rule.attribute("name").unwrap_or_default().trim();
        if name != region && name != "Any" {
            continue;
        }
        let value = rule.child_text("priority").unwrap_or_default().trim();
        if value.is_empty() {
            continue;
        }
        priority = priority.min(value.parse::<i64>().map_err(|_| {
            invalid(format!(
                "invalid gateway priority for region {name}: {value}"
            ))
        })?);
    }
    Ok(priority)
}

fn find_path<'a>(node: &'a XmlNode, path: &[&str]) -> Option<&'a XmlNode> {
    path.iter().try_fold(node, |node, name| {
        node.children.iter().find(|child| child.name == *name)
    })
}

fn text(node: &XmlNode, name: &str) -> String {
    node.child_text(name).unwrap_or_default().trim().into()
}

fn normalize_login_argument(value: &str) -> &str {
    if matches!(value, "" | "(null)" | "-1") {
        ""
    } else {
        value
    }
}

fn normalize_portal_cookie(value: String) -> String {
    if value == "empty" {
        String::new()
    } else {
        value
    }
}

fn response_error(message: &str) -> GlobalProtectFormError {
    let message = message.trim();
    GlobalProtectFormError::Response {
        class: classify_globalprotect_response_error(message),
        message: if message.is_empty() {
            "server returned an unspecified error".into()
        } else {
            message.into()
        },
    }
}

fn parse_form_xml(content: &[u8]) -> Result<XmlNode, GlobalProtectFormError> {
    parse_xml(content)
        .map_err(|error| GlobalProtectFormError::InvalidXml(error.to_string()))
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> GlobalProtectFormError {
    GlobalProtectFormError::InvalidResponse(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prelogin_and_saml_urls() {
        let form = parse_globalprotect_prelogin_response(br#"<prelogin-response><status>Success</status><authentication-message>Sign in</authentication-message><username-label>Account</username-label><password-label>Passcode</password-label><region>EU</region><saml-auth-method>REDIRECT</saml-auth-method><saml-request>aHR0cHM6Ly9pZHAuZXhhbXBsZS8=</saml-request></prelogin-response>"#).unwrap();
        assert_eq!(form.region, "EU");
        assert_eq!(
            decode_globalprotect_saml_url(
                &form.saml_method,
                &form.saml_request
            )
            .unwrap(),
            "https://idp.example/"
        );
    }

    #[test]
    fn parses_and_stably_sorts_portal_gateways() {
        let response = parse_globalprotect_portal_response(br#"<policy><version>6.3</version><gateways><external><list>
          <entry name="late.example"><description>Late</description><priority-rule><entry name="Any"><priority>5</priority></entry></priority-rule></entry>
          <entry name="eu.example"><description>EU</description><priority-rule><entry name="EU"><priority>1</priority></entry></priority-rule></entry>
        </list></external></gateways><hip-collection><hip-report-interval>120</hip-report-interval></hip-collection><portal-userauthcookie>empty</portal-userauthcookie></policy>"#, "EU").unwrap();
        let GlobalProtectPortalResponse::Configuration(configuration) =
            response
        else {
            panic!("expected configuration")
        };
        assert_eq!(configuration.gateways[0].name, "eu.example");
        assert_eq!(configuration.gateways[0].form_value, "eu.example#1");
        assert_eq!(configuration.hip_report_interval, Duration::from_secs(60));
        assert!(configuration.portal_user_auth_cookie.is_empty());
    }

    #[test]
    fn parses_jnlp_into_canonical_opaque_query() {
        let mut arguments = vec!["(null)"; LOGIN_KNOWN_ARGUMENT_COUNT];
        arguments[LOGIN_ARGUMENT_AUTH_COOKIE] = "a%2fb";
        arguments[LOGIN_ARGUMENT_PORTAL] = "portal.example";
        arguments[LOGIN_ARGUMENT_USER] = "alice%40example";
        arguments[LOGIN_ARGUMENT_CONNECTION_TYPE] = "tunnel";
        arguments[LOGIN_ARGUMENT_CLIENT_VERSION] = "4100";
        let body = arguments
            .into_iter()
            .map(|argument| format!("<argument>{argument}</argument>"))
            .collect::<String>();
        let xml =
            format!("<jnlp><application-desc>{body}</application-desc></jnlp>");
        let response =
            parse_globalprotect_login_response(xml.as_bytes(), "host one")
                .unwrap();
        assert_eq!(response, GlobalProtectLoginResponse::OpaqueQuery("authcookie=a%2fb&portal=portal.example&user=alice%40example&computer=host%20one".into()));
    }

    #[test]
    fn accepts_xml_and_javascript_challenges() {
        let xml = parse_globalprotect_portal_response(br#"<challenge><respmsg>OTP &amp; PIN</respmsg><inputstr>abc</inputstr></challenge>"#, "").unwrap();
        assert_eq!(
            xml,
            GlobalProtectPortalResponse::Challenge(GlobalProtectChallenge {
                message: "OTP & PIN".into(),
                input_string: "abc".into()
            })
        );
        let js = parse_globalprotect_portal_response(br#"var respStatus = "Challenge"; var respMsg = "Enter \u004fTP"; thisForm.inputStr.value = "token";"#, "").unwrap();
        assert_eq!(
            js,
            GlobalProtectPortalResponse::Challenge(GlobalProtectChallenge {
                message: "Enter OTP".into(),
                input_string: "token".into()
            })
        );
    }

    #[test]
    fn malformed_percent_sequences_are_preserved() {
        assert_eq!(
            decode_globalprotect_form_component("a+b%2Fc%zz%"),
            "a b/c%zz%"
        );
        assert_eq!(encode_globalprotect_form_component("a b/c"), "a%20b%2fc");
    }
}
