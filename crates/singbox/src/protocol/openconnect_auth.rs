//! AnyConnect authentication XML/form compatibility primitives.
//!
//! The stateful HTTP exchange is intentionally kept outside this module so an
//! embedding application can use its own dialer and TLS stack.  These helpers
//! cover the protocol-owned XML parsing, form mutation, reply encoding, and
//! direct-cookie normalization used by that exchange.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};

use http::HeaderMap;
use quick_xml::{
    Reader, Writer, XmlVersion,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};
use thiserror::Error;

const MAX_AUTH_XML_SIZE: usize = 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnyConnectAuthError {
    #[error("AnyConnect authentication XML exceeds {MAX_AUTH_XML_SIZE} bytes")]
    XmlTooLarge,
    #[error("invalid AnyConnect authentication XML: {0}")]
    InvalidXml(String),
    #[error("unexpected AnyConnect authentication XML root: {0}")]
    UnexpectedRoot(String),
    #[error("AnyConnect authentication XML has no auth node")]
    MissingAuth,
    #[error("AnyConnect authentication auth node has no id")]
    MissingAuthId,
    #[error("unsupported AnyConnect authentication form method: {0}")]
    UnsupportedMethod(String),
    #[error("AnyConnect authentication form has an empty action")]
    EmptyAction,
    #[error("AnyConnect authentication select has no name")]
    SelectWithoutName,
    #[error("direct authentication cookie has no name: {0}")]
    CookieWithoutName(String),
    #[error("direct authentication cookie has an empty name")]
    EmptyCookieName,
    #[error("direct authentication cookie is empty")]
    EmptyCookie,
    #[error("openconnect browser request omitted its URL")]
    BrowserUrlMissing,
    #[error(
        "openconnect browser request must select exactly one completion mode"
    )]
    BrowserModeAmbiguous,
    #[error("invalid openconnect browser request: {0}")]
    InvalidBrowserRequest(String),
    #[error("invalid openconnect browser authentication: {0}")]
    InvalidBrowserResponse(String),
    #[error("unknown openconnect authentication submission key: {0}")]
    UnknownSubmissionKey(String),
    #[error("missing openconnect authentication submission key: {0}")]
    MissingSubmissionKey(String),
    #[error(
        "invalid openconnect authentication selection for submission key: {0}"
    )]
    InvalidSelection(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyConnectAuthFieldKind {
    Text,
    Password,
    Select,
    Hidden,
    Token,
    SsoToken,
    SsoUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyConnectAuthChoice {
    pub name: String,
    pub label: String,
    pub authentication_type: String,
    pub override_name: String,
    pub override_label: String,
    pub second_authentication: bool,
    pub secondary_username: String,
    pub secondary_username_editable: bool,
    pub no_aaa: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyConnectAuthField {
    pub name: String,
    pub label: String,
    pub server_label: String,
    pub value: String,
    pub kind: AnyConnectAuthFieldKind,
    pub second_authentication: bool,
    pub choices: Vec<AnyConnectAuthChoice>,
    pub selected_choice: usize,
    pub ignore: bool,
    pub stable_credential: bool,
    pub submission_key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectOpaque {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub inner_xml: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectHostScan {
    pub ticket: String,
    pub token: String,
    pub base_url: String,
    pub wait_url: String,
    pub stub_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectSso {
    pub login_url: String,
    pub final_url: String,
    pub token_cookie: String,
    pub error_cookie: String,
    pub browser_mode: String,
    pub requested: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectAuthForm {
    pub authentication_id: String,
    pub banner: String,
    pub message: String,
    pub error: String,
    pub action: String,
    pub fields: Vec<AnyConnectAuthField>,
    pub authentication_complete: bool,
    pub post_authentication_complete: bool,
    pub session_token: String,
    pub opaque: Option<AnyConnectOpaque>,
    pub host_scan: AnyConnectHostScan,
    pub sso: AnyConnectSso,
    pub client_certificate_requested: bool,
    pub client_certificate_authenticated: bool,
    pub multiple_certificates_requested: bool,
    pub multiple_certificate_hash_methods: Vec<String>,
    pub raw_response: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectAuthMobileIdentity {
    pub platform_version: String,
    pub device_type: String,
    pub device_unique_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectAuthClientIdentity {
    pub version: String,
    pub reported_os: String,
    pub mobile: Option<AnyConnectAuthMobileIdentity>,
    pub external_auth_disabled: bool,
    pub multiple_certificate_authentication: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenConnectAuthPromptKind {
    Text,
    Password,
    Select,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenConnectAuthPromptChoice {
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenConnectAuthPromptField {
    pub submission_key: String,
    pub name: String,
    pub label: String,
    pub kind: OpenConnectAuthPromptKind,
    pub value: String,
    pub options: Vec<OpenConnectAuthPromptChoice>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenConnectAuthPromptForm {
    pub fields: Vec<OpenConnectAuthPromptField>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenConnectBrowserRequest {
    pub url: String,
    pub final_url: String,
    pub callback_url_prefixes: Vec<String>,
    pub cookie_names: Vec<String>,
    pub early_cookie_names: Vec<String>,
    pub header_names: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenConnectBrowserCookie {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenConnectBrowserResult {
    pub final_url: String,
    pub cookies: Vec<OpenConnectBrowserCookie>,
    pub headers: HeaderMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenConnectAuthChallengeKind {
    Form(OpenConnectAuthPromptForm),
    Browser(OpenConnectBrowserRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenConnectAuthChallenge {
    pub id: String,
    pub banner: String,
    pub message: String,
    pub error: String,
    pub kind: OpenConnectAuthChallengeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenConnectAuthResponse {
    Form(BTreeMap<String, String>),
    Browser(OpenConnectBrowserResult),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenConnectBrowserAuthMode {
    Callback,
    Cookies,
    Headers,
}

static AUTH_CHALLENGE_IDENTIFIER: AtomicU64 = AtomicU64::new(0);

pub fn new_openconnect_auth_challenge(
    banner: impl Into<String>,
    message: impl Into<String>,
    error: impl Into<String>,
    kind: OpenConnectAuthChallengeKind,
) -> OpenConnectAuthChallenge {
    OpenConnectAuthChallenge {
        id: AUTH_CHALLENGE_IDENTIFIER
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .to_string(),
        banner: banner.into(),
        message: message.into(),
        error: error.into(),
        kind,
    }
}

pub fn validate_openconnect_form_response(
    fields: &[OpenConnectAuthPromptField],
    values: &BTreeMap<String, String>,
) -> Result<(), AnyConnectAuthError> {
    let expected = fields
        .iter()
        .map(|field| (field.submission_key.as_str(), field))
        .collect::<BTreeMap<_, _>>();
    for submission_key in values.keys() {
        if !expected.contains_key(submission_key.as_str()) {
            return Err(AnyConnectAuthError::UnknownSubmissionKey(
                submission_key.clone(),
            ));
        }
    }
    for (submission_key, field) in expected {
        let value = values.get(submission_key).ok_or_else(|| {
            AnyConnectAuthError::MissingSubmissionKey(submission_key.into())
        })?;
        if field.kind == OpenConnectAuthPromptKind::Select
            && !field.options.iter().any(|choice| choice.value == *value)
        {
            return Err(AnyConnectAuthError::InvalidSelection(
                submission_key.into(),
            ));
        }
    }
    Ok(())
}

pub fn validate_openconnect_browser_request(
    request: &OpenConnectBrowserRequest,
) -> Result<OpenConnectBrowserAuthMode, AnyConnectAuthError> {
    if request.url.is_empty() {
        return Err(AnyConnectAuthError::BrowserUrlMissing);
    }
    let callback_mode = !request.callback_url_prefixes.is_empty();
    let cookie_mode = !request.final_url.is_empty()
        || !request.cookie_names.is_empty()
        || !request.early_cookie_names.is_empty();
    let header_mode = !request.header_names.is_empty();
    if usize::from(callback_mode)
        + usize::from(cookie_mode)
        + usize::from(header_mode)
        != 1
    {
        return Err(AnyConnectAuthError::BrowserModeAmbiguous);
    }
    if callback_mode {
        if !request.final_url.is_empty()
            || !request.cookie_names.is_empty()
            || !request.early_cookie_names.is_empty()
            || !request.header_names.is_empty()
        {
            return Err(AnyConnectAuthError::InvalidBrowserRequest(
                "callback mode contains fields from another completion mode"
                    .into(),
            ));
        }
        if invalid_string_list(&request.callback_url_prefixes, false) {
            return Err(AnyConnectAuthError::InvalidBrowserRequest(
                "callback mode contains an empty or duplicate URL prefix"
                    .into(),
            ));
        }
        return Ok(OpenConnectBrowserAuthMode::Callback);
    }
    if cookie_mode {
        if request.final_url.is_empty()
            || request.cookie_names.is_empty()
            || !request.callback_url_prefixes.is_empty()
            || !request.header_names.is_empty()
        {
            return Err(AnyConnectAuthError::InvalidBrowserRequest(
                "cookie mode requires only a final URL and cookie names".into(),
            ));
        }
        if invalid_string_list(&request.cookie_names, false)
            || invalid_string_list(&request.early_cookie_names, false)
        {
            return Err(AnyConnectAuthError::InvalidBrowserRequest(
                "cookie mode contains an empty or duplicate cookie name".into(),
            ));
        }
        if request
            .early_cookie_names
            .iter()
            .any(|name| request.cookie_names.contains(name))
        {
            return Err(AnyConnectAuthError::InvalidBrowserRequest(
                "cookie mode repeats an early cookie in final cookie names"
                    .into(),
            ));
        }
        return Ok(OpenConnectBrowserAuthMode::Cookies);
    }
    if !request.final_url.is_empty()
        || !request.callback_url_prefixes.is_empty()
        || !request.cookie_names.is_empty()
        || !request.early_cookie_names.is_empty()
    {
        return Err(AnyConnectAuthError::InvalidBrowserRequest(
            "header mode contains fields from another completion mode".into(),
        ));
    }
    if invalid_string_list(&request.header_names, true) {
        return Err(AnyConnectAuthError::InvalidBrowserRequest(
            "header mode contains an empty or duplicate header name".into(),
        ));
    }
    Ok(OpenConnectBrowserAuthMode::Headers)
}

pub fn validate_openconnect_browser_response(
    request: &OpenConnectBrowserRequest,
    result: &OpenConnectBrowserResult,
) -> Result<(), AnyConnectAuthError> {
    let mode = validate_openconnect_browser_request(request)?;
    match mode {
        OpenConnectBrowserAuthMode::Callback => {
            if result.final_url.is_empty()
                || !result.cookies.is_empty()
                || !result.headers.is_empty()
            {
                return invalid_browser_response(
                    "invalid callback result shape",
                );
            }
            if request
                .callback_url_prefixes
                .iter()
                .any(|prefix| result.final_url.starts_with(prefix))
            {
                Ok(())
            } else {
                invalid_browser_response(
                    "browser callback URL did not match an accepted prefix",
                )
            }
        }
        OpenConnectBrowserAuthMode::Cookies => {
            if result.final_url.is_empty()
                && result.headers.is_empty()
                && result.cookies.len() == 1
            {
                let cookie = &result.cookies[0];
                if !cookie.value.is_empty()
                    && request.early_cookie_names.contains(&cookie.name)
                {
                    return Ok(());
                }
            }
            if result.final_url != request.final_url
                || result.cookies.is_empty()
                || !result.headers.is_empty()
            {
                return invalid_browser_response("invalid cookie result shape");
            }
            let mut seen = BTreeSet::new();
            for cookie in &result.cookies {
                if cookie.name.is_empty()
                    || cookie.value.is_empty()
                    || !request.cookie_names.contains(&cookie.name)
                {
                    return invalid_browser_response(
                        "browser result contains an unrequested cookie",
                    );
                }
                if !seen.insert(cookie.name.as_str()) {
                    return invalid_browser_response(
                        "browser result contains a duplicate cookie",
                    );
                }
            }
            Ok(())
        }
        OpenConnectBrowserAuthMode::Headers => {
            if !result.final_url.is_empty()
                || !result.cookies.is_empty()
                || result.headers.is_empty()
            {
                return invalid_browser_response("invalid header result shape");
            }
            if result.headers.keys().any(|name| {
                !request
                    .header_names
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
            }) {
                return invalid_browser_response(
                    "browser result contains an unrequested header",
                );
            }
            Ok(())
        }
    }
}

fn invalid_browser_response<T>(
    message: &str,
) -> Result<T, AnyConnectAuthError> {
    Err(AnyConnectAuthError::InvalidBrowserResponse(message.into()))
}

fn invalid_string_list(values: &[String], fold: bool) -> bool {
    values.iter().enumerate().any(|(index, value)| {
        value.is_empty()
            || values[..index].iter().any(|previous| {
                previous == value
                    || (fold && previous.eq_ignore_ascii_case(value))
            })
    })
}

#[derive(Debug, Clone, Default)]
struct XmlNode {
    name: String,
    attributes: Vec<(String, String)>,
    text: String,
    content: Vec<XmlContent>,
}

#[derive(Debug, Clone)]
enum XmlContent {
    Text(String),
    Child(XmlNode),
}

impl XmlNode {
    fn attribute(&self, name: &str) -> &str {
        self.attributes
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
            .unwrap_or_default()
    }

    fn child(&self, name: &str) -> Option<&Self> {
        self.content.iter().find_map(|content| match content {
            XmlContent::Child(child) if child.name == name => Some(child),
            _ => None,
        })
    }

    fn children_named<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a Self> + 'a {
        self.content
            .iter()
            .filter_map(move |content| match content {
                XmlContent::Child(child) if child.name == name => Some(child),
                _ => None,
            })
    }

    fn trimmed_text(&self) -> String {
        self.text.trim().to_owned()
    }
}

/// Parse an AnyConnect `config-auth` document or legacy bare `auth` form.
pub fn parse_anyconnect_authentication_xml(
    content: &[u8],
    reported_os: &str,
) -> Result<AnyConnectAuthForm, AnyConnectAuthError> {
    if content.len() > MAX_AUTH_XML_SIZE {
        return Err(AnyConnectAuthError::XmlTooLarge);
    }
    let root = parse_xml(content)?;
    if root.name != "config-auth" && root.name != "auth" {
        return Err(AnyConnectAuthError::UnexpectedRoot(root.name));
    }

    let authentication = if root.name == "auth" {
        Some(&root)
    } else {
        root.child("auth")
    };
    let multiple_certificate = root.child("multiple-client-cert-request");
    let mut result = AnyConnectAuthForm {
        session_token: root
            .child("session-token")
            .map(XmlNode::trimmed_text)
            .unwrap_or_default(),
        opaque: root.child("opaque").map(opaque_from_node),
        client_certificate_requested: root
            .child("client-cert-request")
            .is_some()
            || multiple_certificate.is_some(),
        client_certificate_authenticated: root
            .child("cert-authenticated")
            .is_some(),
        multiple_certificates_requested: multiple_certificate.is_some(),
        multiple_certificate_hash_methods: multiple_certificate
            .map(|node| {
                node.children_named("hash-algorithm")
                    .map(XmlNode::trimmed_text)
                    .collect()
            })
            .unwrap_or_default(),
        raw_response: content.to_vec(),
        ..Default::default()
    };
    if let Some(host_scan) = root.child("host-scan") {
        result.host_scan = AnyConnectHostScan {
            ticket: child_text(host_scan, "host-scan-ticket"),
            token: child_text(host_scan, "host-scan-token"),
            base_url: child_text(host_scan, "host-scan-base-uri"),
            wait_url: child_text(host_scan, "host-scan-wait-uri"),
            stub_url: String::new(),
        };
    }
    let Some(authentication) = authentication else {
        if result.client_certificate_requested {
            return Ok(result);
        }
        return Err(AnyConnectAuthError::MissingAuth);
    };

    result.authentication_id = authentication.attribute("id").to_owned();
    result.banner = message_text(authentication.child("banner"));
    result.message = message_text(authentication.child("message"));
    result.error = message_text(authentication.child("error"));
    result.authentication_complete = result.authentication_id == "success";
    result.post_authentication_complete =
        authentication.child("authentication-complete").is_some();
    if result.post_authentication_complete {
        result.authentication_id = "openconnect_authentication_complete".into();
    }
    result.sso = AnyConnectSso {
        login_url: child_text(authentication, "sso-v2-login"),
        final_url: child_text(authentication, "sso-v2-login-final"),
        token_cookie: child_text(authentication, "sso-v2-token-cookie-name"),
        error_cookie: child_text(authentication, "sso-v2-error-cookie-name"),
        browser_mode: child_text(authentication, "sso-v2-browser-mode"),
        requested: false,
    };
    if result.authentication_id.is_empty()
        && !result.post_authentication_complete
    {
        return Err(AnyConnectAuthError::MissingAuthId);
    }
    merge_legacy_csd(
        &mut result.host_scan,
        select_legacy_csd(authentication, reported_os),
    );

    let Some(form) = authentication.child("form") else {
        return Ok(result);
    };
    if let Some(method) = optional_attribute(form, "method")
        && !method.eq_ignore_ascii_case("POST")
    {
        return Err(AnyConnectAuthError::UnsupportedMethod(method.into()));
    }
    if let Some(action) = optional_attribute(form, "action") {
        if action.is_empty() {
            return Err(AnyConnectAuthError::EmptyAction);
        }
        result.action = action.into();
    }

    for select in form.children_named("select") {
        let field = parse_select(select)?;
        if field.choices.is_empty() {
            continue;
        }
        result.fields.push(field);
        assign_submission_key(&mut result);
    }
    for input in form.children_named("input") {
        let Some(mut field) = parse_input(input) else {
            continue;
        };
        if field.kind == AnyConnectAuthFieldKind::Password {
            field.stable_credential = field.name == "password"
                && result.authentication_id != "challenge";
        }
        if field.kind == AnyConnectAuthFieldKind::SsoToken {
            result.sso.requested = true;
        }
        result.fields.push(field);
        assign_submission_key(&mut result);
    }
    Ok(result)
}

fn assign_submission_key(form: &mut AnyConnectAuthForm) {
    let index = form.fields.len();
    let field = form.fields.last_mut().expect("a field was just pushed");
    field.submission_key =
        format!("{}:{}:{index}", form.authentication_id, field.name);
}

fn parse_select(
    node: &XmlNode,
) -> Result<AnyConnectAuthField, AnyConnectAuthError> {
    let name = node.attribute("name");
    if name.is_empty() {
        return Err(AnyConnectAuthError::SelectWithoutName);
    }
    let mut field = AnyConnectAuthField {
        name: name.into(),
        label: node.attribute("label").into(),
        server_label: node.attribute("label").into(),
        value: String::new(),
        kind: AnyConnectAuthFieldKind::Select,
        second_authentication: false,
        choices: Vec::new(),
        selected_choice: 0,
        ignore: false,
        stable_credential: false,
        submission_key: String::new(),
    };
    for option in node.children_named("option") {
        let mut value = option.attribute("value").to_owned();
        if value.is_empty() {
            value = option.trimmed_text();
        }
        if value.is_empty() {
            continue;
        }
        let choice = AnyConnectAuthChoice {
            name: value,
            label: option.trimmed_text(),
            authentication_type: option.attribute("auth-type").into(),
            override_name: option.attribute("override-name").into(),
            override_label: option.attribute("override-label").into(),
            second_authentication: xml_boolean(option.attribute("second-auth")),
            secondary_username: option.attribute("secondary_username").into(),
            secondary_username_editable: xml_boolean(
                option.attribute("secondary_username_editable"),
            ),
            no_aaa: xml_boolean(option.attribute("noaaa")),
        };
        if xml_boolean(option.attribute("selected")) {
            field.selected_choice = field.choices.len();
        }
        field.choices.push(choice);
    }
    if let Some(selected) = field.choices.get(field.selected_choice) {
        field.value.clone_from(&selected.name);
    }
    Ok(field)
}

fn parse_input(node: &XmlNode) -> Option<AnyConnectAuthField> {
    let input_type = node.attribute("type").to_ascii_lowercase();
    if input_type.is_empty()
        || matches!(input_type.as_str(), "submit" | "reset")
    {
        return None;
    }
    let name = node.attribute("name");
    if name.is_empty() {
        return None;
    }
    let kind = match input_type.as_str() {
        "hidden" => AnyConnectAuthFieldKind::Hidden,
        "text" => AnyConnectAuthFieldKind::Text,
        "password" => AnyConnectAuthFieldKind::Password,
        "sso" => AnyConnectAuthFieldKind::SsoToken,
        _ => return None,
    };
    let server_label = if node.attribute("label").is_empty() {
        format!("{name}:")
    } else {
        node.attribute("label").into()
    };
    Some(AnyConnectAuthField {
        name: name.into(),
        label: server_label.clone(),
        server_label,
        value: node.attribute("value").into(),
        kind,
        second_authentication: xml_boolean(node.attribute("second-auth")),
        choices: Vec::new(),
        selected_choice: 0,
        ignore: false,
        stable_credential: kind == AnyConnectAuthFieldKind::Text
            && username_field(name),
        submission_key: String::new(),
    })
}

/// Move `group_list` to the front as OpenConnect does before collecting credentials.
pub fn reorder_anyconnect_auth_group(form: &mut AnyConnectAuthForm) {
    if let Some(index) = form
        .fields
        .iter()
        .position(|field| field.name == "group_list")
        && index > 0
    {
        let group = form.fields.remove(index);
        form.fields.insert(0, group);
    }
}

/// Apply the selected group/realm overrides and second-factor visibility rules.
pub fn apply_anyconnect_auth_group(
    form: &mut AnyConnectAuthForm,
    selected_group: &str,
) {
    let selected_choice = form.fields.iter_mut().find_map(|field| {
        field.ignore = false;
        field.label.clone_from(&field.server_label);
        if field.name != "group_list"
            || field.kind != AnyConnectAuthFieldKind::Select
        {
            return None;
        }
        let index = field.choices.iter().position(|choice| {
            choice.name == selected_group || choice.label == selected_group
        })?;
        field.selected_choice = index;
        field.value.clone_from(&field.choices[index].name);
        Some(field.choices[index].clone())
    });
    let Some(choice) = selected_choice else {
        return;
    };
    for field in &mut form.fields {
        if choice.override_name == field.name
            && !choice.override_label.is_empty()
        {
            field.label.clone_from(&choice.override_label);
        }
        if !matches!(
            field.kind,
            AnyConnectAuthFieldKind::Text | AnyConnectAuthFieldKind::Password
        ) {
            continue;
        }
        if choice.no_aaa
            || (field.second_authentication && !choice.second_authentication)
        {
            field.ignore = true;
            continue;
        }
        if field.name == "secondary_username"
            && field.second_authentication
            && !choice.secondary_username.is_empty()
        {
            field.value.clone_from(&choice.secondary_username);
            field.ignore = !choice.secondary_username_editable;
        }
    }
}

/// Mark the first field eligible for a configured OATH/SecurID generator.
pub fn configure_anyconnect_token_field(
    form: &mut AnyConnectAuthForm,
    token_type: &str,
    automatic: bool,
    ocserv_oath_round: bool,
) {
    for field in &mut form.fields {
        if field.kind != AnyConnectAuthFieldKind::Password {
            continue;
        }
        let stoken = token_type == "stoken"
            && matches!(field.name.as_str(), "password" | "answer");
        let oath = matches!(token_type, "totp" | "hotp")
            && (field.name == "secondary_password"
                || form.authentication_id == "challenge"
                || (ocserv_oath_round && field.name == "password"));
        if stoken || oath {
            field.stable_credential = false;
            if automatic {
                field.kind = AnyConnectAuthFieldKind::Token;
            }
            return;
        }
    }
}

/// Build the XMLPOST `config-auth type="init"` probe.
pub fn build_anyconnect_initial_xml(
    identity: &AnyConnectAuthClientIdentity,
    server_url: &str,
    auth_group: &str,
    client_certificate_failure: bool,
) -> Result<Vec<u8>, AnyConnectAuthError> {
    let group_access = if server_url.ends_with('/') {
        server_url.to_owned()
    } else {
        format!("{server_url}/")
    };
    let mut writer = auth_writer();
    write_root_start(&mut writer, "init")?;
    write_identity(&mut writer, identity)?;
    write_capabilities(&mut writer, identity)?;
    write_text(&mut writer, "group-access", &group_access, &[])?;
    if client_certificate_failure {
        write_text(&mut writer, "client-cert-fail", "", &[])?;
    }
    if !auth_group.is_empty() {
        write_text(&mut writer, "group-select", auth_group, &[])?;
    }
    write_end(&mut writer, "config-auth")?;
    Ok(writer.into_inner())
}

/// Build the XMLPOST authentication reply, retaining duplicate field order.
pub fn build_anyconnect_authentication_reply_xml(
    identity: &AnyConnectAuthClientIdentity,
    form: &AnyConnectAuthForm,
    opaque: Option<&AnyConnectOpaque>,
    host_scan_token: &str,
) -> Result<Vec<u8>, AnyConnectAuthError> {
    let mut writer = auth_writer();
    write_root_start(&mut writer, "auth-reply")?;
    write_identity(&mut writer, identity)?;
    write_capabilities(&mut writer, identity)?;
    if let Some(opaque) = opaque {
        write_opaque(&mut writer, opaque)?;
    }
    write_start(&mut writer, "auth", &[])?;
    let mut selected_group = "";
    for field in &form.fields {
        if field.name == "group_list" {
            selected_group = &field.value;
            continue;
        }
        let name = match field.name.as_str() {
            "answer" | "whichpin" | "new_password" => "password",
            "verify_pin" | "verify_password" => continue,
            name => name,
        };
        write_text(&mut writer, name, &field.value, &[])?;
    }
    write_end(&mut writer, "auth")?;
    if !selected_group.is_empty() {
        write_text(&mut writer, "group-select", selected_group, &[])?;
    }
    if !host_scan_token.is_empty() {
        write_text(&mut writer, "host-scan-token", host_scan_token, &[])?;
    }
    write_end(&mut writer, "config-auth")?;
    Ok(writer.into_inner())
}

/// Encode the legacy HTML form body using OpenConnect's RFC 3986 byte rules.
pub fn build_anyconnect_legacy_form_body(form: &AnyConnectAuthForm) -> Vec<u8> {
    let mut output = String::new();
    for field in &form.fields {
        if !output.is_empty() {
            output.push('&');
        }
        append_url_encoded(&mut output, &field.name);
        output.push('=');
        append_url_encoded(&mut output, &field.value);
    }
    output.into_bytes()
}

/// Normalize a direct cookie string. A single unnamed value uses `default_name`.
pub fn parse_anyconnect_direct_cookie(
    content: &str,
    default_name: &str,
) -> Result<BTreeMap<String, String>, AnyConnectAuthError> {
    let mut values = BTreeMap::new();
    for raw_cookie in content.split(';') {
        let raw_cookie = raw_cookie.trim();
        if raw_cookie.is_empty() {
            continue;
        }
        let (name, value) =
            if let Some((name, value)) = raw_cookie.split_once('=') {
                (name.trim(), value)
            } else {
                if default_name.is_empty() {
                    return Err(AnyConnectAuthError::CookieWithoutName(
                        raw_cookie.into(),
                    ));
                }
                (default_name, raw_cookie)
            };
        if name.is_empty() {
            return Err(AnyConnectAuthError::EmptyCookieName);
        }
        values.insert(name.into(), value.into());
    }
    if values.is_empty() {
        return Err(AnyConnectAuthError::EmptyCookie);
    }
    Ok(values)
}

fn parse_xml(content: &[u8]) -> Result<XmlNode, AnyConnectAuthError> {
    let mut reader = Reader::from_reader(content);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<XmlNode>::new();
    let mut root = None;
    loop {
        let event = reader.read_event().map_err(|error| {
            AnyConnectAuthError::InvalidXml(error.to_string())
        })?;
        match event {
            Event::Start(start) => {
                stack.push(node_from_start(&reader, &start)?)
            }
            Event::Empty(start) => {
                let node = node_from_start(&reader, &start)?;
                attach_node(&mut stack, &mut root, node)?;
            }
            Event::Text(text) => {
                let decoded = text.xml10_content().map_err(|error| {
                    AnyConnectAuthError::InvalidXml(error.to_string())
                })?;
                let value =
                    quick_xml::escape::unescape(&decoded).map_err(|error| {
                        AnyConnectAuthError::InvalidXml(error.to_string())
                    })?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                    node.content.push(XmlContent::Text(value.into_owned()));
                }
            }
            Event::CData(text) => {
                let value = text.decode().map_err(|error| {
                    AnyConnectAuthError::InvalidXml(error.to_string())
                })?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                    node.content.push(XmlContent::Text(value.into_owned()));
                }
            }
            Event::End(_) => {
                let node = stack.pop().ok_or_else(|| {
                    AnyConnectAuthError::InvalidXml("unexpected end tag".into())
                })?;
                attach_node(&mut stack, &mut root, node)?;
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::PI(_)
            | Event::Comment(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {}
        }
    }
    if !stack.is_empty() {
        return Err(AnyConnectAuthError::InvalidXml(
            "unclosed XML element".into(),
        ));
    }
    root.ok_or_else(|| AnyConnectAuthError::InvalidXml("empty document".into()))
}

fn node_from_start(
    reader: &Reader<&[u8]>,
    start: &BytesStart<'_>,
) -> Result<XmlNode, AnyConnectAuthError> {
    let name = local_name(start.name().as_ref())?;
    let mut attributes = Vec::new();
    for attribute in start.attributes().with_checks(false) {
        let attribute = attribute.map_err(|error| {
            AnyConnectAuthError::InvalidXml(error.to_string())
        })?;
        let key = local_name(attribute.key.as_ref())?;
        let value = attribute
            .decoded_and_normalized_value(
                XmlVersion::Implicit1_0,
                reader.decoder(),
            )
            .map_err(|error| {
                AnyConnectAuthError::InvalidXml(error.to_string())
            })?;
        attributes.push((key, value.into_owned()));
    }
    Ok(XmlNode {
        name,
        attributes,
        text: String::new(),
        content: Vec::new(),
    })
}

fn attach_node(
    stack: &mut [XmlNode],
    root: &mut Option<XmlNode>,
    node: XmlNode,
) -> Result<(), AnyConnectAuthError> {
    if let Some(parent) = stack.last_mut() {
        parent.content.push(XmlContent::Child(node));
    } else if root.replace(node).is_some() {
        return Err(AnyConnectAuthError::InvalidXml(
            "multiple root elements".into(),
        ));
    }
    Ok(())
}

fn local_name(raw: &[u8]) -> Result<String, AnyConnectAuthError> {
    let raw = raw.rsplit(|byte| *byte == b':').next().unwrap_or(raw);
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|error| AnyConnectAuthError::InvalidXml(error.to_string()))
}

fn opaque_from_node(node: &XmlNode) -> AnyConnectOpaque {
    let mut writer = Writer::new(Vec::new());
    for content in &node.content {
        match content {
            XmlContent::Text(text) => writer
                .write_event(Event::Text(BytesText::new(text)))
                .expect("in-memory XML cannot fail"),
            XmlContent::Child(child) => {
                write_xml_node(&mut writer, child)
                    .expect("in-memory XML cannot fail");
            }
        }
    }
    AnyConnectOpaque {
        name: node.name.clone(),
        attributes: node.attributes.clone(),
        inner_xml: String::from_utf8(writer.into_inner())
            .expect("quick-xml emits UTF-8"),
    }
}

fn write_xml_node(
    writer: &mut Writer<Vec<u8>>,
    node: &XmlNode,
) -> Result<(), quick_xml::Error> {
    let attributes: Vec<(&str, &str)> = node
        .attributes
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut start = BytesStart::new(&node.name);
    for attribute in &attributes {
        start.push_attribute(*attribute);
    }
    writer.write_event(Event::Start(start))?;
    for content in &node.content {
        match content {
            XmlContent::Text(text) => {
                writer.write_event(Event::Text(BytesText::new(text)))?;
            }
            XmlContent::Child(child) => write_xml_node(writer, child)?,
        }
    }
    writer.write_event(Event::End(BytesEnd::new(&node.name)))?;
    Ok(())
}

fn child_text(node: &XmlNode, name: &str) -> String {
    node.child(name)
        .map(XmlNode::trimmed_text)
        .unwrap_or_default()
}

fn optional_attribute<'a>(node: &'a XmlNode, name: &str) -> Option<&'a str> {
    node.attributes
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value.as_str()))
}

fn message_text(node: Option<&XmlNode>) -> String {
    let Some(node) = node else {
        return String::new();
    };
    let mut message = node.trimmed_text();
    for parameter in [node.attribute("param1"), node.attribute("param2")] {
        if let Some(position) = message.find("%s") {
            message.replace_range(position..position + 2, parameter);
        }
    }
    message
}

fn xml_boolean(value: &str) -> bool {
    value == "1"
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
}

fn username_field(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("user") || name.starts_with("uname")
}

fn select_legacy_csd(
    authentication: &XmlNode,
    reported_os: &str,
) -> AnyConnectHostScan {
    let node_name = match reported_os {
        "win" => "csd",
        "mac-intel" => "csdMac",
        _ => "csdLinux",
    };
    let mut result = AnyConnectHostScan::default();
    for candidate in authentication.children_named(node_name) {
        for (target, source) in [
            (&mut result.ticket, candidate.attribute("ticket")),
            (&mut result.token, candidate.attribute("token")),
            (&mut result.stub_url, candidate.attribute("stuburl")),
            (&mut result.base_url, candidate.attribute("starturl")),
            (&mut result.wait_url, candidate.attribute("waiturl")),
        ] {
            if !source.is_empty() {
                *target = source.into();
            }
        }
    }
    if matches!(reported_os, "android" | "apple-ios") {
        result.stub_url.clear();
    }
    result
}

fn merge_legacy_csd(
    destination: &mut AnyConnectHostScan,
    source: AnyConnectHostScan,
) {
    for (destination, source) in [
        (&mut destination.ticket, source.ticket),
        (&mut destination.token, source.token),
        (&mut destination.stub_url, source.stub_url),
        (&mut destination.base_url, source.base_url),
        (&mut destination.wait_url, source.wait_url),
    ] {
        if destination.is_empty() {
            *destination = source;
        }
    }
}

pub(super) fn auth_writer() -> Writer<Vec<u8>> {
    let mut writer = Writer::new(Vec::new());
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .expect("in-memory XML cannot fail");
    writer.get_mut().push(b'\n');
    writer
}

pub(super) fn write_root_start(
    writer: &mut Writer<Vec<u8>>,
    auth_type: &str,
) -> Result<(), AnyConnectAuthError> {
    write_start(
        writer,
        "config-auth",
        &[
            ("client", "vpn"),
            ("type", auth_type),
            ("aggregate-auth-version", "2"),
        ],
    )
}

pub(super) fn write_identity(
    writer: &mut Writer<Vec<u8>>,
    identity: &AnyConnectAuthClientIdentity,
) -> Result<(), AnyConnectAuthError> {
    write_text(writer, "version", &identity.version, &[("who", "vpn")])?;
    let mut attributes = Vec::new();
    if let Some(mobile) = &identity.mobile {
        attributes.extend([
            ("platform-version", mobile.platform_version.as_str()),
            ("device-type", mobile.device_type.as_str()),
            ("unique-id", mobile.device_unique_id.as_str()),
        ]);
    }
    write_text(writer, "device-id", &identity.reported_os, &attributes)
}

pub(super) fn write_capabilities(
    writer: &mut Writer<Vec<u8>>,
    identity: &AnyConnectAuthClientIdentity,
) -> Result<(), AnyConnectAuthError> {
    write_start(writer, "capabilities", &[])?;
    if !identity.external_auth_disabled {
        write_text(writer, "auth-method", "single-sign-on-v2", &[])?;
    }
    if identity.multiple_certificate_authentication {
        write_text(writer, "auth-method", "multiple-cert", &[])?;
    }
    write_end(writer, "capabilities")
}

pub(super) fn write_opaque(
    writer: &mut Writer<Vec<u8>>,
    opaque: &AnyConnectOpaque,
) -> Result<(), AnyConnectAuthError> {
    let name = if opaque.name.is_empty() {
        "opaque"
    } else {
        &opaque.name
    };
    let attributes: Vec<(&str, &str)> = opaque
        .attributes
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    write_start(writer, name, &attributes)?;
    writer
        .get_mut()
        .extend_from_slice(opaque.inner_xml.as_bytes());
    write_end(writer, name)
}

pub(super) fn write_start(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    attributes: &[(&str, &str)],
) -> Result<(), AnyConnectAuthError> {
    let mut start = BytesStart::new(name);
    for attribute in attributes {
        start.push_attribute(*attribute);
    }
    writer
        .write_event(Event::Start(start))
        .map_err(xml_write_error)
}

pub(super) fn write_end(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
) -> Result<(), AnyConnectAuthError> {
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(xml_write_error)
}

pub(super) fn write_text(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    value: &str,
    attributes: &[(&str, &str)],
) -> Result<(), AnyConnectAuthError> {
    write_start(writer, name, attributes)?;
    if !value.is_empty() {
        writer
            .write_event(Event::Text(BytesText::new(value)))
            .map_err(xml_write_error)?;
    }
    write_end(writer, name)
}

fn xml_write_error(error: std::io::Error) -> AnyConnectAuthError {
    AnyConnectAuthError::InvalidXml(error.to_string())
}

fn append_url_encoded(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
        {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn prompt_field(
        key: &str,
        kind: OpenConnectAuthPromptKind,
    ) -> OpenConnectAuthPromptField {
        OpenConnectAuthPromptField {
            submission_key: key.into(),
            name: key.into(),
            label: key.into(),
            kind,
            value: String::new(),
            options: if kind == OpenConnectAuthPromptKind::Select {
                vec![OpenConnectAuthPromptChoice {
                    value: "allowed".into(),
                    label: "Allowed".into(),
                }]
            } else {
                Vec::new()
            },
        }
    }

    fn identity() -> AnyConnectAuthClientIdentity {
        AnyConnectAuthClientIdentity {
            version: "5.1.2".into(),
            reported_os: "linux-64".into(),
            mobile: None,
            external_auth_disabled: false,
            multiple_certificate_authentication: false,
        }
    }

    #[test]
    fn validates_prompt_form_submission_keys_and_select_values() {
        let fields = vec![
            prompt_field("username", OpenConnectAuthPromptKind::Text),
            prompt_field("group", OpenConnectAuthPromptKind::Select),
        ];
        let valid = BTreeMap::from([
            ("username".into(), "alice".into()),
            ("group".into(), "allowed".into()),
        ]);
        validate_openconnect_form_response(&fields, &valid).unwrap();

        let mut invalid = valid.clone();
        invalid.insert("group".into(), "other".into());
        assert!(matches!(
            validate_openconnect_form_response(&fields, &invalid),
            Err(AnyConnectAuthError::InvalidSelection(key)) if key == "group"
        ));
        let mut unknown = valid.clone();
        unknown.insert("extra".into(), "value".into());
        assert!(matches!(
            validate_openconnect_form_response(&fields, &unknown),
            Err(AnyConnectAuthError::UnknownSubmissionKey(key)) if key == "extra"
        ));
    }

    #[test]
    fn validates_all_browser_completion_modes() {
        let callback = OpenConnectBrowserRequest {
            url: "https://id.example/login".into(),
            callback_url_prefixes: vec!["com.example.app:/callback".into()],
            ..Default::default()
        };
        validate_openconnect_browser_response(
            &callback,
            &OpenConnectBrowserResult {
                final_url: "com.example.app:/callback?code=1".into(),
                ..Default::default()
            },
        )
        .unwrap();

        let cookies = OpenConnectBrowserRequest {
            url: "https://id.example/login".into(),
            final_url: "https://vpn.example/+CSCOE+/saml/sp/acs".into(),
            cookie_names: vec!["acSamlv2Token".into()],
            early_cookie_names: vec!["acSamlv2Error".into()],
            ..Default::default()
        };
        validate_openconnect_browser_response(
            &cookies,
            &OpenConnectBrowserResult {
                final_url: cookies.final_url.clone(),
                cookies: vec![OpenConnectBrowserCookie {
                    name: "acSamlv2Token".into(),
                    value: "token".into(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        validate_openconnect_browser_response(
            &cookies,
            &OpenConnectBrowserResult {
                cookies: vec![OpenConnectBrowserCookie {
                    name: "acSamlv2Error".into(),
                    value: "denied".into(),
                }],
                ..Default::default()
            },
        )
        .unwrap();

        let headers = OpenConnectBrowserRequest {
            url: "https://id.example/login".into(),
            header_names: vec!["Authorization".into()],
            ..Default::default()
        };
        let mut result = OpenConnectBrowserResult::default();
        result
            .headers
            .insert("authorization", HeaderValue::from_static("Bearer token"));
        validate_openconnect_browser_response(&headers, &result).unwrap();
    }

    #[test]
    fn rejects_ambiguous_duplicate_and_unrequested_browser_results() {
        assert_eq!(
            validate_openconnect_browser_request(&OpenConnectBrowserRequest {
                url: "https://id.example/".into(),
                callback_url_prefixes: vec!["app:/".into()],
                header_names: vec!["authorization".into()],
                ..Default::default()
            })
            .unwrap_err(),
            AnyConnectAuthError::BrowserModeAmbiguous
        );
        assert!(
            validate_openconnect_browser_request(&OpenConnectBrowserRequest {
                url: "https://id.example/".into(),
                header_names: vec!["X-Token".into(), "x-token".into()],
                ..Default::default()
            })
            .is_err()
        );

        let request = OpenConnectBrowserRequest {
            url: "https://id.example/".into(),
            final_url: "https://vpn.example/final".into(),
            cookie_names: vec!["token".into()],
            ..Default::default()
        };
        assert!(
            validate_openconnect_browser_response(
                &request,
                &OpenConnectBrowserResult {
                    final_url: request.final_url.clone(),
                    cookies: vec![OpenConnectBrowserCookie {
                        name: "other".into(),
                        value: "value".into(),
                    }],
                    ..Default::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn challenge_ids_are_monotonic_and_payload_is_cloned() {
        let first = new_openconnect_auth_challenge(
            "banner",
            "message",
            "",
            OpenConnectAuthChallengeKind::Form(
                OpenConnectAuthPromptForm::default(),
            ),
        );
        let second = new_openconnect_auth_challenge(
            "",
            "",
            "",
            OpenConnectAuthChallengeKind::Form(
                OpenConnectAuthPromptForm::default(),
            ),
        );
        assert!(
            first.id.parse::<u64>().unwrap()
                < second.id.parse::<u64>().unwrap()
        );
        assert_eq!(first.banner, "banner");
    }

    #[test]
    fn parses_auth_group_sso_host_scan_and_fields() {
        let xml = br#"<?xml version="1.0"?>
          <config-auth><session-token> session </session-token>
          <opaque nonce="abc"><tunnel-group>g</tunnel-group></opaque>
          <host-scan><host-scan-ticket>ticket</host-scan-ticket></host-scan>
          <auth id="main"><banner param1="Alice">Hello %s</banner>
          <message> Enter credentials </message>
          <sso-v2-login>https://id.example/</sso-v2-login>
          <form method="post" action="/login">
            <input type="text" name="username"/>
            <input type="password" name="password" label="Password"/>
            <input type="sso" name="sso_token"/>
            <input type="submit" name="ignored"/>
            <select name="group_list" label="Group">
              <option value="staff">Staff</option>
              <option selected="yes" value="admin" second-auth="1"
                secondary_username="fixed" override-name="password"
                override-label="OTP">Admin</option>
            </select>
          </form><csdLinux ticket="legacy" stuburl="/stub"/></auth></config-auth>"#;
        let mut form =
            parse_anyconnect_authentication_xml(xml, "linux-64").unwrap();
        assert_eq!(form.authentication_id, "main");
        assert_eq!(form.banner, "Hello Alice");
        assert_eq!(form.session_token, "session");
        assert_eq!(form.host_scan.ticket, "ticket");
        assert_eq!(form.host_scan.stub_url, "/stub");
        assert_eq!(form.action, "/login");
        assert!(form.sso.requested);
        assert_eq!(form.fields[0].name, "group_list");
        assert_eq!(form.fields[0].value, "admin");
        assert_eq!(form.fields[0].submission_key, "main:group_list:1");
        assert_eq!(form.fields[1].submission_key, "main:username:2");
        assert!(form.fields[1].stable_credential);
        assert!(form.fields[2].stable_credential);

        apply_anyconnect_auth_group(&mut form, "admin");
        assert_eq!(form.fields[2].label, "OTP");
    }

    #[test]
    fn accepts_legacy_auth_and_certificate_only_documents() {
        let form = parse_anyconnect_authentication_xml(
            br#"<auth id="success"><authentication-complete/></auth>"#,
            "win",
        )
        .unwrap();
        assert!(form.authentication_complete);
        assert!(form.post_authentication_complete);
        assert_eq!(
            form.authentication_id,
            "openconnect_authentication_complete"
        );

        let certificate = parse_anyconnect_authentication_xml(
            br#"<config-auth><multiple-client-cert-request><hash-algorithm>sha256</hash-algorithm></multiple-client-cert-request></config-auth>"#,
            "linux",
        )
        .unwrap();
        assert!(certificate.client_certificate_requested);
        assert_eq!(certificate.multiple_certificate_hash_methods, ["sha256"]);
    }

    #[test]
    fn builds_go_compatible_initial_and_reply_xml() {
        let initial = build_anyconnect_initial_xml(
            &identity(),
            "https://vpn.example",
            "staff",
            true,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(initial).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config-auth client=\"vpn\" type=\"init\" aggregate-auth-version=\"2\"><version who=\"vpn\">5.1.2</version><device-id>linux-64</device-id><capabilities><auth-method>single-sign-on-v2</auth-method></capabilities><group-access>https://vpn.example/</group-access><client-cert-fail></client-cert-fail><group-select>staff</group-select></config-auth>"
        );

        let mut form = AnyConnectAuthForm::default();
        for (name, value) in [
            ("group_list", "staff"),
            ("username", "a<&"),
            ("answer", "123"),
            ("verify_password", "ignored"),
        ] {
            form.fields.push(AnyConnectAuthField {
                name: name.into(),
                value: value.into(),
                label: String::new(),
                server_label: String::new(),
                kind: AnyConnectAuthFieldKind::Text,
                second_authentication: false,
                choices: Vec::new(),
                selected_choice: 0,
                ignore: false,
                stable_credential: false,
                submission_key: String::new(),
            });
        }
        let reply = build_anyconnect_authentication_reply_xml(
            &identity(),
            &form,
            None,
            "ticket",
        )
        .unwrap();
        let reply = String::from_utf8(reply).unwrap();
        assert_eq!(
            reply,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\"><version who=\"vpn\">5.1.2</version><device-id>linux-64</device-id><capabilities><auth-method>single-sign-on-v2</auth-method></capabilities><auth><username>a&lt;&amp;</username><password>123</password></auth><group-select>staff</group-select><host-scan-token>ticket</host-scan-token></config-auth>"
        );
    }

    #[test]
    fn preserves_legacy_form_order_and_encodes_utf8_bytes() {
        let mut form = AnyConnectAuthForm::default();
        for (name, value) in [("x", "a b"), ("x", "中"), ("safe", "~-_.")] {
            form.fields.push(AnyConnectAuthField {
                name: name.into(),
                value: value.into(),
                label: String::new(),
                server_label: String::new(),
                kind: AnyConnectAuthFieldKind::Text,
                second_authentication: false,
                choices: Vec::new(),
                selected_choice: 0,
                ignore: false,
                stable_credential: false,
                submission_key: String::new(),
            });
        }
        assert_eq!(
            build_anyconnect_legacy_form_body(&form),
            b"x=a%20b&x=%e4%b8%ad&safe=~-_."
        );
    }

    #[test]
    fn normalizes_direct_cookie_and_rejects_invalid_input() {
        assert_eq!(
            parse_anyconnect_direct_cookie("webvpn=one; other=two", "webvpn")
                .unwrap()
                .get("webvpn")
                .unwrap(),
            "one"
        );
        assert_eq!(
            parse_anyconnect_direct_cookie("raw", "webvpn")
                .unwrap()
                .get("webvpn")
                .unwrap(),
            "raw"
        );
        assert_eq!(
            parse_anyconnect_direct_cookie("raw", "").unwrap_err(),
            AnyConnectAuthError::CookieWithoutName("raw".into())
        );
    }

    #[test]
    fn validates_form_root_method_action_and_size() {
        assert!(matches!(
            parse_anyconnect_authentication_xml(b"<wrong/>", "linux"),
            Err(AnyConnectAuthError::UnexpectedRoot(_))
        ));
        assert!(matches!(
            parse_anyconnect_authentication_xml(
                br#"<auth id="main"><form method="GET"/></auth>"#,
                "linux"
            ),
            Err(AnyConnectAuthError::UnsupportedMethod(_))
        ));
        assert_eq!(
            parse_anyconnect_authentication_xml(
                br#"<auth id="main"><form action=""/></auth>"#,
                "linux"
            )
            .unwrap_err(),
            AnyConnectAuthError::EmptyAction
        );
        assert_eq!(
            parse_anyconnect_authentication_xml(
                &vec![b'x'; MAX_AUTH_XML_SIZE + 1],
                "linux"
            )
            .unwrap_err(),
            AnyConnectAuthError::XmlTooLarge
        );
    }
}
