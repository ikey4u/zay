//! Stateful Fortinet HTTP authentication continuation.

use std::{
    collections::{HashMap, HashSet},
    mem,
    net::IpAddr,
};

use cookie_store::RawCookie;
use http::{
    Method, StatusCode,
    header::{CONTENT_TYPE, LOCATION, SET_COOKIE},
};
use thiserror::Error;
use url::Url;

use super::{
    AnyConnectAuthError, AnyConnectAuthHttpClient, AnyConnectAuthHttpError,
    AnyConnectAuthHttpRequest, AnyConnectAuthHttpResponse,
    AnyConnectSoftwareTokenGenerator, FortinetAuthenticationFieldKind,
    FortinetAuthenticationForm, FortinetFormError, OpenConnectAuthChallenge,
    OpenConnectAuthChallengeKind, OpenConnectAuthPromptField,
    OpenConnectAuthPromptForm, OpenConnectAuthPromptKind,
    OpenConnectAuthResponse, OpenConnectBrowserRequest,
    encode_fortinet_authentication_response, is_fortinet_html_response,
    new_openconnect_auth_challenge, parse_anyconnect_direct_cookie,
    parse_fortinet_authentication_result, parse_fortinet_host_check_action,
    parse_fortinet_html_challenge, parse_fortinet_saml_callback,
    parse_fortinet_token_info, parse_fortinet_top_location,
    static_fortinet_authentication_form, validate_openconnect_browser_response,
    validate_openconnect_form_response,
};

pub const FORTINET_MAXIMUM_AUTHENTICATION_BODY: usize = 16 * 1024 * 1024;
pub const FORTINET_MAXIMUM_AUTHENTICATION_REQUESTS: usize = 64;
pub const FORTINET_MAXIMUM_AUTHENTICATION_REDIRECTS: usize = 10;
pub const FORTINET_PROTOCOL_USER_AGENT: &str = "Mozilla/5.0 SV1";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FortinetAuthenticatorOptions {
    pub username: String,
    pub password: String,
    pub direct_cookie: Option<String>,
    pub external_auth_disabled: bool,
    pub host_check: String,
    pub check_virtual_desktop: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortinetAuthenticatedSession {
    pub server_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
    pub svpn_cookie: String,
    pub cookies: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FortinetAuthenticationProgress {
    Challenge(OpenConnectAuthChallenge),
    Complete(FortinetAuthenticatedSession),
}

#[derive(Debug, Error)]
pub enum FortinetAuthenticatorError {
    #[error(transparent)]
    Http(#[from] AnyConnectAuthHttpError),
    #[error(transparent)]
    Form(#[from] FortinetFormError),
    #[error(transparent)]
    Challenge(#[from] AnyConnectAuthError),
    #[error("invalid Fortinet server URL: {0}")]
    InvalidServerUrl(String),
    #[error("Fortinet authentication response exceeds {0} bytes")]
    BodyTooLarge(usize),
    #[error("Fortinet authentication exceeded {0} redirects")]
    TooManyRedirects(usize),
    #[error("Fortinet gateway rejected authentication: {0}")]
    Rejected(String),
    #[error("unsupported Fortinet authentication behavior: {0}")]
    Unsupported(String),
    #[error("Fortinet authentication challenge response is missing")]
    MissingResponse,
    #[error("Fortinet authentication challenge ID does not match")]
    ChallengeMismatch,
    #[error("Fortinet authentication response type does not match")]
    ResponseTypeMismatch,
    #[error("Fortinet authentication is complete")]
    AlreadyComplete,
    #[error("Fortinet authentication is in a terminal state")]
    TerminalState,
    #[error("Fortinet token generation failed: {0}")]
    Token(String),
    #[error("Fortinet authenticated endpoint has no active SVPNCOOKIE")]
    MissingSessionCookie,
}

#[derive(Debug, Clone)]
enum Stage {
    Initial,
    AwaitForm {
        challenge: OpenConnectAuthChallenge,
        form: FortinetAuthenticationForm,
        initial: bool,
    },
    AwaitSaml {
        challenge: OpenConnectAuthChallenge,
    },
    Complete,
    Terminal,
}

enum Action {
    InitialGet {
        url: Url,
        redirects: usize,
    },
    PrepareForm {
        form: FortinetAuthenticationForm,
        initial: bool,
        error: String,
        allow_initial_prefill: bool,
    },
    SubmitForm {
        form: FortinetAuthenticationForm,
        initial: bool,
    },
    BeginSaml(Url),
    CompleteSaml(String),
}

pub struct FortinetAuthenticator {
    http: AnyConnectAuthHttpClient,
    options: FortinetAuthenticatorOptions,
    current_url: Url,
    current_address: Option<IpAddr>,
    peer_certificate_der: Option<Vec<u8>>,
    realm: String,
    username: String,
    stage: Stage,
    immediate_session: Option<FortinetAuthenticatedSession>,
    token_generator: Option<Box<dyn AnyConnectSoftwareTokenGenerator>>,
}

impl FortinetAuthenticator {
    pub fn new(
        mut http: AnyConnectAuthHttpClient,
        server: &str,
        options: FortinetAuthenticatorOptions,
    ) -> Result<Self, FortinetAuthenticatorError> {
        let server_url = parse_server_url(server)?;
        http.set_maximum_wire_requests(Some(
            FORTINET_MAXIMUM_AUTHENTICATION_REQUESTS,
        ));
        let mut immediate_session = None;
        if let Some(content) = options.direct_cookie.as_deref() {
            let cookies =
                parse_anyconnect_direct_cookie(content, "SVPNCOOKIE")?;
            let svpn_cookie =
                cookies.get("SVPNCOOKIE").cloned().ok_or_else(|| {
                    FortinetAuthenticatorError::Rejected(
                        "direct cookie does not contain SVPNCOOKIE".into(),
                    )
                })?;
            for (name, value) in cookies {
                http.set_cookie(&server_url, &name, &value)?;
            }
            immediate_session = Some(FortinetAuthenticatedSession {
                authenticated_address: server_url
                    .host_str()
                    .and_then(|host| host.parse().ok()),
                peer_certificate_der: None,
                svpn_cookie,
                cookies: http.cookie_pairs(&server_url),
                server_url: server_url.clone(),
            });
        } else {
            http.clear_cookies();
        }
        Ok(Self {
            http,
            options,
            current_url: server_url,
            current_address: None,
            peer_certificate_der: None,
            realm: String::new(),
            username: String::new(),
            stage: if immediate_session.is_some() {
                Stage::Complete
            } else {
                Stage::Initial
            },
            immediate_session,
            token_generator: None,
        })
    }

    pub fn set_software_token_generator(
        &mut self,
        generator: Box<dyn AnyConnectSoftwareTokenGenerator>,
    ) {
        self.token_generator = Some(generator);
    }

    pub async fn begin(
        &mut self,
    ) -> Result<FortinetAuthenticationProgress, FortinetAuthenticatorError>
    {
        if let Some(session) = self.immediate_session.take() {
            return Ok(FortinetAuthenticationProgress::Complete(session));
        }
        match self.stage {
            Stage::Initial => {
                let result = self
                    .drive(Action::InitialGet {
                        url: self.current_url.clone(),
                        redirects: 0,
                    })
                    .await;
                if result.is_err() {
                    self.stage = Stage::Terminal;
                }
                result
            }
            Stage::Complete => Err(FortinetAuthenticatorError::AlreadyComplete),
            Stage::Terminal => Err(FortinetAuthenticatorError::TerminalState),
            Stage::AwaitForm { .. } | Stage::AwaitSaml { .. } => {
                Err(FortinetAuthenticatorError::MissingResponse)
            }
        }
    }

    pub async fn respond(
        &mut self,
        challenge_id: &str,
        response: OpenConnectAuthResponse,
    ) -> Result<FortinetAuthenticationProgress, FortinetAuthenticatorError>
    {
        let stage = mem::replace(&mut self.stage, Stage::Terminal);
        let action = match stage {
            Stage::AwaitForm {
                challenge,
                mut form,
                initial,
            } => {
                if challenge.id != challenge_id {
                    return Err(FortinetAuthenticatorError::ChallengeMismatch);
                }
                let OpenConnectAuthChallengeKind::Form(prompt) =
                    &challenge.kind
                else {
                    return Err(
                        FortinetAuthenticatorError::ResponseTypeMismatch,
                    );
                };
                let OpenConnectAuthResponse::Form(values) = response else {
                    return Err(
                        FortinetAuthenticatorError::ResponseTypeMismatch,
                    );
                };
                validate_openconnect_form_response(&prompt.fields, &values)?;
                for field in &mut form.fields {
                    if let Some(value) = values.get(&field.submission_key) {
                        field.value.clone_from(value);
                    }
                }
                Action::SubmitForm { form, initial }
            }
            Stage::AwaitSaml { challenge } => {
                if challenge.id != challenge_id {
                    return Err(FortinetAuthenticatorError::ChallengeMismatch);
                }
                let OpenConnectAuthChallengeKind::Browser(request) =
                    &challenge.kind
                else {
                    return Err(
                        FortinetAuthenticatorError::ResponseTypeMismatch,
                    );
                };
                let OpenConnectAuthResponse::Browser(result) = response else {
                    return Err(
                        FortinetAuthenticatorError::ResponseTypeMismatch,
                    );
                };
                validate_openconnect_browser_response(request, &result)?;
                Action::CompleteSaml(parse_fortinet_saml_callback(
                    &result.final_url,
                )?)
            }
            Stage::Complete => {
                return Err(FortinetAuthenticatorError::AlreadyComplete);
            }
            Stage::Terminal | Stage::Initial => {
                return Err(FortinetAuthenticatorError::TerminalState);
            }
        };
        let result = self.drive(action).await;
        if result.is_err() {
            self.stage = Stage::Terminal;
        }
        result
    }

    async fn drive(
        &mut self,
        mut action: Action,
    ) -> Result<FortinetAuthenticationProgress, FortinetAuthenticatorError>
    {
        loop {
            action = match action {
                Action::InitialGet { url, redirects } => {
                    if redirects > FORTINET_MAXIMUM_AUTHENTICATION_REDIRECTS {
                        return Err(
                            FortinetAuthenticatorError::TooManyRedirects(
                                FORTINET_MAXIMUM_AUTHENTICATION_REDIRECTS,
                            ),
                        );
                    }
                    let response =
                        self.request(Method::GET, url, Vec::new()).await?;
                    self.remember_response(&response);
                    if is_redirect(response.status)
                        && let Some(location) = response
                            .headers
                            .get(LOCATION)
                            .and_then(|value| value.to_str().ok())
                    {
                        let location = response
                            .final_url
                            .join(location)
                            .map_err(|error| {
                                FortinetAuthenticatorError::InvalidServerUrl(
                                    error.to_string(),
                                )
                            })?;
                        if location.path() == "/remote/saml/start" {
                            Action::BeginSaml(location)
                        } else if response.final_url.path()
                            == "/remote/saml/start"
                        {
                            Action::BeginSaml(response.final_url)
                        } else {
                            self.prepare_redirect(
                                &self.current_url.clone(),
                                &location,
                            )?;
                            Action::InitialGet {
                                url: location,
                                redirects: redirects + 1,
                            }
                        }
                    } else if let Some(location) =
                        parse_fortinet_top_location(&response.body)?
                    {
                        let location = response
                            .final_url
                            .join(&location)
                            .map_err(|error| {
                                FortinetAuthenticatorError::InvalidServerUrl(
                                    error.to_string(),
                                )
                            })?;
                        self.prepare_redirect(
                            &self.current_url.clone(),
                            &location,
                        )?;
                        Action::InitialGet {
                            url: location,
                            redirects: redirects + 1,
                        }
                    } else if response.final_url.path() == "/remote/saml/start"
                    {
                        Action::BeginSaml(response.final_url)
                    } else if !response.status.is_success() {
                        return Err(FortinetAuthenticatorError::Rejected(
                            format!(
                                "login page returned HTTP {}",
                                response.status
                            ),
                        ));
                    } else {
                        self.realm = response
                            .final_url
                            .query_pairs()
                            .find_map(|(name, value)| {
                                (name == "realm").then(|| value.into_owned())
                            })
                            .unwrap_or_default();
                        Action::PrepareForm {
                            form: static_fortinet_authentication_form(),
                            initial: true,
                            error: String::new(),
                            allow_initial_prefill: true,
                        }
                    }
                }
                Action::PrepareForm {
                    mut form,
                    initial,
                    error,
                    allow_initial_prefill,
                } => {
                    self.prefill_form(
                        &mut form,
                        initial,
                        allow_initial_prefill,
                    )?;
                    let fields = visible_missing_fields(&form);
                    if fields.is_empty()
                        || (!initial
                            && form.ftm_push
                            && only_empty_code(&form, &fields))
                    {
                        Action::SubmitForm { form, initial }
                    } else {
                        let challenge = new_openconnect_auth_challenge(
                            "",
                            form.message.clone(),
                            error,
                            OpenConnectAuthChallengeKind::Form(
                                OpenConnectAuthPromptForm { fields },
                            ),
                        );
                        self.stage = Stage::AwaitForm {
                            challenge: challenge.clone(),
                            form,
                            initial,
                        };
                        return Ok(FortinetAuthenticationProgress::Challenge(
                            challenge,
                        ));
                    }
                }
                Action::SubmitForm { mut form, initial } => {
                    let values = form
                        .fields
                        .iter()
                        .map(|field| {
                            (field.submission_key.clone(), field.value.clone())
                        })
                        .collect::<HashMap<_, _>>();
                    let encoded = encode_fortinet_authentication_response(
                        &form,
                        &values,
                        &self.realm,
                        initial,
                    )?;
                    if initial {
                        self.username = form
                            .fields
                            .iter()
                            .find(|field| field.name == "username")
                            .map(|field| field.value.clone())
                            .unwrap_or_default();
                    }
                    let request_url = self.authentication_post_url(&form)?;
                    for field in &mut form.fields {
                        if field.kind
                            == FortinetAuthenticationFieldKind::Password
                            || field.name == "code"
                        {
                            field.value.clear();
                        }
                    }
                    let response = self
                        .request(
                            Method::POST,
                            request_url,
                            encoded.body.into_bytes(),
                        )
                        .await?;
                    self.remember_response(&response);
                    if response.status == StatusCode::OK {
                        check_authentication_result(&response.body)?;
                        if let Some(session) =
                            self.session_from_response(&response)?
                        {
                            return self
                                .complete_session(&response, session)
                                .await;
                        }
                    }
                    self.next_after_form_response(response, form, initial)?
                }
                Action::BeginSaml(mut url) => {
                    if self.options.external_auth_disabled {
                        return Err(FortinetAuthenticatorError::Unsupported(
                            "gateway requested disabled external authentication".into(),
                        ));
                    }
                    ensure_same_endpoint(&self.current_url, &url)?;
                    set_query_pair(&mut url, "redirect", "1");
                    let challenge = new_openconnect_auth_challenge(
                        "",
                        "",
                        "",
                        OpenConnectAuthChallengeKind::Browser(
                            OpenConnectBrowserRequest {
                                url: url.to_string(),
                                callback_url_prefixes: vec![
                                    "http://127.0.0.1:".into(),
                                ],
                                ..Default::default()
                            },
                        ),
                    );
                    self.stage = Stage::AwaitSaml {
                        challenge: challenge.clone(),
                    };
                    return Ok(FortinetAuthenticationProgress::Challenge(
                        challenge,
                    ));
                }
                Action::CompleteSaml(session_id) => {
                    let mut url =
                        endpoint_url(&self.current_url, "/remote/saml/auth_id");
                    url.query_pairs_mut().append_pair("id", &session_id);
                    let response =
                        self.request(Method::GET, url, Vec::new()).await?;
                    self.remember_response(&response);
                    if response.status != StatusCode::OK {
                        return Err(FortinetAuthenticatorError::Rejected(
                            format!(
                                "SAML auth_id returned HTTP {}",
                                response.status
                            ),
                        ));
                    }
                    check_authentication_result(&response.body)?;
                    let session =
                        self.session_from_response(&response)?.ok_or(
                            FortinetAuthenticatorError::MissingSessionCookie,
                        )?;
                    return self.complete_session(&response, session).await;
                }
            };
        }
    }

    fn next_after_form_response(
        &self,
        response: AnyConnectAuthHttpResponse,
        form: FortinetAuthenticationForm,
        initial: bool,
    ) -> Result<Action, FortinetAuthenticatorError> {
        if response.final_url.path() == "/remote/saml/start" {
            return Ok(Action::BeginSaml(response.final_url));
        }
        if is_redirect(response.status)
            && let Some(location) = response
                .headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
        {
            let location =
                response.final_url.join(location).map_err(|error| {
                    FortinetAuthenticatorError::InvalidServerUrl(
                        error.to_string(),
                    )
                })?;
            if location.path() == "/remote/saml/start" {
                return Ok(Action::BeginSaml(location));
            }
        }
        match response.status {
            StatusCode::OK => {
                if let Some(location) =
                    parse_fortinet_top_location(&response.body)?
                {
                    let location = response.final_url.join(&location).map_err(
                        |error| {
                            FortinetAuthenticatorError::InvalidServerUrl(
                                error.to_string(),
                            )
                        },
                    )?;
                    if location.path() == "/remote/saml/start" {
                        return Ok(Action::BeginSaml(location));
                    }
                }
                let content_type = response
                    .headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                if is_fortinet_html_response(content_type, &response.body) {
                    let mut saml =
                        endpoint_url(&self.current_url, "/remote/saml/start");
                    if !self.realm.is_empty() {
                        saml.query_pairs_mut()
                            .append_pair("realm", &self.realm);
                    }
                    Ok(Action::BeginSaml(saml))
                } else {
                    Ok(Action::PrepareForm {
                        form: parse_fortinet_token_info(
                            &response.body,
                            &self.username,
                        )?,
                        initial: false,
                        error: String::new(),
                        allow_initial_prefill: false,
                    })
                }
            }
            StatusCode::UNAUTHORIZED => Ok(Action::PrepareForm {
                form: parse_fortinet_html_challenge(&response.body)?,
                initial: false,
                error: String::new(),
                allow_initial_prefill: false,
            }),
            StatusCode::METHOD_NOT_ALLOWED => Ok(Action::PrepareForm {
                form,
                initial,
                error: "Invalid credentials; try again.".into(),
                allow_initial_prefill: false,
            }),
            status
                if is_redirect(status) || status == StatusCode::FORBIDDEN =>
            {
                Err(FortinetAuthenticatorError::Rejected(if initial {
                    "gateway rejected the primary credentials".into()
                } else {
                    "gateway rejected the authentication continuation".into()
                }))
            }
            status => Err(FortinetAuthenticatorError::Rejected(format!(
                "logincheck returned HTTP {status}"
            ))),
        }
    }

    fn prefill_form(
        &mut self,
        form: &mut FortinetAuthenticationForm,
        initial: bool,
        allow_initial_prefill: bool,
    ) -> Result<(), FortinetAuthenticatorError> {
        for field in &mut form.fields {
            if initial && allow_initial_prefill && field.value.is_empty() {
                if field.name == "username" {
                    field.value.clone_from(&self.options.username);
                } else if field.name == "credential" {
                    field.value.clone_from(&self.options.password);
                }
            }
            if !initial
                && field.kind == FortinetAuthenticationFieldKind::Password
                && field.value.is_empty()
                && self.token_generator.as_ref().is_some_and(|generator| {
                    generator.can_generate(&form.message)
                })
            {
                field.value = self
                    .token_generator
                    .as_mut()
                    .expect("checked above")
                    .generate(&form.message)
                    .map_err(|error| {
                        FortinetAuthenticatorError::Token(error.to_string())
                    })?;
            }
        }
        Ok(())
    }

    async fn request(
        &mut self,
        method: Method,
        url: Url,
        body: Vec<u8>,
    ) -> Result<AnyConnectAuthHttpResponse, FortinetAuthenticatorError> {
        let response = self
            .http
            .execute(AnyConnectAuthHttpRequest {
                content_type: (method == Method::POST)
                    .then(|| "application/x-www-form-urlencoded".into()),
                method,
                url,
                body,
                xml_post: false,
                xml_post_probe: false,
                authentication_headers: false,
                preserve_cookie_jar_on_redirect: false,
                follow_redirects: false,
            })
            .await?;
        if response.body.len() > FORTINET_MAXIMUM_AUTHENTICATION_BODY {
            return Err(FortinetAuthenticatorError::BodyTooLarge(
                FORTINET_MAXIMUM_AUTHENTICATION_BODY,
            ));
        }
        Ok(response)
    }

    fn remember_response(&mut self, response: &AnyConnectAuthHttpResponse) {
        self.current_url.clone_from(&response.final_url);
        if response.authenticated_address.is_some() {
            self.current_address = response.authenticated_address;
        }
        if response.peer_certificate_der.is_some() {
            self.peer_certificate_der
                .clone_from(&response.peer_certificate_der);
        }
    }

    fn prepare_redirect(
        &mut self,
        current: &Url,
        location: &Url,
    ) -> Result<(), FortinetAuthenticatorError> {
        validate_https(location)?;
        if !equal_endpoint(current, location) {
            self.http.clear_cookies();
            self.current_address = None;
            self.peer_certificate_der = None;
        }
        Ok(())
    }

    fn authentication_post_url(
        &self,
        form: &FortinetAuthenticationForm,
    ) -> Result<Url, FortinetAuthenticatorError> {
        let url = if form.action.is_empty() {
            endpoint_url(&self.current_url, "/remote/logincheck")
        } else {
            let url = self.current_url.join(&form.action).map_err(|error| {
                FortinetAuthenticatorError::InvalidServerUrl(error.to_string())
            })?;
            ensure_same_endpoint(&self.current_url, &url)?;
            url
        };
        validate_https(&url)?;
        Ok(url)
    }

    fn session_from_response(
        &self,
        response: &AnyConnectAuthHttpResponse,
    ) -> Result<Option<FortinetAuthenticatedSession>, FortinetAuthenticatorError>
    {
        let response_values = response
            .headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| {
                RawCookie::parse(value.to_str().ok()?.to_owned()).ok()
            })
            .filter(|cookie| {
                cookie.name() == "SVPNCOOKIE" && !cookie.value().is_empty()
            })
            .map(|cookie| cookie.value().to_owned())
            .collect::<HashSet<_>>();
        if response_values.is_empty() {
            return Ok(None);
        }
        let svpn_cookie = self
            .http
            .cookie_value(&response.final_url, "SVPNCOOKIE")
            .ok_or(FortinetAuthenticatorError::MissingSessionCookie)?;
        if !response_values.contains(&svpn_cookie) {
            return Err(FortinetAuthenticatorError::Rejected(
                "authentication response did not replace the active SVPNCOOKIE"
                    .into(),
            ));
        }
        Ok(Some(FortinetAuthenticatedSession {
            server_url: response.final_url.clone(),
            authenticated_address: self.current_address,
            peer_certificate_der: self.peer_certificate_der.clone(),
            svpn_cookie,
            cookies: self.http.cookie_pairs(&response.final_url),
        }))
    }

    async fn complete_session(
        &mut self,
        response: &AnyConnectAuthHttpResponse,
        mut session: FortinetAuthenticatedSession,
    ) -> Result<FortinetAuthenticationProgress, FortinetAuthenticatorError>
    {
        if !self.options.host_check.is_empty()
            && let Some(action) =
                parse_fortinet_host_check_action(&response.body)?
        {
            let url = response.final_url.join(&action).map_err(|error| {
                FortinetAuthenticatorError::InvalidServerUrl(error.to_string())
            })?;
            ensure_same_endpoint(&response.final_url, &url)?;
            let body = format!(
                "hostcheck={}&check_virtual_desktop={}",
                query_escape(&self.options.host_check),
                query_escape(&self.options.check_virtual_desktop)
            );
            let response =
                self.request(Method::POST, url, body.into_bytes()).await?;
            self.remember_response(&response);
            if !response.status.is_success() {
                return Err(FortinetAuthenticatorError::Rejected(format!(
                    "host-check returned HTTP {}",
                    response.status
                )));
            }
            let svpn_cookie = self
                .http
                .cookie_value(&response.final_url, "SVPNCOOKIE")
                .ok_or(FortinetAuthenticatorError::MissingSessionCookie)?;
            session.server_url = response.final_url;
            session.authenticated_address = self.current_address;
            session.peer_certificate_der = self.peer_certificate_der.clone();
            session.svpn_cookie = svpn_cookie;
            session.cookies = self.http.cookie_pairs(&session.server_url);
        }
        self.stage = Stage::Complete;
        Ok(FortinetAuthenticationProgress::Complete(session))
    }
}

fn visible_missing_fields(
    form: &FortinetAuthenticationForm,
) -> Vec<OpenConnectAuthPromptField> {
    form.fields
        .iter()
        .filter(|field| {
            field.kind != FortinetAuthenticationFieldKind::Hidden
                && field.value.is_empty()
        })
        .map(|field| OpenConnectAuthPromptField {
            submission_key: field.submission_key.clone(),
            name: field.name.clone(),
            label: field.label.clone(),
            kind: match field.kind {
                FortinetAuthenticationFieldKind::Password => {
                    OpenConnectAuthPromptKind::Password
                }
                FortinetAuthenticationFieldKind::Hidden
                | FortinetAuthenticationFieldKind::Text => {
                    OpenConnectAuthPromptKind::Text
                }
            },
            value: field.value.clone(),
            options: Vec::new(),
        })
        .collect()
}

fn only_empty_code(
    form: &FortinetAuthenticationForm,
    fields: &[OpenConnectAuthPromptField],
) -> bool {
    form.ftm_push && fields.len() == 1 && fields[0].name == "code"
}

fn check_authentication_result(
    body: &[u8],
) -> Result<(), FortinetAuthenticatorError> {
    match parse_fortinet_authentication_result(body)? {
        Some(0) => Err(FortinetAuthenticatorError::Rejected(
            "gateway rejected the Fortinet authentication".into(),
        )),
        Some(6) => Err(FortinetAuthenticatorError::Unsupported(
            "gateway requested an unsupported authentication challenge".into(),
        )),
        _ => Ok(()),
    }
}

fn parse_server_url(server: &str) -> Result<Url, FortinetAuthenticatorError> {
    let server = server.trim();
    let value = if server.contains("://") {
        server.to_owned()
    } else {
        format!("https://{server}")
    };
    let mut url = Url::parse(&value).map_err(|error| {
        FortinetAuthenticatorError::InvalidServerUrl(error.to_string())
    })?;
    validate_https(&url)?;
    if url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url)
}

fn validate_https(url: &Url) -> Result<(), FortinetAuthenticatorError> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(FortinetAuthenticatorError::InvalidServerUrl(
            url.to_string(),
        ));
    }
    Ok(())
}

fn ensure_same_endpoint(
    current: &Url,
    candidate: &Url,
) -> Result<(), FortinetAuthenticatorError> {
    if !equal_endpoint(current, candidate) {
        return Err(FortinetAuthenticatorError::InvalidServerUrl(
            "authentication action changed the accepted origin".into(),
        ));
    }
    Ok(())
}

fn equal_endpoint(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn endpoint_url(server: &Url, path: &str) -> Url {
    let mut result = server.clone();
    result.set_path(path);
    result.set_query(None);
    result.set_fragment(None);
    result
}

fn set_query_pair(url: &mut Url, key: &str, value: &str) {
    let mut pairs = url
        .query_pairs()
        .filter(|(name, _)| name != key)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.push((key.to_owned(), value.to_owned()));
    url.query_pairs_mut().clear().extend_pairs(pairs);
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn query_escape(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use http::{HeaderMap, Request, header::SET_COOKIE};

    use super::*;
    use crate::protocol::openconnect::{
        AnyConnectAuthHttpTransport, AnyConnectAuthRawHttpResponse,
    };

    struct ScriptedTransport {
        responses: Mutex<Vec<AnyConnectAuthRawHttpResponse>>,
        requests: Mutex<Vec<Request<Vec<u8>>>>,
    }

    #[async_trait]
    impl AnyConnectAuthHttpTransport for ScriptedTransport {
        async fn execute(
            &self,
            request: Request<Vec<u8>>,
        ) -> io::Result<AnyConnectAuthRawHttpResponse> {
            self.requests.lock().unwrap().push(request);
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(io::Error::other("script exhausted"));
            }
            Ok(responses.remove(0))
        }
    }

    fn response(
        status: StatusCode,
        body: impl Into<Vec<u8>>,
        cookie: Option<&str>,
    ) -> AnyConnectAuthRawHttpResponse {
        let mut headers = HeaderMap::new();
        if let Some(cookie) = cookie {
            headers.insert(SET_COOKIE, cookie.parse().unwrap());
        }
        AnyConnectAuthRawHttpResponse {
            status,
            headers,
            body: body.into(),
            authenticated_address: Some("192.0.2.1".parse().unwrap()),
            peer_certificate_der: Some(vec![1, 2, 3]),
        }
    }

    fn authenticator(
        responses: Vec<AnyConnectAuthRawHttpResponse>,
        options: FortinetAuthenticatorOptions,
    ) -> (FortinetAuthenticator, Arc<ScriptedTransport>) {
        let transport = Arc::new(ScriptedTransport {
            responses: Mutex::new(responses),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(
            transport.clone(),
            FORTINET_PROTOCOL_USER_AGENT,
        );
        (
            FortinetAuthenticator::new(http, "https://vpn.example/", options)
                .unwrap(),
            transport,
        )
    }

    #[tokio::test]
    async fn configured_credentials_complete_and_preserve_cookie_set() {
        let (mut authenticator, transport) = authenticator(
            vec![
                response(StatusCode::OK, Vec::new(), None),
                response(
                    StatusCode::OK,
                    b"ret=1".to_vec(),
                    Some("SVPNCOOKIE=session; Path=/; Secure"),
                ),
            ],
            FortinetAuthenticatorOptions {
                username: "alice".into(),
                password: "secret".into(),
                ..Default::default()
            },
        );
        let FortinetAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected complete session");
        };
        assert_eq!(session.svpn_cookie, "session");
        assert_eq!(
            session.authenticated_address,
            Some("192.0.2.1".parse().unwrap())
        );
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].uri().path(), "/remote/logincheck");
        assert_eq!(
            requests[1].body(),
            b"username=alice&credential=secret&realm=&ajax=1&just_logged_in=1"
        );
    }

    #[tokio::test]
    async fn missing_password_yields_validated_resumable_challenge() {
        let (mut authenticator, _) = authenticator(
            vec![
                response(StatusCode::OK, Vec::new(), None),
                response(
                    StatusCode::OK,
                    b"ret=1".to_vec(),
                    Some("SVPNCOOKIE=session; Path=/; Secure"),
                ),
            ],
            FortinetAuthenticatorOptions {
                username: "alice".into(),
                ..Default::default()
            },
        );
        let FortinetAuthenticationProgress::Challenge(challenge) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected challenge");
        };
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            panic!("expected form");
        };
        assert_eq!(prompt.fields.len(), 1);
        assert_eq!(prompt.fields[0].name, "credential");
        let response = OpenConnectAuthResponse::Form(BTreeMap::from([(
            prompt.fields[0].submission_key.clone(),
            "secret".into(),
        )]));
        assert!(matches!(
            authenticator
                .respond(&challenge.id, response)
                .await
                .unwrap(),
            FortinetAuthenticationProgress::Complete(_)
        ));
    }

    #[tokio::test]
    async fn ftm_push_challenge_submits_automatically() {
        let (mut authenticator, transport) = authenticator(
            vec![
                response(StatusCode::OK, Vec::new(), None),
                response(
                    StatusCode::OK,
                    b"ret=2,tokeninfo=ftm_push,reqid=r%2F1,magic=m%2B1"
                        .to_vec(),
                    None,
                ),
                response(
                    StatusCode::OK,
                    b"ret=1".to_vec(),
                    Some("SVPNCOOKIE=session; Path=/; Secure"),
                ),
            ],
            FortinetAuthenticatorOptions {
                username: "alice".into(),
                password: "secret".into(),
                ..Default::default()
            },
        );
        assert!(matches!(
            authenticator.begin().await.unwrap(),
            FortinetAuthenticationProgress::Complete(_)
        ));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2].body(),
            b"username=alice&code=&realm=&reqid=r%2F1&ftmpush=1"
        );
    }

    #[tokio::test]
    async fn saml_callback_completes_auth_id_exchange() {
        let mut redirect = response(StatusCode::FOUND, Vec::new(), None);
        redirect
            .headers
            .insert(LOCATION, "/remote/saml/start".parse().unwrap());
        let (mut authenticator, transport) = authenticator(
            vec![
                redirect,
                response(
                    StatusCode::OK,
                    b"ret=1".to_vec(),
                    Some("SVPNCOOKIE=saml; Path=/; Secure"),
                ),
            ],
            FortinetAuthenticatorOptions::default(),
        );
        let FortinetAuthenticationProgress::Challenge(challenge) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected SAML challenge");
        };
        let response = OpenConnectAuthResponse::Browser(
            super::super::OpenConnectBrowserResult {
                final_url: "http://127.0.0.1:8020/?id=session-1".into(),
                ..Default::default()
            },
        );
        assert!(matches!(
            authenticator
                .respond(&challenge.id, response)
                .await
                .unwrap(),
            FortinetAuthenticationProgress::Complete(_)
        ));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests[1].uri().path(), "/remote/saml/auth_id");
        assert_eq!(requests[1].uri().query(), Some("id=session-1"));
    }
}
