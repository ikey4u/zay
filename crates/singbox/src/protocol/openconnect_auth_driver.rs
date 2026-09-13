//! Stateful AnyConnect authentication driver.
//!
//! The driver joins XML/legacy wire encoding, RFC 6265 HTTP state, group and
//! browser challenges, and form continuation into one reusable library API.
//! Its transport remains injected so an embedding runtime can route every
//! request through an arbitrary singbox dialer and TLS implementation.

use std::{collections::BTreeMap, mem, net::IpAddr};

use http::{Method, StatusCode};
use thiserror::Error;
use url::Url;

use super::{
    AnyConnectAuthClientIdentity, AnyConnectAuthContinuationError,
    AnyConnectAuthError, AnyConnectAuthFieldKind, AnyConnectAuthForm,
    AnyConnectAuthHttpClient, AnyConnectAuthHttpError,
    AnyConnectAuthHttpRequest, AnyConnectAuthHttpResponse,
    AnyConnectAuthPrefillOptions, AnyConnectHostScan, AnyConnectHostScanError,
    AnyConnectHostScanOptions, AnyConnectMcaError, AnyConnectMcaIdentity,
    AnyConnectOpaque, AnyConnectPreparedAuthForm,
    AnyConnectSoftwareTokenGenerator, OpenConnectAuthChallenge,
    OpenConnectAuthChallengeKind, OpenConnectAuthPromptChoice,
    OpenConnectAuthPromptField, OpenConnectAuthPromptForm,
    OpenConnectAuthPromptKind, OpenConnectAuthResponse,
    OpenConnectBrowserRequest, apply_anyconnect_auth_group,
    build_anyconnect_authentication_reply_xml, build_anyconnect_initial_xml,
    build_anyconnect_legacy_form_body, build_anyconnect_mca_response,
    complete_anyconnect_auth_form, configure_anyconnect_token_field,
    new_openconnect_auth_challenge, parse_anyconnect_authentication_xml,
    parse_anyconnect_direct_cookie, prepare_anyconnect_auth_form,
    reorder_anyconnect_auth_group, run_anyconnect_host_scan,
    validate_openconnect_browser_response, validate_openconnect_form_response,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectAuthenticatorOptions {
    pub identity: AnyConnectAuthClientIdentity,
    pub prefill: AnyConnectAuthPrefillOptions,
    pub xml_post_disabled: bool,
    pub external_auth_disabled: bool,
    pub password_authentication_disabled: bool,
    /// Whether the injected TLS transport has a client identity configured.
    pub client_certificate_configured: bool,
    pub direct_cookie: Option<String>,
    /// Optional identity for aggregate multiple-certificate authentication.
    pub mca_identity: Option<AnyConnectMcaIdentity>,
    pub host_scan: AnyConnectHostScanOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyConnectAuthenticatedSession {
    pub server_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
    pub webvpn_cookie: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyConnectAuthenticationProgress {
    Challenge(OpenConnectAuthChallenge),
    Complete(AnyConnectAuthenticatedSession),
}

#[derive(Debug, Error)]
pub enum AnyConnectAuthenticatorError {
    #[error(transparent)]
    Auth(#[from] AnyConnectAuthError),
    #[error(transparent)]
    Http(#[from] AnyConnectAuthHttpError),
    #[error(transparent)]
    Continuation(#[from] AnyConnectAuthContinuationError),
    #[error(transparent)]
    Mca(#[from] AnyConnectMcaError),
    #[error(transparent)]
    HostScan(#[from] AnyConnectHostScanError),
    #[error("invalid AnyConnect server URL: {0}")]
    InvalidServerUrl(String),
    #[error("AnyConnect authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error(
        "AnyConnect authentication returned HTTP {status} (retryable: {retryable})"
    )]
    HttpStatus { status: StatusCode, retryable: bool },
    #[error("unsupported AnyConnect authentication behavior: {0}")]
    Unsupported(String),
    #[error("AnyConnect authentication succeeded without a webvpn cookie")]
    MissingWebvpnCookie,
    #[error("no AnyConnect authentication challenge is pending")]
    NoPendingChallenge,
    #[error("AnyConnect authentication challenge ID does not match")]
    ChallengeMismatch,
    #[error(
        "AnyConnect authentication response type does not match the pending challenge"
    )]
    ResponseTypeMismatch,
    #[error("AnyConnect authentication has already completed")]
    AlreadyComplete,
    #[error("AnyConnect authentication continuation is in a terminal state")]
    TerminalState,
}

#[derive(Debug, Clone)]
enum AuthStage {
    InitialXml,
    InitialLegacy,
    ProcessForm(AnyConnectAuthForm),
    AwaitGroup {
        form: AnyConnectAuthForm,
        challenge: OpenConnectAuthChallenge,
    },
    AwaitForm {
        prepared: Box<AnyConnectPreparedAuthForm>,
        challenge: OpenConnectAuthChallenge,
    },
    AwaitSsoCompanion {
        form: AnyConnectAuthForm,
        prepared: Box<AnyConnectPreparedAuthForm>,
        challenge: OpenConnectAuthChallenge,
    },
    AwaitSsoBrowser {
        form: AnyConnectAuthForm,
        challenge: OpenConnectAuthChallenge,
    },
    SubmitForm(AnyConnectAuthForm),
    SubmitMca(AnyConnectAuthForm),
    RunHostScan,
    Complete,
    Terminal,
}

pub struct AnyConnectAuthenticator {
    http: AnyConnectAuthHttpClient,
    options: AnyConnectAuthenticatorOptions,
    server_url: Url,
    current_url: Url,
    stage: AuthStage,
    immediate_session: Option<AnyConnectAuthenticatedSession>,
    xml_post: bool,
    selected_group: String,
    opaque: Option<AnyConnectOpaque>,
    host_scan: AnyConnectHostScan,
    host_scan_completed: bool,
    authenticated_address: Option<IpAddr>,
    peer_certificate_der: Option<Vec<u8>>,
    primary_password_submitted: bool,
    client_certificate_retried: bool,
    client_certificate_failure_count: u8,
    client_certificate_failure_reason: String,
    next_client_certificate_failure: bool,
    software_token_generator: Option<Box<dyn AnyConnectSoftwareTokenGenerator>>,
}

impl AnyConnectAuthenticator {
    pub fn new(
        mut http: AnyConnectAuthHttpClient,
        server_url: impl AsRef<str>,
        options: AnyConnectAuthenticatorOptions,
    ) -> Result<Self, AnyConnectAuthenticatorError> {
        let server_url = Url::parse(server_url.as_ref()).map_err(|error| {
            AnyConnectAuthenticatorError::InvalidServerUrl(error.to_string())
        })?;
        validate_server_url(&server_url)?;
        let mut immediate_session = None;
        if let Some(content) = options.direct_cookie.as_deref() {
            let cookies = parse_anyconnect_direct_cookie(content, "webvpn")?;
            let webvpn_cookie =
                cookies.get("webvpn").cloned().ok_or_else(|| {
                    AnyConnectAuthenticatorError::AuthenticationFailed(
                        "direct cookie does not contain webvpn".into(),
                    )
                })?;
            for (name, value) in cookies {
                http.set_cookie(&server_url, &name, &value)?;
            }
            immediate_session = Some(AnyConnectAuthenticatedSession {
                server_url: server_url.clone(),
                authenticated_address: None,
                peer_certificate_der: None,
                webvpn_cookie,
            });
        }
        let xml_post = !options.xml_post_disabled;
        let stage = if immediate_session.is_some() {
            AuthStage::Complete
        } else if xml_post {
            AuthStage::InitialXml
        } else {
            AuthStage::InitialLegacy
        };
        Ok(Self {
            http,
            options,
            current_url: server_url.clone(),
            server_url,
            stage,
            immediate_session,
            xml_post,
            selected_group: String::new(),
            opaque: None,
            host_scan: AnyConnectHostScan::default(),
            host_scan_completed: false,
            authenticated_address: None,
            peer_certificate_der: None,
            primary_password_submitted: false,
            client_certificate_retried: false,
            client_certificate_failure_count: 0,
            client_certificate_failure_reason: String::new(),
            next_client_certificate_failure: false,
            software_token_generator: None,
        })
    }

    /// Install a per-authentication software-token generator.
    ///
    /// The generator is invoked only when the gateway presents a field that
    /// is eligible for the configured token type, so group selection and
    /// unrelated forms do not consume HOTP counters.
    pub fn set_software_token_generator(
        &mut self,
        generator: Box<dyn AnyConnectSoftwareTokenGenerator>,
    ) {
        self.options.prefill.token_type = Some(generator.token_type().into());
        self.software_token_generator = Some(generator);
    }

    pub fn current_url(&self) -> &Url {
        &self.current_url
    }

    pub fn pending_challenge(&self) -> Option<&OpenConnectAuthChallenge> {
        match &self.stage {
            AuthStage::AwaitGroup { challenge, .. }
            | AuthStage::AwaitForm { challenge, .. }
            | AuthStage::AwaitSsoCompanion { challenge, .. }
            | AuthStage::AwaitSsoBrowser { challenge, .. } => Some(challenge),
            _ => None,
        }
    }

    pub async fn begin(
        &mut self,
    ) -> Result<AnyConnectAuthenticationProgress, AnyConnectAuthenticatorError>
    {
        if self.pending_challenge().is_some() {
            return Err(AnyConnectAuthenticatorError::NoPendingChallenge);
        }
        self.drive(None).await
    }

    pub async fn respond(
        &mut self,
        challenge_id: &str,
        response: OpenConnectAuthResponse,
    ) -> Result<AnyConnectAuthenticationProgress, AnyConnectAuthenticatorError>
    {
        let pending = self
            .pending_challenge()
            .ok_or(AnyConnectAuthenticatorError::NoPendingChallenge)?;
        if pending.id != challenge_id {
            return Err(AnyConnectAuthenticatorError::ChallengeMismatch);
        }
        self.drive(Some(response)).await
    }

    async fn drive(
        &mut self,
        mut response: Option<OpenConnectAuthResponse>,
    ) -> Result<AnyConnectAuthenticationProgress, AnyConnectAuthenticatorError>
    {
        loop {
            let stage = mem::replace(&mut self.stage, AuthStage::Terminal);
            match stage {
                AuthStage::InitialXml => {
                    if response.is_some() {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                    self.advance_initial_xml().await?;
                }
                AuthStage::InitialLegacy => {
                    if response.is_some() {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                    self.advance_initial_legacy().await?;
                }
                AuthStage::ProcessForm(form) => {
                    if response.is_some() {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                    if let Some(progress) = self.process_form(form)? {
                        return Ok(progress);
                    }
                }
                AuthStage::AwaitGroup {
                    mut form,
                    challenge,
                } => {
                    let OpenConnectAuthResponse::Form(values) =
                        response.take().ok_or(
                            AnyConnectAuthenticatorError::NoPendingChallenge,
                        )?
                    else {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    };
                    let OpenConnectAuthChallengeKind::Form(prompt) =
                        &challenge.kind
                    else {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    };
                    validate_openconnect_form_response(
                        &prompt.fields,
                        &values,
                    )?;
                    let field = find_group(&mut form).ok_or_else(|| {
                        AnyConnectAuthenticatorError::Unsupported(
                            "authgroup response has no group_list field".into(),
                        )
                    })?;
                    let selected = values
                        .get(&field.submission_key)
                        .expect("validated above")
                        .clone();
                    let choice = field
                        .choices
                        .iter()
                        .find(|choice| {
                            choice.name == selected || choice.label == selected
                        })
                        .ok_or_else(|| {
                            AnyConnectAuthError::InvalidSelection(
                                field.submission_key.clone(),
                            )
                        })?;
                    let selected = choice.name.clone();
                    let server_selection = field.value.clone();
                    self.selected_group.clone_from(&selected);
                    self.options.prefill.credentials.auth_group =
                        Some(selected.clone());
                    apply_anyconnect_auth_group(&mut form, &selected);
                    if self.xml_post && selected != server_selection {
                        self.stage = AuthStage::InitialXml;
                    } else if let Some(progress) =
                        self.prepare_regular_form(form)?
                    {
                        return Ok(progress);
                    }
                }
                AuthStage::AwaitForm {
                    prepared,
                    challenge: _,
                } => {
                    let completed = complete_anyconnect_auth_form(
                        *prepared,
                        response.take(),
                    )?;
                    self.stage = AuthStage::SubmitForm(completed);
                }
                AuthStage::AwaitSsoCompanion {
                    mut form,
                    prepared,
                    challenge: _,
                } => {
                    let completed = complete_anyconnect_auth_form(
                        *prepared,
                        response.take(),
                    )?;
                    copy_companion_values(&completed, &mut form);
                    let progress = self.prepare_sso_browser(form)?;
                    return Ok(progress);
                }
                AuthStage::AwaitSsoBrowser {
                    mut form,
                    challenge,
                } => {
                    let OpenConnectAuthResponse::Browser(result) =
                        response.take().ok_or(
                            AnyConnectAuthenticatorError::NoPendingChallenge,
                        )?
                    else {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    };
                    let OpenConnectAuthChallengeKind::Browser(request) =
                        &challenge.kind
                    else {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    };
                    validate_openconnect_browser_response(request, &result)?;
                    if let Some(cookie) = result.cookies.iter().find(|cookie| {
                        cookie.name == form.sso.error_cookie
                            && !cookie.value.is_empty()
                    }) {
                        return Err(
                            AnyConnectAuthenticatorError::AuthenticationFailed(
                                format!("SSO failed: {}", cookie.value),
                            ),
                        );
                    }
                    let token = result
                        .cookies
                        .iter()
                        .find(|cookie| {
                            cookie.name == form.sso.token_cookie
                                && !cookie.value.is_empty()
                        })
                        .map(|cookie| cookie.value.clone())
                        .ok_or_else(|| {
                            AnyConnectAuthenticatorError::AuthenticationFailed(
                                "SSO browser result omitted the token cookie"
                                    .into(),
                            )
                        })?;
                    for field in &mut form.fields {
                        if field.kind == AnyConnectAuthFieldKind::SsoToken {
                            field.value.clone_from(&token);
                        }
                    }
                    self.stage = AuthStage::SubmitForm(form);
                }
                AuthStage::SubmitForm(form) => {
                    if response.is_some() {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                    self.submit_form(form).await?;
                }
                AuthStage::SubmitMca(form) => {
                    if response.is_some() {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                    self.submit_mca(form).await?;
                }
                AuthStage::RunHostScan => {
                    if response.is_some() {
                        return Err(
                            AnyConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                    self.run_host_scan().await?;
                }
                AuthStage::Complete => {
                    if let Some(session) = self.immediate_session.take() {
                        self.stage = AuthStage::Complete;
                        return Ok(AnyConnectAuthenticationProgress::Complete(
                            session,
                        ));
                    }
                    return Err(AnyConnectAuthenticatorError::AlreadyComplete);
                }
                AuthStage::Terminal => {
                    return Err(AnyConnectAuthenticatorError::TerminalState);
                }
            }
        }
    }

    async fn advance_initial_xml(
        &mut self,
    ) -> Result<(), AnyConnectAuthenticatorError> {
        self.http.remove_cookie(&self.current_url, "webvpn")?;
        self.selected_group = self
            .options
            .prefill
            .credentials
            .auth_group
            .clone()
            .unwrap_or_default();
        let client_certificate_failure =
            mem::take(&mut self.next_client_certificate_failure);
        let body = build_anyconnect_initial_xml(
            &self.options.identity,
            self.current_url.as_str(),
            &self.selected_group,
            client_certificate_failure,
        )?;
        let response = self
            .request(
                Method::POST,
                Some("application/xml; charset=utf-8"),
                body,
                true,
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(AnyConnectAuthenticatorError::Http(
                AnyConnectAuthHttpError::XmlPostFallback,
            )) => {
                self.reset_for_legacy();
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if response.status != StatusCode::OK {
            if matches!(
                response.status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) {
                return Err(
                    AnyConnectAuthenticatorError::AuthenticationFailed(
                        format!(
                            "XMLPOST initialization rejected with HTTP {}",
                            response.status
                        ),
                    ),
                );
            }
            self.reset_for_legacy();
            return Ok(());
        }
        let form = match parse_anyconnect_authentication_xml(
            &response.body,
            self.reported_os(),
        ) {
            Ok(form) => form,
            Err(_) => {
                self.reset_for_legacy();
                return Ok(());
            }
        };
        self.record_response(&response);
        self.stage = AuthStage::ProcessForm(form);
        Ok(())
    }

    async fn advance_initial_legacy(
        &mut self,
    ) -> Result<(), AnyConnectAuthenticatorError> {
        let response =
            self.request(Method::GET, None, Vec::new(), false).await?;
        require_success(response.status, "legacy AnyConnect authentication")?;
        let form = parse_anyconnect_authentication_xml(
            &response.body,
            self.reported_os(),
        )?;
        self.record_response(&response);
        self.stage = AuthStage::ProcessForm(form);
        Ok(())
    }

    fn process_form(
        &mut self,
        mut form: AnyConnectAuthForm,
    ) -> Result<
        Option<AnyConnectAuthenticationProgress>,
        AnyConnectAuthenticatorError,
    > {
        reorder_anyconnect_auth_group(&mut form);
        if let Some(opaque) = form.opaque.take() {
            self.opaque = Some(opaque);
        }
        if !self.host_scan_completed {
            merge_host_scan(&mut self.host_scan, &form.host_scan);
        }
        if form.client_certificate_requested
            && !form.client_certificate_authenticated
        {
            if self.options.client_certificate_configured
                && !self.client_certificate_retried
            {
                self.client_certificate_retried = true;
                self.stage = AuthStage::InitialXml;
                return Ok(None);
            }
            self.client_certificate_failure_reason = if self
                .options
                .client_certificate_configured
            {
                "gateway did not accept the configured TLS client certificate"
                    .into()
            } else {
                "gateway requested a TLS client certificate, but none was configured"
                    .into()
            };
            if !self.xml_post {
                return Err(
                    AnyConnectAuthenticatorError::AuthenticationFailed(
                        self.client_certificate_failure_reason.clone(),
                    ),
                );
            }
            if self.client_certificate_failure_count >= 1 {
                self.reset_for_legacy();
                return Ok(None);
            }
            self.client_certificate_failure_count += 1;
            self.next_client_certificate_failure = true;
            self.stage = AuthStage::InitialXml;
            return Ok(None);
        }
        if form.multiple_certificates_requested {
            form.opaque.clone_from(&self.opaque);
            self.stage = AuthStage::SubmitMca(form);
            return Ok(None);
        }
        self.apply_form_action(&mut form)?;
        if !self.host_scan_completed && host_scan_requested(&self.host_scan) {
            if self.options.host_scan.disabled {
                return Err(AnyConnectAuthenticatorError::Unsupported(
                    "AnyConnect host scan is disabled".into(),
                ));
            }
            self.stage = AuthStage::RunHostScan;
            return Ok(None);
        }
        if !form.session_token.is_empty() {
            self.http.set_cookie(
                &self.current_url,
                "webvpn",
                &form.session_token,
            )?;
        }
        if form.authentication_complete {
            return self.complete(form.session_token).map(Some);
        }
        if form.post_authentication_complete && form.fields.is_empty() {
            self.stage = AuthStage::SubmitForm(form);
            return Ok(None);
        }
        if form.fields.is_empty() {
            let reason = [&form.error, &form.message]
                .into_iter()
                .find(|value| !value.is_empty())
                .map(|value| value.as_str())
                .unwrap_or("gateway returned an empty authentication form");
            return Err(AnyConnectAuthenticatorError::AuthenticationFailed(
                reason.into(),
            ));
        }
        let mut ocserv_oath_round = false;
        if self.primary_password_submitted {
            ocserv_oath_round =
                form.error.is_empty() && ocserv_oath_message(&form.message);
            let known_password_rejection = !form.error.is_empty()
                || form.message.to_ascii_lowercase().contains("login failed");
            if let Some(password) = ocserv_successor_password(&mut form) {
                if ocserv_oath_round || !known_password_rejection {
                    password.stable_credential = false;
                }
                if !ocserv_oath_round {
                    self.options.prefill.credentials.password = None;
                }
            }
        }
        if let Some(token_type) = self.options.prefill.token_type.as_deref() {
            let automatic = self.options.prefill.generated_token.is_some()
                || self.software_token_generator.as_ref().is_some_and(
                    |generator| generator.can_generate(&form.message),
                );
            configure_anyconnect_token_field(
                &mut form,
                token_type,
                automatic,
                ocserv_oath_round,
            );
        }
        if let Some(group) = find_group(&mut form) {
            let server_selection = group.value.clone();
            if let Some(stable_group) =
                self.options.prefill.credentials.auth_group.as_deref()
                && let Some(choice) = group.choices.iter().find(|choice| {
                    choice.name == stable_group || choice.label == stable_group
                })
            {
                let selected = choice.name.clone();
                self.selected_group.clone_from(&selected);
                self.options.prefill.credentials.auth_group =
                    Some(selected.clone());
                apply_anyconnect_auth_group(&mut form, &selected);
                if self.xml_post && selected != server_selection {
                    self.stage = AuthStage::InitialXml;
                    return Ok(None);
                }
                return self.prepare_regular_form(form);
            }
            let prompt = OpenConnectAuthPromptForm {
                fields: vec![OpenConnectAuthPromptField {
                    submission_key: group.submission_key.clone(),
                    name: group.name.clone(),
                    label: group.label.clone(),
                    kind: OpenConnectAuthPromptKind::Select,
                    value: group.value.clone(),
                    options: group
                        .choices
                        .iter()
                        .map(|choice| OpenConnectAuthPromptChoice {
                            value: choice.name.clone(),
                            label: choice.label.clone(),
                        })
                        .collect(),
                }],
            };
            let challenge = new_openconnect_auth_challenge(
                form.banner.clone(),
                form.message.clone(),
                form.error.clone(),
                OpenConnectAuthChallengeKind::Form(prompt),
            );
            self.stage = AuthStage::AwaitGroup {
                form,
                challenge: challenge.clone(),
            };
            return Ok(Some(AnyConnectAuthenticationProgress::Challenge(
                challenge,
            )));
        }
        self.prepare_regular_form(form)
    }

    fn prepare_regular_form(
        &mut self,
        form: AnyConnectAuthForm,
    ) -> Result<
        Option<AnyConnectAuthenticationProgress>,
        AnyConnectAuthenticatorError,
    > {
        if self.options.password_authentication_disabled {
            return Err(AnyConnectAuthenticatorError::AuthenticationFailed(
                "gateway requested a form while password authentication is disabled"
                    .into(),
            ));
        }
        if form.fields.iter().any(|field| {
            !field.ignore && field.kind == AnyConnectAuthFieldKind::Token
        }) && let Some(generator) = self.software_token_generator.as_mut()
        {
            let token = generator.generate(&form.message).map_err(|error| {
                AnyConnectAuthenticatorError::AuthenticationFailed(format!(
                    "generate AnyConnect software token: {error}"
                ))
            })?;
            self.options.prefill.generated_token = Some(token);
        }
        if form.sso.requested {
            if self.options.external_auth_disabled {
                return Err(AnyConnectAuthenticatorError::Unsupported(
                    "gateway requested disabled external authentication".into(),
                ));
            }
            let mut companion = form.clone();
            for field in &mut companion.fields {
                if field.kind == AnyConnectAuthFieldKind::Token {
                    field.ignore = true;
                }
            }
            let prepared =
                prepare_anyconnect_auth_form(companion, &self.options.prefill)?;
            if let Some(challenge) = prepared.challenge.clone() {
                self.stage = AuthStage::AwaitSsoCompanion {
                    form,
                    prepared: Box::new(prepared),
                    challenge: challenge.clone(),
                };
                return Ok(Some(AnyConnectAuthenticationProgress::Challenge(
                    challenge,
                )));
            }
            let completed = complete_anyconnect_auth_form(prepared, None)?;
            let mut form = form;
            copy_companion_values(&completed, &mut form);
            return self.prepare_sso_browser(form).map(Some);
        }
        let prepared =
            prepare_anyconnect_auth_form(form, &self.options.prefill)?;
        if let Some(challenge) = prepared.challenge.clone() {
            self.stage = AuthStage::AwaitForm {
                prepared: Box::new(prepared),
                challenge: challenge.clone(),
            };
            return Ok(Some(AnyConnectAuthenticationProgress::Challenge(
                challenge,
            )));
        }
        let completed = complete_anyconnect_auth_form(prepared, None)?;
        self.stage = AuthStage::SubmitForm(completed);
        Ok(None)
    }

    fn prepare_sso_browser(
        &mut self,
        mut form: AnyConnectAuthForm,
    ) -> Result<AnyConnectAuthenticationProgress, AnyConnectAuthenticatorError>
    {
        if form.sso.browser_mode.eq_ignore_ascii_case("external") {
            return Err(AnyConnectAuthenticatorError::Unsupported(
                "gateway requested AnyConnect external-browser SSO".into(),
            ));
        }
        if form.sso.login_url.is_empty()
            || form.sso.final_url.is_empty()
            || form.sso.token_cookie.is_empty()
        {
            return Err(AnyConnectAuthenticatorError::AuthenticationFailed(
                "SSO form omitted its login URL, final URL, or token cookie"
                    .into(),
            ));
        }
        let login_url = resolve_https(&self.current_url, &form.sso.login_url)?;
        let final_url = resolve_https(&self.current_url, &form.sso.final_url)?;
        form.sso.login_url = login_url.to_string();
        form.sso.final_url = final_url.to_string();
        for field in &mut form.fields {
            if field.ignore || field.kind != AnyConnectAuthFieldKind::Token {
                continue;
            }
            let token = self
                .options
                .prefill
                .generated_token
                .as_ref()
                .ok_or_else(|| {
                    AnyConnectAuthenticatorError::AuthenticationFailed(format!(
                        "SSO companion token has no generator: {}",
                        field.name
                    ))
                })?;
            field.value.clone_from(token);
        }
        let request = OpenConnectBrowserRequest {
            url: form.sso.login_url.clone(),
            final_url: form.sso.final_url.clone(),
            cookie_names: vec![form.sso.token_cookie.clone()],
            early_cookie_names: (!form.sso.error_cookie.is_empty())
                .then(|| form.sso.error_cookie.clone())
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let challenge = new_openconnect_auth_challenge(
            form.banner.clone(),
            form.message.clone(),
            form.error.clone(),
            OpenConnectAuthChallengeKind::Browser(request),
        );
        self.stage = AuthStage::AwaitSsoBrowser {
            form,
            challenge: challenge.clone(),
        };
        Ok(AnyConnectAuthenticationProgress::Challenge(challenge))
    }

    async fn submit_form(
        &mut self,
        form: AnyConnectAuthForm,
    ) -> Result<(), AnyConnectAuthenticatorError> {
        self.primary_password_submitted = form.fields.iter().any(|field| {
            field.kind == AnyConnectAuthFieldKind::Password
                && field.stable_credential
        });
        let (content_type, body) = if self.xml_post {
            (
                "application/xml; charset=utf-8",
                build_anyconnect_authentication_reply_xml(
                    &self.options.identity,
                    &form,
                    self.opaque.as_ref(),
                    &self.host_scan.token,
                )?,
            )
        } else {
            (
                "application/x-www-form-urlencoded",
                build_anyconnect_legacy_form_body(&form),
            )
        };
        let response = self
            .request(Method::POST, Some(content_type), body, false)
            .await?;
        if matches!(
            response.status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            self.options.prefill.credentials.password = None;
            return Err(AnyConnectAuthenticatorError::AuthenticationFailed(
                format!(
                    "authentication rejected with HTTP {}",
                    response.status
                ),
            ));
        }
        require_success(response.status, "authentication form")?;
        let next = parse_anyconnect_authentication_xml(
            &response.body,
            self.reported_os(),
        )?;
        self.record_response(&response);
        self.stage = AuthStage::ProcessForm(next);
        Ok(())
    }

    async fn submit_mca(
        &mut self,
        form: AnyConnectAuthForm,
    ) -> Result<(), AnyConnectAuthenticatorError> {
        let body = build_anyconnect_mca_response(
            &self.options.identity,
            self.options.mca_identity.as_ref(),
            &form,
        )?;
        let response = self
            .request(
                Method::POST,
                Some("application/xml; charset=utf-8"),
                body,
                false,
            )
            .await?;
        require_success(
            response.status,
            "multiple-certificate authentication",
        )?;
        let next = parse_anyconnect_authentication_xml(
            &response.body,
            self.reported_os(),
        )?;
        self.record_response(&response);
        self.stage = AuthStage::ProcessForm(next);
        Ok(())
    }

    async fn run_host_scan(
        &mut self,
    ) -> Result<(), AnyConnectAuthenticatorError> {
        let state = self.host_scan.clone();
        self.http.clear_cookies();
        let mut scan_http = self.http.isolated();
        let mut host_scan_options = self.options.host_scan.clone();
        host_scan_options
            .wrapper_selected_group
            .clone_from(&self.selected_group);
        host_scan_options.wrapper_authenticated_address =
            self.authenticated_address;
        host_scan_options.wrapper_server_certificate_der =
            self.peer_certificate_der.clone();
        let result = run_anyconnect_host_scan(
            &mut scan_http,
            &self.current_url,
            &state,
            &host_scan_options,
        )
        .await?;
        if result.authenticated_address.is_some() {
            self.authenticated_address = result.authenticated_address;
        }
        self.http
            .set_cookie(&self.current_url, "sdesktop", &state.token)?;
        self.host_scan = AnyConnectHostScan::default();
        self.host_scan_completed = true;

        let (method, content_type, body) = if self.xml_post {
            (
                Method::POST,
                Some("application/xml; charset=utf-8"),
                build_anyconnect_initial_xml(
                    &self.options.identity,
                    self.current_url.as_str(),
                    &self.selected_group,
                    false,
                )?,
            )
        } else {
            (Method::GET, None, Vec::new())
        };
        let response = self.request(method, content_type, body, false).await?;
        require_success(response.status, "post-hostscan refresh")?;
        let next = parse_anyconnect_authentication_xml(
            &response.body,
            self.reported_os(),
        )?;
        self.record_response(&response);
        self.stage = AuthStage::ProcessForm(next);
        Ok(())
    }

    async fn request(
        &mut self,
        method: Method,
        content_type: Option<&str>,
        body: Vec<u8>,
        xml_post_probe: bool,
    ) -> Result<AnyConnectAuthHttpResponse, AnyConnectAuthenticatorError> {
        let initial_url = self.current_url.clone();
        let response = self
            .http
            .execute(AnyConnectAuthHttpRequest {
                method,
                url: initial_url.clone(),
                content_type: content_type.map(str::to_owned),
                body,
                xml_post: self.xml_post,
                xml_post_probe,
                authentication_headers: true,
                preserve_cookie_jar_on_redirect: false,
                follow_redirects: true,
            })
            .await?;
        if !equal_endpoint(&initial_url, &response.final_url) {
            self.authenticated_address = None;
            self.peer_certificate_der = None;
        }
        Ok(response)
    }

    fn record_response(&mut self, response: &AnyConnectAuthHttpResponse) {
        self.current_url.clone_from(&response.final_url);
        if response.authenticated_address.is_some() {
            self.authenticated_address = response.authenticated_address;
        }
        if response.peer_certificate_der.is_some() {
            self.peer_certificate_der
                .clone_from(&response.peer_certificate_der);
        }
    }

    fn apply_form_action(
        &mut self,
        form: &mut AnyConnectAuthForm,
    ) -> Result<(), AnyConnectAuthenticatorError> {
        if form.action.is_empty() {
            return Ok(());
        }
        let target = resolve_https(&self.current_url, &form.action)?;
        if !equal_endpoint(&self.current_url, &target) {
            self.http.clear_cookies();
            self.authenticated_address = None;
            self.peer_certificate_der = None;
        }
        self.current_url = target;
        form.action = self.current_url.to_string();
        Ok(())
    }

    fn complete(
        &mut self,
        session_token: String,
    ) -> Result<AnyConnectAuthenticationProgress, AnyConnectAuthenticatorError>
    {
        if !session_token.is_empty() {
            self.http.set_cookie(
                &self.current_url,
                "webvpn",
                &session_token,
            )?;
        }
        let cookie = self
            .http
            .cookie_value(&self.current_url, "webvpn")
            .filter(|value| !value.is_empty())
            .ok_or(AnyConnectAuthenticatorError::MissingWebvpnCookie)?;
        self.stage = AuthStage::Complete;
        Ok(AnyConnectAuthenticationProgress::Complete(
            AnyConnectAuthenticatedSession {
                server_url: self.current_url.clone(),
                authenticated_address: self.authenticated_address,
                peer_certificate_der: self.peer_certificate_der.clone(),
                webvpn_cookie: cookie,
            },
        ))
    }

    fn reset_for_legacy(&mut self) {
        self.current_url.clone_from(&self.server_url);
        self.stage = AuthStage::InitialLegacy;
        self.xml_post = false;
        self.opaque = None;
        self.host_scan = AnyConnectHostScan::default();
        self.host_scan_completed = false;
        self.authenticated_address = None;
        self.peer_certificate_der = None;
        self.primary_password_submitted = false;
        self.client_certificate_retried = false;
        self.client_certificate_failure_count = 0;
        self.client_certificate_failure_reason.clear();
        self.next_client_certificate_failure = false;
    }

    fn reported_os(&self) -> &str {
        if self.options.identity.reported_os.is_empty() {
            "linux-64"
        } else {
            &self.options.identity.reported_os
        }
    }
}

fn validate_server_url(url: &Url) -> Result<(), AnyConnectAuthenticatorError> {
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(AnyConnectAuthenticatorError::InvalidServerUrl(
            url.to_string(),
        ));
    }
    Ok(())
}

fn resolve_https(
    base: &Url,
    reference: &str,
) -> Result<Url, AnyConnectAuthenticatorError> {
    let url = base.join(reference).map_err(|error| {
        AnyConnectAuthenticatorError::InvalidServerUrl(error.to_string())
    })?;
    validate_server_url(&url)?;
    Ok(url)
}

fn equal_endpoint(left: &Url, right: &Url) -> bool {
    left.host_str()
        .zip(right.host_str())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
        && left.port_or_known_default() == right.port_or_known_default()
}

fn require_success(
    status: StatusCode,
    context: &str,
) -> Result<(), AnyConnectAuthenticatorError> {
    if status == StatusCode::OK {
        return Ok(());
    }
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Err(AnyConnectAuthenticatorError::AuthenticationFailed(
            format!("{context} rejected with HTTP {status}"),
        ));
    }
    let retryable = matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error();
    Err(AnyConnectAuthenticatorError::HttpStatus { status, retryable })
}

fn find_group(
    form: &mut AnyConnectAuthForm,
) -> Option<&mut super::AnyConnectAuthField> {
    form.fields.iter_mut().find(|field| {
        field.name == "group_list"
            && field.kind == AnyConnectAuthFieldKind::Select
    })
}

fn ocserv_successor_password(
    form: &mut AnyConnectAuthForm,
) -> Option<&mut super::AnyConnectAuthField> {
    if form.authentication_id != "main" {
        return None;
    }
    let mut index = None;
    for (candidate, field) in form.fields.iter().enumerate() {
        if field.kind == AnyConnectAuthFieldKind::Hidden {
            continue;
        }
        if field.kind != AnyConnectAuthFieldKind::Password
            || field.name != "password"
            || field.second_authentication
            || index.is_some()
        {
            return None;
        }
        index = Some(candidate);
    }
    index.map(|index| &mut form.fields[index])
}

fn ocserv_oath_message(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase().replace('-', " ");
    normalized.contains("otp password")
        || normalized.contains("one time password")
        || normalized.contains("one time passcode")
}

fn copy_companion_values(
    source: &AnyConnectAuthForm,
    target: &mut AnyConnectAuthForm,
) {
    let values = source
        .fields
        .iter()
        .map(|field| (field.submission_key.as_str(), field.value.as_str()))
        .collect::<BTreeMap<_, _>>();
    for field in &mut target.fields {
        if let Some(value) = values.get(field.submission_key.as_str()) {
            field.value = (*value).to_owned();
        }
    }
}

fn merge_host_scan(
    target: &mut AnyConnectHostScan,
    source: &AnyConnectHostScan,
) {
    if !source.ticket.is_empty() {
        target.ticket.clone_from(&source.ticket);
    }
    if !source.token.is_empty() {
        target.token.clone_from(&source.token);
    }
    if !source.base_url.is_empty() {
        target.base_url.clone_from(&source.base_url);
    }
    if !source.wait_url.is_empty() {
        target.wait_url.clone_from(&source.wait_url);
    }
    if !source.stub_url.is_empty() {
        target.stub_url.clone_from(&source.stub_url);
    }
}

fn host_scan_requested(scan: &AnyConnectHostScan) -> bool {
    !scan.token.is_empty()
        && !scan.ticket.is_empty()
        && !scan.base_url.is_empty()
        && !scan.wait_url.is_empty()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        io,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use http::{HeaderMap, HeaderValue, Request, StatusCode, header::LOCATION};
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder},
    };

    use super::*;
    use crate::protocol::openconnect::{
        AnyConnectAuthHttpTransport, AnyConnectAuthRawHttpResponse,
        AnyConnectMcaPrivateKey, OpenConnectBrowserCookie,
        OpenConnectBrowserResult,
    };

    #[derive(Default)]
    struct ScriptedTransport {
        responses: Mutex<VecDeque<AnyConnectAuthRawHttpResponse>>,
        requests: Mutex<Vec<Request<Vec<u8>>>>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<AnyConnectAuthRawHttpResponse>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl AnyConnectAuthHttpTransport for ScriptedTransport {
        async fn execute(
            &self,
            request: Request<Vec<u8>>,
        ) -> io::Result<AnyConnectAuthRawHttpResponse> {
            self.requests.lock().unwrap().push(request);
            self.responses.lock().unwrap().pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "script exhausted")
            })
        }
    }

    fn response(
        status: StatusCode,
        body: &str,
    ) -> AnyConnectAuthRawHttpResponse {
        AnyConnectAuthRawHttpResponse {
            status,
            headers: HeaderMap::new(),
            body: body.as_bytes().to_vec(),
            authenticated_address: None,
            peer_certificate_der: None,
        }
    }

    fn options() -> AnyConnectAuthenticatorOptions {
        AnyConnectAuthenticatorOptions {
            identity: AnyConnectAuthClientIdentity {
                version: "5.1".into(),
                reported_os: "linux-64".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn mca_identity() -> AnyConnectMcaIdentity {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "MCA driver test").unwrap();
        let name = name.build();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        let serial = serial.to_asn1_integer().unwrap();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_serial_number(&serial).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        AnyConnectMcaIdentity {
            certificates_der: vec![certificate.build().to_der().unwrap()],
            private_key: AnyConnectMcaPrivateKey::Pem(
                key.private_key_to_pem_pkcs8().unwrap(),
            ),
            private_key_password: None,
        }
    }

    #[tokio::test]
    async fn xmlpost_form_challenge_completes_a_session() {
        let mut initial = response(
            StatusCode::OK,
            r#"<config-auth><auth id="main"><form><input type="text" name="username"/><input type="password" name="password"/></form></auth></config-auth>"#,
        );
        initial.authenticated_address = Some("192.0.2.1".parse().unwrap());
        initial.peer_certificate_der = Some(vec![1, 2, 3]);
        let transport = ScriptedTransport::new(vec![
            initial,
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>vpn-cookie</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator = AnyConnectAuthenticator::new(
            http,
            "https://vpn.example/",
            options(),
        )
        .unwrap();

        let AnyConnectAuthenticationProgress::Challenge(challenge) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected form challenge");
        };
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            panic!("expected form challenge");
        };
        let values = prompt
            .fields
            .iter()
            .map(|field| {
                (
                    field.submission_key.clone(),
                    if field.name == "username" {
                        "alice"
                    } else {
                        "secret"
                    }
                    .into(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let AnyConnectAuthenticationProgress::Complete(session) = authenticator
            .respond(&challenge.id, OpenConnectAuthResponse::Form(values))
            .await
            .unwrap()
        else {
            panic!("expected completed session");
        };
        assert_eq!(session.webvpn_cookie, "vpn-cookie");
        assert_eq!(
            session.authenticated_address,
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(session.peer_certificate_der, Some(vec![1, 2, 3]));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].headers()["x-aggregate-auth"], "1");
        let reply = String::from_utf8_lossy(requests[1].body());
        assert!(reply.contains("<username>alice</username>"));
        assert!(reply.contains("<password>secret</password>"));
    }

    #[tokio::test]
    async fn multiple_certificate_request_is_signed_and_continues() {
        let transport = ScriptedTransport::new(vec![
            response(
                StatusCode::OK,
                r#"<config-auth><opaque id="9"><state>keep</state></opaque><cert-authenticated/><multiple-client-cert-request><hash-algorithm>sha256</hash-algorithm><hash-algorithm>sha512</hash-algorithm></multiple-client-cert-request></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>mca-session</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let mut config = options();
        config.identity.multiple_certificate_authentication = true;
        config.mca_identity = Some(mca_identity());
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator =
            AnyConnectAuthenticator::new(http, "https://vpn.example/", config)
                .unwrap();

        let AnyConnectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("MCA should continue directly to a completed session");
        };
        assert_eq!(session.webvpn_cookie, "mca-session");
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let mca = String::from_utf8_lossy(requests[1].body());
        assert!(mca.contains("hash-algorithm-chosen=\"sha512\""));
        assert!(mca.contains("cert-format=\"pkcs7\""));
        assert!(mca.contains("<opaque id=\"9\"><state>keep</state></opaque>"));
    }

    #[tokio::test]
    async fn built_in_host_scan_submits_polls_and_refreshes_authentication() {
        let transport = ScriptedTransport::new(vec![
            response(
                StatusCode::OK,
                r#"<config-auth><host-scan><host-scan-ticket>ticket-1</host-scan-ticket><host-scan-token>auth-token</host-scan-token><host-scan-base-uri>/+CSCOE+/sdesktop/</host-scan-base-uri><host-scan-wait-uri>/+CSCOE+/sdesktop/wait.html</host-scan-wait-uri></host-scan><auth id="main"><form><input type="text" name="username"/></form></auth></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<hostscan><token>scan-token</token></hostscan>"#,
            ),
            response(StatusCode::NO_CONTENT, ""),
            response(StatusCode::OK, "accepted"),
            response(
                StatusCode::OK,
                r#"<html><meta http-equiv="refresh" content="1"></html>"#,
            ),
            response(StatusCode::OK, "<?xml version=\"1.0\"?><done/>"),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>hostscan-session</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let mut config = options();
        config.host_scan.local_hostname = "host-a".into();
        config.host_scan.poll_interval = std::time::Duration::ZERO;
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator = AnyConnectAuthenticator::new(
            http,
            "https://vpn.example/auth",
            config,
        )
        .unwrap();

        let AnyConnectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("host scan should refresh into a complete session");
        };
        assert_eq!(session.webvpn_cookie, "hostscan-session");
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 7);
        assert_eq!(
            requests[1].uri(),
            "https://vpn.example/+CSCOE+/sdesktop/token.xml?ticket=ticket-1&stub=0"
        );
        assert!(!requests[1].headers().contains_key("x-transcend-version"));
        assert_eq!(
            requests[3].uri(),
            "https://vpn.example/+CSCOE+/sdesktop/scan.xml?reusebrowser=1"
        );
        assert!(
            String::from_utf8_lossy(requests[3].body())
                .contains("endpoint.device.hostname=\"host-a\";")
        );
        assert_eq!(requests[3].headers()["cookie"], "sdesktop=scan-token");
        assert_eq!(requests[4].headers()["cookie"], "sdesktop=auth-token");
        assert_eq!(requests[6].headers()["cookie"], "sdesktop=auth-token");
        assert_eq!(requests[6].headers()["x-aggregate-auth"], "1");
    }

    #[tokio::test]
    async fn xmlpost_probe_falls_back_to_legacy_and_prefills() {
        let mut redirect = response(StatusCode::FOUND, "");
        redirect
            .headers
            .insert(LOCATION, HeaderValue::from_static("/"));
        let transport = ScriptedTransport::new(vec![
            redirect,
            response(
                StatusCode::OK,
                r#"<auth id="main"><form action="/login"><input type="text" name="username"/><input type="password" name="password"/></form></auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>legacy-cookie</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let mut config = options();
        config.prefill.credentials.username = Some("alice".into());
        config.prefill.credentials.password = Some("p a+s".into());
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator =
            AnyConnectAuthenticator::new(http, "https://vpn.example/", config)
                .unwrap();

        let AnyConnectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("automatic legacy authentication should complete");
        };
        assert_eq!(session.webvpn_cookie, "legacy-cookie");
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].method(), Method::GET);
        assert_eq!(requests[2].uri(), "https://vpn.example/login");
        assert_eq!(requests[2].body(), b"username=alice&password=p%20a%2bs");
        assert!(!requests[2].headers().contains_key("x-aggregate-auth"));
    }

    #[tokio::test]
    async fn group_change_restarts_xmlpost_with_group_select() {
        let transport = ScriptedTransport::new(vec![
            response(
                StatusCode::OK,
                r#"<config-auth><auth id="main"><form><select name="group_list"><option value="staff" selected="true">Staff</option><option value="admin">Admin</option></select></form></auth></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>admin-cookie</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator = AnyConnectAuthenticator::new(
            http,
            "https://vpn.example/",
            options(),
        )
        .unwrap();
        let AnyConnectAuthenticationProgress::Challenge(challenge) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected group challenge");
        };
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            panic!("expected form");
        };
        let values = BTreeMap::from([(
            prompt.fields[0].submission_key.clone(),
            "admin".into(),
        )]);
        let AnyConnectAuthenticationProgress::Complete(session) = authenticator
            .respond(&challenge.id, OpenConnectAuthResponse::Form(values))
            .await
            .unwrap()
        else {
            panic!("expected completion after group restart");
        };
        assert_eq!(session.webvpn_cookie, "admin-cookie");
        let requests = transport.requests.lock().unwrap();
        let second_init = String::from_utf8_lossy(requests[1].body());
        assert!(second_init.contains("<group-select>admin</group-select>"));
    }

    #[tokio::test]
    async fn sso_cookie_challenge_is_applied_to_the_reply() {
        let transport = ScriptedTransport::new(vec![
            response(
                StatusCode::OK,
                r#"<config-auth><auth id="main"><sso-v2-login>/sso</sso-v2-login><sso-v2-login-final>/done</sso-v2-login-final><sso-v2-token-cookie-name>sso-token</sso-v2-token-cookie-name><sso-v2-error-cookie-name>sso-error</sso-v2-error-cookie-name><form><input type="sso" name="sso_token"/></form></auth></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>sso-session</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator = AnyConnectAuthenticator::new(
            http,
            "https://vpn.example/",
            options(),
        )
        .unwrap();
        let AnyConnectAuthenticationProgress::Challenge(challenge) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected browser challenge");
        };
        let OpenConnectAuthChallengeKind::Browser(browser) = &challenge.kind
        else {
            panic!("expected browser challenge");
        };
        assert_eq!(browser.url, "https://vpn.example/sso");
        assert_eq!(browser.final_url, "https://vpn.example/done");
        let result = OpenConnectBrowserResult {
            final_url: browser.final_url.clone(),
            cookies: vec![OpenConnectBrowserCookie {
                name: "sso-token".into(),
                value: "browser-secret".into(),
            }],
            ..Default::default()
        };
        let AnyConnectAuthenticationProgress::Complete(session) = authenticator
            .respond(&challenge.id, OpenConnectAuthResponse::Browser(result))
            .await
            .unwrap()
        else {
            panic!("expected SSO completion");
        };
        assert_eq!(session.webvpn_cookie, "sso-session");
        let requests = transport.requests.lock().unwrap();
        let reply = String::from_utf8_lossy(requests[1].body());
        assert!(reply.contains("<sso_token>browser-secret</sso_token>"));
    }

    #[tokio::test]
    async fn ocserv_oath_successor_uses_generated_token() {
        let transport = ScriptedTransport::new(vec![
            response(
                StatusCode::OK,
                r#"<config-auth><auth id="main"><form><input type="password" name="password"/></form></auth></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><auth id="main"><message>Enter OTP password</message><form><input type="password" name="password"/></form></auth></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>oath-session</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let mut config = options();
        config.prefill.credentials.password = Some("stable-password".into());
        config.prefill.token_type = Some("totp".into());
        config.prefill.generated_token = Some("123456".into());
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator =
            AnyConnectAuthenticator::new(http, "https://vpn.example/", config)
                .unwrap();

        let AnyConnectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("OATH continuation should be automatic");
        };
        assert_eq!(session.webvpn_cookie, "oath-session");
        let requests = transport.requests.lock().unwrap();
        assert!(
            String::from_utf8_lossy(requests[1].body())
                .contains("<password>stable-password</password>")
        );
        assert!(
            String::from_utf8_lossy(requests[2].body())
                .contains("<password>123456</password>")
        );
    }

    #[tokio::test]
    async fn ocserv_oath_successor_invokes_hotp_generator() {
        let transport = ScriptedTransport::new(vec![
            response(
                StatusCode::OK,
                r#"<config-auth><auth id="main"><form><input type="password" name="password"/></form></auth></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><auth id="main"><message>Enter OTP password</message><form><input type="password" name="password"/></form></auth></config-auth>"#,
            ),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>oath-session</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let mut config = options();
        config.prefill.credentials.password = Some("stable-password".into());
        let factory =
            crate::protocol::openconnect::OpenConnectOathTokenFactory::new(
                "hotp",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                0,
            )
            .unwrap();
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator =
            AnyConnectAuthenticator::new(http, "https://vpn.example/", config)
                .unwrap();
        authenticator
            .set_software_token_generator(Box::new(factory.generator()));

        let AnyConnectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("OATH continuation should be automatic");
        };
        assert_eq!(session.webvpn_cookie, "oath-session");
        assert_eq!(factory.current_counter(), 1);
        let requests = transport.requests.lock().unwrap();
        assert!(
            String::from_utf8_lossy(requests[2].body())
                .contains("<password>755224</password>")
        );
    }

    #[tokio::test]
    async fn client_certificate_request_retries_then_sends_failure_marker() {
        let certificate_request =
            r#"<config-auth><client-cert-request/></config-auth>"#;
        let transport = ScriptedTransport::new(vec![
            response(StatusCode::OK, certificate_request),
            response(StatusCode::OK, certificate_request),
            response(
                StatusCode::OK,
                r#"<config-auth><session-token>certificate-session</session-token><auth id="success"/></config-auth>"#,
            ),
        ]);
        let mut config = options();
        config.client_certificate_configured = true;
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator =
            AnyConnectAuthenticator::new(http, "https://vpn.example/", config)
                .unwrap();

        let AnyConnectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!(
                "client-certificate failure marker should continue authentication"
            );
        };
        assert_eq!(session.webvpn_cookie, "certificate-session");
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(
            !String::from_utf8_lossy(requests[1].body())
                .contains("client-cert-fail")
        );
        assert!(
            String::from_utf8_lossy(requests[2].body())
                .contains("<client-cert-fail></client-cert-fail>")
        );
    }

    #[tokio::test]
    async fn direct_cookie_completes_without_network_io() {
        let transport = ScriptedTransport::new(Vec::new());
        let mut config = options();
        config.direct_cookie = Some("webvpn=direct; other=value".into());
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "agent");
        let mut authenticator =
            AnyConnectAuthenticator::new(http, "https://vpn.example/", config)
                .unwrap();
        let AnyConnectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected direct completion");
        };
        assert_eq!(session.webvpn_cookie, "direct");
        assert!(transport.requests.lock().unwrap().is_empty());
        assert!(matches!(
            authenticator.begin().await,
            Err(AnyConnectAuthenticatorError::AlreadyComplete)
        ));
    }
}
