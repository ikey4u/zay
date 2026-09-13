//! Stateful GlobalProtect portal/gateway authentication driver.

use std::{mem, net::IpAddr, time::Duration};

use http::{Method, StatusCode};
use thiserror::Error;
use url::Url;

use super::{
    AnyConnectAuthError, AnyConnectAuthHttpClient, AnyConnectAuthHttpError,
    AnyConnectAuthHttpRequest, AnyConnectAuthHttpResponse,
    AnyConnectSoftwareTokenGenerator, GLOBALPROTECT_AUTHENTICATION_FORM_ID,
    GLOBALPROTECT_CHALLENGE_FORM_ID, GLOBALPROTECT_DEFAULT_CLIENT_VERSION,
    GLOBALPROTECT_MAXIMUM_AUTHENTICATION_BODY,
    GLOBALPROTECT_MAXIMUM_AUTHENTICATION_REQUESTS, GlobalProtectAuthWireError,
    GlobalProtectFailureClass, GlobalProtectFormError, GlobalProtectInterface,
    GlobalProtectLoginRequestOptions, GlobalProtectLoginResponse,
    GlobalProtectPortalConfiguration, GlobalProtectPortalGateway,
    GlobalProtectPortalResponse, OpenConnectAuthChallenge,
    OpenConnectAuthChallengeKind, OpenConnectAuthPromptChoice,
    OpenConnectAuthPromptField, OpenConnectAuthPromptForm,
    OpenConnectAuthPromptKind, OpenConnectAuthResponse,
    OpenConnectBrowserRequest, build_globalprotect_login_request,
    build_globalprotect_prelogin_request,
    classify_globalprotect_auth_http_status, decode_globalprotect_saml_url,
    new_openconnect_auth_challenge, parse_globalprotect_login_response,
    parse_globalprotect_logout_response, parse_globalprotect_portal_response,
    parse_globalprotect_prelogin_response, parse_globalprotect_server_target,
    validate_openconnect_browser_response, validate_openconnect_form_response,
};

const USERNAME_SUBMISSION_KEY: &str = "gp:user";
const SECRET_SUBMISSION_KEY: &str = "gp:secret";
const GATEWAY_SUBMISSION_KEY: &str = "gp:gateway";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalProtectAuthenticatorOptions {
    pub username: String,
    pub password: String,
    pub auth_group: String,
    pub direct_cookie: Option<String>,
    pub reported_os: String,
    pub local_hostname: String,
    pub external_auth_disabled: bool,
    pub ipv6_disabled: bool,
    pub previous_ipv4: Option<std::net::Ipv4Addr>,
    pub previous_ipv6: Option<std::net::Ipv6Addr>,
}

pub const GLOBALPROTECT_LOGOUT_PATH: &str = "/ssl-vpn/logout.esp";

/// Close an authenticated GlobalProtect session with the complete opaque
/// query returned by gateway login. Redirects are deliberately not followed.
pub async fn logout_globalprotect_session(
    http: &mut AnyConnectAuthHttpClient,
    session: &GlobalProtectAuthenticatedSession,
) -> Result<(), GlobalProtectAuthenticatorError> {
    let mut url = session.server_url.clone();
    url.set_path(GLOBALPROTECT_LOGOUT_PATH);
    url.set_query(None);
    url.set_fragment(None);
    let response = http
        .execute(AnyConnectAuthHttpRequest {
            method: Method::POST,
            url,
            content_type: Some("application/x-www-form-urlencoded".into()),
            body: session.opaque_query.as_bytes().to_vec(),
            xml_post: false,
            xml_post_probe: false,
            authentication_headers: false,
            preserve_cookie_jar_on_redirect: false,
            follow_redirects: false,
        })
        .await?;
    if response.body.len() > GLOBALPROTECT_MAXIMUM_AUTHENTICATION_BODY {
        return Err(GlobalProtectAuthenticatorError::BodyTooLarge(
            GLOBALPROTECT_MAXIMUM_AUTHENTICATION_BODY,
        ));
    }
    if response.status != StatusCode::OK {
        return Err(GlobalProtectAuthenticatorError::HttpStatus {
            status: response.status,
            class: classify_globalprotect_auth_http_status(
                response.status.as_u16(),
            ),
        });
    }
    parse_globalprotect_logout_response(&response.body)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectAuthenticatedSession {
    pub server_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
    pub opaque_query: String,
    pub hip_report_interval: Duration,
    pub client_version: String,
    pub previous_ipv4: Option<std::net::Ipv4Addr>,
    pub previous_ipv6: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalProtectAuthenticationProgress {
    Challenge(OpenConnectAuthChallenge),
    Complete(GlobalProtectAuthenticatedSession),
}

#[derive(Debug, Error)]
pub enum GlobalProtectAuthenticatorError {
    #[error(transparent)]
    Http(#[from] AnyConnectAuthHttpError),
    #[error(transparent)]
    Wire(#[from] GlobalProtectAuthWireError),
    #[error(transparent)]
    Form(#[from] super::GlobalProtectFormError),
    #[error(transparent)]
    Challenge(#[from] AnyConnectAuthError),
    #[error("GlobalProtect authentication returned HTTP {status} ({class:?})")]
    HttpStatus {
        status: StatusCode,
        class: GlobalProtectFailureClass,
    },
    #[error("GlobalProtect authentication response exceeds {0} bytes")]
    BodyTooLarge(usize),
    #[error("unsupported GlobalProtect authentication behavior: {0}")]
    Unsupported(String),
    #[error("GlobalProtect authentication challenge response is missing")]
    MissingResponse,
    #[error("GlobalProtect authentication challenge ID does not match")]
    ChallengeMismatch,
    #[error("GlobalProtect authentication response type does not match")]
    ResponseTypeMismatch,
    #[error("GlobalProtect authentication is complete")]
    AlreadyComplete,
    #[error("GlobalProtect authentication is in a terminal state")]
    TerminalState,
    #[error("GlobalProtect token generation failed: {0}")]
    Token(String),
}

#[derive(Debug, Clone)]
struct LoginForm {
    form_id: &'static str,
    message: String,
    error: String,
    username_label: String,
    username: String,
    secret_name: String,
    secret_label: String,
    secret: String,
    input_string: String,
    challenge: bool,
    token: bool,
}

#[derive(Debug, Clone)]
enum Stage {
    Prelogin,
    AwaitLogin { challenge: OpenConnectAuthChallenge },
    AwaitSaml { challenge: OpenConnectAuthChallenge },
    AwaitGateway { challenge: OpenConnectAuthChallenge },
    Complete,
    Terminal,
}

pub struct GlobalProtectAuthenticator {
    http: AnyConnectAuthHttpClient,
    options: GlobalProtectAuthenticatorOptions,
    current_url: Url,
    interface: GlobalProtectInterface,
    automatic_interface: bool,
    alternate_secret: String,
    stage: Stage,
    immediate_session: Option<GlobalProtectAuthenticatedSession>,
    form: Option<LoginForm>,
    region: String,
    username: String,
    portal_user_auth_cookie: String,
    portal_prelogon_user_auth_cookie: String,
    hip_report_interval: Duration,
    client_version: String,
    gateways: Vec<GlobalProtectPortalGateway>,
    blind_gateway_login: bool,
    authenticated_address: Option<IpAddr>,
    peer_certificate_der: Option<Vec<u8>>,
    token_generator: Option<Box<dyn AnyConnectSoftwareTokenGenerator>>,
}

impl GlobalProtectAuthenticator {
    pub fn new(
        mut http: AnyConnectAuthHttpClient,
        server: &str,
        mut options: GlobalProtectAuthenticatorOptions,
    ) -> Result<Self, GlobalProtectAuthenticatorError> {
        let target = parse_globalprotect_server_target(server)?;
        if options.reported_os.is_empty() {
            options.reported_os = "linux-64".into();
        }
        if !matches!(
            options.reported_os.as_str(),
            "linux"
                | "linux-64"
                | "win"
                | "mac-intel"
                | "android"
                | "apple-ios"
        ) {
            return Err(GlobalProtectAuthenticatorError::Unsupported(format!(
                "reported OS: {}",
                options.reported_os
            )));
        }
        let immediate_session = options.direct_cookie.as_ref().map(|cookie| {
            GlobalProtectAuthenticatedSession {
                server_url: target.url.clone(),
                authenticated_address: None,
                peer_certificate_der: None,
                opaque_query: cookie.clone(),
                hip_report_interval: Duration::ZERO,
                client_version: GLOBALPROTECT_DEFAULT_CLIENT_VERSION.into(),
                previous_ipv4: options.previous_ipv4,
                previous_ipv6: options.previous_ipv6,
            }
        });
        if immediate_session.is_none() {
            http.clear_cookies();
        }
        http.set_maximum_wire_requests(Some(
            GLOBALPROTECT_MAXIMUM_AUTHENTICATION_REQUESTS,
        ));
        Ok(Self {
            http,
            options,
            current_url: target.url,
            interface: target.interface,
            automatic_interface: target.automatic_interface,
            alternate_secret: target.alternate_secret,
            stage: if immediate_session.is_some() {
                Stage::Complete
            } else {
                Stage::Prelogin
            },
            immediate_session,
            form: None,
            region: String::new(),
            username: String::new(),
            portal_user_auth_cookie: String::new(),
            portal_prelogon_user_auth_cookie: String::new(),
            hip_report_interval: Duration::ZERO,
            client_version: String::new(),
            gateways: Vec::new(),
            blind_gateway_login: false,
            authenticated_address: None,
            peer_certificate_der: None,
            token_generator: None,
        })
    }

    pub fn set_software_token_generator(
        &mut self,
        generator: Box<dyn AnyConnectSoftwareTokenGenerator>,
    ) {
        self.token_generator = Some(generator);
    }

    pub fn pending_challenge(&self) -> Option<&OpenConnectAuthChallenge> {
        match &self.stage {
            Stage::AwaitLogin { challenge }
            | Stage::AwaitSaml { challenge }
            | Stage::AwaitGateway { challenge } => Some(challenge),
            _ => None,
        }
    }

    pub async fn begin(
        &mut self,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        if let Some(session) = self.immediate_session.take() {
            return Ok(GlobalProtectAuthenticationProgress::Complete(session));
        }
        if self.pending_challenge().is_some() {
            return Err(GlobalProtectAuthenticatorError::MissingResponse);
        }
        self.drive(None).await
    }

    pub async fn respond(
        &mut self,
        challenge_id: &str,
        response: OpenConnectAuthResponse,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        let pending = self
            .pending_challenge()
            .ok_or(GlobalProtectAuthenticatorError::MissingResponse)?;
        if pending.id != challenge_id {
            return Err(GlobalProtectAuthenticatorError::ChallengeMismatch);
        }
        self.drive(Some(response)).await
    }

    async fn drive(
        &mut self,
        response: Option<OpenConnectAuthResponse>,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        let stage = mem::replace(&mut self.stage, Stage::Terminal);
        let result = match stage {
            Stage::Prelogin if response.is_none() => self.prelogin().await,
            Stage::AwaitLogin { challenge } => {
                self.apply_login_response(&challenge, response)?;
                self.submit_login().await
            }
            Stage::AwaitSaml { challenge } => {
                self.apply_saml_response(&challenge, response)?;
                self.submit_login().await
            }
            Stage::AwaitGateway { challenge } => {
                self.apply_gateway_response(&challenge, response).await
            }
            Stage::Complete => {
                Err(GlobalProtectAuthenticatorError::AlreadyComplete)
            }
            Stage::Terminal => {
                Err(GlobalProtectAuthenticatorError::TerminalState)
            }
            Stage::Prelogin => {
                Err(GlobalProtectAuthenticatorError::ResponseTypeMismatch)
            }
        };
        if result.is_err() && matches!(self.stage, Stage::Terminal) {
            self.stage = Stage::Terminal;
        }
        result
    }

    async fn prelogin(
        &mut self,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        loop {
            let request = build_globalprotect_prelogin_request(
                &self.current_url,
                self.interface,
                &self.options.reported_os,
                self.options.external_auth_disabled,
            );
            let response =
                self.request(request.url, request.body, true).await?;
            if response.status == StatusCode::NOT_FOUND
                && self.automatic_interface
                && self.interface == GlobalProtectInterface::Portal
            {
                self.interface = GlobalProtectInterface::Gateway;
                continue;
            }
            self.require_success(&response)?;
            self.record_response(&response);
            let prelogin =
                match parse_globalprotect_prelogin_response(&response.body) {
                    Err(GlobalProtectFormError::Response {
                        message, ..
                    }) if self.automatic_interface
                        && self.interface == GlobalProtectInterface::Portal
                        && matches!(
                            message.as_str(),
                            "GlobalProtect gateway does not exist"
                                | "GlobalProtect portal does not exist"
                        ) =>
                    {
                        self.interface = GlobalProtectInterface::Gateway;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(prelogin) => prelogin,
                };
            self.region.clone_from(&prelogin.region);
            let message = if prelogin.message.is_empty() {
                "Please enter your username and password".into()
            } else {
                prelogin.message
            };
            let username_label = if prelogin.username_label.is_empty() {
                "Username".into()
            } else {
                prelogin.username_label
            };
            let secret_name = if self.alternate_secret.is_empty() {
                "passwd".into()
            } else {
                self.alternate_secret.clone()
            };
            let secret_label = if prelogin.password_label.is_empty() {
                "Password".into()
            } else {
                prelogin.password_label.clone()
            };
            let token = self.alternate_secret.is_empty()
                && !prelogin.password_label.is_empty()
                && prelogin.password_label != "Password"
                && self
                    .token_generator
                    .as_ref()
                    .is_some_and(|generator| generator.can_generate(&message));
            self.form = Some(LoginForm {
                form_id: GLOBALPROTECT_AUTHENTICATION_FORM_ID,
                message,
                error: String::new(),
                username_label,
                username: self.username.clone(),
                secret_name,
                secret_label,
                secret: String::new(),
                input_string: String::new(),
                challenge: false,
                token,
            });
            if !prelogin.saml_method.is_empty()
                || !prelogin.saml_request.is_empty()
            {
                if self.options.external_auth_disabled {
                    return Err(GlobalProtectAuthenticatorError::Unsupported(
                        "gateway requested disabled external authentication"
                            .into(),
                    ));
                }
                if prelogin.saml_method.is_empty()
                    || prelogin.saml_request.is_empty()
                {
                    return Err(GlobalProtectAuthenticatorError::Unsupported(
                        "prelogin returned incomplete SAML parameters".into(),
                    ));
                }
                if self.alternate_secret.is_empty() {
                    let challenge = new_openconnect_auth_challenge(
                        "",
                        self.form.as_ref().expect("set above").message.clone(),
                        "",
                        OpenConnectAuthChallengeKind::Browser(
                            OpenConnectBrowserRequest {
                                url: decode_globalprotect_saml_url(
                                    &prelogin.saml_method,
                                    &prelogin.saml_request,
                                )?,
                                header_names: vec![
                                    "saml-username".into(),
                                    "prelogin-cookie".into(),
                                    "portal-userauthcookie".into(),
                                ],
                                ..Default::default()
                            },
                        ),
                    );
                    self.stage = Stage::AwaitSaml {
                        challenge: challenge.clone(),
                    };
                    return Ok(GlobalProtectAuthenticationProgress::Challenge(
                        challenge,
                    ));
                }
            }
            return self.prompt_or_submit_login().await;
        }
    }

    async fn prompt_or_submit_login(
        &mut self,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        let form = self.form.as_mut().expect("login form exists");
        if form.username.is_empty() {
            form.username.clone_from(&self.options.username);
        }
        if form.secret.is_empty() {
            if form.token {
                form.secret = self
                    .token_generator
                    .as_mut()
                    .ok_or_else(|| {
                        GlobalProtectAuthenticatorError::Token(
                            "generator is missing".into(),
                        )
                    })?
                    .generate(&form.message)
                    .map_err(|error| {
                        GlobalProtectAuthenticatorError::Token(
                            error.to_string(),
                        )
                    })?;
            } else if !form.challenge {
                form.secret.clone_from(&self.options.password);
            }
        }
        if !form.username.is_empty() && !form.secret.is_empty() {
            return Box::pin(self.submit_login()).await;
        }
        let challenge = self.login_challenge();
        self.stage = Stage::AwaitLogin {
            challenge: challenge.clone(),
        };
        Ok(GlobalProtectAuthenticationProgress::Challenge(challenge))
    }

    fn login_challenge(&self) -> OpenConnectAuthChallenge {
        let form = self.form.as_ref().expect("login form exists");
        let mut fields = Vec::new();
        if form.username.is_empty() {
            fields.push(OpenConnectAuthPromptField {
                submission_key: USERNAME_SUBMISSION_KEY.into(),
                name: "user".into(),
                label: form.username_label.clone(),
                kind: OpenConnectAuthPromptKind::Text,
                value: String::new(),
                options: Vec::new(),
            });
        }
        fields.push(OpenConnectAuthPromptField {
            submission_key: SECRET_SUBMISSION_KEY.into(),
            name: form.secret_name.clone(),
            label: form.secret_label.clone(),
            kind: OpenConnectAuthPromptKind::Password,
            value: String::new(),
            options: Vec::new(),
        });
        new_openconnect_auth_challenge(
            "",
            form.message.clone(),
            form.error.clone(),
            OpenConnectAuthChallengeKind::Form(OpenConnectAuthPromptForm {
                fields,
            }),
        )
    }

    fn apply_login_response(
        &mut self,
        challenge: &OpenConnectAuthChallenge,
        response: Option<OpenConnectAuthResponse>,
    ) -> Result<(), GlobalProtectAuthenticatorError> {
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            return Err(GlobalProtectAuthenticatorError::ResponseTypeMismatch);
        };
        let Some(OpenConnectAuthResponse::Form(values)) = response else {
            return Err(GlobalProtectAuthenticatorError::ResponseTypeMismatch);
        };
        validate_openconnect_form_response(&prompt.fields, &values)?;
        let form = self.form.as_mut().expect("login form exists");
        if let Some(username) = values.get(USERNAME_SUBMISSION_KEY) {
            form.username.clone_from(username);
        }
        form.secret = values
            .get(SECRET_SUBMISSION_KEY)
            .cloned()
            .ok_or(GlobalProtectAuthenticatorError::MissingResponse)?;
        Ok(())
    }

    fn apply_saml_response(
        &mut self,
        challenge: &OpenConnectAuthChallenge,
        response: Option<OpenConnectAuthResponse>,
    ) -> Result<(), GlobalProtectAuthenticatorError> {
        let OpenConnectAuthChallengeKind::Browser(request) = &challenge.kind
        else {
            return Err(GlobalProtectAuthenticatorError::ResponseTypeMismatch);
        };
        let Some(OpenConnectAuthResponse::Browser(result)) = response else {
            return Err(GlobalProtectAuthenticatorError::ResponseTypeMismatch);
        };
        validate_openconnect_browser_response(request, &result)?;
        let header = |name: &str| {
            result
                .headers
                .iter()
                .find_map(|(key, value)| {
                    key.as_str()
                        .eq_ignore_ascii_case(name)
                        .then(|| value.to_str().ok())
                        .flatten()
                })
                .unwrap_or_default()
                .to_owned()
        };
        let username = header("saml-username");
        let prelogin = header("prelogin-cookie");
        let portal = header("portal-userauthcookie");
        let (secret_name, secret) = if prelogin.is_empty() {
            ("portal-userauthcookie", portal)
        } else {
            ("prelogin-cookie", prelogin)
        };
        if username.is_empty() || secret.is_empty() {
            return Err(GlobalProtectAuthenticatorError::Unsupported(
                "SAML result omitted username or authentication cookie".into(),
            ));
        }
        let form = self.form.as_mut().expect("login form exists");
        form.username = username;
        form.secret_name = secret_name.into();
        form.secret = secret;
        Ok(())
    }

    async fn submit_login(
        &mut self,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        let form = self.form.as_ref().expect("login form exists");
        let (url, body) = build_globalprotect_login_request(
            &GlobalProtectLoginRequestOptions {
                interface: self.interface,
                server_url: self.current_url.clone(),
                reported_os: self.options.reported_os.clone(),
                local_hostname: self.options.local_hostname.clone(),
                ipv6_disabled: self.options.ipv6_disabled,
                portal_user_auth_cookie: self.portal_user_auth_cookie.clone(),
                portal_prelogon_user_auth_cookie: self
                    .portal_prelogon_user_auth_cookie
                    .clone(),
                previous_ipv4: self.options.previous_ipv4,
                previous_ipv6: self.options.previous_ipv6,
                input_string: form.input_string.clone(),
                username: form.username.clone(),
                secret_name: form.secret_name.clone(),
                secret: form.secret.clone(),
            },
        );
        let response = self.request(url, body, false).await?;
        if response.status.as_u16() == 512 {
            self.options.password.clear();
            let form = self.form.as_mut().expect("login form exists");
            form.secret.clear();
            form.error =
                String::from_utf8_lossy(&response.body).trim().to_owned();
            if form.error.is_empty() {
                form.error = "Invalid username or password".into();
            }
            return self.prompt_or_submit_login().await;
        }
        self.require_success(&response)?;
        self.record_response(&response);
        match self.interface {
            GlobalProtectInterface::Portal => {
                self.process_portal(response.body).await
            }
            GlobalProtectInterface::Gateway => {
                self.process_gateway(response.body).await
            }
        }
    }

    async fn process_portal(
        &mut self,
        body: Vec<u8>,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        match parse_globalprotect_portal_response(&body, &self.region)? {
            GlobalProtectPortalResponse::Challenge(challenge) => {
                self.apply_protocol_challenge(challenge);
                self.prompt_or_submit_login().await
            }
            GlobalProtectPortalResponse::Configuration(configuration) => {
                self.install_portal_configuration(configuration);
                self.select_configured_gateway().await
            }
        }
    }

    fn install_portal_configuration(
        &mut self,
        configuration: GlobalProtectPortalConfiguration,
    ) {
        let form = self.form.as_ref().expect("login form exists");
        self.username.clone_from(&form.username);
        self.portal_user_auth_cookie = configuration.portal_user_auth_cookie;
        self.portal_prelogon_user_auth_cookie =
            configuration.portal_prelogon_user_auth_cookie;
        self.hip_report_interval = configuration.hip_report_interval;
        self.client_version = configuration.client_version;
        self.gateways = configuration.gateways;
        self.blind_gateway_login = !self.portal_user_auth_cookie.is_empty()
            || !self.portal_prelogon_user_auth_cookie.is_empty()
            || (!form.challenge && self.alternate_secret.is_empty());
    }

    async fn process_gateway(
        &mut self,
        body: Vec<u8>,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        match parse_globalprotect_login_response(
            &body,
            &self.options.local_hostname,
        )? {
            GlobalProtectLoginResponse::Challenge(challenge) => {
                self.apply_protocol_challenge(challenge);
                self.prompt_or_submit_login().await
            }
            GlobalProtectLoginResponse::OpaqueQuery(opaque_query) => {
                self.stage = Stage::Complete;
                let client_version = if self.client_version.is_empty() {
                    GLOBALPROTECT_DEFAULT_CLIENT_VERSION.into()
                } else {
                    self.client_version.clone()
                };
                Ok(GlobalProtectAuthenticationProgress::Complete(
                    GlobalProtectAuthenticatedSession {
                        server_url: self.current_url.clone(),
                        authenticated_address: self.authenticated_address,
                        peer_certificate_der: self.peer_certificate_der.clone(),
                        opaque_query,
                        hip_report_interval: self.hip_report_interval,
                        client_version,
                        previous_ipv4: self.options.previous_ipv4,
                        previous_ipv6: self.options.previous_ipv6,
                    },
                ))
            }
        }
    }

    fn apply_protocol_challenge(
        &mut self,
        challenge: super::GlobalProtectChallenge,
    ) {
        let form = self.form.as_mut().expect("login form exists");
        form.form_id = GLOBALPROTECT_CHALLENGE_FORM_ID;
        form.message = challenge.message;
        form.error.clear();
        form.secret_label = "Challenge:".into();
        form.secret.clear();
        form.input_string = challenge.input_string;
        form.challenge = true;
        form.token = self
            .token_generator
            .as_ref()
            .is_some_and(|generator| generator.can_generate(&form.message));
    }

    async fn select_configured_gateway(
        &mut self,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        if self.gateways.len() == 1 {
            return self.select_gateway(0).await;
        }
        if !self.options.auth_group.is_empty()
            && let Some(index) = self.gateways.iter().position(|gateway| {
                self.options.auth_group == gateway.name
                    || self.options.auth_group == gateway.label
                    || self.options.auth_group == gateway.form_value
            })
        {
            return self.select_gateway(index).await;
        }
        let challenge = new_openconnect_auth_challenge(
            "",
            "Please select GlobalProtect gateway.",
            "",
            OpenConnectAuthChallengeKind::Form(OpenConnectAuthPromptForm {
                fields: vec![OpenConnectAuthPromptField {
                    submission_key: GATEWAY_SUBMISSION_KEY.into(),
                    name: "gateway".into(),
                    label: "GATEWAY:".into(),
                    kind: OpenConnectAuthPromptKind::Select,
                    value: self.gateways[0].form_value.clone(),
                    options: self
                        .gateways
                        .iter()
                        .map(|gateway| OpenConnectAuthPromptChoice {
                            value: gateway.form_value.clone(),
                            label: gateway.label.clone(),
                        })
                        .collect(),
                }],
            }),
        );
        self.stage = Stage::AwaitGateway {
            challenge: challenge.clone(),
        };
        Ok(GlobalProtectAuthenticationProgress::Challenge(challenge))
    }

    async fn apply_gateway_response(
        &mut self,
        challenge: &OpenConnectAuthChallenge,
        response: Option<OpenConnectAuthResponse>,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            return Err(GlobalProtectAuthenticatorError::ResponseTypeMismatch);
        };
        let Some(OpenConnectAuthResponse::Form(values)) = response else {
            return Err(GlobalProtectAuthenticatorError::ResponseTypeMismatch);
        };
        validate_openconnect_form_response(&prompt.fields, &values)?;
        let selected = values
            .get(GATEWAY_SUBMISSION_KEY)
            .ok_or(GlobalProtectAuthenticatorError::MissingResponse)?;
        let index = self
            .gateways
            .iter()
            .position(|gateway| gateway.form_value == *selected)
            .ok_or_else(|| {
                GlobalProtectAuthenticatorError::Unsupported(
                    "gateway selection is unknown".into(),
                )
            })?;
        self.select_gateway(index).await
    }

    async fn select_gateway(
        &mut self,
        index: usize,
    ) -> Result<
        GlobalProtectAuthenticationProgress,
        GlobalProtectAuthenticatorError,
    > {
        let gateway = &self.gateways[index];
        let url = Url::parse(&format!("https://{}", gateway.name)).map_err(
            |error| {
                GlobalProtectAuthenticatorError::Unsupported(format!(
                    "invalid portal gateway: {error}"
                ))
            },
        )?;
        if url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(GlobalProtectAuthenticatorError::Unsupported(
                "portal gateway contains path, query, or fragment".into(),
            ));
        }
        if endpoint(&self.current_url) != endpoint(&url) {
            self.http.clear_cookies();
            self.authenticated_address = None;
            self.peer_certificate_der = None;
        }
        self.current_url = url;
        self.interface = GlobalProtectInterface::Gateway;
        if self.blind_gateway_login {
            Box::pin(self.submit_login()).await
        } else {
            self.stage = Stage::Prelogin;
            self.prelogin().await
        }
    }

    async fn request(
        &mut self,
        url: Url,
        body: Vec<u8>,
        follow_redirects: bool,
    ) -> Result<AnyConnectAuthHttpResponse, GlobalProtectAuthenticatorError>
    {
        let response = self
            .http
            .execute(AnyConnectAuthHttpRequest {
                method: Method::POST,
                url,
                content_type: Some("application/x-www-form-urlencoded".into()),
                body,
                xml_post: false,
                xml_post_probe: false,
                authentication_headers: false,
                preserve_cookie_jar_on_redirect: false,
                follow_redirects,
            })
            .await?;
        if response.body.len() > GLOBALPROTECT_MAXIMUM_AUTHENTICATION_BODY {
            return Err(GlobalProtectAuthenticatorError::BodyTooLarge(
                GLOBALPROTECT_MAXIMUM_AUTHENTICATION_BODY,
            ));
        }
        Ok(response)
    }

    fn record_response(&mut self, response: &AnyConnectAuthHttpResponse) {
        if endpoint(&self.current_url) != endpoint(&response.final_url) {
            self.authenticated_address = None;
            self.peer_certificate_der = None;
            self.current_url
                .set_scheme(response.final_url.scheme())
                .expect("HTTPS scheme");
            self.current_url
                .set_host(response.final_url.host_str())
                .expect("validated URL");
            let _ = self.current_url.set_port(response.final_url.port());
        }
        if response.authenticated_address.is_some() {
            self.authenticated_address = response.authenticated_address;
        }
        if response.peer_certificate_der.is_some() {
            self.peer_certificate_der
                .clone_from(&response.peer_certificate_der);
        }
    }

    fn require_success(
        &self,
        response: &AnyConnectAuthHttpResponse,
    ) -> Result<(), GlobalProtectAuthenticatorError> {
        if response.status == StatusCode::OK {
            Ok(())
        } else {
            Err(GlobalProtectAuthenticatorError::HttpStatus {
                status: response.status,
                class: classify_globalprotect_auth_http_status(
                    response.status.as_u16(),
                ),
            })
        }
    }
}

fn endpoint(url: &Url) -> (&str, Option<&str>, Option<u16>) {
    (url.scheme(), url.host_str(), url.port_or_known_default())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use http::{HeaderMap, HeaderValue, Request};

    use super::*;
    use crate::protocol::openconnect::{
        AnyConnectAuthHttpTransport, AnyConnectAuthRawHttpResponse,
        GLOBALPROTECT_USER_AGENT,
    };

    struct FakeTransport {
        responses: Mutex<Vec<AnyConnectAuthRawHttpResponse>>,
        requests: Mutex<Vec<Request<Vec<u8>>>>,
    }

    #[async_trait]
    impl AnyConnectAuthHttpTransport for FakeTransport {
        async fn execute(
            &self,
            request: Request<Vec<u8>>,
        ) -> std::io::Result<AnyConnectAuthRawHttpResponse> {
            self.requests.lock().unwrap().push(request);
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    fn response(body: impl Into<Vec<u8>>) -> AnyConnectAuthRawHttpResponse {
        AnyConnectAuthRawHttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: body.into(),
            authenticated_address: Some("192.0.2.1".parse().unwrap()),
            peer_certificate_der: Some(vec![1, 2, 3]),
        }
    }

    fn jnlp() -> Vec<u8> {
        let mut args = vec!["(null)"; 21];
        args[1] = "cookie";
        args[4] = "alice";
        args[12] = "tunnel";
        args[14] = "4100";
        format!(
            "<jnlp><application-desc>{}</application-desc></jnlp>",
            args.into_iter()
                .map(|value| format!("<argument>{value}</argument>"))
                .collect::<String>()
        )
        .into_bytes()
    }

    #[test]
    fn cross_endpoint_redirect_discards_stale_peer_identity() {
        let transport = Arc::new(FakeTransport {
            responses: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        });
        let http =
            AnyConnectAuthHttpClient::new(transport, GLOBALPROTECT_USER_AGENT);
        let mut authenticator = GlobalProtectAuthenticator::new(
            http,
            "https://vpn.example/gateway",
            GlobalProtectAuthenticatorOptions::default(),
        )
        .unwrap();
        authenticator.authenticated_address =
            Some("192.0.2.1".parse().unwrap());
        authenticator.peer_certificate_der = Some(vec![1, 2, 3]);
        authenticator.record_response(&AnyConnectAuthHttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Vec::new(),
            final_url: Url::parse("https://login.example/prelogin").unwrap(),
            authenticated_address: None,
            peer_certificate_der: None,
        });
        assert_eq!(authenticator.current_url.host_str(), Some("login.example"));
        assert!(authenticator.authenticated_address.is_none());
        assert!(authenticator.peer_certificate_der.is_none());
    }

    #[tokio::test]
    async fn logout_posts_complete_opaque_query_without_redirects() {
        let transport = Arc::new(FakeTransport {
            responses: Mutex::new(vec![response(
                br#"<response status="success"/>"#.to_vec(),
            )]),
            requests: Mutex::new(Vec::new()),
        });
        let mut http = AnyConnectAuthHttpClient::new(
            transport.clone(),
            GLOBALPROTECT_USER_AGENT,
        );
        let session = GlobalProtectAuthenticatedSession {
            server_url: Url::parse("https://vpn.example:4443/gateway")
                .unwrap(),
            authenticated_address: Some("192.0.2.1".parse().unwrap()),
            peer_certificate_der: None,
            opaque_query:
                "authcookie=secret&portal=portal&user=alice&domain=example&computer=host"
                    .into(),
            hip_report_interval: Duration::ZERO,
            client_version: "6.3.0-33".into(),
            previous_ipv4: None,
            previous_ipv6: None,
        };
        logout_globalprotect_session(&mut http, &session)
            .await
            .unwrap();
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method(), Method::POST);
        assert_eq!(requests[0].uri().path(), GLOBALPROTECT_LOGOUT_PATH);
        assert_eq!(requests[0].uri().query(), None);
        assert_eq!(requests[0].body(), session.opaque_query.as_bytes());
    }

    #[tokio::test]
    async fn gateway_password_flow_completes_and_preserves_peer() {
        let transport = Arc::new(FakeTransport {
            responses: Mutex::new(vec![
                response(br#"<prelogin-response><status>Success</status></prelogin-response>"#.to_vec()),
                response(jnlp()),
            ]),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(
            transport.clone(),
            GLOBALPROTECT_USER_AGENT,
        );
        let mut authenticator = GlobalProtectAuthenticator::new(
            http,
            "https://vpn.example/gateway",
            GlobalProtectAuthenticatorOptions {
                username: "alice".into(),
                password: "secret".into(),
                reported_os: "linux-64".into(),
                local_hostname: "host".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let GlobalProtectAuthenticationProgress::Complete(session) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected complete")
        };
        assert_eq!(
            session.opaque_query,
            "authcookie=cookie&user=alice&computer=host"
        );
        assert_eq!(
            session.authenticated_address,
            Some("192.0.2.1".parse().unwrap())
        );
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests[0].uri().path(), "/ssl-vpn/prelogin.esp");
        assert_eq!(requests[1].uri().path(), "/ssl-vpn/login.esp");
    }

    #[tokio::test]
    async fn form_challenge_and_saml_header_flow_are_validated() {
        let transport = Arc::new(FakeTransport {
            responses: Mutex::new(vec![response(br#"<prelogin-response><status>Success</status><saml-auth-method>REDIRECT</saml-auth-method><saml-request>aHR0cHM6Ly9pZHAuZXhhbXBsZS8=</saml-request></prelogin-response>"#.to_vec()), response(jnlp())]),
            requests: Mutex::new(Vec::new()),
        });
        let http =
            AnyConnectAuthHttpClient::new(transport, GLOBALPROTECT_USER_AGENT);
        let mut authenticator = GlobalProtectAuthenticator::new(
            http,
            "https://vpn.example/gateway",
            GlobalProtectAuthenticatorOptions {
                reported_os: "linux".into(),
                local_hostname: "host".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let GlobalProtectAuthenticationProgress::Challenge(challenge) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected challenge")
        };
        let mut headers = HeaderMap::new();
        headers.insert("saml-username", HeaderValue::from_static("alice"));
        headers
            .insert("prelogin-cookie", HeaderValue::from_static("saml-cookie"));
        let result = super::super::OpenConnectBrowserResult {
            headers,
            ..Default::default()
        };
        let completed = authenticator
            .respond(&challenge.id, OpenConnectAuthResponse::Browser(result))
            .await
            .unwrap();
        assert!(matches!(
            completed,
            GlobalProtectAuthenticationProgress::Complete(_)
        ));
    }

    #[tokio::test]
    async fn portal_gateway_selection_uses_public_select_challenge() {
        let policy = br#"<policy><gateways><external><list><entry name="a.example"/><entry name="b.example"><description>B</description></entry></list></external></gateways></policy>"#;
        let transport = Arc::new(FakeTransport {
            responses: Mutex::new(vec![response(br#"<prelogin-response><status>Success</status></prelogin-response>"#.to_vec()), response(policy.to_vec()), response(jnlp())]),
            requests: Mutex::new(Vec::new()),
        });
        let http =
            AnyConnectAuthHttpClient::new(transport, GLOBALPROTECT_USER_AGENT);
        let mut authenticator = GlobalProtectAuthenticator::new(
            http,
            "https://portal.example/portal",
            GlobalProtectAuthenticatorOptions {
                username: "alice".into(),
                password: "secret".into(),
                reported_os: "linux".into(),
                local_hostname: "host".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let GlobalProtectAuthenticationProgress::Challenge(challenge) =
            authenticator.begin().await.unwrap()
        else {
            panic!("expected gateway challenge")
        };
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            panic!("expected form")
        };
        assert_eq!(prompt.fields[0].options.len(), 2);
        let response = OpenConnectAuthResponse::Form(BTreeMap::from([(
            GATEWAY_SUBMISSION_KEY.into(),
            "b.example#1".into(),
        )]));
        let completed = authenticator
            .respond(&challenge.id, response)
            .await
            .unwrap();
        assert!(matches!(
            completed,
            GlobalProtectAuthenticationProgress::Complete(_)
        ));
    }
}
