//! Resumable F5 HTTPS form authentication over an injected singbox transport.

use std::{collections::BTreeMap, net::IpAddr};

use http::{Method, StatusCode, header::LOCATION};
use thiserror::Error;
use url::Url;

use super::{
    AnyConnectAuthError, AnyConnectAuthHttpClient, AnyConnectAuthHttpError,
    AnyConnectAuthHttpRequest, AnyConnectAuthHttpResponse,
    F5AuthenticationFieldKind, F5AuthenticationForm, F5FormError,
    OpenConnectAuthChallenge, OpenConnectAuthChallengeKind,
    OpenConnectAuthPromptChoice, OpenConnectAuthPromptField,
    OpenConnectAuthPromptForm, OpenConnectAuthPromptKind,
    OpenConnectAuthResponse, encode_f5_authentication_response,
    f5_form_has_password, is_f5_primary_authentication_form,
    new_openconnect_auth_challenge, parse_anyconnect_direct_cookie,
    parse_f5_authentication_document, parse_f5_authentication_expiration,
    static_f5_authentication_form, validate_openconnect_form_response,
};

pub const F5_MAXIMUM_AUTHENTICATION_BODY: usize = 16 * 1024 * 1024;
pub const F5_MAXIMUM_AUTHENTICATION_REQUESTS: usize = 64;
pub const F5_MAXIMUM_AUTHENTICATION_REDIRECTS: usize = 10;
pub const F5_DEFAULT_USER_AGENT: &str =
    "AnyConnect-compatible OpenConnect VPN Agent v1.12";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct F5AuthenticatorOptions {
    pub username: String,
    pub password: String,
    pub auth_group: String,
    pub direct_cookie: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F5AuthenticatedSession {
    pub server_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
    pub mrh_session: String,
    pub f5_st: String,
    pub authentication_expiration: Option<std::time::SystemTime>,
    pub cookies: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum F5AuthenticationProgress {
    Challenge(OpenConnectAuthChallenge),
    Complete(F5AuthenticatedSession),
}

#[derive(Debug, Error)]
pub enum F5AuthenticatorError {
    #[error(transparent)]
    Http(#[from] AnyConnectAuthHttpError),
    #[error(transparent)]
    Form(#[from] F5FormError),
    #[error(transparent)]
    Challenge(#[from] AnyConnectAuthError),
    #[error("invalid F5 server URL: {0}")]
    InvalidServerUrl(String),
    #[error("F5 authentication response exceeds {0} bytes")]
    BodyTooLarge(usize),
    #[error("F5 authentication exceeded {0} redirects")]
    TooManyRedirects(usize),
    #[error("F5 authentication returned unexpected HTTP status {0}")]
    UnexpectedStatus(StatusCode),
    #[error("F5 authentication response has no usable form")]
    MissingForm,
    #[error("unexpected first F5 HTML form ID: {0}")]
    UnexpectedFirstForm(String),
    #[error("F5 authentication challenge response is missing")]
    MissingResponse,
    #[error("F5 authentication challenge ID does not match")]
    ChallengeMismatch,
    #[error("F5 authentication response type does not match")]
    ResponseTypeMismatch,
    #[error("F5 authentication is already complete")]
    AlreadyComplete,
    #[error("F5 authentication is in a terminal state")]
    TerminalState,
    #[error("F5 direct cookie does not contain MRHSession")]
    MissingDirectSession,
    #[error("F5 authenticated endpoint has no accepted peer address")]
    MissingAcceptedAddress,
}

#[derive(Debug, Clone)]
enum Stage {
    Initial,
    AwaitForm {
        challenge: Box<OpenConnectAuthChallenge>,
        form: F5AuthenticationForm,
        primary: bool,
    },
    Complete,
    Terminal,
}

pub struct F5Authenticator {
    http: AnyConnectAuthHttpClient,
    options: F5AuthenticatorOptions,
    current_url: Url,
    current_address: Option<IpAddr>,
    peer_certificate_der: Option<Vec<u8>>,
    stage: Stage,
    immediate_session: Option<F5AuthenticatedSession>,
    form_number: usize,
    seen_html_form: bool,
    primary_password_seen: bool,
    primary_password_sent: bool,
}

impl F5Authenticator {
    pub fn new(
        mut http: AnyConnectAuthHttpClient,
        server: &str,
        options: F5AuthenticatorOptions,
    ) -> Result<Self, F5AuthenticatorError> {
        let current_url = parse_server_url(server)?;
        http.set_maximum_wire_requests(Some(
            F5_MAXIMUM_AUTHENTICATION_REQUESTS,
        ));
        let immediate_session =
            if let Some(content) = options.direct_cookie.as_deref() {
                let cookies =
                    parse_anyconnect_direct_cookie(content, "MRHSession")?;
                let mrh_session = cookies
                    .get("MRHSession")
                    .cloned()
                    .ok_or(F5AuthenticatorError::MissingDirectSession)?;
                for (name, value) in &cookies {
                    http.set_cookie(&current_url, name, value)?;
                }
                let f5_st = cookies.get("F5_ST").cloned().unwrap_or_default();
                Some(F5AuthenticatedSession {
                    authenticated_address: current_url
                        .host_str()
                        .and_then(|host| host.parse().ok()),
                    peer_certificate_der: None,
                    authentication_expiration:
                        parse_f5_authentication_expiration(&f5_st),
                    cookies: http.cookie_pairs(&current_url),
                    server_url: current_url.clone(),
                    mrh_session,
                    f5_st,
                })
            } else {
                http.clear_cookies();
                None
            };
        Ok(Self {
            http,
            options,
            current_url,
            current_address: None,
            peer_certificate_der: None,
            stage: Stage::Initial,
            immediate_session,
            form_number: 0,
            seen_html_form: false,
            primary_password_seen: false,
            primary_password_sent: false,
        })
    }

    pub async fn advance(
        &mut self,
        response: Option<&OpenConnectAuthResponse>,
    ) -> Result<F5AuthenticationProgress, F5AuthenticatorError> {
        if let Some(session) = self.immediate_session.take() {
            if response.is_some() {
                return self
                    .terminal(F5AuthenticatorError::ResponseTypeMismatch);
            }
            self.stage = Stage::Complete;
            return Ok(F5AuthenticationProgress::Complete(session));
        }
        let (method, url, body, submitted_primary) = match &self.stage {
            Stage::Initial => {
                if response.is_some() {
                    return self
                        .terminal(F5AuthenticatorError::ResponseTypeMismatch);
                }
                (Method::GET, self.current_url.clone(), Vec::new(), false)
            }
            Stage::AwaitForm {
                challenge,
                form,
                primary,
            } => {
                let Some(OpenConnectAuthResponse::Form(values)) = response
                else {
                    return self.terminal(if response.is_none() {
                        F5AuthenticatorError::MissingResponse
                    } else {
                        F5AuthenticatorError::ResponseTypeMismatch
                    });
                };
                if challenge.id.is_empty() {
                    return self
                        .terminal(F5AuthenticatorError::ChallengeMismatch);
                }
                let prompt_fields = match &challenge.kind {
                    OpenConnectAuthChallengeKind::Form(form) => &form.fields,
                    _ => {
                        return self.terminal(
                            F5AuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                };
                validate_openconnect_form_response(prompt_fields, values)?;
                let mut all_values = form
                    .fields
                    .iter()
                    .map(|field| {
                        (field.submission_key.clone(), field.value.clone())
                    })
                    .collect::<BTreeMap<_, _>>();
                all_values.extend(values.clone());
                let body =
                    encode_f5_authentication_response(form, &all_values)?
                        .into_bytes();
                let url = if form.action.is_empty() {
                    self.current_url.clone()
                } else {
                    self.current_url.join(&form.action).map_err(|error| {
                        F5AuthenticatorError::InvalidServerUrl(
                            error.to_string(),
                        )
                    })?
                };
                validate_https(&url)?;
                if !equal_endpoint(&self.current_url, &url) {
                    self.http.clear_cookies();
                    self.current_address = None;
                    self.peer_certificate_der = None;
                }
                (Method::POST, url, body, *primary)
            }
            Stage::Complete => {
                return Err(F5AuthenticatorError::AlreadyComplete);
            }
            Stage::Terminal => return Err(F5AuthenticatorError::TerminalState),
        };
        if submitted_primary {
            self.primary_password_sent = true;
        }
        self.exchange(method, url, body).await
    }

    async fn exchange(
        &mut self,
        mut method: Method,
        mut url: Url,
        mut body: Vec<u8>,
    ) -> Result<F5AuthenticationProgress, F5AuthenticatorError> {
        for redirect in 0..=F5_MAXIMUM_AUTHENTICATION_REDIRECTS {
            let response = self
                .request(method.clone(), url.clone(), body.clone())
                .await?;
            self.remember_response(&response);
            if let Some(session) =
                self.session_from_cookies(&response.final_url)?
            {
                self.stage = Stage::Complete;
                return Ok(F5AuthenticationProgress::Complete(session));
            }
            if is_redirect(response.status) {
                let Some(location) = response.headers.get(LOCATION) else {
                    return self.terminal(
                        F5AuthenticatorError::UnexpectedStatus(response.status),
                    );
                };
                if redirect == F5_MAXIMUM_AUTHENTICATION_REDIRECTS {
                    return self.terminal(
                        F5AuthenticatorError::TooManyRedirects(
                            F5_MAXIMUM_AUTHENTICATION_REDIRECTS,
                        ),
                    );
                }
                let location = location.to_str().map_err(|error| {
                    F5AuthenticatorError::InvalidServerUrl(error.to_string())
                })?;
                let next =
                    response.final_url.join(location).map_err(|error| {
                        F5AuthenticatorError::InvalidServerUrl(
                            error.to_string(),
                        )
                    })?;
                validate_https(&next)?;
                if !equal_endpoint(&response.final_url, &next) {
                    self.http.clear_cookies();
                    self.current_address = None;
                    self.peer_certificate_der = None;
                }
                method = Method::GET;
                url = next;
                body.clear();
                continue;
            }
            if !response.status.is_success() {
                return self.terminal(F5AuthenticatorError::UnexpectedStatus(
                    response.status,
                ));
            }
            return self.prepare_form(&response.body);
        }
        unreachable!("bounded redirect loop returns")
    }

    fn prepare_form(
        &mut self,
        content: &[u8],
    ) -> Result<F5AuthenticationProgress, F5AuthenticatorError> {
        let document = parse_f5_authentication_document(content)?;
        let mut form = document.form;
        if let Some(current) = &form
            && current.html
            && !self.seen_html_form
        {
            self.seen_html_form = true;
            if current.id != "auth_form" {
                return self.terminal(
                    F5AuthenticatorError::UnexpectedFirstForm(
                        current.id.clone(),
                    ),
                );
            }
        }
        if form.is_none() && self.form_number == 0 {
            form = Some(static_f5_authentication_form());
        }
        let mut form = form.ok_or(F5AuthenticatorError::MissingForm)?;
        let repeated_primary = self.primary_password_sent
            && is_f5_primary_authentication_form(&form);
        let first_primary =
            !self.primary_password_seen && f5_form_has_password(&form);
        let primary = first_primary || repeated_primary;
        if first_primary {
            self.primary_password_seen = true;
        }
        let stable_username = self.form_number == 0 || primary;
        for field in &mut form.fields {
            if stable_username
                && field.name == "username"
                && field.kind == F5AuthenticationFieldKind::Text
                && field.value.is_empty()
            {
                field.value.clone_from(&self.options.username);
            }
            if primary
                && field.kind == F5AuthenticationFieldKind::Password
                && field.value.is_empty()
            {
                field.value.clone_from(&self.options.password);
            }
            if field.kind == F5AuthenticationFieldKind::Select
                && field.name == "domain"
                && !self.options.auth_group.is_empty()
                && let Some(choice) = field.options.iter().find(|choice| {
                    choice.value == self.options.auth_group
                        || choice.label == self.options.auth_group
                })
            {
                field.value.clone_from(&choice.value);
            }
        }
        self.form_number += 1;
        let fields = form
            .fields
            .iter()
            .filter(|field| field.kind != F5AuthenticationFieldKind::Hidden)
            .map(prompt_field)
            .collect::<Vec<_>>();
        let challenge = new_openconnect_auth_challenge(
            form.banner.clone(),
            form.message.clone(),
            if repeated_primary {
                "gateway rejected the primary credentials"
            } else {
                ""
            },
            OpenConnectAuthChallengeKind::Form(OpenConnectAuthPromptForm {
                fields,
            }),
        );
        self.stage = Stage::AwaitForm {
            challenge: Box::new(challenge.clone()),
            form,
            primary,
        };
        Ok(F5AuthenticationProgress::Challenge(challenge))
    }

    async fn request(
        &mut self,
        method: Method,
        url: Url,
        body: Vec<u8>,
    ) -> Result<AnyConnectAuthHttpResponse, F5AuthenticatorError> {
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
        if response.body.len() > F5_MAXIMUM_AUTHENTICATION_BODY {
            return self.terminal(F5AuthenticatorError::BodyTooLarge(
                F5_MAXIMUM_AUTHENTICATION_BODY,
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

    fn session_from_cookies(
        &self,
        url: &Url,
    ) -> Result<Option<F5AuthenticatedSession>, F5AuthenticatorError> {
        let Some(mrh_session) = self.http.cookie_value(url, "MRHSession")
        else {
            return Ok(None);
        };
        let Some(f5_st) = self.http.cookie_value(url, "F5_ST") else {
            return Ok(None);
        };
        let authenticated_address = self
            .current_address
            .ok_or(F5AuthenticatorError::MissingAcceptedAddress)?;
        Ok(Some(F5AuthenticatedSession {
            server_url: url.clone(),
            authenticated_address: Some(authenticated_address),
            peer_certificate_der: self.peer_certificate_der.clone(),
            authentication_expiration: parse_f5_authentication_expiration(
                &f5_st,
            ),
            cookies: self.http.cookie_pairs(url),
            mrh_session,
            f5_st,
        }))
    }

    fn terminal<T>(
        &mut self,
        error: F5AuthenticatorError,
    ) -> Result<T, F5AuthenticatorError> {
        self.stage = Stage::Terminal;
        Err(error)
    }
}

fn prompt_field(
    field: &super::F5AuthenticationField,
) -> OpenConnectAuthPromptField {
    OpenConnectAuthPromptField {
        submission_key: field.submission_key.clone(),
        name: field.name.clone(),
        label: field.label.clone(),
        kind: match field.kind {
            F5AuthenticationFieldKind::Password => {
                OpenConnectAuthPromptKind::Password
            }
            F5AuthenticationFieldKind::Select => {
                OpenConnectAuthPromptKind::Select
            }
            F5AuthenticationFieldKind::Hidden
            | F5AuthenticationFieldKind::Text => {
                OpenConnectAuthPromptKind::Text
            }
        },
        value: field.value.clone(),
        options: field
            .options
            .iter()
            .map(|choice| OpenConnectAuthPromptChoice {
                value: choice.value.clone(),
                label: choice.label.clone(),
            })
            .collect(),
    }
}

fn parse_server_url(server: &str) -> Result<Url, F5AuthenticatorError> {
    let candidate = if server.contains("://") {
        server.to_owned()
    } else {
        format!("https://{server}")
    };
    let mut url = Url::parse(&candidate).map_err(|error| {
        F5AuthenticatorError::InvalidServerUrl(error.to_string())
    })?;
    validate_https(&url)?;
    if url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url)
}

fn validate_https(url: &Url) -> Result<(), F5AuthenticatorError> {
    if url.scheme() != "https" || url.host_str().is_none() {
        Err(F5AuthenticatorError::InvalidServerUrl(url.to_string()))
    } else {
        Ok(())
    }
}

fn equal_endpoint(left: &Url, right: &Url) -> bool {
    left.scheme().eq_ignore_ascii_case(right.scheme())
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
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

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io, sync::Arc};

    use async_trait::async_trait;
    use http::{HeaderMap, HeaderValue, Request, header::SET_COOKIE};
    use parking_lot::Mutex;

    use super::*;
    use crate::protocol::openconnect::{
        AnyConnectAuthHttpTransport, AnyConnectAuthRawHttpResponse,
    };

    struct ScriptedTransport {
        responses: Mutex<VecDeque<AnyConnectAuthRawHttpResponse>>,
        requests: Mutex<Vec<Request<Vec<u8>>>>,
    }

    #[async_trait]
    impl AnyConnectAuthHttpTransport for ScriptedTransport {
        async fn execute(
            &self,
            request: Request<Vec<u8>>,
        ) -> io::Result<AnyConnectAuthRawHttpResponse> {
            self.requests.lock().push(request);
            self.responses.lock().pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "script exhausted")
            })
        }
    }

    fn response(
        status: StatusCode,
        body: &[u8],
    ) -> AnyConnectAuthRawHttpResponse {
        AnyConnectAuthRawHttpResponse {
            status,
            headers: HeaderMap::new(),
            body: body.to_vec(),
            authenticated_address: Some("192.0.2.10".parse().unwrap()),
            peer_certificate_der: Some(vec![1, 2, 3]),
        }
    }

    #[tokio::test]
    async fn html_form_continuation_completes_from_session_cookies() {
        let form = br#"<form id="auth_form" method="post" action="/my.policy"><input type="text" name="username"><input type="password" name="password"><input type="hidden" name="csrf" value="x"></form>"#;
        let mut complete = response(StatusCode::FOUND, b"");
        complete.headers.append(
            SET_COOKIE,
            HeaderValue::from_static("MRHSession=session; Path=/; Secure"),
        );
        complete.headers.append(
            SET_COOKIE,
            HeaderValue::from_static("F5_ST=azbzcz100z20; Path=/; Secure"),
        );
        let transport = Arc::new(ScriptedTransport {
            responses: Mutex::new(VecDeque::from([
                response(StatusCode::OK, form),
                complete,
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "test");
        let mut authenticator = F5Authenticator::new(
            http,
            "vpn.example",
            F5AuthenticatorOptions {
                username: "alice".into(),
                password: "secret".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let F5AuthenticationProgress::Challenge(challenge) =
            authenticator.advance(None).await.unwrap()
        else {
            panic!("expected form")
        };
        let fields = match challenge.kind {
            OpenConnectAuthChallengeKind::Form(form) => form.fields,
            _ => panic!("expected fields"),
        };
        assert_eq!(fields[0].value, "alice");
        assert_eq!(fields[1].value, "secret");
        let values = fields
            .iter()
            .map(|field| (field.submission_key.clone(), field.value.clone()))
            .collect();
        let F5AuthenticationProgress::Complete(session) = authenticator
            .advance(Some(&OpenConnectAuthResponse::Form(values)))
            .await
            .unwrap()
        else {
            panic!("expected session")
        };
        assert_eq!(session.mrh_session, "session");
        assert_eq!(
            session.authenticated_address.unwrap().to_string(),
            "192.0.2.10"
        );
        let requests = transport.requests.lock();
        assert_eq!(requests[0].method(), Method::GET);
        assert_eq!(requests[1].method(), Method::POST);
        assert_eq!(
            requests[1].body(),
            b"username=alice&password=secret&csrf=x"
        );
    }

    #[tokio::test]
    async fn redirect_changes_to_get_and_cross_endpoint_clears_old_cookies() {
        let mut redirect = response(StatusCode::TEMPORARY_REDIRECT, b"");
        redirect.headers.insert(
            LOCATION,
            HeaderValue::from_static("https://other.example/login"),
        );
        let transport = Arc::new(ScriptedTransport {
            responses: Mutex::new(VecDeque::from([
                redirect,
                response(StatusCode::OK, b"no form"),
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "test");
        let mut authenticator = F5Authenticator::new(
            http,
            "vpn.example",
            F5AuthenticatorOptions::default(),
        )
        .unwrap();
        let progress = authenticator.advance(None).await.unwrap();
        assert!(matches!(progress, F5AuthenticationProgress::Challenge(_)));
        let requests = transport.requests.lock();
        assert_eq!(requests[1].method(), Method::GET);
        assert_eq!(requests[1].uri().host(), Some("other.example"));
    }

    #[tokio::test]
    async fn direct_cookie_skips_http() {
        let transport = Arc::new(ScriptedTransport {
            responses: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "test");
        let mut authenticator = F5Authenticator::new(
            http,
            "192.0.2.1",
            F5AuthenticatorOptions {
                direct_cookie: Some(
                    "MRHSession=session; F5_ST=azbzcz100z20".into(),
                ),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(
            authenticator.advance(None).await.unwrap(),
            F5AuthenticationProgress::Complete(_)
        ));
        assert!(transport.requests.lock().is_empty());
    }
}
