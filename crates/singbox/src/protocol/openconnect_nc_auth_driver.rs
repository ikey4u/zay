//! Resumable Juniper Network Connect HTTPS authentication.

use std::{collections::BTreeMap, net::IpAddr};

use http::{Method, StatusCode, header::LOCATION};
use thiserror::Error;
use url::Url;

use super::{
    AnyConnectAuthError, AnyConnectAuthHttpClient, AnyConnectAuthHttpError,
    AnyConnectAuthHttpRequest, AnyConnectAuthHttpResponse,
    NetworkConnectAuthenticationField, NetworkConnectAuthenticationFieldKind,
    NetworkConnectAuthenticationForm, NetworkConnectFormError,
    OpenConnectAuthChallenge, OpenConnectAuthChallengeKind,
    OpenConnectAuthPromptChoice, OpenConnectAuthPromptField,
    OpenConnectAuthPromptForm, OpenConnectAuthPromptKind,
    OpenConnectAuthResponse, encode_network_connect_authentication_response,
    network_connect_primary_authentication_form,
    network_connect_token_password_field, new_openconnect_auth_challenge,
    parse_anyconnect_direct_cookie,
    parse_network_connect_authentication_document,
    validate_network_connect_authentication_form,
    validate_openconnect_form_response,
};

pub const NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_BODY: usize = 16 * 1024 * 1024;
pub const NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_REQUESTS: usize = 64;
pub const NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_REDIRECTS: usize = 10;
pub const NETWORK_CONNECT_DEFAULT_USER_AGENT: &str =
    "AnyConnect-compatible OpenConnect VPN Agent v1.12";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConnectAuthenticatorOptions {
    pub username: String,
    pub password: String,
    pub auth_group: String,
    pub generated_token: Option<String>,
    pub direct_cookie: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectAuthenticatedSession {
    pub server_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
    pub dsid: String,
    pub cookies: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectTnccRequest {
    pub server_url: Url,
    pub authenticated_address: Option<IpAddr>,
    pub peer_certificate_der: Option<Vec<u8>>,
    pub preauthentication_cookie: String,
    pub sign_in_url: String,
    pub cookies: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkConnectAuthenticationProgress {
    Challenge(OpenConnectAuthChallenge),
    Tncc(NetworkConnectTnccRequest),
    Complete(NetworkConnectAuthenticatedSession),
}

#[derive(Debug, Error)]
pub enum NetworkConnectAuthenticatorError {
    #[error(transparent)]
    Http(#[from] AnyConnectAuthHttpError),
    #[error(transparent)]
    Form(#[from] NetworkConnectFormError),
    #[error(transparent)]
    Challenge(#[from] AnyConnectAuthError),
    #[error("invalid Network Connect server URL: {0}")]
    InvalidServerUrl(String),
    #[error("Network Connect authentication response exceeds {0} bytes")]
    BodyTooLarge(usize),
    #[error("Network Connect authentication exceeded {0} redirects")]
    TooManyRedirects(usize),
    #[error(
        "Network Connect authentication returned unexpected HTTP status {0}"
    )]
    UnexpectedStatus(StatusCode),
    #[error("Network Connect authentication response has no usable form")]
    MissingForm,
    #[error("Network Connect authentication challenge response is missing")]
    MissingResponse,
    #[error("Network Connect authentication response type does not match")]
    ResponseTypeMismatch,
    #[error("Network Connect TNCC response is not currently expected")]
    UnexpectedTnccResponse,
    #[error("Network Connect TNCC returned an empty DSPREAUTH cookie")]
    EmptyTnccCookie,
    #[error("Network Connect authentication is already complete")]
    AlreadyComplete,
    #[error("Network Connect authentication is in a terminal state")]
    TerminalState,
    #[error("Network Connect direct cookie does not contain DSID")]
    MissingDirectSession,
    #[error(
        "Network Connect authenticated endpoint has no accepted peer address"
    )]
    MissingAcceptedAddress,
}

#[derive(Debug, Clone)]
enum Stage {
    Initial,
    AwaitForm {
        form: NetworkConnectAuthenticationForm,
        primary: bool,
    },
    AwaitTncc,
    Complete,
    Terminal,
}

pub struct NetworkConnectAuthenticator {
    http: AnyConnectAuthHttpClient,
    options: NetworkConnectAuthenticatorOptions,
    current_url: Url,
    current_address: Option<IpAddr>,
    peer_certificate_der: Option<Vec<u8>>,
    stage: Stage,
    immediate_session: Option<NetworkConnectAuthenticatedSession>,
    primary_password_seen: bool,
    primary_password_sent: bool,
    tncc_attempted: bool,
}

impl NetworkConnectAuthenticator {
    pub fn new(
        mut http: AnyConnectAuthHttpClient,
        server: &str,
        options: NetworkConnectAuthenticatorOptions,
    ) -> Result<Self, NetworkConnectAuthenticatorError> {
        let current_url = parse_server_url(server)?;
        http.set_maximum_wire_requests(Some(
            NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_REQUESTS,
        ));
        let immediate_session =
            if let Some(content) = options.direct_cookie.as_deref() {
                let cookies = parse_anyconnect_direct_cookie(content, "DSID")?;
                let dsid = cookies.get("DSID").cloned().ok_or(
                    NetworkConnectAuthenticatorError::MissingDirectSession,
                )?;
                for (name, value) in &cookies {
                    http.set_cookie(&current_url, name, value)?;
                }
                Some(NetworkConnectAuthenticatedSession {
                    authenticated_address: current_url
                        .host_str()
                        .and_then(|host| host.parse().ok()),
                    peer_certificate_der: None,
                    cookies: http.cookie_pairs(&current_url),
                    server_url: current_url.clone(),
                    dsid,
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
            primary_password_seen: false,
            primary_password_sent: false,
            tncc_attempted: false,
        })
    }

    pub async fn advance(
        &mut self,
        response: Option<&OpenConnectAuthResponse>,
    ) -> Result<
        NetworkConnectAuthenticationProgress,
        NetworkConnectAuthenticatorError,
    > {
        if let Some(session) = self.immediate_session.take() {
            if response.is_some() {
                return self.terminal(
                    NetworkConnectAuthenticatorError::ResponseTypeMismatch,
                );
            }
            self.stage = Stage::Complete;
            return Ok(NetworkConnectAuthenticationProgress::Complete(session));
        }
        let (method, url, body, submitted_primary) = match &self.stage {
            Stage::Initial => {
                if response.is_some() {
                    return self.terminal(
                        NetworkConnectAuthenticatorError::ResponseTypeMismatch,
                    );
                }
                (Method::GET, self.current_url.clone(), Vec::new(), false)
            }
            Stage::AwaitForm { form, primary } => {
                let Some(OpenConnectAuthResponse::Form(values)) = response
                else {
                    return self.terminal(if response.is_none() {
                        NetworkConnectAuthenticatorError::MissingResponse
                    } else {
                        NetworkConnectAuthenticatorError::ResponseTypeMismatch
                    });
                };
                let visible = form
                    .fields
                    .iter()
                    .filter(|field| {
                        field.kind
                            != NetworkConnectAuthenticationFieldKind::Hidden
                    })
                    .map(prompt_field)
                    .collect::<Vec<_>>();
                validate_openconnect_form_response(&visible, values)?;
                if form.role_form {
                    let field = &form.fields[0];
                    let selected =
                        values.get(&field.submission_key).ok_or_else(|| {
                            NetworkConnectAuthenticatorError::Form(
                                NetworkConnectFormError::MissingResponse(
                                    field.name.clone(),
                                ),
                            )
                        })?;
                    if !field
                        .options
                        .iter()
                        .any(|choice| choice.value == *selected)
                    {
                        return self.terminal(
                            NetworkConnectAuthenticatorError::ResponseTypeMismatch,
                        );
                    }
                    let url =
                        self.current_url.join(selected).map_err(|error| {
                            NetworkConnectAuthenticatorError::InvalidServerUrl(
                                error.to_string(),
                            )
                        })?;
                    validate_https(&url)?;
                    (Method::GET, url, Vec::new(), false)
                } else {
                    let mut all_values = form
                        .fields
                        .iter()
                        .map(|field| {
                            (field.submission_key.clone(), field.value.clone())
                        })
                        .collect::<BTreeMap<_, _>>();
                    all_values.extend(values.clone());
                    let body = encode_network_connect_authentication_response(
                        form,
                        &all_values,
                    )?
                    .into_bytes();
                    let url = if form.action.is_empty() {
                        self.current_url.clone()
                    } else {
                        self.current_url.join(&form.action).map_err(|error| {
                            NetworkConnectAuthenticatorError::InvalidServerUrl(
                                error.to_string(),
                            )
                        })?
                    };
                    validate_https(&url)?;
                    (Method::POST, url, body, *primary)
                }
            }
            Stage::AwaitTncc => {
                return Err(
                    NetworkConnectAuthenticatorError::UnexpectedTnccResponse,
                );
            }
            Stage::Complete => {
                return Err(NetworkConnectAuthenticatorError::AlreadyComplete);
            }
            Stage::Terminal => {
                return Err(NetworkConnectAuthenticatorError::TerminalState);
            }
        };
        if submitted_primary {
            self.primary_password_sent = true;
        }
        self.exchange(method, url, body).await
    }

    /// Resume authentication after a built-in or external TNCC runner has
    /// returned the refreshed DSPREAUTH cookie.
    pub async fn resume_tncc(
        &mut self,
        preauthentication_cookie: &str,
    ) -> Result<
        NetworkConnectAuthenticationProgress,
        NetworkConnectAuthenticatorError,
    > {
        if !matches!(self.stage, Stage::AwaitTncc) {
            return Err(
                NetworkConnectAuthenticatorError::UnexpectedTnccResponse,
            );
        }
        if preauthentication_cookie.is_empty() {
            return self
                .terminal(NetworkConnectAuthenticatorError::EmptyTnccCookie);
        }
        self.http.set_cookie(
            &self.current_url,
            "DSPREAUTH",
            preauthentication_cookie,
        )?;
        self.tncc_attempted = true;
        self.stage = Stage::Initial;
        self.exchange(Method::GET, self.current_url.clone(), Vec::new())
            .await
    }

    async fn exchange(
        &mut self,
        mut method: Method,
        mut url: Url,
        mut body: Vec<u8>,
    ) -> Result<
        NetworkConnectAuthenticationProgress,
        NetworkConnectAuthenticatorError,
    > {
        for redirect in 0..=NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_REDIRECTS {
            let response = self
                .request(method.clone(), url.clone(), body.clone())
                .await?;
            self.remember_response(&response);
            if let Some(session) =
                self.session_from_cookies(&response.final_url)?
            {
                self.stage = Stage::Complete;
                return Ok(NetworkConnectAuthenticationProgress::Complete(
                    session,
                ));
            }
            if response.status != StatusCode::OK
                && let Some(location) = response.headers.get(LOCATION)
            {
                if redirect == NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_REDIRECTS
                {
                    return self.terminal(
                        NetworkConnectAuthenticatorError::TooManyRedirects(
                            NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_REDIRECTS,
                        ),
                    );
                }
                let location = location.to_str().map_err(|error| {
                    NetworkConnectAuthenticatorError::InvalidServerUrl(
                        error.to_string(),
                    )
                })?;
                let next =
                    response.final_url.join(location).map_err(|error| {
                        NetworkConnectAuthenticatorError::InvalidServerUrl(
                            error.to_string(),
                        )
                    })?;
                validate_https(&next)?;
                method = Method::GET;
                url = next;
                body.clear();
                continue;
            }
            if response.status != StatusCode::OK {
                return self.terminal(
                    NetworkConnectAuthenticatorError::UnexpectedStatus(
                        response.status,
                    ),
                );
            }
            let form =
                parse_network_connect_authentication_document(&response.body)?;
            if let Some(form) = form {
                validate_network_connect_authentication_form(&form)?;
                return self.prepare_form(form);
            }
            if !self.tncc_attempted
                && let Some(preauthentication_cookie) =
                    self.http.cookie_value(&response.final_url, "DSPREAUTH")
            {
                let sign_in_url = self
                    .http
                    .cookie_value(&response.final_url, "DSSIGNIN")
                    .unwrap_or_else(|| "null".to_owned());
                self.stage = Stage::AwaitTncc;
                return Ok(NetworkConnectAuthenticationProgress::Tncc(
                    NetworkConnectTnccRequest {
                        server_url: response.final_url,
                        authenticated_address: self.current_address,
                        peer_certificate_der: self.peer_certificate_der.clone(),
                        preauthentication_cookie,
                        sign_in_url,
                        cookies: self.http.cookie_pairs(&self.current_url),
                    },
                ));
            }
            return self
                .terminal(NetworkConnectAuthenticatorError::MissingForm);
        }
        unreachable!("bounded redirect loop returns")
    }

    fn prepare_form(
        &mut self,
        mut form: NetworkConnectAuthenticationForm,
    ) -> Result<
        NetworkConnectAuthenticationProgress,
        NetworkConnectAuthenticatorError,
    > {
        let primary = network_connect_primary_authentication_form(&form);
        let repeated_primary = self.primary_password_sent && primary;
        let first_primary = !self.primary_password_seen && primary;
        if first_primary {
            self.primary_password_seen = true;
        }
        let primary = first_primary || repeated_primary;
        let token_message = format!("{} {}", form.banner, form.message);
        let mut password_number = 0;
        for field in &mut form.fields {
            if matches!(form.id.as_str(), "frmLogin" | "loginForm")
                && field.kind == NetworkConnectAuthenticationFieldKind::Text
                && field.name.eq_ignore_ascii_case("username")
                && field.value.is_empty()
            {
                field.value.clone_from(&self.options.username);
            }
            if field.kind == NetworkConnectAuthenticationFieldKind::Password {
                password_number += 1;
                if primary && password_number == 1 && field.value.is_empty() {
                    field.value.clone_from(&self.options.password);
                } else if network_connect_token_password_field(
                    &form.id,
                    password_number,
                ) && let Some(token) = &self.options.generated_token
                    && !token_message.is_empty()
                {
                    field.value.clone_from(token);
                }
            }
            if form.id == "loginForm"
                && field.kind == NetworkConnectAuthenticationFieldKind::Text
                && field.name == "VerificationCode"
                && let Some(token) = &self.options.generated_token
            {
                field.value.clone_from(token);
            }
            if field.kind == NetworkConnectAuthenticationFieldKind::Select
                && (field.name == "realm" || form.role_form)
                && !self.options.auth_group.is_empty()
                && let Some(choice) = field.options.iter().find(|choice| {
                    choice.value == self.options.auth_group
                        || choice.label == self.options.auth_group
                })
            {
                field.value.clone_from(&choice.value);
            }
        }
        let fields = form
            .fields
            .iter()
            .filter(|field| {
                field.kind != NetworkConnectAuthenticationFieldKind::Hidden
            })
            .map(prompt_field)
            .collect();
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
        self.stage = Stage::AwaitForm { form, primary };
        Ok(NetworkConnectAuthenticationProgress::Challenge(challenge))
    }

    async fn request(
        &mut self,
        method: Method,
        url: Url,
        body: Vec<u8>,
    ) -> Result<AnyConnectAuthHttpResponse, NetworkConnectAuthenticatorError>
    {
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
                preserve_cookie_jar_on_redirect: true,
                follow_redirects: false,
            })
            .await?;
        if response.body.len() > NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_BODY {
            return self.terminal(
                NetworkConnectAuthenticatorError::BodyTooLarge(
                    NETWORK_CONNECT_MAXIMUM_AUTHENTICATION_BODY,
                ),
            );
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
    ) -> Result<
        Option<NetworkConnectAuthenticatedSession>,
        NetworkConnectAuthenticatorError,
    > {
        let Some(dsid) = self.http.cookie_value(url, "DSID") else {
            return Ok(None);
        };
        let authenticated_address = self
            .current_address
            .ok_or(NetworkConnectAuthenticatorError::MissingAcceptedAddress)?;
        Ok(Some(NetworkConnectAuthenticatedSession {
            server_url: url.clone(),
            authenticated_address: Some(authenticated_address),
            peer_certificate_der: self.peer_certificate_der.clone(),
            cookies: self.http.cookie_pairs(url),
            dsid,
        }))
    }

    fn terminal<T>(
        &mut self,
        error: NetworkConnectAuthenticatorError,
    ) -> Result<T, NetworkConnectAuthenticatorError> {
        self.stage = Stage::Terminal;
        Err(error)
    }
}

fn prompt_field(
    field: &NetworkConnectAuthenticationField,
) -> OpenConnectAuthPromptField {
    OpenConnectAuthPromptField {
        submission_key: field.submission_key.clone(),
        name: field.name.clone(),
        label: field.label.clone(),
        kind: match field.kind {
            NetworkConnectAuthenticationFieldKind::Password => {
                OpenConnectAuthPromptKind::Password
            }
            NetworkConnectAuthenticationFieldKind::Select => {
                OpenConnectAuthPromptKind::Select
            }
            NetworkConnectAuthenticationFieldKind::Hidden
            | NetworkConnectAuthenticationFieldKind::Text => {
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

fn parse_server_url(
    server: &str,
) -> Result<Url, NetworkConnectAuthenticatorError> {
    let candidate = if server.contains("://") {
        server.to_owned()
    } else {
        format!("https://{server}")
    };
    let mut url = Url::parse(&candidate).map_err(|error| {
        NetworkConnectAuthenticatorError::InvalidServerUrl(error.to_string())
    })?;
    validate_https(&url)?;
    if url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url)
}

fn validate_https(url: &Url) -> Result<(), NetworkConnectAuthenticatorError> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        Err(NetworkConnectAuthenticatorError::InvalidServerUrl(
            url.to_string(),
        ))
    } else {
        Ok(())
    }
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
            authenticated_address: Some("192.0.2.20".parse().unwrap()),
            peer_certificate_der: Some(vec![4, 5, 6]),
        }
    }

    #[tokio::test]
    async fn login_form_posts_defaults_and_completes_dsid_session() {
        let form = br#"<form name="frmLogin" method="post" action="/login.cgi"><input type="text" name="username"><input type="password" name="password"><input type="hidden" name="realm" value="users"><input type="submit" name="btnSubmit" value="Sign In"></form>"#;
        let mut complete = response(StatusCode::FOUND, b"");
        complete.headers.append(
            SET_COOKIE,
            HeaderValue::from_static("DSID=session; Path=/; Secure"),
        );
        let transport = Arc::new(ScriptedTransport {
            responses: Mutex::new(VecDeque::from([
                response(StatusCode::OK, form),
                complete,
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "test");
        let mut authenticator = NetworkConnectAuthenticator::new(
            http,
            "vpn.example",
            NetworkConnectAuthenticatorOptions {
                username: "alice".into(),
                password: "secret".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let NetworkConnectAuthenticationProgress::Challenge(challenge) =
            authenticator.advance(None).await.unwrap()
        else {
            panic!("expected form")
        };
        let OpenConnectAuthChallengeKind::Form(form) = challenge.kind else {
            panic!("expected fields")
        };
        let values = form
            .fields
            .iter()
            .map(|field| (field.submission_key.clone(), field.value.clone()))
            .collect();
        let NetworkConnectAuthenticationProgress::Complete(session) =
            authenticator
                .advance(Some(&OpenConnectAuthResponse::Form(values)))
                .await
                .unwrap()
        else {
            panic!("expected session")
        };
        assert_eq!(session.dsid, "session");
        let requests = transport.requests.lock();
        assert_eq!(requests[0].method(), Method::GET);
        assert_eq!(requests[1].method(), Method::POST);
        assert_eq!(
            requests[1].body(),
            b"username=alice&password=secret&realm=users&btnSubmit=Sign+In"
        );
        assert_eq!(requests[1].headers()["x-pad"].as_bytes().len(), 4);
    }

    #[tokio::test]
    async fn exposes_and_resumes_tncc_exchange() {
        let mut host_check = response(StatusCode::OK, b"<html>checking</html>");
        host_check.headers.append(
            SET_COOKIE,
            HeaderValue::from_static("DSPREAUTH=old; Path=/; Secure"),
        );
        host_check.headers.append(
            SET_COOKIE,
            HeaderValue::from_static("DSSIGNIN=/signin; Path=/; Secure"),
        );
        let form = br#"<form name="frmConfirmation" method="post"><input type="submit" name="btnContinue" value="Continue"></form>"#;
        let transport = Arc::new(ScriptedTransport {
            responses: Mutex::new(VecDeque::from([
                host_check,
                response(StatusCode::OK, form),
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "test");
        let mut authenticator = NetworkConnectAuthenticator::new(
            http,
            "vpn.example",
            NetworkConnectAuthenticatorOptions::default(),
        )
        .unwrap();
        let NetworkConnectAuthenticationProgress::Tncc(request) =
            authenticator.advance(None).await.unwrap()
        else {
            panic!("expected TNCC")
        };
        assert_eq!(request.preauthentication_cookie, "old");
        assert_eq!(request.sign_in_url, "/signin");
        assert!(matches!(
            authenticator.resume_tncc("new").await.unwrap(),
            NetworkConnectAuthenticationProgress::Challenge(_)
        ));
        assert!(
            transport.requests.lock()[1].headers()["cookie"]
                .to_str()
                .unwrap()
                .contains("DSPREAUTH=new")
        );
    }

    #[tokio::test]
    async fn direct_cookie_skips_http() {
        let transport = Arc::new(ScriptedTransport {
            responses: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
        });
        let http = AnyConnectAuthHttpClient::new(transport.clone(), "test");
        let mut authenticator = NetworkConnectAuthenticator::new(
            http,
            "192.0.2.30",
            NetworkConnectAuthenticatorOptions {
                direct_cookie: Some("DSID=direct".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let NetworkConnectAuthenticationProgress::Complete(session) =
            authenticator.advance(None).await.unwrap()
        else {
            panic!("expected session")
        };
        assert_eq!(
            session.authenticated_address.unwrap().to_string(),
            "192.0.2.30"
        );
        assert!(transport.requests.lock().is_empty());
    }
}
