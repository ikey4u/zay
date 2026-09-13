//! Stateless GlobalProtect authentication request compatibility.

use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use url::Url;

use super::{
    GlobalProtectFailureClass, encode_globalprotect_form_component,
    globalprotect_client_os,
};

pub const GLOBALPROTECT_USER_AGENT: &str = "PAN GlobalProtect";
pub const GLOBALPROTECT_MAXIMUM_AUTHENTICATION_BODY: usize = 16 * 1024 * 1024;
pub const GLOBALPROTECT_MAXIMUM_AUTHENTICATION_REQUESTS: usize = 64;
pub const GLOBALPROTECT_MAXIMUM_AUTHENTICATION_REDIRECTS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalProtectInterface {
    Portal,
    Gateway,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectServerTarget {
    pub url: Url,
    pub interface: GlobalProtectInterface,
    pub automatic_interface: bool,
    pub alternate_secret: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GlobalProtectAuthWireError {
    #[error("invalid GlobalProtect server URL: {0}")]
    InvalidServer(String),
    #[error("unsupported GlobalProtect server path: {0}")]
    UnsupportedPath(String),
    #[error("GlobalProtect alternate secret field name is empty")]
    EmptyAlternateSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectPreloginRequest {
    pub url: Url,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalProtectLoginRequestOptions {
    pub interface: GlobalProtectInterface,
    pub server_url: Url,
    pub reported_os: String,
    pub local_hostname: String,
    pub ipv6_disabled: bool,
    pub portal_user_auth_cookie: String,
    pub portal_prelogon_user_auth_cookie: String,
    pub previous_ipv4: Option<Ipv4Addr>,
    pub previous_ipv6: Option<Ipv6Addr>,
    pub input_string: String,
    pub username: String,
    pub secret_name: String,
    pub secret: String,
}

pub fn parse_globalprotect_server_target(
    server: &str,
) -> Result<GlobalProtectServerTarget, GlobalProtectAuthWireError> {
    let mut url = if server.contains("://") {
        Url::parse(server)
    } else {
        Url::parse(&format!("https://{server}"))
    }
    .map_err(|error| {
        GlobalProtectAuthWireError::InvalidServer(error.to_string())
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GlobalProtectAuthWireError::InvalidServer(server.into()));
    }

    let mut server_path = url.path().trim_matches('/').to_owned();
    let mut alternate_secret = String::new();
    if let Some((path, secret)) = server_path.rsplit_once(':') {
        if secret.is_empty() {
            return Err(GlobalProtectAuthWireError::EmptyAlternateSecret);
        }
        let path = path.to_owned();
        alternate_secret = secret.to_owned();
        server_path = path;
    }
    let (interface, automatic_interface) = match server_path.as_str() {
        "" => (GlobalProtectInterface::Portal, true),
        "portal" | "global-protect" => (GlobalProtectInterface::Portal, false),
        "gateway" | "ssl-vpn" => (GlobalProtectInterface::Gateway, false),
        _ => {
            return Err(GlobalProtectAuthWireError::UnsupportedPath(
                url.path().into(),
            ));
        }
    };
    url.set_path("");
    Ok(GlobalProtectServerTarget {
        url,
        interface,
        automatic_interface,
        alternate_secret,
    })
}

pub fn build_globalprotect_prelogin_request(
    server_url: &Url,
    interface: GlobalProtectInterface,
    reported_os: &str,
    external_auth_disabled: bool,
) -> GlobalProtectPreloginRequest {
    let mut url = server_url.clone();
    url.set_path(match interface {
        GlobalProtectInterface::Portal => "/global-protect/prelogin.esp",
        GlobalProtectInterface::Gateway => "/ssl-vpn/prelogin.esp",
    });
    url.set_query(Some(&format!(
        "tmp=tmp&clientVer=4100&clientos={}",
        encode_globalprotect_form_component(globalprotect_client_os(
            reported_os
        ))
    )));
    GlobalProtectPreloginRequest {
        url,
        body: if external_auth_disabled {
            Vec::new()
        } else {
            b"cas-support=yes".to_vec()
        },
    }
}

pub fn build_globalprotect_login_request(
    options: &GlobalProtectLoginRequestOptions,
) -> (Url, Vec<u8>) {
    let mut url = options.server_url.clone();
    url.set_path(match options.interface {
        GlobalProtectInterface::Portal => "/global-protect/getconfig.esp",
        GlobalProtectInterface::Gateway => "/ssl-vpn/login.esp",
    });
    url.set_query(None);
    url.set_fragment(None);
    let mut values = vec![
        ("jnlpReady", "jnlpReady".to_owned()),
        ("ok", "Login".to_owned()),
        ("direct", "yes".to_owned()),
        ("clientVer", "4100".to_owned()),
        ("prot", "https:".to_owned()),
        ("internal", "no".to_owned()),
        (
            "ipv6-support",
            if options.ipv6_disabled { "no" } else { "yes" }.into(),
        ),
        (
            "clientos",
            globalprotect_client_os(&options.reported_os).into(),
        ),
        ("os-version", options.reported_os.clone()),
        (
            "server",
            options.server_url.host_str().unwrap_or_default().into(),
        ),
        ("computer", options.local_hostname.clone()),
    ];
    if !options.portal_user_auth_cookie.is_empty() {
        values.push((
            "portal-userauthcookie",
            options.portal_user_auth_cookie.clone(),
        ));
    }
    if !options.portal_prelogon_user_auth_cookie.is_empty() {
        values.push((
            "portal-prelogonuserauthcookie",
            options.portal_prelogon_user_auth_cookie.clone(),
        ));
    }
    if let Some(address) = options.previous_ipv4 {
        values.push(("preferred-ip", address.to_string()));
    }
    if !options.ipv6_disabled
        && let Some(address) = options.previous_ipv6
    {
        values.push(("preferred-ipv6", address.to_string()));
    }
    if !options.input_string.is_empty() {
        values.push(("inputStr", options.input_string.clone()));
    }
    values.push(("user", options.username.clone()));
    values.push((options.secret_name.as_str(), options.secret.clone()));
    (url, encode_globalprotect_form(&values))
}

pub fn encode_globalprotect_form(values: &[(&str, String)]) -> Vec<u8> {
    values
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                encode_globalprotect_form_component(name),
                encode_globalprotect_form_component(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

pub fn classify_globalprotect_auth_http_status(
    status: u16,
) -> GlobalProtectFailureClass {
    match status {
        401 | 403 | 513 => GlobalProtectFailureClass::AuthenticationFailed,
        405 => GlobalProtectFailureClass::ProtocolUnsupported,
        512 => GlobalProtectFailureClass::Retryable,
        408 | 425 | 429 | 500..=599 => GlobalProtectFailureClass::Retryable,
        _ => GlobalProtectFailureClass::Terminal,
    }
}

pub const fn is_globalprotect_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_interface_aliases_and_alternate_secret() {
        let automatic =
            parse_globalprotect_server_target("vpn.example").unwrap();
        assert_eq!(automatic.interface, GlobalProtectInterface::Portal);
        assert!(automatic.automatic_interface);

        let gateway = parse_globalprotect_server_target(
            "https://vpn.example/ssl-vpn:otp",
        )
        .unwrap();
        assert_eq!(gateway.interface, GlobalProtectInterface::Gateway);
        assert!(!gateway.automatic_interface);
        assert_eq!(gateway.alternate_secret, "otp");
        assert_eq!(gateway.url.as_str(), "https://vpn.example/");
    }

    #[test]
    fn builds_portal_and_gateway_prelogin_targets() {
        let server = Url::parse("https://vpn.example:4443/").unwrap();
        let portal = build_globalprotect_prelogin_request(
            &server,
            GlobalProtectInterface::Portal,
            "linux-64",
            false,
        );
        assert_eq!(
            portal.url.as_str(),
            "https://vpn.example:4443/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux"
        );
        assert_eq!(portal.body, b"cas-support=yes");
        let gateway = build_globalprotect_prelogin_request(
            &server,
            GlobalProtectInterface::Gateway,
            "win",
            true,
        );
        assert_eq!(gateway.url.path(), "/ssl-vpn/prelogin.esp");
        assert!(gateway.body.is_empty());
    }

    #[test]
    fn login_form_has_upstream_order_and_optional_values() {
        let (url, body) = build_globalprotect_login_request(
            &GlobalProtectLoginRequestOptions {
                interface: GlobalProtectInterface::Gateway,
                server_url: Url::parse("https://vpn.example/").unwrap(),
                reported_os: "linux-64".into(),
                local_hostname: "host one".into(),
                ipv6_disabled: false,
                portal_user_auth_cookie: "portal/cookie".into(),
                portal_prelogon_user_auth_cookie: String::new(),
                previous_ipv4: Some("10.0.0.2".parse().unwrap()),
                previous_ipv6: Some("2001:db8::2".parse().unwrap()),
                input_string: "challenge state".into(),
                username: "alice@example".into(),
                secret_name: "passwd".into(),
                secret: "p a/s".into(),
            },
        );
        assert_eq!(url.path(), "/ssl-vpn/login.esp");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "jnlpReady=jnlpReady&ok=Login&direct=yes&clientVer=4100&prot=https%3a&internal=no&ipv6-support=yes&clientos=Linux&os-version=linux-64&server=vpn.example&computer=host%20one&portal-userauthcookie=portal%2fcookie&preferred-ip=10.0.0.2&preferred-ipv6=2001%3adb8%3a%3a2&inputStr=challenge%20state&user=alice%40example&passwd=p%20a%2fs"
        );
    }
}
