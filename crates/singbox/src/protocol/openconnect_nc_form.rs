//! Juniper Network Connect HTML authentication forms.
//!
//! The gateway predates the XML form protocol used by AnyConnect.  It uses a
//! small, vendor-specific set of HTML form identities plus a role-selection
//! page whose choices are links rather than `<option>` elements.

use std::collections::BTreeMap;

use scraper::{ElementRef, Html, Selector};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkConnectAuthenticationFieldKind {
    Hidden,
    Text,
    Password,
    Select,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectAuthenticationChoice {
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectAuthenticationField {
    pub submission_key: String,
    pub name: String,
    pub label: String,
    pub kind: NetworkConnectAuthenticationFieldKind,
    pub value: String,
    pub options: Vec<NetworkConnectAuthenticationChoice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectAuthenticationForm {
    pub id: String,
    pub action: String,
    pub banner: String,
    pub message: String,
    pub fields: Vec<NetworkConnectAuthenticationField>,
    pub role_form: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkConnectFormError {
    #[error("invalid Network Connect authentication form: {0}")]
    Invalid(String),
    #[error("Network Connect authentication response omitted field {0}")]
    MissingResponse(String),
}

/// Parse the first HTML form exactly as the Network Connect frontend does.
/// A document without a form is a valid intermediate TNCC response.
pub fn parse_network_connect_authentication_document(
    content: &[u8],
) -> Result<Option<NetworkConnectAuthenticationForm>, NetworkConnectFormError> {
    let content = String::from_utf8_lossy(content);
    let document = Html::parse_document(&content);
    let form_selector = selector("form")?;
    let Some(node) = document.select(&form_selector).next() else {
        return Ok(None);
    };

    let form_name = node.value().attr("name").unwrap_or_default().trim();
    let form_id = node.value().attr("id").unwrap_or_default().trim();
    let identifier = if form_name.is_empty() {
        form_id
    } else {
        form_name
    };
    if identifier.is_empty() {
        return Err(invalid("authentication form has no name or ID"));
    }
    if identifier == "frmSelectRoles" {
        return parse_role_form(node).map(Some);
    }
    if !node
        .value()
        .attr("method")
        .is_some_and(|method| method.trim().eq_ignore_ascii_case("post"))
    {
        return Err(invalid(format!(
            "authentication form method is not POST: {identifier}"
        )));
    }

    let mut form = NetworkConnectAuthenticationForm {
        id: identifier.to_owned(),
        action: node
            .value()
            .attr("action")
            .unwrap_or_default()
            .trim()
            .to_owned(),
        banner: identifier.to_owned(),
        message: String::new(),
        fields: Vec::new(),
        role_form: false,
    };
    for descendant in node.descendants() {
        let Some(element) = ElementRef::wrap(descendant) else {
            continue;
        };
        match element.value().name() {
            "input" => {
                if let Some(field) =
                    parse_input(&form.id, form.fields.len(), element)?
                {
                    form.fields.push(field);
                }
            }
            "select" => form.fields.push(parse_select(
                &form.id,
                form.fields.len(),
                element,
            )?),
            "textarea" => {
                let name = element.value().attr("name").unwrap_or_default();
                if name.eq_ignore_ascii_case("sn-postauth-text")
                    || name.eq_ignore_ascii_case("sn-preauth-text")
                {
                    form.banner = text(element);
                }
            }
            _ => {}
        }
    }
    Ok(Some(form))
}

pub fn validate_network_connect_authentication_form(
    form: &NetworkConnectAuthenticationForm,
) -> Result<(), NetworkConnectFormError> {
    if matches!(
        form.id.as_str(),
        "frmLogin"
            | "loginForm"
            | "frmDefender"
            | "frmNextToken"
            | "frmConfirmation"
            | "frmSelectRoles"
            | "frmTotpToken"
            | "hiddenform"
            | "formSAMLSSO"
    ) {
        return Ok(());
    }
    if form.action.contains("remediate.cgi") {
        return Err(invalid(
            "TNCC or Host Checker failed; remediation form returned by gateway",
        ));
    }
    Err(invalid(format!(
        "unknown Network Connect authentication form: {}",
        form.id
    )))
}

pub fn encode_network_connect_authentication_response(
    form: &NetworkConnectAuthenticationForm,
    values: &BTreeMap<String, String>,
) -> Result<String, NetworkConnectFormError> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for field in &form.fields {
        let value = values.get(&field.submission_key).ok_or_else(|| {
            NetworkConnectFormError::MissingResponse(field.name.clone())
        })?;
        serializer.append_pair(&field.name, value);
    }
    Ok(serializer.finish())
}

pub fn network_connect_primary_authentication_form(
    form: &NetworkConnectAuthenticationForm,
) -> bool {
    matches!(form.id.as_str(), "frmLogin" | "loginForm")
        && form.fields.iter().any(|field| {
            field.kind == NetworkConnectAuthenticationFieldKind::Password
        })
}

pub fn network_connect_token_password_field(
    form_id: &str,
    password_number: usize,
) -> bool {
    match form_id {
        "frmLogin" | "loginForm" => password_number > 1,
        "frmDefender" | "frmNextToken" | "frmTotpToken" => true,
        _ => false,
    }
}

pub fn network_connect_submission_key(
    form_id: &str,
    field_index: usize,
) -> String {
    format!("nc:{form_id}:{field_index}")
}

fn parse_input(
    form_id: &str,
    index: usize,
    node: ElementRef<'_>,
) -> Result<Option<NetworkConnectAuthenticationField>, NetworkConnectFormError>
{
    let Some(input_type) = node.value().attr("type") else {
        return Ok(None);
    };
    let input_type = input_type.trim().to_ascii_lowercase();
    let hidden_style = node.value().attr("style").is_some_and(|style| {
        style.trim().eq_ignore_ascii_case("display: none;")
    });
    let kind = if hidden_style
        || matches!(input_type.as_str(), "hidden" | "checkbox")
    {
        NetworkConnectAuthenticationFieldKind::Hidden
    } else if input_type == "password" {
        NetworkConnectAuthenticationFieldKind::Password
    } else if matches!(input_type.as_str(), "text" | "username" | "email") {
        NetworkConnectAuthenticationFieldKind::Text
    } else if input_type == "submit" {
        let name = node.value().attr("name").unwrap_or_default().trim();
        if !submit_field_retained(form_id, name) {
            return Ok(None);
        }
        NetworkConnectAuthenticationFieldKind::Hidden
    } else {
        return Ok(None);
    };
    let name = node.value().attr("name").unwrap_or_default().trim();
    if name.is_empty() {
        return Err(invalid(format!(
            "authentication input has no name in form {form_id}"
        )));
    }
    Ok(Some(NetworkConnectAuthenticationField {
        submission_key: network_connect_submission_key(form_id, index),
        name: name.to_owned(),
        label: format!("{name}:"),
        kind,
        value: node.value().attr("value").unwrap_or_default().to_owned(),
        options: Vec::new(),
    }))
}

fn parse_select(
    form_id: &str,
    index: usize,
    node: ElementRef<'_>,
) -> Result<NetworkConnectAuthenticationField, NetworkConnectFormError> {
    let name = node.value().attr("name").unwrap_or_default().trim();
    if name.is_empty() {
        return Err(invalid(format!(
            "authentication select has no name in form {form_id}"
        )));
    }
    let option_selector = selector("option")?;
    let mut options = Vec::new();
    let mut value = String::new();
    let mut explicitly_selected = false;
    for option in node.select(&option_selector) {
        let label = text(option);
        let option_value =
            option.value().attr("value").unwrap_or(&label).to_owned();
        options.push(NetworkConnectAuthenticationChoice {
            value: option_value.clone(),
            label,
        });
        let selected = option.value().attr("selected").is_some();
        if !explicitly_selected && (selected || options.len() == 1) {
            value = option_value;
            explicitly_selected = selected;
        }
    }
    if options.is_empty() {
        return Err(invalid(format!(
            "authentication select has no choices: {name}"
        )));
    }
    Ok(NetworkConnectAuthenticationField {
        submission_key: network_connect_submission_key(form_id, index),
        name: name.to_owned(),
        label: name.to_owned(),
        kind: NetworkConnectAuthenticationFieldKind::Select,
        value,
        options,
    })
}

fn parse_role_form(
    form: ElementRef<'_>,
) -> Result<NetworkConnectAuthenticationForm, NetworkConnectFormError> {
    let table_selector = selector("table#TABLE_SelectRole_1")?;
    let table = form
        .select(&table_selector)
        .next()
        .ok_or_else(|| invalid("role form has no TABLE_SelectRole_1 table"))?;
    let link_selector = selector("a")?;
    let options: Vec<_> = table
        .select(&link_selector)
        .filter_map(|link| {
            let value = link.value().attr("href")?.trim();
            let label = text(link);
            (!value.is_empty() && !label.is_empty()).then(|| {
                NetworkConnectAuthenticationChoice {
                    value: value.to_owned(),
                    label,
                }
            })
        })
        .collect();
    let Some(first) = options.first() else {
        return Err(invalid("role form has no selectable roles"));
    };
    Ok(NetworkConnectAuthenticationForm {
        id: "frmSelectRoles".to_owned(),
        action: String::new(),
        banner: "frmSelectRoles".to_owned(),
        message: String::new(),
        fields: vec![NetworkConnectAuthenticationField {
            submission_key: network_connect_submission_key("frmSelectRoles", 0),
            name: "frmSelectRoles".to_owned(),
            label: "frmSelectRoles".to_owned(),
            kind: NetworkConnectAuthenticationFieldKind::Select,
            value: first.value.clone(),
            options,
        }],
        role_form: true,
    })
}

fn submit_field_retained(form_id: &str, name: &str) -> bool {
    let expected = match form_id {
        "frmLogin" => "btnSubmit",
        "loginForm" => "submitButton",
        "frmDefender" | "frmNextToken" => "btnAction",
        "frmConfirmation" => "btnContinue",
        "frmTotpToken" => "totpactionEnter",
        "hiddenform" | "formSAMLSSO" => "submit",
        _ => "",
    };
    !name.is_empty()
        && (name == expected
            || matches!(
                name,
                "sn-postauth-proceed"
                    | "sn-preauth-proceed"
                    | "secidactionEnter"
            ))
}

fn selector(value: &str) -> Result<Selector, NetworkConnectFormError> {
    Selector::parse(value)
        .map_err(|error| invalid(format!("invalid HTML selector: {error}")))
}

fn text(node: ElementRef<'_>) -> String {
    node.text().collect::<String>().trim().to_owned()
}

fn invalid(message: impl Into<String>) -> NetworkConnectFormError {
    NetworkConnectFormError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_form_and_encodes_all_retained_fields() {
        let html = br#"
            <form name="frmLogin" method="POST" action="/dana-na/auth/url_default/login.cgi">
              <textarea name="sn-preauth-text"> Welcome to VPN </textarea>
              <input type="hidden" name="tz_offset" value="60">
              <input type="text" name="username">
              <input type="password" name="password">
              <input type="password" name="token">
              <select name="realm">
                <option value="employees">Employees</option>
                <option value="contractors" selected>Contractors</option>
              </select>
              <input type="submit" name="ignored" value="Ignore">
              <input type="submit" name="btnSubmit" value="Sign In">
            </form>
        "#;
        let form = parse_network_connect_authentication_document(html)
            .unwrap()
            .unwrap();
        assert_eq!(form.id, "frmLogin");
        assert_eq!(form.banner, "Welcome to VPN");
        assert_eq!(form.fields.len(), 6);
        assert_eq!(form.fields[4].value, "contractors");
        assert!(network_connect_primary_authentication_form(&form));
        assert!(!network_connect_token_password_field("frmLogin", 1));
        assert!(network_connect_token_password_field("frmLogin", 2));

        let values = form
            .fields
            .iter()
            .map(|field| {
                (
                    field.submission_key.clone(),
                    if field.name == "username" {
                        "user+name".to_owned()
                    } else {
                        field.value.clone()
                    },
                )
            })
            .collect();
        assert_eq!(
            encode_network_connect_authentication_response(&form, &values)
                .unwrap(),
            "tz_offset=60&username=user%2Bname&password=&token=&realm=contractors&btnSubmit=Sign+In"
        );
        validate_network_connect_authentication_form(&form).unwrap();
    }

    #[test]
    fn parses_link_based_role_form() {
        let html = br#"
            <form id="frmSelectRoles">
              <a href="/outside">Outside table</a>
              <table id="TABLE_SelectRole_1">
                <tr><td><a href="/dana-na/auth/url_1/welcome.cgi?p=1"> Admin </a></td></tr>
                <tr><td><a href="/dana-na/auth/url_2/welcome.cgi">User</a></td></tr>
              </table>
            </form>
        "#;
        let form = parse_network_connect_authentication_document(html)
            .unwrap()
            .unwrap();
        assert!(form.role_form);
        assert_eq!(form.fields[0].options.len(), 2);
        assert_eq!(form.fields[0].options[0].label, "Admin");
        assert_eq!(form.fields[0].value, "/dana-na/auth/url_1/welcome.cgi?p=1");
    }

    #[test]
    fn rejects_unknown_and_remediation_forms() {
        let unknown = parse_network_connect_authentication_document(
            br#"<form name="surprise" method="post"></form>"#,
        )
        .unwrap()
        .unwrap();
        assert!(
            validate_network_connect_authentication_form(&unknown)
                .unwrap_err()
                .to_string()
                .contains("unknown")
        );
        let remediation = parse_network_connect_authentication_document(
            br#"<form name="failed" method="post" action="/remediate.cgi"></form>"#,
        )
        .unwrap()
        .unwrap();
        assert!(
            validate_network_connect_authentication_form(&remediation)
                .unwrap_err()
                .to_string()
                .contains("remediation")
        );
    }

    #[test]
    fn permits_formless_tncc_intermediate_document() {
        assert_eq!(
            parse_network_connect_authentication_document(
                b"<html><body>Host Checker</body></html>"
            )
            .unwrap(),
            None
        );
    }
}
