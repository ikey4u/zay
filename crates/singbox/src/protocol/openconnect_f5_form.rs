//! F5 HTML and `appLoader.configure` authentication form compatibility.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scraper::{ElementRef, Html, Selector};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F5AuthenticationFieldKind {
    Hidden,
    Text,
    Password,
    Select,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F5AuthenticationChoice {
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F5AuthenticationField {
    pub submission_key: String,
    pub name: String,
    pub label: String,
    pub kind: F5AuthenticationFieldKind,
    pub value: String,
    pub options: Vec<F5AuthenticationChoice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F5AuthenticationForm {
    pub id: String,
    pub action: String,
    pub banner: String,
    pub message: String,
    pub fields: Vec<F5AuthenticationField>,
    pub html: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F5AuthenticationDocument {
    pub form: Option<F5AuthenticationForm>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum F5FormError {
    #[error("invalid F5 authentication form: {0}")]
    Invalid(String),
    #[error("F5 authentication response omitted field {0}")]
    MissingResponse(String),
}

pub fn parse_f5_authentication_document(
    content: &[u8],
) -> Result<F5AuthenticationDocument, F5FormError> {
    let content = std::str::from_utf8(content).map_err(|error| {
        invalid(format!("authentication HTML is not UTF-8: {error}"))
    })?;
    let document = Html::parse_document(content);
    let form_selector = selector("form")?;
    if let Some(form) = document.select(&form_selector).next() {
        return Ok(F5AuthenticationDocument {
            form: Some(parse_html_form(form)?),
            warnings: Vec::new(),
        });
    }
    parse_json_form(&document)
}

pub fn static_f5_authentication_form() -> F5AuthenticationForm {
    let id = "auth_form".to_owned();
    F5AuthenticationForm {
        fields: vec![
            field(
                &id,
                0,
                "username",
                "username:",
                F5AuthenticationFieldKind::Text,
                "",
            ),
            field(
                &id,
                1,
                "password",
                "password:",
                F5AuthenticationFieldKind::Password,
                "",
            ),
        ],
        id,
        action: String::new(),
        banner: String::new(),
        message: String::new(),
        html: false,
    }
}

pub fn encode_f5_authentication_response(
    form: &F5AuthenticationForm,
    values: &BTreeMap<String, String>,
) -> Result<String, F5FormError> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for field in &form.fields {
        let value = values
            .get(&field.submission_key)
            .ok_or_else(|| F5FormError::MissingResponse(field.name.clone()))?;
        serializer.append_pair(&field.name, value);
    }
    Ok(serializer.finish())
}

pub fn is_f5_primary_authentication_form(form: &F5AuthenticationForm) -> bool {
    form.fields.iter().any(|field| {
        field.name == "username"
            && field.kind == F5AuthenticationFieldKind::Text
    }) && form.fields.iter().any(|field| {
        field.name == "password"
            && field.kind == F5AuthenticationFieldKind::Password
    })
}

pub fn f5_form_has_password(form: &F5AuthenticationForm) -> bool {
    form.fields
        .iter()
        .any(|field| field.kind == F5AuthenticationFieldKind::Password)
}

pub fn parse_f5_authentication_expiration(value: &str) -> Option<SystemTime> {
    let parts: Vec<_> = value.split('z').collect();
    if parts.len() < 5 {
        return None;
    }
    let start = parts[3].parse::<u64>().ok()?;
    let duration = parts[4].parse::<u64>().ok()?;
    if start == 0 || duration == 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(start.checked_add(duration)?))
}

fn parse_html_form(
    node: ElementRef<'_>,
) -> Result<F5AuthenticationForm, F5FormError> {
    if !node
        .value()
        .attr("method")
        .is_some_and(|method| method.trim().eq_ignore_ascii_case("post"))
    {
        return Err(invalid("authentication form method is not POST"));
    }
    let mut form = F5AuthenticationForm {
        id: node
            .value()
            .attr("id")
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or("unknown")
            .to_owned(),
        action: node
            .value()
            .attr("action")
            .unwrap_or_default()
            .trim()
            .to_owned(),
        banner: String::new(),
        message: String::new(),
        fields: Vec::new(),
        html: true,
    };
    for descendant in node.descendants() {
        let Some(element) = ElementRef::wrap(descendant) else {
            continue;
        };
        match element.value().name() {
            "input" => {
                if let Some(field) =
                    parse_html_input(&form.id, form.fields.len(), element)?
                {
                    form.fields.push(field);
                }
            }
            "select" => form.fields.push(parse_html_select(
                &form.id,
                form.fields.len(),
                element,
            )?),
            "td" => match element.value().attr("id") {
                Some("credentials_table_header") => form.banner = text(element),
                Some("credentials_table_postheader") => {
                    form.message = text(element)
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(form)
}

fn parse_html_input(
    form_id: &str,
    index: usize,
    node: ElementRef<'_>,
) -> Result<Option<F5AuthenticationField>, F5FormError> {
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
        F5AuthenticationFieldKind::Hidden
    } else if input_type == "password" {
        F5AuthenticationFieldKind::Password
    } else if matches!(input_type.as_str(), "text" | "username" | "email") {
        F5AuthenticationFieldKind::Text
    } else {
        return Ok(None);
    };
    let name = node.value().attr("name").unwrap_or_default().trim();
    if name.is_empty() {
        return Err(invalid("authentication input has no name"));
    }
    Ok(Some(field(
        form_id,
        index,
        name,
        &format!("{name}:"),
        kind,
        node.value().attr("value").unwrap_or_default(),
    )))
}

fn parse_html_select(
    form_id: &str,
    index: usize,
    node: ElementRef<'_>,
) -> Result<F5AuthenticationField, F5FormError> {
    let name = node.value().attr("name").unwrap_or_default().trim();
    if name.is_empty() {
        return Err(invalid("authentication select has no name"));
    }
    let option_selector = selector("option")?;
    let mut options = Vec::new();
    let mut value = String::new();
    let mut explicitly_selected = false;
    for option in node.select(&option_selector) {
        let label = text(option);
        let option_value =
            option.value().attr("value").unwrap_or(&label).to_owned();
        options.push(F5AuthenticationChoice {
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
    Ok(F5AuthenticationField {
        submission_key: submission_key(form_id, index),
        name: name.to_owned(),
        label: name.to_owned(),
        kind: F5AuthenticationFieldKind::Select,
        value,
        options,
    })
}

fn parse_json_form(
    document: &Html,
) -> Result<F5AuthenticationDocument, F5FormError> {
    let script_selector = selector("script")?;
    let mut objects = Vec::new();
    for script in document.select(&script_selector) {
        let script = script.text().collect::<String>();
        if let Some(encoded) = extract_app_loader_object(&script)? {
            objects.push(encoded);
        }
    }
    if objects.is_empty() {
        return Ok(F5AuthenticationDocument {
            form: None,
            warnings: Vec::new(),
        });
    }
    if objects.len() != 1 {
        return Err(invalid(
            "authentication document contains multiple appLoader.configure objects",
        ));
    }
    decode_json_form(&objects[0])
}

pub fn extract_f5_app_loader_object(
    script: &str,
) -> Result<Option<String>, F5FormError> {
    extract_app_loader_object(script)
}

fn extract_app_loader_object(
    script: &str,
) -> Result<Option<String>, F5FormError> {
    const MARKER: &str = "appLoader.configure";
    let Some(marker_index) = script.find(MARKER) else {
        return Ok(None);
    };
    if script[marker_index + MARKER.len()..].contains(MARKER) {
        return Err(invalid(
            "authentication script contains multiple appLoader.configure calls",
        ));
    }
    let bytes = script.as_bytes();
    let mut position = marker_index + MARKER.len();
    skip_js_space(bytes, &mut position);
    if bytes.get(position) != Some(&b'(') {
        return Err(invalid(
            "appLoader.configure call has no opening parenthesis",
        ));
    }
    position += 1;
    skip_js_space(bytes, &mut position);
    if bytes.get(position) != Some(&b'{') {
        return Err(invalid(
            "appLoader.configure call does not start with a JSON object",
        ));
    }
    let start = position;
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    while position < bytes.len() {
        let byte = bytes[position];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        let result = script[start..=position].to_owned();
                        position += 1;
                        skip_js_space(bytes, &mut position);
                        if bytes.get(position) != Some(&b')') {
                            return Err(invalid(
                                "appLoader.configure JSON object has trailing arguments",
                            ));
                        }
                        return Ok(Some(result));
                    }
                }
                _ => {}
            }
        }
        position += 1;
    }
    Err(invalid("appLoader.configure JSON object is incomplete"))
}

fn decode_json_form(
    encoded: &str,
) -> Result<F5AuthenticationDocument, F5FormError> {
    let root: Value = serde_json::from_str(encoded).map_err(|error| {
        invalid(format!("decode appLoader.configure JSON object: {error}"))
    })?;
    let form = root
        .get("logon")
        .and_then(|value| value.get("form"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid("appLoader.configure logon has no form object")
        })?;
    let id = required_string(form.get("id"), "form id")?;
    let banner = optional_string(form.get("title"), "form title")?;
    let fields =
        form.get("fields")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid("appLoader.configure form has no fields array")
            })?;
    let mut decoded_fields = Vec::with_capacity(fields.len());
    let mut warnings = Vec::new();
    for (index, encoded_field) in fields.iter().enumerate() {
        let encoded_field = encoded_field.as_object().ok_or_else(|| {
            invalid(format!("authentication field {index} is not an object"))
        })?;
        let field_type =
            required_string(encoded_field.get("type"), "field type")?;
        let name = required_string(encoded_field.get("name"), "field name")?;
        let caption =
            optional_string(encoded_field.get("caption"), "field caption")?;
        let value = optional_string(encoded_field.get("value"), "field value")?;
        if let Some(disabled) = encoded_field.get("disabled")
            && !disabled.is_boolean()
        {
            return Err(invalid(
                "appLoader.configure disabled marker is not boolean",
            ));
        }
        let kind = match field_type.as_str() {
            "text" => F5AuthenticationFieldKind::Text,
            "password" => F5AuthenticationFieldKind::Password,
            other => {
                warnings.push(format!(
                    "Unknown F5 JSON authentication field type {other}; treating it as text"
                ));
                F5AuthenticationFieldKind::Text
            }
        };
        decoded_fields.push(field(
            &id,
            index,
            &name,
            &format!("{}:", if caption.is_empty() { &name } else { &caption }),
            kind,
            &value,
        ));
    }
    Ok(F5AuthenticationDocument {
        form: Some(F5AuthenticationForm {
            id,
            action: String::new(),
            banner,
            message: String::new(),
            fields: decoded_fields,
            html: false,
        }),
        warnings,
    })
}

fn required_string(
    value: Option<&Value>,
    description: &str,
) -> Result<String, F5FormError> {
    let value = optional_string(value, description)?;
    if value.is_empty() {
        Err(invalid(format!(
            "appLoader.configure {description} is empty"
        )))
    } else {
        Ok(value)
    }
}

fn optional_string(
    value: Option<&Value>,
    description: &str,
) -> Result<String, F5FormError> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(invalid(format!(
            "appLoader.configure {description} is not a string"
        ))),
    }
}

fn field(
    form_id: &str,
    index: usize,
    name: &str,
    label: &str,
    kind: F5AuthenticationFieldKind,
    value: &str,
) -> F5AuthenticationField {
    F5AuthenticationField {
        submission_key: submission_key(form_id, index),
        name: name.to_owned(),
        label: label.to_owned(),
        kind,
        value: value.to_owned(),
        options: Vec::new(),
    }
}

fn submission_key(form_id: &str, index: usize) -> String {
    format!("f5:{form_id}:{index}")
}

fn selector(value: &str) -> Result<Selector, F5FormError> {
    Selector::parse(value)
        .map_err(|_| invalid(format!("invalid internal selector: {value}")))
}

fn text(element: ElementRef<'_>) -> String {
    element.text().collect::<String>().trim().to_owned()
}

fn skip_js_space(bytes: &[u8], position: &mut usize) {
    while bytes
        .get(*position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        *position += 1;
    }
}

fn invalid(message: impl Into<String>) -> F5FormError {
    F5FormError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_form_preserves_dom_order_banner_and_selected_value() {
        let parsed = parse_f5_authentication_document(br#"
          <form id="logon" method="POST" action="/my.policy">
            <table><tbody><tr><td id="credentials_table_header"> Welcome </td></tr></tbody></table>
            <input type="hidden" name="csrf" value="secret">
            <input type="text" name="username"><input type="password" name="password">
            <select name="domain"><option value="a">A</option><option value="b" selected>B</option></select>
            <table><tbody><tr><td id="credentials_table_postheader"> Try again </td></tr></tbody></table>
          </form>"#).unwrap();
        let form = parsed.form.unwrap();
        assert_eq!(form.id, "logon");
        assert_eq!(form.action, "/my.policy");
        assert_eq!(form.banner, "Welcome");
        assert_eq!(form.message, "Try again");
        assert_eq!(
            form.fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["csrf", "username", "password", "domain"]
        );
        assert_eq!(form.fields[3].value, "b");
        assert!(is_f5_primary_authentication_form(&form));
    }

    #[test]
    fn json_app_loader_form_and_unknown_field_warning_are_parsed() {
        let parsed = parse_f5_authentication_document(br#"<script>
          appLoader.configure({"logon":{"form":{"id":"json","title":"Sign in","fields":[
            {"type":"text","name":"username","caption":"User","value":"alice","disabled":false},
            {"type":"password","name":"password"},{"type":"otp","name":"otp"}
          ]}}});
        </script>"#).unwrap();
        let form = parsed.form.unwrap();
        assert_eq!(form.id, "json");
        assert_eq!(form.banner, "Sign in");
        assert_eq!(form.fields[0].label, "User:");
        assert_eq!(form.fields[0].value, "alice");
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn extraction_handles_braces_and_escapes_inside_strings() {
        assert_eq!(
            extract_f5_app_loader_object(
                r#"x appLoader.configure( {"x":"}\\\"{"} ) ;"#
            )
            .unwrap()
            .unwrap(),
            r#"{"x":"}\\\"{"}"#
        );
        assert!(
            extract_f5_app_loader_object("nothing here")
                .unwrap()
                .is_none()
        );
        assert!(
            extract_f5_app_loader_object("appLoader.configure({} , 1)")
                .is_err()
        );
    }

    #[test]
    fn response_is_form_encoded_in_field_order() {
        let form = static_f5_authentication_form();
        let values = BTreeMap::from([
            ("f5:auth_form:0".into(), "a b@example.com".into()),
            ("f5:auth_form:1".into(), "p&=".into()),
        ]);
        assert_eq!(
            encode_f5_authentication_response(&form, &values).unwrap(),
            "username=a+b%40example.com&password=p%26%3D"
        );
        assert!(
            encode_f5_authentication_response(&form, &BTreeMap::new()).is_err()
        );
    }

    #[test]
    fn f5_st_expiration_requires_positive_safe_fields() {
        assert_eq!(
            parse_f5_authentication_expiration("azbzcz100z20")
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap(),
            Duration::from_secs(120)
        );
        assert!(parse_f5_authentication_expiration("azbzcz0z20").is_none());
        assert!(parse_f5_authentication_expiration("bad").is_none());
    }

    #[test]
    fn invalid_html_and_json_forms_fail_closed() {
        assert!(
            parse_f5_authentication_document(b"<form method='GET'></form>")
                .is_err()
        );
        assert!(
            parse_f5_authentication_document(
                b"<form method='POST'><input type='text'></form>"
            )
            .is_err()
        );
        assert!(
            parse_f5_authentication_document(
                b"<script>appLoader.configure({bad})</script>"
            )
            .is_err()
        );
    }
}
