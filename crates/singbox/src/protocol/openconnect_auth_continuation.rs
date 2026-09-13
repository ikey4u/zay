//! AnyConnect form prefill and challenge continuation.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::{
    AnyConnectAuthError, AnyConnectAuthFieldKind, AnyConnectAuthForm,
    OpenConnectAuthChallenge, OpenConnectAuthChallengeKind,
    OpenConnectAuthPromptChoice, OpenConnectAuthPromptField,
    OpenConnectAuthPromptForm, OpenConnectAuthPromptKind,
    OpenConnectAuthResponse, apply_anyconnect_auth_group,
    new_openconnect_auth_challenge, reorder_anyconnect_auth_group,
    validate_openconnect_form_response,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectAuthFormEntry {
    pub form_id: String,
    pub submission_key: String,
    pub name: String,
    pub value: String,
    pub promote: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectCredentialCache {
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth_group: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyConnectAuthPrefillOptions {
    pub credentials: AnyConnectCredentialCache,
    pub form_entries: Vec<AnyConnectAuthFormEntry>,
    /// Configured software-token mode (`totp`, `hotp`, or `stoken`).
    pub token_type: Option<String>,
    /// Value produced by TOTP/HOTP/SecurID for a field already classified as
    /// `Token`. Token generation remains a separate reusable library concern.
    pub generated_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyConnectPreparedAuthForm {
    pub form: AnyConnectAuthForm,
    pub challenge: Option<OpenConnectAuthChallenge>,
    automatic_values: BTreeMap<String, String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnyConnectAuthContinuationError {
    #[error(transparent)]
    Validation(#[from] AnyConnectAuthError),
    #[error("duplicate openconnect authentication submission key: {0}")]
    DuplicateSubmissionKey(String),
    #[error("token field has no automatic token generator: {0}")]
    MissingToken(String),
    #[error("unsupported openconnect authentication field kind: {0:?}")]
    UnsupportedFieldKind(AnyConnectAuthFieldKind),
    #[error("authentication response is missing")]
    MissingResponse,
    #[error("authentication response type does not match the pending form")]
    ResponseTypeMismatch,
}

/// Convert a parsed vendor form into either an automatic reply or a public,
/// validated challenge suitable for zay's UI.
pub fn prepare_anyconnect_auth_form(
    mut form: AnyConnectAuthForm,
    options: &AnyConnectAuthPrefillOptions,
) -> Result<AnyConnectPreparedAuthForm, AnyConnectAuthContinuationError> {
    reorder_anyconnect_auth_group(&mut form);
    if let Some(group) = options.credentials.auth_group.as_deref()
        && let Some(field) = form.fields.iter().find(|field| {
            field.name == "group_list"
                && field.kind == AnyConnectAuthFieldKind::Select
        })
        && field
            .choices
            .iter()
            .any(|choice| choice.name == group || choice.label == group)
    {
        apply_anyconnect_auth_group(&mut form, group);
    }

    let mut automatic_values = BTreeMap::new();
    let mut visible_fields = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut all_visible_automatic = true;

    for field in &form.fields {
        if field.ignore || field.kind == AnyConnectAuthFieldKind::SsoToken {
            continue;
        }
        if !seen_keys.insert(field.submission_key.clone()) {
            return Err(
                AnyConnectAuthContinuationError::DuplicateSubmissionKey(
                    field.submission_key.clone(),
                ),
            );
        }

        let entry = find_form_entry(
            &options.form_entries,
            &form.authentication_id,
            &field.submission_key,
            &field.name,
        );
        let promote = entry.is_some_and(|entry| entry.promote);
        let (mut value, mut automatic) = prefill_field(field, options);
        if let Some(entry) = entry
            && !entry.promote
        {
            value.clone_from(&entry.value);
            automatic = true;
        }

        if field.kind == AnyConnectAuthFieldKind::Token {
            let token = options.generated_token.as_ref().ok_or_else(|| {
                AnyConnectAuthContinuationError::MissingToken(
                    field.name.clone(),
                )
            })?;
            automatic_values
                .insert(field.submission_key.clone(), token.clone());
            continue;
        }
        if field.kind == AnyConnectAuthFieldKind::Hidden && !promote {
            automatic_values.insert(field.submission_key.clone(), value);
            continue;
        }

        let kind = match field.kind {
            AnyConnectAuthFieldKind::Text | AnyConnectAuthFieldKind::Hidden => {
                OpenConnectAuthPromptKind::Text
            }
            AnyConnectAuthFieldKind::Password => {
                OpenConnectAuthPromptKind::Password
            }
            AnyConnectAuthFieldKind::Select => {
                OpenConnectAuthPromptKind::Select
            }
            other => {
                return Err(
                    AnyConnectAuthContinuationError::UnsupportedFieldKind(
                        other,
                    ),
                );
            }
        };
        if kind == OpenConnectAuthPromptKind::Select
            && automatic
            && !field.choices.iter().any(|choice| choice.name == value)
        {
            automatic = false;
        }
        if automatic {
            automatic_values
                .insert(field.submission_key.clone(), value.clone());
        } else {
            all_visible_automatic = false;
        }
        visible_fields.push(OpenConnectAuthPromptField {
            submission_key: field.submission_key.clone(),
            name: field.name.clone(),
            label: field.label.clone(),
            kind,
            value,
            options: field
                .choices
                .iter()
                .map(|choice| OpenConnectAuthPromptChoice {
                    value: choice.name.clone(),
                    label: choice.label.clone(),
                })
                .collect(),
        });
    }

    let challenge = if visible_fields.is_empty() || all_visible_automatic {
        None
    } else {
        Some(new_openconnect_auth_challenge(
            form.banner.clone(),
            form.message.clone(),
            form.error.clone(),
            OpenConnectAuthChallengeKind::Form(OpenConnectAuthPromptForm {
                fields: visible_fields,
            }),
        ))
    };
    Ok(AnyConnectPreparedAuthForm {
        form,
        challenge,
        automatic_values,
    })
}

/// Validate a challenge response and apply all automatic and visible values to
/// the original parsed form in wire order.
pub fn complete_anyconnect_auth_form(
    mut prepared: AnyConnectPreparedAuthForm,
    response: Option<OpenConnectAuthResponse>,
) -> Result<AnyConnectAuthForm, AnyConnectAuthContinuationError> {
    let mut values = prepared.automatic_values;
    match (&prepared.challenge, response) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(AnyConnectAuthContinuationError::ResponseTypeMismatch);
        }
        (Some(challenge), Some(OpenConnectAuthResponse::Form(response))) => {
            let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind
            else {
                return Err(
                    AnyConnectAuthContinuationError::ResponseTypeMismatch,
                );
            };
            validate_openconnect_form_response(&prompt.fields, &response)?;
            values.extend(response);
        }
        (Some(_), Some(OpenConnectAuthResponse::Browser(_))) => {
            return Err(AnyConnectAuthContinuationError::ResponseTypeMismatch);
        }
        (Some(_), None) => {
            return Err(AnyConnectAuthContinuationError::MissingResponse);
        }
    }

    for field in &mut prepared.form.fields {
        if field.ignore || field.kind == AnyConnectAuthFieldKind::SsoToken {
            continue;
        }
        let value = values.get(&field.submission_key).ok_or_else(|| {
            AnyConnectAuthError::MissingSubmissionKey(
                field.submission_key.clone(),
            )
        })?;
        if field.kind == AnyConnectAuthFieldKind::Select {
            let choice = field
                .choices
                .iter()
                .find(|choice| choice.name == *value || choice.label == *value)
                .ok_or_else(|| {
                    AnyConnectAuthError::InvalidSelection(
                        field.submission_key.clone(),
                    )
                })?;
            field.value.clone_from(&choice.name);
        } else {
            field.value.clone_from(value);
        }
    }
    Ok(prepared.form)
}

fn prefill_field(
    field: &super::AnyConnectAuthField,
    options: &AnyConnectAuthPrefillOptions,
) -> (String, bool) {
    let credential = if field.kind == AnyConnectAuthFieldKind::Text
        && field.stable_credential
    {
        options.credentials.username.as_ref()
    } else if field.kind == AnyConnectAuthFieldKind::Password
        && field.stable_credential
    {
        options.credentials.password.as_ref()
    } else if field.kind == AnyConnectAuthFieldKind::Select
        && field.name == "group_list"
    {
        options.credentials.auth_group.as_ref()
    } else {
        None
    };
    credential
        .map(|value| (value.clone(), true))
        .unwrap_or_else(|| (field.value.clone(), false))
}

fn find_form_entry<'a>(
    entries: &'a [AnyConnectAuthFormEntry],
    form_id: &str,
    submission_key: &str,
    name: &str,
) -> Option<&'a AnyConnectAuthFormEntry> {
    entries
        .iter()
        .rev()
        .find(|entry| {
            !entry.submission_key.is_empty()
                && entry.submission_key == submission_key
        })
        .or_else(|| {
            entries.iter().rev().find(|entry| {
                entry.submission_key.is_empty()
                    && entry.form_id == form_id
                    && entry.name == name
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::openconnect::parse_anyconnect_authentication_xml;

    fn parsed_form() -> AnyConnectAuthForm {
        parse_anyconnect_authentication_xml(
            br#"<auth id="main"><form>
              <input type="hidden" name="token" value="hidden"/>
              <input type="text" name="username"/>
              <input type="password" name="password"/>
              <select name="group_list"><option value="staff">Staff</option><option value="admin">Admin</option></select>
            </form></auth>"#,
            "linux-64",
        )
        .unwrap()
    }

    #[test]
    fn fully_prefilled_form_completes_without_a_challenge() {
        let prepared = prepare_anyconnect_auth_form(
            parsed_form(),
            &AnyConnectAuthPrefillOptions {
                credentials: AnyConnectCredentialCache {
                    username: Some("alice".into()),
                    password: Some("secret".into()),
                    auth_group: Some("admin".into()),
                },
                ..Default::default()
            },
        )
        .unwrap();
        assert!(prepared.challenge.is_none());
        let form = complete_anyconnect_auth_form(prepared, None).unwrap();
        assert_eq!(form.fields[0].name, "group_list");
        assert_eq!(form.fields[0].value, "admin");
        assert_eq!(form.fields[1].value, "hidden");
        assert_eq!(form.fields[2].value, "alice");
        assert_eq!(form.fields[3].value, "secret");
    }

    #[test]
    fn visible_challenge_requires_every_field_and_applies_response() {
        let prepared = prepare_anyconnect_auth_form(
            parsed_form(),
            &AnyConnectAuthPrefillOptions::default(),
        )
        .unwrap();
        let challenge = prepared.challenge.as_ref().unwrap();
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            panic!("expected form challenge");
        };
        assert_eq!(prompt.fields.len(), 3);
        let values = BTreeMap::from([
            (prompt.fields[0].submission_key.clone(), "staff".into()),
            (prompt.fields[1].submission_key.clone(), "bob".into()),
            (prompt.fields[2].submission_key.clone(), "password".into()),
        ]);
        let form = complete_anyconnect_auth_form(
            prepared,
            Some(OpenConnectAuthResponse::Form(values)),
        )
        .unwrap();
        assert_eq!(form.fields[1].value, "hidden");
        assert_eq!(form.fields[2].value, "bob");
    }

    #[test]
    fn form_entry_precedence_and_hidden_promotion_match_go() {
        let form = parsed_form();
        let hidden_key = form
            .fields
            .iter()
            .find(|field| field.name == "token")
            .unwrap()
            .submission_key
            .clone();
        let prepared = prepare_anyconnect_auth_form(
            form.clone(),
            &AnyConnectAuthPrefillOptions {
                form_entries: vec![
                    AnyConnectAuthFormEntry {
                        form_id: "main".into(),
                        name: "username".into(),
                        value: "first".into(),
                        ..Default::default()
                    },
                    AnyConnectAuthFormEntry {
                        form_id: "main".into(),
                        name: "username".into(),
                        value: "last".into(),
                        ..Default::default()
                    },
                    AnyConnectAuthFormEntry {
                        submission_key: hidden_key,
                        promote: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        )
        .unwrap();
        let OpenConnectAuthChallengeKind::Form(prompt) =
            &prepared.challenge.as_ref().unwrap().kind
        else {
            panic!("expected form challenge");
        };
        assert_eq!(prompt.fields[0].name, "group_list");
        assert!(prompt.fields.iter().any(|field| {
            field.name == "username" && field.value == "last"
        }));
        assert!(prompt.fields.iter().any(|field| field.name == "token"));
    }

    #[test]
    fn automatic_token_is_required_and_never_prompts() {
        let mut form = parsed_form();
        let password = form
            .fields
            .iter_mut()
            .find(|field| field.name == "password")
            .unwrap();
        password.kind = AnyConnectAuthFieldKind::Token;
        assert!(matches!(
            prepare_anyconnect_auth_form(
                form.clone(),
                &AnyConnectAuthPrefillOptions::default()
            ),
            Err(AnyConnectAuthContinuationError::MissingToken(_))
        ));
        let prepared = prepare_anyconnect_auth_form(
            form,
            &AnyConnectAuthPrefillOptions {
                generated_token: Some("123456".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let challenge = prepared.challenge.as_ref().unwrap();
        let OpenConnectAuthChallengeKind::Form(prompt) = &challenge.kind else {
            panic!("expected form challenge");
        };
        assert!(!prompt.fields.iter().any(|field| field.name == "password"));
    }
}
