//! sing-box JSON parsing and merge semantics.

use serde_json::Value;

use crate::option::ConfigError;

/// Remove `//` and `/* ... */` comments while preserving byte positions and
/// newlines. Upstream's context-aware JSON decoder accepts these comments.
pub fn strip_comments(input: &str) -> Result<String, ConfigError> {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        String,
        Escape,
        LineComment,
        BlockComment,
        BlockCommentStar,
    }

    let mut state = State::Code;
    let mut chars = input.chars().peekable();
    let mut output = String::with_capacity(input.len());
    while let Some(ch) = chars.next() {
        match state {
            State::Code => match ch {
                '"' => {
                    output.push(ch);
                    state = State::String;
                }
                '/' if chars.peek() == Some(&'/') => {
                    output.push(' ');
                    output.push(' ');
                    chars.next();
                    state = State::LineComment;
                }
                '/' if chars.peek() == Some(&'*') => {
                    output.push(' ');
                    output.push(' ');
                    chars.next();
                    state = State::BlockComment;
                }
                _ => output.push(ch),
            },
            State::String => {
                output.push(ch);
                match ch {
                    '\\' => state = State::Escape,
                    '"' => state = State::Code,
                    _ => {}
                }
            }
            State::Escape => {
                output.push(ch);
                state = State::String;
            }
            State::LineComment => {
                if ch == '\n' {
                    output.push(ch);
                    state = State::Code;
                } else {
                    output.push(' ');
                }
            }
            State::BlockComment => {
                if ch == '*' {
                    output.push(' ');
                    state = State::BlockCommentStar;
                } else if ch == '\n' || ch == '\r' {
                    output.push(ch);
                } else {
                    output.push(' ');
                }
            }
            State::BlockCommentStar => {
                if ch == '/' {
                    output.push(' ');
                    state = State::Code;
                } else {
                    if ch == '\n' || ch == '\r' {
                        output.push(ch);
                    } else {
                        output.push(' ');
                    }
                    state = if ch == '*' {
                        State::BlockCommentStar
                    } else {
                        State::BlockComment
                    };
                }
            }
        }
    }

    match state {
        State::BlockComment | State::BlockCommentStar => {
            Err(ConfigError::Syntax("unterminated block comment".into()))
        }
        State::String | State::Escape => {
            Err(ConfigError::Syntax("unterminated JSON string".into()))
        }
        _ => Ok(output),
    }
}

/// Merge `source` into `destination` using `badjson.MergeJSON` semantics:
/// destination scalars win, objects recurse, and arrays append source items to
/// destination items unless appending is disabled.
pub fn merge_value(
    source: Value,
    destination: Value,
    disable_append: bool,
) -> Result<Value, ConfigError> {
    match destination {
        Value::Array(mut destination) => {
            if !disable_append {
                match source {
                    Value::Array(source) => destination.extend(source),
                    source => destination.push(source),
                }
            }
            Ok(Value::Array(destination))
        }
        Value::Object(mut destination) => {
            let Value::Object(source) = source else {
                return Err(ConfigError::Merge(
                    "cannot merge a non-object into a JSON object".into(),
                ));
            };
            for (key, source_value) in source {
                let value = match destination.remove(&key) {
                    Some(destination_value) => merge_value(
                        source_value,
                        destination_value,
                        disable_append,
                    )?,
                    None => source_value,
                };
                destination.insert(key, value);
            }
            Ok(Value::Object(destination))
        }
        destination => Ok(destination),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{merge_value, strip_comments};

    #[test]
    fn comments_do_not_damage_strings_or_line_numbers() {
        let input = "{\n // note\n \"url\": \"https://example.test/*x*/\", /* block\n line */ \"ok\": true\n}";
        let clean = strip_comments(input).unwrap();
        assert_eq!(clean.lines().count(), input.lines().count());
        let parsed: serde_json::Value = serde_json::from_str(&clean).unwrap();
        assert_eq!(parsed["url"], "https://example.test/*x*/");
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn merge_matches_upstream_destination_precedence_and_array_order() {
        let first = json!({"log":{"level":"info"},"inbounds":[{"tag":"a"}]});
        let second = json!({"log":{"level":"debug","timestamp":true},"inbounds":[{"tag":"b"}]});
        let merged = merge_value(second, first, false).unwrap();
        assert_eq!(merged["log"]["level"], "info");
        assert_eq!(merged["log"]["timestamp"], true);
        assert_eq!(merged["inbounds"][0]["tag"], "a");
        assert_eq!(merged["inbounds"][1]["tag"], "b");
    }
}
