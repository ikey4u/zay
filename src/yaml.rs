//! YAML map key helper for `serde_yaml::Value` merge paths.

use serde_yaml::Value;

pub fn key(s: &str) -> Value {
    Value::from(s)
}
