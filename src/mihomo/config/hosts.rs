use indexmap::IndexMap;
use serde_yaml::Value;

/// `hosts` mapping (domain → IP, alias, or structured value).
pub type HostsConfig = IndexMap<String, Value>;
