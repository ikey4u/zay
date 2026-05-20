use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ClashForAndroidConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append_system_dns: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_subtitle_pattern: Option<String>,
}
