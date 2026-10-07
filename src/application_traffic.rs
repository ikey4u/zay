//! Saved application usage remains visible while the proxy is stopped.

use std::path::Path;

use anyhow::Result;
use singbox_core::outbound::ProcessTrafficState;

pub(crate) fn saved(data_dir: &Path) -> Result<serde_json::Value> {
    let path = data_dir
        .join(crate::settings::SINGBOX_DIR)
        .join("application-traffic.json");
    let state = ProcessTrafficState::read_storage(&path)?.unwrap_or(
        ProcessTrafficState {
            enabled: true,
            started_at: None,
            records: Vec::new(),
        },
    );
    let mut value = state.api_value();
    value["available"] = false.into();
    Ok(value)
}
