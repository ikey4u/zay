//! Built-in NTP client configuration.

use serde::{Deserialize, Serialize};

use super::{DialerOptions, Duration, ServerOptions};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct NtpOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub interval: Duration,
    #[serde(default)]
    pub write_to_system: bool,
    #[serde(flatten)]
    pub server_options: ServerOptions,
    #[serde(flatten)]
    pub dialer: DialerOptions,
}

impl NtpOptions {
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    pub fn server(&self) -> &str {
        if self.server_options.server.is_empty() {
            "time.apple.com"
        } else {
            &self.server_options.server
        }
    }

    pub fn server_port(&self) -> u16 {
        if self.server_options.server_port == 0 {
            123
        } else {
            self.server_options.server_port
        }
    }

    pub fn interval_std(&self) -> std::time::Duration {
        self.interval
            .as_std()
            .filter(|interval| !interval.is_zero())
            .unwrap_or(std::time::Duration::from_secs(30 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::NtpOptions;

    #[test]
    fn decodes_upstream_shape_and_applies_defaults() {
        let options: NtpOptions = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "server": "time.example",
            "interval": "15m",
            "detour": "proxy"
        }))
        .unwrap();
        options.validate().unwrap();
        assert_eq!(options.server_port(), 123);
        assert_eq!(options.interval_std().as_secs(), 15 * 60);
        assert_eq!(options.dialer.detour, "proxy");

        let defaults: NtpOptions = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "server": "time.example"
        }))
        .unwrap();
        assert_eq!(defaults.interval_std().as_secs(), 30 * 60);
    }

    #[test]
    fn applies_upstream_default_server_and_nonpositive_interval() {
        let options: NtpOptions = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "interval": "-1s"
        }))
        .unwrap();
        options.validate().unwrap();
        assert_eq!(options.server(), "time.apple.com");
        assert_eq!(options.server_port(), 123);
        assert_eq!(options.interval_std().as_secs(), 30 * 60);
    }
}
