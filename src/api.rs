use std::sync::{Arc, RwLock};

use crate::{bootstrap::singbox::Prepared, settings::Settings};

#[derive(Clone)]
pub struct AppState {
    pub config_json: Arc<RwLock<String>>,
    pub settings: Settings,
    pub tun_enabled: bool,
}

impl From<Prepared> for AppState {
    fn from(p: Prepared) -> Self {
        Self {
            config_json: Arc::new(RwLock::new(p.config_json)),
            settings: p.settings,
            tun_enabled: p.tun_enabled,
        }
    }
}
