//! Resolved paths for `zay serve` (data dir + zay.toml).

use std::path::{Path, PathBuf};

use crate::settings;

#[derive(Clone, Debug)]
pub struct ServePaths {
    pub data_dir: PathBuf,
    pub toml_path: PathBuf,
}

impl ServePaths {
    pub fn resolve(data_dir: Option<&Path>, config: Option<&Path>) -> Self {
        let (data_dir, toml_path) =
            settings::stack_config_paths(data_dir, config);
        Self {
            data_dir,
            toml_path,
        }
    }

    pub fn ensure_config(&self) -> anyhow::Result<()> {
        settings::ensure_zay_toml(&self.data_dir, &self.toml_path)
    }
}
