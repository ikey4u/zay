use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use toml_edit::{DocumentMut, Item, Table};

use crate::settings;

#[derive(Args, Debug)]
#[command(about = "Inspect and edit zay.toml")]
pub struct ConfigCli {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print the current zay.toml
    Dump(ConfigPathOpts),
    /// Set a TOML key to a TOML literal value
    Set(ConfigSet),
    /// Remove a TOML key
    Unset(ConfigUnset),
    /// Open zay.toml in $EDITOR
    Edit(ConfigPathOpts),
}

#[derive(Args, Debug, Default)]
pub struct ConfigPathOpts {
    /// Zay config directory (uses <DIR>/zay.toml)
    #[arg(short, long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// Path to zay.toml (default: <data-dir>/zay.toml)
    #[arg(short = 'c', long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ConfigSet {
    #[command(flatten)]
    pub path: ConfigPathOpts,

    /// Dot-separated TOML key path, e.g. mihomo.mixin
    pub key: String,

    /// TOML literal value, e.g. 7891, true, '"debug"', or '["cidr"]'
    pub value: String,
}

#[derive(Args, Debug)]
pub struct ConfigUnset {
    #[command(flatten)]
    pub path: ConfigPathOpts,

    /// Dot-separated TOML key path, e.g. mihomo.mixin
    pub key: String,
}

/// Read raw `zay.toml` text (creates default file if missing).
pub fn read_raw(opts: &ConfigPathOpts) -> Result<String> {
    let toml_path = ensure_config(opts)?;
    fs::read_to_string(&toml_path)
        .with_context(|| format!("reading {}", toml_path.display()))
}

/// Replace entire `zay.toml` after TOML syntax check.
pub fn write_raw(opts: &ConfigPathOpts, raw: &str) -> Result<()> {
    raw.parse::<DocumentMut>()
        .context("parsing zay.toml before write")?;
    let toml_path = ensure_config(opts)?;
    fs::write(&toml_path, raw)
        .with_context(|| format!("writing {}", toml_path.display()))
}

/// Validate `zay.toml` syntax (and ensure readable tables).
pub fn validate_file(opts: &ConfigPathOpts) -> Result<()> {
    let toml_path = ensure_config(opts)?;
    let raw = fs::read_to_string(&toml_path)
        .with_context(|| format!("reading {}", toml_path.display()))?;
    raw.parse::<DocumentMut>()
        .with_context(|| format!("parsing {}", toml_path.display()))?;
    Ok(())
}

pub fn run(cli: ConfigCli) -> Result<()> {
    match cli.command {
        ConfigCommand::Dump(opts) => dump(&opts),
        ConfigCommand::Set(cmd) => set(&cmd),
        ConfigCommand::Unset(cmd) => unset(&cmd),
        ConfigCommand::Edit(opts) => edit(&opts),
    }
}

fn config_path(opts: &ConfigPathOpts) -> (PathBuf, PathBuf) {
    settings::stack_config_paths(
        opts.data_dir.as_deref(),
        opts.config.as_deref(),
    )
}

fn ensure_config(opts: &ConfigPathOpts) -> Result<PathBuf> {
    let (data_dir, toml_path) = config_path(opts);
    settings::ensure_zay_toml(&data_dir, &toml_path)?;
    Ok(toml_path)
}

/// Public alias for serve API handlers.
pub fn ensure_config_path(opts: &ConfigPathOpts) -> Result<PathBuf> {
    ensure_config(opts)
}

fn dump(opts: &ConfigPathOpts) -> Result<()> {
    let toml_path = ensure_config(opts)?;
    let raw = fs::read_to_string(&toml_path)
        .with_context(|| format!("reading {}", toml_path.display()))?;
    print!("{raw}");
    Ok(())
}

fn set(cmd: &ConfigSet) -> Result<()> {
    let toml_path = ensure_config(&cmd.path)?;
    update_document(&toml_path, |doc| set_key(doc, &cmd.key, &cmd.value))
}

fn unset(cmd: &ConfigUnset) -> Result<()> {
    let toml_path = ensure_config(&cmd.path)?;
    update_document(&toml_path, |doc| unset_key(doc, &cmd.key))
}

fn edit(opts: &ConfigPathOpts) -> Result<()> {
    let toml_path = ensure_config(opts)?;
    let editor = std::env::var("EDITOR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "vi".to_string());
    let status = Command::new(&editor)
        .arg(&toml_path)
        .status()
        .with_context(|| format!("running editor {editor:?}"))?;
    if !status.success() {
        bail!("editor exited with status {status}");
    }
    Ok(())
}

fn update_document<F>(toml_path: &Path, mutate: F) -> Result<()>
where
    F: FnOnce(&mut DocumentMut) -> Result<()>,
{
    let raw = fs::read_to_string(toml_path)
        .with_context(|| format!("reading {}", toml_path.display()))?;
    let mut doc = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("parsing {}", toml_path.display()))?;
    mutate(&mut doc)?;
    fs::write(toml_path, doc.to_string())
        .with_context(|| format!("writing {}", toml_path.display()))
}

pub fn set_key(
    doc: &mut DocumentMut,
    key: &str,
    value_raw: &str,
) -> Result<()> {
    let path = parse_key_path(key)?;
    let value = parse_value(value_raw)?;
    let (parents, leaf) = path.split_at(path.len() - 1);
    let table = parent_table_mut(doc.as_table_mut(), parents, true)?;
    table[leaf[0]] = value;
    Ok(())
}

pub fn unset_key(doc: &mut DocumentMut, key: &str) -> Result<()> {
    let path = parse_key_path(key)?;
    let (parents, leaf) = path.split_at(path.len() - 1);
    let table = parent_table_mut(doc.as_table_mut(), parents, false)?;
    if table.remove(leaf[0]).is_none() {
        bail!("config key {key:?} does not exist");
    }
    Ok(())
}

fn parent_table_mut<'a>(
    mut table: &'a mut Table,
    parents: &[&str],
    create: bool,
) -> Result<&'a mut Table> {
    for segment in parents {
        if !table.contains_key(segment) {
            if create {
                table.insert(segment, Item::Table(Table::new()));
            } else {
                bail!("config table {segment:?} does not exist");
            }
        }
        let item = table
            .get_mut(segment)
            .with_context(|| format!("accessing config table {segment:?}"))?;
        table = item.as_table_mut().with_context(|| {
            format!("config key {segment:?} is not a table")
        })?;
    }
    Ok(table)
}

fn parse_key_path(key: &str) -> Result<Vec<&str>> {
    if key.trim().is_empty() {
        bail!("config key path cannot be empty");
    }
    let parts: Vec<&str> = key.split('.').collect();
    if parts.iter().any(|part| part.is_empty()) {
        bail!("config key path cannot contain empty segments");
    }
    if parts.iter().any(|part| part.parse::<usize>().is_ok()) {
        bail!("array indexing is not supported in config key paths");
    }
    Ok(parts)
}

pub fn parse_value(raw: &str) -> Result<Item> {
    let wrapper = format!("value = {raw}\n");
    let mut doc = wrapper
        .parse::<DocumentMut>()
        .with_context(|| format!("parsing TOML value {raw:?}"))?;
    doc.as_table_mut()
        .remove("value")
        .context("parsed TOML value missing")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key_creates_nested_tables() {
        let mut doc = "".parse::<DocumentMut>().unwrap();
        set_key(&mut doc, "mihomo.mixin", "'''rules: []\n'''").unwrap();

        assert!(doc.to_string().contains("[mihomo]"));
        assert!(doc.to_string().contains("mixin = '''"));
    }

    #[test]
    fn unset_key_removes_existing_value() {
        let mut doc = "mixed_port = 7890\n".parse::<DocumentMut>().unwrap();
        unset_key(&mut doc, "mixed_port").unwrap();

        assert!(!doc.to_string().contains("mixed_port"));
    }

    #[test]
    fn unset_key_errors_when_missing() {
        let mut doc = "mixed_port = 7890\n".parse::<DocumentMut>().unwrap();
        assert!(unset_key(&mut doc, "log_level").is_err());
    }

    #[test]
    fn parse_key_path_rejects_array_indexing() {
        assert!(parse_key_path("mesh.peers.0").is_err());
    }

    #[test]
    fn parse_value_accepts_typed_toml_literals() {
        let item = parse_value("[\"10.0.0.0/8\"]").unwrap();
        assert!(item.is_value());
    }
}
