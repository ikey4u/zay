//! Zay iOS native core — C ABI for Swift Packet Tunnel + app.

mod embedded_rules;
mod error;
mod logging;
mod mesh;
mod mesh_config;
mod proxy_nodes;
mod proxy_url;
mod rule_convert;
mod rules;
mod singbox_config;

use std::ffi::c_char;
use std::path::PathBuf;

use crate::error::{clear_error, cstr, set_error, to_cstring};
use crate::mesh_config::MeshInput;
use crate::singbox_config::SingboxInput;

pub use error::{zay_ios_free_string, zay_ios_last_error};

/// Set the log file path (App Group container). Pass null to disable file logging.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_set_log_path(path: *const c_char) {
    logging::init_logging();
    let path = if path.is_null() {
        None
    } else {
        match unsafe { cstr(path) } {
            Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
            _ => None,
        }
    };
    if let Some(ref p) = path {
        tracing::info!("log path => {}", p.display());
    }
    logging::set_log_path(path);
}

/// Append a log line from Swift (`level` = info/warn/error/debug).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_log(level: *const c_char, message: *const c_char) {
    let level = unsafe { cstr(level) }.unwrap_or("info");
    let message = unsafe { cstr(message) }.unwrap_or("");
    logging::log_line(level, message);
}

/// Build EasyTier TOML from JSON:
/// `{ "network_name", "network_secret", "relay_url", "ipv4"?, "instance_name"?, "hostname"?, "socks_port"? }`
///
/// Returns heap string (caller frees with `zay_ios_free_string`) or null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_build_easytier_toml(input_json: *const c_char) -> *mut c_char {
    clear_error();
    logging::init_logging();
    let result = (|| {
        let raw = unsafe { cstr(input_json) }?;
        let input: MeshInput =
            serde_json::from_str(raw).map_err(|e| format!("invalid mesh input json: {e}"))?;
        let toml = mesh_config::build_easytier_toml(&input).map_err(|e| e.to_string())?;
        tracing::info!("built EasyTier TOML ({} bytes)", toml.len());
        to_cstring(toml)
    })();
    match result {
        Ok(p) => p,
        Err(e) => {
            set_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Build sing-box JSON from:
/// `{ "proxy_url", "mesh_cidrs": [], "bypass_ips": [], "working_dir"?, "log_level"?, "selected_proxy_tag"?, "custom_rules"? }`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_build_singbox_json(input_json: *const c_char) -> *mut c_char {
    clear_error();
    logging::init_logging();
    let result = (|| {
        let raw = unsafe { cstr(input_json) }?;
        let input: SingboxInput =
            serde_json::from_str(raw).map_err(|e| format!("invalid singbox input json: {e}"))?;
        tracing::info!("building sing-box config for proxy_url={}", input.proxy_url);
        let json = singbox_config::build_singbox_json(&input).map_err(|e| format!("{e:#}"))?;
        tracing::info!("built sing-box JSON ({} bytes)", json.len());
        to_cstring(json)
    })();
    match result {
        Ok(p) => p,
        Err(e) => {
            set_error(e);
            std::ptr::null_mut()
        }
    }
}

/// List proxy nodes for a subscription / URI (caller frees).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_list_proxy_nodes(proxy_url: *const c_char) -> *mut c_char {
    clear_error();
    logging::init_logging();
    let result = (|| {
        let url = unsafe { cstr(proxy_url) }?;
        proxy_nodes::list_proxy_nodes_json(url).map_err(|e| format!("{e:#}"))
    })();
    match result {
        Ok(s) => match to_cstring(s) {
            Ok(p) => p,
            Err(e) => {
                set_error(e);
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Prefetch Clash subscription into `working_dir` cache so tunnel start can work offline.
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_prefetch_proxy(
    proxy_url: *const c_char,
    working_dir: *const c_char,
) -> i32 {
    clear_error();
    logging::init_logging();
    let result = (|| -> Result<(), String> {
        let url = unsafe { cstr(proxy_url) }?;
        let dir = unsafe { cstr(working_dir) }?;
        if dir.is_empty() {
            return Err("working_dir is empty".into());
        }
        let n = proxy_url::prefetch_proxy(url, PathBuf::from(dir).as_path())
            .map_err(|e| format!("{e:#}"))?;
        tracing::info!("prefetch_proxy ok ({n} node(s))");
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Convert rule list text → `{ format, rule_count, json }`.
/// `hint` may be `auto` / `clash` / `shadowrocket` / `singbox` / `plain` (or null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_convert_rule_text(
    raw: *const c_char,
    hint: *const c_char,
) -> *mut c_char {
    clear_error();
    logging::init_logging();
    let result = (|| {
        let text = unsafe { cstr(raw) }?;
        let hint = if hint.is_null() {
            None
        } else {
            Some(unsafe { cstr(hint) }?)
        };
        rule_convert::convert_rule_text(text, hint).map_err(|e| e.to_string())
    })();
    match result {
        Ok(s) => match to_cstring(s) {
            Ok(p) => p,
            Err(e) => {
                set_error(e);
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Embedded Loyalsoldier rule-set overview. `working_dir` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_embedded_rules_info(
    working_dir: *const c_char,
) -> *mut c_char {
    clear_error();
    let dir = if working_dir.is_null() {
        None
    } else {
        unsafe { cstr(working_dir) }
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    let json = embedded_rules::info_json(dir.as_deref());
    match to_cstring(json) {
        Ok(p) => p,
        Err(e) => {
            set_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Extract embedded Loyalsoldier clash-rules into `working_dir/ruleset-embedded/`.
/// Call before building / starting sing-box. Returns 0 on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_ensure_embedded_rules(working_dir: *const c_char) -> i32 {
    clear_error();
    logging::init_logging();
    match (|| {
        let dir = unsafe { cstr(working_dir) }?;
        if dir.is_empty() {
            return Err("working_dir is empty".into());
        }
        embedded_rules::ensure_installed(std::path::Path::new(dir)).map_err(|e| e.to_string())
    })() {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Start EasyTier from a TOML config string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_start_mesh(toml: *const c_char) -> i32 {
    clear_error();
    logging::init_logging();
    match (|| {
        let toml = unsafe { cstr(toml) }?;
        mesh::start_mesh(toml).map_err(|e| e.to_string())
    })() {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Stop all EasyTier instances.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_stop_mesh() -> i32 {
    clear_error();
    match mesh::stop_mesh() {
        Ok(()) => 0,
        Err(e) => {
            set_error(e.to_string());
            -1
        }
    }
}

/// JSON status of running mesh instances (caller frees).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_mesh_status_json() -> *mut c_char {
    clear_error();
    match mesh::mesh_status_json() {
        Ok(s) => match to_cstring(s) {
            Ok(p) => p,
            Err(e) => {
                set_error(e);
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Attach a TUN fd to a named instance (optional; SOCKS-bridge mode usually skips this).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_set_tun_fd(inst_name: *const c_char, fd: i32) -> i32 {
    clear_error();
    match (|| {
        let name = unsafe { cstr(inst_name) }?;
        mesh::set_tun_fd(name, fd).map_err(|e| e.to_string())
    })() {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Extract relay host + suggested default mesh CIDR helpers for Swift.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_relay_host(relay_url: *const c_char) -> *mut c_char {
    clear_error();
    match unsafe { cstr(relay_url) } {
        Ok(u) => match mesh::parse_relay_host(u) {
            Some(h) => to_cstring(h).unwrap_or(std::ptr::null_mut()),
            None => {
                set_error("cannot parse relay host");
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(e);
            std::ptr::null_mut()
        }
    }
}
