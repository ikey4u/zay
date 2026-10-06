//! Native, signed helper installation and authenticated XPC worker ownership.
#[cfg(feature = "desktop-macos-helper")]
use std::ffi::{CStr, CString, c_char, c_void};
use std::path::Path;

use anyhow::{Result, bail};

#[cfg(feature = "desktop-macos-helper")]
unsafe extern "C" {
    fn zay_macos_start(
        directory: *const c_char,
        config: *const c_char,
        pid: *mut i32,
        error: *mut c_char,
        length: usize,
    ) -> *mut c_void;
    fn zay_macos_release(handle: *mut c_void);
    fn zay_macos_helper_run() -> i32;
}

pub(super) struct Worker {
    // Store the retained XPC connection as an integer so the owner can move
    // between Tokio threads. Foundation manages the connection's internal queue.
    #[cfg(feature = "desktop-macos-helper")]
    connection: usize,
    pid: u32,
}
impl Worker {
    pub(super) fn is_alive(&self) -> bool {
        crate::daemon::process_is_alive(self.pid)
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        #[cfg(feature = "desktop-macos-helper")]
        unsafe {
            zay_macos_release(self.connection as *mut c_void);
        }
    }
}

pub(super) fn start(directory: &Path, config: &Path) -> Result<Worker> {
    #[cfg(feature = "desktop-macos-helper")]
    {
        use std::os::unix::ffi::OsStrExt;
        // Resolve macOS /var -> /private/var aliases before validating paths.
        let directory = std::fs::canonicalize(directory)?;
        let config = std::fs::canonicalize(config)?;
        let directory = CString::new(directory.as_os_str().as_bytes())?;
        let config = CString::new(config.as_os_str().as_bytes())?;
        let mut error = [0 as c_char; 2048];
        let mut pid = 0;
        let connection = unsafe {
            zay_macos_start(
                directory.as_ptr(),
                config.as_ptr(),
                &mut pid,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if connection.is_null() {
            let error =
                unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
            bail!("{error}");
        }
        return Ok(Worker {
            connection: connection as usize,
            pid: pid as u32,
        });
    }
    #[cfg(not(feature = "desktop-macos-helper"))]
    {
        let _ = (directory, config);
        bail!("This build does not include the native desktop helper.");
    }
}

pub(crate) fn run_helper() -> Result<()> {
    #[cfg(feature = "desktop-macos-helper")]
    {
        let status = unsafe { zay_macos_helper_run() };
        anyhow::ensure!(
            status == 0,
            "The networking helper must be launched by macOS."
        );
        Ok(())
    }
    #[cfg(not(feature = "desktop-macos-helper"))]
    {
        bail!("This build does not include the native desktop helper.");
    }
}

#[cfg(all(test, feature = "desktop-macos-helper"))]
mod tests {
    use super::*;
    unsafe extern "C" {
        fn zay_macos_probe_fixture(
            delay: f64,
            fail: i32,
            error: *mut c_char,
            length: usize,
        ) -> i32;
    }
    #[test]
    fn cold_helper_reply_is_not_cancelled_after_five_seconds() {
        let mut error = [0 as c_char; 256];
        assert_eq!(
            unsafe {
                zay_macos_probe_fixture(6.0, 0, error.as_mut_ptr(), error.len())
            },
            1
        );
    }
    #[test]
    fn helper_connection_failure_keeps_diagnostic_details() {
        let mut error = [0 as c_char; 256];
        assert_eq!(
            unsafe {
                zay_macos_probe_fixture(0.0, 1, error.as_mut_ptr(), error.len())
            },
            0
        );
        let message =
            unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
        assert!(message.contains("fixture connection refused"));
        assert!(message.contains("4099"));
    }

    #[test]
    fn helper_rejects_unowned_symlinked_and_external_configuration() {
        use std::os::unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
        };
        unsafe extern "C" {
            fn zay_macos_validate_paths(
                directory: *const c_char,
                config: *const c_char,
                uid: u32,
            ) -> i32;
        }
        let dir = std::env::temp_dir()
            .join(format!("zay-helper-paths-{}", uuid::Uuid::new_v4()));
        let client = crate::desktop::Client::new(dir.clone()).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let config = dir.join("zay.toml");
        let valid = |directory: &Path, config: &Path, uid| {
            let directory =
                CString::new(directory.as_os_str().as_bytes()).unwrap();
            let config = CString::new(config.as_os_str().as_bytes()).unwrap();
            unsafe {
                zay_macos_validate_paths(
                    directory.as_ptr(),
                    config.as_ptr(),
                    uid,
                ) != 0
            }
        };
        let uid = unsafe { libc::getuid() };
        assert!(valid(&dir, &config, uid));
        assert!(!valid(&dir, &config, uid + 1));
        assert!(!valid(&dir, &dir.join("other.toml"), uid));
        let alias = dir.join("alias.toml");
        symlink(&config, &alias).unwrap();
        assert!(!valid(&dir, &alias, uid));
        std::fs::set_permissions(
            &config,
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(!valid(&dir, &config, uid));
        drop(client);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unsigned_process_rejects_elevation_before_connecting_or_authorizing() {
        let dir = std::env::temp_dir().join(format!(
            "zay-native-helper-preflight-{}",
            uuid::Uuid::new_v4()
        ));
        let client = crate::desktop::Client::new(dir.clone()).unwrap();
        let error = match start(&dir, client.config_path()) {
            Ok(_) => panic!(
                "an unsigned test executable must not authorize a helper"
            ),
            Err(error) => error,
        };
        assert!(error.to_string().contains("signed Zay Desktop app bundle"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
