use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub fn set_error(msg: impl AsRef<str>) {
    let msg = msg.as_ref();
    tracing::error!("{msg}");
    let Ok(c) = CString::new(msg) else {
        return;
    };
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(c));
}

pub fn clear_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Return the last error message (caller must `zay_ios_free_string`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_last_error() -> *mut c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow_mut()
            .take()
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut())
    })
}

/// Free a string allocated by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(s) });
}

pub unsafe fn cstr<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null C string".into());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| e.to_string())
}

pub fn to_cstring(s: impl Into<String>) -> Result<*mut c_char, String> {
    CString::new(s.into())
        .map(|c| c.into_raw())
        .map_err(|e| e.to_string())
}
