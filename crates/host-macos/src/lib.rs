//! Versioned, thread-confined C ABI and native macOS AppKit host bridge.
//!
//! The main `szu-securelink-rs` crate forbids `unsafe_code`; this crate is the isolated C ABI
//! boundary that native AppKit Objective-C++ (`platforms/macos/src/SecureLinkNativeApp.mm`) links against,
//! mirroring `metasequoiaime/msime`'s `crates/host-api` + `2026-10-18-apple-rust-client-table.md`.

#![allow(unsafe_code)]

use std::cell::RefCell;
use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

/// Current C ABI version of `securelink_client.h`.
pub const CLIENT_ABI_VERSION: u32 = 1;

/// Callback invoked on the main AppKit thread to initialize the session and return a JSON envelope.
pub type InitCallback = Box<dyn FnMut() -> String>;
/// Callback invoked on the main AppKit thread to dispatch a UTF-8 JSON request.
pub type DispatchCallback = Box<dyn FnMut(&[u8]) -> String>;
/// Callback invoked on the main AppKit thread to drain pending background `SessionEvent`s.
pub type PollCallback = Box<dyn FnMut() -> Option<String>>;
/// Callback invoked on the main AppKit thread before application exit.
pub type ShutdownCallback = Box<dyn FnMut()>;

/// Thread-confined callback table registered by the pure-Rust core (`szu-securelink-rs`).
pub struct NativeHostCallbacks {
    /// Initializes the main-thread session (including `NSStatusItem`) and returns the initial JSON envelope.
    pub init_on_main_thread: InitCallback,
    /// Dispatches a UTF-8 JSON request and returns a JSON response envelope.
    pub dispatch: DispatchCallback,
    /// Polls pending background `SessionEvent`s and returns `Some(envelope)` if state changed.
    pub poll_events: PollCallback,
    /// Cleans up the status item and stops background workers on quit.
    pub shutdown: ShutdownCallback,
}

thread_local! {
    static HOST_CALLBACKS: RefCell<Option<NativeHostCallbacks>> = const { RefCell::new(None) };
}

fn into_owned_c_string(s: String) -> *mut c_char {
    let clean = if s.as_bytes().contains(&0) {
        s.replace('\0', "")
    } else {
        s
    };
    CString::new(clean)
        .unwrap_or_else(|_| CString::new("{\"ok\":false,\"error\":\"InvalidNul\"}").unwrap())
        .into_raw()
}

/// Returns the version of the `securelink_client.h` C ABI.
#[unsafe(no_mangle)]
pub extern "C" fn securelink_client_abi_version() -> u32 {
    CLIENT_ABI_VERSION
}

/// Initializes the main-thread Rust session and returns the initial UTF-8 JSON snapshot envelope.
#[unsafe(no_mangle)]
pub extern "C" fn securelink_client_init_on_main_thread() -> *mut c_char {
    let out = catch_unwind(AssertUnwindSafe(|| {
        HOST_CALLBACKS.with(|cell| {
            let mut borrow = cell.borrow_mut();
            match borrow.as_mut() {
                Some(cb) => (cb.init_on_main_thread)(),
                None => "{\"ok\":false,\"error\":\"HostNotInitialized\"}".to_string(),
            }
        })
    }))
    .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"HostPanic\"}".to_string());
    into_owned_c_string(out)
}

/// Dispatches a bounded UTF-8 JSON request into the active main-thread Rust session.
///
/// # Safety
/// `request` must be either null or a valid pointer to at least `length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn securelink_client_dispatch(request: *const u8, length: usize) -> *mut c_char {
    if request.is_null() || length == 0 || length > 65_536 {
        return into_owned_c_string("{\"ok\":false,\"error\":\"InvalidRequestBounds\"}".to_string());
    }
    let bytes = unsafe { slice::from_raw_parts(request, length) };
    let out = catch_unwind(AssertUnwindSafe(|| {
        HOST_CALLBACKS.with(|cell| {
            let mut borrow = cell.borrow_mut();
            match borrow.as_mut() {
                Some(cb) => (cb.dispatch)(bytes),
                None => "{\"ok\":false,\"error\":\"HostNotInitialized\"}".to_string(),
            }
        })
    }))
    .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"HostPanic\"}".to_string());
    into_owned_c_string(out)
}

/// Drains pending background `SessionEvent`s on the main AppKit thread.
#[unsafe(no_mangle)]
pub extern "C" fn securelink_client_poll_events() -> *mut c_char {
    let out = catch_unwind(AssertUnwindSafe(|| {
        HOST_CALLBACKS.with(|cell| {
            let mut borrow = cell.borrow_mut();
            borrow.as_mut().and_then(|cb| (cb.poll_events)())
        })
    }))
    .unwrap_or(None);
    match out {
        Some(json) => into_owned_c_string(json),
        None => std::ptr::null_mut(),
    }
}

/// Shuts down the menu bar status item and background tunnel actor on application exit.
#[unsafe(no_mangle)]
pub extern "C" fn securelink_client_shutdown() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        HOST_CALLBACKS.with(|cell| {
            if let Some(mut cb) = cell.borrow_mut().take() {
                (cb.shutdown)();
            }
        });
    }));
}

/// Releases an owned UTF-8 JSON string returned by `securelink_client_*`.
///
/// # Safety
/// `ptr` must be either null or a pointer previously returned by `securelink_client_*` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn securelink_client_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn securelink_macos_run_native_app();
}

/// Installs `callbacks` on the main thread and runs the native macOS AppKit `NSApplication` loop.
pub fn run_native_macos_app(callbacks: NativeHostCallbacks) {
    HOST_CALLBACKS.with(|cell| {
        *cell.borrow_mut() = Some(callbacks);
    });
    #[cfg(target_os = "macos")]
    unsafe {
        securelink_macos_run_native_app();
    }
}

/// Exercises the C ABI dispatch and release lifecycle on the current thread for automated tests.
#[must_use]
pub fn c_abi_roundtrip_for_test(callbacks: NativeHostCallbacks, request_json: &[u8]) -> (u32, String, String) {
    HOST_CALLBACKS.with(|cell| {
        *cell.borrow_mut() = Some(callbacks);
    });
    let ver = securelink_client_abi_version();
    let init_ptr = securelink_client_init_on_main_thread();
    let init_str = unsafe { std::ffi::CStr::from_ptr(init_ptr).to_string_lossy().into_owned() };
    unsafe {
        securelink_client_string_free(init_ptr);
    }

    let resp_ptr = unsafe { securelink_client_dispatch(request_json.as_ptr(), request_json.len()) };
    let resp_str = unsafe { std::ffi::CStr::from_ptr(resp_ptr).to_string_lossy().into_owned() };
    unsafe {
        securelink_client_string_free(resp_ptr);
    }

    securelink_client_shutdown();
    (ver, init_str, resp_str)
}
