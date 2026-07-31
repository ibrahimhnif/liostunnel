//! The JNI surface `LiosVpnService` calls into.
//!
//! # Symbol names are load-bearing
//!
//! JNI resolves `external fun nativeStart` on `com.liostunnel.app.LiosVpnService`
//! to the exported symbol `Java_com_liostunnel_app_LiosVpnService_nativeStart`.
//! Renaming the Kotlin class, moving it between packages, or changing
//! `applicationId` silently breaks the link — the app builds, installs, and
//! throws `UnsatisfiedLinkError` the moment the service starts.
//!
//! The package was normalised to `com.liostunnel.app` in Task 1 for this
//! reason: `flutter create` derives it from the project name, which would have
//! produced `com.liostunnel.liostunnel_app`, and JNI escapes an underscore in
//! a package segment to `_1`.

use jni::JNIEnv;
use jni::objects::JObject;
use std::ffi::{CString, c_char};

// `liblog`'s writer, declared rather than depended on.
//
// `tracing` calls from this crate go nowhere on Android: nothing installs a
// subscriber in the app process, so `tracing::info!` is silently discarded and
// a device log shows no evidence a native call happened at all.
//
// Bridging all of `tracing` to logcat would mean a subscriber and another
// dependency. These few JNI-boundary diagnostics are the ones that have to
// survive on a device, so they go straight to `liblog`, which Android links
// into every process already.
//
// `c_char`, not `i8`: it is unsigned on aarch64 and armv7 Android, so a
// hardcoded `i8` fails to compile on exactly the architecture that ships.
unsafe extern "C" {
    fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
}

const ANDROID_LOG_INFO: i32 = 4;
const ANDROID_LOG_ERROR: i32 = 6;

/// Writes one line to logcat under the `liostunnel` tag.
///
/// Never called with payload bytes, DNS names or secret material — the same
/// rule every other sink in this project follows.
fn log(prio: i32, msg: &str) {
    let (Ok(tag), Ok(text)) = (CString::new("liostunnel"), CString::new(msg)) else {
        // An interior NUL is the only failure here, and a diagnostic is not
        // worth a panic on a device.
        return;
    };
    unsafe { __android_log_write(prio, tag.as_ptr(), text.as_ptr()) };
}

/// Called by `LiosVpnService.onStartCommand` with the descriptor from
/// `ParcelFileDescriptor.detachFd()`.
///
/// Ownership of `fd` transfers to native code here: `detachFd` gives up the
/// Java-side descriptor, so nothing on the Kotlin side will close it.
///
/// Task 2 stub — Task 4 replaces the body with `AndroidTun` construction and
/// starts the engine on it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeStart(
    _env: JNIEnv,
    _this: JObject,
    fd: i32,
) {
    // A descriptor number is not secret material, and it is the one value
    // worth having in a log here: a negative fd means `establish()` returned
    // null, which is a different failure from the engine refusing to start.
    if fd < 0 {
        log(ANDROID_LOG_ERROR, "nativeStart: refusing a negative fd");
        return;
    }
    log(ANDROID_LOG_INFO, &format!("nativeStart: fd={fd}"));
}

/// Called from `LiosVpnService.onDestroy`, before the `ParcelFileDescriptor`
/// is closed.
///
/// Task 2 stub — Task 4 stops the engine and drops the tun.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeStop(
    _env: JNIEnv,
    _this: JObject,
) {
    log(ANDROID_LOG_INFO, "nativeStop");
}
