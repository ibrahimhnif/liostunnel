//! The JNI surface `LiosVpnService` calls into.
//!
//! # Symbol names are load-bearing
//!
//! JNI resolves `external fun nativeStart` on `id.liostech.liostunnel.LiosVpnService`
//! to the exported symbol `Java_id_liostech_liostunnel_LiosVpnService_nativeStart`.
//! Renaming the Kotlin class, moving it between packages, or changing
//! `applicationId` silently breaks the link — the app builds, installs, and
//! throws `UnsatisfiedLinkError` the moment the service starts.
//!
//! The package has been renamed twice, and both times every symbol below had
//! to move with it. `flutter create` first derived `com.liostunnel.liostunnel_app`
//! from the project name, which JNI would have rendered as
//! `Java_com_liostunnel_liostunnel_1app_...` because an underscore in a package
//! segment escapes to `_1`. It is now `id.liostech.liostunnel`, which has no
//! underscores and so needs no escaping.
//!
//! Nothing checks this at build time. `testing/verify-jni-symbols.sh` compares
//! what this file exports against what Kotlin declares, which is the only
//! mechanism that has actually caught a mismatch here.

pub mod engine;

use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use std::ffi::{CString, c_char};
use std::io;
use std::os::fd::RawFd;
use std::sync::OnceLock;

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

/// The JVM, captured once so native threads can attach to it later.
static VM: OnceLock<JavaVM> = OnceLock::new();

/// A global reference to the live `LiosVpnService`.
///
/// A plain `JObject` is only valid for the JNI call that produced it, so it
/// cannot be stored. `protect` is called from tokio worker threads long after
/// `nativeInit` returned, which is exactly what a global reference is for.
static SERVICE: OnceLock<GlobalRef> = OnceLock::new();

/// Captures the JVM and the service instance.
///
/// Called by `LiosVpnService.onStartCommand` before the tunnel is established
/// and therefore before any socket exists to protect.
#[unsafe(no_mangle)]
pub extern "system" fn Java_id_liostech_liostunnel_LiosVpnService_nativeInit(
    env: JNIEnv,
    this: JObject,
) {
    match env.get_java_vm() {
        Ok(vm) => {
            let _ = VM.set(vm);
        }
        Err(e) => {
            log(ANDROID_LOG_ERROR, &format!("nativeInit: no JavaVM: {e}"));
            return;
        }
    }
    match env.new_global_ref(this) {
        // `set` fails only if the service was started twice without the
        // process dying. The first reference is still valid, so keeping it is
        // correct rather than merely convenient.
        Ok(global) => {
            let _ = SERVICE.set(global);
        }
        Err(e) => log(
            ANDROID_LOG_ERROR,
            &format!("nativeInit: no global ref: {e}"),
        ),
    }
    log(ANDROID_LOG_INFO, "nativeInit");
}

/// Excludes `fd` from the VPN's own routing table, via `VpnService.protect`.
///
/// # This must be called before the socket connects
///
/// Protecting an already-connected socket is too late: the handshake has
/// already been routed into the tunnel we are trying to stay out of. Callers
/// create the descriptor without connecting — `tokio::net::TcpSocket` for SSH,
/// and for Shadowsocks the crate's own hook, which it invokes at the same
/// point.
///
/// # Failure is not cosmetic
///
/// A socket that escapes this routes into the tunnel and the flow hangs. For
/// Shadowsocks that is one socket *per flow*, so a partial failure looks like
/// an intermittent stall under load rather than a clean error.
pub fn protect_fd(fd: RawFd) -> io::Result<()> {
    let vm = VM
        .get()
        .ok_or_else(|| io::Error::other("JavaVM not captured; nativeInit did not run"))?;
    let service = SERVICE
        .get()
        .ok_or_else(|| io::Error::other("no VpnService reference; nativeInit did not run"))?;

    // Tokio worker threads are native threads the JVM has never seen. Without
    // attaching, any JNI call from them is undefined behaviour rather than an
    // error -- this is the single most important line in the file.
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| io::Error::other(format!("cannot attach thread to JVM: {e}")))?;

    let protected = env
        .call_method(service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)])
        .and_then(|v| v.z())
        .map_err(|e| io::Error::other(format!("VpnService.protect failed: {e}")))?;

    if protected {
        Ok(())
    } else {
        // `protect` returns false rather than throwing when it declines.
        // Treating that as success is the exact bug this function exists to
        // prevent, so it becomes an error here.
        Err(io::Error::other("VpnService.protect returned false"))
    }
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
pub extern "system" fn Java_id_liostech_liostunnel_LiosVpnService_nativeStart(
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
    engine::start(fd);
}

/// The tunnel address `VpnService.Builder` must use.
///
/// Kotlin reads it from here rather than repeating the literal: the builder's
/// address and `StackConfig::address` have to agree, and a silent divergence
/// would leave the stack answering on an address the descriptor never carries.
#[unsafe(no_mangle)]
pub extern "system" fn Java_id_liostech_liostunnel_LiosVpnService_nativeTunAddress<'a>(
    env: JNIEnv<'a>,
    _this: JObject<'a>,
) -> jni::sys::jstring {
    let s = engine::TUN_ADDRESS.to_string();
    match env.new_string(s) {
        Ok(v) => v.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The MTU `VpnService.Builder` must use, for the same reason.
#[unsafe(no_mangle)]
pub extern "system" fn Java_id_liostech_liostunnel_LiosVpnService_nativeTunMtu(
    _env: JNIEnv,
    _this: JObject,
) -> i32 {
    engine::TUN_MTU as i32
}

/// Called from `LiosVpnService.onDestroy`, before the `ParcelFileDescriptor`
/// is closed.
///
/// Blocks until the engine's threads have joined, so the `AndroidTun` holding
/// the descriptor is dropped before Kotlin closes its own handle to it.
/// Returning early would leave a thread reading a descriptor that is about to
/// be closed underneath it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_id_liostech_liostunnel_LiosVpnService_nativeStop(
    _env: JNIEnv,
    _this: JObject,
) {
    engine::stop();
    log(ANDROID_LOG_INFO, "nativeStop");
}
