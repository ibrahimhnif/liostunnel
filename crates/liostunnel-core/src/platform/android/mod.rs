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

use crate::net::android_tun::AndroidTun;
use crate::net::tun::PacketIo;
use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use std::ffi::{CString, c_char};
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
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
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeInit(
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
        Err(e) => log(ANDROID_LOG_ERROR, &format!("nativeInit: no global ref: {e}")),
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

    let tun = match AndroidTun::new(fd, MTU) {
        Ok(t) => t,
        Err(e) => {
            log(ANDROID_LOG_ERROR, &format!("nativeStart: {e}"));
            return;
        }
    };

    STOP.store(false, Ordering::SeqCst);
    std::thread::spawn(move || drain(tun));
}

/// Matches `Builder.setMtu` in `LiosVpnService`. The two have to agree: the
/// descriptor will not deliver a packet larger than what the builder set.
const MTU: usize = 1500;

/// Set by `nativeStop` to bring [`drain`] down.
static STOP: AtomicBool = AtomicBool::new(false);

/// **Task 4 scaffolding.** Reads the tunnel and counts what arrives.
///
/// Task 5 replaces this with the smoltcp stack, which consumes the same
/// `Box<dyn PacketIo>`. It exists because "the descriptor is wired up
/// correctly" and "the protocols work" are separate claims, and this proves
/// the first one without depending on the second.
fn drain(mut tun: AndroidTun) {
    let mut buf = vec![0u8; MTU + 4];
    let mut packets: u64 = 0;
    let mut reported = 0u64;

    while !STOP.load(Ordering::SeqCst) {
        match tun.read_packet(&mut buf) {
            Ok(0) => {
                // Nothing available. Sleep on the descriptor rather than
                // spinning -- the same contract the desktop driving loop
                // follows, and the reason `read_packet` maps EWOULDBLOCK to 0
                // instead of erroring.
                wait_readable(&tun, 250);
            }
            Ok(_) => {
                packets += 1;
                // A count, never a byte of payload.
                if packets >= reported + 25 {
                    reported = packets;
                    log(ANDROID_LOG_INFO, &format!("tun: {packets} packets read"));
                }
            }
            Err(e) => {
                log(ANDROID_LOG_ERROR, &format!("tun: read failed: {e}"));
                break;
            }
        }
    }
    log(
        ANDROID_LOG_INFO,
        &format!("tun: drain stopped after {packets} packets"),
    );
}

/// Blocks until the descriptor has data or `timeout_ms` elapses.
fn wait_readable(tun: &AndroidTun, timeout_ms: i32) {
    let Some(fd) = tun.pollable_fd() else { return };
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
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
    // The drain thread owns the `AndroidTun` and closes the descriptor when it
    // drops, so this must return before Kotlin closes its ParcelFileDescriptor.
    STOP.store(true, Ordering::SeqCst);
    log(ANDROID_LOG_INFO, "nativeStop");
}

/// **Temporary — Task 3 only. Deleted once the device answer is recorded.**
///
/// Establishes the `protect()` result on real hardware, which is the only
/// place it can be established: every symbol above is
/// `#[cfg(target_os = "android")]` and compiles nowhere else.
///
/// # Why both sockets, in one run
///
/// A `protect` that returns `true` while excluding nothing would pass a
/// protected-only probe. The control socket is what makes the result mean
/// something: with a default route installed, an *unprotected* connection to
/// an external host routes into the tunnel and must fail or hang, while a
/// protected one must succeed.
///
/// Both run in the same pass, seconds apart, so the comparison is not across
/// two different moments of network weather.
///
/// **If both succeed, `protect()` is not what made the difference and the
/// probe has proved nothing** — that is a failed run, not a pass.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeProbeProtect(
    _env: JNIEnv,
    _this: JObject,
) {
    // A plain thread, deliberately: it proves `attach_current_thread` works
    // from a thread the JVM has never seen, which is the case every tokio
    // worker will be in.
    std::thread::spawn(|| {
        // `establish()` returning is not the same as the routes being live.
        //
        // Found by observation, not reasoning: an earlier run logged
        // "control: connect OK" 100ms after nativeStart, while a ping issued
        // 30 seconds later saw 100% loss. Both cannot describe the same
        // routing state -- the control socket had connected through the
        // pre-VPN route, so its success said nothing about protect() at all.
        //
        // Without this wait the probe reports "both succeeded", which its own
        // rule calls a failed run. That is the safe direction to be wrong in,
        // but it would have wasted a hardware session.
        std::thread::sleep(std::time::Duration::from_secs(5));

        log(ANDROID_LOG_INFO, "probe: begin");
        probe_one("protected", true);
        probe_one("control", false);
        log(ANDROID_LOG_INFO, "probe: end");
    });
}

/// One leg of the probe: create a socket, optionally protect it, then connect.
///
/// Protection happens before `connect` for the reason [`protect_fd`] states.
fn probe_one(label: &str, protect: bool) {
    // The descriptor has to exist before `connect`, so that `protect` can be
    // called in between -- the same constraint that makes the SSH path use
    // `TcpSocket` instead of `TcpStream::connect`. `socket(2)` directly avoids
    // pulling a crate in for a function that is deleted at the end of the task.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        log(ANDROID_LOG_ERROR, &format!("probe {label}: socket: {e}"));
        return;
    }

    if protect {
        match protect_fd(fd) {
            Ok(()) => log(ANDROID_LOG_INFO, &format!("probe {label}: protect OK")),
            Err(e) => {
                log(
                    ANDROID_LOG_ERROR,
                    &format!("probe {label}: protect FAILED: {e}"),
                );
                unsafe { libc::close(fd) };
                return;
            }
        }
    }

    // 1.1.1.1:80 as a literal, so no DNS lookup happens on a descriptor whose
    // routing is the thing under test.
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 80u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([1, 1, 1, 1]).to_be(),
        },
        sin_zero: [0; 8],
    };
    // Non-blocking, so the attempt can be given a deadline. A blocking connect
    // into the tunnel takes the kernel's full SYN-retry budget -- measured at
    // 133 seconds on the emulator, which reads like a hang rather than a
    // result and makes a hardware session needlessly slow.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

    let rc = unsafe {
        libc::connect(
            fd,
            (&raw const addr).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    let outcome = if rc == 0 {
        Ok(())
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            Err(e)
        } else {
            connect_result(fd, 15_000)
        }
    };

    match outcome {
        Ok(()) => log(ANDROID_LOG_INFO, &format!("probe {label}: connect OK")),
        Err(e) => log(
            ANDROID_LOG_ERROR,
            &format!("probe {label}: connect FAILED: {e}"),
        ),
    }
    unsafe { libc::close(fd) };
}

/// Waits for an in-progress connect to finish, or `timeout_ms` to elapse.
///
/// Temporary — deleted with the rest of the probe.
fn connect_result(fd: RawFd, timeout_ms: i32) -> io::Result<()> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    match unsafe { libc::poll(&mut pfd, 1, timeout_ms) } {
        0 => return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
        n if n < 0 => return Err(io::Error::last_os_error()),
        _ => {}
    }

    // A writable socket is not necessarily a connected one: a refused or
    // unreachable connection also wakes poll, and the reason is in SO_ERROR.
    let mut err: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut err).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err));
    }
    Ok(())
}
