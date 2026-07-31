# LiosTunnel on Android — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** LiosTunnel runs on Android as a real VPN client — Shadowsocks and SSH profiles carrying live traffic through a `VpnService` tunnel, with the existing UI showing state, totals and live speed, surviving the app being swiped away.

**Architecture:** The Flutter UI drives the Rust engine directly over FFI. A Kotlin `VpnService` obtains the tunnel file descriptor and hands it to Rust over JNI; the engine then runs in native threads owned by a foreground Service. An `AndroidTun` implementing the existing four-method `PacketIo` trait is the only new code below the smoltcp stack — everything above it is unchanged.

**Tech Stack:** Flutter, flutter_rust_bridge 2.12.0, cargokit, Kotlin, Android NDK 27, `jni` crate, shadowsocks 1.24, russh 0.62.

**Spec:** `docs/superpowers/specs/2026-07-31-liostunnel-android-design.md`

## Global Constraints

- **Min SDK 29 (Android 10), target SDK 34.**
- **flutter_rust_bridge is pinned at `=2.12.0`.** 2.13.0-beta is forbidden.
- **Generated code is never hand-edited.** Regenerate with `flutter_rust_bridge_codegen generate`.
- **Credentials never cross the Kotlin boundary.** The Shadowsocks password and SSH key go Dart → Rust over FFI. The *only* thing crossing `MethodChannel` or JNI is a file descriptor and non-secret control data.
- **Never log payload bytes, DNS query names or answers, or secret material** — not in logs, errors, `Debug` output, or protocol fields. This applies to Kotlin `Log` calls too.
- **`protect()` must cover every socket the tunnel opens.** For Shadowsocks that is one per flow, bounded by `MAX_CONCURRENT_FLOWS = 64`.
- **`protect()` is called before `connect`,** never after — a post-connect call leaves the handshake already routed into the tunnel.
- **Keep the `#[cfg(target_os = "android")]` surface minimal.** It cannot be tested on the development machine, so it must be small enough to audit by reading.
- **`doh` stays enabled.** Do not disable it to save size.
- **Release builds are per-ABI** (`--split-per-abi`), never universal.
- **Commit messages go through a file with `git commit -F`.** Never `-m` with backticks.
- **The applicationId is `com.liostunnel.app`.** JNI symbol names depend on it.

## Testing Reality

**Most of this plan cannot be tested by `cargo test`.** Everything under `#[cfg(target_os = "android")]` is invisible to host builds and to CI on macOS and Linux. Tasks below are explicit about which of three kinds of verification applies:

- **HOST** — a real automated test, runs in `cargo test` / `flutter test`.
- **EMULATOR** — runs on `Medium_Phone_API_36.1`; proves the code runs and the plumbing connects. **Not faithful for `protect()` or routing** (emulator networking is NAT-ed through the host).
- **DEVICE** — a physical phone over USB. The only verification that proves the tunnel works. Reported by the operator.

A task is not complete until its stated verification kind has actually been run. An EMULATOR pass never substitutes for a DEVICE check where the plan asks for one.

## File Structure

| File | Responsibility |
|---|---|
| `app/android/**` | Generated Flutter Android project (Task 1) |
| `app/android/app/src/main/kotlin/com/liostunnel/app/LiosVpnService.kt` | `VpnService` subclass: builder, fd, foreground notification |
| `app/android/app/src/main/kotlin/com/liostunnel/app/VpnChannel.kt` | `MethodChannel` handler: consent, start, stop |
| `app/android/app/src/main/AndroidManifest.xml` | Service declaration, permissions, foreground service type |
| `crates/liostunnel-core/src/platform/android/mod.rs` | JNI bridge: `JavaVM`/service refs, `protect_fd` |
| `crates/liostunnel-core/src/net/android_tun.rs` | `AndroidTun`: `PacketIo` over the VpnService fd |
| `crates/liostunnel-core/src/protocols/shadowsocks.rs` | Modified: `connect_with_opts` + `ConnectOpts` protect hook |
| `crates/liostunnel-core/src/protocols/ssh.rs` | Modified: `TcpSocket` → protect → `connect_stream` |
| `app/lib/services/vpn_platform.dart` | Dart side of the `MethodChannel` |

---

### Task 1: Android project exists and runs Rust

**Files:**
- Create: `app/android/**` (generated)
- Modify: `app/android/app/build.gradle.kts`
- Modify: `.gitignore` (Android build outputs)

**Interfaces:**
- Produces: a running Android app whose Dart can call an existing FFI function.

**Blockers to clear first — these are the operator's, not the implementer's:**

- [ ] **Step 1: Accept the Android SDK licences**

This is a legal agreement between the operator and Google. **Do not accept it on their behalf.** Ask the operator to run:

```bash
flutter doctor --android-licenses
```

Then confirm:

```bash
flutter doctor 2>&1 | grep -A2 "Android toolchain"
```

Expected: no "Android license status unknown".

- [ ] **Step 2: Generate the Android platform directory**

```bash
cd app && flutter create --platforms=android --org com.liostunnel .
```

Verify the applicationId — the JNI symbol names in Task 3 depend on it:

```bash
grep -rn "applicationId" app/android/app/build.gradle.kts
```

Expected: `applicationId = "com.liostunnel.app"`. If it differs, **stop and report** — do not proceed with a mismatched package.

- [ ] **Step 3: Set the SDK levels**

In `app/android/app/build.gradle.kts`:

```kotlin
android {
    compileSdk = 34
    ndkVersion = "27.1.12297006"

    defaultConfig {
        applicationId = "com.liostunnel.app"
        minSdk = 29
        targetSdk = 34
    }
}
```

- [ ] **Step 4: Build the debug APK**

```bash
cd app && flutter build apk --debug 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL, and a `.so` produced by cargokit. Confirm the Rust library is actually in the APK:

```bash
unzip -l app/build/app/outputs/flutter-apk/app-debug.apk | grep -i "liostunnel"
```

Expected: at least one `lib/<abi>/libliostunnel_ffi.so`. **An APK without it means cargokit did not run** — stop and report rather than continuing.

- [ ] **Step 5: EMULATOR — run it and prove FFI works**

```bash
$ANDROID_HOME/emulator/emulator -avd Medium_Phone_API_36.1 -no-snapshot &
adb wait-for-device
cd app && flutter run -d emulator-5554
```

Expected: the app launches and the profile list screen renders. The list is populated over FFI, so a rendering list is itself the FFI smoke test.

- [ ] **Step 6: Commit**

```bash
git add app/android .gitignore
git commit -F /tmp/task1.txt
```

---

### Task 2: LiosVpnService — consent, tunnel, foreground

**Files:**
- Create: `app/android/app/src/main/kotlin/com/liostunnel/app/LiosVpnService.kt`
- Create: `app/android/app/src/main/kotlin/com/liostunnel/app/VpnChannel.kt`
- Create: `app/lib/services/vpn_platform.dart`
- Modify: `app/android/app/src/main/AndroidManifest.xml`

**Interfaces:**
- Produces: `LiosVpnService` holding an established tunnel fd; `VpnPlatform.prepare()`, `VpnPlatform.start()`, `VpnPlatform.stop()` in Dart.
- Consumed by: Task 3 (the fd), Task 7 (start/stop from the UI).

- [ ] **Step 1: Manifest**

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>

<service
    android:name=".LiosVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:foregroundServiceType="specialUse"
    android:exported="false">
    <intent-filter>
        <action android:name="android.net.VpnService"/>
    </intent-filter>
    <property
        android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
        android:value="VPN tunnel client"/>
</service>
```

`FOREGROUND_SERVICE_SPECIAL_USE` and the `<property>` are both required on API 34. A missing type throws at `startForeground` — at runtime, on device, where no host test sees it.

- [ ] **Step 2: The service**

```kotlin
package com.liostunnel.app

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

class LiosVpnService : VpnService() {

    companion object {
        const val CHANNEL_ID = "liostunnel"
        const val NOTIFICATION_ID = 1
        @Volatile var instance: LiosVpnService? = null
    }

    private var tunnel: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        val fd = establishTunnel()
        if (fd < 0) {
            stopSelf()
            return START_NOT_STICKY
        }
        nativeStart(fd)
        return START_STICKY
    }

    /** Returns the detached fd, or -1 if the tunnel could not be established. */
    private fun establishTunnel(): Int {
        val pfd = Builder()
            .setSession("LiosTunnel")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setMtu(1500)
            .establish() ?: return -1
        tunnel = pfd
        return pfd.detachFd()
    }

    override fun onDestroy() {
        nativeStop()
        tunnel?.close()
        tunnel = null
        instance = null
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_ID, "LiosTunnel", NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(ch)
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("LiosTunnel")
            .setContentText("Tunnel active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    private external fun nativeStart(fd: Int)
    private external fun nativeStop()
}
```

**Note `detachFd()`:** it transfers ownership to native code. The `ParcelFileDescriptor` must not also be closed while the engine holds the fd — `onDestroy` closes it only after `nativeStop`.

- [ ] **Step 3: The channel**

`VpnService.prepare(context)` returns an `Intent` when consent has not been granted, and `null` when it has.

```kotlin
package com.liostunnel.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import io.flutter.plugin.common.MethodChannel

class VpnChannel(private val activity: Activity) : MethodChannel.MethodCallHandler {

    companion object {
        const val CHANNEL = "com.liostunnel.app/vpn"
        const val REQUEST_CONSENT = 9001
    }

    private var pendingConsent: MethodChannel.Result? = null

    override fun onMethodCall(call: io.flutter.plugin.common.MethodCall,
                              result: MethodChannel.Result) {
        when (call.method) {
            "prepare" -> {
                val intent = VpnService.prepare(activity)
                if (intent == null) {
                    result.success(true)
                } else {
                    pendingConsent = result
                    activity.startActivityForResult(intent, REQUEST_CONSENT)
                }
            }
            "start" -> {
                activity.startForegroundService(
                    Intent(activity, LiosVpnService::class.java))
                result.success(null)
            }
            "stop" -> {
                activity.stopService(Intent(activity, LiosVpnService::class.java))
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    fun onActivityResult(requestCode: Int, resultCode: Int) {
        if (requestCode != REQUEST_CONSENT) return
        pendingConsent?.success(resultCode == Activity.RESULT_OK)
        pendingConsent = null
    }
}
```

**No credential appears in any call above.** `start` carries no arguments — the profile is already in the engine (Task 7).

- [ ] **Step 4: The Dart side**

```dart
// app/lib/services/vpn_platform.dart
import 'package:flutter/services.dart';

class VpnPlatform {
  static const _channel = MethodChannel('com.liostunnel.app/vpn');

  /// Raises the system VPN consent dialog if needed.
  /// Returns true when consent is granted.
  static Future<bool> prepare() async =>
      await _channel.invokeMethod<bool>('prepare') ?? false;

  static Future<void> start() => _channel.invokeMethod('start');
  static Future<void> stop() => _channel.invokeMethod('stop');
}
```

- [ ] **Step 5: Stub the natives so it links**

Task 3 implements these. For now, in `crates/liostunnel-core/src/platform/android/mod.rs`:

```rust
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeStart(
    _env: jni::JNIEnv, _this: jni::objects::JObject, fd: i32,
) {
    tracing::info!(fd, "nativeStart called");
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeStop(
    _env: jni::JNIEnv, _this: jni::objects::JObject,
) {
    tracing::info!("nativeStop called");
}
```

Logging the fd number is fine — it is not secret material.

- [ ] **Step 6: EMULATOR — consent and tunnel establish**

```bash
cd app && flutter run -d emulator-5554
```

Then trigger `prepare()` and `start()` from the UI (a temporary debug button is acceptable and is removed in Task 7).

Expected, verified via `adb logcat`:
```bash
adb logcat -s liostunnel:* ActivityManager:I | grep -i "nativeStart\|VpnService"
```
- the system VPN consent dialog appears;
- after approval, a key icon appears in the status bar;
- `nativeStart called` is logged with a non-negative fd.

**A negative fd means `establish()` returned null** — usually a missing permission or consent. Stop and report.

- [ ] **Step 7: Commit**

---

### Task 3: The `protect()` bridge — the decision point

This is the spike. It ships no user-visible feature and answers the question everything else depends on.

**Files:**
- Modify: `crates/liostunnel-core/src/platform/android/mod.rs`
- Modify: `crates/liostunnel-core/Cargo.toml` (add `jni`, android-only)
- Modify: `LiosVpnService.kt` (pass `this` to native)

**Interfaces:**
- Produces: `pub fn protect_fd(fd: RawFd) -> std::io::Result<()>`, callable from any thread.
- Consumed by: Tasks 4 and 5.

- [ ] **Step 1: Android-only dependency**

```toml
[target.'cfg(target_os = "android")'.dependencies]
jni = "0.21"
```

Gating it by target keeps `jni` out of every desktop build.

- [ ] **Step 2: The bridge**

The critical constraint: **tokio worker threads are native threads unknown to the JVM.** Calling JNI from them without attaching crashes. `attach_current_thread` is not optional.

```rust
//! The JNI bridge. This is the whole `#[cfg(target_os = "android")]` surface
//! for socket protection, kept in one file because nothing here can be
//! exercised by `cargo test` on a development machine -- it has to be
//! auditable by reading instead.

use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use std::io;
use std::os::fd::RawFd;
use std::sync::OnceLock;

static VM: OnceLock<JavaVM> = OnceLock::new();
static SERVICE: OnceLock<GlobalRef> = OnceLock::new();

/// Called once by `LiosVpnService.onStartCommand`, before any socket exists.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeInit(
    env: JNIEnv,
    this: JObject,
) {
    if let Ok(vm) = env.get_java_vm() {
        let _ = VM.set(vm);
    }
    if let Ok(global) = env.new_global_ref(this) {
        let _ = SERVICE.set(global);
    }
}

/// Excludes `fd` from the VPN's own routing table.
///
/// Must be called *before* the socket connects: protecting an
/// already-connected socket leaves the handshake routed into the tunnel.
pub fn protect_fd(fd: RawFd) -> io::Result<()> {
    let vm = VM
        .get()
        .ok_or_else(|| io::Error::other("JavaVM not initialised"))?;
    let service = SERVICE
        .get()
        .ok_or_else(|| io::Error::other("VpnService reference not initialised"))?;

    // Tokio worker threads are not JVM threads. Attaching is mandatory.
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| io::Error::other(format!("cannot attach thread: {e}")))?;

    let ok = env
        .call_method(service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)])
        .and_then(|v| v.z())
        .map_err(|e| io::Error::other(format!("protect call failed: {e}")))?;

    if ok {
        Ok(())
    } else {
        Err(io::Error::other("VpnService.protect returned false"))
    }
}
```

**`protect` returns `boolean`, and `false` is a real failure** — not an error, just a refusal. Treating it as success is the bug this whole task exists to prevent.

- [ ] **Step 3: Call `nativeInit` from Kotlin**

In `LiosVpnService.onStartCommand`, **before** `nativeStart`:

```kotlin
nativeInit()
val fd = establishTunnel()
```

and declare it:

```kotlin
private external fun nativeInit()
```

- [ ] **Step 4: A temporary proof hook**

Add, to be deleted in Step 7:

```rust
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_liostunnel_app_LiosVpnService_nativeProbeProtect(
    _env: JNIEnv, _this: JObject,
) {
    std::thread::spawn(|| {
        let sock = match std::net::TcpStream::connect("1.1.1.1:80") {
            Ok(s) => s,
            Err(e) => { tracing::error!(error = %e, "probe: connect failed"); return; }
        };
        use std::os::fd::AsRawFd;
        match protect_fd(sock.as_raw_fd()) {
            Ok(()) => tracing::info!("probe: protect OK"),
            Err(e) => tracing::error!(error = %e, "probe: protect FAILED"),
        }
    });
}
```

The `std::thread::spawn` is deliberate: it proves `attach_current_thread` works from a thread the JVM has never seen, which is the case that matters.

- [ ] **Step 5: DEVICE — the decision**

Emulator is **not** sufficient here. On a physical phone:

```bash
adb logcat -c && adb logcat -s liostunnel:*
```

Expected: `probe: protect OK`.

**If it logs `probe: protect FAILED`, stop the phase and report.** Every remaining task assumes this works, and the spec's fallback options (a `vpn_protect_path` unix socket, or a fork) become the next decision.

- [ ] **Step 6: DEVICE — prove it does something**

A `protect` that returns `true` without excluding the socket would pass Step 5. With the tunnel established and a default route installed, an *unprotected* socket to an external host must fail or hang, and a protected one must succeed. Add a second probe that omits the `protect_fd` call and confirm the two behave **differently**.

**If both succeed, `protect()` is not the thing making the difference** and the result proves nothing — report it as such rather than recording a pass.

- [ ] **Step 7: Delete the probes and commit**

---

### Task 4: `AndroidTun` — packets flow

**Files:**
- Create: `crates/liostunnel-core/src/net/android_tun.rs`
- Modify: `crates/liostunnel-core/src/net/mod.rs`

**Interfaces:**
- Consumes: the fd from Task 2.
- Produces: `AndroidTun::new(fd: RawFd, mtu: usize) -> Self`, implementing `PacketIo`.

- [ ] **Step 1: Implement `PacketIo`**

`PacketIo` (`net/tun.rs:7`) requires `read_packet`, `write_packet`, `mtu`, `pollable_fd`. **`read_packet` must not block** — the driving loop calls it until it returns 0, then sleeps on `pollable_fd`.

```rust
use crate::error::TunnelError;
use crate::net::tun::PacketIo;
use std::os::fd::RawFd;

/// `PacketIo` over an Android `VpnService` descriptor.
///
/// The fd arrives from `ParcelFileDescriptor.detachFd()`, so this type owns
/// it and closes it on drop.
pub struct AndroidTun {
    fd: RawFd,
    mtu: usize,
}

impl AndroidTun {
    pub fn new(fd: RawFd, mtu: usize) -> Result<Self, TunnelError> {
        // The driving loop requires a non-blocking descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(TunnelError::Io(std::io::Error::last_os_error()));
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(TunnelError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self { fd, mtu })
    }
}

impl PacketIo for AndroidTun {
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
        let n = unsafe {
            libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            // Nothing available. The contract is 0, not an error.
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => Ok(0),
            _ => Err(TunnelError::Io(err)),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        let n = unsafe {
            libc::write(self.fd, packet.as_ptr() as *const libc::c_void, packet.len())
        };
        if n < 0 {
            return Err(TunnelError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    #[cfg(unix)]
    fn pollable_fd(&self) -> Option<RawFd> {
        Some(self.fd)
    }
}

impl Drop for AndroidTun {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
```

**`EWOULDBLOCK` must map to `Ok(0)`, not an error.** Returning an error there kills the driving loop on the first idle poll — the tunnel would appear to connect and then immediately die.

- [ ] **Step 2: HOST — test the error mapping**

This part is *not* Android-specific: a `pipe(2)` gives a non-blocking fd on any Unix. Put this test in `android_tun.rs` behind `#[cfg(unix)]` so it runs on the development machine.

```rust
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// An empty non-blocking descriptor reports "nothing available", not a
    /// failure. Returning an error here kills the driving loop on its first
    /// idle poll, which presents as a tunnel that connects and instantly dies.
    #[test]
    fn an_empty_descriptor_reads_zero_rather_than_erroring() {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut tun = AndroidTun::new(fds[0], 1500).expect("construct");
        let mut buf = [0u8; 2048];
        assert_eq!(tun.read_packet(&mut buf).expect("read"), 0);
        unsafe { libc::close(fds[1]) };
    }

    /// What is written comes back, unmodified and whole.
    #[test]
    fn a_written_packet_is_read_back_intact() {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut rx = AndroidTun::new(fds[0], 1500).expect("rx");
        let mut tx = AndroidTun::new(fds[1], 1500).expect("tx");
        tx.write_packet(&[1, 2, 3, 4]).expect("write");
        let mut buf = [0u8; 2048];
        assert_eq!(rx.read_packet(&mut buf).expect("read"), 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    }
}
```

- [ ] **Step 3: Run it, and prove it discriminates**

```bash
cargo test -p liostunnel-core android_tun -- --nocapture
```
Expected: 2 passed.

**Then break it deliberately** — change the `WouldBlock` arm to return an error, re-run, and confirm `an_empty_descriptor_reads_zero_rather_than_erroring` **fails**. Restore it. A test that passes against both versions is not testing anything, and this project has shipped three of those.

- [ ] **Step 4: Wire `nativeStart` to build the tun**

Replace the Task 2 stub so `nativeStart(fd)` constructs an `AndroidTun` and starts the engine on it.

- [ ] **Step 5: EMULATOR — packets arrive**

Log a packet counter (a count, never bytes). Browse in another app; the counter must rise. Expected: non-zero within seconds of connecting.

- [ ] **Step 6: Commit**

---

### Task 5: Shadowsocks with the protect hook

**Files:**
- Modify: `crates/liostunnel-core/src/protocols/shadowsocks.rs`

**Interfaces:**
- Consumes: `protect_fd` (Task 3), `AndroidTun` (Task 4).

- [ ] **Step 1: Build `ConnectOpts` and pass it**

`ProxyClientStream::connect` takes no opts; `connect_with_opts` (`client.rs:70`) takes `&ConnectOpts`. `MakeSocketProtect` is implemented for any `Fn(RawFd) -> io::Result<()> + Send + Sync + 'static`, so a closure suffices.

```rust
/// The crate calls this for every socket it opens -- and it opens one per
/// flow, not one per tunnel. That is why the hook exists rather than a
/// single call site: a missed socket routes into the tunnel and the flow
/// hangs, intermittently, under load, after the happy path already passed.
fn connect_opts() -> shadowsocks::net::ConnectOpts {
    let mut opts = shadowsocks::net::ConnectOpts::default();
    #[cfg(target_os = "android")]
    opts.set_vpn_socket_protect(|fd| crate::platform::android::protect_fd(fd));
    opts
}
```

On every non-Android target this returns `ConnectOpts::default()`, which is what the crate used implicitly before — so desktop behaviour is unchanged by construction.

- [ ] **Step 2: Switch the call site**

```rust
let stream = ProxyClientStream::connect_with_opts(
    context.clone(), &cfg, target, &opts,
).await?;
```

- [ ] **Step 3: HOST — desktop behaviour is unchanged**

```bash
cargo test -p liostunnel-core shadowsocks
```
Expected: the existing Shadowsocks tests still pass, unchanged. They exercise the desktop path, which now flows through `connect_with_opts` with default opts.

- [ ] **Step 4: DEVICE — a single request**

Connect a Shadowsocks profile on the phone, load a page. Expected: it loads, and byte counters rise.

- [ ] **Step 5: DEVICE — concurrent flows (AND-4, the one that matters)**

A single request can pass with a broken hook. Open a page with many subresources, or run:

```bash
adb shell 'for i in $(seq 1 30); do (curl -s -o /dev/null -w "%{http_code} " http://example.com &) ; done; wait; echo'
```

Expected: **all 30 succeed.** A subset hanging or failing is a socket escaping `protect()` — the exact failure this task exists to prevent, and it does not reproduce with one request.

- [ ] **Step 6: Commit**

---

### Task 6: SSH with the protect hook

**Files:**
- Modify: `crates/liostunnel-core/src/protocols/ssh.rs`

- [ ] **Step 1: Replace `client::connect` with a protected socket**

`connect_inner` currently ends at `client::connect(config, addr, handler)`. That creates and connects the socket in one step, leaving no moment to protect it — and protecting after connect is too late.

`tokio::net::TcpSocket` creates the descriptor *without* connecting, which is the whole reason it is used here:

```rust
// `TcpStream::connect` gives no window between socket creation and the
// SYN. `TcpSocket` does, and that window is the only correct place to
// call `protect`: afterwards, the handshake has already been routed into
// the tunnel we are trying to stay out of.
let sock = match addr {
    SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
    SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
}
.map_err(|e| TunnelError::Protocol(format!("cannot create socket: {e}")))?;

#[cfg(target_os = "android")]
{
    use std::os::fd::AsRawFd;
    crate::platform::android::protect_fd(sock.as_raw_fd())
        .map_err(|e| TunnelError::Protocol(format!("cannot protect socket: {e}")))?;
}

let stream = sock
    .connect(addr)
    .await
    .map_err(|e| TunnelError::Protocol(format!("cannot connect: {e}")))?;

let mut handle = client::connect_stream(config, stream, handler).await?;
```

`connect_stream` (`russh/src/client/mod.rs:995`) accepts any `R: AsyncRead + AsyncWrite + Unpin + Send + 'static`; `TcpStream` satisfies it.

**No host or profile string appears in any of these messages** — the existing rule in this function, preserved.

- [ ] **Step 2: HOST — desktop SSH is unchanged**

```bash
cargo test -p liostunnel-core ssh
```
Expected: all existing SSH tests pass. This is a transport-construction change only; auth, host-key policy and the handle are untouched.

- [ ] **Step 3: DEVICE — SSH carries traffic**

Connect an SSH profile on the phone and load a page. Expected: it loads.

Unlike Shadowsocks this is a single socket, so it either works immediately or not at all — there is no load-dependent failure mode to chase here.

- [ ] **Step 4: Commit**

---

### Task 7: UI, lifetime, and stats

**Files:**
- Modify: `app/lib/services/connection_model.dart` (Android stats source)
- Modify: the connection screen (connect/disconnect calls `VpnPlatform`)
- Modify: `LiosVpnService.kt` (stop path)

**Interfaces:**
- Consumes: `VpnPlatform` (Task 2), the engine (Tasks 4–6).

- [ ] **Step 1: Start sequence, credentials-first**

Order matters and is a constraint, not a preference:

1. Dart loads the profile into the engine over **FFI**.
2. Dart calls `VpnPlatform.prepare()`; if it returns false, stop — the user declined.
3. Dart calls `VpnPlatform.start()`.

The password never appears in step 2 or 3.

- [ ] **Step 2: Stats by polling**

There is no helper and no socket on Android. Dart polls the engine over FFI once per second and feeds `ConnectionModel` the same shape the desktop `Stats` frame produces.

**No change to speed monitoring.** It is a pure function of the stats stream and an injected clock, so it works as-is.

- [ ] **Step 3: HOST — the model is unchanged**

```bash
cd app && flutter test test/services/connection_model_test.dart
```
Expected: all existing tests pass, untouched. If this task required editing them, the stats shape diverged and that is a defect, not an update.

- [ ] **Step 4: DEVICE — survive swipe-away (AND-5)**

With the tunnel connected and traffic flowing, swipe the app from recents. Expected:
- the notification remains;
- the key icon remains;
- **traffic still flows** (browse in another app);
- reopening LiosTunnel shows `Connected` with counters continuing, not reset.

**Counters resetting means the engine was owned by the Dart isolate** rather than being a process-global, and the tunnel was rebuilt rather than survived. That is the design error §4 of the spec names — report it rather than accepting a screen that merely looks right.

- [ ] **Step 5: DEVICE — teardown (AND-7)**

Disconnect. Expected: notification gone, key icon gone, traffic returns to direct routing.

- [ ] **Step 6: Commit**

---

### Task 8: Per-ABI release build

**Files:**
- Modify: `app/android/app/build.gradle.kts`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

- [ ] **Step 1: Build split APKs**

```bash
cd app && flutter build apk --release --split-per-abi
```

- [ ] **Step 2: Confirm the split actually happened**

```bash
ls -lh app/build/app/outputs/flutter-apk/*.apk
for f in app/build/app/outputs/flutter-apk/*.apk; do
  echo "== $f"; unzip -l "$f" | grep "lib/" | awk '{print $4}' | cut -d/ -f2 | sort -u
done
```

Expected: separate `app-arm64-v8a-release.apk`, `app-armeabi-v7a-release.apk`, `app-x86_64-release.apk`, **each containing exactly one ABI**.

**An APK listing more than one ABI directory means the split did not take effect** regardless of the filename — check the contents, not the name.

- [ ] **Step 3: CI**

Add an Android job to the `package` matrix building the release APKs and uploading them. It must not be gated behind the macOS/Linux OS checks the existing `package` job uses.

- [ ] **Step 4: README**

Document: sideloading, that the APKs are unsigned debug-keystore builds, and that the VPN consent dialog appears once per install.

- [ ] **Step 5: Commit**

---

## Self-Review

**Spec coverage:** AND-1 → Task 3. AND-2 → Task 5. AND-3 → Task 6. AND-4 → Task 5 Step 5. AND-5 → Task 7 Step 4. AND-6 → Task 7 Steps 2–3. AND-7 → Task 7 Step 5. AND-8 → Task 8. All eight covered.

**Known gap, stated rather than hidden:** no automated test covers `protect_fd`, the JNI bridge, or the two protect call sites, because none of them compiles off Android. Tasks 3, 5 and 6 rely on DEVICE verification alone. This is the phase's accepted risk and the reason Task 3 exists as a standalone gate.

**Deliberate A/B checks** (a passing test shown failing against the defect it names): Task 4 Step 3 and Task 3 Step 6. Both exist because this project has repeatedly shipped assertions that read the wrong thing.
