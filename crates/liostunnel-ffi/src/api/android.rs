//! Android tunnel control.
//!
//! # Why this exists only on Android
//!
//! On desktop the engine runs in `liostunnel-helper`, as root, and the app
//! drives it over a unix socket. Android has no helper and no such socket:
//! the per-app sandbox is the privilege boundary, and the engine runs in this
//! process. These functions are the app's only way to reach it.
//!
//! # Credentials come through here, and only here
//!
//! [`android_stage_profile`] is where the password or key crosses into the
//! engine. It goes Dart → Rust directly. Nothing is passed to Kotlin, and
//! nothing goes into the `Intent` that starts the service — an `Intent` extra
//! can be written to the system log, and `MethodChannel` arguments are
//! ordinary Java objects visible in a heap dump.

use crate::dto::profile::ProfileDto;

/// A secret the app resolved, paired with the reference the profile uses.
///
/// `kind` is `"file"` or `"env"`, matching `SecretRef`'s two forms, and `key`
/// is the path or variable name the profile names. The engine looks secrets
/// up by reference, so both halves are needed to match them.
pub struct SecretPair {
    pub kind: String,
    pub key: String,
    pub value: String,
}

/// Engine state, flattened for the UI.
///
/// `detail` carries the failure reason and is empty otherwise. Kept separate
/// from `state` so the UI can show a reason without parsing a string.
pub struct EngineStatusDto {
    pub state: String,
    pub detail: String,
}

/// Counters, mirroring the desktop `Stats` frame so `ConnectionModel`
/// consumes one shape on both platforms.
pub struct EngineStatsDto {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active_flows: u64,
    pub flows_failed: u64,
    pub dns_queries: u64,
}

/// Hands the engine a profile and its secrets, ready for the service to start.
///
/// Must be called before asking Android to start the service. The descriptor
/// arrives from a different direction entirely — Kotlin, over JNI — and the
/// engine needs both halves before it can run.
#[cfg(target_os = "android")]
pub fn android_stage_profile(
    dto: ProfileDto,
    user: String,
    secrets: Vec<SecretPair>,
) -> Result<(), String> {
    use liostunnel_core::config::profile::ServerProfile;
    use liostunnel_core::config::secret::SecretRef;
    use liostunnel_core::platform::android::engine::{AndroidSecrets, StartRequest, stage};

    let profile = ServerProfile::try_from(dto).map_err(|e| e.to_string())?;

    let pairs = secrets
        .into_iter()
        .map(|s| {
            let r = match s.kind.as_str() {
                "file" => SecretRef::File {
                    path: s.key.clone().into(),
                },
                "env" => SecretRef::Env { var: s.key.clone() },
                other => return Err(format!("unknown secret kind: {other}")),
            };
            Ok((r, s.value))
        })
        .collect::<Result<Vec<_>, String>>()?;

    stage(StartRequest {
        profile,
        user,
        secrets: AndroidSecrets::new(pairs),
    });
    Ok(())
}

/// The engine's current state.
#[cfg(target_os = "android")]
pub fn android_status() -> EngineStatusDto {
    use liostunnel_core::platform::android::engine::{EngineState, state};
    match state() {
        EngineState::Idle => EngineStatusDto {
            state: "idle".into(),
            detail: String::new(),
        },
        EngineState::Connecting => EngineStatusDto {
            state: "connecting".into(),
            detail: String::new(),
        },
        EngineState::Connected => EngineStatusDto {
            state: "connected".into(),
            detail: String::new(),
        },
        EngineState::Failed(why) => EngineStatusDto {
            state: "failed".into(),
            detail: why,
        },
    }
}

/// Current counters. Zeros when nothing is running.
#[cfg(target_os = "android")]
pub fn android_stats() -> EngineStatsDto {
    let (bytes_up, bytes_down, active_flows, flows_failed, dns_queries) =
        liostunnel_core::platform::android::engine::stats();
    EngineStatsDto {
        bytes_up,
        bytes_down,
        active_flows,
        flows_failed,
        dns_queries,
    }
}

// Off Android these are compiled as failures rather than omitted, so the
// generated Dart binding exists on every platform and the UI can call it
// behind a `Platform.isAndroid` check without a second code path.

#[cfg(not(target_os = "android"))]
pub fn android_stage_profile(
    _dto: ProfileDto,
    _user: String,
    _secrets: Vec<SecretPair>,
) -> Result<(), String> {
    Err("the in-process engine exists only on Android".into())
}

#[cfg(not(target_os = "android"))]
pub fn android_status() -> EngineStatusDto {
    EngineStatusDto {
        state: "idle".into(),
        detail: String::new(),
    }
}

#[cfg(not(target_os = "android"))]
pub fn android_stats() -> EngineStatsDto {
    EngineStatsDto {
        bytes_up: 0,
        bytes_down: 0,
        active_flows: 0,
        flows_failed: 0,
        dns_queries: 0,
    }
}
