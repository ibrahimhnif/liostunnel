//! Profile operations the UI calls through `flutter_rust_bridge`.
//!
//! The app parses profiles here rather than re-implementing the schema in
//! Dart — that is exit criterion P1a-1. A format implemented twice drifts,
//! and the drift shows up as a user's profile working in the CLI and failing
//! in the app for no visible reason.

use crate::dto::profile::ProfileDto;

/// Parses a profile JSON document into a UI-shaped DTO.
///
/// Returns a description of the profile, never its secret material.
///
/// The error deliberately omits serde's message: its `Display` quotes keys
/// and enum tags from the offending input, and the input is a profile.
pub fn parse_profile(json: String) -> Result<ProfileDto, String> {
    let core: liostunnel_core::config::profile::ServerProfile =
        serde_json::from_str(&json).map_err(|_| "not a valid profile".to_string())?;
    Ok(ProfileDto::from(core))
}

/// Renders a DTO back to the canonical on-disk profile JSON.
///
/// Spec §9 asks for "portable import/export". Import is `parse_profile`;
/// this is export, so a profile can leave the app and come back unchanged.
/// §4 puts in-app *editing* out of scope, not portability.
///
/// The output is a profile document, so it names where secrets live and
/// never carries them — exactly what `parse_profile` accepted.
pub fn export_profile(dto: ProfileDto) -> Result<String, String> {
    let core = liostunnel_core::config::profile::ServerProfile::try_from(dto)
        .map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&core).map_err(|_| "could not serialize".to_string())
}

/// A fresh profile id.
///
/// Generated in Rust so the id format stays a property of the schema rather
/// than something Dart reimplements — the same reasoning as parse_profile
/// (P1a-1). A v4 UUID formatted the way `ServerProfile` expects to read it
/// back.
pub fn new_profile_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Checks a profile the UI is about to save, without touching its secret.
///
/// Deliberately NOT `ServerProfile::validate`: that resolves every
/// `SecretRef` through a `SecretStore`, which would have the app read key
/// material it has no business reading. This checks the shape only — the
/// helper re-validates properly at connect time, as the caller's uid.
pub fn check_profile(dto: ProfileDto) -> Result<(), String> {
    let core = liostunnel_core::config::profile::ServerProfile::try_from(dto)
        .map_err(|e| e.to_string())?;
    if core.host.trim().is_empty() {
        return Err("host must not be empty".into());
    }
    if core.port == 0 {
        return Err("port must not be zero".into());
    }
    if core.dns.servers.is_empty() {
        return Err("at least one DNS server is required".into());
    }
    // Mirrors ServerProfile::validate's DoH rules. Without these the editor
    // happily saved a profile with mode `https` and no endpoint, which the
    // helper then refused at connect time — the failure arriving minutes
    // later, from a different process, about a field the form never asked
    // for.
    if core.dns.mode == liostunnel_core::config::profile::DnsMode::Https {
        match &core.dns.https {
            None => return Err("DNS-over-HTTPS needs a server name and path".into()),
            Some(d) if d.sni.trim().is_empty() => {
                return Err("the DoH server name must not be empty".into());
            }
            Some(d) if !d.path.starts_with('/') => {
                return Err("the DoH path must start with `/`".into());
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// One-line summary for the profiles list.
pub fn profile_summary(dto: ProfileDto) -> String {
    format!("{} — {}:{}", dto.name, dto.host, dto.port)
}
