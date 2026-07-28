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

/// One-line summary for the profiles list.
pub fn profile_summary(dto: ProfileDto) -> String {
    format!("{} — {}:{}", dto.name, dto.host, dto.port)
}
