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
    // Same reasoning as the DoH rules below. Shadowsocks has no handshake, so
    // a cipher this build cannot construct is not caught by the server either
    // -- it surfaces at connect time as a config error from a different
    // process, minutes later, about a field the form did offer. The name is
    // not echoed back: it is the user's own input, and this error reaches a
    // root-owned log.
    if let liostunnel_core::config::profile::AuthMethod::Shadowsocks { method, .. } = &core.auth
        && !liostunnel_core::protocols::shadowsocks::offered_ciphers().contains(&method.as_str())
    {
        return Err(format!(
            "that is not a cipher this build offers; one of: {}",
            liostunnel_core::protocols::shadowsocks::offered_ciphers().join(", ")
        ));
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

/// The cipher names a Shadowsocks profile may use.
///
/// Exists so the editor's dropdown can be checked against the core's own
/// list rather than against a second copy of it. Offering a cipher the core
/// refuses is advice the user follows and that then fails as unknown -- a bug
/// the core's own list shipped with once already.
pub fn offered_ciphers() -> Vec<String> {
    liostunnel_core::protocols::shadowsocks::offered_ciphers()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Turns an `ss://` link into a profile the editor can show.
///
/// Returns the profile WITHOUT its password: `auth_secret_source` is left
/// empty and the caller writes the password to a `0600` file, then fills it
/// in. Returning the password inside the DTO would put a credential in a
/// value that crosses into Dart and gets rendered on screen — the one thing
/// this type exists not to do.
///
/// The password comes back separately from [`ss_uri_password`], which the
/// caller feeds straight to the secret writer without ever storing it.
///
/// The error deliberately says nothing about the link. An `ss://` URI *is*
/// the credential, so quoting any part of it — the blob, a fragment, "near
/// here" — puts a live password in a message that reaches a root-owned log
/// and comes back over the wire.
pub fn import_ss_uri(uri: String) -> Result<ProfileDto, String> {
    let p = parse(&uri)?;
    Ok(ProfileDto {
        id: new_profile_id(),
        name: p.tag.unwrap_or_else(|| p.host.clone()),
        protocol: "shadowsocks".into(),
        host: p.host,
        port: p.port,
        auth_kind: "shadowsocks".into(),
        cipher: Some(p.method),
        // Empty on purpose: no file holds this password yet. A placeholder
        // path here would name a file that does not exist, and the profile
        // would look ready to connect when it is not.
        auth_secret_source: String::new(),
        auth_passphrase_source: None,
        peer_public_key: None,
        dns_mode: "tcp".into(),
        dns_servers: vec!["1.1.1.1".into()],
        doh_sni: None,
        doh_path: None,
        split_tunnel: "all_traffic".into(),
        split_tunnel_apps: Vec::new(),
        kill_switch: false,
    })
}

/// The password from an `ss://` link, for the caller to write to a `0600`
/// file. Separate from [`import_ss_uri`] so the credential never travels
/// inside a struct that anything renders.
pub fn ss_uri_password(uri: String) -> Result<String, String> {
    Ok(parse(&uri)?.password.expose().clone())
}

/// Shared by both entry points so the link is parsed by one implementation.
///
/// Note the error is `e.to_string()` on a `TunnelError::Config` whose reason
/// is a `&'static str` by construction in `ss_uri` — that is what makes it
/// safe to surface. See `ss_uri::bad`.
fn parse(uri: &str) -> Result<liostunnel_core::protocols::ss_uri::SsUri, String> {
    liostunnel_core::protocols::ss_uri::parse_ss_uri(uri).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ss_uri_imports_to_a_usable_profile() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388#Home")).unwrap();
        assert_eq!(dto.name, "Home");
        assert_eq!(dto.host, "198.51.100.7");
        assert_eq!(dto.port, 8388);
        assert_eq!(dto.protocol, "shadowsocks");
        assert_eq!(dto.cipher.as_deref(), Some("aes-256-gcm"));
        // The password is NOT in the DTO. It comes back separately so the
        // caller can write it to a 0600 file.
        assert!(!format!("{dto:?}").contains("pw"));
    }

    #[test]
    fn an_imported_profile_needs_its_password_written_before_use() {
        // auth_secret_source is a placeholder until the caller writes the
        // password; it must not silently claim a file that does not exist.
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let dto = import_ss_uri(format!("ss://{creds}@h:1")).unwrap();
        assert!(
            dto.auth_secret_source.is_empty(),
            "the caller supplies this"
        );
    }

    /// The gap A/B 7 found: `check_profile` accepted any cipher string, so
    /// the editor could save a profile the helper refuses at connect time --
    /// minutes later, from another process, about a field the form offered.
    #[test]
    fn a_cipher_this_build_cannot_construct_is_refused_at_save_time() {
        use base64::Engine;
        let creds =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("2022-blake3-aes-256-gcm:pw");
        let mut dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388")).unwrap();
        dto.auth_secret_source = "file:/tmp/k".into();
        let e = check_profile(dto).unwrap_err();
        assert!(e.contains("aes-256-gcm"), "must say what IS offered: {e}");
        assert!(
            !e.contains("2022-blake3"),
            "must not echo the user's own input: {e}"
        );
    }

    #[test]
    fn an_offered_cipher_passes_the_same_check() {
        use base64::Engine;
        let creds =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pw");
        let mut dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388")).unwrap();
        dto.auth_secret_source = "file:/tmp/k".into();
        check_profile(dto).expect("an offered cipher must save");
    }

    #[test]
    fn a_bad_uri_is_refused_without_echoing_it() {
        use base64::Engine;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("no-colon-SECRET");
        let e = import_ss_uri(format!("ss://{b}")).unwrap_err();
        assert!(!e.contains("SECRET"), "echoed: {e}");
    }
}
