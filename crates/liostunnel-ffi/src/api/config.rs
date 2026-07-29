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
    if let liostunnel_core::config::profile::AuthMethod::Shadowsocks { method, .. } = &core.auth {
        check_cipher(method)?;
    }
    // And the pairing itself. Exactly the same reasoning one field over: the
    // editor's Authentication dropdown can be moved off Shadowsocks on an
    // imported profile, which leaves `protocol: shadowsocks` beside password
    // credentials. The cipher check above does not fire (there is no
    // Shadowsocks auth left to check), the save succeeds, and
    // `ShadowsocksTunnel::prepare` refuses it at connect time -- another
    // process, minutes later, about a field the form did offer.
    check_pairing(&core.protocol, &core.auth)?;
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

/// Refuses a cipher this build cannot construct, naming only what IS
/// offered.
///
/// Shared by [`check_profile`] and [`import_ss_uri`] so the save path and the
/// paste box give the same answer. The name the caller supplied is never in
/// the message: it is user input, and these errors reach a root-owned log and
/// come back over the wire.
fn check_cipher(method: &str) -> Result<(), String> {
    if liostunnel_core::protocols::shadowsocks::offered_ciphers().contains(&method) {
        return Ok(());
    }
    Err(format!(
        "that is not a cipher this build offers; one of: {}",
        liostunnel_core::protocols::shadowsocks::offered_ciphers().join(", ")
    ))
}

/// Refuses a profile whose protocol and credentials do not go together.
///
/// The three pairings below are the only ones any tunnel accepts:
/// `SshTunnel::connect` answers `Unsupported` to preshared-key and
/// shadowsocks credentials, and `ShadowsocksTunnel::prepare` refuses both a
/// non-shadowsocks protocol and non-shadowsocks credentials. Neither the
/// protocol nor the credential kind is echoed -- both are caller-supplied,
/// and the actionable half is which pairings exist.
fn check_pairing(
    protocol: &liostunnel_core::config::profile::ProtocolKind,
    auth: &liostunnel_core::config::profile::AuthMethod,
) -> Result<(), String> {
    use liostunnel_core::config::profile::{AuthMethod as A, ProtocolKind as P};
    let agrees = matches!(
        (protocol, auth),
        (P::Ssh, A::Password { .. })
            | (P::Ssh, A::PrivateKey { .. })
            | (P::WireGuard, A::PresharedKey { .. })
            | (P::Shadowsocks, A::Shadowsocks { .. })
    );
    if agrees {
        return Ok(());
    }
    Err(
        "this protocol and this kind of credential do not go together; ssh takes a password \
         or a private key, wireguard a pre-shared key, and shadowsocks its own"
            .into(),
    )
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
///
/// A cipher this build cannot construct is refused here, BEFORE the DTO
/// exists. `parse_ss_uri` deliberately does not check the method — the cipher
/// list has one owner — so this is the first place that can. Doing it later
/// was worth a crash: the caller writes the password to a `0600` file the
/// moment the import succeeds and only then puts the cipher in front of a
/// dropdown that asserts its value is one of its items, so an Outline key
/// (`2022-blake3-aes-256-gcm`) destroyed the editor with the credential
/// already on disk.
pub fn import_ss_uri(uri: String) -> Result<ProfileDto, String> {
    let p = parse(&uri)?;
    check_cipher(&p.method)?;
    Ok(ProfileDto {
        id: new_profile_id(),
        // `host:port`, not `host`. The name becomes a filename, and two links
        // to the same host on different ports would otherwise slug to one
        // file: the second import is refused by `checkNameFree` after the
        // caller has already written its secret.
        name: p.tag.unwrap_or_else(|| format!("{}:{}", p.host, p.port)),
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
        // A link carries no DNS information at all, and this DTO must still
        // be valid (`check_profile` refuses an empty list), so this is a
        // default and nothing more. It is the editor's own new-profile
        // default, both resolvers: a caller with no form in front of it —
        // a test, the CLI — should land where the form's user does. One
        // resolver is not the smaller choice, it is a worse one; `probe_once`
        // reads `dns.servers.first()` and fails the entire connect on an 8s
        // timeout if it does not answer. The editor, which has a form,
        // deliberately ignores this field: see `_import`.
        dns_servers: vec!["1.1.1.1".into(), "1.0.0.1".into()],
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

/// Renders a Shadowsocks profile as an `ss://` link the user can copy.
///
/// **The returned String carries the password.** It is what every other
/// Shadowsocks client accepts, which is the point, and there is no
/// secret-free form of an `ss://` link. The caller is responsible for asking
/// before putting it anywhere shared.
///
/// The password comes in as a parameter: the app runs as the user and the
/// secret file is the user's own, so Dart reads it. This crate does not open
/// files on the app's behalf.
///
/// Refusals name no field of the profile. Every one of them is
/// caller-supplied and this error crosses back over the wire.
pub fn export_ss_uri(dto: ProfileDto, password: String) -> Result<String, String> {
    if dto.auth_kind != "shadowsocks" || dto.protocol != "shadowsocks" {
        return Err("only a shadowsocks profile can be rendered as an ss:// link".into());
    }
    let method = dto
        .cipher
        .as_deref()
        .ok_or("a shadowsocks profile without a cipher cannot be rendered")?;
    Ok(liostunnel_core::protocols::ss_uri::render_ss_uri(
        method,
        &password,
        &dto.host,
        dto.port,
        Some(dto.name.as_str()).filter(|n| !n.is_empty()),
    ))
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

    const SAMPLE_SSH: &str = r#"{
        "id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Home VPS",
        "protocol":"ssh","host":"198.51.100.7","port":22,
        "auth":{"type":"password","password":{"source":"file","path":"/tmp/k"}},
        "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
        "kill_switch":false}"#;

    #[test]
    fn a_shadowsocks_profile_exports_to_a_link_that_imports_back() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388#Home")).unwrap();
        let link = export_ss_uri(dto.clone(), "pw".into()).unwrap();
        let back = import_ss_uri(link).unwrap();
        assert_eq!(back.host, dto.host);
        assert_eq!(back.port, dto.port);
        assert_eq!(back.cipher, dto.cipher);
        assert_eq!(back.name, "Home");
    }

    #[test]
    fn exporting_a_non_shadowsocks_profile_is_refused() {
        let dto = parse_profile(SAMPLE_SSH.into()).unwrap();
        let e = export_ss_uri(dto, "pw".into()).unwrap_err();
        assert!(
            e.contains("shadowsocks"),
            "must say which protocol this is for: {e}"
        );
    }

    /// The refusal must not quote the profile. Every field of it is
    /// caller-supplied and this error crosses back over the wire.
    #[test]
    fn an_export_refusal_never_echoes_the_profile() {
        let mut dto = parse_profile(SAMPLE_SSH.into()).unwrap();
        dto.host = "MARKER-HOST".into();
        dto.name = "MARKER-NAME".into();
        let e = export_ss_uri(dto, "MARKER-PASSWORD".into()).unwrap_err();
        for marker in ["MARKER-HOST", "MARKER-NAME", "MARKER-PASSWORD"] {
            assert!(!e.contains(marker), "echoed {marker}: {e}");
        }
    }

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

    /// Finding 1. An Outline or shadowsocks-rust key names
    /// `2022-blake3-aes-256-gcm` -- today's default server cipher -- and the
    /// import used to copy it straight into the DTO. The caller then wrote
    /// the password to disk and only afterwards handed the name to a
    /// dropdown that asserts its value is one of its items, so the editor
    /// died with the credential already on disk. Refused here, before a DTO
    /// exists, so nothing is written and the message lands at the paste box.
    #[test]
    fn a_cipher_this_build_cannot_construct_is_refused_at_import_time() {
        use base64::Engine;
        let creds =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("2022-blake3-aes-256-gcm:pw");
        let e = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388#Home")).unwrap_err();
        assert!(e.contains("aes-256-gcm"), "must say what IS offered: {e}");
        assert!(
            !e.contains("2022-blake3"),
            "must not echo the user's own input: {e}"
        );
        assert!(!e.contains("Home"), "nor any other part of the link: {e}");
    }

    /// The gap A/B 7 found: `check_profile` accepted any cipher string, so
    /// the editor could save a profile the helper refuses at connect time --
    /// minutes later, from another process, about a field the form offered.
    ///
    /// Reached by hand rather than through `import_ss_uri`, which refuses
    /// this cipher outright now: the profile can still arrive from a CLI-
    /// written file, where `method` is a free `String`.
    #[test]
    fn a_cipher_this_build_cannot_construct_is_refused_at_save_time() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let mut dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388")).unwrap();
        dto.auth_secret_source = "file:/tmp/k".into();
        dto.cipher = Some("2022-blake3-aes-256-gcm".into());
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

    /// Finding 5. One gesture reaches this: open an imported profile and
    /// change Authentication to Password. `_save` keeps the profile's
    /// `protocol` and the cipher check does not fire, so the save succeeded
    /// and `ShadowsocksTunnel::prepare` refused it at connect time -- from
    /// another process, minutes later, about a field the form did offer.
    /// That is verbatim the reasoning that justified the cipher check.
    #[test]
    fn a_protocol_that_disagrees_with_its_credentials_is_refused_at_save_time() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388")).unwrap();

        // Authentication switched to Password on a shadowsocks profile.
        let mut password_on_shadowsocks = dto.clone();
        password_on_shadowsocks.auth_kind = "password".into();
        password_on_shadowsocks.cipher = None;
        password_on_shadowsocks.auth_secret_source = "file:/tmp/k".into();
        let e = check_profile(password_on_shadowsocks).unwrap_err();
        assert!(
            e.contains("shadowsocks"),
            "must say what a shadowsocks profile needs: {e}"
        );

        // And the mirror image: shadowsocks credentials on an ssh profile,
        // which `SshTunnel::connect` refuses as unsupported.
        let mut shadowsocks_on_ssh = dto;
        shadowsocks_on_ssh.protocol = "ssh".into();
        shadowsocks_on_ssh.auth_secret_source = "file:/tmp/k".into();
        assert!(check_profile(shadowsocks_on_ssh).is_err());
    }

    #[test]
    fn every_pairing_the_helper_accepts_still_saves() {
        // The check must refuse disagreement without refusing the three
        // combinations that actually connect.
        let base = ProfileDto {
            id: new_profile_id(),
            name: "x".into(),
            protocol: "ssh".into(),
            host: "h".into(),
            port: 22,
            auth_kind: "password".into(),
            auth_secret_source: "file:/tmp/k".into(),
            auth_passphrase_source: None,
            peer_public_key: None,
            cipher: None,
            dns_mode: "tcp".into(),
            dns_servers: vec!["1.1.1.1".into()],
            doh_sni: None,
            doh_path: None,
            split_tunnel: "all_traffic".into(),
            split_tunnel_apps: Vec::new(),
            kill_switch: false,
        };
        for (protocol, auth_kind) in [
            ("ssh", "password"),
            ("ssh", "private_key"),
            ("wireguard", "preshared_key"),
            ("shadowsocks", "shadowsocks"),
        ] {
            let dto = ProfileDto {
                protocol: protocol.into(),
                auth_kind: auth_kind.into(),
                peer_public_key: (auth_kind == "preshared_key").then(|| "AAAA".to_string()),
                cipher: (auth_kind == "shadowsocks").then(|| "aes-256-gcm".to_string()),
                ..base.clone()
            };
            check_profile(dto).unwrap_or_else(|e| panic!("{protocol}/{auth_kind} refused: {e}"));
        }
    }

    /// Finding 3. An `ss://` link says nothing about DNS, so the import has
    /// to return *something*: the same pair the editor's own new-profile
    /// default uses. A single resolver is not a neutral choice -- `probe_once`
    /// reads `dns.servers.first()` and fails the whole connect on an 8s
    /// timeout if it does not answer.
    #[test]
    fn an_import_does_not_narrow_dns_to_one_resolver() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388")).unwrap();
        assert_eq!(
            dto.dns_servers,
            vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            "the editor's own default for a new profile"
        );
    }

    /// Finding 8. The name becomes a filename, and a filename is where two
    /// profiles collide: both of these slug to `198-51-100-7` if only the
    /// host is used, so the second import is refused by `checkNameFree` --
    /// after the caller has already written its secret file.
    #[test]
    fn two_untagged_links_to_the_same_host_are_named_apart() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let a = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388")).unwrap();
        let b = import_ss_uri(format!("ss://{creds}@198.51.100.7:8389")).unwrap();
        assert_eq!(a.name, "198.51.100.7:8388");
        assert_ne!(a.name, b.name);
    }

    #[test]
    fn a_bad_uri_is_refused_without_echoing_it() {
        use base64::Engine;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("no-colon-SECRET");
        let e = import_ss_uri(format!("ss://{b}")).unwrap_err();
        assert!(!e.contains("SECRET"), "echoed: {e}");
    }
}
