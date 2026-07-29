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

/// What a `file:` secret's *value* is, given the file's bytes.
///
/// Not the raw bytes. `FileSecretStore::resolve` — the thing the helper
/// actually connects with — strips one trailing line ending, because a
/// password written by `echo hunter2 > pw` means `hunter2` while a PEM private
/// key's own final newline is content. That rule has exactly one owner, in the
/// core, and this hands it to Dart rather than letting a second copy grow
/// there. A second copy is free to drift, on a rule whose entire purpose is
/// that two components agree about the user's password: the app read the file
/// itself and copied an `ss://` link carrying `hunter2\n`, which every other
/// client then derives a different key from, and Shadowsocks has no handshake
/// in which to report it.
///
/// Bytes in, because a credential is bytes: a binary pre-shared key or a
/// DER-encoded private key is not text, and `read_to_string` — like Dart's
/// `readAsStringSync` — answers one with a decoder's complaint about byte
/// offsets. A refusal is the honest outcome for anything that needs a
/// `String`, but it should be a sentence the app wrote. Nothing of the file
/// appears in it.
pub fn file_secret_value(bytes: Vec<u8>) -> Result<String, String> {
    let body = String::from_utf8(bytes)
        .map_err(|_| "this secret file is not text, so it cannot be read as a password")?;
    Ok(liostunnel_core::config::secret::strip_one_trailing_line_ending(&body).to_string())
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
///
/// **This is the well-formedness guard.** `render_ss_uri` is total, but not
/// every input renders something a Shadowsocks client can read: an empty host,
/// port 0, an IPv6 or bracketed host, an empty cipher and an empty password
/// each produce a link that this build's own `parse_ss_uri` then refuses.
/// `ProfileDto` enforces none of those — its fields are a `String`, a `u16` and
/// an `Option<String>` — and nothing upstream is guaranteed to have screened
/// them. Without these checks the user copies something no client can use.
///
/// It is deliberately NOT a round-trip guard, and that is the one asymmetry
/// with [`import_ss_uri`], which calls [`check_cipher`]. A profile written by
/// the CLI may name `2022-blake3-aes-256-gcm` — today's default server cipher —
/// and the link this renders for it is perfectly well formed and perfectly
/// usable in Outline or shadowsocks-rust. That it will not import back into
/// *this* build is a limitation of this build's cipher feature set, not a
/// defect in the link, and "copy as a link" exists precisely so a profile can
/// be used in another client. Refusing here would withhold a working link from
/// a profile this app cannot connect with OR edit — a dead end, in place of the
/// one gesture that still gets the user's own credential out. The cipher name
/// is not secret and the link says it plainly, so nothing is hidden by letting
/// it through. `a_link_is_rendered_for_a_cipher_this_build_cannot_speak` pins
/// this decision, including the half that makes it a decision: our own import
/// still refuses it.
pub fn export_ss_uri(dto: ProfileDto, password: String) -> Result<String, String> {
    if dto.auth_kind != "shadowsocks" || dto.protocol != "shadowsocks" {
        return Err("only a shadowsocks profile can be rendered as an ss:// link".into());
    }
    let method = dto
        .cipher
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or("a shadowsocks profile without a cipher cannot be rendered")?;
    if password.is_empty() {
        return Err("a link needs the profile's password, and this one is empty".into());
    }
    if dto.host.is_empty() {
        return Err("a link needs a host, and this profile has none".into());
    }
    // `parse_ss_uri` splits `host:port` on the last colon and refuses IPv6
    // outright — the packet stack is IPv4-only. A bracketed literal renders a
    // link that only this build's own parser would have to unpick, so it is
    // refused here rather than emitted.
    if dto.host.contains(':') || dto.host.contains('[') {
        return Err("an IPv6 host cannot be written as an ss:// link this build reads".into());
    }
    if dto.port == 0 {
        return Err("a link needs a port, and this profile's is zero".into());
    }
    Ok(liostunnel_core::protocols::ss_uri::render_ss_uri(
        method,
        &password,
        &dto.host,
        dto.port,
        // `render_ss_uri` maps `Some("")` to no fragment itself, so this is
        // just the `&str`.
        Some(dto.name.as_str()),
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
        // The cipher is set deliberately. Without it this test could not tell
        // the protocol guard from the no-cipher fallback: an SSH profile has
        // no cipher either, so dropping the protocol guard entirely still
        // produced a refusal whose message also contains "shadowsocks", and
        // the A/B that named the guard passed against its absence.
        let mut dto = parse_profile(SAMPLE_SSH.into()).unwrap();
        dto.cipher = Some("aes-256-gcm".into());
        let e = export_ss_uri(dto, "pw".into()).unwrap_err();
        assert!(
            e.contains("only a shadowsocks profile"),
            "must be the protocol guard, not the cipher fallback: {e}"
        );
    }

    /// Every shape that passes the protocol and cipher guards but renders a
    /// link this build's own parser refuses.
    ///
    /// Found by a reviewer running the real functions rather than reasoning
    /// about them: five of these reached `render_ss_uri` and produced a link
    /// that `parse_ss_uri` then rejected. The user copies a link, pastes it
    /// back, and it does not import.
    #[test]
    fn a_profile_that_would_render_an_unreadable_link_is_refused() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let good = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388#Home")).unwrap();

        // Concrete DTOs rather than a table of boxed closures: that shape is
        // exactly what clippy's `type_complexity` is for, and the mutations
        // read better inline anyway.
        let host = |h: &str| {
            let mut d = good.clone();
            d.host = h.into();
            d
        };
        let mut zero_port = good.clone();
        zero_port.port = 0;
        let mut empty_cipher = good.clone();
        empty_cipher.cipher = Some(String::new());

        for (what, dto, password) in [
            ("empty host", host(""), "pw"),
            ("ipv6 host", host("2001:db8::1"), "pw"),
            ("bracketed ipv6 host", host("[2001:db8::1]"), "pw"),
            ("port zero", zero_port, "pw"),
            ("empty cipher", empty_cipher, "pw"),
            ("empty password", good.clone(), ""),
        ] {
            assert!(
                export_ss_uri(dto, password.into()).is_err(),
                "{what} must be refused, not rendered into a link nothing reads"
            );
        }
    }

    /// The other half: everything the guard lets through must survive the
    /// round trip. A guard that refused everything would pass the test above.
    #[test]
    fn every_link_this_guard_lets_through_imports_back() {
        use base64::Engine;
        for (cipher, host, port, name) in [
            ("aes-256-gcm", "198.51.100.7", 8388u16, "Home"),
            ("aes-128-gcm", "example.com", 1u16, "a?b#c"),
            ("chacha20-ietf-poly1305", "h", 65535u16, ""),
        ] {
            let creds =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{cipher}:pw"));
            let mut dto = import_ss_uri(format!("ss://{creds}@{host}:{port}")).unwrap();
            dto.name = name.into();
            let link = export_ss_uri(dto.clone(), "pw".into())
                .unwrap_or_else(|e| panic!("{cipher}/{host}:{port} refused: {e}"));
            let back = import_ss_uri(link).expect("our own link must import");
            assert_eq!(back.host, dto.host);
            assert_eq!(back.port, dto.port);
            assert_eq!(back.cipher, dto.cipher);
            if !name.is_empty() {
                assert_eq!(back.name, name);
            }
        }
    }

    /// The decision the export guard makes about a cipher, stated once.
    ///
    /// `import_ss_uri` refuses `2022-blake3-aes-256-gcm`; this deliberately
    /// does not. A CLI-written profile can name it — `method` is a free
    /// `String` in the schema — and the link rendered for one is well formed
    /// and usable in Outline or shadowsocks-rust, which is the entire point of
    /// "copy as a link". Refusing would leave a profile this build can neither
    /// connect with nor edit with no way at all to get the user's own
    /// credential out.
    ///
    /// Both halves are asserted, because the second is what makes this a
    /// decision rather than an oversight: the link is real, and our own import
    /// still says no to it. If that ever becomes intolerable, the fix is
    /// `check_cipher` here AND the doc comment above losing its second
    /// paragraph — not one without the other.
    #[test]
    fn a_link_is_rendered_for_a_cipher_this_build_cannot_speak() {
        use base64::Engine;
        let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let mut dto = import_ss_uri(format!("ss://{creds}@198.51.100.7:8388#Home")).unwrap();
        dto.cipher = Some("2022-blake3-aes-256-gcm".into());

        let link = export_ss_uri(dto, "pw".into())
            .expect("a link for another client is not this build's to refuse");

        // Parsed by the core, which deliberately does not check the method --
        // the cipher list has one owner. This is what any other client sees.
        let seen = liostunnel_core::protocols::ss_uri::parse_ss_uri(&link).unwrap();
        assert_eq!(seen.method, "2022-blake3-aes-256-gcm");
        assert_eq!(seen.password.expose(), "pw");
        assert_eq!(seen.host, "198.51.100.7");
        assert_eq!(seen.port, 8388);

        // And the asymmetry, on purpose: this build will not take it back.
        assert!(
            import_ss_uri(link).is_err(),
            "if this ever imports, the export guard is no longer the looser of \
             the two and the doc comment above needs rewriting"
        );
    }

    /// The refusal must not quote the profile. Every field of it is
    /// caller-supplied and this error crosses back over the wire.
    #[test]
    fn an_export_refusal_never_echoes_the_profile() {
        let mut dto = parse_profile(SAMPLE_SSH.into()).unwrap();
        dto.host = "MARKER-HOST".into();
        dto.name = "MARKER-NAME".into();
        // `protocol` and `auth_kind` are the two fields the guard actually
        // reads, so they are the two most likely to end up interpolated into
        // its message -- and they were the two this test did not mark.
        dto.protocol = "MARKER-PROTOCOL".into();
        dto.auth_kind = "MARKER-AUTHKIND".into();
        dto.cipher = Some("MARKER-CIPHER".into());
        let e = export_ss_uri(dto, "MARKER-PASSWORD".into()).unwrap_err();
        for marker in [
            "MARKER-HOST",
            "MARKER-NAME",
            "MARKER-PROTOCOL",
            "MARKER-AUTHKIND",
            "MARKER-CIPHER",
            "MARKER-PASSWORD",
        ] {
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

    /// A `file:` secret's value is the core's, not the file's raw bytes.
    ///
    /// Asserted against `FileSecretStore` itself rather than against a second
    /// statement of the rule. That is the whole point of this function
    /// existing: the helper resolves the secret one way, and anything in the
    /// app that reads the same file must land on the same string or the two
    /// components disagree about what the user's password is. `_copyLink` read
    /// the file itself and handed the raw bytes to `export_ss_uri`, so a
    /// password written by `echo hunter2 > pw` -- the case the core's helper
    /// is documented for -- produced a link whose password was `hunter2\n`.
    /// The tunnel connects with `hunter2`; the link derives a different key,
    /// the server drops the ciphertext, and Shadowsocks has no handshake in
    /// which to say why.
    #[test]
    fn a_file_secrets_value_is_whatever_the_core_resolves() {
        use liostunnel_core::config::secret::{FileSecretStore, SecretRef, SecretStore};
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("lios-ffi-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Every shape the core's own helper distinguishes, so this cannot pass
        // by trimming more (or less) than the core does.
        for raw in [
            &b"hunter2\n"[..],
            b"hunter2\r\n",
            b"hunter2",
            b"hunter2\n\n",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----\n",
        ] {
            let p = dir.join("pw");
            std::fs::write(&p, raw).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();

            let resolved = FileSecretStore
                .resolve(&SecretRef::File { path: p.clone() })
                .unwrap();
            let ours = file_secret_value(raw.to_vec()).unwrap();
            assert_eq!(
                &ours,
                resolved.expose(),
                "the app must read {raw:?} as the helper does"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A credential is bytes, and not every credential is text.
    ///
    /// The refusal has to be ours. `readAsStringSync` in Dart answers a binary
    /// pre-shared key with a UTF-8 decoder's complaint about byte offsets,
    /// from a gesture that said "copy link", for a profile with nothing wrong
    /// with it -- the lesson `ProfileWriter._readSecretFile` already records
    /// one menu item over.
    #[test]
    fn a_secret_file_that_is_not_text_is_refused_in_our_own_words() {
        let e = file_secret_value(vec![0x00, 0xff, 0xfe, 0x80]).unwrap_err();
        assert!(
            e.contains("not text"),
            "the app's own sentence, not a decoder's: {e}"
        );
        // It reads a credential, so it may not quote one back.
        assert!(!e.contains("0xff") && !e.contains("byte"), "{e}");
    }
}
