//! `ss://` links, both forms in circulation. Spec §9.
//!
//! Parsed here rather than in Dart for the same reason profiles are: the
//! format has one owner. A second parser is free to drift from the first.

use base64::Engine;

use crate::config::secret::Redacted;
use crate::error::TunnelError;

/// The contents of a `ss://` link, before anything decides whether this build
/// can actually speak to it.
///
/// `method` is deliberately *not* checked against `shadowsocks::OFFERED` here.
/// Parsing reports what the link says; `ShadowsocksTunnel::connect` owns which
/// ciphers this build offers and already refuses the rest by name. Two places
/// that both know the cipher list is two places that can disagree about it.
///
/// `password` is a [`Redacted<String>`] rather than a `String` because this
/// struct derives `Debug`, and a caller that nests it in its own derived
/// `Debug` — which the import path in Task 6 does — would otherwise print the
/// credential into a log with no call site to blame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsUri {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub password: Redacted<String>,
    pub tag: Option<String>,
}

/// Every error is a fixed string.
///
/// The URI contains the password, so an error that quotes its input hands the
/// credential to a log. Phase 0 shipped that in `profile_io::load` and Phase
/// 1a shipped it again in the protocol codec; the tests named
/// `a_malformed_uri_never_echoes_itself` and `no_error_exit_echoes_any_part_of_the_uri`
/// are what stop a third. The `&'static str` is the enforcement: a caller
/// cannot pass a `format!` through this signature.
fn bad(reason: &'static str) -> TunnelError {
    TunnelError::config("ss uri", reason)
}

fn decode(s: &str) -> Result<String, TunnelError> {
    // Links appear with and without padding, and in both alphabets. The two
    // alphabets differ only in their 62nd and 63rd characters, so no input can
    // decode under both engines to different bytes -- the first success is the
    // only success.
    let engines = [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
    ];
    let trimmed = s.trim_end_matches('=');
    let bytes = engines
        .iter()
        .find_map(|e| e.decode(trimmed).ok())
        .ok_or_else(|| bad("the encoded section is not valid base64"))?;
    // Not `from_utf8_lossy`: a link whose credentials are not text is a broken
    // link, and silently substituting U+FFFD would turn it into an
    // authentication failure nobody can explain. Not `unwrap` either -- these
    // bytes come from a paste.
    String::from_utf8(bytes).map_err(|_| bad("the encoded section is not text"))
}

/// Splits `method:password` on the FIRST colon. Passwords contain colons.
fn split_creds(s: &str) -> Result<(String, Redacted<String>), TunnelError> {
    match s.split_once(':') {
        Some((m, p)) if !m.is_empty() && !p.is_empty() => {
            Ok((m.to_string(), Redacted::new(p.to_string())))
        }
        _ => Err(bad("expected method:password")),
    }
}

fn split_host_port(s: &str) -> Result<(String, u16), TunnelError> {
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| bad("expected host:port"))?;
    let port: u16 = p.parse().map_err(|_| bad("the port is not a number"))?;
    if h.is_empty() {
        return Err(bad("the host is empty"));
    }
    if port == 0 {
        return Err(bad("the port is zero"));
    }
    Ok((h.to_string(), port))
}

/// Parses either form of `ss://` link.
///
/// Total on `&str`: no byte indexing anywhere, because the input is a paste and
/// half of one is a normal thing to receive.
pub fn parse_ss_uri(uri: &str) -> Result<SsUri, TunnelError> {
    let rest = uri
        .strip_prefix("ss://")
        .ok_or_else(|| bad("not an ss:// link"))?;

    let (body, tag) = match rest.split_once('#') {
        Some((b, t)) => (b, (!t.is_empty()).then(|| t.to_string())),
        None => (rest, None),
    };
    // Query parameters (plugin=...) are ignored; plugins are out of scope.
    let body = body.split_once('?').map_or(body, |(b, _)| b);

    if let Some((creds, hostport)) = body.rsplit_once('@') {
        // SIP002: base64(method:password) @ host:port
        let (method, password) = split_creds(&decode(creds)?)?;
        let (host, port) = split_host_port(hostport)?;
        Ok(SsUri {
            host,
            port,
            method,
            password,
            tag,
        })
    } else {
        // Legacy: base64(method:password@host:port)
        let all = decode(body)?;
        let (creds, hostport) = all
            .rsplit_once('@')
            .ok_or_else(|| bad("expected method:password@host:port"))?;
        let (method, password) = split_creds(creds)?;
        let (host, port) = split_host_port(hostport)?;
        Ok(SsUri {
            host,
            port,
            method,
            password,
            tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    }

    fn b64_bytes(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    #[test]
    fn a_sip002_uri_parses() {
        let uri = format!("ss://{}@198.51.100.7:8388#Home", b64("aes-256-gcm:hunter2"));
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.method, "aes-256-gcm");
        assert_eq!(p.password.expose(), "hunter2");
        assert_eq!(p.tag.as_deref(), Some("Home"));
    }

    #[test]
    fn the_legacy_all_in_one_form_parses() {
        // Still in wide circulation; a client that only reads SIP002 rejects
        // half the links people actually have.
        let uri = format!("ss://{}", b64("aes-256-gcm:hunter2@198.51.100.7:8388"));
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.password.expose(), "hunter2");
        assert_eq!(p.tag, None);
    }

    #[test]
    fn a_password_containing_a_colon_survives() {
        // The method/password split is on the FIRST colon; passwords contain
        // colons routinely and a greedy split silently truncates them.
        let uri = format!("ss://{}@h:1#t", b64("aes-256-gcm:a:b:c"));
        assert_eq!(parse_ss_uri(&uri).unwrap().password.expose(), "a:b:c");
    }

    #[test]
    fn a_uri_without_a_tag_parses() {
        let uri = format!("ss://{}@198.51.100.7:8388", b64("aes-256-gcm:pw"));
        assert_eq!(parse_ss_uri(&uri).unwrap().tag, None);
    }

    #[test]
    fn a_uri_that_is_not_shadowsocks_is_refused() {
        assert!(parse_ss_uri("https://example.com").is_err());
        // A body that would parse perfectly under `ss://`, so the only thing
        // that can reject this is the scheme check itself. Without this case
        // the test passes against a parser that ignores the scheme entirely,
        // because `example.com` fails to base64-decode for unrelated reasons.
        let body = format!("{}@198.51.100.7:8388", b64("aes-256-gcm:pw"));
        assert!(parse_ss_uri(&format!("ssh://{body}")).is_err());
        assert!(parse_ss_uri(&format!("//{body}")).is_err());
    }

    #[test]
    fn a_malformed_uri_never_echoes_itself() {
        // The URI CONTAINS THE PASSWORD. This is the rule Phase 0 broke in
        // profile_io::load and Phase 1a broke again in the protocol codec.
        let uri = format!("ss://{}", b64("no-colon-here-SECRET"));
        let err = parse_ss_uri(&uri).unwrap_err();
        assert!(!format!("{err}").contains("SECRET"), "echoed: {err}");
        assert!(!format!("{err}").contains(&uri), "echoed the whole uri");
        assert!(!format!("{err:?}").contains("SECRET"));
    }

    /// Every reachable error exit, not just the one `a_malformed_uri_never_echoes_itself`
    /// happens to reach. An error that quotes its input is a credential in a
    /// root-owned log, and the caller wraps these into `TunnelError` and logs
    /// them with `tracing::warn!(error = %e)`.
    #[test]
    fn no_error_exit_echoes_any_part_of_the_uri() {
        let marker = "SECRETMARKER";
        let cases = [
            // not an ss:// link
            format!("https://{marker}"),
            // the encoded section is not base64 at all
            format!("ss://!!{marker}!!@198.51.100.7:8388"),
            // base64, but not method:password
            format!("ss://{}@198.51.100.7:8388", b64(marker)),
            // base64, but no @host:port in the legacy form
            format!("ss://{}", b64(marker)),
            // legacy form, credentials present but not method:password
            format!("ss://{}", b64(&format!("{marker}@198.51.100.7:8388"))),
            // the port is not a number
            format!(
                "ss://{}@198.51.100.7:notaport",
                b64(&format!("aes-256-gcm:{marker}"))
            ),
            // the host is empty
            format!("ss://{}@:8388", b64(&format!("aes-256-gcm:{marker}"))),
            // no host:port at all
            format!("ss://{}@nocolon", b64(&format!("aes-256-gcm:{marker}"))),
            // the port does not fit in a u16
            format!(
                "ss://{}@198.51.100.7:99999",
                b64(&format!("aes-256-gcm:{marker}"))
            ),
            // decodes to bytes that are not text
            format!("ss://{}@198.51.100.7:8388", b64_bytes(&[0xff, 0xfe, 0xfd])),
        ];
        for uri in cases {
            let err = parse_ss_uri(&uri).expect_err("should not parse");
            let display = format!("{err}");
            let debug = format!("{err:?}");
            let source = std::error::Error::source(&err).map(|s| format!("{s} {s:?}"));
            for rendered in [Some(display), Some(debug), source].into_iter().flatten() {
                assert!(
                    !rendered.contains(marker),
                    "echoed the credential: {rendered}"
                );
                assert!(!rendered.contains(&uri), "echoed the whole uri: {rendered}");
                // Not even a fragment of the encoded section.
                assert!(
                    !rendered.contains("198.51.100.7"),
                    "echoed the uri's contents: {rendered}"
                );
            }
        }
    }

    #[test]
    fn the_parsed_password_is_not_rendered_by_debug() {
        // The password must be carried in a type that cannot print itself, so
        // that it stays redacted when a caller nests `SsUri` inside its own
        // derived `Debug` — which is exactly what Task 6's import path will do.
        let uri = format!("ss://{}@198.51.100.7:8388#Home", b64("aes-256-gcm:SECRET"));
        let p = parse_ss_uri(&uri).unwrap();
        let rendered = format!("{p:?}");
        assert!(
            !rendered.contains("SECRET"),
            "password leaked into Debug: {rendered}"
        );
        assert!(
            rendered.contains("198.51.100.7"),
            "the non-secret fields should still be debuggable: {rendered}"
        );
    }

    #[test]
    fn a_port_that_is_not_a_port_is_refused() {
        let uri = format!("ss://{}@h:notaport", b64("aes-256-gcm:pw"));
        assert!(parse_ss_uri(&uri).is_err());
    }

    #[test]
    fn a_zero_port_is_refused() {
        // `ServerProfile::validate` rejects port 0 anyway, but it rejects it as
        // a config error against a profile the user did not type -- they typed
        // a link. Refusing it here names the thing they can actually fix.
        let uri = format!("ss://{}@198.51.100.7:0", b64("aes-256-gcm:pw"));
        assert!(parse_ss_uri(&uri).is_err());
    }

    #[test]
    fn truncated_input_is_an_error_never_a_panic() {
        // A `ss://` link arrives as a paste, so every one of these is a real
        // input. Nothing here may index by byte offset: the last few cut a
        // multi-byte character in half at exactly the offset a naive
        // `&uri[5..]` would slice.
        let truncated = [
            "",
            "s",
            "ss",
            "ss:",
            "ss:/",
            "ss://",
            "ss://#",
            "ss://@",
            "ss://@:",
            "ss://:@",
            "ss://#tag",
            "ss://?plugin=x",
            "ss:/\u{1f600}",
            "ss:/\u{1f600}\u{1f600}",
            "ss://\u{1f600}",
            "ss://\u{1f600}@\u{1f600}:1",
            "\u{1f600}",
        ];
        for uri in truncated {
            assert!(
                parse_ss_uri(uri).is_err(),
                "should have been refused cleanly: {uri:?}"
            );
        }
    }

    #[test]
    fn an_encoded_section_that_is_not_text_is_an_error_never_a_panic() {
        // Valid base64 whose bytes are not UTF-8. `String::from_utf8` is the
        // only thing standing between this and a panic on a pasted link.
        let raw = b64_bytes(&[0xff, 0xfe, 0x80, 0x01]);
        assert!(parse_ss_uri(&format!("ss://{raw}")).is_err());
        assert!(parse_ss_uri(&format!("ss://{raw}@198.51.100.7:8388")).is_err());
    }
}
