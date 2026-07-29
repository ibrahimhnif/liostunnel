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
    // `rsplit_once(':')` above takes the LAST colon, so an IPv6 literal
    // either keeps its brackets (`h == "[2001:db8::1]"`) or, unbracketed,
    // silently donates its trailing hextet to `port`. Refused here, plainly,
    // rather than left to fail much later at resolution with an unrelated
    // message. This is a clarity fix, not a capability loss: the stack is
    // IPv4-only regardless.
    if h.contains(':') || h.contains('[') {
        return Err(bad(
            "IPv6 hosts are not supported; this build only speaks IPv4",
        ));
    }
    Ok((h.to_string(), port))
}

/// Percent-encodes everything outside RFC 3986's unreserved set.
///
/// Conservative on purpose. The tag is a profile name and this only has to be
/// total and reversible, not minimal -- an over-encoded tag is ugly in a link
/// and correct; an under-encoded one silently truncates someone's profile
/// name at the first `#`.
fn encode_tag(tag: &str) -> String {
    let mut out = String::with_capacity(tag.len());
    for b in tag.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The inverse, deliberately lenient.
///
/// Links in circulation carry raw tags -- `#My Server` is ordinary -- so a
/// strict decoder would reject or mangle every link a provider has issued.
/// `%` followed by two hex digits decodes; anything else, including a bare
/// `%`, is literal. Total on any `&str`: iterates bytes, never indexes.
fn decode_tag(tag: &str) -> String {
    let b = tag.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    // A tag whose decoded bytes are not text is a broken tag, not a reason to
    // fail the whole link: fall back to the input unchanged rather than
    // erroring on a field that is only a label.
    String::from_utf8(out).unwrap_or_else(|_| tag.to_string())
}

/// Parses either form of `ss://` link.
///
/// Total on `&str`: no byte indexing anywhere, because the input is a paste and
/// half of one is a normal thing to receive.
pub fn parse_ss_uri(uri: &str) -> Result<SsUri, TunnelError> {
    // A pasted link routinely carries a leading/trailing newline or space;
    // `trim` is total on any `&str` (it works on whitespace, not byte
    // offsets), so this adds no panic surface.
    let uri = uri.trim();
    let rest = uri
        .strip_prefix("ss://")
        .ok_or_else(|| bad("not an ss:// link"))?;

    let (body, tag) = match rest.split_once('#') {
        Some((b, t)) => (b, (!t.is_empty()).then(|| decode_tag(t))),
        None => (rest, None),
    };
    // Query parameters (plugin=...) are ignored; plugins are out of scope.
    let body = body.split_once('?').map_or(body, |(b, _)| b);

    if let Some((creds, hostport)) = body.rsplit_once('@') {
        // SIP002: base64(method:password) @ host:port
        //
        // SIP002's ABNF allows an optional trailing `/` after the port
        // (every Outline access key carries one). Stripped here, scoped to
        // this already-`@`-split `hostport` -- NOT from `body` above. A fix
        // that instead treats `/` as a generic path separator on the shared
        // `body` (e.g. truncating at the first `/`) happens to still work
        // for SIP002 but silently corrupts a legacy blob whose base64
        // (standard alphabet) contains `/` as an ordinary data character.
        let hostport = hostport.strip_suffix('/').unwrap_or(hostport);
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

/// Renders a SIP002 `ss://` link.
///
/// **The returned `String` is a credential.** It carries the password in a
/// form any Shadowsocks client can use. Callers must treat it as one: it
/// belongs on a clipboard the user asked for, and nowhere else -- not an
/// error, not a log, not a widget.
///
/// The password is a parameter rather than a field of a struct that crosses a
/// boundary, for the same reason `ss_uri_password` is a separate FFI call
/// from `import_ss_uri`: a credential inside a value that gets rendered is the
/// thing this module exists to prevent.
pub fn render_ss_uri(
    method: &str,
    password: &str,
    host: &str,
    port: u16,
    tag: Option<&str>,
) -> String {
    let creds =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
    let fragment = match tag {
        Some(t) if !t.is_empty() => format!("#{}", encode_tag(t)),
        _ => String::new(),
    };
    format!("ss://{creds}@{host}:{port}{fragment}")
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
    fn a_sip002_uri_with_the_optional_path_and_query_parses() {
        // SIP002's ABNF is `"ss://" userinfo "@" hostname ":" port [ "/" ]
        // [ "?" plugin ] [ "#" tag ]` -- every Outline access key carries the
        // trailing `/`. Without handling it, the query strip at `?` leaves
        // `host:port/`, and the port parse fails on `port/`, misreporting a
        // conformant link as having a non-numeric port.
        let uri = format!(
            "ss://{}@198.51.100.7:8388/?outline=1#Home",
            b64("aes-256-gcm:hunter2")
        );
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.tag.as_deref(), Some("Home"));
    }

    #[test]
    fn a_sip002_uri_with_a_trailing_slash_and_no_query_parses() {
        // The trailing-slash-without-query form of the same defect.
        let uri = format!("ss://{}@198.51.100.7:8388/", b64("aes-256-gcm:hunter2"));
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
    }

    #[test]
    fn a_legacy_link_using_padded_standard_alphabet_with_a_slash_parses() {
        // Legacy links are conventionally emitted standard-alphabet and often
        // padded -- `decode`'s dual-alphabet/padding tolerance has no coverage
        // otherwise, since every other fixture goes through `b64`/`b64_bytes`
        // (URL_SAFE_NO_PAD only). This body's base64 also contains a literal
        // `/`, which pins that the SIP002 fix for the optional trailing slash
        // must not strip `/` from `body` before the `@` split: the standard
        // alphabet uses `/` as a real data character, and a body-wide strip
        // (rather than one scoped to the SIP002 branch's already-split
        // `hostport`) would silently truncate a legacy blob like this one.
        let plaintext = "aes-256-gcm:.NnOB?FXL4k@198.51.100.7:8388";
        let encoded = base64::engine::general_purpose::STANDARD.encode(plaintext);
        assert!(encoded.contains('/'), "fixture must contain a literal /");
        assert!(encoded.ends_with('='), "fixture must be padded");
        let uri = format!("ss://{encoded}");
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.password.expose(), ".NnOB?FXL4k");
    }

    #[test]
    fn a_sip002_uri_using_padded_standard_alphabet_parses() {
        // The SIP002-form counterpart of the test above: standard-alphabet,
        // padded, and containing a character (`+`) outside the URL-safe
        // alphabet, so deleting either `STANDARD_NO_PAD` from the engine list
        // or the `=`-trim breaks it.
        let plaintext = "aes-256-gcm:(Jr3(J1T~W";
        let encoded = base64::engine::general_purpose::STANDARD.encode(plaintext);
        assert!(encoded.contains('+'), "fixture must contain a literal +");
        assert!(encoded.ends_with('='), "fixture must be padded");
        let uri = format!("ss://{encoded}@198.51.100.7:8388");
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.password.expose(), "(Jr3(J1T~W");
    }

    #[test]
    fn surrounding_whitespace_from_a_paste_is_tolerated() {
        // A trailing newline is the single most common paste accident, and
        // without a trim it is refused as "the encoded section is not valid
        // base64" -- the least helpful message in the module, since the link
        // itself was fine.
        let uri = format!(
            "  ss://{}@198.51.100.7:8388#Home\n",
            b64("aes-256-gcm:hunter2")
        );
        let p = parse_ss_uri(&uri).unwrap();
        assert_eq!(p.host, "198.51.100.7");
        assert_eq!(p.port, 8388);
        assert_eq!(p.password.expose(), "hunter2");
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
        // No `"//{body}"` case: under a scheme-ignoring mutation that string
        // has length ≡ 1 (mod 4) and fails base64 decode for reasons wholly
        // unrelated to the scheme check, so it would pass against the exact
        // defect this test exists to catch. Only the `ssh://` case above
        // carries signal; a second assertion that reads as a witness but
        // isn't is worse than no assertion.
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
            // the port is zero
            format!(
                "ss://{}@198.51.100.7:0",
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
        // Deliberate policy choice, not an oversight: `SsUri` is a parse
        // result a developer inspects directly, so its non-secret fields
        // (including `host`) stay in `Debug` for debuggability -- only the
        // password is redacted, via its own type. This is NOT a precedent
        // for DTOs downstream: Task 6's import path nests `SsUri` and other
        // profile data into its own types, and a Task 4 fix wave already had
        // to remove `profile.host` from exactly those logging sinks. A Task
        // 6 reviewer should check that its DTO does not itself derive (or
        // hand-roll) a `Debug`/`Display` that gets logged with `{:?}`/`{}`.
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
    fn a_bracketed_ipv6_host_is_refused_with_an_accurate_message() {
        // Accepted with brackets intact today, producing a profile that only
        // fails much later at resolution with an unrelated message. This
        // stack is IPv4-only, so refuse it here, clearly, instead of later.
        let uri = format!("ss://{}@[2001:db8::1]:8388", b64("aes-256-gcm:pw"));
        let err = parse_ss_uri(&uri).unwrap_err();
        assert!(format!("{err}").contains("IPv4"));
    }

    #[test]
    fn an_unbracketed_ipv6_host_is_refused_not_silently_misparsed() {
        // Without a check, `rsplit_once(':')` takes the LAST colon, silently
        // accepting the trailing segment as the port and everything before
        // it -- `2001:db8::1` -- as the host.
        let uri = format!("ss://{}@2001:db8::1:8388", b64("aes-256-gcm:pw"));
        let err = parse_ss_uri(&uri).unwrap_err();
        assert!(format!("{err}").contains("IPv4"));
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

    /// The round trip is the whole point: a link this build renders must parse
    /// back to what it was rendered from. A password containing `@` and `:` is
    /// the case that makes the parser's `rsplit_once`/`split_once` choices
    /// non-obvious, so it is the case the test uses.
    #[test]
    fn a_rendered_link_parses_back_to_what_it_was_rendered_from() {
        let link = render_ss_uri(
            "aes-256-gcm",
            "p@ss:word",
            "198.51.100.7",
            8388,
            Some("Home"),
        );
        let back = parse_ss_uri(&link).expect("our own output must parse");
        assert_eq!(back.method, "aes-256-gcm");
        assert_eq!(back.password.expose(), "p@ss:word");
        assert_eq!(back.host, "198.51.100.7");
        assert_eq!(back.port, 8388);
        assert_eq!(back.tag.as_deref(), Some("Home"));
    }

    /// The tag is the profile's NAME, and a name is whatever the user typed.
    /// Unencoded, `#` starts a second tag and `?` starts a query the parser
    /// strips -- so the name comes back truncated or wrong.
    #[test]
    fn a_name_with_uri_syntax_in_it_survives_the_round_trip() {
        for name in ["Home #2", "a?b", "100%", "My Server", "café", "a&b=c"] {
            let link = render_ss_uri("aes-256-gcm", "pw", "h", 1, Some(name));
            let back = parse_ss_uri(&link).expect("must parse");
            assert_eq!(back.tag.as_deref(), Some(name), "link was {link}");
        }
    }

    /// Links already in circulation carry raw, unencoded tags. Rejecting or
    /// mangling those would break every link a provider has ever issued.
    #[test]
    fn a_raw_tag_from_an_existing_link_still_reads_literally() {
        let creds = b64("aes-256-gcm:pw");
        let back = parse_ss_uri(&format!("ss://{creds}@h:1#My Server")).unwrap();
        assert_eq!(back.tag.as_deref(), Some("My Server"));
        // A bare `%` is not an escape and must not be swallowed.
        let back = parse_ss_uri(&format!("ss://{creds}@h:1#100% done")).unwrap();
        assert_eq!(back.tag.as_deref(), Some("100% done"));
    }

    #[test]
    fn an_untagged_link_renders_without_a_fragment() {
        let link = render_ss_uri("aes-256-gcm", "pw", "h", 1, None);
        assert!(!link.contains('#'), "no tag means no fragment: {link}");
        assert_eq!(parse_ss_uri(&link).unwrap().tag, None);
    }

    /// Every offered cipher must survive, not just the one the other tests use.
    #[test]
    fn every_offered_cipher_round_trips_through_a_rendered_link() {
        for m in crate::protocols::shadowsocks::offered_ciphers() {
            let link = render_ss_uri(m, "pw", "198.51.100.7", 8388, None);
            assert_eq!(parse_ss_uri(&link).unwrap().method, *m, "{m}");
        }
    }
}
