# Profile Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make creating, finding, copying and sharing a profile match how they are actually used — a pasted `ss://` link as the front door, search and duplicate on the list, and a link you can copy back out.

**Architecture:** Rendering an `ss://` link goes in Rust beside the parser, because two implementations of a format whose payload is a password is how they drift. The Dart side gains a `duplicate` on `ProfileWriter`, a search field and overflow menu on the list, and a link row plus a Server/Advanced split in the editor. No new persistent state and no change to the profile document format.

**Tech Stack:** Rust 2024 / 1.93, flutter_rust_bridge 2.12.0, Flutter (Material 3).

## Global Constraints

Every task's requirements implicitly include this section.

- **Rust edition 2024, `rust-version = "1.93"`. flutter_rust_bridge 2.12.0** (2.13.0-beta is a prerelease and forbidden).
- **An `ss://` link IS a credential.** It must never appear in an error message, a log line, a `Debug` output, a snackbar, or any on-screen text. `ss_uri.rs`'s `bad(reason: &'static str)` is the only error constructor in that module and stays that way — a `format!` cannot pass through that signature, and that is the enforcement, not a convention.
- **No new dependency for percent-encoding.** `percent-encoding` is in the lock file only transitively and behind the optional `doh` feature chain; `ss_uri.rs` must build under `--no-default-features`. Hand-roll it, as specified in Task 1.
- **Nothing destructive runs before it is known to be valid.** `writeSecret` overwrites the file keyed to a profile id, so any new path that writes a secret must validate first. A refused save that destroyed the credential it was refusing has already shipped in this codebase once.
- **TDD, strictly.** Failing test first, run it, confirm it fails for the *expected* reason, then implement. Report RED and GREEN transcripts.
- **A test that passes must be shown failing against the defect it names.** Phase 1b caught more than twenty tests that were green while the thing they named was broken, several found only because an A/B refused to fail. Every A/B is run and its transcript pasted.
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, and `flutter analyze` must pass before every commit.
- **Dart changes require `./testing/build-ffi-for-tests.sh` before `flutter test`** — the app links Rust statically, but `flutter test` opens a dylib by path.
- **Generated code** (`crates/liostunnel-ffi/src/frb_generated.rs`, `app/lib/src/rust/**`) comes from `flutter_rust_bridge_codegen generate`. Run it when the FFI surface changes; never hand-edit it.
- Conventional commit prefixes. **Write commit messages to a file and use `git commit -F`** — backticks inside `-m` are command substitution and will execute. This has happened once in this project and ran a `route delete`.
- **`profile_editor.dart` is 692 lines and a prior change landed on one of two branches** because `dart format` had rewrapped the other; the missing control was reported as present twice before anyone read the source. Verify every change on every path a user can reach it.

## File structure

| File | Responsibility |
|---|---|
| `crates/liostunnel-core/src/protocols/ss_uri.rs` | `render_ss_uri`, tag percent-encoding, matching lenient decode in `parse_ss_uri` |
| `crates/liostunnel-ffi/src/api/config.rs` | `export_ss_uri` — the DTO-shaped entry point |
| `app/lib/services/profile_writer.dart` | `duplicate` — new id, non-colliding name, its own secret file |
| `app/lib/screens/profiles.dart` | search field, per-row overflow menu |
| `app/lib/screens/profile_editor.dart` | link row on create only, Server/Advanced split |
| `app/lib/main.dart` | wiring for the new list callbacks |

**Milestones.** A (Tasks 1–2) is the link out. B (Task 3) is duplicate, the one with a credential-loss failure mode. C (Tasks 4–5) is the UI.

---

### Task 1: `render_ss_uri` and a tag that survives the round trip

**Files:**
- Modify: `crates/liostunnel-core/src/protocols/ss_uri.rs`

**Interfaces:**
- Produces: `pub fn render_ss_uri(method: &str, password: &str, host: &str, port: u16, tag: Option<&str>) -> String`

**Why the parser changes too.** `parse_ss_uri` splits on the first `#` and takes everything after it as the tag, then strips a `?` query from the body. A profile named `Home #2` renders a link that parses back as `Home ` with a different tag; one named `a?b` loses part of its name. So the tag is percent-encoded on render and leniently decoded on parse.

**Lenient decode is the requirement, not strictness.** Links in circulation carry raw tags (`#My Server`). A decoder that rejected them would break every existing link. `%` followed by two hex digits decodes; anything else — including a bare `%` — passes through literally.

- [ ] **Step 1: Write the failing tests**

Add to `ss_uri.rs`'s tests module:

```rust
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel-core --lib ss_uri`
Expected: FAIL — `cannot find function 'render_ss_uri' in this scope`.

- [ ] **Step 3: Implement percent-encoding**

Add above `parse_ss_uri`:

```rust
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
```

- [ ] **Step 4: Implement `render_ss_uri`**

Add below `parse_ss_uri`:

```rust
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
    let creds = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{method}:{password}"));
    let fragment = match tag {
        Some(t) if !t.is_empty() => format!("#{}", encode_tag(t)),
        _ => String::new(),
    };
    format!("ss://{creds}@{host}:{port}{fragment}")
}
```

- [ ] **Step 5: Decode the tag on parse**

In `parse_ss_uri`, replace the tag binding:

```rust
    let (body, tag) = match rest.split_once('#') {
        Some((b, t)) => (b, (!t.is_empty()).then(|| decode_tag(t))),
        None => (rest, None),
    };
```

- [ ] **Step 6: Run to verify they pass**

Run: `cargo test -p liostunnel-core --lib ss_uri`
Expected: PASS, 24 tests.

- [ ] **Step 7: A/B each new assertion**

Run each, capture the failure, revert:

| Change | Test that must fail |
|---|---|
| `encode_tag` returns `tag.to_string()` unchanged | `a_name_with_uri_syntax_in_it_survives_the_round_trip` |
| `decode_tag` returns `tag.to_string()` unchanged | same |
| `decode_tag` decodes `%` unconditionally (drop the hex check) | `a_raw_tag_from_an_existing_link_still_reads_literally` |
| `render_ss_uri` uses `STANDARD` (padded) instead of `URL_SAFE_NO_PAD` | `a_rendered_link_parses_back_to_what_it_was_rendered_from` |
| `render_ss_uri` emits `#` even when `tag` is `None` | `an_untagged_link_renders_without_a_fragment` |

- [ ] **Step 8: Verify the lean build**

Run: `cargo test -p liostunnel-core --no-default-features --no-run`
Expected: compiles. No new dependency was added; `encode_tag`/`decode_tag` are hand-rolled precisely so this holds.

- [ ] **Step 9: Commit**

```bash
git add crates/liostunnel-core/src/protocols/ss_uri.rs
git commit -F /tmp/msg-t1.txt
```

with `/tmp/msg-t1.txt`:

```
feat: render ss:// links, with a tag that survives the round trip

Rendering lives beside parsing because the format has one owner -- and this
one's payload is a password, so a second implementation free to drift is
worse here than anywhere else.

The tag is the profile's name and a name is user-typed. Unencoded, a profile
called "Home #2" renders a link that parses back with a different name, and
one called "a?b" loses part of it to the query-stripping. So the tag is
percent-encoded on render and leniently decoded on parse: %XX decodes,
anything else is literal, because every link a provider has ever issued
carries a raw tag and rejecting those would be worse than the bug.
```

---

### Task 2: `export_ss_uri` across the FFI

**Files:**
- Modify: `crates/liostunnel-ffi/src/api/config.rs`
- Regenerate: `crates/liostunnel-ffi/src/frb_generated.rs`, `app/lib/src/rust/**`

**Interfaces:**
- Consumes: `render_ss_uri` (Task 1).
- Produces: `pub fn export_ss_uri(dto: ProfileDto, password: String) -> Result<String, String>`; Dart `exportSsUri({required ProfileDto dto, required String password}) -> Future<String>`.

**The password is a parameter.** The app runs as the user and the secret file is the user's own, so Dart reads it and passes it in — the mirror of `ss_uri_password`, which parses in Rust and hands the credential out. Rust does not open files on the app's behalf; the helper is the only component that does that, and only behind the ownership gate.

- [ ] **Step 1: Write the failing tests**

In `api/config.rs`'s tests module:

```rust
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
```

And beside the existing fixtures in that module:

```rust
    const SAMPLE_SSH: &str = r#"{
        "id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Home VPS",
        "protocol":"ssh","host":"198.51.100.7","port":22,
        "auth":{"type":"password","password":{"source":"file","path":"/tmp/k"}},
        "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
        "kill_switch":false}"#;
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p liostunnel_ffi`
Expected: FAIL — `cannot find function 'export_ss_uri' in this scope`.

- [ ] **Step 3: Implement it**

In `api/config.rs`, below `ss_uri_password`:

```rust
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
```

- [ ] **Step 4: Regenerate the bridge and run**

```bash
flutter_rust_bridge_codegen generate
cargo fmt --all
cargo test -p liostunnel_ffi
```
Expected: PASS.

- [ ] **Step 5: A/B each assertion**

| Change | Test that must fail |
|---|---|
| drop the `auth_kind`/`protocol` guard | `exporting_a_non_shadowsocks_profile_is_refused` |
| make the refusal `format!("{} is not shadowsocks", dto.protocol)` | `an_export_refusal_never_echoes_the_profile` |
| pass `None` for the tag | `a_shadowsocks_profile_exports_to_a_link_that_imports_back` |

- [ ] **Step 6: Commit**

```bash
git add crates/liostunnel-ffi app/lib/src/rust
git commit -F /tmp/msg-t2.txt
```

with `/tmp/msg-t2.txt`:

```
feat: export a Shadowsocks profile as an ss:// link

The mirror of import_ss_uri, and the password crosses the same way it does
there -- as its own value, never inside the DTO. The DTO is what Dart renders
on screen; the link is what the user asked to copy.

The refusal names no field of the profile. Every field is caller-supplied and
the message goes back over the wire, which is the sixth time that rule has
had to be applied in this codebase.
```

---

### Task 3: `duplicate`, with its own secret file

**Files:**
- Modify: `app/lib/services/profile_writer.dart`
- Test: `app/test/profile_writer_test.dart`

**Interfaces:**
- Produces: `Future<File> duplicate(LoadedProfile source)` on `ProfileWriter`.

**The whole point is the secret file.** `writeSecret` names the file after the profile id. A duplicate that shares the original's file looks correct until you change the copy's password — at which point the original's credential is gone, from a gesture that said "duplicate". This codebase has shipped that failure twice already, once from a name collision and once from a refused save.

- [ ] **Step 1: Write the failing tests**

In `app/test/profile_writer_test.dart`:

```dart
  test('a duplicate gets its own secret file', () async {
    final dir = Directory.systemTemp.createTempSync('lios-dup');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'original-password');
    final original = await w.writeProfile(dto(source: ref));

    final copy = await w.duplicate(LoadedProfile(
      path: original.path,
      profile: await parseProfile(json: original.readAsStringSync()),
    ));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    expect(copyDto.id, isNot(id), 'a copy is a different profile');
    expect(copyDto.authSecretSource, isNot(ref),
        'sharing the file means editing the copy destroys the original');
    expect(File(copyDto.authSecretSource.substring(5)).readAsStringSync(),
        'original-password', 'the copy must carry the credential, not a stub');
    dir.deleteSync(recursive: true);
  });

  test('changing the copy leaves the original credential intact', () async {
    // The failure this exists to prevent. writeSecret keys on profile id, so a
    // shared secret file means "duplicate then edit" silently overwrites the
    // password the ORIGINAL profile still points at.
    final dir = Directory.systemTemp.createTempSync('lios-dup2');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'original-password');
    final original = await w.writeProfile(dto(source: ref));
    final copy = await w.duplicate(LoadedProfile(
      path: original.path,
      profile: await parseProfile(json: original.readAsStringSync()),
    ));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    await w.writeSecret(copyDto.id, 'changed');

    expect(File(ref.substring(5)).readAsStringSync(), 'original-password',
        'the original credential must survive a change to the copy');
    dir.deleteSync(recursive: true);
  });

  test('duplicating twice does not collide', () async {
    final dir = Directory.systemTemp.createTempSync('lios-dup3');
    final w = ProfileWriter(directory: dir.path);
    final ref = await w.writeSecret('11111111-1111-1111-1111-111111111111', 'p');
    final original = await w.writeProfile(dto(source: ref));
    final loaded = LoadedProfile(
      path: original.path,
      profile: await parseProfile(json: original.readAsStringSync()),
    );
    final a = await w.duplicate(loaded);
    final b = await w.duplicate(loaded);
    expect(a.path, isNot(b.path), 'the second copy needs its own name');
    dir.deleteSync(recursive: true);
  });

  test('duplicating a profile whose secret is not a file is refused', () async {
    final dir = Directory.systemTemp.createTempSync('lios-dup4');
    final w = ProfileWriter(directory: dir.path);
    final original = await w.writeProfile(dto(source: 'env:PW'));
    final loaded = LoadedProfile(
      path: original.path,
      profile: await parseProfile(json: original.readAsStringSync()),
    );
    await expectLater(
      w.duplicate(loaded),
      throwsA(predicate((e) => '$e'.contains('secret'))),
    );
    dir.deleteSync(recursive: true);
  });
```

- [ ] **Step 2: Run to verify failure**

```bash
./testing/build-ffi-for-tests.sh
cd app && flutter test test/profile_writer_test.dart
```
Expected: FAIL — `The method 'duplicate' isn't defined for the type 'ProfileWriter'`.

- [ ] **Step 3: Implement it**

In `profile_writer.dart`:

```dart
  /// Copies a profile, including its secret file.
  ///
  /// The secret copy is the point. [writeSecret] names the file after the
  /// profile id, so a duplicate that pointed at the original's file would look
  /// correct right up until someone changed the copy's password -- and the
  /// original's credential would be gone, from a gesture that said
  /// "duplicate". This codebase has shipped that failure twice: once when a
  /// name collision destroyed another profile's password, once when a refused
  /// save destroyed the one it was refusing.
  ///
  /// Refused if the source's secret is not a `file:` reference or cannot be
  /// read, rather than producing a copy that points at nothing.
  Future<File> duplicate(LoadedProfile source) async {
    final src = source.profile;
    if (src == null) {
      throw StateError('a profile that does not parse cannot be duplicated');
    }
    if (!src.authSecretSource.startsWith('file:')) {
      throw StateError(
        'this profile\'s secret is not a file, so there is nothing to copy '
        'alongside it',
      );
    }
    final srcSecret = File(src.authSecretSource.substring('file:'.length));
    if (!srcSecret.existsSync()) {
      throw StateError('this profile\'s secret file is missing');
    }

    // `checkNameFree` owns what "taken" means, including the slug collapsing
    // that makes `Home VPS` and `home-vps` the same file. Asking it in a loop
    // is the whole rule; a single ` copy` suffix can still collide.
    var name = '${src.name} copy';
    for (var n = 2;; n++) {
      try {
        checkNameFree(name);
        break;
      } on StateError {
        name = '${src.name} copy $n';
      }
    }

    final id = await newProfileId();
    final ref = await writeSecret(id, srcSecret.readAsStringSync());
    final copy = ProfileDto(
      id: id,
      name: name,
      protocol: src.protocol,
      host: src.host,
      port: src.port,
      authKind: src.authKind,
      authSecretSource: ref,
      authPassphraseSource: src.authPassphraseSource,
      peerPublicKey: src.peerPublicKey,
      cipher: src.cipher,
      dnsMode: src.dnsMode,
      dnsServers: src.dnsServers,
      dohSni: src.dohSni,
      dohPath: src.dohPath,
      splitTunnel: src.splitTunnel,
      splitTunnelApps: src.splitTunnelApps,
      killSwitch: src.killSwitch,
    );
    await checkProfile(dto: copy);

    // The SSH username lives in a sidecar, not in the profile, so it has to be
    // carried across explicitly or the copy silently loses it.
    final sidecar = File('${source.path}.user');
    return writeProfile(
      copy,
      sshUser: sidecar.existsSync() ? sidecar.readAsStringSync() : null,
    );
  }
```

Add `import '../src/rust/api/config.dart';` if it is not already imported.

- [ ] **Step 4: Run to verify they pass**

```bash
cd app && flutter test test/profile_writer_test.dart
```
Expected: PASS.

- [ ] **Step 5: A/B each assertion**

| Change | Test that must fail |
|---|---|
| `authSecretSource: src.authSecretSource` (share the file) | `changing the copy leaves the original credential intact` |
| `id: src.id` (share the id) | `a duplicate gets its own secret file` |
| drop the naming loop, always ` copy` | `duplicating twice does not collide` |
| drop the `file:` guard | `duplicating a profile whose secret is not a file is refused` |

- [ ] **Step 6: Commit**

```bash
git add app/lib/services/profile_writer.dart app/test/profile_writer_test.dart
git commit -F /tmp/msg-t3.txt
```

with `/tmp/msg-t3.txt`:

```
feat: duplicate a profile, secret file and all

The secret copy is the point. writeSecret names the file after the profile id,
so a duplicate pointing at the original's file looks correct until someone
changes the copy's password -- and the original's credential is gone, from a
gesture that said "duplicate". That failure has shipped twice here already.

The name uses checkNameFree in a loop rather than a single " copy" suffix,
because checkNameFree owns what "taken" means, including the slug collapsing
that makes "Home VPS" and "home-vps" the same file.
```

---

### Task 4: The list — search and an overflow menu

**Files:**
- Modify: `app/lib/screens/profiles.dart`, `app/lib/main.dart`
- Test: `app/test/widget_test.dart`

**Interfaces:**
- Consumes: `exportSsUri` (Task 2), `ProfileWriter.duplicate` (Task 3).
- Produces: `ProfilesScreen` gains `onDuplicate`, `onCopyLink`, `onDelete` callbacks alongside the existing `onSelect`, `onReload`, `onCreate`, `onEdit`.

`ProfilesScreen` is a `StatelessWidget` handed an already-loaded list. Search is local UI state, so it becomes a `StatefulWidget`; filtering stays pure and the I/O stays in `main.dart`.

`LoadedProfile`'s constructor is `const LoadedProfile({required String path, ProfileDto? profile, String? error, String? sshUser})` — verified, so the broken-profile fixture below compiles as written.

- [ ] **Step 1: Write the failing tests**

In `app/test/widget_test.dart`:

```dart
  testWidgets('search filters by name and by host', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [okProfile(name: 'Home', host: '198.51.100.7'),
                   okProfile(name: 'Work', host: '203.0.113.9')],
        directory: '/tmp',
        selectedPath: null,
        onSelect: (_) {}, onReload: () {}, onCreate: () {},
        onEdit: (_) {}, onDuplicate: (_) {}, onCopyLink: (_) {},
        onDelete: (_) {},
      ),
    ));
    expect(find.text('Home'), findsOneWidget);
    expect(find.text('Work'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('profile-search')), 'wor');
    await tester.pumpAndSettle();
    expect(find.text('Home'), findsNothing, reason: 'filtered by name');
    expect(find.text('Work'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('profile-search')), '198.51');
    await tester.pumpAndSettle();
    expect(find.text('Home'), findsOneWidget, reason: 'filtered by host');
    expect(find.text('Work'), findsNothing);
  });

  testWidgets('the copy-link entry appears only on shadowsocks profiles',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [okProfile(name: 'SSH', protocol: 'ssh')],
        directory: '/tmp', selectedPath: null,
        onSelect: (_) {}, onReload: () {}, onCreate: () {},
        onEdit: (_) {}, onDuplicate: (_) {}, onCopyLink: (_) {},
        onDelete: (_) {},
      ),
    ));
    await tester.tap(find.byKey(const Key('menu-/tmp/SSH.json')));
    await tester.pumpAndSettle();
    expect(find.text('Copy ss:// link'), findsNothing,
        reason: 'ss:// cannot represent an SSH profile');
    expect(find.text('Duplicate'), findsOneWidget);
  });

  testWidgets('a broken profile offers only edit and delete', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [const LoadedProfile(path: '/tmp/bad.json', error: 'nope')],
        directory: '/tmp', selectedPath: null,
        onSelect: (_) {}, onReload: () {}, onCreate: () {},
        onEdit: (_) {}, onDuplicate: (_) {}, onCopyLink: (_) {},
        onDelete: (_) {},
      ),
    ));
    await tester.tap(find.byKey(const Key('menu-/tmp/bad.json')));
    await tester.pumpAndSettle();
    expect(find.text('Edit'), findsOneWidget);
    expect(find.text('Delete'), findsOneWidget);
    expect(find.text('Duplicate'), findsNothing,
        reason: 'there is nothing to duplicate');
    expect(find.text('Copy ss:// link'), findsNothing);
  });
```

Add the fixture helper beside the others in that file:

```dart
/// A profile as the store would hand one back, parsed and healthy.
LoadedProfile okProfile({
  String name = 'Home',
  String host = '198.51.100.7',
  String protocol = 'shadowsocks',
}) =>
    LoadedProfile(
      path: '/tmp/$name.json',
      profile: ProfileDto(
        id: 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
        name: name,
        protocol: protocol,
        host: host,
        port: 8388,
        authKind: protocol == 'shadowsocks' ? 'shadowsocks' : 'password',
        authSecretSource: 'file:/tmp/k',
        cipher: protocol == 'shadowsocks' ? 'aes-256-gcm' : null,
        dnsMode: 'tcp',
        dnsServers: const ['1.1.1.1'],
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      ),
    );
```

- [ ] **Step 2: Run to verify failure**

```bash
cd app && flutter test test/widget_test.dart
```
Expected: FAIL — `No named parameter with the name 'onDuplicate'`.

- [ ] **Step 3: Rewrite `profiles.dart`**

Replace the whole file:

```dart
import 'package:flutter/material.dart';

import '../services/profile_store.dart';

/// The profiles list.
///
/// Takes an already-loaded list rather than doing the loading itself. Reading
/// and parsing crosses the FFI, and a widget that awaits that internally is
/// only testable through a real event loop — this way the rendering is pure
/// and the I/O lives in one place. Search is the one piece of local state, so
/// this is stateful; filtering stays pure.
class ProfilesScreen extends StatefulWidget {
  const ProfilesScreen({
    super.key,
    required this.profiles,
    required this.directory,
    required this.selectedPath,
    required this.onSelect,
    required this.onReload,
    required this.onCreate,
    required this.onEdit,
    required this.onDuplicate,
    required this.onCopyLink,
    required this.onDelete,
  });

  final List<LoadedProfile> profiles;
  final String directory;
  final String? selectedPath;
  final void Function(LoadedProfile) onSelect;
  final VoidCallback onReload;
  final VoidCallback onCreate;
  final void Function(LoadedProfile) onEdit;
  final void Function(LoadedProfile) onDuplicate;
  final void Function(LoadedProfile) onCopyLink;
  final void Function(LoadedProfile) onDelete;

  @override
  State<ProfilesScreen> createState() => _ProfilesScreenState();
}

class _ProfilesScreenState extends State<ProfilesScreen> {
  final _search = TextEditingController();

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  /// Name and host, case-insensitively. Host matters as much as name: a
  /// provider's profiles are often all called some variation of its own name,
  /// and the address is what distinguishes them.
  List<LoadedProfile> get _visible {
    final q = _search.text.trim().toLowerCase();
    if (q.isEmpty) return widget.profiles;
    return widget.profiles.where((p) {
      final host = p.profile?.host ?? '';
      return p.name.toLowerCase().contains(q) || host.toLowerCase().contains(q);
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    final visible = _visible;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Profiles'),
        actions: [
          IconButton(
            key: const Key('create-button'),
            icon: const Icon(Icons.add),
            tooltip: 'New profile',
            onPressed: widget.onCreate,
          ),
          IconButton(
            key: const Key('reload-button'),
            icon: const Icon(Icons.refresh),
            tooltip: 'Reload',
            onPressed: widget.onReload,
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
            child: TextField(
              key: const Key('profile-search'),
              controller: _search,
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search),
                hintText: 'Search by name or host',
                isDense: true,
                border: OutlineInputBorder(),
              ),
            ),
          ),
          Expanded(
            child: widget.profiles.isEmpty
                ? Center(
                    child: Padding(
                      padding: const EdgeInsets.all(24),
                      child: Text(
                        'No profiles in ${widget.directory}.\n'
                        'Use + to create one, or drop a JSON file there and '
                        'reload.',
                        textAlign: TextAlign.center,
                      ),
                    ),
                  )
                : visible.isEmpty
                    ? const Center(child: Text('Nothing matches that search.'))
                    : ListView.builder(
                        itemCount: visible.length,
                        itemBuilder: (context, i) => _row(visible[i]),
                      ),
          ),
        ],
      ),
    );
  }

  Widget _row(LoadedProfile p) {
    // A file that failed to parse is shown as a broken entry rather than
    // hidden — a profile that silently vanishes looks the same as one the
    // user never saved. It stays tappable and editable: it is exactly the one
    // that needs opening and repairing.
    if (!p.ok) {
      return ListTile(
        key: ValueKey(p.path),
        leading: const Icon(Icons.error_outline),
        title: Text(p.name),
        subtitle: Text(p.error!),
        trailing: _menu(p),
      );
    }
    final dto = p.profile!;
    return ListTile(
      key: ValueKey(p.path),
      selected: p.path == widget.selectedPath,
      leading: const Icon(Icons.dns_outlined),
      title: Text(dto.name),
      subtitle: Text('${dto.host}:${dto.port} · ${dto.protocol}'),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (p.path == widget.selectedPath) const Icon(Icons.check),
          _menu(p),
        ],
      ),
      onTap: () => widget.onSelect(p),
    );
  }

  Widget _menu(LoadedProfile p) {
    // Duplicate and Copy need a profile that parsed; `ss://` additionally
    // cannot represent anything but Shadowsocks.
    final ss = p.ok && p.profile!.protocol == 'shadowsocks';
    return PopupMenuButton<String>(
      key: ValueKey('menu-${p.path}'),
      onSelected: (v) => switch (v) {
        'edit' => widget.onEdit(p),
        'duplicate' => widget.onDuplicate(p),
        'copy' => widget.onCopyLink(p),
        'delete' => widget.onDelete(p),
        _ => null,
      },
      itemBuilder: (_) => [
        const PopupMenuItem(value: 'edit', child: Text('Edit')),
        if (p.ok) const PopupMenuItem(value: 'duplicate', child: Text('Duplicate')),
        if (ss) const PopupMenuItem(value: 'copy', child: Text('Copy ss:// link')),
        const PopupMenuItem(value: 'delete', child: Text('Delete')),
      ],
    );
  }
}
```

- [ ] **Step 4: Wire it in `main.dart`**

Find the `ProfilesScreen(` construction and add the three callbacks:

```dart
                onDuplicate: (p) async {
                  try {
                    await _writer.duplicate(p);
                    await _reload();
                  } catch (e) {
                    if (mounted) _toast('$e');
                  }
                },
                onCopyLink: (p) => _copyLink(p),
                onDelete: (p) async {
                  await _writer.delete(p.path);
                  await _reload();
                },
```

and add to `_HomePageState`:

```dart
  void _toast(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  /// Copies a profile's `ss://` link, after asking.
  ///
  /// The link carries the password: there is no secret-free form of one. A
  /// clipboard is readable by every process running as this user and
  /// pasteboard managers keep history, so this asks first and names that —
  /// the same reasoning as the CLI's warning on `export --include-secrets`.
  ///
  /// The link itself is never shown. Putting it in the confirmation or the
  /// snackbar would leave a live credential on screen for a screenshot.
  Future<void> _copyLink(LoadedProfile p) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Copy this profile as a link?'),
        content: const Text(
          'The link contains the password — that is what makes it usable in '
          'another client. Anything running as you can read the clipboard, '
          'and clipboard managers keep history.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm-copy'),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Copy'),
          ),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    try {
      final source = p.profile!.authSecretSource;
      if (!source.startsWith('file:')) {
        _toast('this profile\'s password is not in a file this app can read');
        return;
      }
      final password = File(source.substring('file:'.length)).readAsStringSync();
      final link = await exportSsUri(dto: p.profile!, password: password);
      await Clipboard.setData(ClipboardData(text: link));
      if (mounted) _toast('Link copied. It contains the password.');
    } catch (e) {
      if (mounted) _toast('$e');
    }
  }
```

Add to `main.dart`'s imports:

```dart
import 'package:flutter/services.dart';
import 'src/rust/api/config.dart';
```

- [ ] **Step 5: Run to verify they pass**

```bash
./testing/build-ffi-for-tests.sh
cd app && flutter analyze && flutter test
```
Expected: PASS, analyze clean.

- [ ] **Step 6: A/B each assertion**

| Change | Test that must fail |
|---|---|
| `_visible` returns `widget.profiles` unconditionally | `search filters by name and by host` |
| `_visible` matches on name only | same (the host half) |
| `final ss = p.ok;` (drop the protocol check) | `the copy-link entry appears only on shadowsocks profiles` |
| drop the `if (p.ok)` on Duplicate | `a broken profile offers only edit and delete` |

- [ ] **Step 7: Commit**

```bash
git add app/lib/screens/profiles.dart app/lib/main.dart app/test/widget_test.dart
git commit -F /tmp/msg-t4.txt
```

with `/tmp/msg-t4.txt`:

```
feat: search, duplicate and copy-as-link on the profiles list

Search matches host as well as name: a provider's profiles are often all
called some variation of its own name, and the address is what tells them
apart.

Copying asks first. The link carries the password -- there is no secret-free
form of an ss:// link -- and a clipboard is readable by everything running as
this user. The link is never shown, in the dialog or the snackbar, because
that would leave a live credential on screen.

Duplicate and Copy are hidden on a profile that failed to parse: there is
nothing to duplicate, and nothing to render.
```

---

### Task 5: The editor — a link row on create, and two groups

**Files:**
- Modify: `app/lib/screens/profile_editor.dart`
- Test: `app/test/widget_test.dart`

**Interfaces:**
- Consumes: nothing new. `_import` and `offeredCiphers` already exist.

**The hazard in this file.** It is 692 lines and a prior change landed on one of two branches because `dart format` had rewrapped the other; the missing control was reported as present twice before anyone read the source. After every change here, grep for the key you added and confirm it appears on every path that can reach it.

Today the `ss://` row and cipher dropdown are inside `if (_authKind == 'shadowsocks')`, so pasting a link requires choosing Shadowsocks from a dropdown first — even though importing is what decides the protocol. That gate goes.

- [ ] **Step 1: Write the failing tests**

In `app/test/widget_test.dart`:

```dart
  testWidgets('a new profile leads with the link row, without a dropdown first',
      (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-linkrow');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);
    // Present immediately: _authKind defaults to 'password', and requiring
    // the user to find Shadowsocks in a dropdown before they can paste a
    // link is backwards -- importing is what decides the protocol.
    expect(find.byKey(const Key('f-uri')), findsOneWidget);
    expect(find.byKey(const Key('import-button')), findsOneWidget);
  });

  testWidgets('an edit has no link row', (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-linkrow2');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path, existing: ssProfile());
    expect(find.byKey(const Key('f-uri')), findsNothing,
        reason: 'you are not re-importing a profile that exists');
  });

  testWidgets('importing works without touching the auth dropdown',
      (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-linkrow3');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    expect(fieldText(tester, const Key('f-host')), '198.51.100.7');
    // And the cipher control is now present, because the import chose the
    // protocol.
    expect(find.byKey(const Key('f-cipher')), findsOneWidget);
  });

  testWidgets('DNS settings are collapsed until asked for', (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-adv');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);
    expect(find.byKey(const Key('f-dns')), findsNothing,
        reason: 'set once and forgotten; it should not compete with the '
            'fields you actually edit');
    await tester.tap(find.byKey(const Key('advanced-section')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('f-dns')), findsOneWidget);
  });
```

- [ ] **Step 2: Run to verify failure**

```bash
cd app && flutter test test/widget_test.dart
```
Expected: FAIL — `f-uri` not found on a new profile (it is behind the Shadowsocks gate), and `f-dns` found when it should be collapsed.

- [ ] **Step 3: Move the link row out of the Shadowsocks gate**

In `build`, immediately after the `editor-saved` card and **before** `_text(_name, 'Name', …)`, insert:

```dart
            // A provider hands you a link; nobody creates a Shadowsocks
            // profile by typing a cipher name. So this goes first, and it is
            // NOT gated on picking Shadowsocks from a dropdown -- importing
            // is what decides the protocol.
            //
            // Create only. On an edit you are not re-importing, and a link
            // sitting here on a save is what let a rotation be silently
            // discarded.
            if (!_editing) ...[
              _text(_uri, 'Paste an ss:// link', key: 'f-uri',
                  hint: 'ss://...',
                  obscure: true,
                  help: 'Fills in the form. The password is written to a 0600 '
                      'file and never stored in the profile.',
                  validator: (_) => null),
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: FilledButton.tonal(
                  key: const Key('import-button'),
                  onPressed: _busy ? null : _import,
                  child: const Text('Import from link'),
                ),
              ),
              const Divider(height: 32),
            ],
```

Then delete the `_text(_uri, …)` and `import-button` block from inside the existing `if (_authKind == 'shadowsocks') ...[` list, leaving the cipher dropdown there.

- [ ] **Step 4: Collapse DNS behind an Advanced section**

Replace the DNS block — from `const SizedBox(height: 16),` before `f-dns-mode` through the closing `],` of the `if (_dnsMode == 'https')` list — with:

```dart
            const SizedBox(height: 16),
            // Split by how often you touch it, not by protocol. DNS is set
            // once and forgotten, and having it on screen means it competes
            // with the fields you actually edit.
            ExpansionTile(
              key: const Key('advanced-section'),
              title: const Text('Advanced'),
              subtitle: const Text('DNS and DNS-over-HTTPS'),
              children: [
                DropdownButtonFormField<String>(
                  key: const Key('f-dns-mode'),
                  initialValue: _dnsMode,
                  decoration: const InputDecoration(labelText: 'DNS'),
                  items: const [
                    DropdownMenuItem(value: 'tcp', child: Text('DNS over TCP')),
                    DropdownMenuItem(
                        value: 'https', child: Text('DNS over HTTPS')),
                  ],
                  onChanged: (v) => setState(() => _dnsMode = v!),
                ),
                _text(
                  _dns,
                  'DNS servers',
                  key: 'f-dns',
                  hint: '1.1.1.1, 1.0.0.1',
                  help: _dnsMode == 'https'
                      ? 'The IP of the DoH endpoint. No bootstrap lookup is '
                          'done, so this must be an address, not a name.'
                      : 'Tried in order, five seconds each. Many tunnel '
                          'providers block outbound port 53 — if lookups are '
                          'slow or fail, switch to DNS over HTTPS, which uses '
                          '443.',
                ),
                if (_dnsMode == 'https') ...[
                  _text(_dohSni, 'DoH server name', key: 'f-doh-sni',
                      hint: 'cloudflare-dns.com'),
                  _text(_dohPath, 'DoH path', key: 'f-doh-path',
                      hint: '/dns-query',
                      validator: (v) => (v == null || !v.startsWith('/'))
                          ? 'must start with /'
                          : null),
                ],
              ],
            ),
```

- [ ] **Step 5: Make the credential field say what it is**

This is the one widget the two protocols share while meaning different things:
for SSH key auth it is a path to a key you already have, for everything else
it is a password you type. Today both say "Password" / "Path to the file"
regardless.

Add above `build`'s `return`:

```dart
  /// What the credential field is called, for the protocol in play.
  ///
  /// The same two widgets serve an SSH private key and a Shadowsocks
  /// password, which is fine — but labelling a key file "Password" is not.
  String get _secretLabel =>
      _authKind == 'private_key' ? 'Private key' : 'Password';
```

Then in the credential block, replace the two labels:

```dart
            if (_secretMode == 'typed')
              _text(
                _secret,
                _secretLabel,
                key: 'f-secret',
                obscure: true,
                help: 'Written to ${widget.writer.secretsDirectory}, mode 0600. '
                    'The profile stores the path, never the $_secretLabel.',
              )
            else
              _text(
                _secretPath,
                _authKind == 'private_key'
                    ? 'Path to the key file'
                    : 'Path to the password file',
                key: 'f-secret-path',
                hint: _authKind == 'private_key'
                    ? '/Users/you/.ssh/id_ed25519'
                    : '/Users/you/.liostunnel/secrets/password',
                help: 'Must be owned by you and mode 0600, or the helper will '
                    'refuse it.',
              ),
```

Cover it:

```dart
  testWidgets('the credential field names what it actually is', (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-label');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);

    await choose(tester, const Key('f-auth'), 'Private key');
    await choose(
        tester, const Key('f-secret-mode'), 'Type it — save to a 0600 file');
    expect(find.widgetWithText(TextFormField, 'Private key'), findsOneWidget,
        reason: 'calling an SSH key "Password" is wrong');

    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    expect(find.widgetWithText(TextFormField, 'Password'), findsOneWidget);
  });
```

A/B: hardcode `_secretLabel` to `'Password'` and this test fails on the
private-key half.

- [ ] **Step 6: Run to verify they pass**

```bash
./testing/build-ffi-for-tests.sh
cd app && flutter analyze && flutter test
```
Expected: PASS. If an existing DoH test fails because its field is now collapsed, open the section in that test with `await tester.tap(find.byKey(const Key('advanced-section')));` — do not weaken the assertion.

- [ ] **Step 7: Verify the change is on every path**

```bash
cd app && grep -n "f-uri\|import-button\|advanced-section" lib/screens/profile_editor.dart
```
Expected: `f-uri` and `import-button` appear exactly once each, inside `if (!_editing)`. `advanced-section` appears once. **If any appears twice, one of them is a leftover** — this file has shipped that exact mistake before.

- [ ] **Step 8: A/B each assertion**

| Change | Test that must fail |
|---|---|
| put the link row back inside `if (_authKind == 'shadowsocks')` | `a new profile leads with the link row, without a dropdown first` |
| change `if (!_editing)` to an unconditional include | `an edit has no link row` |
| replace `ExpansionTile` with a plain `Column` | `DNS settings are collapsed until asked for` |
| hardcode `_secretLabel` to `'Password'` | `the credential field names what it actually is` |

- [ ] **Step 9: Commit**

```bash
git add app/lib/screens/profile_editor.dart app/test/widget_test.dart
git commit -F /tmp/msg-t5.txt
```

with `/tmp/msg-t5.txt`:

```
feat: lead a new profile with the link, and collapse what you set once

Pasting a link used to require choosing Shadowsocks from a dropdown first,
which is backwards: importing is what decides the protocol. The row now comes
first on a new profile, and is absent on an edit -- you are not re-importing
something that exists, and a link sitting there on a save is what let a
password rotation be silently discarded.

DNS moves behind an Advanced section. The split is by how often you touch a
field, not by which protocol owns it.
```

---

## Exit criteria

| Criterion | Verified by |
|---|---|
| PM-1 — a pasted link creates a profile without touching the auth dropdown | Task 5 step 1, `importing works without touching the auth dropdown` |
| PM-2 — render → parse round-trips every field, `@` and `:` in the password included | Task 1 step 1 |
| PM-3 — copying asks first; the link appears in no error, log or on-screen text | Task 2 step 1 (`an_export_refusal_never_echoes_the_profile`), Task 4 step 4 |
| PM-4 — duplicating then changing the copy leaves the original credential intact | Task 3 step 1, `changing the copy leaves the original credential intact` |
| PM-5 — search finds by name and by host | Task 4 step 1 |
| PM-6 — the copy entry is absent on SSH and on unparsed profiles | Task 4 step 1 |

PM-4 is the one to care about. The others confirm features work; that one says a convenience did not become a way to lose a credential.
