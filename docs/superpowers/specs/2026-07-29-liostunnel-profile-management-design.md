# Profile management in the app — design

**Goal.** Make creating, finding, copying and sharing a profile match how they
are actually used, now that a second protocol exists. Three complaints drive
it: getting profiles in and out, managing more than a couple, and an editor
that "feels clunky".

**Not in scope.** Diagnostics — last-connected times, last-error surfacing,
orphaned-secret collection. QR codes. Changing a profile's protocol.

---

## 1. Where this sits

The app is four screens and four services, ~1550 lines of Dart. Everything
below touches three files and adds one Rust function:

| File | Change |
|---|---|
| `app/lib/screens/profiles.dart` | search field, per-row overflow menu |
| `app/lib/screens/profile_editor.dart` | link row on create, Server/Advanced split |
| `app/lib/services/profile_writer.dart` | `duplicate` |
| `crates/liostunnel-core/src/protocols/ss_uri.rs` | `render_ss_uri` |
| `crates/liostunnel-ffi/src/api/config.rs` | `export_ss_uri` |

The profile document format does not change. Nothing here adds persistent
state beyond the profile files and their secrets, which is why
most-recently-used ordering is out: it would need a record of connections
that nothing writes today.

## 2. Create — the link is the front door

A provider hands you an `ss://` link. Typing a cipher name is not how anyone
creates a Shadowsocks profile, so the link goes first.

For a **new** profile the editor leads with one row: a text field labelled
*Paste an `ss://` link* and an **Import** button. Importing sets protocol,
cipher, host, port and name, and writes the password to its `0600` file. It
is not gated on choosing "Shadowsocks" from a dropdown first — importing is
what decides the protocol.

Ignoring the row and filling the form by hand is unchanged, which is the SSH
path: a provider gives you a host, a username and a password, and there is no
link to paste.

For an **edit** the row is absent. You are not re-importing a profile that
exists, and its presence there is what allowed a pasted-but-unimported link to
be silently discarded on save.

### Why not a separate "how do you want to start" screen

One less surface, and the manual path keeps its current single tap. A choice
screen would put a question in front of every create, including the ones where
the answer is always "manually".

## 3. Editor — grouped by how often you touch it

Two groups, split by edit frequency rather than by protocol:

**Server** — name, host, port, authentication, then whichever of *SSH
username* or *cipher* the authentication kind implies, then the credential.

**Advanced** — a collapsed `ExpansionTile`: DNS mode, DNS servers, and the
DoH name and path when the mode is `https`.

Two rules for the credential field, which is the one place the two protocols
share a widget and mean different things:

- The label names what it is: *Password* for a Shadowsocks profile or SSH
  password auth, *Private key file* for SSH key auth.
- The helper text names the consequence: a typed password is written to a
  `0600` file and the profile stores the path.

Validation is unchanged. `check_profile` in Rust remains the authority — a
profile the app accepts must be one the helper can parse, and the form does
not re-implement that judgement.

## 4. List — find and act

A search field above the list filtering on name and host, case-insensitively.
Empty search shows everything. Filtering is pure — the list is already handed
an already-loaded `List<LoadedProfile>`, and that stays true.

Each row gains an overflow menu:

| Entry | Shown when |
|---|---|
| Edit | always |
| Duplicate | the profile parsed |
| Copy `ss://` link | the profile parsed **and** `protocol == "shadowsocks"` |
| Delete | always |

A profile that failed to parse keeps Edit and Delete only: it is exactly the
one you need to open and repair, and there is nothing to duplicate or render.

Ordering stays alphabetical by name. Search is what answers "find the one I
want"; ordering by use would need state nothing records.

## 5. Export — one implementation of the format

`render_ss_uri` goes in `ss_uri.rs`, beside `parse_ss_uri`. The format is
already implemented there and a second implementation in Dart is how the two
drift — on a format whose payload is a password.

```rust
/// Renders a SIP002 `ss://` link.
///
/// The password is a parameter rather than a field of any struct that
/// crosses a boundary: the returned String IS the credential, and callers
/// must treat it as one.
pub fn render_ss_uri(
    method: &str,
    password: &str,
    host: &str,
    port: u16,
    tag: Option<&str>,
) -> String
```

SIP002 form: `ss://` + `base64url_nopad(method:password)` + `@host:port` +
`#tag`. URL-safe alphabet, unpadded — what `parse_ss_uri` already accepts and
what providers emit.

**The tag is the profile's name, and a name is user-typed.** `parse_ss_uri`
splits on the first `#` and takes everything after it as the tag, so a profile
called `Home #2` would render a link that parses back with a different name —
or, with a `?` in it, one whose query-stripping eats part of the name. The tag
is therefore percent-encoded on render, and `parse_ss_uri` gains matching
decoding. That is a change to the parser, so it comes with its own round-trip
test over the characters that matter: `#`, `?`, `%`, space, and a non-ASCII
name. A name that survives the round trip is the requirement; a name that
cannot be encoded is not a case that exists, since percent-encoding is total.

The FFI entry point reads the password from the profile's secret file:

```rust
pub fn export_ss_uri(dto: ProfileDto, password: String) -> Result<String, String>
```

The password is passed in rather than read in Rust, because the app runs as
the user and the file is the user's own — the same asymmetry as
`ss_uri_password`, in the other direction.

### The clipboard is a shared surface

Copying puts a live credential where every other process running as the user
can read it, and pasteboard managers persist it. So the action asks first,
naming that, in the same spirit as the CLI's warning on
`export --include-secrets`. Confirm, and the link goes to the clipboard with a
snackbar saying what was copied — never the link itself, which would put it on
screen for a screenshot to catch.

## 6. Duplicate copies the secret file

```dart
Future<File> duplicate(LoadedProfile source)
```

A new id, and a name that does not collide: ` copy` appended, then ` copy 2`,
` copy 3`… until `checkNameFree` stops throwing. That loop is the whole rule —
`checkNameFree` already owns what "taken" means, including the slug collapsing
that made `Home VPS` and `home-vps` the same file. Every other field is
carried across verbatim, and — the part that matters — **the secret file copied to the
new id's path**, with the new profile pointing at the copy.

A duplicate sharing the original's secret file looks correct until you change
the copy's password: `writeSecret` keys on the profile id, so it would
overwrite the original's credential on a gesture that says "duplicate". That
is the exact failure this codebase has already shipped twice — once when a
name collision destroyed another profile's credential, once when a refused
save destroyed the one it was refusing.

If the source's secret is not a `file:` reference, or the file is unreadable,
the duplicate is refused with a message naming which — rather than silently
producing a profile pointing at nothing.

## 7. Error handling

Every new failure path follows the rules this codebase already enforces:

- **No error echoes caller-supplied content.** `render_ss_uri` cannot fail. The
  `export_ss_uri` wrapper's only failures are "not a Shadowsocks profile" and
  "no cipher", both fixed strings.
- **The link never reaches an error, a log, or the screen.** It is returned,
  shown as a confirmation *about* a copy, and put on the clipboard. It is not
  rendered in a snackbar, not printed, and not stored in widget state beyond
  the copy.
- **Nothing destructive runs before it is known to be valid.** Duplicate
  writes the profile and its secret only after `checkNameFree` and
  `check_profile` both pass, matching what `_save` now does.

## 8. Testing

**Rust.** The load-bearing test is a round trip: `render_ss_uri` then
`parse_ss_uri`, asserting every field survives — including a password
containing `@` and `:`, which is what makes `rsplit_once`/`split_once` in the
parser non-obvious. Plus: a rendered link parses under the *legacy* reader
too, and the offered ciphers all round-trip.

**Dart.** Search filters and restores. The overflow menu shows and hides the
copy entry by protocol and by parse state. Duplicate produces a distinct
secret file, and writing to the copy leaves the original's credential intact —
asserted by reading the original file after, because that is the failure the
copy exists to prevent. The link row appears on create and not on edit.

**A/B.** Every test must be shown failing against the defect it names. This
branch caught more than twenty tests that were green while the thing they
named was broken, several found only because an A/B refused to fail.

## 9. Exit criteria

| | |
|---|---|
| PM-1 | A pasted `ss://` link creates a working profile without touching the authentication dropdown first |
| PM-2 | `render_ss_uri` → `parse_ss_uri` round-trips every field, including a password containing `@` and `:` |
| PM-3 | Copying a link asks first, and the link appears in no error, log, or on-screen text |
| PM-4 | Duplicating a profile and changing the copy's password leaves the original's credential intact |
| PM-5 | Search finds a profile by name and by host |
| PM-6 | The copy entry is absent on SSH profiles and on profiles that failed to parse |

PM-4 is the one to care about. The others confirm the features work; that one
says a convenience did not become a way to lose a credential.

## 10. Risks

**The editor is 692 lines and this changes its skeleton.** A prior change
landed on one of two branches because `dart format` had rewrapped the other,
and the missing control was reported as present twice before anyone checked
the source. Every change here must be verified on every path a user can reach
it, not just the one edited.

**Duplicate and export both add secret files and secret-bearing strings** to a
surface that previously only consumed them. The orphaned-secret problem —
delete never removes a key file — is out of scope and this makes it larger.
Worth a separate slice, not worth blocking this one.
