import 'package:flutter/material.dart';

import '../services/profile_store.dart';
import '../services/profile_writer.dart';
import '../src/rust/api/config.dart';
import 'dialogs.dart';
import '../src/rust/dto/profile.dart';

/// The cipher names the editor offers for Shadowsocks.
///
/// Must match `OFFERED` in `crates/liostunnel-core/src/protocols/
/// shadowsocks.rs` exactly. A name this dropdown offers that the core refuses
/// is the same bug the core's own list already had once: advice the user
/// follows and that then fails as unknown. Public so a test can prove the
/// agreement against the core itself rather than against a second copy of
/// this list.
///
/// The `2022-blake3-*` family is deliberately absent — it cannot be built
/// under this build's cipher feature set.
const offeredCiphers = [
  'aes-128-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
];

/// Creates a profile.
///
/// **This form collects where a secret lives, not the secret.** A profile
/// carries a `file:` or `env:` reference and the helper resolves it later, as
/// the calling user — which is the whole reason a profile naming a file you
/// do not own gets refused. The one exception is [_secret], offered because
/// password auth would otherwise need a terminal, and it writes to a `0600`
/// file and stores only that path.
class ProfileEditorScreen extends StatefulWidget {
  const ProfileEditorScreen({
    super.key,
    required this.writer,
    required this.onSaved,
    this.existing,
  });

  final ProfileWriter writer;
  final VoidCallback onSaved;

  /// The profile being edited, or null to create one.
  final LoadedProfile? existing;

  @override
  State<ProfileEditorScreen> createState() => _ProfileEditorScreenState();
}

class _ProfileEditorScreenState extends State<ProfileEditorScreen> {
  final _form = GlobalKey<FormState>();

  final _name = TextEditingController();
  final _host = TextEditingController();
  final _port = TextEditingController();
  final _user = TextEditingController();
  final _dns = TextEditingController();
  final _secretPath = TextEditingController();
  final _secret = TextEditingController();
  final _dohSni = TextEditingController();
  final _dohPath = TextEditingController();
  final _uri = TextEditingController();

  String _authKind = 'password';
  String _cipher = 'aes-256-gcm';
  String _secretMode = 'file';
  String _dnsMode = 'tcp';
  bool _busy = false;
  String? _error;
  String? _saved;

  /// The id [_import] wrote the secret file under.
  ///
  /// [ProfileWriter.writeSecret] keys the file on the profile id, and that is
  /// an invariant the profile has to honour: `_save` used to mint a *second*
  /// id, so every import left a 0600 file no profile named. The connection
  /// still worked — `authSecretSource` holds the literal path — but nothing
  /// ever collected the orphan, deletion deliberately does not touch secret
  /// files, and re-importing to fix a typo left another.
  String? _importedId;

  /// The password the last successful [_import] took out of the link, held
  /// until [_save] has somewhere safe to put it.
  ///
  /// Not written at import time, and that ordering is the whole point.
  /// [ProfileWriter.writeSecret] truncates `secrets/<slug(id)>`, and on an
  /// edit that id is the existing profile's — the file the on-disk profile
  /// already points at. Writing there the instant Import is pressed destroyed
  /// a live credential before `checkNameFree`, before `checkProfile` and
  /// before Save: paste what you believe is the rotated link, notice the host
  /// is wrong, press Back, and the original password is gone with nothing
  /// saved. It came from an `ss://` link, so it cannot be retyped.
  ///
  /// Held in widget state exactly as a typed password already is ([_secret])
  /// and under the same rule: it never reaches the profile document, is never
  /// rendered, and goes straight from here into a `0600` file.
  String? _importedPassword;

  /// The exact text the last [_import] consumed out of [_uri].
  ///
  /// [_save] used to clear [_uri] whenever `_importedId != null`, and
  /// `_importedId` is never reset — so after one import that was permanently
  /// true. Paste link A, Import, paste link B, Save: B was silently dropped,
  /// the profile kept A's credential, and the UI reported success. The user
  /// believed the password was rotated and found out eight seconds into the
  /// next connect.
  ///
  /// Comparing against what was actually consumed is what tells "the box
  /// still holds the link the import took" from "the box holds one it never
  /// saw" — and [_import] empties the box on success, so in practice the
  /// second case is any non-empty box at all.
  String? _importedUri;

  bool get _editing => widget.existing?.profile != null;

  /// Whether the `ss://` paste box is on screen.
  ///
  /// One predicate, named once. `_save`'s guard against a pasted-but-not-
  /// imported link and the box's own render condition have to agree exactly —
  /// a guard that fires while the box is hidden refuses a save over a field
  /// the user cannot see, and one that does not fire while the box is visible
  /// discards a credential under a green "Saved to …". They were two separate
  /// literals of `!_editing`, which is the arrangement this file has already
  /// been bitten by: a change landed on one of two branches because
  /// `dart format` had rewrapped the other.
  bool get _linkRowVisible => !_editing;

  /// Opens and closes the Advanced section from code.
  ///
  /// Held here so [_save] can open it when the helper refuses something it
  /// hides — see [_namesSomethingAdvanced].
  final _advanced = ExpansibleController();

  @override
  void initState() {
    super.initState();
    final p = widget.existing?.profile;
    if (p == null) {
      _name.text = 'My server';
      _port.text = '22';
      _dns.text = '1.1.1.1, 1.0.0.1';
      _dohSni.text = 'cloudflare-dns.com';
      _dohPath.text = '/dns-query';
      return;
    }
    _name.text = p.name;
    _host.text = p.host;
    _port.text = '${p.port}';
    _user.text = widget.existing?.sshUser ?? '';
    _dns.text = p.dnsServers.join(', ');
    _dnsMode = p.dnsMode;
    _authKind = p.authKind;
    _dohSni.text = p.dohSni ?? 'cloudflare-dns.com';
    _dohPath.text = p.dohPath ?? '/dns-query';
    _cipher = p.cipher ?? 'aes-256-gcm';

    // The profile records where the secret lives, so the form can show that
    // much. A password typed on a previous visit is NOT recoverable — it was
    // written to a file and never kept here, which is the point.
    final source = p.authSecretSource;
    if (source.startsWith('env:')) {
      // Kept viewable so an imported profile can be repaired, but the form
      // will not produce one: the helper refuses env secrets outright,
      // because they resolve against root's environment.
      _secretMode = 'file';
      _secretPath.text = '';
    } else if (source.startsWith('file:')) {
      _secretMode = 'file';
      _secretPath.text = source.substring(5);
    }
  }

  @override
  void dispose() {
    for (final c in [
      _name,
      _host,
      _port,
      _user,
      _dns,
      _secretPath,
      _secret,
      _dohSni,
      _dohPath,
      _uri,
    ]) {
      c.dispose();
    }
    // Ours, not the tile's: ExpansionTile only disposes a controller it made
    // itself.
    _advanced.dispose();
    super.dispose();
  }

  /// Fills the form from an `ss://` link.
  ///
  /// Order is load-bearing. The link is parsed first, so a malformed one
  /// changes nothing at all; and **nothing is written to disk here**, so an
  /// import the user then abandons leaves every file exactly as it was. See
  /// [_importedPassword] for what that closes.
  Future<void> _import() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      // An `ss://` link is a Shadowsocks credential and nothing else, so
      // importing one into a profile of another protocol cannot be made
      // coherent. Refused here as well as in `_save` so the message lands at
      // the paste box, where the gesture was.
      _refuseAProtocolChange('shadowsocks');
      final uri = _uri.text.trim();
      final dto = await importSsUri(uri: uri);
      final password = await ssUriPassword(uri: uri);
      // The file `writeSecret` will produce is named after the id it is
      // given, so that id has to be the one the saved profile will carry. On
      // an edit that is the existing profile's, which is stable across saves
      // by design; only a new profile uses the one the import minted. Using
      // `dto.id` unconditionally left an orphan 0600 file behind every single
      // import — nothing collects those, and deletion deliberately never
      // touches a secret file.
      // `_importedId` and not just `dto.id`: on a new profile, a second
      // paste (to correct a typo'd link) would otherwise mint a fresh id and
      // orphan the first import's 0600 file — the very case the paragraph
      // above claims to close, reached one gesture later.
      final id = widget.existing?.profile?.id ?? _importedId ?? dto.id;

      if (!mounted) return;
      setState(() {
        // Kept so `_save` writes the profile under the id whose secret file
        // it will write, instead of minting a second one and orphaning it.
        _importedId = id;
        // Carried, not written. `_save` puts it in a 0600 file once the
        // profile has actually been accepted.
        _importedPassword = password;
        // What the user typed and this import consumed, so `_save` can tell
        // a link it has already taken from one pasted afterwards.
        _importedUri = uri;
        _name.text = dto.name;
        _host.text = dto.host;
        _port.text = dto.port.toString();
        _authKind = 'shadowsocks';
        // Guaranteed to be an offered cipher: `import_ss_uri` refuses the
        // rest before it returns, which is what stops this assigning a value
        // the Cipher dropdown cannot show.
        _cipher = dto.cipher ?? 'aes-256-gcm';
        _secretMode = 'file';
        // Where the password WILL live, shown before anything is written —
        // the same thing `_save` does for a typed one.
        _secretPath.text = widget.writer.secretPathFor(id);
        // DNS is deliberately NOT touched. An `ss://` link carries no DNS
        // information, so the DTO's value is a default the FFI had to invent,
        // and writing it back over the form discarded whatever the user had:
        // a Quad9 DoH profile kept its mode and SNI but had its resolver
        // replaced by 1.1.1.1, so the probe dialled Cloudflare presenting
        // Quad9's name.
        // It contains the password; do not leave it on screen.
        _uri.clear();
      });
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// The protocol a credential kind implies.
  ///
  /// The form has no protocol control, so the Authentication dropdown is the
  /// only thing that can express one — which is exactly how an SSH profile
  /// came to be saved as Shadowsocks.
  static String _protocolFor(String authKind) => switch (authKind) {
        'shadowsocks' => 'shadowsocks',
        'preshared_key' => 'wireguard',
        _ => 'ssh',
      };

  /// Refuses a change of protocol on an existing profile, because the editor
  /// cannot make one coherently.
  ///
  /// Picking "Shadowsocks" on an SSH profile used to save: `check_profile`
  /// saw a shadowsocks/shadowsocks pairing and passed, and what landed on
  /// disk was a Shadowsocks profile whose password file was the SSH private
  /// key the profile already named, under a cipher nobody chose — `_cipher`'s
  /// default, which is precisely the "pick a cipher on the user's behalf"
  /// that `dto/profile.rs` refuses to do. Shadowsocks has no handshake, so
  /// the result connects and carries nothing.
  ///
  /// The reverse was a dead end rather than a hazard, and this fixes that
  /// too: a Shadowsocks profile could never move off `shadowsocks`, and the
  /// refusal the user got ("ssh takes a password or a private key…") is
  /// advice about a control this form does not have.
  ///
  /// Refusing, not converting. Every field that would have to change means
  /// something different to the two protocols — the credential, the cipher,
  /// the username — so there is no honest automatic answer, and a protocol
  /// dropdown would only move the same incoherence one control over. A new
  /// profile is cheap and is the thing the user actually wants.
  ///
  /// Applies to edits only. A NEW profile has no protocol to change.
  void _refuseAProtocolChange(String authKind) {
    final old = widget.existing?.profile;
    if (old == null) return;
    final wanted = _protocolFor(authKind);
    if (wanted == old.protocol) return;
    throw StateError(
      'This is a ${old.protocol} profile and it cannot be turned into a '
      '$wanted one here: the credential, the cipher and the username all mean '
      'different things to the two, so the result would save and then fail to '
      'connect. Create a new profile instead — for a Shadowsocks server, '
      'paste its ss:// link into one.',
    );
  }

  Future<void> _save() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
      _saved = null;
    });
    try {
      _refuseAProtocolChange(_authKind);
      // A link in the box that no import consumed is a credential the save is
      // about to ignore. It used to be cleared instead, on a guard that was
      // permanently true after the first import, so the profile was written
      // with the OLD password under a green "Saved to …".
      //
      // Only when the box is on screen, and that is [_linkRowVisible] — the
      // very getter the box is rendered under, rather than a second literal
      // of the same condition — rather than "the Authentication dropdown says
      // Shadowsocks". The paste box no longer lives behind that dropdown —
      // importing is what decides the protocol — so keying on `_authKind`
      // would have let the commonest case through untouched: paste a link
      // into a brand-new profile whose authentication still reads Password,
      // fill the rest in by hand, press Save, and the credential in front of
      // the user is discarded under a green "Saved to …".
      //
      // Refusing a save over a field the user cannot see
      // would be its own trap, which is why this is still conditional at all.
      if (_linkRowVisible &&
          _uri.text.trim().isNotEmpty &&
          _uri.text.trim() != _importedUri) {
        throw StateError(
          'There is an ss:// link in the paste box that has not been '
          'imported. Press "Import from link" to use it, or clear the box to '
          'save without it.',
        );
      }

      final old = widget.existing?.profile;
      // An edit keeps its id. Minting a new one would make the profile a
      // different server as far as anything keyed on id is concerned.
      // An import keeps the id its secret file will be written under, for the
      // same reason one step down: `writeSecret` keys on the profile id.
      final id = old?.id ?? _importedId ?? await newProfileId();

      // Refuse the name BEFORE writing a secret. Doing it afterwards meant a
      // collision destroyed another profile's credential and then reported
      // failure, so the user believed nothing had happened.
      widget.writer.checkNameFree(
        _name.text.trim(),
        replacingPath: widget.existing?.path,
      );

      // Where the secret WILL live, before anything is written. `writeSecret`
      // overwrites the file keyed to this id, so running it before the
      // profile is checked meant a refused save could destroy the credential
      // the profile on disk still points at — an imported Shadowsocks
      // password wiped by a typed one on a save the UI then reported as
      // failed. Same shape as the name-collision bug, one field over.
      final source = _secretMode == 'typed'
          ? 'file:${widget.writer.secretPathFor(id)}'
          : 'file:${_secretPath.text.trim()}';

      final dto = ProfileDto(
        id: id,
        name: _name.text.trim(),
        // Every field the form does not offer is carried through, not
        // defaulted. Rebuilding from scratch quietly rewrote a wireguard
        // profile to ssh, dropped an encrypted key's passphrase reference,
        // turned kill_switch off and reset split_tunnel — on a save where the
        // user had only corrected a typo.
        // A Shadowsocks profile must say so. Before this, a link imported
        // into a NEW profile saved with protocol `ssh` and authKind
        // `shadowsocks`, and the helper's factory — which dispatches on
        // protocol — handed it to the SSH tunnel, which refused it.
        protocol: _authKind == 'shadowsocks'
            ? 'shadowsocks'
            : (old?.protocol ?? 'ssh'),
        host: _host.text.trim(),
        port: int.parse(_port.text),
        authKind: _authKind,
        authSecretSource: source,
        cipher: _authKind == 'shadowsocks' ? _cipher : old?.cipher,
        dnsMode: _dnsMode,
        // Only meaningful for DoH, and required there — a profile with mode
        // `https` and no endpoint is refused by the helper at connect time.
        dohSni: _dnsMode == 'https' ? _dohSni.text.trim() : null,
        dohPath: _dnsMode == 'https' ? _dohPath.text.trim() : null,
        dnsServers: _dns.text
            .split(',')
            .map((s) => s.trim())
            .where((s) => s.isNotEmpty)
            .toList(),
        // Carried only where it means something. A passphrase belongs to an
        // encrypted private key; on any other credential kind `TryFrom` drops
        // it silently, so carrying it there is a value that looks preserved
        // and is not.
        authPassphraseSource:
            _authKind == 'private_key' ? old?.authPassphraseSource : null,
        peerPublicKey: old?.peerPublicKey,
        splitTunnel: old?.splitTunnel ?? 'all_traffic',
        splitTunnelApps: old?.splitTunnelApps ?? const [],
        killSwitch: old?.killSwitch ?? false,
      );

      // Checked by the same Rust that will read it back, so a profile the
      // app accepts is one the helper can parse. Everything above this line
      // is reversible; nothing below it should run if this throws.
      await checkProfile(dto: dto);
      if (_secretMode == 'typed') {
        await widget.writer.writeSecret(id, _secret.text);
      } else if (_importedPassword != null &&
          _secretPath.text.trim() == widget.writer.secretPathFor(id)) {
        // The imported password, written only now that the profile has been
        // accepted — see `_importedPassword`. Guarded on the path still being
        // the managed one: if the user has since pointed the form at a file
        // of their own, that file is what the profile names and writing
        // elsewhere would leave an orphan.
        await widget.writer.writeSecret(id, _importedPassword!);
      }
      final file = await widget.writer.writeProfile(
        dto,
        // Shadowsocks has no username. Passing one wrote a `.user` sidecar
        // beside a profile for a protocol that has nowhere to send it.
        sshUser: _authKind == 'shadowsocks' ? null : _user.text,
        replacingPath: widget.existing?.path,
      );
      if (!mounted) return;
      setState(() => _saved = file.path);
      widget.onSaved();
    } catch (e) {
      if (!mounted) return;
      // A refusal about a field behind the collapse has to bring the field
      // with it. The message lands in the card at the top of the form, and
      // "the DoH path must start with `/`" over a form with no DoH path on it
      // is advice the user cannot act on.
      if (_namesSomethingAdvanced('$e')) _advanced.expand();
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Whether a refusal is about a field the Advanced section hides.
  ///
  /// Deliberately NOT `maintainState: true` on the section instead. Keeping
  /// the children alive behind the collapse would put the form's own
  /// validators back in play from somewhere invisible, so Save would do
  /// nothing at all and say nothing either — strictly worse than an error card
  /// naming a field you then have to go and find.
  ///
  /// Matched on the message rather than on which check failed, because the
  /// messages come from Rust — `check_profile`'s DoH rules and the DTO
  /// conversion's field names (`dns_mode`, `dns_servers`, `doh_sni/doh_path`)
  /// — and there is no structured error to switch on. Opening the section for
  /// a message that merely happens to contain "dns" costs the user nothing.
  static bool _namesSomethingAdvanced(String message) =>
      RegExp('dns|doh', caseSensitive: false).hasMatch(message);

  /// Deletes, after asking.
  ///
  /// The question itself lives in [confirmDeleteProfile], shared with the
  /// profiles list's menu entry. Two copies of a confirmation drift, and the
  /// one that drifts is the one nothing asserts — which is how the list's
  /// entry came to have no confirmation at all while this one did.
  Future<void> _confirmDelete() async {
    final ok = await confirmDeleteProfile(context, _name.text);
    if (!ok || !mounted) return;
    await widget.writer.delete(widget.existing!.path);
    widget.onSaved();
    if (mounted) Navigator.of(context).pop();
  }

  /// What the credential field is called, for the protocol in play.
  ///
  /// The same two widgets serve an SSH private key, a WireGuard pre-shared key
  /// and a Shadowsocks password, which is fine — but labelling either key
  /// "Password" is not. `preshared_key` fell to the `else` of a ternary and
  /// was called a password, which is the same mislabelling one credential
  /// over.
  String get _secretLabel => switch (_authKind) {
        'private_key' => 'Private key',
        'preshared_key' => 'Pre-shared key',
        _ => 'Password',
      };

  /// What the *path* field is called, and what it suggests.
  ///
  /// Split from [_secretLabel] because "Path to the private key file" reads
  /// worse than the name the field has always had, and because the hint is a
  /// third thing again: an unconditional `/Users/you/.ssh/id_ed25519` told a
  /// Shadowsocks profile to point its password at an SSH key, which is advice
  /// rather than a placeholder.
  String get _secretPathLabel => switch (_authKind) {
        'private_key' => 'Path to the key file',
        'preshared_key' => 'Path to the pre-shared key file',
        _ => 'Path to the password file',
      };

  String get _secretPathHint => switch (_authKind) {
        'private_key' => '/Users/you/.ssh/id_ed25519',
        'preshared_key' => '/Users/you/.liostunnel/secrets/wg-psk',
        _ => '/Users/you/.liostunnel/secrets/password',
      };

  /// Whether the credential in play is a key file rather than something a
  /// person can type.
  ///
  /// [_text] builds a one-line field, and it cannot be made multi-line while
  /// it is obscured — `TextField` asserts `!obscureText || maxLines == 1`, so
  /// the alternative to hiding the typed mode is rendering key material
  /// legibly on screen. An OpenSSH private key is a multi-line PEM document:
  /// offering "Type it" for one invites a paste whose newlines do not survive,
  /// [ProfileWriter.writeSecret] writes the mangled blob, `check_profile` sees
  /// a perfectly well-formed `(Ssh, PrivateKey)` pairing, the save reports
  /// success, and the failure arrives at connect time from another process.
  ///
  /// Nothing is lost by removing it: a key you already have IS a file, which
  /// is exactly what the other mode is for. A WireGuard pre-shared key is one
  /// line of base64 and keeps both modes.
  bool get _secretIsAKeyFile => _authKind == 'private_key';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_editing ? 'Edit profile' : 'New profile'),
        actions: [
          if (_editing)
            IconButton(
              key: const Key('delete-button'),
              icon: const Icon(Icons.delete_outline),
              tooltip: 'Delete',
              onPressed: _busy ? null : _confirmDelete,
            ),
        ],
      ),
      body: Form(
        key: _form,
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            if (_error != null)
              Card(
                key: const Key('editor-error'),
                color: Theme.of(context).colorScheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(_error!),
                ),
              ),
            if (_saved != null)
              Card(
                key: const Key('editor-saved'),
                color: Theme.of(context).colorScheme.secondaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text('Saved to $_saved'),
                ),
              ),
            // A provider hands you a link; nobody creates a Shadowsocks
            // profile by typing a cipher name. So this goes first, and it is
            // NOT gated on picking Shadowsocks from a dropdown -- importing
            // is what decides the protocol.
            //
            // Shown whenever the editor is not editing a profile that parsed
            // — which is NOT the same as "there is no file". `_editing` is
            // `existing?.profile != null`, and the profiles list offers Edit
            // on a broken row too, deliberately and under test. So opening an
            // unreadable profile to repair it lands here with a path, no
            // profile, and the link row on screen. That is the right answer:
            // re-importing is a plausible repair for a Shadowsocks profile
            // nothing can read, and the save replaces the file it came from.
            //
            // On an edit proper you are not re-importing, and a link sitting
            // here on a save is what let a rotation be silently discarded —
            // which is why [_linkRowVisible], and not a second copy of this
            // condition, is what `_save`'s guard keys on.
            //
            // Obscured: an `ss://` link IS the password, so it is a
            // credential field like any other.
            if (_linkRowVisible) ...[
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
            _text(_name, 'Name', key: 'f-name'),
            _text(_host, 'Host', key: 'f-host', hint: 'example.com or an IP'),
            _text(
              _port,
              'Port',
              key: 'f-port',
              validator: (v) {
                final n = int.tryParse(v ?? '');
                if (n == null || n < 1 || n > 65535) return '1–65535';
                return null;
              },
            ),
            if (_authKind != 'shadowsocks')
              _text(_user, 'SSH username', key: 'f-user'),
            const SizedBox(height: 16),

            DropdownButtonFormField<String>(
              key: const Key('f-auth'),
              initialValue: _authKind,
              decoration: const InputDecoration(labelText: 'Authentication'),
              items: const [
                DropdownMenuItem(value: 'password', child: Text('Password')),
                DropdownMenuItem(
                    value: 'private_key', child: Text('Private key')),
                // Present so opening a preshared_key profile does not crash
                // the form: DropdownButtonFormField asserts its value matches
                // exactly one item. WireGuard is not connectable yet, but the
                // profile is editable and must survive a round trip.
                DropdownMenuItem(
                    value: 'preshared_key', child: Text('Pre-shared key')),
                DropdownMenuItem(
                    value: 'shadowsocks', child: Text('Shadowsocks')),
              ],
              onChanged: (v) => setState(() {
                _authKind = v!;
                // The mode dropdown below drops "Type it" for a key file, and
                // DropdownButtonFormField asserts that exactly one of its
                // items matches its value: leaving `_secretMode` on `typed`
                // here turned the whole form into an ErrorWidget. Same
                // assertion the Cipher dropdown already has to dodge.
                if (_secretIsAKeyFile) _secretMode = 'file';
              }),
            ),
            if (_authKind == 'shadowsocks') ...[
              const SizedBox(height: 8),
              DropdownButtonFormField<String>(
                key: const Key('f-cipher'),
                initialValue: _cipher,
                decoration: const InputDecoration(labelText: 'Cipher'),
                items: [
                  for (final c in _cipherItems())
                    DropdownMenuItem(value: c, child: Text(c)),
                ],
                onChanged: (v) => setState(() => _cipher = v!),
              ),
            ],
            const SizedBox(height: 8),
            DropdownButtonFormField<String>(
              key: const Key('f-secret-mode'),
              initialValue: _secretMode,
              decoration: const InputDecoration(labelText: 'Where the secret lives'),
              items: [
                const DropdownMenuItem(
                    value: 'file', child: Text('A file I already have')),
                // Not offered for a key file — see [_secretIsAKeyFile]. The
                // option, not just the field: a label that invites a gesture
                // the widget silently mangles is the defect.
                if (!_secretIsAKeyFile)
                  const DropdownMenuItem(
                      value: 'typed',
                      child: Text('Type it — save to a 0600 file')),
              ],
              onChanged: (v) => setState(() => _secretMode = v!),
            ),
            const SizedBox(height: 8),
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
                _secretPathLabel,
                key: 'f-secret-path',
                hint: _secretPathHint,
                help: 'Must be owned by you and mode 0600, or the helper will '
                    'refuse it.',
              ),

            const SizedBox(height: 16),
            // Split by how often you touch it, not by protocol. DNS is set
            // once and forgotten, and having it on screen means it competes
            // with the fields you actually edit.
            ExpansionTile(
              key: const Key('advanced-section'),
              // So a refusal naming a DNS or DoH field can open the section
              // that holds it — see [_namesSomethingAdvanced].
              controller: _advanced,
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

            const SizedBox(height: 24),
            FilledButton(
              key: const Key('save-button'),
              onPressed: _busy ? null : _save,
              child: Text(
                _busy
                    ? 'Saving…'
                    : _editing
                        ? 'Save changes'
                        : 'Save profile',
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// What the Cipher dropdown offers for the profile in front of it.
  ///
  /// [offeredCiphers], plus the profile's own value when this build does not
  /// offer it. `DropdownButtonFormField` asserts that exactly one of its items
  /// matches its value, and `method` is a free `String` in the schema: a
  /// profile written by the CLI naming `2022-blake3-aes-256-gcm` — today's
  /// default server cipher — made the editor unusable the moment it opened.
  /// In debug the assertion fired and the whole form became an ErrorWidget; in
  /// release the assert is stripped and the field rendered blank while the
  /// rejected name was still what a Save would write.
  ///
  /// Shown rather than replaced by a default, deliberately. Shadowsocks has no
  /// handshake, so a cipher silently substituted here would look exactly like
  /// a working one and simply discard every packet; the user has to see what
  /// their profile actually says. Saving it is still refused, by the same
  /// `check_profile` the Save button already goes through, with a message
  /// naming what IS offered. This is the treatment `preshared_key` already
  /// gets in the Authentication dropdown above, for the same reason.
  List<String> _cipherItems() => [
        ...offeredCiphers,
        if (!offeredCiphers.contains(_cipher)) _cipher,
      ];

  Widget _text(
    TextEditingController c,
    String label, {
    required String key,
    String? hint,
    String? help,
    bool obscure = false,
    String? Function(String?)? validator,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: TextFormField(
        key: Key(key),
        controller: c,
        obscureText: obscure,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          helperText: help,
          helperMaxLines: 3,
        ),
        validator: validator ??
            (v) => (v == null || v.trim().isEmpty) ? 'required' : null,
      ),
    );
  }
}
