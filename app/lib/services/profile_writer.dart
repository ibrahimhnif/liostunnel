import 'dart:convert';
import 'dart:io';

import '../src/rust/api/config.dart';
import '../src/rust/dto/profile.dart';
import 'profile_store.dart';

/// Writes profiles and, when asked, the secret file one refers to.
///
/// Kept out of the widget so the file-permission rules have tests. They are
/// the reason this class exists at all: the helper refuses any secret file
/// the calling user does not own, or that is readable by anyone else, so a
/// profile whose secret file is written carelessly produces a refusal the
/// user cannot diagnose from the UI.
class ProfileWriter {
  ProfileWriter({required this.directory});

  final String directory;

  /// Where a password written by [writeSecret] lives.
  String get secretsDirectory => '$directory/secrets';

  /// Throws if saving under [name] would land on a different profile.
  ///
  /// Separate from [writeProfile] so it can run *before* a secret is written.
  /// It used to be checked inside the write, after [writeSecret] had already
  /// replaced a credential — so a name collision destroyed another profile's
  /// password and then reported failure, leaving the user certain nothing had
  /// happened.
  void checkNameFree(String name, {String? replacingPath}) {
    final path = '$directory/${_slug(name)}.json';
    if (File(path).existsSync() && path != replacingPath) {
      throw StateError('a different profile is already called "$name"');
    }
  }

  /// Serialises through the FFI and writes it.
  ///
  /// The document is produced by `export_profile`, not by string-building
  /// here — the schema has one owner (P1a-1), and a hand-rolled encoder in
  /// Dart would be a second one free to drift.
  /// Writes the profile and, beside it, the SSH username.
  ///
  /// The username is NOT part of `ServerProfile` — it is a connect-time
  /// parameter, so the schema has nowhere to put it. Without somewhere to
  /// keep it the app fell back to the local account name, which is almost
  /// never the account on the server: every connection to a host like
  /// `user-provider.com@host` failed as "the server rejected the
  /// credentials" while the password was fine.
  ///
  /// A sidecar rather than an extension to the profile format: that format is
  /// shared with the CLI and belongs to the core, and widening it from here
  /// would fork it.
  /// [replacingPath] is the profile being edited, if any.
  ///
  /// The filename comes from the profile's name, so renaming one means moving
  /// it. Both halves matter: the old file has to go, or the list shows the
  /// profile twice under two names, and the new name must not land on top of
  /// a *different* profile, which would silently destroy it.
  Future<File> writeProfile(
    ProfileDto dto, {
    String? sshUser,
    String? replacingPath,
  }) async {
    final json = await exportProfile(dto: dto);
    Directory(directory).createSync(recursive: true);
    final file = File('$directory/${_slug(dto.name)}.json');
    checkNameFree(dto.name, replacingPath: replacingPath);

    file.writeAsStringSync(json);
    final sidecar = File('${file.path}.user');
    if (sshUser != null && sshUser.trim().isNotEmpty) {
      sidecar.writeAsStringSync(sshUser.trim());
    } else if (sidecar.existsSync()) {
      // Cleared on purpose: leaving the old one would keep sending a username
      // the user has just removed.
      sidecar.deleteSync();
    }

    if (replacingPath != null && replacingPath != file.path) {
      _deleteQuietly(replacingPath);
      _deleteQuietly('$replacingPath.user');
    }
    return file;
  }

  /// Copies a profile, including every file its credentials live in.
  ///
  /// The secret copy is the point. [writeSecret] names the file after the
  /// profile id, so a duplicate that pointed at the original's file would look
  /// correct right up until someone changed the copy's password — and the
  /// original's credential would be gone, from a gesture that said
  /// "duplicate". This codebase has shipped that failure twice: once when a
  /// name collision destroyed another profile's password, once when a refused
  /// save destroyed the one it was refusing.
  ///
  /// **Every** file, plural: an ssh `private_key` credential is two of them.
  /// `PortableProfile::import` writes `<id>.private_key` *and*
  /// `<id>.passphrase`, both keyed on the profile id, and a copy that carried
  /// the passphrase reference across unchanged would alias the original's
  /// file — the same defect one field over, and a quieter one, because
  /// nothing in the app writes a passphrase today, so only a profile that
  /// arrived through the CLI's portable import has one to lose.
  ///
  /// Refused if the secret is not a `file:` reference at all, rather than
  /// producing a copy that points at nothing — and if a file this app is about
  /// to copy cannot be read, for the same reason. A passphrase that is not a
  /// `file:` reference is the exception and is carried as it stands:
  /// `env:PASS` names no file, so two profiles reading it destroy nothing.
  ///
  /// **Only a file this app wrote is copied**, i.e. one in [secretsDirectory].
  /// The argument above is entirely about that directory: [writeSecret] names
  /// the file after the profile id, which is what makes two profiles sharing
  /// one managed file one edit away from destroying each other. A credential
  /// the user keeps elsewhere — `file:/Users/you/.ssh/id_ed25519` — is under
  /// no such threat. [_writeSecretBytes] can only write inside
  /// [secretsDirectory], and for `private_key` the editor removes the "type
  /// it" mode altogether, so [writeSecret] is never called for an SSH key
  /// profile at all: nothing this app does can clobber that file. Copying it
  /// anyway produced a second copy of a private key under a UUID the user
  /// never asked for, which [delete] deliberately never collects — and a
  /// *decoupled* one, so rotating `~/.ssh/id_ed25519` left the original
  /// working and the duplicate failing as "the server rejected the
  /// credentials". Such a reference is carried across unchanged, on the same
  /// reasoning as the `env:` passphrase above: two profiles reading it destroy
  /// nothing. It is not read either, so a key on a volume that is not mounted
  /// today does not refuse a duplicate of a profile with nothing wrong with
  /// it.
  Future<File> duplicate(LoadedProfile source) async {
    final src = source.profile;
    if (src == null) {
      throw StateError('a profile that does not parse cannot be duplicated');
    }
    if (!src.authSecretSource.startsWith('file:')) {
      throw StateError(
        "this profile's secret is not a file, so there is nothing to copy "
        'alongside it',
      );
    }
    final copySecret = _isManaged(src.authSecretSource);
    final secret = copySecret
        ? _readSecretFile(
            src.authSecretSource,
            "this profile's secret file is missing",
          )
        : null;
    // Read before *either* copy is written, so a refusal about the passphrase
    // cannot leave the copied key behind. Same rule as moving `checkNameFree`
    // ahead of `writeSecret`: everything that can refuse runs first.
    final passSource = src.authPassphraseSource;
    final copyPassphrase = passSource != null && _isManaged(passSource);
    final passphrase = copyPassphrase
        ? _readSecretFile(
            passSource,
            "this profile's passphrase file is missing",
          )
        : null;

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
    // Where the credentials WILL live, named before anything is written — the
    // same ordering `_save` was fixed to use. Or where they already live, for
    // a file this app does not manage and is therefore not copying.
    final ref = copySecret ? 'file:${secretPathFor(id)}' : src.authSecretSource;
    final copy = ProfileDto(
      id: id,
      name: name,
      protocol: src.protocol,
      host: src.host,
      port: src.port,
      authKind: src.authKind,
      authSecretSource: ref,
      authPassphraseSource:
          copyPassphrase ? 'file:${passphrasePathFor(id)}' : passSource,
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
    if (secret != null) {
      await _writeSecretBytes(id, secret);
    }
    if (passphrase != null) {
      await _writeSecretBytes('$id.passphrase', passphrase);
    }

    // The SSH username lives in a sidecar, not in the profile, so it has to be
    // carried across explicitly or the copy silently loses it.
    final sidecar = File('${source.path}.user');
    try {
      return await writeProfile(
        copy,
        sshUser: sidecar.existsSync() ? sidecar.readAsStringSync() : null,
      );
    } catch (_) {
      // The files above are already on disk, and `writeProfile` runs
      // `checkNameFree` a second time — after them. That second check is not
      // theoretical: everything before `await newProfileId()` is synchronous,
      // so a double-tap on a Duplicate menu item enters this method twice
      // before either call yields, both settle on the same `<name> copy`, and
      // whichever loses is refused about a name the user never typed. Without
      // this, the loser leaves a 0600 file holding a live credential that no
      // profile names and nothing ever collects.
      //
      // Refused rather than retried under a further-suffixed name: the second
      // tap was an accident, and answering it with a second copy is a worse
      // surprise than answering it with nothing.
      //
      // Only these two paths, and never the profile document. Both are keyed
      // on `id`, a UUID minted here that nothing else can own, so this cannot
      // reach another profile's credential — whereas the `.json` the refusal
      // named belongs to a DIFFERENT profile, and deleting it is precisely the
      // destruction `checkNameFree` exists to refuse.
      _deleteQuietly(secretPathFor(id));
      _deleteQuietly(passphrasePathFor(id));
      rethrow;
    }
  }

  /// Whether a `file:` reference names a file in this app's own secrets
  /// directory — one [writeSecret] wrote and [secretPathFor] can name.
  ///
  /// Compared on the parent directory rather than as a string prefix, and
  /// that is the whole of the check: `dirname` leaves every `..` in place, so
  /// `<secrets>/../../.ssh/id_ed25519` has a parent of `<secrets>/../../.ssh`
  /// and is correctly seen as somewhere else. A prefix test would have called
  /// it managed and copied the key — and the path field is free text the user
  /// types.
  bool _isManaged(String ref) =>
      ref.startsWith('file:') &&
      File(ref.substring('file:'.length)).parent.path == secretsDirectory;

  /// The bytes behind a `file:` reference, or [missing] if it is not there.
  ///
  /// Bytes rather than a String. `readAsStringSync` decodes UTF-8, so a
  /// credential that is not text — a binary pre-shared key, a DER-encoded
  /// private key — came back out of here as a decode failure about byte
  /// offsets, from a gesture that said "duplicate", for a profile with nothing
  /// wrong with it.
  static List<int> _readSecretFile(String ref, String missing) {
    final f = File(ref.substring('file:'.length));
    if (!f.existsSync()) throw StateError(missing);
    return f.readAsBytesSync();
  }

  /// Removes a profile and its sidecar.
  Future<void> delete(String profilePath) async {
    _deleteQuietly(profilePath);
    _deleteQuietly('$profilePath.user');
  }

  static void _deleteQuietly(String path) {
    final f = File(path);
    if (f.existsSync()) f.deleteSync();
  }

  /// Writes a password to a file only this user can read, and returns the
  /// `file:` reference a profile should carry.
  ///
  /// The profile itself never holds the password — it holds this path. That
  /// is the same rule the DTO enforces, applied to the one place where the
  /// app unavoidably touches secret material.
  ///
  /// Created with `0600` *before* anything is written to it. Writing first
  /// and chmod-ing after leaves a window where the file exists with default
  /// permissions and the secret already in it.
  /// [profileId] rather than a name.
  ///
  /// Names are many-to-one under [_slug] — `Home VPS`, `home vps` and
  /// `HOME-VPS` all collapse to `home-vps`, and a name with no alphanumerics
  /// becomes `profile`. Two profiles therefore shared one secret file, and
  /// the second silently overwrote the first's credential. An id is unique by
  /// construction.
  /// Where [writeSecret] would put this profile's secret, without writing
  /// anything.
  ///
  /// Exists so a caller can name the file in a profile it is still checking.
  /// Writing the secret first and validating after meant a refused save had
  /// already overwritten the credential the on-disk profile pointed at.
  String secretPathFor(String profileId) =>
      '$secretsDirectory/${_slug(profileId)}';

  /// Where an ssh `private_key` profile's passphrase would go.
  ///
  /// A second file for the same profile, because that credential is two
  /// pieces: `PortableProfile::import` writes `<id>.private_key` beside
  /// `<id>.passphrase`. Derived from the id like [secretPathFor] and for the
  /// same reason — names are many-to-one under [_slug], ids are not — and it
  /// cannot collide with another profile's secret, since a slugged UUID is 36
  /// characters and this is eleven longer.
  String passphrasePathFor(String profileId) =>
      secretPathFor('$profileId.passphrase');

  Future<String> writeSecret(String profileId, String secret) =>
      _writeSecretBytes(profileId, utf8.encode(secret));

  /// The half of [writeSecret] that does not assume the secret is text.
  ///
  /// A credential is bytes. Passing one through a String means decoding it as
  /// UTF-8 first, which throws on a binary pre-shared key or a DER-encoded
  /// private key — and silently substitutes replacement characters wherever a
  /// decoder is lenient, which corrupts the credential instead of refusing it.
  Future<String> _writeSecretBytes(String profileId, List<int> bytes) async {
    final dir = Directory(secretsDirectory);
    dir.createSync(recursive: true);
    // 0700: the file is 0600, but a world-readable parent would let anyone
    // list what secrets exist and for which host.
    await Process.run('chmod', ['700', dir.path]);

    final path = '${dir.path}/${_slug(profileId)}';
    final file = File(path);
    // Not exclusive: re-saving an edit legitimately replaces its own secret,
    // and the id makes "its own" unambiguous.
    file.createSync();
    final chmod = await Process.run('chmod', ['600', path]);
    if (chmod.exitCode != 0) {
      throw FileSystemException('cannot restrict permissions on', path);
    }
    file.writeAsBytesSync(bytes, flush: true);
    return 'file:$path';
  }

  /// A filename that cannot escape the profiles directory.
  ///
  /// A profile called `../../etc/cron.d/x` would otherwise write wherever the
  /// name pointed, which for a name the user types is a needless hazard.
  static String _slug(String name) {
    final cleaned = name
        .trim()
        .toLowerCase()
        .replaceAll(RegExp(r'[^a-z0-9]+'), '-')
        .replaceAll(RegExp(r'^-+|-+$'), '');
    return cleaned.isEmpty ? 'profile' : cleaned;
  }
}
