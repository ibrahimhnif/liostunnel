import 'dart:io';

import '../src/rust/api/config.dart';
import '../src/rust/dto/profile.dart';

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

  /// Serialises through the FFI and writes it.
  ///
  /// The document is produced by `export_profile`, not by string-building
  /// here — the schema has one owner (P1a-1), and a hand-rolled encoder in
  /// Dart would be a second one free to drift.
  Future<File> writeProfile(ProfileDto dto) async {
    final json = await exportProfile(dto: dto);
    Directory(directory).createSync(recursive: true);
    final file = File('$directory/${_slug(dto.name)}.json');
    file.writeAsStringSync(json);
    return file;
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
  Future<String> writeSecret(String name, String secret) async {
    final dir = Directory(secretsDirectory);
    dir.createSync(recursive: true);
    // 0700: the file is 0600, but a world-readable parent would let anyone
    // list what secrets exist and for which host.
    await Process.run('chmod', ['700', dir.path]);

    final path = '${dir.path}/${_slug(name)}';
    final file = File(path);
    file.createSync();
    final chmod = await Process.run('chmod', ['600', path]);
    if (chmod.exitCode != 0) {
      throw FileSystemException('cannot restrict permissions on', path);
    }
    file.writeAsStringSync(secret, flush: true);
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
