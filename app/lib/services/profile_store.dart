import 'dart:io';

import '../src/rust/api/config.dart';
import '../src/rust/dto/profile.dart';

/// One profile on disk, and what happened when we tried to read it.
class LoadedProfile {
  final String path;
  final ProfileDto? profile;

  /// Why this file could not be used. Kept rather than discarded: a profile
  /// that silently vanishes from the list is indistinguishable from one the
  /// user never saved.
  final String? error;

  /// The account on the server, from the `.user` sidecar.
  ///
  /// Not part of `ServerProfile` — it is a connect-time parameter — so it is
  /// kept beside the profile rather than inside it.
  final String? sshUser;

  const LoadedProfile({
    required this.path,
    this.profile,
    this.error,
    this.sshUser,
  });

  bool get ok => profile != null;
  String get name => profile?.name ?? path.split('/').last;
}

/// Reads profiles from `~/.liostunnel/*.json`.
///
/// **Parsing goes through the FFI**, never a Dart reimplementation of the
/// schema — that is exit criterion P1a-1. Two implementations of one format
/// drift, and the drift shows up as a profile that works in the CLI and
/// fails in the app for no visible reason.
class ProfileStore {
  ProfileStore({String? directory}) : directory = directory ?? _defaultDir();

  final String directory;

  static String _defaultDir() {
    final home = Platform.environment['HOME'] ?? '.';
    return '$home/.liostunnel';
  }

  Future<List<LoadedProfile>> load() async {
    final dir = Directory(directory);
    if (!dir.existsSync()) return const [];

    final files =
        dir
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.json'))
            .toList()
          ..sort((a, b) => a.path.compareTo(b.path));

    final out = <LoadedProfile>[];
    for (final f in files) {
      try {
        final dto = await parseProfile(json: f.readAsStringSync());
        final sidecar = File('${f.path}.user');
        out.add(LoadedProfile(
          path: f.path,
          profile: dto,
          sshUser: sidecar.existsSync()
              ? sidecar.readAsStringSync().trim()
              : null,
        ));
      } catch (_) {
        // Deliberately not the underlying message: it may quote parts of a
        // profile document. The path is enough to find the file.
        out.add(LoadedProfile(path: f.path, error: 'not a valid profile'));
      }
    }
    return out;
  }
}
