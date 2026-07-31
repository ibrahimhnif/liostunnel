import 'dart:async';
import 'dart:io';

import '../src/rust/api/android.dart';
import '../src/rust/api/config.dart';
import '../src/rust/dto/profile.dart';
import 'vpn_platform.dart';

/// Drives the in-process engine on Android.
///
/// # Why this is not [HelperClient]
///
/// On desktop the engine runs as root in `liostunnel-helper` and the app
/// drives it over a unix socket, which pushes a stats frame every second.
/// Android has no helper and no socket — the engine is in this process, so
/// state and counters are *pulled* over FFI instead of pushed.
///
/// The shape handed to `ConnectionModel` is identical either way, which is
/// what lets live speed work on Android with no Android-specific code: it is
/// a pure function of the stats stream.
///
/// # Order of operations is a security property
///
/// [connect] stages the profile **over FFI** before asking Kotlin to start the
/// service. The service start carries no arguments at all, so no credential
/// ever reaches an `Intent` or a `MethodChannel`.
class AndroidTunnel {
  AndroidTunnel({Duration pollInterval = const Duration(seconds: 1)})
    : _pollInterval = pollInterval;

  final Duration _pollInterval;
  Timer? _poll;

  /// Emits engine state and counters on the same cadence the desktop helper
  /// pushes its `Stats` frame.
  final _events = StreamController<AndroidTunnelEvent>.broadcast();
  Stream<AndroidTunnelEvent> get events => _events.stream;

  static bool get isSupported => Platform.isAndroid;

  /// Stages the profile, asks for VPN consent, then starts the service.
  ///
  /// Returns false when the user declined consent. That is an answer rather
  /// than an error and must not be retried on its own.
  Future<bool> connect({
    required ProfileDto profile,
    required String user,
    required List<SecretPair> secrets,
  }) async {
    // FFI first: the engine must already hold the credential before anything
    // is handed to Kotlin.
    await androidStageProfile(dto: profile, user: user, secrets: secrets);

    if (!await VpnPlatform.prepare()) return false;

    await VpnPlatform.start();
    _startPolling();
    return true;
  }

  Future<void> disconnect() async {
    await VpnPlatform.stop();
    // One last read, so the UI settles on the real post-stop state rather
    // than the last value seen while it was still running.
    await _tick();
    _poll?.cancel();
    _poll = null;
  }

  void _startPolling() {
    _poll?.cancel();
    _poll = Timer.periodic(_pollInterval, (_) => _tick());
  }

  Future<void> _tick() async {
    try {
      final status = await androidStatus();
      final stats = await androidStats();
      if (!_events.isClosed) {
        _events.add(AndroidTunnelEvent(status: status, stats: stats));
      }
    } catch (e) {
      // A failed poll is not a failed tunnel. Reporting it as one would put
      // an error banner over a working connection because a single FFI call
      // lost a race with teardown.
      if (!_events.isClosed) _events.addError(e);
    }
  }

  void dispose() {
    _poll?.cancel();
    _poll = null;
    _events.close();
  }
}

class AndroidTunnelEvent {
  const AndroidTunnelEvent({required this.status, required this.stats});
  final EngineStatusDto status;
  final EngineStatsDto stats;
}

/// Reads the secret material a profile points at, for [AndroidTunnel.connect].
///
/// On desktop the root helper resolves these itself, from files only it can
/// read. Android has no helper: the profile's secrets live in the app's own
/// sandbox, written there by the profile editor, and the app is the only
/// thing that can read them.
///
/// Values are read through `fileSecretValue`, the core's own
/// `strip_one_trailing_line_ending`, rather than a Dart reimplementation —
/// an editor that appends a newline would otherwise produce a password that
/// differs from the one the CLI sends, and the failure would look like a
/// rejected credential.
Future<List<SecretPair>> resolveSecrets(ProfileDto profile) async {
  final out = <SecretPair>[];
  for (final source in [
    profile.authSecretSource,
    if (profile.authPassphraseSource != null) profile.authPassphraseSource!,
  ]) {
    out.add(await _resolveOne(source));
  }
  return out;
}

Future<SecretPair> _resolveOne(String source) async {
  final sep = source.indexOf(':');
  if (sep < 0) {
    throw FormatException('secret source is neither file: nor env:', source);
  }
  final kind = source.substring(0, sep);
  final key = source.substring(sep + 1);

  switch (kind) {
    case 'file':
      final bytes = await File(key).readAsBytes();
      final value = await fileSecretValue(bytes: bytes);
      return SecretPair(kind: 'file', key: key, value: value);
    case 'env':
      final value = Platform.environment[key];
      if (value == null) {
        // Android gives an app almost no environment, so this is nearly
        // always a profile written on a desktop and copied over. Saying so
        // beats a rejected-credential error later.
        throw StateError('the environment variable $key is not set');
      }
      return SecretPair(kind: 'env', key: key, value: value);
    default:
      throw FormatException('unknown secret source kind: $kind', source);
  }
}
