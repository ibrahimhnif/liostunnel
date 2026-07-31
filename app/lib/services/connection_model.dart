import 'dart:io';

import 'package:flutter/foundation.dart';

import '../src/rust/api/protocol.dart';
import 'helper_client.dart';

/// Something that went wrong, in terms the UI can act on.
///
/// Covers the helper's own [ErrorKindDto]s plus two conditions it can never
/// report, because in both the socket never opened at all.
enum Fault {
  helperNotInstalled,
  notAuthorized,
  versionMismatch,
  unauthorized,
  secretNotPermitted,
  alreadyConnected,
  notConnected,
  authFailed,
  badRequest,
  internal,
}

/// Connection state and the latest stats, for two screens.
///
/// A single [ChangeNotifier] rather than a state-management framework (D8):
/// two screens and one live value do not justify Riverpod or Bloc.
class ConnectionModel extends ChangeNotifier {
  /// [clock] is injected so tests assert exact rates instead of sleeping.
  ConnectionModel({DateTime Function()? clock}) : _clock = clock ?? DateTime.now;

  final DateTime Function() _clock;

  /// Samples closer together than this carry no usable rate.
  ///
  /// The helper ticks once a second, so a gap this small means frames were
  /// buffered and drained, not that traffic was measured over it.
  static const _minSampleGap = 0.25;

  String _state = 'Disconnected';
  BigInt _bytesUp = BigInt.zero;
  BigInt _bytesDown = BigInt.zero;
  int _activeFlows = 0;
  BigInt _flowsFailed = BigInt.zero;
  BigInt _dnsQueries = BigInt.zero;
  Fault? _lastFault;

  /// The previous sample, for the delta. Null means no rate can be computed
  /// yet -- the first frame of a connection, or the one after a reset.
  DateTime? _lastSampleAt;
  BigInt? _lastUp;
  BigInt? _lastDown;
  double? _upPerSec;
  double? _downPerSec;

  /// Current speed in bytes per second, or null when there is no rate.
  ///
  /// Null is deliberately not 0.0: zero is a claim that no traffic moved, and
  /// before the second sample there is no such claim to make. The distinction
  /// lasts one second per connection -- which is exactly the second someone is
  /// watching to see whether connecting worked.
  double? get bytesUpPerSec => _upPerSec;
  double? get bytesDownPerSec => _downPerSec;

  /// What the first-launch installer is doing, if anything.
  ///
  /// Separate from [Fault] because it is not a fault: an install in progress
  /// is a normal startup, and a cancelled one is the user's answer.
  String? _installNotice;
  String? get installNotice => _installNotice;

  set installNotice(String? v) {
    _installNotice = v;
    notifyListeners();
  }

  String get state => _state;
  bool get isConnected => _state == 'Connected';
  BigInt get bytesUp => _bytesUp;
  BigInt get bytesDown => _bytesDown;
  int get activeFlows => _activeFlows;
  BigInt get flowsFailed => _flowsFailed;
  BigInt get dnsQueries => _dnsQueries;
  Fault? get lastFault => _lastFault;

  void applyEvent(HelperEvent e) {
    switch (e) {
      case StateEvent(:final state):
        _state = state;
        // Numbers left on screen after a tunnel stops read as live traffic.
        if (state != 'Connected') _zeroStats();
        // Cleared only on success. Clearing on EVERY state event wiped the
        // banner that had just been raised: a helper dying mid-connect fails
        // the in-flight request (scheduling applyError) and then synthesises
        // StateEvent('Disconnected') — the error microtask ran first and the
        // state event erased it, so the spinner stopped and nothing else
        // appeared.
        if (state == 'Connected') _lastFault = null;
      case StatsEvent(
        :final bytesUp,
        :final bytesDown,
        :final activeFlows,
        :final flowsFailed,
        :final dnsQueries,
      ):
        _recomputeRates(bytesUp, bytesDown);
        _bytesUp = bytesUp;
        _bytesDown = bytesDown;
        _activeFlows = activeFlows;
        _flowsFailed = flowsFailed;
        _dnsQueries = dnsQueries;
    }
    notifyListeners();
  }

  /// Accepts any of the three exception types the client can throw.
  void applyError(Object e) {
    _lastFault = switch (e) {
      HelperUnavailable() => Fault.helperNotInstalled,
      HelperForbidden() => Fault.notAuthorized,
      // Exhaustive over ErrorKindDto: a new variant in the protocol fails to
      // compile here rather than falling through to a generic message.
      HelperError(:final kind) => switch (kind) {
        ErrorKindDto.versionMismatch => Fault.versionMismatch,
        ErrorKindDto.unauthorized => Fault.unauthorized,
        ErrorKindDto.secretNotPermitted => Fault.secretNotPermitted,
        ErrorKindDto.alreadyConnected => Fault.alreadyConnected,
        ErrorKindDto.notConnected => Fault.notConnected,
        ErrorKindDto.authFailed => Fault.authFailed,
        ErrorKindDto.badRequest => Fault.badRequest,
        ErrorKindDto.internal => Fault.internal,
      },
      _ => Fault.internal,
    };
    notifyListeners();
  }

  /// Wording for the current fault, or null when there is none.
  ///
  /// Derived from the fault, never from the helper's message. The kind is the
  /// contract; the wording is ours, and a UI that displayed the helper's text
  /// would break the first time that text changed.
  String? get userFacingError => switch (_lastFault) {
    null => null,
    // Neither shipped artifact has a `packaging/` in it, which is what this
    // used to send the user looking for. On macOS the package already
    // installed the helper, so a missing one is a broken install rather than
    // an absent one — and reinstalling from the app would paper over whatever
    // removed it. On Linux the app offers to install it itself, in the panel
    // above this banner, so the sentence does not need to name a command.
    Fault.helperNotInstalled => Platform.isMacOS
        ? 'The helper is not installed. Reinstall LiosTunnel from its '
              'installer package.'
        : 'The helper is not installed or not running.',
    Fault.notAuthorized =>
      'You are not authorized to use the helper. It was installed '
          'for a different user.',
    Fault.versionMismatch =>
      'The helper is out of date. Reinstall it to match this app.',
    Fault.unauthorized => 'This user is not authorized to use the helper.',
    Fault.secretNotPermitted =>
      'That profile points at a key file you do not own. '
          'The helper will not read it on your behalf.',
    Fault.alreadyConnected =>
      'A tunnel is already running. Disconnect it first.',
    Fault.notConnected => 'No tunnel is running.',
    Fault.authFailed => 'The server rejected the credentials.',
    Fault.badRequest =>
      'The helper rejected the request. Reinstall it and try again.',
    Fault.internal => 'The helper hit an internal error. Check its log.',
  };

  /// Rate from the measured gap between samples.
  ///
  /// Not from the helper's `STATS_INTERVAL`: it ticks every second, but a
  /// frame arrives late on a loaded machine, and dividing a 1.4s gap by 1s
  /// reports traffic 40% faster than occurred.
  void _recomputeRates(BigInt up, BigInt down) {
    final now = _clock();
    final prevAt = _lastSampleAt;
    final prevUp = _lastUp;
    final prevDown = _lastDown;

    void rebaseline() {
      _lastSampleAt = now;
      _lastUp = up;
      _lastDown = down;
    }

    if (prevAt == null || prevUp == null || prevDown == null) {
      rebaseline();
      _upPerSec = null;
      _downPerSec = null;
      return;
    }
    // A total that went down means the counters restarted -- a reconnect
    // (`_zeroStats`) or a helper restart. Subtracting would give a negative
    // rate, and unsigned arithmetic an enormous one. Report nothing and let
    // the sample just stored become the new baseline. Both are dropped
    // together because they come from one snapshot: a rate for `down`
    // measured against a sample that `up` proves stale is worse than none.
    if (up < prevUp || down < prevDown) {
      rebaseline();
      _upPerSec = null;
      _downPerSec = null;
      return;
    }
    final secs = now.difference(prevAt).inMicroseconds / 1e6;
    if (secs < _minSampleGap) {
      // Not just a zero gap. The isolate stalls -- a GC pause, a window
      // resize, sleep/wake -- while the helper keeps writing one frame per
      // second into the socket buffer. On resume `LineSplitter` emits them
      // back to back, microseconds apart, and a megabyte over 16us is
      // 62 GB/s. Measured gaps in a tight loop: 0, 1 and 16us.
      //
      // And deliberately WITHOUT rebaselining: returning before the baseline
      // is updated leaves the old sample in place, so the next well-separated
      // frame measures across the whole stall instead of against a drained
      // one. Rebaselining here would replace one wrong answer with another.
      _upPerSec = null;
      _downPerSec = null;
      return;
    }
    rebaseline();
    _upPerSec = (up - prevUp).toDouble() / secs;
    _downPerSec = (down - prevDown).toDouble() / secs;
  }

  void _zeroStats() {
    _bytesUp = BigInt.zero;
    _bytesDown = BigInt.zero;
    _activeFlows = 0;
    _flowsFailed = BigInt.zero;
    _dnsQueries = BigInt.zero;
    _upPerSec = null;
    _downPerSec = null;
    // The baseline too. Keeping it would measure the next connection's first
    // sample against the previous session's totals.
    _lastSampleAt = null;
    _lastUp = null;
    _lastDown = null;
  }

  @visibleForTesting
  void setFaultForTest(Fault f) {
    _lastFault = f;
    notifyListeners();
  }
}
