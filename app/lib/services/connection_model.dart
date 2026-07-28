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
  String _state = 'Disconnected';
  BigInt _bytesUp = BigInt.zero;
  BigInt _bytesDown = BigInt.zero;
  int _activeFlows = 0;
  BigInt _flowsFailed = BigInt.zero;
  BigInt _dnsQueries = BigInt.zero;
  Fault? _lastFault;

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
        // A banner that outlives its cause is worse than no banner.
        _lastFault = null;
      case StatsEvent(
        :final bytesUp,
        :final bytesDown,
        :final activeFlows,
        :final flowsFailed,
        :final dnsQueries,
      ):
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
    Fault.helperNotInstalled =>
      'The helper is not installed or not running. '
          'Run packaging/install-helper.sh.',
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

  void _zeroStats() {
    _bytesUp = BigInt.zero;
    _bytesDown = BigInt.zero;
    _activeFlows = 0;
    _flowsFailed = BigInt.zero;
    _dnsQueries = BigInt.zero;
  }

  @visibleForTesting
  void setFaultForTest(Fault f) {
    _lastFault = f;
    notifyListeners();
  }
}
