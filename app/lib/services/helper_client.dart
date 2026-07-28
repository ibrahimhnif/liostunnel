import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../src/rust/api/protocol.dart';

/// Something the helper pushed without being asked.
sealed class HelperEvent {
  const HelperEvent();
}

class StateEvent extends HelperEvent {
  final String state;
  const StateEvent(this.state);
}

class StatsEvent extends HelperEvent {
  final BigInt bytesUp;
  final BigInt bytesDown;
  final int activeFlows;
  final BigInt flowsFailed;
  final BigInt dnsQueries;
  const StatsEvent({
    required this.bytesUp,
    required this.bytesDown,
    required this.activeFlows,
    required this.flowsFailed,
    required this.dnsQueries,
  });
}

/// The helper is not reachable: no socket, or the connection dropped.
class HelperUnavailable implements Exception {
  final String detail;
  const HelperUnavailable([this.detail = 'the helper is not reachable']);
  @override
  String toString() => 'HelperUnavailable: $detail';
}

/// The socket exists but this user cannot open it.
///
/// Deliberately distinct from [HelperUnavailable]: one means "run the
/// installer", the other means "you are not the authorized user". Collapsing
/// them would send the user after the wrong fix.
class HelperForbidden implements Exception {
  const HelperForbidden();
  @override
  String toString() => 'HelperForbidden: this user may not open the socket';
}

/// The helper answered with a refusal.
///
/// Callers branch on [kind]; [message] is diagnostic and must never be
/// parsed. The kind is the contract, the wording is not.
class HelperError implements Exception {
  final ErrorKindDto kind;
  final String message;
  const HelperError(this.kind, this.message);
  @override
  String toString() => 'HelperError($kind): $message';
}

/// Talks to the privileged helper over its unix socket.
///
/// Framing and lifecycle only. Every request is encoded and every reply
/// decoded by the Rust codec across the FFI, so this file contains no
/// knowledge of the wire format — that lives in one place, and a change to it
/// cannot leave the two sides disagreeing.
class HelperClient {
  HelperClient({this.retryDelay = const Duration(seconds: 2)});

  /// Fixed rather than exponential: the helper is local, and a user who just
  /// ran the installer should not wait thirty seconds to find out it worked.
  final Duration retryDelay;

  Socket? _socket;
  String? _path;
  StreamSubscription<String>? _reader;
  Timer? _retryTimer;
  bool _closed = false;

  final _events = StreamController<HelperEvent>.broadcast();
  final _pending = <BigInt, Completer<void>>{};
  var _nextId = BigInt.one;
  var _reconnected = Completer<void>();

  Stream<HelperEvent> get events => _events.stream;

  /// Completes the next time a dropped connection is re-established.
  Future<void> get whenReconnected => _reconnected.future;

  /// True while a reconnect is scheduled. Exposed so a test can prove
  /// [close] actually stops the loop rather than leaving it dialling.
  bool get isRetrying => _retryTimer?.isActive ?? false;

  Future<void> connect(String socketPath) async {
    _path = socketPath;
    _closed = false;
    await _open();
  }

  Future<void> _open() async {
    final addr = InternetAddress(_path!, type: InternetAddressType.unix);
    try {
      // The port argument is required and ignored for unix sockets.
      _socket = await Socket.connect(addr, 0);
    } on SocketException catch (e) {
      // Split by errno, because the two have opposite fixes. ENOENT means the
      // helper was never installed; EACCES/EPERM means it was, for someone
      // else.
      final code = e.osError?.errorCode;
      if (code == 13 || code == 1) throw const HelperForbidden();
      throw HelperUnavailable(e.osError?.message ?? 'cannot open $_path');
    }

    _reader = _socket!
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(
          _onLine,
          onError: (_) => _onDropped(),
          onDone: _onDropped,
          cancelOnError: true,
        );
  }

  Future<void> _onLine(String line) async {
    final IncomingDto msg;
    try {
      msg = await decodeMessage(line: line);
    } catch (_) {
      // A helper newer than this build may push something unknown. Ignoring
      // it deliberately is right; taking the connection down over it is not.
      return;
    }
    switch (msg) {
      case IncomingDto_Ack(:final id):
        _pending.remove(id)?.complete();
      case IncomingDto_Error(:final id, :final kind, :final message):
        _pending.remove(id)?.completeError(HelperError(kind, message));
      case IncomingDto_State(:final state):
        _events.add(StateEvent(state));
      case IncomingDto_Stats(
        :final bytesUp,
        :final bytesDown,
        :final activeFlows,
        :final flowsFailed,
        :final dnsQueries,
      ):
        _events.add(
          StatsEvent(
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            activeFlows: activeFlows,
            flowsFailed: flowsFailed,
            dnsQueries: dnsQueries,
          ),
        );
    }
  }

  void _onDropped() {
    _socket?.destroy();
    _socket = null;

    // Fail every in-flight request. Without this the future never completes
    // and whatever the UI was showing spins forever.
    final inflight = List.of(_pending.values);
    _pending.clear();
    for (final c in inflight) {
      if (!c.isCompleted) {
        c.completeError(const HelperUnavailable('the connection dropped'));
      }
    }

    if (_closed) return;
    _events.add(const StateEvent('Disconnected'));
    _scheduleRetry();
  }

  void _scheduleRetry() {
    _retryTimer?.cancel();
    _retryTimer = Timer(retryDelay, () async {
      if (_closed) return;
      try {
        await _open();
        await hello();
        if (!_reconnected.isCompleted) _reconnected.complete();
        _reconnected = Completer<void>();
      } catch (_) {
        _scheduleRetry();
      }
    });
  }

  Future<void> _send(RequestDto Function(BigInt id) build) async {
    final s = _socket;
    if (s == null) throw const HelperUnavailable('not connected');
    final id = _nextId;
    _nextId += BigInt.one;
    final completer = Completer<void>();
    _pending[id] = completer;
    try {
      s.write('${await encodeRequest(req: build(id))}\n');
    } catch (e) {
      _pending.remove(id);
      throw HelperUnavailable('$e');
    }
    return completer.future;
  }

  Future<void> hello() => _send((id) => RequestDto.hello(id: id));

  Future<void> sendConnect(ConnectParamsDto params) =>
      _send((id) => RequestDto.connect(id: id, params: params));

  Future<void> disconnect() => _send((id) => RequestDto.disconnect(id: id));

  Future<void> getStatus() => _send((id) => RequestDto.getStatus(id: id));

  Future<void> close() async {
    _closed = true;
    _retryTimer?.cancel();
    _retryTimer = null;
    await _reader?.cancel();
    _reader = null;
    _socket?.destroy();
    _socket = null;
    await _events.close();
  }
}
