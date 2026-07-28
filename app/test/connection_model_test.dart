import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/connection_model.dart';
import 'package:liostunnel_app/services/helper_client.dart';
import 'package:liostunnel_app/src/rust/api/protocol.dart';

void main() {
  test('starts disconnected with zeroed stats', () {
    final m = ConnectionModel();
    expect(m.state, 'Disconnected');
    expect(m.bytesUp, BigInt.zero);
    expect(m.activeFlows, 0);
    expect(m.lastFault, isNull);
  });

  test('a state event updates state and notifies listeners', () {
    final m = ConnectionModel();
    var notified = 0;
    m.addListener(() => notified++);
    m.applyEvent(const StateEvent('Connected'));
    expect(m.state, 'Connected');
    expect(notified, 1);
  });

  test('a stats event updates counters', () {
    final m = ConnectionModel();
    m.applyEvent(StatsEvent(
      bytesUp: BigInt.from(5),
      bytesDown: BigInt.from(9),
      activeFlows: 2,
      flowsFailed: BigInt.one,
      dnsQueries: BigInt.from(4),
    ));
    expect(m.bytesUp, BigInt.from(5));
    expect(m.activeFlows, 2);
    expect(m.dnsQueries, BigInt.from(4));
  });

  test('a helper refusal is surfaced by kind, not message text', () {
    final m = ConnectionModel();
    m.applyError(const HelperError(
      ErrorKindDto.versionMismatch,
      'helper speaks v1, client speaks v2',
    ));
    expect(m.lastFault, Fault.versionMismatch);
    // The UI decides its own wording from the kind; the helper's message is
    // diagnostic only and is never rendered.
    expect(m.userFacingError, isNot(contains('helper speaks v1')));
    expect(m.userFacingError, contains('out of date'));
  });

  test('an unreachable helper and a forbidden one read differently', () {
    // These are the two the user can actually fix, and the fixes are
    // opposites: install it, versus you are not the authorized user.
    final a = ConnectionModel()..applyError(const HelperUnavailable());
    final b = ConnectionModel()..applyError(const HelperForbidden());
    expect(a.lastFault, Fault.helperNotInstalled);
    expect(b.lastFault, Fault.notAuthorized);
    expect(a.userFacingError, contains('not installed'));
    expect(b.userFacingError, contains('not authorized'));
    expect(a.userFacingError, isNot(b.userFacingError));
  });

  test('every ErrorKind maps to its own fault', () {
    // A kind that fell through to a shared default would tell the user the
    // wrong thing about a real refusal — most damagingly for
    // secretNotPermitted, which is a security refusal, not a config typo.
    final seen = <Fault>{};
    for (final k in ErrorKindDto.values) {
      final m = ConnectionModel()..applyError(HelperError(k, 'diagnostic'));
      expect(m.lastFault, isNotNull, reason: '$k produced no fault');
      seen.add(m.lastFault!);
    }
    expect(seen.length, ErrorKindDto.values.length,
        reason: 'two kinds collapsed onto one fault');
  });

  test('every fault has wording the user can act on', () {
    for (final f in Fault.values) {
      final m = ConnectionModel()..setFaultForTest(f);
      final text = m.userFacingError!;
      expect(text, isNotEmpty, reason: '$f has no wording');
      expect(text.length, greaterThan(15), reason: '$f says too little: $text');
    }
  });

  test('a successful action clears the previous fault', () {
    final m = ConnectionModel()..applyError(const HelperUnavailable());
    expect(m.lastFault, isNotNull);
    m.applyEvent(const StateEvent('Connected'));
    expect(m.lastFault, isNull,
        reason: 'a stale banner outlives the problem it named');
  });

  test('disconnecting zeroes the stats rather than freezing them', () {
    // Numbers left on screen after a tunnel stops read as live traffic.
    final m = ConnectionModel()
      ..applyEvent(StatsEvent(
        bytesUp: BigInt.from(100),
        bytesDown: BigInt.from(200),
        activeFlows: 3,
        flowsFailed: BigInt.zero,
        dnsQueries: BigInt.from(7),
      ))
      ..applyEvent(const StateEvent('Disconnected'));
    expect(m.bytesUp, BigInt.zero);
    expect(m.activeFlows, 0);
  });

  test('isConnected follows the state the helper reports', () {
    final m = ConnectionModel();
    expect(m.isConnected, isFalse);
    m.applyEvent(const StateEvent('Connected'));
    expect(m.isConnected, isTrue);
    m.applyEvent(const StateEvent('Disconnected'));
    expect(m.isConnected, isFalse);
  });
}
