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
    m.applyEvent(
      StatsEvent(
        bytesUp: BigInt.from(5),
        bytesDown: BigInt.from(9),
        activeFlows: 2,
        flowsFailed: BigInt.one,
        dnsQueries: BigInt.from(4),
      ),
    );
    expect(m.bytesUp, BigInt.from(5));
    expect(m.activeFlows, 2);
    expect(m.dnsQueries, BigInt.from(4));
  });

  test('a helper refusal is surfaced by kind, not message text', () {
    final m = ConnectionModel();
    m.applyError(
      const HelperError(
        ErrorKindDto.versionMismatch,
        'helper speaks v1, client speaks v2',
      ),
    );
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
    expect(
      seen.length,
      ErrorKindDto.values.length,
      reason: 'two kinds collapsed onto one fault',
    );
  });

  test('every fault has wording the user can act on', () {
    for (final f in Fault.values) {
      final m = ConnectionModel()..setFaultForTest(f);
      final text = m.userFacingError!;
      expect(text, isNotEmpty, reason: '$f has no wording');
      expect(text.length, greaterThan(15), reason: '$f says too little: $text');
    }
  });

  test('a Disconnected event does not erase the error that caused it', () {
    // The helper dying mid-connect fails the in-flight request AND emits a
    // synthetic Disconnected. Clearing on every state event meant the second
    // wiped the first, so the user saw the spinner stop and nothing else.
    final m = ConnectionModel()
      ..applyError(const HelperUnavailable())
      ..applyEvent(const StateEvent('Disconnected'));
    expect(m.lastFault, Fault.helperNotInstalled,
        reason: 'the banner must survive the disconnect that produced it');
    expect(m.userFacingError, isNotNull);
  });

  test('a successful action clears the previous fault', () {
    final m = ConnectionModel()..applyError(const HelperUnavailable());
    expect(m.lastFault, isNotNull);
    m.applyEvent(const StateEvent('Connected'));
    expect(
      m.lastFault,
      isNull,
      reason: 'a stale banner outlives the problem it named',
    );
  });

  test('disconnecting zeroes the stats rather than freezing them', () {
    // Numbers left on screen after a tunnel stops read as live traffic.
    final m = ConnectionModel()
      ..applyEvent(
        StatsEvent(
          bytesUp: BigInt.from(100),
          bytesDown: BigInt.from(200),
          activeFlows: 3,
          flowsFailed: BigInt.zero,
          dnsQueries: BigInt.from(7),
        ),
      )
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

  group('live speed', () {
    late FakeClock clock;
    late ConnectionModel m;

    setUp(() {
      clock = FakeClock();
      m = ConnectionModel(clock: clock.call);
      m.applyEvent(const StateEvent('Connected'));
    });

    test('the first sample has no rate, which is not a rate of zero', () {
      m.applyEvent(stats(1000, 2000));
      expect(m.bytesUpPerSec, isNull);
      expect(m.bytesDownPerSec, isNull);
    });

    test('two samples a second apart give the delta as the rate', () {
      m.applyEvent(stats(1000, 2000));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(1500, 4000));
      expect(m.bytesUpPerSec, 500.0);
      expect(m.bytesDownPerSec, 2000.0);
    });

    test('a late frame divides by the time that actually passed', () {
      // The assertion that fails against the obvious wrong implementation.
      // Dividing by the 1s tick interval would report 500 and 2000 here,
      // which is 40% faster than the traffic that occurred.
      m.applyEvent(stats(1000, 2000));
      clock.advance(const Duration(milliseconds: 1400));
      m.applyEvent(stats(1500, 4800));
      expect(m.bytesUpPerSec, closeTo(357.14, 0.01));
      expect(m.bytesDownPerSec, closeTo(2000.0, 0.01));
    });

    test('identical counters are a real zero, not an absent rate', () {
      m.applyEvent(stats(1000, 2000));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(1000, 2000));
      expect(m.bytesUpPerSec, 0.0);
      expect(m.bytesDownPerSec, 0.0);
    });

    test('a counter going backwards yields no rate, and rebaselines', () {
      // SPD-3. `_zeroStats` runs on every non-Connected state and a helper
      // restart zeroes them too, so a total CAN go down without the tunnel
      // having stopped. Subtracting then gives a negative rate -- or, if
      // anyone ever reaches for unsigned arithmetic, an enormous one.
      // A REAL rate first. Feeding the reset while the rate was already null
      // -- which is what this test did at first -- meant the guard's
      // `_upPerSec = null` had no witness: delete it and the suite stayed
      // green while a stale 1.2 MiB/s froze on screen across a helper
      // restart, which is the exact lie the design is written against.
      m.applyEvent(stats(5000, 9000));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(6000, 10000));
      expect(m.bytesUpPerSec, 1000.0);

      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(100, 200));
      expect(m.bytesUpPerSec, isNull, reason: 'a reset is not a negative rate');
      expect(m.bytesDownPerSec, isNull);

      // And the NEXT sample measures from 100/200, not from 5000/9000.
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(400, 700));
      expect(m.bytesUpPerSec, 300.0);
      expect(m.bytesDownPerSec, 500.0);
    });

    test('one counter going backwards does not corrupt the other', () {
      // Reporting a rate for down against a sample the up-reset invalidated
      // would be worse than reporting none: the pair comes from one snapshot.
      m.applyEvent(stats(5000, 9000));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(10, 9500));
      expect(m.bytesUpPerSec, isNull);
      expect(m.bytesDownPerSec, isNull);
    });

    test('down going backwards alone is also a reset', () {
      // The mirror of the test above. Without it, `|| down < prevDown` can be
      // deleted with the suite green, and a down-only reset renders as
      // "-500 B/s" -- `_bytes` prints a negative BigInt raw.
      m.applyEvent(stats(5000, 9000));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(6000, 10000));
      expect(m.bytesDownPerSec, 1000.0);

      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(9500, 10));
      expect(m.bytesDownPerSec, isNull);
      expect(m.bytesUpPerSec, isNull);
    });

    test('frames drained microseconds apart carry no rate', () {
      // The isolate stalls and the helper keeps writing; on resume the frames
      // arrive back to back. A megabyte over 16us is 62 GB/s.
      m.applyEvent(stats(0, 0));
      clock.advance(const Duration(microseconds: 16));
      m.applyEvent(stats(1000000, 1000000));
      expect(m.bytesUpPerSec, isNull);
      expect(m.bytesDownPerSec, isNull);
    });

    test('after a drained burst, the next frame measures the whole stall', () {
      // The baseline is deliberately NOT advanced by a too-close sample, so
      // the rate that follows spans the stall rather than measuring against
      // a drained frame.
      m.applyEvent(stats(0, 0));
      clock.advance(const Duration(microseconds: 16));
      m.applyEvent(stats(500, 500));
      expect(m.bytesUpPerSec, isNull);

      // 2s after the FIRST sample, not 2s after the drained one.
      clock.advance(const Duration(seconds: 2));
      m.applyEvent(stats(4000, 4000));
      // 4000 bytes over 2.000016s -- the stall plus the 16us -- so 1999.98,
      // not exactly 2000. The tolerance is what separates that from 1750.0,
      // which is what rebaselining at the drained sample would have given:
      // (4000-500)/2. Tight enough to fail the defect, loose enough not to
      // fail arithmetic that is right.
      expect(m.bytesUpPerSec, closeTo(2000.0, 1.0),
          reason: 'measured across the stall, from the sample before it');
    });

    test('disconnecting clears the rate and its baseline', () {
      // SPD-4. A frozen "1.2 MB/s" asserts traffic is flowing, which is a
      // louder version of the lie `_zeroStats` already exists to prevent.
      m.applyEvent(stats(1000, 2000));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(1500, 4000));
      expect(m.bytesUpPerSec, 500.0);

      m.applyEvent(const StateEvent('Disconnected'));
      expect(m.bytesUpPerSec, isNull);
      expect(m.bytesDownPerSec, isNull);

      // The baseline went too: the first sample of the next connection has no
      // predecessor, rather than being measured against the old session.
      //
      // The counters must be LARGER than the stale baseline (1500/4000) for
      // this to discriminate. Feeding smaller ones lets the backwards-counter
      // guard return null either way, so the assertion passes whether or not
      // the baseline was cleared -- which is what it did on the first
      // attempt, and only a pre-existing widget test caught the mutation.
      m.applyEvent(const StateEvent('Connected'));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(9000, 9000));
      expect(
        m.bytesUpPerSec,
        isNull,
        reason: 'measuring against the previous session is worse than none',
      );
      expect(m.bytesDownPerSec, isNull);
    });

    test('two samples at the same instant yield no rate', () {
      // Guards the division. Two frames can share a timestamp if the clock is
      // coarse, or if the app was resumed and drained a backlog.
      m.applyEvent(stats(1000, 2000));
      m.applyEvent(stats(9000, 9000));
      expect(m.bytesUpPerSec, isNull);
      expect(m.bytesDownPerSec, isNull);
    });

    test('a rate notifies listeners, so the screen redraws', () {
      // The rate is computed inside applyEvent; one that never notified would
      // be correct and invisible.
      // Asserting the COUNT alone tested nothing new: notifyListeners is
      // unconditional and pre-existing, so deleting the whole rate
      // computation left it green. What matters is that the rate is readable
      // by the time listeners run.
      final seen = <double?>[];
      m.addListener(() => seen.add(m.bytesUpPerSec));
      m.applyEvent(stats(1000, 2000));
      clock.advance(const Duration(seconds: 1));
      m.applyEvent(stats(1500, 4000));
      expect(seen, [null, 500.0]);
    });
  });
}

/// A clock the test drives by hand, so rates are asserted exactly rather than
/// slept for. A wall-clock version would be the shape this project has already
/// been bitten by: green because a timer expired, not because the arithmetic
/// was right.
class FakeClock {
  var now = DateTime(2026, 1, 1);
  DateTime call() => now;
  void advance(Duration d) => now = now.add(d);
}

StatsEvent stats(int up, int down) => StatsEvent(
  bytesUp: BigInt.from(up),
  bytesDown: BigInt.from(down),
  activeFlows: 0,
  flowsFailed: BigInt.zero,
  dnsQueries: BigInt.zero,
);
