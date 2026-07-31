# Live Transfer Speed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show current upload and download speed on the connection screen.

**Architecture:** The helper already pushes a stats snapshot every second and the app already stores the byte totals, so this is a subtraction over measured elapsed time. `ConnectionModel` gains the rate; the screen renders it. No protocol, helper, FFI or dependency change.

**Tech Stack:** Flutter, Dart.

## Global Constraints

- **Divide by measured elapsed time, never by an assumed one second.** A late frame otherwise reads as faster traffic than actually occurred.
- **Time comes from an injected clock**, so tests assert exact rates instead of sleeping. A test that passes because a timer expired rather than because anything worked has already shipped in this repo once.
- **A counter going backwards is a reset, not a negative rate.** `_zeroStats()` runs on every non-`Connected` state, so a reconnect takes the totals to zero.
- **No rate is not zero rate.** `0 B/s` is a claim about traffic; before the second sample there is none to make.
- **TDD, strictly.** Failing test first, run it, confirm it fails for the *expected* reason, then implement.
- **A test that passes must be shown failing against the defect it names.** Across the last three branches, plan-specified A/Bs failed to discriminate more often than they succeeded — one read a stub's argv instead of a file, one passed against an empty directory, one failed a *correct* artifact. **Before trusting an assertion, ask what it reads.** If an A/B does not reproduce, report it; that has been the most valuable output of every task.
- `flutter analyze` must pass; `./testing/build-ffi-for-tests.sh` before `flutter test`.
- **Commit messages go through a file with `git commit -F`** — backticks inside `-m` are command substitution and have run a destructive command in this repo once.
- Do not write to the operator's real `~/.liostunnel`; tests use `Directory.systemTemp`.

## File structure

| File | Responsibility |
|---|---|
| `app/lib/services/connection_model.dart` | the rate, its baseline, and the reset rules |
| `app/lib/screens/connection.dart` | two rows, and `—` before the first rate |
| `app/test/connection_model_test.dart` | the arithmetic, against an injected clock |
| `app/test/widget_test.dart` | what the screen shows before and after |

**One task.** The model and the screen are a single deliverable: a rate nothing renders is not shippable, and a screen with no rate to render has nothing to test.

---

### Task 1: Live speed

**Files:**
- Modify: `app/lib/services/connection_model.dart`, `app/lib/screens/connection.dart`
- Test: `app/test/connection_model_test.dart`, `app/test/widget_test.dart`

**Interfaces:**
- Produces: `ConnectionModel({DateTime Function()? clock})`, `double? get bytesUpPerSec`, `double? get bytesDownPerSec` (null = no rate yet).

- [ ] **Step 1: Write the failing model tests**

Create `app/test/connection_model_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/connection_model.dart';
import 'package:liostunnel_app/services/helper_client.dart';

/// A clock the test drives by hand, so rates are asserted exactly rather than
/// slept for. A wall-clock version of these tests would be the shape this
/// project has already been bitten by: green because a timer expired, not
/// because the arithmetic was right.
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

void main() {
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
    // Dividing by the 1s tick interval would report 500 and 2000 here, which
    // is 40% faster than the traffic that occurred.
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
    // having stopped. Subtracting then gives a negative rate — or, if anyone
    // ever reaches for unsigned arithmetic, an enormous one.
    m.applyEvent(stats(5000, 9000));
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
    m.applyEvent(const StateEvent('Connected'));
    clock.advance(const Duration(seconds: 1));
    m.applyEvent(stats(50, 50));
    expect(m.bytesUpPerSec, isNull,
        reason: 'measuring against the previous session is worse than no rate');
  });

  test('two samples at the same instant yield no rate', () {
    // Guards the division. Two frames can share a timestamp if the clock is
    // coarse or the app was resumed and drained a backlog.
    m.applyEvent(stats(1000, 2000));
    m.applyEvent(stats(9000, 9000));
    expect(m.bytesUpPerSec, isNull);
    expect(m.bytesDownPerSec, isNull);
  });
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd app && flutter test test/connection_model_test.dart`
Expected: FAIL — `No named parameter with the name 'clock'`, and `bytesUpPerSec` undefined.

- [ ] **Step 3: Implement the model**

In `app/lib/services/connection_model.dart`, add a constructor and fields:

```dart
  /// [clock] is injected so tests assert exact rates instead of sleeping.
  ConnectionModel({DateTime Function()? clock})
      : _clock = clock ?? DateTime.now;

  final DateTime Function() _clock;

  /// The previous sample, for the delta. Null means no rate can be computed
  /// yet — the first frame of a connection, or the one after a reset.
  DateTime? _lastSampleAt;
  BigInt? _lastUp;
  BigInt? _lastDown;

  double? _upPerSec;
  double? _downPerSec;

  /// Current speed, or null when there is no rate to report.
  ///
  /// Null is deliberately not 0.0: zero is a claim that no traffic moved, and
  /// before the second sample there is no such claim to make. The distinction
  /// lasts one second per connection — which is exactly the second someone is
  /// watching to see whether connecting worked.
  double? get bytesUpPerSec => _upPerSec;
  double? get bytesDownPerSec => _downPerSec;
```

In the `StatsEvent` arm of `applyEvent`, **before** assigning `_bytesUp`:

```dart
        _recomputeRates(bytesUp, bytesDown);
```

and add:

```dart
  /// Rate from the measured gap between samples.
  ///
  /// Not from `STATS_INTERVAL`: the helper ticks every second, but a frame
  /// arrives late on a loaded machine, and dividing a 1.4s gap by 1s reports
  /// traffic 40% faster than occurred.
  void _recomputeRates(BigInt up, BigInt down) {
    final now = _clock();
    final prevAt = _lastSampleAt;
    final prevUp = _lastUp;
    final prevDown = _lastDown;
    _lastSampleAt = now;
    _lastUp = up;
    _lastDown = down;

    if (prevAt == null || prevUp == null || prevDown == null) {
      _upPerSec = null;
      _downPerSec = null;
      return;
    }
    // A total that went down means the counters restarted -- a reconnect
    // (`_zeroStats`) or a helper restart. Subtracting would give a negative
    // rate, and unsigned arithmetic an enormous one. Report nothing and let
    // the sample just stored become the new baseline.
    if (up < prevUp || down < prevDown) {
      _upPerSec = null;
      _downPerSec = null;
      return;
    }
    final secs = now.difference(prevAt).inMicroseconds / 1e6;
    if (secs <= 0) {
      _upPerSec = null;
      _downPerSec = null;
      return;
    }
    _upPerSec = (up - prevUp).toDouble() / secs;
    _downPerSec = (down - prevDown).toDouble() / secs;
  }
```

And in `_zeroStats()`, add the rate **and its baseline**:

```dart
    _upPerSec = null;
    _downPerSec = null;
    // The baseline too. Keeping it would measure the next connection's first
    // sample against the previous session's totals.
    _lastSampleAt = null;
    _lastUp = null;
    _lastDown = null;
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd app && flutter test test/connection_model_test.dart`
Expected: 7 pass.

- [ ] **Step 5: Write the failing widget test**

Add to `app/test/widget_test.dart`:

```dart
  testWidgets('speed shows a dash until there is a rate to show',
      (tester) async {
    final model = ConnectionModel();
    await tester.pumpWidget(
      ChangeNotifierProvider<ConnectionModel>.value(
        value: model,
        child: MaterialApp(
          home: ConnectionScreen(
            selected: null,
            onConnect: () {},
            onDisconnect: () {},
          ),
        ),
      ),
    );
    model.applyEvent(const StateEvent('Connected'));
    model.applyEvent(StatsEvent(
      bytesUp: BigInt.from(1000),
      bytesDown: BigInt.from(2000),
      activeFlows: 0,
      flowsFailed: BigInt.zero,
      dnsQueries: BigInt.zero,
    ));
    await tester.pumpAndSettle();
    // One sample is not a rate. `0 B/s` here would claim no traffic moved.
    expect(find.text('—'), findsNWidgets(2));
  });
```

Both constructors above are verified against the source, not guessed:
`StatsEvent` takes those five required named parameters, and
`ConnectionScreen` takes `selected` / `onConnect` / `onDisconnect` plus two
optional install-panel parameters this test does not need.

- [ ] **Step 6: Run to verify it fails**

Run: `cd app && flutter test test/widget_test.dart`
Expected: FAIL — `Expected: exactly 2 matching candidates, Actual: 0`.

- [ ] **Step 7: Render it**

In `app/lib/screens/connection.dart`, replace the two stat rows:

```dart
            _StatRow(
              label: 'Sent',
              value: '${_bytes(m.bytesUp)}   ${_rate(m.bytesUpPerSec)}',
            ),
            _StatRow(
              label: 'Received',
              value: '${_bytes(m.bytesDown)}   ${_rate(m.bytesDownPerSec)}',
            ),
```

and add beside `_bytes`:

```dart
/// A rate, or an em dash when there is none.
///
/// Built on `_bytes` rather than a second formatter, so the total and the
/// rate cannot disagree about what a mebibyte is.
String _rate(double? perSec) {
  if (perSec == null) return '—';
  return '${_bytes(BigInt.from(perSec.round()))}/s';
}
```

- [ ] **Step 8: Run everything**

```bash
./testing/build-ffi-for-tests.sh
cd app && flutter analyze && flutter test
```
Expected: analyze clean, all pass.

- [ ] **Step 9: A/B each assertion**

| Change | Test that must fail |
|---|---|
| divide by a hardcoded `1.0` instead of `secs` | `a late frame divides by the time that actually passed` |
| drop the `up < prevUp` guard | `a counter going backwards yields no rate` |
| keep the baseline in `_zeroStats` (clear only the rates) | `disconnecting clears the rate and its baseline` |
| return `0.0` instead of `null` when there is no previous sample | `the first sample has no rate` and the widget test |
| drop the `secs <= 0` guard | `two samples at the same instant yield no rate` |

- [ ] **Step 10: Commit**

```bash
git add app/lib app/test
git commit -F /tmp/msg-spd.txt
```

`/tmp/msg-spd.txt`:

```
feat: show live transfer speed

The helper already pushes a stats snapshot every second and the model already
stores the totals, so this is a subtraction -- no protocol, helper or FFI
change.

Divided by measured elapsed time rather than by the tick interval. A frame
arrives late on a loaded machine, and dividing a 1.4s gap by 1s reports
traffic 40% faster than occurred. The clock is injected so the tests assert
exact rates instead of sleeping.

A total that goes down is a reset, not a negative rate: _zeroStats runs on
every non-Connected state, and a helper restart zeroes the counters without
the tunnel having stopped. That sample reports nothing and becomes the new
baseline.

Speed clears with the totals, and so does its baseline. _zeroStats exists
because "numbers left on screen after a tunnel stops read as live traffic" --
a frozen 1.2 MB/s is that same lie, louder, and a stale baseline would make
the next connection's first sample a measurement against the last one.

Before the second sample the screen shows an em dash. 0 B/s is a claim that
no traffic moved, and there is no such claim to make yet.
```

---

## Exit criteria

| Criterion | Verified by |
|---|---|
| SPD-1 — speed appears while connected | Step 5's widget test, plus Step 1's rate assertions |
| SPD-2 — computed from measured elapsed time | `a late frame divides by the time that actually passed` |
| SPD-3 — a backwards counter yields no rate | `a counter going backwards yields no rate, and rebaselines` |
| SPD-4 — disconnect clears rate and baseline | `disconnecting clears the rate and its baseline` |
| SPD-5 — `—` before the second sample | `the first sample has no rate` and the widget test |

**SPD-3 is the one to care about.** The others make the number useful; that
one keeps it from becoming nonsense at exactly the moment someone reconnects
to see whether things improved.
