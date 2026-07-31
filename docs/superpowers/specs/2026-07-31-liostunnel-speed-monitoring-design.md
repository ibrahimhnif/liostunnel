# Live transfer speed — design

**Goal.** Show current upload and download speed on the connection screen, so
"is anything actually moving?" is answerable at a glance rather than by
watching a total tick up.

**Not in scope.** A history graph or sparkline. Session peak and average.
Per-flow attribution — the helper counts active flows but does no per-flow
byte accounting, so that needs new engine counters and a protocol change.

---

## 1. Everything needed already arrives

The helper pushes a `Stats` frame **every second**
(`crates/liostunnel-helper/src/main.rs:16`, `STATS_INTERVAL`), the client
turns it into a `StatsEvent`, and `ConnectionModel` already stores `bytesUp`
and `bytesDown` as `BigInt`.

So this feature is a subtraction. **No protocol change, no helper change, no
FFI change, no new dependency.** It touches `ConnectionModel` and the
connection screen.

## 2. Rate is measured, not assumed

The obvious implementation divides the byte delta by one second, because that
is the tick interval. That is wrong whenever the frame is late — a loaded
machine, a scheduler hiccup, an app that was backgrounded — and a 1.4 s gap
then reads as 40% faster than reality.

The model timestamps each arrival and divides by the elapsed time between
consecutive frames. The number then means *bytes per second as observed*,
which is both honest and what a user wants when they are asking whether the
tunnel is moving.

Elapsed time is taken from an **injected clock**, not `DateTime.now()`
directly. That is what lets a test assert an exact rate rather than sleeping
and hoping — a distinction this codebase has already paid for once, in a test
that passed because a timer expired rather than because anything worked.

## 3. A counter going backwards is a reset

`ConnectionModel._zeroStats()` runs on any state that is not `Connected`, so
a reconnect takes `bytesUp` from 5 000 to 0. Subtracting the previous value
then yields a negative rate, or with unsigned arithmetic an enormous one.

**Backwards means the counters restarted.** The model reports no rate for that
sample and takes the new value as the new baseline. The same rule covers a
helper restart, which is the other way the counters can go back to zero
without the tunnel having stopped.

## 4. Speed dies with the tunnel

`_zeroStats()` exists because of a lesson already recorded in its own comment:
*"Numbers left on screen after a tunnel stops read as live traffic."*

A frozen `1.2 MB/s` is that same lie, louder — a total that stops rising is at
least ambiguous, whereas a speed that stops updating actively asserts traffic
is flowing. Speed is cleared on the same path as the totals, and its baseline
is discarded so the next connection starts fresh rather than measuring against
a stale sample.

## 5. No rate is not zero

The first frame after connecting has no predecessor, so there is no rate to
compute. The screen shows `—`.

`0 B/s` would be a claim about traffic, and we do not have one to make. The
distinction matters for exactly one second per connection, which is precisely
the second a user is watching to see whether it worked.

## 6. What the screen shows

Two rows beside the existing Sent and Received:

```
Sent          1.4 MB        340 KB/s
Received      12.1 MB       1.2 MB/s
```

Formatted by the same helper the totals use, with `/s` appended — one
formatter, so the two cannot disagree about what a megabyte is.

## 7. Testing

The model is pure arithmetic over injected time, so every case is a unit test
with no sleeping:

- two frames one second apart give the byte delta as the rate;
- two frames **1.4 seconds** apart divide by 1.4, not by 1 — the assertion
  that fails against the obvious wrong implementation;
- a counter going backwards yields no rate, and the next sample is measured
  from the new baseline rather than the old one;
- the first frame yields no rate, not zero;
- a non-`Connected` state clears the rate **and** the baseline, so the first
  frame of the next connection yields no rate rather than a rate measured
  against the previous session;
- two frames with identical counters give exactly `0 B/s` — traffic genuinely
  stopped, which is a real answer and distinct from "no rate yet".

A widget test asserts the screen shows `—` before the second frame and a
formatted rate after.

## 8. Exit criteria

| | |
|---|---|
| SPD-1 | Current up and down speed appear on the connection screen while connected |
| SPD-2 | The rate is computed from measured elapsed time, not an assumed one-second tick |
| SPD-3 | A counter that goes backwards produces no rate, not a negative or enormous one |
| SPD-4 | Disconnecting clears both the rate and its baseline |
| SPD-5 | Before the second sample the screen shows `—`, not `0 B/s` |

**SPD-3 is the one to care about.** The others make the number useful; that
one keeps it from becoming nonsense at exactly the moment a user reconnects
to see whether things improved.
