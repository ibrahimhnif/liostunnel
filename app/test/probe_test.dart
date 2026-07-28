// Proves the flutter_rust_bridge pipeline end to end before any real DTO is
// written. Spec §9 names FRB codegen as the least-known surface in this
// slice; the probe deliberately carries the shapes the profile and protocol
// DTOs need, so a limitation surfaces here rather than halfway through.
import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/src/rust/api/probe.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

void main() {
  setUpAll(() async => await RustLib.init());

  test('a DTO with option, vec and tagged enum survives the bridge', () async {
    final got = await echoProbe(
      input: const ProbeDto(
        name: 'x',
        count: 7,
        maybe: 'present',
        items: ['a', 'b'],
        choice: ProbeChoice.second(detail: 'd'),
      ),
    );
    expect(got.name, 'x');
    expect(got.count, 7);
    expect(got.maybe, 'present');
    expect(got.items, ['a', 'b']);
    expect(got.choice, isA<ProbeChoice_Second>());
    expect((got.choice as ProbeChoice_Second).detail, 'd');
  });

  test('a null Option survives as null, and an empty Vec as empty', () async {
    final got = await echoProbe(
      input: const ProbeDto(
        name: 'y',
        count: 0,
        maybe: null,
        items: [],
        choice: ProbeChoice.first(),
      ),
    );
    expect(got.maybe, isNull);
    expect(got.items, isEmpty);
    expect(got.choice, isA<ProbeChoice_First>());
  });

  test('a unit variant does not silently become the payload variant', () async {
    // The two variants have different shapes, and a generator that collapsed
    // them would make every tagged enum in the protocol unreliable — an
    // ErrorKind that arrived as the wrong variant is exactly the kind of
    // thing that reads as success.
    final first = await echoProbe(
      input: const ProbeDto(
        name: 'z', count: 1, items: [], choice: ProbeChoice.first(),
      ),
    );
    expect(first.choice, isNot(isA<ProbeChoice_Second>()));
  });
}
