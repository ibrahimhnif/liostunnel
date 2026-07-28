// Dart never encodes or decodes the wire format itself — it calls these.
// The message types are defined once in Rust and mirrored here by codegen,
// so a new ErrorKind cannot fall into a hand-written default branch and be
// reported as success.
import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/src/rust/api/protocol.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

void main() {
  setUpAll(() async => await RustLib.init());

  test('an encoded request is one newline-free line', () async {
    final line = await encodeRequest(
      req: RequestDto.disconnect(id: BigInt.from(4)),
    );
    expect(line, isNot(contains('\n')));
    expect(line, contains('"type":"disconnect"'));
  });

  test('hello carries a version the UI never supplies', () async {
    // RequestDto.hello has no version argument at all, so the app cannot
    // send the wrong one — the version belongs to the build.
    final line = await encodeRequest(req: RequestDto.hello(id: BigInt.from(1)));
    final v = await protocolVersion();
    expect(line, contains('"protocol_version":$v'));
  });

  test('an ack decodes with its id', () async {
    final m = await decodeMessage(line: '{"type":"ack","id":42}');
    expect(m, isA<IncomingDto_Ack>());
    expect((m as IncomingDto_Ack).id, BigInt.from(42));
  });

  test('an error decodes with a typed kind, not a string', () async {
    // The UI branches on this. A String would let a typo compile.
    final m = await decodeMessage(
      line:
          '{"type":"error","id":9,"kind":"secret_not_permitted","message":"nope"}',
    );
    expect(m, isA<IncomingDto_Error>());
    expect((m as IncomingDto_Error).kind, ErrorKindDto.secretNotPermitted);
  });

  test('a stats event decodes with its counters', () async {
    final m = await decodeMessage(
      line:
          '{"type":"stats","snapshot":{"bytes_up":10,"bytes_down":20,'
          '"active_flows":1,"flows_failed":0,"dns_queries":3}}',
    );
    expect(m, isA<IncomingDto_Stats>());
    final s = m as IncomingDto_Stats;
    expect(s.bytesUp, BigInt.from(10));
    expect(s.activeFlows, 1);
  });

  test('a state event decodes with its state', () async {
    final m = await decodeMessage(line: '{"type":"state","state":"Connected"}');
    expect(m, isA<IncomingDto_State>());
    expect((m as IncomingDto_State).state, 'Connected');
  });

  test('a message this build does not understand throws', () async {
    // A helper newer than the app must be ignored deliberately. If this
    // returned some default, the client would act on a message it never
    // understood — most likely by treating it as success.
    await expectLater(
      decodeMessage(line: '{"type":"quantum_flux","id":1}'),
      throwsA(anything),
    );
  });

  test('a truncated line throws rather than half-decoding', () async {
    await expectLater(decodeMessage(line: '{"type":"sta'), throwsA(anything));
  });

  test('every ErrorKind the helper can send exists on this side', () async {
    // Pins the mirror. If Rust gains a variant and Dart does not, this list
    // stops compiling — which is the entire reason the codec crosses the
    // bridge instead of being hand-written here.
    const all = ErrorKindDto.values;
    expect(all, contains(ErrorKindDto.versionMismatch));
    expect(all, contains(ErrorKindDto.unauthorized));
    expect(all, contains(ErrorKindDto.secretNotPermitted));
    expect(all, contains(ErrorKindDto.alreadyConnected));
    expect(all, contains(ErrorKindDto.notConnected));
    expect(all, contains(ErrorKindDto.authFailed));
    expect(all, contains(ErrorKindDto.badRequest));
    expect(all, contains(ErrorKindDto.internal));
    expect(all.length, 8, reason: 'a new kind needs handling in the UI too');
  });

  test('a connect request carries its params across', () async {
    final line = await encodeRequest(
      req: RequestDto.connect(
        id: BigInt.from(3),
        params: const ConnectParamsDto(
          profileJson: '{}',
          user: 'u',
          routeMode: 'test',
          cidrs: ['10.0.0.0/8'],
          captureDns: true,
          tunAddress: '10.90.0.1',
        ),
      ),
    );
    expect(line, contains('"type":"connect"'));
    expect(line, contains('10.0.0.0/8'));
    expect(line, isNot(contains('\n')));
  });
}
