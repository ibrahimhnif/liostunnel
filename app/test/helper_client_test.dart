// The client does socket framing and lifecycle only. Encoding and decoding
// go through the FFI codec, so jsonEncode/jsonDecode appear here to build
// fixtures but never inside the client itself.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/helper_client.dart';
import 'package:liostunnel_app/src/rust/api/protocol.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

/// A stand-in helper: acks whatever it is sent, then pushes anything queued.
class FakeHelper {
  late final ServerSocket _server;
  late final StreamSubscription _sub;
  final List<String> received = [];
  final List<Socket> _accepted = [];
  final List<String> _toPush;
  final String _path;

  FakeHelper(this._path, {List<String> push = const []}) : _toPush = push;

  Future<void> start() async {
    try {
      File(_path).deleteSync();
    } catch (_) {}
    final addr = InternetAddress(_path, type: InternetAddressType.unix);
    _server = await ServerSocket.bind(addr, 0);
    _sub = _server.listen((sock) {
      _accepted.add(sock);
      sock
          .cast<List<int>>()
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((line) {
            received.add(line);
            final msg = jsonDecode(line) as Map<String, dynamic>;
            sock.write('${jsonEncode({"type": "ack", "id": msg["id"]})}\n');
            for (final p in _toPush) {
              sock.write('$p\n');
            }
          });
    });
  }

  Future<void> stop() async {
    // Established connections outlive ServerSocket.close(), so a client would
    // never see the helper go away — this has to tear them down explicitly to
    // model a helper that actually died.
    for (final s in _accepted) {
      s.destroy();
    }
    _accepted.clear();
    // A live ServerSocket listener keeps the isolate alive, so a leaked one
    // hangs the suite instead of failing it.
    await _sub.cancel();
    await _server.close();
    try {
      File(_path).deleteSync();
    } catch (_) {}
  }
}

String sock(String tag) => '${Directory.systemTemp.path}/lios-t-$tag-$pid.sock';

bool get isRoot => Platform.environment['USER'] == 'root';

void main() {
  setUpAll(() async => await RustLib.init());

  test('hello is acked and the handshake completes', () async {
    final path = sock('hello');
    final helper = FakeHelper(path);
    await helper.start();

    final client = HelperClient();
    await client.connect(path);
    await client.hello();

    expect(helper.received.length, 1);
    expect(jsonDecode(helper.received.first)['type'], 'hello');

    await client.close();
    await helper.stop();
  });

  test('pushed stats events reach the event stream', () async {
    final path = sock('stats');
    final stats = jsonEncode({
      "type": "stats",
      "snapshot": {
        "bytes_up": 10,
        "bytes_down": 20,
        "active_flows": 1,
        "flows_failed": 0,
        "dns_queries": 3,
      },
    });
    final helper = FakeHelper(path, push: [stats]);
    await helper.start();

    final client = HelperClient();
    await client.connect(path);
    final first = client.events.first;
    await client.hello();
    final ev = await first.timeout(const Duration(seconds: 5));

    expect(ev, isA<StatsEvent>());
    expect((ev as StatsEvent).bytesUp, BigInt.from(10));
    expect(ev.activeFlows, 1);

    await client.close();
    await helper.stop();
  });

  test('a helper error surfaces by kind, not by message text', () async {
    final path = sock('err');
    try {
      File(path).deleteSync();
    } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((s) {
      s
          .cast<List<int>>()
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((line) {
            final id = jsonDecode(line)['id'];
            s.write(
              '${jsonEncode({"type": "error", "id": id, "kind": "version_mismatch", "message": "helper speaks v1"})}\n',
            );
          });
    });

    final client = HelperClient();
    await client.connect(path);
    await expectLater(
      client.hello(),
      throwsA(
        isA<HelperError>().having(
          (e) => e.kind,
          'kind',
          ErrorKindDto.versionMismatch,
        ),
      ),
    );

    await client.close();
    await sub.cancel();
    await server.close();
    try {
      File(path).deleteSync();
    } catch (_) {}
  });

  test(
    'connecting to a missing socket reports the helper is not installed',
    () async {
      final client = HelperClient();
      await expectLater(
        client.connect('${Directory.systemTemp.path}/definitely-not-here.sock'),
        throwsA(isA<HelperUnavailable>()),
      );
    },
  );

  test(
    'a socket the user cannot open reports unauthorized, not missing',
    () async {
      // Spec §10 lists "socket permission denied" as its own case. It means the
      // helper is installed but this user is not authorized — the opposite
      // advice from "helper not installed", so the two must not collapse.
      final path = sock('noperm');
      try {
        File(path).deleteSync();
      } catch (_) {}
      final addr = InternetAddress(path, type: InternetAddressType.unix);
      final server = await ServerSocket.bind(addr, 0);
      final sub = server.listen((_) {});
      await Process.run('chmod', ['000', path]);

      final client = HelperClient();
      await expectLater(client.connect(path), throwsA(isA<HelperForbidden>()));

      await sub.cancel();
      await server.close();
      try {
        File(path).deleteSync();
      } catch (_) {}
    },
    skip: isRoot ? 'root bypasses file permission bits' : null,
  );

  test('a partial line is buffered until its newline arrives', () async {
    // Framing regression: JSON split across socket reads must not be parsed
    // twice or dropped. This pins that we did not replace LineSplitter with
    // a naive per-chunk decode.
    final path = sock('partial');
    try {
      File(path).deleteSync();
    } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((s) async {
      s.write('{"type":"sta');
      await Future.delayed(const Duration(milliseconds: 50));
      s.write('te","state":"Connected"}\n');
    });

    final client = HelperClient();
    await client.connect(path);
    final ev = await client.events.first.timeout(const Duration(seconds: 5));
    expect(ev, isA<StateEvent>());
    expect((ev as StateEvent).state, 'Connected');

    await client.close();
    await sub.cancel();
    await server.close();
    try {
      File(path).deleteSync();
    } catch (_) {}
  });

  test('a line this build cannot decode is dropped, not fatal', () async {
    // A helper newer than the app may push something unknown. Ignoring it
    // deliberately is right; taking the connection down over it is not.
    final path = sock('unknown');
    try {
      File(path).deleteSync();
    } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((s) async {
      s.write('{"type":"quantum_flux","id":1}\n');
      await Future.delayed(const Duration(milliseconds: 30));
      s.write('{"type":"state","state":"Connected"}\n');
    });

    final client = HelperClient();
    await client.connect(path);
    final ev = await client.events.first.timeout(const Duration(seconds: 5));
    expect(ev, isA<StateEvent>(), reason: 'the good line must still arrive');

    await client.close();
    await sub.cancel();
    await server.close();
    try {
      File(path).deleteSync();
    } catch (_) {}
  });

  test(
    'the helper dying mid-session surfaces as a disconnect, not a hang',
    () async {
      // The UI must not sit on "Connected" forever after the daemon dies.
      final path = sock('death');
      try {
        File(path).deleteSync();
      } catch (_) {}
      final addr = InternetAddress(path, type: InternetAddressType.unix);
      final server = await ServerSocket.bind(addr, 0);
      final sub = server.listen((s) async {
        s.write('{"type":"state","state":"Connected"}\n');
        await Future.delayed(const Duration(milliseconds: 50));
        await s.close();
      });

      final client = HelperClient(retryDelay: const Duration(milliseconds: 20));
      final states = <String>[];
      await client.connect(path);
      client.events.listen((e) {
        if (e is StateEvent) states.add(e.state);
      });
      await Future.delayed(const Duration(milliseconds: 400));

      expect(states, contains('Connected'));
      expect(
        states,
        contains('Disconnected'),
        reason: 'a dropped socket must produce a Disconnected state event',
      );

      await client.close();
      await sub.cancel();
      await server.close();
      try {
        File(path).deleteSync();
      } catch (_) {}
    },
  );

  test('an in-flight request fails when the socket drops', () async {
    // Otherwise the future never completes and the connect button spins
    // forever.
    final path = sock('inflight');
    try {
      File(path).deleteSync();
    } catch (_) {}
    final addr = InternetAddress(path, type: InternetAddressType.unix);
    final server = await ServerSocket.bind(addr, 0);
    final sub = server.listen((s) async {
      await Future.delayed(const Duration(milliseconds: 30));
      await s.close(); // never acks
    });

    final client = HelperClient(retryDelay: const Duration(milliseconds: 20));
    await client.connect(path);
    await expectLater(
      client.hello().timeout(const Duration(seconds: 3)),
      throwsA(isA<HelperUnavailable>()),
    );

    await client.close();
    await sub.cancel();
    await server.close();
    try {
      File(path).deleteSync();
    } catch (_) {}
  });

  test('the client reconnects after the helper comes back', () async {
    // Spec §10 requires a reconnect loop. The helper is the long-lived
    // process; the app must re-attach rather than require a restart.
    final path = sock('reconnect');
    final first = FakeHelper(path);
    await first.start();

    final client = HelperClient(retryDelay: const Duration(milliseconds: 20));
    await client.connect(path);
    await client.hello();
    final reconnected = client.whenReconnected;
    await first.stop();

    await Future.delayed(const Duration(milliseconds: 60));
    final second = FakeHelper(path);
    await second.start();

    await reconnected.timeout(const Duration(seconds: 5));
    expect(second.received.length, greaterThanOrEqualTo(1));
    expect(
      jsonDecode(second.received.first)['type'],
      'hello',
      reason: 'a reconnect must re-handshake',
    );

    await client.close();
    await second.stop();
  });

  test('close stops the reconnect loop', () async {
    // A client the UI has dismissed must not keep dialling in the background
    // for the life of the process.
    final path = sock('closeloop');
    final helper = FakeHelper(path);
    await helper.start();

    final client = HelperClient(retryDelay: const Duration(milliseconds: 20));
    await client.connect(path);
    await client.close();
    await helper.stop();

    await Future.delayed(const Duration(milliseconds: 120));
    expect(client.isRetrying, isFalse);
  });
}
