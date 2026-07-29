// Exit criterion P1a-1: the app parses profiles through the FFI, never by
// re-implementing the schema in Dart. These tests exercise the real bridge,
// so a codegen or conversion regression shows up here rather than as a user's
// profile mysteriously failing to load.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/src/rust/api/config.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

import 'dto_fields.dart';

const sample = '''
{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Home VPS",
 "protocol":"ssh","host":"198.51.100.7","port":22,
 "auth":{"type":"password","password":{"source":"env","var":"PW"}},
 "dns":["1.1.1.1","1.0.0.1"],
 "split_tunnel":{"type":"all_traffic"},"kill_switch":false}
''';

const keyfile = '''
{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Key VPS",
 "protocol":"ssh","host":"example.test","port":2222,
 "auth":{"type":"private_key",
         "private_key":{"source":"file","path":"/home/u/.ssh/id_ed25519"}},
 "dns":{"mode":"https","servers":["1.1.1.1"],
        "https":{"sni":"cloudflare-dns.com","path":"/dns-query"}},
 "split_tunnel":{"type":"all_traffic"},"kill_switch":true}
''';

void main() {
  setUpAll(() async => await RustLib.init());

  test('a profile parses through the bridge into UI-shaped fields', () async {
    final p = await parseProfile(json: sample);
    expect(p.name, 'Home VPS');
    expect(p.host, '198.51.100.7');
    expect(p.port, 22);
    expect(p.protocol, 'ssh');
    expect(p.dnsServers, ['1.1.1.1', '1.0.0.1']);
    expect(p.dnsMode, 'tcp');
  });

  test(
    'what reaches Dart describes where a secret lives, not what it is',
    () async {
      // A real key on disk, and the profile points at it. Both halves matter.
      //
      // This used to assert `p.toString()` did not contain 'BEGIN'. The
      // generated `ProfileDto` overrides `==` and `hashCode` but not
      // `toString`, so that rendered `Instance of 'ProfileDto'` and could not
      // have failed whatever the fields held — and the profile named a path
      // under /home/u that does not exist on any machine running this, so
      // there was nothing for a leak to leak. `everyFieldOf` reads the fields
      // themselves (`profile_writer_test.dart` already built it for exactly
      // this), and the file gives it something to find: a `describe` that
      // read the key instead of describing it now fails here.
      final key = File(
        '${Directory.systemTemp.createTempSync('lios-dto-key').path}/id_ed25519',
      );
      addTearDown(() => key.parent.deleteSync(recursive: true));
      key.writeAsStringSync(
        '-----BEGIN OPENSSH PRIVATE KEY-----\nc2VjcmV0\n',
      );

      final p = await parseProfile(
        json: keyfile.replaceAll('/home/u/.ssh/id_ed25519', key.path),
      );
      expect(p.authKind, 'private_key');
      expect(p.authSecretSource, 'file:${key.path}');
      // Nothing on this object may be key material — it gets rendered on
      // screen and its `profile_json` reaches the helper over a socket.
      expect(everyFieldOf(p), contains(key.path), reason: 'says where');
      expect(everyFieldOf(p), isNot(contains('BEGIN')),
          reason: 'and never what');
    },
  );

  test('a DoH profile carries its endpoint across', () async {
    final p = await parseProfile(json: keyfile);
    expect(p.dnsMode, 'https');
    expect(p.dohSni, 'cloudflare-dns.com');
    expect(p.dohPath, '/dns-query');
  });

  test('export is the inverse of parse', () async {
    final out = await exportProfile(dto: await parseProfile(json: sample));
    final again = await parseProfile(json: out);
    final first = await parseProfile(json: sample);
    expect(again.id, first.id);
    expect(again.host, first.host);
    expect(again.dnsServers, first.dnsServers);
    expect(again.authSecretSource, first.authSecretSource);
  });

  test('a summary reads as one line for the profiles list', () async {
    final s = await profileSummary(dto: await parseProfile(json: sample));
    expect(s, contains('Home VPS'));
    expect(s, contains('198.51.100.7'));
    expect(s, isNot(contains('\n')));
  });

  test(
    'an invalid profile throws rather than returning something empty',
    () async {
      // A silently-empty profile would show up in the list as a nameless entry
      // that fails only at connect time.
      await expectLater(
        parseProfile(json: '{"protocol":"nonsense"}'),
        throwsA(anything),
      );
    },
  );
}
