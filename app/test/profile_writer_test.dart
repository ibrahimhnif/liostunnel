// The permission rules here are the point. The helper refuses any secret file
// the calling user does not own or that anyone else can read, so a carelessly
// written one produces a refusal the user cannot diagnose from the UI.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/profile_writer.dart';
import 'package:liostunnel_app/src/rust/api/config.dart';
import 'package:liostunnel_app/src/rust/dto/profile.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

ProfileDto dto({
  String name = 'Home VPS',
  String source = 'file:/tmp/key',
}) =>
    ProfileDto(
      id: 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
      name: name,
      protocol: 'ssh',
      host: '198.51.100.7',
      port: 22,
      authKind: 'password',
      authSecretSource: source,
      dnsMode: 'tcp',
      dnsServers: const ['1.1.1.1'],
      splitTunnel: 'all_traffic',
      splitTunnelApps: const [],
      killSwitch: false,
    );

void main() {
  setUpAll(() async => await RustLib.init());

  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('lios-writer'));
  tearDown(() => dir.deleteSync(recursive: true));

  test('a written profile is one the FFI can read back', () async {
    // The document goes out through export_profile and comes back through
    // parse_profile, so a profile the editor saves is one the helper parses.
    final file = await ProfileWriter(directory: dir.path).writeProfile(dto());
    final back = await parseProfile(json: file.readAsStringSync());
    expect(back.name, 'Home VPS');
    expect(back.host, '198.51.100.7');
    expect(back.authSecretSource, 'file:/tmp/key');
  });

  test('a typed password lands in a 0600 file, never in the profile',
      () async {
    final w = ProfileWriter(directory: dir.path);
    final ref = await w.writeSecret('Home VPS', 'hunter2');

    expect(ref, startsWith('file:'));
    final path = ref.substring(5);
    expect(File(path).readAsStringSync(), 'hunter2');

    final mode = (await Process.run('stat', ['-f', '%Lp', path])).stdout
        .toString()
        .trim();
    expect(mode, '600', reason: 'the helper refuses anything looser');

    // And the profile that references it carries the path, not the password.
    final file = await w.writeProfile(dto(source: ref));
    final text = file.readAsStringSync();
    expect(text, contains(path));
    expect(text, isNot(contains('hunter2')));
  });

  test('the secrets directory is not world-readable', () async {
    // 0600 on the file is not enough on its own: a listable parent tells
    // anyone which hosts you have credentials for.
    final w = ProfileWriter(directory: dir.path);
    await w.writeSecret('Home VPS', 'hunter2');
    final mode = (await Process.run('stat', ['-f', '%Lp', w.secretsDirectory]))
        .stdout
        .toString()
        .trim();
    expect(mode, '700');
  });

  test('a name cannot escape the profiles directory', () async {
    // A profile called ../../etc/cron.d/x would otherwise be written wherever
    // the name pointed.
    final file = await ProfileWriter(directory: dir.path)
        .writeProfile(dto(name: '../../etc/cron.d/evil'));
    expect(file.parent.path, dir.path);
    expect(file.path, isNot(contains('..')));
  });

  test('a name with nothing usable in it still produces a file', () async {
    final file =
        await ProfileWriter(directory: dir.path).writeProfile(dto(name: '///'));
    expect(file.path, endsWith('profile.json'));
  });

  test('check_profile rejects what the helper would reject', () async {
    // Validated by the same Rust that reads it back, so the editor cannot
    // save something the helper then refuses to parse.
    await expectLater(checkProfile(dto: dto()), completes);

    final noDns = ProfileDto(
      id: 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
      name: 'x',
      protocol: 'ssh',
      host: 'h',
      port: 22,
      authKind: 'password',
      authSecretSource: 'file:/tmp/k',
      dnsMode: 'tcp',
      dnsServers: const [],
      splitTunnel: 'all_traffic',
      splitTunnelApps: const [],
      killSwitch: false,
    );
    await expectLater(checkProfile(dto: noDns), throwsA(anything));
  });

  test('a fresh id is a distinct UUID each time', () async {
    final a = await newProfileId();
    final b = await newProfileId();
    expect(a, isNot(b));
    expect(a.length, 36);
  });
}
