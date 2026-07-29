// The permission rules here are the point. The helper refuses any secret file
// the calling user does not own or that anyone else can read, so a carelessly
// written one produces a refusal the user cannot diagnose from the UI.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/screens/profile_editor.dart';
import 'package:liostunnel_app/services/profile_store.dart';
import 'package:liostunnel_app/services/profile_writer.dart';
// The editor's `offeredCiphers` and the core's are two different lists with
// the same name, on purpose: one test's whole job is to prove they agree.
import 'package:liostunnel_app/src/rust/api/config.dart' hide offeredCiphers;
import 'package:liostunnel_app/src/rust/api/config.dart' as rust
    show offeredCiphers;
import 'package:liostunnel_app/src/rust/dto/profile.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

Future<List<String>> offeredCiphersRust() => rust.offeredCiphers();

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

  usernameTests();
  editTests();
  dohTests();
  criticalTests();

  test('a fresh id is a distinct UUID each time', () async {
    final a = await newProfileId();
    final b = await newProfileId();
    expect(a, isNot(b));
    expect(a.length, 36);
  });
}

// The SSH username is a connect-time parameter with nowhere to live in
// ServerProfile, so it is kept beside the profile. Losing it means falling
// back to the local account name, which for a host like
// `user-provider.com@server` fails as "credentials rejected" while the
// password is perfectly good — a message that sends you after the wrong fix.
void usernameTests() {
  test('the ssh username survives a write and a reload', () async {
    final dir = Directory.systemTemp.createTempSync('lios-user');
    final w = ProfileWriter(directory: dir.path);
    await w.writeProfile(dto(), sshUser: 'hanif-provider.com');

    final loaded = await ProfileStore(directory: dir.path).load();
    expect(loaded.single.sshUser, 'hanif-provider.com');
    dir.deleteSync(recursive: true);
  });

  test('a profile saved without one reports null, not an empty string',
      () async {
    // Null means "fall back"; an empty string would be sent to the server as
    // a username and rejected.
    final dir = Directory.systemTemp.createTempSync('lios-nouser');
    final w = ProfileWriter(directory: dir.path);
    await w.writeProfile(dto(), sshUser: '   ');

    final loaded = await ProfileStore(directory: dir.path).load();
    expect(loaded.single.sshUser, isNull);
    dir.deleteSync(recursive: true);
  });

  test('the sidecar is not mistaken for a profile', () async {
    // It sits next to the .json; the store must not try to parse it.
    final dir = Directory.systemTemp.createTempSync('lios-sidecar');
    await ProfileWriter(directory: dir.path)
        .writeProfile(dto(), sshUser: 'someone');
    final loaded = await ProfileStore(directory: dir.path).load();
    expect(loaded.length, 1);
    expect(loaded.single.ok, isTrue);
    dir.deleteSync(recursive: true);
  });
}

// Editing renames the file, because the filename comes from the profile name.
// Both halves of that matter: the old file has to go, or the list shows one
// profile twice; and the new name must not land on a different profile, which
// would destroy it without a word.
void editTests() {
  test('an edit keeps the id', () async {
    // A new id would make it a different server to anything keyed on id.
    final dir = Directory.systemTemp.createTempSync('lios-edit-id');
    final w = ProfileWriter(directory: dir.path);
    final first = await w.writeProfile(dto());
    final original = await parseProfile(json: first.readAsStringSync());

    final edited = await w.writeProfile(
      ProfileDto(
        id: original.id,
        name: original.name,
        protocol: 'ssh',
        host: '203.0.113.9',
        port: 2222,
        authKind: original.authKind,
        authSecretSource: original.authSecretSource,
        dnsMode: original.dnsMode,
        dnsServers: original.dnsServers,
        splitTunnel: original.splitTunnel,
        splitTunnelApps: original.splitTunnelApps,
        killSwitch: original.killSwitch,
      ),
      replacingPath: first.path,
    );
    final back = await parseProfile(json: edited.readAsStringSync());
    expect(back.id, original.id);
    expect(back.host, '203.0.113.9');
    dir.deleteSync(recursive: true);
  });

  test('renaming moves the file and leaves no duplicate behind', () async {
    final dir = Directory.systemTemp.createTempSync('lios-rename');
    final w = ProfileWriter(directory: dir.path);
    final first = await w.writeProfile(dto(name: 'Old name'), sshUser: 'u');
    expect(File('${first.path}.user').existsSync(), isTrue);

    final renamed = await w.writeProfile(
      dto(name: 'New name'),
      sshUser: 'u',
      replacingPath: first.path,
    );

    expect(renamed.path, isNot(first.path));
    expect(File(first.path).existsSync(), isFalse, reason: 'the old profile');
    expect(File('${first.path}.user').existsSync(), isFalse,
        reason: 'and its sidecar');
    expect((await ProfileStore(directory: dir.path).load()).length, 1);
    dir.deleteSync(recursive: true);
  });

  test('renaming onto a different profile is refused, not silent', () async {
    final dir = Directory.systemTemp.createTempSync('lios-collide');
    final w = ProfileWriter(directory: dir.path);
    final a = await w.writeProfile(dto(name: 'Server A'));
    await w.writeProfile(dto(name: 'Server B'));

    // Renaming A to B would otherwise overwrite B and destroy it.
    await expectLater(
      w.writeProfile(dto(name: 'Server B'), replacingPath: a.path),
      throwsA(isA<StateError>()),
    );
    expect((await ProfileStore(directory: dir.path).load()).length, 2);
    dir.deleteSync(recursive: true);
  });

  test('saving over itself under the same name is allowed', () async {
    final dir = Directory.systemTemp.createTempSync('lios-same');
    final w = ProfileWriter(directory: dir.path);
    final f = await w.writeProfile(dto(name: 'Same'));
    await expectLater(
      w.writeProfile(dto(name: 'Same'), replacingPath: f.path),
      completes,
    );
    dir.deleteSync(recursive: true);
  });

  test('clearing the username removes the sidecar', () async {
    // Left behind, it would keep sending a username the user just deleted.
    final dir = Directory.systemTemp.createTempSync('lios-clear');
    final w = ProfileWriter(directory: dir.path);
    final f = await w.writeProfile(dto(), sshUser: 'someone');
    expect(File('${f.path}.user').existsSync(), isTrue);

    await w.writeProfile(dto(), sshUser: '', replacingPath: f.path);
    expect(File('${f.path}.user').existsSync(), isFalse);
    expect((await ProfileStore(directory: dir.path).load()).single.sshUser,
        isNull);
    dir.deleteSync(recursive: true);
  });

  test('delete removes the profile and its sidecar, not the secret',
      () async {
    // Deleting a profile is not consent to destroy a credential: the key may
    // be one the user relies on elsewhere.
    final dir = Directory.systemTemp.createTempSync('lios-del');
    final w = ProfileWriter(directory: dir.path);
    final secret = await w.writeSecret('Home VPS', 'hunter2');
    final f = await w.writeProfile(dto(source: secret), sshUser: 'u');

    await w.delete(f.path);
    expect(File(f.path).existsSync(), isFalse);
    expect(File('${f.path}.user').existsSync(), isFalse);
    expect(File(secret.substring(5)).existsSync(), isTrue,
        reason: 'the credential is left where it is');
    dir.deleteSync(recursive: true);
  });
}

// Selecting DNS-over-HTTPS without an endpoint used to save happily and fail
// at connect time — in a different process, minutes later, about a field the
// form never asked for.
void dohTests() {
  ProfileDto doh({String? sni, String? path}) => ProfileDto(
        id: 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
        name: 'DoH',
        protocol: 'ssh',
        host: 'h.example',
        port: 22,
        authKind: 'password',
        authSecretSource: 'file:/tmp/k',
        dnsMode: 'https',
        dnsServers: const ['1.1.1.1'],
        dohSni: sni,
        dohPath: path,
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      );

  test('DoH without an endpoint is refused at save time', () async {
    await expectLater(checkProfile(dto: doh()), throwsA(anything));
  });

  test('a DoH path that is not a path is refused', () async {
    await expectLater(
      checkProfile(dto: doh(sni: 'cloudflare-dns.com', path: 'dns-query')),
      throwsA(anything),
    );
  });

  test('a complete DoH profile round-trips with its endpoint', () async {
    final dto = doh(sni: 'cloudflare-dns.com', path: '/dns-query');
    await expectLater(checkProfile(dto: dto), completes);

    final dir = Directory.systemTemp.createTempSync('lios-doh');
    final file = await ProfileWriter(directory: dir.path).writeProfile(dto);
    final back = await parseProfile(json: file.readAsStringSync());
    expect(back.dnsMode, 'https');
    expect(back.dohSni, 'cloudflare-dns.com');
    expect(back.dohPath, '/dns-query');
    dir.deleteSync(recursive: true);
  });
}

// Three defects an independent review found, each of which destroyed user
// data on a path the user believed had failed safely.
void criticalTests() {
  /// A profile using every field the editor does not offer.
  ProfileDto rich() => const ProfileDto(
        id: 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
        name: 'Rich',
        protocol: 'wireguard',
        host: 'h.example',
        port: 51820,
        authKind: 'preshared_key',
        authSecretSource: 'file:/tmp/k',
        peerPublicKey: 'AAAA',
        dnsMode: 'tcp',
        dnsServers: ['1.1.1.1'],
        splitTunnel: 'exclude_apps',
        splitTunnelApps: ['Mail', 'Music'],
        killSwitch: true,
      );

  test('a field the editor does not offer survives a round trip', () async {
    // The editor rebuilt the DTO from scratch, hardcoding protocol to ssh,
    // kill_switch to false and split_tunnel to all_traffic, and dropping the
    // passphrase and peer key entirely. Correcting a typo in the host
    // silently rewrote a wireguard profile to ssh with its app list gone.
    final dir = Directory.systemTemp.createTempSync('lios-rich');
    final file = await ProfileWriter(directory: dir.path).writeProfile(rich());
    final back = await parseProfile(json: file.readAsStringSync());

    expect(back.protocol, 'wireguard');
    expect(back.authKind, 'preshared_key');
    expect(back.peerPublicKey, 'AAAA');
    expect(back.splitTunnel, 'exclude_apps');
    expect(back.splitTunnelApps, ['Mail', 'Music']);
    expect(back.killSwitch, isTrue);
    dir.deleteSync(recursive: true);
  });

  test('a name collision is refused before any secret is written', () async {
    // writeSecret used to run first, so a collision overwrote another
    // profile's password and THEN reported failure — the user saw an error,
    // assumed nothing had happened, and the first profile now authenticated
    // with the second's password.
    final dir = Directory.systemTemp.createTempSync('lios-order');
    final w = ProfileWriter(directory: dir.path);
    await w.writeProfile(dto(name: 'Server A'));

    expect(
      () => w.checkNameFree('server a'),
      throwsA(isA<StateError>()),
      reason: 'names slug to the same file, so this must be refused',
    );
    // And nothing was written on the way to finding that out.
    expect(Directory(w.secretsDirectory).existsSync(), isFalse);
    dir.deleteSync(recursive: true);
  });

  test('two profiles with colliding names get separate secret files',
      () async {
    // The secret filename came from the profile NAME, which is many-to-one:
    // "Home VPS", "home vps" and "HOME-VPS" all collapsed to one file, and
    // the second profile silently overwrote the first's credential.
    final dir = Directory.systemTemp.createTempSync('lios-two');
    final w = ProfileWriter(directory: dir.path);
    final a = await w.writeSecret('11111111-1111-1111-1111-111111111111', 'first');
    final b = await w.writeSecret('22222222-2222-2222-2222-222222222222', 'second');

    expect(a, isNot(b),
        reason: 'distinct profiles must not share a secret file');
    expect(File(a.substring(5)).readAsStringSync(), 'first',
        reason: 'the first credential must survive the second being written');
    expect(File(b.substring(5)).readAsStringSync(), 'second');
    dir.deleteSync(recursive: true);
  });

  test('saving an edit may replace its own secret', () async {
    // The flip side: an id is stable across edits, so re-saving must be able
    // to overwrite the file it owns.
    final dir = Directory.systemTemp.createTempSync('lios-own');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    await w.writeSecret(id, 'old');
    final again = await w.writeSecret(id, 'new');
    expect(File(again.substring(5)).readAsStringSync(), 'new');
    dir.deleteSync(recursive: true);
  });

  test('an ss:// link imports without putting the password in the profile',
      () async {
    final creds =
        base64Url.encode(utf8.encode('aes-256-gcm:hunter2')).replaceAll('=', '');
    const link = 'ss://CREDS@198.51.100.7:8388#Home';
    final uri = link.replaceFirst('CREDS', creds);

    final imported = await importSsUri(uri: uri);
    expect(imported.protocol, 'shadowsocks');
    expect(imported.authKind, 'shadowsocks');
    expect(imported.cipher, 'aes-256-gcm');
    expect(imported.name, 'Home');
    expect(imported.host, '198.51.100.7');
    expect(imported.port, 8388);
    // The DTO is rendered on screen and crosses the FFI. The credential must
    // not be in it -- not in a field, not in its toString.
    expect(imported.authSecretSource, isEmpty,
        reason: 'no file holds this password yet; the caller writes it');
    expect('$imported', isNot(contains('hunter2')));

    final dir = Directory.systemTemp.createTempSync('lios-ss');
    final w = ProfileWriter(directory: dir.path);
    final pw = await ssUriPassword(uri: uri);
    expect(pw, 'hunter2');
    final ref = await w.writeSecret(imported.id, pw);
    final file = await w.writeProfile(
      ProfileDto(
        id: imported.id,
        name: imported.name,
        protocol: imported.protocol,
        host: imported.host,
        port: imported.port,
        authKind: imported.authKind,
        authSecretSource: ref,
        cipher: imported.cipher,
        dnsMode: imported.dnsMode,
        dnsServers: imported.dnsServers,
        splitTunnel: imported.splitTunnel,
        splitTunnelApps: imported.splitTunnelApps,
        killSwitch: imported.killSwitch,
      ),
    );
    final text = file.readAsStringSync();
    expect(text, isNot(contains('hunter2')),
        reason: 'the profile holds the path, never the password');
    expect(text, contains('aes-256-gcm'));
    dir.deleteSync(recursive: true);
  });

  test('a malformed ss:// link is refused without echoing it', () async {
    // The link IS the credential, so the message may not quote any of it.
    final blob =
        base64Url.encode(utf8.encode('no-colon-hunter2')).replaceAll('=', '');
    await expectLater(
      importSsUri(uri: 'ss://$blob'),
      throwsA(predicate((e) =>
          !'$e'.contains('hunter2') && !'$e'.contains(blob))),
    );
  });

  test('the editor offers exactly the ciphers the core accepts', () async {
    // Compared against the core's own list, not a second copy of it. This is
    // the assertion that failed to fail on the first attempt: checkProfile
    // did not validate the cipher at all, so a dropdown entry the core could
    // never construct sailed through.
    expect(offeredCiphers, await offeredCiphersRust(),
        reason: 'the dropdown and the core must offer the same ciphers');
    for (final c in offeredCiphers) {
      final creds =
          base64Url.encode(utf8.encode('$c:pw')).replaceAll('=', '');
      final d = await importSsUri(uri: 'ss://$creds@198.51.100.7:8388');
      expect(d.cipher, c);
      await checkProfile(
        dto: ProfileDto(
          id: d.id,
          name: 'x',
          protocol: d.protocol,
          host: d.host,
          port: d.port,
          authKind: d.authKind,
          authSecretSource: 'file:/tmp/k',
          cipher: d.cipher,
          dnsMode: d.dnsMode,
          dnsServers: d.dnsServers,
          splitTunnel: d.splitTunnel,
          splitTunnelApps: d.splitTunnelApps,
          killSwitch: d.killSwitch,
        ),
      );
    }
  });
}
