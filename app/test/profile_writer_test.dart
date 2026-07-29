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

// Moved out of this file so `profile_test.dart` can use it too: the
// assertion it replaces there was the same inert `toString()` pattern.
import 'dto_fields.dart';

Future<List<String>> offeredCiphersRust() => rust.offeredCiphers();

// `id` is a parameter because `writeSecret` keys the secret file on the
// profile id: a test that writes a secret under one id and then saves a
// profile carrying a *different* one is not describing anything the app can
// produce, and an assertion about "the copy's id" made against it would hold
// no matter what `duplicate` did.
ProfileDto dto({
  String name = 'Home VPS',
  String source = 'file:/tmp/key',
  String id = 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
}) =>
    ProfileDto(
      id: id,
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

/// A profile using every field the editor does not offer.
///
/// At file scope rather than inside `criticalTests`, because `duplicate`
/// rebuilds a DTO field by field exactly the way the editor used to and needs
/// the same fixture to prove it carries everything.
ProfileDto rich({
  String source = 'file:/tmp/k',
  String id = 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
}) =>
    ProfileDto(
      id: id,
      name: 'Rich',
      protocol: 'wireguard',
      host: 'h.example',
      port: 51820,
      authKind: 'preshared_key',
      authSecretSource: source,
      peerPublicKey: 'AAAA',
      dnsMode: 'tcp',
      dnsServers: const ['1.1.1.1'],
      splitTunnel: 'exclude_apps',
      splitTunnelApps: const ['Mail', 'Music'],
      killSwitch: true,
    );

/// The three fields [rich] structurally cannot hold.
///
/// `cipher` belongs to shadowsocks credentials and the DoH endpoint to
/// `dnsMode: https`; `ServerProfile` has nowhere to put either on a wireguard
/// profile, so `parse_profile` hands back `null` for them however the DTO was
/// built. A wireguard fixture therefore cannot witness them being carried —
/// the assertion would read `null == null` no matter what `duplicate` did.
ProfileDto richShadowsocks({
  String source = 'file:/tmp/k',
  String id = 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e3a',
}) =>
    ProfileDto(
      id: id,
      name: 'Rich SS',
      protocol: 'shadowsocks',
      host: 'ss.example',
      port: 8388,
      authKind: 'shadowsocks',
      authSecretSource: source,
      cipher: 'aes-256-gcm',
      dnsMode: 'https',
      dnsServers: const ['9.9.9.9'],
      dohSni: 'dns.example',
      dohPath: '/dns-query',
      splitTunnel: 'include_only',
      splitTunnelApps: const ['Safari'],
      killSwitch: true,
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
  duplicateTests();

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
    // Field by field, because `'$imported'` — what this used to assert on —
    // is inert: the generated ProfileDto overrides `==` and `hashCode` but
    // not `toString`, so it renders as `Instance of 'ProfileDto'` and no
    // implementation could have made that assertion fail.
    expect(everyFieldOf(imported), isNot(contains('hunter2')));

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
    //
    // The expected text is asserted, not just the absence of the secret. The
    // predicate this replaced — `!'$e'.contains('hunter2') && ...` — was
    // satisfied by *any* throw at all: an uninitialised bridge, a panic, a
    // refusal for a completely different reason. It had no defect to name.
    final blob =
        base64Url.encode(utf8.encode('no-colon-hunter2')).replaceAll('=', '');
    Object? thrown;
    try {
      await importSsUri(uri: 'ss://$blob');
      fail('a link with no method:password in it must be refused');
    } catch (e) {
      thrown = e;
    }
    final text = '$thrown';
    expect(text, contains('expected method:password@host:port'),
        reason: 'the refusal must name the shape it wanted');
    expect(text, isNot(contains('hunter2')), reason: 'echoed the password');
    expect(text, isNot(contains(blob)), reason: 'echoed the encoded section');
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

// Duplicating a profile is a convenience; the secret file is the whole of what
// makes it a safe one. `writeSecret` names the file after the profile id, so a
// copy that shared the original's file would look correct right up until
// someone changed the copy's password — and the original's credential would be
// gone, from a gesture that said "duplicate".
void duplicateTests() {
  Future<LoadedProfile> loaded(File f) async => LoadedProfile(
        path: f.path,
        profile: await parseProfile(json: f.readAsStringSync()),
      );

  test('a duplicate gets its own secret file, and the original survives',
      () async {
    final dir = Directory.systemTemp.createTempSync('lios-dup');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'original-password');
    final original = await w.writeProfile(dto(id: id, source: ref));

    final copy = await w.duplicate(await loaded(original));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    expect(copyDto.id, isNot(id), reason: 'a copy is a different profile');
    expect(copyDto.authSecretSource, isNot(ref),
        reason: 'sharing the file means editing the copy destroys the '
            'original');
    expect(File(copyDto.authSecretSource.substring(5)).readAsStringSync(),
        'original-password',
        reason: 'the copy must carry the credential, not a stub');

    // The whole premise of the gesture, and nothing above says it: every
    // assertion so far reads the COPY, so a `duplicate` that ended by
    // deleting its source — one stray `replacingPath: source.path` on the
    // final `writeProfile`, one `await delete(source.path)` — passed all of
    // them. A duplicate that removes the thing it duplicated is the failure
    // this file exists to prevent, in its most literal form.
    expect(File(original.path).existsSync(), isTrue,
        reason: 'duplicating must not consume the original');
    expect((await ProfileStore(directory: dir.path).load()).length, 2,
        reason: 'the list must now hold both, not one');

    // And the copy's credential is as protected as the original's. Written
    // through `writeSecret`, not with a bare `writeAsStringSync`, which would
    // leave a live password in a 0644 file.
    final copyPath = copyDto.authSecretSource.substring(5);
    final mode = (await Process.run('stat', ['-f', '%Lp', copyPath]))
        .stdout
        .toString()
        .trim();
    expect(mode, '600', reason: 'the copy is a credential like any other');
    dir.deleteSync(recursive: true);
  });

  // `duplicate` rebuilds the DTO field by field, which is exactly how this app
  // once rewrote a wireguard profile to ssh with its app list gone (see "a
  // field the editor does not offer survives a round trip"). Every duplicate
  // test above builds its source from `dto()` — ssh, password, kill switch
  // off, no apps, no peer key, no cipher, no DoH — so replacing any of those
  // lines with a literal changed nothing anyone could see.
  Future<void> carriesEveryField(ProfileDto Function({String source, String id})
      fixture) async {
    final dir = Directory.systemTemp.createTempSync('lios-dup-fields');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'p');
    final original = await w.writeProfile(fixture(source: ref, id: id));
    final src = await parseProfile(json: original.readAsStringSync());

    final copy = await w.duplicate(await loaded(original));
    final got = await parseProfile(json: copy.readAsStringSync());

    // Asserted against the SOURCE rather than against literals, so the fixture
    // and the assertion cannot drift apart. Three fields are meant to differ —
    // the id, the name and the secret reference — and every other one is here.
    // `authPassphraseSource` is deliberately absent: the copy points at its
    // own passphrase file, which its own test covers.
    expect(got.protocol, src.protocol);
    expect(got.host, src.host);
    expect(got.port, src.port);
    expect(got.authKind, src.authKind);
    expect(got.peerPublicKey, src.peerPublicKey);
    expect(got.cipher, src.cipher);
    expect(got.dnsMode, src.dnsMode);
    expect(got.dnsServers, src.dnsServers);
    expect(got.dohSni, src.dohSni);
    expect(got.dohPath, src.dohPath);
    expect(got.splitTunnel, src.splitTunnel);
    expect(got.splitTunnelApps, src.splitTunnelApps);
    expect(got.killSwitch, src.killSwitch);
    dir.deleteSync(recursive: true);
  }

  test('a wireguard profile is duplicated as a wireguard profile', () async {
    await carriesEveryField(rich);
  });

  test('the cipher and the DoH endpoint are carried too', () async {
    // A second fixture because the first structurally cannot hold these: a
    // cipher lives on shadowsocks credentials and a DoH endpoint on
    // `dnsMode: https`, and `parse_profile` returns null for both on a
    // wireguard profile however the DTO was built.
    await carriesEveryField(richShadowsocks);
  });

  test('changing the copy leaves the original credential intact', () async {
    // The failure this exists to prevent. "Duplicate then edit" must not
    // overwrite the password the ORIGINAL profile still points at.
    final dir = Directory.systemTemp.createTempSync('lios-dup2');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'original-password');
    final original = await w.writeProfile(dto(id: id, source: ref));
    final copy = await w.duplicate(await loaded(original));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    // Both of the ways a credential gets changed, because they are keyed on
    // different things and neither alone catches both defects. `writeSecret`
    // is what the editor calls and it keys on the profile ID, so it catches a
    // copy that kept the original's id — and nothing else: give the copy a
    // fresh id but the original's `authSecretSource` and this call lands
    // harmlessly on a file no profile names, while the copy still points at
    // the original's credential. Writing through the reference the copy
    // carries is what "this profile's password" means on disk, and it is the
    // half that catches that.
    await w.writeSecret(copyDto.id, 'changed');
    File(copyDto.authSecretSource.substring(5)).writeAsStringSync('changed');

    expect(File(ref.substring(5)).readAsStringSync(), 'original-password',
        reason: 'the original credential must survive a change to the copy');
    dir.deleteSync(recursive: true);
  });

  test('the copy carries the ssh username', () async {
    // The username is in a sidecar, not in the profile, so a copy that only
    // copies the document loses it — and the failure that produces is "the
    // server rejected the credentials" against a password that is perfectly
    // good, which sends you after the wrong fix.
    final dir = Directory.systemTemp.createTempSync('lios-dup7');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'p');
    final original =
        await w.writeProfile(dto(id: id, source: ref), sshUser: 'hanif');

    final copy = await w.duplicate(await loaded(original));

    expect(File('${copy.path}.user').readAsStringSync(), 'hanif');
    // Read off the COPY above, so a `duplicate` that moved the original onto
    // the new name — deleting `home-vps.json` and `home-vps.json.user` on its
    // way out — satisfied that line perfectly. The original's username has to
    // still be there too, or the profile it belongs to falls back to the local
    // account name and every connection fails as "credentials rejected".
    expect(File('${original.path}.user').existsSync(), isTrue,
        reason: "the original's username is not the copy's to take");
    expect(File('${original.path}.user').readAsStringSync(), 'hanif');
    dir.deleteSync(recursive: true);
  });

  test('duplicating twice does not collide', () async {
    final dir = Directory.systemTemp.createTempSync('lios-dup3');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'p');
    final original = await w.writeProfile(dto(id: id, source: ref));
    final source = await loaded(original);
    final a = await w.duplicate(source);
    final b = await w.duplicate(source);
    expect(a.path, isNot(b.path), reason: 'the second copy needs its own name');
    dir.deleteSync(recursive: true);
  });

  test('two duplicates in one tick leave no orphaned credential', () async {
    // A double-tap on a Duplicate menu item, and it is reachable exactly as
    // written: everything before `await newProfileId()` — the guards, the read,
    // the whole naming loop — is synchronous, so the second call enters
    // `duplicate` before the first has yielded and both settle on
    // "Home VPS copy". Both then write a secret under their own fresh id, and
    // the refusal comes from `writeProfile`'s OWN `checkNameFree`, which runs
    // after `writeSecret` — so the loser leaves a 0600 file holding a live
    // credential that no profile names and nothing ever collects.
    final dir = Directory.systemTemp.createTempSync('lios-dup-race');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'original-password');
    final original = await w.writeProfile(dto(id: id, source: ref));
    final source = await loaded(original);

    // Neither is awaited before the other starts. That is the whole scenario.
    final settled = await Future.wait([
      w.duplicate(source).then<Object>((f) => f, onError: (Object e) => e),
      w.duplicate(source).then<Object>((f) => f, onError: (Object e) => e),
    ]);

    expect(settled.whereType<File>().length, 1, reason: 'one copy is made');
    expect(settled.whereType<StateError>().length, 1,
        reason: 'and the other is refused rather than overwriting it');
    expect(Directory(w.secretsDirectory).listSync().length, 2,
        reason: "the original's secret and the one copy that exists; a "
            'refusal must collect the credential it had already written');
    dir.deleteSync(recursive: true);
  });

  test('a secret that is not valid UTF-8 is copied byte for byte', () async {
    // A binary pre-shared key, a DER-encoded private key. Reading the source
    // with `readAsStringSync` decodes it as UTF-8, so duplicating one threw a
    // FormatException about byte offsets out of a menu item that said
    // "duplicate" — not the readable refusal the doc promises for a secret
    // that cannot be read, and not a refusal that was owed at all: there is
    // nothing wrong with the profile.
    final dir = Directory.systemTemp.createTempSync('lios-dup-bin');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'placeholder');
    const bytes = [0x00, 0xff, 0xfe, 0x80, 0x41];
    File(ref.substring(5)).writeAsBytesSync(bytes);
    final original = await w.writeProfile(dto(id: id, source: ref));

    final copy = await w.duplicate(await loaded(original));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    expect(File(copyDto.authSecretSource.substring(5)).readAsBytesSync(), bytes,
        reason: 'a credential is bytes; a round trip through a String would '
            'corrupt one even where it did not throw');
    dir.deleteSync(recursive: true);
  });

  // An ssh `private_key` credential is TWO files, not one: `portable.rs`
  // writes `<id>.private_key` and `<id>.passphrase`, both keyed on the profile
  // id. Copying the first and aliasing the second is the same defect the
  // secret copy exists to prevent, one field over — and quieter, because
  // nothing in the app writes a passphrase today, so only a profile that came
  // in through the CLI's portable import has one to lose.
  ProfileDto keyProfile({
    required String source,
    String? passphrase,
    String id = '11111111-1111-1111-1111-111111111111',
  }) =>
      ProfileDto(
        id: id,
        name: 'Key VPS',
        protocol: 'ssh',
        host: '198.51.100.9',
        port: 22,
        authKind: 'private_key',
        authSecretSource: source,
        authPassphraseSource: passphrase,
        dnsMode: 'tcp',
        dnsServers: const ['1.1.1.1'],
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      );

  test('the copy gets its own passphrase file too', () async {
    final dir = Directory.systemTemp.createTempSync('lios-dup-pass');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final keyRef = await w.writeSecret(id, 'PRIVATE KEY');
    final passRef = await w.writeSecret('$id.passphrase', 'original-phrase');
    final original =
        await w.writeProfile(keyProfile(source: keyRef, passphrase: passRef));

    final copy = await w.duplicate(await loaded(original));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    expect(copyDto.authPassphraseSource, isNotNull,
        reason: 'a copy that loses the passphrase cannot open its own key');
    expect(copyDto.authPassphraseSource, isNot(passRef),
        reason: 'sharing the file means changing the copy destroys the '
            "original's passphrase");
    final copyPass = copyDto.authPassphraseSource!.substring(5);
    expect(File(copyPass).readAsStringSync(), 'original-phrase',
        reason: 'and it must be the passphrase, not a stub');
    final mode = (await Process.run('stat', ['-f', '%Lp', copyPass]))
        .stdout
        .toString()
        .trim();
    expect(mode, '600', reason: 'a passphrase is a credential like any other');

    // The same demonstration the secret gets: writing through the reference
    // the COPY carries must not reach the original's file.
    File(copyPass).writeAsStringSync('changed');
    expect(File(passRef.substring(5)).readAsStringSync(), 'original-phrase',
        reason: 'the original passphrase must survive a change to the copy');
    dir.deleteSync(recursive: true);
  });

  test('a passphrase that is not a file is carried, not copied', () async {
    // `env:KEY_PASS` names no file, so both profiles reading it destroys
    // nothing — and refusing to duplicate over it would refuse a profile with
    // nothing wrong with it. Copying it blindly would look for a file called
    // `KEY_PASS` and refuse for a reason that is not true.
    final dir = Directory.systemTemp.createTempSync('lios-dup-envpass');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final keyRef = await w.writeSecret(id, 'PRIVATE KEY');
    final original = await w
        .writeProfile(keyProfile(source: keyRef, passphrase: 'env:KEY_PASS'));

    final copy = await w.duplicate(await loaded(original));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    expect(copyDto.authPassphraseSource, 'env:KEY_PASS');
    dir.deleteSync(recursive: true);
  });

  test('a source whose passphrase file is gone is refused, and cleanly',
      () async {
    // Symmetrical with the missing secret one field over: a refusal the caller
    // can show, rather than a copy pointing at a passphrase that is not there.
    // And it must arrive before the secret copy is written, or a refusal about
    // the passphrase leaves an orphaned key behind — the same ordering rule
    // `checkNameFree` was moved ahead of `writeSecret` for.
    final dir = Directory.systemTemp.createTempSync('lios-dup-nopass');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final keyRef = await w.writeSecret(id, 'PRIVATE KEY');
    final passRef = await w.writeSecret('$id.passphrase', 'original-phrase');
    final original =
        await w.writeProfile(keyProfile(source: keyRef, passphrase: passRef));
    final source = await loaded(original);
    File(passRef.substring(5)).deleteSync();

    await expectLater(
      w.duplicate(source),
      throwsA(isA<StateError>().having(
          (e) => '$e', 'message', contains('passphrase file is missing'))),
    );
    expect(dir.listSync().whereType<File>().length, 1,
        reason: 'no half-made copy was left behind');
    expect(Directory(w.secretsDirectory).listSync().length, 1,
        reason: "only the original's key — a refusal about the passphrase "
            'must not leave the copied key behind');
    dir.deleteSync(recursive: true);
  });

  test('duplicating a profile whose secret is not a file is refused', () async {
    // What the refusal SAYS, not merely that something was thrown. Asserting
    // `contains('secret')` was satisfied by the *next* guard down: `env:PW`
    // minus five characters is `W`, which does not exist, so "secret file is
    // missing" answered a test about a secret that is not a file at all. It
    // passed with this guard deleted and so had no defect to name.
    final dir = Directory.systemTemp.createTempSync('lios-dup4');
    final w = ProfileWriter(directory: dir.path);
    final original = await w.writeProfile(dto(source: 'env:PW'));
    await expectLater(
      w.duplicate(await loaded(original)),
      throwsA(isA<StateError>().having(
          (e) => '$e', 'message', contains('secret is not a file'))),
    );
    dir.deleteSync(recursive: true);
  });

  test('duplicating a profile whose secret file is gone is refused', () async {
    // A refusal the caller can put in front of the user, rather than a
    // FileSystemException out of `readAsStringSync` — and it has to arrive
    // before the copy exists, not as a profile pointing at an empty file.
    final dir = Directory.systemTemp.createTempSync('lios-dup5');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final ref = await w.writeSecret(id, 'p');
    final original = await w.writeProfile(dto(id: id, source: ref));
    final source = await loaded(original);
    File(ref.substring(5)).deleteSync();

    await expectLater(
      w.duplicate(source),
      throwsA(isA<StateError>()
          .having((e) => '$e', 'message', contains('secret file is missing'))),
    );
    expect(dir.listSync().whereType<File>().length, 1,
        reason: 'no half-made copy was left behind');
    // Where a half-made copy actually lands. `dir.listSync().whereType<File>()`
    // above cannot see one: secrets live in `<dir>/secrets/`, which is a
    // Directory and gets filtered straight out, so that line only ever counted
    // `.json` files. An orphaned 0600 file holding a live credential that no
    // profile names and nothing collects is the leftover worth asserting on.
    expect(Directory(w.secretsDirectory).listSync(), isEmpty,
        reason: 'and no orphaned credential either');
    dir.deleteSync(recursive: true);
  });

  // A credential this app did not write is not this app's to copy. The copy
  // rule exists because `writeSecret` keys the file on the profile id, so two
  // profiles naming ONE managed file are one edit away from destroying each
  // other's password. Nothing of the sort is true of a file outside
  // `secretsDirectory`: `_writeSecretBytes` can only write inside it, and for
  // `private_key` the editor removes the "Type it" mode entirely, so
  // `writeSecret` is never called for an SSH key profile at all. This is the
  // reasoning `duplicate` already applies one field over to an `env:`
  // passphrase — "two profiles reading it destroy nothing".
  test('a secret file outside the secrets directory is carried, not copied',
      () async {
    final dir = Directory.systemTemp.createTempSync('lios-dup-external');
    final w = ProfileWriter(directory: dir.path);
    final key = '${dir.path}/id_ed25519';
    File(key).writeAsStringSync('-----BEGIN OPENSSH PRIVATE KEY-----');
    final original = await w.writeProfile(keyProfile(source: 'file:$key'));

    final copy = await w.duplicate(await loaded(original));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    expect(copyDto.authSecretSource, 'file:$key',
        reason: 'a copy of your ~/.ssh key under a UUID in the app\'s own '
            'directory is a second copy of a private key you never asked '
            'for, and one `delete` deliberately never collects');
    expect(Directory(w.secretsDirectory).existsSync(), isFalse,
        reason: 'nothing may be written into the managed directory for a '
            'credential that does not live there');
    expect(File(key).readAsStringSync(),
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        reason: 'and the original file is untouched either way');
    dir.deleteSync(recursive: true);
  });

  test('a passphrase file outside the secrets directory is carried too',
      () async {
    // The same rule, one field over. The key here IS managed, so the copy gets
    // its own — which is what stops this passing on a `duplicate` that simply
    // stopped copying everything.
    final dir = Directory.systemTemp.createTempSync('lios-dup-external2');
    final w = ProfileWriter(directory: dir.path);
    const id = '11111111-1111-1111-1111-111111111111';
    final keyRef = await w.writeSecret(id, 'PRIVATE KEY');
    final phrase = '${dir.path}/key-passphrase';
    File(phrase).writeAsStringSync('original-phrase');
    final original = await w
        .writeProfile(keyProfile(source: keyRef, passphrase: 'file:$phrase'));

    final copy = await w.duplicate(await loaded(original));

    final copyDto = await parseProfile(json: copy.readAsStringSync());
    expect(copyDto.authPassphraseSource, 'file:$phrase',
        reason: 'the passphrase lives where the user put it');
    expect(copyDto.authSecretSource, isNot(keyRef),
        reason: 'while the managed key is still copied — the rule is where '
            'the file lives, not which field it is');
    expect(Directory(w.secretsDirectory).listSync().length, 2,
        reason: "the original's key and the copy's, and no third file for a "
            'passphrase that was never this app\'s to copy');
    dir.deleteSync(recursive: true);
  });

  test('duplicating a profile that did not parse is refused', () async {
    // Reachable: the list deliberately shows files it could not read, so
    // whatever menu offers Duplicate can be pointed at one. `source.profile!`
    // would answer with "Null check operator used on a null value", which
    // names nothing the user can act on.
    final dir = Directory.systemTemp.createTempSync('lios-dup6');
    final w = ProfileWriter(directory: dir.path);
    await expectLater(
      w.duplicate(LoadedProfile(
        path: '${dir.path}/broken.json',
        error: 'not a valid profile',
      )),
      throwsA(isA<StateError>()
          .having((e) => '$e', 'message', contains('does not parse'))),
    );
    dir.deleteSync(recursive: true);
  });
}
