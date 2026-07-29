import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:liostunnel_app/screens/connection.dart';
import 'package:liostunnel_app/screens/profile_editor.dart';
import 'package:liostunnel_app/screens/profiles.dart';
import 'package:liostunnel_app/services/connection_model.dart';
import 'package:liostunnel_app/services/helper_client.dart';
import 'package:liostunnel_app/services/profile_store.dart';
import 'package:liostunnel_app/services/profile_writer.dart';
import 'package:liostunnel_app/src/rust/dto/profile.dart';
import 'package:liostunnel_app/src/rust/frb_generated.dart';

const sample = '''
{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Home VPS",
 "protocol":"ssh","host":"198.51.100.7","port":22,
 "auth":{"type":"password","password":{"source":"env","var":"PW"}},
 "dns":["1.1.1.1"],
 "split_tunnel":{"type":"all_traffic"},"kill_switch":false}
''';

Widget wrap(ConnectionModel m, Widget child) => ChangeNotifierProvider.value(
  value: m,
  child: MaterialApp(home: child),
);

/// Built directly rather than through the FFI.
///
/// `testWidgets` runs its body in a fake-async zone, so a real Future from
/// the bridge never completes there — the first version of this file hung
/// for five minutes on exactly that. Parsing is covered by profile_test.dart
/// and by the store test at the bottom of this file, where a real event loop
/// exists; these tests are about rendering.
const aProfile = LoadedProfile(
  path: '/tmp/x.json',
  profile: ProfileDto(
    id: 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
    name: 'Home VPS',
    protocol: 'ssh',
    host: '198.51.100.7',
    port: 22,
    authKind: 'password',
    authSecretSource: 'env:PW',
    dnsMode: 'tcp',
    dnsServers: ['1.1.1.1'],
    splitTunnel: 'all_traffic',
    splitTunnelApps: [],
    killSwitch: false,
  ),
);

void main() {
  setUpAll(() async => await RustLib.init());

  testWidgets('the button reads Connect when disconnected', (tester) async {
    final m = ConnectionModel();
    await tester.pumpWidget(
      wrap(
        m,
        ConnectionScreen(
          selected: aProfile,
          onConnect: () {},
          onDisconnect: () {},
        ),
      ),
    );
    expect(find.text('Connect'), findsOneWidget);
    expect(find.text('Disconnect'), findsNothing);
  });

  testWidgets('the button reads Disconnect once connected', (tester) async {
    final m = ConnectionModel()..applyEvent(const StateEvent('Connected'));
    await tester.pumpWidget(
      wrap(
        m,
        ConnectionScreen(
          selected: aProfile,
          onConnect: () {},
          onDisconnect: () {},
        ),
      ),
    );
    expect(find.text('Disconnect'), findsOneWidget);
  });

  testWidgets('the button is disabled with no profile selected', (
    tester,
  ) async {
    // A connect with nothing selected can only produce an error the user
    // cannot act on.
    await tester.pumpWidget(
      wrap(
        ConnectionModel(),
        ConnectionScreen(selected: null, onConnect: () {}, onDisconnect: () {}),
      ),
    );
    final button = tester.widget<FilledButton>(
      find.byKey(const Key('connect-button')),
    );
    expect(button.onPressed, isNull);
  });

  testWidgets('a running tunnel can be stopped without a profile selected',
      (tester) async {
    // `_selected` is null on every relaunch, and the app then asks the helper
    // for status and is told Connected. Requiring a profile here left the
    // button greyed out with no way to stop the tunnel at all.
    var stopped = false;
    final m = ConnectionModel()..applyEvent(const StateEvent('Connected'));
    await tester.pumpWidget(wrap(
      m,
      ConnectionScreen(
        selected: null,
        onConnect: () {},
        onDisconnect: () => stopped = true,
      ),
    ));
    final button = tester.widget<FilledButton>(
      find.byKey(const Key('connect-button')),
    );
    expect(button.onPressed, isNotNull, reason: 'Disconnect needs no profile');
    await tester.tap(find.byKey(const Key('connect-button')));
    expect(stopped, isTrue);
  });

  testWidgets('no error banner when nothing has gone wrong', (tester) async {
    await tester.pumpWidget(
      wrap(
        ConnectionModel(),
        ConnectionScreen(selected: null, onConnect: () {}, onDisconnect: () {}),
      ),
    );
    expect(find.byKey(const Key('error-banner')), findsNothing);
  });

  testWidgets('a fault shows our wording, never the helper\'s message', (
    tester,
  ) async {
    final m = ConnectionModel()
      ..applyError(const HelperUnavailable('ENOENT from the socket layer'));
    await tester.pumpWidget(
      wrap(
        m,
        ConnectionScreen(selected: null, onConnect: () {}, onDisconnect: () {}),
      ),
    );
    expect(find.byKey(const Key('error-banner')), findsOneWidget);
    expect(find.textContaining('not installed'), findsOneWidget);
    expect(find.textContaining('ENOENT'), findsNothing);
  });

  testWidgets('the banner clears once the helper reports a state', (
    tester,
  ) async {
    final m = ConnectionModel()..applyError(const HelperUnavailable());
    await tester.pumpWidget(
      wrap(
        m,
        ConnectionScreen(selected: null, onConnect: () {}, onDisconnect: () {}),
      ),
    );
    expect(find.byKey(const Key('error-banner')), findsOneWidget);
    m.applyEvent(const StateEvent('Connected'));
    await tester.pump();
    expect(find.byKey(const Key('error-banner')), findsNothing);
  });

  testWidgets('stats render as they arrive', (tester) async {
    final m = ConnectionModel()..applyEvent(const StateEvent('Connected'));
    await tester.pumpWidget(
      wrap(
        m,
        ConnectionScreen(selected: null, onConnect: () {}, onDisconnect: () {}),
      ),
    );
    m.applyEvent(
      StatsEvent(
        bytesUp: BigInt.from(2048),
        bytesDown: BigInt.from(4096),
        activeFlows: 3,
        flowsFailed: BigInt.zero,
        dnsQueries: BigInt.from(11),
      ),
    );
    await tester.pump();
    expect(find.text('2.0 KiB'), findsOneWidget);
    expect(find.text('4.0 KiB'), findsOneWidget);
    expect(find.text('3'), findsOneWidget);
  });

  testWidgets('the list renders a profile as name, host, port and protocol', (
    tester,
  ) async {
    // Rendering only. That the DTO came from parse_profile rather than a Dart
    // reimplementation — P1a-1 — is proven by the store test below and by
    // profile_test.dart, not here.
    const loaded = aProfile;
    await tester.pumpWidget(
      MaterialApp(
        home: ProfilesScreen(
          profiles: [loaded],
          directory: '/tmp/whatever',
          selectedPath: null,
          onSelect: (_) {},
          onReload: () {},
        onCreate: () {},
        onEdit: _ignore,
        ),
      ),
    );
    expect(find.text('Home VPS'), findsOneWidget);
    expect(find.text('198.51.100.7:22 · ssh'), findsOneWidget);
  });

  testWidgets('an unreadable profile is shown as broken, not hidden', (
    tester,
  ) async {
    // A profile that silently vanishes from the list looks the same as one
    // the user never saved.
    await tester.pumpWidget(
      MaterialApp(
        home: ProfilesScreen(
          profiles: const [
            LoadedProfile(
              path: '/tmp/broken.json',
              error: 'not a valid profile',
            ),
          ],
          directory: '/tmp/whatever',
          selectedPath: null,
          onSelect: (_) {},
          onReload: () {},
        onCreate: () {},
        onEdit: _ignore,
        ),
      ),
    );
    expect(find.text('broken.json'), findsOneWidget);
    expect(find.text('not a valid profile'), findsOneWidget);
  });

  testWidgets('every row has an edit button, including a broken one',
      (tester) async {
    // The feature shipped with this button on the BROKEN-profile branch only:
    // a patch failed to match the healthy branch after dart format rewrapped
    // it, and nothing asserted the affordance existed. The whole feature was
    // unreachable for every profile that actually parsed, with a green suite.
    const broken = LoadedProfile(path: '/tmp/b.json', error: 'not a valid profile');
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: const [aProfile, broken],
        directory: '/tmp/whatever',
        selectedPath: aProfile.path,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: _ignore,
      ),
    ));
    expect(find.byIcon(Icons.edit_outlined), findsNWidgets(2));
    expect(find.byKey(ValueKey('edit-${aProfile.path}')), findsOneWidget,
        reason: 'a healthy profile must be editable');
    expect(find.byKey(const ValueKey('edit-/tmp/b.json')), findsOneWidget,
        reason: 'and a broken one especially so');
    // The selected row shows both a tick and an edit button.
    expect(find.byIcon(Icons.check), findsOneWidget);
  });

  testWidgets('the edit button reports which profile it belongs to',
      (tester) async {
    LoadedProfile? edited;
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: const [aProfile],
        directory: '/tmp/whatever',
        selectedPath: null,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: (p) => edited = p,
      ),
    ));
    await tester.tap(find.byKey(ValueKey('edit-${aProfile.path}')));
    expect(edited?.path, aProfile.path);
  });

  testWidgets('tapping a profile selects it', (tester) async {
    LoadedProfile? picked;
    const loaded = aProfile;
    await tester.pumpWidget(
      MaterialApp(
        home: ProfilesScreen(
          profiles: [loaded],
          directory: '/tmp/whatever',
          selectedPath: null,
          onSelect: (p) => picked = p,
          onReload: () {},
        onCreate: () {},
        onEdit: _ignore,
        ),
      ),
    );
    await tester.tap(find.text('Home VPS'));
    expect(picked?.path, loaded.path);
  });

  testWidgets('an empty profiles directory says where to put one', (
    tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: ProfilesScreen(
          profiles: [],
          directory: '/somewhere/.liostunnel',
          selectedPath: null,
          onSelect: _ignore,
          onReload: _noop,
          onCreate: _noop,
          onEdit: _ignore,
        ),
      ),
    );
    expect(find.textContaining('/somewhere/.liostunnel'), findsOneWidget);
  });

  test('the store reads and parses real files through the FFI', () async {
    // The I/O half, exercised as a plain test where a real event loop is
    // available. The widget half above stays pure.
    final dir = Directory.systemTemp.createTempSync('lios-store');
    File('${dir.path}/home.json').writeAsStringSync(sample);
    File('${dir.path}/broken.json').writeAsStringSync('{"protocol":"nope"}');
    File('${dir.path}/ignored.txt').writeAsStringSync('not json');

    final loaded = await ProfileStore(directory: dir.path).load();
    expect(loaded.length, 2, reason: 'only .json files are considered');
    final broken = loaded.firstWhere((p) => p.path.endsWith('broken.json'));
    expect(broken.ok, isFalse);
    // The message must not quote the document: it may hold secret material.
    expect(broken.error, 'not a valid profile');
    final good = loaded.firstWhere((p) => p.path.endsWith('home.json'));
    expect(good.profile!.name, 'Home VPS');

    dir.deleteSync(recursive: true);
  });

  editorTests();

  test('a missing profiles directory is empty, not an error', () async {
    final loaded = await ProfileStore(
      directory: '/nonexistent/lios-profiles',
    ).load();
    expect(loaded, isEmpty);
  });
}

void _ignore(LoadedProfile _) {}
void _noop() {}

// --- profile editor -------------------------------------------------------
// Rendering and validation only. The save path crosses the FFI, and
// testWidgets runs its body in a fake-async zone where those futures never
// complete — that is covered by profile_writer_test.dart instead.

/// A surface tall enough that the whole form is built.
///
/// The save button sits below the fold of a lazy ListView on the default
/// 800x600 test view, so it is never constructed and `tap` finds nothing.
/// scrollUntilVisible is not the answer here: it calls `.single` on the
/// scrollable finder and the form has several.
Future<void> pumpEditor(
  WidgetTester tester, {
  LoadedProfile? existing,
  String? directory,
}) async {
  tester.view.physicalSize = const Size(1200, 2400);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(editor(existing: existing, directory: directory));
}

Widget editor({LoadedProfile? existing, String? directory}) => MaterialApp(
      home: ProfileEditorScreen(
        writer: ProfileWriter(directory: directory ?? '/tmp/lios-editor-test'),
        onSaved: () {},
        existing: existing,
      ),
    );

/// A saved Shadowsocks profile, as the store would hand one back.
LoadedProfile ssProfile({
  String cipher = 'aes-256-gcm',
  List<String> dns = const ['1.1.1.1'],
}) =>
    LoadedProfile(
      path: '/tmp/ss.json',
      profile: ProfileDto(
        id: 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f',
        name: 'SS',
        protocol: 'shadowsocks',
        host: '198.51.100.7',
        port: 8388,
        authKind: 'shadowsocks',
        authSecretSource: 'file:/tmp/ss-key',
        cipher: cipher,
        dnsMode: 'tcp',
        dnsServers: dns,
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      ),
    );

/// A live `ss://` link. The password is only ever in this file's memory and
/// in the 0600 file the editor writes under a temp directory.
String ssLink({int port = 8388, String? tag}) {
  final creds =
      base64Url.encode(utf8.encode('aes-256-gcm:hunter2')).replaceAll('=', '');
  return 'ss://$creds@198.51.100.7:$port${tag == null ? '' : '#$tag'}';
}

/// Presses a button whose handler crosses the FFI, on the real event loop.
///
/// The header note above is the reason: `testWidgets` runs its body in a
/// fake-async zone, and a Future from the bridge never completes there. The
/// tap happens *inside* `runAsync`, so the handler's awaits are real awaits
/// rather than ones parked forever in fake time; the delay lets the bridge
/// answer; the frame that renders the resulting `setState` is pumped
/// afterwards, outside. Without this the save path has no test at all, which
/// is how `protocol: 'ssh'` shipped on a Shadowsocks profile.
Future<void> pressAndSettle(WidgetTester tester, Key key) async {
  await tester.runAsync(() async {
    await tester.tap(find.byKey(key));
    await Future<void>.delayed(const Duration(milliseconds: 500));
  });
  await tester.pumpAndSettle();
}

/// Picks a value from one of the form's dropdowns.
Future<void> choose(WidgetTester tester, Key dropdown, String label) async {
  await tester.tap(find.byKey(dropdown));
  await tester.pumpAndSettle();
  await tester.tap(find.text(label).last);
  await tester.pumpAndSettle();
}

/// The text a form field currently holds.
String fieldText(WidgetTester tester, Key key) => tester
    .widget<EditableText>(
      find.descendant(of: find.byKey(key), matching: find.byType(EditableText)),
    )
    .controller
    .text;

void editorTests() {
  testWidgets('an empty host is refused before anything is written',
      (tester) async {
    await pumpEditor(tester);
    await tester.enterText(find.byKey(const Key('f-host')), '');
    await tester.tap(find.byKey(const Key('save-button')));
    await tester.pump();
    expect(find.text('required'), findsWidgets);
    expect(find.byKey(const Key('editor-saved')), findsNothing);
  });

  testWidgets('a port outside 1-65535 is refused', (tester) async {
    await pumpEditor(tester);
    await tester.enterText(find.byKey(const Key('f-port')), '70000');
    await tester.tap(find.byKey(const Key('save-button')));
    await tester.pump();
    expect(find.text('1–65535'), findsOneWidget);
  });

  testWidgets('a typed password is obscured on screen', (tester) async {
    await pumpEditor(tester);
    await tester.tap(find.byKey(const Key('f-secret-mode')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Type it — save to a 0600 file').last);
    await tester.pumpAndSettle();
    final editable = tester.widget<EditableText>(
      find.descendant(
        of: find.byKey(const Key('f-secret')),
        matching: find.byType(EditableText),
      ),
    );
    expect(editable.obscureText, isTrue);
  });

  testWidgets('the file mode says the ownership rule the helper enforces',
      (tester) async {
    // A user whose key is 0644 gets refused at connect time with no way to
    // know why from the form, so the form has to say it up front.
    await pumpEditor(tester);
    expect(find.textContaining('owned by you and mode 0600'), findsOneWidget);
  });

  testWidgets('a profile whose cipher this build does not offer still opens',
      (tester) async {
    // `method` is a free String in the schema, so a CLI-written profile can
    // name anything. DropdownButtonFormField asserts exactly one item matches
    // its value: in debug the whole editor became an ErrorWidget the moment it
    // opened, and in release the assert is stripped and the field rendered
    // blank while the rejected name was still what would be saved. The form
    // already carries `preshared_key` for exactly this reason.
    await pumpEditor(tester, existing: ssProfile(cipher: '2022-blake3-aes-256-gcm'));
    expect(tester.takeException(), isNull,
        reason: 'the editor must open, not turn into an ErrorWidget');
    expect(find.text('2022-blake3-aes-256-gcm'), findsOneWidget,
        reason: 'and must show what the profile says, not a default it '
            'silently substituted — shadowsocks has no handshake, so the '
            'wrong cipher looks exactly like a working one');
  });

  testWidgets('the paste box is obscured, like any other credential field',
      (tester) async {
    // The link IS the password. Only a *successful* import used to clear it,
    // so a failed one — or toggling Authentication away and back — left the
    // whole credential legible on screen.
    await pumpEditor(tester);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    final editable = tester.widget<EditableText>(
      find.descendant(
        of: find.byKey(const Key('f-uri')),
        matching: find.byType(EditableText),
      ),
    );
    expect(editable.obscureText, isTrue);
  });

  testWidgets('an unofferable cipher is refused at the paste box, writing '
      'nothing', (tester) async {
    // The import used to succeed for any cipher the link named, and the
    // caller wrote the password to disk before the cipher ever reached the
    // dropdown that refuses it. An Outline key — `2022-blake3-aes-256-gcm`,
    // today's default server cipher — therefore destroyed the editor with the
    // credential already on disk.
    final dir = Directory.systemTemp.createTempSync('lios-editor-bad-cipher');
    addTearDown(() => dir.deleteSync(recursive: true));
    final creds = base64Url
        .encode(utf8.encode('2022-blake3-aes-256-gcm:hunter2'))
        .replaceAll('=', '');

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await tester.enterText(
        find.byKey(const Key('f-uri')), 'ss://$creds@198.51.100.7:8388');
    await pressAndSettle(tester, const Key('import-button'));

    expect(tester.takeException(), isNull);
    expect(find.byKey(const Key('editor-error')), findsOneWidget,
        reason: 'the refusal belongs at the paste box');
    expect(Directory('${dir.path}/secrets').existsSync(), isFalse,
        reason: 'nothing may be written before the link is accepted');
    expect(find.textContaining('2022-blake3'), findsNothing,
        reason: 'the message may not echo what the user pasted');
    final message = tester
        .widget<Text>(find.descendant(
          of: find.byKey(const Key('editor-error')),
          matching: find.byType(Text),
        ))
        .data!;
    expect(message, contains('aes-128-gcm'),
        reason: 'it must name what IS offered');
    expect(message, isNot(contains('hunter2')));
  });

  testWidgets('an import leaves the DNS the profile already had', (tester) async {
    // An ss:// link carries no DNS information, so the form's value wins. The
    // import used to write its own default over it: a Quad9 profile kept its
    // mode and SNI but had its resolver replaced by 1.1.1.1, so the DoH probe
    // dialled Cloudflare presenting Quad9's name.
    final dir = Directory.systemTemp.createTempSync('lios-editor-dns');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester,
        existing: ssProfile(dns: const ['9.9.9.9']), directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());
    await pressAndSettle(tester, const Key('import-button'));

    expect(find.byKey(const Key('editor-error')), findsNothing);
    // Asserting on f-host would prove nothing: `ssProfile` and `ssLink` name
    // the same host, so `initState` had already put it there. The name is
    // what the import actually changes -- `SS` becomes the link's own label.
    expect(fieldText(tester, const Key('f-name')), '198.51.100.7:8388',
        reason: 'the import did happen');
    expect(fieldText(tester, const Key('f-dns')), '9.9.9.9',
        reason: 'the link says nothing about DNS');
    // The other half of the orphaned-secret defect: an edit keeps its own id,
    // so the secret has to be written under that one and not under the fresh
    // id the import minted.
    expect(fieldText(tester, const Key('f-secret-path')),
        endsWith('b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f'),
        reason: 'the secret file is keyed on the id the profile will carry');
  });

  testWidgets('an imported link saves as shadowsocks, keyed to its own secret',
      (tester) async {
    // Two defects in one gesture. The helper's factory dispatches on
    // `protocol`, so a profile saved as `ssh` with shadowsocks auth goes to
    // the SSH tunnel and is refused. And `_import` wrote the secret under the
    // id the import minted while `_save` minted a second one, so every import
    // left an orphan 0600 file that deletion never collects.
    final dir = Directory.systemTemp.createTempSync('lios-editor-import');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(tag: 'Home'));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);

    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);

    final written = Directory(dir.path)
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.json'))
        .toList();
    expect(written.length, 1);
    final doc = jsonDecode(written.single.readAsStringSync())
        as Map<String, dynamic>;
    expect(doc['protocol'], 'shadowsocks',
        reason: 'the factory dispatches on this');
    expect(doc['auth']['type'], 'shadowsocks');
    expect(doc['auth']['method'], 'aes-256-gcm');

    final secrets = Directory('${dir.path}/secrets').listSync();
    expect(secrets.length, 1, reason: 'one import, one secret file');
    expect(doc['auth']['password']['path'], secrets.single.path,
        reason: 'the profile must name the file that was written');
    expect(secrets.single.path, endsWith(doc['id'] as String),
        reason: 'writeSecret keys on the profile id, so the profile must '
            'carry the id the import used');
    expect(File(secrets.single.path).readAsStringSync(), 'hunter2');
    expect(written.single.readAsStringSync(), isNot(contains('hunter2')));
  });

  testWidgets('saving keeps a link the import never consumed', (tester) async {
    // The box is cleared when an import takes the link, not on every save.
    // Clearing unconditionally meant a user who pasted a NEW link to rotate a
    // password and then pressed Save instead of Import saved the OLD
    // credential, and the link vanished with nothing saying it was ignored.
    final dir = Directory.systemTemp.createTempSync('lios-editor-clear');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await tester.enterText(find.byKey(const Key('f-name')), 'Manual');
    await tester.enterText(find.byKey(const Key('f-host')), '198.51.100.7');
    await tester.enterText(find.byKey(const Key('f-port')), '8388');
    await tester.enterText(
        find.byKey(const Key('f-secret-path')), '${dir.path}/key');
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());

    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);
    expect(fieldText(tester, const Key('f-uri')), ssLink(),
        reason: 'the link was never imported, so it is still the user\'s');
  });

  testWidgets('an imported link is gone from the box by the time it is saved',
      (tester) async {
    // The other half: once the import has taken it, the credential must not
    // stay legible on screen through the save.
    final dir = Directory.systemTemp.createTempSync('lios-editor-clear2');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());
    await pressAndSettle(tester, const Key('import-button'));
    expect(fieldText(tester, const Key('f-uri')), isEmpty,
        reason: 'the import consumed it');
    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);
    expect(fieldText(tester, const Key('f-uri')), isEmpty);
  });

  testWidgets('re-importing to fix a typo does not orphan the first secret',
      (tester) async {
    // `writeSecret` names the file after the id it is given, and deletion
    // deliberately never touches secret files -- so an id minted fresh on
    // each import leaves a live password on disk that no profile references
    // and nothing collects.
    final dir = Directory.systemTemp.createTempSync('lios-editor-reimport');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');

    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(port: 8388));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    final first = fieldText(tester, const Key('f-secret-path'));

    // The user notices the port is wrong and pastes the corrected link.
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(port: 8389));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    final second = fieldText(tester, const Key('f-secret-path'));

    expect(second, first, reason: 'the second import must reuse the first id');
    expect(Directory('${dir.path}/secrets').listSync().length, 1,
        reason: 'exactly one secret file, not one per paste');
  });

  testWidgets('a profile whose cipher this build cannot speak will not save',
      (tester) async {
    // The editor opens such a profile rather than crashing -- proven above.
    // This is the other half: it must not let the profile be saved back, or
    // the user gets a tunnel that reports Connected and carries nothing,
    // because Shadowsocks has no handshake in which to disagree.
    final dir = Directory.systemTemp.createTempSync('lios-editor-badcipher');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester,
        existing: ssProfile(cipher: '2022-blake3-aes-256-gcm'),
        directory: dir.path);
    await tester.enterText(
        find.byKey(const Key('f-secret-path')), '${dir.path}/key');
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    expect(find.byKey(const Key('editor-saved')), findsNothing);
    expect(
        Directory(dir.path).listSync().whereType<File>().where(
            (f) => f.path.endsWith('.json')),
        isEmpty,
        reason: 'nothing may reach disk');
  });

  testWidgets('a refused save does not destroy the credential it points at',
      (tester) async {
    // writeSecret overwrites the file keyed to the profile id, so running it
    // before checkProfile meant a refused save wiped the password the on-disk
    // profile still pointed at -- and then reported failure, so the user
    // believed nothing had happened. Same shape as the name-collision bug.
    final dir = Directory.systemTemp.createTempSync('lios-editor-order');
    addTearDown(() => dir.deleteSync(recursive: true));

    // An existing Shadowsocks profile whose secret file already holds a
    // credential the user cannot retype -- it came from an ss:// link.
    // Written synchronously rather than through `writeSecret`: that shells
    // out to chmod, and a real subprocess never completes inside a
    // `testWidgets` fake-async zone -- the test simply hangs.
    const id = 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f';
    final secretPath = ProfileWriter(directory: dir.path).secretPathFor(id);
    File(secretPath).parent.createSync(recursive: true);
    File(secretPath).writeAsStringSync('hunter2');
    final ref = 'file:$secretPath';
    final saved = ssProfile().profile!;

    await pumpEditor(
      tester,
      directory: dir.path,
      existing: LoadedProfile(
        path: '${dir.path}/ss.json',
        profile: ProfileDto(
          id: id,
          name: saved.name,
          protocol: saved.protocol,
          host: saved.host,
          port: saved.port,
          authKind: saved.authKind,
          authSecretSource: ref,
          cipher: saved.cipher,
          dnsMode: saved.dnsMode,
          dnsServers: saved.dnsServers,
          splitTunnel: saved.splitTunnel,
          splitTunnelApps: saved.splitTunnelApps,
          killSwitch: saved.killSwitch,
        ),
      ),
    );

    // A save the profile checker will refuse: the protocol stays shadowsocks
    // because the form does not own it, but the auth kind no longer matches.
    await choose(tester, const Key('f-auth'), 'Password');
    // Switching away from Shadowsocks reveals the SSH username field, which
    // the form requires -- without it `_save` returns at validation and never
    // reaches the code this test is about.
    await tester.enterText(find.byKey(const Key('f-user')), 'someone');
    await choose(
        tester, const Key('f-secret-mode'), 'Type it — save to a 0600 file');
    await tester.enterText(find.byKey(const Key('f-secret')), 'overwritten');
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    expect(find.byKey(const Key('editor-saved')), findsNothing);
    expect(File(secretPath).readAsStringSync(), 'hunter2',
        reason: 'a refused save must not have written the secret');
  });
}
