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
Future<void> pumpEditor(WidgetTester tester) async {
  tester.view.physicalSize = const Size(1200, 2400);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(editor());
}

Widget editor() => MaterialApp(
      home: ProfileEditorScreen(
        writer: ProfileWriter(directory: '/tmp/lios-editor-test'),
        onSaved: () {},
      ),
    );

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
}
