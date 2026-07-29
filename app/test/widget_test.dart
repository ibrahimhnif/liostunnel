import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:liostunnel_app/main.dart';
import 'package:liostunnel_app/screens/connection.dart';
import 'package:liostunnel_app/screens/dialogs.dart';
import 'package:liostunnel_app/screens/profile_editor.dart';
import 'package:liostunnel_app/screens/profiles.dart';
import 'package:liostunnel_app/services/connection_model.dart';
import 'package:liostunnel_app/services/helper_client.dart';
import 'package:liostunnel_app/services/link_export.dart';
import 'package:liostunnel_app/services/profile_store.dart';
import 'package:liostunnel_app/services/profile_writer.dart';
import 'package:liostunnel_app/src/rust/api/config.dart';
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
          onDuplicate: _ignore,
          onCopyLink: _ignore,
          onDelete: _ignore,
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
          onDuplicate: _ignore,
          onCopyLink: _ignore,
          onDelete: _ignore,
        ),
      ),
    );
    expect(find.text('broken.json'), findsOneWidget);
    expect(find.text('not a valid profile'), findsOneWidget);
  });

  testWidgets('every row has a menu offering Edit, including a broken one',
      (tester) async {
    // The affordance shipped once on the BROKEN-profile branch only: a patch
    // failed to match the healthy branch after dart format rewrapped it, and
    // nothing asserted it existed. The whole feature was unreachable for every
    // profile that actually parsed, with a green suite. Editing moved from a
    // per-row IconButton into this menu when Duplicate, Copy and Delete
    // arrived; the invariant did not move with it, so it is restated here
    // against the menu.
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
        onDuplicate: _ignore,
        onCopyLink: _ignore,
        onDelete: _ignore,
      ),
    ));
    expect(find.byType(PopupMenuButton<String>), findsNWidgets(2));
    for (final path in [aProfile.path, '/tmp/b.json']) {
      expect(find.byKey(ValueKey('menu-$path')), findsOneWidget,
          reason: 'every row carries one, healthy or broken');
      await tester.tap(find.byKey(ValueKey('menu-$path')));
      await tester.pumpAndSettle();
      expect(find.text('Edit'), findsOneWidget,
          reason: 'and a broken profile especially needs opening and repairing');
      // Dismiss it: the next row's menu cannot be opened over this one.
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();
    }
    // The selected row shows both a tick and a menu.
    expect(find.byIcon(Icons.check), findsOneWidget);
  });

  testWidgets('the menu reports which profile it belongs to', (tester) async {
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
        onDuplicate: _ignore,
        onCopyLink: _ignore,
        onDelete: _ignore,
      ),
    ));
    await tester.tap(find.byKey(ValueKey('menu-${aProfile.path}')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Edit'));
    await tester.pumpAndSettle();
    expect(edited?.path, aProfile.path);
  });

  testWidgets('each entry reports the row it was chosen from', (tester) async {
    // One `onSelected` switch serves four entries and four callbacks, and
    // nothing else in this file would notice two of them wired to the same
    // one. Duplicate and Delete are the pair worth pinning: both act on a
    // profile without opening anything first, so a swap is invisible until
    // after it has happened.
    final called = <String, String>{};
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [ssProfile(path: '/tmp/ss.json')],
        directory: '/tmp/whatever',
        selectedPath: null,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: (p) => called['edit'] = p.path,
        onDuplicate: (p) => called['duplicate'] = p.path,
        onCopyLink: (p) => called['copy'] = p.path,
        onDelete: (p) => called['delete'] = p.path,
      ),
    ));
    for (final entry in {
      'Duplicate': 'duplicate',
      'Copy ss:// link': 'copy',
      'Delete': 'delete',
    }.entries) {
      await tester.tap(find.byKey(const ValueKey('menu-/tmp/ss.json')));
      await tester.pumpAndSettle();
      await tester.tap(find.text(entry.key));
      await tester.pumpAndSettle();
      expect(called, {entry.value: '/tmp/ss.json'},
          reason: '${entry.key} must call ${entry.value} and nothing else');
      called.clear();
    }
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
          onDuplicate: _ignore,
          onCopyLink: _ignore,
          onDelete: _ignore,
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
          onDuplicate: _ignore,
          onCopyLink: _ignore,
          onDelete: _ignore,
        ),
      ),
    );
    expect(find.textContaining('/somewhere/.liostunnel'), findsOneWidget);
  });

  testWidgets('search filters by name and by host', (tester) async {
    // Host as well as name: a provider's profiles are often all called some
    // variation of its own name, and the address is what tells them apart.
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [
          ssProfile(name: 'Home', host: '198.51.100.7', path: '/tmp/home.json'),
          ssProfile(name: 'Work', host: '203.0.113.9', path: '/tmp/work.json'),
        ],
        directory: '/tmp',
        selectedPath: null,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: _ignore,
        onDuplicate: _ignore,
        onCopyLink: _ignore,
        onDelete: _ignore,
      ),
    ));
    expect(find.text('Home'), findsOneWidget);
    expect(find.text('Work'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('profile-search')), 'wor');
    await tester.pumpAndSettle();
    expect(find.text('Home'), findsNothing, reason: 'filtered by name');
    expect(find.text('Work'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('profile-search')), '198.51');
    await tester.pumpAndSettle();
    expect(find.text('Home'), findsOneWidget, reason: 'filtered by host');
    expect(find.text('Work'), findsNothing);
  });

  testWidgets('the copy-link entry appears only on shadowsocks profiles',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [sshProfile(path: '/tmp/ssh.json', keyPath: '/tmp/k')],
        directory: '/tmp',
        selectedPath: null,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: _ignore,
        onDuplicate: _ignore,
        onCopyLink: _ignore,
        onDelete: _ignore,
      ),
    ));
    await tester.tap(find.byKey(const ValueKey('menu-/tmp/ssh.json')));
    await tester.pumpAndSettle();
    expect(find.text('Copy ss:// link'), findsNothing,
        reason: 'ss:// cannot represent an SSH profile');
    expect(find.text('Duplicate'), findsOneWidget);
  });

  testWidgets('a broken profile offers only edit and delete', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: const [LoadedProfile(path: '/tmp/bad.json', error: 'nope')],
        directory: '/tmp',
        selectedPath: null,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: _ignore,
        onDuplicate: _ignore,
        onCopyLink: _ignore,
        onDelete: _ignore,
      ),
    ));
    await tester.tap(find.byKey(const ValueKey('menu-/tmp/bad.json')));
    await tester.pumpAndSettle();
    expect(find.text('Edit'), findsOneWidget);
    expect(find.text('Delete'), findsOneWidget);
    expect(find.text('Duplicate'), findsNothing,
        reason: 'there is nothing to duplicate');
    expect(find.text('Copy ss:// link'), findsNothing);
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

  test('the list is ordered by name, not by filename', () async {
    // Spec §4: "Ordering stays alphabetical by name." Sorting by path put
    // every copy ABOVE the profile it was copied from — `home-vps-copy.json`
    // sorts before `home-vps.json` because `-` is below `.` — so `duplicate`,
    // whose whole point is a profile that sits beside its original, produced a
    // list in which it never did.
    //
    // Case-insensitively, which the fixture pins: `Home VPS` and a broken
    // `aaa-broken.json` order the other way round under `compareTo`, where
    // every capital sorts before every lower-case letter.
    final dir = Directory.systemTemp.createTempSync('lios-store-order');
    addTearDown(() => dir.deleteSync(recursive: true));
    File('${dir.path}/home-vps-copy.json')
        .writeAsStringSync(sample.replaceAll('Home VPS', 'Home VPS copy'));
    File('${dir.path}/home-vps.json').writeAsStringSync(sample);
    // A profile that did not parse has no name to sort on. The filename is
    // what the row shows for one, so it is what the row sorts on too.
    File('${dir.path}/aaa-broken.json').writeAsStringSync('{ not a profile');

    final loaded = await ProfileStore(directory: dir.path).load();
    expect(loaded.map((p) => p.name).toList(),
        ['aaa-broken.json', 'Home VPS', 'Home VPS copy']);
  });

  testWidgets('a search that matches nothing says so', (tester) async {
    // Without this the list falls through to an empty ListView, which reads
    // exactly like "your profiles are gone" — the same failure the
    // empty-directory message exists to prevent, reached from the other side.
    // And it must not be the empty-directory message either: that one names a
    // path and tells the user to put a file there, which would send them
    // looking for profiles that are on disk and merely filtered out.
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [ssProfile(name: 'Home', path: '/tmp/home.json')],
        directory: '/somewhere/.liostunnel',
        selectedPath: null,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: _ignore,
        onDuplicate: _ignore,
        onCopyLink: _ignore,
        onDelete: _ignore,
      ),
    ));
    await tester.enterText(find.byKey(const Key('profile-search')), 'zzz');
    await tester.pumpAndSettle();

    expect(find.text('Home'), findsNothing, reason: 'precondition: filtered');
    expect(find.text('Nothing matches that search.'), findsOneWidget);
    expect(find.textContaining('/somewhere/.liostunnel'), findsNothing,
        reason: 'the directory is not empty; only the filter is');
  });

  testWidgets('whitespace around a search term is ignored', (tester) async {
    // A term arrives with a space more often than not — from a paste, or from
    // a keyboard that adds one after a word. Matching on the raw text turns
    // that into "Nothing matches that search." over a list that does.
    await tester.pumpWidget(MaterialApp(
      home: ProfilesScreen(
        profiles: [
          ssProfile(name: 'Home', host: '198.51.100.7', path: '/tmp/home.json'),
          ssProfile(name: 'Work', host: '203.0.113.9', path: '/tmp/work.json'),
        ],
        directory: '/tmp',
        selectedPath: null,
        onSelect: _ignore,
        onReload: _noop,
        onCreate: _noop,
        onEdit: _ignore,
        onDuplicate: _ignore,
        onCopyLink: _ignore,
        onDelete: _ignore,
      ),
    ));
    await tester.enterText(find.byKey(const Key('profile-search')), '  wor  ');
    await tester.pumpAndSettle();

    expect(find.text('Work'), findsOneWidget);
    expect(find.text('Home'), findsNothing);
  });

  copyLinkTests();
  deleteTests();
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

// --- copy as a link -------------------------------------------------------
// The one path in the app that handles a live, rendered-adjacent credential.
// Two invariants: it asks before copying, and the link never reaches the
// screen. Both used to be held by reading `_copyLink` — a private method of
// `_HomePageState` that nothing could pump.

/// Every `Clipboard.setData` that reaches the platform channel.
///
/// The real one is unavailable under `flutter test`, so without this the copy
/// path throws into its own catch and the test cannot tell "copied" from
/// "refused". Returned live: the list fills as the calls arrive.
List<String> captureClipboard() {
  final written = <String>[];
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
    if (call.method == 'Clipboard.setData') {
      written.add((call.arguments as Map)['text'] as String);
    }
    return null;
  });
  addTearDown(
      () => messenger.setMockMethodCallHandler(SystemChannels.platform, null));
  return written;
}

/// Puts [confirmAndCopyLink] behind a button and presses it.
///
/// A plain `pumpAndSettle`, deliberately: [producer] is a fake that completes
/// inside the fake-async zone. The real one crosses the FFI, which is why the
/// production code takes a producer at all — `pressAndSettle` wraps
/// `tester.runAsync`, and nesting another throws "Reentrant call to
/// runAsync() denied".
Future<void> pumpCopyLink(
  WidgetTester tester,
  Future<String> Function() producer,
) async {
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: Builder(
        builder: (context) => TextButton(
          key: const Key('copy-link'),
          onPressed: () => confirmAndCopyLink(context, producer),
          child: const Text('Copy as a link'),
        ),
      ),
    ),
  ));
  await tester.tap(find.byKey(const Key('copy-link')));
  await tester.pumpAndSettle();
}

void copyLinkTests() {
  testWidgets('Cancel does not read the secret, let alone copy it',
      (tester) async {
    // Stronger than "did not copy": the producer is never invoked, so the
    // 0600 file is not even opened. That is what makes the confirmation a
    // decision rather than a formality — and it is what fails if the read is
    // hoisted above the dialog for convenience.
    final clipboard = captureClipboard();
    var asked = false;
    await pumpCopyLink(tester, () async {
      asked = true;
      return 'ss://FAKE-CREDENTIAL@h:1';
    });

    expect(find.text('Copy this profile as a link?'), findsOneWidget,
        reason: 'it must ask at all');
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();

    expect(asked, isFalse, reason: 'the secret file must not have been read');
    expect(clipboard, isEmpty);
  });

  testWidgets('Copy puts the link on the clipboard and nowhere on screen',
      (tester) async {
    final clipboard = captureClipboard();
    await pumpCopyLink(tester, () async => 'ss://FAKE-CREDENTIAL@h:1');

    await tester.tap(find.byKey(const Key('confirm-copy')));
    await tester.pumpAndSettle();

    expect(clipboard, ['ss://FAKE-CREDENTIAL@h:1']);
    expect(find.textContaining('ss://'), findsNothing,
        reason: 'a live credential on screen is one screenshot from being '
            'someone else\'s');
    expect(find.textContaining('FAKE-CREDENTIAL'), findsNothing);
    expect(find.textContaining('Link copied'), findsOneWidget,
        reason: 'and the user has to be told it worked');
  });

  testWidgets('a refusal is shown, without the link in it', (tester) async {
    final clipboard = captureClipboard();
    await pumpCopyLink(
        tester,
        () async =>
            throw StateError("this profile's password file is missing"));

    await tester.tap(find.byKey(const Key('confirm-copy')));
    await tester.pumpAndSettle();

    expect(tester.takeException(), isNull,
        reason: 'a failure here must reach the user, not the console');
    expect(find.textContaining('password file is missing'), findsOneWidget);
    expect(find.textContaining('ss://'), findsNothing);
    expect(clipboard, isEmpty);
  });

  test('the link carries the password the tunnel uses, not the file\'s bytes',
      () async {
    // `echo hunter2 > pw` — literally the case the core's
    // `strip_one_trailing_line_ending` is documented for, and what the README
    // sanctions. `FileSecretStore::resolve` reads that as `hunter2`, so that
    // is what the helper connects with. Reading the raw string here produced a
    // link whose password was `hunter2\n`: another client derives a different
    // key, the server drops the ciphertext, and Shadowsocks has no handshake
    // in which to say why. The link is silently wrong, and other clients
    // accepting it is the entire point of the feature.
    //
    // A plain `test`, because `ssLinkFor` crosses the FFI twice and those
    // futures never complete in a `testWidgets` fake-async zone.
    final dir = Directory.systemTemp.createTempSync('lios-link-newline');
    addTearDown(() => dir.deleteSync(recursive: true));
    final secret = '${dir.path}/pw';
    File(secret).writeAsStringSync('hunter2\n');

    final link = await ssLinkFor(ssProfile(source: 'file:$secret'));
    expect(await ssUriPassword(uri: link), 'hunter2',
        reason: 'the value of a file: secret is the core\'s, not the file\'s');
  });

  test('a secret file that is not text is refused in the app\'s own words',
      () async {
    // `ProfileWriter._readSecretFile` records this exact lesson one menu item
    // over: a credential that is not text came back out of `readAsStringSync`
    // as a decode failure about byte offsets, from a gesture that said
    // "duplicate", for a profile with nothing wrong with it. `exportSsUri`
    // takes a String, so a refusal is the honest outcome either way — but it
    // has to be a sentence this app wrote.
    final dir = Directory.systemTemp.createTempSync('lios-link-binary');
    addTearDown(() => dir.deleteSync(recursive: true));
    final secret = '${dir.path}/psk';
    File(secret).writeAsBytesSync([0x00, 0xff, 0xfe, 0x80]);

    final e = await ssLinkFor(ssProfile(source: 'file:$secret'))
        .then<Object?>((_) => null, onError: (Object e) => e);
    expect(e, isNotNull, reason: 'a binary credential cannot become a link');
    expect('$e', contains('not text'));
    expect('$e', isNot(contains('utf-8')),
        reason: 'not a UTF-8 decoder\'s complaint about byte offsets');
    expect('$e', isNot(contains(secret)),
        reason: 'and the decoder\'s version named the secret file too');
  });
}

// --- deleting from the list -----------------------------------------------
// These pump the real `HomePage`, because the three defects below live in the
// wiring rather than in either screen: what the menu entry does, and what the
// page still holds afterwards.

/// Pumps the real [HomePage] against a throwaway profiles directory.
///
/// `runAsync` around the first pump because `_reload` awaits `parseProfile`
/// across the FFI, and a `testWidgets` fake-async zone never completes that —
/// the list would stay empty for the whole test and every assertion below
/// would be vacuous.
///
/// The socket path is inside the temp directory, so nothing is listening on
/// it: `_attach` fails into the error banner rather than reaching a helper
/// that may genuinely be running on the machine running the suite.
Future<void> pumpHome(WidgetTester tester, String directory) async {
  tester.view.physicalSize = const Size(1200, 2400);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);
  await tester.runAsync(() async {
    await tester.pumpWidget(wrap(
      ConnectionModel(),
      HomePage(
        profilesDirectory: directory,
        socketPath: '$directory/nobody-is-listening.sock',
      ),
    ));
    await Future<void>.delayed(const Duration(milliseconds: 500));
  });
  await tester.pumpAndSettle();
}

/// Opens a row's overflow menu and chooses [entry].
Future<void> chooseInMenu(
  WidgetTester tester,
  String path,
  String entry,
) async {
  await tester.tap(find.byKey(ValueKey('menu-$path')));
  await tester.pumpAndSettle();
  await tester.tap(find.text(entry));
  await tester.pumpAndSettle();
}

void deleteTests() {
  testWidgets('the menu asks before deleting, and Cancel deletes nothing',
      (tester) async {
    // The same action behind the editor's Delete button was already guarded by
    // a dialog; this one — one tap, in a menu whose other three entries are
    // harmless, and the *more* accidental affordance of the two — was not. The
    // profile document is the only copy and there is no undo.
    final dir = Directory.systemTemp.createTempSync('lios-home-cancel');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/home.json';
    File(path).writeAsStringSync(sample);

    await pumpHome(tester, dir.path);
    expect(find.text('Home VPS'), findsOneWidget, reason: 'precondition');

    await chooseInMenu(tester, path, 'Delete');
    expect(find.text('Delete "Home VPS"?'), findsOneWidget,
        reason: 'it must name the profile, as the editor\'s dialog does');
    expect(find.textContaining('left where it is'), findsOneWidget,
        reason: 'and say the thing the user cannot otherwise know: the key '
            'or password file it points at survives');

    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();

    expect(File(path).existsSync(), isTrue);
    expect(find.text('Home VPS'), findsOneWidget);
  });

  testWidgets('deleting the selected profile lets go of it', (tester) async {
    // `_selected` held the in-memory DTO, and the Connection screen's guard is
    // `selected?.profile == null`. So after a delete the profile was still
    // named there and Connect was still enabled; pressing it read a file that
    // is gone, and `applyError` fell through to `Fault.internal` — the generic
    // internal-error wording, for a profile the user deleted themselves.
    // `_openEditor`'s `onSaved` does exactly this, twelve lines above, with
    // the reason written out.
    final dir = Directory.systemTemp.createTempSync('lios-home-selected');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/home.json';
    File(path).writeAsStringSync(sample);

    await pumpHome(tester, dir.path);
    // Tapping a row selects it and jumps to the Connection tab.
    await tester.tap(find.text('Home VPS'));
    await tester.pumpAndSettle();
    expect(find.text('Connect'), findsOneWidget, reason: 'precondition');
    final before = tester.widget<FilledButton>(
      find.byKey(const Key('connect-button')),
    );
    expect(before.onPressed, isNotNull,
        reason: 'precondition: the connection screen is holding it');

    await tester.tap(find.text('Profiles'));
    await tester.pumpAndSettle();
    await chooseInMenu(tester, path, 'Delete');
    // Through `pressAndSettle`: the reload behind the delete crosses the FFI.
    await pressAndSettle(tester, const Key('confirm-delete'));

    expect(File(path).existsSync(), isFalse, reason: 'it really was deleted');
    expect(find.text('Home VPS'), findsNothing, reason: 'and the list reloaded');

    await tester.tap(find.text('Connection'));
    await tester.pumpAndSettle();
    expect(find.text('No profile selected'), findsOneWidget);
    final after = tester.widget<FilledButton>(
      find.byKey(const Key('connect-button')),
    );
    expect(after.onPressed, isNull,
        reason: 'Connect on a deleted profile can only produce the generic '
            'internal-error wording');
  });

  testWidgets('a delete that fails says so, and leaves the row', (tester) async {
    // `_deleteQuietly` guards `existsSync` and then calls `deleteSync`, which
    // still throws on a permission failure or a file removed between the two.
    // With no `try/catch` the exception escaped an unawaited async callback:
    // no toast, no reload, the row stayed, and the user got no signal at all.
    // `onDuplicate`, immediately above, already had the right shape.
    final dir = Directory.systemTemp.createTempSync('lios-home-refused');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/home.json';
    File(path).writeAsStringSync(sample);

    await pumpHome(tester, dir.path);
    expect(find.text('Home VPS'), findsOneWidget, reason: 'precondition');

    // Readable and listable, so the profile still loads; not writable, so the
    // unlink is refused. Registered after the directory's own teardown so it
    // runs BEFORE it — tearDowns run in reverse.
    Process.runSync('chmod', ['500', dir.path]);
    addTearDown(() => Process.runSync('chmod', ['700', dir.path]));

    await chooseInMenu(tester, path, 'Delete');
    await pressAndSettle(tester, const Key('confirm-delete'));

    expect(tester.takeException(), isNull,
        reason: 'the failure must reach the user, not the console');
    expect(find.byType(SnackBar), findsOneWidget);
    expect(File(path).existsSync(), isTrue);
    expect(find.text('Home VPS'), findsOneWidget,
        reason: 'the profile is still on disk, so the row must still be there');
  });

  testWidgets('the editor asks the same question, and Cancel keeps the file',
      (tester) async {
    // The other call site of the shared dialog. Two copies of a confirmation
    // drift, and the one that drifts is the one nothing asserts.
    final dir = Directory.systemTemp.createTempSync('lios-editor-delete');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/ss.json';
    File(path).writeAsStringSync('{}');

    await pumpEditor(tester,
        directory: dir.path, existing: ssProfile(path: path, name: 'SS'));
    await tester.tap(find.byKey(const Key('delete-button')));
    await tester.pumpAndSettle();

    expect(find.text('Delete "SS"?'), findsOneWidget);
    expect(find.textContaining('left where it is'), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(File(path).existsSync(), isTrue);
  });
}

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
///
/// [name] and [host] are parameters because the profiles list searches on
/// both, and telling two profiles apart in that test needs two of each.
LoadedProfile ssProfile({
  String cipher = 'aes-256-gcm',
  List<String> dns = const ['1.1.1.1'],
  String path = '/tmp/ss.json',
  String source = 'file:/tmp/ss-key',
  String name = 'SS',
  String host = '198.51.100.7',
}) =>
    LoadedProfile(
      path: path,
      profile: ProfileDto(
        id: ssProfileId,
        name: name,
        protocol: 'shadowsocks',
        host: host,
        port: 8388,
        authKind: 'shadowsocks',
        authSecretSource: source,
        cipher: cipher,
        dnsMode: 'tcp',
        dnsServers: dns,
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      ),
    );

const ssProfileId = 'b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f';

/// A saved SSH profile whose credential is a private key file.
LoadedProfile sshProfile({required String path, required String keyPath}) =>
    LoadedProfile(
      path: path,
      profile: ProfileDto(
        id: '11111111-2222-3333-4444-555555555555',
        name: 'Home VPS',
        protocol: 'ssh',
        host: '198.51.100.9',
        port: 22,
        authKind: 'private_key',
        authSecretSource: 'file:$keyPath',
        dnsMode: 'tcp',
        dnsServers: const ['1.1.1.1'],
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      ),
    );

/// A saved profile whose DoH endpoint is wrong in a way only the helper's own
/// check catches.
///
/// [dohPath] without a leading `/` is refused by `check_profile` — and by
/// `ServerProfile::validate` after it — but not by anything in the DTO
/// conversion, so it survives as far as the save. [sshUser] is filled in
/// because the SSH username field is required and an edit loads it from the
/// sidecar: without it the form's own validator refuses the save before
/// `checkProfile` is ever reached.
LoadedProfile dohProfile({
  required String path,
  required String dohPath,
  required String secretPath,
}) =>
    LoadedProfile(
      path: path,
      sshUser: 'someone',
      profile: ProfileDto(
        id: '22222222-3333-4444-5555-666666666666',
        name: 'DoH VPS',
        protocol: 'ssh',
        host: '198.51.100.11',
        port: 22,
        authKind: 'password',
        authSecretSource: 'file:$secretPath',
        dnsMode: 'https',
        dohSni: 'cloudflare-dns.com',
        dohPath: dohPath,
        dnsServers: const ['1.1.1.1'],
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      ),
    );

/// A live `ss://` link. The password is only ever in this file's memory and
/// in the 0600 file the editor writes under a temp directory.
String ssLink({
  int port = 8388,
  String? tag,
  String host = '198.51.100.7',
  String password = 'hunter2',
}) {
  final creds = base64Url
      .encode(utf8.encode('aes-256-gcm:$password'))
      .replaceAll('=', '');
  return 'ss://$creds@$host:$port${tag == null ? '' : '#$tag'}';
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

/// The decoration a form field was built with.
///
/// Read off the widget rather than looked for on screen: a hint is only
/// painted while the field is empty, and a label like "Pre-shared key" is also
/// the text of a dropdown entry, so `find.text` cannot say which one it found.
InputDecoration decorationOf(WidgetTester tester, Key key) => tester
    .widget<TextField>(
      find.descendant(of: find.byKey(key), matching: find.byType(TextField)),
    )
    .decoration!;

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
    // Every OTHER required field is filled in, and the assertion is
    // `findsOneWidget`. Three fields are empty on a fresh editor -- host, SSH
    // username and the path to the secret -- so `findsWidgets` on a form
    // where none of them had been touched was true whether the host had a
    // validator or not: deleting it left this green.
    await pumpEditor(tester);
    await tester.enterText(find.byKey(const Key('f-user')), 'someone');
    await tester.enterText(
        find.byKey(const Key('f-secret-path')), '/tmp/lios-not-read');
    await tester.enterText(find.byKey(const Key('f-host')), '');
    await tester.tap(find.byKey(const Key('save-button')));
    await tester.pump();
    expect(find.text('required'), findsOneWidget,
        reason: 'the host, and only the host, is what is missing');
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
    //
    // `_import` writes nothing at all now (see 'an import that is never saved
    // leaves the live credential alone'), so the secrets-directory assertion
    // below can no longer fail on its own — it is kept as a guard against an
    // eager write coming back. What still discriminates here is the refusal
    // itself, and its wording: delete `check_cipher` from `import_ss_uri` and
    // the error card does not appear.
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
    //
    // Driven on a NEW profile because the paste box is create-only now (see
    // 'an edit has no link row'). The DNS the import must not touch is
    // therefore one the user typed rather than one `initState` loaded, which
    // is the same value from `_import`'s point of view -- it reads `_dns`
    // either way -- and it is what a user pasting a provider's link into a
    // fresh profile actually has in front of them.
    final dir = Directory.systemTemp.createTempSync('lios-editor-dns');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await tester.tap(find.byKey(const Key('advanced-section')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('f-dns')), '9.9.9.9');

    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());
    await pressAndSettle(tester, const Key('import-button'));

    expect(find.byKey(const Key('editor-error')), findsNothing);
    // The name is what the import demonstrably changes -- the default
    // 'My server' becomes the link's own label.
    expect(fieldText(tester, const Key('f-name')), '198.51.100.7:8388',
        reason: 'the import did happen');
    expect(fieldText(tester, const Key('f-dns')), '9.9.9.9',
        reason: 'the link says nothing about DNS');
    // This test used to also pin "an edit reuses its own id rather than the
    // one the import minted", by asserting `f-secret-path` ended with
    // `ssProfileId`. An edit can no longer reach `_import` at all, so that
    // assertion had no gesture behind it. The surviving half of the same
    // invariant -- one id, and so one secret file, across repeated imports --
    // is held by 're-importing to fix a typo keeps one id, and one secret
    // file'.
  });

  testWidgets('an import that is never saved leaves the live credential alone',
      (tester) async {
    // `writeSecret` truncates `secrets/<slug(id)>`, and `_importedId` is held
    // across imports -- so the second import in this test names the very file
    // the profile just saved points at. Running the write inside `_import`
    // destroyed that credential the instant the button was pressed: before
    // `checkNameFree`, before `checkProfile`, before Save. Paste what you
    // believe is the rotated link, see that the host is wrong, press Back:
    // nothing was saved and the original password is gone, unrecoverably,
    // because it came from a link.
    //
    // This is verbatim the defect the Save button already had (see 'a refused
    // save does not destroy the credential it points at'); the fix was never
    // applied one button over.
    //
    // Reached by saving first rather than by opening an existing profile: the
    // paste box is create-only now (see 'an edit has no link row'), so the
    // one way to have `_import` aim at a live secret file is to have this
    // editor write one. The state the defect needs is identical -- a 0600
    // file on disk that `_importedId` resolves to -- and this route is one a
    // user reaches by correcting a link right after saving it.
    final dir = Directory.systemTemp.createTempSync('lios-editor-import-live');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());
    await pressAndSettle(tester, const Key('import-button'));
    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-saved')), findsOneWidget,
        reason: 'precondition: there is a live credential on disk to lose');
    final secretPath = fieldText(tester, const Key('f-secret-path'));
    expect(File(secretPath).readAsStringSync(), 'hunter2');

    // A link the user believes is a rotation but which names the wrong host.
    await tester.enterText(
        find.byKey(const Key('f-uri')),
        ssLink(host: '203.0.113.9', password: 'pasted-by-mistake'));
    await pressAndSettle(tester, const Key('import-button'));

    expect(find.byKey(const Key('editor-error')), findsNothing);
    expect(fieldText(tester, const Key('f-host')), '203.0.113.9',
        reason: 'the import did happen; without this the rest is vacuous');
    expect(fieldText(tester, const Key('f-secret-path')), secretPath,
        reason: 'and it is aimed at the live file; without this the '
            'assertion below is about a path nothing writes to');

    // ...and the user presses Back rather than Save.
    expect(File(secretPath).readAsStringSync(), 'hunter2',
        reason: 'an import that was never saved must not have replaced the '
            'credential the on-disk profile still points at');
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

  testWidgets('a link the import never consumed refuses the save',
      (tester) async {
    // The user pastes link B to rotate a password and presses Save instead of
    // Import. The old guard was `if (_importedId != null) _uri.clear()`, and
    // `_importedId` is never reset — so after ONE import it is permanently
    // true: B was silently cleared, the profile kept A's credential, and a
    // green "Saved to …" said it had worked. The next connect fails eight
    // seconds into a probe, over a password the user is certain they changed.
    //
    // The previous version of this test never imported at all, so the guard
    // was trivially false and the fixture could not reach the branch it was
    // named after. This one imports first, which is the state the guard is
    // wrong in.
    //
    // Refusing rather than saving-and-keeping-the-text: a save that quietly
    // ignores a credential in front of the user is the failure, and the box
    // staying full is a signal nobody is obliged to notice.
    final dir = Directory.systemTemp.createTempSync('lios-editor-clear');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(tag: 'A'));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing,
        reason: 'precondition: one import really did happen');

    // Link B, pasted and never imported.
    final b = ssLink(port: 8389, tag: 'B', password: 'rotated');
    await tester.enterText(find.byKey(const Key('f-uri')), b);
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-saved')), findsNothing,
        reason: 'a save that would ignore a pasted credential must not '
            'report success');
    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    expect(fieldText(tester, const Key('f-uri')), b,
        reason: 'the link is still the user\'s; it was not consumed');
    final message = tester
        .widget<Text>(find.descendant(
          of: find.byKey(const Key('editor-error')),
          matching: find.byType(Text),
        ))
        .data!;
    expect(message, contains('Import from link'),
        reason: 'it must name the button that would use it');
    expect(message, isNot(contains('rotated')),
        reason: 'the link IS the password; the message may not quote it');
  });

  testWidgets('an imported link is consumed, and saves without complaint',
      (tester) async {
    // The other half, and the reason the guard above cannot simply be "refuse
    // whenever this is a Shadowsocks profile": once the import HAS taken the
    // link, the save must go through. The box being empty is what says so —
    // and it is `_import` that empties it, so this pins that too. The
    // credential must not stay legible on screen through the save either.
    final dir = Directory.systemTemp.createTempSync('lios-editor-clear2');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());
    await pressAndSettle(tester, const Key('import-button'));
    expect(fieldText(tester, const Key('f-uri')), isEmpty,
        reason: 'the import consumed it');
    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);
    expect(fieldText(tester, const Key('f-uri')), isEmpty);
  });

  testWidgets('the auth dropdown cannot turn an SSH profile into a '
      'Shadowsocks one', (tester) async {
    // Pick "Shadowsocks" in f-auth on an SSH profile and Save, and
    // `check_profile` passed: protocol became `shadowsocks`, the password
    // file stayed the SSH private key the profile already named, and the
    // cipher was whatever `_cipher` had defaulted to — the exact "pick a
    // cipher on the user's behalf" that `dto/profile.rs` refuses to do,
    // arrived at from the other side. Shadowsocks has no handshake, so the
    // result saves cleanly and then carries nothing.
    //
    // The reverse was a dead end rather than a hazard: no protocol control
    // exists, so a Shadowsocks profile could never move off `shadowsocks`,
    // and `check_pairing`'s refusal reads "ssh takes a password or a private
    // key…" — advice about a control the user does not have.
    final dir = Directory.systemTemp.createTempSync('lios-editor-convert');
    addTearDown(() => dir.deleteSync(recursive: true));
    final keyPath = '${dir.path}/id_ed25519';
    File(keyPath).writeAsStringSync('-----BEGIN OPENSSH PRIVATE KEY-----');

    await pumpEditor(tester,
        directory: dir.path,
        existing: sshProfile(path: '${dir.path}/home.json', keyPath: keyPath));
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-saved')), findsNothing);
    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    final message = tester
        .widget<Text>(find.descendant(
          of: find.byKey(const Key('editor-error')),
          matching: find.byType(Text),
        ))
        .data!;
    expect(message, contains('ssh'));
    expect(message, contains('shadowsocks'));
    expect(message, contains('new profile'),
        reason: 'the wording has to name a remedy the user can actually reach');
    expect(
        Directory(dir.path)
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.json')),
        isEmpty,
        reason: 'nothing may reach disk');
    expect(File(keyPath).readAsStringSync(),
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        reason: 'and the SSH key it named is not a Shadowsocks password');
  });

  testWidgets('a Shadowsocks profile leaves no SSH username sidecar',
      (tester) async {
    // `_user` was passed to `writeProfile` unconditionally, so typing a
    // username and then switching to Shadowsocks wrote a `.user` sidecar for
    // a protocol that has no user — a connect-time parameter the helper will
    // read and hand to nothing.
    final dir = Directory.systemTemp.createTempSync('lios-editor-sidecar');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-name')), 'Manual');
    await tester.enterText(find.byKey(const Key('f-host')), '198.51.100.7');
    await tester.enterText(find.byKey(const Key('f-port')), '8388');
    await tester.enterText(find.byKey(const Key('f-user')), 'someone');
    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    await tester.enterText(
        find.byKey(const Key('f-secret-path')), '${dir.path}/key');
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-saved')), findsOneWidget);
    expect(
        Directory(dir.path)
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.user')),
        isEmpty,
        reason: 'shadowsocks has no username to send');
  });

  testWidgets('re-importing to fix a typo keeps one id, and one secret file',
      (tester) async {
    // `writeSecret` names the file after the id it is given, so an id minted
    // fresh on each import used to leave a live password on disk that no
    // profile referenced -- deletion deliberately never touches secret files,
    // and nothing collects them.
    //
    // The write is deferred to Save now (see 'an import that is never saved
    // leaves the live credential alone'), so a second paste can no longer
    // leave a file behind at all. `_importedId` still has to be stable, and
    // for a sharper reason: `_save` mints an id of its own when it is null,
    // and the file it then writes is not the one `f-secret-path` -- and so
    // the saved profile -- names. The profile would point at a file that does
    // not exist.
    final dir = Directory.systemTemp.createTempSync('lios-editor-reimport');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await choose(tester, const Key('f-auth'), 'Shadowsocks');

    await tester.enterText(find.byKey(const Key('f-uri')),
        ssLink(port: 8388, password: 'first-paste'));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    final first = fieldText(tester, const Key('f-secret-path'));

    // The user notices the port is wrong and pastes the corrected link.
    await tester.enterText(find.byKey(const Key('f-uri')),
        ssLink(port: 8389, password: 'second-paste'));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    final second = fieldText(tester, const Key('f-secret-path'));

    expect(second, first, reason: 'the second import must reuse the first id');

    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);

    final secrets = Directory('${dir.path}/secrets').listSync();
    expect(secrets.length, 1,
        reason: 'exactly one secret file, not one per paste');
    expect(secrets.single.path, second,
        reason: 'and it is the one the form -- and so the profile -- names');
    expect(File(secrets.single.path).readAsStringSync(), 'second-paste',
        reason: 'the credential saved is the one the last import took');
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
    final secretPath =
        ProfileWriter(directory: dir.path).secretPathFor(ssProfileId);
    File(secretPath).parent.createSync(recursive: true);
    File(secretPath).writeAsStringSync('hunter2');

    // The refusal has to come from `checkProfile` and from nothing earlier,
    // or this test cannot see the ordering it is named after. It used to use
    // an auth-kind switch, which `_refuseAProtocolChange` now catches on the
    // first line of `_save` -- before `writeSecret` could have run either
    // way, so the assertion below would have held no matter where the write
    // sat. A cipher this build cannot construct is refused by `check_profile`
    // itself, which is exactly one step *after* the write.
    await pumpEditor(
      tester,
      directory: dir.path,
      existing: ssProfile(
        path: '${dir.path}/ss.json',
        source: 'file:$secretPath',
        cipher: '2022-blake3-aes-256-gcm',
      ),
    );

    await choose(
        tester, const Key('f-secret-mode'), 'Type it — save to a 0600 file');
    await tester.enterText(find.byKey(const Key('f-secret')), 'overwritten');
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    expect(find.byKey(const Key('editor-saved')), findsNothing);
    expect(File(secretPath).readAsStringSync(), 'hunter2',
        reason: 'a refused save must not have written the secret');
  });

  testWidgets('a new profile leads with the link row, without a dropdown first',
      (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-linkrow');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);
    // Present immediately: _authKind defaults to 'password', and requiring
    // the user to find Shadowsocks in a dropdown before they can paste a
    // link is backwards -- importing is what decides the protocol.
    expect(find.byKey(const Key('f-uri')), findsOneWidget);
    expect(find.byKey(const Key('import-button')), findsOneWidget);
  });

  testWidgets('an edit has no link row', (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-linkrow2');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path, existing: ssProfile());
    expect(find.byKey(const Key('f-uri')), findsNothing,
        reason: 'you are not re-importing a profile that exists');
  });

  testWidgets('importing works without touching the auth dropdown',
      (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-linkrow3');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink());
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    expect(fieldText(tester, const Key('f-host')), '198.51.100.7');
    // And the cipher control is now present, because the import chose the
    // protocol.
    expect(find.byKey(const Key('f-cipher')), findsOneWidget);
  });

  testWidgets('a link nobody imported refuses the save, whatever the auth '
      'dropdown says', (tester) async {
    // The guard that catches a pasted-but-not-imported link was written when
    // the box only existed under `_authKind == 'shadowsocks'`, and it tested
    // for exactly that. The box is now on screen for every new profile, so
    // that condition would let the commonest case through: paste a link,
    // fill nothing else in, press Save -- and the link is silently dropped
    // while a green "Saved to ..." says otherwise. The box being visible is
    // what the guard has to key on.
    final dir = Directory.systemTemp.createTempSync('lios-linkrow4');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);
    // Everything the form needs to save as a plain SSH/password profile...
    await tester.enterText(find.byKey(const Key('f-host')), '198.51.100.9');
    await tester.enterText(find.byKey(const Key('f-user')), 'someone');
    await tester.enterText(
        find.byKey(const Key('f-secret-path')), '${dir.path}/key');
    // ...and a link the user pasted and expected to be used.
    await tester.enterText(
        find.byKey(const Key('f-uri')), ssLink(password: 'never-imported'));
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-saved')), findsNothing,
        reason: 'a save that would ignore a pasted credential must not '
            'report success');
    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    final message = tester
        .widget<Text>(find.descendant(
          of: find.byKey(const Key('editor-error')),
          matching: find.byType(Text),
        ))
        .data!;
    expect(message, contains('Import from link'),
        reason: 'it must name the button that would use it');
    expect(message, isNot(contains('never-imported')),
        reason: 'the link IS the password; the message may not quote it');
  });

  testWidgets('DNS settings are collapsed until asked for', (tester) async {
    final dir = Directory.systemTemp.createTempSync('lios-adv');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);
    expect(find.byKey(const Key('f-dns')), findsNothing,
        reason: 'set once and forgotten; it should not compete with the '
            'fields you actually edit');
    await tester.tap(find.byKey(const Key('advanced-section')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('f-dns')), findsOneWidget);
  });

  testWidgets('the credential field names what it actually is', (tester) async {
    // The private-key half of this test used to type a key into `f-secret`,
    // which is the gesture 'a private key cannot be typed into one obscured
    // line' now refuses outright; what a key is called is asserted on the path
    // field instead, by 'the path field names the credential it points at'.
    final dir = Directory.systemTemp.createTempSync('lios-label');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);

    await choose(
        tester, const Key('f-secret-mode'), 'Type it — save to a 0600 file');
    expect(decorationOf(tester, const Key('f-secret')).labelText, 'Password');

    // WireGuard's pre-shared key is not a password. It is one line of base64,
    // so unlike a private key it can honestly be typed here — which is why
    // this case keeps the typed field and the private-key one does not.
    await choose(tester, const Key('f-auth'), 'Pre-shared key');
    expect(decorationOf(tester, const Key('f-secret')).labelText,
        'Pre-shared key',
        reason: 'a WireGuard pre-shared key called "Password" is the same '
            'mislabelling one credential over');

    await choose(tester, const Key('f-auth'), 'Shadowsocks');
    expect(decorationOf(tester, const Key('f-secret')).labelText, 'Password');
  });

  testWidgets('a private key cannot be typed into one obscured line',
      (tester) async {
    // `_text` builds a one-line field, and it cannot be made multi-line while
    // it is obscured: `TextField` asserts `!obscureText || maxLines == 1`, so
    // the only way to accept a pasted OpenSSH key here would be to render key
    // material legibly on screen. Offering "type it" for a key therefore
    // invites a paste whose newlines are dropped on the way in — `writeSecret`
    // writes the mangled blob, `check_profile` sees a well-formed
    // (Ssh, PrivateKey) pairing, the save reports success, and the failure
    // arrives at connect time from another process.
    //
    // A key you already have IS a file, which is exactly what the other mode
    // is for, so nothing is lost by removing the option.
    final dir = Directory.systemTemp.createTempSync('lios-keymode');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);

    // Switched to the typed mode FIRST, so the auth change has to pull the
    // mode back with it: `DropdownButtonFormField` asserts that exactly one
    // item matches its value, and a value of `typed` beside items that no
    // longer offer it turns the whole form into an ErrorWidget — the same
    // assertion the Cipher dropdown already has to dodge.
    await choose(
        tester, const Key('f-secret-mode'), 'Type it — save to a 0600 file');
    await choose(tester, const Key('f-auth'), 'Private key');
    expect(tester.takeException(), isNull,
        reason: 'the form must survive the mode it was left in');

    expect(find.byKey(const Key('f-secret')), findsNothing,
        reason: 'a key that fits on one obscured line is not a key');
    expect(find.byKey(const Key('f-secret-path')), findsOneWidget,
        reason: 'and the file it lives in is what the form should ask for');

    await tester.tap(find.byKey(const Key('f-secret-mode')));
    await tester.pumpAndSettle();
    expect(find.text('Type it — save to a 0600 file'), findsNothing,
        reason: 'the option has to be gone, not merely unselected — a label '
            'that invites a gesture the field cannot support is the defect');
  });

  testWidgets('the path field names the credential it points at',
      (tester) async {
    // One field, three credentials. Unconditional text sent a Shadowsocks
    // password to `/Users/you/.ssh/id_ed25519`, which is advice, not a
    // placeholder.
    final dir = Directory.systemTemp.createTempSync('lios-pathlabel');
    addTearDown(() => dir.deleteSync(recursive: true));
    await pumpEditor(tester, directory: dir.path);

    expect(decorationOf(tester, const Key('f-secret-path')).labelText,
        'Path to the password file');
    expect(decorationOf(tester, const Key('f-secret-path')).hintText,
        isNot(contains('id_ed25519')),
        reason: 'a password does not live in an SSH key file');

    await choose(tester, const Key('f-auth'), 'Private key');
    expect(decorationOf(tester, const Key('f-secret-path')).labelText,
        'Path to the key file');
    expect(decorationOf(tester, const Key('f-secret-path')).hintText,
        '/Users/you/.ssh/id_ed25519');

    await choose(tester, const Key('f-auth'), 'Pre-shared key');
    expect(decorationOf(tester, const Key('f-secret-path')).labelText,
        'Path to the pre-shared key file');
  });

  testWidgets('a refusal about DNS opens the section that hides the field',
      (tester) async {
    // Not a data problem: `check_profile` validates the DoH path (twice, in
    // fact — `ServerProfile::validate` does it again), and `_save` calls it
    // before `writeSecret` and before `writeProfile`. Every field the collapse
    // un-validates has a server-side twin that runs before the first byte is
    // written.
    //
    // What the collapse can do is put the refusal and the field it names on
    // opposite sides of a closed section: the user reads "the DoH path must
    // start with `/`" over a form with no DoH path on it.
    //
    // Fixed by opening the section, NOT by `maintainState: true`. Keeping the
    // children alive behind the collapse would have the form's own validator
    // refuse from somewhere invisible, so Save would do nothing at all and say
    // nothing either — worse than the error card.
    final dir = Directory.systemTemp.createTempSync('lios-adv-doh');
    addTearDown(() => dir.deleteSync(recursive: true));
    final secretPath = '${dir.path}/pw';
    File(secretPath).writeAsStringSync('hunter2');

    await pumpEditor(
      tester,
      directory: dir.path,
      existing: dohProfile(
        path: '${dir.path}/doh.json',
        dohPath: 'dns-query',
        secretPath: secretPath,
      ),
    );
    expect(find.byKey(const Key('f-doh-path')), findsNothing,
        reason: 'precondition: the field is behind the collapse');

    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-saved')), findsNothing);
    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    final message = tester
        .widget<Text>(find.descendant(
          of: find.byKey(const Key('editor-error')),
          matching: find.byType(Text),
        ))
        .data!;
    expect(message, contains('DoH path'),
        reason: 'precondition: the refusal is about a field Advanced hides');
    expect(find.byKey(const Key('f-doh-path')), findsOneWidget,
        reason: 'a refusal naming a field the form is hiding is one the user '
            'cannot act on');
    expect(fieldText(tester, const Key('f-doh-path')), 'dns-query',
        reason: 'and the value it is complaining about must be in front of '
            'them, editable');
  });

  testWidgets('saving a new profile twice under one name saves it twice, not '
      'once and then a refusal', (tester) async {
    // The editor did not adopt the profile it had just written, so
    // `widget.existing` stayed null and every Save was a CREATE. Pressing Save
    // a second time — because a field was wrong, or because the button was
    // tapped twice — therefore ran `checkNameFree` with no `replacingPath`,
    // found the file the same editor had written a moment earlier, and refused
    // with "a different profile is already called …" about the profile in
    // front of the user.
    final dir = Directory.systemTemp.createTempSync('lios-editor-twice-same');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(tag: 'Home'));
    await pressAndSettle(tester, const Key('import-button'));
    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-saved')), findsOneWidget,
        reason: 'precondition: the first save went through');

    await tester.enterText(find.byKey(const Key('f-host')), '203.0.113.9');
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-error')), findsNothing,
        reason: 'saving the same profile again is an edit of it, not a '
            'collision with it');
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);
    final jsons = Directory(dir.path)
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.json'))
        .toList();
    expect(jsons.length, 1);
    final doc =
        jsonDecode(jsons.single.readAsStringSync()) as Map<String, dynamic>;
    expect(doc['host'], '203.0.113.9',
        reason: 'and the second save is what landed');
  });

  testWidgets('saving a new profile twice under two names renames it, rather '
      'than cloning it onto one id', (tester) async {
    // Two `.json` files carrying the SAME `id` and the SAME
    // `auth_secret_source`. Editing either one's password in "Type it" mode
    // then silently changed both, because `writeSecret` keys the file on the
    // profile id — which is verbatim the failure `duplicate` writes its own
    // secret file to avoid, reached from the editor instead.
    //
    // The link-led flow is what makes the ids collide rather than merely
    // producing two profiles: `_importedId` persists across saves, so the
    // second save reuses it.
    final dir = Directory.systemTemp.createTempSync('lios-editor-twice-diff');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(tag: 'Home'));
    await pressAndSettle(tester, const Key('import-button'));
    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-saved')), findsOneWidget,
        reason: 'precondition: the first save went through');

    await tester.enterText(find.byKey(const Key('f-name')), 'Renamed');
    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);

    final jsons = Directory(dir.path)
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.json'))
        .toList();
    expect(jsons.length, 1,
        reason: 'a rename moves the profile; a second file carrying the same '
            'id and the same secret file is two profiles that edit each '
            "other's credential");
    expect(jsons.single.path, endsWith('/renamed.json'));

    final doc =
        jsonDecode(jsons.single.readAsStringSync()) as Map<String, dynamic>;
    final secrets = Directory('${dir.path}/secrets').listSync();
    expect(secrets.length, 1, reason: 'one profile, one secret file');
    expect(doc['auth']['password']['path'], secrets.single.path,
        reason: 'and the profile that survived names it');
    expect(secrets.single.path, endsWith(doc['id'] as String),
        reason: 'writeSecret keys on the id, so the surviving profile must '
            'carry the id its secret file is named after');
  });

  testWidgets('redirecting the secret path after an import refuses the save',
      (tester) async {
    // The password came out of an `ss://` link and is held in widget state
    // until Save has somewhere safe to put it — and the only place this app
    // can put it is the managed path `_import` filled in. Point the field at
    // a file of your own, expecting the app to create it, and the save used to
    // succeed with the write skipped: a green "Saved to …" over a profile
    // naming a file that does not exist, and a password that cannot be
    // retyped gone with the widget. It surfaced at connect time, from another
    // process, as "secret file … cannot read".
    //
    // Refused rather than written blindly: `writeSecret` overwrites the file
    // keyed to the id, and the user may well have redirected to a file that
    // already holds this very password — in which case discarding it is
    // correct. The app cannot tell, so it says so instead of guessing. Same
    // shape as the pasted-but-not-imported refusal above.
    final dir = Directory.systemTemp.createTempSync('lios-editor-redirect');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(tag: 'Home'));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing,
        reason: 'precondition: the import took the password out of the link');
    final managed = fieldText(tester, const Key('f-secret-path'));
    expect(managed, startsWith('${dir.path}/secrets/'),
        reason: 'precondition: the field holds the path Import filled in');

    // The user renames it to a file they intend the app to create.
    final chosen = '${dir.path}/home-pw';
    await tester.enterText(find.byKey(const Key('f-secret-path')), chosen);
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-saved')), findsNothing,
        reason: 'a save that would discard the imported password must not '
            'report success');
    expect(find.byKey(const Key('editor-error')), findsOneWidget);
    expect(
        Directory(dir.path)
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.json')),
        isEmpty,
        reason: 'no profile may be written naming a file nothing wrote');
    expect(File(chosen).existsSync(), isFalse,
        reason: 'and the refusal is a refusal: writing the password to the '
            'file the user named would be a write to a path this app does '
            'not manage');
    expect(fieldText(tester, const Key('f-secret-path')), chosen,
        reason: "the user's own text is not the form's to revert");

    final message = tester
        .widget<Text>(find.descendant(
          of: find.byKey(const Key('editor-error')),
          matching: find.byType(Text),
        ))
        .data!;
    expect(message, contains(managed),
        reason: 'it must name the path that would keep the password');
    expect(message, isNot(contains('hunter2')),
        reason: 'the message may not carry the credential it is about');
    expect(message, isNot(contains('ss://')));
  });

  testWidgets('an import saved to the path it filled in still writes the '
      'password', (tester) async {
    // The other half of the guard above, and the reason it cannot simply be
    // "refuse whenever a link has been imported": leaving the path alone is
    // the ordinary case and it must go through, with the password on disk.
    final dir = Directory.systemTemp.createTempSync('lios-editor-redirect2');
    addTearDown(() => dir.deleteSync(recursive: true));

    await pumpEditor(tester, directory: dir.path);
    await tester.enterText(find.byKey(const Key('f-uri')), ssLink(tag: 'Home'));
    await pressAndSettle(tester, const Key('import-button'));
    final managed = fieldText(tester, const Key('f-secret-path'));
    await pressAndSettle(tester, const Key('save-button'));

    expect(find.byKey(const Key('editor-error')), findsNothing);
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);
    expect(File(managed).readAsStringSync(), 'hunter2');
  });

  testWidgets('a profile that does not parse is opened for repair, link row '
      'and all', (tester) async {
    // `_editing` is "this profile parsed", not "this file exists" — and the
    // list offers Edit on a broken row deliberately, which is tested. So this
    // branch reaches the editor with `error` set and no profile, and it shows
    // the link row: re-importing IS a repair for a Shadowsocks profile nothing
    // can read, and the save guard covers the case where the box is left full.
    //
    // The save still replaces the file that is there. `existing.path` is what
    // `writeProfile` is told to replace, and it does not depend on the profile
    // having parsed — without that, repairing a broken profile would leave the
    // unreadable file in the list beside its replacement.
    final dir = Directory.systemTemp.createTempSync('lios-broken');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/broken.json';
    File(path).writeAsStringSync('{ this is not a profile');

    await pumpEditor(
      tester,
      directory: dir.path,
      existing: LoadedProfile(path: path, error: 'not a valid profile'),
    );

    expect(find.byKey(const Key('f-uri')), findsOneWidget,
        reason: 'a Shadowsocks profile nothing can read is repaired by '
            'pasting its link again');

    await tester.enterText(
        find.byKey(const Key('f-uri')), ssLink(tag: 'Repaired'));
    await pressAndSettle(tester, const Key('import-button'));
    expect(find.byKey(const Key('editor-error')), findsNothing);
    await pressAndSettle(tester, const Key('save-button'));
    expect(find.byKey(const Key('editor-saved')), findsOneWidget);

    expect(File(path).existsSync(), isFalse,
        reason: 'the broken file was being repaired, not kept beside its '
            'repair');
    expect(
        Directory(dir.path)
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.json'))
            .length,
        1,
        reason: 'one profile went in and one came out');
  });
}
