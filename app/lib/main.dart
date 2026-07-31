import 'dart:io';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'screens/connection.dart';
import 'screens/dialogs.dart';
import 'screens/profile_editor.dart';
import 'screens/profiles.dart';
import 'services/android_tunnel.dart';
import 'services/connection_model.dart';
import 'services/helper_client.dart';
import 'services/helper_install.dart';
import 'services/link_export.dart';
import 'services/profile_store.dart';
import 'services/profile_writer.dart';
import 'src/rust/api/android.dart';
import 'src/rust/api/protocol.dart';
import 'src/rust/frb_generated.dart';

/// Where the installer puts the helper's socket. Spec §7.1.
const kSocketPath = '/var/run/liostunnel.sock';

Future<void> main() async {
  // `defaultDirectory` reaches a platform channel on Android, which needs the
  // binding up first.
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  runApp(LiosApp(profilesDirectory: await ProfileStore.defaultDirectory()));
}

class LiosApp extends StatelessWidget {
  const LiosApp({super.key, this.profilesDirectory});

  /// Resolved once at startup rather than per-[ProfileStore], because on
  /// Android it can only be obtained asynchronously and every construction
  /// site here is synchronous.
  final String? profilesDirectory;

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => ConnectionModel(),
      child: MaterialApp(
        title: 'LiosTunnel',
        theme: ThemeData(useMaterial3: true),
        home: HomePage(profilesDirectory: profilesDirectory),
      ),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({
    super.key,
    this.profilesDirectory,
    this.socketPath = kSocketPath,
    this.installer,
    this.installsHelper,
  });

  /// Where profiles live. Null means the operator's own `~/.liostunnel`.
  ///
  /// A seam for tests and nothing else. This page deletes files, and a widget
  /// test that pumped it without one would do that in the directory the person
  /// running the suite keeps their real profiles in.
  final String? profilesDirectory;

  /// Where the helper listens.
  ///
  /// Overridable for the same reason: a test points it at a path nobody is
  /// listening on, so [_attach] fails into the error banner instead of
  /// reaching a helper that may genuinely be running on this machine.
  final String socketPath;

  /// Injected so no test raises a real authorization dialog.
  final Future<InstallResult> Function(int)? installer;

  /// Whether this platform installs the helper from the app at all.
  ///
  /// Null asks the platform, which is what production does — see
  /// [appInstallsHelper]. Overridden only by the tests that drive the Linux
  /// path on a machine that is not Linux; without that seam the once-only
  /// guard and the panel have no test on any machine this suite runs on,
  /// because the platform gate would answer first and every assertion would
  /// pass against its own defect.
  final bool? installsHelper;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _client = HelperClient();

  /// The in-process engine, on Android only. Null everywhere else, where the
  /// root helper owns the tunnel instead.
  AndroidTunnel? _android;
  late final _store = ProfileStore(directory: widget.profilesDirectory);
  late final _writer = ProfileWriter(directory: _store.directory);
  List<LoadedProfile> _profiles = const [];
  LoadedProfile? _selected;
  int _tab = 0;

  /// At most once per process launch. See [_installHelper].
  bool _installAttempted = false;
  String? _installCommandText;

  /// True while a privileged install is in flight.
  ///
  /// The panel names the command while the dialog is up — deliberately, so it
  /// can be read before it runs as root — which puts its button on screen at
  /// the one moment pressing it would raise a SECOND dialog over the first.
  /// Disabled rather than hidden: the command stays readable, which is the
  /// panel's other job.
  bool _installRunning = false;

  bool get _installsHelper => widget.installsHelper ?? appInstallsHelper();

  @override
  void initState() {
    super.initState();
    // Subscribed once, here, rather than inside `_attach`. A successful
    // install runs `_attach` a second time, and a second listener on the same
    // broadcast stream applies every event the helper pushes twice.
    final model = context.read<ConnectionModel>();
    if (AndroidTunnel.isSupported) {
      // No helper, no socket, and nothing to attach to: the engine is in this
      // process. Polled state and counters are turned into the same two events
      // the helper pushes, so `ConnectionModel` -- and live speed with it --
      // needs no Android-specific code.
      _android = AndroidTunnel();
      _android!.events.listen(
        (e) {
          model.applyEvent(StateEvent(_stateLabel(e.status)));
          model.applyEvent(
            StatsEvent(
              // The generated bindings give BigInt for every u64; only
              // `activeFlows` is an int on the helper's side.
              bytesUp: e.stats.bytesUp,
              bytesDown: e.stats.bytesDown,
              activeFlows: e.stats.activeFlows.toInt(),
              flowsFailed: e.stats.flowsFailed,
              dnsQueries: e.stats.dnsQueries,
            ),
          );
        },
        onError: model.applyError,
      );
      // Reflect a tunnel that is already running. `_attach` does this on
      // desktop by asking the helper for status; the engine here outlives the
      // Activity in exactly the same way, so the UI has to ask.
      _android!.attach();
    } else {
      _client.events.listen(model.applyEvent);
      _attach();
    }
    _reload();
  }

  /// One page for both, so creating and editing cannot drift apart.
  void _openEditor(LoadedProfile? existing) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => ProfileEditorScreen(
          writer: _writer,
          existing: existing,
          // Reload rather than patch the list in place: the store is the
          // truth, and a list built from what we *think* we wrote drifts from
          // what is on disk — which is what a rename would expose first.
          onSaved: () {
            _reload();
            // A profile that was renamed or deleted is no longer the one the
            // connection screen is holding.
            if (existing != null && _selected?.path == existing.path) {
              setState(() => _selected = null);
            }
          },
        ),
      ),
    );
  }

  Future<void> _reload() async {
    final loaded = await _store.load();
    if (mounted) setState(() => _profiles = loaded);
  }

  void _toast(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  /// Connects to the helper and asks it where things stand.
  ///
  /// Asking for status immediately is what makes a relaunched app re-sync to
  /// a tunnel that is still running rather than show Disconnected over a
  /// working one (P1a-4). The helper owns the tunnel; this only reflects it.
  ///
  /// Runs again after a first-launch install, so it must be safe to repeat —
  /// hence the event subscription living in [initState] instead.
  Future<void> _attach() async {
    final model = context.read<ConnectionModel>();
    try {
      await _client.connect(widget.socketPath);
      await _client.hello();
      await _client.getStatus();
    } catch (e) {
      model.applyError(e);
      // Only ENOENT, and only on Linux. `HelperForbidden` means the helper IS
      // installed, for somebody else. macOS is installed by its package.
      if (installWouldFix(e) && _installsHelper) await _installHelper();
    }
  }

  /// Installs the bundled helper under pkexec, raising the polkit dialog.
  ///
  /// Guarded by [_installAttempted] because a successful install sends the app
  /// straight back to [_attach] — where the socket may still be absent, the
  /// daemon not yet listening, the unit refused. Unguarded, that installs,
  /// retries, installs, retries, raising the dialog every time round: a loop
  /// the user cannot escape without force-quitting. A user who cancels has
  /// said no, and asking again unprompted is how an app becomes something you
  /// close. The panel's retry button is the way back, because that one was
  /// asked for.
  Future<void> _installHelper({bool force = false}) async {
    if (_installAttempted && !force) return;
    if (_installRunning) return;
    _installAttempted = true;
    final model = context.read<ConnectionModel>();
    final uid = currentUid();
    setState(() {
      _installCommandText = installCommand(uid);
      _installRunning = true;
    });
    model.installNotice =
        'Installing the privileged helper. Your system is asking for your '
        'password.';
    final run = widget.installer ?? runInstallPrivileged;
    final result = await run(uid);
    if (!mounted) return;
    setState(() => _installRunning = false);
    switch (result.outcome) {
      case InstallOutcome.installed:
        model.installNotice = null;
        setState(() => _installCommandText = null);
        await _attach();
      case InstallOutcome.cancelled:
      case InstallOutcome.failed:
        model.installNotice = result.message;
    }
  }

  /// Maps engine state onto the labels the desktop helper already sends, so
  /// the chip and `ConnectionModel`'s "not Connected clears the numbers" rule
  /// behave identically on both platforms.
  static String _stateLabel(EngineStatusDto s) => switch (s.state) {
    'connected' => 'Connected',
    'connecting' => 'Connecting',
    'failed' => 'Failed',
    _ => 'Disconnected',
  };

  Future<void> _connectAndroid(LoadedProfile selected) async {
    final model = context.read<ConnectionModel>();
    try {
      final secrets = await resolveSecrets(selected.profile!);
      await _android!.connect(
        profile: selected.profile!,
        // The account on the SERVER. Android has no USER environment
        // variable to fall back to, so an SSH profile without one is a
        // profile that cannot connect -- and saying so beats "credentials
        // rejected".
        user: selected.sshUser ?? '',
        secrets: secrets,
      );
    } catch (e) {
      model.applyError(e);
    }
  }

  Future<void> _connect() async {
    final model = context.read<ConnectionModel>();
    final selected = _selected;
    if (selected?.profile == null) return;
    if (_android != null) return _connectAndroid(selected!);
    try {
      await _client.sendConnect(
        ConnectParamsDto(
          // The helper re-parses this itself, after authorizing the caller, so
          // the document is passed through rather than reconstructed.
          profileJson: File(selected!.path).readAsStringSync(),
          // The account on the SERVER, not this machine's login. Falling
          // back to the local name is what made every connection to a host
          // whose account differs fail as "credentials rejected".
          user: selected.sshUser ?? Platform.environment['USER'] ?? '',
          routeMode: 'default',
          cidrs: const [],
          captureDns: true,
          tunAddress: '10.90.0.1',
        ),
      );
    } catch (e) {
      model.applyError(e);
    }
  }

  Future<void> _disconnect() async {
    final model = context.read<ConnectionModel>();
    try {
      if (_android != null) {
        await _android!.disconnect();
        return;
      }
      await _client.disconnect();
    } catch (e) {
      model.applyError(e);
    }
  }

  @override
  void dispose() {
    _android?.dispose();
    _client.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final screens = [
      ProfilesScreen(
        profiles: _profiles,
        directory: _store.directory,
        selectedPath: _selected?.path,
        onReload: _reload,
        onSelect: (p) => setState(() {
          _selected = p;
          _tab = 1;
        }),
        onCreate: () => _openEditor(null),
        onEdit: _openEditor,
        onDuplicate: (p) async {
          try {
            await _writer.duplicate(p);
            await _reload();
          } catch (e) {
            if (mounted) _toast('$e');
          }
        },
        // The producer is passed unevaluated: Cancel then returns without the
        // secret file having been opened at all.
        onCopyLink: (p) => confirmAndCopyLink(context, () => ssLinkFor(p)),
        // The only destructive entry in this menu, and the profile document is
        // the only copy: it asks first, through the same dialog the editor's
        // Delete button uses.
        onDelete: (p) async {
          if (!await confirmDeleteProfile(context, p.name)) return;
          try {
            await _writer.delete(p.path);
            // A profile that was deleted is no longer the one the connection
            // screen is holding — the same rule, and the same two lines, as
            // `_openEditor`'s `onSaved`. Without this the Connection tab still
            // named it and Connect was still enabled, because that guard is
            // `selected?.profile == null` and the DTO is still in memory.
            if (_selected?.path == p.path) setState(() => _selected = null);
            await _reload();
          } catch (e) {
            // `_deleteQuietly` checks `existsSync` and then calls
            // `deleteSync`, which still throws on a permission failure or a
            // file removed between the two. Unhandled, that escaped an
            // unawaited async callback: no toast, no reload, the row stayed,
            // and the user got no signal at all. Same shape as `onDuplicate`.
            if (mounted) _toast('$e');
          }
        },
      ),
      ConnectionScreen(
        selected: _selected,
        onConnect: _connect,
        onDisconnect: _disconnect,
        installCommandText: _installCommandText,
        onRetryInstall:
            _installRunning ? null : () => _installHelper(force: true),
      ),
    ];

    return Scaffold(
      body: screens[_tab],
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.list), label: 'Profiles'),
          NavigationDestination(
            icon: Icon(Icons.vpn_lock),
            label: 'Connection',
          ),
        ],
      ),
    );
  }
}
