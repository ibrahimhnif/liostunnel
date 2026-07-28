import 'dart:io';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'screens/connection.dart';
import 'screens/profiles.dart';
import 'services/connection_model.dart';
import 'services/helper_client.dart';
import 'services/profile_store.dart';
import 'src/rust/api/protocol.dart';
import 'src/rust/frb_generated.dart';

/// Where the installer puts the helper's socket. Spec §7.1.
const kSocketPath = '/var/run/liostunnel.sock';

Future<void> main() async {
  await RustLib.init();
  runApp(const LiosApp());
}

class LiosApp extends StatelessWidget {
  const LiosApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => ConnectionModel(),
      child: MaterialApp(
        title: 'LiosTunnel',
        theme: ThemeData(useMaterial3: true),
        home: const HomePage(),
      ),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _client = HelperClient();
  final _store = ProfileStore();
  List<LoadedProfile> _profiles = const [];
  LoadedProfile? _selected;
  int _tab = 0;

  @override
  void initState() {
    super.initState();
    _attach();
    _reload();
  }

  Future<void> _reload() async {
    final loaded = await _store.load();
    if (mounted) setState(() => _profiles = loaded);
  }

  /// Connects to the helper and mirrors everything it pushes into the model.
  ///
  /// Asking for status immediately is what makes a relaunched app re-sync to
  /// a tunnel that is still running rather than show Disconnected over a
  /// working one (P1a-4). The helper owns the tunnel; this only reflects it.
  Future<void> _attach() async {
    final model = context.read<ConnectionModel>();
    _client.events.listen(model.applyEvent);
    try {
      await _client.connect(kSocketPath);
      await _client.hello();
      await _client.getStatus();
    } catch (e) {
      model.applyError(e);
    }
  }

  Future<void> _connect() async {
    final model = context.read<ConnectionModel>();
    final selected = _selected;
    if (selected?.profile == null) return;
    try {
      await _client.sendConnect(
        ConnectParamsDto(
          // The helper re-parses this itself, after authorizing the caller, so
          // the document is passed through rather than reconstructed.
          profileJson: File(selected!.path).readAsStringSync(),
          user: Platform.environment['USER'] ?? '',
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
      await _client.disconnect();
    } catch (e) {
      model.applyError(e);
    }
  }

  @override
  void dispose() {
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
      ),
      ConnectionScreen(
        selected: _selected,
        onConnect: _connect,
        onDisconnect: _disconnect,
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
