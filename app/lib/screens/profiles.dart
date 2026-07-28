import 'package:flutter/material.dart';

import '../services/profile_store.dart';

/// The profiles list. Read-only: §4 puts creation and editing out of scope,
/// so profiles arrive as JSON files and this shows what is there.
///
/// Takes an already-loaded list rather than doing the loading itself. Reading
/// and parsing crosses the FFI, and a widget that awaits that internally is
/// only testable through a real event loop — this way the rendering is pure
/// and the I/O lives in one place.
class ProfilesScreen extends StatelessWidget {
  const ProfilesScreen({
    super.key,
    required this.profiles,
    required this.directory,
    required this.selectedPath,
    required this.onSelect,
    required this.onReload,
  });

  final List<LoadedProfile> profiles;
  final String directory;
  final String? selectedPath;
  final void Function(LoadedProfile) onSelect;
  final VoidCallback onReload;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Profiles'),
        actions: [
          IconButton(
            key: const Key('reload-button'),
            icon: const Icon(Icons.refresh),
            tooltip: 'Reload',
            onPressed: onReload,
          ),
        ],
      ),
      body: profiles.isEmpty
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(
                  'No profiles in $directory.\n'
                  'Drop a profile JSON file there and reload.',
                  textAlign: TextAlign.center,
                ),
              ),
            )
          : ListView.builder(
              itemCount: profiles.length,
              itemBuilder: (context, i) {
                final p = profiles[i];
                // A file that failed to parse is shown as a broken entry
                // rather than hidden — a profile that silently vanishes looks
                // the same as one the user never saved.
                if (!p.ok) {
                  return ListTile(
                    key: ValueKey(p.path),
                    leading: const Icon(Icons.error_outline),
                    title: Text(p.name),
                    subtitle: Text(p.error!),
                    enabled: false,
                  );
                }
                final dto = p.profile!;
                return ListTile(
                  key: ValueKey(p.path),
                  selected: p.path == selectedPath,
                  leading: const Icon(Icons.dns_outlined),
                  title: Text(dto.name),
                  subtitle: Text('${dto.host}:${dto.port} · ${dto.protocol}'),
                  trailing:
                      p.path == selectedPath ? const Icon(Icons.check) : null,
                  onTap: () => onSelect(p),
                );
              },
            ),
    );
  }
}
