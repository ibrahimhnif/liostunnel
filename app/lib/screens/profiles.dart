import 'package:flutter/material.dart';

import '../services/profile_store.dart';

/// The profiles list.
///
/// Takes an already-loaded list rather than doing the loading itself. Reading
/// and parsing crosses the FFI, and a widget that awaits that internally is
/// only testable through a real event loop — this way the rendering is pure
/// and the I/O lives in one place. Search is the one piece of local state, so
/// this is stateful; filtering stays pure.
class ProfilesScreen extends StatefulWidget {
  const ProfilesScreen({
    super.key,
    required this.profiles,
    required this.directory,
    required this.selectedPath,
    required this.onSelect,
    required this.onReload,
    required this.onCreate,
    required this.onEdit,
    required this.onDuplicate,
    required this.onCopyLink,
    required this.onDelete,
  });

  final List<LoadedProfile> profiles;
  final String directory;
  final String? selectedPath;
  final void Function(LoadedProfile) onSelect;
  final VoidCallback onReload;
  final VoidCallback onCreate;
  final void Function(LoadedProfile) onEdit;
  final void Function(LoadedProfile) onDuplicate;
  final void Function(LoadedProfile) onCopyLink;
  final void Function(LoadedProfile) onDelete;

  @override
  State<ProfilesScreen> createState() => _ProfilesScreenState();
}

class _ProfilesScreenState extends State<ProfilesScreen> {
  final _search = TextEditingController();

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  /// Name and host, case-insensitively. Host matters as much as name: a
  /// provider's profiles are often all called some variation of its own name,
  /// and the address is what distinguishes them.
  List<LoadedProfile> get _visible {
    final q = _search.text.trim().toLowerCase();
    if (q.isEmpty) return widget.profiles;
    return widget.profiles.where((p) {
      final host = p.profile?.host ?? '';
      return p.name.toLowerCase().contains(q) || host.toLowerCase().contains(q);
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    final visible = _visible;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Profiles'),
        actions: [
          IconButton(
            key: const Key('create-button'),
            icon: const Icon(Icons.add),
            tooltip: 'New profile',
            onPressed: widget.onCreate,
          ),
          IconButton(
            key: const Key('reload-button'),
            icon: const Icon(Icons.refresh),
            tooltip: 'Reload',
            onPressed: widget.onReload,
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
            child: TextField(
              key: const Key('profile-search'),
              controller: _search,
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search),
                hintText: 'Search by name or host',
                isDense: true,
                border: OutlineInputBorder(),
              ),
            ),
          ),
          Expanded(
            child: widget.profiles.isEmpty
                ? Center(
                    child: Padding(
                      padding: const EdgeInsets.all(24),
                      child: Text(
                        'No profiles in ${widget.directory}.\n'
                        'Use + to create one, or drop a JSON file there and '
                        'reload.',
                        textAlign: TextAlign.center,
                      ),
                    ),
                  )
                : visible.isEmpty
                    ? const Center(child: Text('Nothing matches that search.'))
                    : ListView.builder(
                        itemCount: visible.length,
                        itemBuilder: (context, i) => _row(visible[i]),
                      ),
          ),
        ],
      ),
    );
  }

  Widget _row(LoadedProfile p) {
    // A file that failed to parse is shown as a broken entry rather than
    // hidden — a profile that silently vanishes looks the same as one the
    // user never saved. It stays editable through the same menu every other
    // row carries: it is exactly the one that needs opening and repairing.
    if (!p.ok) {
      return ListTile(
        key: ValueKey(p.path),
        leading: const Icon(Icons.error_outline),
        title: Text(p.name),
        subtitle: Text(p.error!),
        trailing: _menu(p),
      );
    }
    final dto = p.profile!;
    return ListTile(
      key: ValueKey(p.path),
      selected: p.path == widget.selectedPath,
      leading: const Icon(Icons.dns_outlined),
      title: Text(dto.name),
      subtitle: Text('${dto.host}:${dto.port} · ${dto.protocol}'),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (p.path == widget.selectedPath) const Icon(Icons.check),
          _menu(p),
        ],
      ),
      onTap: () => widget.onSelect(p),
    );
  }

  /// One menu builder for both branches of [_row].
  ///
  /// Not two copies: this affordance shipped once already on the broken-row
  /// branch only, after a patch failed to match the healthy branch, and every
  /// profile that actually parsed lost it with a green suite.
  Widget _menu(LoadedProfile p) {
    // Duplicate and Copy need a profile that parsed; `ss://` additionally
    // cannot represent anything but Shadowsocks.
    final ss = p.ok && p.profile!.protocol == 'shadowsocks';
    return PopupMenuButton<String>(
      key: ValueKey('menu-${p.path}'),
      onSelected: (v) => switch (v) {
        'edit' => widget.onEdit(p),
        'duplicate' => widget.onDuplicate(p),
        'copy' => widget.onCopyLink(p),
        'delete' => widget.onDelete(p),
        _ => null,
      },
      itemBuilder: (_) => [
        const PopupMenuItem(value: 'edit', child: Text('Edit')),
        if (p.ok)
          const PopupMenuItem(value: 'duplicate', child: Text('Duplicate')),
        if (ss)
          const PopupMenuItem(value: 'copy', child: Text('Copy ss:// link')),
        const PopupMenuItem(value: 'delete', child: Text('Delete')),
      ],
    );
  }
}
