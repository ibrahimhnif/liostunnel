import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/connection_model.dart';
import '../services/profile_store.dart';

/// Connect/disconnect, the current state, and live stats.
class ConnectionScreen extends StatelessWidget {
  const ConnectionScreen({
    super.key,
    required this.selected,
    required this.onConnect,
    required this.onDisconnect,
  });

  final LoadedProfile? selected;
  final VoidCallback onConnect;
  final VoidCallback onDisconnect;

  @override
  Widget build(BuildContext context) {
    final m = context.watch<ConnectionModel>();
    final dto = selected?.profile;

    return Scaffold(
      appBar: AppBar(title: const Text('Connection')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (m.userFacingError != null)
              Card(
                key: const Key('error-banner'),
                color: Theme.of(context).colorScheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      const Icon(Icons.warning_amber_outlined),
                      const SizedBox(width: 12),
                      Expanded(child: Text(m.userFacingError!)),
                    ],
                  ),
                ),
              ),
            const SizedBox(height: 12),
            Text(
              dto == null ? 'No profile selected' : dto.name,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            if (dto != null)
              Text('${dto.host}:${dto.port} · ${dto.protocol}',
                  style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 20),
            Row(
              children: [
                Chip(
                  key: const Key('state-chip'),
                  label: Text(m.state),
                  avatar: Icon(
                    m.isConnected ? Icons.lock_outline : Icons.lock_open,
                    size: 18,
                  ),
                ),
                const SizedBox(width: 16),
                FilledButton(
                  key: const Key('connect-button'),
                  // Disabled without a profile: a connect with nothing
                  // selected can only produce an error the user cannot act on.
                  onPressed: dto == null
                      ? null
                      : (m.isConnected ? onDisconnect : onConnect),
                  child: Text(m.isConnected ? 'Disconnect' : 'Connect'),
                ),
              ],
            ),
            const SizedBox(height: 28),
            Text('Traffic', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            _StatRow(label: 'Sent', value: _bytes(m.bytesUp)),
            _StatRow(label: 'Received', value: _bytes(m.bytesDown)),
            _StatRow(label: 'Active flows', value: '${m.activeFlows}'),
            _StatRow(label: 'Failed flows', value: '${m.flowsFailed}'),
            _StatRow(label: 'DNS queries', value: '${m.dnsQueries}'),
          ],
        ),
      ),
    );
  }
}

class _StatRow extends StatelessWidget {
  const _StatRow({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          SizedBox(width: 140, child: Text(label)),
          Text(value, style: const TextStyle(fontFeatures: [
            FontFeature.tabularFigures(),
          ])),
        ],
      ),
    );
  }
}

/// Counters cross the FFI as BigInt (Rust `u64`), so this formats BigInt
/// rather than int — an `as int` here would throw on a busy tunnel rather
/// than at any point a test would notice.
String _bytes(BigInt n) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  var v = n.toDouble();
  var i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i == 0 ? '$n B' : '${v.toStringAsFixed(1)} ${units[i]}';
}
