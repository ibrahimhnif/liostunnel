import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/connection_model.dart';
import '../services/profile_store.dart';
import '../services/vpn_platform.dart';

/// Connect/disconnect, the current state, and live stats.
class ConnectionScreen extends StatelessWidget {
  const ConnectionScreen({
    super.key,
    required this.selected,
    required this.onConnect,
    required this.onDisconnect,
    this.installCommandText,
    this.onRetryInstall,
  });

  final LoadedProfile? selected;
  final VoidCallback onConnect;
  final VoidCallback onDisconnect;

  /// The install command, shown beside the notice so it can be read before it
  /// is run as root. Null once there is nothing to install.
  final String? installCommandText;

  /// Asks for the install again — the only thing that does, after a cancel.
  final VoidCallback? onRetryInstall;

  @override
  Widget build(BuildContext context) {
    final m = context.watch<ConnectionModel>();
    final dto = selected?.profile;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Connection'),
        actions: const [_AndroidVpnSmokeTest()],
      ),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Above the banner, and not styled as an error: a first launch
            // that has not installed the helper yet is a normal first launch,
            // and a cancelled install is the user's answer rather than a
            // fault.
            if (m.installNotice != null)
              Card(
                key: const Key('install-panel'),
                color: Theme.of(context).colorScheme.secondaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(m.installNotice!),
                      if (installCommandText != null) ...[
                        const SizedBox(height: 8),
                        // What remains of "read it before it runs as root".
                        SelectableText(
                          installCommandText!,
                          style: const TextStyle(fontFamily: 'monospace'),
                        ),
                        const SizedBox(height: 8),
                        FilledButton.tonal(
                          key: const Key('install-retry'),
                          onPressed: onRetryInstall,
                          child: const Text('Install the helper'),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
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
              Text(
                '${dto.host}:${dto.port} · ${dto.protocol}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
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
                  // Connect needs a profile; DISCONNECT DOES NOT. `_selected`
                  // is null on every relaunch, so requiring one here left a
                  // freshly-launched app showing "Connected" with a greyed-out
                  // Disconnect and no way to stop the tunnel at all.
                  onPressed: m.isConnected
                      ? onDisconnect
                      : (dto == null ? null : onConnect),
                  child: Text(m.isConnected ? 'Disconnect' : 'Connect'),
                ),
              ],
            ),
            const SizedBox(height: 28),
            Text('Traffic', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            _StatRow(
              label: 'Sent',
              value: '${_bytes(m.bytesUp)}   ${_rate(m.bytesUpPerSec)}',
            ),
            _StatRow(
              label: 'Received',
              value: '${_bytes(m.bytesDown)}   ${_rate(m.bytesDownPerSec)}',
            ),
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
          // Expanded because the value now carries a total AND a rate:
          // "1.1 TiB   117.7 MiB/s" is 21 characters on a busy tunnel, and
          // a non-flexible Row child overflows a narrow window.
          Expanded(
            child: Text(
              value,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                fontFeatures: [FontFeature.tabularFigures()],
              ),
            ),
          ),
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

/// A rate, or an em dash when there is none.
///
/// Built on [_bytes] rather than a second formatter, so the total and the rate
/// cannot disagree about what a mebibyte is.
///
/// The dash is not decoration: `0 B/s` would be a claim that no traffic moved,
/// and before the second sample there is no such claim to make.
///
/// `!isFinite` is guarded here rather than trusted to the model. `round()`
/// throws on Infinity and NaN, and this runs inside `build` -- so a division
/// that ever produced one would replace the whole screen with a red error box
/// rather than one wrong number.
String _rate(double? perSec) => perSec == null || !perSec.isFinite
    ? '—'
    : '${_bytes(BigInt.from(perSec.round()))}/s';

/// Raises the VPN consent dialog and starts the tunnel service, with no
/// profile and no engine behind it.
///
/// **Temporary — Task 7 replaces this with the real connect path and deletes
/// it.** It exists because a `BIND_VPN_SERVICE` service cannot be started
/// from `adb shell`: the system refuses any caller but itself, so the only
/// way to exercise `LiosVpnService` before the UI is wired is from inside the
/// app.
///
/// Debug builds on Android only, so it cannot reach a release artifact.
class _AndroidVpnSmokeTest extends StatelessWidget {
  const _AndroidVpnSmokeTest();

  @override
  Widget build(BuildContext context) {
    if (!kDebugMode || !Platform.isAndroid) return const SizedBox.shrink();
    return IconButton(
      icon: const Icon(Icons.bug_report),
      tooltip: 'Start VpnService (debug)',
      onPressed: () async {
        if (await VpnPlatform.prepare()) {
          await VpnPlatform.start();
        }
      },
    );
  }
}
