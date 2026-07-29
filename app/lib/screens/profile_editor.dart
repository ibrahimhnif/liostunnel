import 'package:flutter/material.dart';

import '../services/profile_store.dart';
import '../services/profile_writer.dart';
import '../src/rust/api/config.dart';
import '../src/rust/dto/profile.dart';

/// The cipher names the editor offers for Shadowsocks.
///
/// Must match `OFFERED` in `crates/liostunnel-core/src/protocols/
/// shadowsocks.rs` exactly. A name this dropdown offers that the core refuses
/// is the same bug the core's own list already had once: advice the user
/// follows and that then fails as unknown. Public so a test can prove the
/// agreement against the core itself rather than against a second copy of
/// this list.
///
/// The `2022-blake3-*` family is deliberately absent — it cannot be built
/// under this build's cipher feature set.
const offeredCiphers = [
  'aes-128-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
];

/// Creates a profile.
///
/// **This form collects where a secret lives, not the secret.** A profile
/// carries a `file:` or `env:` reference and the helper resolves it later, as
/// the calling user — which is the whole reason a profile naming a file you
/// do not own gets refused. The one exception is [_secret], offered because
/// password auth would otherwise need a terminal, and it writes to a `0600`
/// file and stores only that path.
class ProfileEditorScreen extends StatefulWidget {
  const ProfileEditorScreen({
    super.key,
    required this.writer,
    required this.onSaved,
    this.existing,
  });

  final ProfileWriter writer;
  final VoidCallback onSaved;

  /// The profile being edited, or null to create one.
  final LoadedProfile? existing;

  @override
  State<ProfileEditorScreen> createState() => _ProfileEditorScreenState();
}

class _ProfileEditorScreenState extends State<ProfileEditorScreen> {
  final _form = GlobalKey<FormState>();

  final _name = TextEditingController();
  final _host = TextEditingController();
  final _port = TextEditingController();
  final _user = TextEditingController();
  final _dns = TextEditingController();
  final _secretPath = TextEditingController();
  final _secret = TextEditingController();
  final _dohSni = TextEditingController();
  final _dohPath = TextEditingController();
  final _uri = TextEditingController();

  String _authKind = 'password';
  String _cipher = 'aes-256-gcm';
  String _secretMode = 'file';
  String _dnsMode = 'tcp';
  bool _busy = false;
  String? _error;
  String? _saved;

  bool get _editing => widget.existing?.profile != null;

  @override
  void initState() {
    super.initState();
    final p = widget.existing?.profile;
    if (p == null) {
      _name.text = 'My server';
      _port.text = '22';
      _dns.text = '1.1.1.1, 1.0.0.1';
      _dohSni.text = 'cloudflare-dns.com';
      _dohPath.text = '/dns-query';
      return;
    }
    _name.text = p.name;
    _host.text = p.host;
    _port.text = '${p.port}';
    _user.text = widget.existing?.sshUser ?? '';
    _dns.text = p.dnsServers.join(', ');
    _dnsMode = p.dnsMode;
    _authKind = p.authKind;
    _dohSni.text = p.dohSni ?? 'cloudflare-dns.com';
    _dohPath.text = p.dohPath ?? '/dns-query';
    _cipher = p.cipher ?? 'aes-256-gcm';

    // The profile records where the secret lives, so the form can show that
    // much. A password typed on a previous visit is NOT recoverable — it was
    // written to a file and never kept here, which is the point.
    final source = p.authSecretSource;
    if (source.startsWith('env:')) {
      // Kept viewable so an imported profile can be repaired, but the form
      // will not produce one: the helper refuses env secrets outright,
      // because they resolve against root's environment.
      _secretMode = 'file';
      _secretPath.text = '';
    } else if (source.startsWith('file:')) {
      _secretMode = 'file';
      _secretPath.text = source.substring(5);
    }
  }

  @override
  void dispose() {
    for (final c in [
      _name,
      _host,
      _port,
      _user,
      _dns,
      _secretPath,
      _secret,
      _dohSni,
      _dohPath,
      _uri,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  /// Fills the form from an `ss://` link.
  ///
  /// Order is load-bearing. The link is parsed first, so a malformed one
  /// leaves no secret file behind; the password is written before any form
  /// field is touched, so a failed write leaves the form as it was rather
  /// than half-filled with a credential that never landed.
  Future<void> _import() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final uri = _uri.text.trim();
      final dto = await importSsUri(uri: uri);
      final password = await ssUriPassword(uri: uri);
      // Straight to a 0600 file. The password is never held in widget state
      // and never reaches the profile document.
      final ref = await widget.writer.writeSecret(dto.id, password);

      if (!mounted) return;
      setState(() {
        _name.text = dto.name;
        _host.text = dto.host;
        _port.text = dto.port.toString();
        _authKind = 'shadowsocks';
        _cipher = dto.cipher ?? 'aes-256-gcm';
        _secretMode = 'file';
        _secretPath.text = ref.substring('file:'.length);
        _dns.text = dto.dnsServers.join(', ');
        // It contains the password; do not leave it on screen.
        _uri.clear();
      });
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _save() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
      _saved = null;
    });
    try {
      final old = widget.existing?.profile;
      // An edit keeps its id. Minting a new one would make the profile a
      // different server as far as anything keyed on id is concerned.
      final id = old?.id ?? await newProfileId();

      // Refuse the name BEFORE writing a secret. Doing it afterwards meant a
      // collision destroyed another profile's credential and then reported
      // failure, so the user believed nothing had happened.
      widget.writer.checkNameFree(
        _name.text.trim(),
        replacingPath: widget.existing?.path,
      );

      // A typed password becomes a 0600 file and the profile keeps the path.
      final source = _secretMode == 'typed'
          ? await widget.writer.writeSecret(id, _secret.text)
          : 'file:${_secretPath.text.trim()}';

      final dto = ProfileDto(
        id: id,
        name: _name.text.trim(),
        // Every field the form does not offer is carried through, not
        // defaulted. Rebuilding from scratch quietly rewrote a wireguard
        // profile to ssh, dropped an encrypted key's passphrase reference,
        // turned kill_switch off and reset split_tunnel — on a save where the
        // user had only corrected a typo.
        // A Shadowsocks profile must say so. Before this, a link imported
        // into a NEW profile saved with protocol `ssh` and authKind
        // `shadowsocks`, and the helper's factory — which dispatches on
        // protocol — handed it to the SSH tunnel, which refused it.
        protocol: _authKind == 'shadowsocks'
            ? 'shadowsocks'
            : (old?.protocol ?? 'ssh'),
        host: _host.text.trim(),
        port: int.parse(_port.text),
        authKind: _authKind,
        authSecretSource: source,
        cipher: _authKind == 'shadowsocks' ? _cipher : old?.cipher,
        dnsMode: _dnsMode,
        // Only meaningful for DoH, and required there — a profile with mode
        // `https` and no endpoint is refused by the helper at connect time.
        dohSni: _dnsMode == 'https' ? _dohSni.text.trim() : null,
        dohPath: _dnsMode == 'https' ? _dohPath.text.trim() : null,
        dnsServers: _dns.text
            .split(',')
            .map((s) => s.trim())
            .where((s) => s.isNotEmpty)
            .toList(),
        authPassphraseSource: old?.authPassphraseSource,
        peerPublicKey: old?.peerPublicKey,
        splitTunnel: old?.splitTunnel ?? 'all_traffic',
        splitTunnelApps: old?.splitTunnelApps ?? const [],
        killSwitch: old?.killSwitch ?? false,
      );

      // Checked by the same Rust that will read it back, so a profile the
      // app accepts is one the helper can parse.
      await checkProfile(dto: dto);
      final file = await widget.writer.writeProfile(
        dto,
        sshUser: _user.text,
        replacingPath: widget.existing?.path,
      );
      if (!mounted) return;
      setState(() => _saved = file.path);
      widget.onSaved();
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _confirmDelete() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Delete "${_name.text}"?'),
        // The secret file is deliberately left alone: it may be an SSH key
        // the user relies on elsewhere, and deleting a profile is not consent
        // to destroy a credential.
        content: const Text(
          'The profile is removed. Any key or password file it points at is '
          'left where it is.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm-delete'),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    await widget.writer.delete(widget.existing!.path);
    widget.onSaved();
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_editing ? 'Edit profile' : 'New profile'),
        actions: [
          if (_editing)
            IconButton(
              key: const Key('delete-button'),
              icon: const Icon(Icons.delete_outline),
              tooltip: 'Delete',
              onPressed: _busy ? null : _confirmDelete,
            ),
        ],
      ),
      body: Form(
        key: _form,
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            if (_error != null)
              Card(
                key: const Key('editor-error'),
                color: Theme.of(context).colorScheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(_error!),
                ),
              ),
            if (_saved != null)
              Card(
                key: const Key('editor-saved'),
                color: Theme.of(context).colorScheme.secondaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text('Saved to $_saved'),
                ),
              ),
            _text(_name, 'Name', key: 'f-name'),
            _text(_host, 'Host', key: 'f-host', hint: 'example.com or an IP'),
            _text(
              _port,
              'Port',
              key: 'f-port',
              validator: (v) {
                final n = int.tryParse(v ?? '');
                if (n == null || n < 1 || n > 65535) return '1–65535';
                return null;
              },
            ),
            if (_authKind != 'shadowsocks')
              _text(_user, 'SSH username', key: 'f-user'),
            const SizedBox(height: 16),

            DropdownButtonFormField<String>(
              key: const Key('f-auth'),
              initialValue: _authKind,
              decoration: const InputDecoration(labelText: 'Authentication'),
              items: const [
                DropdownMenuItem(value: 'password', child: Text('Password')),
                DropdownMenuItem(
                    value: 'private_key', child: Text('Private key')),
                // Present so opening a preshared_key profile does not crash
                // the form: DropdownButtonFormField asserts its value matches
                // exactly one item. WireGuard is not connectable yet, but the
                // profile is editable and must survive a round trip.
                DropdownMenuItem(
                    value: 'preshared_key', child: Text('Pre-shared key')),
                DropdownMenuItem(
                    value: 'shadowsocks', child: Text('Shadowsocks')),
              ],
              onChanged: (v) => setState(() => _authKind = v!),
            ),
            if (_authKind == 'shadowsocks') ...[
              const SizedBox(height: 8),
              _text(_uri, 'Paste an ss:// link', key: 'f-uri',
                  hint: 'ss://...',
                  help: 'Fills in the form from the link. The password is '
                      'written to a 0600 file and never stored in the '
                      'profile.',
                  validator: (_) => null),
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: FilledButton.tonal(
                  key: const Key('import-button'),
                  onPressed: _busy ? null : _import,
                  child: const Text('Import from link'),
                ),
              ),
              DropdownButtonFormField<String>(
                key: const Key('f-cipher'),
                initialValue: _cipher,
                decoration: const InputDecoration(labelText: 'Cipher'),
                items: [
                  for (final c in offeredCiphers)
                    DropdownMenuItem(value: c, child: Text(c)),
                ],
                onChanged: (v) => setState(() => _cipher = v!),
              ),
            ],
            const SizedBox(height: 8),
            DropdownButtonFormField<String>(
              key: const Key('f-secret-mode'),
              initialValue: _secretMode,
              decoration: const InputDecoration(labelText: 'Where the secret lives'),
              items: const [
                DropdownMenuItem(
                    value: 'file', child: Text('A file I already have')),
                DropdownMenuItem(
                    value: 'typed', child: Text('Type it — save to a 0600 file')),
              ],
              onChanged: (v) => setState(() => _secretMode = v!),
            ),
            const SizedBox(height: 8),
            if (_secretMode == 'typed')
              _text(
                _secret,
                'Password',
                key: 'f-secret',
                obscure: true,
                help: 'Written to ${widget.writer.secretsDirectory}, mode 0600. '
                    'The profile stores the path, never the password.',
              )
            else
              _text(
                _secretPath,
                'Path to the file',
                key: 'f-secret-path',
                hint: '/Users/you/.ssh/id_ed25519',
                help: 'Must be owned by you and mode 0600, or the helper will '
                    'refuse it.',
              ),

            const SizedBox(height: 16),
            DropdownButtonFormField<String>(
              key: const Key('f-dns-mode'),
              initialValue: _dnsMode,
              decoration: const InputDecoration(labelText: 'DNS'),
              items: const [
                DropdownMenuItem(value: 'tcp', child: Text('DNS over TCP')),
                DropdownMenuItem(value: 'https', child: Text('DNS over HTTPS')),
              ],
              onChanged: (v) => setState(() => _dnsMode = v!),
            ),
            _text(
              _dns,
              'DNS servers',
              key: 'f-dns',
              hint: '1.1.1.1, 1.0.0.1',
              help: _dnsMode == 'https'
                  ? 'The IP of the DoH endpoint. No bootstrap lookup is done, '
                      'so this must be an address, not a name.'
                  : 'Tried in order, five seconds each. Many tunnel providers '
                      'block outbound port 53 — if lookups are slow or fail, '
                      'switch to DNS over HTTPS, which uses 443.',
            ),
            if (_dnsMode == 'https') ...[
              _text(_dohSni, 'DoH server name', key: 'f-doh-sni',
                  hint: 'cloudflare-dns.com'),
              _text(_dohPath, 'DoH path', key: 'f-doh-path',
                  hint: '/dns-query',
                  validator: (v) => (v == null || !v.startsWith('/'))
                      ? 'must start with /'
                      : null),
            ],

            const SizedBox(height: 24),
            FilledButton(
              key: const Key('save-button'),
              onPressed: _busy ? null : _save,
              child: Text(
                _busy
                    ? 'Saving…'
                    : _editing
                        ? 'Save changes'
                        : 'Save profile',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _text(
    TextEditingController c,
    String label, {
    required String key,
    String? hint,
    String? help,
    bool obscure = false,
    String? Function(String?)? validator,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: TextFormField(
        key: Key(key),
        controller: c,
        obscureText: obscure,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          helperText: help,
          helperMaxLines: 3,
        ),
        validator: validator ??
            (v) => (v == null || v.trim().isEmpty) ? 'required' : null,
      ),
    );
  }
}
