import 'package:flutter/material.dart';

import '../services/profile_writer.dart';
import '../src/rust/api/config.dart';
import '../src/rust/dto/profile.dart';

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
  });

  final ProfileWriter writer;
  final VoidCallback onSaved;

  @override
  State<ProfileEditorScreen> createState() => _ProfileEditorScreenState();
}

class _ProfileEditorScreenState extends State<ProfileEditorScreen> {
  final _form = GlobalKey<FormState>();

  final _name = TextEditingController(text: 'My server');
  final _host = TextEditingController();
  final _port = TextEditingController(text: '22');
  final _user = TextEditingController();
  final _dns = TextEditingController(text: '1.1.1.1, 1.0.0.1');
  final _secretPath = TextEditingController();
  final _secret = TextEditingController();

  String _authKind = 'password';
  String _secretMode = 'file';
  String _dnsMode = 'tcp';
  bool _busy = false;
  String? _error;
  String? _saved;

  @override
  void dispose() {
    for (final c in [_name, _host, _port, _user, _dns, _secretPath, _secret]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _save() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
      _saved = null;
    });
    try {
      // A typed password becomes a 0600 file and the profile keeps the path.
      final source = _secretMode == 'typed'
          ? await widget.writer.writeSecret(_name.text, _secret.text)
          : _secretMode == 'env'
              ? 'env:${_secretPath.text.trim()}'
              : 'file:${_secretPath.text.trim()}';

      final dto = ProfileDto(
        id: await newProfileId(),
        name: _name.text.trim(),
        protocol: 'ssh',
        host: _host.text.trim(),
        port: int.parse(_port.text),
        authKind: _authKind,
        authSecretSource: source,
        dnsMode: _dnsMode,
        dnsServers: _dns.text
            .split(',')
            .map((s) => s.trim())
            .where((s) => s.isNotEmpty)
            .toList(),
        splitTunnel: 'all_traffic',
        splitTunnelApps: const [],
        killSwitch: false,
      );

      // Checked by the same Rust that will read it back, so a profile the
      // app accepts is one the helper can parse.
      await checkProfile(dto: dto);
      final file = await widget.writer.writeProfile(dto);
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('New profile')),
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
              ],
              onChanged: (v) => setState(() => _authKind = v!),
            ),
            const SizedBox(height: 8),
            DropdownButtonFormField<String>(
              key: const Key('f-secret-mode'),
              initialValue: _secretMode,
              decoration: const InputDecoration(labelText: 'Where the secret lives'),
              items: const [
                DropdownMenuItem(
                    value: 'file', child: Text('A file I already have')),
                DropdownMenuItem(
                    value: 'env', child: Text('An environment variable')),
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
                _secretMode == 'env' ? 'Variable name' : 'Path to the file',
                key: 'f-secret-path',
                hint: _secretMode == 'env'
                    ? 'LIOS_PASSWORD'
                    : '/Users/you/.ssh/id_ed25519',
                help: _secretMode == 'env'
                    ? 'Environment variables are refused by the helper: it '
                        'would be reading root’s environment, not yours.'
                    : 'Must be owned by you and mode 0600, or the helper will '
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
            _text(_dns, 'DNS servers', key: 'f-dns', hint: '1.1.1.1, 1.0.0.1'),

            const SizedBox(height: 24),
            FilledButton(
              key: const Key('save-button'),
              onPressed: _busy ? null : _save,
              child: Text(_busy ? 'Saving…' : 'Save profile'),
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
