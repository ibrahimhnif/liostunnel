import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Copies an `ss://` link to the clipboard, after asking.
///
/// The link carries the password: there is no secret-free form of one. A
/// clipboard is readable by every process running as this user and pasteboard
/// managers keep history, so this asks first and names that — the same
/// reasoning as the CLI's warning on `export --include-secrets`.
///
/// **The link itself is never shown.** Not in the confirmation, not in the
/// snackbar, not in the refusal: a live credential on screen is one
/// screenshot, one screen-share or one shoulder away from being someone
/// else's.
///
/// [link] is a producer rather than the link itself, and that is what makes
/// Cancel mean something: choosing it returns before the secret file is even
/// opened. It is also the seam this has a test through — the real producer
/// crosses the FFI, whose futures never complete inside a `testWidgets`
/// fake-async zone, while a fake one completes under a plain `pumpAndSettle`.
Future<void> confirmAndCopyLink(
  BuildContext context,
  Future<String> Function() link,
) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: const Text('Copy this profile as a link?'),
      content: const Text(
        'The link contains the password — that is what makes it usable in '
        'another client. Anything running as you can read the clipboard, '
        'and clipboard managers keep history.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(ctx, false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('confirm-copy'),
          onPressed: () => Navigator.pop(ctx, true),
          child: const Text('Copy'),
        ),
      ],
    ),
  );
  if (ok != true || !context.mounted) return;
  // Taken before the await: the widget that owns this context can be gone by
  // the time the link comes back, and `ScaffoldMessenger.of` after that throws
  // rather than toasts.
  final messenger = ScaffoldMessenger.of(context);
  try {
    await Clipboard.setData(ClipboardData(text: await link()));
    messenger.showSnackBar(
      const SnackBar(content: Text('Link copied. It contains the password.')),
    );
  } catch (e) {
    messenger.showSnackBar(SnackBar(content: Text('$e')));
  }
}
