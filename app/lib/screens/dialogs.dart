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

/// Asks before a profile is deleted, and says what deletion leaves behind.
///
/// One dialog for both call sites — the editor's Delete button and the list
/// row's overflow menu — so they cannot drift. They already had: the editor
/// asked, and the menu entry deleted on one tap, from a menu whose other three
/// entries are harmless. The asymmetry is the argument, because the *more*
/// accidental affordance is the one that had the weaker guard. The profile
/// document is the only copy and there is no undo.
///
/// The body says the thing the user cannot otherwise know: the credential file
/// survives. That is deliberate — [ProfileWriter.delete] touches only the
/// `.json` and the `.user` sidecar, because the secret may be an SSH key
/// relied on elsewhere and deleting a profile is not consent to destroy a
/// credential.
Future<bool> confirmDeleteProfile(BuildContext context, String name) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text('Delete "$name"?'),
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
  return ok == true;
}
