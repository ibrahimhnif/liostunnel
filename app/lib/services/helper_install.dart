/// Installing the privileged helper that ships inside this app.
///
/// **Linux only.** The macOS package installs the helper from its own
/// `postinstall`, which runs as root under Installer.app — so on macOS a
/// missing helper means something that reinstalling from the app would paper
/// over, and the app says so instead.
///
/// An AppImage has no install step and nothing runs as root, so on Linux the
/// app asks `pkexec` to run the same `install-helper.sh` the package would
/// have. **The polkit dialog is the consent gate**; nothing here escalates
/// without it.
library;

import 'dart:ffi';
import 'dart:io';

import 'helper_client.dart';

/// Where the bundled helper and its install script live.
///
/// Relative to the executable, because an AppImage mounts itself at
/// `/tmp/.mount_XXXXXX` and any fixed path would be wrong. `make-appimage.sh`
/// puts the app at `usr/bin/liostunnel_app` and this directory beside it.
String helperBundleDir({String? resolvedExecutable}) =>
    '${File(resolvedExecutable ?? Platform.resolvedExecutable).parent.path}'
    '/helper';

/// Whether the app installs the helper itself on this platform.
///
/// Only Linux, and the asymmetry is deliberate: the macOS `.pkg` already ran
/// `install-helper.sh` as root from its `postinstall`, so a missing helper
/// there is a broken install rather than an absent one. Reinstalling it from
/// the app would paper over whatever removed it.
bool appInstallsHelper() => Platform.isLinux;

/// Whether installing the helper is what would fix [e].
///
/// ENOENT — [HelperUnavailable] — means no helper was ever installed.
/// [HelperForbidden] is EACCES: there IS one, installed for another account,
/// and a second install is not the fix. Everything else came back down a
/// socket that opened, so the helper is present by definition.
bool installWouldFix(Object e) => e is HelperUnavailable;

/// The install script, named so it can be read before it is run as root.
///
/// Shown in the panel if the user cancels. Note this is the path *inside* the
/// bundle: readable by the user who launched the app, which is what reading it
/// needs. It is deliberately not what gets elevated — see
/// [runInstallPrivileged], which runs a copy, because root cannot read an
/// AppImage's own mountpoint.
String installCommand(int uid, {String? resolvedExecutable}) =>
    '${helperBundleDir(resolvedExecutable: resolvedExecutable)}'
    '/install-helper.sh --uid $uid';

/// This process's real uid.
///
/// The install script deliberately refuses to guess: under `sudo`, `pkexec`
/// and a package's postinstall alike, guessing yields 0, and a helper
/// authorizing root accepts a root client.
///
/// Through `getuid(2)` rather than `id -u`, and synchronously. The install
/// runs from `initState`, and a `testWidgets` fake-async zone never completes
/// a real subprocess — an `await Process.run` here would park first launch
/// forever in every widget test that drives it, on the one platform that
/// reaches this code. `getuid` cannot fail and has nothing to parse.
int currentUid() => _getuid();

final int Function() _getuid = DynamicLibrary.process()
    .lookupFunction<Uint32 Function(), int Function()>('getuid');

enum InstallOutcome { installed, cancelled, failed }

class InstallResult {
  const InstallResult(this.outcome, this.message);
  final InstallOutcome outcome;
  final String message;
}

/// Runs the bundled install script under `pkexec`, raising the polkit dialog.
///
/// **Against a copy, never against the bundle.** An AppImage mounts its
/// squashfs through libfuse without `allow_other`, so the kernel denies that
/// mountpoint to every uid except the one that mounted it — root included.
/// A `pkexec` pointed at `/tmp/.mount_XXXXXX/usr/bin/helper/install-helper.sh`
/// gets EACCES on the path itself and the script never runs. So the whole
/// directory is copied to a temp directory the invoking user owns, on a real
/// filesystem, and that copy is what is elevated. `install-helper.sh` prefers
/// the binary beside itself, so the copy installs the bundled helper rather
/// than anything stale, and the copy goes away afterwards.
///
/// The failure is invisible on a developer machine, where the app runs from a
/// plain directory and there is no mountpoint to be refused by.
///
/// [run] is injected so tests never escalate: no test in this repo may invoke
/// a real `pkexec`.
Future<InstallResult> runInstallPrivileged(
  int uid, {
  String? resolvedExecutable,
  Future<ProcessResult> Function(String, List<String>)? run,
}) async {
  final bundle = helperBundleDir(resolvedExecutable: resolvedExecutable);
  final Directory staged;
  try {
    staged = _copyOutOfTheBundle(bundle);
  } on FileSystemException catch (e) {
    // Nothing is elevated, because there is nothing to elevate: a password
    // prompt for a script that is not there asks the user to authorize
    // nothing. `flutter run` from a checkout is exactly this case.
    return InstallResult(
      InstallOutcome.failed,
      'This build has no helper to install: ${e.message} ($bundle).',
    );
  }

  final script = '${staged.path}/install-helper.sh';
  final exec = run ?? (String e, List<String> a) => Process.run(e, a);
  // Kept only when the message tells the user to run it themselves — a
  // command naming a path that has just been deleted is not a command, and
  // the bundle's own path is the one root cannot read.
  var keep = false;
  try {
    final ProcessResult r;
    try {
      // pkexec takes argv directly, so no shell is involved and a path with a
      // space needs no quoting -- there is nothing to misparse it.
      r = await exec('pkexec', [script, '--uid', '$uid']);
    } on ProcessException {
      // Process.run THROWS when the program is not on PATH; 127 for that is a
      // shell's convention, not this one. Uncaught, a system without polkit
      // got an unhandled exception out of an unawaited callback rather than
      // the one sentence that fixes it.
      keep = true;
      return InstallResult(
        InstallOutcome.failed,
        'This system has no pkexec, so the helper cannot be installed from '
        'the app. Run it yourself: sudo $script --uid $uid',
      );
    }

    if (r.exitCode == 0) {
      return const InstallResult(
        InstallOutcome.installed,
        'The helper is installed.',
      );
    }
    // 126 is "dismissed or not authorized". The user said no.
    if (r.exitCode == 126) {
      return const InstallResult(
        InstallOutcome.cancelled,
        'Installation was cancelled.',
      );
    }
    // 127 is pkexec's "could not execute the program" — a /tmp mounted
    // noexec, or no authentication agent to ask.
    if (r.exitCode == 127) {
      keep = true;
      return InstallResult(
        InstallOutcome.failed,
        'The installer could not be run. Run it yourself: '
        'sudo $script --uid $uid',
      );
    }
    // Past here the script itself ran and refused. Its messages are fixed
    // strings we wrote — unlike the helper's own error text, which the app
    // never renders.
    final err = '${r.stderr}'.trim();
    return InstallResult(
      InstallOutcome.failed,
      err.isEmpty ? 'The installer failed (exit ${r.exitCode}).' : err,
    );
  } finally {
    if (!keep && staged.existsSync()) staged.deleteSync(recursive: true);
  }
}

/// Copies [bundle] to a temp directory this user owns, and returns it.
///
/// The whole directory, not the script: `install-helper.sh` reads the helper
/// binary and the systemd unit from beside itself, so a copy of the script
/// alone installs nothing. Throws [FileSystemException] if there is no bundle.
Directory _copyOutOfTheBundle(String bundle) {
  final source = Directory(bundle);
  // Listing first, so a missing bundle throws before a temp directory is made
  // that nothing would ever delete.
  final entries = source.listSync(followLinks: false);
  final staged = Directory.systemTemp.createTempSync('liostunnel-helper-');
  _copyInto(entries, staged);
  return staged;
}

void _copyInto(List<FileSystemEntity> entries, Directory into) {
  for (final entry in entries) {
    final dest = '${into.path}/${entry.uri.pathSegments.lastWhere((s) => s.isNotEmpty)}';
    if (entry is Directory) {
      Directory(dest).createSync();
      _copyInto(entry.listSync(followLinks: false), Directory(dest));
    } else if (entry is File) {
      // copySync rather than a read-then-write: it creates the copy with the
      // source's mode, and pkexec EXECS install-helper.sh — a 0644 copy is
      // one it cannot run.
      entry.copySync(dest);
    }
  }
}
