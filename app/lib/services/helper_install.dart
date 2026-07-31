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
/// [HelperNotInstalled] is ENOENT and nothing else: there is no socket, so no
/// helper was ever installed, and installing one is the fix.
///
/// Every other failure is a helper that exists. [HelperForbidden] is
/// EACCES/EPERM — one IS installed, for another account, and the user cannot
/// authorize their way out of somebody else's socket. Plain
/// [HelperUnavailable] is ECONNREFUSED (a socket with a dead daemon behind
/// it), a dropped connection, a send with no socket, a failed write: all of
/// them a helper that is present. This read `e is HelperUnavailable`, which
/// caught all four of those, so on Linux a helper that was installed and had
/// crashed raised the polkit dialog at startup and reinstalled over itself.
bool installWouldFix(Object e) => e is HelperNotInstalled;

/// A command the user can paste that installs the helper, for the panel.
///
/// It has to work when pasted, which the bundle's own path does not: run plain
/// it refuses with "must run as root", and run under `sudo` it gets EACCES on
/// the AppImage's FUSE mountpoint — the exact failure [runInstallPrivileged]
/// copies out of the bundle to avoid. So this is the shell form of what that
/// function does: copy the directory somewhere root can read, then elevate
/// against the copy. The copy is made as the invoking user, who mounted the
/// AppImage and is the one uid the kernel lets read it.
///
/// The whole directory, not the script: `install-helper.sh` reads the helper
/// binary and the unit file from beside itself.
String installCommand(int uid, {String? resolvedExecutable}) {
  final bundle = helperBundleDir(resolvedExecutable: resolvedExecutable);
  return 'd="\$(mktemp -d)" && cp -R ${_shellQuote('$bundle/.')} "\$d" '
      '&& sudo "\$d/install-helper.sh" --uid $uid';
}

/// Single-quotes [s] for a POSIX shell.
///
/// The bundle path is `dirname(Platform.resolvedExecutable)/helper` — whatever
/// directory the user put the AppImage in, so spaces and quotes are theirs to
/// choose, and this is a string a person is invited to paste into a shell.
String _shellQuote(String s) => "'${s.replaceAll("'", r"'\''")}'";

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
  // Every message that tells the user to run something names
  // [installCommand] — the same string the panel prints, which stages its own
  // copy. This used to name `sudo ${staged.path}/install-helper.sh` and keep
  // the copy alive for it, which put two different commands on screen at
  // once: this one in the notice, and the panel's `installCommand` directly
  // beneath it. The panel's was the unusable in-mount path, so the pair was
  // not merely inconsistent — one of them was wrong.
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
      return InstallResult(
        InstallOutcome.failed,
        'This system has no pkexec, so the helper cannot be installed from '
        'the app. Run it yourself: '
        '${installCommand(uid, resolvedExecutable: resolvedExecutable)}',
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
      return InstallResult(
        InstallOutcome.failed,
        'The installer could not be run. Run it yourself: '
        '${installCommand(uid, resolvedExecutable: resolvedExecutable)}',
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
    if (staged.existsSync()) staged.deleteSync(recursive: true);
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
