import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:liostunnel_app/services/helper_client.dart';
import 'package:liostunnel_app/services/helper_install.dart';
import 'package:liostunnel_app/src/rust/api/protocol.dart';

void main() {
  test('the helper directory is beside the executable', () {
    // An AppImage mounts itself at /tmp/.mount_XXXXXX, so this must be
    // relative to the executable rather than any fixed path.
    expect(
      helperBundleDir(
        resolvedExecutable: '/tmp/.mount_abc/usr/bin/liostunnel_app',
      ),
      '/tmp/.mount_abc/usr/bin/helper',
    );
  });

  test('the command names the script and the uid', () {
    final cmd = installCommand(
      501,
      resolvedExecutable: '/tmp/.mount_abc/usr/bin/liostunnel_app',
    );
    expect(cmd, contains('install-helper.sh'));
    expect(cmd, contains('--uid 501'));
  });

  test('the command the panel shows is one root can actually read', () async {
    // The panel's monospace line used to be
    // `<AppImage mount>/usr/bin/helper/install-helper.sh --uid N`. Run plain
    // it says "must run as root"; run under sudo it gets EACCES on the FUSE
    // mountpoint, because an AppImage mounts its squashfs without
    // `allow_other` and the kernel denies that mountpoint to every uid but the
    // one that mounted it -- root included. That is the same failure
    // `runInstallPrivileged` copies out of the bundle to avoid, printed as an
    // instruction.
    //
    // So run the command. `sudo` is a stub on PATH that execs its arguments:
    // nothing is escalated, nothing is installed, and no root is needed. It
    // cannot reproduce the FUSE refusal -- a temp directory is not a
    // mountpoint, which is the same blind spot make-appimage.sh's own comment
    // records -- so the load-bearing assertion is structural: the path handed
    // to the privileged program must not be inside the bundle.
    final tmp = Directory.systemTemp.createTempSync('lios-manual');
    addTearDown(() => tmp.deleteSync(recursive: true));
    final record = '${tmp.path}/argv';
    final exe = fakeBundle(installScript: '''
#!/usr/bin/env bash
{ printf '%s\\n' "\$0" "\$@"; ls "\$(dirname "\$0")"; } > '$record'
''');
    final bundle = helperBundleDir(resolvedExecutable: exe);
    final bin = Directory('${tmp.path}/bin')..createSync();
    File('${bin.path}/sudo').writeAsStringSync('#!/bin/sh\nexec "\$@"\n');
    Process.runSync('chmod', ['0755', '${bin.path}/sudo']);
    final env = {'PATH': '${bin.path}:${Platform.environment['PATH']}'};

    // Checked BEFORE the command is run, and not merely arranged: if the real
    // sudo were reachable this would raise a password prompt and hang the
    // suite. `expect` throws, so nothing below runs when it does not hold.
    final which = await Process.run(
      'bash', ['-c', 'command -v sudo'], environment: env);
    expect('${which.stdout}'.trim(), '${bin.path}/sudo',
        reason: 'precondition: no test in this repo may run a real sudo');

    final r = await Process.run(
      'bash',
      ['-c', installCommand(501, resolvedExecutable: exe)],
      environment: env,
    );
    expect(r.exitCode, 0, reason: 'the command must run: ${r.stderr}');

    final out = File(record).readAsLinesSync();
    final ran = out.first;
    addTearDown(() {
      final d = File(ran).parent;
      if (d.existsSync()) d.deleteSync(recursive: true);
    });
    expect(ran, isNot(startsWith(bundle)),
        reason: 'root cannot read the AppImage mount the bundle is inside');
    expect(ran, endsWith('/install-helper.sh'));
    expect(out.sublist(1, 3), ['--uid', '501']);
    // The whole directory moved, not the script: install-helper.sh reads both
    // of these from beside itself, so a copy of the script alone installs
    // nothing.
    expect(out, contains('liostunnel-helper'));
    expect(out, contains('liostunnel-helper.service'));
  });

  test('a bundle path with a quote in it survives the shell', () {
    // The bundle path is dirname(resolvedExecutable)/helper -- whatever
    // directory the user put the AppImage in. This is a string a person is
    // invited to paste into a shell, so an unescaped `'` does not merely fail:
    // it changes what the rest of the line means.
    final cmd = installCommand(
      501,
      resolvedExecutable: "/home/me/O'Brien's Apps/usr/bin/liostunnel_app",
    );
    // `-n` reads the command and does not execute it, so nothing here runs
    // sudo, cp or mktemp. Unescaped, the `'` closes the quote this opens and
    // bash reports an unterminated string.
    final r = Process.runSync('bash', ['-nc', cmd]);
    expect(r.exitCode, 0,
        reason: 'the command must parse as one shell command: ${r.stderr}');
    expect(cmd, contains(r"'\''"), reason: 'the quote is escaped, not dropped');
  });

  test('pkexec is pointed OUT of the bundle, never into it', () async {
    // The one that matters, and the one a developer machine cannot notice.
    //
    // An AppImage mounts its squashfs through libfuse WITHOUT `allow_other`,
    // so the kernel refuses that mountpoint to every uid except the one that
    // mounted it -- root included. A pkexec pointed at
    // /tmp/.mount_XXXXXX/usr/bin/helper/install-helper.sh gets EACCES on the
    // path itself and the script never runs. Run from a plain directory --
    // every developer build -- the identical code works.
    final exe = fakeBundle();
    final bundle = helperBundleDir(resolvedExecutable: exe);
    late List<String> args;
    var existedWhenRun = false;
    var executableWhenRun = false;

    await runInstallPrivileged(
      501,
      resolvedExecutable: exe,
      run: (_, a) async {
        args = a;
        final f = File(a.first);
        existedWhenRun = f.existsSync();
        // 0o100: owner-execute. pkexec execs this path, so a 0644 copy is one
        // it cannot run.
        executableWhenRun = existedWhenRun && f.statSync().mode & 0x40 != 0;
        return ProcessResult(0, 0, '', '');
      },
    );

    expect(
      args.first,
      isNot(startsWith(bundle)),
      reason: 'root cannot read the AppImage mount the bundle is inside',
    );
    expect(args.first, endsWith('/install-helper.sh'));
    expect(existedWhenRun, isTrue, reason: 'the copy must exist when it runs');
    expect(executableWhenRun, isTrue, reason: 'pkexec execs it');
  });

  test('the whole directory moves, not just the script', () async {
    // install-helper.sh reads the helper binary and the systemd unit from
    // beside itself, so a copy of the script alone installs nothing.
    final exe = fakeBundle();
    late String staged;
    await runInstallPrivileged(
      501,
      resolvedExecutable: exe,
      run: (_, a) async {
        staged = File(a.first).parent.path;
        expect(File('$staged/liostunnel-helper').existsSync(), isTrue);
        expect(File('$staged/liostunnel-helper.service').existsSync(), isTrue);
        expect(
          File('$staged/liostunnel-helper').statSync().mode & 0x40,
          isNot(0),
          reason: 'install-helper.sh installs it with `install -m 0755`, but '
              'a copy that lost the bit is not the file that was bundled',
        );
        return ProcessResult(0, 0, '', '');
      },
    );
  });

  test('the copy is deleted afterwards', () async {
    final exe = fakeBundle();
    late String staged;
    await runInstallPrivileged(
      501,
      resolvedExecutable: exe,
      run: (_, a) async {
        staged = File(a.first).parent.path;
        return ProcessResult(0, 0, '', '');
      },
    );
    expect(Directory(staged).existsSync(), isFalse);
  });

  test('a path with a space survives quoting', () async {
    final exe = fakeBundle(prefix: 'My Apps ');
    expect(exe, contains('My Apps '));
    late List<String> args;
    await runInstallPrivileged(
      501,
      resolvedExecutable: exe,
      run: (_, a) async {
        args = a;
        expect(File(a.first).readAsStringSync(), contains('#!/usr/bin/env'),
            reason: 'the copy was made from the path with the space in it');
        return ProcessResult(0, 0, '', '');
      },
    );
    // pkexec takes argv directly, so the path is one element rather than a
    // quoted string -- which is the point: no shell means nothing to break.
    expect(args, hasLength(3));
    expect(args, contains('--uid'));
    expect(args, contains('501'));
  });

  test('a cancel is not a failure', () async {
    // pkexec exits 126 when the dialog is dismissed or authorization is
    // refused. The user said no; that is not an error to show red text about.
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: fakeBundle(),
      run: (_, _) async => ProcessResult(0, 126, '', ''),
    );
    expect(r.outcome, InstallOutcome.cancelled);
  });

  test('a script pkexec could not run names the manual command', () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: fakeBundle(),
      run: (_, _) async => ProcessResult(0, 127, '', ''),
    );
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('install-helper.sh'));
  });

  test('a missing pkexec names the manual command', () async {
    // Process.run THROWS on a program that is not on PATH -- it does not come
    // back with 127, which is a shell's convention and not this one. Left
    // uncaught, a system without polkit installed got an unhandled exception
    // out of an unawaited callback instead of the sentence that fixes it.
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: fakeBundle(),
      run: (_, _) async =>
          throw ProcessException('pkexec', const [], 'No such file', 2),
    );
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('install-helper.sh'));
  });

  test('the command in the message is the one the panel shows', () async {
    // Two commands on screen at once is one too many, and the pair used to
    // disagree about which one worked: the notice named `sudo
    // /tmp/liostunnel-helper-XXXX/install-helper.sh`, the panel's monospace
    // line directly beneath it named the in-mount path that root cannot read.
    // They are now the same string, so there is one command and it is the one
    // that works.
    final exe = fakeBundle();
    final expected = installCommand(501, resolvedExecutable: exe);
    for (final r in [
      await runInstallPrivileged(501,
          resolvedExecutable: exe, run: (_, _) async => ProcessResult(0, 127, '', '')),
      await runInstallPrivileged(501,
          resolvedExecutable: exe,
          run: (_, _) async =>
              throw ProcessException('pkexec', const [], 'No such file', 2)),
    ]) {
      expect(r.outcome, InstallOutcome.failed);
      expect(r.message, contains(expected));
    }
  });

  test('the staged copy is always cleaned up, on every outcome', () async {
    // It is no longer kept for a message to name -- the message names
    // `installCommand`, which stages its own -- so nothing should survive any
    // of these.
    final staged = <String>[];
    Future<ProcessResult> Function(String, List<String>) recorder(
            ProcessResult result) =>
        (_, a) async {
          staged.add(File(a.first).parent.path);
          return result;
        };
    final exe = fakeBundle();
    for (final code in [0, 126, 127, 1]) {
      await runInstallPrivileged(501,
          resolvedExecutable: exe, run: recorder(ProcessResult(0, code, '', '')));
    }
    expect(staged, hasLength(4), reason: 'precondition: four runs, four copies');
    for (final d in staged) {
      expect(Directory(d).existsSync(), isFalse, reason: d);
    }
  });

  test("a failing script's own words are shown", () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: fakeBundle(),
      run: (_, _) async =>
          ProcessResult(0, 1, '', 'error: refusing to authorize uid 0'),
    );
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('refusing to authorize uid 0'));
  });

  test('success is reported as installed', () async {
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: fakeBundle(),
      run: (_, _) async => ProcessResult(0, 0, 'helper installed', ''),
    );
    expect(r.outcome, InstallOutcome.installed);
  });

  test('nothing is escalated when there is nothing to install', () async {
    // A build without the helper beside it -- `flutter run` from a checkout is
    // exactly that. Raising a password prompt for a script that is not there
    // asks the user to authorize nothing.
    var ran = false;
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: '/nonexistent/usr/bin/liostunnel_app',
      run: (_, _) async {
        ran = true;
        return ProcessResult(0, 0, '', '');
      },
    );
    expect(ran, isFalse);
    expect(r.outcome, InstallOutcome.failed);
    expect(r.message, contains('/nonexistent/usr/bin/helper'));
  });

  test('the uid is this process\'s own, and matches the system', () async {
    // Read through getuid(2) rather than `id -u`: a subprocess never
    // completes inside a testWidgets fake-async zone, and the install runs
    // from `initState`, so a Process.run here would park the whole first
    // launch forever in every widget test that drives it.
    final r = await Process.run('id', ['-u']);
    expect(currentUid(), int.parse('${r.stdout}'.trim()));
  });

  test('only a helper that was never installed is worth installing', () {
    // ENOENT means no helper. EACCES means there IS one, installed for
    // somebody else -- installing a second is not the fix, and the user
    // cannot authorize their way out of another account's socket.
    expect(installWouldFix(const HelperNotInstalled()), isTrue);
    expect(installWouldFix(const HelperForbidden()), isFalse);
    expect(
      installWouldFix(const HelperError(ErrorKindDto.unauthorized, 'no')),
      isFalse,
    );
  });

  test('a helper that answered once is never reinstalled over', () {
    // This read `e is HelperUnavailable`, and helper_client.dart throws that
    // from four places. Three of them are on a socket that OPENED -- the
    // connection dropped, a send with no socket, a failed write -- and the
    // fourth is every connect errno that is not EACCES/EPERM, ECONNREFUSED
    // included, which is a socket that is there with a dead daemon behind it.
    // All four said "install the helper", so on Linux a crashed helper raised
    // the polkit dialog at startup and, on approval, reinstalled over itself.
    for (final e in const [
      HelperUnavailable('Connection refused'),
      HelperUnavailable('the connection dropped'),
      HelperUnavailable('not connected'),
      HelperUnavailable('SocketException: write failed'),
    ]) {
      expect(installWouldFix(e), isFalse, reason: '$e');
    }
    // And the subtype relationship is the trap this has to survive: a
    // HelperNotInstalled IS a HelperUnavailable, so an `is HelperUnavailable`
    // test still passes on the one case that should say yes.
    expect(const HelperNotInstalled(), isA<HelperUnavailable>());
  });
}

/// A tree shaped like the AppImage's, on a real filesystem.
///
/// The app at `usr/bin/liostunnel_app`, its helper directory beside it at
/// `usr/bin/helper` — the layout `make-appimage.sh` builds. Returns the path
/// of the executable, which is what the app knows about itself.
String fakeBundle({String prefix = 'lios-bundle', String? installScript}) {
  final root = Directory.systemTemp.createTempSync(prefix);
  addTearDown(() {
    if (root.existsSync()) root.deleteSync(recursive: true);
  });
  final bin = Directory('${root.path}/usr/bin')..createSync(recursive: true);
  final helper = Directory('${bin.path}/helper')..createSync();
  _executable(
      '${helper.path}/install-helper.sh', installScript ?? '#!/usr/bin/env bash\n');
  _executable('${helper.path}/liostunnel-helper', 'not really an ELF\n');
  File('${helper.path}/liostunnel-helper.service')
      .writeAsStringSync('[Unit]\n');
  return '${bin.path}/liostunnel_app';
}

/// Writes a 0755 file, the mode `make-appimage.sh` installs these two with.
void _executable(String path, String content) {
  File(path).writeAsStringSync(content);
  final r = Process.runSync('chmod', ['0755', path]);
  if (r.exitCode != 0) throw StateError('chmod $path: ${r.stderr}');
}
