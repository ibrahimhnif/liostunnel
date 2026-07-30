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

  test('a command the user is told to run still exists to be run', () async {
    // The copy is deleted after a normal run. On the two failures whose whole
    // message is "run this yourself", deleting it would name a path that is
    // already gone -- and the bundle's own path is the one root cannot read.
    final exe = fakeBundle();
    late String staged;
    final r = await runInstallPrivileged(
      501,
      resolvedExecutable: exe,
      run: (_, a) async {
        staged = File(a.first).parent.path;
        return ProcessResult(0, 127, '', '');
      },
    );
    addTearDown(() {
      final d = Directory(staged);
      if (d.existsSync()) d.deleteSync(recursive: true);
    });
    expect(r.message, contains(staged));
    expect(File('$staged/install-helper.sh').existsSync(), isTrue);
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
    expect(installWouldFix(const HelperUnavailable()), isTrue);
    expect(installWouldFix(const HelperForbidden()), isFalse);
    expect(
      installWouldFix(const HelperError(ErrorKindDto.unauthorized, 'no')),
      isFalse,
    );
  });
}

/// A tree shaped like the AppImage's, on a real filesystem.
///
/// The app at `usr/bin/liostunnel_app`, its helper directory beside it at
/// `usr/bin/helper` — the layout `make-appimage.sh` builds. Returns the path
/// of the executable, which is what the app knows about itself.
String fakeBundle({String prefix = 'lios-bundle'}) {
  final root = Directory.systemTemp.createTempSync(prefix);
  addTearDown(() {
    if (root.existsSync()) root.deleteSync(recursive: true);
  });
  final bin = Directory('${root.path}/usr/bin')..createSync(recursive: true);
  final helper = Directory('${bin.path}/helper')..createSync();
  _executable('${helper.path}/install-helper.sh', '#!/usr/bin/env bash\n');
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
