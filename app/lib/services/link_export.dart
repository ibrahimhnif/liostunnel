import 'dart:io';

import '../src/rust/api/config.dart';
import 'profile_store.dart';

/// The `ss://` link for a saved profile — password and all.
///
/// **The returned String is a credential.** There is no secret-free form of an
/// `ss://` link: the password is what makes it usable in another client, which
/// is the entire point of the feature. It must never be rendered, logged or
/// put in an error message; see [confirmAndCopyLink], which is the only thing
/// that should call this.
///
/// Kept out of the widget so it has a test on a real event loop — it crosses
/// the FFI twice — and so the two rules below are stated once.
///
/// The secret file is read as **bytes** and turned into a password by
/// [fileSecretValue], not by `readAsStringSync`. Both halves matter:
///
///  * A `file:` secret's *value* is not the file's raw contents. The core
///    strips one trailing line ending, so a password written by
///    `echo hunter2 > pw` is `hunter2` — that is what the helper connects
///    with. Reading the raw string here produced a link whose password was
///    `hunter2\n`: the tunnel worked, the copied link did not, and Shadowsocks
///    has no handshake in which to say so.
///  * A credential is bytes, and not every credential is text. Decoding one
///    in Dart answers a binary key with a complaint about UTF-8 byte offsets,
///    from a gesture that said "copy link". The refusal is ours instead.
Future<String> ssLinkFor(LoadedProfile p) async {
  final dto = p.profile;
  if (dto == null) {
    throw StateError('a profile that does not parse cannot be copied as a link');
  }
  final source = dto.authSecretSource;
  if (!source.startsWith('file:')) {
    throw StateError(
      "this profile's password is not in a file this app can read",
    );
  }
  final file = File(source.substring('file:'.length));
  if (!file.existsSync()) {
    throw StateError("this profile's password file is missing");
  }
  final password = await fileSecretValue(bytes: file.readAsBytesSync());
  return exportSsUri(dto: dto, password: password);
}
