#!/usr/bin/env bash
#
# Stages the FFI dynamic library where `flutter test` expects it.
#
#     ./testing/build-ffi-for-tests.sh && (cd app && flutter test)
#
# Two different loading paths, deliberately:
#
#   * The **app** links the Rust statically. cargokit builds
#     `libliostunnel_ffi.a` and the podspec force-loads it into the binary, so
#     a shipped `.app` carries no separate library at all.
#   * **`flutter test`** runs on the plain Dart VM with no Xcode build behind
#     it, so it uses the generated loader, which opens a dynamic library from
#     the directory named in `frb_generated.dart`.
#
# That directory is the crate's own `target/`, which the workspace does not
# otherwise use — everything builds into the shared `/target`. Hence this
# copy. It is git-ignored: a build artifact, not a source of truth.
#
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

case "$(uname -s)" in
  Darwin) lib=libliostunnel_ffi.dylib ;;
  Linux)  lib=libliostunnel_ffi.so ;;
  *) echo "unsupported platform $(uname -s)"; exit 1 ;;
esac

cargo build --release -p liostunnel_ffi
dest="crates/liostunnel-ffi/target/release"
mkdir -p "$dest"
cp "target/release/$lib" "$dest/$lib"
echo "staged $dest/$lib"
