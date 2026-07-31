#!/usr/bin/env bash
#
# Builds the Linux AppImage. Assumes both builds have run:
#
#     cargo build --release -p liostunnel-helper
#     cd app && flutter build linux --release
#     ./packaging/make-appimage.sh
#
# appimagetool is downloaded into ~/.cache/liostunnel if absent: it is not in
# this repo and not on the author's machine, so CI is where it first runs.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
# Named for the tree that was built, not the commit it sits on -- the same
# rule, and the same `git describe` suffix, as make-pkg.sh. An AppImage built
# from a working tree with uncommitted changes carries code that is at no
# commit at all, and a bare short SHA in the filename is a claim this script
# had not checked.
sha="$(git -C "$repo" rev-parse --short HEAD)"
[ -z "$(git -C "$repo" status --porcelain)" ] || sha="$sha-dirty"
helper="$repo/target/release/liostunnel-helper"
build="$repo/app/build/linux"

die() { echo "error: $*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || die "this builds a Linux AppImage; run it on Linux"
[ -f "$helper" ] || die "no helper at $helper — run: cargo build --release -p liostunnel-helper"

# The directory first, because the `find` below cannot report its absence: with
# `set -euo pipefail` the pipeline's status decided the assignment's fate, and
# `find` exits 1 on a missing tree. The script died HERE, on a raw
# `find: … No such file or directory`, and the die whose entire job is to name
# the command that fixes it was unreachable in exactly the case it was written
# for. Reproduced: rc=1, and the message below never printed.
[ -d "$build" ] || die "no $build — run: cd app && flutter build linux --release"
# `-path '*/release/bundle'`, not `-name bundle`: `flutter build linux --debug`
# and `--profile` leave x64/debug/bundle and x64/profile/bundle beside
# x64/release/bundle, and `head -1` chose between them by directory order --
# which is a filesystem hash, not a rule (on APFS here it returned
# release, aaa, zzz for those three names: neither sorted nor creation order).
# Losing that coin flip ships a debug build named for the commit, labelled
# release, and nothing downstream -- including the verifier -- can tell.
#
# No `head`, and `|| true` inside the substitution, for the other half of the
# same problem: `head` closing the pipe early makes the pipeline 141 on a large
# enough result, which under `pipefail` killed the script with no message at
# all. Reproduced at 5 runs out of 5 on a 4000-match tree.
bundles="$(find "$build" -maxdepth 3 -type d -path '*/release/bundle' 2>/dev/null || true)"
[ -n "$bundles" ] || die "no release bundle under $build — run: cd app && flutter build linux --release"
# Cross-compiling leaves x64/release/bundle and arm64/release/bundle side by
# side, and which one to ship is not this script's guess to make.
[ "$(printf '%s\n' "$bundles" | wc -l)" -eq 1 ] \
  || die "more than one release bundle under $build; remove the ones you are not shipping: $(printf '%s' "$bundles" | tr '\n' ' ')"
bundle="$bundles"

dist="$repo/dist"; appdir="$dist/AppDir"
rm -rf "$dist"; mkdir -p "$appdir/usr/bin"

cp -R "$bundle/." "$appdir/usr/bin/"
inner="$appdir/usr/bin/helper"
mkdir -p "$inner"
# THESE CANNOT BE RUN FROM INSIDE THE MOUNTED APPIMAGE BY ANOTHER USER.
#
# An AppImage mounts its squashfs through libfuse WITHOUT `allow_other`, so the
# kernel denies that mountpoint to every uid except the one that mounted it --
# root included. A first-launch flow that elevates with pkexec (or sudo, or
# anything else) and points the elevated process at
# /tmp/.mount_XXXXXX/usr/bin/helper/install-helper.sh gets EACCES on the path
# itself: the script never runs, and the error names a temp directory rather
# than a permission model.
#
# So whatever drives the install MUST copy this whole directory out of the
# mount onto a real filesystem the elevated process can read -- a temp dir the
# invoking user owns -- and elevate against THAT copy. install-helper.sh is
# already written for it: it prefers the binary beside itself, so the copy is
# self-contained and installs the bundled helper rather than anything stale.
#
# testing/verify-appimage.sh cannot catch a regression here. It extracts rather
# than mounts, so it never has a FUSE mountpoint to be refused by, and every
# path it checks is an ordinary directory it owns.
install -m 0755 "$helper"                         "$inner/liostunnel-helper"
install -m 0755 "$here/install-helper.sh"         "$inner/install-helper.sh"
install -m 0755 "$here/uninstall-helper.sh"       "$inner/uninstall-helper.sh"
# Only the systemd unit. A launchd plist in a Linux AppImage reads as an
# oversight rather than symmetry.
install -m 0644 "$here/liostunnel-helper.service" "$inner/liostunnel-helper.service"

install -m 0644 "$here/appimage/liostunnel.desktop" "$appdir/liostunnel.desktop"
# Reuse the macOS icon rather than adding a second one to keep in step.
# The canonical raster, not the macOS asset catalogue: reaching into another
# platform's icon set to build this one is how the two quietly diverge.
install -m 0644 "$repo/assets/logo/liostunnel-1024.png" "$appdir/liostunnel.png"

cat > "$appdir/AppRun" <<'RUN'
#!/bin/sh
# An AppImage mounts itself at /tmp/.mount_XXXXXX, so the AppDir is at no fixed
# path at runtime and has to be resolved. `readlink -f "$0"` does that without
# depending on anything the runtime sets: AppRun sits at the AppDir root, so
# its own directory IS the AppDir. (The runtime also exports $APPDIR, which
# says the same thing; this deliberately does not read it, so extract-and-run
# and a plain mount behave identically.) The app finds its bundled helper
# relative to its own executable, which is inside this same tree.
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/liostunnel_app" "$@"
RUN
chmod 755 "$appdir/AppRun"

# Outside $dist, which is rm -rf'd above. A cache inside the directory this
# script deletes on every run was not a cache: the `-x` guard was always false,
# the tool was refetched every build, and every build therefore depended on
# GitHub being reachable. A downloaded build tool belongs in XDG_CACHE_HOME
# anyway, where it survives `rm -rf dist` and a `git clean`.
cache="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/liostunnel"
tool="$cache/appimagetool-x86_64.AppImage"
if [ ! -x "$tool" ]; then
  mkdir -p "$cache"
  # AppImage/AppImageKit's "continuous" release is now marked obsolete by its
  # maintainers, who moved the tool to its own repo; the old URL still
  # resolves but only serves a stale, unmaintained build.
  url=https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
  # Into .part and moved into place only on success. `curl -S` does print its
  # own diagnostic, but it names neither this tool nor this URL -- and the
  # comment above records that this URL has moved once already, so the failure
  # worth naming is precisely the one curl will not name. And now that this is
  # a cache that persists, a half-written file from an interrupted download
  # would be executable, would satisfy the guard above, and would poison every
  # later build on the machine.
  curl -fsSL -o "$tool.part" "$url" \
    || die "could not download appimagetool from $url"
  chmod 755 "$tool.part"
  mv "$tool.part" "$tool"
fi

out="$dist/LiosTunnel-$sha-x86_64.AppImage"
# --appimage-extract-and-run because CI containers have no FUSE.
ARCH=x86_64 "$tool" --appimage-extract-and-run "$appdir" "$out"
echo "$out"
