#!/usr/bin/env bash
#
# Checks that the symbols Rust exports are exactly the ones Kotlin's native
# methods will look for, package and all.
#
#     ./testing/verify-jni-symbols.sh [path/to/libliostunnel_ffi.so]
#
# Nothing else checks this. JNI derives a symbol name from the class's package,
# so renaming the package, moving the class, or changing `applicationId` breaks
# the link silently: Kotlin compiles, Rust compiles, the APK builds and
# installs, and the service throws UnsatisfiedLinkError the first time a user
# taps Connect.
#
# Already caught in this repo: `nativeStop` deleted while Kotlin still declared
# it, and `nativeTunAddress`/`nativeTunMtu` exported but never called, which
# left the VpnService builder hardcoding an address the packet stack did not
# answer on.
#
# THE FULL SYMBOL IS COMPARED, NOT THE METHOD NAME. An earlier version of this
# script stripped everything up to the last underscore and compared only the
# tail, so `Java_com_liostunnel_app_..._nativeInit` and
# `Java_id_liostech_liostunnel_..._nativeInit` looked identical to it. It
# passed a package rename that had not reached the library at all -- the exact
# failure the script exists to catch.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kt_dir="$repo/app/android/app/src/main/kotlin"

# THE NEWEST LIBRARY, NAMED OUT LOUD. A plain `find | head -1` picked a release
# build from the previous day here, so the check ran against a library that
# predated the change being verified.
so="${1:-}"
if [ -z "$so" ]; then
    so="$(find "$repo/app/build" -name libliostunnel_ffi.so -path '*arm64*' \
          -exec stat -f '%m %N' {} + 2>/dev/null \
          | sort -rn | head -1 | cut -d' ' -f2-)"
fi
[ -f "$so" ] || { echo "no .so given and none found under app/build; build first" >&2; exit 1; }
echo "library: ${so#"$repo"/}"
echo "built:   $(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$so" 2>/dev/null || date -r "$so" 2>/dev/null)"

nm=""
for c in llvm-nm nm; do command -v "$c" >/dev/null && nm="$c" && break; done
if [ -z "$nm" ]; then
    ndk_nm="$(find "${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk" -name llvm-nm -type f 2>/dev/null | head -1)"
    [ -x "$ndk_nm" ] && nm="$ndk_nm"
fi
[ -n "$nm" ] || { echo "no nm available to read $so" >&2; exit 1; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# What Kotlin will ask for: package + class + method, mangled the way JNI does
# it. A dot becomes an underscore and an underscore becomes `_1`; the second
# rule is why the package deliberately has no underscores in it.
: > "$tmp/kotlin"
for f in $(grep -rl 'external fun' "$kt_dir" 2>/dev/null); do
    pkg="$(sed -n 's/^package  *\([A-Za-z0-9_.]*\).*/\1/p' "$f" | head -1)"
    cls="$(basename "$f" .kt)"
    [ -n "$pkg" ] || { echo "no package declaration in $f" >&2; exit 1; }
    mangled="$(printf '%s' "$pkg" | sed 's/_/_1/g; s/\./_/g')"
    grep -o 'external fun [a-zA-Z][a-zA-Z0-9_]*' "$f" | awk '{print $3}' \
        | sed "s/_/_1/g; s/^/Java_${mangled}_${cls}_/" >> "$tmp/kotlin"
done
sort -u -o "$tmp/kotlin" "$tmp/kotlin"

"$nm" -D --defined-only "$so" 2>/dev/null \
    | grep -o 'Java_[A-Za-z0-9_]*' | sort -u > "$tmp/rust"

echo
echo "kotlin expects:"; sed 's/^/  /' "$tmp/kotlin"
echo "rust exports:";   sed 's/^/  /' "$tmp/rust"
echo

fail=0
missing="$(comm -13 "$tmp/rust" "$tmp/kotlin")"
if [ -n "$missing" ]; then
    echo "FAIL  Kotlin will look for these and not find them (UnsatisfiedLinkError):" >&2
    echo "$missing" | sed 's/^/        /' >&2
    fail=1
fi

extra="$(comm -23 "$tmp/rust" "$tmp/kotlin")"
if [ -n "$extra" ]; then
    echo "FAIL  exported by Rust, nothing in Kotlin declares them (dead, or a forgotten call site):" >&2
    echo "$extra" | sed 's/^/        /' >&2
    fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS  the JNI surfaces match exactly, package included"
exit "$fail"
