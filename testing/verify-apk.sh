#!/usr/bin/env bash
#
# Proves a release APK carries what it claims, without installing it.
#
#     ./testing/verify-apk.sh app/build/app/outputs/flutter-apk/app-arm64-v8a-release.apk
#
# Reads the archive only. Nothing here needs a device, an emulator, or the
# Android SDK -- which matters because CI has none of them, and the thing most
# worth catching (an APK with no Rust library in it, or one carrying every ABI
# despite its filename) is visible in the zip listing.
set -uo pipefail
apk="${1:-}"
[ -f "$apk" ] || { echo "usage: $0 <file.apk>"; exit 1; }

pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

echo "verifying $(basename "$apk")"

listing="$(unzip -l "$apk" 2>/dev/null)"
[ -n "$listing" ] || { echo "  FAIL  not a readable zip archive"; exit 1; }

# 1. The Rust engine is in there.
#
# An APK that builds without it is the failure mode worth guarding: cargokit
# runs as part of the Gradle build, and when it silently does not, the app
# installs, launches, and dies at the first FFI call.
so_count="$(printf '%s\n' "$listing" | grep -c 'libliostunnel_ffi\.so')"
if [ "$so_count" -ge 1 ]; then
    ok "carries libliostunnel_ffi.so"
else
    bad "no libliostunnel_ffi.so -- cargokit did not run"
fi

# 2. Exactly one ABI.
#
# CHECKED IN THE CONTENTS, NOT THE FILENAME. `--split-per-abi` names its
# outputs after the ABI whether or not the split took effect, so
# `app-arm64-v8a-release.apk` containing four ABIs is a real and silent
# outcome -- and the only symptom is an artifact three times bigger than it
# should be, which nobody notices.
abis="$(printf '%s\n' "$listing" | awk '{print $4}' | grep '^lib/' | cut -d/ -f2 | sort -u)"
abi_count="$(printf '%s\n' "$abis" | grep -c .)"
if [ "$abi_count" -eq 1 ]; then
    ok "exactly one ABI: $(printf '%s' "$abis" | tr '\n' ' ')"
else
    bad "expected one ABI, found $abi_count: $(printf '%s' "$abis" | tr '\n' ' ')"
fi

# 3. The filename and the contents agree.
#
# A mismatch means the artifacts were renamed or reordered somewhere, and
# whoever downloads `arm64-v8a` gets a library their phone cannot load.
name_abi="$(basename "$apk" | sed -n 's/^app-\(.*\)-release\.apk$/\1/p')"
if [ -z "$name_abi" ]; then
    ok "filename carries no ABI claim to contradict"
elif [ "$name_abi" = "$(printf '%s' "$abis" | head -1)" ]; then
    ok "filename ABI matches contents ($name_abi)"
else
    bad "filename says $name_abi, contents say $(printf '%s' "$abis" | tr '\n' ' ')"
fi

# 4. The service is declared.
#
# A VpnService that is not declared cannot be started at all, and the app fails
# only when the user taps Connect -- long after every build and install step
# has reported success.
#
# The manifest is Android binary XML and its string pool is UTF-16LE, which is
# why this decodes rather than greps. `strings` and `grep` both find nothing in
# it: the first version of this check used `tr -d '\000' | grep`, reported
# "does not mention LiosVpnService" for three APKs that all declared it
# correctly, and would have failed CI on a perfectly good artifact.
if unzip -p "$apk" AndroidManifest.xml 2>/dev/null | python3 -c '
import sys
blob = sys.stdin.buffer.read()
sys.exit(0 if "LiosVpnService" in blob.decode("utf-16-le", errors="ignore") else 1)
'; then
    ok "declares LiosVpnService"
else
    bad "AndroidManifest.xml does not declare LiosVpnService"
fi

# 5. The native library is 16 KB page aligned.
#
# Android 15 brought devices with a 16 KB memory page size, and a library whose
# LOAD segments are aligned to the older 4 KB cannot be mapped on them: the app
# installs and then fails to load its own engine. Play requires this of anything
# targeting 15 or later, which this app does.
#
# The ELF headers are parsed here rather than shelled out to readelf, which is
# not present on every runner. Checked in the artifact rather than the build
# tree, because the thing that ships is the only thing worth asserting about.
lib="$(printf '%s\n' "$listing" | awk '{print $4}' | grep 'libliostunnel_ffi\.so$' | head -1)"
if [ -z "$lib" ]; then
    bad "no native library to check alignment on"
else
    align="$(unzip -p "$apk" "$lib" 2>/dev/null | python3 -c '
import struct, sys
d = sys.stdin.buffer.read()
if d[:4] != b"\x7fELF":
    print("not-elf"); raise SystemExit
is64 = d[4] == 2
if is64:
    phoff, = struct.unpack_from("<Q", d, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
    ptype_off, align_off = 0, 48
else:
    phoff, = struct.unpack_from("<I", d, 0x1c)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x2a)
    ptype_off, align_off = 0, 28
worst = None
for i in range(phnum):
    o = phoff + i * phentsize
    ptype, = struct.unpack_from("<I", d, o + ptype_off)
    if ptype != 1:          # PT_LOAD
        continue
    a, = struct.unpack_from("<Q" if is64 else "<I", d, o + align_off)
    worst = a if worst is None else min(worst, a)
print(worst if worst is not None else "no-load")
')"
    case "$align" in
        16384|32768|65536) ok "native library is $align-byte page aligned" ;;
        not-elf|no-load|"") bad "could not read ELF program headers from $lib" ;;
        *) bad "native library aligned to $align, needs at least 16384 for Android 15+ devices" ;;
    esac
fi

# 6. Flutter's own assets are present, so this is an app rather than a shell.
if printf '%s\n' "$listing" | grep -q 'flutter_assets'; then
    ok "carries flutter_assets"
else
    bad "no flutter_assets"
fi

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
