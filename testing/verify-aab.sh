#!/usr/bin/env bash
#
# Checks an Android App Bundle before it is uploaded to Play.
#
#     ./testing/verify-aab.sh app/build/app/outputs/bundle/release/app-release.aab
#
# Reads the archive only. Every check here corresponds to something Play
# rejects or something a device fails on after installing successfully, and
# each one costs a round trip through the Play Console to discover otherwise.
set -uo pipefail
aab="${1:-}"
[ -f "$aab" ] || { echo "usage: $0 <file.aab>"; exit 1; }

pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
warn() { echo "  WARN  $*"; }

echo "verifying $(basename "$aab")"
listing="$(unzip -l "$aab" 2>/dev/null)"
[ -n "$listing" ] || { echo "  FAIL  not a readable zip archive"; exit 1; }

# 1. It is actually a bundle, not an APK with the wrong extension.
if printf '%s\n' "$listing" | grep -q 'BundleConfig\.pb'; then
    ok "is an app bundle (BundleConfig.pb present)"
else
    bad "no BundleConfig.pb — this is not an app bundle"
fi

# 2. The Rust engine is in it, for every ABI.
#
# A bundle carries all ABIs and Play splits them per device, so unlike the
# per-ABI APKs this one SHOULD list several. A missing one means devices of
# that architecture get an app that cannot load its own engine.
abis="$(printf '%s\n' "$listing" | awk '{print $4}' \
        | grep 'libliostunnel_ffi\.so$' | sed 's#.*/lib/\([^/]*\)/.*#\1#' | sort -u)"
n="$(printf '%s\n' "$abis" | grep -c .)"
if [ "$n" -ge 3 ]; then
    ok "carries the engine for $n ABIs: $(printf '%s' "$abis" | tr '\n' ' ')"
else
    bad "engine present for only $n ABI(s): $(printf '%s' "$abis" | tr '\n' ' ')"
fi

# 3. Signed with a real upload key, not the debug key.
#
# Play rejects a debug-signed bundle. Without android/key.properties the
# release build falls back to debug signing so CI keeps working, which is
# convenient and would otherwise be discovered only at upload.
cert="$(printf '%s\n' "$listing" | awk '{print $4}' | grep -E 'META-INF/.*\.(RSA|DSA|EC)$' | head -1)"
if [ -z "$cert" ]; then
    bad "not signed at all"
elif ! command -v keytool >/dev/null; then
    warn "keytool not available; cannot check which key signed this"
else
    owner="$(unzip -p "$aab" "$cert" 2>/dev/null | keytool -printcert 2>/dev/null | sed -n 's/^Owner: //p' | head -1)"
    case "$owner" in
        *"CN=Android Debug"*)
            bad "DEBUG-SIGNED ($owner) — Play will reject this. Create android/key.properties; see docs/ANDROID-RELEASE.md" ;;
        "")
            bad "could not read the signing certificate" ;;
        *)
            ok "signed by $owner" ;;
    esac
fi

# 4. Native libraries are 16 KB page aligned.
#
# Android 15 brought 16 KB page devices, and a library aligned to the older
# 4 KB cannot be mapped on them: the app installs and then cannot load its
# engine. Required by Play for anything targeting 15 or later.
lib="$(printf '%s\n' "$listing" | awk '{print $4}' | grep 'libliostunnel_ffi\.so$' | head -1)"
if [ -z "$lib" ]; then
    bad "no native library to check alignment on"
else
    align="$(unzip -p "$aab" "$lib" 2>/dev/null | python3 -c '
import struct, sys
d = sys.stdin.buffer.read()
if d[:4] != b"\x7fELF":
    print("not-elf"); raise SystemExit
is64 = d[4] == 2
if is64:
    phoff, = struct.unpack_from("<Q", d, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
    align_off = 48
else:
    phoff, = struct.unpack_from("<I", d, 0x1c)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x2a)
    align_off = 28
worst = None
for i in range(phnum):
    o = phoff + i * phentsize
    ptype, = struct.unpack_from("<I", d, o)
    if ptype != 1:
        continue
    a, = struct.unpack_from("<Q" if is64 else "<I", d, o + align_off)
    worst = a if worst is None else min(worst, a)
print(worst if worst is not None else "no-load")
')"
    case "$align" in
        16384|32768|65536) ok "native libraries are $align-byte page aligned" ;;
        not-elf|no-load|"")  bad "could not read ELF program headers from $lib" ;;
        *) bad "aligned to $align, needs at least 16384 for Android 15+ devices" ;;
    esac
fi

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
