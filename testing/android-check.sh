#!/bin/sh
# Compile-check the Rust crates for Android without a Gradle cycle.
#
# `flutter build apk` takes ~6 minutes to tell you that a `#[cfg]` is wrong.
# This does the same job in seconds, which matters because the entire
# Android-specific surface is invisible to `cargo test` and to CI -- the only
# thing standing between a cfg mistake and a device is a compile.
#
# cargokit sets this toolchain up itself during a real build; this script
# exists so the same check can be run on its own.
#
# Usage: testing/android-check.sh [extra cargo args]
set -eu

NDK_VERSION=27.1.12297006
API=29

sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
ndk="$sdk/ndk/$NDK_VERSION"
[ -d "$ndk" ] || { echo "NDK $NDK_VERSION not found at $ndk" >&2; exit 1; }

case "$(uname -s)" in
    Darwin) host=darwin-x86_64 ;;
    Linux)  host=linux-x86_64 ;;
    *)      echo "unsupported host: $(uname -s)" >&2; exit 1 ;;
esac

bin="$ndk/toolchains/llvm/prebuilt/$host/bin"
[ -d "$bin" ] || { echo "NDK toolchain not found at $bin" >&2; exit 1; }

# aws-lc-sys (BoringSSL, via russh) compiles C and looks for a bare
# `aarch64-linux-android-clang`, which the NDK does not ship -- its clang
# wrappers carry the API level in the name. Pointing CC at the versioned
# wrapper is what makes the SSH dependency cross-compile at all.
target=aarch64-linux-android
cc="$bin/${target}${API}-clang"
[ -x "$cc" ] || { echo "clang not found: $cc" >&2; exit 1; }

CC_aarch64_linux_android="$cc" \
AR_aarch64_linux_android="$bin/llvm-ar" \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$cc" \
exec cargo check -p liostunnel-core -p liostunnel_ffi \
    --target "$target" "$@"
