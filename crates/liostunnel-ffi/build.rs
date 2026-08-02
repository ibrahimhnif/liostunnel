//! Link flags that must survive however the crate is built.
//!
//! # Why a build script and not `.cargo/config.toml`
//!
//! A `[target.<triple>] rustflags` entry is discarded the moment the
//! `RUSTFLAGS` environment variable is set, and CI sets it workflow-wide
//! (`RUSTFLAGS: -D warnings`). The flag below would therefore apply on a
//! development machine and vanish in the artifacts that actually ship —
//! producing a library that looks correct everywhere it is checked by hand and
//! is wrong everywhere it matters.
//!
//! `cargo::rustc-link-arg` is not subject to that precedence, so the flag
//! holds regardless of the environment.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    // 16 KB page alignment, required on Android from API 35.
    //
    // Android 15 introduced devices with a 16 KB memory page size, and a
    // native library whose LOAD segments are aligned to the older 4 KB cannot
    // be mapped on them: the app installs and then fails to load its own
    // library. Google Play requires 16 KB support for apps targeting 15 or
    // later, which this one now does.
    //
    // Measured rather than assumed: before this, `llvm-readelf -l` reported
    // `align 0x1000` on every .so cargokit produced, on all four ABIs.
    // `testing/verify-apk.sh` asserts the alignment so a regression fails CI
    // instead of reaching a device that cannot start the app.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo::rustc-link-arg=-Wl,-z,max-page-size=16384");
        println!("cargo::rustc-link-arg=-Wl,-z,common-page-size=16384");
    }
}
