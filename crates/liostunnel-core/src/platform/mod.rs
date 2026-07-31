//! Platform-specific code that has no cross-platform counterpart.
//!
//! Everything here is gated on a single target and therefore invisible to
//! `cargo test` on a development machine and to CI. That is a permanent
//! property, not a temporary gap, so the rule for this module is that it
//! stays small enough to audit by reading: plumbing only, no logic that
//! could be written and tested somewhere testable instead.

#[cfg(target_os = "android")]
pub mod android;
