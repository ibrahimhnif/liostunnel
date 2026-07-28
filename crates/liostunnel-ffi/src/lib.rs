//! FFI surface for the LiosTunnel desktop app.
//!
//! Owns its own DTOs rather than exporting `liostunnel-core` types, so that
//! `flutter_rust_bridge`'s type constraints cannot reach into the core and
//! core changes cannot silently break Dart codegen. Spec §9.

pub mod dto;
