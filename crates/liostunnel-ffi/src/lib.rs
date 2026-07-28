//! FFI surface for the LiosTunnel desktop app.
//!
//! Owns its own DTOs rather than exporting `liostunnel-core` types, so that
//! `flutter_rust_bridge`'s type constraints cannot reach into the core and
//! core changes cannot silently break Dart codegen. Spec §9.

pub mod api;
pub mod dto;

/// Written by `flutter_rust_bridge_codegen generate`; never edited by hand.
///
/// The allow is scoped to this module rather than the crate. FRB's IO
/// boilerplate takes raw pointers across the FFI boundary from a safe fn,
/// which `not_unsafe_ptr_arg_deref` objects to and which we do not control.
/// Allowing it crate-wide would silence the same lint over code we DO write,
/// and this crate exists to hand pointers between two runtimes — exactly
/// where that lint earns its keep.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub mod frb_generated;
