//! LiosTunnel core engine. See docs/superpowers/specs/2026-07-27-liostunnel-phase0-design.md

pub mod config;
pub mod error;
pub mod net;
pub mod protocols;
pub mod stats;

pub use error::TunnelError;
