//! Exists only to prove the codegen pipeline before the real DTOs are
//! written.
//!
//! Spec §9 names FRB codegen as the least-known surface in this slice, and
//! every unfamiliar API in Phase 0 produced at least one genuine plan error.
//! This is the cheap version of that lesson: the probe deliberately carries
//! the shapes the profile and protocol DTOs need — a struct, an `Option`, a
//! `Vec`, and a tagged enum — so an FRB limitation surfaces here rather than
//! halfway through the real work.
//!
//! Kept rather than deleted after verification: it is a permanent smoke test
//! that fails loudly whenever the toolchain breaks on a future `generate`.

#[derive(Clone, Debug, PartialEq)]
pub struct ProbeDto {
    pub name: String,
    pub count: u32,
    pub maybe: Option<String>,
    pub items: Vec<String>,
    pub choice: ProbeChoice,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeChoice {
    First,
    Second { detail: String },
}

/// Round-trips its argument. Dart asserts the value survives unchanged.
pub fn echo_probe(input: ProbeDto) -> ProbeDto {
    input
}
