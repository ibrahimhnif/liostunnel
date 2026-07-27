use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::TunnelError;
use crate::route::RouteCommand;

/// Written *before* routes are applied, so a `kill -9` leaves a record behind
/// and the next start can clean up. The third of the three cleanup paths in
/// spec §10; PRD §8 requires surviving a crash.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppliedState {
    pub interface: String,
    /// Exactly the commands needed to undo what was applied.
    pub revert: Vec<RouteCommand>,
    pub pid: u32,
}

impl AppliedState {
    pub fn save(&self, path: &Path) -> Result<(), TunnelError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| TunnelError::Route(format!("cannot create state dir: {e}")))?;
        }
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| TunnelError::Route(format!("cannot serialise state: {e}")))?;
        std::fs::write(path, body)
            .map_err(|e| TunnelError::Route(format!("cannot write state file: {e}")))
    }

    pub fn load(path: &Path) -> Result<Self, TunnelError> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| TunnelError::Route(format!("cannot read state file: {e}")))?;
        serde_json::from_str(&body)
            .map_err(|e| TunnelError::Route(format!("cannot parse state file: {e}")))
    }

    pub fn clear(path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

/// Whether `pid` refers to a currently-running process.
///
/// This is deliberately a **bare** PID check, not a check that also confirms
/// the process is actually a liostunnel instance (e.g. by matching its
/// executable name or start time). Two things make that an acceptable
/// tradeoff for Phase 0 rather than a latent safety hole:
///
/// - `kill(pid, 0)` succeeding is the *only* branch that treats the previous
///   run as "still alive and off-limits" (see `recover_if_stale` below); when
///   it succeeds for an unrelated process that happens to have inherited a
///   recycled PID, the result is `recover_if_stale` returning `Err` and
///   refusing to touch anything. That is a false refusal (annoying: the
///   operator must intervene, e.g. by confirming the old process is gone and
///   deleting the state file by hand), never a false deletion. The dangerous
///   direction — deciding a still-live instance's routes are safe to revert —
///   cannot happen through this path, because it requires `kill` to report
///   "not alive" for a PID that is in fact alive, which does not happen for a
///   root-owned liostunnel signalling another root-owned process (the normal
///   case, since route mutation requires root on both ends).
/// - A stricter check (matching `/proc/<pid>/comm` on Linux, `ps -p <pid> -o
///   comm=` on macOS, or a stored start-time) would reduce how often a
///   genuinely stale state file gets misjudged as live, but adds
///   platform-specific process introspection for a failure mode whose only
///   cost, as things stand, is an extra manual step by the operator — not a
///   connectivity-destroying one. That refinement is deferred past Phase 0.
#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Signal 0 tests for existence without delivering anything.
    // SAFETY: `kill` with signal 0 has no effect beyond returning a status.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

/// Cleans up routes left behind by a crashed run. Returns whether anything was
/// recovered. Called at startup, before any new routes are installed.
pub fn recover_if_stale(path: &Path) -> Result<bool, TunnelError> {
    if !path.exists() {
        return Ok(false);
    }
    let state = AppliedState::load(path)?;

    if process_is_alive(state.pid) && state.pid != std::process::id() {
        return Err(TunnelError::Route(format!(
            "another liostunnel (pid {}) is holding routes on {}",
            state.pid, state.interface
        )));
    }
    if state.pid == std::process::id() {
        return Ok(false);
    }

    tracing::warn!(
        pid = state.pid,
        interface = %state.interface,
        "found routes from a previous run that exited uncleanly; reverting them"
    );
    for cmd in &state.revert {
        if let Err(e) = cmd.run() {
            // The route may already be gone; keep going regardless.
            tracing::debug!(%e, "recovery step failed");
        }
    }
    AppliedState::clear(path);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::RouteCommand;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-state-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("applied_routes.json")
    }

    fn state() -> AppliedState {
        AppliedState {
            interface: "utun7".into(),
            revert: vec![RouteCommand::new("ip", &["route", "del", "0.0.0.0/1"])],
            pid: std::process::id(),
        }
    }

    #[test]
    fn state_round_trips_through_disk() {
        let p = tmp("round");
        state().save(&p).unwrap();
        assert_eq!(AppliedState::load(&p).unwrap().interface, "utun7");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn clearing_removes_the_file_so_the_next_start_sees_nothing() {
        let p = tmp("clear");
        state().save(&p).unwrap();
        AppliedState::clear(&p);
        assert!(AppliedState::load(&p).is_err());
    }

    #[test]
    fn a_state_file_from_our_own_live_process_is_not_treated_as_stale() {
        let p = tmp("live");
        state().save(&p).unwrap();
        assert!(!recover_if_stale(&p).unwrap(), "our own pid is not a crash");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_state_file_from_a_dead_process_is_recovered() {
        let p = tmp("dead");
        let mut s = state();
        // A pid that cannot be running: reserved and never assigned.
        s.pid = 0;
        // The revert command is a no-op so the test does not need root.
        s.revert = vec![RouteCommand::new("true", &[])];
        s.save(&p).unwrap();

        assert!(recover_if_stale(&p).unwrap(), "a crash must be cleaned up");
        assert!(AppliedState::load(&p).is_err(), "recovery clears the file");
    }

    #[test]
    fn a_missing_state_file_is_not_an_error() {
        assert!(!recover_if_stale(&tmp("absent")).unwrap());
    }
}
