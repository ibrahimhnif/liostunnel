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
/// This is deliberately a **bare** PID check — it does not also confirm the
/// process is a liostunnel instance (by executable name or start time). What
/// makes that acceptable for Phase 0 is not that the check is always right,
/// but that every way it can be wrong lands on the side of refusing to act:
///
/// - Reporting a dead PID as alive (a recycled PID now owned by an unrelated
///   process, or a corrupt record) makes `recover_if_stale` return `Err` and
///   touch nothing. The operator must confirm the old process is gone and
///   remove the state file by hand — annoying, never destructive.
/// - Reporting a *live* PID as dead is the dangerous direction: it would let
///   one process revert a running instance's routes and delete its crash
///   record. Only `ESRCH` is read as dead, precisely so this cannot happen.
///
/// An earlier version of this comment claimed the dangerous direction was
/// unreachable "because route mutation requires root on both ends". That was
/// wrong, and worth recording so it is not reintroduced: `kill` also fails
/// with `EPERM` when the target exists but cannot be signalled, and the code
/// treated any failure as death. Measured: `kill(1, 0)` as an ordinary user
/// returns `EPERM`, so PID 1 — unambiguously alive — read as dead. Reachable
/// whenever the recovering process can mutate routes but not signal the
/// recorded PID: `setcap cap_net_admin+ep` without root, or a root-owned
/// record sitting in a user-owned state directory.
///
/// A stricter check (`/proc/<pid>/comm`, `ps -p <pid> -o comm=`, or a stored
/// start time) would narrow how often a genuinely stale file is misjudged as
/// live. That is a convenience refinement, not a safety one, and is deferred
/// past Phase 0.
#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    // POSIX gives pid 0 the meaning "every process in my process group", so
    // `kill(0, 0)` succeeds and would report a corrupt record as live. Reject
    // it before asking the kernel anything.
    if pid == 0 {
        return false;
    }
    // A pid beyond i32::MAX wraps negative through the cast below, which POSIX
    // reads as a process-group broadcast. Treat a corrupt record as live so we
    // refuse rather than tear down something we cannot identify.
    let Ok(raw) = libc::pid_t::try_from(pid) else {
        return true;
    };

    // Signal 0 tests for existence without delivering anything.
    // SAFETY: `kill` with signal 0 has no effect beyond returning a status.
    if unsafe { libc::kill(raw, 0) } == 0 {
        return true;
    }

    // `kill` fails two ways and they mean opposite things:
    //   ESRCH — no such process. Genuinely dead; recovering is correct.
    //   EPERM — the process exists but we may not signal it.
    // Collapsing EPERM into "dead" is the dangerous direction: a recovering
    // process holding CAP_NET_ADMIN but not root (`setcap cap_net_admin+ep`),
    // or reading a root-owned record from a user-owned state directory, would
    // tear down a *live* instance's routes and delete its crash record. Only
    // ESRCH may be read as dead; everything else errs toward "still running",
    // whose worst outcome is a refusal the operator can resolve by hand.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
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
        // Name the state file: this refusal is also what a recycled PID looks
        // like, and without the path the operator has no way to resolve it.
        return Err(TunnelError::Route(format!(
            "another liostunnel (pid {}) is holding routes on {}. If that \
             process is gone, delete {} and retry.",
            state.pid,
            state.interface,
            path.display()
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
