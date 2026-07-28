//! Finding 3: the fail-closed `--uid` behaviour had no automated test. The
//! constraint under test is: a helper started without an authorized uid
//! refuses every connection rather than defaulting permissive. `main.rs`
//! enforces this before a socket is ever touched, so it needs no refactor to
//! be testable — spawning the real compiled binary is enough.
//!
//! Both tests avoid any real system path: everything binds under a fresh
//! temp directory, cleaned up afterwards.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn helper_bin() -> &'static str {
    env!("CARGO_BIN_EXE_liostunnel-helper")
}

/// A private temp dir per test, never a real system path.
fn tmp_socket(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("lios-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join("s.sock")
}

/// Waits up to `timeout` for `child` to exit on its own. If it hasn't, kills
/// and reaps it so no test ever leaves a helper process running.
///
/// Returns the exit status if the process exited by itself, or `None` if it
/// had to be killed. `None` is expected once Task 5 adds a real accept loop
/// (a healthy helper with a valid uid then runs forever until told to
/// stop) — this test must not block on that.
fn wait_or_kill(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn missing_uid_refuses_to_start_and_says_why() {
    let sock = tmp_socket("no-uid");

    let out = Command::new(helper_bin())
        .arg("--socket")
        .arg(&sock)
        .output()
        .expect("the compiled helper binary must run");

    assert!(
        !out.status.success(),
        "a helper started without --uid must exit non-zero, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("uid"),
        "stderr must explain the refusal is about the missing uid, got: {stderr:?}"
    );
    assert!(
        !sock.exists(),
        "refusing to start must happen before any socket is created"
    );

    std::fs::remove_dir_all(sock.parent().unwrap()).ok();
}

#[test]
fn a_valid_uid_does_not_trigger_the_fail_closed_uid_refusal() {
    // SAFETY: getuid cannot fail and has no preconditions.
    let me = unsafe { libc::getuid() };
    let sock = tmp_socket("with-uid");

    let mut child = Command::new(helper_bin())
        .arg("--socket")
        .arg(&sock)
        .arg("--uid")
        .arg(me.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the compiled helper binary must run");

    // As of Task 4 there is no accept loop yet, so a successful bind exits
    // immediately; bound with a timeout regardless so this test cannot hang
    // once Task 5 adds one (see `wait_or_kill`).
    let status = wait_or_kill(&mut child, Duration::from_secs(5));

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }

    // The one thing this test pins: it must not have exited for the
    // fail-closed missing-uid reason, since a uid was given.
    assert!(
        !stderr.contains("--uid is required"),
        "must not hit the fail-closed uid-missing path when --uid is given, got: {stderr:?}"
    );
    if let Some(status) = status {
        assert!(
            status.success(),
            "a valid --uid binding a fresh temp socket must not fail, stderr: {stderr:?}"
        );
    }

    std::fs::remove_dir_all(sock.parent().unwrap()).ok();
}
