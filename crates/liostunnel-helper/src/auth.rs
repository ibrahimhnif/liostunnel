use std::os::fd::RawFd;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("cannot read peer credentials: {0}")]
    PeerCred(std::io::Error),
    #[error("connection from uid {actual} refused; only uid {expected} is authorized")]
    WrongUid { expected: u32, actual: u32 },
    #[error("secret file {path} is not owned by uid {uid}")]
    SecretNotOwned { path: String, uid: u32 },
    #[error("secret file {path}: {reason}")]
    SecretRejected { path: String, reason: String },
}

/// The uid of the process on the other end of a connected unix socket.
///
/// Platform-split, and `nix` does not cover both: nix 0.31 provides
/// `sockopt::PeerCredentials` (Linux `SO_PEERCRED`) and has no macOS
/// equivalent, so macOS calls `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)`
/// directly for a `xucred`.
///
/// Filesystem permissions on the socket are not a substitute: they are
/// advisory against a root-adjacent attacker and say nothing about *which*
/// user connected. Spec §7.1.
#[cfg(target_os = "linux")]
pub fn peer_uid(fd: RawFd) -> Result<u32, AuthError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::fd::BorrowedFd;

    // SAFETY: the caller owns `fd` for the duration of this call; we only
    // borrow it to read a socket option and never retain it.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let cred = getsockopt(&borrowed, PeerCredentials)
        .map_err(|e| AuthError::PeerCred(std::io::Error::from(e)))?;
    Ok(cred.uid())
}

#[cfg(target_os = "macos")]
pub fn peer_uid(fd: RawFd) -> Result<u32, AuthError> {
    use std::mem;

    let mut cred: libc::xucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::xucred>() as libc::socklen_t;

    // SAFETY: `cred` is a correctly-sized, zeroed xucred and `len` describes
    // it accurately; getsockopt writes at most `len` bytes and updates it.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            &mut cred as *mut libc::xucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(AuthError::PeerCred(std::io::Error::last_os_error()));
    }
    Ok(cred.cr_uid)
}

/// Refuses any uid but the authorized one.
pub fn authorize(fd: RawFd, expected: u32) -> Result<(), AuthError> {
    let actual = peer_uid(fd)?;
    if actual != expected {
        return Err(AuthError::WrongUid { expected, actual });
    }
    Ok(())
}

/// Whether `uid` may have this file used as a secret.
///
/// The helper runs as root and can read anything; this is what stops a
/// caller from borrowing that power. Ownership is checked against the
/// *calling* uid, and the mode rule Phase 0 established is preserved.
///
/// Deliberately uses `metadata` (which follows symlinks) rather than
/// `symlink_metadata`: a link the caller owns pointing at a file they do
/// not is exactly the bypass this must refuse.
pub fn secret_readable_by(path: &Path, uid: u32) -> Result<(), AuthError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).map_err(|e| AuthError::SecretRejected {
        path: path.display().to_string(),
        reason: format!("cannot stat: {e}"),
    })?;

    if !meta.is_file() {
        return Err(AuthError::SecretRejected {
            path: path.display().to_string(),
            reason: "not a regular file".into(),
        });
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(AuthError::SecretRejected {
            path: path.display().to_string(),
            reason: format!("mode {mode:o} grants access beyond the owner"),
        });
    }

    if meta.uid() != uid {
        return Err(AuthError::SecretNotOwned {
            path: path.display().to_string(),
            uid,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn peer_uid_of_a_socketpair_is_our_own_uid() {
        // Both ends of a socketpair belong to this process, so the peer uid
        // must be our own. This is the only assertion available without
        // spawning a process as another user, and it is enough to prove the
        // platform-specific getsockopt path is wired correctly — the failure
        // mode it guards against is "returns garbage" or "returns 0", not
        // "returns the wrong real user".
        let (a, _b) = UnixStream::pair().unwrap();
        let got = peer_uid(a.as_raw_fd()).expect("peer_uid must succeed on a socketpair");
        // SAFETY: getuid cannot fail and has no preconditions.
        let expected = unsafe { libc::getuid() };
        assert_eq!(got, expected);
    }

    #[test]
    fn peer_uid_of_a_socketpair_reports_our_real_uid_on_success() {
        // NB: this only proves that on a *successful* getsockopt call we
        // report the real (and, for a non-root test process, nonzero) uid.
        // It is NOT a guard against a checked-vs-unchecked getsockopt bug:
        // a real connected socketpair's getsockopt call succeeds and fills
        // the output buffer correctly whether or not the caller checks the
        // return code, so this fixture cannot tell a checked implementation
        // from an unchecked one apart — confirmed empirically, this test
        // still passes with the `rc`/error check deleted from `peer_uid`.
        // See `peer_uid_on_getsockopt_failure_does_not_silently_report_uid_zero`
        // below for the fixture that can tell them apart.
        let (a, _b) = UnixStream::pair().unwrap();
        let got = peer_uid(a.as_raw_fd()).unwrap();
        let expected = unsafe { libc::getuid() };
        if expected != 0 {
            assert_ne!(got, 0, "a non-root test process must not report peer uid 0");
        }
    }

    #[test]
    fn peer_uid_on_getsockopt_failure_does_not_silently_report_uid_zero() {
        // This is the fixture that can distinguish a checked getsockopt
        // from an unchecked one: on a non-socket fd the syscall genuinely
        // fails, so an implementation that forgets to check the return
        // code / Result falls through to the zeroed output buffer and
        // would silently report uid 0 (i.e. authorize the connection as
        // root) instead of surfacing an error. A/B-verified: deleting the
        // rc/error check from `peer_uid` turns this test red.
        let f = std::fs::File::open("/dev/null").unwrap();
        let result = peer_uid(f.as_raw_fd());
        assert!(
            result.is_err(),
            "a non-socket fd must surface an error, not silently succeed with a zeroed uid: got {result:?}"
        );
    }

    #[test]
    fn authorize_accepts_our_own_uid() {
        // `authorize` is the function that embodies P1a-5 ("who is allowed
        // to talk to me"); this proves the accept path actually accepts the
        // right caller, not just that `peer_uid` works in isolation.
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: getuid cannot fail and has no preconditions.
        let our_uid = unsafe { libc::getuid() };
        assert!(authorize(a.as_raw_fd(), our_uid).is_ok());
    }

    #[test]
    fn authorize_rejects_a_mismatched_uid() {
        // The other half of P1a-5: a caller who is not the expected uid
        // must be refused, and the error must carry both uids (never
        // anything else — no path, no token, no credential material) so
        // the caller can log who was refused and who was expected.
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: getuid cannot fail and has no preconditions.
        let our_uid = unsafe { libc::getuid() };
        let expected = our_uid.wrapping_add(1);

        match authorize(a.as_raw_fd(), expected) {
            Err(AuthError::WrongUid {
                expected: got_expected,
                actual,
            }) => {
                assert_eq!(got_expected, expected);
                assert_eq!(actual, our_uid);
            }
            other => panic!("expected Err(AuthError::WrongUid {{ .. }}), got {other:?}"),
        }
    }

    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lios-auth-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_owned(dir: &std::path::Path, mode: u32) -> PathBuf {
        let p = dir.join("secret");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&p)
            .unwrap();
        f.write_all(b"KEYMATERIAL").unwrap();
        p
    }

    #[test]
    fn a_file_the_caller_owns_is_permitted() {
        let d = scratch("owned");
        let p = write_owned(&d, 0o600);
        let me = unsafe { libc::getuid() };
        assert!(secret_readable_by(&p, me).is_ok());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_file_owned_by_another_uid_is_refused() {
        // THE ESCALATION. A file that the given uid does not own must be
        // refused even though the helper, running as root, could trivially
        // read it. We do not need a real foreign-owned fixture (there is no
        // system file whose ownership is guaranteed across macOS, Linux, and
        // root/non-root): `secret_readable_by` takes the uid as a parameter,
        // so a file we own plus a deliberately mismatched uid exercises the
        // exact same `meta.uid() != uid` branch, deterministically, on any
        // platform and any caller identity.
        let d = scratch("not-owned");
        let p = write_owned(&d, 0o600);
        let me = unsafe { libc::getuid() };
        let mismatched = me.wrapping_add(1);

        let err = secret_readable_by(&p, mismatched)
            .expect_err("a file not owned by the given uid must be refused");
        assert!(
            matches!(err, AuthError::SecretNotOwned { .. }),
            "expected SecretNotOwned, got {err:?}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_world_readable_file_is_still_refused_even_if_owned() {
        // Phase 0's FileSecretStore already rejects looser-than-0600. This
        // check runs first, so the mode rule is not lost by moving ownership
        // enforcement into the helper.
        let d = scratch("loose");
        let p = write_owned(&d, 0o644);
        let me = unsafe { libc::getuid() };
        assert!(secret_readable_by(&p, me).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_panic() {
        let me = unsafe { libc::getuid() };
        assert!(secret_readable_by(std::path::Path::new("/nonexistent/lios"), me).is_err());
    }

    #[test]
    fn a_symlink_resolves_its_type_and_mode_through_the_link() {
        // What this pins: `secret_readable_by` stats a symlink with a
        // *following* call (`metadata`, not `symlink_metadata`) for the
        // purposes of the type and mode checks. We build a real target file
        // (owned by us, mode 0600, via `write_owned`) and a symlink to it,
        // then call with a deliberately mismatched uid.
        //
        // What this does NOT pin: which owner is consulted for the
        // ownership check. The link and its target here are owned by the
        // same process (us), so an implementation that read ownership from
        // the link's own inode instead of the target's would produce the
        // exact same `SecretNotOwned` result — this fixture cannot tell the
        // two apart. Constructing a fixture where link-owner and
        // target-owner genuinely differ needs root (chowning a file to a
        // uid you are not requires CAP_CHOWN); see the root-only
        // `a_root_owned_link_to_a_foreign_owned_target_is_still_refused`
        // below for that discriminator.
        //
        // The two implementations this test *can* tell apart both reach a
        // real error either way, so `.is_err()` would not be enough; the
        // specific variant is what carries the evidence:
        //   - `metadata` on the link resolves to the *target*: a regular
        //     file, mode 0600 (passes the type and mode checks), so the
        //     call reaches the ownership check and is refused there ->
        //     `SecretNotOwned`. This is the behavior we want to pin.
        //   - `symlink_metadata` on the link resolves to the *link itself*:
        //     its file type is a symlink, not a regular file, so it is
        //     rejected by the earlier `is_file()` check with
        //     `SecretRejected { reason: "not a regular file" }` — an error,
        //     but the wrong one, and it never reaches the ownership check
        //     at all.
        let d = scratch("symlink");
        let target = write_owned(&d, 0o600);
        let link = d.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let me = unsafe { libc::getuid() };
        let mismatched = me.wrapping_add(1);

        let err = secret_readable_by(&link, mismatched)
            .expect_err("a symlink to a file the given uid does not own must be refused");
        assert!(
            matches!(err, AuthError::SecretNotOwned { .. }),
            "expected SecretNotOwned (proving the symlink's type and mode were resolved \
             through the link rather than rejected at the link's own type), got {err:?}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    #[ignore = "needs root: chowns a file to a non-root uid to make link-owner != target-owner; \
                run with `cargo test -p liostunnel-helper auth -- --include-ignored` as root \
                (see the Linux/Docker invocation in task-3-report.md)"]
    fn a_root_owned_link_to_a_foreign_owned_target_is_still_refused() {
        // The property `a_symlink_resolves_its_type_and_mode_through_the_link`
        // above cannot pin: whether *ownership* is read from the target or
        // from the link's own inode, because in that fixture link-owner and
        // target-owner are identical. This test makes them genuinely
        // different, which needs root (chowning a file to a uid you are not
        // requires CAP_CHOWN) — hence `#[ignore]` rather than a silent early
        // `return`. An ignored test still prints as "ignored" in `cargo
        // test` output, so a reader can see this coverage exists and is
        // gated on a privilege the ordinary dev/CI environment lacks,
        // instead of it silently reporting a pass it never earned.
        use std::os::unix::fs::MetadataExt;

        let me = unsafe { libc::getuid() };
        assert_eq!(
            me, 0,
            "this test requires root to chown a file to a foreign uid; got uid {me}. \
             Run it deliberately (see the Docker invocation in task-3-report.md) — \
             do not let it report a pass for an assertion it never ran."
        );

        let d = scratch("symlink-foreign-owner");
        let target = write_owned(&d, 0o600); // created by us: root, uid 0
        let link = d.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // Find a non-root uid to chown the target to. 65534 (`nobody`) is
        // present in the Debian slim image this test is designed to run in,
        // but we look it up rather than assume the number.
        let nobody: u32 = {
            let out = std::process::Command::new("id")
                .args(["-u", "nobody"])
                .output()
                .expect("`id -u nobody` must be runnable in the test environment");
            assert!(
                out.status.success(),
                "`id -u nobody` failed: {out:?} (need a non-root uid to build this fixture)"
            );
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .expect("`id -u nobody` must print a uid")
        };
        assert_ne!(
            nobody, 0,
            "need a non-root uid for the target owner; `nobody` resolved to uid 0"
        );

        // Chown only the TARGET to `nobody`. The link itself is untouched
        // and remains owned by root (0) — this is the divergence the
        // deterministic test above cannot produce.
        std::os::unix::fs::chown(&target, Some(nobody), None)
            .expect("chown(target, nobody) must succeed as root");

        let link_owner = std::fs::symlink_metadata(&link).unwrap().uid();
        assert_eq!(link_owner, 0, "the link itself must remain root-owned");
        let target_owner = std::fs::metadata(&target).unwrap().uid();
        assert_eq!(
            target_owner, nobody,
            "the target must now be owned by `nobody`"
        );

        // Ask on behalf of root (0), the link's own owner. A correct
        // implementation resolves ownership from the *target* (nobody) and
        // refuses; an implementation that reads the *link's* metadata
        // instead would see owner 0 == uid 0 and wrongly accept.
        let err = secret_readable_by(&link, 0).expect_err(
            "target is owned by `nobody`, not root; a root-owned link to it must still be refused",
        );
        assert!(
            matches!(err, AuthError::SecretNotOwned { .. }),
            "expected SecretNotOwned (proving ownership was resolved from the target, \
             not the link), got {err:?}"
        );

        std::fs::remove_dir_all(&d).ok();
    }
}
