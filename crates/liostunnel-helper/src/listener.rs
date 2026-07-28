use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::auth::{self, AuthError};

#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error("accept failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Unauthorized(AuthError),
}

/// What `connect(2)` against an existing path told us about whatever, if
/// anything, is there.
enum ExistingSocket {
    /// `ENOENT`: nothing at the path. Nothing to clean up.
    None,
    /// The path exists but nothing is listening on it: either a genuinely
    /// dead socket left behind by a crash (`ECONNREFUSED`), or the path
    /// isn't even a socket (`ENOTSOCK` — observed on macOS for a plain file;
    /// Linux reports `ECONNREFUSED` for the same case, since the kernel
    /// checks "is this a socket" as part of the same connect and folds a
    /// "no" into connection-refused). Either way: safe to unlink.
    Stale,
}

/// Probes `path` with a client `connect()` before anything is unlinked.
///
/// launchd (`KeepAlive`) and systemd (`Restart=on-failure`) can start a
/// replacement instance before the previous one has exited. Unlinking
/// unconditionally would let the replacement steal a *live* instance's
/// socket out from under it: new clients would reach the replacement while
/// the original runs on, unaware its name has been taken. Probing first and
/// refusing to start on a successful connect closes that race.
fn probe_existing(path: &Path) -> std::io::Result<ExistingSocket> {
    match UnixStream::connect(path) {
        // Someone answered: a live listener already owns this name. Fail
        // closed rather than clobber it, matching the posture already used
        // for a missing `--uid`.
        Ok(_stream) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "a live liostunnel-helper is already listening on {}; refusing to start a second instance",
                path.display()
            ),
        )),
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOENT) => Ok(ExistingSocket::None),
            Some(libc::ECONNREFUSED) | Some(libc::ENOTSOCK) => Ok(ExistingSocket::Stale),
            // Anything else (permission errors and the like) is ambiguous:
            // err toward refusing rather than guessing it is safe to remove.
            _ => Err(e),
        },
    }
}

/// Owns the listening socket and removes it on drop.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    authorized_uid: u32,
    /// Device and inode of the socket file this `Listener` actually bound,
    /// captured right after `bind`. Compared against the path's current
    /// contents before `Drop` unlinks anything: if a different instance has
    /// since taken over the name, the file at `path` is *theirs*, and
    /// deleting it would tear down a healthy service. See `Drop` below.
    dev: u64,
    ino: u64,
}

impl Listener {
    pub fn bind(path: &Path, authorized_uid: u32) -> std::io::Result<Self> {
        // A crash leaves the socket file behind and bind(2) then fails with
        // EADDRINUSE forever. Only unlink it once we've confirmed nothing is
        // actually listening there — see `probe_existing`.
        match probe_existing(path)? {
            ExistingSocket::None => {}
            ExistingSocket::Stale => {
                let _ = std::fs::remove_file(path);
            }
        }

        let inner = UnixListener::bind(path)?;

        // Owner-only. Not sufficient on its own (spec §7.1) but there is no
        // reason to be reachable by other users at all.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        let meta = std::fs::metadata(path)?;

        Ok(Self {
            inner,
            path: path.to_path_buf(),
            authorized_uid,
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    /// Accepts a connection and authorizes it, refusing any other uid.
    pub fn accept(&self) -> Result<UnixStream, AcceptError> {
        let (stream, _) = self.inner.accept()?;
        auth::authorize(stream.as_raw_fd(), self.authorized_uid)
            .map_err(AcceptError::Unauthorized)?;
        Ok(stream)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Unlink only if the path still refers to the exact file we bound.
        // A mismatch (or the path already being gone) means someone else's
        // socket now lives there, or there is nothing to remove; either way,
        // touching it would be wrong, so leave it alone. Never panic here.
        if let Ok(meta) = std::fs::metadata(&self.path)
            && meta.dev() == self.dev
            && meta.ino() == self.ino
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn sock(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-lis-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("s.sock")
    }

    #[test]
    fn binding_creates_the_socket_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let p = sock("perms");
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must not be reachable by other users");
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn a_stale_socket_file_does_not_prevent_binding() {
        // A crash leaves the socket file behind; bind(2) then fails with
        // EADDRINUSE and the helper never starts again until someone deletes
        // it by hand. Unlink first.
        let p = sock("stale");
        std::fs::write(&p, b"not a socket").unwrap();
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).expect("a stale file must not block startup");
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn dropping_the_listener_removes_the_socket_file() {
        let p = sock("cleanup");
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).unwrap();
        assert!(p.exists());
        drop(l);
        assert!(!p.exists(), "the socket file must not outlive the listener");
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn a_connection_from_the_authorized_uid_is_accepted() {
        let p = sock("ok");
        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me).unwrap();
        let _client = UnixStream::connect(&p).unwrap();
        assert!(l.accept().is_ok());
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn binding_refuses_to_start_when_a_live_listener_already_owns_the_path() {
        // The launchd/systemd restart race Finding 1 is about: instance A is
        // still up and listening at `p` when instance B tries to start.
        // `Listener::bind` must probe first and refuse rather than unlink A's
        // live socket out from under it.
        let p = sock("live-collision");
        let me = unsafe { libc::getuid() };
        let a = Listener::bind(&p, me).expect("instance A binds first, uncontested");

        let result = Listener::bind(&p, me);
        assert!(
            result.is_err(),
            "a second bind while a live listener owns the path must refuse to start"
        );

        // A must be completely unharmed: its socket file must still be there
        // and it must still be the thing answering, not merely a
        // coincidentally-surviving path.
        assert!(
            p.exists(),
            "instance A's socket file must survive B's refused start"
        );
        let _client = UnixStream::connect(&p).expect("A must still be reachable");
        assert!(
            a.accept().is_ok(),
            "A must still be able to accept a connection"
        );

        drop(a);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn binding_removes_a_genuinely_dead_orphaned_socket_file() {
        // Distinct from `a_stale_socket_file_does_not_prevent_binding` above:
        // that test leaves plain junk bytes (never a socket at all) at the
        // path. This one leaves a real socket-typed file with nothing
        // listening on it any more (as a crashed helper would), which is the
        // ECONNREFUSED case Finding 1 names explicitly.
        let p = sock("dead-socket");
        {
            let orphan = UnixListener::bind(&p).expect("create the orphaned socket file");
            // Dropped without unlinking: `UnixListener::drop` does not remove
            // the path, so the file remains after `orphan` goes away.
            drop(orphan);
        }
        assert!(p.exists(), "the orphaned socket file must still be on disk");

        let me = unsafe { libc::getuid() };
        let l = Listener::bind(&p, me)
            .expect("a dead socket file with no listener must not block startup");
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn dropping_the_listener_does_not_remove_a_different_socket_now_at_the_same_path() {
        // Finding 2's scenario, continued from Finding 1's: instance A's name
        // got taken over by instance B (or, deterministically here, by any
        // other listener) while A was still alive. When A eventually shuts
        // down, its Drop must not delete the socket that now lives at that
        // path.
        let p = sock("drop-mismatch");
        let me = unsafe { libc::getuid() };
        let a = Listener::bind(&p, me).unwrap();

        // Simulate the takeover: remove the path out from under `a` and put
        // a different listener there, without ever going through `a`'s Drop.
        std::fs::remove_file(&p).unwrap();
        let replacement = UnixListener::bind(&p).unwrap();

        drop(a);

        assert!(
            p.exists(),
            "the replacement listener's socket file must survive the original's Drop"
        );
        let _client = UnixStream::connect(&p).expect("the replacement must still be reachable");
        assert!(
            replacement.accept().is_ok(),
            "the replacement must still be able to accept a connection"
        );

        drop(replacement);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn a_connection_from_a_different_uid_is_refused() {
        // We cannot connect as another user from a test, so authorize against
        // a uid we are definitely not. The accept must be refused rather than
        // returning a usable stream.
        let p = sock("wronguid");
        let me = unsafe { libc::getuid() };
        let not_me = if me == 12345 { 54321 } else { 12345 };
        let l = Listener::bind(&p, not_me).unwrap();
        let _client = UnixStream::connect(&p).unwrap();
        let err = l.accept().expect_err("a foreign uid must be refused");
        assert!(matches!(err, AcceptError::Unauthorized(_)), "got {err:?}");
        drop(l);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }
}
