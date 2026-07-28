use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

/// Identity of a particular file, used to tell "the socket we bound" from
/// "whatever happens to be at that path now".
///
/// Both sides of the comparison go through `libc::stat`, so the field types
/// match natively on every platform and nothing has to be cast.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: libc::dev_t,
    ino: libc::ino_t,
}

/// Identity of the *directory entry* at `path`.
///
/// Deliberately not `fstat` on the listening descriptor: for an AF_UNIX
/// socket that returns the socket's own kernel inode, not the filesystem
/// entry it is bound to. Measured on macOS — `fstat(sockfd)` gave
/// `dev=-1 ino=529782` where `stat(path)` gave `dev=16777231 ino=66740537`.
/// The two are unrelated, so the descriptor cannot answer "is this still my
/// file". The TOCTOU window that would otherwise argue for `fstat` is closed
/// by the lock: no other helper can be inside `bind` at all while we hold it.
fn stat_path(path: &Path) -> std::io::Result<FileId> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call, and
    // `st` is a correctly sized, zeroed buffer that stat fills entirely.
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileId {
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

/// An exclusive advisory lock proving this process owns the socket path.
///
/// Liveness cannot be decided by connecting to the existing socket. A live
/// listener whose accept backlog is full refuses connections exactly like a
/// dead one — on macOS both give `ECONNREFUSED`, and on Linux the connect
/// blocks forever with no timeout — so a probe would unlink a healthy
/// instance's socket and steal its name, which is the failure the probe was
/// added to prevent. Worse, each probe that *does* connect leaves a phantom
/// connection in the live listener's backlog, so a restart loop exhausts the
/// backlog on its own and manufactures the misreading.
///
/// `flock` has the property the probe was reaching for: the kernel releases
/// it when the holder dies, however abruptly — `SIGKILL` and panics included.
/// Holding it means no live helper owns this path, so anything at it is
/// debris.
struct PathLock {
    _file: File,
}

impl PathLock {
    /// Path of the lockfile guarding `socket`.
    fn path_for(socket: &Path) -> PathBuf {
        let mut s = socket.as_os_str().to_os_string();
        s.push(".lock");
        PathBuf::from(s)
    }

    fn acquire(socket: &Path) -> std::io::Result<Self> {
        let lock_path = Self::path_for(socket);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&lock_path)?;

        // Two helpers racing here both open the same inode — `create` is
        // idempotent for an existing file — and flock then arbitrates.
        // SAFETY: `file` owns a valid descriptor for the duration of the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            return if matches!(e.raw_os_error(), Some(libc::EWOULDBLOCK)) {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!(
                        "a live liostunnel-helper already owns {}; refusing to start a second instance",
                        socket.display()
                    ),
                ))
            } else {
                Err(e)
            };
        }

        Ok(Self { _file: file })
    }
}

// The lockfile is deliberately never unlinked. Removing it would let a second
// helper create a fresh one, lock that, and start alongside us — the lock
// lives on the inode, not the name. It is an empty file; leaving it costs
// nothing. Dropping `_file` releases the lock, which is what matters.

/// Owns the listening socket and removes it on drop.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    authorized_uid: u32,
    /// Identity of the socket file this `Listener` bound, taken while the
    /// lock was held. Compared against the path's current contents before
    /// `Drop` unlinks anything: if a different instance has since taken the
    /// name, the file there is *theirs*, and deleting it would tear down a
    /// healthy service.
    id: FileId,
    /// Released on drop, after which another helper may take this path.
    _lock: PathLock,
}

impl Listener {
    pub fn bind(path: &Path, authorized_uid: u32) -> std::io::Result<Self> {
        // Refuses if a live helper already holds the path.
        let lock = PathLock::acquire(path)?;

        // We hold the lock, so nothing at the path is live: a crash leaves the
        // socket file behind and `bind` would then fail EADDRINUSE forever.
        // `remove_file` acts on the name itself, so a dangling symlink planted
        // here goes too — otherwise `bind` fails EADDRINUSE on Linux, or on
        // macOS resolves through the link and strands the real socket.
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        let inner = UnixListener::bind(path)?;

        // From here the file exists, so every failure path must remove it.
        let id = match stat_path(path) {
            Ok(id) => id,
            Err(e) => {
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
        };

        // Constructed before the remaining fallible steps so `Drop` owns the
        // cleanup from the moment the socket file exists.
        let listener = Self {
            inner,
            path: path.to_path_buf(),
            authorized_uid,
            id,
            _lock: lock,
        };

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        listener.give_to_authorized_uid()?;

        Ok(listener)
    }

    /// Hands the socket to the uid this helper serves.
    ///
    /// Both platforms enforce a socket's permission bits on `connect`, so a
    /// root-owned `0600` socket is unreachable by the unprivileged GUI it
    /// exists for: the daemon would run correctly and the app could never
    /// reach it. Ownership plus `0600` means exactly one user can open it,
    /// and the peer-uid check at `accept` stays as the second gate — the mode
    /// bits say nothing about *which* user connected (spec §7.1).
    fn give_to_authorized_uid(&self) -> std::io::Result<()> {
        // SAFETY: geteuid cannot fail and has no preconditions.
        let me = unsafe { libc::geteuid() };
        if self.authorized_uid == me {
            return Ok(()); // already ours; the chown would be a no-op
        }

        let c = CString::new(self.path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // SAFETY: `c` is a valid NUL-terminated path outliving the call.
        // gid `u32::MAX` is -1 cast to gid_t, chown's "leave the group alone".
        if unsafe { libc::chown(c.as_ptr(), self.authorized_uid, u32::MAX) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                e.kind(),
                format!(
                    "could not give {} to uid {}: {e}. The helper must run as root to serve another user",
                    self.path.display(),
                    self.authorized_uid
                ),
            ));
        }
        Ok(())
    }

    /// Accepts a connection and authorizes it, refusing any other uid.
    pub fn accept(&self) -> Result<UnixStream, AcceptError> {
        let (stream, _) = self.inner.accept()?;
        auth::authorize(stream.as_raw_fd(), self.authorized_uid)
            .map_err(AcceptError::Unauthorized)?;
        Ok(stream)
    }

    #[cfg(test)]
    fn inner(&self) -> &UnixListener {
        &self.inner
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Unlink only if the path still refers to the exact file we bound. A
        // mismatch means someone else's socket lives there now, and removing
        // it would tear down a healthy service. Never panic here.
        if stat_path(&self.path).is_ok_and(|id| id == self.id) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;

    fn sock(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-lis-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("s.sock")
    }

    fn cleanup(p: &Path) {
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    fn owner_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().uid()
    }

    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    #[test]
    fn binding_creates_the_socket_with_owner_only_permissions() {
        let p = sock("perms");
        let l = Listener::bind(&p, me()).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must not be reachable by other users");
        drop(l);
        cleanup(&p);
    }

    #[test]
    fn a_socket_bound_for_another_uid_belongs_to_that_uid_or_is_not_created() {
        // THE DEPLOYMENT SHAPE. The helper runs as root and serves an
        // unprivileged GUI. Both platforms enforce a socket's permission bits
        // on connect(), so a root-owned 0600 socket is one the GUI can never
        // open — the daemon runs perfectly and the app cannot reach it.
        //
        // Asserted as an either/or so it is meaningful in both environments
        // with no skip: as root the chown succeeds and the socket must belong
        // to the target uid; as an ordinary user it cannot succeed, so bind
        // must refuse and leave nothing behind rather than quietly create a
        // socket its intended reader can never open.
        //
        // A test binding for our OWN uid cannot catch this at all — the
        // socket is born owned by us — which is exactly how the bug survived.
        let p = sock("foreign-owner");
        let target = me().wrapping_add(1);
        match Listener::bind(&p, target) {
            Ok(l) => {
                assert_eq!(
                    owner_of(&p),
                    target,
                    "the socket must belong to the uid it was bound to serve"
                );
                drop(l);
            }
            Err(_) => assert!(
                !p.exists(),
                "a refused bind must not leave a socket nobody can use"
            ),
        }
        cleanup(&p);
    }

    #[test]
    fn a_stale_socket_file_does_not_prevent_binding() {
        // A crash leaves the socket file behind; bind(2) then fails with
        // EADDRINUSE and the helper never starts again until someone deletes
        // it by hand.
        let p = sock("stale");
        std::fs::write(&p, b"not a socket").unwrap();
        let l = Listener::bind(&p, me()).expect("a stale file must not block startup");
        drop(l);
        cleanup(&p);
    }

    #[test]
    fn binding_removes_a_genuinely_dead_orphaned_socket_file() {
        // Distinct from the junk-bytes case above: a real socket-typed file
        // with nothing listening on it any more, as a crashed helper leaves.
        let p = sock("dead-socket");
        {
            let orphan = UnixListener::bind(&p).expect("create the orphaned socket file");
            drop(orphan); // UnixListener::drop does not unlink
        }
        assert!(p.exists(), "the orphaned socket file must still be on disk");
        let l = Listener::bind(&p, me()).expect("a dead socket must not block startup");
        drop(l);
        cleanup(&p);
    }

    #[test]
    fn binding_clears_a_dangling_symlink_at_the_socket_path() {
        // connect() through a broken link reports ENOENT, so a probe reads it
        // as "nothing there" and leaves it. bind() then fails EADDRINUSE on
        // Linux and the helper can never start; on macOS it resolves through
        // the link and strands the real socket at the target.
        let p = sock("dangling");
        std::os::unix::fs::symlink(p.parent().unwrap().join("gone"), &p).unwrap();
        let l = Listener::bind(&p, me()).expect("a dangling symlink must not block startup");
        assert!(
            std::fs::symlink_metadata(&p)
                .unwrap()
                .file_type()
                .is_socket(),
            "the path must now be the real socket, not the leftover link"
        );
        drop(l);
        cleanup(&p);
    }

    #[test]
    fn dropping_the_listener_removes_the_socket_file() {
        let p = sock("cleanup");
        let l = Listener::bind(&p, me()).unwrap();
        assert!(p.exists());
        drop(l);
        assert!(!p.exists(), "the socket file must not outlive the listener");
        cleanup(&p);
    }

    #[test]
    fn dropping_the_listener_does_not_remove_a_different_socket_now_at_the_same_path() {
        // Instance A's name was taken over while A was still alive. When A
        // shuts down, its Drop must not delete the socket now living there.
        let p = sock("drop-mismatch");
        let a = Listener::bind(&p, me()).unwrap();

        std::fs::remove_file(&p).unwrap();
        let replacement = UnixListener::bind(&p).unwrap();

        drop(a);

        assert!(
            p.exists(),
            "the replacement's socket file must survive the original's Drop"
        );
        let _client = UnixStream::connect(&p).expect("the replacement must still be reachable");
        assert!(
            replacement.accept().is_ok(),
            "the replacement must still be able to accept a connection"
        );

        drop(replacement);
        cleanup(&p);
    }

    #[test]
    fn binding_refuses_to_start_when_a_live_listener_already_owns_the_path() {
        // The launchd/systemd restart race: instance A is still up when B
        // tries to start. B must refuse rather than unlink A's live socket.
        let p = sock("live-collision");
        let a = Listener::bind(&p, me()).expect("instance A binds first, uncontested");

        let result = Listener::bind(&p, me());
        assert!(
            result.is_err(),
            "a second bind while a live listener owns the path must refuse"
        );

        assert!(p.exists(), "A's socket file must survive B's refused start");
        let _client = UnixStream::connect(&p).expect("A must still be reachable");
        assert!(a.accept().is_ok(), "A must still be able to accept");

        drop(a);
        cleanup(&p);
    }

    #[test]
    fn a_refused_bind_never_connects_to_the_live_listener() {
        // Liveness must not be decided by connecting. A probe that connects
        // leaves a phantom connection in the live listener's backlog, so a
        // restart loop exhausts the backlog on its own — and a listener with
        // a full backlog refuses connections exactly like a dead one, which
        // makes the probe unlink a healthy instance's socket.
        //
        // Pins the property directly: after B's refused start, A has nothing
        // waiting to be accepted.
        let p = sock("no-phantom");
        let a = Listener::bind(&p, me()).unwrap();

        for _ in 0..3 {
            assert!(Listener::bind(&p, me()).is_err(), "B must refuse");
        }

        a.inner().set_nonblocking(true).unwrap();
        let pending = a.inner().accept();
        assert!(
            matches!(&pending, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a refused bind must leave no connection queued on the live listener; got {pending:?}"
        );

        a.inner().set_nonblocking(false).unwrap();
        drop(a);
        cleanup(&p);
    }

    #[test]
    fn a_connection_from_the_authorized_uid_is_accepted() {
        let p = sock("ok");
        let l = Listener::bind(&p, me()).unwrap();
        let _client = UnixStream::connect(&p).unwrap();
        assert!(l.accept().is_ok());
        drop(l);
        cleanup(&p);
    }

    #[test]
    #[ignore = "needs root: binds a socket for a uid we are not, which requires chown. \
                Run as root with: docker run --rm -v \"$PWD\":/w -w /w \
                -e CARGO_TARGET_DIR=/w/target-linux rust:1.93-slim \
                cargo test -p liostunnel-helper -- --include-ignored"]
    fn a_connection_from_a_different_uid_is_refused() {
        // The real deployment shape: the socket belongs to the served user,
        // and a connection from anyone else — including root — is refused at
        // accept. Needs root, because binding for another uid means chowning
        // to it. #[ignore] rather than a silent early return: an ignored test
        // prints as ignored, where a skip prints as a pass it never earned.
        assert_eq!(me(), 0, "requires root; do not let it pass unrun");
        let p = sock("wronguid");
        let target = 65534; // nobody
        let l = Listener::bind(&p, target).unwrap();
        assert_eq!(owner_of(&p), target);

        // Root can open it despite the mode bits; the peer-uid gate is what
        // must stop us, which is precisely why mode bits are not the gate.
        let _client = UnixStream::connect(&p).unwrap();
        let err = l.accept().expect_err("a foreign uid must be refused");
        assert!(matches!(err, AcceptError::Unauthorized(_)), "got {err:?}");
        drop(l);
        cleanup(&p);
    }
}
