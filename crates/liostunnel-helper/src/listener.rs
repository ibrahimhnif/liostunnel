use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
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

/// Owns the listening socket and removes it on drop.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    authorized_uid: u32,
}

impl Listener {
    pub fn bind(path: &Path, authorized_uid: u32) -> std::io::Result<Self> {
        // A crash leaves the socket file behind and bind(2) then fails with
        // EADDRINUSE forever. Remove it first; the permissions on the parent
        // directory are what stop an attacker planting one.
        let _ = std::fs::remove_file(path);

        let inner = UnixListener::bind(path)?;

        // Owner-only. Not sufficient on its own (spec §7.1) but there is no
        // reason to be reachable by other users at all.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        Ok(Self {
            inner,
            path: path.to_path_buf(),
            authorized_uid,
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
        let _ = std::fs::remove_file(&self.path);
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
