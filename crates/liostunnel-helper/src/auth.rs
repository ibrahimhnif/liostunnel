use std::os::fd::RawFd;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("cannot read peer credentials: {0}")]
    PeerCred(std::io::Error),
    #[error("connection from uid {actual} refused; only uid {expected} is authorized")]
    WrongUid { expected: u32, actual: u32 },
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
    fn peer_uid_is_not_silently_zero() {
        // Guards the specific bug where an unchecked getsockopt leaves the
        // output buffer zeroed and every caller is authorised as root.
        let (a, _b) = UnixStream::pair().unwrap();
        let got = peer_uid(a.as_raw_fd()).unwrap();
        let expected = unsafe { libc::getuid() };
        if expected != 0 {
            assert_ne!(got, 0, "a non-root test process must not report peer uid 0");
        }
    }

    #[test]
    fn peer_uid_on_a_non_socket_fd_is_an_error_not_a_panic() {
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(peer_uid(f.as_raw_fd()).is_err());
    }
}
