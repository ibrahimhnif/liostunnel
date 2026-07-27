use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::TunnelError;

/// Wraps secret material so it cannot leak through `Debug` or `Display` —
/// including derived `Debug` on containing structs, and panic backtraces.
/// Spec §11.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Deliberately verbose: reading a secret should be visible at the call site.
    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A pointer to secret material. Never the material itself — this is what makes
/// `ServerProfile` safe to serialise. Spec §6.3.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SecretRef {
    File { path: PathBuf },
    Env { var: String },
}

pub trait SecretStore: Send + Sync {
    fn resolve(&self, r: &SecretRef) -> Result<Redacted<String>, TunnelError>;
}

/// Phase 0 store. Phase 1 replaces this with the OS keychain behind the same trait.
pub struct FileSecretStore;

impl SecretStore for FileSecretStore {
    fn resolve(&self, r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
        match r {
            SecretRef::File { path } => {
                check_permissions(path)?;
                let body = std::fs::read_to_string(path).map_err(|e| {
                    TunnelError::config(
                        format!("secret file {}", path.display()),
                        format!("cannot read: {e}"),
                    )
                })?;
                Ok(Redacted::new(
                    strip_one_trailing_line_ending(&body).to_string(),
                ))
            }
            SecretRef::Env { var } => std::env::var(var)
                .map(Redacted::new)
                .map_err(|_| TunnelError::config(format!("env `{var}`"), "not set")),
        }
    }
}

/// Strips at most one trailing line ending (`\r\n` or `\n`) — never more.
///
/// We strip exactly one because a human editing a secret in a text editor,
/// e.g. `echo hunter2 > pw`, ends up with a trailing `hunter2\n` and means
/// `hunter2`. But we strip *no more than* one because SSH/WireGuard private
/// keys conventionally end with exactly one newline after their final PEM
/// line, and everything beyond the first trailing line ending is real
/// content, not editor residue. Blindly trimming every trailing `\n` (the
/// previous behaviour) silently corrupted such keys on every read, and on
/// CRLF files left a stray `\r` glued to the end of the secret.
fn strip_one_trailing_line_ending(body: &str) -> &str {
    body.strip_suffix("\r\n")
        .or_else(|| body.strip_suffix('\n'))
        .unwrap_or(body)
}

/// Spec §9.2: secret files must be 0600 or stricter.
#[cfg(unix)]
fn check_permissions(path: &std::path::Path) -> Result<(), TunnelError> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).map_err(|e| {
        TunnelError::config(
            format!("secret file {}", path.display()),
            format!("cannot stat: {e}"),
        )
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TunnelError::config(
            format!("secret file {}", path.display()),
            format!("mode {mode:o} grants access beyond the owner; must be 600 or stricter"),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &std::path::Path) -> Result<(), TunnelError> {
    // Windows ACL checking lands with the Phase 1 desktop work.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn redacted_never_prints_its_contents() {
        let s = Redacted::new("hunter2".to_string());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(format!("{s}"), "<redacted>");
        // The value is still reachable when explicitly asked for.
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn redacted_survives_nesting_in_a_derived_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: String,
            key: Redacted<String>,
        }
        let h = Holder {
            name: "prod".into(),
            key: Redacted::new("secret".into()),
        };
        let rendered = format!("{h:?}");
        assert!(rendered.contains("prod"));
        assert!(
            !rendered.contains("secret"),
            "secret leaked into Debug: {rendered}"
        );
    }

    #[test]
    fn secret_ref_round_trips_through_json() {
        let r = SecretRef::File {
            path: "/tmp/key".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"source":"file","path":"/tmp/key"}"#);
        assert_eq!(serde_json::from_str::<SecretRef>(&json).unwrap(), r);
    }

    fn write_key(dir: &std::path::Path, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("id_ed25519");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"KEYMATERIAL").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn file_store_reads_a_correctly_permissioned_secret() {
        let dir = std::env::temp_dir().join(format!("lios-sec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_key(&dir, 0o600);

        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::File { path: p }).unwrap();
        assert_eq!(got.expose(), "KEYMATERIAL");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_rejects_a_world_readable_secret() {
        let dir = std::env::temp_dir().join(format!("lios-sec-lax-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_key(&dir, 0o644);

        let store = FileSecretStore;
        let err = store.resolve(&SecretRef::File { path: p }).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("644"),
            "error should name the offending mode: {msg}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_reads_from_the_environment() {
        // SAFETY: single-threaded test, no other thread reads this var.
        unsafe { std::env::set_var("LIOS_TEST_SECRET", "from-env") };
        let store = FileSecretStore;
        let got = store
            .resolve(&SecretRef::Env {
                var: "LIOS_TEST_SECRET".into(),
            })
            .unwrap();
        assert_eq!(got.expose(), "from-env");
    }

    #[test]
    fn file_store_reports_a_missing_environment_variable() {
        let store = FileSecretStore;
        let err = store
            .resolve(&SecretRef::Env {
                var: "LIOS_DEFINITELY_UNSET".into(),
            })
            .unwrap_err();
        assert!(err.to_string().contains("LIOS_DEFINITELY_UNSET"));
    }

    fn write_secret(dir: &std::path::Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    #[test]
    fn file_store_strips_a_single_trailing_lf() {
        let dir = std::env::temp_dir().join(format!("lios-sec-lf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_secret(&dir, "pw", b"hunter2\n");

        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::File { path: p }).unwrap();
        assert_eq!(got.expose(), "hunter2");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_strips_a_single_trailing_crlf() {
        let dir = std::env::temp_dir().join(format!("lios-sec-crlf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_secret(&dir, "pw", b"hunter2\r\n");

        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::File { path: p }).unwrap();
        assert_eq!(
            got.expose(),
            "hunter2",
            "both the LF and the stray CR must be gone"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_strips_only_the_last_of_two_trailing_newlines() {
        let dir = std::env::temp_dir().join(format!("lios-sec-doublenl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_secret(&dir, "pw", b"hunter2\n\n");

        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::File { path: p }).unwrap();
        assert_eq!(
            got.expose(),
            "hunter2\n",
            "only one trailing newline may be stripped"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_leaves_a_secret_with_no_trailing_newline_unchanged() {
        let dir = std::env::temp_dir().join(format!("lios-sec-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_secret(&dir, "pw", b"hunter2");

        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::File { path: p }).unwrap();
        assert_eq!(got.expose(), "hunter2");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_preserves_interior_newlines_in_a_multiline_key() {
        let dir = std::env::temp_dir().join(format!("lios-sec-pem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----\n";
        let p = write_secret(&dir, "id_ed25519", pem.as_bytes());

        let store = FileSecretStore;
        let got = store.resolve(&SecretRef::File { path: p }).unwrap();
        assert_eq!(
            got.expose(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----",
            "interior newlines must survive; only the final trailing one is stripped"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
