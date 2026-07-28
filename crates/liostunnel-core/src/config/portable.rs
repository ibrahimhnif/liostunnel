use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::profile::{AuthMethod, DnsConfig, ProtocolKind, ServerProfile, SplitTunnelRule};
use crate::config::secret::{SecretRef, SecretStore};
use crate::error::TunnelError;

pub const EXPORT_WARNING: &str = "This export contains private keys and passwords in \
     plaintext. Anyone who obtains this file gains full access to the server. Transfer it \
     over a secure channel and delete it once imported.";

/// The shareable `.liostunnel.json` format (PRD §5.2) and future QR payload.
/// Carries inline secrets, unlike [`ServerProfile`]. Spec §6.3.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PortableProfile {
    pub id: Uuid,
    pub name: String,
    pub protocol: ProtocolKind,
    pub host: String,
    pub port: u16,
    pub auth: PortableAuth,
    pub dns: DnsConfig,
    pub split_tunnel: SplitTunnelRule,
    pub kill_switch: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PortableAuth {
    Password {
        password: String,
    },
    PrivateKey {
        private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    PresharedKey {
        private_key: String,
        peer_public_key: String,
    },
}

/// Manual impl so a stray `{:?}` (log line, panic backtrace, CLI error path)
/// can never print a private key or password. Mirrors `Redacted<T>`'s intent
/// in `secret.rs`, applied here because `PortableAuth` holds raw `String`
/// secrets rather than `SecretRef`s. `peer_public_key` is public by
/// definition, so it stays visible.
impl std::fmt::Debug for PortableAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortableAuth::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            PortableAuth::PrivateKey { passphrase, .. } => f
                .debug_struct("PrivateKey")
                .field("private_key", &"<redacted>")
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .finish(),
            PortableAuth::PresharedKey {
                peer_public_key, ..
            } => f
                .debug_struct("PresharedKey")
                .field("private_key", &"<redacted>")
                .field("peer_public_key", peer_public_key)
                .finish(),
        }
    }
}

impl PortableProfile {
    /// Moves inline secrets onto disk at mode 0600 and returns a profile that
    /// only references them.
    pub fn import(self, secret_dir: &Path) -> Result<ServerProfile, TunnelError> {
        std::fs::create_dir_all(secret_dir).map_err(|e| {
            TunnelError::config(
                format!("secret dir {}", secret_dir.display()),
                format!("cannot create: {e}"),
            )
        })?;

        let write = |field: &str, value: &str| -> Result<SecretRef, TunnelError> {
            let path = secret_dir.join(format!("{}.{field}", self.id));
            write_secret_file(&path, value)?;
            Ok(SecretRef::File { path })
        };

        let auth = match &self.auth {
            PortableAuth::Password { password } => AuthMethod::Password {
                password: write("password", password)?,
            },
            PortableAuth::PrivateKey {
                private_key,
                passphrase,
            } => AuthMethod::PrivateKey {
                private_key: write("private_key", private_key)?,
                passphrase: match passphrase {
                    Some(p) => Some(write("passphrase", p)?),
                    None => None,
                },
            },
            PortableAuth::PresharedKey {
                private_key,
                peer_public_key,
            } => AuthMethod::PresharedKey {
                private_key: write("private_key", private_key)?,
                peer_public_key: peer_public_key.clone(),
            },
        };

        Ok(ServerProfile {
            id: self.id,
            name: self.name,
            protocol: self.protocol,
            host: self.host,
            port: self.port,
            auth,
            dns: self.dns,
            split_tunnel: self.split_tunnel,
            kill_switch: self.kill_switch,
        })
    }

    /// Resolves every `SecretRef` back to inline material. Callers must show
    /// [`EXPORT_WARNING`] first.
    pub fn export(profile: &ServerProfile, store: &dyn SecretStore) -> Result<Self, TunnelError> {
        let auth = match &profile.auth {
            AuthMethod::Password { password } => PortableAuth::Password {
                password: store.resolve(password)?.into_inner(),
            },
            AuthMethod::PrivateKey {
                private_key,
                passphrase,
            } => PortableAuth::PrivateKey {
                private_key: store.resolve(private_key)?.into_inner(),
                passphrase: match passphrase {
                    Some(p) => Some(store.resolve(p)?.into_inner()),
                    None => None,
                },
            },
            AuthMethod::PresharedKey {
                private_key,
                peer_public_key,
            } => PortableAuth::PresharedKey {
                private_key: store.resolve(private_key)?.into_inner(),
                peer_public_key: peer_public_key.clone(),
            },
            AuthMethod::Shadowsocks { .. } => {
                // `PortableAuth` gains its own variant with the Phase 1b config
                // surface (Task 5/6); until then there is nowhere to put the
                // inlined secret, so export is refused rather than silently
                // dropping it.
                return Err(TunnelError::Unsupported("exporting a shadowsocks profile"));
            }
        };

        Ok(Self {
            id: profile.id,
            name: profile.name.clone(),
            protocol: profile.protocol,
            host: profile.host.clone(),
            port: profile.port,
            auth,
            dns: profile.dns.clone(),
            split_tunnel: profile.split_tunnel.clone(),
            kill_switch: profile.kill_switch,
        })
    }
}

/// Creates the file with 0600 already set, so the secret is never briefly
/// world-readable between `create` and `set_permissions`.
///
/// Always opens with `create_new`, which both refuses to follow an existing
/// symlink at `path` and guarantees the mode we pass is the mode the file is
/// born with — POSIX only honours `open()`'s mode argument on creation, so a
/// plain `create(true)` would silently inherit a looser mode (or write
/// through a symlink) if something already sat at `path`. `ServerProfile`'s
/// `id` is stable across re-import, so a stale file at this exact path is a
/// real, reachable case, not a hypothetical one: if `create_new` reports
/// `AlreadyExists`, we remove whatever is there and retry once. Any other
/// failure — including a second `AlreadyExists` — is propagated rather than
/// falling back to a non-atomic create.
fn write_secret_file(path: &Path, value: &str) -> Result<(), TunnelError> {
    use std::io::Write;

    let open_fresh = || -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    };

    let mut f = match open_fresh() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(path).map_err(|e| {
                TunnelError::config(
                    format!("secret file {}", path.display()),
                    format!("cannot remove stale file before re-import: {e}"),
                )
            })?;
            open_fresh().map_err(|e| {
                TunnelError::config(
                    format!("secret file {}", path.display()),
                    format!("cannot write after removing stale file: {e}"),
                )
            })?
        }
        Err(e) => {
            return Err(TunnelError::config(
                format!("secret file {}", path.display()),
                format!("cannot write: {e}"),
            ));
        }
    };
    f.write_all(value.as_bytes())
        .map_err(|e| TunnelError::config(format!("secret file {}", path.display()), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::profile::{DnsMode, ProtocolKind, SplitTunnelRule};
    use crate::config::secret::FileSecretStore;

    #[test]
    fn the_prd_example_parses_as_a_portable_profile() {
        // PRD §5.2's JSON has inline secrets, which makes it a PortableProfile
        // by definition — this test is the proof that the split in spec §6.3
        // matches the PRD's own example.
        let raw = include_str!("../../tests/fixtures/prd_example.json");
        let p: PortableProfile = serde_json::from_str(raw).unwrap();

        assert_eq!(p.name, "Home VPS - SG");
        assert_eq!(p.protocol, ProtocolKind::WireGuard);
        assert_eq!(p.port, 51820);
        assert_eq!(p.dns.mode, DnsMode::Tcp);
        assert_eq!(p.dns.servers.len(), 2);
        assert_eq!(p.split_tunnel, SplitTunnelRule::AllTraffic);
        assert!(p.kill_switch);
        assert!(matches!(p.auth, PortableAuth::PresharedKey { .. }));
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-portable-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn import_writes_secrets_to_disk_at_mode_600_and_returns_refs() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmpdir("import_writes_secrets_to_disk_at_mode_600_and_returns_refs");
        let portable = PortableProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: PortableAuth::PrivateKey {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n".into(),
                passphrase: None,
            },
            dns: serde_json::from_str(r#"["1.1.1.1"]"#).unwrap(),
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };

        let profile = portable.import(&dir).unwrap();

        let SecretRef::File { path } = (match &profile.auth {
            AuthMethod::PrivateKey { private_key, .. } => private_key.clone(),
            other => panic!("wrong auth variant: {other:?}"),
        }) else {
            panic!("import must produce a file-backed SecretRef");
        };

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "imported secret must be 0600, got {mode:o}");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("BEGIN OPENSSH")
        );

        // And the resulting ServerProfile is safe to serialise.
        let json = serde_json::to_string(&profile).unwrap();
        assert!(
            !json.contains("BEGIN OPENSSH"),
            "key material leaked: {json}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_round_trips_back_to_the_same_secret() {
        let dir = tmpdir("export_round_trips_back_to_the_same_secret");
        let original = PortableProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: PortableAuth::Password {
                password: "hunter2".into(),
            },
            dns: serde_json::from_str(r#"["1.1.1.1"]"#).unwrap(),
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };

        let imported = original.clone().import(&dir).unwrap();
        let exported = PortableProfile::export(&imported, &FileSecretStore).unwrap();

        assert_eq!(exported.auth, original.auth);
        assert_eq!(exported.name, original.name);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_export_warning_mentions_plaintext() {
        assert!(EXPORT_WARNING.to_lowercase().contains("plaintext"));
    }

    #[test]
    fn reimporting_over_a_stale_file_yields_fresh_0600_content_not_the_old_mode() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        // `ServerProfile`/`PortableProfile` ids are stable across re-import,
        // so a second import for the same id lands on the exact same
        // destination path. Simulate that by pre-creating the destination
        // (loosely permissioned, with stale content) before calling
        // `import()`, proving the fix does not inherit the old mode or
        // silently keep the old bytes.
        let dir =
            tmpdir("reimporting_over_a_stale_file_yields_fresh_0600_content_not_the_old_mode");
        let id = uuid::Uuid::nil();
        let dest = dir.join(format!("{id}.password"));
        {
            let mut f = std::fs::File::create(&dest).unwrap();
            f.write_all(b"stale content from a previous export")
                .unwrap();
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let portable = PortableProfile {
            id,
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: PortableAuth::Password {
                password: "hunter2".into(),
            },
            dns: serde_json::from_str(r#"["1.1.1.1"]"#).unwrap(),
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };

        let profile = portable.import(&dir).unwrap();
        let AuthMethod::Password { password } = profile.auth else {
            panic!("wrong auth variant");
        };
        let SecretRef::File { path } = password else {
            panic!("import must produce a file-backed SecretRef");
        };
        assert_eq!(path, dest, "must write to the deterministic id-based path");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "re-imported secret must be 0600, got {mode:o}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "hunter2",
            "re-imported secret must replace the stale content"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn preshared_key_round_trips_through_import_and_export() {
        let dir = tmpdir("preshared_key_round_trips_through_import_and_export");
        let original = PortableProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::WireGuard,
            host: "198.51.100.7".into(),
            port: 51820,
            auth: PortableAuth::PresharedKey {
                private_key: "psk-material".into(),
                peer_public_key: "peer-pubkey".into(),
            },
            dns: serde_json::from_str(r#"["1.1.1.1"]"#).unwrap(),
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };

        let imported = original.clone().import(&dir).unwrap();
        match &imported.auth {
            AuthMethod::PresharedKey {
                private_key,
                peer_public_key,
            } => {
                assert!(matches!(private_key, SecretRef::File { .. }));
                // Public by definition — must stay a plain String, never a SecretRef.
                assert_eq!(peer_public_key, "peer-pubkey");
            }
            other => panic!("wrong auth variant: {other:?}"),
        }

        let exported = PortableProfile::export(&imported, &FileSecretStore).unwrap();
        assert_eq!(exported.auth, original.auth);
        assert_eq!(exported.name, original.name);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn private_key_with_passphrase_round_trips_and_writes_two_distinct_files() {
        let dir = tmpdir("private_key_with_passphrase_round_trips_and_writes_two_distinct_files");
        let original = PortableProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: PortableAuth::PrivateKey {
                // No trailing newline: `FileSecretStore::resolve` (secret.rs)
                // deliberately trims a trailing newline when reading a secret
                // file back, for human-edited key files. That's orthogonal to
                // what this test checks (distinct paths for key vs.
                // passphrase, and passphrase survival), so avoid tripping it
                // here.
                //
                // NB (see fix-secret-newline-report.md): restoring a trailing
                // `\n` here does NOT make the round trip hold, even after
                // secret.rs's trim-at-most-one fix. `import` writes the key
                // verbatim; `export` reads it back through
                // `FileSecretStore::resolve`, which strips exactly one
                // trailing line ending when present. A key ending in exactly
                // one `\n` therefore always loses it on export, identically
                // under both the old ("trim all trailing `\n`") and new
                // ("trim at most one") behaviour, since both strip the same
                // single trailing character here. That asymmetry is between
                // `import` (raw write) and `export` (normalizing read) and is
                // out of scope for this fix.
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc".into(),
                passphrase: Some("swordfish".into()),
            },
            dns: serde_json::from_str(r#"["1.1.1.1"]"#).unwrap(),
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };

        let imported = original.clone().import(&dir).unwrap();

        let (key_ref, pass_ref) = match &imported.auth {
            AuthMethod::PrivateKey {
                private_key,
                passphrase,
            } => (
                private_key.clone(),
                passphrase.clone().expect("passphrase must survive import"),
            ),
            other => panic!("wrong auth variant: {other:?}"),
        };
        let SecretRef::File { path: key_path } = key_ref else {
            panic!("import must produce a file-backed SecretRef for the key");
        };
        let SecretRef::File { path: pass_path } = pass_ref else {
            panic!("import must produce a file-backed SecretRef for the passphrase");
        };
        assert_ne!(
            key_path, pass_path,
            "key and passphrase must be written to distinct files"
        );

        let exported = PortableProfile::export(&imported, &FileSecretStore).unwrap();
        assert_eq!(exported.auth, original.auth);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn portable_auth_debug_never_prints_secret_material() {
        let auth = PortableAuth::PrivateKey {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n".into(),
            passphrase: Some("swordfish".into()),
        };
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("BEGIN OPENSSH"), "leaked: {rendered}");
        assert!(!rendered.contains("swordfish"), "leaked: {rendered}");
        assert!(rendered.contains("<redacted>"));

        let psk = PortableAuth::PresharedKey {
            private_key: "psk-material".into(),
            peer_public_key: "peer-pubkey".into(),
        };
        let rendered = format!("{psk:?}");
        assert!(!rendered.contains("psk-material"), "leaked: {rendered}");
        // Public by definition — fine, even expected, to show up in Debug.
        assert!(rendered.contains("peer-pubkey"));
    }
}
