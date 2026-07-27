//! Requires the Docker fixture: `make -C testing/docker up`
//! Run with: `cargo test -p liostunnel-core --test ssh_integration -- --ignored`

use std::path::PathBuf;

use liostunnel_core::config::profile::{
    AuthMethod, DnsConfig, ProtocolKind, ServerProfile, SplitTunnelRule,
};
use liostunnel_core::config::secret::{FileSecretStore, SecretRef};
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use liostunnel_core::stats::ConnectionState;

fn keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testing/docker/sshd/keys")
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lios-ssh-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn profile(auth: AuthMethod) -> ServerProfile {
    ServerProfile {
        id: uuid::Uuid::nil(),
        name: "fixture".into(),
        protocol: ProtocolKind::Ssh,
        host: "127.0.0.1".into(),
        port: 22022,
        auth,
        dns: serde_json::from_str::<DnsConfig>(r#"["1.1.1.1"]"#).unwrap(),
        split_tunnel: SplitTunnelRule::AllTraffic,
        kill_switch: false,
    }
}

/// File-backed rather than env-backed: `std::env::set_var` is `unsafe` in
/// edition 2024 because concurrent set/get is UB, and these tests share this
/// helper across threads in one test binary.
fn secret_file(tag: &str, body: &str) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = scratch(tag);
    let path = dir.join("secret");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

fn password_auth() -> AuthMethod {
    AuthMethod::Password {
        password: SecretRef::File {
            path: secret_file("pw", "tunnelpass"),
        },
    }
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn connects_with_a_password_and_learns_the_host_key_on_first_use() {
    let known = scratch("tofu").join("known_hosts");
    let mut t = SshTunnel::new(
        "tunneluser".into(),
        HostKeyPolicy::Verify {
            known_hosts: known.clone(),
        },
    );

    t.connect(&profile(password_auth()), &FileSecretStore)
        .await
        .unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);

    let learned = std::fs::read_to_string(&known).unwrap();
    assert!(
        learned.contains("22022"),
        "known_hosts should record the port: {learned}"
    );
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn rejects_a_host_key_that_does_not_match_known_hosts() {
    let known = scratch("mismatch").join("known_hosts");
    // A syntactically valid entry for the right host carrying the wrong key.
    std::fs::create_dir_all(known.parent().unwrap()).unwrap();
    std::fs::write(
        &known,
        "[127.0.0.1]:22022 ssh-ed25519 \
         AAAAC3NzaC1lZDI1NTE5AAAAIEbGVzc29uc2xlYXJuZWRhcmVoYXJkd29u\n",
    )
    .unwrap();

    let mut t = SshTunnel::new(
        "tunneluser".into(),
        HostKeyPolicy::Verify { known_hosts: known },
    );
    let err = t
        .connect(&profile(password_auth()), &FileSecretStore)
        .await
        .unwrap_err();
    assert!(
        matches!(err, liostunnel_core::TunnelError::HostKey(_)),
        "expected HostKey rejection, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn accept_any_policy_bypasses_verification() {
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(password_auth()), &FileSecretStore)
        .await
        .unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn connects_with_a_private_key() {
    let auth = AuthMethod::PrivateKey {
        private_key: SecretRef::File {
            path: keys_dir().join("client_ed25519"),
        },
        passphrase: None,
    };
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(auth), &FileSecretStore).await.unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);
    t.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn a_wrong_password_produces_an_auth_error() {
    let auth = AuthMethod::Password {
        password: SecretRef::File {
            path: secret_file("badpw", "not-the-password"),
        },
    };
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    let err = t
        .connect(&profile(auth), &FileSecretStore)
        .await
        .unwrap_err();
    assert!(
        matches!(err, liostunnel_core::TunnelError::Auth(_)),
        "got {err:?}"
    );
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn a_wireguard_profile_is_rejected_as_unsupported() {
    let mut p = profile(password_auth());
    p.protocol = ProtocolKind::WireGuard;
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    let err = t.connect(&p, &FileSecretStore).await.unwrap_err();
    assert!(
        matches!(err, liostunnel_core::TunnelError::Unsupported(_)),
        "got {err:?}"
    );
}
