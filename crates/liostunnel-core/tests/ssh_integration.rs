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

/// `tag` must be unique to the calling test: `secret_file` truncates and
/// rewrites its target on every call, and these are `#[tokio::test]`s that
/// cargo may run concurrently on separate threads within one binary. A tag
/// shared between tests used to mean one test could truncate the password
/// file while a sibling was mid-`resolve()`, handing it an empty password.
fn password_auth(tag: &str) -> AuthMethod {
    AuthMethod::Password {
        password: SecretRef::File {
            path: secret_file(tag, "tunnelpass"),
        },
    }
}

/// Generates a real key pair via `ssh-keygen` under `dir` and returns the
/// parsed public key. Real keys, not a hardcoded base64 blob: a fabricated
/// blob that merely fails to *parse* exercises a decode-error path, not the
/// same-algorithm/different-algorithm `known_hosts` branches these mismatch
/// tests are actually about.
fn gen_public_key(
    dir: &std::path::Path,
    name: &str,
    keygen_type_args: &[&str],
) -> russh::keys::ssh_key::PublicKey {
    let path = dir.join(name);
    let status = std::process::Command::new("ssh-keygen")
        .args(keygen_type_args)
        .args(["-N", "", "-C", "lios-test", "-f"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen must be on PATH to run this test");
    assert!(status.success(), "ssh-keygen failed generating {name}");
    russh::keys::load_public_key(path.with_extension("pub")).unwrap()
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn connects_with_a_password_and_learns_the_host_key_on_first_use() {
    let dir = scratch("tofu");
    let known = dir.join("known_hosts");
    let mut t = SshTunnel::new(
        "tunneluser".into(),
        HostKeyPolicy::Verify {
            known_hosts: known.clone(),
        },
    );

    t.connect(&profile(password_auth("tofu")), &FileSecretStore)
        .await
        .unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);

    let learned = std::fs::read_to_string(&known).unwrap();
    assert!(
        learned.contains("22022"),
        "known_hosts should record the port: {learned}"
    );
    t.disconnect().await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn rejects_a_same_algorithm_host_key_that_does_not_match_known_hosts() {
    let dir = scratch("mismatch-same-algo");
    let known = dir.join("known_hosts");
    // A real, valid ed25519 key — just not the fixture server's — recorded
    // for the fixture's host:port. The server's real key is also ed25519, so
    // this exercises `check_known_hosts_path`'s `Err(KeyChanged)` path.
    let wrong_key = gen_public_key(&dir, "wrong-ed25519", &["-t", "ed25519"]);
    russh::keys::known_hosts::learn_known_hosts_path("127.0.0.1", 22022, &wrong_key, &known)
        .unwrap();

    let mut t = SshTunnel::new(
        "tunneluser".into(),
        HostKeyPolicy::Verify { known_hosts: known },
    );
    let err = t
        .connect(
            &profile(password_auth("mismatch-same-algo")),
            &FileSecretStore,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, liostunnel_core::TunnelError::HostKey(_)),
        "expected HostKey rejection, got {err:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Critical regression coverage: `check_known_hosts_path` returns `Ok(false)`
/// both for a genuinely new host *and* for a known host presenting a key of
/// an algorithm that was never recorded — the fixture server's real key is
/// ed25519, so recording an RSA key here and then connecting for real
/// reproduces exactly the scenario an on-path attacker gets if they simply
/// offer an algorithm the client hasn't seen yet. This must fail-closed, not
/// be treated as first contact.
#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn rejects_a_different_algorithm_host_key_for_a_known_host() {
    let dir = scratch("mismatch-diff-algo");
    let known = dir.join("known_hosts");
    let wrong_key = gen_public_key(&dir, "wrong-rsa", &["-t", "rsa", "-b", "2048"]);
    russh::keys::known_hosts::learn_known_hosts_path("127.0.0.1", 22022, &wrong_key, &known)
        .unwrap();
    let before = std::fs::read_to_string(&known).unwrap();

    let mut t = SshTunnel::new(
        "tunneluser".into(),
        HostKeyPolicy::Verify {
            known_hosts: known.clone(),
        },
    );
    let err = t
        .connect(
            &profile(password_auth("mismatch-diff-algo")),
            &FileSecretStore,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, liostunnel_core::TunnelError::HostKey(_)),
        "a host with a recorded rsa key must reject the server's real (different) \
         ed25519 key rather than trusting it as a new host, got {err:?}"
    );

    let after = std::fs::read_to_string(&known).unwrap();
    assert_eq!(
        before, after,
        "the server's real key must never be learned after a rejection"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn accept_any_policy_bypasses_verification() {
    let dir = scratch("acceptany");
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(password_auth("acceptany")), &FileSecretStore)
        .await
        .unwrap();
    assert_eq!(t.stats().state, ConnectionState::Connected);
    t.disconnect().await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
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
    let path = secret_file("badpw", "not-the-password");
    let dir = path.parent().unwrap().to_path_buf();
    let auth = AuthMethod::Password {
        password: SecretRef::File { path },
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
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn a_wireguard_profile_is_rejected_as_unsupported() {
    let dir = scratch("wireguard");
    let mut p = profile(password_auth("wireguard"));
    p.protocol = ProtocolKind::WireGuard;
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    let err = t.connect(&p, &FileSecretStore).await.unwrap_err();
    assert!(
        matches!(err, liostunnel_core::TunnelError::Unsupported(_)),
        "got {err:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `Result::unwrap_err` requires `T: Debug`, but `Box<dyn TunnelStream>`
/// deliberately does not implement `Debug` (Spec §11: payload-carrying types
/// must never gain a `Debug` impl that could leak bytes). Extract the error
/// by hand instead of via `unwrap_err()` so these tests don't require relaxing
/// that guarantee just to make an assertion compile.
fn expect_err<T>(r: Result<T, liostunnel_core::TunnelError>) -> liostunnel_core::TunnelError {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// The target is reachable only from inside the compose network, so a
/// successful fetch proves the bytes really traversed the SSH channel.
#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn opens_a_channel_and_proxies_http_to_an_internal_target() {
    let dir = scratch("open-channel");
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(password_auth("open-channel")), &FileSecretStore)
        .await
        .unwrap();

    // 172.x is the compose-internal address; resolve it by name through the
    // tunnel host instead by using the alias the compose file assigns.
    let dest: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
    let mut s = t
        .open_tcp_stream_named("target.internal", 80, dest)
        .await
        .unwrap();

    s.write_all(b"GET / HTTP/1.0\r\nHost: target.internal\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).await.unwrap();

    assert!(
        body.contains("tunnel-target-ok"),
        "unexpected response: {body}"
    );
    assert!(t.stats().bytes_down > 0, "byte counters must move");
    assert!(t.stats().bytes_up > 0);
    t.disconnect().await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn a_refused_destination_reports_a_protocol_error_without_killing_the_session() {
    let dir = scratch("refused-dest");
    let mut t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    t.connect(&profile(password_auth("refused-dest")), &FileSecretStore)
        .await
        .unwrap();

    // Nothing listens on this port inside the container.
    let dest: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let err = expect_err(t.open_tcp_stream(dest).await);
    assert!(
        matches!(err, liostunnel_core::TunnelError::Protocol(_)),
        "got {err:?}"
    );

    // Spec §11: a per-flow failure must not tear down the session.
    assert_eq!(t.stats().state, ConnectionState::Connected);
    assert_eq!(t.stats().flows_failed, 1);
    t.disconnect().await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
#[ignore = "requires docker fixture: make -C testing/docker up"]
async fn opening_a_stream_before_connecting_is_a_protocol_error() {
    let t = SshTunnel::new("tunneluser".into(), HostKeyPolicy::AcceptAny);
    let err = expect_err(t.open_tcp_stream("127.0.0.1:80".parse().unwrap()).await);
    assert!(
        matches!(err, liostunnel_core::TunnelError::Protocol(_)),
        "got {err:?}"
    );
}
