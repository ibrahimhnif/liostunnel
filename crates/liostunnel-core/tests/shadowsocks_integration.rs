//! Against real Shadowsocks servers. Run with:
//!   make -C testing/docker up
//!   cargo test -p liostunnel-core --test shadowsocks_integration -- --ignored
//!
//! Every test is `#[ignore]`d with the command that provides the fixture, so a
//! run without it reports *ignored* rather than passing on nothing.

use liostunnel_core::config::profile::ServerProfile;
use liostunnel_core::config::secret::{Redacted, SecretRef, SecretStore};
use liostunnel_core::error::TunnelError;
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::shadowsocks::ShadowsocksTunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Pw(String);
impl SecretStore for Pw {
    fn resolve(&self, _r: &SecretRef) -> Result<Redacted<String>, TunnelError> {
        Ok(Redacted::new(self.0.clone()))
    }
}

fn password() -> String {
    std::fs::read_to_string("../../testing/docker/ss/conf/password")
        .expect("run: make -C testing/docker up")
        .trim()
        .to_string()
}

/// A fixture container's address on the compose network.
///
/// Discovered rather than hardcoded: the compose network is recreated by
/// `make down`/`make up` and the addresses move. A stale literal would fail
/// the test for a reason that has nothing to do with the tunnel.
fn container_ip(container: &str) -> std::net::IpAddr {
    let out = std::process::Command::new("docker")
        .args([
            "inspect",
            container,
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ])
        .output()
        .expect("docker must be on PATH: make -C testing/docker up");
    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        !ip.is_empty(),
        "{container} has no compose address; run: make -C testing/docker up"
    );
    ip.parse().expect("a compose address")
}

/// The nginx target, which the host publishes no port for.
fn internal_target() -> std::net::SocketAddr {
    std::net::SocketAddr::new(container_ip("docker-target-1"), 80)
}

/// The fixture's own resolver, on the compose network.
///
/// Every test in this file calls `connect()`, every `connect()` runs the
/// probe, and the probe relays one DNS query to whatever `profile.dns` names.
/// That used to be 1.1.1.1, so the entire suite depended on the compose
/// network's outbound internet access -- which contradicts
/// `phase1b-verification.md`'s justification for the compose target, and,
/// worse, made both credential tests pass for the *wrong reason* wherever
/// that access is absent: a correct password produces the same timeout,
/// naming the same "cipher or password", as a wrong one.
///
/// Like `internal_target`, the host publishes no port for it. See the `dns`
/// service in `testing/docker/docker-compose.yml`.
fn internal_resolver() -> std::net::IpAddr {
    container_ip("docker-dns-1")
}

fn profile(port: u16, method: &str) -> ServerProfile {
    serde_json::from_str(&format!(
        r#"{{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"fixture",
            "protocol":"shadowsocks","host":"127.0.0.1","port":{port},
            "auth":{{"type":"shadowsocks","method":"{method}",
                    "password":{{"source":"file","path":"/tmp/k"}}}},
            "dns":["{}"],"split_tunnel":{{"type":"all_traffic"}},
            "kill_switch":false}}"#,
        internal_resolver()
    ))
    .unwrap()
}

/// Nothing in this suite may depend on the machine's own internet access.
///
/// Both credential tests below assert that a bad credential fails, and the
/// failure they observe is the probe running out of time. An unreachable
/// resolver produces exactly that -- so if the resolver the fixture profile
/// names were reachable only over the open internet, both of them would go
/// green on a machine with none, against a *correct* password. The whole
/// point of the compose target is that it does not.
///
/// Asserted, not assumed: this is the precondition every other test here
/// silently rests on.
#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn the_probe_reaches_a_resolver_only_the_relay_can_reach() {
    // Whether the resolver answers this machine directly is a property of the
    // platform, not of the code: Docker Desktop does not route compose
    // networks to the host, native Linux Docker does. Asserting
    // unreachability would pass here and fail in CI for a reason having
    // nothing to do with the tunnel -- and this repo has been bitten by that
    // exact difference before (see verify-phase1a.sh's note on the bridge
    // route). It is reported, not asserted.
    let resolver = std::net::SocketAddr::new(internal_resolver(), 53);
    let direct = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(resolver),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    eprintln!("note: {resolver} reachable directly from this host: {direct}");

    // The platform-independent proof is the counters. `CountingStream` wraps
    // ONLY streams that came out of `ProxyClientStream`, so a byte counted
    // here is a byte the Shadowsocks server relayed. The probe writes a
    // 19-byte DNS query and reads its 2-byte length prefix; nothing else in
    // `connect` moves a byte.
    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8388, "aes-256-gcm"), &Pw(password()))
        .await
        .expect("the probe's query must travel through the relay");
    let s = t.stats();
    assert_eq!(
        s.bytes_up, 19,
        "the probe's query did not go through the relay"
    );
    assert!(
        s.bytes_down >= 2,
        "nothing came back through the relay: down={}",
        s.bytes_down
    );
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn connects_to_the_c_reference_implementation() {
    // P1b-2. A Rust client against a Rust server proves the crate agrees with
    // itself; this proves it agrees with Shadowsocks.
    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8388, "aes-256-gcm"), &Pw(password()))
        .await
        .expect("libev must accept these credentials");
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn connects_to_the_rust_server_with_a_chacha_cipher() {
    // The other implementation AND the other cipher family: libev on 8388
    // speaks aes-256-gcm, rust on 8389 speaks chacha20-ietf-poly1305. If our
    // cipher plumbing were hardcoded to one family this would catch it.
    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8389, "chacha20-ietf-poly1305"), &Pw(password()))
        .await
        .expect("the rust server must accept chacha20-ietf-poly1305");
}

/// P1b-1 at the protocol layer: bytes out and bytes back.
///
/// The target sits on the compose network and the host publishes no port for
/// it. The plan named a public IP for this; that address was example.com's
/// and has since been retired, which would have failed the test for a reason
/// having nothing to do with the tunnel, and would have made the result
/// depend on the machine's own internet access.
///
/// What proves the bytes traversed the relay is the counter delta below, not
/// the target's reachability -- whether a compose address answers the host
/// directly is a property of the platform (Docker Desktop no, native Linux
/// Docker yes), so asserting on it would pass here and fail in CI.
#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn relays_a_real_http_request_to_a_target_only_it_can_reach() {
    let target = internal_target();
    let direct = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(target),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    eprintln!("note: {target} reachable directly from this host: {direct}");

    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8388, "aes-256-gcm"), &Pw(password()))
        .await
        .unwrap();

    // Snapshotted AFTER connect, and compared as a delta (finding 8).
    // `connect` runs the probe, which goes through `open_dns_stream` ->
    // `open_flow` -> `CountingStream` and writes 19 bytes and reads 2, so both
    // counters are already non-zero here no matter what the HTTP exchange
    // below does. Asserting `> 0` on the absolute values therefore said
    // nothing at all about the relay -- unlike the identical-looking
    // assertion in `ssh_integration.rs`, which is load-bearing precisely
    // because SSH has no probe in front of it.
    let before = t.stats();

    let mut s = t.open_tcp_stream(target).await.expect("a relayed stream");
    s.write_all(b"GET / HTTP/1.0\r\nHost: target.internal\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).await.unwrap();
    assert!(
        body.contains("tunnel-target-ok"),
        "unexpected response: {body}"
    );

    let after = t.stats();
    assert!(
        after.bytes_up > before.bytes_up && after.bytes_down > before.bytes_down,
        "the counters must move for THIS exchange, not merely be non-zero from \
         the probe: up {} -> {}, down {} -> {}",
        before.bytes_up,
        after.bytes_up,
        before.bytes_down,
        after.bytes_down
    );
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn a_wrong_password_fails_at_connect() {
    // P1b-3, and the whole reason the probe exists. Without it this returns
    // Ok: Shadowsocks has no handshake, so a server given the wrong key
    // accepts the connection and discards everything silently. The failure
    // would surface much later as a tunnel that reports Connected and
    // carries nothing.
    //
    // Note WHICH error arrives. The unit fixtures hang up on a bad key and so
    // reach the probe's `read_exact` arm (`Auth`); a real ss-libev server
    // does not hang up -- it holds the connection and discards the bytes, so
    // the probe runs out of time instead. That is the arm a real user hits,
    // and no loopback fixture could have shown it.
    //
    // Fix wave 3, finding 3: that timeout is a `Config` at `auth`, not a
    // `Transport`. `dispatch::connect_failed` maps `Transport` to
    // `ErrorKind::Internal` — "the helper hit an internal error, check its
    // log" — so the arm a real user hits most often was reported as a helper
    // fault rather than as the profile mistake it usually is.
    let mut t = ShadowsocksTunnel::new();
    let err = t
        .connect(
            &profile(8388, "aes-256-gcm"),
            &Pw("definitely-wrong".into()),
        )
        .await
        .expect_err("a wrong password must fail at connect");
    assert!(
        matches!(&err, TunnelError::Auth(_))
            || matches!(&err, TunnelError::Config { field, .. } if field == "auth"),
        "a bad credential is the user's own profile to fix, at `auth`: got {err:?}"
    );
    // Whichever arm it takes, the message must name the credential as a
    // possible cause -- this is the most likely reason a user is here.
    let msg = format!("{err}");
    assert!(
        msg.contains("cipher or password"),
        "must name the credential: {msg}"
    );
    assert!(
        !msg.contains("definitely-wrong") && !format!("{err:?}").contains("definitely-wrong"),
        "the error carried the password: {err:?}"
    );
}

#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn the_wrong_cipher_against_a_real_server_also_fails_at_connect() {
    // The other half of "the credentials work": libev on 8388 speaks
    // aes-256-gcm. Offering it chacha with the RIGHT password must fail too,
    // and for the same reason -- the server cannot decrypt, so nothing comes
    // back. A client that only checked the password would pass this while
    // building a tunnel that carries nothing.
    let mut t = ShadowsocksTunnel::new();
    let err = t
        .connect(&profile(8388, "chacha20-ietf-poly1305"), &Pw(password()))
        .await
        .expect_err("the wrong cipher must fail at connect");
    assert!(
        matches!(&err, TunnelError::Auth(_))
            || matches!(&err, TunnelError::Config { field, .. } if field == "auth"),
        "a bad credential is the user's own profile to fix, at `auth`: got {err:?}"
    );
    assert!(
        format!("{err}").contains("cipher or password"),
        "must name the cipher: {err}"
    );
}
