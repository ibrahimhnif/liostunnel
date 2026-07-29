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

/// The nginx target's address on the compose network.
///
/// Discovered rather than hardcoded: the compose network is recreated by
/// `make down`/`make up` and the address moves. A stale literal would fail
/// the test for a reason that has nothing to do with the tunnel.
fn internal_target() -> std::net::SocketAddr {
    let out = std::process::Command::new("docker")
        .args([
            "inspect",
            "docker-target-1",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ])
        .output()
        .expect("docker must be on PATH: make -C testing/docker up");
    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        !ip.is_empty(),
        "the target container has no compose address; run: make -C testing/docker up"
    );
    format!("{ip}:80").parse().expect("a compose address")
}

fn profile(port: u16, method: &str) -> ServerProfile {
    serde_json::from_str(&format!(
        r#"{{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"fixture",
            "protocol":"shadowsocks","host":"127.0.0.1","port":{port},
            "auth":{{"type":"shadowsocks","method":"{method}",
                    "password":{{"source":"file","path":"/tmp/k"}}}},
            "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
            "kill_switch":false}}"#
    ))
    .unwrap()
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
/// The target is reachable only from inside the compose network -- the host
/// publishes no port for it -- so a successful fetch proves the bytes really
/// traversed the Shadowsocks relay rather than taking a direct route. The
/// plan named a public IP for this; that address was example.com's and has
/// since been retired, which would have failed the test for a reason having
/// nothing to do with the tunnel, and would have made the result depend on
/// the machine's own internet access.
#[tokio::test]
#[ignore = "needs the fixture: make -C testing/docker up"]
async fn relays_a_real_http_request_to_a_target_only_it_can_reach() {
    let target = internal_target();

    // Not reachable from here, only from inside the compose network. If this
    // succeeded, the fetch below would prove nothing.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(target),
        )
        .await
        .map(|r| r.is_err())
        .unwrap_or(true),
        "{target} is reachable without the tunnel; this test would prove nothing"
    );

    let mut t = ShadowsocksTunnel::new();
    t.connect(&profile(8388, "aes-256-gcm"), &Pw(password()))
        .await
        .unwrap();

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

    let stats = t.stats();
    assert!(
        stats.bytes_up > 0 && stats.bytes_down > 0,
        "counters must move: up={} down={}",
        stats.bytes_up,
        stats.bytes_down
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
    let mut t = ShadowsocksTunnel::new();
    let err = t
        .connect(
            &profile(8388, "aes-256-gcm"),
            &Pw("definitely-wrong".into()),
        )
        .await
        .expect_err("a wrong password must fail at connect");
    assert!(
        matches!(err, TunnelError::Auth(_) | TunnelError::Transport(_)),
        "got {err:?}"
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
        matches!(err, TunnelError::Auth(_) | TunnelError::Transport(_)),
        "got {err:?}"
    );
    assert!(
        format!("{err}").contains("cipher or password"),
        "must name the cipher: {err}"
    );
}
