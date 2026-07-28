use liostunnel_ffi::dto::protocol::{ErrorKind, Event, PROTOCOL_VERSION, Request, Response};

use crate::session::{StartError, Tunnel};

/// What a `connect` line asks the caller to actually do.
///
/// `handle` stays synchronous and pure by *describing* the privileged work
/// rather than performing it: bringing a tunnel up is async and takes
/// seconds, and folding that into the dispatcher would make the whole
/// protocol untestable without a TUN device and a live SSH server.
#[must_use]
pub enum Action {
    /// Nothing beyond writing the replies.
    None,
    /// Run `Tunnel::start`, then report the outcome back through
    /// `connect_succeeded` / `connect_failed` with this request id.
    Start(u64, Box<crate::session::Authorized>),
    /// Tear the running tunnel down. The replies are already written — a
    /// disconnect is acked optimistically because the teardown cannot fail
    /// in a way the caller could act on, and `RouteGuard` reverts regardless.
    StopTunnel,
}

/// One client connection's protocol state.
///
/// Deliberately line-in, lines-out with no socket and no I/O: the entire
/// protocol is then testable without spawning a daemon, the same separation
/// that made Phase 0's `StackCore` testable without a TUN device.
pub struct Session {
    greeted: bool,
    connected: bool,
    /// The uid the socket layer authenticated. Secrets are resolved against
    /// this, never against the daemon's own root identity.
    caller_uid: u32,
}

impl Session {
    pub fn new(caller_uid: u32) -> Self {
        Self {
            greeted: false,
            connected: false,
            caller_uid,
        }
    }

    /// True once a `hello` with a matching protocol version has been acked.
    ///
    /// A refused hello leaves this false, so nothing downstream serves a
    /// client that was told to reinstall.
    pub fn is_greeted(&self) -> bool {
        self.greeted
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Adopts a tunnel the daemon already had running.
    ///
    /// A relaunched UI opens a fresh connection and must re-sync to reality
    /// rather than report Disconnected over a working tunnel (P1a-4). The
    /// daemon owns the tunnel; the session only mirrors it.
    pub fn resume_connected(&mut self) {
        self.connected = true;
    }

    /// Records that the work `Action::Start` described succeeded.
    pub fn connect_succeeded(&mut self, id: u64) -> Vec<String> {
        self.connected = true;
        vec![ack(id), event(&self.state_event())]
    }

    /// Records that it failed, mapping the cause to the wire's error kinds.
    pub fn connect_failed(&mut self, id: u64, e: &StartError) -> Vec<String> {
        self.connected = false;
        let kind = match e {
            StartError::BadProfile(_)
            | StartError::BadRouteMode(_)
            | StartError::BadTunAddress
            | StartError::EnvSecretNotAllowed => ErrorKind::BadRequest,
            StartError::SecretNotPermitted(_) => ErrorKind::SecretNotPermitted,
            // Only a real authentication failure may be reported as one.
            // This was `Tunnel(_) => AuthFailed` for every variant, so a DNS
            // failure, an unreachable host, a host-key mismatch and a route
            // error all told the user "the server rejected the credentials"
            // -- sending them to re-check a password that was never the
            // problem. Everything else is Internal, whose wording points at
            // the helper log, which does name the cause.
            StartError::Tunnel(liostunnel_core::TunnelError::Auth(_)) => ErrorKind::AuthFailed,
            // A profile the user can fix, not a helper fault. `Internal`'s
            // wording points at the helper log, which is the wrong place to
            // send someone who typed a cipher name wrong, gave a shadowsocks
            // profile ssh credentials, or left `dns.https` out of a `https`
            // profile — all `Config`, all newly reachable through the helper
            // now that it can dial Shadowsocks, and all five-second fixes in
            // their own file. `SshTunnel` essentially never produced `Config`,
            // which is why this never mattered before.
            StartError::Tunnel(liostunnel_core::TunnelError::Config { .. }) => {
                ErrorKind::BadRequest
            }
            StartError::Tunnel(_) => ErrorKind::Internal,
        };
        // `e`'s Display is safe to send back over the wire. Every variant
        // except `BadRouteMode` carries no input at all, or carries only a
        // path and uid; `BadProfile` carries a reason too, but it is
        // `&'static str` -- a literal in `session.rs`, which no request can
        // influence -- and Task 6's echo tests still pin that the profile
        // itself never comes back.
        //
        // `BadRouteMode(String)` is the one exception, and does carry a
        // caller string verbatim, at two sites: `session.rs:568`
        // ("cidr is not valid: {c}") and `session.rs:596-598` ("expected
        // `test` or `default`, got `{other}`"). Echoing there is fine, but
        // for a narrower reason than "no input" -- a gate failure (this
        // whole `Connect` arm, from `Tunnel::authorize_params`) never
        // reaches `tracing::warn!(error = %e, "connect failed")`: that only
        // fires in `main.rs` for a `StartError` from `Tunnel::start`, which
        // runs strictly after the gate has already returned `Ok`, so it
        // can never itself produce `BadRouteMode`. The only sink left is
        // the wire, back to the same caller who supplied the string in the
        // first place -- there is nothing in it they did not already have.
        // That reasoning does not extend to a message that also reaches the
        // helper log; do not copy this pattern for one that does.
        vec![err(id, kind, &e.to_string())]
    }

    /// Records that the tunnel stopped without being asked to — the engine
    /// exiting on its own. Without this the UI shows Connected over a dead
    /// tunnel, which is the blackout Phase 0 had to fix in the CLI.
    pub fn tunnel_stopped(&mut self) -> Vec<String> {
        self.connected = false;
        vec![event(&self.state_event())]
    }

    /// Handles one line, returning replies to write and any privileged work
    /// the caller must then perform.
    pub fn handle(&mut self, line: &str) -> (Vec<String>, Action) {
        let req: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => {
                // Deliberately does NOT include the serde error: its Display
                // quotes keys and enum tags from the offending input, and the
                // input may contain secret material. Phase 0 shipped exactly
                // this leak once already.
                return (
                    vec![err(0, ErrorKind::BadRequest, "malformed request")],
                    Action::None,
                );
            }
        };

        let id = request_id(&req);

        if let Request::Hello {
            protocol_version, ..
        } = req
        {
            if protocol_version != PROTOCOL_VERSION {
                // `greeted` stays false: a client told to reinstall must not
                // then be served, or the gate is decorative.
                return (
                    vec![err(
                        id,
                        ErrorKind::VersionMismatch,
                        &format!(
                            "helper speaks protocol {PROTOCOL_VERSION}, client speaks \
                             {protocol_version}; reinstall the helper"
                        ),
                    )],
                    Action::None,
                );
            }
            self.greeted = true;
            return (vec![ack(id)], Action::None);
        }

        if !self.greeted {
            return (
                vec![err(id, ErrorKind::BadRequest, "expected hello first")],
                Action::None,
            );
        }

        match req {
            Request::Hello { .. } => unreachable!("handled above"),
            Request::GetStatus { id } => (vec![ack(id), event(&self.state_event())], Action::None),
            Request::Disconnect { id } => {
                if !self.connected {
                    return (
                        vec![err(id, ErrorKind::NotConnected, "no tunnel is running")],
                        Action::None,
                    );
                }
                self.connected = false;
                (
                    vec![ack(id), event(&self.state_event())],
                    Action::StopTunnel,
                )
            }
            Request::Connect { id, params } => {
                if self.connected {
                    return (
                        vec![err(
                            id,
                            ErrorKind::AlreadyConnected,
                            "a tunnel is already running; there is one routing table",
                        )],
                        Action::None,
                    );
                }
                // THE GATE, on the caller's uid rather than the daemon's.
                // Everything decidable without privilege is decided here, so
                // a refusal costs no TUN device and no route.
                match Tunnel::authorize_params(&params, self.caller_uid) {
                    Ok(authorized) => (vec![], Action::Start(id, Box::new(authorized))),
                    Err(e) => (self.connect_failed(id, &e), Action::None),
                }
            }
        }
    }

    fn state_event(&self) -> Event {
        Event::State {
            state: if self.connected {
                "Connected"
            } else {
                "Disconnected"
            }
            .into(),
        }
    }
}

fn request_id(r: &Request) -> u64 {
    match r {
        Request::Hello { id, .. }
        | Request::Connect { id, .. }
        | Request::Disconnect { id }
        | Request::GetStatus { id } => *id,
    }
}

fn ack(id: u64) -> String {
    serde_json::to_string(&Response::Ack { id }).expect("Ack always serializes")
}

fn err(id: u64, kind: ErrorKind, message: &str) -> String {
    serde_json::to_string(&Response::Error {
        id,
        kind,
        message: message.into(),
    })
    .expect("Error always serializes")
}

fn event(e: &Event) -> String {
    serde_json::to_string(e).expect("Event always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use liostunnel_ffi::dto::protocol::*;
    use std::os::unix::fs::PermissionsExt;

    fn parse_one(out: &[String]) -> serde_json::Value {
        assert_eq!(out.len(), 1, "expected exactly one reply, got {out:?}");
        serde_json::from_str(&out[0]).unwrap()
    }

    fn sess() -> Session {
        Session::new(unsafe { libc::getuid() })
    }

    /// The replies only. Tests that care about the requested work match on
    /// `handle`'s second element directly.
    fn lines(s: &mut Session, line: &str) -> Vec<String> {
        s.handle(line).0
    }

    /// A syntactically valid connect naming `key` as its password file.
    fn connect_line(key: &std::path::Path, id: u64) -> String {
        serde_json::to_string(&Request::Connect {
            id,
            params: ConnectParams {
                profile_json: format!(
                    r#"{{"id":"00000000-0000-0000-0000-000000000000","name":"t",
                        "protocol":"ssh","host":"127.0.0.1","port":22,
                        "auth":{{"type":"password","password":{{"source":"file","path":"{}"}}}},
                        "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
                        "kill_switch":false}}"#,
                    key.display()
                ),
                user: "u".into(),
                route_mode: "test".into(),
                cidrs: vec!["93.184.216.0/24".into()],
                capture_dns: false,
                tun_address: "10.90.0.1".into(),
            },
        })
        .unwrap()
    }

    fn hello(s: &mut Session) {
        lines(
            s,
            &serde_json::to_string(&Request::Hello {
                id: 1,
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap(),
        );
    }

    #[test]
    fn hello_with_a_matching_version_is_acked() {
        let mut s = sess();
        let req = serde_json::to_string(&Request::Hello {
            id: 1,
            protocol_version: PROTOCOL_VERSION,
        })
        .unwrap();
        let v = parse_one(&lines(&mut s, &req));
        assert_eq!(v["type"], "ack");
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn hello_with_a_mismatched_version_is_refused() {
        // The helper is installed once and privileged; the app updates
        // independently. A newer app must be told to reinstall, not allowed to
        // misinterpret fields. Spec §8.
        let mut s = sess();
        let req = serde_json::to_string(&Request::Hello {
            id: 1,
            protocol_version: PROTOCOL_VERSION + 1,
        })
        .unwrap();
        let v = parse_one(&lines(&mut s, &req));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "version_mismatch");
    }

    #[test]
    fn a_refused_hello_does_not_leave_the_session_greeted() {
        // Otherwise the version gate is decorative: a mismatched client is
        // told to reinstall and then served anyway.
        let mut s = sess();
        lines(
            &mut s,
            &serde_json::to_string(&Request::Hello {
                id: 1,
                protocol_version: PROTOCOL_VERSION + 1,
            })
            .unwrap(),
        );
        let v = parse_one(&lines(
            &mut s,
            &serde_json::to_string(&Request::GetStatus { id: 2 }).unwrap(),
        ));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "bad_request");
    }

    #[test]
    fn requests_before_hello_are_refused() {
        // Without this, a client that never handshakes gets full access and
        // the version gate is decorative.
        let mut s = sess();
        let req = serde_json::to_string(&Request::GetStatus { id: 5 }).unwrap();
        let v = parse_one(&lines(&mut s, &req));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "bad_request");
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let mut s = sess();
        let v = parse_one(&lines(&mut s, "{not json"));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "bad_request");
    }

    #[test]
    fn a_malformed_line_does_not_carry_its_contents_back() {
        // serde_json's Display echoes parts of the input, and Phase 0 shipped
        // exactly that leak in profile_io::load, where a misplaced secret came
        // back in the error text. The same rule crosses the socket.
        //
        // Measured which shapes actually echo, because guessing produced a
        // test that could not fail: serde_json quotes **keys and enum tags**,
        // never values.
        //
        //   {"type":"X"}                    -> unknown variant `X`, expected …
        //   {…,"params":{"X":…}}            -> unknown field `X`, expected …
        //   {…,"profile_json":"X"}          -> missing field `user`   (no echo)
        //   {…,"profile_json":X}            -> expected value at line 1 col 51
        //
        // So the marker goes in the positions that leak. A version of this
        // test with the marker in a value passes against a deliberately
        // echoing implementation and proves nothing.
        let leaky = [
            r#"{"type":"hunter2-SECRET","id":1}"#,
            r#"{"type":"connect","id":1,"params":{"hunter2-SECRET":"x"}}"#,
        ];
        for line in leaky {
            let mut s = sess();
            let joined = lines(&mut s, line).join(" ");
            assert!(
                !joined.contains("hunter2-SECRET"),
                "the error must not echo request content.\n  input: {line}\n  reply: {joined}"
            );
        }
    }

    #[test]
    fn a_well_formed_connect_does_not_echo_its_profile_either() {
        // The malformed path is not the only way content comes back. A
        // syntactically valid request carries the profile through dispatch,
        // and every reply it produces must stay free of it.
        let mut s = sess();
        hello(&mut s);
        let req = serde_json::to_string(&Request::Connect {
            id: 2,
            params: ConnectParams {
                profile_json: "hunter2-SECRET".into(),
                user: "someone".into(),
                route_mode: "test".into(),
                cidrs: vec![],
                capture_dns: false,
                tun_address: "10.9.0.2".into(),
            },
        })
        .unwrap();
        let joined = lines(&mut s, &req).join(" ");
        assert!(
            !joined.contains("hunter2-SECRET"),
            "a reply must not echo the profile: {joined}"
        );
    }

    #[test]
    fn get_status_after_hello_reports_disconnected() {
        let mut s = sess();
        hello(&mut s);
        let out = lines(
            &mut s,
            &serde_json::to_string(&Request::GetStatus { id: 2 }).unwrap(),
        );
        let joined = out.join("\n");
        assert!(joined.contains(r#""type":"state""#), "got {joined}");
        assert!(joined.contains("Disconnected"), "got {joined}");
    }

    #[test]
    fn disconnect_when_not_connected_is_refused_cleanly() {
        let mut s = sess();
        hello(&mut s);
        let v = parse_one(&lines(
            &mut s,
            &serde_json::to_string(&Request::Disconnect { id: 2 }).unwrap(),
        ));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "not_connected");
    }

    #[test]
    fn a_connect_naming_a_foreign_secret_is_refused_and_asks_for_no_work() {
        // The gate runs inside dispatch, on the caller's uid. A refusal must
        // produce an error reply AND no Action — if it returned Start, the
        // accept loop would go on to open a TUN device and install routes for
        // a request that was already denied.
        let d = std::env::temp_dir().join(format!("lios-disp-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let key = d.join("key");
        std::fs::write(&key, b"k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

        // A session whose authenticated caller is NOT the file's owner.
        let mut s = Session::new(unsafe { libc::getuid() }.wrapping_add(1));
        hello(&mut s);
        let (replies, action) = s.handle(&connect_line(&key, 7));

        let v: serde_json::Value = serde_json::from_str(&replies[0]).unwrap();
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "secret_not_permitted");
        assert!(
            matches!(action, Action::None),
            "a refused connect must not ask for any privileged work"
        );
        assert!(!s.is_connected());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_authorized_connect_asks_for_the_work_and_acks_nothing_yet() {
        // The ack belongs after the tunnel is actually up, not before. A
        // client that saw `ack` and then a failure would have been told the
        // opposite of what happened.
        let d = std::env::temp_dir().join(format!("lios-disp-ok-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let key = d.join("key");
        std::fs::write(&key, b"k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut s = sess();
        hello(&mut s);
        let (replies, action) = s.handle(&connect_line(&key, 7));
        assert!(replies.is_empty(), "nothing is reported until it happened");
        match action {
            Action::Start(id, _) => assert_eq!(id, 7),
            _ => panic!("expected Start"),
        }
        assert!(!s.is_connected(), "not connected until start succeeds");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_disconnect_asks_for_the_teardown() {
        let mut s = sess();
        hello(&mut s);
        s.connect_succeeded(1);
        assert!(s.is_connected());
        let (replies, action) =
            s.handle(&serde_json::to_string(&Request::Disconnect { id: 2 }).unwrap());
        assert!(matches!(action, Action::StopTunnel));
        assert!(replies.iter().any(|l| l.contains("Disconnected")));
        assert!(!s.is_connected());
    }

    #[test]
    fn an_engine_that_stops_on_its_own_is_reported_as_disconnected() {
        // Phase 0's blackout: routes installed, no engine behind them, and
        // the UI still showing Connected. The session must be able to say so.
        let mut s = sess();
        hello(&mut s);
        s.connect_succeeded(1);
        let out = s.tunnel_stopped();
        assert!(!s.is_connected());
        assert!(
            out.iter().any(|l| l.contains("Disconnected")),
            "got {out:?}"
        );
    }

    #[test]
    fn a_failed_start_is_reported_with_the_matching_kind() {
        let mut s = sess();
        hello(&mut s);
        let out = s.connect_failed(3, &StartError::EnvSecretNotAllowed);
        let v: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(v["kind"], "bad_request");
        assert!(!s.is_connected());
    }

    #[test]
    fn a_shadowsocks_probe_failure_is_not_reported_as_a_wrong_password() {
        // Shadowsocks has no handshake, so `connect` proves the credentials
        // with one relayed round trip — which means it can now fail for
        // NETWORK reasons as well as credential ones. A probe that times out
        // is `Transport`; a DoH resolver whose TLS failed through a
        // proven-good relay is `Dns`. Neither means the password was wrong,
        // and saying so sends the user to change a credential that works.
        //
        // Fix wave 1, finding 6: the last row is the direction nothing
        // guarded. Only `Tunnel(_) => Internal` was pinned, so mutating the
        // `Auth` arm to `Internal` left the suite green and silently stopped
        // ever telling a user their password was wrong — the exact failure
        // this test's first two rows exist to prevent, in reverse.
        use liostunnel_core::TunnelError;
        let mut s = sess();
        let failures = [
            (
                StartError::Tunnel(TunnelError::Transport(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "probe",
                ))),
                "internal",
            ),
            (
                StartError::Tunnel(TunnelError::Dns("resolver refused the handshake".into())),
                "internal",
            ),
            (
                StartError::Tunnel(TunnelError::Auth("server rejected credentials".into())),
                "auth_failed",
            ),
        ];
        for (e, expected) in &failures {
            let out = s.connect_failed(3, e);
            let v: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
            assert_eq!(v["kind"], *expected, "{e} was reported as {v}");
        }
    }

    /// Fix wave 1, finding 3. `dispatch` mapped every non-`Auth` `TunnelError`
    /// to `Internal`, whose wording sends the user to the helper's log.
    /// `SshTunnel` essentially never produced `Config`, so that never
    /// mattered — but the Shadowsocks arm reaches the helper now, and it
    /// returns `Config` for an unoffered cipher name, wrong-kind credentials
    /// and a missing `dns.https`: all things the user fixes in their own
    /// profile in five seconds, none of them a helper fault.
    ///
    /// The error is produced by the real code path rather than hand-built, so
    /// this cannot pass against a `Config` shape the tunnel never actually
    /// returns. No network: the cipher allow-list refuses before anything is
    /// resolved, opened or read.
    #[tokio::test]
    async fn a_cipher_this_build_does_not_offer_is_the_users_mistake_not_an_internal_error() {
        use liostunnel_core::protocols::Protocol;
        use liostunnel_core::protocols::shadowsocks::ShadowsocksTunnel;

        let profile = serde_json::from_str(
            r#"{"id":"00000000-0000-0000-0000-000000000000","name":"t",
                "protocol":"shadowsocks","host":"127.0.0.1","port":8388,
                "auth":{"type":"shadowsocks","method":"rot13",
                        "password":{"source":"file","path":"/tmp/lios-absent"}},
                "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
                "kill_switch":false}"#,
        )
        .unwrap();
        let mut t = ShadowsocksTunnel::new();
        let e = StartError::Tunnel(
            t.connect(&profile, &crate::session::ResolvedSecrets::default())
                .await
                .expect_err("`rot13` is not a cipher this build offers"),
        );

        let mut s = sess();
        let out = s.connect_failed(9, &e);
        let v: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(
            v["kind"], "bad_request",
            "a cipher name the user typed is theirs to fix, not a helper fault: {v}"
        );
    }

    #[test]
    fn every_reply_is_a_single_line() {
        // The wire framing is newline-delimited JSON, so an embedded newline
        // in any reply would desynchronise the client for the rest of the
        // connection. Cheap to pin, and impossible to notice by eye.
        let mut s = sess();
        let mut all: Vec<String> = vec![];
        all.extend(lines(&mut s, "{not json"));
        all.extend(lines(
            &mut s,
            &serde_json::to_string(&Request::Hello {
                id: 1,
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap(),
        ));
        all.extend(lines(
            &mut s,
            &serde_json::to_string(&Request::GetStatus { id: 2 }).unwrap(),
        ));
        all.extend(lines(
            &mut s,
            &serde_json::to_string(&Request::Disconnect { id: 3 }).unwrap(),
        ));
        for line in &all {
            assert!(!line.contains('\n'), "reply must be one line: {line:?}");
        }
        assert!(!all.is_empty());
    }
}
