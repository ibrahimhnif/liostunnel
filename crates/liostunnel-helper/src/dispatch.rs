use liostunnel_ffi::dto::protocol::{ErrorKind, Event, PROTOCOL_VERSION, Request, Response};

/// One client connection's protocol state.
///
/// Deliberately line-in, lines-out with no socket and no I/O: the entire
/// protocol is then testable without spawning a daemon, the same separation
/// that made Phase 0's `StackCore` testable without a TUN device.
pub struct Session {
    greeted: bool,
    connected: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            greeted: false,
            connected: false,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Handles one line, returning zero or more lines to write back.
    pub fn handle(&mut self, line: &str) -> Vec<String> {
        let req: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => {
                // Deliberately does NOT include the serde error: its Display
                // echoes the offending input, and the input may contain secret
                // material. Phase 0 shipped exactly this leak once already.
                return vec![err(0, ErrorKind::BadRequest, "malformed request")];
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
                return vec![err(
                    id,
                    ErrorKind::VersionMismatch,
                    &format!(
                        "helper speaks protocol {PROTOCOL_VERSION}, client speaks \
                         {protocol_version}; reinstall the helper"
                    ),
                )];
            }
            self.greeted = true;
            return vec![ack(id)];
        }

        if !self.greeted {
            return vec![err(id, ErrorKind::BadRequest, "expected hello first")];
        }

        match req {
            Request::Hello { .. } => unreachable!("handled above"),
            Request::GetStatus { id } => vec![ack(id), event(&self.state_event())],
            Request::Disconnect { id } => {
                if !self.connected {
                    return vec![err(id, ErrorKind::NotConnected, "no tunnel is running")];
                }
                self.connected = false;
                vec![ack(id), event(&self.state_event())]
            }
            // Wired to the engine in Task 6.
            Request::Connect { id, .. } => {
                if self.connected {
                    return vec![err(
                        id,
                        ErrorKind::AlreadyConnected,
                        "a tunnel is already running; there is one routing table",
                    )];
                }
                vec![err(id, ErrorKind::Internal, "connect is not wired yet")]
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

    fn parse_one(out: &[String]) -> serde_json::Value {
        assert_eq!(out.len(), 1, "expected exactly one reply, got {out:?}");
        serde_json::from_str(&out[0]).unwrap()
    }

    fn hello(s: &mut Session) {
        s.handle(
            &serde_json::to_string(&Request::Hello {
                id: 1,
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap(),
        );
    }

    #[test]
    fn hello_with_a_matching_version_is_acked() {
        let mut s = Session::new();
        let req = serde_json::to_string(&Request::Hello {
            id: 1,
            protocol_version: PROTOCOL_VERSION,
        })
        .unwrap();
        let v = parse_one(&s.handle(&req));
        assert_eq!(v["type"], "ack");
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn hello_with_a_mismatched_version_is_refused() {
        // The helper is installed once and privileged; the app updates
        // independently. A newer app must be told to reinstall, not allowed to
        // misinterpret fields. Spec §8.
        let mut s = Session::new();
        let req = serde_json::to_string(&Request::Hello {
            id: 1,
            protocol_version: PROTOCOL_VERSION + 1,
        })
        .unwrap();
        let v = parse_one(&s.handle(&req));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "version_mismatch");
    }

    #[test]
    fn a_refused_hello_does_not_leave_the_session_greeted() {
        // Otherwise the version gate is decorative: a mismatched client is
        // told to reinstall and then served anyway.
        let mut s = Session::new();
        s.handle(
            &serde_json::to_string(&Request::Hello {
                id: 1,
                protocol_version: PROTOCOL_VERSION + 1,
            })
            .unwrap(),
        );
        let v =
            parse_one(&s.handle(&serde_json::to_string(&Request::GetStatus { id: 2 }).unwrap()));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "bad_request");
    }

    #[test]
    fn requests_before_hello_are_refused() {
        // Without this, a client that never handshakes gets full access and
        // the version gate is decorative.
        let mut s = Session::new();
        let req = serde_json::to_string(&Request::GetStatus { id: 5 }).unwrap();
        let v = parse_one(&s.handle(&req));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "bad_request");
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let mut s = Session::new();
        let v = parse_one(&s.handle("{not json"));
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
            let mut s = Session::new();
            let joined = s.handle(line).join(" ");
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
        let mut s = Session::new();
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
        let joined = s.handle(&req).join(" ");
        assert!(
            !joined.contains("hunter2-SECRET"),
            "a reply must not echo the profile: {joined}"
        );
    }

    #[test]
    fn get_status_after_hello_reports_disconnected() {
        let mut s = Session::new();
        hello(&mut s);
        let out = s.handle(&serde_json::to_string(&Request::GetStatus { id: 2 }).unwrap());
        let joined = out.join("\n");
        assert!(joined.contains(r#""type":"state""#), "got {joined}");
        assert!(joined.contains("Disconnected"), "got {joined}");
    }

    #[test]
    fn disconnect_when_not_connected_is_refused_cleanly() {
        let mut s = Session::new();
        hello(&mut s);
        let v =
            parse_one(&s.handle(&serde_json::to_string(&Request::Disconnect { id: 2 }).unwrap()));
        assert_eq!(v["type"], "error");
        assert_eq!(v["kind"], "not_connected");
    }

    #[test]
    fn every_reply_is_a_single_line() {
        // The wire framing is newline-delimited JSON, so an embedded newline
        // in any reply would desynchronise the client for the rest of the
        // connection. Cheap to pin, and impossible to notice by eye.
        let mut s = Session::new();
        let mut all: Vec<String> = vec![];
        all.extend(s.handle("{not json"));
        all.extend(
            s.handle(
                &serde_json::to_string(&Request::Hello {
                    id: 1,
                    protocol_version: PROTOCOL_VERSION,
                })
                .unwrap(),
            ),
        );
        all.extend(s.handle(&serde_json::to_string(&Request::GetStatus { id: 2 }).unwrap()));
        all.extend(s.handle(&serde_json::to_string(&Request::Disconnect { id: 3 }).unwrap()));
        for line in &all {
            assert!(!line.contains('\n'), "reply must be one line: {line:?}");
        }
        assert!(!all.is_empty());
    }
}
