//! The wire codec, exposed to Dart.
//!
//! The message types are defined once, in Rust, and mirrored to Dart by
//! codegen. Dart does socket framing and nothing else — it never calls
//! `jsonEncode` on a request or `jsonDecode` on a reply.
//!
//! This is exit criterion P1a-1's reasoning applied to the protocol. A format
//! re-implemented in a second language drifts from the first; for profiles
//! the drift is a visible parse failure, but here a new `ErrorKind` would
//! fall into a hand-written default branch and get reported as success.

use crate::dto::protocol::{self, PROTOCOL_VERSION};

/// Mirrors [`protocol::ConnectParams`] field for field. Every field is a
/// `String` or a primitive, so nothing here needs FRB to model a core type.
#[derive(Clone, Debug)]
pub struct ConnectParamsDto {
    pub profile_json: String,
    pub user: String,
    /// `"test"` or `"default"`.
    pub route_mode: String,
    /// Only meaningful when `route_mode == "test"`.
    pub cidrs: Vec<String>,
    pub capture_dns: bool,
    pub tun_address: String,
}

/// What the UI can ask the helper to do.
///
/// Deliberately smaller than [`protocol::Request`]: `protocol_version` is not
/// a field here, because the version belongs to this build rather than to the
/// caller. There is no way to send the wrong one.
#[derive(Clone, Debug)]
pub enum RequestDto {
    Hello { id: u64 },
    Connect { id: u64, params: ConnectParamsDto },
    Disconnect { id: u64 },
    GetStatus { id: u64 },
}

/// Anything arriving from the helper — replies and pushed events alike.
/// Flattened into one enum so the Dart side has a single switch.
#[derive(Clone, Debug)]
pub enum IncomingDto {
    Ack {
        id: u64,
    },
    Error {
        id: u64,
        kind: ErrorKindDto,
        message: String,
    },
    State {
        state: String,
    },
    /// Field types match [`protocol::StatsSnapshot`] exactly — `flows_failed`
    /// is a `u64` there, and narrowing it here would silently truncate.
    Stats {
        bytes_up: u64,
        bytes_down: u64,
        active_flows: u32,
        flows_failed: u64,
        dns_queries: u64,
    },
}

/// The machine-readable failure contract. The UI branches on this; `message`
/// is for humans and must never be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKindDto {
    VersionMismatch,
    Unauthorized,
    SecretNotPermitted,
    AlreadyConnected,
    NotConnected,
    AuthFailed,
    BadRequest,
    Internal,
}

impl From<protocol::ErrorKind> for ErrorKindDto {
    fn from(k: protocol::ErrorKind) -> Self {
        // Exhaustive on purpose: a new variant in the protocol fails to
        // compile here rather than reaching Dart as something plausible.
        match k {
            protocol::ErrorKind::VersionMismatch => Self::VersionMismatch,
            protocol::ErrorKind::Unauthorized => Self::Unauthorized,
            protocol::ErrorKind::SecretNotPermitted => Self::SecretNotPermitted,
            protocol::ErrorKind::AlreadyConnected => Self::AlreadyConnected,
            protocol::ErrorKind::NotConnected => Self::NotConnected,
            protocol::ErrorKind::AuthFailed => Self::AuthFailed,
            protocol::ErrorKind::BadRequest => Self::BadRequest,
            protocol::ErrorKind::Internal => Self::Internal,
        }
    }
}

/// Serializes a request to a single wire line, without the trailing newline.
pub fn encode_request(req: RequestDto) -> Result<String, String> {
    let r = match req {
        RequestDto::Hello { id } => protocol::Request::Hello {
            id,
            protocol_version: PROTOCOL_VERSION,
        },
        RequestDto::Connect { id, params } => protocol::Request::Connect {
            id,
            params: protocol::ConnectParams {
                profile_json: params.profile_json,
                user: params.user,
                route_mode: params.route_mode,
                cidrs: params.cidrs,
                capture_dns: params.capture_dns,
                tun_address: params.tun_address,
            },
        },
        RequestDto::Disconnect { id } => protocol::Request::Disconnect { id },
        RequestDto::GetStatus { id } => protocol::Request::GetStatus { id },
    };
    // The error text is fixed rather than serde's: a Connect request carries
    // a profile, and serde's Display quotes parts of what it was given.
    serde_json::to_string(&r).map_err(|_| "could not encode request".to_string())
}

/// Parses one wire line.
///
/// Unknown message types are an error, never a default — a helper newer than
/// the app must be ignored deliberately rather than silently. Both `Response`
/// and `Event` are `#[serde(tag = "type")]`, so an unrecognised tag fails
/// both attempts.
pub fn decode_message(line: String) -> Result<IncomingDto, String> {
    if let Ok(r) = serde_json::from_str::<protocol::Response>(&line) {
        return Ok(match r {
            protocol::Response::Ack { id } => IncomingDto::Ack { id },
            protocol::Response::Error { id, kind, message } => IncomingDto::Error {
                id,
                kind: kind.into(),
                message,
            },
        });
    }
    if let Ok(e) = serde_json::from_str::<protocol::Event>(&line) {
        return Ok(match e {
            protocol::Event::State { state } => IncomingDto::State { state },
            protocol::Event::Stats { snapshot } => IncomingDto::Stats {
                bytes_up: snapshot.bytes_up,
                bytes_down: snapshot.bytes_down,
                active_flows: snapshot.active_flows,
                flows_failed: snapshot.flows_failed,
                dns_queries: snapshot.dns_queries,
            },
        });
    }
    // Describes the shape of the failure, never the line. A malformed line
    // may hold a partial, secret-bearing field.
    Err("not a message this build understands".to_string())
}

/// The protocol version this build speaks.
pub fn protocol_version() -> u32 {
    PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_encoded_request_is_exactly_one_wire_line() {
        // Dart appends nothing but a newline. If encode ever emitted a bare
        // newline of its own, framing would break in a way that looks like a
        // helper bug rather than a client bug.
        let line = encode_request(RequestDto::Disconnect { id: 4 }).unwrap();
        assert!(
            !line.contains('\n'),
            "encoded request must be newline-free: {line}"
        );
        assert!(line.contains(r#""type":"disconnect""#), "got {line}");
    }

    #[test]
    fn encoding_matches_what_the_helper_parses() {
        // The whole point of the codec: what Dart sends must deserialize as
        // the Request the helper's dispatcher matches on.
        let line = encode_request(RequestDto::Hello { id: 1 }).unwrap();
        let parsed: crate::dto::protocol::Request = serde_json::from_str(&line).unwrap();
        assert_eq!(
            parsed,
            crate::dto::protocol::Request::Hello {
                id: 1,
                protocol_version: PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn hello_carries_the_version_the_client_never_chooses() {
        // RequestDto::Hello has no version field. The version is a property of
        // this build, not something the UI can get wrong or a caller can spoof
        // by constructing a DTO.
        let line = encode_request(RequestDto::Hello { id: 1 }).unwrap();
        assert!(
            line.contains(&format!(r#""protocol_version":{PROTOCOL_VERSION}"#)),
            "got {line}"
        );
    }

    #[test]
    fn a_connect_request_round_trips_through_the_helper_s_own_type() {
        // ConnectParams is the largest thing that crosses, and nothing else
        // in the suite constructs it — Task 1's own tests skipped it.
        let line = encode_request(RequestDto::Connect {
            id: 3,
            params: ConnectParamsDto {
                profile_json: "{}".into(),
                user: "u".into(),
                route_mode: "test".into(),
                cidrs: vec!["10.0.0.0/8".into()],
                capture_dns: true,
                tun_address: "10.90.0.1".into(),
            },
        })
        .unwrap();
        match serde_json::from_str::<crate::dto::protocol::Request>(&line).unwrap() {
            crate::dto::protocol::Request::Connect { id, params } => {
                assert_eq!(id, 3);
                assert_eq!(params.user, "u");
                assert_eq!(params.cidrs, vec!["10.0.0.0/8".to_string()]);
                assert!(params.capture_dns);
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn an_error_reply_decodes_with_its_kind_intact() {
        let line = r#"{"type":"error","id":9,"kind":"secret_not_permitted","message":"nope"}"#;
        match decode_message(line.to_string()).unwrap() {
            IncomingDto::Error { id, kind, .. } => {
                assert_eq!(id, 9);
                assert_eq!(kind, ErrorKindDto::SecretNotPermitted);
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_message_type_is_an_error_not_a_silent_default() {
        // A helper newer than the app must not have its messages swallowed.
        // Returning Err makes the client log and ignore deliberately; a
        // default branch would make it report success for something it never
        // understood.
        let r = decode_message(r#"{"type":"quantum_flux","id":1}"#.to_string());
        assert!(r.is_err(), "unknown message types must not decode");
    }

    #[test]
    fn a_truncated_line_is_an_error() {
        assert!(decode_message(r#"{"type":"sta"#.to_string()).is_err());
    }

    #[test]
    fn a_decode_error_does_not_echo_the_line() {
        // Same rule as everywhere else. The marker sits in an enum tag, which
        // is where serde_json actually quotes; a marker in a value would make
        // this test pass against an echoing implementation and prove nothing.
        let e = decode_message(r#"{"type":"SECRET-VALUE-HERE","id":1}"#.to_string()).unwrap_err();
        assert!(!e.contains("SECRET-VALUE-HERE"), "error echoed input: {e}");
    }

    #[test]
    fn every_error_kind_survives_the_round_trip() {
        // Exhaustive by construction: adding an ErrorKind without adding it
        // here fails to compile, which is the point.
        use crate::dto::protocol::ErrorKind as K;
        let all = [
            K::VersionMismatch,
            K::Unauthorized,
            K::SecretNotPermitted,
            K::AlreadyConnected,
            K::NotConnected,
            K::AuthFailed,
            K::BadRequest,
            K::Internal,
        ];
        for k in all {
            let line = serde_json::to_string(&crate::dto::protocol::Response::Error {
                id: 1,
                kind: k,
                message: String::new(),
            })
            .unwrap();
            match decode_message(line).unwrap() {
                IncomingDto::Error { .. } => {}
                other => panic!("{k:?} decoded as {other:?}"),
            }
        }
    }

    #[test]
    fn stats_events_decode_with_their_counters() {
        let line = serde_json::to_string(&crate::dto::protocol::Event::Stats {
            snapshot: crate::dto::protocol::StatsSnapshot {
                bytes_up: 10,
                bytes_down: 20,
                active_flows: 1,
                flows_failed: 0,
                dns_queries: 3,
            },
        })
        .unwrap();
        match decode_message(line).unwrap() {
            IncomingDto::Stats {
                bytes_up,
                active_flows,
                ..
            } => {
                assert_eq!(bytes_up, 10);
                assert_eq!(active_flows, 1);
            }
            other => panic!("expected stats, got {other:?}"),
        }
    }

    #[test]
    fn a_state_event_decodes_with_its_state() {
        match decode_message(r#"{"type":"state","state":"Connected"}"#.to_string()).unwrap() {
            IncomingDto::State { state } => assert_eq!(state, "Connected"),
            other => panic!("expected state, got {other:?}"),
        }
    }

    #[test]
    fn an_ack_decodes_with_its_id() {
        match decode_message(r#"{"type":"ack","id":42}"#.to_string()).unwrap() {
            IncomingDto::Ack { id } => assert_eq!(id, 42),
            other => panic!("expected ack, got {other:?}"),
        }
    }
}
