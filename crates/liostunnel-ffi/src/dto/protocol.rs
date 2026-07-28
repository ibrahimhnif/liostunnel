use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the message shapes below.
///
/// The helper is installed once and is privileged; the app updates
/// independently through normal channels. A newer app talking to an older
/// helper must fail with `ErrorKind::VersionMismatch` rather than
/// misinterpret a field. Spec §8.
pub const PROTOCOL_VERSION: u32 = 1;

/// Client → helper. `id` correlates a `Response` back to its request.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Hello { id: u64, protocol_version: u32 },
    Connect { id: u64, params: ConnectParams },
    Disconnect { id: u64 },
    GetStatus { id: u64 },
}

/// Helper → client, in reply to a specific `Request`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ack {
        id: u64,
    },
    Error {
        id: u64,
        kind: ErrorKind,
        message: String,
    },
}

/// Helper → client, unsolicited.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    State { state: String },
    Stats { snapshot: StatsSnapshot },
}

/// Machine-readable failure category. The UI branches on this; `message` is
/// for humans and must never be parsed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    VersionMismatch,
    Unauthorized,
    SecretNotPermitted,
    AlreadyConnected,
    NotConnected,
    AuthFailed,
    BadRequest,
    Internal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectParams {
    /// The profile as the UI holds it, in the same on-disk JSON form the
    /// user imported. Converted to a core `ServerProfile` by the helper
    /// *after* authorization, never before -- that ordering is the whole
    /// point of spec 7.2.
    pub profile_json: String,
    pub user: String,
    /// "test" or "default".
    pub route_mode: String,
    /// Only meaningful when `route_mode == "test"`.
    pub cidrs: Vec<String>,
    pub capture_dns: bool,
    pub tun_address: String,
}

/// Only fields the engine actually populates. See the omission test above.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active_flows: u32,
    pub flows_failed: u64,
    pub dns_queries: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_format_is_self_describing() {
        // Every message carries a "type" tag, so a human debugging with socat
        // can read the traffic without a schema in front of them.
        let json = serde_json::to_string(&Request::Disconnect { id: 3 }).unwrap();
        assert!(json.contains(r#""type":"disconnect""#), "got {json}");
    }

    #[test]
    fn requests_round_trip() {
        let cases = vec![
            Request::Hello {
                id: 1,
                protocol_version: PROTOCOL_VERSION,
            },
            Request::Disconnect { id: 2 },
            Request::GetStatus { id: 3 },
        ];
        for c in cases {
            let s = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), c);
        }
    }

    #[test]
    fn an_error_response_carries_a_machine_readable_kind() {
        // The UI reacts to `kind`; `message` is for humans only. A UI that has
        // to string-match on `message` breaks the first time wording changes.
        let r = Response::Error {
            id: 9,
            kind: ErrorKind::VersionMismatch,
            message: "helper speaks v1, client speaks v2".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""kind":"version_mismatch""#), "got {json}");
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), r);
    }

    #[test]
    fn events_round_trip() {
        let e = Event::Stats {
            snapshot: StatsSnapshot {
                bytes_up: 100,
                bytes_down: 200,
                active_flows: 3,
                flows_failed: 1,
                dns_queries: 7,
            },
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&s).unwrap(), e);
    }

    #[test]
    fn stats_omits_the_counters_core_never_populates() {
        // Spec 8.2: udp_dropped, syn_dropped, malformed_dropped and
        // bytes_discarded are computed in StackCore but have no callers, so
        // ConnectionStats reports them as permanently zero. They are omitted
        // from the protocol entirely rather than rendered as a fake measurement.
        let json = serde_json::to_string(&StatsSnapshot {
            bytes_up: 0,
            bytes_down: 0,
            active_flows: 0,
            flows_failed: 0,
            dns_queries: 0,
        })
        .unwrap();
        for absent in [
            "udp_dropped",
            "syn_dropped",
            "malformed_dropped",
            "bytes_discarded",
        ] {
            assert!(
                !json.contains(absent),
                "{absent} must not appear in the wire format: {json}"
            );
        }
    }
}
