use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the message shapes below.
///
/// The helper is installed once and is privileged; the app updates
/// independently through normal channels. A newer app talking to an older
/// helper must fail with `ErrorKind::VersionMismatch` rather than
/// misinterpret a field. Spec §8.
///
/// 2 since Phase 1b: the profile schema gained `auth.type: "shadowsocks"`,
/// and `ConnectParams::profile_json` crosses the socket verbatim, so a
/// version-1 helper's `serde_json::from_str::<ServerProfile>` fails on the
/// unknown tag and reports `BadRequest: "profile is not valid"` about a
/// profile that is entirely valid -- with no hint that the helper is the
/// stale half. A new value in a field the peer parses is a breaking change to
/// the message shapes even when no field was added or removed.
pub const PROTOCOL_VERSION: u32 = 2;

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

    /// Fix wave 3, finding 7. `AuthMethod::Shadowsocks` is new to the profile
    /// schema on this branch, and `profile_json` crosses the socket verbatim
    /// -- so a Phase 1a helper hands it to `serde_json::from_str::<ServerProfile>`,
    /// which fails on the unknown `auth.type` tag. The user updated the app,
    /// imported an `ss://` link, pressed Connect, and was told `BadRequest:
    /// "profile is not valid"` about a perfectly valid profile, with nothing
    /// to suggest the helper was the stale half. The helper installs once, as
    /// root, and updates independently of the app: that asymmetry is the whole
    /// reason `PROTOCOL_VERSION` exists (spec §8), and it was not bumped.
    ///
    /// Written as an implication rather than a bare `assert_eq!` so it says
    /// something: it is the schema accepting a tag no version-1 helper knows
    /// that obliges the bump. Both halves can move it -- take the shadowsocks
    /// arm out of `AuthMethod` and the premise goes away; leave the version at
    /// 1 and the conclusion fails.
    #[test]
    fn a_profile_schema_that_grew_a_new_auth_type_bumped_the_protocol_version() {
        /// The wire version in which `auth.type: "shadowsocks"` first became
        /// something a helper could be expected to parse.
        const SHADOWSOCKS_ARRIVED_IN: u32 = 2;

        let ss = r#"{"id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"SS",
            "protocol":"shadowsocks","host":"198.51.100.7","port":8388,
            "auth":{"type":"shadowsocks","method":"aes-256-gcm",
                    "password":{"source":"file","path":"/tmp/k"}},
            "dns":["1.1.1.1"],"split_tunnel":{"type":"all_traffic"},
            "kill_switch":false}"#;

        // Read through the FFI's own accessor, which is the value the app
        // puts in its `hello` (`api::protocol::hello_line`) and the value
        // `app/test/protocol_test.dart` compares that line against -- so this
        // is the number both sides actually agree on, not a second copy of it.
        let speaks = crate::api::protocol::protocol_version();

        if serde_json::from_str::<liostunnel_core::config::profile::ServerProfile>(ss).is_ok() {
            assert!(
                speaks >= SHADOWSOCKS_ARRIVED_IN,
                "the profile schema accepts `auth.type: shadowsocks`, which a \
                 helper speaking protocol {} cannot parse -- a client that \
                 sends one must be told to reinstall the helper, not told its \
                 own profile is invalid",
                SHADOWSOCKS_ARRIVED_IN - 1
            );
        }
    }

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
