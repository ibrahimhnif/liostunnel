use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::secret::SecretRef;

/// Spec §9.1 / PRD §5.2.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServerProfile {
    pub id: Uuid,
    pub name: String,
    pub protocol: ProtocolKind,
    pub host: String,
    pub port: u16,
    pub auth: AuthMethod,
    pub dns: DnsConfig,
    pub split_tunnel: SplitTunnelRule,
    pub kill_switch: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Ssh,
    // `rename_all = "snake_case"` alone would produce "wire_guard" (it inserts an
    // underscore at every internal capital), but the wire format is "wireguard" —
    // override just this variant.
    #[serde(rename = "wireguard")]
    WireGuard,
    Shadowsocks,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMethod {
    Password {
        password: SecretRef,
    },
    PrivateKey {
        private_key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<SecretRef>,
    },
    /// WireGuard. Parsed in Phase 0, rejected at connect time. Spec §9.3.
    PresharedKey {
        private_key: SecretRef,
        /// Public by definition, so not a `SecretRef`.
        peer_public_key: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    #[default]
    Tcp,
    Https,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DohConfig {
    /// TLS SNI and `Host:` for the DoH endpoint. `servers` holds the IP, so
    /// there is no bootstrap resolution to perform. Spec §9.1.
    pub sni: String,
    pub path: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DnsConfig {
    pub mode: DnsMode,
    pub servers: Vec<IpAddr>,
    pub https: Option<DohConfig>,
}

/// Accepts both the widened struct and PRD §5.2's bare `["1.1.1.1", "1.0.0.1"]`,
/// so the PRD's own example stays valid. Spec §9.1.
impl<'de> Deserialize<'de> for DnsConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            // Must come first: an array can never match the struct form.
            Bare(Vec<IpAddr>),
            Full {
                #[serde(default)]
                mode: DnsMode,
                servers: Vec<IpAddr>,
                #[serde(default)]
                https: Option<DohConfig>,
            },
        }

        Ok(match Repr::deserialize(d)? {
            Repr::Bare(servers) => DnsConfig {
                mode: DnsMode::Tcp,
                servers,
                https: None,
            },
            Repr::Full {
                mode,
                servers,
                https,
            } => DnsConfig {
                mode,
                servers,
                https,
            },
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SplitTunnelRule {
    AllTraffic,
    ExcludeApps { apps: Vec<String> },
    IncludeOnly { apps: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn dns_accepts_the_prd_bare_array_form() {
        let cfg: DnsConfig = serde_json::from_str(r#"["1.1.1.1", "1.0.0.1"]"#).unwrap();
        assert_eq!(
            cfg.mode,
            DnsMode::Tcp,
            "bare array must default to DNS-over-TCP"
        );
        assert_eq!(cfg.servers, vec![ip(1, 1, 1, 1), ip(1, 0, 0, 1)]);
        assert!(cfg.https.is_none());
    }

    #[test]
    fn dns_accepts_the_widened_struct_form() {
        let cfg: DnsConfig = serde_json::from_str(
            r#"{"mode":"https","servers":["1.1.1.1"],
                "https":{"sni":"cloudflare-dns.com","path":"/dns-query"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.mode, DnsMode::Https);
        assert_eq!(cfg.https.unwrap().sni, "cloudflare-dns.com");
    }

    #[test]
    fn dns_always_serialises_to_the_struct_form() {
        let cfg = DnsConfig {
            mode: DnsMode::Tcp,
            servers: vec![ip(9, 9, 9, 9)],
            https: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(json, r#"{"mode":"tcp","servers":["9.9.9.9"],"https":null}"#);
    }

    #[test]
    fn prd_fixture_dns_field_parses() {
        let raw = include_str!("../../tests/fixtures/prd_example.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let dns: DnsConfig = serde_json::from_value(v["dns"].clone()).unwrap();
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.mode, DnsMode::Tcp);
    }

    #[test]
    fn protocol_kind_uses_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&ProtocolKind::WireGuard).unwrap(),
            r#""wireguard""#
        );
        assert_eq!(
            serde_json::from_str::<ProtocolKind>(r#""shadowsocks""#).unwrap(),
            ProtocolKind::Shadowsocks
        );
    }

    #[test]
    fn split_tunnel_uses_the_prd_tagged_form() {
        let r: SplitTunnelRule = serde_json::from_str(r#"{"type":"all_traffic"}"#).unwrap();
        assert_eq!(r, SplitTunnelRule::AllTraffic);

        let r: SplitTunnelRule =
            serde_json::from_str(r#"{"type":"exclude_apps","apps":["com.example.a"]}"#).unwrap();
        assert_eq!(
            r,
            SplitTunnelRule::ExcludeApps {
                apps: vec!["com.example.a".into()]
            }
        );
    }

    #[test]
    fn server_profile_round_trips_and_never_serialises_secret_material() {
        let p = ServerProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: AuthMethod::PrivateKey {
                private_key: SecretRef::File {
                    path: "/home/h/.ssh/id_ed25519".into(),
                },
                passphrase: None,
            },
            dns: DnsConfig {
                mode: DnsMode::Tcp,
                servers: vec![ip(1, 1, 1, 1)],
                https: None,
            },
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""source":"file""#));
        assert!(
            !json.contains("BEGIN"),
            "no key material may appear: {json}"
        );
        assert_eq!(serde_json::from_str::<ServerProfile>(&json).unwrap(), p);
    }
}
