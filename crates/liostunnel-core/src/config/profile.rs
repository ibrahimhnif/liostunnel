use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::secret::{SecretRef, SecretStore};
use crate::error::TunnelError;

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

impl ServerProfile {
    /// Spec §9.2. Every failure names the offending field path.
    pub fn validate(&self, store: &dyn SecretStore) -> Result<(), TunnelError> {
        if self.host.trim().is_empty() {
            return Err(TunnelError::config("host", "must not be empty"));
        }
        if self.port == 0 {
            return Err(TunnelError::config("port", "must not be zero"));
        }
        if self.dns.servers.is_empty() {
            return Err(TunnelError::config("dns.servers", "must not be empty"));
        }
        if self.dns.mode == DnsMode::Https {
            match &self.dns.https {
                None => {
                    return Err(TunnelError::config(
                        "dns.https",
                        "required when dns.mode is `https`",
                    ));
                }
                Some(d) if d.sni.trim().is_empty() => {
                    return Err(TunnelError::config("dns.https.sni", "must not be empty"));
                }
                Some(d) if !d.path.starts_with('/') => {
                    return Err(TunnelError::config("dns.https.path", "must start with `/`"));
                }
                Some(_) => {}
            }
        }

        // Resolve every secret now, so a bad reference fails at load rather than
        // halfway through a connection attempt.
        for r in self.auth.secret_refs() {
            store.resolve(r)?;
        }
        Ok(())
    }

    /// Spec §9.3: fields that parse but are not honoured in Phase 0. The CLI
    /// prints these prominently at startup.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if self.kill_switch {
            w.push(
                "kill_switch is set but is not enforced in this Phase 0 build; \
                 traffic will not be blocked if the tunnel drops"
                    .to_string(),
            );
        }
        if self.split_tunnel != SplitTunnelRule::AllTraffic {
            w.push(
                "split_tunnel is set but is not enforced in this Phase 0 build; \
                 all routed traffic will use the tunnel"
                    .to_string(),
            );
        }
        w
    }
}

impl AuthMethod {
    pub fn secret_refs(&self) -> Vec<&SecretRef> {
        match self {
            AuthMethod::Password { password } => vec![password],
            AuthMethod::PrivateKey {
                private_key,
                passphrase,
            } => {
                let mut v = vec![private_key];
                v.extend(passphrase.iter());
                v
            }
            AuthMethod::PresharedKey { private_key, .. } => vec![private_key],
        }
    }
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

    use crate::config::secret::{FileSecretStore, SecretStore};

    fn valid_profile() -> ServerProfile {
        ServerProfile {
            id: uuid::Uuid::nil(),
            name: "lab".into(),
            protocol: ProtocolKind::Ssh,
            host: "198.51.100.7".into(),
            port: 22,
            auth: AuthMethod::Password {
                password: SecretRef::File {
                    path: secret_file("valid", "pw"),
                },
            },
            dns: DnsConfig {
                mode: DnsMode::Tcp,
                servers: vec![ip(1, 1, 1, 1)],
                https: None,
            },
            split_tunnel: SplitTunnelRule::AllTraffic,
            kill_switch: false,
        }
    }

    /// A real 0600 file rather than an env var. `std::env::set_var` is `unsafe`
    /// in edition 2024 because concurrent set/get is UB, and cargo runs the
    /// tests in one binary across threads — several of these tests share a
    /// helper, so env vars would be a genuine data race.
    fn secret_file(tag: &str, body: &str) -> std::path::PathBuf {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let dir = std::env::temp_dir().join(format!("lios-pv-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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

    fn store() -> impl SecretStore {
        FileSecretStore
    }

    #[test]
    fn a_valid_profile_passes() {
        valid_profile().validate(&store()).unwrap();
    }

    #[test]
    fn empty_host_is_rejected() {
        let mut p = valid_profile();
        p.host = String::new();
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("host"), "{e}");
    }

    #[test]
    fn port_zero_is_rejected() {
        let mut p = valid_profile();
        p.port = 0;
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("port"), "{e}");
    }

    #[test]
    fn empty_dns_servers_are_rejected() {
        let mut p = valid_profile();
        p.dns.servers.clear();
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("dns.servers"), "{e}");
    }

    #[test]
    fn https_mode_without_a_doh_block_is_rejected() {
        let mut p = valid_profile();
        p.dns.mode = DnsMode::Https;
        p.dns.https = None;
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("dns.https"), "{e}");
    }

    #[test]
    fn an_unresolvable_secret_is_rejected_at_validation_not_at_connect() {
        let mut p = valid_profile();
        p.auth = AuthMethod::Password {
            password: SecretRef::File {
                path: "/nonexistent/lios/secret".into(),
            },
        };
        let e = p.validate(&store()).unwrap_err().to_string();
        assert!(e.contains("/nonexistent/lios/secret"), "{e}");
    }

    #[test]
    fn kill_switch_produces_an_unenforced_warning() {
        let mut p = valid_profile();
        p.kill_switch = true;
        let w = p.warnings();
        assert!(
            w.iter()
                .any(|m| m.contains("kill_switch") && m.contains("not enforced")),
            "spec §9.3 requires a loud warning, got {w:?}"
        );
    }

    #[test]
    fn non_default_split_tunnel_produces_an_unenforced_warning() {
        let mut p = valid_profile();
        p.split_tunnel = SplitTunnelRule::ExcludeApps {
            apps: vec!["a".into()],
        };
        assert!(p.warnings().iter().any(|m| m.contains("split_tunnel")));
    }

    #[test]
    fn a_clean_profile_warns_about_nothing() {
        assert!(valid_profile().warnings().is_empty());
    }
}
