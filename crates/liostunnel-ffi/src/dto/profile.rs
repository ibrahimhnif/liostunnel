use liostunnel_core::config::profile::{
    AuthMethod, DnsConfig, DnsMode, DohConfig, ProtocolKind, ServerProfile, SplitTunnelRule,
};
use liostunnel_core::config::secret::SecretRef;

/// A profile in the shape the UI wants: flat, and made of types
/// `flutter_rust_bridge` models without persuasion.
///
/// The FFI crate owns this rather than exporting `ServerProfile` directly.
/// The core type holds a `Uuid`, `IpAddr`s and nested tagged enums; binding
/// Dart to it would let any core change break codegen, and would start
/// shaping the core around what FRB finds convenient (spec §9, D7).
///
/// **It describes where secrets live and never what they are.** This value
/// crosses into Dart, gets rendered on screen, and its `profile_json` reaches
/// the helper over a socket.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileDto {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    /// `"password"`, `"private_key"`, `"preshared_key"` or `"shadowsocks"`.
    pub auth_kind: String,
    /// Where the material lives — `"file:/path"` or `"env:NAME"` — never the
    /// material itself.
    pub auth_secret_source: String,
    /// Present only for `private_key` with a passphrase, and again only ever
    /// a location.
    pub auth_passphrase_source: Option<String>,
    /// Public by definition for `preshared_key`; not a secret.
    pub peer_public_key: Option<String>,
    pub dns_mode: String,
    pub dns_servers: Vec<String>,
    pub doh_sni: Option<String>,
    pub doh_path: Option<String>,
    pub split_tunnel: String,
    pub split_tunnel_apps: Vec<String>,
    pub kill_switch: bool,
}

/// Names the field that failed, never its value.
///
/// Phase 0 shipped the opposite in `profile_io::load`, where a misplaced
/// secret came back inside the error text. A field name is a fixed string
/// chosen here; a field value is whatever the caller supplied.
#[derive(Debug, thiserror::Error)]
#[error("profile field `{field}` is not valid")]
pub struct ProfileDtoError {
    pub field: &'static str,
}

impl ProfileDtoError {
    fn at(field: &'static str) -> Self {
        Self { field }
    }
}

/// Renders where a secret lives, never what it is.
fn describe(r: &SecretRef) -> String {
    match r {
        SecretRef::File { path } => format!("file:{}", path.display()),
        SecretRef::Env { var } => format!("env:{var}"),
    }
}

/// Inverse of [`describe`].
fn undescribe(s: &str, field: &'static str) -> Result<SecretRef, ProfileDtoError> {
    if let Some(p) = s.strip_prefix("file:") {
        Ok(SecretRef::File { path: p.into() })
    } else if let Some(v) = s.strip_prefix("env:") {
        Ok(SecretRef::Env { var: v.into() })
    } else {
        Err(ProfileDtoError::at(field))
    }
}

impl From<ServerProfile> for ProfileDto {
    fn from(p: ServerProfile) -> Self {
        let (auth_kind, secret, passphrase, peer_public_key) = match &p.auth {
            AuthMethod::Password { password } => ("password", describe(password), None, None),
            AuthMethod::PrivateKey {
                private_key,
                passphrase,
            } => (
                "private_key",
                describe(private_key),
                passphrase.as_ref().map(describe),
                None,
            ),
            AuthMethod::PresharedKey {
                private_key,
                peer_public_key,
            } => (
                "preshared_key",
                describe(private_key),
                None,
                Some(peer_public_key.clone()),
            ),
            // The cipher name (`method`) has nowhere to land in this DTO yet —
            // that lands with the Phase 1b config surface (cipher field on
            // `ProfileDto`). Until then this loses the cipher on the way to
            // Dart; it does not lose or expose the secret.
            AuthMethod::Shadowsocks { password, .. } => {
                ("shadowsocks", describe(password), None, None)
            }
        };

        let (split_tunnel, split_tunnel_apps) = match &p.split_tunnel {
            SplitTunnelRule::AllTraffic => ("all_traffic", vec![]),
            SplitTunnelRule::ExcludeApps { apps } => ("exclude_apps", apps.clone()),
            SplitTunnelRule::IncludeOnly { apps } => ("include_only", apps.clone()),
        };

        Self {
            id: p.id.to_string(),
            name: p.name,
            protocol: match p.protocol {
                ProtocolKind::Ssh => "ssh",
                ProtocolKind::WireGuard => "wireguard",
                ProtocolKind::Shadowsocks => "shadowsocks",
            }
            .into(),
            host: p.host,
            port: p.port,
            auth_kind: auth_kind.into(),
            auth_secret_source: secret,
            auth_passphrase_source: passphrase,
            peer_public_key,
            dns_mode: match p.dns.mode {
                DnsMode::Tcp => "tcp",
                DnsMode::Https => "https",
            }
            .into(),
            dns_servers: p.dns.servers.iter().map(|s| s.to_string()).collect(),
            doh_sni: p.dns.https.as_ref().map(|d| d.sni.clone()),
            doh_path: p.dns.https.as_ref().map(|d| d.path.clone()),
            split_tunnel: split_tunnel.into(),
            split_tunnel_apps,
            kill_switch: p.kill_switch,
        }
    }
}

impl TryFrom<ProfileDto> for ServerProfile {
    type Error = ProfileDtoError;

    fn try_from(d: ProfileDto) -> Result<Self, Self::Error> {
        let secret = undescribe(&d.auth_secret_source, "auth_secret_source")?;
        let auth = match d.auth_kind.as_str() {
            "password" => AuthMethod::Password { password: secret },
            "private_key" => AuthMethod::PrivateKey {
                private_key: secret,
                passphrase: d
                    .auth_passphrase_source
                    .as_deref()
                    .map(|s| undescribe(s, "auth_passphrase_source"))
                    .transpose()?,
            },
            "preshared_key" => AuthMethod::PresharedKey {
                private_key: secret,
                peer_public_key: d
                    .peer_public_key
                    .ok_or_else(|| ProfileDtoError::at("peer_public_key"))?,
            },
            _ => return Err(ProfileDtoError::at("auth_kind")),
        };

        let https = match (d.doh_sni, d.doh_path) {
            (Some(sni), Some(path)) => Some(DohConfig { sni, path }),
            (None, None) => None,
            _ => return Err(ProfileDtoError::at("doh_sni/doh_path")),
        };

        Ok(Self {
            id: d.id.parse().map_err(|_| ProfileDtoError::at("id"))?,
            name: d.name,
            protocol: match d.protocol.as_str() {
                "ssh" => ProtocolKind::Ssh,
                "wireguard" => ProtocolKind::WireGuard,
                "shadowsocks" => ProtocolKind::Shadowsocks,
                _ => return Err(ProfileDtoError::at("protocol")),
            },
            host: d.host,
            port: d.port,
            auth,
            dns: DnsConfig {
                mode: match d.dns_mode.as_str() {
                    "tcp" => DnsMode::Tcp,
                    "https" => DnsMode::Https,
                    _ => return Err(ProfileDtoError::at("dns_mode")),
                },
                servers: d
                    .dns_servers
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProfileDtoError::at("dns_servers"))?,
                https,
            },
            split_tunnel: match d.split_tunnel.as_str() {
                "all_traffic" => SplitTunnelRule::AllTraffic,
                "exclude_apps" => SplitTunnelRule::ExcludeApps {
                    apps: d.split_tunnel_apps,
                },
                "include_only" => SplitTunnelRule::IncludeOnly {
                    apps: d.split_tunnel_apps,
                },
                _ => return Err(ProfileDtoError::at("split_tunnel")),
            },
            kill_switch: d.kill_switch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Home VPS",
        "protocol":"ssh","host":"198.51.100.7","port":22,
        "auth":{"type":"password","password":{"source":"env","var":"PW"}},
        "dns":["1.1.1.1","1.0.0.1"],
        "split_tunnel":{"type":"all_traffic"},"kill_switch":false}"#;

    const KEYFILE: &str = r#"{
        "id":"b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f","name":"Key VPS",
        "protocol":"ssh","host":"example.test","port":2222,
        "auth":{"type":"private_key","private_key":{"source":"file","path":"/home/u/.ssh/id_ed25519"},
                "passphrase":{"source":"env","var":"PASS"}},
        "dns":{"mode":"https","servers":["1.1.1.1"],
               "https":{"sni":"cloudflare-dns.com","path":"/dns-query"}},
        "split_tunnel":{"type":"all_traffic"},"kill_switch":true}"#;

    #[test]
    fn a_core_profile_converts_to_a_flat_dto() {
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let dto = ProfileDto::from(core);
        assert_eq!(dto.name, "Home VPS");
        assert_eq!(dto.host, "198.51.100.7");
        assert_eq!(dto.port, 22);
        assert_eq!(dto.protocol, "ssh");
        assert_eq!(dto.dns_servers, vec!["1.1.1.1", "1.0.0.1"]);
        assert_eq!(dto.dns_mode, "tcp");
        // UUIDs and IPs cross as strings so FRB never has to model them.
        assert_eq!(dto.id, "b6f1a0de-1f2c-4c3a-9b7e-0a1b2c3d4e2f");
    }

    #[test]
    fn the_dto_round_trips_back_to_an_equal_core_profile() {
        for doc in [SAMPLE, KEYFILE] {
            let core: ServerProfile = serde_json::from_str(doc).unwrap();
            let back = ServerProfile::try_from(ProfileDto::from(core.clone())).unwrap();
            assert_eq!(back, core, "round trip lost something in {doc}");
        }
    }

    #[test]
    fn the_dto_never_carries_secret_material() {
        // The DTO crosses into Dart and its contents reach the socket. It may
        // describe where a secret lives; it must never contain one.
        let core: ServerProfile = serde_json::from_str(KEYFILE).unwrap();
        let dto = ProfileDto::from(core);
        let rendered = format!("{dto:?}");
        for forbidden in ["BEGIN", "PRIVATE KEY", "hunter2"] {
            assert!(
                !rendered.contains(forbidden),
                "secret-shaped content in DTO: {rendered}"
            );
        }
        // It records the *kind* of auth and where the material lives, no more.
        assert_eq!(dto.auth_kind, "private_key");
        assert_eq!(dto.auth_secret_source, "file:/home/u/.ssh/id_ed25519");
    }

    #[test]
    fn an_env_secret_is_described_by_its_variable_name_not_its_value() {
        // Reading the variable here would put a live secret in a struct whose
        // whole job is to be displayed.
        unsafe { std::env::set_var("PW", "hunter2") };
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let dto = ProfileDto::from(core);
        assert_eq!(dto.auth_secret_source, "env:PW");
        assert!(!format!("{dto:?}").contains("hunter2"));
        unsafe { std::env::remove_var("PW") };
    }

    #[test]
    fn exporting_a_parsed_profile_reproduces_an_equal_document() {
        // Portability means a profile can leave the app and come back
        // unchanged. Compared as parsed values, not text: key order and
        // whitespace are not part of the contract.
        for doc in [SAMPLE, KEYFILE] {
            let dto = crate::api::config::parse_profile(doc.to_string()).unwrap();
            let out = crate::api::config::export_profile(dto).unwrap();
            let a: ServerProfile = serde_json::from_str(doc).unwrap();
            let b: ServerProfile = serde_json::from_str(&out).unwrap();
            assert_eq!(a, b, "export is not the inverse of parse for {doc}");
        }
    }

    #[test]
    fn an_exported_profile_carries_no_secret_material() {
        unsafe { std::env::set_var("PASS", "hunter2") };
        let dto = crate::api::config::parse_profile(KEYFILE.to_string()).unwrap();
        let out = crate::api::config::export_profile(dto).unwrap();
        // It records the source of the secret, not the secret.
        assert!(out.contains("id_ed25519"), "got {out}");
        assert!(
            !out.contains("hunter2"),
            "exported document contains a secret"
        );
        assert!(
            !out.contains("BEGIN"),
            "exported document contains key material"
        );
        unsafe { std::env::remove_var("PASS") };
    }

    #[test]
    fn parse_profile_rejects_a_bad_document_without_echoing_it() {
        // Same rule as everywhere else, and the marker sits where serde_json
        // actually echoes — an unknown enum tag, not a value.
        let e = crate::api::config::parse_profile(
            r#"{"protocol":"SECRET-VALUE-HERE","host":"h","port":1}"#.into(),
        )
        .unwrap_err();
        assert!(!e.contains("SECRET-VALUE-HERE"), "error echoed input: {e}");
    }

    #[test]
    fn a_malformed_uuid_is_rejected_on_the_way_back() {
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let mut dto = ProfileDto::from(core);
        dto.id = "not-a-uuid".into();
        assert!(ServerProfile::try_from(dto).is_err());
    }

    #[test]
    fn a_malformed_ip_is_rejected_on_the_way_back() {
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let mut dto = ProfileDto::from(core);
        dto.dns_servers = vec!["999.999.999.999".into()];
        assert!(ServerProfile::try_from(dto).is_err());
    }

    #[test]
    fn a_conversion_error_names_the_field_but_not_its_value() {
        // Phase 0 shipped the opposite in profile_io::load, where a misplaced
        // secret came back inside the error text. A field name is a fixed
        // string; a field value is attacker- or user-controlled.
        let core: ServerProfile = serde_json::from_str(SAMPLE).unwrap();
        let mut dto = ProfileDto::from(core);
        dto.id = "SECRET-VALUE-HERE".into();
        let e = ServerProfile::try_from(dto).unwrap_err();
        let text = format!("{e}");
        assert!(text.contains("id"), "error must name the field: {text}");
        assert!(
            !text.contains("SECRET-VALUE-HERE"),
            "error echoed the value: {text}"
        );
        assert!(
            !format!("{e:?}").contains("SECRET-VALUE-HERE"),
            "Debug echoed the value"
        );
    }
}
