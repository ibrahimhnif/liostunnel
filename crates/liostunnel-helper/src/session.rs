use std::net::Ipv4Addr;

use liostunnel_core::config::profile::ServerProfile;
use liostunnel_core::config::secret::SecretRef;
use liostunnel_core::route::{RouteMode, reject_full_default_prefixes};
use liostunnel_ffi::dto::protocol::ConnectParams;

use crate::auth::{self, AuthError};

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Deliberately carries nothing. serde_json's Display quotes keys and
    /// enum tags from the offending input, and that input is a profile.
    #[error("profile is not valid")]
    BadProfile,
    #[error("{0}")]
    BadRouteMode(String),
    #[error("tun address is not a valid IPv4 address")]
    BadTunAddress,
    #[error("env-var secrets are not available through the helper")]
    EnvSecretNotAllowed,
    #[error("{0}")]
    SecretNotPermitted(AuthError),
    #[error("{0}")]
    Tunnel(#[from] liostunnel_core::TunnelError),
}

/// A connect request that has passed every check decidable without privilege.
///
/// Holding one of these is the evidence that `authorize_params` ran and
/// approved: `start` takes this rather than raw `ConnectParams`, so there is
/// no way to reach the privileged path without going through the gate.
pub struct Authorized {
    pub profile: ServerProfile,
    pub user: String,
    pub route_mode: RouteMode,
    pub tun_address: Ipv4Addr,
}

/// Hand-written rather than derived. A derived impl would render the whole
/// profile — including the paths and variable names its `SecretRef`s point
/// at — into anything that formats this with `{:?}`, and the helper's log is
/// the most sensitive one in the system. Names what it is, not what it holds.
impl std::fmt::Debug for Authorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorized")
            .field("host", &self.profile.host)
            .field("port", &self.profile.port)
            .field("tun_address", &self.tun_address)
            .finish_non_exhaustive()
    }
}

pub struct Tunnel {/* engine handles land here in Step 5 */}

impl Tunnel {
    /// Everything that must be checked *before* any privileged action.
    ///
    /// Split out from `start` deliberately: it is pure, so the escalation
    /// guard is testable without root, a TUN device, or a routing table.
    pub fn authorize_params(
        params: &ConnectParams,
        caller_uid: u32,
    ) -> Result<Authorized, StartError> {
        // Note the discarded error: serde_json's Display quotes keys and enum
        // tags from the input, and the input is a profile.
        let profile: ServerProfile =
            serde_json::from_str(&params.profile_json).map_err(|_| StartError::BadProfile)?;

        let route_mode = parse_route_mode(&params.route_mode, &params.cidrs, params.capture_dns)?;

        let tun_address: Ipv4Addr = params
            .tun_address
            .parse()
            .map_err(|_| StartError::BadTunAddress)?;

        // THE ESCALATION GATE. The helper runs as root and could read any of
        // these; this is what stops the caller borrowing that power.
        for r in profile.auth.secret_refs() {
            match r {
                SecretRef::File { path } => auth::secret_readable_by(path, caller_uid)
                    .map_err(StartError::SecretNotPermitted)?,
                // Refused outright rather than checked. SecretRef::Env
                // resolves against the *process* environment, and this
                // process is root — so an env ref can only ever name
                // something that was never the caller's, and the value would
                // leave as a credential to a server they chose. There is no
                // ownership test that makes it safe, because the caller
                // cannot put anything into the helper's environment. Env
                // secrets only make sense where the process IS the user,
                // which is the CLI, not the daemon.
                SecretRef::Env { .. } => return Err(StartError::EnvSecretNotAllowed),
            }
        }

        Ok(Authorized {
            profile,
            user: params.user.clone(),
            route_mode,
            tun_address,
        })
    }
}

/// Maps the wire's route-mode strings to a [`RouteMode`], purely.
///
/// Mirrors `liostunnel-cli`'s `parse_route_mode`. Duplicated rather than
/// shared because the CLI is a binary crate the helper must not depend on,
/// and the plan forbids modifying it. The checks it performs — especially
/// `reject_full_default_prefixes` — live in core, so the rule itself is not
/// duplicated, only the string mapping.
fn parse_route_mode(
    route_mode: &str,
    cidrs: &[String],
    capture_dns: bool,
) -> Result<RouteMode, StartError> {
    match route_mode {
        "test" => {
            let parsed = cidrs
                .iter()
                .map(|c| {
                    c.parse::<ipnet::IpNet>()
                        .map_err(|_| StartError::BadRouteMode(format!("cidr is not valid: {c}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parsed.is_empty() {
                return Err(StartError::BadRouteMode(
                    "test route mode needs at least one prefix".into(),
                ));
            }
            reject_full_default_prefixes(&parsed)?;
            Ok(RouteMode::Test {
                cidrs: parsed,
                capture_dns,
            })
        }
        "default" => Ok(RouteMode::Default),
        other => Err(StartError::BadRouteMode(format!(
            "expected `test` or `default`, got `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use liostunnel_ffi::dto::protocol::ConnectParams;

    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lios-sess-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A 0600 file owned by this process, standing in for a private key.
    fn owned_secret(dir: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("key");
        std::fs::write(&p, b"not really a key").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    fn params_with_file_secret(path: &std::path::Path) -> ConnectParams {
        ConnectParams {
            profile_json: format!(
                r#"{{"id":"00000000-0000-0000-0000-000000000000","name":"t",
                    "protocol":"ssh","host":"127.0.0.1","port":22,
                    "auth":{{"type":"password","password":{{"source":"file","path":"{}"}}}},
                    "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
                    "kill_switch":false}}"#,
                path.display()
            ),
            user: "someone".into(),
            route_mode: "test".into(),
            cidrs: vec!["93.184.216.0/24".into()],
            capture_dns: false,
            tun_address: "10.90.0.1".into(),
        }
    }

    fn params_with_env_secret(var: &str) -> ConnectParams {
        ConnectParams {
            profile_json: format!(
                r#"{{"id":"00000000-0000-0000-0000-000000000000","name":"t",
                    "protocol":"ssh","host":"127.0.0.1","port":22,
                    "auth":{{"type":"password","password":{{"source":"env","var":"{var}"}}}},
                    "dns":["1.1.1.1"],"split_tunnel":{{"type":"all_traffic"}},
                    "kill_switch":false}}"#
            ),
            user: "someone".into(),
            route_mode: "test".into(),
            cidrs: vec!["93.184.216.0/24".into()],
            capture_dns: false,
            tun_address: "10.90.0.1".into(),
        }
    }

    #[test]
    fn a_secret_the_caller_does_not_own_is_refused() {
        // THE ESCALATION, at the layer that matters: refused before a TUN
        // device exists, before a route is installed, and before any file is
        // read.
        //
        // The discriminator is a mismatched uid argument, not a root-owned
        // system file. /etc/shadow is absent on macOS, "ours" in a root
        // container, and mode 0640 on Debian — every one of which makes the
        // test vacuous exactly where it must not be. Task 3 learned this the
        // expensive way.
        let d = scratch("foreign-secret");
        let p = owned_secret(&d);
        let err = Tunnel::authorize_params(&params_with_file_secret(&p), me().wrapping_add(1))
            .expect_err("a secret the caller does not own must be refused");
        assert!(
            matches!(err, StartError::SecretNotPermitted(_)),
            "got {err:?}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_secret_the_caller_owns_is_permitted() {
        let d = scratch("own-secret");
        let p = owned_secret(&d);
        Tunnel::authorize_params(&params_with_file_secret(&p), me())
            .expect("our own 0600 file must be accepted");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_env_var_secret_is_refused_outright() {
        // SecretRef::Env resolves against the *process* environment, and this
        // process is root. A caller naming an env var would be reaching into
        // root's environment for something that was never theirs, and the
        // result would leave as an SSH password to a server they chose.
        //
        // There is no ownership check that makes this safe, because the
        // caller cannot put anything into the helper's environment in the
        // first place. Env secrets are a CLI affordance — they only make
        // sense when the process IS the user — so the daemon refuses them.
        let err = Tunnel::authorize_params(&params_with_env_secret("SSH_AUTH_SOCK"), me())
            .expect_err("an env-var secret must be refused by the daemon");
        assert!(
            matches!(err, StartError::EnvSecretNotAllowed),
            "got {err:?}"
        );
    }

    #[test]
    fn a_profile_that_does_not_parse_is_refused_without_echoing_it() {
        // The marker sits where serde_json actually echoes — an unknown enum
        // tag. Put it in a value and the test passes against an
        // implementation that leaks, proving nothing (Task 5's lesson).
        let mut p = params_with_file_secret(std::path::Path::new("/tmp/whatever"));
        p.profile_json = r#"{"protocol":"SECRET-VALUE-HERE","host":"h","port":22}"#.into();
        let err = Tunnel::authorize_params(&p, me()).expect_err("must not parse");
        let text = format!("{err}");
        assert!(
            !text.contains("SECRET-VALUE-HERE"),
            "error echoed input: {text}"
        );
        let debug = format!("{err:?}");
        assert!(
            !debug.contains("SECRET-VALUE-HERE"),
            "Debug echoed input: {debug}"
        );
    }

    #[test]
    fn an_unknown_route_mode_is_refused() {
        let d = scratch("bad-mode");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.route_mode = "wide-open".into();
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn test_mode_without_any_cidr_is_refused() {
        // Otherwise `test` mode installs nothing and the tunnel silently
        // carries no traffic at all.
        let d = scratch("no-cidr");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.cidrs = vec![];
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_full_default_prefix_in_test_mode_is_refused() {
        // Phase 0's route layer refuses 0.0.0.0/0 as a `test` CIDR because it
        // would silently become a default route without the split-default
        // machinery that makes one reversible. The helper must not offer a
        // way around that check.
        let d = scratch("full-default");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.cidrs = vec!["0.0.0.0/0".into()];
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_malformed_tun_address_is_refused() {
        let d = scratch("bad-tun");
        let p = owned_secret(&d);
        let mut params = params_with_file_secret(&p);
        params.tun_address = "not-an-address".into();
        assert!(Tunnel::authorize_params(&params, me()).is_err());
        std::fs::remove_dir_all(&d).ok();
    }
}
