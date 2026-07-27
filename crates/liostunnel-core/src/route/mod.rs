pub mod linux;
pub mod macos;

use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::TunnelError;

#[derive(Clone, Debug)]
pub enum RouteMode {
    /// Route only these prefixes. Cannot lock the operator out of the machine,
    /// which is why it is built first. Decision D6.
    Test {
        cidrs: Vec<IpNet>,
        capture_dns: bool,
    },
    /// Full default-route override. Lands in Task 21.
    Default,
}

#[derive(Clone, Debug)]
pub struct RoutePlan {
    pub interface: String,
    pub mode: RouteMode,
    /// Pinned via the original gateway in `Default` mode so the tunnel's own
    /// transport does not route through itself. Spec §10.
    pub server_ip: IpAddr,
    pub original_gateway: IpAddr,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl RouteCommand {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn run(&self) -> Result<(), TunnelError> {
        let out = std::process::Command::new(&self.program)
            .args(&self.args)
            .output()
            .map_err(|e| TunnelError::Route(format!("cannot execute `{}`: {e}", self.program)))?;
        if !out.status.success() {
            return Err(TunnelError::Route(format!(
                "`{} {}` failed: {}",
                self.program,
                self.args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}

/// Rejects a full-default prefix (`0.0.0.0/0` or `::/0`) in `test` mode.
/// `test` mode's entire reason for existing is that it cannot lock the
/// operator out of their own machine (Decision D6); a `/0` prefix is a literal
/// default route wearing a CIDR list's clothes, so it is refused outright.
/// Only the exact zero-length prefix is rejected, not merely a "wide" one —
/// an operator may have a legitimate reason to test against a `/1` or `/4`,
/// and second-guessing that would be a stricter policy than the safety
/// property requires. A check on the input value only: no process spawn, no
/// filesystem access, no env read, so it stays inside the pure construction
/// path.
///
/// `pub` so a caller (e.g. the CLI, parsing `--cidr` before anything with
/// side effects has run) can apply this same rule at argument-validation
/// time instead of discovering it only after a TUN device and stack thread
/// already exist. [`RouteManager::apply_commands`]/`revert_commands` call it
/// too, unconditionally — this function does not trust callers to have done
/// so already, and neither should you skip calling it here just because an
/// earlier layer might have.
pub fn reject_full_default_prefixes(cidrs: &[IpNet]) -> Result<(), TunnelError> {
    if let Some(cidr) = cidrs.iter().find(|c| c.prefix_len() == 0) {
        return Err(TunnelError::config(
            "route.test.cidrs",
            format!(
                "`{cidr}` is a full-default prefix (/0); test mode only routes explicit, bounded prefixes"
            ),
        ));
    }
    Ok(())
}

/// Command construction is pure so it can be unit-tested without privileges;
/// only [`RouteCommand::run`] needs root. Spec §10.
pub trait RouteManager: Send + Sync {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>;
    fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>;
    fn detect_gateway(&self) -> Result<IpAddr, TunnelError>;
}

pub fn platform_manager() -> Box<dyn RouteManager> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsRoutes)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(linux::LinuxRoutes)
    }
}

/// Reverts on drop, covering normal exit and unwinding panics. The other two
/// cleanup paths (signals, state file) arrive in Task 21. Spec §10.
pub struct RouteGuard {
    manager: Box<dyn RouteManager>,
    plan: RoutePlan,
    active: bool,
}

impl RouteGuard {
    pub fn apply(manager: Box<dyn RouteManager>, plan: RoutePlan) -> Result<Self, TunnelError> {
        for cmd in manager.apply_commands(&plan)? {
            cmd.run()?;
        }
        tracing::info!(interface = %plan.interface, "routes applied");
        Ok(Self {
            manager,
            plan,
            active: true,
        })
    }

    pub fn revert_now(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        match self.manager.revert_commands(&self.plan) {
            Ok(cmds) => {
                for cmd in cmds {
                    if let Err(e) = cmd.run() {
                        // Keep going: a partial revert beats an early return.
                        tracing::error!(%e, "route revert step failed");
                    }
                }
                tracing::info!("routes reverted");
            }
            Err(e) => tracing::error!(%e, "cannot build revert commands"),
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.revert_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(mode: RouteMode) -> RoutePlan {
        RoutePlan {
            interface: "utun7".into(),
            mode,
            server_ip: "198.51.100.7".parse().unwrap(),
            original_gateway: "192.168.1.1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
        }
    }

    fn test_mode(capture_dns: bool) -> RouteMode {
        RouteMode::Test {
            cidrs: vec!["93.184.216.0/24".parse().unwrap()],
            capture_dns,
        }
    }

    fn rendered(cmds: &[RouteCommand]) -> Vec<String> {
        cmds.iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    #[test]
    fn macos_test_mode_routes_only_the_listed_cidrs() {
        let cmds = macos::MacOsRoutes
            .apply_commands(&plan(test_mode(false)))
            .unwrap();
        let r = rendered(&cmds);
        assert_eq!(r.len(), 1, "no DNS capture was requested: {r:?}");
        assert_eq!(r[0], "route -n add -net 93.184.216.0/24 -interface utun7");
    }

    #[test]
    fn macos_test_mode_adds_host_routes_for_dns_when_asked() {
        let cmds = macos::MacOsRoutes
            .apply_commands(&plan(test_mode(true)))
            .unwrap();
        let r = rendered(&cmds);
        assert!(
            r.iter()
                .any(|c| c.contains("-host 1.1.1.1") && c.contains("utun7")),
            "spec §10 requires --capture-dns to route the resolvers: {r:?}"
        );
    }

    #[test]
    fn linux_test_mode_uses_ip_route() {
        let cmds = linux::LinuxRoutes
            .apply_commands(&plan(test_mode(false)))
            .unwrap();
        assert_eq!(rendered(&cmds)[0], "ip route add 93.184.216.0/24 dev utun7");
    }

    #[test]
    fn test_mode_never_touches_the_default_route() {
        for r in [
            rendered(
                &macos::MacOsRoutes
                    .apply_commands(&plan(test_mode(true)))
                    .unwrap(),
            ),
            rendered(
                &linux::LinuxRoutes
                    .apply_commands(&plan(test_mode(true)))
                    .unwrap(),
            ),
        ] {
            assert!(
                !r.iter()
                    .any(|c| c.contains("0.0.0.0/1") || c.contains("128.0.0.0/1")),
                "test mode must not install default-beating routes: {r:?}"
            );
        }
    }

    #[test]
    fn test_mode_rejects_a_full_default_prefix() {
        for full_default in ["0.0.0.0/0", "::/0"] {
            let mode = RouteMode::Test {
                cidrs: vec![full_default.parse().unwrap()],
                capture_dns: false,
            };
            let p = plan(mode);

            let mac_err = macos::MacOsRoutes.apply_commands(&p).unwrap_err();
            assert!(
                matches!(mac_err, TunnelError::Config { .. }),
                "macOS apply_commands should reject {full_default}: {mac_err:?}"
            );
            let mac_revert_err = macos::MacOsRoutes.revert_commands(&p).unwrap_err();
            assert!(
                matches!(mac_revert_err, TunnelError::Config { .. }),
                "macOS revert_commands should reject {full_default}: {mac_revert_err:?}"
            );

            let linux_err = linux::LinuxRoutes.apply_commands(&p).unwrap_err();
            assert!(
                matches!(linux_err, TunnelError::Config { .. }),
                "linux apply_commands should reject {full_default}: {linux_err:?}"
            );
            let linux_revert_err = linux::LinuxRoutes.revert_commands(&p).unwrap_err();
            assert!(
                matches!(linux_revert_err, TunnelError::Config { .. }),
                "linux revert_commands should reject {full_default}: {linux_revert_err:?}"
            );
        }
    }

    #[test]
    fn test_mode_still_allows_an_ordinary_bounded_cidr() {
        // The /0 guard must not overreach into legitimate wide-but-bounded
        // ranges (e.g. a /1 or /4 test target) — only the exact full-default
        // prefix is refused.
        assert!(
            macos::MacOsRoutes
                .apply_commands(&plan(test_mode(false)))
                .is_ok()
        );
        assert!(
            linux::LinuxRoutes
                .apply_commands(&plan(test_mode(false)))
                .is_ok()
        );
    }

    #[test]
    fn reverting_undoes_exactly_what_was_applied() {
        for mgr in [
            Box::new(macos::MacOsRoutes) as Box<dyn RouteManager>,
            Box::new(linux::LinuxRoutes),
        ] {
            let p = plan(test_mode(true));
            let applied = mgr.apply_commands(&p).unwrap();
            let reverted = mgr.revert_commands(&p).unwrap();
            assert_eq!(
                applied.len(),
                reverted.len(),
                "every applied route needs a matching revert"
            );
            assert!(rendered(&reverted).iter().all(|c| c.contains("del")));

            // Same count and "del" verb aren't enough on their own — a revert
            // that undoes the wrong target (or in the wrong order) would still
            // pass both checks above. Zip apply/revert pairwise and require
            // every non-verb token (the CIDR/host address and the interface)
            // to match exactly, so a reordered or mismatched target fails here.
            fn strip_verb(cmd: &RouteCommand) -> Vec<&str> {
                cmd.args
                    .iter()
                    .map(String::as_str)
                    .filter(|tok| !matches!(*tok, "add" | "delete" | "del"))
                    .collect()
            }

            for (a, r) in applied.iter().zip(reverted.iter()) {
                assert_eq!(
                    a.program, r.program,
                    "apply/revert pair uses a different program: {a:?} vs {r:?}"
                );
                assert_eq!(
                    strip_verb(a),
                    strip_verb(r),
                    "apply/revert pair targets do not match once the verb is ignored: {a:?} vs {r:?}"
                );
            }
        }
    }
}
