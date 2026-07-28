pub mod linux;
pub mod macos;
pub mod state;

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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

    fn default_plan() -> RoutePlan {
        plan(RouteMode::Default)
    }

    #[test]
    fn default_mode_beats_the_default_route_without_deleting_it() {
        for (name, cmds) in [
            (
                "macos",
                macos::MacOsRoutes.apply_commands(&default_plan()).unwrap(),
            ),
            (
                "linux",
                linux::LinuxRoutes.apply_commands(&default_plan()).unwrap(),
            ),
        ] {
            let r = rendered(&cmds);
            assert!(r.iter().any(|c| c.contains("0.0.0.0/1")), "{name}: {r:?}");
            assert!(r.iter().any(|c| c.contains("128.0.0.0/1")), "{name}: {r:?}");
            assert_no_default_route_deletion(name, &r);
        }
    }

    /// The apply arm is the obvious place to look for a stray `delete default`,
    /// and it is the less dangerous one. The revert arm runs on every clean
    /// exit, every unwinding panic, and every crash recovery — so a deletion
    /// there strips the operator's real default route constantly rather than
    /// once. Both arms, both platforms, both route modes are checked.
    fn assert_no_default_route_deletion(name: &str, rendered: &[String]) {
        for c in rendered {
            assert!(
                !(c.contains("delete default") || c.contains("del default")),
                "{name} must never remove the real default route: {c}"
            );
            // `route delete 0.0.0.0/0` / `ip route del 0.0.0.0/0` are the same
            // act spelled as a prefix. The split-default technique works by
            // being *more specific* than 0.0.0.0/0 and leaving it untouched,
            // so naming it at all in a delete is a bug.
            assert!(
                !((c.contains("delete") || c.contains(" del "))
                    && (c.contains("0.0.0.0/0") || c.contains("::/0"))),
                "{name} must never remove the real default route: {c}"
            );
        }
    }

    #[test]
    fn reverting_default_mode_never_removes_the_real_default_route() {
        for (name, cmds) in [
            (
                "macos",
                macos::MacOsRoutes.revert_commands(&default_plan()).unwrap(),
            ),
            (
                "linux",
                linux::LinuxRoutes.revert_commands(&default_plan()).unwrap(),
            ),
        ] {
            let r = rendered(&cmds);
            // The split-default routes must come back out...
            assert!(r.iter().any(|c| c.contains("0.0.0.0/1")), "{name}: {r:?}");
            assert!(r.iter().any(|c| c.contains("128.0.0.0/1")), "{name}: {r:?}");
            // ...and nothing may touch the real default route on the way.
            assert_no_default_route_deletion(name, &r);
        }
    }

    #[test]
    fn reverting_test_mode_never_removes_the_real_default_route() {
        for (name, cmds) in [
            (
                "macos",
                macos::MacOsRoutes
                    .revert_commands(&plan(test_mode(true)))
                    .unwrap(),
            ),
            (
                "linux",
                linux::LinuxRoutes
                    .revert_commands(&plan(test_mode(true)))
                    .unwrap(),
            ),
        ] {
            assert_no_default_route_deletion(name, &rendered(&cmds));
        }
    }

    #[test]
    fn default_mode_pins_the_server_via_the_original_gateway() {
        // Without this the tunnel's own transport routes through itself and
        // the connection deadlocks. Spec §10.
        for (name, cmds) in [
            (
                "macos",
                macos::MacOsRoutes.apply_commands(&default_plan()).unwrap(),
            ),
            (
                "linux",
                linux::LinuxRoutes.apply_commands(&default_plan()).unwrap(),
            ),
        ] {
            let r = rendered(&cmds);
            assert!(
                r.iter()
                    .any(|c| c.contains("198.51.100.7") && c.contains("192.168.1.1")),
                "{name} must pin the server route via the original gateway: {r:?}"
            );
        }
    }

    #[test]
    fn default_mode_overrides_dns() {
        let r = rendered(&macos::MacOsRoutes.apply_commands(&default_plan()).unwrap());
        assert!(r.iter().any(|c| c.starts_with("networksetup")), "{r:?}");
    }

    #[test]
    fn the_server_pin_is_installed_before_the_default_beating_routes() {
        // Ordering matters: install 0/1 first and the SSH connection can drop
        // before its own pin exists.
        let cmds = rendered(&linux::LinuxRoutes.apply_commands(&default_plan()).unwrap());
        assert_pin_precedes_both_halves("linux", &cmds);
    }

    /// Checking the pin against only `0.0.0.0/1` leaves the other half
    /// unconstrained: an ordering of `[128.0.0.0/1, pin, 0.0.0.0/1]` would pass
    /// while still installing a default-beating route before the escape route
    /// exists. Both halves must come after the pin.
    fn assert_pin_precedes_both_halves(name: &str, cmds: &[String]) {
        let pin = cmds
            .iter()
            .position(|c| c.contains("198.51.100.7"))
            .unwrap_or_else(|| panic!("{name}: no server pin found: {cmds:?}"));
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let at = cmds
                .iter()
                .position(|c| c.contains(half))
                .unwrap_or_else(|| panic!("{name}: no {half} route found: {cmds:?}"));
            assert!(pin < at, "{name}: server pin must precede {half}: {cmds:?}");
        }
    }

    #[test]
    fn macos_also_installs_the_server_pin_before_the_default_beating_routes() {
        // The brief's ordering test only exercises Linux; the same property
        // (deadlock avoidance, spec §10) is just as load-bearing on macOS, so
        // it needs the same regression coverage on that platform too.
        let cmds = rendered(&macos::MacOsRoutes.apply_commands(&default_plan()).unwrap());
        assert_pin_precedes_both_halves("macos", &cmds);
    }

    #[test]
    fn default_modes_routing_commands_are_symmetric_between_apply_and_revert() {
        // Unlike `test` mode, `Default` mode's revert order is not a literal
        // reverse of its apply order (the pin is installed first but deleted
        // last), so this compares destinations as a set rather than zipping
        // apply/revert positionally or comparing full argument lists.
        //
        // Full argument-list comparison (as `reverting_undoes_exactly_what_was_applied`
        // does for `test` mode) is deliberately *not* used here: macOS's
        // `route delete -host <dest> <gateway>` requires the gateway
        // positionally even to delete, while Linux's `ip route del <dest>`
        // does not need (or take) a `via` clause to identify the same
        // route -- both are correct, idiomatic uses of their platform's own
        // command, not an inconsistency to paper over. Comparing destinations
        // only means this test asserts the property that actually matters --
        // every network/host we add is removed, nothing extra is removed --
        // without assuming a syntax both platforms don't share.
        fn destination(cmd: &RouteCommand) -> Option<String> {
            if cmd.program == "networksetup" {
                return None;
            }
            cmd.args
                .iter()
                .find(|tok| tok.contains('/') || tok.parse::<IpAddr>().is_ok())
                .cloned()
        }

        for (name, mgr) in [
            (
                "macos",
                Box::new(macos::MacOsRoutes) as Box<dyn RouteManager>,
            ),
            ("linux", Box::new(linux::LinuxRoutes)),
        ] {
            let p = default_plan();
            let applied = mgr.apply_commands(&p).unwrap();
            let reverted = mgr.revert_commands(&p).unwrap();

            let mut applied_dests: Vec<_> = applied.iter().filter_map(destination).collect();
            let mut reverted_dests: Vec<_> = reverted.iter().filter_map(destination).collect();
            applied_dests.sort();
            reverted_dests.sort();
            assert_eq!(
                applied_dests, reverted_dests,
                "{name}: every destination Default mode applies must have exactly one \
                 matching revert, and vice versa: applied={applied:?} reverted={reverted:?}"
            );

            // Matching destinations alone would pass if the revert arm re-issued
            // `add` for every route it was supposed to remove — the routes would
            // then survive teardown, wedging the operator's network for exactly
            // as long as the interface outlives the process.
            for cmd in &reverted {
                if cmd.program == "networksetup" {
                    continue;
                }
                assert!(
                    cmd.args.iter().any(|a| a == "delete" || a == "del"),
                    "{name}: every revert command must actually delete: {cmd:?}"
                );
            }
            for cmd in &applied {
                if cmd.program == "networksetup" {
                    continue;
                }
                assert!(
                    cmd.args.iter().any(|a| a == "add"),
                    "{name}: every apply command must actually add: {cmd:?}"
                );
            }
        }
    }

    // Not asserted above: the macOS DNS override's revert
    // (`networksetup -setdnsservers Wi-Fi Empty`) does not restore whatever
    // manual DNS servers the operator had configured before `connect` ran --
    // it clears back to "automatic" (DHCP-assigned) instead. For an operator
    // on the common case (no manual DNS override already in place) this is a
    // no-op difference. For one who *did* have a manual override, reverting
    // does not restore it exactly, unlike every routing command in this
    // module. Capturing and restoring the pre-existing DNS configuration
    // would need `apply_commands` to read current system state, which would
    // break the "construction stays pure, no fs/process access" contract
    // Task 16 established -- so this is left as a known Phase 0 limitation
    // rather than "fixed" here.
}
