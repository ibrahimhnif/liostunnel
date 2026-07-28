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
    /// Whether this host has a working IPv6 stack at all. Set once, before
    /// construction, via [`RouteManager::ipv6_available`] (impure -- it opens
    /// a socket) -- `apply_commands`/`revert_commands` only ever read this
    /// flag, never probe for it themselves, exactly like `server_ip`,
    /// `original_gateway`, and `dns_servers` above. Gates whether `Default`
    /// mode's IPv6 split-default (`::/1` + `8000::/1`) is emitted at all: a
    /// route command that fails on a v6-less host would abort the apply
    /// mid-way and strand whatever was already installed, so a host with no
    /// IPv6 support gets no IPv6 commands rather than a failing one.
    pub ipv6_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RouteCommand {
    pub program: String,
    pub args: Vec<String>,
    /// Content piped to the child process's stdin before it runs. `None` for
    /// every ordinary route/DNS command, which take no input. The only user
    /// today is Linux `Default` mode's DNS override (Gap 1): the replacement
    /// `/etc/resolv.conf` body is textual and small (a handful of
    /// `nameserver` lines), so a plain `String` -- not raw bytes, and not a
    /// filesystem path -- keeps the value trivially part of the pure
    /// construction path and trivially serializable into the crash-recovery
    /// state file (`route/state.rs`) alongside `program`/`args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
}

impl RouteCommand {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: None,
        }
    }

    /// Like [`Self::new`], but pipes `stdin` to the child process rather than
    /// leaving it closed. Used to install new file content (e.g. a
    /// replacement `/etc/resolv.conf`) without a shell: the destination path
    /// is a literal argument, never interpolated, and the content travels
    /// over a pipe rather than through anything a shell would parse.
    pub fn with_stdin(program: &str, args: &[&str], stdin: impl Into<String>) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: Some(stdin.into()),
        }
    }

    pub fn run(&self) -> Result<(), TunnelError> {
        use std::io::Write;
        use std::process::Stdio;

        let mut command = std::process::Command::new(&self.program);
        command.args(&self.args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdin(if self.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });

        let mut child = command
            .spawn()
            .map_err(|e| TunnelError::Route(format!("cannot execute `{}`: {e}", self.program)))?;

        if let Some(data) = &self.stdin {
            // Written and dropped (closing the write end, so the child sees
            // EOF) before `wait_with_output` reads anything back. Every
            // caller today (`dd of=<path>`) writes a resolv.conf-sized body
            // -- well under a pipe buffer -- so there is no reader/writer
            // deadlock risk between this write and the child's own stdout;
            // this is not a general-purpose subprocess I/O primitive.
            let mut stdin = child
                .stdin
                .take()
                .expect("stdin was requested as piped above");
            stdin.write_all(data.as_bytes()).map_err(|e| {
                TunnelError::Route(format!("cannot write to `{}`'s stdin: {e}", self.program))
            })?;
        }

        let out = child
            .wait_with_output()
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

/// Which resolver addresses still need their own host route in `test` mode.
///
/// `--capture-dns` adds a host route per resolver so DNS reaches the TUN. If
/// the operator also listed a prefix that already covers that resolver, the
/// two collide: the kernel rejects the duplicate with `RTNETLINK answers: File
/// exists` (Linux) and the whole apply fails partway, leaving earlier routes
/// installed with no guard to remove them.
///
/// Found by running `--cidr 1.1.1.1/32 --capture-dns` against a real routing
/// table with `dns.servers = ["1.1.1.1"]` — a natural thing for an operator to
/// type, and it made `connect` fail outright.
///
/// Containment rather than equality: a listed `1.1.1.0/24` covers `1.1.1.1`
/// just as surely as `1.1.1.1/32` does, and the kernel would reject that
/// duplicate too.
pub fn dns_servers_needing_host_routes<'a>(
    cidrs: &[IpNet],
    dns_servers: &'a [IpAddr],
) -> Vec<&'a IpAddr> {
    dns_servers
        .iter()
        .filter(|dns| !cidrs.iter().any(|c| c.contains(*dns)))
        .collect()
}

/// Command construction is pure so it can be unit-tested without privileges;
/// only [`RouteCommand::run`], `detect_gateway`, and `ipv6_available` touch
/// the system. Spec §10.
pub trait RouteManager: Send + Sync {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>;
    fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError>;
    fn detect_gateway(&self) -> Result<IpAddr, TunnelError>;

    /// Whether this host has a working IPv6 stack at all -- not merely
    /// "configured with a routable address", but able to create an `AF_INET6`
    /// socket and bind it to `::1` in the first place. That is exactly the
    /// condition under which `ip -6 route add`/`route -inet6 add` can
    /// succeed, so it is the right gate for Gap 2's IPv6 split-default: a
    /// host with IPv6 disabled at the kernel level (common in minimal
    /// containers, e.g. `net.ipv6.conf.all.disable_ipv6=1`) would otherwise
    /// have those route commands fail and abort `apply_commands` partway
    /// through, stranding whatever was already installed.
    ///
    /// Identical on every platform, so it is a provided method rather than
    /// something each `impl RouteManager` repeats. Deliberately outside
    /// `apply_commands`/`revert_commands`: those stay pure and only ever read
    /// [`RoutePlan::ipv6_available`], which callers (e.g. `connect.rs`) are
    /// expected to fill in from this method before building the plan --
    /// exactly the same pattern `detect_gateway` already established for
    /// `original_gateway`.
    fn ipv6_available(&self) -> bool {
        std::net::UdpSocket::bind("[::1]:0").is_ok()
    }
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
            // The common case for existing tests below, which predate Gap 2
            // and are not about IPv6 availability at all: a host with a
            // working IPv6 stack. Tests that care about the `false` case use
            // `plan_ipv6` directly instead of this default.
            ipv6_available: true,
        }
    }

    /// Like `plan`, but with an explicit IPv6-availability flag, for tests
    /// that specifically exercise Gap 2's host-has-no-IPv6 gate.
    fn plan_ipv6(mode: RouteMode, ipv6_available: bool) -> RoutePlan {
        RoutePlan {
            ipv6_available,
            ..plan(mode)
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
    fn capture_dns_does_not_duplicate_a_route_the_operator_already_listed() {
        // Regression: `--cidr 1.1.1.1/32 --capture-dns` with dns.servers =
        // ["1.1.1.1"] emitted the same route twice. Against a real routing
        // table the second one fails -- Linux answers `RTNETLINK answers: File
        // exists` -- and because that happens mid-apply, `RouteGuard::apply`
        // returns Err before the guard exists, stranding the routes already
        // installed. Found by running `connect` for real, not by inspection.
        let p = RoutePlan {
            interface: "utun7".into(),
            mode: RouteMode::Test {
                cidrs: vec!["1.1.1.1/32".parse().unwrap()],
                capture_dns: true,
            },
            server_ip: "198.51.100.7".parse().unwrap(),
            original_gateway: "192.168.1.1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            ipv6_available: true,
        };

        for (name, cmds) in [
            ("macos", macos::MacOsRoutes.apply_commands(&p).unwrap()),
            ("linux", linux::LinuxRoutes.apply_commands(&p).unwrap()),
        ] {
            let r = rendered(&cmds);
            assert_eq!(
                r.len(),
                1,
                "{name}: the resolver is already covered by a listed CIDR, so it \
                 must not also get its own host route: {r:?}"
            );
        }
    }

    #[test]
    fn capture_dns_skips_a_resolver_covered_by_a_wider_listed_prefix() {
        // Containment, not just equality: a listed /24 covers the resolver too,
        // and the kernel rejects that duplicate exactly the same way.
        let p = RoutePlan {
            interface: "utun7".into(),
            mode: RouteMode::Test {
                cidrs: vec!["1.1.1.0/24".parse().unwrap()],
                capture_dns: true,
            },
            server_ip: "198.51.100.7".parse().unwrap(),
            original_gateway: "192.168.1.1".parse().unwrap(),
            dns_servers: vec![
                "1.1.1.1".parse().unwrap(), // covered by the /24
                "9.9.9.9".parse().unwrap(), // not covered, still needs its route
            ],
            ipv6_available: true,
        };

        for (name, cmds) in [
            ("macos", macos::MacOsRoutes.apply_commands(&p).unwrap()),
            ("linux", linux::LinuxRoutes.apply_commands(&p).unwrap()),
        ] {
            let r = rendered(&cmds);
            assert_eq!(r.len(), 2, "{name}: expected the /24 plus 9.9.9.9: {r:?}");
            assert!(
                r.iter().any(|c| c.contains("9.9.9.9")),
                "{name}: an uncovered resolver still needs its host route: {r:?}"
            );
            assert!(
                !r.iter().any(|c| c.contains("1.1.1.1")),
                "{name}: 1.1.1.1 is inside the listed /24: {r:?}"
            );
        }
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
                !r.iter().any(|c| c.contains("0.0.0.0/1")
                    || c.contains("128.0.0.0/1")
                    || c.contains("::/1")
                    || c.contains("8000::/1")),
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
        //
        // DNS-management commands (macOS's `networksetup`, Linux's `cp`/`dd`
        // backup-and-write pair for `/etc/resolv.conf`) are excluded from this
        // destination comparison entirely: they carry file paths, not
        // route/host destinations, and `/etc/resolv.conf` appears as *both*
        // source and destination arguments across the backup/write/restore
        // trio, which would make a naive "first arg containing '/'" match
        // compare the wrong tokens. Their own apply/revert correctness is
        // covered by dedicated tests below instead.
        fn is_dns_command(program: &str) -> bool {
            matches!(program, "networksetup" | "cp" | "dd")
        }

        fn destination(cmd: &RouteCommand) -> Option<String> {
            if is_dns_command(&cmd.program) {
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
                if is_dns_command(&cmd.program) {
                    continue;
                }
                assert!(
                    cmd.args.iter().any(|a| a == "delete" || a == "del"),
                    "{name}: every revert command must actually delete: {cmd:?}"
                );
            }
            for cmd in &applied {
                if is_dns_command(&cmd.program) {
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
    // rather than "fixed" here. Linux's own DNS override (`route/linux.rs`,
    // Gap 2 report) does not share this limitation: it backs up and restores
    // the exact original file rather than resetting to some other state, and
    // that exactness is covered directly by linux.rs's own tests.

    // --- Gap 2: IPv6 split-default -----------------------------------------
    //
    // `rendered()` strings are space-joined, and IPv6 CIDRs collide under a
    // plain substring search in a way IPv4's `"0.0.0.0/1"`/`"128.0.0.0/1"`
    // never do: `"8000::/1"` itself contains the substring `"::/1"`. Every
    // v6-specific assertion below matches a whole whitespace-delimited token
    // instead of using `str::contains`, to avoid the false positive that
    // substring search would produce between the two halves.
    fn has_token(line: &str, token: &str) -> bool {
        line.split_whitespace().any(|t| t == token)
    }

    #[test]
    fn default_mode_installs_the_v6_split_default_when_the_host_has_ipv6() {
        // A/B'd against the pre-fix code: before this change, neither
        // platform's `Default` arm emitted `::/1`/`8000::/1` at all, so
        // `::/0` stayed untouched and every v6 packet left the machine
        // outside the tunnel in cleartext -- this test failed on both
        // `any(...)` assertions below. The packet engine cannot carry IPv6
        // (`net::smoltcp_stack::inspect::inspect` parses IPv4 only and
        // reports `Ignored` for anything else), so routing v6 into the TUN
        // does not tunnel it -- it blackholes it, which is still the right
        // trade for a privacy tool: failing closed beats leaking in
        // cleartext.
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
            assert!(r.iter().any(|c| has_token(c, "::/1")), "{name}: {r:?}");
            assert!(r.iter().any(|c| has_token(c, "8000::/1")), "{name}: {r:?}");
            assert_no_default_route_deletion(name, &r);
        }
    }

    #[test]
    fn reverting_default_mode_removes_the_v6_split_default_symmetrically() {
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
            for half in ["::/1", "8000::/1"] {
                let line = r
                    .iter()
                    .find(|c| has_token(c, half))
                    .unwrap_or_else(|| panic!("{name}: no revert command found for {half}: {r:?}"));
                assert!(
                    line.contains("delete") || line.contains(" del "),
                    "{name}: {half}'s revert must actually delete it: {line}"
                );
            }
            assert_no_default_route_deletion(name, &r);
        }
    }

    #[test]
    fn default_mode_skips_the_v6_split_default_when_the_host_has_no_ipv6() {
        // Gap 2's explicit failure-mode guard: a route command that fails on
        // a v6-less host (IPv6 disabled at the kernel level, which is common
        // in minimal containers) would abort `apply_commands` partway
        // through and strand whatever was already installed. A host with no
        // IPv6 stack must get no IPv6 route commands in either direction --
        // not just skipped on apply, but not referenced on revert either,
        // since nothing was ever installed to remove.
        let p = plan_ipv6(RouteMode::Default, false);
        for (name, mgr) in [
            (
                "macos",
                Box::new(macos::MacOsRoutes) as Box<dyn RouteManager>,
            ),
            ("linux", Box::new(linux::LinuxRoutes)),
        ] {
            let r_apply = rendered(&mgr.apply_commands(&p).unwrap());
            let r_revert = rendered(&mgr.revert_commands(&p).unwrap());
            for r in [&r_apply, &r_revert] {
                assert!(
                    !r.iter()
                        .any(|c| has_token(c, "::/1") || has_token(c, "8000::/1")),
                    "{name}: a v6-less host must get no IPv6 route commands: {r:?}"
                );
            }
            // The rest of `Default` mode -- pin, v4 halves, DNS override --
            // must still be installed; the flag gates IPv6 alone.
            assert!(
                r_apply.iter().any(|c| c.contains("0.0.0.0/1")),
                "{name}: {r_apply:?}"
            );
            assert!(
                r_apply.iter().any(|c| c.contains("128.0.0.0/1")),
                "{name}: {r_apply:?}"
            );
        }
    }

    #[test]
    fn the_server_pin_precedes_the_v6_split_default_too() {
        // Same reasoning as `assert_pin_precedes_both_halves`: the pin must
        // exist before *any* default-beating route, v4 or v6, or the SSH
        // connection could be cut before its own escape route does.
        for (name, cmds) in [
            (
                "macos",
                rendered(&macos::MacOsRoutes.apply_commands(&default_plan()).unwrap()),
            ),
            (
                "linux",
                rendered(&linux::LinuxRoutes.apply_commands(&default_plan()).unwrap()),
            ),
        ] {
            let pin = cmds
                .iter()
                .position(|c| c.contains("198.51.100.7"))
                .unwrap_or_else(|| panic!("{name}: no server pin found: {cmds:?}"));
            for half in ["::/1", "8000::/1"] {
                let at = cmds
                    .iter()
                    .position(|c| has_token(c, half))
                    .unwrap_or_else(|| panic!("{name}: no {half} route found: {cmds:?}"));
                assert!(pin < at, "{name}: server pin must precede {half}: {cmds:?}");
            }
        }
    }

    #[test]
    fn default_mode_pins_an_ipv6_ssh_server_correctly() {
        // Not reachable from `connect` today: `SshTunnel::pick_ipv4`
        // (`protocols/ssh.rs`) already refuses to resolve to an IPv6-only
        // server address, specifically because route construction used to
        // hardcode a `/32` and an IPv4-shaped command. This test exists so
        // route construction is correct in its own right -- defence in
        // depth, the same reasoning `reject_full_default_prefixes` already
        // gets both at CLI parse time and unconditionally again inside
        // `apply_commands`/`revert_commands` -- not because this is a live
        // production path yet.
        let p = RoutePlan {
            interface: "utun7".into(),
            mode: RouteMode::Default,
            server_ip: "2001:db8::7".parse().unwrap(),
            original_gateway: "2001:db8::1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            ipv6_available: true,
        };

        let linux_cmds = rendered(&linux::LinuxRoutes.apply_commands(&p).unwrap());
        assert!(
            linux_cmds
                .iter()
                .any(|c| c.contains("2001:db8::7/128") && c.contains("2001:db8::1")),
            "linux must pin an IPv6 server with a /128, not a /32: {linux_cmds:?}"
        );
        assert!(
            !linux_cmds.iter().any(|c| c.contains("2001:db8::7/32")),
            "linux must never emit a /32 for an IPv6 address: {linux_cmds:?}"
        );

        let macos_cmds = rendered(&macos::MacOsRoutes.apply_commands(&p).unwrap());
        assert!(
            macos_cmds.iter().any(|c| c.contains("-inet6")
                && c.contains("2001:db8::7")
                && c.contains("2001:db8::1")),
            "macos must pin an IPv6 server with -inet6: {macos_cmds:?}"
        );

        let linux_revert = rendered(&linux::LinuxRoutes.revert_commands(&p).unwrap());
        assert!(
            linux_revert
                .iter()
                .any(|c| c.contains("2001:db8::7/128") && (c.contains("del"))),
            "linux revert must remove the /128 pin: {linux_revert:?}"
        );
        let macos_revert = rendered(&macos::MacOsRoutes.revert_commands(&p).unwrap());
        assert!(
            macos_revert
                .iter()
                .any(|c| c.contains("-inet6") && c.contains("2001:db8::7")),
            "macos revert must remove the -inet6 pin: {macos_revert:?}"
        );
    }

    #[test]
    fn default_mode_overrides_dns_on_linux_too() {
        // A/B'd against the pre-fix code: before this change, Linux's
        // `Default` arm emitted no DNS-related command at all, so this
        // `any(...)` found nothing and failed. `linux.rs`'s own tests cover
        // the `cp`/`dd` mechanism in detail; this is the cross-platform
        // sanity check that both platforms' `Default` mode do *something*
        // to override DNS, mirroring `default_mode_overrides_dns` above.
        let r = rendered(&linux::LinuxRoutes.apply_commands(&default_plan()).unwrap());
        assert!(r.iter().any(|c| c.starts_with("cp ")), "{r:?}");
        assert!(r.iter().any(|c| c.starts_with("dd ")), "{r:?}");
    }
}
