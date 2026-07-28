use std::net::IpAddr;

use crate::error::TunnelError;
use crate::route::{
    RouteCommand, RouteManager, RouteMode, RoutePlan, dns_servers_needing_host_routes,
    reject_full_default_prefixes,
};

pub struct LinuxRoutes;

/// Parse the gateway address out of `ip route show default` output, e.g.
/// "default via 192.168.1.1 dev eth0 proto dhcp metric 100". Factored out of
/// `detect_gateway` so it can be unit-tested without shelling out.
fn parse_gateway(text: &str) -> Option<IpAddr> {
    text.split_whitespace()
        .skip_while(|t| *t != "via")
        .nth(1)
        .and_then(|v| v.parse().ok())
}

/// Single-host prefix length for a route: 32 bits for IPv4, 128 for IPv6.
/// A hardcoded `/32` would silently mismatch an IPv6 DNS resolver -- or, per
/// Gap 2, an IPv6 SSH server address in the pin route below.
fn host_prefix_len(addr: &IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

/// Gap 1: `/etc/resolv.conf` is overwritten in place, backed up first so
/// revert (including crash recovery replaying the state file after a
/// `kill -9`) can restore it exactly. Fixed, not derived from the
/// environment -- `apply_commands`/`revert_commands` stay pure, so this
/// cannot be a path under the operator's actual `~/.liostunnel` (only
/// `liostunnel-cli`'s impure orchestration layer knows that location).
/// `/etc` already requires root to write, which `default` mode already
/// demands to install routes at all, so this adds no new privilege
/// requirement.
const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP: &str = "/etc/resolv.conf.liostunnel-backup";

/// The full replacement body for `/etc/resolv.conf` in `default` mode: one
/// `nameserver` line per configured resolver, in the order the profile lists
/// them. Pure -- a plain string built from data already in `RoutePlan`, no
/// filesystem access -- so `apply_commands` can hand it to a `RouteCommand`
/// as its stdin without ever touching disk itself. The write happens later,
/// inside `RouteCommand::run`'s `dd` invocation.
fn resolv_conf_body(dns_servers: &[IpAddr]) -> String {
    let mut body = String::from("# written by liostunnel (default route mode)\n");
    for server in dns_servers {
        body.push_str("nameserver ");
        body.push_str(&server.to_string());
        body.push('\n');
    }
    body
}

impl RouteManager for LinuxRoutes {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                reject_full_default_prefixes(cidrs)?;
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "add", &cidr.to_string(), "dev", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in dns_servers_needing_host_routes(cidrs, &plan.dns_servers) {
                        cmds.push(RouteCommand::new(
                            "ip",
                            &[
                                "route",
                                "add",
                                &format!("{dns}/{}", host_prefix_len(dns)),
                                "dev",
                                &plan.interface,
                            ],
                        ));
                    }
                }
            }
            RouteMode::Default => {
                // The server pin comes first: install it after 0.0.0.0/1 and the
                // SSH connection can be cut before its own escape route exists.
                // Family-correct prefix: a hardcoded /32 would silently
                // mismatch an IPv6 server address (Gap 2). Not reachable from
                // `connect` today -- `SshTunnel::pick_ipv4` already refuses an
                // IPv6-only-resolved server -- but construction stays correct
                // regardless of what a caller hands it, the same defence in
                // depth `reject_full_default_prefixes` already gets.
                cmds.push(RouteCommand::new(
                    "ip",
                    &[
                        "route",
                        "add",
                        &format!("{}/{}", plan.server_ip, host_prefix_len(&plan.server_ip)),
                        "via",
                        &plan.original_gateway.to_string(),
                    ],
                ));
                // Two /1 routes beat 0.0.0.0/0 by being more specific, so the
                // real default route is never deleted and restoring is exact.
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "add", half, "dev", &plan.interface],
                    ));
                }
                if plan.ipv6_available {
                    // Gap 2: the packet engine only parses IPv4
                    // (`net/smoltcp_stack/inspect.rs`'s `inspect` returns
                    // `Ignored` for anything else), so routing v6 into the TUN
                    // does not tunnel it -- it blackholes it. That is still
                    // strictly better than leaving `::/0` untouched, which
                    // lets v6 traffic (including v6-only DNS) bypass the
                    // tunnel in cleartext. Skipped entirely when the host has
                    // no IPv6 stack (`RoutePlan::ipv6_available`), because a
                    // route command that fails there would abort this whole
                    // apply partway through and strand the routes above.
                    for half in ["::/1", "8000::/1"] {
                        cmds.push(RouteCommand::new(
                            "ip",
                            &["route", "add", half, "dev", &plan.interface],
                        ));
                    }
                }
                // Gap 1: back up the current resolver config, then overwrite
                // it, so DNS resolves through the tunnel instead of leaking
                // to the LAN resolver via a connected route more specific
                // than the split-default halves above. Last, matching
                // macOS's existing `networksetup` placement -- see that
                // module's own comment, and the README's "Limitations"
                // section, for the ordering trade-off this shares with it.
                cmds.push(RouteCommand::new("cp", &[RESOLV_CONF, RESOLV_CONF_BACKUP]));
                cmds.push(RouteCommand::with_stdin(
                    "dd",
                    &[&format!("of={RESOLV_CONF}")],
                    resolv_conf_body(&plan.dns_servers),
                ));
            }
        }
        Ok(cmds)
    }

    fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                reject_full_default_prefixes(cidrs)?;
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "del", &cidr.to_string(), "dev", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in dns_servers_needing_host_routes(cidrs, &plan.dns_servers) {
                        cmds.push(RouteCommand::new(
                            "ip",
                            &[
                                "route",
                                "del",
                                &format!("{dns}/{}", host_prefix_len(dns)),
                                "dev",
                                &plan.interface,
                            ],
                        ));
                    }
                }
            }
            RouteMode::Default => {
                if plan.ipv6_available {
                    for half in ["::/1", "8000::/1"] {
                        cmds.push(RouteCommand::new(
                            "ip",
                            &["route", "del", half, "dev", &plan.interface],
                        ));
                    }
                }
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "del", half, "dev", &plan.interface],
                    ));
                }
                cmds.push(RouteCommand::new(
                    "ip",
                    &[
                        "route",
                        "del",
                        &format!("{}/{}", plan.server_ip, host_prefix_len(&plan.server_ip)),
                    ],
                ));
                // Gap 1: restore the exact pre-existing resolver config from
                // the backup `apply_commands` made, rather than clearing to
                // some other state -- unlike macOS's `networksetup -setdnsservers
                // ... Empty` (which resets to "automatic" DHCP-assigned DNS,
                // not necessarily what was there before), this is an exact
                // restore for every operator, not just the common case.
                cmds.push(RouteCommand::new("cp", &[RESOLV_CONF_BACKUP, RESOLV_CONF]));
            }
        }
        Ok(cmds)
    }

    fn detect_gateway(&self) -> Result<IpAddr, TunnelError> {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| TunnelError::Route(format!("cannot run `ip route show default`: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        parse_gateway(&text).ok_or_else(|| TunnelError::Route("no default gateway found".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_from_ip_route_show_default_output() {
        let text = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n";
        assert_eq!(
            parse_gateway(text),
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn parse_gateway_returns_none_when_absent() {
        let text = "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n";
        assert_eq!(parse_gateway(text), None);
    }

    #[test]
    fn dns_capture_uses_a_128_bit_mask_for_ipv6_resolvers() {
        let plan = RoutePlan {
            interface: "utun7".into(),
            mode: RouteMode::Test {
                cidrs: vec![],
                capture_dns: true,
            },
            server_ip: "198.51.100.7".parse().unwrap(),
            original_gateway: "192.168.1.1".parse().unwrap(),
            dns_servers: vec!["2001:4860:4860::8888".parse().unwrap()],
            ipv6_available: true,
        };
        let cmds = LinuxRoutes.apply_commands(&plan).unwrap();
        let rendered: Vec<String> = cmds
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect();
        assert!(
            rendered
                .iter()
                .any(|c| c.contains("2001:4860:4860::8888/128")),
            "IPv6 resolvers must get a single-host /128, not /32: {rendered:?}"
        );
    }

    fn default_plan() -> RoutePlan {
        RoutePlan {
            interface: "utun7".into(),
            mode: RouteMode::Default,
            server_ip: "198.51.100.7".parse().unwrap(),
            original_gateway: "192.168.1.1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
            ipv6_available: true,
        }
    }

    fn rendered(cmds: &[RouteCommand]) -> Vec<String> {
        cmds.iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    // --- Gap 1: DNS override on Linux's `default` mode ---------------------
    //
    // A/B'd against the pre-fix code: before this change, `RouteMode::Default`
    // emitted no `cp`/`dd` commands at all, so every `.find(...).expect(...)`
    // below panicked with "a cp backup command must be present" /
    // "a dd write command must be present".

    #[test]
    fn default_mode_backs_up_resolv_conf_before_overwriting_it() {
        let cmds = LinuxRoutes.apply_commands(&default_plan()).unwrap();
        let backup = cmds
            .iter()
            .find(|c| c.program == "cp")
            .expect("a cp backup command must be present");
        assert_eq!(
            backup.args,
            vec![
                "/etc/resolv.conf".to_string(),
                "/etc/resolv.conf.liostunnel-backup".to_string(),
            ],
            "backup must copy the real file to the fixed backup path: {backup:?}"
        );
        assert!(
            backup.stdin.is_none(),
            "cp needs no stdin -- only dd's write does: {backup:?}"
        );
    }

    #[test]
    fn default_mode_writes_the_new_resolv_conf_body_over_stdin_not_a_shell() {
        let cmds = LinuxRoutes.apply_commands(&default_plan()).unwrap();
        let write = cmds
            .iter()
            .find(|c| c.program == "dd")
            .expect("a dd write command must be present");
        assert_eq!(
            write.args,
            vec!["of=/etc/resolv.conf".to_string()],
            "dd's only argument must be the literal destination path, never an \
             interpolated shell string: {write:?}"
        );
        let body = write
            .stdin
            .as_deref()
            .expect("the new resolv.conf body must travel on stdin, not as an arg");
        assert!(body.contains("nameserver 1.1.1.1"), "{body}");
        assert!(body.contains("nameserver 1.0.0.1"), "{body}");
    }

    #[test]
    fn default_mode_dns_commands_never_invoke_a_shell() {
        // The design tension this whole gap turns on: `printf > file` needs a
        // shell, and interpolating resolver addresses into a shell string is
        // an injection surface. Guard against ever reintroducing one.
        for cmds in [
            LinuxRoutes.apply_commands(&default_plan()).unwrap(),
            LinuxRoutes.revert_commands(&default_plan()).unwrap(),
        ] {
            for c in &cmds {
                assert!(
                    !matches!(c.program.as_str(), "sh" | "bash" | "/bin/sh" | "/bin/bash"),
                    "no route/DNS command may shell out: {c:?}"
                );
            }
        }
    }

    #[test]
    fn default_mode_dns_override_reverts_by_restoring_the_exact_backup() {
        let cmds = LinuxRoutes.revert_commands(&default_plan()).unwrap();
        let restore = cmds
            .iter()
            .find(|c| c.program == "cp")
            .expect("a cp restore command must be present");
        assert_eq!(
            restore.args,
            vec![
                "/etc/resolv.conf.liostunnel-backup".to_string(),
                "/etc/resolv.conf".to_string(),
            ],
            "restore must copy the backup back over the real file -- the exact \
             reverse of the backup command's args: {restore:?}"
        );
    }

    #[test]
    fn default_mode_dns_backup_and_restore_are_a_true_argument_reversal() {
        // Symmetric in the strongest sense available here: not just "both
        // exist", but the restore's argument order is the backup's reversed.
        let apply = LinuxRoutes.apply_commands(&default_plan()).unwrap();
        let revert = LinuxRoutes.revert_commands(&default_plan()).unwrap();
        let backup = apply.iter().find(|c| c.program == "cp").unwrap();
        let restore = revert.iter().find(|c| c.program == "cp").unwrap();
        let mut reversed = backup.args.clone();
        reversed.reverse();
        assert_eq!(
            reversed, restore.args,
            "restore must be the backup's args exactly reversed: backup={backup:?} \
             restore={restore:?}"
        );
    }

    #[test]
    fn a_v6_less_host_gets_no_ipv6_route_commands_in_either_direction() {
        let mut p = default_plan();
        p.ipv6_available = false;
        let r_apply = rendered(&LinuxRoutes.apply_commands(&p).unwrap());
        let r_revert = rendered(&LinuxRoutes.revert_commands(&p).unwrap());
        for r in [&r_apply, &r_revert] {
            assert!(
                !r.iter()
                    .any(|c| c.split_whitespace().any(|t| t == "::/1" || t == "8000::/1")),
                "a host with no IPv6 stack must get no IPv6 route commands, in \
                 either direction, so a failing command there cannot strand \
                 the routes already applied: {r:?}"
            );
        }
        // DNS override is unrelated to IPv6 availability and must still run.
        assert!(r_apply.iter().any(|c| c.starts_with("dd ")), "{r_apply:?}");
    }
}
