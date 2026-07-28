use std::net::IpAddr;

use crate::error::TunnelError;
use crate::route::{
    RouteCommand, RouteManager, RouteMode, RoutePlan, dns_servers_needing_host_routes,
    reject_full_default_prefixes,
};

pub struct MacOsRoutes;

/// Parse the `gateway:` line out of `route -n get default` output. Factored
/// out of `detect_gateway` so it can be unit-tested without shelling out.
fn parse_gateway(text: &str) -> Option<IpAddr> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .and_then(|v| v.trim().parse().ok())
}

/// BSD `route`'s address-family flag, needed explicitly for IPv6
/// destinations: unlike Linux's `ip`, macOS's `route` does not reliably infer
/// family from a bare `::`-containing argument for `-host`/`-net` routes.
fn family_flag(addr: &IpAddr) -> Option<&'static str> {
    if addr.is_ipv6() { Some("-inet6") } else { None }
}

/// Builds the server-pin route command (`add` or `delete`), matching
/// `route`'s family-flag requirement for whichever family `server_ip`
/// actually is. Not reachable from `connect` today -- `SshTunnel::pick_ipv4`
/// (`protocols/ssh.rs`) already refuses to resolve to an IPv6-only server
/// address -- but Gap 2 asks route construction itself to handle the case
/// correctly regardless, the same defence-in-depth `reject_full_default_prefixes`
/// already gets both at CLI parse time and unconditionally again here.
fn pin_command(verb: &str, server_ip: &IpAddr, original_gateway: &IpAddr) -> RouteCommand {
    let mut args = vec!["-n".to_string(), verb.to_string()];
    if let Some(flag) = family_flag(server_ip) {
        args.push(flag.to_string());
    }
    args.push("-host".to_string());
    args.push(server_ip.to_string());
    args.push(original_gateway.to_string());
    RouteCommand {
        program: "route".into(),
        args,
        stdin: None,
    }
}

impl RouteManager for MacOsRoutes {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                reject_full_default_prefixes(cidrs)?;
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "route",
                        &[
                            "-n",
                            "add",
                            "-net",
                            &cidr.to_string(),
                            "-interface",
                            &plan.interface,
                        ],
                    ));
                }
                if *capture_dns {
                    for dns in dns_servers_needing_host_routes(cidrs, &plan.dns_servers) {
                        cmds.push(RouteCommand::new(
                            "route",
                            &[
                                "-n",
                                "add",
                                "-host",
                                &dns.to_string(),
                                "-interface",
                                &plan.interface,
                            ],
                        ));
                    }
                }
            }
            RouteMode::Default => {
                // The server pin comes first: install it after 0.0.0.0/1 and the
                // SSH connection can be cut before its own escape route exists.
                cmds.push(pin_command("add", &plan.server_ip, &plan.original_gateway));
                // Two /1 routes beat 0.0.0.0/0 by being more specific, so the
                // real default route is never deleted and restoring is exact.
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "add", "-net", half, "-interface", &plan.interface],
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
                            "route",
                            &[
                                "-n",
                                "add",
                                "-inet6",
                                "-net",
                                half,
                                "-interface",
                                &plan.interface,
                            ],
                        ));
                    }
                }
                let mut args = vec!["-setdnsservers".to_string(), "Wi-Fi".to_string()];
                args.extend(plan.dns_servers.iter().map(|d| d.to_string()));
                cmds.push(RouteCommand {
                    program: "networksetup".into(),
                    args,
                    stdin: None,
                });
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
                        "route",
                        &[
                            "-n",
                            "delete",
                            "-net",
                            &cidr.to_string(),
                            "-interface",
                            &plan.interface,
                        ],
                    ));
                }
                if *capture_dns {
                    for dns in dns_servers_needing_host_routes(cidrs, &plan.dns_servers) {
                        cmds.push(RouteCommand::new(
                            "route",
                            &[
                                "-n",
                                "delete",
                                "-host",
                                &dns.to_string(),
                                "-interface",
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
                            "route",
                            &[
                                "-n",
                                "delete",
                                "-inet6",
                                "-net",
                                half,
                                "-interface",
                                &plan.interface,
                            ],
                        ));
                    }
                }
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "delete", "-net", half, "-interface", &plan.interface],
                    ));
                }
                cmds.push(pin_command(
                    "delete",
                    &plan.server_ip,
                    &plan.original_gateway,
                ));
                cmds.push(RouteCommand::new(
                    "networksetup",
                    &["-setdnsservers", "Wi-Fi", "Empty"],
                ));
            }
        }
        Ok(cmds)
    }

    fn detect_gateway(&self) -> Result<IpAddr, TunnelError> {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| TunnelError::Route(format!("cannot run `route get default`: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        parse_gateway(&text).ok_or_else(|| TunnelError::Route("no default gateway found".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_from_macos_route_get_default_output() {
        let text = "   route to: default\n\
destination: default\n\
       mask: default\n\
    gateway: 192.168.1.1\n\
  interface: en0\n\
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        assert_eq!(
            parse_gateway(text),
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn parse_gateway_returns_none_when_absent() {
        let text = "   route to: default\ndestination: default\n";
        assert_eq!(parse_gateway(text), None);
    }
}
