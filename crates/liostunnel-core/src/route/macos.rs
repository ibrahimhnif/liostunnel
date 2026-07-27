use std::net::IpAddr;

use crate::error::TunnelError;
use crate::route::{
    RouteCommand, RouteManager, RouteMode, RoutePlan, reject_full_default_prefixes,
};

pub struct MacOsRoutes;

/// Parse the `gateway:` line out of `route -n get default` output. Factored
/// out of `detect_gateway` so it can be unit-tested without shelling out.
fn parse_gateway(text: &str) -> Option<IpAddr> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .and_then(|v| v.trim().parse().ok())
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
                    for dns in &plan.dns_servers {
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
                cmds.push(RouteCommand::new(
                    "route",
                    &[
                        "-n",
                        "add",
                        "-host",
                        &plan.server_ip.to_string(),
                        &plan.original_gateway.to_string(),
                    ],
                ));
                // Two /1 routes beat 0.0.0.0/0 by being more specific, so the
                // real default route is never deleted and restoring is exact.
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "add", "-net", half, "-interface", &plan.interface],
                    ));
                }
                let mut args = vec!["-setdnsservers".to_string(), "Wi-Fi".to_string()];
                args.extend(plan.dns_servers.iter().map(|d| d.to_string()));
                cmds.push(RouteCommand {
                    program: "networksetup".into(),
                    args,
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
                    for dns in &plan.dns_servers {
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
                for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                    cmds.push(RouteCommand::new(
                        "route",
                        &["-n", "delete", "-net", half, "-interface", &plan.interface],
                    ));
                }
                cmds.push(RouteCommand::new(
                    "route",
                    &[
                        "-n",
                        "delete",
                        "-host",
                        &plan.server_ip.to_string(),
                        &plan.original_gateway.to_string(),
                    ],
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
