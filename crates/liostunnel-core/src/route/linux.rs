use std::net::IpAddr;

use crate::error::TunnelError;
use crate::route::{RouteCommand, RouteManager, RouteMode, RoutePlan};

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
/// A hardcoded `/32` would silently mismatch an IPv6 DNS resolver.
fn host_prefix_len(addr: &IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

impl RouteManager for LinuxRoutes {
    fn apply_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "add", &cidr.to_string(), "dev", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in &plan.dns_servers {
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
            RouteMode::Default => return Err(TunnelError::Unsupported("default route mode")),
        }
        Ok(cmds)
    }

    fn revert_commands(&self, plan: &RoutePlan) -> Result<Vec<RouteCommand>, TunnelError> {
        let mut cmds = Vec::new();
        match &plan.mode {
            RouteMode::Test { cidrs, capture_dns } => {
                for cidr in cidrs {
                    cmds.push(RouteCommand::new(
                        "ip",
                        &["route", "del", &cidr.to_string(), "dev", &plan.interface],
                    ));
                }
                if *capture_dns {
                    for dns in &plan.dns_servers {
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
            RouteMode::Default => return Err(TunnelError::Unsupported("default route mode")),
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
}
