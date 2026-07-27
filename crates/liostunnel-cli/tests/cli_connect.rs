//! Argument-parsing coverage for the `connect` subcommand (Task 17).
//!
//! Everything here is root-free by construction: it only exercises
//! `Cli::try_parse_from`, never `commands::connect::run`, so none of it
//! touches a TUN device or the routing table.

use std::net::Ipv4Addr;

use clap::Parser;
use liostunnel_cli::cli::{Cli, Command};

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    let mut full = vec!["liostunnel"];
    full.extend_from_slice(args);
    Cli::try_parse_from(full)
}

#[test]
fn connect_applies_its_documented_defaults() {
    let cli = parse(&["connect", "profile.json", "--user", "alice"]).unwrap();
    match cli.command {
        Command::Connect {
            profile,
            user,
            route_mode,
            cidrs,
            capture_dns,
            tun_address,
        } => {
            assert_eq!(profile, std::path::PathBuf::from("profile.json"));
            assert_eq!(user, "alice");
            assert_eq!(route_mode, "test", "brief specifies `test` as the default");
            assert!(cidrs.is_empty());
            assert!(!capture_dns);
            assert_eq!(tun_address, Ipv4Addr::new(10, 90, 0, 1));
        }
        other => panic!("expected Command::Connect, got {other:?}"),
    }
}

#[test]
fn repeated_cidr_flags_are_all_collected() {
    let cli = parse(&[
        "connect",
        "profile.json",
        "--user",
        "alice",
        "--cidr",
        "93.184.216.0/24",
        "--cidr",
        "198.51.100.0/24",
    ])
    .unwrap();
    let Command::Connect { cidrs, .. } = cli.command else {
        panic!("expected Command::Connect");
    };
    assert_eq!(cidrs, vec!["93.184.216.0/24", "198.51.100.0/24"]);
}

#[test]
fn capture_dns_and_route_mode_and_tun_address_are_all_overridable() {
    let cli = parse(&[
        "connect",
        "profile.json",
        "--user",
        "alice",
        "--route-mode",
        "default",
        "--capture-dns",
        "--tun-address",
        "10.8.0.1",
    ])
    .unwrap();
    let Command::Connect {
        route_mode,
        capture_dns,
        tun_address,
        ..
    } = cli.command
    else {
        panic!("expected Command::Connect");
    };
    assert_eq!(route_mode, "default");
    assert!(capture_dns);
    assert_eq!(tun_address, Ipv4Addr::new(10, 8, 0, 1));
}

#[test]
fn missing_required_user_is_a_clear_clap_error_not_a_panic() {
    let err = parse(&["connect", "profile.json"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    assert!(
        err.to_string().contains("--user"),
        "error should name the missing flag: {err}"
    );
}

#[test]
fn missing_profile_positional_is_a_clear_clap_error() {
    let err = parse(&["connect", "--user", "alice"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn a_malformed_tun_address_is_rejected_at_parse_time() {
    let err = parse(&[
        "connect",
        "profile.json",
        "--user",
        "alice",
        "--tun-address",
        "not-an-ip",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    assert!(
        err.to_string().contains("tun-address"),
        "error should name the offending flag: {err}"
    );
}

#[test]
fn connect_help_renders_and_documents_every_flag() {
    let err = parse(&["connect", "--help"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    let rendered = err.to_string();
    for needle in [
        "--user",
        "--route-mode",
        "--cidr",
        "--capture-dns",
        "--tun-address",
    ] {
        assert!(
            rendered.contains(needle),
            "connect --help should document {needle}: {rendered}"
        );
    }
}

#[test]
fn top_level_help_lists_connect() {
    let err = parse(&["--help"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    assert!(err.to_string().contains("connect"));
}
