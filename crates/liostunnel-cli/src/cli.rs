use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "liostunnel", version, about = "Tunnel client — Phase 0 CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Bypass SSH host key verification. Dangerous; for self-signed lab setups only.
    #[arg(long, global = true)]
    pub insecure_accept_any_hostkey: bool,

    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Parse and validate a profile without connecting.
    Validate { profile: PathBuf },

    /// Open one SSH channel to a destination and proxy stdin/stdout through it.
    Probe {
        profile: PathBuf,
        /// SSH username.
        #[arg(long)]
        user: String,
        /// Destination as host:port, resolved by the *server*, not locally.
        #[arg(long)]
        dest: String,
    },

    /// Import a shareable profile, moving its secrets to disk.
    Import { profile: PathBuf },

    /// Export a profile in shareable form. Writes secrets in plaintext.
    Export {
        profile: PathBuf,
        #[arg(long)]
        include_secrets: bool,
    },

    /// Bring up the TUN device and route traffic through the tunnel.
    Connect {
        profile: PathBuf,
        /// SSH username.
        #[arg(long)]
        user: String,
        /// `test` routes only --cidr; `default` takes over all traffic (Task 21).
        #[arg(long, default_value = "test")]
        route_mode: String,
        /// Prefixes to route in test mode. Repeatable.
        #[arg(long = "cidr")]
        cidrs: Vec<String>,
        /// Also route the profile's DNS servers through the tunnel. Spec §10.
        #[arg(long)]
        capture_dns: bool,
        /// Address assigned to the TUN interface.
        #[arg(long, default_value = "10.90.0.1")]
        tun_address: std::net::Ipv4Addr,
    },
}
