pub mod auth;
pub mod dispatch;
pub mod listener;
pub mod session;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "liostunnel-helper",
    version,
    about = "Privileged tunnel helper"
)]
struct Args {
    /// Unix socket to listen on.
    #[arg(long, default_value = "/var/run/liostunnel.sock")]
    socket: PathBuf,

    /// The only uid permitted to connect. Written into the launchd plist /
    /// systemd unit by the installer, so it is root-owned configuration an
    /// unprivileged process cannot alter. Spec §7.1.
    #[arg(long)]
    uid: Option<u32>,
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    // Refuse to run permissively. A helper with no authorized uid would accept
    // anyone, which is strictly worse than not starting.
    let Some(uid) = args.uid else {
        eprintln!("error: --uid is required; refusing to accept connections from any user");
        return std::process::ExitCode::FAILURE;
    };

    match listener::Listener::bind(&args.socket, uid) {
        Ok(_l) => {
            tracing::info!(socket = %args.socket.display(), uid, "helper listening");
            // The accept loop arrives in Task 5.
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot bind {}: {e}", args.socket.display());
            std::process::ExitCode::FAILURE
        }
    }
}
