use clap::Parser;
use liostunnel_cli::cli::{Cli, Command};
use liostunnel_cli::{commands, profile_io};
use liostunnel_core::config::portable::{EXPORT_WARNING, PortableProfile};
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::protocols::ssh::HostKeyPolicy;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.clone().into()),
        )
        .init();

    if cli.insecure_accept_any_hostkey {
        eprintln!(
            "\n  !!  --insecure-accept-any-hostkey is set. Host key verification is OFF.\n\
               !!  This connection can be silently intercepted. Use only on a network\n\
               !!  you control, against a server you are certain of.\n"
        );
    }

    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), liostunnel_core::TunnelError> {
    let home = profile_io::home();
    let secret_dir = home.join("secrets");
    let policy = if cli.insecure_accept_any_hostkey {
        HostKeyPolicy::AcceptAny
    } else {
        HostKeyPolicy::Verify {
            known_hosts: home.join("known_hosts"),
        }
    };

    match cli.command {
        Command::Validate { profile } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            p.validate(&FileSecretStore)?;
            emit_warnings(&p);
            println!("{} — ok ({:?} {}:{})", p.name, p.protocol, p.host, p.port);
            Ok(())
        }
        Command::Import { profile } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            p.validate(&FileSecretStore)?;
            let out = home.join(format!("{}.json", p.id));
            std::fs::create_dir_all(&home).map_err(liostunnel_core::TunnelError::from)?;
            std::fs::write(&out, serde_json::to_string_pretty(&p).unwrap())
                .map_err(liostunnel_core::TunnelError::from)?;
            println!("imported to {}", out.display());
            Ok(())
        }
        Command::Export {
            profile,
            include_secrets,
        } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            if !include_secrets {
                return Err(liostunnel_core::TunnelError::config(
                    "--include-secrets",
                    "export writes private keys in plaintext; pass --include-secrets \
                     to confirm you understand this",
                ));
            }
            eprintln!("WARNING: {EXPORT_WARNING}");
            let portable = PortableProfile::export(&p, &FileSecretStore)?;
            println!("{}", serde_json::to_string_pretty(&portable).unwrap());
            Ok(())
        }
        Command::Probe {
            profile,
            user,
            dest,
        } => {
            let p = profile_io::load(&profile, &secret_dir)?;
            p.validate(&FileSecretStore)?;
            emit_warnings(&p);
            commands::probe::run(&p, user, &dest, policy).await
        }
    }
}

/// Spec §9.3.
fn emit_warnings(p: &liostunnel_core::config::profile::ServerProfile) {
    for w in p.warnings() {
        eprintln!("  !!  WARNING: {w}");
    }
}
