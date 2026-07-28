pub mod auth;
pub mod dispatch;
pub mod listener;
pub mod session;

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use dispatch::{Action, Session};
use session::{HelperPaths, Tunnel};

/// How often a connected client is sent a stats frame.
const STATS_INTERVAL: Duration = Duration::from_secs(1);

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

    // Bind before the runtime exists: the flock, the unlink and the chown are
    // all blocking, and failing here should look like a startup error rather
    // than a task that died.
    let listener = match listener::Listener::bind(&args.socket, uid) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}: {e}", args.socket.display());
            return std::process::ExitCode::FAILURE;
        }
    };
    tracing::info!(socket = %args.socket.display(), uid, "helper listening");

    let paths = HelperPaths::beside_socket(&args.socket);

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match rt.block_on(serve(&listener, uid, paths)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Accepts connections until the process is asked to stop.
///
/// One client at a time by construction, because there is one routing table.
/// A second connection is accepted and authorized — so it gets a real protocol
/// error rather than a silent hang — but it finds no tunnel of its own.
async fn serve(listener: &listener::Listener, uid: u32, paths: HelperPaths) -> std::io::Result<()> {
    // tokio drives a duplicate of the descriptor; the original stays owned by
    // `listener`, whose Drop is what unlinks the socket and releases the lock.
    let std_listener = listener.try_clone_std()?;
    std_listener.set_nonblocking(true)?;
    let tl = tokio::net::UnixListener::from_std(std_listener)?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // The tunnel belongs to the daemon, not to whichever client happened to
    // start it. Quitting the UI must leave traffic flowing, and relaunching it
    // must find the tunnel still here (P1a-4) — so this outlives every
    // connection and only an explicit disconnect or daemon shutdown ends it.
    let mut tunnel: Option<Tunnel> = None;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupted; shutting down");
                return Ok(());
            }
            _ = sigterm.recv() => {
                tracing::info!("terminated; shutting down");
                return Ok(());
            }
            accepted = tl.accept() => {
                let (stream, _) = accepted?;
                // The peer-uid gate, before a single byte is read.
                if let Err(e) = listener.authorize_peer(&stream) {
                    tracing::warn!(error = %e, "refused a connection");
                    continue;
                }
                // Serialised deliberately: one routing table, one tunnel, and
                // a second concurrent client would race the first's teardown.
                if let Err(e) = serve_one(stream, uid, &paths, &mut tunnel).await {
                    tracing::warn!(error = %e, "client connection ended with an error");
                }
            }
        }
    }
    // `tunnel` drops here on the shutdown paths above, reverting routes and
    // clearing the state file — a daemon that stops must not leave the
    // machine routing through an interface that no longer exists.
}

/// Drives one authorized client until it disconnects.
async fn serve_one(
    stream: tokio::net::UnixStream,
    caller_uid: u32,
    paths: &HelperPaths,
    tunnel: &mut Option<Tunnel>,
) -> std::io::Result<()> {
    let (read_half, mut write) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    let mut sess = Session::new(caller_uid);
    // A relaunched UI must re-sync to a tunnel that is still up rather than
    // report Disconnected over a working one (P1a-4). The daemon's state is
    // the truth; the fresh session adopts it.
    if tunnel.is_some() {
        sess.resume_connected();
    }
    let mut ticker = tokio::time::interval(STATS_INTERVAL);

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { break };  // client hung up
                let (replies, action) = sess.handle(&line);
                write_all(&mut write, &replies).await?;

                match action {
                    Action::None => {}
                    Action::StopTunnel => {
                        if let Some(t) = tunnel.take() {
                            t.stop();
                        }
                    }
                    Action::Start(id, authorized) => {
                        // Everything decidable without privilege already
                        // passed; this is the part that needs root.
                        let out = match Tunnel::start(*authorized, paths).await {
                            Ok(t) => {
                                *tunnel = Some(t);
                                sess.connect_succeeded(id)
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "connect failed");
                                sess.connect_failed(id, &e)
                            }
                        };
                        write_all(&mut write, &out).await?;
                    }
                }
            }
            _ = ticker.tick() => {
                let Some(t) = tunnel.as_ref() else { continue };
                // An engine that exited on its own leaves routes installed
                // with nothing behind them. Phase 0 had to fix exactly this
                // in the CLI, where the process waited forever on a tunnel
                // that had already died while stats still read Connected.
                if t.has_stopped() {
                    let out = sess.tunnel_stopped();
                    if let Some(t) = tunnel.take() {
                        t.stop();
                    }
                    write_all(&mut write, &out).await?;
                    continue;
                }
                let frame = serde_json::to_string(
                    &liostunnel_ffi::dto::protocol::Event::Stats { snapshot: t.stats() },
                )
                .expect("Stats always serializes");
                write_all(&mut write, std::slice::from_ref(&frame)).await?;
            }
        }
    }

    // The client is gone, but the tunnel is not the client's to end: quitting
    // the UI must leave traffic flowing (P1a-4). It stays owned by the caller
    // — only an explicit disconnect or the daemon stopping takes it down.
    if tunnel.is_some() {
        tracing::info!("client disconnected; tunnel left running");
    }
    Ok(())
}

async fn write_all(
    w: &mut tokio::net::unix::OwnedWriteHalf,
    lines: &[String],
) -> std::io::Result<()> {
    for l in lines {
        w.write_all(l.as_bytes()).await?;
        w.write_all(b"\n").await?;
    }
    Ok(())
}
