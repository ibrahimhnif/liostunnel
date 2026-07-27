use liostunnel_core::TunnelError;
use liostunnel_core::config::profile::ServerProfile;
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn run(
    profile: &ServerProfile,
    user: String,
    dest: &str,
    policy: HostKeyPolicy,
) -> Result<(), TunnelError> {
    let (host, port) = dest
        .rsplit_once(':')
        .ok_or_else(|| TunnelError::config("--dest", "expected host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TunnelError::config("--dest", "port must be a number"))?;

    let mut tunnel = SshTunnel::new(user, policy);
    tunnel.connect(profile, &FileSecretStore).await?;
    tracing::info!(%dest, "opening channel");

    let origin = "127.0.0.1:0"
        .parse()
        .expect("literal is a valid SocketAddr");
    let mut stream = tunnel.open_tcp_stream_named(host, port, origin).await?;

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut up = [0u8; 8192];
    let mut down = [0u8; 8192];

    // `stdin` reaching EOF must not tear down the whole proxy: in the common
    // non-interactive case (piped input, exactly what the Milestone A check
    // does), the local side finishes writing its request well before the
    // remote has replied, and a plain `select!` with a fresh `stdin.read`
    // future each iteration will very often have that read "win" the race
    // against the network round trip — breaking the loop and discarding a
    // response that hasn't arrived yet. So a closed stdin only half-closes:
    // we stop polling it (the `if stdin_open` guard also keeps a
    // repeatedly-Ok(0) stdin from spinning the loop) and propagate our own
    // EOF to the remote via `shutdown`, but keep relaying downstream data
    // until the *remote* side reports EOF or errors — only then does the
    // whole proxy end.
    let mut stdin_open = true;

    loop {
        tokio::select! {
            n = stdin.read(&mut up), if stdin_open => match n {
                Ok(0) => {
                    stdin_open = false;
                    stream.shutdown().await?;
                }
                Err(_) => {
                    stdin_open = false;
                }
                Ok(n) => stream.write_all(&up[..n]).await?,
            },
            n = stream.read(&mut down) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => { stdout.write_all(&down[..n]).await?; stdout.flush().await?; }
            },
        }
    }

    let s = tunnel.stats();
    tracing::info!(
        bytes_up = s.bytes_up,
        bytes_down = s.bytes_down,
        "channel closed"
    );
    tunnel.disconnect().await
}
