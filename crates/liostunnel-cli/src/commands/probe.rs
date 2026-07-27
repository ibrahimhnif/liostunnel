use liostunnel_core::TunnelError;
use liostunnel_core::config::profile::ServerProfile;
use liostunnel_core::config::secret::FileSecretStore;
use liostunnel_core::protocols::Protocol;
use liostunnel_core::protocols::ssh::{HostKeyPolicy, SshTunnel};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    let stream = tunnel.open_tcp_stream_named(host, port, origin).await?;

    relay(tokio::io::stdin(), tokio::io::stdout(), stream).await?;

    let s = tunnel.stats();
    tracing::info!(
        bytes_up = s.bytes_up,
        bytes_down = s.bytes_down,
        "channel closed"
    );
    tunnel.disconnect().await
}

/// The stdin/stream proxy loop, factored out of [`run`] so it can be driven
/// by an in-memory duplex pair in tests instead of a real terminal and a live
/// SSH channel — see the `tests` module below.
///
/// `input` reaching EOF (or erroring) must not tear down the whole proxy: in
/// the common non-interactive case (piped input, exactly what the Milestone A
/// check does), the local side finishes writing its request well before the
/// remote has replied, and a plain `select!` with a fresh `input.read` future
/// each iteration will very often have that read "win" the race against the
/// network round trip — breaking the loop and discarding a response that
/// hasn't arrived yet. So a closed (or broken) `input` only half-closes: we
/// stop polling it (the `if input_open` guard also keeps an EOF'd or
/// permanently-erroring `input` from spinning the loop) and propagate our own
/// EOF to the remote via `shutdown` on *either* path — a read error means the
/// local side can supply no more data just as surely as a clean EOF does, so
/// the remote must be told either way, or it can be left waiting forever for
/// an EOF that will never come. We keep relaying downstream data until the
/// *remote* side reports EOF or errors — only then does the whole proxy end.
async fn relay<R, W, S>(mut input: R, mut output: W, mut stream: S) -> Result<(), TunnelError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut up = [0u8; 8192];
    let mut down = [0u8; 8192];
    let mut input_open = true;

    loop {
        tokio::select! {
            n = input.read(&mut up), if input_open => match n {
                Ok(0) | Err(_) => {
                    input_open = false;
                    stream.shutdown().await?;
                }
                Ok(n) => stream.write_all(&up[..n]).await?,
            },
            n = stream.read(&mut down) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => { output.write_all(&down[..n]).await?; output.flush().await?; }
            },
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Regression coverage for `relay`'s half-close behaviour, driven by
    //! `tokio::io::duplex` pairs instead of a real terminal or a live SSH
    //! channel — same in-process technique the SSH tests use for their own
    //! regressions (`crates/liostunnel-core/src/protocols/ssh.rs`).
    use std::io::Error as IoError;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    use super::*;

    /// Always reports a hard read error, never an EOF. Stands in for a
    /// genuinely broken stdin fd, which a `tokio::io::duplex` pair alone
    /// cannot produce (closing a duplex half only ever yields a clean EOF).
    struct ErroringReader;

    impl AsyncRead for ErroringReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(IoError::other("simulated broken stdin fd")))
        }
    }

    /// The Milestone A scenario: local input closes first, but the remote
    /// still has a response in flight. Before the fix, `relay` broke its
    /// whole loop on the first `Ok(0)` from `input`, discarding a response
    /// that arrived even a moment later.
    #[tokio::test]
    async fn local_input_closing_first_does_not_discard_a_response_still_in_flight() {
        let (mut input_tx, input_rx) = tokio::io::duplex(64);
        let (output_tx, mut output_rx) = tokio::io::duplex(64);
        let (client_stream, mut server_stream) = tokio::io::duplex(64);

        // Local side writes its request, then closes -- well before the
        // remote replies, exactly like the piped `printf | ... probe` check.
        input_tx.write_all(b"request").await.unwrap();
        drop(input_tx);

        let relay_task = tokio::spawn(relay(input_rx, output_tx, client_stream));

        // Remote: read the forwarded request, then reply only after the
        // local side is already closed, and close in turn.
        let mut buf = [0u8; 64];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");
        server_stream.write_all(b"response").await.unwrap();
        drop(server_stream);

        relay_task
            .await
            .expect("relay task must not panic")
            .expect("relay must return Ok");

        let mut got = Vec::new();
        output_rx.read_to_end(&mut got).await.unwrap();
        assert_eq!(
            got, b"response",
            "a response that arrives after local EOF must not be discarded"
        );
    }

    /// The remote closing first, while the local side is still open (e.g. an
    /// interactive session where the user hasn't typed EOF), must still end
    /// the whole relay promptly rather than hang waiting on local input.
    #[tokio::test]
    async fn remote_closing_first_terminates_the_relay_promptly() {
        let (_input_tx, input_rx) = tokio::io::duplex(64); // kept open: never EOFs
        let (output_tx, mut output_rx) = tokio::io::duplex(64);
        let (client_stream, server_stream) = tokio::io::duplex(64);

        drop(server_stream); // remote closes immediately, before any local EOF

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay(input_rx, output_tx, client_stream),
        )
        .await
        .expect("relay must terminate promptly when the remote closes first")
        .expect("relay must return Ok");

        let mut got = Vec::new();
        output_rx.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());
    }

    /// The asymmetric-half-close regression: a local read *error* (not a
    /// clean EOF) must shut down the stream just as a clean EOF does. Before
    /// the fix, the `Err(_)` arm stopped polling `input` but never called
    /// `stream.shutdown()`, so the remote was never told local input was
    /// done and could wait for that EOF forever.
    #[tokio::test]
    async fn a_local_read_error_shuts_down_the_stream_not_just_local_polling() {
        let (output_tx, _output_rx) = tokio::io::duplex(64);
        let (client_stream, mut server_stream) = tokio::io::duplex(64);

        let relay_task = tokio::spawn(relay(ErroringReader, output_tx, client_stream));

        // If the read error propagated the shutdown to the remote, the
        // remote observes EOF promptly. Pre-fix, this would hang until the
        // timeout instead.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server_stream.read(&mut buf),
        )
        .await
        .expect("remote must observe EOF promptly after a local read error")
        .unwrap();
        assert_eq!(n, 0, "remote must see a clean EOF, not more data");

        drop(server_stream);
        relay_task
            .await
            .expect("relay task must not panic")
            .expect("relay must return Ok");
    }
}
