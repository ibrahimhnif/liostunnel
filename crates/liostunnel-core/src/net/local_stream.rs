use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// The tokio-side handle for one proxied TCP connection.
///
/// Reading yields bytes the application on the device sent (they are on their
/// way *out* through the tunnel). Writing delivers bytes that came back from
/// the tunnel *to* the application. Spec §7.2.
pub struct LocalStream {
    /// Bytes from the device.
    inbound: mpsc::Receiver<Vec<u8>>,
    /// Bytes towards the device.
    outbound: PollSender<Vec<u8>>,
    /// Remainder of a chunk that did not fit the caller's buffer.
    partial: Option<(Vec<u8>, usize)>,
}

/// The stack-thread half. Every method here is non-blocking so it can be
/// driven from the synchronous poll loop.
pub struct StreamPeer {
    /// Push bytes read out of the smoltcp socket.
    pub to_stream: mpsc::Sender<Vec<u8>>,
    /// Pull bytes to write into the smoltcp socket.
    pub from_stream: mpsc::Receiver<Vec<u8>>,
}

pub fn local_stream_pair(depth: usize) -> (LocalStream, StreamPeer) {
    let (to_stream, inbound) = mpsc::channel(depth);
    let (outbound, from_stream) = mpsc::channel(depth);
    (
        LocalStream {
            inbound,
            outbound: PollSender::new(outbound),
            partial: None,
        },
        StreamPeer {
            to_stream,
            from_stream,
        },
    )
}

impl AsyncRead for LocalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Serve any leftover from a previous chunk first.
        if let Some((chunk, offset)) = self.partial.take() {
            let n = (chunk.len() - offset).min(buf.remaining());
            buf.put_slice(&chunk[offset..offset + n]);
            if offset + n < chunk.len() {
                self.partial = Some((chunk, offset + n));
            }
            return Poll::Ready(Ok(()));
        }

        match self.inbound.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            // Channel closed and drained: the application half is gone.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.partial = Some((chunk, n));
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.outbound.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "packet stack closed this flow",
            ))),
            Poll::Ready(Ok(())) => {
                let n = buf.len();
                self.outbound.send_item(buf.to_vec()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "flow closed")
                })?;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Delivery is the channel's job; there is no buffer of our own to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Closing the sender makes the stack thread see EOF and emit FIN.
        self.outbound.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reading_yields_bytes_the_application_sent() {
        let (mut stream, peer) = local_stream_pair(4);
        peer.to_stream.try_send(b"hello".to_vec()).unwrap();

        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn a_short_read_buffer_leaves_the_remainder_for_the_next_read() {
        let (mut stream, peer) = local_stream_pair(4);
        peer.to_stream.try_send(b"abcdef".to_vec()).unwrap();

        let mut first = [0u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ab");

        let mut rest = [0u8; 4];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"cdef");
    }

    #[tokio::test]
    async fn writing_delivers_bytes_towards_the_application() {
        let (mut stream, mut peer) = local_stream_pair(4);
        stream.write_all(b"down").await.unwrap();
        assert_eq!(peer.from_stream.try_recv().unwrap(), b"down".to_vec());
    }

    #[tokio::test]
    async fn dropping_the_stack_side_signals_eof() {
        let (mut stream, peer) = local_stream_pair(4);
        peer.to_stream.try_send(b"tail".to_vec()).unwrap();
        drop(peer);

        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"tail".to_vec(), "buffered data must survive the drop");
    }

    #[tokio::test]
    async fn shutting_down_the_stream_closes_the_stack_side() {
        let (mut stream, mut peer) = local_stream_pair(4);
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);

        assert_eq!(peer.from_stream.recv().await, Some(b"x".to_vec()));
        assert_eq!(
            peer.from_stream.recv().await,
            None,
            "closed channel must report None"
        );
    }

    #[tokio::test]
    async fn a_full_channel_applies_backpressure_rather_than_buffering() {
        let (stream, peer) = local_stream_pair(1);
        peer.to_stream.try_send(vec![0u8; 8]).unwrap();
        // Depth 1 is now full: the stack thread learns to stop draining smoltcp,
        // which shrinks the TCP window. Spec §7.2.
        assert!(peer.to_stream.try_send(vec![0u8; 8]).is_err());
        drop(stream);
    }
}
