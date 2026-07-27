use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::net::Wakeup;

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
    /// Wakes the stack loop. Every operation on this type changes something the
    /// loop will act on but has no way to observe:
    ///
    /// * a write queues a chunk `pump_outbound` should pick up;
    /// * a read frees a slot in the channel `pump_inbound` stopped at, which is
    ///   how TCP-window backpressure is released;
    /// * a shutdown or a drop is the *only* signal `StackCore` gets that the
    ///   tunnel side has finished, and the one that starts its shutdown clock.
    ///
    /// Putting it here rather than in the engine is deliberate: `Drop` covers
    /// the error and cancellation paths for free, which is exactly where
    /// `poll_delay`'s contract says a hand-written notification would be
    /// forgotten.
    wake: Wakeup,
}

/// The stack-thread half. Every method here is non-blocking so it can be
/// driven from the synchronous poll loop.
pub struct StreamPeer {
    /// Push bytes read out of the smoltcp socket.
    pub to_stream: mpsc::Sender<Vec<u8>>,
    /// Pull bytes to write into the smoltcp socket.
    pub from_stream: mpsc::Receiver<Vec<u8>>,
}

pub fn local_stream_pair(depth: usize, wake: Wakeup) -> (LocalStream, StreamPeer) {
    let (to_stream, inbound) = mpsc::channel(depth);
    let (outbound, from_stream) = mpsc::channel(depth);
    (
        LocalStream {
            inbound,
            outbound: PollSender::new(outbound),
            partial: None,
            wake,
        },
        StreamPeer {
            to_stream,
            from_stream,
        },
    )
}

impl Drop for LocalStream {
    fn drop(&mut self) {
        // Both halves are closed here rather than left to the fields' own
        // drops, because `Drop::drop` runs *before* a type's fields are
        // dropped. Waking first and closing afterwards would race the loop
        // against our own teardown: it would look at `from_stream.is_closed()`,
        // still see a live sender, and go back to sleep with nothing left to
        // wake it. That is precisely the leak `poll_delay`'s contract warns
        // about, arrived at from the other direction.
        self.outbound.close();
        self.inbound.close();
        self.wake.wake();
    }
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

        loop {
            match self.inbound.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // Channel closed and drained: the application half is gone.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                // An empty chunk carries no data. Returning `Ready(Ok(()))`
                // here would be indistinguishable from the `None` case above
                // (both are a zero-progress `Ok`), so a reader would treat it
                // as EOF and stop consuming. Skip it and keep polling instead.
                Poll::Ready(Some(chunk)) if chunk.is_empty() => {
                    self.wake.wake();
                    continue;
                }
                Poll::Ready(Some(chunk)) => {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.partial = Some((chunk, n));
                    }
                    // A slot just came free. `pump_inbound` stops the moment
                    // this channel is full — that *is* the backpressure path —
                    // and it has nothing that would tell it the channel drained
                    // again. Without this wake, throughput out of the device is
                    // capped at one channel-full per idle-ceiling tick.
                    self.wake.wake();
                    return Poll::Ready(Ok(()));
                }
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
                // Queued *before* waking, so the loop cannot be woken, find the
                // channel empty, and go back to sleep on the chunk it was told
                // about.
                self.wake.wake();
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
        self.wake.wake();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A `Wakeup` that just counts.
    fn counting_wakeup() -> (Wakeup, Arc<AtomicUsize>) {
        let n = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&n);
        (
            Wakeup::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
            }),
            n,
        )
    }

    #[tokio::test]
    async fn a_write_announces_itself_to_the_stack_loop() {
        // The loop sleeps on a descriptor and a timer, and a chunk arriving in
        // this channel moves neither.
        let (wake, count) = counting_wakeup();
        let (mut stream, mut peer) = local_stream_pair(4, wake);

        stream.write_all(b"down").await.unwrap();

        assert_eq!(peer.from_stream.try_recv().unwrap(), b"down".to_vec());
        assert!(
            count.load(Ordering::SeqCst) >= 1,
            "a write must wake the loop"
        );
    }

    #[tokio::test]
    async fn a_read_announces_the_slot_it_freed() {
        // `pump_inbound` stops dead when this channel is full — that is the
        // backpressure mechanism — and has no way to learn that it drained.
        let (wake, count) = counting_wakeup();
        let (mut stream, peer) = local_stream_pair(1, wake);
        peer.to_stream.try_send(b"up".to_vec()).unwrap();

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();

        assert!(
            count.load(Ordering::SeqCst) >= 1,
            "a read must tell the loop the channel has room again"
        );
    }

    #[tokio::test]
    async fn dropping_the_stream_closes_the_channel_before_waking_the_loop() {
        // `Drop::drop` runs *before* a type's fields are dropped. A wake raised
        // there, with the closing left to the fields, is a lost wakeup: the
        // loop is woken, looks at `from_stream.is_closed()`, still sees a live
        // sender, and parks with the flow leaked. Assert the ordering itself,
        // not just that a wake happened.
        let closed_when_woken = Arc::new(Mutex::new(None::<bool>));
        let observed: Arc<Mutex<Option<mpsc::Receiver<Vec<u8>>>>> = Arc::default();

        let probe = Arc::clone(&observed);
        let record = Arc::clone(&closed_when_woken);
        let wake = Wakeup::new(move || {
            if let Some(rx) = probe.lock().unwrap().as_ref() {
                *record.lock().unwrap() = Some(rx.is_closed());
            }
        });

        let (stream, peer) = local_stream_pair(4, wake);
        *observed.lock().unwrap() = Some(peer.from_stream);

        drop(stream);

        assert_eq!(
            *closed_when_woken.lock().unwrap(),
            Some(true),
            "the channel must already read as closed by the time the loop is woken"
        );
    }

    #[tokio::test]
    async fn reading_yields_bytes_the_application_sent() {
        let (mut stream, peer) = local_stream_pair(4, Wakeup::default());
        peer.to_stream.try_send(b"hello".to_vec()).unwrap();

        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn a_short_read_buffer_leaves_the_remainder_for_the_next_read() {
        let (mut stream, peer) = local_stream_pair(4, Wakeup::default());
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
        let (mut stream, mut peer) = local_stream_pair(4, Wakeup::default());
        stream.write_all(b"down").await.unwrap();
        assert_eq!(peer.from_stream.try_recv().unwrap(), b"down".to_vec());
    }

    #[tokio::test]
    async fn dropping_the_stack_side_signals_eof() {
        let (mut stream, peer) = local_stream_pair(4, Wakeup::default());
        peer.to_stream.try_send(b"tail".to_vec()).unwrap();
        drop(peer);

        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"tail".to_vec(), "buffered data must survive the drop");
    }

    #[tokio::test]
    async fn shutting_down_the_stream_closes_the_stack_side() {
        let (mut stream, mut peer) = local_stream_pair(4, Wakeup::default());
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
    async fn an_empty_chunk_is_not_mistaken_for_eof() {
        let (mut stream, peer) = local_stream_pair(4, Wakeup::default());
        peer.to_stream.try_send(Vec::new()).unwrap();
        peer.to_stream.try_send(b"real".to_vec()).unwrap();

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            &buf, b"real",
            "the empty chunk must not terminate the stream"
        );
    }

    #[tokio::test]
    async fn a_full_channel_applies_backpressure_rather_than_buffering() {
        let (stream, peer) = local_stream_pair(1, Wakeup::default());
        peer.to_stream.try_send(vec![0u8; 8]).unwrap();
        // Depth 1 is now full: the stack thread learns to stop draining smoltcp,
        // which shrinks the TCP window. Spec §7.2.
        assert!(peer.to_stream.try_send(vec![0u8; 8]).is_err());
        drop(stream);
    }
}
