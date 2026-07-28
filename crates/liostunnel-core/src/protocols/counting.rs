use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a tunnel stream and accumulates byte counters for [`crate::stats`].
/// Counts bytes only — never inspects or records payload content. Spec §11.
pub struct CountingStream<S> {
    inner: S,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
    /// Released when the stream drops, bounding concurrent SSH channels.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<S> CountingStream<S> {
    pub fn new(
        inner: S,
        up: Arc<AtomicU64>,
        down: Arc<AtomicU64>,
        active: Arc<AtomicU64>,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self {
            inner,
            up,
            down,
            active,
            _permit: permit,
        }
    }
}

impl<S> Drop for CountingStream<S> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = buf.filled().len().saturating_sub(before);
            self.down.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.up.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The bytes reported to a UI are counted here and nowhere else.
    ///
    /// Until this module had tests, the only assertion that these counters
    /// move on real traffic lived in an `#[ignore]`d integration test behind a
    /// Docker fixture. The engine's own test proves `StatsHandle` *forwards*
    /// whatever the protocol reports — with a mock written in the same commit
    /// to report exactly the fields it reads. Neither would have caught a
    /// counter that simply never incremented.
    fn counters() -> (Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>) {
        (
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
    }

    #[tokio::test]
    async fn writing_counts_exactly_the_bytes_written() {
        let (up, down, active) = counters();
        let (near, mut far) = tokio::io::duplex(1024);
        let mut s = CountingStream::new(near, up.clone(), down.clone(), active.clone(), None);

        s.write_all(b"hello world").await.unwrap();
        s.flush().await.unwrap();

        assert_eq!(up.load(Ordering::Relaxed), 11, "one byte per byte written");
        assert_eq!(down.load(Ordering::Relaxed), 0, "nothing was read");

        let mut sink = [0u8; 11];
        far.read_exact(&mut sink).await.unwrap();
        assert_eq!(&sink, b"hello world", "and the payload is untouched");
    }

    #[tokio::test]
    async fn reading_counts_exactly_the_bytes_read() {
        let (up, down, active) = counters();
        let (near, mut far) = tokio::io::duplex(1024);
        let mut s = CountingStream::new(near, up.clone(), down.clone(), active.clone(), None);

        far.write_all(b"0123456789").await.unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).await.unwrap();

        assert_eq!(down.load(Ordering::Relaxed), 10);
        assert_eq!(up.load(Ordering::Relaxed), 0, "nothing was written");
    }

    #[tokio::test]
    async fn the_two_directions_are_not_confused() {
        // Distinct sizes, so a swapped pair of counters cannot pass.
        let (up, down, active) = counters();
        let (near, mut far) = tokio::io::duplex(1024);
        let mut s = CountingStream::new(near, up.clone(), down.clone(), active.clone(), None);

        s.write_all(&[0u8; 7]).await.unwrap();
        s.flush().await.unwrap();
        let mut drain = [0u8; 7];
        far.read_exact(&mut drain).await.unwrap();

        far.write_all(&[0u8; 3]).await.unwrap();
        let mut buf = [0u8; 3];
        s.read_exact(&mut buf).await.unwrap();

        assert_eq!(up.load(Ordering::Relaxed), 7, "up is what we sent");
        assert_eq!(down.load(Ordering::Relaxed), 3, "down is what we received");
    }

    #[tokio::test]
    async fn a_partial_write_counts_only_what_was_accepted() {
        // The counter follows poll_write's return value, not the buffer's
        // length: counting the whole buffer on a short write would inflate the
        // reported total over a slow link, which is exactly when a user looks.
        let (up, down, active) = counters();
        let (near, mut far) = tokio::io::duplex(4);
        let mut s = CountingStream::new(near, up.clone(), down.clone(), active.clone(), None);

        let n = s.write(&[0u8; 64]).await.unwrap();
        assert!(n <= 4, "the pipe cannot take more than its capacity");
        assert_eq!(up.load(Ordering::Relaxed), n as u64, "counted what went");

        let mut drain = vec![0u8; n];
        far.read_exact(&mut drain).await.unwrap();
        assert_eq!(down.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn the_active_count_falls_when_the_stream_is_dropped() {
        let (up, down, active) = counters();
        let (near, _far) = tokio::io::duplex(64);
        let s = CountingStream::new(near, up, down, active.clone(), None);
        assert_eq!(active.load(Ordering::Relaxed), 1);
        drop(s);
        assert_eq!(active.load(Ordering::Relaxed), 0, "a flow must not leak");
    }
}
