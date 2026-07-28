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
