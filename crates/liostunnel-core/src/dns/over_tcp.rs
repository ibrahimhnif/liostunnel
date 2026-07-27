//! DNS-over-TCP `Resolver` (RFC 7766 two-byte length prefix over
//! `Protocol::open_tcp_stream`). Reserved for Task 19.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::dns::Resolver;
use crate::error::TunnelError;
use crate::protocols::Protocol;

const DNS_PORT: u16 = 53;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Plain DNS carried over a TCP channel through the tunnel, framed per RFC 7766
/// with a two-byte big-endian length prefix. The zero-dependency default that
/// makes DNS work at all when the protocol cannot forward UDP. Decision D3.
///
/// ## What this type bounds, and what it doesn't
///
/// `query_one`'s doc comment below covers the *per-query* guarantee: one
/// call here allocates at most one 65,535-byte answer buffer (RFC 1035's own
/// ceiling) and is bounded in time by `timeout`, no matter how the far end
/// misbehaves. That guarantee is real, but it is per query, not per system:
/// nothing in `TcpResolver`, in the `Resolver` trait, or in the `Protocol`
/// trait's contract limits how many queries run *concurrently*.
/// `engine.rs`'s `spawn_dns_query` hands every inbound UDP:53 datagram its
/// own `tokio::spawn` with no semaphore of its own, so nothing here caps
/// aggregate memory across many simultaneous in-flight queries.
///
/// What actually bounds that today, in the deployed system, is a property of
/// the *`Protocol` implementation* in use, not of this module:
/// `SshTunnel::open_tcp_stream` is gated by `MAX_CONCURRENT_CHANNELS` (64,
/// `protocols/ssh.rs`), shared with ordinary proxied TCP flows, which caps
/// worst-case simultaneous answer buffers at roughly 64 * 65,535 bytes
/// (~4.2 MB). That is `SshTunnel`'s own choice, not something the
/// `Resolver`/`Protocol` trait contracts require -- a future `Protocol` impl
/// that does not throttle concurrent `open_tcp_stream` calls the same way
/// would not inherit that ceiling for free, and neither `TcpResolver` nor
/// `engine.rs`'s dispatch loop would catch that on its own. Fixing that
/// properly (a concurrency limit at the dispatch layer, independent of
/// whatever the `Protocol` impl happens to do) belongs to `engine.rs`, not
/// here.
pub struct TcpResolver {
    protocol: Arc<dyn Protocol>,
    servers: Vec<IpAddr>,
    timeout: Duration,
}

impl TcpResolver {
    pub fn new(protocol: Arc<dyn Protocol>, servers: Vec<IpAddr>) -> Self {
        Self {
            protocol,
            servers,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Sends `query` to `server` and returns its answer, framed per RFC 7766.
    ///
    /// The far end is never trusted: the claimed answer length is bounded by
    /// `u16` (RFC 1035's own ceiling, 65,535 bytes) before anything is
    /// allocated, so a hostile or buggy resolver can make this allocate at
    /// most one legal-sized answer buffer, never more. A short read, a
    /// mid-answer close, or a claimed length that the far end never actually
    /// sends all surface as a plain `Err` from `read_exact` -- never a panic,
    /// never an unbounded read. The overall wall-clock bound against a
    /// resolver that claims a length and then sends nothing at all is the
    /// caller's `tokio::time::timeout`, not this function.
    ///
    /// This is a per-call guarantee only -- see `TcpResolver`'s own doc for
    /// what (and what doesn't) bound how many of these run at once.
    async fn query_one(&self, server: IpAddr, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        let dest = SocketAddr::new(server, DNS_PORT);
        let mut stream = self.protocol.open_tcp_stream(dest).await?;

        // The caller (`query`) already rejected anything over `u16::MAX`, so
        // this cannot fail -- kept as a `try_from` rather than an
        // unchecked cast so a future refactor that removes that guard fails
        // loudly here instead of silently wrapping.
        let len = u16::try_from(query.len())
            .map_err(|_| TunnelError::Dns("query exceeds 65535 bytes".into()))?;

        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot send query length: {e}")))?;
        stream
            .write_all(query)
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot send query: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot flush query: {e}")))?;

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot read answer length: {e}")))?;

        let n = u16::from_be_bytes(len_buf) as usize;
        if n == 0 {
            return Err(TunnelError::Dns("resolver returned an empty answer".into()));
        }
        // `n` is a `u16` value (at most 65,535), so this is a single bounded
        // allocation no matter what the far end claims -- never unbounded,
        // never a read that continues past what was declared.
        let mut answer = vec![0u8; n];
        stream
            .read_exact(&mut answer)
            .await
            .map_err(|e| TunnelError::Dns(format!("cannot read answer: {e}")))?;

        Ok(answer)
    }
}

#[async_trait]
impl Resolver for TcpResolver {
    async fn query(&self, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        if self.servers.is_empty() {
            return Err(TunnelError::Dns("no DNS servers configured".into()));
        }
        // Reject before opening a channel, so a malformed query costs nothing.
        if u16::try_from(query.len()).is_err() {
            return Err(TunnelError::Dns("query exceeds 65535 bytes".into()));
        }

        let mut last = None;
        for server in &self.servers {
            match tokio::time::timeout(self.timeout, self.query_one(*server, query)).await {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(e)) => {
                    tracing::debug!(%server, %e, "resolver failed; trying the next");
                    last = Some(e);
                }
                Err(_) => {
                    tracing::debug!(%server, "resolver timed out; trying the next");
                    last = Some(TunnelError::Dns(format!("{server} timed out")));
                }
            }
        }
        Err(last.unwrap_or_else(|| TunnelError::Dns("all resolvers failed".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::TunnelStream;
    use crate::stats::ConnectionStats;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Speaks RFC 7766 on the far end of the "tunnel": reads a length-prefixed
    /// query and answers with a length-prefixed response.
    struct EchoDnsProtocol {
        asked: Mutex<Vec<SocketAddr>>,
        answer: Vec<u8>,
        refuse: bool,
        /// The exact two bytes of the query's length prefix this protocol
        /// observed on the wire. `Arc`-wrapped (unlike `asked`, which is
        /// mutated synchronously before the spawn below) because capturing
        /// it requires actually reading from the far end, which only
        /// happens inside the spawned task -- this is the shared handle
        /// that lets the test observe it afterward. A framing regression
        /// (wrong byte order, an off-by-one in the length) shows up here as
        /// a direct mismatch rather than a hang or a confusing parse error.
        observed_len_prefix: Arc<Mutex<Option<[u8; 2]>>>,
    }

    #[async_trait]
    impl crate::protocols::Protocol for EchoDnsProtocol {
        async fn connect(
            &mut self,
            _p: &crate::config::profile::ServerProfile,
            _s: &dyn crate::config::secret::SecretStore,
        ) -> Result<(), TunnelError> {
            Ok(())
        }

        async fn open_tcp_stream(
            &self,
            dest: SocketAddr,
        ) -> Result<Box<dyn TunnelStream>, TunnelError> {
            self.asked.lock().unwrap().push(dest);
            if self.refuse {
                return Err(TunnelError::Protocol("refused".into()));
            }
            let (near, mut far) = tokio::io::duplex(4096);
            let answer = self.answer.clone();
            let observed_len_prefix = self.observed_len_prefix.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if far.read_exact(&mut len).await.is_err() {
                    return;
                }
                *observed_len_prefix.lock().unwrap() = Some(len);
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if far.read_exact(&mut q).await.is_err() {
                    return;
                }
                let _ = far.write_all(&(answer.len() as u16).to_be_bytes()).await;
                let _ = far.write_all(&answer).await;
            });
            Ok(Box::new(near))
        }

        async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
            Err(TunnelError::Unsupported("udp"))
        }
        async fn disconnect(&mut self) -> Result<(), TunnelError> {
            Ok(())
        }
        fn stats(&self) -> ConnectionStats {
            ConnectionStats::default()
        }
    }

    fn proto(answer: &[u8], refuse: bool) -> Arc<EchoDnsProtocol> {
        Arc::new(EchoDnsProtocol {
            asked: Mutex::new(Vec::new()),
            answer: answer.to_vec(),
            refuse,
            observed_len_prefix: Arc::new(Mutex::new(None)),
        })
    }

    #[tokio::test]
    async fn a_query_is_framed_with_a_two_byte_length_and_the_answer_unframed() {
        let p = proto(b"\xAB\xCDanswer-bytes", false);
        let r = TcpResolver::new(p.clone(), vec!["1.1.1.1".parse().unwrap()]);

        let got = r.query(b"\xAB\xCDquery").await.unwrap();
        assert_eq!(got, b"\xAB\xCDanswer-bytes".to_vec());
        assert_eq!(
            p.asked.lock().unwrap().as_slice(),
            &["1.1.1.1:53".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn the_next_server_is_tried_when_the_first_is_unreachable() {
        let p = proto(b"", true);
        let r = TcpResolver::new(
            p.clone(),
            vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
        );

        assert!(r.query(b"\xAB\xCDq").await.is_err());
        assert_eq!(
            p.asked.lock().unwrap().len(),
            2,
            "both configured resolvers must be attempted"
        );
    }

    #[tokio::test]
    async fn an_oversized_query_is_rejected_before_it_reaches_the_wire() {
        let p = proto(b"x", false);
        let r = TcpResolver::new(p.clone(), vec!["1.1.1.1".parse().unwrap()]);

        let huge = vec![0u8; 70_000];
        assert!(r.query(&huge).await.is_err());
        assert!(
            p.asked.lock().unwrap().is_empty(),
            "must not open a channel"
        );
    }

    #[tokio::test]
    async fn no_configured_servers_is_an_error_not_a_hang() {
        let p = proto(b"x", false);
        let r = TcpResolver::new(p, vec![]);
        assert!(r.query(b"\xAB\xCDq").await.is_err());
    }

    #[tokio::test]
    async fn the_outbound_length_prefix_is_the_exact_big_endian_query_length() {
        // A direct byte-level check on the frame itself: without this, an
        // off-by-one in the outbound prefix would surface only as the mock
        // reading a garbled or short query and failing in some other,
        // harder-to-diagnose way -- not as a clear assertion on the bytes
        // that were actually sent.
        let p = proto(b"\xAB\xCDans", false);
        let r = TcpResolver::new(p.clone(), vec!["1.1.1.1".parse().unwrap()]);
        let query = b"\xAB\xCDquery-of-a-specific-length";

        r.query(query).await.unwrap();

        let observed = p
            .observed_len_prefix
            .lock()
            .unwrap()
            .expect("the far end must have received a two-byte length prefix");
        assert_eq!(
            observed,
            (query.len() as u16).to_be_bytes(),
            "the outbound prefix must be the query's own length, big-endian"
        );
    }

    // --- Hostile far-end coverage --------------------------------------
    //
    // The far end of `open_tcp_stream` is never trusted: it controls the
    // length prefix entirely, and can lie about it in every direction —
    // claim more than it sends, claim zero, close mid-frame, or claim the
    // legal maximum and never deliver. Every one of these must come back as
    // a plain `Err`, never a panic, an unbounded allocation, or a hang.

    /// Consumes a framed query like `EchoDnsProtocol`, then writes back
    /// exactly `reply` (no framing added — the test controls the bytes,
    /// including a length prefix that lies about what follows). If
    /// `hold_open` is set, the channel is kept alive afterward instead of
    /// being dropped, standing in for a resolver that accepted the query
    /// and then simply never answers; otherwise the channel closes right
    /// after `reply`, standing in for one that answers partially (or not at
    /// all) and hangs up.
    struct HostileDnsProtocol {
        reply: Vec<u8>,
        hold_open: bool,
    }

    #[async_trait]
    impl crate::protocols::Protocol for HostileDnsProtocol {
        async fn connect(
            &mut self,
            _p: &crate::config::profile::ServerProfile,
            _s: &dyn crate::config::secret::SecretStore,
        ) -> Result<(), TunnelError> {
            Ok(())
        }

        async fn open_tcp_stream(
            &self,
            _dest: SocketAddr,
        ) -> Result<Box<dyn TunnelStream>, TunnelError> {
            let (near, mut far) = tokio::io::duplex(4096);
            let reply = self.reply.clone();
            let hold_open = self.hold_open;
            tokio::spawn(async move {
                // Drain the framed query so the near side's `write_all`
                // never blocks on a full duplex buffer.
                let mut len = [0u8; 2];
                if far.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if far.read_exact(&mut q).await.is_err() {
                    return;
                }
                let _ = far.write_all(&reply).await;
                if hold_open {
                    // Keep the channel alive instead of dropping `far` --
                    // dropping it here would surface as a clean EOF, not
                    // the genuine hang this is meant to simulate. The test
                    // that uses this drops its own runtime long before this
                    // fires.
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            });
            Ok(Box::new(near))
        }

        async fn send_udp(&self, _d: SocketAddr, _b: &[u8]) -> Result<(), TunnelError> {
            Err(TunnelError::Unsupported("udp"))
        }
        async fn disconnect(&mut self) -> Result<(), TunnelError> {
            Ok(())
        }
        fn stats(&self) -> ConnectionStats {
            ConnectionStats::default()
        }
    }

    #[tokio::test]
    async fn a_claimed_length_of_zero_is_rejected_rather_than_treated_as_a_valid_answer() {
        let p = Arc::new(HostileDnsProtocol {
            reply: vec![0x00, 0x00],
            hold_open: false,
        });
        let r = TcpResolver::new(p, vec!["1.1.1.1".parse().unwrap()]);
        let err = r
            .query(b"\xAB\xCDq")
            .await
            .expect_err("a claimed length of zero must not be treated as a valid answer");
        assert!(matches!(err, TunnelError::Dns(_)));
    }

    #[tokio::test]
    async fn an_answer_shorter_than_its_own_claimed_length_is_a_clean_error() {
        // Claims 50 bytes, delivers 10, then the channel closes: must
        // surface as `Err`, never hang waiting for bytes that never come
        // and never panic reading past what was actually sent.
        let mut reply = vec![0x00, 0x32]; // claims 50 bytes
        reply.extend(vec![0xAA; 10]); // delivers 10
        let p = Arc::new(HostileDnsProtocol {
            reply,
            hold_open: false,
        });
        let r = TcpResolver::new(p, vec!["1.1.1.1".parse().unwrap()]);
        let err = r
            .query(b"\xAB\xCDq")
            .await
            .expect_err("an answer shorter than its own claimed length must be a clean error");
        assert!(matches!(err, TunnelError::Dns(_)));
    }

    #[tokio::test]
    async fn a_close_during_the_two_byte_length_prefix_itself_is_a_clean_error() {
        let p = Arc::new(HostileDnsProtocol {
            reply: vec![0x00], // one byte of the required two, then EOF
            hold_open: false,
        });
        let r = TcpResolver::new(p, vec!["1.1.1.1".parse().unwrap()]);
        let err = r
            .query(b"\xAB\xCDq")
            .await
            .expect_err("a close mid length-prefix must be a clean error");
        assert!(matches!(err, TunnelError::Dns(_)));
    }

    #[tokio::test]
    async fn a_connection_that_accepts_the_query_and_sends_nothing_at_all_is_a_clean_error() {
        // Distinct from the "claims a length and never delivers it" case
        // below: here the far end never sends even the first byte of the
        // length prefix -- it accepts the query and closes immediately, the
        // literal "sends nothing" case rather than "claims something and
        // stalls."
        let p = Arc::new(HostileDnsProtocol {
            reply: vec![],
            hold_open: false,
        });
        let r = TcpResolver::new(p, vec!["1.1.1.1".parse().unwrap()]);
        let err = r
            .query(b"\xAB\xCDq")
            .await
            .expect_err("a connection that sends nothing at all must be a clean error");
        assert!(matches!(err, TunnelError::Dns(_)));
    }

    #[tokio::test]
    async fn a_maximal_claimed_length_with_nothing_behind_it_is_a_clean_error_not_a_stall() {
        // The far end claims the RFC 1035 ceiling (65,535 bytes) and closes
        // immediately. Must allocate at most one bounded buffer and fail
        // cleanly and quickly, not hang trying to read bytes that were
        // never sent.
        let p = Arc::new(HostileDnsProtocol {
            reply: vec![0xFF, 0xFF],
            hold_open: false,
        });
        let r = TcpResolver::new(p, vec!["1.1.1.1".parse().unwrap()]);
        let err = tokio::time::timeout(Duration::from_secs(2), r.query(b"\xAB\xCDq"))
            .await
            .expect("must fail promptly, not stall")
            .expect_err("a maximal claim with nothing behind it must be a clean error");
        assert!(matches!(err, TunnelError::Dns(_)));
    }

    #[tokio::test]
    async fn a_resolver_that_claims_an_answer_and_then_never_sends_it_times_out() {
        let p = Arc::new(HostileDnsProtocol {
            reply: vec![0xFF, 0xFF],
            hold_open: true,
        });
        let mut r = TcpResolver::new(p, vec!["1.1.1.1".parse().unwrap()]);
        // The production default is 5s; shortened here only so the test
        // itself stays fast. The outer bound below is a generous safety net
        // in case this guard regresses -- it should never actually be hit.
        r.timeout = Duration::from_millis(50);
        let outcome = tokio::time::timeout(Duration::from_secs(2), r.query(b"\xAB\xCDq")).await;
        let result = outcome.expect(
            "the resolver's own timeout must fire well inside this outer bound -- if it \
             doesn't, the internal timeout guard has regressed",
        );
        assert!(result.is_err());
    }
}
