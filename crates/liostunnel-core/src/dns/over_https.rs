//! DNS-over-HTTPS `Resolver` (RFC 8484) carried through the tunnel.
//!
//! The transport is a `TunnelStream` (our own trait object over the
//! `Protocol`'s channel), not a `TcpStream`, so `reqwest` is not usable here
//! -- hyper's connection API is driven directly over our own IO, wrapped in
//! `tokio_rustls` for TLS and `hyper_util::rt::TokioIo` to bridge tokio's
//! `AsyncRead`/`AsyncWrite` to hyper's own `Read`/`Write` traits. Spec §7.6,
//! §9.1.
//!
//! ## The bootstrap problem
//!
//! Resolving a DoH server's own hostname (e.g. `cloudflare-dns.com`) would
//! itself require DNS -- a chicken-and-egg problem. This is solved by
//! config, not code: `dns.servers` holds IP literals (never resolved), and
//! `DohConfig::sni` supplies the TLS server name separately. The channel is
//! opened to an IP address; TLS is verified against the configured SNI.
//! Nothing here ever calls a resolver to get started.
//!
//! ## What this module bounds, and what it doesn't
//!
//! Per query, this module guarantees two things: the response body is never
//! collected past [`crate::dns::MAX_UDP_PAYLOAD`] bytes (via
//! `http_body_util::Limited`, checked below), and the query is time-bounded
//! by `timeout` no matter how the far end behaves. Neither of those says
//! anything about how many queries run *concurrently* -- exactly the same
//! situation `over_tcp::TcpResolver` documents on itself. Nothing in this
//! module, in the `Resolver` trait, or in the `Protocol` trait's contract
//! caps concurrent in-flight queries; that bound today comes entirely from
//! `SshTunnel::open_tcp_stream` being gated by `MAX_CONCURRENT_CHANNELS`
//! (64, `protocols/ssh.rs`), shared with ordinary proxied TCP flows and with
//! `TcpResolver`'s own channels. A future `Protocol` impl that does not
//! throttle concurrent `open_tcp_stream` calls the same way would not
//! inherit that ceiling for free, and neither `DohResolver` nor its caller
//! would catch that on its own.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;

use crate::config::profile::DohConfig;
use crate::dns::{MAX_UDP_PAYLOAD, Resolver};
use crate::error::TunnelError;
use crate::protocols::Protocol;

const HTTPS_PORT: u16 = 443;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MEDIA_TYPE: &str = "application/dns-message";

/// DNS-over-HTTPS (RFC 8484) carried through the tunnel. See the module doc
/// for the bootstrap argument and what concurrency bound this type does (and
/// doesn't) provide on its own.
pub struct DohResolver {
    protocol: Arc<dyn Protocol>,
    servers: Vec<IpAddr>,
    doh: DohConfig,
    timeout: Duration,
}

impl DohResolver {
    pub fn new(protocol: Arc<dyn Protocol>, servers: Vec<IpAddr>, doh: DohConfig) -> Self {
        Self {
            protocol,
            servers,
            doh,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Pure request construction, so the wire shape is testable without a server.
pub fn build_doh_request(
    sni: &str,
    path: &str,
    query: &[u8],
) -> Result<http::Request<Full<Bytes>>, TunnelError> {
    if sni.trim().is_empty() {
        return Err(TunnelError::Dns("dns.https.sni must not be empty".into()));
    }
    if !path.starts_with('/') {
        return Err(TunnelError::Dns(
            "dns.https.path must start with `/`".into(),
        ));
    }

    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{sni}{path}"))
        .header(http::header::HOST, sni)
        .header(http::header::CONTENT_TYPE, MEDIA_TYPE)
        .header(http::header::ACCEPT, MEDIA_TYPE)
        .header(http::header::CONTENT_LENGTH, query.len().to_string())
        .body(Full::new(Bytes::copy_from_slice(query)))
        .map_err(|e| TunnelError::Dns(format!("cannot build DoH request: {e}")))
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Collects `body` into memory, refusing to buffer past `limit` bytes no
/// matter what the far end sends or claims.
///
/// The far end is never trusted: `http_body_util::BodyExt::collect` on its
/// own will buffer an unbounded response, so the body is wrapped in
/// [`Limited`] first -- a claimed or actual length past `limit` surfaces as
/// a plain `Err` from the very next frame that would exceed it, not an
/// ever-growing allocation.
async fn collect_bounded<B>(body: B, limit: usize) -> Result<Vec<u8>, TunnelError>
where
    B: hyper::body::Body<Data = Bytes> + Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let collected = Limited::new(body, limit)
        .collect()
        .await
        .map_err(|e| TunnelError::Dns(format!("cannot read DoH response body: {e}")))?;
    Ok(collected.to_bytes().to_vec())
}

impl DohResolver {
    async fn query_one(&self, server: IpAddr, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        // The channel is opened to an IP literal; TLS is verified against
        // the configured SNI. This is what removes the bootstrap loop --
        // see the module doc.
        let stream = self
            .protocol
            .open_tcp_stream(SocketAddr::new(server, HTTPS_PORT))
            .await?;

        let name = rustls::pki_types::ServerName::try_from(self.doh.sni.clone())
            .map_err(|e| TunnelError::Dns(format!("invalid SNI `{}`: {e}", self.doh.sni)))?;

        let tls = tokio_rustls::TlsConnector::from(tls_config())
            .connect(name, stream)
            .await
            .map_err(|e| TunnelError::Dns(format!("TLS handshake with {server} failed: {e}")))?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| TunnelError::Dns(format!("HTTP handshake failed: {e}")))?;

        // The connection task drives IO to completion; it ends on its own
        // once `sender` (below) is dropped and any response in flight has
        // finished, at which point the TLS/TCP stream it owns drops with
        // it. Nothing here holds `conn` itself past this spawn, so the task
        // -- and the channel it holds open -- cannot outlive `query_one`.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(%e, "DoH connection closed");
            }
        });

        let req = build_doh_request(&self.doh.sni, &self.doh.path, query)?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| TunnelError::Dns(format!("DoH request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(TunnelError::Dns(format!(
                "resolver answered HTTP {}",
                resp.status()
            )));
        }

        // Cheap, early rejection when the far end is honest about an
        // oversized answer -- avoids polling a single frame of a body we
        // already know is too large. `collect_bounded` below is the actual
        // guarantee (it also catches a lying or absent Content-Length, e.g.
        // chunked transfer encoding).
        if let Some(len) = resp
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            && len > MAX_UDP_PAYLOAD
        {
            return Err(TunnelError::Dns(format!(
                "resolver answered with a {len}-byte body, over the {MAX_UDP_PAYLOAD}-byte limit"
            )));
        }

        let body = collect_bounded(resp.into_body(), MAX_UDP_PAYLOAD).await?;
        if body.is_empty() {
            return Err(TunnelError::Dns("resolver returned an empty body".into()));
        }
        Ok(body)
    }
}

#[async_trait]
impl Resolver for DohResolver {
    async fn query(&self, query: &[u8]) -> Result<Vec<u8>, TunnelError> {
        if self.servers.is_empty() {
            return Err(TunnelError::Dns("no DNS servers configured".into()));
        }

        let mut last = None;
        for server in &self.servers {
            match tokio::time::timeout(self.timeout, self.query_one(*server, query)).await {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(e)) => {
                    tracing::debug!(%server, %e, "DoH resolver failed; trying the next");
                    last = Some(e);
                }
                Err(_) => {
                    tracing::debug!(%server, "DoH resolver timed out; trying the next");
                    last = Some(TunnelError::Dns(format!("{server} timed out")));
                }
            }
        }
        Err(last.unwrap_or_else(|| TunnelError::Dns("all DoH resolvers failed".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_targets_the_configured_sni_and_path() {
        let req = build_doh_request("cloudflare-dns.com", "/dns-query", b"\xAB\xCDq").unwrap();
        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(
            req.uri().to_string(),
            "https://cloudflare-dns.com/dns-query"
        );
    }

    #[test]
    fn the_request_declares_the_dns_message_media_type_both_ways() {
        // RFC 8484 §4.1 — a DoH server may refuse anything else.
        let req = build_doh_request("dns.google", "/dns-query", b"\xAB\xCDq").unwrap();
        assert_eq!(req.headers()["content-type"], "application/dns-message");
        assert_eq!(req.headers()["accept"], "application/dns-message");
        // `b"\xAB\xCDq"` is 3 bytes (0xAB, 0xCD, 'q'), not 5 — the brief's
        // own assertion here claimed "5", which `Content-Length` must
        // never fabricate to match; it always reflects the actual body.
        assert_eq!(req.headers()["content-length"], "3");
    }

    #[test]
    fn a_path_without_a_leading_slash_is_rejected() {
        assert!(build_doh_request("dns.google", "dns-query", b"q").is_err());
    }

    #[test]
    fn an_empty_sni_is_rejected() {
        assert!(build_doh_request("", "/dns-query", b"q").is_err());
    }

    // --- Response-size bounding -----------------------------------------
    //
    // `collect_bounded` is the guarantee that a hostile or buggy resolver
    // cannot make this module allocate without limit. Exercised directly
    // against a `Full<Bytes>` body -- a real `hyper`/TLS round trip isn't
    // needed to prove the bounding logic itself, only a `Body` impl, and
    // `Full` is the simplest one available.

    #[tokio::test]
    async fn a_body_within_the_limit_is_collected_whole() {
        let body = Full::new(Bytes::from_static(b"\xAB\xCDanswer"));
        let got = collect_bounded(body, MAX_UDP_PAYLOAD).await.unwrap();
        assert_eq!(got, b"\xAB\xCDanswer".to_vec());
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_rejected_not_buffered_whole() {
        // One byte past a small limit, not `MAX_UDP_PAYLOAD` itself -- this
        // keeps the test fast while still proving the boundary is a real
        // rejection, not a coincidence of the specific size chosen.
        let limit = 8;
        let body = Full::new(Bytes::from(vec![0xAAu8; limit + 1]));
        let err = collect_bounded(body, limit)
            .await
            .expect_err("a body one byte past the limit must be rejected");
        assert!(matches!(err, TunnelError::Dns(_)));
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_limit_is_still_accepted() {
        let limit = 8;
        let body = Full::new(Bytes::from(vec![0xAAu8; limit]));
        let got = collect_bounded(body, limit).await.unwrap();
        assert_eq!(got.len(), limit);
    }

    /// Exercises the real path against a public resolver. Not part of the
    /// default suite — it needs outbound network.
    #[tokio::test]
    #[ignore = "requires outbound network access to 1.1.1.1:443"]
    async fn resolves_a_real_name_over_the_public_internet() {
        use crate::dns::testutil::DirectProtocol;
        use std::sync::Arc;

        let r = DohResolver::new(
            Arc::new(DirectProtocol),
            vec!["1.1.1.1".parse().unwrap()],
            crate::config::profile::DohConfig {
                sni: "cloudflare-dns.com".into(),
                path: "/dns-query".into(),
            },
        );

        // A minimal query for example.com A, transaction id 0xABCD.
        let query: Vec<u8> = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let answer = r.query(&query).await.unwrap();
        assert_eq!(&answer[..2], &[0xAB, 0xCD], "transaction id must be echoed");
        assert!(answer.len() > query.len(), "an answer carries records");
    }
}
