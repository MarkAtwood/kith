//! SSRF-safe host validator and shared tailnet HTTPS client builder.
//!
//! `is_valid_fetch_host` guards any outbound HTTP fetch initiated by the
//! daemon (e.g. fetching a peer's avatar or resource URL supplied in a
//! JMAP request).  It rejects loopback, RFC 1918, link-local, and
//! unspecified addresses so that a malicious peer cannot redirect the
//! daemon to internal services.  Plain hostnames are rejected to prevent
//! SSRF via DNS, with an explicit exception for Tailscale MagicDNS names
//! (`.ts.net` and `.tailscale.net`).
//!
//! `build_tailnet_https_client` returns a Hyper client configured to
//! accept self-signed TLS certificates from tailnet peers.  Tailscale
//! provides cryptographic identity at the network layer, so the TLS
//! certificate is used only for confidentiality, not authentication.
//!
//! `fetch_peer_blob` fetches a single attachment blob from a peer's
//! mailbox, verifies its SHA-256 hash, and writes it to the local blob store.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// When set to `true`, `is_valid_fetch_host` allows loopback addresses
/// (`127.x.x.x` and `[::1]`) to pass the SSRF guard.
///
/// This flag exists solely to enable integration tests that spin up two
/// kithd instances on 127.0.0.1 without a real tailnet.  It must never
/// be set outside `#[cfg(any(test, feature = "test-utils"))]` call sites.
#[cfg(any(test, feature = "test-utils"))]
pub static ALLOW_LOOPBACK_FOR_TESTS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ---------------------------------------------------------------------------
// SSRF validator
// ---------------------------------------------------------------------------

/// Return `true` if `host` is safe to connect to for an outbound fetch.
///
/// `host` is the authority portion of a URL: either a bare hostname/IP, or
/// `host:port` (including `[ipv6]:port`).  The function:
///
/// - Strips any `:port` suffix; rejects port 0 or anything that doesn't
///   parse as a valid `u16`.
/// - Rejects an empty host.
/// - If the host part parses as an [`IpAddr`], applies IP-range checks
///   (loopback, unspecified, RFC 1918, link-local).
/// - If it does not parse as an IP, allows Tailscale MagicDNS hostnames
///   (`.ts.net` and `.tailscale.net` suffixes) as an explicit exception.
///   All other plain hostnames are rejected: a hostname could resolve to an
///   RFC 1918 or loopback address at fetch time (SSRF via DNS).
pub(crate) fn is_valid_fetch_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    if host.contains('@') {
        return false;
    }

    // Split host from optional port.
    //
    // Formats handled:
    //   hostname          — no colon, no brackets
    //   hostname:port     — exactly one colon, port is a valid u16
    //   ipv4              — no colon (or one colon when port is absent, but
    //                       IPv4 dotted notation has no colons at all)
    //   ipv4:port         — exactly one colon
    //   [ipv6]            — bracketed, no port
    //   [ipv6]:port       — bracketed, with port
    //   ipv6              — bare (multiple colons) — no port, whole string is IP
    //
    // Disambiguation rule: if the string contains more than one colon and
    // does not start with '[', treat the whole string as a bare IPv6 address
    // (no port component).  A string with exactly one colon that does not
    // parse as an IPv6 address is treated as host:port.
    let (ip_part, port_opt): (&str, Option<u16>) = if host.starts_with('[') {
        // Bracketed IPv6
        let close = match host.find(']') {
            Some(i) => i,
            None => return false, // malformed
        };
        let bracketed = &host[1..close]; // strip [ ]
        let after = &host[close + 1..];
        if after.is_empty() {
            (bracketed, None)
        } else {
            // Must be ":port"
            let port_str = match after.strip_prefix(':') {
                Some(s) => s,
                None => return false,
            };
            let port: u16 = match port_str.parse() {
                Ok(p) => p,
                Err(_) => return false,
            };
            (bracketed, Some(port))
        }
    } else {
        // Count colons to distinguish bare IPv6 from host:port
        let colon_count = host.chars().filter(|&c| c == ':').count();

        if colon_count > 1 {
            // Multiple colons → bare IPv6 address with no port (e.g. "::1", "fe80::1")
            (host, None)
        } else if colon_count == 1 {
            // Exactly one colon → could be host:port or a pathological case.
            let colon = host.find(':').expect("one colon confirmed above");
            let maybe_port = &host[colon + 1..];
            if let Ok(port) = maybe_port.parse::<u16>() {
                (&host[..colon], Some(port))
            } else {
                // One colon but the suffix doesn't parse as a valid port
                // (e.g. "alice.ts.net:99999").  Reject it.
                return false;
            }
        } else {
            // No colon: bare hostname or IPv4 with no port
            (host, None)
        }
    };

    // Reject port 0.
    if let Some(0) = port_opt {
        return false;
    }

    // Empty host after stripping brackets/port.
    if ip_part.is_empty() {
        return false;
    }

    // Case-insensitive "localhost" check before IP parsing.
    if ip_part.eq_ignore_ascii_case("localhost") {
        return false;
    }

    // Integration-test bypass: when ALLOW_LOOPBACK_FOR_TESTS is set, permit
    // 127.x.x.x and ::1 so tests can target an in-process kithd listener.
    // This flag is only compiled in under test/test-utils builds.
    #[cfg(any(test, feature = "test-utils"))]
    if ALLOW_LOOPBACK_FOR_TESTS.load(std::sync::atomic::Ordering::Relaxed)
        && (ip_part.starts_with("127.") || ip_part == "::1")
    {
        return true;
    }

    // Try to parse as an IP address.
    let ip: IpAddr = match ip_part.parse() {
        Ok(addr) => addr,
        Err(_) => {
            // Allow Tailscale MagicDNS hostnames; reject all other plain names
            // to prevent SSRF via DNS resolution.
            if ip_part.ends_with(".ts.net") || ip_part.ends_with(".tailscale.net") {
                return true;
            }
            return false;
        }
    };

    // --- IP range checks ---

    if ip.is_loopback() {
        return false;
    }

    if ip.is_unspecified() {
        return false;
    }

    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            // RFC 1918: 10.0.0.0/8
            if octets[0] == 10 {
                return false;
            }

            // RFC 1918: 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return false;
            }

            // RFC 1918: 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return false;
            }

            // Link-local: 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return false;
            }

            // Accept only the Tailscale CGNAT range 100.64.0.0/10.
            // This covers all Tailscale IPv4 peer addresses and prevents
            // SSRF to arbitrary public internet IPs if a mailbox_host value
            // ever ends up pointing outside the tailnet.
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(v6) => {
            // Link-local: fe80::/10
            // First two bytes: 0xfe80..0xfebf (top 10 bits = 1111 1110 10)
            let segs = v6.segments();
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }

            // Accept only ULA addresses (fc00::/7), which covers Tailscale's
            // IPv6 range (fd7a:115c:a1e0::/48).  Reject all public IPv6
            // addresses to prevent SSRF to the public internet.
            (segs[0] & 0xfe00) == 0xfc00
        }
    }
}

// ---------------------------------------------------------------------------
// TailnetCertVerifier — re-exported from discovery
// ---------------------------------------------------------------------------

use crate::discovery::TailnetCertVerifier;

// ---------------------------------------------------------------------------
// HTTPS client builder
// ---------------------------------------------------------------------------

/// Percent-encode a string using the RFC 3986 unreserved character set.
///
/// Encodes all characters except RFC 3986 unreserved characters
/// (A–Z, a–z, 0–9, `-`, `.`, `_`, `~`). Everything else, including
/// `#`, `?`, `/`, and space, is encoded as `%XX` using uppercase hex digits.
///
/// Suitable for encoding single URL path segments (not full paths, since `/`
/// is encoded) and single query parameter values.
fn percent_encode_unreserved(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                encoded.push(
                    char::from_digit((b & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    encoded
}

/// The client uses [`TailnetCertVerifier`] so it can connect to kithd
/// instances that present self-signed certificates.  HTTP/1.1 only;
/// plaintext (`http://`) connections are rejected by the connector.
pub(crate) fn build_tailnet_https_client(
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>> {
    let verifier = Arc::new(TailnetCertVerifier::new());
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Process-wide singleton HTTPS client for tailnet peer blob fetches.
///
/// Building a `rustls::ClientConfig` on every `fetch_peer_blob` call is
/// unnecessary overhead.  `OnceLock` initialises the client exactly once and
/// returns a cheap `Arc::clone` on every subsequent call.
static TAILNET_CLIENT: OnceLock<
    Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>>,
> = OnceLock::new();

/// Return a reference-counted handle to the shared tailnet HTTPS client,
/// building it on the first call.
fn tailnet_https_client() -> Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>> {
    Arc::clone(TAILNET_CLIENT.get_or_init(|| Arc::new(build_tailnet_https_client())))
}

// ---------------------------------------------------------------------------
// Blob fetch
// ---------------------------------------------------------------------------

/// Errors returned by [`fetch_peer_blob`].
#[derive(Debug)]
pub(crate) enum FetchBlobError {
    /// The `mailbox_host` failed the SSRF safety check.
    HostRejected,
    /// The `blob_id` failed format validation.
    BlobIdInvalid,
    /// Network-level error (connection refused, DNS failure, etc.).
    Network(String),
    /// The server returned a non-200 HTTP status.
    HttpError(u16),
    /// The received bytes did not match the expected SHA-256 digest.
    HashMismatch { expected: String, got: String },
    /// The response body exceeded `expected_size`.
    SizeExceeded,
    /// The entire fetch did not complete within the computed timeout.
    Timeout,
    /// Writing the verified blob to the local store failed.
    BlobStore(std::io::Error),
}

impl std::fmt::Display for FetchBlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchBlobError::HostRejected => write!(f, "host rejected by SSRF guard"),
            FetchBlobError::BlobIdInvalid => write!(f, "blob_id failed format validation"),
            FetchBlobError::Network(msg) => write!(f, "network error: {msg}"),
            FetchBlobError::HttpError(status) => write!(f, "HTTP error {status}"),
            FetchBlobError::HashMismatch { expected, got } => {
                write!(f, "hash mismatch: expected {expected}, got {got}")
            }
            FetchBlobError::SizeExceeded => write!(f, "response exceeded expected size"),
            FetchBlobError::Timeout => write!(f, "fetch timed out"),
            FetchBlobError::BlobStore(e) => write!(f, "blob store error: {e}"),
        }
    }
}

/// Fetch a single attachment blob from a peer's mailbox, verify its
/// SHA-256 hash, and write it to `blob_store`.
///
/// `mailbox_host` is validated by [`is_valid_fetch_host`] before any
/// network activity, guarding against SSRF.  The received body is
/// limited to `expected_size + 1` bytes; any excess returns
/// [`FetchBlobError::SizeExceeded`] without touching the blob store.
/// Only a body whose SHA-256 digest matches `expected_sha256` is written.
pub(crate) async fn fetch_peer_blob(
    blob_store: &kith_attach::BlobStore,
    mailbox_host: &str,
    blob_id: &str,
    filename: &str,
    content_type: &str,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<(), FetchBlobError> {
    if !is_valid_fetch_host(mailbox_host) {
        tracing::warn!(blob_id, "fetch_peer_blob: host rejected by SSRF guard");
        return Err(FetchBlobError::HostRejected);
    }
    if kith_attach::BlobStore::validate_blob_id(blob_id).is_err() {
        tracing::warn!(blob_id, "fetch_peer_blob: blob_id failed validation");
        return Err(FetchBlobError::BlobIdInvalid);
    }

    // Percent-encode the content_type query parameter value using the RFC 3986
    // unreserved character set.  A naive replace of only '/' and '+' leaves
    // '&', '=', '#', and other characters that would corrupt the query string
    // or enable SSRF if a malicious peer supplies a crafted content_type.
    let ct_encoded = percent_encode_unreserved(content_type);
    // Percent-encode the filename path segment: characters like '#' or '?' would
    // truncate or corrupt the URL path before it reaches the server.
    let filename_encoded = percent_encode_unreserved(filename);
    let url = format!(
        "https://{mailbox_host}/jmap/download/a-self/{blob_id}/{filename_encoded}?accept={ct_encoded}"
    );

    let fetch_timeout = Duration::from_secs((expected_size / 65536).saturating_add(30).min(300));

    let client = tailnet_https_client();
    fetch_with_https_client(
        &client,
        &url,
        blob_store,
        blob_id,
        expected_sha256,
        expected_size,
        fetch_timeout,
        content_type,
    )
    .await
}

/// Inner fetch logic shared between production (`fetch_peer_blob`) and tests
/// (`fetch_peer_blob_from_url`).  Separated so tests can inject a plain-HTTP
/// client via the cfg(test) helper without duplicating the verification logic.
#[allow(clippy::too_many_arguments)]
async fn fetch_with_https_client(
    client: &Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    url: &str,
    blob_store: &kith_attach::BlobStore,
    blob_id: &str,
    expected_sha256: &str,
    expected_size: u64,
    fetch_timeout: Duration,
    content_type: &str,
) -> Result<(), FetchBlobError> {
    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri(url)
        .header("Accept", content_type)
        .body(Full::new(Bytes::new()))
        .map_err(|e| FetchBlobError::Network(e.to_string()))?;

    let resp = match tokio::time::timeout(fetch_timeout, client.request(req)).await {
        Err(_elapsed) => {
            tracing::warn!(blob_id, "fetch_peer_blob: timed out");
            return Err(FetchBlobError::Timeout);
        }
        Ok(Err(e)) => {
            tracing::warn!(blob_id, "fetch_peer_blob: network error: {e}");
            return Err(FetchBlobError::Network(e.to_string()));
        }
        Ok(Ok(r)) => r,
    };

    if resp.status().as_u16() != 200 {
        let status = resp.status().as_u16();
        tracing::warn!(blob_id, status, "fetch_peer_blob: HTTP error");
        return Err(FetchBlobError::HttpError(status));
    }

    // Fast-path: reject if Content-Length header already exceeds the limit.
    if let Some(cl) = resp.headers().get(hyper::header::CONTENT_LENGTH) {
        if let Ok(s) = cl.to_str() {
            if let Ok(n) = s.parse::<u64>() {
                if n > expected_size + 1 {
                    tracing::warn!(
                        blob_id,
                        "fetch_peer_blob: Content-Length exceeds expected_size"
                    );
                    return Err(FetchBlobError::SizeExceeded);
                }
            }
        }
    }

    // Collect body with a hard limit of expected_size + 1 bytes.
    let limit = (expected_size as usize).saturating_add(1);
    let collected = match Limited::new(resp.into_body(), limit).collect().await {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(blob_id, "fetch_peer_blob: body read error: {msg}");
            return Err(FetchBlobError::Network(msg));
        }
    };

    let body_bytes = collected.to_bytes();

    if body_bytes.len() > expected_size as usize {
        tracing::warn!(
            blob_id,
            "fetch_peer_blob: body length exceeds expected_size"
        );
        return Err(FetchBlobError::SizeExceeded);
    }

    verify_and_store(blob_store, blob_id, body_bytes, expected_sha256).await
}

/// Verify the SHA-256 of `body` and, if it matches, write it to `blob_store`.
///
/// Extracted so that the test helper (which uses a plain-HTTP client) can
/// exercise the same hash-verification and store-write path as production code.
async fn verify_and_store(
    blob_store: &kith_attach::BlobStore,
    blob_id: &str,
    body: Bytes,
    expected_sha256: &str,
) -> Result<(), FetchBlobError> {
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_hex = format!("{:x}", hasher.finalize());

    if computed_hex != expected_sha256 {
        tracing::warn!(blob_id, "fetch_peer_blob: hash mismatch (expected != got)");
        return Err(FetchBlobError::HashMismatch {
            expected: expected_sha256.to_string(),
            got: computed_hex,
        });
    }

    blob_store.write_blob(blob_id, &body).await.map_err(|e| {
        tracing::warn!(blob_id, "fetch_peer_blob: blob store write failed: {e}");
        FetchBlobError::BlobStore(e)
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
/// Fetch a blob from an arbitrary URL using a plain HTTP (non-TLS) client.
///
/// Skips the SSRF host check so tests can point at a 127.0.0.1 mock server.
/// Uses the same size-limit, hash-verification, and store-write logic as
/// the production code path via `verify_and_store`.
async fn fetch_peer_blob_from_url(
    blob_store: &kith_attach::BlobStore,
    url: &str,
    blob_id: &str,
    content_type: &str,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<(), FetchBlobError> {
    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);

    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri(url)
        .header("Accept", content_type)
        .body(Full::new(Bytes::new()))
        .map_err(|e| FetchBlobError::Network(e.to_string()))?;

    let fetch_timeout = Duration::from_secs(30);

    let resp = match tokio::time::timeout(fetch_timeout, client.request(req)).await {
        Err(_) => return Err(FetchBlobError::Timeout),
        Ok(Err(e)) => return Err(FetchBlobError::Network(e.to_string())),
        Ok(Ok(r)) => r,
    };

    if resp.status().as_u16() != 200 {
        return Err(FetchBlobError::HttpError(resp.status().as_u16()));
    }

    if let Some(cl) = resp.headers().get(hyper::header::CONTENT_LENGTH) {
        if let Ok(s) = cl.to_str() {
            if let Ok(n) = s.parse::<u64>() {
                if n > expected_size + 1 {
                    return Err(FetchBlobError::SizeExceeded);
                }
            }
        }
    }

    let limit = (expected_size as usize).saturating_add(1);
    let collected = match Limited::new(resp.into_body(), limit).collect().await {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            return Err(FetchBlobError::Network(msg));
        }
    };

    let body_bytes = collected.to_bytes();

    if body_bytes.len() > expected_size as usize {
        return Err(FetchBlobError::SizeExceeded);
    }

    verify_and_store(blob_store, blob_id, body_bytes, expected_sha256).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Oracle: the validation rules in the module doc-comment are the spec.
    // These tests are derived from the rules, not from the implementation.

    #[test]
    fn loopback_rejected() {
        assert!(!is_valid_fetch_host("127.0.0.1"));
        assert!(!is_valid_fetch_host("::1"));
        assert!(!is_valid_fetch_host("localhost"));
        assert!(!is_valid_fetch_host("LOCALHOST"));
    }

    #[test]
    fn rfc1918_rejected() {
        assert!(!is_valid_fetch_host("10.0.0.1"));
        assert!(!is_valid_fetch_host("172.16.0.1"));
        assert!(!is_valid_fetch_host("172.31.255.255"));
        assert!(!is_valid_fetch_host("192.168.1.1"));
    }

    #[test]
    fn link_local_rejected() {
        assert!(!is_valid_fetch_host("169.254.1.1"));
        assert!(!is_valid_fetch_host("[fe80::1]"));
    }

    #[test]
    fn unspecified_rejected() {
        assert!(!is_valid_fetch_host("0.0.0.0"));
        assert!(!is_valid_fetch_host("::"));
    }

    #[test]
    fn tailscale_ip_accepted() {
        // Tailscale CGNAT range 100.64.0.0/10 — not RFC 1918, not loopback.
        assert!(is_valid_fetch_host("100.64.0.1"));
        // Full extent of the CGNAT range (100.64.0.0/10 = 100.64–127.x)
        assert!(is_valid_fetch_host("100.127.255.255"));
    }

    // Oracle: public internet IPs must be rejected even though they are not
    // RFC 1918 or link-local.  Only the Tailscale CGNAT range is allowed.
    #[test]
    fn public_ipv4_rejected() {
        assert!(!is_valid_fetch_host("1.2.3.4"));
        assert!(!is_valid_fetch_host("8.8.8.8"));
        assert!(!is_valid_fetch_host("100.63.255.255")); // one below CGNAT range
        assert!(!is_valid_fetch_host("100.128.0.0")); // one above CGNAT range
    }

    // Oracle: Tailscale ULA IPv6 (fd7a:115c:a1e0::/48) is within fc00::/7;
    // public IPv6 addresses are outside fc00::/7 and must be rejected.
    #[test]
    fn tailscale_ipv6_ula_accepted() {
        assert!(is_valid_fetch_host("fd7a:115c:a1e0::1"));
        assert!(is_valid_fetch_host("fd00::1"));
    }

    #[test]
    fn public_ipv6_rejected() {
        assert!(!is_valid_fetch_host("2001:db8::1")); // documentation range (public)
        assert!(!is_valid_fetch_host("2600::1")); // public IPv6
    }

    // Oracle: Tailscale MagicDNS hostnames (.ts.net and .tailscale.net) must be
    // accepted.  Contacts whose mailbox_host is a MagicDNS name (e.g.
    // alice.tail-xxx.ts.net) must be reachable for blob fetch.
    #[test]
    fn magicdns_hostname_accepted() {
        assert!(is_valid_fetch_host("alice-kith.tail-xxxxx.ts.net"));
        assert!(is_valid_fetch_host("alice-node.tail12345.ts.net"));
        assert!(is_valid_fetch_host("bob.devices.tailscale.net"));
    }

    // Oracle: arbitrary non-Tailscale hostnames must be rejected to prevent SSRF
    // via DNS resolution.  Only MagicDNS (.ts.net / .tailscale.net) exceptions apply.
    #[test]
    fn arbitrary_hostname_rejected() {
        assert!(!is_valid_fetch_host("evil.attacker.com"));
        assert!(!is_valid_fetch_host("internal.corp.example"));
    }

    // Oracle: a MagicDNS hostname with a valid port must be accepted.
    // kithd can listen on ports other than 443 in non-standard deployments.
    #[test]
    fn magicdns_hostname_with_port_accepted() {
        assert!(is_valid_fetch_host("alice.ts.net:8443"));
    }

    // Oracle: an arbitrary non-Tailscale hostname with a port must be rejected.
    #[test]
    fn arbitrary_hostname_with_port_rejected() {
        assert!(!is_valid_fetch_host("evil.attacker.com:8443"));
    }

    #[test]
    fn test_is_valid_fetch_host_rejects_at_sign() {
        assert!(!is_valid_fetch_host("attacker@100.64.0.1"));
        assert!(!is_valid_fetch_host("attacker@node.ts.net"));
        assert!(!is_valid_fetch_host("user@100.64.1.2:8080"));
    }

    #[test]
    fn port_zero_rejected() {
        assert!(!is_valid_fetch_host("alice.ts.net:0"));
    }

    #[test]
    fn invalid_port_rejected() {
        // 99999 > u16::MAX (65535) — does not parse as u16
        assert!(!is_valid_fetch_host("alice.ts.net:99999"));
    }

    // -----------------------------------------------------------------------
    // fetch_peer_blob integration tests via mock HTTP server
    //
    // Oracle for SHA-256: `echo -n 'test blob content' | sha256sum`
    //   dccfe42873d40807d0da4be11f3a412e4914f1315288d3c6e8cf0a19a8928feb
    // -----------------------------------------------------------------------

    const TEST_CONTENT: &[u8] = b"test blob content";
    // Computed offline: echo -n 'test blob content' | sha256sum
    const TEST_SHA256: &str = "dccfe42873d40807d0da4be11f3a412e4914f1315288d3c6e8cf0a19a8928feb";
    const TEST_BLOB_ID: &str = "testblobid0000000000000000000001";

    fn make_temp_blob_store() -> (kith_attach::BlobStore, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("TempDir::new should succeed");
        let store = kith_attach::BlobStore::new(dir.path());
        store.init().expect("BlobStore::init failed");
        (store, dir)
    }

    /// Spin up an axum mock server on 127.0.0.1 and return its port.
    /// `handler` is the axum router to serve.
    async fn start_mock_server(router: axum::Router) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let port = listener.local_addr().expect("local_addr").port();
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock server error");
        });
        port
    }

    #[tokio::test]
    async fn happy_path() {
        use axum::response::IntoResponse;

        let router = axum::Router::new().route(
            "/jmap/download/a-self/testblobid0000000000000000000001/testfile.bin",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    TEST_CONTENT,
                )
                    .into_response()
            }),
        );

        let port = start_mock_server(router).await;
        let (store, _dir) = make_temp_blob_store();
        let url =
            format!("http://127.0.0.1:{port}/jmap/download/a-self/{TEST_BLOB_ID}/testfile.bin");

        let result = fetch_peer_blob_from_url(
            &store,
            &url,
            TEST_BLOB_ID,
            "application/octet-stream",
            TEST_SHA256,
            TEST_CONTENT.len() as u64,
        )
        .await;

        assert!(result.is_ok(), "expected Ok, got {result:?}");

        // Verify the blob was actually written to the store.
        let written = store
            .read_blob(TEST_BLOB_ID)
            .await
            .expect("read_blob failed")
            .expect("expected Some after happy_path");
        assert_eq!(written.as_slice(), TEST_CONTENT);
    }

    #[tokio::test]
    async fn hash_mismatch() {
        use axum::response::IntoResponse;

        // Server returns different bytes than what the oracle hash covers.
        let router = axum::Router::new().route(
            "/jmap/download/a-self/testblobid0000000000000000000001/testfile.bin",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    b"this is NOT the expected content".as_slice(),
                )
                    .into_response()
            }),
        );

        let port = start_mock_server(router).await;
        let (store, _dir) = make_temp_blob_store();
        let url =
            format!("http://127.0.0.1:{port}/jmap/download/a-self/{TEST_BLOB_ID}/testfile.bin");

        let result = fetch_peer_blob_from_url(
            &store,
            &url,
            TEST_BLOB_ID,
            "application/octet-stream",
            TEST_SHA256,
            64,
        )
        .await;

        assert!(
            matches!(result, Err(FetchBlobError::HashMismatch { .. })),
            "expected HashMismatch, got {result:?}"
        );

        // Blob must NOT be written on hash mismatch.
        assert!(
            store
                .read_blob(TEST_BLOB_ID)
                .await
                .expect("read_blob failed")
                .is_none(),
            "blob should not be written on hash mismatch"
        );
    }

    #[tokio::test]
    async fn http_404() {
        let router = axum::Router::new().route(
            "/jmap/download/a-self/testblobid0000000000000000000001/testfile.bin",
            axum::routing::get(|| async { axum::http::StatusCode::NOT_FOUND }),
        );

        let port = start_mock_server(router).await;
        let (store, _dir) = make_temp_blob_store();
        let url =
            format!("http://127.0.0.1:{port}/jmap/download/a-self/{TEST_BLOB_ID}/testfile.bin");

        let result = fetch_peer_blob_from_url(
            &store,
            &url,
            TEST_BLOB_ID,
            "application/octet-stream",
            TEST_SHA256,
            TEST_CONTENT.len() as u64,
        )
        .await;

        assert!(
            matches!(result, Err(FetchBlobError::HttpError(404))),
            "expected HttpError(404), got {result:?}"
        );
    }

    #[tokio::test]
    async fn size_exceeded() {
        use axum::response::IntoResponse;

        // Server returns 10 bytes; we tell the helper to expect only 4.
        let large_body = b"0123456789";
        let router = axum::Router::new().route(
            "/jmap/download/a-self/testblobid0000000000000000000001/testfile.bin",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    large_body.as_slice(),
                )
                    .into_response()
            }),
        );

        let port = start_mock_server(router).await;
        let (store, _dir) = make_temp_blob_store();
        let url =
            format!("http://127.0.0.1:{port}/jmap/download/a-self/{TEST_BLOB_ID}/testfile.bin");

        // Declare expected_size = 4 — body of 10 bytes must trigger SizeExceeded.
        let result = fetch_peer_blob_from_url(
            &store,
            &url,
            TEST_BLOB_ID,
            "application/octet-stream",
            // Wrong hash — irrelevant since we expect SizeExceeded first.
            "0000000000000000000000000000000000000000000000000000000000000000",
            4,
        )
        .await;

        assert!(
            matches!(result, Err(FetchBlobError::SizeExceeded)),
            "expected SizeExceeded, got {result:?}"
        );
    }
}
