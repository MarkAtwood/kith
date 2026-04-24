//! Peer auto-discovery: probe tailnet IPs for running kithd instances.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use kith_store::Store;
use kith_tslocal::LocalApiClient;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::Deserialize;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Maximum response body accepted from a probe target (64 KiB).
const MAX_PROBE_RESPONSE_BYTES: usize = 64 * 1024;

/// Timeout for the entire probe round trip.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of peer probes running concurrently per discovery round.
const PROBE_CONCURRENCY: usize = 10;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Identity returned by probing a remote kithd's `/.well-known/jmap` endpoint.
#[derive(Debug, Clone)]
pub struct PeerSession {
    pub owner_user_id: String,
    pub owner_login: String,
    pub owner_display_name: Option<String>,
    /// Hostname (and optional `:port`) extracted from the session's `apiUrl`.
    /// Used as `mailboxHost` in the contacts table.
    pub mailbox_host: String,
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// Minimal subset of the JMAP session needed for discovery.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionProbe {
    owner_user_id: Option<String>,
    owner_login: Option<String>,
    owner_display_name: Option<String>,
    api_url: Option<String>,
}

// ---------------------------------------------------------------------------
// TLS verifier: accept any certificate from a tailnet IP
// ---------------------------------------------------------------------------

/// A TLS certificate verifier that accepts any certificate from a tailnet IP.
///
/// # Safety rationale
///
/// Tailscale provides cryptographic identity guarantees at the network layer:
/// only the machine with the correct WireGuard private key can send traffic
/// from a given tailnet IP.  The TLS certificate is used only for
/// confidentiality (encryption), not for authentication.  Therefore
/// accepting any cert from a tailnet IP is safe for discovery probing.
#[derive(Debug)]
pub(crate) struct TailnetCertVerifier {
    /// Supported signature schemes from the active `CryptoProvider`.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl TailnetCertVerifier {
    pub(crate) fn new() -> Self {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        Self {
            supported: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for TailnetCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Probe function
// ---------------------------------------------------------------------------

/// Build a shared HTTPS client for tailnet probes.
///
/// The client uses `TailnetCertVerifier` to accept self-signed certificates
/// from kithd instances.  Building once and sharing via `Arc` avoids
/// allocating a new `rustls::ClientConfig` per probe task.
pub(crate) fn build_probe_client() -> Arc<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
> {
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
    Arc::new(Client::builder(TokioExecutor::new()).build(connector))
}

/// Process-wide singleton HTTPS client for discovery probes.
///
/// `OnceLock` initialises the client exactly once and returns a cheap
/// `Arc::clone` on every subsequent call, avoiding a new `rustls::ClientConfig`
/// on every discovery round.
static PROBE_CLIENT: OnceLock<
    Arc<
        Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            Full<Bytes>,
        >,
    >,
> = OnceLock::new();

/// Return a reference-counted handle to the shared discovery probe client,
/// building it on the first call.
fn probe_https_client() -> Arc<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
> {
    Arc::clone(PROBE_CLIENT.get_or_init(build_probe_client))
}

/// Build the probe URL for a given IP and port.
///
/// IPv6 literal addresses are bracketed per RFC 3986 §3.2.2.
/// An unbracketed IPv6 address like "fd7a::1" produces an invalid URL
/// because the colons are ambiguous with the port separator.
pub(crate) fn probe_url(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("https://[{}]:{}/.well-known/jmap", ip, port)
    } else {
        format!("https://{}:{}/.well-known/jmap", ip, port)
    }
}

/// Probe a single tailnet IP:port for a running kithd instance.
///
/// Makes a `GET https://<ip>:<port>/.well-known/jmap` and parses the
/// JMAP session object.  Returns `Some(PeerSession)` if the target responds
/// with a valid kith session, `None` on any error (timeout, connection
/// refused, non-kith response, parse failure, etc.).
///
/// A 5-second hard timeout covers the entire round trip.
///
/// `client` is a pre-built shared HTTPS client from `build_probe_client`.
/// Sharing a single client across concurrent probe tasks avoids allocating
/// a new `rustls::ClientConfig` per probe.
pub async fn probe_peer(
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    ip: &str,
    port: u16,
) -> Option<PeerSession> {
    let url = probe_url(ip, port);

    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        let req = Request::builder()
            .method(hyper::Method::GET)
            .uri(&url)
            .header("Accept", "application/json")
            .body(Full::new(Bytes::new()))
            .ok()?;

        let resp = client.request(req).await.ok()?;

        if !resp.status().is_success() {
            return None;
        }

        let raw = Limited::new(resp.into_body(), MAX_PROBE_RESPONSE_BYTES)
            .collect()
            .await
            .ok()?
            .to_bytes();

        let probe: SessionProbe = serde_json::from_slice(&raw).ok()?;

        let owner_user_id = probe.owner_user_id?;
        let owner_login = probe.owner_login?;
        let api_url = probe.api_url?;
        let mailbox_host = extract_mailbox_host(&api_url)?;

        Some(PeerSession {
            owner_user_id,
            owner_login,
            owner_display_name: probe.owner_display_name,
            mailbox_host,
        })
    })
    .await;

    result.ok().flatten()
}

// ---------------------------------------------------------------------------
// Helper: extract host[:port] from an API URL
// ---------------------------------------------------------------------------

/// Extract `host` or `host:port` from a URL string.
///
/// Port 443 is treated as the default for `https://` and is omitted from
/// the result, matching the convention used by `mailboxHost` in the contacts
/// table.
///
/// Returns `None` if the URL cannot be parsed or has no host.
pub fn extract_mailbox_host(api_url: &str) -> Option<String> {
    // Strip the scheme prefix ("https://" or "http://").
    let rest = if let Some(s) = api_url.strip_prefix("https://") {
        s
    } else if let Some(s) = api_url.strip_prefix("http://") {
        s
    } else {
        return None;
    };

    // The authority is everything before the first '/'.
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }

    // Split authority into host and optional port.
    // IPv6 addresses are enclosed in brackets: [::1]:8443
    if authority.starts_with('[') {
        // IPv6: find the closing ']'
        let close = authority.find(']')?;
        let host = &authority[..=close];
        let after_bracket = &authority[close + 1..];
        if after_bracket.is_empty() {
            return Some(host.to_string());
        }
        // Must be ":port"
        let port_str = after_bracket.strip_prefix(':')?;
        let port: u16 = port_str.parse().ok()?;
        if port == 443 {
            return Some(host.to_string());
        }
        return Some(format!("{}:{}", host, port));
    }

    // Non-IPv6: host is everything before the last ':'
    // But we only split on ':' if what follows parses as a port number.
    if let Some(colon) = authority.rfind(':') {
        let maybe_port = &authority[colon + 1..];
        if let Ok(port) = maybe_port.parse::<u16>() {
            let host = &authority[..colon];
            if host.is_empty() {
                return None;
            }
            if port == 443 {
                return Some(host.to_string());
            }
            return Some(format!("{}:{}", host, port));
        }
    }

    // No port (or port not parseable as u16): return authority as-is.
    Some(authority.to_string())
}

// ---------------------------------------------------------------------------
// Background discovery task
// ---------------------------------------------------------------------------

/// Spawn a background tokio task that periodically probes all tailnet peers
/// for running kithd instances and upserts them as contacts.
///
/// The task is fire-and-forget: errors are logged and ignored; the task
/// never terminates unless the process exits.
pub fn spawn_discovery_task(
    tslocal: Arc<LocalApiClient>,
    store: Arc<Mutex<Store>>,
    port: u16,
    owner_user_id: String,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        loop {
            run_discovery_round(&tslocal, &store, port, &owner_user_id).await;
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
        }
    });
}

async fn run_discovery_round(
    tslocal: &LocalApiClient,
    store: &Arc<Mutex<Store>>,
    port: u16,
    owner_user_id: &str,
) {
    let status = match tslocal.status().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("discovery: LocalAPI status failed: {e}");
            return;
        }
    };

    let peers = status.peer_nodes_excluding(owner_user_id);
    if peers.is_empty() {
        tracing::debug!("discovery: no tailnet peers found");
        return;
    }

    // Obtain the shared HTTPS client singleton.  The client is built once for
    // the process lifetime; subsequent rounds get a cheap Arc::clone.
    let probe_client = probe_https_client();

    // Fan out probes concurrently — one task per peer, bounded by PROBE_CONCURRENCY.
    // Each task tries the peer's IPs in order and returns as soon as one responds.
    let sem = Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
    let mut join_set = tokio::task::JoinSet::new();

    for peer in peers.into_iter().cloned() {
        let sem = Arc::clone(&sem);
        let client = Arc::clone(&probe_client);
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore never closed");
            let mut session = None;
            for ip in &peer.tailscale_ips {
                if let Some(s) = probe_peer(&client, ip, port).await {
                    session = Some(s);
                    break;
                }
            }
            (peer.dns_name.clone(), session)
        });
    }

    let mut found = 0usize;
    while let Some(res) = join_set.join_next().await {
        let (dns_name, session_opt) = match res {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("discovery: probe task panicked: {e}");
                continue;
            }
        };

        let Some(ps) = session_opt else {
            tracing::debug!("discovery: no kithd found for peer {dns_name}");
            continue;
        };

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let result = {
            let guard = store.lock();
            match guard {
                Ok(g) => g.contacts().upsert_discovered_contact(
                    &ps.owner_user_id,
                    &ps.owner_login,
                    &ps.mailbox_host,
                    ps.owner_display_name.as_deref(),
                    now_unix,
                ),
                Err(_) => {
                    tracing::error!("discovery: store lock poisoned");
                    return;
                }
            }
        };

        match result {
            Ok(()) => {
                found += 1;
                tracing::debug!("discovery: upserted contact uid={}", ps.owner_user_id);
            }
            Err(e) => {
                tracing::warn!("discovery: upsert failed for uid={}: {e}", ps.owner_user_id);
            }
        }
    }

    tracing::info!("discovery: round complete, {found} kithd peer(s) found");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- extract_mailbox_host unit tests ---
    // Oracle: expected values are derived from the URL parsing rules in
    // RFC 3986 and the kith convention that port 443 is omitted.

    #[test]
    fn extract_mailbox_host_standard_port() {
        assert_eq!(
            extract_mailbox_host("https://alice.ts.net/jmap/api"),
            Some("alice.ts.net".to_string())
        );
    }

    #[test]
    fn extract_mailbox_host_custom_port() {
        assert_eq!(
            extract_mailbox_host("https://alice.ts.net:8443/jmap/api"),
            Some("alice.ts.net:8443".to_string())
        );
    }

    #[test]
    fn extract_mailbox_host_443_omitted() {
        assert_eq!(
            extract_mailbox_host("https://alice.ts.net:443/jmap/api"),
            Some("alice.ts.net".to_string())
        );
    }

    #[test]
    fn extract_mailbox_host_no_path() {
        assert_eq!(
            extract_mailbox_host("https://alice.ts.net"),
            Some("alice.ts.net".to_string())
        );
    }

    #[test]
    fn extract_mailbox_host_bad_scheme() {
        assert_eq!(extract_mailbox_host("ftp://alice.ts.net/foo"), None);
    }

    #[test]
    fn extract_mailbox_host_empty_host() {
        assert_eq!(extract_mailbox_host("https:///jmap/api"), None);
    }

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    // --- probe_peer integration test ---

    #[tokio::test]
    async fn probe_peer_returns_none_on_refused() {
        install_crypto_provider();
        // Nothing is expected to be listening on port 19999 during tests.
        let client = build_probe_client();
        let result = probe_peer(&client, "127.0.0.1", 19999).await;
        assert!(
            result.is_none(),
            "probe_peer must return None when connection is refused"
        );
    }

    // -----------------------------------------------------------------------
    // probe_peer_ipv6_url_is_bracketed
    // Oracle: RFC 3986 §3.2.2 — IPv6 literal addresses in URLs must be
    //         enclosed in square brackets.  "https://fd7a::1:4430/..." is an
    //         invalid URL; "https://[fd7a::1]:4430/..." is correct.
    // -----------------------------------------------------------------------
    #[test]
    fn probe_peer_ipv6_url_is_bracketed() {
        assert_eq!(
            probe_url("fd7a::1", 4430),
            "https://[fd7a::1]:4430/.well-known/jmap"
        );
    }

    // -----------------------------------------------------------------------
    // probe_peer_ipv4_url_is_not_bracketed
    // Oracle: IPv4 addresses must NOT be bracketed.
    // -----------------------------------------------------------------------
    #[test]
    fn probe_peer_ipv4_url_is_not_bracketed() {
        assert_eq!(
            probe_url("127.0.0.1", 4430),
            "https://127.0.0.1:4430/.well-known/jmap"
        );
    }
}
