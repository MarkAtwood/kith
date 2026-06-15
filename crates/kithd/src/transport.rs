//! Tailscale implementation of [`kith_core::transport::FederationTransport`].
//!
//! [`TailscaleTransport`] wraps a [`LocalApiClient`] and provides:
//! - **Identity verification** via the Tailscale LocalAPI WhoIs endpoint.
//! - **Peer discovery** by probing tailnet peers for running kithd instances.
//! - **Host validation** via SSRF-safe IP-range and MagicDNS checks.
//!
//! Also houses [`TailnetCertVerifier`], the TLS verifier that accepts any
//! certificate from a tailnet IP (Tailscale provides authentication at the
//! network layer; TLS is used only for confidentiality).

use kith_core::auth::Identity;
use kith_core::error::AuthError;
use kith_core::transport::{ConnectionContext, DiscoveredPeer, FederationTransport, IdentityProvider};
use kith_tslocal::LocalApiClient;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::net::IpAddr;
use std::sync::Arc;

/// Maximum number of peer probes running concurrently per discovery round.
const PROBE_CONCURRENCY: usize = 10;

/// When set to `true`, [`TailscaleTransport::is_valid_host`] allows loopback
/// addresses (`127.x.x.x` and `[::1]`) to pass the SSRF guard.
///
/// This flag exists solely to enable integration tests that spin up two kithd
/// instances on 127.0.0.1 without a real tailnet. It must never be set outside
/// `#[cfg(any(test, feature = "test-utils"))]` call sites.
#[cfg(any(test, feature = "test-utils"))]
pub static ALLOW_LOOPBACK_FOR_TESTS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
// TailscaleTransport
// ---------------------------------------------------------------------------

/// Tailscale-backed implementation of [`FederationTransport`].
///
/// Wraps a [`LocalApiClient`] to provide identity verification, peer
/// discovery, and host validation through the Tailscale LocalAPI.
pub struct TailscaleTransport {
    client: Arc<LocalApiClient>,
}

impl TailscaleTransport {
    /// Create a new transport backed by the given [`LocalApiClient`].
    pub fn new(client: Arc<LocalApiClient>) -> Self {
        Self { client }
    }

    /// Build a [`rustls::ClientConfig`] that uses [`TailnetCertVerifier`]
    /// to accept self-signed certificates from tailnet peers.
    ///
    /// Suitable for constructing HTTPS clients that connect to kithd
    /// instances presenting self-signed certs.  Tailscale provides
    /// authentication at the network layer; TLS is used only for
    /// confidentiality.
    pub fn client_tls_config() -> rustls::ClientConfig {
        let verifier = Arc::new(TailnetCertVerifier::new());
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    }
}

// ---------------------------------------------------------------------------
// TailscaleIdentityProvider
// ---------------------------------------------------------------------------

/// Standalone Tailscale identity provider for use outside a full transport.
///
/// Wraps [`LocalApiClient`] and verifies callers via the WhoIs endpoint.
/// Used when identity verification is needed independently of transport
/// concerns (e.g. testing, or composing with a non-Tailscale transport).
pub struct TailscaleIdentityProvider {
    client: Arc<LocalApiClient>,
}

impl TailscaleIdentityProvider {
    pub fn new(client: Arc<LocalApiClient>) -> Self {
        Self { client }
    }
}

impl IdentityProvider for TailscaleIdentityProvider {
    fn identify_caller(
        &self,
        ctx: &ConnectionContext,
    ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_ {
        let addr = ctx.peer_addr;
        async move {
            let who = self.client.whois(addr).await?;
            Ok(Identity::new(
                who.user_profile.id,
                who.user_profile.login_name,
                who.user_profile.display_name,
                who.node.name,
            ))
        }
    }
}

impl IdentityProvider for TailscaleTransport {
    /// Identify a peer from their inbound connection address via Tailscale WhoIs.
    fn identify_caller(
        &self,
        ctx: &ConnectionContext,
    ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_ {
        let addr = ctx.peer_addr;
        async move {
            let who = self.client.whois(addr).await?;
            Ok(Identity::new(
                who.user_profile.id,
                who.user_profile.login_name,
                who.user_profile.display_name,
                who.node.name,
            ))
        }
    }
}

impl FederationTransport for TailscaleTransport {
    /// Discover reachable peers by probing all tailnet nodes for running kithd instances.
    ///
    /// For each peer returned by Tailscale LocalAPI status, probes
    /// `/.well-known/jmap` and cross-validates the session's claimed
    /// `owner_user_id` against the Tailscale-verified identity.
    async fn discover_peers(&self, port: u16) -> Result<Vec<DiscoveredPeer>, AuthError> {
        let status = self
            .client
            .status()
            .await
            .map_err(|e| AuthError::WhoIsFailed(format!("discovery status: {e}")))?;

        let owner_user_id = &status.self_node.user_id;
        let peers = status.peer_nodes_excluding(owner_user_id);
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        // Obtain the shared HTTPS probe client from the discovery module.
        let probe_client = crate::discovery::build_probe_client();

        // Fan out probes concurrently, bounded by PROBE_CONCURRENCY.
        let sem = Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
        let mut join_set = tokio::task::JoinSet::new();

        for peer in peers.into_iter().cloned() {
            let sem = Arc::clone(&sem);
            let client = Arc::clone(&probe_client);
            join_set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore never closed");
                let mut session = None;
                let mut responding_ip: Option<String> = None;
                for ip in &peer.tailscale_ips {
                    if let Some(s) = crate::discovery::probe_peer(&client, ip, port).await {
                        session = Some(s);
                        responding_ip = Some(ip.clone());
                        break;
                    }
                }
                (peer.dns_name.clone(), peer.user_id.clone(), session, responding_ip)
            });
        }

        let mut discovered = Vec::new();
        while let Some(res) = join_set.join_next().await {
            let (dns_name, whois_user_id, session_opt, responding_ip) = match res {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("transport: probe task panicked: {e}");
                    continue;
                }
            };

            let Some(ps) = session_opt else {
                tracing::debug!("transport: no kithd found for peer {dns_name}");
                continue;
            };

            let Some(ip) = responding_ip else {
                tracing::warn!(
                    "transport: session present but responding_ip missing for {dns_name}; skipping"
                );
                continue;
            };

            // Cross-validate: the session's claimed owner_user_id must match
            // the Tailscale-verified user_id. A malicious node could serve any
            // owner_user_id; accepting it would let an attacker redirect
            // outbound delivery for the spoofed user.
            if ps.owner_user_id != whois_user_id {
                tracing::warn!(
                    "transport: peer {dns_name} claims owner_user_id={} but Tailscale says {}; skipping",
                    ps.owner_user_id,
                    whois_user_id,
                );
                continue;
            }

            // Derive mailbox_host from the Tailscale-verified IP and port.
            let mailbox_host = crate::discovery::build_mailbox_host(&ip, port);

            discovered.push(DiscoveredPeer {
                user_id: ps.owner_user_id,
                login_name: ps.owner_login,
                display_name: ps.owner_display_name,
                mailbox_host,
            });
        }

        Ok(discovered)
    }

    /// Get the local owner's Tailscale user ID.
    async fn local_owner_id(&self) -> Result<String, AuthError> {
        let status = self.client.status().await?;
        Ok(status.self_node.user_id)
    }

    /// Get the local node's tailnet IP addresses.
    async fn local_addresses(&self) -> Result<Vec<String>, AuthError> {
        let status = self.client.status().await?;
        Ok(status.tailscale_ips)
    }

    /// Check if a host address is valid for outbound connections on Tailscale.
    ///
    /// Accepts Tailscale CGNAT IPs (100.64.0.0/10), ULA IPv6 (fc00::/7),
    /// and `.ts.net`/`.tailscale.net` MagicDNS names.
    /// Rejects loopback, RFC 1918, link-local, public internet, and plain hostnames.
    fn is_valid_host(&self, host: &str) -> bool {
        is_valid_tailscale_host(host)
    }
}

// ---------------------------------------------------------------------------
// Host validation (SSRF guard)
// ---------------------------------------------------------------------------

/// Return `true` if `host` is safe to connect to on the Tailscale network.
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
///   All other plain hostnames are rejected.
pub(crate) fn is_valid_tailscale_host(host: &str) -> bool {
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
    //   ipv4              — no colon
    //   ipv4:port         — exactly one colon
    //   [ipv6]            — bracketed, no port
    //   [ipv6]:port       — bracketed, with port
    //   ipv6              — bare (multiple colons) — no port, whole string is IP
    let (ip_part, port_opt): (&str, Option<u16>) = if host.starts_with('[') {
        // Bracketed IPv6
        let close = match host.find(']') {
            Some(i) => i,
            None => return false,
        };
        let bracketed = &host[1..close];
        let after = &host[close + 1..];
        if after.is_empty() {
            (bracketed, None)
        } else {
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
        let colon_count = host.chars().filter(|&c| c == ':').count();

        if colon_count > 1 {
            // Multiple colons: bare IPv6 address with no port
            (host, None)
        } else if colon_count == 1 {
            // Exactly one colon: host:port
            let colon = host.find(':').expect("one colon confirmed above");
            let maybe_port = &host[colon + 1..];
            if let Ok(port) = maybe_port.parse::<u16>() {
                (&host[..colon], Some(port))
            } else {
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
            // Allow Tailscale MagicDNS hostnames; reject all other plain names.
            if ip_part.ends_with(".ts.net") || ip_part.ends_with(".tailscale.net") {
                return true;
            }
            return false;
        }
    };

    // --- IP range checks ---

    // Loopback and unspecified are rejected unconditionally.
    if ip.is_loopback() {
        return false;
    }
    if ip.is_unspecified() {
        return false;
    }

    // IP-range logic is centralised in kith_core::is_tailnet_ip.
    kith_core::is_tailnet_ip(ip)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===================================================================
    // is_valid_tailscale_host tests
    //
    // Oracle: the validation rules are derived from:
    //   - Tailscale CGNAT range: 100.64.0.0/10
    //   - Tailscale ULA IPv6: fd7a:115c:a1e0::/48, within fc00::/7
    //   - MagicDNS suffixes: .ts.net and .tailscale.net
    //   - SSRF prevention: reject loopback, RFC 1918, link-local, public IPs
    // Test vectors are independent of the implementation.
    // ===================================================================

    // --- Empty and malformed inputs ---

    #[test]
    fn empty_host_rejected() {
        assert!(!is_valid_tailscale_host(""));
    }

    #[test]
    fn at_sign_rejected() {
        assert!(!is_valid_tailscale_host("attacker@100.64.0.1"));
        assert!(!is_valid_tailscale_host("attacker@node.ts.net"));
        assert!(!is_valid_tailscale_host("user@100.64.1.2:8080"));
    }

    // --- Loopback addresses ---

    #[test]
    fn loopback_rejected() {
        assert!(!is_valid_tailscale_host("127.0.0.1"));
        assert!(!is_valid_tailscale_host("::1"));
        assert!(!is_valid_tailscale_host("localhost"));
        assert!(!is_valid_tailscale_host("LOCALHOST"));
    }

    // --- Unspecified addresses ---

    #[test]
    fn unspecified_rejected() {
        assert!(!is_valid_tailscale_host("0.0.0.0"));
        assert!(!is_valid_tailscale_host("::"));
    }

    // --- RFC 1918 private addresses ---

    #[test]
    fn rfc1918_rejected() {
        assert!(!is_valid_tailscale_host("10.0.0.1"));
        assert!(!is_valid_tailscale_host("172.16.0.1"));
        assert!(!is_valid_tailscale_host("172.31.255.255"));
        assert!(!is_valid_tailscale_host("192.168.1.1"));
    }

    // --- Link-local addresses ---

    #[test]
    fn link_local_rejected() {
        assert!(!is_valid_tailscale_host("169.254.1.1"));
        assert!(!is_valid_tailscale_host("[fe80::1]"));
    }

    // --- Public internet IPs ---

    #[test]
    fn public_ipv4_rejected() {
        assert!(!is_valid_tailscale_host("1.2.3.4"));
        assert!(!is_valid_tailscale_host("8.8.8.8"));
        assert!(!is_valid_tailscale_host("100.63.255.255")); // one below CGNAT
        assert!(!is_valid_tailscale_host("100.128.0.0")); // one above CGNAT
    }

    #[test]
    fn public_ipv6_rejected() {
        assert!(!is_valid_tailscale_host("2001:db8::1"));
        assert!(!is_valid_tailscale_host("2600::1"));
    }

    // --- Tailscale CGNAT IPv4 (100.64.0.0/10) ---

    #[test]
    fn tailscale_cgnat_ipv4_accepted() {
        assert!(is_valid_tailscale_host("100.64.0.1"));
        assert!(is_valid_tailscale_host("100.127.255.255"));
    }

    #[test]
    fn tailscale_cgnat_with_port_accepted() {
        assert!(is_valid_tailscale_host("100.64.0.1:8443"));
    }

    // --- Tailscale ULA IPv6 (fc00::/7) ---

    #[test]
    fn tailscale_ula_ipv6_accepted() {
        assert!(is_valid_tailscale_host("fd7a:115c:a1e0::1"));
        assert!(is_valid_tailscale_host("fd00::1"));
    }

    #[test]
    fn tailscale_bracketed_ipv6_accepted() {
        assert!(is_valid_tailscale_host("[fd7a:115c:a1e0::1]"));
        assert!(is_valid_tailscale_host("[fd7a:115c:a1e0::1]:8443"));
    }

    // --- MagicDNS hostnames ---

    #[test]
    fn magicdns_ts_net_accepted() {
        assert!(is_valid_tailscale_host("alice-kith.tail-xxxxx.ts.net"));
        assert!(is_valid_tailscale_host("alice-node.tail12345.ts.net"));
    }

    #[test]
    fn magicdns_tailscale_net_accepted() {
        assert!(is_valid_tailscale_host("bob.devices.tailscale.net"));
    }

    #[test]
    fn magicdns_with_port_accepted() {
        assert!(is_valid_tailscale_host("alice.ts.net:8443"));
    }

    // --- Arbitrary hostnames rejected ---

    #[test]
    fn arbitrary_hostname_rejected() {
        assert!(!is_valid_tailscale_host("evil.attacker.com"));
        assert!(!is_valid_tailscale_host("internal.corp.example"));
    }

    #[test]
    fn arbitrary_hostname_with_port_rejected() {
        assert!(!is_valid_tailscale_host("evil.attacker.com:8443"));
    }

    // --- Port edge cases ---

    #[test]
    fn port_zero_rejected() {
        assert!(!is_valid_tailscale_host("alice.ts.net:0"));
    }

    #[test]
    fn invalid_port_rejected() {
        // 99999 > u16::MAX (65535)
        assert!(!is_valid_tailscale_host("alice.ts.net:99999"));
    }

    // --- Bracketed IPv6 edge cases ---

    #[test]
    fn malformed_unclosed_bracket_rejected() {
        assert!(!is_valid_tailscale_host("[fd7a::1"));
    }

    #[test]
    fn empty_brackets_rejected() {
        assert!(!is_valid_tailscale_host("[]"));
    }

    // --- Hostname-like but not MagicDNS ---

    #[test]
    fn plain_hostname_rejected() {
        // Single-label hostnames must be rejected (no dot, not an IP).
        assert!(!is_valid_tailscale_host("mynode"));
    }

    #[test]
    fn ts_net_bare_rejected() {
        // "ts.net" itself has no subdomain; not a valid MagicDNS name.
        assert!(!is_valid_tailscale_host("ts.net"));
    }

    #[test]
    fn ts_net_suffix_not_at_end_rejected() {
        assert!(!is_valid_tailscale_host("evil.ts.net.example.com"));
    }

    // --- loopback bypass ---

    #[test]
    fn loopback_bypass_when_flag_set() {
        ALLOW_LOOPBACK_FOR_TESTS.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(is_valid_tailscale_host("127.0.0.1"));
        assert!(is_valid_tailscale_host("::1"));
        ALLOW_LOOPBACK_FOR_TESTS.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn loopback_rejected_when_flag_not_set() {
        ALLOW_LOOPBACK_FOR_TESTS.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!is_valid_tailscale_host("127.0.0.1"));
        assert!(!is_valid_tailscale_host("::1"));
    }

    // ===================================================================
    // TailnetCertVerifier tests
    // ===================================================================

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[test]
    fn cert_verifier_accepts_any_cert() {
        install_crypto_provider();
        let verifier = TailnetCertVerifier::new();
        let dummy_cert = CertificateDer::from(vec![0u8; 32]);
        let server_name = ServerName::try_from("test.example.com").unwrap();
        let result = verifier.verify_server_cert(
            &dummy_cert,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );
        assert!(result.is_ok(), "TailnetCertVerifier must accept any cert");
    }

    #[test]
    fn cert_verifier_has_supported_schemes() {
        install_crypto_provider();
        let verifier = TailnetCertVerifier::new();
        let schemes = verifier.supported_verify_schemes();
        assert!(
            !schemes.is_empty(),
            "TailnetCertVerifier must report supported signature schemes"
        );
    }

    // ===================================================================
    // client_tls_config tests
    // ===================================================================

    #[test]
    fn client_tls_config_builds_successfully() {
        install_crypto_provider();
        let config = TailscaleTransport::client_tls_config();
        // The config should exist and not require client auth.
        // We cannot easily inspect internal state, but building without
        // panic is the primary check.
        assert!(
            config.alpn_protocols.is_empty(),
            "default config should have no ALPN protocols set"
        );
    }

    // ===================================================================
    // TailscaleTransport compile-time checks
    // ===================================================================

    /// Verify that `TailscaleTransport` satisfies `FederationTransport` bounds.
    /// This is a compile-time check; the function is never called.
    #[allow(dead_code)]
    fn _assert_transport_is_federation_transport() {
        fn _require_federation<T: FederationTransport>() {}
        _require_federation::<TailscaleTransport>();
    }

    /// Verify that `TailscaleTransport` implements `IdentityProvider`.
    #[allow(dead_code)]
    fn _assert_transport_is_identity_provider() {
        fn _require_identity<T: IdentityProvider>() {}
        _require_identity::<TailscaleTransport>();
    }

    /// Verify that `TailscaleIdentityProvider` implements `IdentityProvider`.
    #[allow(dead_code)]
    fn _assert_standalone_identity_provider() {
        fn _require_identity<T: IdentityProvider>() {}
        _require_identity::<TailscaleIdentityProvider>();
    }

    /// Verify that `TailscaleTransport` is Send + Sync.
    #[allow(dead_code)]
    fn _assert_send_sync() {
        fn _require_send_sync<T: Send + Sync>() {}
        _require_send_sync::<TailscaleTransport>();
    }

    /// Verify that `TailscaleIdentityProvider` is Send + Sync.
    #[allow(dead_code)]
    fn _assert_standalone_send_sync() {
        fn _require_send_sync<T: Send + Sync>() {}
        _require_send_sync::<TailscaleIdentityProvider>();
    }
}
