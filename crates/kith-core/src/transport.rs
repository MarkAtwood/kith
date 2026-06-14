//! Federation transport and identity provider abstractions.
//!
//! Defines [`FederationTransport`] and [`IdentityProvider`] — the two traits
//! that decouple the JMAP Chat protocol layer from any specific network
//! overlay or authentication mechanism.
//!
//! **Transport** answers "how did this connection get here?" — peer discovery,
//! host validation, bind addresses.
//!
//! **Identity** answers "who is the person on the other end?" — verifying
//! caller identity from connection metadata (WhoIs, TLS client certs, TOFU
//! key pins, DID signatures, etc.).
//!
//! The two concerns are orthogonal: you can run X.509 identity over Tailscale
//! transport, or TOFU identity over DNS+mTLS transport.  `FederationTransport`
//! requires `IdentityProvider` as a supertrait, so any concrete transport
//! provides both — typically by delegating identity to a composed provider.

use crate::auth::Identity;
use crate::error::AuthError;
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// Connection context
// ---------------------------------------------------------------------------

/// Metadata about an inbound connection, passed to [`IdentityProvider::identify_caller`].
///
/// Carries whatever information the transport layer can extract from the
/// connection.  Identity providers inspect the fields relevant to their
/// mechanism and ignore the rest.
///
/// New fields may be added over time (e.g. HTTP headers for bearer tokens,
/// SPIFFE SVIDs) without breaking existing providers — providers that don't
/// need new fields simply ignore them.
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// Socket address of the remote peer.
    pub peer_addr: SocketAddr,

    /// DER-encoded X.509 client certificate from the TLS handshake, if the
    /// transport performs mutual TLS (mTLS).  `None` when the transport does
    /// not use mTLS or the peer did not present a client certificate.
    ///
    /// Used by X.509, TOFU, and DANE identity providers.
    pub peer_cert_der: Option<Vec<u8>>,
}

impl ConnectionContext {
    /// Create a context with only a peer address (no TLS client cert).
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            peer_addr: addr,
            peer_cert_der: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Identity provider
// ---------------------------------------------------------------------------

/// Abstraction over the mechanism used to verify a caller's identity.
///
/// Implementations extract and verify identity from connection metadata:
/// - **Tailscale WhoIs** — call the LocalAPI to identify the peer by IP.
/// - **X.509 client certificate** — extract CN/SAN from `ctx.peer_cert_der`.
/// - **TOFU** — look up the peer's pinned public key from `ctx.peer_cert_der`.
/// - **DID resolution** — verify an HTTP signature against a DID document.
/// - **SASL** — negotiate and verify via a SASL mechanism.
///
/// Identity providers are orthogonal to transports: the same provider can
/// be used with different transports, and the same transport can be paired
/// with different providers.
///
/// # Object safety
///
/// This trait uses RPITIT and is **not** object-safe.  Use concrete generics
/// (`I: IdentityProvider`) rather than `dyn IdentityProvider`.
pub trait IdentityProvider: Send + Sync + 'static {
    /// Verify the identity of an inbound caller.
    ///
    /// Called on every inbound JMAP request.  The [`ConnectionContext`]
    /// carries whatever metadata the transport could extract from the
    /// connection (socket address, TLS client cert, etc.).
    ///
    /// Returns the verified [`Identity`] or an [`AuthError`] on failure.
    fn identify_caller(
        &self,
        ctx: &ConnectionContext,
    ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_;
}

// ---------------------------------------------------------------------------
// Discovered peer
// ---------------------------------------------------------------------------

/// A peer discovered on the federation network.
///
/// Returned by [`FederationTransport::discover_peers`].  Contains enough
/// information to upsert a contact row and begin message delivery.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Opaque user identifier from the transport's identity layer.
    pub user_id: String,
    /// Login name or email address of the peer.
    pub login_name: String,
    /// Human-readable display name, if available.
    pub display_name: Option<String>,
    /// Network address suitable for outbound HTTPS delivery
    /// (e.g. `100.64.1.2:8443`, `alice.ts.net`).
    pub mailbox_host: String,
}

// ---------------------------------------------------------------------------
// Federation transport
// ---------------------------------------------------------------------------

/// Abstraction over the network transport used for peer-to-peer federation.
///
/// Implementations provide:
/// - **Peer discovery** — enumerating reachable peers (probing, cross-validation).
/// - **Host validation** — checking whether an outbound host is valid for this transport.
/// - **Local node info** — owner ID, bind addresses.
///
/// Identity verification is provided by the [`IdentityProvider`] supertrait.
/// Transports typically compose with an identity provider internally,
/// delegating `identify_caller` to a provider chosen at construction time.
///
/// # Object safety
///
/// This trait uses RPITIT and is **not** object-safe.  Use concrete generics
/// (`T: FederationTransport`) rather than `dyn FederationTransport`.
pub trait FederationTransport: IdentityProvider + Send + Sync + 'static {
    /// Discover reachable peers on this transport.
    ///
    /// Implementations should enumerate peers, probe for running kithd
    /// instances, cross-validate identity, and return only verified peers.
    /// The caller upserts the returned peers as contacts.
    fn discover_peers(
        &self,
        port: u16,
    ) -> impl std::future::Future<Output = Result<Vec<DiscoveredPeer>, AuthError>> + Send + '_;

    /// Get the local owner's user ID on this transport.
    fn local_owner_id(
        &self,
    ) -> impl std::future::Future<Output = Result<String, AuthError>> + Send + '_;

    /// Get the local node's bind addresses (IPs or hostnames).
    fn local_addresses(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<String>, AuthError>> + Send + '_;

    /// Check if a host address is valid for outbound connections on this transport.
    ///
    /// Used by the outbox worker and blob fetcher to reject SSRF-unsafe destinations.
    /// `host` is the authority portion of a URL (e.g. `100.64.1.2:8443`, `alice.ts.net`).
    fn is_valid_host(&self, host: &str) -> bool;
}
