//! Federation transport abstraction.
//!
//! Defines the [`FederationTransport`] trait that decouples the JMAP Chat
//! protocol layer (Peer/deliver, Peer/receipt, outbox retry) from any
//! specific network overlay.  The default implementation is Tailscale
//! (in `kithd::transport`); alternative bindings (DNS+mTLS, onion services,
//! mDNS, etc.) implement this trait without touching the protocol layer.

use crate::auth::Identity;
use crate::error::AuthError;
use std::net::SocketAddr;

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

/// Abstraction over the network transport used for peer-to-peer federation.
///
/// Implementations provide:
/// - **Identity verification** — authenticating inbound callers by connection address.
/// - **Peer discovery** — enumerating reachable peers (including probing and cross-validation).
/// - **Host validation** — checking whether an outbound host address is valid for this transport.
///
/// The protocol layer (`Peer/deliver`, `Peer/receipt`, outbox worker) is transport-agnostic
/// and works through this trait.
///
/// # Object safety
///
/// This trait uses RPITIT (return-position `impl Trait` in trait methods) and is therefore
/// **not** object-safe.  Use concrete generics (`T: FederationTransport`) rather than
/// `dyn FederationTransport`.  This matches the existing `WhoIsProvider` pattern and avoids
/// a dependency on `async-trait`.
pub trait FederationTransport: Send + Sync + 'static {
    /// Identify a peer from their inbound connection address.
    ///
    /// Called on every inbound JMAP request to authenticate the caller.
    /// Returns the verified [`Identity`] or an [`AuthError`] on failure.
    fn identify_caller(
        &self,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_;

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
