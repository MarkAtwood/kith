//! Loopback identity provider: identifies local connections by a configured identity.
//!
//! Connections from loopback addresses (127.0.0.1, ::1) are identified as
//! the configured local user. All other connections are rejected.
//!
//! This is the foundation for Unix socket identity. When ConnectionContext
//! gains a `peer_uid` field (via SO_PEERCRED), this provider can be
//! extended to map UIDs to identities.

use kith_core::{AuthError, ConnectionContext, Identity, IdentityProvider};

/// Identity provider that identifies loopback connections as a configured user.
///
/// Any connection from `127.0.0.1` or `::1` is identified as the configured
/// [`Identity`]. All other source addresses return [`AuthError::Unauthorized`].
pub struct LoopbackIdentityProvider {
    identity: Identity,
}

impl LoopbackIdentityProvider {
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }
}

impl IdentityProvider for LoopbackIdentityProvider {
    fn identify_caller(
        &self,
        ctx: &ConnectionContext,
    ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_ {
        let ip = ctx.peer_addr.ip();
        async move {
            if ip.is_loopback() {
                Ok(self.identity.clone())
            } else {
                Err(AuthError::Unauthorized)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_identity() -> Identity {
        Identity {
            user_id: "uid-local-owner".to_string(),
            login_name: "alice@localhost".to_string(),
            display_name: Some("Alice Local".to_string()),
            node_name: "localhost".to_string(),
        }
    }

    fn ctx_from(addr: &str) -> ConnectionContext {
        ConnectionContext {
            peer_addr: addr.parse::<SocketAddr>().unwrap(),
            peer_cert_der: None,
        }
    }

    // Oracle: 127.0.0.1 is IPv4 loopback — must return the configured identity.
    #[tokio::test]
    async fn loopback_ipv4_returns_configured_identity() {
        let provider = LoopbackIdentityProvider::new(test_identity());
        let ctx = ctx_from("127.0.0.1:12345");
        let result = provider.identify_caller(&ctx).await;
        let id = result.expect("loopback IPv4 must succeed");
        assert_eq!(id.user_id, "uid-local-owner");
        assert_eq!(id.login_name, "alice@localhost");
    }

    // Oracle: ::1 is IPv6 loopback — must return the configured identity.
    #[tokio::test]
    async fn loopback_ipv6_returns_configured_identity() {
        let provider = LoopbackIdentityProvider::new(test_identity());
        let ctx = ctx_from("[::1]:12345");
        let result = provider.identify_caller(&ctx).await;
        let id = result.expect("loopback IPv6 must succeed");
        assert_eq!(id.user_id, "uid-local-owner");
        assert_eq!(id.login_name, "alice@localhost");
    }

    // Oracle: 192.168.1.1 is a private LAN address, not loopback — must be rejected.
    #[tokio::test]
    async fn non_loopback_returns_unauthorized() {
        let provider = LoopbackIdentityProvider::new(test_identity());
        let ctx = ctx_from("192.168.1.1:12345");
        let result = provider.identify_caller(&ctx).await;
        assert!(
            result.is_err(),
            "non-loopback address must return Err(Unauthorized)"
        );
    }

    // Oracle: 100.64.0.1 is a Tailscale CGNAT address, not loopback — must be rejected.
    #[tokio::test]
    async fn tailscale_ip_returns_unauthorized() {
        let provider = LoopbackIdentityProvider::new(test_identity());
        let ctx = ctx_from("100.64.0.1:12345");
        let result = provider.identify_caller(&ctx).await;
        assert!(
            result.is_err(),
            "Tailscale CGNAT address must return Err(Unauthorized)"
        );
    }
}
