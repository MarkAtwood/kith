//! Dev-mode identity provider: identifies all connections as a fixed user.
//!
//! **WARNING**: This provider performs NO authentication. Every connection
//! is identified as the configured user regardless of source. It exists
//! solely for development and testing without tailscaled.
//!
//! Gated behind `cfg(any(test, feature = "test-utils"))` — cannot be
//! compiled into production builds.

use kith_core::auth::Identity;
use kith_core::error::AuthError;
use kith_core::transport::{ConnectionContext, IdentityProvider};

/// Read identity from environment, returning a provider.
///
/// Reads `KITHD_DEV_IDENTITY` (format: `"user_id:login_name"` or just `"user_id"`).
/// Returns `None` if the env var is not set.
/// Returns `Some(Err(...))` if the env var is set but malformed.
pub fn from_env() -> Option<Result<DevIdentityProvider, String>> {
    let val = std::env::var("KITHD_DEV_IDENTITY").ok()?;
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Some(Err(
            "KITHD_DEV_IDENTITY is set but empty".to_string(),
        ));
    }
    let (user_id, login_name) = match trimmed.split_once(':') {
        Some((uid, login)) => {
            let uid = uid.trim();
            let login = login.trim();
            if uid.is_empty() {
                return Some(Err(
                    "KITHD_DEV_IDENTITY user_id part is empty".to_string(),
                ));
            }
            (uid.to_string(), login.to_string())
        }
        None => (trimmed.to_string(), trimmed.to_string()),
    };
    let identity = Identity::new(user_id, login_name, None, "dev.local");
    Some(Ok(DevIdentityProvider::new(identity)))
}

/// Dev-only identity provider that identifies every connection as a fixed user.
pub struct DevIdentityProvider {
    identity: Identity,
}

impl DevIdentityProvider {
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }
}

impl IdentityProvider for DevIdentityProvider {
    fn identify_caller(
        &self,
        _ctx: &ConnectionContext,
    ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_ {
        let result = Ok(self.identity.clone());
        async move { result }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_ctx() -> ConnectionContext {
        ConnectionContext {
            peer_addr: "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            peer_cert_der: None,
        }
    }

    /// Oracle: DevIdentityProvider always returns the configured identity
    /// for any ConnectionContext, regardless of peer address.
    #[tokio::test]
    async fn any_connection_returns_configured_identity() {
        let identity = Identity::new("uid-test".to_string(), "test@example.com".to_string(), None, "dev.local".to_string());
        let provider = DevIdentityProvider::new(identity.clone());
        let result = provider.identify_caller(&make_ctx()).await;
        assert_eq!(result.unwrap(), identity);
    }

    /// Oracle: "alice" (no colon) produces user_id="alice", login_name="alice".
    #[test]
    fn from_env_bare_user_id() {
        unsafe { std::env::set_var("KITHD_DEV_IDENTITY", "alice") };
        let result = from_env();
        unsafe { std::env::remove_var("KITHD_DEV_IDENTITY") };

        let provider = result
            .expect("must return Some when var is set")
            .expect("must return Ok for valid format");
        assert_eq!(provider.identity.user_id, "alice");
        assert_eq!(provider.identity.login_name, "alice");
    }

    /// Oracle: "alice:alice@example.com" produces user_id="alice",
    /// login_name="alice@example.com".
    #[test]
    fn from_env_user_id_and_login() {
        unsafe { std::env::set_var("KITHD_DEV_IDENTITY", "alice:alice@example.com") };
        let result = from_env();
        unsafe { std::env::remove_var("KITHD_DEV_IDENTITY") };

        let provider = result
            .expect("must return Some when var is set")
            .expect("must return Ok for valid format");
        assert_eq!(provider.identity.user_id, "alice");
        assert_eq!(provider.identity.login_name, "alice@example.com");
    }

    /// Oracle: when KITHD_DEV_IDENTITY is not set, from_env returns None.
    #[test]
    fn from_env_unset_returns_none() {
        unsafe { std::env::remove_var("KITHD_DEV_IDENTITY") };
        assert!(from_env().is_none());
    }

    /// Oracle: multiple calls to identify_caller all return the same identity,
    /// proving no internal state mutation.
    #[tokio::test]
    async fn multiple_connections_return_same_identity() {
        let identity = Identity::new("uid-stable".to_string(), "stable@example.com".to_string(), None, "dev.local".to_string());
        let provider = DevIdentityProvider::new(identity.clone());

        let ctx1 = ConnectionContext {
            peer_addr: "127.0.0.1:1111".parse::<SocketAddr>().unwrap(),
            peer_cert_der: None,
        };
        let ctx2 = ConnectionContext {
            peer_addr: "192.168.1.1:2222".parse::<SocketAddr>().unwrap(),
            peer_cert_der: None,
        };
        let ctx3 = ConnectionContext {
            peer_addr: "[::1]:3333".parse::<SocketAddr>().unwrap(),
            peer_cert_der: None,
        };

        let r1 = provider.identify_caller(&ctx1).await.unwrap();
        let r2 = provider.identify_caller(&ctx2).await.unwrap();
        let r3 = provider.identify_caller(&ctx3).await.unwrap();

        assert_eq!(r1, identity);
        assert_eq!(r2, identity);
        assert_eq!(r3, identity);
    }
}
