//! Static identity provider: maps IP ranges to identities via configuration.

use kith_core::auth::Identity;
use kith_core::error::AuthError;
use kith_core::transport::{ConnectionContext, IdentityProvider};
use std::net::IpAddr;

/// A configured identity mapping: an IP range and the identity it maps to.
#[derive(Debug, Clone)]
pub struct StaticPeerEntry {
    /// Network address (host bits are ignored during matching).
    addr: IpAddr,
    /// CIDR prefix length (0-32 for IPv4, 0-128 for IPv6).
    prefix_len: u8,
    /// Identity to return for matching peers.
    pub identity: Identity,
}

/// Static identity provider that maps IP addresses/CIDR ranges to identities.
///
/// Entries are checked in order; the first matching entry wins.  If no entry
/// matches, `identify_caller` returns `AuthError::Unauthorized`.
#[derive(Debug)]
pub struct StaticIdentityProvider {
    entries: Vec<StaticPeerEntry>,
}

impl StaticIdentityProvider {
    /// Create a new provider from pre-built entries.
    pub fn new(entries: Vec<StaticPeerEntry>) -> Self {
        Self { entries }
    }

    /// Parse entries from `(cidr_string, identity)` pairs.
    ///
    /// Each string is either `"ip/prefix"` (e.g. `"192.168.1.0/24"`) or a bare
    /// IP address (e.g. `"10.0.0.1"`).  A bare IPv4 address gets prefix 32; a
    /// bare IPv6 address gets prefix 128.
    pub fn from_entries(entries: Vec<(String, Identity)>) -> Result<Self, String> {
        let mut parsed = Vec::with_capacity(entries.len());
        for (cidr, identity) in entries {
            let (addr, prefix_len) = parse_cidr(&cidr)?;
            parsed.push(StaticPeerEntry {
                addr,
                prefix_len,
                identity,
            });
        }
        Ok(Self { entries: parsed })
    }
}

impl IdentityProvider for StaticIdentityProvider {
    fn identify_caller(
        &self,
        ctx: &ConnectionContext,
    ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_ {
        let peer_ip = ctx.peer_addr.ip();
        let result = self
            .entries
            .iter()
            .find(|entry| cidr_matches(entry.addr, entry.prefix_len, peer_ip))
            .map(|entry| entry.identity.clone())
            .ok_or(AuthError::Unauthorized);
        async move { result }
    }
}

/// Parse a CIDR string like `"192.168.1.0/24"` or a bare IP like `"10.0.0.1"`.
fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let addr: IpAddr = ip_str
            .parse()
            .map_err(|e| format!("invalid IP in {s:?}: {e}"))?;
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|e| format!("invalid prefix in {s:?}: {e}"))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(format!(
                "prefix /{prefix_len} exceeds maximum /{max} for {s:?}"
            ));
        }
        Ok((addr, prefix_len))
    } else {
        let addr: IpAddr = s.parse().map_err(|e| format!("invalid IP {s:?}: {e}"))?;
        let prefix_len = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Ok((addr, prefix_len))
    }
}

/// Check whether `candidate` falls within the CIDR block `(network, prefix_len)`.
fn cidr_matches(network: IpAddr, prefix_len: u8, candidate: IpAddr) -> bool {
    match (network, candidate) {
        (IpAddr::V4(net), IpAddr::V4(cand)) => {
            if prefix_len == 0 {
                return true;
            }
            let net_bits = u32::from(net);
            let cand_bits = u32::from(cand);
            let mask = u32::MAX << (32 - prefix_len);
            (net_bits & mask) == (cand_bits & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(cand)) => {
            if prefix_len == 0 {
                return true;
            }
            let net_bits = u128::from(net);
            let cand_bits = u128::from(cand);
            let mask = u128::MAX << (128 - prefix_len);
            (net_bits & mask) == (cand_bits & mask)
        }
        // IPv4 network never matches IPv6 candidate and vice versa.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_identity(id: &str) -> Identity {
        Identity {
            user_id: id.into(),
            login_name: format!("{id}@example.com"),
            display_name: None,
            node_name: format!("{id}-node.local"),
        }
    }

    fn ctx(ip: &str, port: u16) -> ConnectionContext {
        let addr: SocketAddr = format!("{ip}:{port}").parse().unwrap();
        ConnectionContext::from_addr(addr)
    }

    #[tokio::test]
    async fn exact_ipv4_match() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "192.168.1.100".into(),
            make_identity("alice"),
        )])
        .unwrap();

        let result = provider.identify_caller(&ctx("192.168.1.100", 12345)).await;
        assert_eq!(result.unwrap().user_id, "alice");
    }

    #[tokio::test]
    async fn cidr_24_match() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "192.168.1.0/24".into(),
            make_identity("subnet-24"),
        )])
        .unwrap();

        // Any host in 192.168.1.0/24 should match.
        let r1 = provider.identify_caller(&ctx("192.168.1.1", 1000)).await;
        assert_eq!(r1.unwrap().user_id, "subnet-24");

        let r2 = provider.identify_caller(&ctx("192.168.1.254", 2000)).await;
        assert_eq!(r2.unwrap().user_id, "subnet-24");

        // Outside the /24 should not match.
        let r3 = provider.identify_caller(&ctx("192.168.2.1", 3000)).await;
        assert!(r3.is_err());
    }

    #[tokio::test]
    async fn cidr_16_match() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "10.20.0.0/16".into(),
            make_identity("subnet-16"),
        )])
        .unwrap();

        let r1 = provider.identify_caller(&ctx("10.20.0.1", 80)).await;
        assert_eq!(r1.unwrap().user_id, "subnet-16");

        let r2 = provider.identify_caller(&ctx("10.20.255.255", 80)).await;
        assert_eq!(r2.unwrap().user_id, "subnet-16");

        let r3 = provider.identify_caller(&ctx("10.21.0.1", 80)).await;
        assert!(r3.is_err());
    }

    #[tokio::test]
    async fn ipv6_exact_match() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "fd00::1".into(),
            make_identity("v6-exact"),
        )])
        .unwrap();

        let r1 = provider
            .identify_caller(&ctx("[fd00::1]", 443))
            .await;
        assert_eq!(r1.unwrap().user_id, "v6-exact");

        let r2 = provider
            .identify_caller(&ctx("[fd00::2]", 443))
            .await;
        assert!(r2.is_err());
    }

    #[tokio::test]
    async fn ipv6_prefix_match() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "fd00:abcd::/32".into(),
            make_identity("v6-prefix"),
        )])
        .unwrap();

        let r1 = provider
            .identify_caller(&ctx("[fd00:abcd::1]", 443))
            .await;
        assert_eq!(r1.unwrap().user_id, "v6-prefix");

        let r2 = provider
            .identify_caller(&ctx("[fd00:abcd:1234::99]", 443))
            .await;
        assert_eq!(r2.unwrap().user_id, "v6-prefix");

        // Different /32 prefix.
        let r3 = provider
            .identify_caller(&ctx("[fd00:abce::1]", 443))
            .await;
        assert!(r3.is_err());
    }

    #[tokio::test]
    async fn no_match_returns_unauthorized() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "10.0.0.1".into(),
            make_identity("only-this"),
        )])
        .unwrap();

        let result = provider.identify_caller(&ctx("10.0.0.2", 80)).await;
        assert!(
            matches!(result, Err(AuthError::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
    }

    #[tokio::test]
    async fn first_match_wins() {
        let provider = StaticIdentityProvider::from_entries(vec![
            ("192.168.1.0/24".into(), make_identity("narrow")),
            ("192.168.0.0/16".into(), make_identity("wide")),
        ])
        .unwrap();

        // 192.168.1.50 matches both entries; first (/24) should win.
        let r1 = provider.identify_caller(&ctx("192.168.1.50", 80)).await;
        assert_eq!(r1.unwrap().user_id, "narrow");

        // 192.168.2.50 only matches the second (/16) entry.
        let r2 = provider.identify_caller(&ctx("192.168.2.50", 80)).await;
        assert_eq!(r2.unwrap().user_id, "wide");
    }

    #[tokio::test]
    async fn slash_zero_matches_everything() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "0.0.0.0/0".into(),
            make_identity("catch-all"),
        )])
        .unwrap();

        let r1 = provider.identify_caller(&ctx("1.2.3.4", 80)).await;
        assert_eq!(r1.unwrap().user_id, "catch-all");

        let r2 = provider.identify_caller(&ctx("255.255.255.255", 80)).await;
        assert_eq!(r2.unwrap().user_id, "catch-all");
    }

    #[tokio::test]
    async fn port_is_ignored() {
        let provider = StaticIdentityProvider::from_entries(vec![(
            "10.0.0.1".into(),
            make_identity("portless"),
        )])
        .unwrap();

        let r1 = provider.identify_caller(&ctx("10.0.0.1", 80)).await;
        assert_eq!(r1.unwrap().user_id, "portless");

        let r2 = provider.identify_caller(&ctx("10.0.0.1", 443)).await;
        assert_eq!(r2.unwrap().user_id, "portless");

        let r3 = provider.identify_caller(&ctx("10.0.0.1", 0)).await;
        assert_eq!(r3.unwrap().user_id, "portless");
    }

    #[test]
    fn parse_cidr_rejects_bad_prefix() {
        let result = StaticIdentityProvider::from_entries(vec![(
            "10.0.0.0/33".into(),
            make_identity("x"),
        )]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn parse_cidr_rejects_bad_ip() {
        let result = StaticIdentityProvider::from_entries(vec![(
            "not-an-ip/24".into(),
            make_identity("x"),
        )]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ipv4_v6_mismatch_never_matches() {
        // IPv4 entry should not match an IPv6 peer.
        let provider = StaticIdentityProvider::from_entries(vec![(
            "0.0.0.0/0".into(),
            make_identity("v4-only"),
        )])
        .unwrap();

        let result = provider
            .identify_caller(&ctx("[::1]", 80))
            .await;
        assert!(result.is_err(), "IPv4 /0 must not match IPv6 address");
    }
}
