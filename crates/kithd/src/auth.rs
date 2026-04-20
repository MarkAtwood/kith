use kith_core::{AuthError, Identity, Role};
use kith_store::contact::ContactStore;
use kith_tslocal::{LocalApiClient, WhoIsResponse};
use std::net::SocketAddr;

/// Abstraction over the Tailscale WhoIs call, enabling test doubles.
///
/// Implemented for [`LocalApiClient`] in production and for mock structs in tests.
/// Use with concrete generics (`W: WhoIsProvider`) rather than `dyn WhoIsProvider`
/// to avoid a dependency on `async-trait`.
pub trait WhoIsProvider {
    fn whois(
        &self,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send;
}

impl WhoIsProvider for LocalApiClient {
    fn whois(
        &self,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send {
        LocalApiClient::whois(self, addr)
    }
}

/// Classify a verified [`Identity`] as [`Role::Owner`] or [`Role::Peer`].
///
/// This is the single authoritative source of the authorization decision rules.
/// Both [`authorize`] and the axum [`crate::extractors::Caller`] extractor call
/// this function so the rules live in exactly one place.
///
/// # Rules
/// - `identity.user_id == owner_id` → [`Role::Owner`]
/// - `contacts.is_permitted(user_id)` returns `true` → [`Role::Peer`]
/// - Otherwise → [`AuthError::Unauthorized`]
/// - Store error → [`AuthError::WhoIsFailed`] (fail closed; 500, not 401)
///
/// # Defensive rules
/// - Comparison is `==` only; never parses or normalizes `user_id`.
/// - Store errors map to `WhoIsFailed` so callers can distinguish denial from failure.
pub(crate) fn classify(
    identity: &Identity,
    contacts: &ContactStore<'_>,
    owner_id: &str,
) -> Result<Role, AuthError> {
    if identity.user_id == owner_id {
        return Ok(Role::Owner);
    }
    match contacts.is_permitted(&identity.user_id) {
        Ok(true) => Ok(Role::Peer),
        Ok(false) => Err(AuthError::Unauthorized),
        // Fail-closed: a store error surfaces as 500, not 401, so a DB failure cannot accidentally grant access.
        Err(e) => Err(AuthError::WhoIsFailed(format!("store error: {e}"))),
    }
}

/// Resolve a peer socket address to an authorized [`Role`] and [`Identity`].
///
/// # Algorithm
/// 1. Call `ts.whois(addr)` — any failure propagates as [`AuthError::WhoIsFailed`].
/// 2. Build an [`Identity`] from the WhoIs result.
/// 3. Delegate to [`classify`] for the authorization decision.
///
/// # Defensive rules
/// - No PII (peer addr, user_id, login_name) appears in error messages returned here.
/// - Store errors are mapped to `WhoIsFailed` so the HTTP layer returns 500, not 401.
#[allow(dead_code)]
pub async fn authorize<W: WhoIsProvider>(
    addr: SocketAddr,
    ts: &W,
    contacts: &ContactStore<'_>,
    owner_id: &str,
) -> Result<(Role, Identity), AuthError> {
    let who = ts.whois(addr).await?;
    let identity = Identity {
        user_id: who.user_profile.id,
        login_name: who.user_profile.login_name,
        display_name: who.user_profile.display_name,
        node_name: who.node.name,
    };
    let role = classify(&identity, contacts, owner_id)?;
    Ok((role, identity))
}

/// Validate that the sender claimed in a `Peer/deliver` request body matches
/// the WhoIs-verified caller identity.
///
/// # Defensive rules
/// - Comparison is exact string equality only — never normalize or parse.
/// - Must be called before any database write.
/// - Returns `AuthError::SenderMismatch`; the HTTP layer must map this to 401.
#[allow(dead_code)]
pub fn check_sender(identity: &Identity, claimed_sender_id: &str) -> Result<(), AuthError> {
    if identity.user_id != claimed_sender_id {
        return Err(AuthError::SenderMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_store::Store;

    /// Test double: returns a fixed WhoIs result for any address.
    ///
    /// `Some(response)` → Ok(response); `None` → Err(WhoIsFailed("test")).
    /// We cannot clone AuthError, so failures are represented as None and
    /// reconstructed to a canonical WhoIsFailed in the provider impl.
    struct MockWhoIs(Option<WhoIsResponse>);

    impl WhoIsProvider for MockWhoIs {
        fn whois(
            &self,
            _addr: SocketAddr,
        ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send {
            let result: Result<WhoIsResponse, AuthError> = match &self.0 {
                Some(r) => Ok(r.clone()),
                None => Err(AuthError::WhoIsFailed("test".into())),
            };
            async move { result }
        }
    }

    fn make_whois(id: &str, login: &str) -> WhoIsResponse {
        use kith_tslocal::{UserProfile, WhoIsNode};
        WhoIsResponse {
            node: WhoIsNode {
                name: "test-node".into(),
            },
            user_profile: UserProfile {
                id: id.into(),
                login_name: login.into(),
                display_name: None,
            },
        }
    }

    fn any_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    // -----------------------------------------------------------------------
    // owner_path: WhoIs returns the owner's user_id → Role::Owner
    // Oracle: authorize() returns Owner when user_id == owner_id.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn owner_path() {
        let store = Store::open_in_memory().expect("in-memory store");
        let contacts = store.contacts();
        let ts = MockWhoIs(Some(make_whois("uid-owner", "owner@example.com")));

        let (role, identity) = authorize(any_addr(), &ts, &contacts, "uid-owner")
            .await
            .expect("owner must be authorized");

        assert_eq!(role, Role::Owner);
        assert_eq!(identity.user_id, "uid-owner");
        assert_eq!(identity.login_name, "owner@example.com");
        assert_eq!(identity.display_name, None);
    }

    // -----------------------------------------------------------------------
    // peer_path: WhoIs returns uid-bob, contacts has uid-bob unblocked → Role::Peer
    // Oracle: authorize() returns Peer when caller is in contacts and not blocked.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn peer_path() {
        let store = Store::open_in_memory().expect("in-memory store");
        let contacts = store.contacts();
        contacts
            .upsert(
                "uid-bob",
                "bob@example.com",
                "bob-kith.tail.ts.net",
                None,
                1000,
            )
            .expect("upsert must succeed");

        let ts = MockWhoIs(Some(make_whois("uid-bob", "bob@example.com")));
        let (role, identity) = authorize(any_addr(), &ts, &contacts, "uid-owner")
            .await
            .expect("bob must be authorized as peer");

        assert_eq!(role, Role::Peer);
        assert_eq!(identity.user_id, "uid-bob");
    }

    // -----------------------------------------------------------------------
    // peer_blocked_rejected: WhoIs returns uid-bob, contacts has uid-bob blocked
    // Oracle: authorize() returns Err(Unauthorized) when caller is blocked.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn peer_blocked_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let contacts = store.contacts();
        contacts
            .upsert(
                "uid-bob",
                "bob@example.com",
                "bob-kith.tail.ts.net",
                None,
                1000,
            )
            .expect("upsert must succeed");
        contacts
            .set_blocked("uid-bob", true)
            .expect("set_blocked must succeed");

        let ts = MockWhoIs(Some(make_whois("uid-bob", "bob@example.com")));
        let err = authorize(any_addr(), &ts, &contacts, "uid-owner")
            .await
            .expect_err("blocked peer must be rejected");

        assert!(
            matches!(err, AuthError::Unauthorized),
            "expected Unauthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // unknown_rejected: WhoIs returns uid-stranger, contacts is empty
    // Oracle: authorize() returns Err(Unauthorized) for unknown callers.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn unknown_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let contacts = store.contacts();

        let ts = MockWhoIs(Some(make_whois("uid-stranger", "stranger@example.com")));
        let err = authorize(any_addr(), &ts, &contacts, "uid-owner")
            .await
            .expect_err("unknown peer must be rejected");

        assert!(
            matches!(err, AuthError::Unauthorized),
            "expected Unauthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // whois_error_propagated: WhoIs fails → error propagates immediately
    // Oracle: authorize() propagates WhoIsFailed without touching the store.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn whois_error_propagated() {
        let store = Store::open_in_memory().expect("in-memory store");
        let contacts = store.contacts();

        let ts = MockWhoIs(None);
        let err = authorize(any_addr(), &ts, &contacts, "uid-owner")
            .await
            .expect_err("WhoIs error must propagate");

        assert!(
            matches!(err, AuthError::WhoIsFailed(ref msg) if msg == "test"),
            "expected WhoIsFailed(\"test\"), got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // store_error_is_not_unauthorized: contacts returns Err → WhoIsFailed, not Unauthorized
    // Oracle: authorize() fails closed (500-class) rather than silently denying.
    // Uses a raw rusqlite connection without schema to force a store error.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn store_error_is_not_unauthorized() {
        // Open a raw connection with no schema applied. When is_permitted queries
        // the contacts table it will hit a "no such table" rusqlite error.
        let raw_conn =
            rusqlite::Connection::open_in_memory().expect("raw in-memory connection must open");
        let contacts = ContactStore::new(&raw_conn, None);

        let ts = MockWhoIs(Some(make_whois("uid-stranger", "stranger@example.com")));
        let err = authorize(any_addr(), &ts, &contacts, "uid-owner")
            .await
            .expect_err("store error must yield an error");

        assert!(
            matches!(err, AuthError::WhoIsFailed(_)),
            "store error must map to WhoIsFailed (not Unauthorized), got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // check_sender tests — oracle: exact string equality per spec
    // -----------------------------------------------------------------------

    #[test]
    fn check_sender_match_ok() {
        let identity = Identity {
            user_id: "uid-bob".into(),
            login_name: "bob@example.com".into(),
            display_name: None,
            node_name: "bob-node.tail12345.ts.net".into(),
        };
        assert!(check_sender(&identity, "uid-bob").is_ok());
    }

    #[test]
    fn check_sender_mismatch_err() {
        let identity = Identity {
            user_id: "uid-bob".into(),
            login_name: "bob@example.com".into(),
            display_name: None,
            node_name: "bob-node.tail12345.ts.net".into(),
        };
        let err = check_sender(&identity, "uid-evil").expect_err("mismatch must fail");
        assert!(matches!(err, AuthError::SenderMismatch));
    }

    #[test]
    fn check_sender_empty_claimed_err() {
        let identity = Identity {
            user_id: "uid-bob".into(),
            login_name: "bob@example.com".into(),
            display_name: None,
            node_name: "bob-node.tail12345.ts.net".into(),
        };
        let err = check_sender(&identity, "").expect_err("empty claimed id must fail");
        assert!(matches!(err, AuthError::SenderMismatch));
    }
}
