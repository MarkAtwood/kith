use kith_core::{AuthError, Identity, Role};
use kith_store::contact::ContactStore;

/// Classify a verified [`Identity`] as [`Role::Owner`] or [`Role::Peer`].
///
/// This is the single authoritative source of the authorization decision rules.
/// The axum [`crate::extractors::Caller`] extractor calls this function so the
/// rules live in exactly one place.
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

#[cfg(test)]
mod tests {
    use super::*;
    use kith_store::Store;

    fn make_identity(user_id: &str, login: &str) -> Identity {
        Identity::new(user_id.into(), login.into(), None, "test-node.tail12345.ts.net".into())
    }

    // -----------------------------------------------------------------------
    // classify_owner: identity.user_id == owner_id → Role::Owner
    // Oracle: classify() returns Owner when user_id matches owner_id exactly.
    // -----------------------------------------------------------------------
    #[test]
    fn classify_owner() {
        let store = Store::open_in_memory().expect("in-memory store");
        let contacts = store.contacts();
        let identity = make_identity("uid-owner", "owner@example.com");

        let role = classify(&identity, &contacts, "uid-owner").expect("owner must be classified");

        assert_eq!(role, Role::Owner);
    }

    // -----------------------------------------------------------------------
    // classify_peer: identity in contacts and not blocked → Role::Peer
    // Oracle: classify() returns Peer when caller is in contacts and not blocked.
    // -----------------------------------------------------------------------
    #[test]
    fn classify_peer() {
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
        let identity = make_identity("uid-bob", "bob@example.com");

        let role =
            classify(&identity, &contacts, "uid-owner").expect("bob must be classified as peer");

        assert_eq!(role, Role::Peer);
    }

    // -----------------------------------------------------------------------
    // classify_blocked_rejected: blocked contact → Unauthorized
    // Oracle: classify() returns Err(Unauthorized) when caller is blocked.
    // -----------------------------------------------------------------------
    #[test]
    fn classify_blocked_rejected() {
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
        let identity = make_identity("uid-bob", "bob@example.com");

        let err =
            classify(&identity, &contacts, "uid-owner").expect_err("blocked peer must be rejected");

        assert!(
            matches!(err, AuthError::Unauthorized),
            "expected Unauthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // classify_unknown_rejected: user_id not in contacts → Unauthorized
    // Oracle: classify() returns Err(Unauthorized) for unknown callers.
    // -----------------------------------------------------------------------
    #[test]
    fn classify_unknown_rejected() {
        let store = Store::open_in_memory().expect("in-memory store");
        let contacts = store.contacts();
        let identity = make_identity("uid-stranger", "stranger@example.com");

        let err = classify(&identity, &contacts, "uid-owner")
            .expect_err("unknown caller must be rejected");

        assert!(
            matches!(err, AuthError::Unauthorized),
            "expected Unauthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // classify_store_error_fails_closed: store error → WhoIsFailed, not Unauthorized
    // Oracle: classify() fails closed (500-class) rather than silently denying.
    // Uses a raw rusqlite connection without schema to force a store error.
    // -----------------------------------------------------------------------
    #[test]
    fn classify_store_error_fails_closed() {
        let raw_conn =
            rusqlite::Connection::open_in_memory().expect("raw in-memory connection must open");
        let contacts = ContactStore::new(&raw_conn, None);
        let identity = make_identity("uid-stranger", "stranger@example.com");

        let err = classify(&identity, &contacts, "uid-owner")
            .expect_err("store error must yield an error");

        assert!(
            matches!(err, AuthError::WhoIsFailed(_)),
            "store error must map to WhoIsFailed (not Unauthorized), got {err:?}"
        );
    }
}
