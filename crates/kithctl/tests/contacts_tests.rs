//! Integration tests for `kithctl contacts list` data layer.
//!
//! These tests verify the store round-trip used by cmd_contacts_list:
//! that contacts inserted via ContactStore::upsert are returned by
//! ContactStore::list with the correct field values.
//!
//! Oracle: values inserted by the test itself — independent of any
//! display/formatting logic in cmd_contacts_list.

use kith_store::Store;

#[test]
fn contacts_list_empty() {
    // Oracle: a freshly-opened store has no contacts.
    // Verifies that list() returns an empty Vec, not an error.
    let store = Store::open_in_memory().expect("in-memory store must open");
    let contacts = store
        .contacts()
        .list()
        .expect("list must not fail on empty store");
    assert!(
        contacts.is_empty(),
        "expected empty contacts list on fresh store"
    );
}

#[test]
fn contacts_list_with_data() {
    // Oracle: we insert two contacts with known field values and verify
    // that list() returns exactly those values.
    let store = Store::open_in_memory().expect("in-memory store must open");
    let cs = store.contacts();

    cs.upsert(
        "uid-alice",
        "alice@example.com",
        "alice-kith.tail.ts.net",
        Some("Alice Liddell"),
        1_000_000,
    )
    .expect("upsert alice must succeed");

    cs.upsert(
        "uid-bob",
        "bob@example.com",
        "bob-kith.tail.ts.net",
        None,
        2_000_000,
    )
    .expect("upsert bob must succeed");

    let contacts = cs.list().expect("list must not fail");

    assert_eq!(contacts.len(), 2, "expected exactly 2 contacts");

    let logins: Vec<&str> = contacts.iter().map(|c| c.login.as_str()).collect();
    assert!(
        logins.contains(&"alice@example.com"),
        "alice must be present; got {:?}",
        logins
    );
    assert!(
        logins.contains(&"bob@example.com"),
        "bob must be present; got {:?}",
        logins
    );

    let alice = contacts
        .iter()
        .find(|c| c.tailscale_user_id == "uid-alice")
        .expect("alice must be findable by tailscale_user_id");
    assert_eq!(alice.display_name, Some("Alice Liddell".to_string()));
    assert_eq!(alice.mailbox_host, "alice-kith.tail.ts.net");
    assert!(!alice.blocked);

    let bob = contacts
        .iter()
        .find(|c| c.tailscale_user_id == "uid-bob")
        .expect("bob must be findable by tailscale_user_id");
    assert_eq!(bob.display_name, None);
    assert_eq!(bob.mailbox_host, "bob-kith.tail.ts.net");
    assert!(!bob.blocked);
}

#[test]
fn contacts_list_long_login_stored_intact() {
    // Oracle: a login name longer than 30 characters must be stored as-is in
    // the database.  Truncation for display (fit_col) must not affect the
    // stored value.  This test verifies the store round-trip only.
    let long_login = "very-long-login-name-that-exceeds-thirty-chars@example.com";
    assert!(
        long_login.len() > 30,
        "test invariant: login must be longer than 30 chars"
    );

    let store = Store::open_in_memory().expect("in-memory store must open");
    let cs = store.contacts();

    cs.upsert("uid-long", long_login, "host.tail.ts.net", None, 3_000_000)
        .expect("upsert with long login must succeed");

    let contacts = cs.list().expect("list must not fail");
    assert_eq!(contacts.len(), 1);

    let c = &contacts[0];
    assert_eq!(
        c.login, long_login,
        "stored login must be the full original string, not truncated"
    );
}
