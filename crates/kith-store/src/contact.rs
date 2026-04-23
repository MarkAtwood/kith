use crate::db_err;
use crate::message::ChangesResult;
use kith_core::{ChatContact, KithError, StateChange};
use rusqlite::{params, Connection};
use tokio::sync::broadcast;

pub struct ContactStore<'a> {
    conn: &'a Connection,
    events_tx: Option<&'a broadcast::Sender<StateChange>>,
}

impl<'a> ContactStore<'a> {
    pub fn new(
        conn: &'a Connection,
        events_tx: Option<&'a broadcast::Sender<StateChange>>,
    ) -> Self {
        ContactStore { conn, events_tx }
    }

    fn emit(&self, new_state: String) {
        if let Some(tx) = self.events_tx {
            let _ = tx.send(StateChange {
                type_name: "ChatContact".to_string(),
                new_state,
            });
        }
    }

    /// Insert or replace a contact record.  Advances the contact state counter.
    pub fn upsert(
        &self,
        peer_user_id: &str,
        peer_login: &str,
        peer_mailbox_host: &str,
        display_name: Option<&str>,
        now_unix: i64,
    ) -> Result<(), KithError> {
        // Use INSERT OR REPLACE so re-delivery from the same peer updates the record.
        // first_seen_at is preserved via the coalesce sub-select when the row exists.
        self.conn
            .execute(
                "INSERT INTO contacts \
                    (peer_user_id, peer_login, peer_mailbox_host, display_name, \
                     first_seen_at, last_seen_at, blocked) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0) \
                 ON CONFLICT(peer_user_id) DO UPDATE SET \
                    peer_login        = excluded.peer_login, \
                    peer_mailbox_host = excluded.peer_mailbox_host, \
                    display_name      = excluded.display_name, \
                    last_seen_at      = excluded.last_seen_at",
                params![
                    peer_user_id,
                    peer_login,
                    peer_mailbox_host,
                    display_name,
                    now_unix,
                ],
            )
            .map_err(db_err)?;
        let new_state = advance_state(self.conn)?;
        self.emit(new_state);
        Ok(())
    }

    /// Upsert a contact discovered via the automatic peer-discovery probe.
    ///
    /// Idempotent. On conflict:
    /// - Updates peer_login, peer_mailbox_host, last_seen_at
    /// - Updates display_name ONLY if it is currently NULL (preserves user-set names)
    /// - NEVER updates first_seen_at or blocked
    pub fn upsert_discovered_contact(
        &self,
        peer_user_id: &str,
        peer_login: &str,
        peer_mailbox_host: &str,
        discovered_display_name: Option<&str>,
        now_unix: i64,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "INSERT INTO contacts \
                    (peer_user_id, peer_login, peer_mailbox_host, display_name, \
                     first_seen_at, last_seen_at, blocked) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0) \
                 ON CONFLICT(peer_user_id) DO UPDATE SET \
                    peer_login        = excluded.peer_login, \
                    peer_mailbox_host = excluded.peer_mailbox_host, \
                    display_name      = CASE WHEN display_name IS NULL \
                                             THEN excluded.display_name \
                                             ELSE display_name END, \
                    last_seen_at      = excluded.last_seen_at",
                params![
                    peer_user_id,
                    peer_login,
                    peer_mailbox_host,
                    discovered_display_name,
                    now_unix,
                ],
            )
            .map_err(db_err)?;
        let new_state = advance_state(self.conn)?;
        self.emit(new_state);
        Ok(())
    }

    /// Fetch a single contact by peer_user_id.  Returns None if not found.
    pub fn get_by_peer_user_id(&self, peer_user_id: &str) -> Result<Option<ChatContact>, KithError> {
        let result = self.conn.query_row(
            "SELECT peer_user_id, peer_login, peer_mailbox_host, display_name, \
                    first_seen_at, last_seen_at, blocked \
             FROM contacts WHERE peer_user_id = ?1",
            params![peer_user_id],
            row_to_contact,
        );
        match result {
            Ok(c) => Ok(Some(c)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
        }
    }

    /// Return all contacts ordered by peer_login.
    pub fn list(&self) -> Result<Vec<ChatContact>, KithError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT peer_user_id, peer_login, peer_mailbox_host, display_name, \
                        first_seen_at, last_seen_at, blocked \
                 FROM contacts ORDER BY peer_login",
            )
            .map_err(db_err)?;
        let rows = stmt.query_map([], row_to_contact).map_err(db_err)?;
        let mut contacts = Vec::new();
        for row in rows {
            contacts.push(row.map_err(db_err)?);
        }
        Ok(contacts)
    }

    /// Set the blocked flag for a contact.
    ///
    /// Advances the contact state counter only if the peer exists (i.e. the UPDATE
    /// actually matched a row). No-ops silently — without advancing state — when
    /// `peer_user_id` is not in the contacts table.
    pub fn set_blocked(&self, peer_user_id: &str, blocked: bool) -> Result<(), KithError> {
        let affected = self
            .conn
            .execute(
                "UPDATE contacts SET blocked = ?1 WHERE peer_user_id = ?2",
                params![blocked as i64, peer_user_id],
            )
            .map_err(db_err)?;
        if affected > 0 {
            let new_state = advance_state(self.conn)?;
            self.emit(new_state);
        }
        Ok(())
    }

    /// Returns true if the peer is in contacts and not blocked.
    pub fn is_permitted(&self, peer_user_id: &str) -> Result<bool, KithError> {
        let result: Result<i64, rusqlite::Error> = self.conn.query_row(
            "SELECT blocked FROM contacts WHERE peer_user_id = ?1",
            params![peer_user_id],
            |row| row.get(0),
        );
        match result {
            Ok(blocked) => Ok(blocked == 0),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(db_err(e)),
        }
    }

    /// Return the current contact state string (e.g. "s-3").
    pub fn get_state(&self) -> Result<String, KithError> {
        let counter: i64 = self
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'contact'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(format!("s-{counter}"))
    }

    /// Increment the contact state counter and return the new state string.
    pub fn advance_state(&self) -> Result<String, KithError> {
        advance_state(self.conn)
    }

    /// Return IDs of all contacts if the state has advanced since `since_state`.
    ///
    /// Phase 1: no per-row state tracking for contacts.  Any change after
    /// `since_state` triggers a full re-sync: all peer_user_ids are returned
    /// as `added`.  If `since_state` is already the current state, the result
    /// is empty.
    pub fn get_changes_since(&self, since_state: &str) -> Result<ChangesResult, KithError> {
        let since_counter = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Validation("invalid state token".to_string()))?;

        let current_state = self.get_state()?;
        let current_counter: i64 = current_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .expect("get_state always returns s-<integer>");

        if since_counter >= current_counter {
            return Ok(ChangesResult {
                added: vec![],
                updated: vec![],
                destroyed: vec![],
                new_state: current_state,
            });
        }

        let mut stmt = self
            .conn
            .prepare("SELECT peer_user_id FROM contacts ORDER BY peer_login")
            .map_err(db_err)?;
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(ChangesResult {
            added: ids,
            updated: vec![],
            destroyed: vec![],
            new_state: current_state,
        })
    }
}

/// Map a rusqlite Row to a ChatContact.  Column order must match the SELECT above.
fn row_to_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatContact> {
    let peer_user_id: String = row.get(0)?;
    let peer_login: String = row.get(1)?;
    let peer_mailbox_host: String = row.get(2)?;
    let display_name: Option<String> = row.get(3)?;
    let first_seen_at: i64 = row.get(4)?;
    let last_seen_at: i64 = row.get(5)?;
    let blocked: i64 = row.get(6)?;
    Ok(ChatContact {
        id: peer_user_id.clone(),
        tailscale_user_id: peer_user_id,
        login: peer_login,
        mailbox_host: peer_mailbox_host,
        display_name,
        first_seen_at: crate::util::unix_secs_to_rfc3339(first_seen_at),
        last_seen_at: crate::util::unix_secs_to_rfc3339(last_seen_at),
        blocked: blocked != 0,
    })
}

/// Increment the contact state counter and return the new state string like "s-5".
///
/// # Concurrency
/// This function reads and then increments the counter in two separate
/// statements. It is safe only for single-threaded use (Phase 1 constraint).
/// Phase 2, if it introduces concurrent writers, must wrap this in a
/// single atomic UPDATE … RETURNING or hold a write-level transaction.
fn advance_state(conn: &Connection) -> Result<String, KithError> {
    conn.execute(
        "UPDATE state_counters SET counter = counter + 1 WHERE type_name = 'contact'",
        [],
    )
    .map_err(db_err)?;
    let counter: i64 = conn
        .query_row(
            "SELECT counter FROM state_counters WHERE type_name = 'contact'",
            [],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    Ok(format!("s-{counter}"))
}

#[cfg(test)]
mod tests {
    use crate::Store;
    use kith_core::KithError;

    fn open() -> Store {
        Store::open_in_memory().expect("in-memory store must open")
    }

    #[test]
    fn upsert_then_get_returns_matching_fields() {
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-1",
            "alice@example.com",
            "alice-kith.tail.ts.net",
            Some("Alice"),
            1000,
        )
        .unwrap();
        let c = cs
            .get_by_peer_user_id("uid-1")
            .unwrap()
            .expect("contact must exist");
        assert_eq!(c.tailscale_user_id, "uid-1");
        assert_eq!(c.login, "alice@example.com");
        assert_eq!(c.mailbox_host, "alice-kith.tail.ts.net");
        assert_eq!(c.display_name, Some("Alice".into()));
        assert_eq!(c.first_seen_at, crate::util::unix_secs_to_rfc3339(1000));
        assert_eq!(c.last_seen_at, crate::util::unix_secs_to_rfc3339(1000));
        assert!(!c.blocked);
    }

    #[test]
    fn get_by_peer_user_id_unknown_returns_none() {
        let store = open();
        let result = store.contacts().get_by_peer_user_id("nobody").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn is_permitted_unknown_peer_returns_false() {
        let store = open();
        assert!(!store.contacts().is_permitted("no-such-id").unwrap());
    }

    #[test]
    fn is_permitted_known_unblocked_returns_true() {
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-2",
            "bob@example.com",
            "bob-kith.tail.ts.net",
            None,
            2000,
        )
        .unwrap();
        assert!(cs.is_permitted("uid-2").unwrap());
    }

    #[test]
    fn is_permitted_blocked_returns_false() {
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-3",
            "eve@example.com",
            "eve-kith.tail.ts.net",
            None,
            3000,
        )
        .unwrap();
        cs.set_blocked("uid-3", true).unwrap();
        assert!(!cs.is_permitted("uid-3").unwrap());
    }

    #[test]
    fn set_blocked_advances_state() {
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-4",
            "mal@example.com",
            "mal-kith.tail.ts.net",
            None,
            4000,
        )
        .unwrap();
        let state_before = cs.get_state().unwrap();
        cs.set_blocked("uid-4", true).unwrap();
        let state_after = cs.get_state().unwrap();
        assert_ne!(
            state_before, state_after,
            "set_blocked must advance state counter"
        );
    }

    #[test]
    fn list_returns_all_contacts() {
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-a",
            "aaa@example.com",
            "aaa-kith.tail.ts.net",
            None,
            1000,
        )
        .unwrap();
        cs.upsert(
            "uid-b",
            "bbb@example.com",
            "bbb-kith.tail.ts.net",
            None,
            2000,
        )
        .unwrap();
        let all = cs.list().unwrap();
        assert_eq!(all.len(), 2);
        let logins: Vec<&str> = all.iter().map(|c| c.login.as_str()).collect();
        assert!(logins.contains(&"aaa@example.com"));
        assert!(logins.contains(&"bbb@example.com"));
    }

    #[test]
    fn upsert_preserves_first_seen_at_on_update() {
        // Oracle: the ON CONFLICT clause must NOT update first_seen_at.
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-5",
            "carol@example.com",
            "carol-kith.tail.ts.net",
            None,
            1000,
        )
        .unwrap();
        cs.upsert(
            "uid-5",
            "carol@example.com",
            "carol-kith.tail.ts.net",
            None,
            9999,
        )
        .unwrap();
        let c = cs.get_by_peer_user_id("uid-5").unwrap().unwrap();
        // first_seen_at must remain at the original insert time.
        assert_eq!(c.first_seen_at, crate::util::unix_secs_to_rfc3339(1000));
        // last_seen_at must be updated.
        assert_eq!(c.last_seen_at, crate::util::unix_secs_to_rfc3339(9999));
    }

    #[test]
    fn upsert_advances_state() {
        let store = open();
        let cs = store.contacts();
        let s0 = cs.get_state().unwrap();
        cs.upsert(
            "uid-6",
            "dave@example.com",
            "dave-kith.tail.ts.net",
            None,
            5000,
        )
        .unwrap();
        let s1 = cs.get_state().unwrap();
        assert_ne!(s0, s1, "upsert must advance state counter");
    }

    #[test]
    fn set_blocked_on_nonexistent_does_not_advance_state() {
        // Oracle: set_blocked on an unknown peer_user_id must not advance the state
        // counter (UPDATE affects 0 rows, so no data actually changed).  Advancing state
        // for a no-op write produces spurious Contact/changes deltas for clients.
        let store = open();
        let cs = store.contacts();
        let state_before = cs.get_state().unwrap();
        cs.set_blocked("no-such-peer", true).unwrap();
        let state_after = cs.get_state().unwrap();
        assert_eq!(
            state_before, state_after,
            "set_blocked on a nonexistent peer must not advance the state counter"
        );
    }

    #[test]
    fn initial_state_is_s0() {
        // Oracle: state_counters initialized to 0 by SCHEMA_V1 migration.
        let store = open();
        assert_eq!(store.contacts().get_state().unwrap(), "s-0");
    }

    #[test]
    fn contact_changes_no_advance() {
        // Oracle: when since_state equals the current state, added must be empty.
        let store = open();
        let cs = store.contacts();
        let current = cs.get_state().unwrap();
        let result = cs.get_changes_since(&current).unwrap();
        assert!(result.added.is_empty(), "no advance means no changes");
        assert!(result.updated.is_empty());
        assert!(result.destroyed.is_empty());
        assert_eq!(result.new_state, current);
    }

    #[test]
    fn contact_changes_after_upsert() {
        // Oracle: a contact upserted after s-0 must appear in get_changes_since("s-0").added.
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-changes-1",
            "zara@example.com",
            "zara-kith.tail.ts.net",
            None,
            7000,
        )
        .unwrap();
        let result = cs.get_changes_since("s-0").unwrap();
        assert!(
            result.added.contains(&"uid-changes-1".to_string()),
            "upserted contact must appear in added; got {:?}",
            result.added
        );
        assert!(result.updated.is_empty());
        assert!(result.destroyed.is_empty());
    }

    #[test]
    fn contact_changes_malformed_state() {
        // Oracle: a non-"s-N" token must return KithError::Validation.
        let store = open();
        let cs = store.contacts();
        let result = cs.get_changes_since("garbage");
        match result {
            Err(KithError::Validation(msg)) => {
                assert_eq!(msg, "invalid state token");
            }
            other => panic!("expected KithError::Validation, got {:?}", other),
        }
    }

    // --- upsert_discovered_contact tests ---
    // Oracle: SQLite CASE WHEN semantics and ON CONFLICT DO UPDATE behavior
    // verified against the SQL spec and SQLite documentation independently of
    // any Rust code path.

    #[test]
    fn upsert_discovered_contact_inserts_new() {
        // Oracle: fresh INSERT must populate all columns as supplied.
        let store = open();
        store
            .contacts()
            .upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", Some("Bob"), 1000)
            .unwrap();
        let c = store
            .contacts()
            .get_by_peer_user_id("uid-bob")
            .unwrap()
            .unwrap();
        assert_eq!(c.login, "bob@test");
        assert_eq!(c.mailbox_host, "bob.ts.net");
        assert_eq!(c.display_name, Some("Bob".to_string()));
        assert_eq!(c.first_seen_at, crate::util::unix_secs_to_rfc3339(1000));
        assert!(!c.blocked);
    }

    #[test]
    fn upsert_discovered_preserves_existing_display_name() {
        // Oracle: ON CONFLICT CASE WHEN display_name IS NULL — when display_name
        // is non-NULL the ELSE branch keeps the existing value unchanged.
        let store = open();
        let cs = store.contacts();
        cs.upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", Some("Bob Auto"), 1000)
            .unwrap();
        // Simulate user having set a custom display name via the normal upsert path.
        cs.upsert(
            "uid-bob",
            "bob@test",
            "bob.ts.net",
            Some("Bob Custom"),
            2000,
        )
        .unwrap();
        // Re-discover with a different auto name — custom name must survive.
        cs.upsert_discovered_contact(
            "uid-bob",
            "bob@test",
            "bob-new.ts.net",
            Some("Bob Auto Again"),
            3000,
        )
        .unwrap();
        let c = cs.get_by_peer_user_id("uid-bob").unwrap().unwrap();
        assert_eq!(c.display_name, Some("Bob Custom".to_string())); // preserved
        assert_eq!(c.mailbox_host, "bob-new.ts.net"); // updated
    }

    #[test]
    fn upsert_discovered_sets_display_name_when_null() {
        // Oracle: ON CONFLICT CASE WHEN display_name IS NULL — when display_name
        // is NULL the THEN branch replaces it with excluded.display_name.
        let store = open();
        let cs = store.contacts();
        cs.upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", None, 1000)
            .unwrap();
        // Re-discover with a display name now available.
        cs.upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", Some("Bob"), 2000)
            .unwrap();
        let c = cs.get_by_peer_user_id("uid-bob").unwrap().unwrap();
        assert_eq!(c.display_name, Some("Bob".to_string()));
    }

    #[test]
    fn upsert_discovered_is_idempotent() {
        // Oracle: repeated identical calls must produce exactly one row and
        // never return an error (ON CONFLICT absorbs the duplicate).
        let store = open();
        for _ in 0..3 {
            store
                .contacts()
                .upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", Some("Bob"), 1000)
                .unwrap();
        }
        assert_eq!(store.contacts().list().unwrap().len(), 1);
    }

    #[test]
    fn upsert_discovered_preserves_first_seen_at() {
        // Oracle: first_seen_at is not listed in the ON CONFLICT DO UPDATE SET
        // clause, so SQLite leaves it at its original value on every conflict.
        let store = open();
        let cs = store.contacts();
        cs.upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", None, 1000)
            .unwrap();
        cs.upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", None, 9999)
            .unwrap();
        let c = cs.get_by_peer_user_id("uid-bob").unwrap().unwrap();
        assert_eq!(
            c.first_seen_at,
            crate::util::unix_secs_to_rfc3339(1000),
            "first_seen_at must not be overwritten on re-discovery"
        );
    }

    #[test]
    fn upsert_discovered_does_not_unblock() {
        // Oracle: blocked is not listed in the ON CONFLICT DO UPDATE SET clause,
        // so a blocked contact remains blocked after re-discovery.
        let store = open();
        let cs = store.contacts();
        cs.upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", None, 1000)
            .unwrap();
        cs.set_blocked("uid-bob", true).unwrap();
        cs.upsert_discovered_contact("uid-bob", "bob@test", "bob.ts.net", None, 2000)
            .unwrap();
        let c = cs.get_by_peer_user_id("uid-bob").unwrap().unwrap();
        assert!(
            c.blocked,
            "upsert_discovered_contact must not clear the blocked flag"
        );
    }
}
