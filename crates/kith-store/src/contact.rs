use crate::db_err;
use crate::message::ChangesResult;
use kith_core::{ChatContact, JmapError, KithError, StateChange};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::broadcast;

/// Row returned by `get_changes_since_ordered`: (peer_user_id, changed_at_counter, is_create).
type ContactChangeRow = (String, i64, bool);

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

    /// Insert or replace a contact record.  Advances the contact state counter only
    /// when the row is newly inserted or at least one column value actually changed.
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
        //
        // The DO UPDATE WHERE clause ensures the statement changes 0 rows (and
        // therefore does NOT advance the state counter) when every column is already
        // at the supplied value — identical successive calls are idempotent.
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "INSERT INTO contacts \
                    (peer_user_id, peer_login, peer_mailbox_host, display_name, \
                     first_seen_at, last_seen_at, blocked) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0) \
                 ON CONFLICT(peer_user_id) DO UPDATE SET \
                    peer_login        = excluded.peer_login, \
                    peer_mailbox_host = excluded.peer_mailbox_host, \
                    display_name      = excluded.display_name, \
                    last_seen_at      = excluded.last_seen_at \
                 WHERE excluded.peer_login IS NOT peer_login \
                    OR excluded.peer_mailbox_host IS NOT peer_mailbox_host \
                    OR excluded.display_name IS NOT display_name \
                    OR excluded.last_seen_at IS NOT last_seen_at",
                params![
                    peer_user_id,
                    peer_login,
                    peer_mailbox_host,
                    display_name,
                    now_unix,
                ],
            )
            .map_err(db_err)?;
        if affected > 0 {
            // Atomic: advance state counter and write changed_at_counter in one transaction.
            // A crash after the counter advances but before the row update would leave
            // this contact invisible to ChatContact/changes forever.
            let counter = crate::advance_state_counter_in_tx(&tx, "contact")?;
            stamp_contact_counters(&tx, peer_user_id, counter)?;
            tx.commit().map_err(db_err)?;
            self.emit(format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
        }
        Ok(())
    }

    /// Upsert a contact discovered via the automatic peer-discovery probe.
    ///
    /// Idempotent. On conflict:
    /// - Updates peer_login, peer_mailbox_host, last_seen_at
    /// - Updates display_name ONLY if it is currently NULL (preserves user-set names)
    /// - NEVER updates first_seen_at or blocked
    ///
    /// **mailbox_host is always overwritten** with the newly discovered value.
    /// In Phase 1 there is no UI to manually edit mailbox_host, so this is safe.
    /// If Phase 2 adds a Contact/set patch for mailbox_host, this function must
    /// be updated to preserve the owner-set value (e.g. add an `owner_set_host`
    /// column so discovery only updates when `owner_set_host IS NULL`).
    ///
    /// Advances the state counter only when a row is newly inserted or at least one
    /// column value actually changed; identical successive calls do not advance state.
    pub fn upsert_discovered_contact(
        &self,
        peer_user_id: &str,
        peer_login: &str,
        peer_mailbox_host: &str,
        discovered_display_name: Option<&str>,
        now_unix: i64,
    ) -> Result<(), KithError> {
        // The effective display_name after conflict resolution is either the existing
        // value (when non-NULL) or excluded.display_name (when NULL).  The WHERE
        // clause must mirror that CASE logic so the guard correctly detects no-ops.
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
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
                    last_seen_at      = excluded.last_seen_at \
                 WHERE excluded.peer_login IS NOT peer_login \
                    OR excluded.peer_mailbox_host IS NOT peer_mailbox_host \
                    OR (display_name IS NULL AND excluded.display_name IS NOT NULL) \
                    OR excluded.last_seen_at IS NOT last_seen_at",
                params![
                    peer_user_id,
                    peer_login,
                    peer_mailbox_host,
                    discovered_display_name,
                    now_unix,
                ],
            )
            .map_err(db_err)?;
        if affected > 0 {
            let counter = crate::advance_state_counter_in_tx(&tx, "contact")?;
            stamp_contact_counters(&tx, peer_user_id, counter)?;
            tx.commit().map_err(db_err)?;
            self.emit(format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
        }
        Ok(())
    }

    /// Fetch a single contact by peer_user_id.  Returns None if not found.
    pub fn get_by_peer_user_id(
        &self,
        peer_user_id: &str,
    ) -> Result<Option<ChatContact>, KithError> {
        let result = self.conn.query_row(
            "SELECT peer_user_id, peer_login, display_name, \
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

    /// Return the delivery host for a contact (DB-only; not in ChatContact JMAP type).
    pub fn get_mailbox_host(&self, peer_user_id: &str) -> Result<Option<String>, KithError> {
        let result = self.conn.query_row(
            "SELECT peer_mailbox_host FROM contacts WHERE peer_user_id = ?1",
            params![peer_user_id],
            |row| row.get(0),
        );
        match result {
            Ok(host) => Ok(Some(host)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
        }
    }

    /// Return all contacts ordered by peer_login.
    pub fn list(&self) -> Result<Vec<ChatContact>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT peer_user_id, peer_login, display_name, \
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

    /// Return the 0-based position of `peer_user_id` in the `ORDER BY peer_login` list.
    ///
    /// Counts contacts whose `peer_login` sorts strictly before the given contact's
    /// `peer_login`.  Returns `None` if `peer_user_id` is not in the table.
    ///
    /// Used by `Contact/queryChanges` to report insertion indices without loading the
    /// full contact list into memory.
    pub fn query_index(&self, peer_user_id: &str) -> Result<Option<u64>, KithError> {
        // Outer FROM anchors on the target contact so the query returns no rows
        // (→ None via .optional()) when peer_user_id is not in the table, rather
        // than returning 0 like a plain COUNT(*) would when the subquery returns NULL.
        let n: Option<i64> = self
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM contacts c2 WHERE c2.peer_login < c1.peer_login) \
                 FROM contacts c1 \
                 WHERE c1.peer_user_id = ?1",
                params![peer_user_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err)?;
        Ok(n.map(|n| n as u64))
    }

    /// Set the blocked flag for a contact.
    ///
    /// Advances the contact state counter only if the peer exists (i.e. the UPDATE
    /// actually matched a row). No-ops silently — without advancing state — when
    /// `peer_user_id` is not in the contacts table.
    pub fn set_blocked(&self, peer_user_id: &str, blocked: bool) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "UPDATE contacts SET blocked = ?1 WHERE peer_user_id = ?2 AND blocked IS NOT ?1",
                params![blocked as i64, peer_user_id],
            )
            .map_err(db_err)?;
        if affected > 0 {
            let counter = crate::advance_state_counter_in_tx(&tx, "contact")?;
            tx.execute(
                "UPDATE contacts SET changed_at_counter = ?1 WHERE peer_user_id = ?2",
                params![counter, peer_user_id],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            self.emit(format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
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

    /// Return IDs of contacts that changed after `since_state`.
    ///
    /// Uses per-row `changed_at_counter` to return only contacts that were
    /// actually modified after the given state — not a full re-sync.  Results
    /// are ordered by `changed_at_counter ASC`.
    ///
    /// `new_state` in the result is always the current store state, regardless
    /// of how many items are returned.
    ///
    /// **⚠ Do not use this method when `maxChanges` pagination is required.**
    /// When the caller must truncate the result and compute `newState` from the
    /// last returned item's counter, use [`get_changes_since_ordered`] instead —
    /// it surfaces per-row counters so the caller can derive the correct `newState`
    /// without a second query.  Using this method with truncation produces a
    /// `newState` that equals the current store state rather than the last
    /// returned item, which causes the client to skip over intermediate changes.
    ///
    /// [`get_changes_since_ordered`]: ContactStore::get_changes_since_ordered
    pub fn get_changes_since(&self, since_state: &str) -> Result<ChangesResult, KithError> {
        let (since_counter, current_counter, current_state) =
            self.resolve_since_counters(since_state)?;

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
            .prepare_cached(
                "SELECT peer_user_id, created_at_counter FROM contacts \
                 WHERE changed_at_counter > ?1 \
                 ORDER BY changed_at_counter ASC",
            )
            .map_err(db_err)?;
        let rows: Vec<(String, i64)> = stmt
            .query_map(params![since_counter], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut added = Vec::new();
        let mut updated = Vec::new();
        for (id, created_at) in rows {
            // is_create: row was first inserted after sinceState (RFC 8620 §5.2 created[]).
            // created_at_counter == 0 is the pre-V8 sentinel meaning "existed before
            // classification" — treat as updated, not created.
            if created_at > since_counter && created_at > 0 {
                added.push(id);
            } else {
                updated.push(id);
            }
        }

        Ok(ChangesResult {
            added,
            updated,
            destroyed: vec![],
            new_state: current_state,
        })
    }

    /// Return contacts that changed after `since_state` with per-row counters.
    ///
    /// Returns `(Vec<(peer_user_id, changed_at_counter)>, current_state)` ordered
    /// by `changed_at_counter ASC`.  The caller uses the last entry's counter to
    /// compute the correct `newState` when `maxChanges` truncation is applied
    /// (RFC 8620 §5.6): `newState = format!("s-{last_counter}")`.
    pub fn get_changes_since_ordered(
        &self,
        since_state: &str,
    ) -> Result<(Vec<ContactChangeRow>, String), KithError> {
        let (since_counter, current_counter, current_state) =
            self.resolve_since_counters(since_state)?;

        if since_counter >= current_counter {
            return Ok((vec![], current_state));
        }

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT peer_user_id, changed_at_counter, created_at_counter FROM contacts \
                 WHERE changed_at_counter > ?1 \
                 ORDER BY changed_at_counter ASC",
            )
            .map_err(db_err)?;
        // is_create = true when created_at_counter > since_counter, meaning the row
        // was first inserted after sinceState (RFC 8620 §5.2 created[]).
        // is_create = false means the row existed before sinceState and was updated.
        let rows: Vec<ContactChangeRow> = stmt
            .query_map(params![since_counter], |row| {
                let id: String = row.get(0)?;
                let changed: i64 = row.get(1)?;
                let created: i64 = row.get(2)?;
                Ok((id, changed, created > since_counter))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok((rows, current_state))
    }

    /// Parse `since_state` and return `(since_counter, current_counter, current_state)`.
    ///
    /// Factored out of `get_changes_since` and `get_changes_since_ordered` to
    /// eliminate the duplicated token-parse + state-read logic.
    fn resolve_since_counters(&self, since_state: &str) -> Result<(i64, i64, String), KithError> {
        let since_counter = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(JmapError::cannot_calculate_changes()))?;

        let current_state = self.get_state()?;
        let current_counter: i64 = current_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .expect("get_state always returns s-<integer>");

        Ok((since_counter, current_counter, current_state))
    }
}

/// Advance the per-row counters for a contact after an INSERT or UPDATE.
///
/// Sentinel logic:
/// - `created_at_counter == 0`: fresh insert — stamp both counters so the contact
///   appears in `created[]` in `ChatContact/changes`.
/// - `created_at_counter < 0`: pre-V8 row (V17 sentinel = -1) — reset
///   `created_at_counter` to 0 so `is_create = (0 > sinceState) = false`
///   (i.e. the contact is classified as *updated*, not created).
/// - otherwise: existing row — advance only `changed_at_counter`.
///
/// Must be called inside an open transaction `tx` that has already advanced the
/// global state counter to `counter`.
fn stamp_contact_counters(
    tx: &rusqlite::Transaction,
    peer_user_id: &str,
    counter: i64,
) -> Result<(), KithError> {
    let created_at: i64 = tx
        .query_row(
            "SELECT created_at_counter FROM contacts WHERE peer_user_id = ?1",
            params![peer_user_id],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    if created_at == 0 {
        // Fresh insert: stamp both counters so the contact appears in created[].
        tx.execute(
            "UPDATE contacts SET changed_at_counter = ?1, created_at_counter = ?1 \
             WHERE peer_user_id = ?2",
            params![counter, peer_user_id],
        )
        .map_err(db_err)?;
    } else if created_at < 0 {
        // Pre-V8 row (V17 sentinel = -1): existed before V8 classification.
        // Set created_at_counter = 0 so is_create = (0 > sinceState) = false.
        tx.execute(
            "UPDATE contacts SET changed_at_counter = ?1, created_at_counter = 0 \
             WHERE peer_user_id = ?2",
            params![counter, peer_user_id],
        )
        .map_err(db_err)?;
    } else {
        tx.execute(
            "UPDATE contacts SET changed_at_counter = ?1 WHERE peer_user_id = ?2",
            params![counter, peer_user_id],
        )
        .map_err(db_err)?;
    }
    Ok(())
}

/// Map a rusqlite Row to a ChatContact.  Column order must match the SELECT above.
/// Note: peer_mailbox_host is not selected here — it is a DB-only routing field.
/// Use ContactStore::get_mailbox_host when delivery routing is needed.
fn row_to_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatContact> {
    let peer_user_id: String = row.get(0)?;
    let peer_login: String = row.get(1)?;
    let display_name: Option<String> = row.get(2)?;
    let first_seen_at: i64 = row.get(3)?;
    let last_seen_at: i64 = row.get(4)?;
    let blocked: i64 = row.get(5)?;
    Ok(ChatContact {
        id: peer_user_id,
        login: peer_login,
        display_name,
        first_seen_at: {
            debug_assert!(
                first_seen_at >= 0,
                "timestamp must be non-negative Unix seconds, got {first_seen_at}"
            );
            crate::util::unix_secs_to_rfc3339(first_seen_at.max(0) as u64)
        },
        last_seen_at: {
            debug_assert!(
                last_seen_at >= 0,
                "timestamp must be non-negative Unix seconds, got {last_seen_at}"
            );
            crate::util::unix_secs_to_rfc3339(last_seen_at.max(0) as u64)
        },
        blocked: blocked != 0,
    })
}

/// Increment the contact state counter and return the new state string like "s-5".
///
/// The UPDATE and SELECT are wrapped in a transaction so that no concurrent
/// writer can advance the counter between the two statements and cause this
/// caller to return a stale value.
fn advance_state(conn: &Connection) -> Result<String, KithError> {
    let tx = conn.unchecked_transaction().map_err(db_err)?;
    tx.execute(
        "UPDATE state_counters SET counter = counter + 1 WHERE type_name = 'contact'",
        [],
    )
    .map_err(db_err)?;
    let counter: i64 = tx
        .query_row(
            "SELECT counter FROM state_counters WHERE type_name = 'contact'",
            [],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    tx.commit().map_err(db_err)?;
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
        assert_eq!(c.id, "uid-1");
        assert_eq!(c.login, "alice@example.com");
        assert_eq!(
            cs.get_mailbox_host("uid-1").unwrap(),
            Some("alice-kith.tail.ts.net".to_string())
        );
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
    fn contact_changes_update_goes_to_updated_not_added() {
        // Oracle: a contact that existed before sinceState and was then modified
        // must appear in updated[], NOT added[].  get_changes_since previously put
        // all IDs in added[] regardless of create/update status (KITH-hqrw.51).
        //
        // Sequence:
        //   1. Insert uid-upd at t=1000  → state s-1
        //   2. Record s-1 as sinceState
        //   3. Update uid-upd at t=2000 (different last_seen_at → counter advances)
        //   4. get_changes_since("s-1") must have uid-upd in updated[], NOT added[].
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-upd",
            "upd@example.com",
            "upd-kith.tail.ts.net",
            None,
            1000,
        )
        .unwrap();
        let since = cs.get_state().unwrap();
        // Touch the row so it appears in the next changes window.
        cs.upsert(
            "uid-upd",
            "upd@example.com",
            "upd-kith.tail.ts.net",
            None,
            2000,
        )
        .unwrap();
        let result = cs.get_changes_since(&since).unwrap();
        assert!(
            !result.added.contains(&"uid-upd".to_string()),
            "updated contact must NOT appear in added[]; added={:?}",
            result.added
        );
        assert!(
            result.updated.contains(&"uid-upd".to_string()),
            "updated contact must appear in updated[]; updated={:?}",
            result.updated
        );
    }

    #[test]
    fn contact_changes_malformed_state() {
        // Oracle: a non-"s-N" token must return cannotCalculateChanges (RFC 8620 §5.2).
        let store = open();
        let cs = store.contacts();
        let result = cs.get_changes_since("garbage");
        match result {
            Err(KithError::Jmap(e)) => {
                assert_eq!(e.error_type, "cannotCalculateChanges");
            }
            other => panic!("expected cannotCalculateChanges, got {:?}", other),
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
        assert_eq!(
            store.contacts().get_mailbox_host("uid-bob").unwrap(),
            Some("bob.ts.net".to_string())
        );
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
        assert_eq!(
            cs.get_mailbox_host("uid-bob").unwrap(),
            Some("bob-new.ts.net".to_string())
        ); // updated
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
    fn upsert_identical_twice_does_not_advance_state() {
        // Oracle: calling upsert twice with identical values must NOT advance the state
        // counter the second time — no data changed so no state event should fire.
        // Independent check: state string read before and after the second call must be equal.
        let store = open();
        let cs = store.contacts();
        cs.upsert(
            "uid-idem",
            "idem@example.com",
            "idem-kith.tail.ts.net",
            Some("Idem"),
            1000,
        )
        .unwrap();
        let state_after_first = cs.get_state().unwrap();
        // Second call with identical values.
        cs.upsert(
            "uid-idem",
            "idem@example.com",
            "idem-kith.tail.ts.net",
            Some("Idem"),
            1000,
        )
        .unwrap();
        let state_after_second = cs.get_state().unwrap();
        assert_eq!(
            state_after_first, state_after_second,
            "upsert with identical values must not advance the state counter"
        );
    }

    #[test]
    fn upsert_discovered_identical_twice_does_not_advance_state() {
        // Oracle: calling upsert_discovered_contact twice with identical values must NOT
        // advance the state counter the second time.
        let store = open();
        let cs = store.contacts();
        cs.upsert_discovered_contact(
            "uid-idem2",
            "idem2@example.com",
            "idem2-kith.tail.ts.net",
            Some("Idem2"),
            2000,
        )
        .unwrap();
        let state_after_first = cs.get_state().unwrap();
        cs.upsert_discovered_contact(
            "uid-idem2",
            "idem2@example.com",
            "idem2-kith.tail.ts.net",
            Some("Idem2"),
            2000,
        )
        .unwrap();
        let state_after_second = cs.get_state().unwrap();
        assert_eq!(
            state_after_first, state_after_second,
            "upsert_discovered_contact with identical values must not advance the state counter"
        );
    }

    #[test]
    fn query_index_returns_position_in_sorted_order() {
        // Oracle: contacts are sorted by peer_login ASC.
        // Insert alice (aaa@), bob (bbb@), carol (ccc@) in that order.
        // alice → index 0 (0 contacts before "aaa@")
        // bob   → index 1 (1 contact before "bbb@": alice)
        // carol → index 2 (2 contacts before "ccc@": alice, bob)
        // uid-nobody → None (not in table)
        let store = open();
        let cs = store.contacts();
        cs.upsert("uid-alice", "aaa@example.com", "alice.ts.net", None, 1000)
            .unwrap();
        cs.upsert("uid-bob", "bbb@example.com", "bob.ts.net", None, 1000)
            .unwrap();
        cs.upsert("uid-carol", "ccc@example.com", "carol.ts.net", None, 1000)
            .unwrap();

        assert_eq!(cs.query_index("uid-alice").unwrap(), Some(0));
        assert_eq!(cs.query_index("uid-bob").unwrap(), Some(1));
        assert_eq!(cs.query_index("uid-carol").unwrap(), Some(2));
        assert_eq!(
            cs.query_index("uid-nobody").unwrap(),
            None,
            "non-existent contact must return None"
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

    #[test]
    fn pre_v8_contact_upsert_classified_as_updated() {
        // Oracle: contacts migrated from before V8 have created_at_counter = 0 after V13,
        // which V17 changes to -1. The first upsert() on such a row must classify it as
        // "updated" (not "created") in get_changes_since_ordered. An is_create = true
        // result for a pre-existing contact is a protocol violation (RFC 8620 \u00a75.2).
        //
        // The test manually sets created_at_counter = -1 to simulate the V17 migration
        // state, then verifies the returned is_create flag using get_changes_since_ordered
        // independent of the upsert code path that determines the flag.
        use rusqlite::params;
        let store = open();
        let cs = store.contacts();

        // Insert a contact normally (creates a fresh row with created_at_counter = N).
        cs.upsert(
            "uid-pre-v8",
            "oldpeer@example.com",
            "oldpeer-kith.tail.ts.net",
            None,
            1000,
        )
        .unwrap();

        // Simulate V18 migration state: set created_at_counter = -1 to mimic a pre-V8
        // row that V13 left at 0 and V17 re-stamped as -1.
        store
            .conn
            .execute(
                "UPDATE contacts SET created_at_counter = -1 WHERE peer_user_id = ?1",
                params!["uid-pre-v8"],
            )
            .expect("manual sentinel set must succeed");

        // Record state before the upsert so we can use it as sinceState.
        let since = cs.get_state().unwrap();

        // Touch the contact (last_seen_at changes) to trigger the sentinel path.
        cs.upsert(
            "uid-pre-v8",
            "oldpeer@example.com",
            "oldpeer-kith.tail.ts.net",
            None,
            9999,
        )
        .unwrap();

        // get_changes_since_ordered must classify this contact as updated (is_create = false).
        let (rows, _new_state) = cs.get_changes_since_ordered(&since).unwrap();
        let entry = rows
            .iter()
            .find(|(id, _, _)| id == "uid-pre-v8")
            .expect("uid-pre-v8 must appear in changes after upsert");
        let is_create = entry.2;
        assert!(
            !is_create,
            "pre-V8 contact touched by upsert must appear as updated (is_create=false), not created"
        );
    }
}
