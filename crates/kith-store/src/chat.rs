use crate::db_err;
use crate::message::ChangesResult;
use kith_core::{Chat, ChatKind, Id, JmapError, KithError, StateChange, UTCDate};
use rusqlite::{params, Connection};
use tokio::sync::broadcast;

/// Row type returned by [`ChatStore::get_changes_since_ordered`].
/// Fields: (chat_id, changed_at_counter, is_create).
pub type ChatChangeRow = (String, i64, bool);

/// Convert a DB kind string ("direct", "group", "channel") to the typed enum.
/// Unknown values are preserved via `ChatKind::Other(s)`.
fn parse_chat_kind(s: &str) -> ChatKind {
    match s {
        "direct" => ChatKind::Direct,
        "group" => ChatKind::Group,
        "channel" => ChatKind::Channel,
        other => ChatKind::Other(other.to_owned()),
    }
}

pub struct ChatStore<'a> {
    conn: &'a Connection,
    events_tx: Option<&'a broadcast::Sender<StateChange>>,
}

impl<'a> ChatStore<'a> {
    pub fn new(
        conn: &'a Connection,
        events_tx: Option<&'a broadcast::Sender<StateChange>>,
    ) -> Self {
        Self { conn, events_tx }
    }

    fn emit(&self, new_state: String) {
        if let Some(tx) = self.events_tx {
            let _ = tx.send(StateChange {
                type_name: "Chat".to_string(),
                new_state,
            });
        }
    }

    /// Create a chat with a caller-supplied ID (server-assigned ULID for owner
    /// chats, peer-supplied chatId for inbound Peer/deliver).
    ///
    /// Idempotent: INSERT OR IGNORE means a second call is a no-op when a row
    /// already exists.  State is advanced only when a new row is actually inserted.
    ///
    /// Two distinct cases trigger IGNORE:
    /// - Same `chat_id` already exists (PRIMARY KEY conflict): `self.get(chat_id)`
    ///   returns the existing row.  This is the Peer/deliver retry path.
    /// - Same `contact_id` already exists with a different ULID (UNIQUE INDEX
    ///   `chats_direct_contact` conflict): `self.get(chat_id)` returns None because
    ///   the new ULID was never written.  We fall back to `find_direct_by_contact_id`
    ///   to return the row that won the race.  This is the concurrent Chat/set path.
    pub fn create(
        &self,
        chat_id: &str,
        kind: &str,
        contact_id: Option<&str>,
        now_unix: i64,
    ) -> Result<Chat, KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "INSERT OR IGNORE INTO chats (id, kind, contact_id, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![chat_id, kind, contact_id, now_unix],
            )
            .map_err(db_err)?;

        if affected > 0 {
            // Atomic: advance state counter and write both counters in one transaction.
            // created_at_counter is stamped once at creation so Chat/changes can
            // distinguish new chats (is_create=true) from updated chats (is_create=false).
            let counter = crate::advance_state_counter_in_tx(&tx, "chat")?;
            tx.execute(
                "UPDATE chats SET changed_at_counter = ?1, created_at_counter = ?1 WHERE id = ?2",
                params![counter, chat_id],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            self.emit(format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
        }

        // Try by primary key first (covers PK conflict and the new-insert case).
        if let Some(chat) = self.get(chat_id)? {
            return Ok(chat);
        }
        // INSERT OR IGNORE fired due to the contact_id UNIQUE constraint: a concurrent
        // create for the same contact won the race.  Return whichever row was written.
        if let Some(cid) = contact_id {
            if let Some(chat) = self.find_direct_by_contact_id(cid)? {
                return Ok(chat);
            }
        }
        Err(KithError::Store(format!(
            "chat '{}' not found after insert",
            chat_id
        )))
    }

    /// Add a peer participant to a group chat.
    ///
    /// Idempotent: INSERT OR IGNORE is a no-op if the row already exists.
    pub fn add_member(&self, chat_id: &str, peer_user_id: &str) -> Result<(), KithError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO chat_members (chat_id, peer_user_id) VALUES (?1, ?2)",
                params![chat_id, peer_user_id],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Return all peer participant IDs for a chat.
    ///
    /// For group chats, returns members stored in `chat_members`.
    pub fn get_members(&self, chat_id: &str) -> Result<Vec<String>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT peer_user_id FROM chat_members WHERE chat_id = ?1")
            .map_err(db_err)?;
        let members = stmt
            .query_map(params![chat_id], |row| row.get::<_, String>(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(members)
    }

    /// Find an existing direct chat by the peer contact's userId.
    ///
    /// Used by Chat/set create to deduplicate: if a direct chat with this
    /// contact already exists, return it rather than creating a new one.
    pub fn find_direct_by_contact_id(&self, contact_id: &str) -> Result<Option<Chat>, KithError> {
        let row = self.conn.query_row(
            "SELECT c.id, c.kind, c.contact_id, c.created_at, c.last_message_at, \
                    (SELECT COUNT(*) FROM messages m \
                     WHERE m.chat_id = c.id \
                       AND m.delivery_state = 'received' \
                       AND m.read_at IS NULL) AS unread_count \
             FROM chats c WHERE c.kind = 'direct' AND c.contact_id = ?1",
            params![contact_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, u32>(5)?,
                ))
            },
        );
        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(db_err(e)),
            Ok(_) => {}
        }
        let (id, kind, contact_id_val, created_at_secs, last_message_at_secs, unread_count) =
            row.unwrap();
        debug_assert!(
            created_at_secs >= 0,
            "timestamp must be non-negative Unix seconds, got {created_at_secs}"
        );
        let mut chat = Chat::new(
            Id::from(id),
            parse_chat_kind(&kind),
            UTCDate::from(crate::util::unix_secs_to_rfc3339(created_at_secs.max(0) as u64)),
            unread_count as u64,
            vec![],   // pinned_message_ids (not implemented yet)
            false,    // muted (not implemented yet)
            false,    // receive_typing_indicators (not implemented yet)
        );
        chat.contact_id = contact_id_val.map(Id::from);
        chat.last_message_at = last_message_at_secs.map(|s| {
            debug_assert!(
                s >= 0,
                "timestamp must be non-negative Unix seconds, got {s}"
            );
            UTCDate::from(crate::util::unix_secs_to_rfc3339(s.max(0) as u64))
        });
        Ok(Some(chat))
    }

    /// Fetch a single chat by ID, returning None if it does not exist.
    pub fn get(&self, chat_id: &str) -> Result<Option<Chat>, KithError> {
        let row = self.conn.query_row(
            "SELECT c.id, c.kind, c.contact_id, c.created_at, c.last_message_at, \
                    (SELECT COUNT(*) FROM messages m \
                     WHERE m.chat_id = c.id \
                       AND m.delivery_state = 'received' \
                       AND m.read_at IS NULL) AS unread_count \
             FROM chats c WHERE c.id = ?1",
            params![chat_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, u32>(5)?,
                ))
            },
        );

        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(db_err(e)),
            Ok(_) => {}
        }

        let (id, kind, contact_id, created_at_secs, last_message_at_secs, unread_count) =
            row.unwrap();

        debug_assert!(
            created_at_secs >= 0,
            "timestamp must be non-negative Unix seconds, got {created_at_secs}"
        );
        let mut chat = Chat::new(
            Id::from(id),
            parse_chat_kind(&kind),
            UTCDate::from(crate::util::unix_secs_to_rfc3339(created_at_secs.max(0) as u64)),
            unread_count as u64,
            vec![],   // pinned_message_ids (not implemented yet)
            false,    // muted (not implemented yet)
            false,    // receive_typing_indicators (not implemented yet)
        );
        chat.contact_id = contact_id.map(Id::from);
        chat.last_message_at = last_message_at_secs.map(|s| {
            debug_assert!(
                s >= 0,
                "timestamp must be non-negative Unix seconds, got {s}"
            );
            UTCDate::from(crate::util::unix_secs_to_rfc3339(s.max(0) as u64))
        });
        Ok(Some(chat))
    }

    /// List all chats ordered by last_message_at DESC (nulls last), then created_at DESC.
    pub fn list(&self) -> Result<Vec<Chat>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT c.id, c.kind, c.contact_id, c.created_at, c.last_message_at, \
                        (SELECT COUNT(*) FROM messages m \
                         WHERE m.chat_id = c.id \
                           AND m.delivery_state = 'received' \
                           AND m.read_at IS NULL) AS unread_count \
                 FROM chats c \
                 ORDER BY c.last_message_at DESC NULLS LAST, c.created_at DESC",
            )
            .map_err(db_err)?;

        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, String, Option<String>, i64, Option<i64>, u32)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, u32>(5)?,
                ))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let chats = rows
            .into_iter()
            .map(
                |(id, kind, contact_id, created_at_secs, last_message_at_secs, unread_count)| {
                    debug_assert!(created_at_secs >= 0, "timestamp must be non-negative Unix seconds, got {created_at_secs}");
                    let mut chat = Chat::new(
                        Id::from(id),
                        parse_chat_kind(&kind),
                        UTCDate::from(crate::util::unix_secs_to_rfc3339(created_at_secs.max(0) as u64)),
                        unread_count as u64,
                        vec![],   // pinned_message_ids (not implemented yet)
                        false,    // muted (not implemented yet)
                        false,    // receive_typing_indicators (not implemented yet)
                    );
                    chat.contact_id = contact_id.map(Id::from);
                    chat.last_message_at = last_message_at_secs.map(|s| {
                        debug_assert!(s >= 0, "timestamp must be non-negative Unix seconds, got {s}");
                        UTCDate::from(crate::util::unix_secs_to_rfc3339(s.max(0) as u64))
                    });
                    chat
                },
            )
            .collect();

        Ok(chats)
    }

    /// List all chat IDs ordered by last_message_at DESC (nulls last), then created_at DESC.
    ///
    /// More efficient than `list()` when only IDs are needed.
    pub fn list_ids(&self) -> Result<Vec<String>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM chats \
                 ORDER BY last_message_at DESC NULLS LAST, created_at DESC",
            )
            .map_err(db_err)?;

        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(ids)
    }

    /// List a page of chat IDs with SQL-level LIMIT and OFFSET.
    ///
    /// Uses the same ORDER BY as `list()`: last_message_at DESC NULLS LAST, created_at DESC.
    /// Returns up to `limit` IDs starting at 0-based `offset`.
    pub fn list_ids_paged(&self, limit: u32, offset: u32) -> Result<Vec<String>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM chats \
                 ORDER BY last_message_at DESC NULLS LAST, created_at DESC \
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(db_err)?;

        let ids = stmt
            .query_map(params![limit, offset], |row| row.get::<_, String>(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(ids)
    }

    /// Return the total number of chats as a `u64`.
    pub fn count(&self) -> Result<u64, KithError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM chats", [], |row| row.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }

    /// Update the last_message_at timestamp for a chat and advance the chat state counter.
    ///
    /// Only advances the state counter if the chat actually exists (UPDATE matched a row).
    /// Returns `Err(KithError::Store)` if `chat_id` does not exist.
    pub fn update_last_message_at(&self, chat_id: &str, ts: i64) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "UPDATE chats SET last_message_at = ?1 WHERE id = ?2",
                params![ts, chat_id],
            )
            .map_err(db_err)?;
        if affected > 0 {
            let counter = crate::advance_state_counter_in_tx(&tx, "chat")?;
            tx.execute(
                "UPDATE chats SET changed_at_counter = ?1 WHERE id = ?2",
                params![counter, chat_id],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            self.emit(format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
            return Err(KithError::Store("chat not found".into()));
        }
        Ok(())
    }

    /// Count messages in this chat that are received and unread (read_at IS NULL).
    pub fn unread_count(&self, chat_id: &str) -> Result<u32, KithError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages \
                 WHERE chat_id = ?1 \
                   AND delivery_state = 'received' \
                   AND read_at IS NULL",
                params![chat_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(count as u32)
    }

    /// Return the current chat state counter as a string token.
    pub fn get_state(&self) -> Result<String, KithError> {
        let counter: i64 = self
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'chat'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(format!("s-{counter}"))
    }

    /// Increment the chat state counter and return the new value as a string token.
    ///
    /// The UPDATE and SELECT are wrapped in a transaction so that no concurrent
    /// writer can advance the counter between the two statements and cause this
    /// caller to return a stale value.
    ///
    /// **Warning:** This method advances the global state counter WITHOUT stamping
    /// any chat row's `changed_at_counter`.  A caller that invokes this directly
    /// produces a phantom state advance: `new_state > since_state` but
    /// `get_changes_since` returns no rows, which can confuse RFC 8620 §5.2 clients.
    /// The only legitimate use is in `kithd` integration tests that need to prime
    /// the state counter to a known value before asserting SSE replay behaviour —
    /// never in production code paths.  All production writes use
    /// `advance_state_counter_in_tx` inside a transaction that also stamps the
    /// per-row counter.  This method remains `pub` only because `kithd` (a separate
    /// crate) calls it from tests; it cannot be `pub(crate)`.
    pub fn advance_state(&self) -> Result<String, KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        // Delegate to the shared helper so the i64 overflow guard fires here
        // too, not just in production paths that use advance_state_counter_in_tx
        // directly within a larger transaction.
        let counter = crate::advance_state_counter_in_tx(&tx, "chat")?;
        tx.commit().map_err(db_err)?;
        Ok(format!("s-{counter}"))
    }

    /// Return IDs of chats that were created or updated after `since_state`.
    ///
    /// Uses per-row `changed_at_counter` (added in V9 migration) to return only
    /// chats that were actually modified after the given state — not a full re-sync.
    /// Results are ordered by `changed_at_counter ASC` (oldest change first).
    ///
    /// `new_state` in the result is always the current store state.
    ///
    /// **⚠ Do not use this method when `maxChanges` pagination is required.**
    /// When the caller must truncate the result and compute `newState` from the
    /// last returned item's counter, use [`get_changes_since_ordered`] instead.
    ///
    /// [`get_changes_since_ordered`]: ChatStore::get_changes_since_ordered
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
                "SELECT id, created_at_counter FROM chats \
                 WHERE changed_at_counter > ?1 ORDER BY changed_at_counter ASC",
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
            // created_at_counter == 0 is the pre-classification sentinel — treat as updated.
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

    /// Return `(id, changed_at_counter)` pairs for chats created or updated after
    /// `since_state`, ordered by `changed_at_counter ASC` (oldest change first).
    ///
    /// This is the ordered form of `get_changes_since`, suitable for `maxChanges`
    /// truncation: callers can take the first N items, use the last item's
    /// `changed_at_counter` to compute `newState = "s-{counter}"`, and page
    /// forward correctly without skipping intermediate changes.
    pub fn get_changes_since_ordered(
        &self,
        since_state: &str,
    ) -> Result<(Vec<ChatChangeRow>, String), KithError> {
        let (since_counter, current_counter, current_state) =
            self.resolve_since_counters(since_state)?;

        if since_counter >= current_counter {
            return Ok((vec![], current_state));
        }

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, changed_at_counter, created_at_counter \
                 FROM chats WHERE changed_at_counter > ?1 ORDER BY changed_at_counter ASC",
            )
            .map_err(db_err)?;
        let rows: Vec<(String, i64, bool)> = stmt
            .query_map(params![since_counter], |row| {
                let id: String = row.get(0)?;
                let changed: i64 = row.get(1)?;
                let created: i64 = row.get(2)?;
                // Match get_changes_since: created_at_counter=0 is the
                // pre-classification sentinel — treat as updated, not created.
                Ok((id, changed, created > since_counter && created > 0))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok((rows, current_state))
    }

    /// Parse `since_state` and return `(since_counter, current_counter, current_state)`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use kith_core::KithError;

    #[test]
    fn create_is_idempotent() {
        // Oracle: calling create twice with the same ID must return the
        // same created_at value and not error. INSERT OR IGNORE semantics.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let chat1 = cs
            .create("chat-aaa", "direct", Some("uid:bob"), 1_000_000)
            .unwrap();
        let chat2 = cs
            .create("chat-aaa", "direct", Some("uid:bob"), 2_000_000)
            .unwrap();

        assert_eq!(chat1.id, chat2.id);
        assert_eq!(
            chat1.created_at, chat2.created_at,
            "created_at must not change on second call"
        );
        assert_eq!(chat1.kind, ChatKind::Direct);
        assert_eq!(chat1.contact_id.as_ref().map(|id| id.as_ref()), Some("uid:bob"));
    }

    #[test]
    fn find_direct_by_contact_id_returns_existing() {
        // Oracle: a direct chat created with contact_id must be findable by that id.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-bbb", "direct", Some("uid:carol"), 1_000_000)
            .unwrap();

        let found = cs
            .find_direct_by_contact_id("uid:carol")
            .unwrap()
            .expect("must find existing direct chat");
        assert_eq!(found.id, "chat-bbb");
        assert_eq!(found.contact_id.as_ref().map(|id| id.as_ref()), Some("uid:carol"));
    }

    #[test]
    fn find_direct_by_contact_id_returns_none_when_absent() {
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        let result = cs.find_direct_by_contact_id("uid:nobody").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_ordered_by_last_message_at_desc() {
        // Oracle: SQL ORDER BY last_message_at DESC NULLS LAST.
        // We insert three chats, set last_message_at on two of them, and verify
        // the returned order. The chat with no last_message_at comes last.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-x1", "direct", Some("uid:alice"), 1_000_000)
            .unwrap();
        cs.create("chat-x2", "direct", Some("uid:bob"), 1_000_001)
            .unwrap();
        cs.create("chat-x3", "direct", Some("uid:carol"), 1_000_002)
            .unwrap();

        // Give chat-x1 a more recent message, chat-x2 an older one; chat-x3 has none.
        cs.update_last_message_at("chat-x1", 2_000_000).unwrap();
        cs.update_last_message_at("chat-x2", 1_500_000).unwrap();

        let chats = cs.list().unwrap();
        assert_eq!(chats.len(), 3);
        assert_eq!(chats[0].id, "chat-x1", "most recent message first");
        assert_eq!(chats[1].id, "chat-x2", "second most recent next");
        assert_eq!(chats[2].id, "chat-x3", "no messages comes last");
    }

    #[test]
    fn list_returns_correct_unread_count() {
        // Oracle: list() must return unread_count matching the correlated subquery —
        // messages with delivery_state='received' AND read_at IS NULL for that chat.
        // Insert 3 received+unread, 1 received+read, 1 pending into chat-y1.
        // chat-y2 has no messages at all. Expect unread_count=3 and 0 respectively.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-y1", "direct", Some("uid:hank"), 1_000_000)
            .unwrap();
        cs.create("chat-y2", "direct", Some("uid:irene"), 1_000_001)
            .unwrap();

        let insert_msg = |id: &str, chat: &str, state: &str, read_at: Option<i64>| {
            store
                .conn
                .execute(
                    "INSERT INTO messages \
                     (id, chat_id, sender_user_id, body, created_at, delivery_state, read_at, sender_msg_id) \
                     VALUES (?1, ?2, 'uid:hank', 'hi', 1000000, ?3, ?4, ?1)",
                    params![id, chat, state, read_at],
                )
                .unwrap();
        };

        insert_msg("uy-r1", "chat-y1", "received", None); // unread
        insert_msg("uy-r2", "chat-y1", "received", None); // unread
        insert_msg("uy-r3", "chat-y1", "received", None); // unread
        insert_msg("uy-r4", "chat-y1", "received", Some(1_000_001)); // read
        insert_msg("uy-p1", "chat-y1", "pending", None); // outgoing — not counted

        let chats = cs.list().unwrap();
        assert_eq!(chats.len(), 2);

        let y2 = chats.iter().find(|c| c.id == "chat-y2").unwrap();
        assert_eq!(
            y2.unread_count, 0,
            "chat with no messages must have unread_count=0"
        );

        let y1 = chats.iter().find(|c| c.id == "chat-y1").unwrap();
        assert_eq!(
            y1.unread_count, 3,
            "list() must return 3 for chat with 3 received+unread messages"
        );
    }

    #[test]
    fn update_last_message_at_changes_field_and_advances_state() {
        // Oracle: after update_last_message_at, the returned Chat reflects the new
        // timestamp and the state counter is strictly greater than before.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-ccc", "direct", Some("uid:eve"), 1_000_000)
            .unwrap();
        let parse_n = |s: String| s.strip_prefix("s-").unwrap().parse::<u64>().unwrap();
        let state_before = parse_n(cs.get_state().unwrap());

        cs.update_last_message_at("chat-ccc", 1_600_000_000)
            .unwrap();

        let state_after = parse_n(cs.get_state().unwrap());
        assert!(
            state_after > state_before,
            "state counter must advance after update_last_message_at"
        );

        let chat = cs.get("chat-ccc").unwrap().unwrap();
        assert_eq!(
            chat.last_message_at.as_ref().map(|d| d.as_ref()),
            Some("2020-09-13T12:26:40Z"),
            "last_message_at must reflect the stored unix timestamp (oracle: Python 3 utcfromtimestamp(1_600_000_000))"
        );
    }

    #[test]
    fn unread_count_counts_only_received_and_unread() {
        // Oracle: unread_count = messages with delivery_state='received' AND read_at IS NULL.
        // Insert 3 received+unread, 1 received+read, 1 pending. Expect count=3.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-ddd", "direct", Some("uid:frank"), 1_000_000)
            .unwrap();

        // Insert messages directly — we don't have a MessageStore yet.
        let insert_msg = |id: &str, state: &str, read_at: Option<i64>| {
            store
                .conn
                .execute(
                    "INSERT INTO messages \
                     (id, chat_id, sender_user_id, body, created_at, delivery_state, read_at, sender_msg_id) \
                     VALUES (?1, 'chat-ddd', 'uid:frank', 'hi', 1000000, ?2, ?3, ?1)",
                    params![id, state, read_at],
                )
                .unwrap();
        };

        insert_msg("msg-r1", "received", None); // unread
        insert_msg("msg-r2", "received", None); // unread
        insert_msg("msg-r3", "received", None); // unread
        insert_msg("msg-r4", "received", Some(1_000_001)); // read
        insert_msg("msg-p1", "pending", None); // outgoing — not counted

        let count = cs.unread_count("chat-ddd").unwrap();
        assert_eq!(count, 3, "only received+unread messages should be counted");
    }

    #[test]
    fn create_does_not_advance_state_on_cache_hit() {
        // Oracle: when the chat already exists, INSERT OR IGNORE is a no-op (0 rows
        // affected), so the state counter must NOT advance. Spurious advances produce
        // phantom Chat/changes deltas for clients.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-zzz", "direct", Some("uid:alice"), 1_000_000)
            .unwrap();
        let state_after_create = cs.get_state().unwrap();

        // Second call with identical args — pure cache hit.
        cs.create("chat-zzz", "direct", Some("uid:alice"), 1_000_000)
            .unwrap();
        let state_after_hit = cs.get_state().unwrap();

        assert_eq!(
            state_after_create, state_after_hit,
            "state counter must not advance on a pure cache hit"
        );
    }

    #[test]
    fn list_ids_returns_only_ids_in_correct_order() {
        // Oracle: list_ids must return the same ordering as list() but only the id field.
        // With last_message_at set: chat-x1 (most recent) → chat-x2 → chat-x3 (no message).
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-lid1", "direct", Some("uid:a"), 1_000_001)
            .unwrap();
        cs.create("chat-lid2", "direct", Some("uid:b"), 1_000_002)
            .unwrap();
        cs.create("chat-lid3", "direct", Some("uid:c"), 1_000_003)
            .unwrap();

        cs.update_last_message_at("chat-lid1", 2_000_000).unwrap();
        cs.update_last_message_at("chat-lid2", 1_500_000).unwrap();
        // chat-lid3 has no message.

        let ids = cs.list_ids().unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], "chat-lid1", "most recent message first");
        assert_eq!(ids[1], "chat-lid2", "second most recent next");
        assert_eq!(ids[2], "chat-lid3", "no messages last");
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        let result = cs.get("no-such-chat").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_state_initially_zero() {
        // Oracle: SCHEMA_V1 initializes state_counters with counter=0 for 'chat'.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        assert_eq!(cs.get_state().unwrap(), "s-0");
    }

    #[test]
    fn advance_state_increments_by_one() {
        // Oracle: each advance_state call returns exactly one more than before.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        let s1 = cs.advance_state().unwrap();
        let s2 = cs.advance_state().unwrap();
        let s3 = cs.advance_state().unwrap();
        assert_eq!(s1, "s-1");
        assert_eq!(s2, "s-2");
        assert_eq!(s3, "s-3");
    }

    #[test]
    fn chat_changes_no_advance() {
        // Oracle: when since_state equals the current state, added must be empty.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        let current = cs.get_state().unwrap();
        let result = cs.get_changes_since(&current).unwrap();
        assert!(result.added.is_empty(), "no advance means no changes");
        assert!(result.updated.is_empty());
        assert!(result.destroyed.is_empty());
        assert_eq!(result.new_state, current);
    }

    #[test]
    fn chat_changes_after_create() {
        // Oracle: a chat created after s-0 must appear in get_changes_since("s-0").added.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        cs.create("chat-gc1", "direct", Some("uid:alice"), 1_000_000)
            .unwrap();
        let result = cs.get_changes_since("s-0").unwrap();
        assert!(
            result.added.contains(&"chat-gc1".to_string()),
            "created chat must appear in added; got {:?}",
            result.added
        );
        assert!(result.updated.is_empty());
        assert!(result.destroyed.is_empty());
    }

    #[test]
    fn chat_changes_malformed_state() {
        // Oracle: a token without "s-" prefix must return cannotCalculateChanges (RFC 8620 §5.2).
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        let result = cs.get_changes_since("x-1");
        match result {
            Err(KithError::Jmap(e)) => {
                assert_eq!(e.error_type, "cannotCalculateChanges");
            }
            other => panic!("expected cannotCalculateChanges, got {:?}", other),
        }
    }

    #[test]
    fn chat_changes_update_goes_to_updated_not_added() {
        // Oracle: a chat that existed before sinceState and was then modified must
        // appear in updated[], NOT added[].  get_changes_since previously put all
        // IDs in added[] regardless of create/update status (KITH-s8kd.4).
        //
        // Sequence:
        //   1. Create chat-upd → state s-1
        //   2. Record s-1 as sinceState
        //   3. Call update_last_message_at (modifies the chat) → state s-2
        //   4. get_changes_since("s-1") must have chat-upd in updated[], NOT added[].
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        cs.create("chat-upd", "direct", Some("uid:alice"), 1_000_000)
            .unwrap();
        let since = cs.get_state().unwrap();
        // Touch the chat so it appears in the next changes window.
        cs.update_last_message_at("chat-upd", 2_000_000).unwrap();
        let result = cs.get_changes_since(&since).unwrap();
        assert!(
            !result.added.contains(&"chat-upd".to_string()),
            "updated chat must NOT appear in added[]; added={:?}",
            result.added
        );
        assert!(
            result.updated.contains(&"chat-upd".to_string()),
            "updated chat must appear in updated[]; updated={:?}",
            result.updated
        );
    }
}
