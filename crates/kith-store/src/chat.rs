use crate::db_err;
use crate::message::ChangesResult;
use kith_core::{Chat, KithError, StateChange};
use rusqlite::{params, Connection};
use tokio::sync::broadcast;

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

    /// Get or create a chat by its deterministic ID.
    ///
    /// The `chat_id` must already be computed by the caller via
    /// `kith_core::compute_chat_id`. `participant_user_ids` contains the
    /// peer_user_id values excluding self.
    ///
    /// The chat INSERT and all member INSERTs are wrapped in a single transaction
    /// so a crash mid-way cannot leave a chat with missing members. The state
    /// counter is advanced only if at least one row was actually inserted
    /// (i.e. the chat is new or new members were added) to avoid spurious
    /// Chat/changes deltas on repeated calls for an existing chat.
    pub fn get_or_create(
        &self,
        chat_id: &str,
        kind: &str,
        participant_user_ids: &[&str],
        now_unix: i64,
    ) -> Result<Chat, KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        let chat_rows = tx
            .execute(
                "INSERT OR IGNORE INTO chats (id, kind, created_at) VALUES (?1, ?2, ?3)",
                params![chat_id, kind, now_unix],
            )
            .map_err(db_err)?;
        let mut any_new = chat_rows > 0;

        for peer_id in participant_user_ids {
            let member_rows = tx
                .execute(
                    "INSERT OR IGNORE INTO chat_members (chat_id, peer_user_id) VALUES (?1, ?2)",
                    params![chat_id, peer_id],
                )
                .map_err(db_err)?;
            any_new |= member_rows > 0;
        }

        tx.commit().map_err(db_err)?;

        if any_new {
            let new_state = self.advance_state()?;
            self.emit(new_state);
        }

        self.get(chat_id)?
            .ok_or_else(|| KithError::Store(format!("chat '{}' not found after insert", chat_id)))
    }

    /// Fetch a single chat by ID, returning None if it does not exist.
    pub fn get(&self, chat_id: &str) -> Result<Option<Chat>, KithError> {
        let row = self.conn.query_row(
            "SELECT id, kind, created_at, last_message_at FROM chats WHERE id = ?1",
            params![chat_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        );

        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(db_err(e)),
            Ok(_) => {}
        }

        let (id, kind, created_at_secs, last_message_at_secs) = row.unwrap();
        let participants = self.load_participants(chat_id)?;
        let unread = self.unread_count(chat_id)?;

        Ok(Some(Chat {
            id,
            kind,
            participants,
            created_at: crate::util::unix_secs_to_rfc3339(created_at_secs),
            last_message_at: last_message_at_secs.map(crate::util::unix_secs_to_rfc3339),
            unread_count: unread,
        }))
    }

    /// List all chats ordered by last_message_at DESC (nulls last), then created_at DESC.
    pub fn list(&self) -> Result<Vec<Chat>, KithError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, kind, created_at, last_message_at \
                 FROM chats \
                 ORDER BY last_message_at DESC NULLS LAST, created_at DESC",
            )
            .map_err(db_err)?;

        let rows: Vec<(String, String, i64, Option<i64>)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut chats = Vec::with_capacity(rows.len());
        for (id, kind, created_at_secs, last_message_at_secs) in rows {
            let participants = self.load_participants(&id)?;
            let unread = self.unread_count(&id)?;
            chats.push(Chat {
                id,
                kind,
                participants,
                created_at: crate::util::unix_secs_to_rfc3339(created_at_secs),
                last_message_at: last_message_at_secs.map(crate::util::unix_secs_to_rfc3339),
                unread_count: unread,
            });
        }

        Ok(chats)
    }

    /// Update the last_message_at timestamp for a chat and advance the chat state counter.
    ///
    /// Only advances the state counter if the chat actually exists (UPDATE matched a row).
    /// Returns `Ok(())` silently if `chat_id` is not found.
    pub fn update_last_message_at(&self, chat_id: &str, ts: i64) -> Result<(), KithError> {
        let affected = self
            .conn
            .execute(
                "UPDATE chats SET last_message_at = ?1 WHERE id = ?2",
                params![ts, chat_id],
            )
            .map_err(db_err)?;
        if affected > 0 {
            let new_state = self.advance_state()?;
            self.emit(new_state);
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
    /// # Concurrency
    /// This function reads and then increments the counter in two separate
    /// statements. It is safe only for single-threaded use (Phase 1 constraint).
    /// Phase 2, if it introduces concurrent writers, must wrap this in a
    /// single atomic UPDATE … RETURNING or hold a write-level transaction.
    pub fn advance_state(&self) -> Result<String, KithError> {
        self.conn
            .execute(
                "UPDATE state_counters SET counter = counter + 1 WHERE type_name = 'chat'",
                [],
            )
            .map_err(db_err)?;
        self.get_state()
    }

    /// Return IDs of all chats if the state has advanced since `since_state`.
    ///
    /// Phase 1: no per-row state tracking for chats.  Any change after
    /// `since_state` triggers a full re-sync: all chat IDs are returned as
    /// `added`.  If `since_state` is already the current state, the result
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
            .prepare("SELECT id FROM chats ORDER BY created_at")
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

    /// Load the peer_user_ids of all members for the given chat.
    fn load_participants(&self, chat_id: &str) -> Result<Vec<String>, KithError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT peer_user_id FROM chat_members WHERE chat_id = ?1 ORDER BY peer_user_id",
            )
            .map_err(db_err)?;
        let ids: Vec<String> = stmt
            .query_map(params![chat_id], |row| row.get(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use kith_core::KithError;

    #[test]
    fn get_or_create_is_idempotent() {
        // Oracle: calling get_or_create twice with the same ID must return the
        // same created_at value and not error. This verifies INSERT OR IGNORE
        // semantics for both chats and chat_members.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let chat1 = cs
            .get_or_create("chat-aaa", "direct", &["uid:bob"], 1_000_000)
            .unwrap();
        let chat2 = cs
            .get_or_create("chat-aaa", "direct", &["uid:bob"], 2_000_000)
            .unwrap();

        assert_eq!(chat1.id, chat2.id);
        assert_eq!(
            chat1.created_at, chat2.created_at,
            "created_at must not change on second call"
        );
        assert_eq!(chat1.kind, "direct");
    }

    #[test]
    fn participants_match_inserted_values() {
        // Oracle: chat_members rows we insert must come back in the participants Vec.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let chat = cs
            .get_or_create("chat-bbb", "group", &["uid:carol", "uid:dave"], 1_000_000)
            .unwrap();

        let mut got = chat.participants.clone();
        got.sort();
        assert_eq!(got, vec!["uid:carol", "uid:dave"]);
    }

    #[test]
    fn list_ordered_by_last_message_at_desc() {
        // Oracle: SQL ORDER BY last_message_at DESC NULLS LAST.
        // We insert three chats, set last_message_at on two of them, and verify
        // the returned order. The chat with no last_message_at comes last.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.get_or_create("chat-x1", "direct", &["uid:alice"], 1_000_000)
            .unwrap();
        cs.get_or_create("chat-x2", "direct", &["uid:bob"], 1_000_001)
            .unwrap();
        cs.get_or_create("chat-x3", "direct", &["uid:carol"], 1_000_002)
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
    fn update_last_message_at_changes_field_and_advances_state() {
        // Oracle: after update_last_message_at, the returned Chat reflects the new
        // timestamp and the state counter is strictly greater than before.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.get_or_create("chat-ccc", "direct", &["uid:eve"], 1_000_000)
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
            chat.last_message_at,
            Some("2020-09-13T12:26:40Z".to_string()),
            "last_message_at must reflect the stored unix timestamp (oracle: Python 3 utcfromtimestamp(1_600_000_000))"
        );
    }

    #[test]
    fn unread_count_counts_only_received_and_unread() {
        // Oracle: unread_count = messages with delivery_state='received' AND read_at IS NULL.
        // Insert 3 received+unread, 1 received+read, 1 pending. Expect count=3.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.get_or_create("chat-ddd", "direct", &["uid:frank"], 1_000_000)
            .unwrap();

        // Insert messages directly — we don't have a MessageStore yet.
        let insert_msg = |id: &str, state: &str, read_at: Option<i64>| {
            store
                .conn
                .execute(
                    "INSERT INTO messages \
                     (id, chat_id, sender_user_id, body, created_at, delivery_state, read_at) \
                     VALUES (?1, 'chat-ddd', 'uid:frank', 'hi', 1000000, ?2, ?3)",
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
    fn get_or_create_does_not_advance_state_on_cache_hit() {
        // Oracle: when the chat and all members already exist, the INSERT OR IGNORE rows
        // are no-ops (0 affected), so the state counter must NOT advance.  Spurious
        // advances produce phantom Chat/changes deltas for clients.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.get_or_create("chat-zzz", "direct", &["uid:alice"], 1_000_000)
            .unwrap();
        let state_after_create = cs.get_state().unwrap();

        // Second call with identical args — pure cache hit.
        cs.get_or_create("chat-zzz", "direct", &["uid:alice"], 1_000_000)
            .unwrap();
        let state_after_hit = cs.get_state().unwrap();

        assert_eq!(
            state_after_create, state_after_hit,
            "state counter must not advance on a pure cache hit"
        );
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
        cs.get_or_create("chat-gc1", "direct", &["uid:alice"], 1_000_000)
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
        // Oracle: a token without "s-" prefix must return KithError::Validation.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        let result = cs.get_changes_since("x-1");
        match result {
            Err(KithError::Validation(msg)) => {
                assert_eq!(msg, "invalid state token");
            }
            other => panic!("expected KithError::Validation, got {:?}", other),
        }
    }
}
