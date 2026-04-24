use crate::{attachment, db_err};
use kith_core::{DeliveryState, JmapError, KithError, Message, StateChange};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use tokio::sync::broadcast;

pub struct MessageStore<'a> {
    conn: &'a Connection,
    events_tx: Option<&'a broadcast::Sender<StateChange>>,
}

/// The result of a Message/changes query.
#[derive(Debug)]
pub struct ChangesResult {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub destroyed: Vec<String>,
    pub new_state: String,
}

fn delivery_state_str(s: &DeliveryState) -> &'static str {
    match s {
        DeliveryState::Pending => "pending",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Failed => "failed",
        DeliveryState::Received => "received",
    }
}

fn parse_delivery_state(s: &str) -> Result<DeliveryState, KithError> {
    match s {
        "pending" => Ok(DeliveryState::Pending),
        "delivered" => Ok(DeliveryState::Delivered),
        "failed" => Ok(DeliveryState::Failed),
        "received" => Ok(DeliveryState::Received),
        other => Err(KithError::Store(format!("unknown delivery_state: {other}"))),
    }
}

/// Deserialize a rusqlite row into a `Message`.
///
/// Column order must match the SELECT list used in both `get()` and
/// `list_by_chat()`:
///   0  id               TEXT
///   1  chat_id          TEXT
///   2  sender_user_id   TEXT
///   3  body             TEXT
///   4  body_type        TEXT
///   5  sent_at_peer     TEXT NULL
///   6  created_at       INTEGER (Unix seconds)
///   7  delivery_state   TEXT
///   8  delivered_at     INTEGER NULL (Unix seconds)
///   9  read_at          INTEGER NULL (Unix seconds)
///   10 reply_to         TEXT NULL
///   11 sender_msg_id    TEXT NULL
fn row_to_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    let id: String = row.get(0)?;
    let chat_id: String = row.get(1)?;
    let sender_user_id: String = row.get(2)?;
    let body: String = row.get(3)?;
    let body_type: String = row.get(4)?;
    let sent_at_peer: Option<String> = row.get(5)?;
    let created_at: i64 = row.get(6)?;
    let delivery_state_raw: String = row.get(7)?;
    let delivered_at_unix: Option<i64> = row.get(8)?;
    let read_at_unix: Option<i64> = row.get(9)?;
    let reply_to: Option<String> = row.get(10)?;
    let sender_msg_id: Option<String> = row.get(11)?;

    let delivery_state = parse_delivery_state(&delivery_state_raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let received_at = crate::util::unix_secs_to_rfc3339(created_at);
    let sent_at = sent_at_peer.unwrap_or_else(|| received_at.clone());
    let delivered_at = delivered_at_unix.map(crate::util::unix_secs_to_rfc3339);
    let read_at = read_at_unix.map(crate::util::unix_secs_to_rfc3339);
    let sender_msg_id = sender_msg_id.unwrap_or_else(|| id.clone());

    Ok(Message {
        id,
        sender_msg_id,
        chat_id,
        sender_id: sender_user_id,
        body,
        body_type,
        attachments: vec![],
        reply_to,
        sent_at,
        received_at,
        delivery_state,
        delivered_at,
        read_at,
    })
}

impl<'a> MessageStore<'a> {
    pub fn new(
        conn: &'a Connection,
        events_tx: Option<&'a broadcast::Sender<StateChange>>,
    ) -> Self {
        MessageStore { conn, events_tx }
    }

    fn emit(&self, new_state: String) {
        if let Some(tx) = self.events_tx {
            let _ = tx.send(StateChange {
                type_name: "Message".to_string(),
                new_state,
            });
        }
    }

    /// Insert a new message row. Advances the message state counter and stores
    /// the resulting counter value in `state_version`.
    ///
    /// # state_version invariant
    /// The counter increment and the INSERT are wrapped in a single transaction
    /// so that a failed INSERT (e.g., FK violation, duplicate ID) does not leave
    /// a permanent hole in the state_version sequence. After a successful commit,
    /// `get_changes_since("s-N")` returns this message for any `N` less than the
    /// new counter value.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        id: &str,
        chat_id: &str,
        sender_user_id: &str,
        body: &str,
        body_type: &str,
        sent_at_peer: Option<&str>,
        created_at_unix: i64,
        delivery_state: &DeliveryState,
        reply_to: Option<&str>,
        sender_msg_id: &str,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        let state_str = delivery_state_str(delivery_state);
        tx.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, body_type, sent_at_peer, \
              created_at, state_version, delivery_state, reply_to, sender_msg_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                chat_id,
                sender_user_id,
                body,
                body_type,
                sent_at_peer,
                created_at_unix,
                version,
                state_str,
                reply_to,
                sender_msg_id,
            ],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    /// Retrieve a message by its ID. Returns `None` if not found.
    pub fn get(&self, id: &str) -> Result<Option<Message>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, chat_id, sender_user_id, body, body_type, \
                        sent_at_peer, created_at, delivery_state, \
                        delivered_at, read_at, reply_to, sender_msg_id \
                 FROM messages WHERE id = ?1",
            )
            .map_err(db_err)?;

        let mut rows = stmt
            .query_map(params![id], row_to_message)
            .map_err(db_err)?;

        match rows.next() {
            None => Ok(None),
            Some(row) => {
                let mut msg = row.map_err(db_err)?;
                msg.attachments =
                    attachment::AttachmentStore::new(self.conn).list_by_message(&msg.id)?;
                Ok(Some(msg))
            }
        }
    }

    /// List messages for a chat, newest first, up to `limit` rows.
    pub fn list_by_chat(&self, chat_id: &str, limit: u32) -> Result<Vec<Message>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, chat_id, sender_user_id, body, body_type, \
                        sent_at_peer, created_at, delivery_state, \
                        delivered_at, read_at, reply_to, sender_msg_id \
                 FROM messages \
                 WHERE chat_id = ?1 \
                 ORDER BY created_at DESC \
                 LIMIT ?2",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![chat_id, limit], row_to_message)
            .map_err(db_err)?;

        let mut messages: Vec<Message> = rows
            .map(|r| r.map_err(db_err))
            .collect::<Result<Vec<_>, _>>()?;

        if messages.is_empty() {
            return Ok(messages);
        }

        // Batch-load all attachments for all messages in a single query.
        let ids: Vec<&str> = messages.iter().map(|m| m.id.as_str()).collect();
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT id, message_id, filename, content_type, size_bytes, sha256 \
             FROM attachments WHERE message_id IN ({placeholders}) ORDER BY created_at"
        );
        let mut att_stmt = self.conn.prepare_cached(&sql).map_err(db_err)?;
        let att_rows = att_stmt
            .query_map(rusqlite::params_from_iter(ids.iter()), |row| {
                Ok((
                    row.get::<_, String>(1)?, // message_id
                    kith_core::Attachment {
                        blob_id: row.get(0)?,
                        filename: row.get(2)?,
                        content_type: row.get(3)?,
                        size: row.get::<_, i64>(4)?.max(0) as u64,
                        sha256: row.get(5)?,
                    },
                ))
            })
            .map_err(db_err)?;

        let mut att_map: HashMap<String, Vec<kith_core::Attachment>> = HashMap::new();
        for row in att_rows {
            let (msg_id, att) = row.map_err(db_err)?;
            att_map.entry(msg_id).or_default().push(att);
        }

        for msg in &mut messages {
            if let Some(atts) = att_map.remove(&msg.id) {
                msg.attachments = atts;
            }
        }

        Ok(messages)
    }

    /// Find a message by the sender-assigned ID within a specific chat.
    ///
    /// Used by Peer/deliver to detect duplicate deliveries (idempotency check).
    /// Returns `None` if no matching message is found.
    pub fn find_by_sender_msg_id(
        &self,
        chat_id: &str,
        sender_msg_id: &str,
    ) -> Result<Option<Message>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, chat_id, sender_user_id, body, body_type, \
                        sent_at_peer, created_at, delivery_state, \
                        delivered_at, read_at, reply_to, sender_msg_id \
                 FROM messages WHERE chat_id = ?1 AND sender_msg_id = ?2",
            )
            .map_err(db_err)?;

        let mut rows = stmt
            .query_map(params![chat_id, sender_msg_id], row_to_message)
            .map_err(db_err)?;

        match rows.next() {
            None => Ok(None),
            Some(row) => {
                let mut msg = row.map_err(db_err)?;
                msg.attachments =
                    attachment::AttachmentStore::new(self.conn).list_by_message(&msg.id)?;
                Ok(Some(msg))
            }
        }
    }

    /// Update the delivery state of a message, advancing the state counter.
    ///
    /// # Delivery state regression prevention
    /// The UPDATE is guarded with `AND delivery_state != 'delivered'` so that
    /// a `Delivered` row can never be overwritten at the SQL level, regardless
    /// of application-layer bugs or races. If the message is already `Delivered`,
    /// this call is idempotent (returns `Ok(())` without advancing the state
    /// counter or emitting an event).
    ///
    /// # Atomicity
    /// All three operations (UPDATE messages, counter advance, state_version stamp)
    /// are wrapped in a single transaction. A crash at any point between them will
    /// roll back atomically, so delivery_state and state_version are always consistent.
    pub fn update_delivery_state(
        &self,
        id: &str,
        state: &DeliveryState,
        delivered_at_unix: Option<i64>,
    ) -> Result<(), KithError> {
        let state_str = delivery_state_str(state);

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // The WHERE guard `delivery_state != 'delivered'` is the authoritative
        // regression barrier; application logic alone is not sufficient.
        let affected = tx
            .execute(
                "UPDATE messages \
                 SET delivery_state = ?1, delivered_at = ?2 \
                 WHERE id = ?3 AND delivery_state != 'delivered'",
                params![state_str, delivered_at_unix, id],
            )
            .map_err(db_err)?;

        if affected == 0 {
            // Either the message does not exist, or it is already `Delivered`.
            // Distinguish the two cases with a point-read (still inside the tx).
            let existing_state: Option<String> = tx
                .query_row(
                    "SELECT delivery_state FROM messages WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_err)?;

            // Transaction is not committed — drops and rolls back automatically.
            return match existing_state.as_deref() {
                Some("delivered") => {
                    // Already terminal — idempotent, do not advance counter.
                    Ok(())
                }
                Some(_) => {
                    // Row exists in a non-delivered state but UPDATE touched 0
                    // rows. This should not happen under Phase 1 single-threaded
                    // access; surface it as an internal store error.
                    Err(KithError::Store(format!(
                        "unexpected: update_delivery_state touched 0 rows for message {id}"
                    )))
                }
                None => Err(KithError::Store(format!("message not found: {id}"))),
            };
        }

        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.execute(
            "UPDATE messages SET state_version = ?1 WHERE id = ?2",
            params![version, id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    /// Mark a message as read at the given Unix timestamp, advancing the state counter.
    ///
    /// # Atomicity
    /// All three operations (UPDATE messages, counter advance, state_version stamp) are
    /// wrapped in a single transaction. A missing message ID causes the transaction to
    /// roll back without advancing the counter. A crash at any intermediate point rolls
    /// back atomically, keeping read_at and state_version consistent.
    pub fn update_read_at(&self, id: &str, read_at_unix: i64) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "UPDATE messages SET read_at = ?1 WHERE id = ?2",
                params![read_at_unix, id],
            )
            .map_err(db_err)?;
        if affected == 0 {
            // Transaction drops here, rolling back automatically.
            return Err(KithError::Store(format!("message not found: {id}")));
        }
        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.execute(
            "UPDATE messages SET state_version = ?1 WHERE id = ?2",
            params![version, id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    /// Return IDs of messages created or updated since the given state token.
    ///
    /// Phase 1: all changes are reported as `added`; no distinction between
    /// creates and updates, and no destroy tracking.
    pub fn get_changes_since(&self, since_state: &str) -> Result<ChangesResult, KithError> {
        let since_version = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(JmapError::cannot_calculate_changes()))?;

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM messages WHERE state_version > ?1 ORDER BY state_version",
            )
            .map_err(db_err)?;

        let ids: Vec<String> = stmt
            .query_map(params![since_version], |row| row.get(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let new_state = self.get_state()?;

        Ok(ChangesResult {
            added: ids,
            updated: vec![],
            destroyed: vec![],
            new_state,
        })
    }

    /// Return the current state token for messages.
    pub fn get_state(&self) -> Result<String, KithError> {
        let counter: i64 = self
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'message'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(format!("s-{counter}"))
    }

    /// Advance the message state counter by one, returning the new value.
    pub fn advance_state(&self) -> Result<String, KithError> {
        let v = self.advance_state_counter()?;
        Ok(format!("s-{v}"))
    }

    /// Internal: increment counter and return the new integer value.
    ///
    /// # Concurrency
    /// This function reads and then increments the counter in two separate
    /// statements. It is safe only for single-threaded use (Phase 1 constraint).
    /// Phase 2, if it introduces concurrent writers, must wrap this in a
    /// single atomic UPDATE … RETURNING or hold a write-level transaction.
    fn advance_state_counter(&self) -> Result<i64, KithError> {
        self.conn
            .execute(
                "UPDATE state_counters SET counter = counter + 1 WHERE type_name = 'message'",
                [],
            )
            .map_err(db_err)?;
        let v: i64 = self
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'message'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    /// Insert a chat row so that messages FK is satisfied.
    fn insert_chat(conn: &Connection, chat_id: &str) {
        conn.execute(
            "INSERT INTO chats (id, kind, created_at) VALUES (?1, 'direct', ?2)",
            params![chat_id, 1000i64],
        )
        .expect("insert chat");
    }

    #[test]
    fn insert_then_get_round_trip() {
        // Oracle: fields stored and retrieved must be identical to what was inserted.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-001");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-001",
            "chat-001",
            "user-abc",
            "Hello, world!",
            "text/plain",
            Some("2026-04-18T12:00:00Z"),
            1745971200, // 2026-04-18T00:00:00Z in unix secs
            &DeliveryState::Received,
            None,
            "msg-001",
        )
        .expect("insert");

        let msg = ms.get("msg-001").expect("get").expect("should exist");
        assert_eq!(msg.id, "msg-001");
        assert_eq!(msg.chat_id, "chat-001");
        assert_eq!(msg.sender_id, "user-abc");
        assert_eq!(msg.body, "Hello, world!");
        assert_eq!(msg.body_type, "text/plain");
        assert_eq!(msg.sent_at, "2026-04-18T12:00:00Z");
        assert_eq!(msg.delivery_state, DeliveryState::Received);
        assert_eq!(msg.reply_to, None);
        assert_eq!(msg.delivered_at, None);
        assert_eq!(msg.read_at, None);
        assert!(msg.attachments.is_empty());
    }

    #[test]
    fn list_by_chat_returns_newest_first() {
        // Oracle: ORDER BY created_at DESC means largest timestamp comes first.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-002");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-100",
            "chat-002",
            "user-a",
            "first",
            "text/plain",
            None,
            100,
            &DeliveryState::Received,
            None,
            "msg-100",
        )
        .expect("insert t=100");
        ms.insert(
            "msg-200",
            "chat-002",
            "user-a",
            "second",
            "text/plain",
            None,
            200,
            &DeliveryState::Received,
            None,
            "msg-200",
        )
        .expect("insert t=200");
        ms.insert(
            "msg-300",
            "chat-002",
            "user-a",
            "third",
            "text/plain",
            None,
            300,
            &DeliveryState::Received,
            None,
            "msg-300",
        )
        .expect("insert t=300");

        let msgs = ms.list_by_chat("chat-002", 10).expect("list");
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].id, "msg-300", "newest first");
        assert_eq!(msgs[1].id, "msg-200");
        assert_eq!(msgs[2].id, "msg-100", "oldest last");
    }

    #[test]
    fn update_delivery_state_changes_state_and_advances_counter() {
        // Oracle: after update_delivery_state, get returns the new state; state
        // counter must be strictly greater than before the call.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-003");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ds",
            "chat-003",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Pending,
            None,
            "msg-ds",
        )
        .expect("insert");

        let state_before = ms.get_state().expect("state before");

        ms.update_delivery_state("msg-ds", &DeliveryState::Delivered, Some(2000))
            .expect("update");

        let state_after = ms.get_state().expect("state after");
        assert_ne!(
            state_before, state_after,
            "state counter must advance after update"
        );

        let msg = ms.get("msg-ds").expect("get").expect("exists");
        assert_eq!(msg.delivery_state, DeliveryState::Delivered);
        assert!(
            msg.delivered_at.is_some(),
            "delivered_at must be set after delivery"
        );
    }

    #[test]
    fn get_changes_since_includes_new_message_and_empty_at_current() {
        // Oracle: a message inserted after a captured state must appear in
        // get_changes_since(old_state).added; get_changes_since(current_state)
        // must return an empty added list.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-004");

        let ms = MessageStore::new(&store.conn, None);
        let state_before = ms.get_state().expect("state before insert");

        ms.insert(
            "msg-cs",
            "chat-004",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-cs",
        )
        .expect("insert");

        let changes = ms
            .get_changes_since(&state_before)
            .expect("changes since old state");
        assert!(
            changes.added.contains(&"msg-cs".to_string()),
            "newly inserted message must appear in added"
        );
        assert!(changes.updated.is_empty());
        assert!(changes.destroyed.is_empty());

        let current_state = ms.get_state().expect("current state");
        let no_changes = ms
            .get_changes_since(&current_state)
            .expect("changes since current state");
        assert!(
            no_changes.added.is_empty(),
            "no new changes since current state"
        );
    }

    #[test]
    fn update_read_at_sets_field() {
        // Oracle: after update_read_at, get returns a non-None read_at.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-005");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ra",
            "chat-005",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ra",
        )
        .expect("insert");

        let msg_before = ms.get("msg-ra").expect("get").expect("exists");
        assert!(
            msg_before.read_at.is_none(),
            "read_at must be None before update"
        );

        ms.update_read_at("msg-ra", 5000).expect("update_read_at");

        let msg_after = ms.get("msg-ra").expect("get").expect("exists");
        assert!(
            msg_after.read_at.is_some(),
            "read_at must be set after update_read_at"
        );
    }

    #[test]
    fn update_delivery_state_appears_in_get_changes_since() {
        // Oracle: after update_delivery_state, get_changes_since(state_before_update)
        // must include the message ID in `added`.  This tests the end-to-end contract:
        // update_delivery_state must write the new state_version to the row so that
        // the JMAP polling path (get_changes_since) surfaces the change to clients.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-us1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-us1",
            "chat-us1",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Pending,
            None,
            "msg-us1",
        )
        .expect("insert");

        // Capture state AFTER insert so the initial message is already "seen".
        let state_after_insert = ms.get_state().expect("state after insert");

        ms.update_delivery_state("msg-us1", &DeliveryState::Delivered, Some(2000))
            .expect("update");

        let changes = ms
            .get_changes_since(&state_after_insert)
            .expect("changes after update");
        assert!(
            changes.added.contains(&"msg-us1".to_string()),
            "update_delivery_state must advance state_version so the message appears \
             in get_changes_since; added={:?}",
            changes.added
        );
    }

    #[test]
    fn update_read_at_appears_in_get_changes_since() {
        // Oracle: after update_read_at, get_changes_since(state_before_update) must
        // include the message ID in `added`.  Verifies state_version is written on
        // the messages row when read receipt is recorded.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-us2");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-us2",
            "chat-us2",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-us2",
        )
        .expect("insert");

        let state_after_insert = ms.get_state().expect("state after insert");

        ms.update_read_at("msg-us2", 5000).expect("update_read_at");

        let changes = ms
            .get_changes_since(&state_after_insert)
            .expect("changes after read-at update");
        assert!(
            changes.added.contains(&"msg-us2".to_string()),
            "update_read_at must advance state_version so the message appears \
             in get_changes_since; added={:?}",
            changes.added
        );
    }

    #[test]
    fn update_read_at_nonexistent_does_not_advance_counter() {
        // Oracle: calling update_read_at with a nonexistent message ID must return
        // Err and must NOT advance the state counter.
        // The independent oracle is: state counter read before the failed call
        // must be identical to state counter read after the failed call.
        let store = Store::open_in_memory().expect("open");
        let ms = MessageStore::new(&store.conn, None);

        let state_before = ms.get_state().expect("state before");
        let result = ms.update_read_at("does-not-exist", 9999);
        assert!(
            result.is_err(),
            "update_read_at on nonexistent id must return Err"
        );
        let state_after = ms.get_state().expect("state after");
        assert_eq!(
            state_before, state_after,
            "state counter must not advance when update_read_at finds no row"
        );
    }

    #[test]
    fn update_delivery_state_delivered_is_terminal_no_regression() {
        // Oracle: the delivery state machine specifies Delivered as a terminal
        // state. Once a message reaches Delivered, no subsequent call may
        // regress it to Pending or any other non-terminal state.
        //
        // Verification path:
        //   1. Insert message in Pending state.
        //   2. Advance to Delivered — confirm state counter advances.
        //   3. Capture state after delivery.
        //   4. Call update_delivery_state(Pending) — must return Ok(()).
        //   5. Confirm delivery_state is still Delivered (no regression).
        //   6. Confirm state counter did NOT advance (idempotent call).
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-term");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-term",
            "chat-term",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Pending,
            None,
            "msg-term",
        )
        .expect("insert");

        // Advance to Delivered — legitimate transition.
        ms.update_delivery_state("msg-term", &DeliveryState::Delivered, Some(2000))
            .expect("pending → delivered must succeed");

        let state_after_delivery = ms.get_state().expect("state after delivery");

        // Attempt regression: try to write Pending onto a Delivered message.
        let result = ms.update_delivery_state("msg-term", &DeliveryState::Pending, None);
        assert!(
            result.is_ok(),
            "regression attempt on Delivered message must return Ok(()), got {:?}",
            result
        );

        // State must still be Delivered — the SQL guard must have blocked the write.
        let msg = ms.get("msg-term").expect("get").expect("exists");
        assert_eq!(
            msg.delivery_state,
            DeliveryState::Delivered,
            "delivery_state must remain Delivered after regression attempt"
        );

        // State counter must NOT have advanced — idempotent call produces no event.
        let state_after_regression = ms.get_state().expect("state after regression attempt");
        assert_eq!(
            state_after_delivery, state_after_regression,
            "state counter must not advance for idempotent delivered→delivered call"
        );
    }

    #[test]
    fn get_changes_since_invalid_state_returns_error() {
        // Oracle: a malformed since_state must return KithError::Jmap with
        // cannotCalculateChanges, not panic.
        let store = Store::open_in_memory().expect("open");
        let ms = MessageStore::new(&store.conn, None);
        let result = ms.get_changes_since("garbage");
        match result {
            Err(KithError::Jmap(e)) => {
                assert_eq!(e.error_type, "cannotCalculateChanges");
            }
            other => panic!("expected cannotCalculateChanges error, got {:?}", other),
        }
    }

    #[test]
    fn message_get_returns_populated_attachments() {
        // Oracle: attachments table contents, queried independently via AttachmentStore.
        // get() must surface the same rows that were inserted via insert_message_with_attachments.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-att1");

        let blob_id_1 = "a".repeat(64);
        let blob_id_2 = "c".repeat(64);
        let attachments = vec![
            kith_core::Attachment {
                blob_id: blob_id_1.clone(),
                filename: "first.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: 42,
                sha256: "b".repeat(64),
            },
            kith_core::Attachment {
                blob_id: blob_id_2.clone(),
                filename: "second.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                size: 100,
                sha256: "d".repeat(64),
            },
        ];

        store
            .insert_message_with_attachments(
                "msg-att1",
                "chat-att1",
                "user-a",
                "body",
                "text/plain",
                None,
                1000,
                &DeliveryState::Received,
                None,
                "msg-att1",
                &attachments,
            )
            .expect("insert_message_with_attachments");

        let ms = MessageStore::new(&store.conn, None);
        let msg = ms.get("msg-att1").expect("get").expect("must exist");

        assert_eq!(msg.attachments.len(), 2, "must return both attachments");
        assert_eq!(msg.attachments[0].blob_id, blob_id_1);
        assert_eq!(msg.attachments[0].filename, "first.txt");
        assert_eq!(msg.attachments[1].blob_id, blob_id_2);
    }

    #[test]
    fn message_list_by_chat_returns_attachments() {
        // Oracle: attachments table contents match what was inserted.
        // list_by_chat must populate attachments on each returned Message.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-att2");

        // First message: one attachment.
        let att = kith_core::Attachment {
            blob_id: "e".repeat(64),
            filename: "doc.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 7,
            sha256: "f".repeat(64),
        };
        store
            .insert_message_with_attachments(
                "msg-att2a",
                "chat-att2",
                "user-a",
                "with attachment",
                "text/plain",
                None,
                100,
                &DeliveryState::Received,
                None,
                "msg-att2a",
                &[att],
            )
            .expect("insert msg with attachment");

        // Second message: no attachments.
        store
            .insert_message_with_attachments(
                "msg-att2b",
                "chat-att2",
                "user-a",
                "no attachment",
                "text/plain",
                None,
                200,
                &DeliveryState::Received,
                None,
                "msg-att2b",
                &[],
            )
            .expect("insert msg without attachment");

        let ms = MessageStore::new(&store.conn, None);
        // list_by_chat returns newest first; msg-att2b (t=200) comes before msg-att2a (t=100).
        let msgs = ms.list_by_chat("chat-att2", 10).expect("list");
        assert_eq!(msgs.len(), 2);

        let msg_no_att = msgs
            .iter()
            .find(|m| m.id == "msg-att2b")
            .expect("msg-att2b");
        let msg_with_att = msgs
            .iter()
            .find(|m| m.id == "msg-att2a")
            .expect("msg-att2a");

        assert!(
            msg_no_att.attachments.is_empty(),
            "message with no attachments must return empty vec"
        );
        assert_eq!(
            msg_with_att.attachments.len(),
            1,
            "message with one attachment must return it"
        );
        assert_eq!(msg_with_att.attachments[0].blob_id, "e".repeat(64));
    }

    #[test]
    fn message_get_no_attachments_returns_empty() {
        // Oracle: message inserted via insert() (no attachments path) must return
        // an empty attachments vec — not an error, not a panic.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-att3");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-att3",
            "chat-att3",
            "user-a",
            "plain text, no files",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-att3",
        )
        .expect("insert");

        let msg = ms.get("msg-att3").expect("get").expect("must exist");
        assert!(
            msg.attachments.is_empty(),
            "message with no attachments must return empty vec, got {:?}",
            msg.attachments
        );
    }
}
