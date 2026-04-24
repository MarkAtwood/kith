use crate::{attachment, db_err};
use kith_core::{DeliveryState, JmapError, KithError, Message, StateChange};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use tokio::sync::broadcast;

/// Row from `get_changes_since_ordered`: (message_id, state_version, is_create).
type ChangeRow = (String, i64, bool);

/// Row from `get_querychanges_since_for_chat`: (message_id, sort_position).
type QueryChangeRow = (String, u64);

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

/// Batch-load all attachments for a set of message IDs in a single SQL query.
///
/// Returns a `HashMap` keyed by `message_id`. Each value is the ordered list
/// of attachments for that message.  Callers merge the map into their message
/// list by removing entries by ID.
///
/// When `msg_ids` is empty the function returns an empty map without touching
/// the database.
fn load_attachments_for_messages(
    conn: &Connection,
    msg_ids: &[String],
) -> Result<HashMap<String, Vec<kith_core::Attachment>>, KithError> {
    if msg_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = msg_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT id, message_id, filename, content_type, size_bytes, sha256 \
         FROM attachments WHERE message_id IN ({placeholders}) ORDER BY created_at"
    );
    // The SQL string varies by message count (different ? placeholders per call),
    // so prepare() is used here instead of prepare_cached() to avoid unbounded
    // cache growth — each unique placeholder count would add a permanent cache entry.
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(msg_ids.iter()), |row| {
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
    for row in rows {
        let (msg_id, att) = row.map_err(db_err)?;
        att_map.entry(msg_id).or_default().push(att);
    }

    Ok(att_map)
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
              created_at, state_version, created_at_version, delivery_state, reply_to, sender_msg_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11)",
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
                 ORDER BY created_at DESC, id DESC \
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

        let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
        let mut att_map = load_attachments_for_messages(self.conn, &ids)?;
        for msg in &mut messages {
            if let Some(atts) = att_map.remove(&msg.id) {
                msg.attachments = atts;
            }
        }

        Ok(messages)
    }

    /// List messages for a chat with SQL-level pagination.
    ///
    /// Returns up to `limit` messages starting at 0-based `offset`, newest first.
    /// Both `limit` and `offset` are applied in SQL via `LIMIT ? OFFSET ?`.
    pub fn list_by_chat_paged(
        &self,
        chat_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Message>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, chat_id, sender_user_id, body, body_type, \
                        sent_at_peer, created_at, delivery_state, \
                        delivered_at, read_at, reply_to, sender_msg_id \
                 FROM messages \
                 WHERE chat_id = ?1 \
                 ORDER BY created_at DESC, id DESC \
                 LIMIT ?2 OFFSET ?3",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![chat_id, limit, offset], row_to_message)
            .map_err(db_err)?;

        let mut messages: Vec<Message> = rows
            .map(|r| r.map_err(db_err))
            .collect::<Result<Vec<_>, _>>()?;

        if messages.is_empty() {
            return Ok(messages);
        }

        let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
        let mut att_map = load_attachments_for_messages(self.conn, &ids)?;
        for msg in &mut messages {
            if let Some(atts) = att_map.remove(&msg.id) {
                msg.attachments = atts;
            }
        }

        Ok(messages)
    }

    /// Count the total number of messages in a chat.
    pub fn count_by_chat(&self, chat_id: &str) -> Result<usize, KithError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE chat_id = ?1",
                params![chat_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(count as usize)
    }

    /// Return the 0-based position of a message in its chat's newest-first ordering.
    ///
    /// Returns the count of messages that are newer than (or tie-break-after) the
    /// given message, which equals its 0-based index in `ORDER BY created_at DESC, id DESC`.
    ///
    /// Returns `None` if the message does not exist in this chat.
    pub fn get_position_in_chat(
        &self,
        chat_id: &str,
        msg_id: &str,
    ) -> Result<Option<u32>, KithError> {
        // Check the message exists in this chat first.
        let exists: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id = ?1 AND chat_id = ?2",
                params![msg_id, chat_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0;

        if !exists {
            return Ok(None);
        }

        // Count messages that come before this one in newest-first order.
        // A message M is "before" (has a lower index) if it has a larger created_at,
        // or the same created_at but a lexicographically larger id.
        let pos: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages \
                 WHERE chat_id = ?1 \
                 AND (created_at > (SELECT created_at FROM messages WHERE id = ?2) \
                      OR (created_at = (SELECT created_at FROM messages WHERE id = ?2) AND id > ?2))",
                params![chat_id, msg_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;

        Ok(Some(pos as u32))
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
    /// # Monotonicity
    /// The UPDATE is guarded with `AND (read_at IS NULL OR read_at < ?1)` so that a
    /// second call with a smaller (or equal) timestamp does not overwrite a later
    /// `read_at` that is already stored. If 0 rows are affected and the message exists,
    /// the call is idempotent (returns `Ok(())`). If the message does not exist,
    /// returns `Err`.
    ///
    /// # Atomicity
    /// All three operations (UPDATE messages, counter advance, state_version stamp) are
    /// wrapped in a single transaction. A missing message ID causes the transaction to
    /// roll back without advancing the counter. A crash at any intermediate point rolls
    /// back atomically, keeping read_at and state_version consistent.
    pub fn update_read_at(&self, id: &str, read_at_unix: i64) -> Result<(), KithError> {
        if read_at_unix <= 0 {
            return Err(KithError::Validation(
                "read_at_unix must be a positive Unix timestamp".to_string(),
            ));
        }
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "UPDATE messages SET read_at = ?1 \
                 WHERE id = ?2 AND (read_at IS NULL OR read_at < ?1)",
                params![read_at_unix, id],
            )
            .map_err(db_err)?;
        if affected == 0 {
            // Either the message does not exist, or read_at is already >= ?1.
            let existing: Option<Option<i64>> = tx
                .query_row(
                    "SELECT read_at FROM messages WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_err)?;

            // Transaction drops here, rolling back automatically.
            return match existing {
                None => Err(KithError::Store(format!("message not found: {id}"))),
                Some(_) => {
                    // Row exists but read_at is already >= read_at_unix — idempotent.
                    Ok(())
                }
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

    /// Return classified change rows for messages created or updated after `since_state`.
    ///
    /// Each row is `(id, state_version, is_create)` where:
    /// - `is_create = true`  → the message was first inserted after `since_state`
    ///   (RFC 8620 §5.2 `created` list)
    /// - `is_create = false` → the message existed before `since_state` and was
    ///   subsequently modified (RFC 8620 §5.2 `updated` map)
    ///
    /// Rows are ordered by `state_version ASC` (oldest change first) so that
    /// `maxChanges` truncation always produces a correct `newState`: the caller
    /// takes the first N rows, uses the last row's `state_version` to compute
    /// `newState = "s-{version}"`, and pages forward without skipping changes.
    pub fn get_changes_since_ordered(
        &self,
        since_state: &str,
    ) -> Result<(Vec<ChangeRow>, String), KithError> {
        let since_version = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(JmapError::cannot_calculate_changes()))?;

        let current_state = self.get_state()?;
        let current_version: i64 = current_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .expect("get_state always returns s-<integer>");

        if since_version >= current_version {
            return Ok((vec![], current_state));
        }

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, state_version, created_at_version \
                 FROM messages WHERE state_version > ?1 ORDER BY state_version",
            )
            .map_err(db_err)?;

        let rows: Vec<(String, i64, bool)> = stmt
            .query_map(params![since_version], |row| {
                let id: String = row.get(0)?;
                let sv: i64 = row.get(1)?;
                let cav: i64 = row.get(2)?;
                Ok((id, sv, cav > since_version))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok((rows, current_state))
    }

    /// Return IDs of messages in a specific chat created or updated since the given state token.
    ///
    /// Scoped to a single `chat_id`. Returns only the added IDs; messages cannot be
    /// deleted so there is no destroyed list.
    ///
    /// **TOCTOU warning**: if the caller needs `new_state` to accompany these IDs,
    /// both this call and `get_state()` must be made within the *same* lock
    /// acquisition on the parent `Store`.  Calling `get_state()` in a separate
    /// lock scope after this method returns creates a window where newly-arrived
    /// messages advance the state counter but are absent from the returned IDs,
    /// making them permanently invisible to the caller.
    pub fn get_changes_since_for_chat(
        &self,
        since_state: &str,
        chat_id: &str,
    ) -> Result<Vec<String>, KithError> {
        let since_version = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(JmapError::cannot_calculate_changes()))?;

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM messages \
                 WHERE state_version > ?1 AND chat_id = ?2 \
                 ORDER BY state_version",
            )
            .map_err(db_err)?;

        let ids: Vec<String> = stmt
            .query_map(params![since_version, chat_id], |row| row.get(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(ids)
    }

    /// Return `(id, index)` pairs for messages newly added to `chat_id` since `since_state`,
    /// ordered by `state_version ASC` (insertion order).
    ///
    /// `index` is the 0-based position in the chat's newest-first query result — the same
    /// ordering as `Message/query` (created_at DESC, id DESC).  All positions are computed
    /// against the chat's final message set in a single CTE query, avoiding N+1 round trips.
    ///
    /// `max_changes`: if `Some(n)`, return at most `n` entries and signal `has_more = true`
    /// when the result was truncated.  `newQueryState` is then set to the `state_version`
    /// of the last returned entry so the client can page forward correctly.
    pub fn get_querychanges_since_for_chat(
        &self,
        since_state: &str,
        chat_id: &str,
        max_changes: Option<usize>,
    ) -> Result<(Vec<QueryChangeRow>, bool, String), KithError> {
        let since_version = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(JmapError::cannot_calculate_changes()))?;

        let current_state = self.get_state()?;
        let current_counter: i64 = current_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .expect("get_state always returns s-<integer>");

        if since_version >= current_counter {
            return Ok((vec![], false, current_state));
        }

        // Fetch max_changes+1 rows to detect whether there are more results.
        // SQLite treats LIMIT -1 as "no limit".  Cap at i64::MAX-1 before adding 1
        // so the result always fits in i64 (prevents two's-complement wrap on
        // pathological max_changes=usize::MAX input).
        let limit: i64 = max_changes
            .map(|n| (n.min((i64::MAX - 1) as usize) as i64).saturating_add(1))
            .unwrap_or(-1);

        let mut stmt = self
            .conn
            .prepare_cached(
                "WITH all_in_chat AS ( \
                 SELECT id, \
                        ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) - 1 AS idx \
                 FROM messages WHERE chat_id = ?1 \
             ), \
             new_msgs AS ( \
                 SELECT id, state_version FROM messages \
                 WHERE chat_id = ?1 AND state_version > ?2 \
                 ORDER BY state_version LIMIT ?3 \
             ) \
             SELECT n.id, a.idx, n.state_version \
             FROM new_msgs n \
             JOIN all_in_chat a ON a.id = n.id \
             ORDER BY n.state_version",
            )
            .map_err(db_err)?;

        // Each row: (id, 0-based-index, state_version).
        let mut rows: Vec<(String, u64, i64)> = stmt
            .query_map(params![chat_id, since_version, limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let has_more = max_changes.map(|n| rows.len() > n).unwrap_or(false);
        if has_more {
            rows.truncate(max_changes.expect("has_more implies max_changes is Some"));
        }

        let new_state = if has_more {
            rows.last()
                .map(|(_, _, sv)| format!("s-{sv}"))
                .expect("rows is non-empty when has_more is true")
        } else {
            current_state
        };

        let result: Vec<(String, u64)> = rows.into_iter().map(|(id, idx, _)| (id, idx)).collect();
        Ok((result, has_more, new_state))
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
        // A second call with an EARLIER timestamp must not overwrite the stored value.
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

        // Capture the stored read_at string (independent oracle: it must equal the
        // RFC 3339 representation of unix timestamp 5000).
        let read_at_after_first = msg_after.read_at.clone().unwrap();

        // Second call with an earlier timestamp must be idempotent (Ok) and must NOT
        // overwrite the stored value with the smaller timestamp.
        ms.update_read_at("msg-ra", 1000)
            .expect("second call with earlier ts must return Ok");

        let msg_final = ms.get("msg-ra").expect("get").expect("exists");
        assert_eq!(
            msg_final.read_at.as_deref(),
            Some(read_at_after_first.as_str()),
            "read_at must not regress: earlier timestamp must not overwrite a later one"
        );
    }

    #[test]
    fn update_read_at_does_not_regress() {
        // Oracle: update_read_at is monotonic — a second call with a smaller timestamp
        // must return Ok(()) but must not change the stored read_at.
        // Independent oracle: the state counter must also not advance on the no-op call,
        // since no row was actually changed.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-rnd");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-rnd",
            "chat-rnd",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-rnd",
        )
        .expect("insert");

        // First call: sets read_at to timestamp 9000.
        ms.update_read_at("msg-rnd", 9000).expect("first update");
        let state_after_first = ms.get_state().expect("state after first update");
        let msg_after_first = ms.get("msg-rnd").expect("get").expect("exists");
        let read_at_first = msg_after_first.read_at.clone().unwrap();

        // Second call with a smaller timestamp (3000 < 9000).
        let result = ms.update_read_at("msg-rnd", 3000);
        assert!(
            result.is_ok(),
            "second call with earlier timestamp must return Ok(()), got {:?}",
            result
        );

        // read_at must be unchanged (still the value set by the first call).
        let msg_final = ms.get("msg-rnd").expect("get").expect("exists");
        assert_eq!(
            msg_final.read_at.as_deref(),
            Some(read_at_first.as_str()),
            "read_at must not regress after second call with earlier timestamp"
        );

        // State counter must NOT have advanced — no row was changed.
        let state_after_second = ms.get_state().expect("state after second update");
        assert_eq!(
            state_after_first, state_after_second,
            "state counter must not advance when update_read_at is a no-op (earlier timestamp)"
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
    fn update_read_at_zero_returns_err() {
        // Oracle: zero is not a valid Unix timestamp for a read receipt; the guard
        // must reject it before touching the database. The state counter must not advance.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ra0");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ra0",
            "chat-ra0",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ra0",
        )
        .expect("insert");

        let state_before = ms.get_state().expect("state before");
        let result = ms.update_read_at("msg-ra0", 0);
        assert!(result.is_err(), "update_read_at(id, 0) must return Err");
        let state_after = ms.get_state().expect("state after");
        assert_eq!(
            state_before, state_after,
            "state counter must not advance when update_read_at rejects zero timestamp"
        );
    }

    #[test]
    fn update_read_at_negative_returns_err() {
        // Oracle: negative Unix timestamps are pre-epoch and invalid for read receipts.
        // The guard must reject them before touching the database.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ran");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ran",
            "chat-ran",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ran",
        )
        .expect("insert");

        let state_before = ms.get_state().expect("state before");
        let result = ms.update_read_at("msg-ran", -1);
        assert!(result.is_err(), "update_read_at(id, -1) must return Err");
        let state_after = ms.get_state().expect("state after");
        assert_eq!(
            state_before, state_after,
            "state counter must not advance when update_read_at rejects negative timestamp"
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
    fn get_position_in_chat_returns_correct_0_based_index() {
        // Oracle: with 3 messages at created_at 100, 200, 300, newest-first order is
        // msg-300 (index 0), msg-200 (index 1), msg-100 (index 2).
        // get_position_in_chat must return the COUNT of messages that are newer, which
        // equals the 0-based index in ORDER BY created_at DESC, id DESC.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-pos");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-pos-100",
            "chat-pos",
            "u",
            "a",
            "text/plain",
            None,
            100,
            &DeliveryState::Received,
            None,
            "msg-pos-100",
        )
        .expect("insert t=100");
        ms.insert(
            "msg-pos-200",
            "chat-pos",
            "u",
            "b",
            "text/plain",
            None,
            200,
            &DeliveryState::Received,
            None,
            "msg-pos-200",
        )
        .expect("insert t=200");
        ms.insert(
            "msg-pos-300",
            "chat-pos",
            "u",
            "c",
            "text/plain",
            None,
            300,
            &DeliveryState::Received,
            None,
            "msg-pos-300",
        )
        .expect("insert t=300");

        // Newest message → index 0.
        assert_eq!(
            ms.get_position_in_chat("chat-pos", "msg-pos-300")
                .expect("query"),
            Some(0),
            "newest message must be at index 0"
        );
        // Middle message → index 1.
        assert_eq!(
            ms.get_position_in_chat("chat-pos", "msg-pos-200")
                .expect("query"),
            Some(1),
            "middle message must be at index 1"
        );
        // Oldest message → index 2.
        assert_eq!(
            ms.get_position_in_chat("chat-pos", "msg-pos-100")
                .expect("query"),
            Some(2),
            "oldest message must be at index 2"
        );
        // Nonexistent message → None.
        assert_eq!(
            ms.get_position_in_chat("chat-pos", "no-such-msg")
                .expect("query"),
            None,
            "nonexistent message must return None"
        );
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
