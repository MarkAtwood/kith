use crate::db_err;
use crate::message::ChangesResult;
use kith_core::{Chat, ChatKind, Id, JmapError, KithError, StateChange, UTCDate};
use rusqlite::{params, Connection, OptionalExtension};
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

/// Column list shared by all SELECT queries that construct a [`Chat`].
///
/// Indices:
///   0  c.id
///   1  c.kind
///   2  c.contact_id
///   3  c.created_at
///   4  c.last_message_at
///   5  unread_count (correlated subquery)
///   6  c.name
///   7  c.description
///   8  c.avatar_blob_id
///   9  c.muted
///  10  c.mute_until
///  11  c.receive_typing_indicators
///  12  c.receipt_sharing
///  13  c.message_expiry_seconds
const CHAT_SELECT_COLS: &str = "\
    c.id, c.kind, c.contact_id, c.created_at, c.last_message_at, \
    (SELECT COUNT(*) FROM messages m \
     WHERE m.chat_id = c.id \
       AND m.delivery_state = 'received' \
       AND m.read_at IS NULL) AS unread_count, \
    c.name, c.description, c.avatar_blob_id, c.muted, c.mute_until, \
    c.receive_typing_indicators, c.receipt_sharing, c.message_expiry_seconds";

/// Intermediate struct holding the raw DB row values before Chat construction.
/// Avoids a 14-element tuple.
struct ChatRow {
    id: String,
    kind: String,
    contact_id: Option<String>,
    created_at_secs: i64,
    last_message_at_secs: Option<i64>,
    unread_count: u32,
    name: Option<String>,
    description: Option<String>,
    avatar_blob_id: Option<String>,
    muted: bool,
    mute_until: Option<String>,
    receive_typing_indicators: bool,
    receipt_sharing: Option<bool>,
    message_expiry_seconds: Option<u64>,
}

/// Extract a [`ChatRow`] from a rusqlite `Row`.
///
/// Column order must match [`CHAT_SELECT_COLS`].
fn extract_chat_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatRow> {
    let muted_int: i32 = row.get(9)?;
    let rti_int: i32 = row.get(11)?;
    let receipt_sharing_opt: Option<i32> = row.get(12)?;
    let expiry_opt: Option<i64> = row.get(13)?;
    Ok(ChatRow {
        id: row.get(0)?,
        kind: row.get(1)?,
        contact_id: row.get(2)?,
        created_at_secs: row.get(3)?,
        last_message_at_secs: row.get(4)?,
        unread_count: row.get(5)?,
        name: row.get(6)?,
        description: row.get(7)?,
        avatar_blob_id: row.get(8)?,
        muted: muted_int != 0,
        mute_until: row.get(10)?,
        receive_typing_indicators: rti_int != 0,
        receipt_sharing: receipt_sharing_opt.map(|v| v != 0),
        message_expiry_seconds: expiry_opt.map(|v| {
            debug_assert!(
                v >= 0,
                "message_expiry_seconds must be non-negative, got {v}"
            );
            v.max(0) as u64
        }),
    })
}

/// Build a [`Chat`] from a [`ChatRow`].  Pinned messages are populated separately.
fn build_chat(r: ChatRow) -> Chat {
    debug_assert!(
        r.created_at_secs >= 0,
        "timestamp must be non-negative Unix seconds, got {}",
        r.created_at_secs
    );
    let mut chat = Chat::new(
        Id::from(r.id),
        parse_chat_kind(&r.kind),
        UTCDate::from(crate::util::unix_secs_to_rfc3339(
            r.created_at_secs.max(0) as u64
        )),
        r.unread_count as u64,
        vec![], // pinned_message_ids populated separately via load_pinned_messages
        r.muted,
        r.receive_typing_indicators,
    );
    chat.contact_id = r.contact_id.map(Id::from);
    chat.name = r.name;
    chat.description = r.description;
    chat.avatar_blob_id = r.avatar_blob_id.map(Id::from);
    chat.mute_until = r.mute_until.map(UTCDate::from);
    chat.receipt_sharing = r.receipt_sharing;
    chat.message_expiry_seconds = r.message_expiry_seconds;
    chat.last_message_at = r.last_message_at_secs.map(|s| {
        debug_assert!(
            s >= 0,
            "timestamp must be non-negative Unix seconds, got {s}"
        );
        UTCDate::from(crate::util::unix_secs_to_rfc3339(s.max(0) as u64))
    });
    chat
}

/// Optional metadata fields for [`ChatStore::create`].
///
/// All fields default to `None` via [`Default`].
#[derive(Default)]
pub struct CreateChatMeta<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
}

/// Settable metadata fields for [`ChatStore::update_metadata`].
///
/// Each field is `Option<Option<T>>`:
/// - `None` → leave the column unchanged
/// - `Some(None)` → set the column to NULL
/// - `Some(Some(v))` → set the column to `v`
///
/// Boolean fields are `Option<bool>`:
/// - `None` → leave unchanged
/// - `Some(v)` → set to `v`
#[derive(Default)]
pub struct ChatMetadataUpdate<'a> {
    pub name: Option<Option<&'a str>>,
    pub description: Option<Option<&'a str>>,
    pub avatar_blob_id: Option<Option<&'a str>>,
    pub muted: Option<bool>,
    pub mute_until: Option<Option<&'a str>>,
    pub receive_typing_indicators: Option<bool>,
    pub receipt_sharing: Option<Option<bool>>,
    pub message_expiry_seconds: Option<Option<u64>>,
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
            let _ = tx.send(StateChange::new("Chat", new_state));
        }
    }

    /// Load pinned message IDs for a chat from the `pinned_messages` table.
    pub fn load_pinned_messages(&self, chat_id: &str) -> Result<Vec<Id>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT message_id FROM pinned_messages WHERE chat_id = ?1 ORDER BY message_id",
            )
            .map_err(db_err)?;
        let ids = stmt
            .query_map(params![chat_id], |row| row.get::<_, String>(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(ids.into_iter().map(Id::from).collect())
    }

    /// Fetch a single chat by ID and populate its pinned message IDs.
    fn get_with_pins(&self, chat_id: &str) -> Result<Option<Chat>, KithError> {
        let mut chat = match self.get(chat_id)? {
            Some(c) => c,
            None => return Ok(None),
        };
        chat.pinned_message_ids = self.load_pinned_messages(chat_id)?;
        Ok(Some(chat))
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
        self.create_with_meta(
            chat_id,
            kind,
            contact_id,
            now_unix,
            &CreateChatMeta::default(),
        )
    }

    /// Create a chat with optional name/description metadata.
    pub fn create_with_meta(
        &self,
        chat_id: &str,
        kind: &str,
        contact_id: Option<&str>,
        now_unix: i64,
        meta: &CreateChatMeta<'_>,
    ) -> Result<Chat, KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "INSERT OR IGNORE INTO chats (id, kind, contact_id, created_at, name, description) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![chat_id, kind, contact_id, now_unix, meta.name, meta.description],
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

    /// Remove a peer participant from a group chat.
    ///
    /// Idempotent: DELETE affects 0 rows if the member was not present.
    pub fn remove_member(&self, chat_id: &str, peer_user_id: &str) -> Result<(), KithError> {
        self.conn
            .execute(
                "DELETE FROM chat_members WHERE chat_id = ?1 AND peer_user_id = ?2",
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

    /// Return the `space_id` for a chat, or `None` if the chat is not a channel.
    ///
    /// Used by the permission resolution engine to look up the Space that owns
    /// a channel chat.
    pub fn get_space_id(&self, chat_id: &str) -> Result<Option<String>, KithError> {
        let space_id: Option<String> = self
            .conn
            .query_row(
                "SELECT space_id FROM chats WHERE id = ?1",
                params![chat_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err)?
            .flatten();
        Ok(space_id)
    }

    /// Find an existing direct chat by the peer contact's userId.
    ///
    /// Used by Chat/set create to deduplicate: if a direct chat with this
    /// contact already exists, return it rather than creating a new one.
    pub fn find_direct_by_contact_id(&self, contact_id: &str) -> Result<Option<Chat>, KithError> {
        let row = self.conn.query_row(
            &format!(
                "SELECT {CHAT_SELECT_COLS} FROM chats c \
                 WHERE c.kind = 'direct' AND c.contact_id = ?1"
            ),
            params![contact_id],
            extract_chat_row,
        );
        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
            Ok(r) => {
                let chat_id = r.id.clone();
                let mut chat = build_chat(r);
                chat.pinned_message_ids = self.load_pinned_messages(&chat_id)?;
                Ok(Some(chat))
            }
        }
    }

    /// Fetch a single chat by ID, returning None if it does not exist.
    pub fn get(&self, chat_id: &str) -> Result<Option<Chat>, KithError> {
        let row = self.conn.query_row(
            &format!("SELECT {CHAT_SELECT_COLS} FROM chats c WHERE c.id = ?1"),
            params![chat_id],
            extract_chat_row,
        );

        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
            Ok(r) => {
                let mut chat = build_chat(r);
                chat.pinned_message_ids = self.load_pinned_messages(chat_id)?;
                Ok(Some(chat))
            }
        }
    }

    /// List all chats ordered by last_message_at DESC (nulls last), then created_at DESC.
    pub fn list(&self) -> Result<Vec<Chat>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!(
                "SELECT {CHAT_SELECT_COLS} FROM chats c \
                 ORDER BY c.last_message_at DESC NULLS LAST, c.created_at DESC"
            ))
            .map_err(db_err)?;

        let rows: Vec<ChatRow> = stmt
            .query_map([], extract_chat_row)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut chats = Vec::with_capacity(rows.len());
        for r in rows {
            let chat_id = r.id.clone();
            let mut chat = build_chat(r);
            chat.pinned_message_ids = self.load_pinned_messages(&chat_id)?;
            chats.push(chat);
        }

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

    /// Update chat metadata fields and advance the chat state counter.
    ///
    /// Only fields with `Some(...)` values in the update struct are modified;
    /// `None` fields are left unchanged.  Returns the updated [`Chat`].
    ///
    /// Returns `Err(KithError::Store)` if `chat_id` does not exist.
    pub fn update_metadata(
        &self,
        chat_id: &str,
        update: &ChatMetadataUpdate<'_>,
    ) -> Result<Chat, KithError> {
        // Build SET clauses dynamically to avoid overwriting fields not in the update.
        let mut set_clauses: Vec<String> = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(v) = update.name {
            set_clauses.push(format!("name = ?{}", param_values.len() + 1));
            param_values.push(Box::new(v.map(|s| s.to_owned())));
        }
        if let Some(v) = update.description {
            set_clauses.push(format!("description = ?{}", param_values.len() + 1));
            param_values.push(Box::new(v.map(|s| s.to_owned())));
        }
        if let Some(v) = update.avatar_blob_id {
            set_clauses.push(format!("avatar_blob_id = ?{}", param_values.len() + 1));
            param_values.push(Box::new(v.map(|s| s.to_owned())));
        }
        if let Some(v) = update.muted {
            set_clauses.push(format!("muted = ?{}", param_values.len() + 1));
            param_values.push(Box::new(v as i32));
        }
        if let Some(v) = update.mute_until {
            set_clauses.push(format!("mute_until = ?{}", param_values.len() + 1));
            param_values.push(Box::new(v.map(|s| s.to_owned())));
        }
        if let Some(v) = update.receive_typing_indicators {
            set_clauses.push(format!(
                "receive_typing_indicators = ?{}",
                param_values.len() + 1
            ));
            param_values.push(Box::new(v as i32));
        }
        if let Some(v) = update.receipt_sharing {
            set_clauses.push(format!("receipt_sharing = ?{}", param_values.len() + 1));
            param_values.push(Box::new(v.map(|b| b as i32)));
        }
        if let Some(v) = update.message_expiry_seconds {
            set_clauses.push(format!(
                "message_expiry_seconds = ?{}",
                param_values.len() + 1
            ));
            param_values.push(Box::new(v.map(|n| n as i64)));
        }

        if set_clauses.is_empty() {
            // Nothing to update — just return the current chat.
            return self
                .get_with_pins(chat_id)?
                .ok_or_else(|| KithError::Store("chat not found".into()));
        }

        // Add chat_id as the last parameter.
        let id_param_idx = param_values.len() + 1;
        param_values.push(Box::new(chat_id.to_owned()));

        let sql = format!(
            "UPDATE chats SET {} WHERE id = ?{}",
            set_clauses.join(", "),
            id_param_idx
        );

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();
        let affected = tx.execute(&sql, param_refs.as_slice()).map_err(db_err)?;

        if affected == 0 {
            tx.commit().map_err(db_err)?;
            return Err(KithError::Store("chat not found".into()));
        }

        let counter = crate::advance_state_counter_in_tx(&tx, "chat")?;
        tx.execute(
            "UPDATE chats SET changed_at_counter = ?1 WHERE id = ?2",
            params![counter, chat_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{counter}"));

        self.get_with_pins(chat_id)?
            .ok_or_else(|| KithError::Store("chat not found after update".into()))
    }

    /// Replace the set of pinned messages for a chat.
    ///
    /// Validates that all message IDs exist and belong to the given chat.
    /// Advances the chat state counter.
    pub fn set_pinned_messages(
        &self,
        chat_id: &str,
        message_ids: &[&str],
    ) -> Result<(), KithError> {
        // Validate all message IDs belong to this chat.
        for msg_id in message_ids {
            let exists: bool = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE id = ?1 AND chat_id = ?2)",
                    params![msg_id, chat_id],
                    |row| row.get(0),
                )
                .map_err(db_err)?;
            if !exists {
                return Err(KithError::Validation(format!(
                    "message '{}' does not exist in chat '{}'",
                    msg_id, chat_id
                )));
            }
        }

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Clear existing pins.
        tx.execute(
            "DELETE FROM pinned_messages WHERE chat_id = ?1",
            params![chat_id],
        )
        .map_err(db_err)?;

        // Insert new pins.
        for msg_id in message_ids {
            tx.execute(
                "INSERT INTO pinned_messages (chat_id, message_id) VALUES (?1, ?2)",
                params![chat_id, msg_id],
            )
            .map_err(db_err)?;
        }

        let counter = crate::advance_state_counter_in_tx(&tx, "chat")?;
        tx.execute(
            "UPDATE chats SET changed_at_counter = ?1 WHERE id = ?2",
            params![counter, chat_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{counter}"));

        Ok(())
    }

    /// Check if a blob ID exists in the attachments table.
    ///
    /// Used to validate `avatarBlobId` before storing it.
    pub fn blob_exists(&self, blob_id: &str) -> Result<bool, KithError> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM attachments WHERE id = ?1)",
                params![blob_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(exists)
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
    /// **Do not use this method when `maxChanges` pagination is required.**
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
        assert_eq!(
            chat1.contact_id.as_ref().map(|id| id.as_ref()),
            Some("uid:bob")
        );
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
        assert_eq!(
            found.contact_id.as_ref().map(|id| id.as_ref()),
            Some("uid:carol")
        );
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

    // --- V20 metadata tests ---

    #[test]
    fn create_with_name_and_description() {
        // Oracle: name and description passed to create_with_meta must be
        // persisted and returned by get().
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let meta = CreateChatMeta {
            name: Some("Engineering"),
            description: Some("Main engineering channel"),
        };
        let chat = cs
            .create_with_meta("chat-grp1", "group", None, 1_000_000, &meta)
            .unwrap();
        assert_eq!(chat.name.as_deref(), Some("Engineering"));
        assert_eq!(
            chat.description.as_deref(),
            Some("Main engineering channel")
        );

        // Verify via independent get.
        let loaded = cs.get("chat-grp1").unwrap().unwrap();
        assert_eq!(loaded.name.as_deref(), Some("Engineering"));
        assert_eq!(
            loaded.description.as_deref(),
            Some("Main engineering channel")
        );
    }

    #[test]
    fn default_metadata_values() {
        // Oracle: a chat created without metadata must have muted=false,
        // receive_typing_indicators=true, and all optional fields None.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-def1", "direct", Some("uid:alice"), 1_000_000)
            .unwrap();
        let chat = cs.get("chat-def1").unwrap().unwrap();

        assert!(!chat.muted, "muted must default to false");
        assert!(
            chat.receive_typing_indicators,
            "receive_typing_indicators must default to true"
        );
        assert!(chat.name.is_none(), "name must default to None");
        assert!(
            chat.description.is_none(),
            "description must default to None"
        );
        assert!(
            chat.avatar_blob_id.is_none(),
            "avatar_blob_id must default to None"
        );
        assert!(chat.mute_until.is_none(), "mute_until must default to None");
        assert!(
            chat.receipt_sharing.is_none(),
            "receipt_sharing must default to None"
        );
        assert!(
            chat.message_expiry_seconds.is_none(),
            "message_expiry_seconds must default to None"
        );
        assert!(
            chat.pinned_message_ids.is_empty(),
            "pinned_message_ids must default to empty"
        );
    }

    #[test]
    fn update_metadata_muted() {
        // Oracle: setting muted=true must persist and be returned by get().
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-mut1", "direct", Some("uid:bob"), 1_000_000)
            .unwrap();

        let updated = cs
            .update_metadata(
                "chat-mut1",
                &ChatMetadataUpdate {
                    muted: Some(true),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(updated.muted, "muted must be true after update");

        let loaded = cs.get("chat-mut1").unwrap().unwrap();
        assert!(loaded.muted, "muted must persist after update");
    }

    #[test]
    fn update_metadata_name_change() {
        // Oracle: updating the name must persist and be returned by get().
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let meta = CreateChatMeta {
            name: Some("Old Name"),
            ..Default::default()
        };
        cs.create_with_meta("chat-nm1", "group", None, 1_000_000, &meta)
            .unwrap();

        let updated = cs
            .update_metadata(
                "chat-nm1",
                &ChatMetadataUpdate {
                    name: Some(Some("New Name")),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(updated.name.as_deref(), Some("New Name"));

        let loaded = cs.get("chat-nm1").unwrap().unwrap();
        assert_eq!(loaded.name.as_deref(), Some("New Name"));
    }

    #[test]
    fn update_metadata_advances_state() {
        // Oracle: update_metadata must advance the chat state counter.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-st1", "direct", Some("uid:carol"), 1_000_000)
            .unwrap();
        let state_before = cs.get_state().unwrap();

        cs.update_metadata(
            "chat-st1",
            &ChatMetadataUpdate {
                muted: Some(true),
                ..Default::default()
            },
        )
        .unwrap();

        let state_after = cs.get_state().unwrap();
        assert_ne!(
            state_before, state_after,
            "state counter must advance after update_metadata"
        );
    }

    #[test]
    fn update_metadata_nonexistent_chat() {
        // Oracle: updating a nonexistent chat must return Err.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let result = cs.update_metadata(
            "no-such-chat",
            &ChatMetadataUpdate {
                muted: Some(true),
                ..Default::default()
            },
        );
        assert!(
            result.is_err(),
            "update_metadata on nonexistent chat must fail"
        );
    }

    #[test]
    fn pinned_messages_persist() {
        // Oracle: pinning messages must be returned by get() and load_pinned_messages().
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-pin1", "direct", Some("uid:dave"), 1_000_000)
            .unwrap();

        // Insert messages for the chat.
        store
            .conn
            .execute(
                "INSERT INTO messages \
                 (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
                 VALUES ('msg-pin-a', 'chat-pin1', 'uid:dave', 'hello', 1000000, 'received', 'msg-pin-a')",
                [],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO messages \
                 (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
                 VALUES ('msg-pin-b', 'chat-pin1', 'uid:dave', 'world', 1000001, 'received', 'msg-pin-b')",
                [],
            )
            .unwrap();

        cs.set_pinned_messages("chat-pin1", &["msg-pin-a", "msg-pin-b"])
            .unwrap();

        let pins = cs.load_pinned_messages("chat-pin1").unwrap();
        let pin_strs: Vec<&str> = pins.iter().map(|id| id.as_ref()).collect();
        assert!(
            pin_strs.contains(&"msg-pin-a"),
            "msg-pin-a must be in pinned_message_ids"
        );
        assert!(
            pin_strs.contains(&"msg-pin-b"),
            "msg-pin-b must be in pinned_message_ids"
        );

        // Verify via get().
        let chat = cs.get("chat-pin1").unwrap().unwrap();
        let chat_pin_strs: Vec<&str> = chat
            .pinned_message_ids
            .iter()
            .map(|id| id.as_ref())
            .collect();
        assert_eq!(chat_pin_strs.len(), 2);
        assert!(chat_pin_strs.contains(&"msg-pin-a"));
        assert!(chat_pin_strs.contains(&"msg-pin-b"));
    }

    // ── Additional coverage tests ──────────────────────────────────────────

    #[test]
    fn create_direct_chat_sets_kind_and_contact_id() {
        // Oracle: a direct chat must store kind=Direct and the supplied contact_id.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let chat = cs
            .create("chat-dir1", "direct", Some("uid:alice"), 1_000_000)
            .unwrap();
        assert_eq!(chat.kind, ChatKind::Direct);
        assert_eq!(
            chat.contact_id.as_ref().map(|id| id.as_ref()),
            Some("uid:alice")
        );
    }

    #[test]
    fn create_group_chat_sets_kind_group() {
        // Oracle: a group chat must store kind=Group with no contact_id.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let chat = cs
            .create("chat-grp2", "group", None, 1_000_000)
            .unwrap();
        assert_eq!(chat.kind, ChatKind::Group);
        assert!(
            chat.contact_id.is_none(),
            "group chat must have no contact_id"
        );
    }

    #[test]
    fn list_ids_returns_ids_only() {
        // Oracle: list_ids returns Vec<String> of just IDs, not full Chat objects.
        // The count must match the number of created chats.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-id1", "direct", Some("uid:x"), 1_000_000)
            .unwrap();
        cs.create("chat-id2", "group", None, 1_000_001).unwrap();

        let ids = cs.list_ids().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"chat-id1".to_string()));
        assert!(ids.contains(&"chat-id2".to_string()));
    }

    #[test]
    fn get_members_returns_member_user_ids() {
        // Oracle: after add_member, get_members must return the added peer_user_ids.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-mem1", "group", None, 1_000_000).unwrap();
        cs.add_member("chat-mem1", "uid:alice").unwrap();
        cs.add_member("chat-mem1", "uid:bob").unwrap();

        let members = cs.get_members("chat-mem1").unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&"uid:alice".to_string()));
        assert!(members.contains(&"uid:bob".to_string()));
    }

    #[test]
    fn add_member_is_idempotent() {
        // Oracle: INSERT OR IGNORE means adding the same member twice is a no-op.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-mem2", "group", None, 1_000_000).unwrap();
        cs.add_member("chat-mem2", "uid:carol").unwrap();
        cs.add_member("chat-mem2", "uid:carol").unwrap(); // duplicate

        let members = cs.get_members("chat-mem2").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0], "uid:carol");
    }

    #[test]
    fn remove_member_removes_from_chat_members() {
        // Oracle: DELETE FROM chat_members removes the specific (chat_id, peer_user_id) row.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-rm1", "group", None, 1_000_000).unwrap();
        cs.add_member("chat-rm1", "uid:alice").unwrap();
        cs.add_member("chat-rm1", "uid:bob").unwrap();

        cs.remove_member("chat-rm1", "uid:alice").unwrap();

        let members = cs.get_members("chat-rm1").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0], "uid:bob");
    }

    #[test]
    fn update_last_message_at_updates_timestamp_and_advances_state() {
        // Oracle: update_last_message_at must both update the chat's last_message_at
        // field and advance the state counter.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-lma1", "direct", Some("uid:frank"), 1_000_000)
            .unwrap();
        let state_before = cs.get_state().unwrap();

        cs.update_last_message_at("chat-lma1", 2_000_000).unwrap();

        let state_after = cs.get_state().unwrap();
        assert_ne!(
            state_before, state_after,
            "state must advance after update_last_message_at"
        );

        let chat = cs.get("chat-lma1").unwrap().unwrap();
        assert!(
            chat.last_message_at.is_some(),
            "last_message_at must be set"
        );
    }

    #[test]
    fn unread_count_returns_correct_count() {
        // Oracle: unread_count = received + read_at IS NULL messages for that chat.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-uc1", "direct", Some("uid:greg"), 1_000_000)
            .unwrap();

        // Insert 2 received+unread, 1 received+read, 1 pending.
        let insert = |id: &str, state: &str, read_at: Option<i64>| {
            store
                .conn
                .execute(
                    "INSERT INTO messages \
                     (id, chat_id, sender_user_id, body, created_at, delivery_state, read_at, sender_msg_id) \
                     VALUES (?1, 'chat-uc1', 'uid:greg', 'hi', 1000000, ?2, ?3, ?1)",
                    params![id, state, read_at],
                )
                .unwrap();
        };
        insert("uc-r1", "received", None);
        insert("uc-r2", "received", None);
        insert("uc-r3", "received", Some(1_000_001));
        insert("uc-p1", "pending", None);

        let count = cs.unread_count("chat-uc1").unwrap();
        assert_eq!(count, 2, "only received+unread messages count");
    }

    #[test]
    fn pinned_messages_validation_rejects_wrong_chat() {
        // Oracle: pinning a message that belongs to a different chat must fail.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-pinv1", "direct", Some("uid:eve"), 1_000_000)
            .unwrap();
        cs.create("chat-pinv2", "direct", Some("uid:frank"), 1_000_001)
            .unwrap();

        store
            .conn
            .execute(
                "INSERT INTO messages \
                 (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
                 VALUES ('msg-other', 'chat-pinv2', 'uid:frank', 'hi', 1000000, 'received', 'msg-other')",
                [],
            )
            .unwrap();

        let result = cs.set_pinned_messages("chat-pinv1", &["msg-other"]);
        assert!(
            result.is_err(),
            "pinning a message from another chat must fail"
        );
    }

    #[test]
    fn update_metadata_receipt_sharing_and_expiry() {
        // Oracle: receipt_sharing and message_expiry_seconds must persist.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-rse1", "group", None, 1_000_000).unwrap();

        let updated = cs
            .update_metadata(
                "chat-rse1",
                &ChatMetadataUpdate {
                    receipt_sharing: Some(Some(true)),
                    message_expiry_seconds: Some(Some(3600)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(updated.receipt_sharing, Some(true));
        assert_eq!(updated.message_expiry_seconds, Some(3600));

        let loaded = cs.get("chat-rse1").unwrap().unwrap();
        assert_eq!(loaded.receipt_sharing, Some(true));
        assert_eq!(loaded.message_expiry_seconds, Some(3600));
    }

    #[test]
    fn update_metadata_clear_name() {
        // Oracle: setting name to None must clear it in the database.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let meta = CreateChatMeta {
            name: Some("Team Chat"),
            ..Default::default()
        };
        cs.create_with_meta("chat-clr1", "group", None, 1_000_000, &meta)
            .unwrap();

        // Verify name is set.
        let before = cs.get("chat-clr1").unwrap().unwrap();
        assert_eq!(before.name.as_deref(), Some("Team Chat"));

        // Clear the name.
        let after = cs
            .update_metadata(
                "chat-clr1",
                &ChatMetadataUpdate {
                    name: Some(None),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(after.name.is_none(), "name must be None after clearing");

        let loaded = cs.get("chat-clr1").unwrap().unwrap();
        assert!(loaded.name.is_none(), "name must persist as None");
    }

    // -----------------------------------------------------------------------
    // Additional chat store edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_direct_chat_same_contact_twice_returns_same_chat() {
        // Oracle: the UNIQUE INDEX chats_direct_contact ON chats(contact_id)
        // WHERE kind = 'direct' prevents two direct chats for the same contact.
        // The second create call returns the existing chat (INSERT OR IGNORE).
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        let chat1 = cs
            .create("chat-dup-a", "direct", Some("uid:same-contact"), 1_000_000)
            .unwrap();

        // Second create with a DIFFERENT chat ID but SAME contact_id.
        let chat2 = cs
            .create("chat-dup-b", "direct", Some("uid:same-contact"), 2_000_000)
            .unwrap();

        // Must return the same chat (the one that won the UNIQUE race).
        assert_eq!(
            chat1.id, chat2.id,
            "second create with same contact must return the existing chat"
        );
        assert_eq!(
            chat1.created_at, chat2.created_at,
            "created_at must not change"
        );
    }

    #[test]
    fn get_nonexistent_chat_returns_none() {
        // Oracle: get() on a chat ID not in the database returns Ok(None).
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);
        let result = cs.get("totally-nonexistent").unwrap();
        assert!(result.is_none(), "nonexistent chat must return None");
    }

    #[test]
    fn list_chats_ordered_by_last_message_at_desc_nulls_last() {
        // Oracle: SQL ORDER BY last_message_at DESC NULLS LAST, created_at DESC.
        // Chat with most recent last_message_at comes first;
        // chat with no messages (NULL) comes last.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-ord-a", "direct", Some("uid:alice-ord"), 1_000_000)
            .unwrap();
        cs.create("chat-ord-b", "direct", Some("uid:bob-ord"), 1_000_001)
            .unwrap();
        cs.create("chat-ord-c", "direct", Some("uid:carol-ord"), 1_000_002)
            .unwrap();

        cs.update_last_message_at("chat-ord-b", 5_000_000).unwrap();
        cs.update_last_message_at("chat-ord-a", 3_000_000).unwrap();
        // chat-ord-c has no last_message_at (NULL).

        let chats = cs.list().unwrap();
        let ids: Vec<&str> = chats.iter().map(|c| c.id.as_ref()).collect();

        assert_eq!(ids[0], "chat-ord-b", "most recent last_message_at first");
        assert_eq!(ids[1], "chat-ord-a", "second most recent next");
        assert_eq!(ids[2], "chat-ord-c", "NULL last_message_at comes last");
    }

    #[test]
    fn create_group_chat_add_members_verify_get_members() {
        // Oracle: add_member inserts into chat_members; get_members returns them.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-grp-m", "group", None, 1_000_000).unwrap();
        cs.add_member("chat-grp-m", "uid:alice").unwrap();
        cs.add_member("chat-grp-m", "uid:bob").unwrap();
        cs.add_member("chat-grp-m", "uid:carol").unwrap();

        let members = cs.get_members("chat-grp-m").unwrap();
        assert_eq!(members.len(), 3);
        assert!(members.contains(&"uid:alice".to_string()));
        assert!(members.contains(&"uid:bob".to_string()));
        assert!(members.contains(&"uid:carol".to_string()));
    }

    #[test]
    fn delete_chat_cascades_to_messages_and_members() {
        // Oracle: chats table has ON DELETE CASCADE on chat_members(chat_id)
        // and ON DELETE CASCADE on messages(chat_id) (via V16 migration).
        // Deleting the chat row must cascade to both tables.
        let store = Store::open_in_memory().unwrap();
        let cs = ChatStore::new(&store.conn, None);

        cs.create("chat-del-c", "group", None, 1_000_000).unwrap();
        cs.add_member("chat-del-c", "uid:peer1").unwrap();

        // Insert a message into the chat.
        store
            .conn
            .execute(
                "INSERT INTO messages \
                 (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
                 VALUES ('msg-del-c', 'chat-del-c', 'uid:peer1', 'hello', 1000, 'received', 'msg-del-c')",
                [],
            )
            .unwrap();

        // Verify the rows exist.
        let member_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM chat_members WHERE chat_id = 'chat-del-c'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(member_count, 1, "member must exist before delete");

        let msg_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE chat_id = 'chat-del-c'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(msg_count, 1, "message must exist before delete");

        // Delete the chat.
        store
            .conn
            .execute("DELETE FROM chats WHERE id = 'chat-del-c'", [])
            .unwrap();

        // Oracle: cascade must remove both members and messages.
        let member_count_after: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM chat_members WHERE chat_id = 'chat-del-c'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            member_count_after, 0,
            "chat_members must be cascade-deleted when chat is deleted"
        );

        let msg_count_after: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE chat_id = 'chat-del-c'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            msg_count_after, 0,
            "messages must be cascade-deleted when chat is deleted"
        );
    }
}
