use crate::{attachment, db_err};
use kith_core::{
    make_broadcast_mention, make_message_revision, BroadcastMention, DeliveryReceipt,
    DeliveryState, Id, JmapError, KithError, Message, MessageAction, MessageRevision, Reaction,
    ReadDisposition, SenderId, StateChange, UTCDate,
};
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
        // DeliveryState is #[non_exhaustive]; unknown variants are defensive-defaulted
        // to "pending" so the DB CHECK constraint never rejects them.
        _ => "pending",
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
/// Column order must match the SELECT list `MESSAGE_COLUMNS`:
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
///   12 deleted_at       INTEGER NULL (Unix seconds)
///   13 deleted_for_all  INTEGER NULL (0 or 1)
///   14 edited_at        INTEGER NULL (Unix seconds)
///   15 thread_root_id   TEXT NULL
///   16 sender_expires_at INTEGER NULL (Unix seconds)
///   17 burn_on_read     INTEGER NULL (0 or 1)
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
    let deleted_at_unix: Option<i64> = row.get(12)?;
    let deleted_for_all_raw: Option<i64> = row.get(13)?;
    let edited_at_unix: Option<i64> = row.get(14)?;
    let thread_root_id: Option<String> = row.get(15)?;
    let sender_expires_at_unix: Option<i64> = row.get(16)?;
    let burn_on_read_raw: Option<i64> = row.get(17)?;

    let delivery_state = parse_delivery_state(&delivery_state_raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;
    debug_assert!(
        created_at >= 0,
        "timestamp must be non-negative Unix seconds, got {created_at}"
    );
    let received_at = crate::util::unix_secs_to_rfc3339(created_at.max(0) as u64);
    let sent_at = sent_at_peer.unwrap_or_else(|| received_at.clone());
    let delivered_at = delivered_at_unix.map(|s| {
        debug_assert!(
            s >= 0,
            "timestamp must be non-negative Unix seconds, got {s}"
        );
        crate::util::unix_secs_to_rfc3339(s.max(0) as u64)
    });
    let read_at = read_at_unix.map(|s| {
        debug_assert!(
            s >= 0,
            "timestamp must be non-negative Unix seconds, got {s}"
        );
        crate::util::unix_secs_to_rfc3339(s.max(0) as u64)
    });
    // sender_msg_id is enforced NOT NULL by the V6 trigger; NULL means
    // pre-V6 data or DB corruption.  Reject rather than silently fall back.
    let sender_msg_id = sender_msg_id.ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            11,
            rusqlite::types::Type::Null,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sender_msg_id is NULL (pre-V6 row or DB corruption)",
            )),
        )
    })?;

    let is_deleted = deleted_at_unix.is_some();

    // In the DB, sender_user_id is always a peer user ID (never "self")
    // because "self" is a display-time concept. Use Contact variant.
    let sender_id = SenderId::Contact(sender_user_id);

    // When deleted_at is set, body should be cleared and attachments should be empty.
    let effective_body = if is_deleted { String::new() } else { body };

    let sender_expires_at = sender_expires_at_unix.map(|s| {
        debug_assert!(
            s >= 0,
            "timestamp must be non-negative Unix seconds, got {s}"
        );
        UTCDate::from(crate::util::unix_secs_to_rfc3339(s.max(0) as u64))
    });
    let burn_on_read = burn_on_read_raw.map(|v| v != 0);

    let mut msg = Message::new(
        Id::from(id),
        Id::from(sender_msg_id),
        sender_id,
        Id::from(chat_id),
        effective_body,
        body_type,
        UTCDate::from(sent_at),
        UTCDate::from(received_at),
        delivery_state,
    );
    msg.reply_to = reply_to.map(Id::from);
    msg.delivered_at = delivered_at.map(UTCDate::from);
    msg.read_at = read_at.map(UTCDate::from);

    // Populate deletion fields.
    msg.deleted_at = deleted_at_unix.map(|s| {
        debug_assert!(
            s >= 0,
            "timestamp must be non-negative Unix seconds, got {s}"
        );
        UTCDate::from(crate::util::unix_secs_to_rfc3339(s.max(0) as u64))
    });
    msg.deleted_for_all = deleted_for_all_raw.map(|v| v != 0);

    // Populate edited_at.
    msg.edited_at = edited_at_unix.map(|s| {
        debug_assert!(
            s >= 0,
            "timestamp must be non-negative Unix seconds, got {s}"
        );
        UTCDate::from(crate::util::unix_secs_to_rfc3339(s.max(0) as u64))
    });

    // Threading + expiry fields.
    msg.thread_root_id = thread_root_id.map(Id::from);
    msg.sender_expires_at = sender_expires_at;
    msg.burn_on_read = burn_on_read;

    Ok(msg)
}

/// The standard SELECT column list for message queries.
///
/// All queries that use `row_to_message` must SELECT exactly these columns
/// in this order.  Centralised here to avoid column-order drift across the
/// five query sites (get, list, list_by_chat, list_by_chat_paged,
/// find_by_sender_msg_id).
const MESSAGE_COLUMNS: &str = "id, chat_id, sender_user_id, body, body_type, \
                                sent_at_peer, created_at, delivery_state, \
                                delivered_at, read_at, reply_to, sender_msg_id, \
                                deleted_at, deleted_for_all, edited_at, \
                                thread_root_id, sender_expires_at, burn_on_read";

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
            let blob_id: String = row.get(0)?;
            let msg_id: String = row.get(1)?;
            let filename: String = row.get(2)?;
            let content_type: String = row.get(3)?;
            let size: i64 = row.get(4)?;
            // Negative means DB corruption; reject rather than clamp.
            if size < 0 {
                return Err(rusqlite::Error::IntegralValueOutOfRange(4, size));
            }
            let sha256: String = row.get(5)?;
            Ok((
                msg_id,
                kith_core::make_attachment(blob_id, filename, content_type, size as u64, sha256),
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

/// Batch-load all mentions for a set of message IDs in a single SQL query.
fn load_mentions_for_messages(
    conn: &Connection,
    msg_ids: &[String],
) -> Result<HashMap<String, Vec<kith_core::Mention>>, KithError> {
    if msg_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = msg_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT message_id, contact_id, byte_offset, byte_length \
         FROM mentions WHERE message_id IN ({placeholders}) ORDER BY byte_offset"
    );
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(msg_ids.iter()), |row| {
            let msg_id: String = row.get(0)?;
            let contact_id: String = row.get(1)?;
            let offset: i64 = row.get(2)?;
            let length: i64 = row.get(3)?;
            if offset < 0 || length < 0 {
                return Err(rusqlite::Error::IntegralValueOutOfRange(
                    2,
                    offset.min(length),
                ));
            }
            Ok((
                msg_id,
                kith_core::make_mention(contact_id, offset as u64, length as u64),
            ))
        })
        .map_err(db_err)?;

    let mut mention_map: HashMap<String, Vec<kith_core::Mention>> = HashMap::new();
    for row in rows {
        let (msg_id, mention) = row.map_err(db_err)?;
        mention_map.entry(msg_id).or_default().push(mention);
    }

    Ok(mention_map)
}

/// Load the edit history for a single message from the `message_revisions` table.
///
/// Returns `None` if no revisions exist (message was never edited).
/// Returns `Some(vec)` with revisions ordered by `revision_index ASC`.
fn load_edit_history(
    conn: &Connection,
    message_id: &str,
) -> Result<Option<Vec<MessageRevision>>, KithError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT body, body_type, edited_at FROM message_revisions \
             WHERE message_id = ?1 ORDER BY revision_index ASC",
        )
        .map_err(db_err)?;

    let rows: Vec<MessageRevision> = stmt
        .query_map(params![message_id], |row| {
            let body: String = row.get(0)?;
            let body_type: String = row.get(1)?;
            let edited_at: String = row.get(2)?;

            Ok(make_message_revision(body, body_type, edited_at))
        })
        .map_err(db_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_err)?;

    if rows.is_empty() {
        Ok(None)
    } else {
        Ok(Some(rows))
    }
}

/// Batch-load edit history for a set of message IDs in a single SQL query.
fn load_edit_history_for_messages(
    conn: &Connection,
    msg_ids: &[String],
) -> Result<HashMap<String, Vec<MessageRevision>>, KithError> {
    if msg_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = msg_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT message_id, body, body_type, edited_at \
         FROM message_revisions WHERE message_id IN ({placeholders}) \
         ORDER BY message_id, revision_index ASC"
    );
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(msg_ids.iter()), |row| {
            let msg_id: String = row.get(0)?;
            let body: String = row.get(1)?;
            let body_type: String = row.get(2)?;
            let edited_at: String = row.get(3)?;
            Ok((msg_id, make_message_revision(body, body_type, edited_at)))
        })
        .map_err(db_err)?;

    let mut rev_map: HashMap<String, Vec<MessageRevision>> = HashMap::new();
    for row in rows {
        let (msg_id, rev) = row.map_err(db_err)?;
        rev_map.entry(msg_id).or_default().push(rev);
    }

    Ok(rev_map)
}

/// Batch-load all reactions for a set of message IDs in a single SQL query.
fn load_reactions_for_messages(
    conn: &Connection,
    msg_ids: &[String],
) -> Result<HashMap<String, HashMap<String, Reaction>>, KithError> {
    if msg_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = msg_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT message_id, sender_reaction_id, emoji, custom_emoji_id, sender_id, sent_at \
         FROM reactions WHERE message_id IN ({placeholders}) ORDER BY sent_at"
    );
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(msg_ids.iter()), |row| {
            let msg_id: String = row.get(0)?;
            let sender_reaction_id: String = row.get(1)?;
            let emoji: String = row.get(2)?;
            let custom_emoji_id: Option<String> = row.get(3)?;
            let sender_id_str: String = row.get(4)?;
            let sent_at: String = row.get(5)?;
            Ok((
                msg_id,
                sender_reaction_id,
                emoji,
                custom_emoji_id,
                sender_id_str,
                sent_at,
            ))
        })
        .map_err(db_err)?;

    let mut map: HashMap<String, HashMap<String, Reaction>> = HashMap::new();
    for row in rows {
        let (msg_id, sender_reaction_id, emoji, custom_emoji_id, sender_id_str, sent_at) =
            row.map_err(db_err)?;

        let mut json = serde_json::json!({
            "emoji": emoji,
            "senderId": sender_id_str,
            "sentAt": sent_at,
        });
        if let Some(ref cei) = custom_emoji_id {
            json["customEmojiId"] = serde_json::Value::String(cei.clone());
        }
        let reaction: Reaction = serde_json::from_value(json)
            .map_err(|e| KithError::Store(format!("failed to construct Reaction: {e}")))?;

        map.entry(msg_id)
            .or_default()
            .insert(sender_reaction_id, reaction);
    }

    Ok(map)
}

/// Batch-load all delivery receipts for a set of message IDs in a single SQL query.
fn load_delivery_receipts_for_messages(
    conn: &Connection,
    msg_ids: &[String],
) -> Result<HashMap<String, HashMap<String, DeliveryReceipt>>, KithError> {
    if msg_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = msg_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT message_id, recipient_id, delivered_at, device_delivered_at, read_at, read_disposition \
         FROM delivery_receipts WHERE message_id IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(msg_ids.iter()), |row| {
            let msg_id: String = row.get(0)?;
            let recipient_id: String = row.get(1)?;
            let delivered_at: Option<String> = row.get(2)?;
            let device_delivered_at: Option<String> = row.get(3)?;
            let read_at: Option<String> = row.get(4)?;
            let read_disposition: Option<String> = row.get(5)?;
            Ok((
                msg_id,
                recipient_id,
                delivered_at,
                device_delivered_at,
                read_at,
                read_disposition,
            ))
        })
        .map_err(db_err)?;

    let mut map: HashMap<String, HashMap<String, DeliveryReceipt>> = HashMap::new();
    for row in rows {
        let (msg_id, recipient_id, delivered_at, device_delivered_at, read_at, read_disposition) =
            row.map_err(db_err)?;

        let mut json = serde_json::json!({});
        if let Some(ref da) = delivered_at {
            json["deliveredAt"] = serde_json::Value::String(da.clone());
        }
        if let Some(ref dda) = device_delivered_at {
            json["deviceDeliveredAt"] = serde_json::Value::String(dda.clone());
        }
        if let Some(ref ra) = read_at {
            json["readAt"] = serde_json::Value::String(ra.clone());
        }
        if let Some(ref rd) = read_disposition {
            json["readDisposition"] = serde_json::Value::String(rd.clone());
        }
        let receipt: DeliveryReceipt = serde_json::from_value(json)
            .map_err(|e| KithError::Store(format!("failed to construct DeliveryReceipt: {e}")))?;

        map.entry(msg_id).or_default().insert(recipient_id, receipt);
    }

    Ok(map)
}

/// Batch-load all actions for a set of message IDs in a single SQL query.
fn load_actions_for_messages(
    conn: &Connection,
    msg_ids: &[String],
) -> Result<HashMap<String, Vec<MessageAction>>, KithError> {
    if msg_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = msg_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT message_id, action_type, uri, label, expires_at, metadata \
         FROM message_actions WHERE message_id IN ({placeholders}) ORDER BY action_index"
    );
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(msg_ids.iter()), |row| {
            let msg_id: String = row.get(0)?;
            let action_type: String = row.get(1)?;
            let uri: String = row.get(2)?;
            let label: Option<String> = row.get(3)?;
            let expires_at: Option<String> = row.get(4)?;
            let metadata_str: Option<String> = row.get(5)?;
            Ok((msg_id, action_type, uri, label, expires_at, metadata_str))
        })
        .map_err(db_err)?;

    let mut map: HashMap<String, Vec<MessageAction>> = HashMap::new();
    for row in rows {
        let (msg_id, action_type, uri, label, expires_at, metadata_str) = row.map_err(db_err)?;

        let mut json = serde_json::json!({
            "type": action_type,
            "uri": uri,
        });
        if let Some(ref l) = label {
            json["label"] = serde_json::Value::String(l.clone());
        }
        if let Some(ref ea) = expires_at {
            json["expiresAt"] = serde_json::Value::String(ea.clone());
        }
        if let Some(ref ms) = metadata_str {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(ms) {
                json["metadata"] = parsed;
            }
        }
        let action: MessageAction = serde_json::from_value(json)
            .map_err(|e| KithError::Store(format!("failed to construct MessageAction: {e}")))?;

        map.entry(msg_id).or_default().push(action);
    }

    Ok(map)
}

/// Batch-load all broadcast mentions for a set of message IDs in a single SQL query.
///
/// Returns a `HashMap` keyed by `message_id`. Each value is the ordered list
/// of broadcast mentions for that message.  Callers merge the map into their
/// message list by removing entries by ID.
///
/// When `msg_ids` is empty the function returns an empty map without touching
/// the database.
fn load_broadcast_mentions_for_messages(
    conn: &Connection,
    msg_ids: &[String],
) -> Result<HashMap<String, Vec<BroadcastMention>>, KithError> {
    if msg_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = msg_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT message_id, scope, byte_offset, byte_length \
         FROM broadcast_mentions WHERE message_id IN ({placeholders}) ORDER BY byte_offset"
    );
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(msg_ids.iter()), |row| {
            let msg_id: String = row.get(0)?;
            let scope: String = row.get(1)?;
            let offset: i64 = row.get(2)?;
            let length: i64 = row.get(3)?;
            if offset < 0 || length < 0 {
                return Err(rusqlite::Error::IntegralValueOutOfRange(
                    2,
                    offset.min(length),
                ));
            }
            Ok((
                msg_id,
                make_broadcast_mention(scope, offset as u64, length as u64),
            ))
        })
        .map_err(db_err)?;

    let mut bm_map: HashMap<String, Vec<BroadcastMention>> = HashMap::new();
    for row in rows {
        let (msg_id, bm) = row.map_err(db_err)?;
        bm_map.entry(msg_id).or_default().push(bm);
    }

    Ok(bm_map)
}

/// Insert broadcast mentions for a single message into the `extra` map
/// of each message so they appear as `broadcastMentions` in the wire JSON.
fn populate_broadcast_mentions(
    msgs: &mut [Message],
    bm_map: &mut HashMap<String, Vec<BroadcastMention>>,
) {
    for msg in msgs {
        if let Some(bms) = bm_map.remove(msg.id.as_ref()) {
            if !bms.is_empty() {
                if let Ok(val) = serde_json::to_value(&bms) {
                    msg.extra.insert("broadcastMentions".to_string(), val);
                }
            }
        }
    }
}

/// Populate reactions, delivery_receipts, actions, and broadcast mentions on a
/// slice of messages.
///
/// Batch-loads all four associated tables for the given message IDs and
/// merges the results into the messages.  This avoids N+1 queries.
fn populate_message_extras(conn: &Connection, messages: &mut [Message]) -> Result<(), KithError> {
    if messages.is_empty() {
        return Ok(());
    }

    let ids: Vec<String> = messages.iter().map(|m| m.id.as_ref().to_owned()).collect();

    let mut reaction_map = load_reactions_for_messages(conn, &ids)?;
    let mut receipt_map = load_delivery_receipts_for_messages(conn, &ids)?;
    let mut action_map = load_actions_for_messages(conn, &ids)?;
    let mut bm_map = load_broadcast_mentions_for_messages(conn, &ids)?;

    for msg in messages.iter_mut() {
        let id = msg.id.as_ref();
        if let Some(reactions) = reaction_map.remove(id) {
            msg.reactions = reactions;
        }
        if let Some(receipts) = receipt_map.remove(id) {
            msg.delivery_receipts = Some(receipts);
        }
        if let Some(actions) = action_map.remove(id) {
            msg.actions = actions;
        }
    }
    populate_broadcast_mentions(messages, &mut bm_map);

    Ok(())
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

    // ── Mentions ──────────────────────────────────────────────────────────

    /// Batch-insert mention rows for a given message.
    ///
    /// Callers are responsible for ensuring `message_id` references an existing
    /// message; a FK violation will return `KithError::Validation`.
    pub fn insert_mentions(
        &self,
        message_id: &str,
        mentions: &[kith_core::Mention],
    ) -> Result<(), KithError> {
        if mentions.is_empty() {
            return Ok(());
        }
        let mut stmt = self
            .conn
            .prepare_cached(
                "INSERT INTO mentions (message_id, contact_id, byte_offset, byte_length) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(db_err)?;
        for m in mentions {
            let offset = i64::try_from(m.offset)
                .map_err(|_| KithError::Store("mention offset overflow".into()))?;
            let length = i64::try_from(m.length)
                .map_err(|_| KithError::Store("mention length overflow".into()))?;
            stmt.execute(params![message_id, m.id.as_ref(), offset, length])
                .map_err(db_err)?;
        }
        Ok(())
    }

    /// Load all mentions for a single message, ordered by byte offset.
    pub fn load_mentions(&self, message_id: &str) -> Result<Vec<kith_core::Mention>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT contact_id, byte_offset, byte_length \
                 FROM mentions WHERE message_id = ?1 ORDER BY byte_offset",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![message_id], |row| {
                let contact_id: String = row.get(0)?;
                let offset: i64 = row.get(1)?;
                let length: i64 = row.get(2)?;
                if offset < 0 || length < 0 {
                    return Err(rusqlite::Error::IntegralValueOutOfRange(
                        1,
                        offset.min(length),
                    ));
                }
                Ok(kith_core::make_mention(
                    contact_id,
                    offset as u64,
                    length as u64,
                ))
            })
            .map_err(db_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
    }

    // ── Reactions ─────────────────────────────────────────────────────────

    /// Load all reactions for a single message.
    pub fn load_reactions(&self, message_id: &str) -> Result<HashMap<String, Reaction>, KithError> {
        let ids = vec![message_id.to_owned()];
        let mut map = load_reactions_for_messages(self.conn, &ids)?;
        Ok(map.remove(message_id).unwrap_or_default())
    }

    /// Insert a single reaction, advancing the message state counter.
    pub fn insert_reaction(
        &self,
        message_id: &str,
        sender_reaction_id: &str,
        reaction: &Reaction,
    ) -> Result<(), KithError> {
        if reaction.emoji.is_empty() {
            return Err(KithError::Validation("emoji must not be empty".into()));
        }
        if sender_reaction_id.is_empty() {
            return Err(KithError::Validation(
                "sender_reaction_id must not be empty".into(),
            ));
        }

        let sender_id_str = match &reaction.sender_id {
            SenderId::Owner => "self".to_string(),
            SenderId::Contact(id) => id.clone(),
            _ => "self".to_string(),
        };
        let custom_emoji_id: Option<String> = reaction
            .custom_emoji_id
            .as_ref()
            .map(|id| id.as_ref().to_owned());

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT OR REPLACE INTO reactions \
             (message_id, sender_reaction_id, emoji, custom_emoji_id, sender_id, sent_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                message_id,
                sender_reaction_id,
                reaction.emoji,
                custom_emoji_id,
                sender_id_str,
                reaction.sent_at.as_ref(),
            ],
        )
        .map_err(db_err)?;
        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.execute(
            "UPDATE messages SET state_version = ?1 WHERE id = ?2",
            params![version, message_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    /// Delete a single reaction by message_id + sender_reaction_id.
    ///
    /// Advances the message state counter if a row was actually deleted.
    /// Returns `Ok(())` even if the reaction did not exist (idempotent).
    pub fn delete_reaction(
        &self,
        message_id: &str,
        sender_reaction_id: &str,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "DELETE FROM reactions WHERE message_id = ?1 AND sender_reaction_id = ?2",
                params![message_id, sender_reaction_id],
            )
            .map_err(db_err)?;
        if affected == 0 {
            return Ok(());
        }
        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.execute(
            "UPDATE messages SET state_version = ?1 WHERE id = ?2",
            params![version, message_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    // ── Delivery Receipts ────────────────────────────────────────────────

    /// Load all delivery receipts for a single message.
    pub fn load_delivery_receipts(
        &self,
        message_id: &str,
    ) -> Result<HashMap<String, DeliveryReceipt>, KithError> {
        let ids = vec![message_id.to_owned()];
        let mut map = load_delivery_receipts_for_messages(self.conn, &ids)?;
        Ok(map.remove(message_id).unwrap_or_default())
    }

    /// Insert or update a delivery receipt for a specific recipient.
    pub fn upsert_delivery_receipt(
        &self,
        message_id: &str,
        recipient_id: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), KithError> {
        if recipient_id.is_empty() {
            return Err(KithError::Validation(
                "recipient_id must not be empty".into(),
            ));
        }

        if let Some(ref rd) = receipt.read_disposition {
            match rd {
                ReadDisposition::Displayed
                | ReadDisposition::Deleted
                | ReadDisposition::Processed => {}
                _ => {
                    return Err(KithError::Validation(format!(
                        "unknown read_disposition: {rd:?}"
                    )));
                }
            }
        }

        let delivered_at: Option<String> =
            receipt.delivered_at.as_ref().map(|d| d.as_ref().to_owned());
        let device_delivered_at: Option<String> = receipt
            .device_delivered_at
            .as_ref()
            .map(|d| d.as_ref().to_owned());
        let read_at: Option<String> = receipt.read_at.as_ref().map(|d| d.as_ref().to_owned());
        let read_disposition: Option<String> = receipt.read_disposition.as_ref().map(|rd| {
            serde_json::to_value(rd)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default()
        });

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT OR REPLACE INTO delivery_receipts \
             (message_id, recipient_id, delivered_at, device_delivered_at, read_at, read_disposition) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                message_id,
                recipient_id,
                delivered_at,
                device_delivered_at,
                read_at,
                read_disposition,
            ],
        )
        .map_err(db_err)?;
        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.execute(
            "UPDATE messages SET state_version = ?1 WHERE id = ?2",
            params![version, message_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    // ── Message Actions ──────────────────────────────────────────────────

    /// Load all actions for a single message, ordered by action_index.
    pub fn load_actions(&self, message_id: &str) -> Result<Vec<MessageAction>, KithError> {
        let ids = vec![message_id.to_owned()];
        let mut map = load_actions_for_messages(self.conn, &ids)?;
        Ok(map.remove(message_id).unwrap_or_default())
    }

    /// Insert a list of actions for a message (store-and-forward: no inspection).
    pub fn insert_actions(
        &self,
        message_id: &str,
        actions: &[MessageAction],
    ) -> Result<(), KithError> {
        if actions.is_empty() {
            return Ok(());
        }

        for (i, action) in actions.iter().enumerate() {
            if action.action_type.is_empty() {
                return Err(KithError::Validation(format!(
                    "actions[{i}].type must not be empty"
                )));
            }
            if action.uri.is_empty() {
                return Err(KithError::Validation(format!(
                    "actions[{i}].uri must not be empty"
                )));
            }
        }

        for (i, action) in actions.iter().enumerate() {
            let metadata_str: Option<String> = action
                .metadata
                .as_ref()
                .map(|m| serde_json::to_string(m).unwrap_or_default());
            let expires_at: Option<String> =
                action.expires_at.as_ref().map(|d| d.as_ref().to_owned());
            self.conn
                .execute(
                    "INSERT INTO message_actions \
                     (message_id, action_index, action_type, uri, label, expires_at, metadata) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        message_id,
                        i as i64,
                        action.action_type,
                        action.uri,
                        action.label,
                        expires_at,
                        metadata_str,
                    ],
                )
                .map_err(db_err)?;
        }

        Ok(())
    }

    // ── Insert ───────────────────────────────────────────────────────────

    /// Insert a new message row. Advances the message state counter and stores
    /// the resulting counter value in `state_version`.
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
        self.insert_full(
            id,
            chat_id,
            sender_user_id,
            body,
            body_type,
            sent_at_peer,
            created_at_unix,
            delivery_state,
            reply_to,
            sender_msg_id,
            None,
            None,
            false,
        )
    }

    /// Insert with all fields including threading and expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_full(
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
        thread_root_id: Option<&str>,
        sender_expires_at: Option<i64>,
        burn_on_read: bool,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        let state_str = delivery_state_str(delivery_state);
        tx.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, body_type, sent_at_peer, \
              created_at, state_version, created_at_version, delivery_state, reply_to, sender_msg_id, \
              thread_root_id, sender_expires_at, burn_on_read) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                thread_root_id,
                sender_expires_at,
                burn_on_read as i64,
            ],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────────────────

    /// Retrieve a message by its ID. Returns `None` if not found.
    pub fn get(&self, id: &str) -> Result<Option<Message>, KithError> {
        let sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE id = ?1");
        let mut stmt = self.conn.prepare_cached(&sql).map_err(db_err)?;

        let mut rows = stmt
            .query_map(params![id], row_to_message)
            .map_err(db_err)?;

        match rows.next() {
            None => Ok(None),
            Some(row) => {
                let mut msg = row.map_err(db_err)?;
                let msg_id_ref = msg.id.as_ref();
                // When deleted, suppress attachments (return empty vec).
                if msg.deleted_at.is_none() {
                    msg.attachments =
                        attachment::AttachmentStore::new(self.conn).list_by_message(msg_id_ref)?;
                }
                msg.mentions = self.load_mentions(msg_id_ref)?;
                msg.edit_history = load_edit_history(self.conn, msg_id_ref)?;
                self.populate_reply_counts(std::slice::from_mut(&mut msg))?;
                populate_message_extras(self.conn, std::slice::from_mut(&mut msg))?;
                Ok(Some(msg))
            }
        }
    }

    /// List all messages across all chats, ordered by created_at DESC, id DESC.
    pub fn list(&self) -> Result<Vec<Message>, KithError> {
        let sql =
            format!("SELECT {MESSAGE_COLUMNS} FROM messages ORDER BY created_at DESC, id DESC");
        let mut stmt = self.conn.prepare_cached(&sql).map_err(db_err)?;

        let rows = stmt.query_map([], row_to_message).map_err(db_err)?;

        let mut messages: Vec<Message> = rows
            .map(|r| r.map_err(db_err))
            .collect::<Result<Vec<_>, _>>()?;

        if messages.is_empty() {
            return Ok(messages);
        }

        let ids: Vec<String> = messages.iter().map(|m| m.id.as_ref().to_owned()).collect();
        let mut att_map = load_attachments_for_messages(self.conn, &ids)?;
        let mut mention_map = load_mentions_for_messages(self.conn, &ids)?;
        let mut rev_map = load_edit_history_for_messages(self.conn, &ids)?;
        for msg in &mut messages {
            let mid = msg.id.as_ref();
            if msg.deleted_at.is_none() {
                if let Some(atts) = att_map.remove(mid) {
                    msg.attachments = atts;
                }
            }
            if let Some(mentions) = mention_map.remove(mid) {
                msg.mentions = mentions;
            }
            if let Some(revs) = rev_map.remove(mid) {
                msg.edit_history = Some(revs);
            }
        }
        self.populate_reply_counts(&mut messages)?;
        populate_message_extras(self.conn, &mut messages)?;

        Ok(messages)
    }

    /// List messages for a chat, newest first, up to `limit` rows.
    pub fn list_by_chat(&self, chat_id: &str, limit: u32) -> Result<Vec<Message>, KithError> {
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages \
             WHERE chat_id = ?1 \
             ORDER BY created_at DESC, id DESC \
             LIMIT ?2"
        );
        let mut stmt = self.conn.prepare_cached(&sql).map_err(db_err)?;

        let rows = stmt
            .query_map(params![chat_id, limit], row_to_message)
            .map_err(db_err)?;

        let mut messages: Vec<Message> = rows
            .map(|r| r.map_err(db_err))
            .collect::<Result<Vec<_>, _>>()?;

        if messages.is_empty() {
            return Ok(messages);
        }

        let ids: Vec<String> = messages.iter().map(|m| m.id.as_ref().to_owned()).collect();
        let mut att_map = load_attachments_for_messages(self.conn, &ids)?;
        let mut mention_map = load_mentions_for_messages(self.conn, &ids)?;
        let mut rev_map = load_edit_history_for_messages(self.conn, &ids)?;
        for msg in &mut messages {
            let mid = msg.id.as_ref();
            if msg.deleted_at.is_none() {
                if let Some(atts) = att_map.remove(mid) {
                    msg.attachments = atts;
                }
            }
            if let Some(mentions) = mention_map.remove(mid) {
                msg.mentions = mentions;
            }
            if let Some(revs) = rev_map.remove(mid) {
                msg.edit_history = Some(revs);
            }
        }
        self.populate_reply_counts(&mut messages)?;
        populate_message_extras(self.conn, &mut messages)?;

        Ok(messages)
    }

    /// List messages for a chat with SQL-level pagination.
    pub fn list_by_chat_paged(
        &self,
        chat_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Message>, KithError> {
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages \
             WHERE chat_id = ?1 \
             ORDER BY created_at DESC, id DESC \
             LIMIT ?2 OFFSET ?3"
        );
        let mut stmt = self.conn.prepare_cached(&sql).map_err(db_err)?;

        let rows = stmt
            .query_map(params![chat_id, limit, offset], row_to_message)
            .map_err(db_err)?;

        let mut messages: Vec<Message> = rows
            .map(|r| r.map_err(db_err))
            .collect::<Result<Vec<_>, _>>()?;

        if messages.is_empty() {
            return Ok(messages);
        }

        let ids: Vec<String> = messages.iter().map(|m| m.id.as_ref().to_owned()).collect();
        let mut att_map = load_attachments_for_messages(self.conn, &ids)?;
        let mut mention_map = load_mentions_for_messages(self.conn, &ids)?;
        let mut rev_map = load_edit_history_for_messages(self.conn, &ids)?;
        for msg in &mut messages {
            let mid = msg.id.as_ref();
            if msg.deleted_at.is_none() {
                if let Some(atts) = att_map.remove(mid) {
                    msg.attachments = atts;
                }
            }
            if let Some(mentions) = mention_map.remove(mid) {
                msg.mentions = mentions;
            }
            if let Some(revs) = rev_map.remove(mid) {
                msg.edit_history = Some(revs);
            }
        }
        self.populate_reply_counts(&mut messages)?;
        populate_message_extras(self.conn, &mut messages)?;

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
        // Single query: look up the target message and count predecessors in one
        // round-trip, eliminating the separate existence check and the duplicate
        // correlated subquery.
        //
        // The outer SELECT drives off the target row (m).  If the message is absent
        // or belongs to a different chat, the FROM clause returns no rows and
        // .optional() yields None.  The subquery COUNT runs only once (the target
        // message's created_at is read from m, not from a repeated correlated
        // subquery).
        //
        // A message N is "before" M in newest-first order when:
        //   N.created_at > M.created_at, OR
        //   N.created_at = M.created_at AND N.id > M.id  (tie-break by id desc)
        let pos: Option<i64> = self
            .conn
            .query_row(
                "SELECT \
                    (SELECT COUNT(*) FROM messages \
                     WHERE chat_id = ?1 \
                     AND (created_at > m.created_at \
                          OR (created_at = m.created_at AND id > ?2))) \
                 FROM messages m \
                 WHERE m.id = ?2 AND m.chat_id = ?1",
                params![chat_id, msg_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err)?;

        Ok(pos.map(|p| p as u32))
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
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE chat_id = ?1 AND sender_msg_id = ?2"
        );
        let mut stmt = self.conn.prepare_cached(&sql).map_err(db_err)?;

        let mut rows = stmt
            .query_map(params![chat_id, sender_msg_id], row_to_message)
            .map_err(db_err)?;

        match rows.next() {
            None => Ok(None),
            Some(row) => {
                let mut msg = row.map_err(db_err)?;
                let msg_id_ref = msg.id.as_ref();
                if msg.deleted_at.is_none() {
                    msg.attachments =
                        attachment::AttachmentStore::new(self.conn).list_by_message(msg_id_ref)?;
                }
                msg.mentions = self.load_mentions(msg_id_ref)?;
                msg.edit_history = load_edit_history(self.conn, msg_id_ref)?;
                populate_message_extras(self.conn, std::slice::from_mut(&mut msg))?;
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
    /// Splits results into `added` (new messages) and `updated` (modified existing
    /// messages) per RFC 8620 §5.2. Uses `created_at_version` to distinguish the two.
    pub fn get_changes_since(&self, since_state: &str) -> Result<ChangesResult, KithError> {
        let since_version = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(JmapError::cannot_calculate_changes()))?;

        let current_state = self.get_state()?;
        let current_version: i64 = current_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .expect("get_state always returns s-<integer>");

        if since_version > current_version {
            return Err(KithError::Jmap(JmapError::cannot_calculate_changes()));
        }

        if since_version == current_version {
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
                "SELECT id, created_at_version FROM messages \
                 WHERE state_version > ?1 ORDER BY state_version",
            )
            .map_err(db_err)?;

        let rows: Vec<(String, i64)> = stmt
            .query_map(params![since_version], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut added = Vec::new();
        let mut updated = Vec::new();
        for (id, created_at) in rows {
            // is_create: message was first inserted after sinceState (RFC 8620 §5.2 created[]).
            if created_at > since_version {
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
        // Compute new_state from the last RETURNED row (index max_changes-1) before
        // truncating, so the client can resume from the right position.  For
        // max_changes=0 there is no returned row; fall back to current_state so the
        // client's next request is a no-op (RFC 8620 §5.6 prohibits max_changes=0,
        // so this branch is unreachable in practice — it's a robustness guard only).
        let new_state = if has_more {
            max_changes
                .filter(|&n| n > 0)
                .and_then(|n| rows.get(n - 1))
                .map(|(_, _, sv)| format!("s-{sv}"))
                .unwrap_or_else(|| current_state.clone())
        } else {
            current_state
        };
        if has_more {
            rows.truncate(max_changes.expect("has_more implies max_changes is Some"));
        }

        let result: Vec<(String, u64)> = rows.into_iter().map(|(id, idx, _)| (id, idx)).collect();
        Ok((result, has_more, new_state))
    }

    // ── Soft-delete + Edit history ──────────────────────────────────────

    /// Soft-delete a message: set `deleted_at`, clear body/attachments in the DB,
    /// and advance the state counter.
    pub fn soft_delete(
        &self,
        message_id: &str,
        deleted_for_all: bool,
        now_unix: i64,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        let existing: Option<Option<i64>> = tx
            .query_row(
                "SELECT deleted_at FROM messages WHERE id = ?1",
                params![message_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err)?;

        match existing {
            None => return Err(KithError::Store(format!("message not found: {message_id}"))),
            Some(Some(_)) => {
                return Ok(());
            }
            Some(None) => {}
        }

        let deleted_for_all_int: i64 = if deleted_for_all { 1 } else { 0 };

        tx.execute(
            "UPDATE messages SET deleted_at = ?1, deleted_for_all = ?2, body = '' \
             WHERE id = ?3",
            params![now_unix, deleted_for_all_int, message_id],
        )
        .map_err(db_err)?;

        tx.execute(
            "DELETE FROM attachments WHERE message_id = ?1",
            params![message_id],
        )
        .map_err(db_err)?;

        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.execute(
            "UPDATE messages SET state_version = ?1 WHERE id = ?2",
            params![version, message_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    /// Push a revision (prior body) to the `message_revisions` table.
    pub fn push_revision(
        &self,
        message_id: &str,
        old_body: &str,
        old_body_type: &str,
        edited_at_rfc3339: &str,
    ) -> Result<(), KithError> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id = ?1",
                params![message_id],
                |row| row.get::<_, i64>(0).map(|c| c > 0),
            )
            .map_err(db_err)?;
        if !exists {
            return Err(KithError::Store(format!("message not found: {message_id}")));
        }

        let next_idx: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(revision_index), -1) + 1 FROM message_revisions \
                 WHERE message_id = ?1",
                params![message_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;

        debug_assert!(
            next_idx >= 0,
            "revision_index must be non-negative, got {next_idx}"
        );

        self.conn
            .execute(
                "INSERT INTO message_revisions \
                 (message_id, revision_index, body, body_type, edited_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    message_id,
                    next_idx,
                    old_body,
                    old_body_type,
                    edited_at_rfc3339
                ],
            )
            .map_err(db_err)?;

        Ok(())
    }

    /// Update a message's body: push a revision of the old body, then update
    /// body/bodyType and set edited_at. Advances the state counter.
    pub fn update_body(
        &self,
        message_id: &str,
        new_body: &str,
        new_body_type: &str,
        now_unix: i64,
    ) -> Result<(), KithError> {
        let (old_body, old_body_type): (String, String) = self
            .conn
            .query_row(
                "SELECT body, body_type FROM messages WHERE id = ?1",
                params![message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db_err)?
            .ok_or_else(|| KithError::Store(format!("message not found: {message_id}")))?;

        let deleted: Option<i64> = self
            .conn
            .query_row(
                "SELECT deleted_at FROM messages WHERE id = ?1",
                params![message_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        if deleted.is_some() {
            return Err(KithError::Validation(
                "cannot edit a deleted message".to_string(),
            ));
        }

        let edited_at_rfc3339 = crate::util::unix_secs_to_rfc3339(now_unix.max(0) as u64);

        self.push_revision(message_id, &old_body, &old_body_type, &edited_at_rfc3339)?;

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "UPDATE messages SET body = ?1, body_type = ?2, edited_at = ?3 \
             WHERE id = ?4",
            params![new_body, new_body_type, now_unix, message_id],
        )
        .map_err(db_err)?;
        let version = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.execute(
            "UPDATE messages SET state_version = ?1 WHERE id = ?2",
            params![version, message_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit(format!("s-{version}"));
        Ok(())
    }

    // ── Expiry ───────────────────────────────────────────────────────────

    /// Delete all messages whose `sender_expires_at` is in the past.
    ///
    /// Returns the number of messages deleted.
    pub fn delete_expired(&self, now_unix: i64) -> Result<u64, KithError> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM messages WHERE sender_expires_at IS NOT NULL AND sender_expires_at <= ?1",
                params![now_unix],
            )
            .map_err(db_err)?;
        if deleted > 0 {
            let tx = self.conn.unchecked_transaction().map_err(db_err)?;
            let version = crate::advance_state_counter_in_tx(&tx, "message")?;
            tx.commit().map_err(db_err)?;
            self.emit(format!("s-{version}"));
        }
        Ok(deleted as u64)
    }

    // ── Reply counts ─────────────────────────────────────────────────────

    /// Populate `reply_count` and `unread_reply_count` on each message that
    /// has replies (i.e., other messages reference it via `reply_to`).
    fn populate_reply_counts(&self, messages: &mut [Message]) -> Result<(), KithError> {
        if messages.is_empty() {
            return Ok(());
        }
        let ids: Vec<String> = messages.iter().map(|m| m.id.as_ref().to_owned()).collect();
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT reply_to, \
                    COUNT(*) AS total, \
                    SUM(CASE WHEN read_at IS NULL THEN 1 ELSE 0 END) AS unread \
             FROM messages \
             WHERE reply_to IN ({placeholders}) \
             GROUP BY reply_to"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(ids.iter()), |row| {
                let parent_id: String = row.get(0)?;
                let total: u64 = row.get(1)?;
                let unread: u64 = row.get(2)?;
                Ok((parent_id, total, unread))
            })
            .map_err(db_err)?;

        let mut counts: HashMap<String, (u64, u64)> = HashMap::new();
        for row in rows {
            let (parent_id, total, unread) = row.map_err(db_err)?;
            counts.insert(parent_id, (total, unread));
        }

        for msg in messages {
            if let Some(&(total, unread)) = counts.get(msg.id.as_ref()) {
                msg.reply_count = Some(total);
                msg.unread_reply_count = Some(unread);
            }
        }

        Ok(())
    }

    // ── State ────────────────────────────────────────────────────────────

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
    /// Wrapped in a transaction so that the counter read and write are atomic.
    /// Delegates to `advance_state_counter_in_tx` so the i64 overflow guard
    /// fires here too, matching production paths.
    fn advance_state_counter(&self) -> Result<i64, KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let v = crate::advance_state_counter_in_tx(&tx, "message")?;
        tx.commit().map_err(db_err)?;
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
        assert_eq!(msg.sender_id, SenderId::Contact("user-abc".to_string()));
        assert_eq!(msg.body, "Hello, world!");
        assert_eq!(msg.body_type, "text/plain");
        assert_eq!(msg.sent_at.as_ref(), "2026-04-18T12:00:00Z");
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
        let read_at_after_first: String = msg_after.read_at.as_ref().unwrap().as_ref().to_owned();

        // Second call with an earlier timestamp must be idempotent (Ok) and must NOT
        // overwrite the stored value with the smaller timestamp.
        ms.update_read_at("msg-ra", 1000)
            .expect("second call with earlier ts must return Ok");

        let msg_final = ms.get("msg-ra").expect("get").expect("exists");
        assert_eq!(
            msg_final.read_at.as_ref().map(|d| d.as_ref()),
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
        let read_at_first: String = msg_after_first
            .read_at
            .as_ref()
            .unwrap()
            .as_ref()
            .to_owned();

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
            msg_final.read_at.as_ref().map(|d| d.as_ref()),
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
        // Oracle: after update_delivery_state, get_changes_since(state_after_insert)
        // must include the message ID in `updated` (not `added`) — the message existed
        // before sinceState, so RFC 8620 §5.2 requires it in updated[], not created[].
        // The state_version is advanced so clients learn about the delivery state change.
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
            !changes.added.contains(&"msg-us1".to_string()),
            "update_delivery_state must NOT put message in added[] — it existed before sinceState; \
             added={:?}",
            changes.added
        );
        assert!(
            changes.updated.contains(&"msg-us1".to_string()),
            "update_delivery_state must advance state_version so the message appears \
             in updated[] (RFC 8620 §5.2); updated={:?}",
            changes.updated
        );
    }

    #[test]
    fn update_read_at_appears_in_get_changes_since() {
        // Oracle: after update_read_at, get_changes_since(state_after_insert) must
        // include the message ID in `updated` (not `added`) — the message existed
        // before sinceState, so RFC 8620 §5.2 requires it in updated[], not created[].
        // Verifies state_version is written on the messages row when read receipt is recorded.
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
            !changes.added.contains(&"msg-us2".to_string()),
            "update_read_at must NOT put message in added[] — it existed before sinceState; \
             added={:?}",
            changes.added
        );
        assert!(
            changes.updated.contains(&"msg-us2".to_string()),
            "update_read_at must advance state_version so the message appears \
             in updated[] (RFC 8620 §5.2); updated={:?}",
            changes.updated
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
            kith_core::make_attachment(
                blob_id_1.clone(),
                "first.txt",
                "text/plain",
                42,
                "b".repeat(64),
            ),
            kith_core::make_attachment(
                blob_id_2.clone(),
                "second.pdf",
                "application/pdf",
                100,
                "d".repeat(64),
            ),
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
                &[],
                None,
                None,
                false,
                &[],
            )
            .expect("insert_message_with_attachments");

        let ms = MessageStore::new(&store.conn, None);
        let msg = ms.get("msg-att1").expect("get").expect("must exist");

        assert_eq!(msg.attachments.len(), 2, "must return both attachments");
        assert_eq!(msg.attachments[0].blob_id.as_ref(), blob_id_1);
        assert_eq!(msg.attachments[0].filename, "first.txt");
        assert_eq!(msg.attachments[1].blob_id.as_ref(), blob_id_2);
    }

    #[test]
    fn message_list_by_chat_returns_attachments() {
        // Oracle: attachments table contents match what was inserted.
        // list_by_chat must populate attachments on each returned Message.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-att2");

        // First message: one attachment.
        let att =
            kith_core::make_attachment("e".repeat(64), "doc.txt", "text/plain", 7, "f".repeat(64));
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
                &[],
                None,
                None,
                false,
                &[],
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
                &[],
                None,
                None,
                false,
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
        assert_eq!(msg_with_att.attachments[0].blob_id.as_ref(), "e".repeat(64));
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

    #[test]
    fn message_changes_update_goes_to_updated_not_added() {
        // Oracle: a message that existed before sinceState and was then modified must
        // appear in updated[], NOT added[].  get_changes_since previously put all
        // IDs in added[] regardless of create/update status (KITH-s8kd.21).
        //
        // Sequence:
        //   1. Insert msg-upd → state s-1
        //   2. Record s-1 as sinceState
        //   3. Call update_delivery_state (modifies the message) → state s-2
        //   4. get_changes_since("s-1") must have msg-upd in updated[], NOT added[].
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-mu");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-upd",
            "chat-mu",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Pending,
            None,
            "msg-upd",
        )
        .expect("insert");

        let since = ms.get_state().expect("state after insert");

        // Touch the message so it appears in the next changes window.
        ms.update_delivery_state("msg-upd", &DeliveryState::Delivered, Some(2000))
            .expect("update delivery state");

        let result = ms.get_changes_since(&since).expect("get_changes_since");
        assert!(
            !result.added.contains(&"msg-upd".to_string()),
            "updated message must NOT appear in added[]; added={:?}",
            result.added
        );
        assert!(
            result.updated.contains(&"msg-upd".to_string()),
            "updated message must appear in updated[]; updated={:?}",
            result.updated
        );
    }

    // -----------------------------------------------------------------------
    // Broadcast mentions tests
    // -----------------------------------------------------------------------

    #[test]
    fn broadcast_mentions_store_round_trip() {
        // Oracle: broadcast mentions stored via insert_message_with_attachments
        // must be retrievable via get() in the message's extra field.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-bm1");

        let bms = vec![
            kith_core::make_broadcast_mention("everyone", 0, 9),
            kith_core::make_broadcast_mention("here", 15, 5),
        ];

        store
            .insert_message_with_attachments(
                "msg-bm1",
                "chat-bm1",
                "user-a",
                "Hey @everyone and @here!",
                "text/plain",
                None,
                1000,
                &DeliveryState::Received,
                None,
                "msg-bm1",
                &[],
                &[],
                None,
                None,
                false,
                &bms,
            )
            .expect("insert with broadcast mentions");

        let ms = MessageStore::new(&store.conn, None);
        let msg = ms.get("msg-bm1").expect("get").expect("must exist");

        // broadcastMentions must appear in the extra map.
        let bm_val = msg
            .extra
            .get("broadcastMentions")
            .expect("broadcastMentions must be in extra");
        let bm_arr = bm_val.as_array().expect("must be an array");
        assert_eq!(bm_arr.len(), 2);
        assert_eq!(bm_arr[0]["scope"], "everyone");
        assert_eq!(bm_arr[0]["offset"], 0);
        assert_eq!(bm_arr[0]["length"], 9);
        assert_eq!(bm_arr[1]["scope"], "here");
        assert_eq!(bm_arr[1]["offset"], 15);
        assert_eq!(bm_arr[1]["length"], 5);
    }

    #[test]
    fn broadcast_mentions_empty_not_in_extra() {
        // Oracle: when no broadcast mentions are stored, the extra map must
        // NOT contain a broadcastMentions key.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-bm2");

        store
            .insert_message_with_attachments(
                "msg-bm2",
                "chat-bm2",
                "user-a",
                "no mentions here",
                "text/plain",
                None,
                1000,
                &DeliveryState::Received,
                None,
                "msg-bm2",
                &[],
                &[],
                None,
                None,
                false,
                &[],
            )
            .expect("insert without broadcast mentions");

        let ms = MessageStore::new(&store.conn, None);
        let msg = ms.get("msg-bm2").expect("get").expect("must exist");
        assert!(
            msg.extra.get("broadcastMentions").is_none(),
            "broadcastMentions must not appear in extra when empty"
        );
    }

    #[test]
    fn broadcast_mentions_batch_load_in_list() {
        // Oracle: list_by_chat must populate broadcastMentions for all messages
        // via the batch loader.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-bm3");

        let bms1 = vec![kith_core::make_broadcast_mention("admins", 0, 7)];
        store
            .insert_message_with_attachments(
                "msg-bm3a",
                "chat-bm3",
                "user-a",
                "@admins alert",
                "text/plain",
                None,
                100,
                &DeliveryState::Received,
                None,
                "msg-bm3a",
                &[],
                &[],
                None,
                None,
                false,
                &bms1,
            )
            .expect("insert msg with broadcast mention");

        store
            .insert_message_with_attachments(
                "msg-bm3b",
                "chat-bm3",
                "user-a",
                "no mentions",
                "text/plain",
                None,
                200,
                &DeliveryState::Received,
                None,
                "msg-bm3b",
                &[],
                &[],
                None,
                None,
                false,
                &[],
            )
            .expect("insert msg without broadcast mention");

        let ms = MessageStore::new(&store.conn, None);
        let msgs = ms.list_by_chat("chat-bm3", 10).expect("list");
        assert_eq!(msgs.len(), 2);

        let msg_with = msgs.iter().find(|m| m.id == "msg-bm3a").expect("msg-bm3a");
        let msg_without = msgs.iter().find(|m| m.id == "msg-bm3b").expect("msg-bm3b");

        assert!(
            msg_with.extra.get("broadcastMentions").is_some(),
            "message with broadcast mentions must have them in extra"
        );
        assert!(
            msg_without.extra.get("broadcastMentions").is_none(),
            "message without broadcast mentions must not have them in extra"
        );
    }

    #[test]
    fn broadcast_mentions_cascade_delete() {
        // Oracle: deleting a message must cascade-delete its broadcast mentions.
        // This tests the ON DELETE CASCADE FK constraint.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-bm4");

        let bms = vec![kith_core::make_broadcast_mention("everyone", 0, 9)];
        store
            .insert_message_with_attachments(
                "msg-bm4",
                "chat-bm4",
                "user-a",
                "@everyone!",
                "text/plain",
                None,
                1000,
                &DeliveryState::Received,
                None,
                "msg-bm4",
                &[],
                &[],
                None,
                None,
                false,
                &bms,
            )
            .expect("insert");

        // Verify broadcast mention exists.
        let count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM broadcast_mentions WHERE message_id = 'msg-bm4'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "broadcast mention must exist before delete");

        // Delete the message.
        store
            .conn
            .execute("DELETE FROM messages WHERE id = 'msg-bm4'", [])
            .unwrap();

        // Broadcast mention must be cascade-deleted.
        let count_after: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM broadcast_mentions WHERE message_id = 'msg-bm4'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count_after, 0,
            "broadcast mention must be cascade-deleted with message"
        );
    }

    // -----------------------------------------------------------------------
    // Reactions tests
    // -----------------------------------------------------------------------

    /// Helper: construct a Reaction via serde (type is #[non_exhaustive]).
    fn make_reaction(emoji: &str, sender_id: &str, sent_at: &str) -> Reaction {
        serde_json::from_value(serde_json::json!({
            "emoji": emoji,
            "senderId": sender_id,
            "sentAt": sent_at,
        }))
        .expect("valid reaction")
    }

    /// Helper: construct a Reaction with a custom emoji ID.
    fn make_reaction_with_custom(
        emoji: &str,
        sender_id: &str,
        sent_at: &str,
        custom_emoji_id: &str,
    ) -> Reaction {
        serde_json::from_value(serde_json::json!({
            "emoji": emoji,
            "senderId": sender_id,
            "sentAt": sent_at,
            "customEmojiId": custom_emoji_id,
        }))
        .expect("valid reaction with custom emoji")
    }

    /// Helper: construct a DeliveryReceipt via serde (type is #[non_exhaustive]).
    fn make_receipt(delivered_at: Option<&str>) -> DeliveryReceipt {
        let mut json = serde_json::json!({});
        if let Some(da) = delivered_at {
            json["deliveredAt"] = serde_json::Value::String(da.to_string());
        }
        serde_json::from_value(json).expect("valid receipt")
    }

    /// Helper: construct a DeliveryReceipt with read_at and read_disposition.
    fn make_receipt_full(
        delivered_at: Option<&str>,
        read_at: Option<&str>,
        read_disposition: Option<&str>,
    ) -> DeliveryReceipt {
        let mut json = serde_json::json!({});
        if let Some(da) = delivered_at {
            json["deliveredAt"] = serde_json::Value::String(da.to_string());
        }
        if let Some(ra) = read_at {
            json["readAt"] = serde_json::Value::String(ra.to_string());
        }
        if let Some(rd) = read_disposition {
            json["readDisposition"] = serde_json::Value::String(rd.to_string());
        }
        serde_json::from_value(json).expect("valid receipt")
    }

    /// Helper: construct a MessageAction via serde (type is #[non_exhaustive]).
    fn make_action(action_type: &str, uri: &str, label: Option<&str>) -> MessageAction {
        let mut json = serde_json::json!({
            "type": action_type,
            "uri": uri,
        });
        if let Some(l) = label {
            json["label"] = serde_json::Value::String(l.to_string());
        }
        serde_json::from_value(json).expect("valid action")
    }

    /// Helper: insert a test message and return the MessageStore.
    fn setup_with_message<'a>(
        store: &'a Store,
        chat_id: &str,
        msg_id: &str,
    ) -> MessageStore<'a> {
        insert_chat(&store.conn, chat_id);
        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            msg_id,
            chat_id,
            "user-sender",
            "test body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            msg_id,
        )
        .expect("insert test message");
        ms
    }

    #[test]
    fn reaction_insert_and_load_round_trip() {
        // Oracle: insert a reaction, load it, verify emoji/sender/sent_at match input.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx1", "msg-rx1");

        let reaction = make_reaction("\u{1F44D}", "user-bob", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx1", "rxn-001", &reaction)
            .expect("insert_reaction");

        let reactions = ms.load_reactions("msg-rx1").expect("load_reactions");
        assert_eq!(reactions.len(), 1);
        let loaded = reactions.get("rxn-001").expect("rxn-001 must exist");
        assert_eq!(loaded.emoji, "\u{1F44D}");
        assert_eq!(
            loaded.sender_id,
            SenderId::Contact("user-bob".to_string())
        );
        assert_eq!(loaded.sent_at.as_ref(), "2026-06-13T12:00:00Z");
    }

    #[test]
    fn reaction_with_custom_emoji_id() {
        // Oracle: custom_emoji_id round-trips through insert/load.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx2", "msg-rx2");

        let reaction = make_reaction_with_custom(
            ":party_parrot:",
            "user-carol",
            "2026-06-13T12:01:00Z",
            "custom-emoji-42",
        );
        ms.insert_reaction("msg-rx2", "rxn-002", &reaction)
            .expect("insert_reaction");

        let reactions = ms.load_reactions("msg-rx2").expect("load_reactions");
        let loaded = reactions.get("rxn-002").expect("rxn-002 must exist");
        assert_eq!(loaded.emoji, ":party_parrot:");
        assert!(
            loaded.custom_emoji_id.is_some(),
            "custom_emoji_id must be preserved"
        );
        assert_eq!(loaded.custom_emoji_id.as_ref().unwrap().as_ref(), "custom-emoji-42");
    }

    #[test]
    fn reaction_replace_existing_same_sender_reaction_id() {
        // Oracle: INSERT OR REPLACE on same (message_id, sender_reaction_id)
        // must overwrite the previous reaction.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx3", "msg-rx3");

        let r1 = make_reaction("\u{1F44D}", "user-bob", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx3", "rxn-003", &r1)
            .expect("insert first");

        let r2 = make_reaction("\u{2764}", "user-bob", "2026-06-13T12:01:00Z");
        ms.insert_reaction("msg-rx3", "rxn-003", &r2)
            .expect("insert replacement");

        let reactions = ms.load_reactions("msg-rx3").expect("load");
        assert_eq!(reactions.len(), 1, "should still have exactly one reaction");
        let loaded = reactions.get("rxn-003").expect("rxn-003");
        assert_eq!(loaded.emoji, "\u{2764}", "emoji must be the replacement value");
    }

    #[test]
    fn reaction_multiple_from_different_senders() {
        // Oracle: different sender_reaction_ids are independent entries.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx4", "msg-rx4");

        let r1 = make_reaction("\u{1F44D}", "user-alice", "2026-06-13T12:00:00Z");
        let r2 = make_reaction("\u{1F602}", "user-bob", "2026-06-13T12:00:01Z");
        let r3 = make_reaction("\u{2764}", "user-carol", "2026-06-13T12:00:02Z");
        ms.insert_reaction("msg-rx4", "rxn-a", &r1).expect("insert r1");
        ms.insert_reaction("msg-rx4", "rxn-b", &r2).expect("insert r2");
        ms.insert_reaction("msg-rx4", "rxn-c", &r3).expect("insert r3");

        let reactions = ms.load_reactions("msg-rx4").expect("load");
        assert_eq!(reactions.len(), 3);
        assert!(reactions.contains_key("rxn-a"));
        assert!(reactions.contains_key("rxn-b"));
        assert!(reactions.contains_key("rxn-c"));
    }

    #[test]
    fn reaction_delete_removes_it() {
        // Oracle: after delete_reaction, load_reactions must not contain the removed key.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx5", "msg-rx5");

        let r = make_reaction("\u{1F44D}", "user-bob", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx5", "rxn-del", &r).expect("insert");
        assert_eq!(ms.load_reactions("msg-rx5").expect("load").len(), 1);

        ms.delete_reaction("msg-rx5", "rxn-del").expect("delete");
        let reactions = ms.load_reactions("msg-rx5").expect("load after delete");
        assert!(reactions.is_empty(), "reaction must be gone after delete");
    }

    #[test]
    fn reaction_delete_idempotent() {
        // Oracle: deleting a non-existent reaction must return Ok(()) without error.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx6", "msg-rx6");

        let result = ms.delete_reaction("msg-rx6", "no-such-rxn");
        assert!(result.is_ok(), "delete_reaction on missing must be idempotent");

        // Second delete on same key also OK.
        let r = make_reaction("\u{1F44D}", "user-bob", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx6", "rxn-once", &r).expect("insert");
        ms.delete_reaction("msg-rx6", "rxn-once").expect("first delete");
        let result2 = ms.delete_reaction("msg-rx6", "rxn-once");
        assert!(result2.is_ok(), "second delete must also be Ok");
    }

    #[test]
    fn reaction_load_empty_for_no_reactions() {
        // Oracle: a message with no reactions must return an empty HashMap.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx7", "msg-rx7");

        let reactions = ms.load_reactions("msg-rx7").expect("load");
        assert!(reactions.is_empty(), "no reactions must yield empty map");
    }

    #[test]
    fn reaction_batch_load_for_messages() {
        // Oracle: load_reactions_for_messages returns reactions keyed by message_id.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-rx8");
        let ms = MessageStore::new(&store.conn, None);

        ms.insert("msg-rx8a", "chat-rx8", "user-a", "a", "text/plain", None, 100, &DeliveryState::Received, None, "msg-rx8a").expect("insert a");
        ms.insert("msg-rx8b", "chat-rx8", "user-a", "b", "text/plain", None, 200, &DeliveryState::Received, None, "msg-rx8b").expect("insert b");

        let r1 = make_reaction("\u{1F44D}", "user-x", "2026-06-13T12:00:00Z");
        let r2 = make_reaction("\u{2764}", "user-y", "2026-06-13T12:00:01Z");
        ms.insert_reaction("msg-rx8a", "rxn-1", &r1).expect("insert r1");
        ms.insert_reaction("msg-rx8b", "rxn-2", &r2).expect("insert r2");

        let ids = vec!["msg-rx8a".to_string(), "msg-rx8b".to_string()];
        let map = load_reactions_for_messages(&store.conn, &ids).expect("batch load");
        assert_eq!(map.len(), 2);
        assert!(map.get("msg-rx8a").unwrap().contains_key("rxn-1"));
        assert!(map.get("msg-rx8b").unwrap().contains_key("rxn-2"));
    }

    #[test]
    fn reaction_insert_advances_state_counter() {
        // Oracle: state counter before insert_reaction must be strictly less
        // than state counter after.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx9", "msg-rx9");

        let state_before = ms.get_state().expect("state before");
        let r = make_reaction("\u{1F44D}", "user-bob", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx9", "rxn-sc", &r).expect("insert");
        let state_after = ms.get_state().expect("state after");

        assert_ne!(state_before, state_after, "state counter must advance on insert_reaction");
    }

    #[test]
    fn reaction_delete_advances_state_counter() {
        // Oracle: when delete_reaction actually removes a row, the state counter
        // must advance. When it does not remove a row (idempotent), counter must not.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx10", "msg-rx10");

        let r = make_reaction("\u{1F44D}", "user-bob", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx10", "rxn-dsc", &r).expect("insert");
        let state_before_delete = ms.get_state().expect("state before delete");

        ms.delete_reaction("msg-rx10", "rxn-dsc").expect("delete");
        let state_after_delete = ms.get_state().expect("state after delete");
        assert_ne!(
            state_before_delete, state_after_delete,
            "state counter must advance when delete actually removes a row"
        );

        // Idempotent delete must NOT advance counter.
        let state_before_noop = ms.get_state().expect("state before noop");
        ms.delete_reaction("msg-rx10", "rxn-dsc").expect("noop delete");
        let state_after_noop = ms.get_state().expect("state after noop");
        assert_eq!(
            state_before_noop, state_after_noop,
            "state counter must not advance on noop delete"
        );
    }

    #[test]
    fn reaction_empty_emoji_rejected() {
        // Oracle: insert_reaction must reject empty emoji with a Validation error.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx11", "msg-rx11");

        let reaction: Reaction = serde_json::from_value(serde_json::json!({
            "emoji": "",
            "senderId": "user-bob",
            "sentAt": "2026-06-13T12:00:00Z",
        }))
        .expect("construct reaction");
        let result = ms.insert_reaction("msg-rx11", "rxn-empty", &reaction);
        assert!(result.is_err(), "empty emoji must be rejected");
    }

    #[test]
    fn reaction_appears_in_get_via_populate_message_extras() {
        // Oracle: get() calls populate_message_extras which must surface reactions.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx12", "msg-rx12");

        let r = make_reaction("\u{1F680}", "user-dan", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx12", "rxn-get", &r).expect("insert");

        let msg = ms.get("msg-rx12").expect("get").expect("must exist");
        assert_eq!(msg.reactions.len(), 1, "reactions must be populated by get()");
        let loaded = msg.reactions.get("rxn-get").expect("rxn-get key");
        assert_eq!(loaded.emoji, "\u{1F680}");
    }

    #[test]
    fn reaction_cascade_deletes_when_message_deleted() {
        // Oracle: ON DELETE CASCADE on reactions FK means deleting the message
        // must remove its reactions from the reactions table.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-rx13", "msg-rx13");

        let r = make_reaction("\u{1F44D}", "user-bob", "2026-06-13T12:00:00Z");
        ms.insert_reaction("msg-rx13", "rxn-casc", &r).expect("insert");

        // Verify reaction exists.
        let count: i64 = store.conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE message_id = 'msg-rx13'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "reaction must exist before message delete");

        // Hard-delete the message row.
        store.conn
            .execute("DELETE FROM messages WHERE id = 'msg-rx13'", [])
            .unwrap();

        let count_after: i64 = store.conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE message_id = 'msg-rx13'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count_after, 0, "reaction must be cascade-deleted with message");
    }

    // -----------------------------------------------------------------------
    // Delivery receipts tests
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_upsert_and_load_round_trip() {
        // Oracle: upsert a delivery receipt, load it, verify delivered_at matches.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr1", "msg-dr1");

        let receipt = make_receipt(Some("2026-06-13T14:00:00Z"));
        ms.upsert_delivery_receipt("msg-dr1", "recipient-alice", &receipt)
            .expect("upsert");

        let receipts = ms.load_delivery_receipts("msg-dr1").expect("load");
        assert_eq!(receipts.len(), 1);
        let loaded = receipts.get("recipient-alice").expect("recipient-alice");
        assert_eq!(
            loaded.delivered_at.as_ref().map(|d| d.as_ref()),
            Some("2026-06-13T14:00:00Z")
        );
    }

    #[test]
    fn receipt_upsert_with_read_at_and_disposition() {
        // Oracle: all optional fields round-trip through upsert/load.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr2", "msg-dr2");

        let receipt = make_receipt_full(
            Some("2026-06-13T14:00:00Z"),
            Some("2026-06-13T14:05:00Z"),
            Some("displayed"),
        );
        ms.upsert_delivery_receipt("msg-dr2", "recipient-bob", &receipt)
            .expect("upsert");

        let receipts = ms.load_delivery_receipts("msg-dr2").expect("load");
        let loaded = receipts.get("recipient-bob").expect("recipient-bob");
        assert_eq!(
            loaded.delivered_at.as_ref().map(|d| d.as_ref()),
            Some("2026-06-13T14:00:00Z")
        );
        assert_eq!(
            loaded.read_at.as_ref().map(|d| d.as_ref()),
            Some("2026-06-13T14:05:00Z")
        );
        assert_eq!(loaded.read_disposition, Some(ReadDisposition::Displayed));
    }

    #[test]
    fn receipt_upsert_updates_existing() {
        // Oracle: upserting the same recipient_id must overwrite the previous receipt.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr3", "msg-dr3");

        let r1 = make_receipt(Some("2026-06-13T14:00:00Z"));
        ms.upsert_delivery_receipt("msg-dr3", "recipient-carol", &r1)
            .expect("first upsert");

        let r2 = make_receipt_full(
            Some("2026-06-13T14:00:00Z"),
            Some("2026-06-13T14:10:00Z"),
            Some("displayed"),
        );
        ms.upsert_delivery_receipt("msg-dr3", "recipient-carol", &r2)
            .expect("second upsert");

        let receipts = ms.load_delivery_receipts("msg-dr3").expect("load");
        assert_eq!(receipts.len(), 1, "still one receipt for same recipient");
        let loaded = receipts.get("recipient-carol").expect("recipient-carol");
        assert!(
            loaded.read_at.is_some(),
            "read_at must be set after second upsert"
        );
    }

    #[test]
    fn receipt_upsert_idempotent() {
        // Oracle: upserting the same data twice must succeed without error.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr4", "msg-dr4");

        let receipt = make_receipt(Some("2026-06-13T14:00:00Z"));
        ms.upsert_delivery_receipt("msg-dr4", "recipient-dan", &receipt)
            .expect("first upsert");
        let result = ms.upsert_delivery_receipt("msg-dr4", "recipient-dan", &receipt);
        assert!(result.is_ok(), "identical upsert must succeed");
    }

    #[test]
    fn receipt_load_empty_for_no_receipts() {
        // Oracle: a message with no delivery receipts must return an empty HashMap.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr5", "msg-dr5");

        let receipts = ms.load_delivery_receipts("msg-dr5").expect("load");
        assert!(receipts.is_empty(), "no receipts must yield empty map");
    }

    #[test]
    fn receipt_batch_load_across_messages() {
        // Oracle: load_delivery_receipts_for_messages returns receipts keyed by message_id.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dr6");
        let ms = MessageStore::new(&store.conn, None);

        ms.insert("msg-dr6a", "chat-dr6", "user-a", "a", "text/plain", None, 100, &DeliveryState::Received, None, "msg-dr6a").expect("insert a");
        ms.insert("msg-dr6b", "chat-dr6", "user-a", "b", "text/plain", None, 200, &DeliveryState::Received, None, "msg-dr6b").expect("insert b");

        let r1 = make_receipt(Some("2026-06-13T14:00:00Z"));
        let r2 = make_receipt(Some("2026-06-13T14:01:00Z"));
        ms.upsert_delivery_receipt("msg-dr6a", "alice", &r1).expect("upsert r1");
        ms.upsert_delivery_receipt("msg-dr6b", "bob", &r2).expect("upsert r2");

        let ids = vec!["msg-dr6a".to_string(), "msg-dr6b".to_string()];
        let map = load_delivery_receipts_for_messages(&store.conn, &ids).expect("batch load");
        assert_eq!(map.len(), 2);
        assert!(map.get("msg-dr6a").unwrap().contains_key("alice"));
        assert!(map.get("msg-dr6b").unwrap().contains_key("bob"));
    }

    #[test]
    fn receipt_upsert_advances_state_counter() {
        // Oracle: state counter must advance on upsert_delivery_receipt.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr7", "msg-dr7");

        let state_before = ms.get_state().expect("state before");
        let receipt = make_receipt(Some("2026-06-13T14:00:00Z"));
        ms.upsert_delivery_receipt("msg-dr7", "recipient-x", &receipt)
            .expect("upsert");
        let state_after = ms.get_state().expect("state after");

        assert_ne!(state_before, state_after, "state counter must advance on upsert");
    }

    #[test]
    fn receipt_appears_in_get_via_populate_message_extras() {
        // Oracle: get() calls populate_message_extras which must surface delivery_receipts.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr8", "msg-dr8");

        let receipt = make_receipt(Some("2026-06-13T14:00:00Z"));
        ms.upsert_delivery_receipt("msg-dr8", "recipient-eve", &receipt)
            .expect("upsert");

        let msg = ms.get("msg-dr8").expect("get").expect("must exist");
        assert!(
            msg.delivery_receipts.is_some(),
            "delivery_receipts must be populated by get()"
        );
        let dr_map = msg.delivery_receipts.as_ref().unwrap();
        assert_eq!(dr_map.len(), 1);
        assert!(dr_map.contains_key("recipient-eve"));
    }

    #[test]
    fn receipt_read_disposition_values() {
        // Oracle: all three known ReadDisposition values must round-trip correctly.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dr9");
        let ms = MessageStore::new(&store.conn, None);

        let cases = [
            ("msg-dr9a", "displayed"),
            ("msg-dr9b", "deleted"),
            ("msg-dr9c", "processed"),
        ];

        for (msg_id, disp) in &cases {
            ms.insert(msg_id, "chat-dr9", "user-a", "body", "text/plain", None, 1000, &DeliveryState::Received, None, msg_id)
                .expect("insert");
            let receipt = make_receipt_full(
                Some("2026-06-13T14:00:00Z"),
                Some("2026-06-13T14:05:00Z"),
                Some(disp),
            );
            ms.upsert_delivery_receipt(msg_id, "recipient", &receipt)
                .expect("upsert");
        }

        let expected_dispositions = [
            ReadDisposition::Displayed,
            ReadDisposition::Deleted,
            ReadDisposition::Processed,
        ];
        for ((msg_id, _), expected) in cases.iter().zip(expected_dispositions.iter()) {
            let receipts = ms.load_delivery_receipts(msg_id).expect("load");
            let loaded = receipts.get("recipient").expect("recipient");
            assert_eq!(
                loaded.read_disposition.as_ref(),
                Some(expected),
                "read_disposition must round-trip for {msg_id}"
            );
        }
    }

    #[test]
    fn receipt_cascade_deletes_when_message_deleted() {
        // Oracle: ON DELETE CASCADE on delivery_receipts FK means deleting the
        // message must remove its receipts.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-dr10", "msg-dr10");

        let receipt = make_receipt(Some("2026-06-13T14:00:00Z"));
        ms.upsert_delivery_receipt("msg-dr10", "recipient-z", &receipt)
            .expect("upsert");

        let count: i64 = store.conn
            .query_row(
                "SELECT COUNT(*) FROM delivery_receipts WHERE message_id = 'msg-dr10'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "receipt must exist before message delete");

        store.conn
            .execute("DELETE FROM messages WHERE id = 'msg-dr10'", [])
            .unwrap();

        let count_after: i64 = store.conn
            .query_row(
                "SELECT COUNT(*) FROM delivery_receipts WHERE message_id = 'msg-dr10'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count_after, 0, "receipt must be cascade-deleted with message");
    }

    // -----------------------------------------------------------------------
    // Message actions tests
    // -----------------------------------------------------------------------

    #[test]
    fn action_insert_and_load_round_trip() {
        // Oracle: insert actions, load them, verify type/uri/label match input.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-ma1", "msg-ma1");

        let action = make_action("button", "https://example.com/approve", Some("Approve"));
        ms.insert_actions("msg-ma1", &[action]).expect("insert_actions");

        let actions = ms.load_actions("msg-ma1").expect("load_actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_type, "button");
        assert_eq!(actions[0].uri, "https://example.com/approve");
        assert_eq!(actions[0].label.as_deref(), Some("Approve"));
    }

    #[test]
    fn action_insert_multiple_on_one_message() {
        // Oracle: multiple actions on one message must all be retrievable.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-ma2", "msg-ma2");

        let actions = vec![
            make_action("button", "https://example.com/yes", Some("Yes")),
            make_action("button", "https://example.com/no", Some("No")),
            make_action("link", "https://example.com/details", Some("Details")),
        ];
        ms.insert_actions("msg-ma2", &actions).expect("insert");

        let loaded = ms.load_actions("msg-ma2").expect("load");
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].label.as_deref(), Some("Yes"));
        assert_eq!(loaded[1].label.as_deref(), Some("No"));
        assert_eq!(loaded[2].label.as_deref(), Some("Details"));
    }

    #[test]
    fn action_empty_list_is_noop() {
        // Oracle: inserting an empty actions list must not create any rows.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-ma3", "msg-ma3");

        ms.insert_actions("msg-ma3", &[]).expect("insert empty");
        let actions = ms.load_actions("msg-ma3").expect("load");
        assert!(actions.is_empty(), "empty insert must produce no rows");
    }

    #[test]
    fn action_with_expires_at_and_metadata() {
        // Oracle: expires_at and metadata round-trip through insert/load.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-ma4", "msg-ma4");

        let action: MessageAction = serde_json::from_value(serde_json::json!({
            "type": "button",
            "uri": "https://example.com/vote",
            "label": "Vote",
            "expiresAt": "2026-06-14T00:00:00Z",
            "metadata": {"poll_id": "poll-123", "option": 2}
        }))
        .expect("construct action");

        ms.insert_actions("msg-ma4", &[action]).expect("insert");

        let loaded = ms.load_actions("msg-ma4").expect("load");
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].expires_at.is_some(), "expires_at must round-trip");
        assert_eq!(loaded[0].expires_at.as_ref().unwrap().as_ref(), "2026-06-14T00:00:00Z");
        assert!(loaded[0].metadata.is_some(), "metadata must round-trip");
        let meta = loaded[0].metadata.as_ref().unwrap();
        assert_eq!(meta["poll_id"], "poll-123");
        assert_eq!(meta["option"], 2);
    }

    #[test]
    fn action_appears_in_get_via_populate_message_extras() {
        // Oracle: get() calls populate_message_extras which must surface actions.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-ma5", "msg-ma5");

        let action = make_action("button", "https://example.com/click", Some("Click"));
        ms.insert_actions("msg-ma5", &[action]).expect("insert");

        let msg = ms.get("msg-ma5").expect("get").expect("must exist");
        assert_eq!(msg.actions.len(), 1, "actions must be populated by get()");
        assert_eq!(msg.actions[0].action_type, "button");
    }

    #[test]
    fn action_batch_loading() {
        // Oracle: load_actions_for_messages returns actions keyed by message_id.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ma6");
        let ms = MessageStore::new(&store.conn, None);

        ms.insert("msg-ma6a", "chat-ma6", "user-a", "a", "text/plain", None, 100, &DeliveryState::Received, None, "msg-ma6a").expect("insert a");
        ms.insert("msg-ma6b", "chat-ma6", "user-a", "b", "text/plain", None, 200, &DeliveryState::Received, None, "msg-ma6b").expect("insert b");

        let a1 = make_action("button", "https://a.com", Some("A"));
        let a2 = make_action("link", "https://b.com", Some("B"));
        ms.insert_actions("msg-ma6a", &[a1]).expect("insert a1");
        ms.insert_actions("msg-ma6b", &[a2]).expect("insert a2");

        let ids = vec!["msg-ma6a".to_string(), "msg-ma6b".to_string()];
        let map = load_actions_for_messages(&store.conn, &ids).expect("batch load");
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("msg-ma6a").unwrap().len(), 1);
        assert_eq!(map.get("msg-ma6b").unwrap().len(), 1);
        assert_eq!(map.get("msg-ma6a").unwrap()[0].action_type, "button");
        assert_eq!(map.get("msg-ma6b").unwrap()[0].action_type, "link");
    }

    #[test]
    fn action_cascade_deletes_when_message_deleted() {
        // Oracle: ON DELETE CASCADE on message_actions FK means deleting the
        // message must remove its actions.
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-ma7", "msg-ma7");

        let action = make_action("button", "https://example.com", Some("Go"));
        ms.insert_actions("msg-ma7", &[action]).expect("insert");

        let count: i64 = store.conn
            .query_row(
                "SELECT COUNT(*) FROM message_actions WHERE message_id = 'msg-ma7'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "action must exist before message delete");

        store.conn
            .execute("DELETE FROM messages WHERE id = 'msg-ma7'", [])
            .unwrap();

        let count_after: i64 = store.conn
            .query_row(
                "SELECT COUNT(*) FROM message_actions WHERE message_id = 'msg-ma7'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count_after, 0, "action must be cascade-deleted with message");
    }

    #[test]
    fn action_ordering_preserved_by_action_index() {
        // Oracle: actions must be returned in the order they were inserted,
        // determined by the action_index column (0, 1, 2...).
        let store = Store::open_in_memory().expect("open");
        let ms = setup_with_message(&store, "chat-ma8", "msg-ma8");

        let actions = vec![
            make_action("button", "https://first.com", Some("First")),
            make_action("link", "https://second.com", Some("Second")),
            make_action("button", "https://third.com", Some("Third")),
        ];
        ms.insert_actions("msg-ma8", &actions).expect("insert");

        let loaded = ms.load_actions("msg-ma8").expect("load");
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].label.as_deref(), Some("First"));
        assert_eq!(loaded[1].label.as_deref(), Some("Second"));
        assert_eq!(loaded[2].label.as_deref(), Some("Third"));

        // Also verify via batch load preserves order.
        let ids = vec!["msg-ma8".to_string()];
        let map = load_actions_for_messages(&store.conn, &ids).expect("batch load");
        let batch_loaded = map.get("msg-ma8").expect("msg-ma8");
        assert_eq!(batch_loaded[0].label.as_deref(), Some("First"));
        assert_eq!(batch_loaded[1].label.as_deref(), Some("Second"));
        assert_eq!(batch_loaded[2].label.as_deref(), Some("Third"));
    }


    // -----------------------------------------------------------------------
    // Threading tests
    // -----------------------------------------------------------------------

    #[test]
    fn thread_root_id_round_trip_via_get() {
        // Oracle: a message inserted with thread_root_id must return that same
        // value when retrieved via get(). The FK points at the root message.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-thr1");

        let ms = MessageStore::new(&store.conn, None);
        // Insert root message first (no thread_root_id).
        ms.insert_full(
            "msg-root-1",
            "chat-thr1",
            "user-a",
            "root message",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-root-1",
            None,
            None,
            false,
        )
        .expect("insert root");

        // Insert reply with thread_root_id pointing to root.
        ms.insert_full(
            "msg-reply-1",
            "chat-thr1",
            "user-b",
            "reply in thread",
            "text/plain",
            None,
            1001,
            &DeliveryState::Received,
            Some("msg-root-1"),
            "msg-reply-1",
            Some("msg-root-1"),
            None,
            false,
        )
        .expect("insert reply");

        let reply = ms.get("msg-reply-1").expect("get").expect("must exist");
        assert_eq!(
            reply.thread_root_id.as_ref().map(|id| id.as_ref()),
            Some("msg-root-1"),
            "thread_root_id must round-trip through get()"
        );

        let root = ms.get("msg-root-1").expect("get").expect("must exist");
        assert!(
            root.thread_root_id.is_none(),
            "root message must have no thread_root_id"
        );
    }

    #[test]
    fn reply_count_computed_correctly() {
        // Oracle: create root + 3 replies using reply_to, verify root.reply_count == 3.
        // populate_reply_counts counts messages whose reply_to points to the root.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-rc1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-rc-root",
            "chat-rc1",
            "user-a",
            "root",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-rc-root",
        )
        .expect("insert root");

        for i in 1..=3 {
            ms.insert(
                &format!("msg-rc-reply-{i}"),
                "chat-rc1",
                "user-b",
                &format!("reply {i}"),
                "text/plain",
                None,
                1000 + i64::from(i),
                &DeliveryState::Received,
                Some("msg-rc-root"),
                &format!("msg-rc-reply-{i}"),
            )
            .expect("insert reply");
        }

        let root = ms.get("msg-rc-root").expect("get").expect("must exist");
        assert_eq!(
            root.reply_count,
            Some(3),
            "root must have reply_count == 3"
        );
    }

    #[test]
    fn unread_reply_count_excludes_read_replies() {
        // Oracle: of 3 replies, mark 1 as read. unread_reply_count must be 2,
        // total reply_count must still be 3.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-urc");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-urc-root",
            "chat-urc",
            "user-a",
            "root",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-urc-root",
        )
        .expect("insert root");

        for i in 1..=3 {
            ms.insert(
                &format!("msg-urc-reply-{i}"),
                "chat-urc",
                "user-b",
                &format!("reply {i}"),
                "text/plain",
                None,
                1000 + i64::from(i),
                &DeliveryState::Received,
                Some("msg-urc-root"),
                &format!("msg-urc-reply-{i}"),
            )
            .expect("insert reply");
        }

        // Mark one reply as read.
        ms.update_read_at("msg-urc-reply-2", 5000)
            .expect("mark read");

        let root = ms.get("msg-urc-root").expect("get").expect("must exist");
        assert_eq!(root.reply_count, Some(3), "total reply_count must be 3");
        assert_eq!(
            root.unread_reply_count,
            Some(2),
            "unread_reply_count must be 2 after marking one read"
        );
    }

    #[test]
    fn reply_count_zero_for_messages_with_no_replies() {
        // Oracle: a message with no replies must have reply_count = None (not Some(0)).
        // populate_reply_counts only sets counts for messages that have entries in the
        // GROUP BY result; messages with zero replies get no entry.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-rc0");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-rc0",
            "chat-rc0",
            "user-a",
            "no replies",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-rc0",
        )
        .expect("insert");

        let msg = ms.get("msg-rc0").expect("get").expect("must exist");
        assert!(
            msg.reply_count.is_none(),
            "message with no replies must have reply_count = None, got {:?}",
            msg.reply_count
        );
        assert!(
            msg.unread_reply_count.is_none(),
            "message with no replies must have unread_reply_count = None"
        );
    }

    #[test]
    fn reply_count_not_set_on_reply_messages() {
        // Oracle: a reply message should not have reply_count set if nobody
        // replied to it. reply_count is based on reply_to references pointing
        // at a message, not on being a reply itself.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-rcnr");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-rcnr-root",
            "chat-rcnr",
            "user-a",
            "root",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-rcnr-root",
        )
        .expect("insert root");

        ms.insert(
            "msg-rcnr-reply",
            "chat-rcnr",
            "user-b",
            "reply",
            "text/plain",
            None,
            1001,
            &DeliveryState::Received,
            Some("msg-rcnr-root"),
            "msg-rcnr-reply",
        )
        .expect("insert reply");

        let reply = ms.get("msg-rcnr-reply").expect("get").expect("must exist");
        assert!(
            reply.reply_count.is_none(),
            "reply with no sub-replies must have reply_count = None"
        );
    }

    #[test]
    fn thread_root_id_on_delete_set_null() {
        // Oracle: V24 schema declares thread_root_id with ON DELETE SET NULL.
        // Deleting the root message must set thread_root_id to NULL on replies,
        // not cascade-delete them.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-tds");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert_full(
            "msg-tds-root",
            "chat-tds",
            "user-a",
            "root",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-tds-root",
            None,
            None,
            false,
        )
        .expect("insert root");

        ms.insert_full(
            "msg-tds-reply",
            "chat-tds",
            "user-b",
            "reply",
            "text/plain",
            None,
            1001,
            &DeliveryState::Received,
            None,
            "msg-tds-reply",
            Some("msg-tds-root"),
            None,
            false,
        )
        .expect("insert reply");

        // Verify thread_root_id is set before delete.
        let before = ms.get("msg-tds-reply").expect("get").expect("exists");
        assert_eq!(
            before.thread_root_id.as_ref().map(|id| id.as_ref()),
            Some("msg-tds-root")
        );

        // Hard-delete the root message.
        store
            .conn
            .execute("DELETE FROM messages WHERE id = 'msg-tds-root'", [])
            .expect("delete root");

        // Reply must still exist with thread_root_id set to NULL.
        let after = ms.get("msg-tds-reply").expect("get").expect("must still exist");
        assert!(
            after.thread_root_id.is_none(),
            "thread_root_id must be NULL after root is deleted (ON DELETE SET NULL)"
        );
    }

    #[test]
    fn thread_root_id_fk_rejects_nonexistent_parent() {
        // Oracle: thread_root_id REFERENCES messages(id), so inserting a message
        // with a thread_root_id that does not exist must fail with an FK violation.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-tfk");

        let ms = MessageStore::new(&store.conn, None);
        let result = ms.insert_full(
            "msg-tfk",
            "chat-tfk",
            "user-a",
            "orphan reply",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-tfk",
            Some("nonexistent-root"),
            None,
            false,
        );
        assert!(
            result.is_err(),
            "inserting with nonexistent thread_root_id must fail: FK constraint"
        );
    }

    #[test]
    fn thread_root_id_in_list_by_chat_results() {
        // Oracle: list_by_chat must populate thread_root_id on returned messages.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-tlbc");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert_full(
            "msg-tlbc-root",
            "chat-tlbc",
            "user-a",
            "root",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-tlbc-root",
            None,
            None,
            false,
        )
        .expect("insert root");

        ms.insert_full(
            "msg-tlbc-reply",
            "chat-tlbc",
            "user-b",
            "reply",
            "text/plain",
            None,
            1001,
            &DeliveryState::Received,
            None,
            "msg-tlbc-reply",
            Some("msg-tlbc-root"),
            None,
            false,
        )
        .expect("insert reply");

        let msgs = ms.list_by_chat("chat-tlbc", 10).expect("list");
        let reply = msgs
            .iter()
            .find(|m| m.id == "msg-tlbc-reply")
            .expect("reply in list");
        assert_eq!(
            reply.thread_root_id.as_ref().map(|id| id.as_ref()),
            Some("msg-tlbc-root"),
            "thread_root_id must appear in list_by_chat results"
        );
    }

    #[test]
    fn multiple_threads_in_same_chat_counted_independently() {
        // Oracle: two root messages in the same chat, each with different reply
        // counts. populate_reply_counts must count them independently.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-mt");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-mt-root-a",
            "chat-mt",
            "user-a",
            "root A",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-mt-root-a",
        )
        .expect("insert root A");

        ms.insert(
            "msg-mt-root-b",
            "chat-mt",
            "user-a",
            "root B",
            "text/plain",
            None,
            1001,
            &DeliveryState::Received,
            None,
            "msg-mt-root-b",
        )
        .expect("insert root B");

        // 2 replies to root A.
        for i in 1..=2 {
            ms.insert(
                &format!("msg-mt-a-reply-{i}"),
                "chat-mt",
                "user-b",
                &format!("reply to A #{i}"),
                "text/plain",
                None,
                2000 + i64::from(i),
                &DeliveryState::Received,
                Some("msg-mt-root-a"),
                &format!("msg-mt-a-reply-{i}"),
            )
            .expect("insert reply to A");
        }

        // 1 reply to root B.
        ms.insert(
            "msg-mt-b-reply-1",
            "chat-mt",
            "user-b",
            "reply to B #1",
            "text/plain",
            None,
            3000,
            &DeliveryState::Received,
            Some("msg-mt-root-b"),
            "msg-mt-b-reply-1",
        )
        .expect("insert reply to B");

        let msgs = ms.list_by_chat("chat-mt", 10).expect("list");
        let root_a = msgs
            .iter()
            .find(|m| m.id == "msg-mt-root-a")
            .expect("root A");
        let root_b = msgs
            .iter()
            .find(|m| m.id == "msg-mt-root-b")
            .expect("root B");

        assert_eq!(
            root_a.reply_count,
            Some(2),
            "root A must have 2 replies"
        );
        assert_eq!(
            root_b.reply_count,
            Some(1),
            "root B must have 1 reply"
        );
    }

    #[test]
    fn thread_root_id_in_find_by_sender_msg_id() {
        // Oracle: find_by_sender_msg_id must return thread_root_id on the result.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-fsmi");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert_full(
            "msg-fsmi-root",
            "chat-fsmi",
            "user-a",
            "root",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "sender-root-id",
            None,
            None,
            false,
        )
        .expect("insert root");

        ms.insert_full(
            "msg-fsmi-reply",
            "chat-fsmi",
            "user-b",
            "reply",
            "text/plain",
            None,
            1001,
            &DeliveryState::Received,
            None,
            "sender-reply-id",
            Some("msg-fsmi-root"),
            None,
            false,
        )
        .expect("insert reply");

        let found = ms
            .find_by_sender_msg_id("chat-fsmi", "sender-reply-id")
            .expect("find")
            .expect("must exist");
        assert_eq!(
            found.thread_root_id.as_ref().map(|id| id.as_ref()),
            Some("msg-fsmi-root"),
            "find_by_sender_msg_id must return thread_root_id"
        );
    }

    #[test]
    fn reply_count_in_list_by_chat() {
        // Oracle: list_by_chat must populate reply_count via populate_reply_counts.
        // This verifies the batch path (not just get()).
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-rclbc");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-rclbc-root",
            "chat-rclbc",
            "user-a",
            "root",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-rclbc-root",
        )
        .expect("insert root");

        ms.insert(
            "msg-rclbc-reply",
            "chat-rclbc",
            "user-b",
            "reply",
            "text/plain",
            None,
            1001,
            &DeliveryState::Received,
            Some("msg-rclbc-root"),
            "msg-rclbc-reply",
        )
        .expect("insert reply");

        let msgs = ms.list_by_chat("chat-rclbc", 10).expect("list");
        let root = msgs
            .iter()
            .find(|m| m.id == "msg-rclbc-root")
            .expect("root");
        assert_eq!(
            root.reply_count,
            Some(1),
            "list_by_chat must populate reply_count"
        );
    }

    // -----------------------------------------------------------------------
    // Expiry tests
    // -----------------------------------------------------------------------

    #[test]
    fn sender_expires_at_round_trip() {
        // Oracle: a message inserted with sender_expires_at must return
        // that value when retrieved via get().
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-exp1");

        let ms = MessageStore::new(&store.conn, None);
        let expiry_ts: i64 = 2000000000; // well in the future
        ms.insert_full(
            "msg-exp1",
            "chat-exp1",
            "user-a",
            "ephemeral",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-exp1",
            None,
            Some(expiry_ts),
            false,
        )
        .expect("insert");

        let msg = ms.get("msg-exp1").expect("get").expect("must exist");
        assert!(
            msg.sender_expires_at.is_some(),
            "sender_expires_at must be set"
        );
        // Verify the timestamp round-trips: the stored RFC3339 string must
        // correspond to the Unix timestamp we inserted.
        let expected_rfc3339 = crate::util::unix_secs_to_rfc3339(expiry_ts as u64);
        assert_eq!(
            msg.sender_expires_at.as_ref().unwrap().as_ref(),
            &expected_rfc3339,
            "sender_expires_at must round-trip as RFC3339"
        );
    }

    #[test]
    fn burn_on_read_round_trip() {
        // Oracle: a message inserted with burn_on_read=true must return
        // burn_on_read=Some(true) when retrieved via get().
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-bor1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert_full(
            "msg-bor1",
            "chat-bor1",
            "user-a",
            "read and burn",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-bor1",
            None,
            None,
            true,
        )
        .expect("insert");

        let msg = ms.get("msg-bor1").expect("get").expect("must exist");
        assert_eq!(
            msg.burn_on_read,
            Some(true),
            "burn_on_read must be Some(true)"
        );
    }

    #[test]
    fn delete_expired_removes_past_messages() {
        // Oracle: messages with sender_expires_at <= now must be deleted by
        // delete_expired. Messages with future expiry must remain.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dexp");

        let ms = MessageStore::new(&store.conn, None);
        // Expired message (expires at t=500, now=1000).
        ms.insert_full(
            "msg-dexp-old",
            "chat-dexp",
            "user-a",
            "expired",
            "text/plain",
            None,
            100,
            &DeliveryState::Received,
            None,
            "msg-dexp-old",
            None,
            Some(500),
            false,
        )
        .expect("insert expired");

        // Future message (expires at t=9999).
        ms.insert_full(
            "msg-dexp-future",
            "chat-dexp",
            "user-a",
            "not expired",
            "text/plain",
            None,
            100,
            &DeliveryState::Received,
            None,
            "msg-dexp-future",
            None,
            Some(9999),
            false,
        )
        .expect("insert future");

        let deleted = ms.delete_expired(1000).expect("delete_expired");
        assert_eq!(deleted, 1, "must delete exactly 1 expired message");

        assert!(
            ms.get("msg-dexp-old").expect("get").is_none(),
            "expired message must be gone"
        );
        assert!(
            ms.get("msg-dexp-future").expect("get").is_some(),
            "future message must remain"
        );
    }

    #[test]
    fn delete_expired_leaves_future_messages() {
        // Oracle: when all messages have future expiry, delete_expired must
        // delete 0 and all messages must remain.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dxf");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert_full(
            "msg-dxf",
            "chat-dxf",
            "user-a",
            "not expired",
            "text/plain",
            None,
            100,
            &DeliveryState::Received,
            None,
            "msg-dxf",
            None,
            Some(9999),
            false,
        )
        .expect("insert");

        let deleted = ms.delete_expired(1000).expect("delete_expired");
        assert_eq!(deleted, 0, "no messages should be deleted");
        assert!(
            ms.get("msg-dxf").expect("get").is_some(),
            "message must remain"
        );
    }

    #[test]
    fn delete_expired_returns_count() {
        // Oracle: delete_expired must return the exact count of deleted messages.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dxc");

        let ms = MessageStore::new(&store.conn, None);
        for i in 1..=4 {
            ms.insert_full(
                &format!("msg-dxc-{i}"),
                "chat-dxc",
                "user-a",
                "ephemeral",
                "text/plain",
                None,
                100,
                &DeliveryState::Received,
                None,
                &format!("msg-dxc-{i}"),
                None,
                Some(500), // all expire at t=500
                false,
            )
            .expect("insert");
        }

        let count = ms.delete_expired(1000).expect("delete_expired");
        assert_eq!(count, 4, "must return exact count of deleted messages");
    }

    #[test]
    fn delete_expired_returns_zero_when_none_expired() {
        // Oracle: when no messages are expired, delete_expired must return 0.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dxz");

        let ms = MessageStore::new(&store.conn, None);
        // Message with no expiry.
        ms.insert(
            "msg-dxz",
            "chat-dxz",
            "user-a",
            "permanent",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-dxz",
        )
        .expect("insert");

        let count = ms.delete_expired(9999).expect("delete_expired");
        assert_eq!(count, 0, "no messages expired, count must be 0");
    }

    #[test]
    fn delete_expired_advances_state_only_when_deleted() {
        // Oracle: delete_expired must advance the state counter only when it
        // actually deletes messages. When count is 0, state must not advance.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dxs");

        let ms = MessageStore::new(&store.conn, None);
        // Insert one expired message.
        ms.insert_full(
            "msg-dxs-exp",
            "chat-dxs",
            "user-a",
            "ephemeral",
            "text/plain",
            None,
            100,
            &DeliveryState::Received,
            None,
            "msg-dxs-exp",
            None,
            Some(500),
            false,
        )
        .expect("insert");

        let state_before = ms.get_state().expect("state before");

        // Delete the expired message.
        let deleted = ms.delete_expired(1000).expect("delete_expired");
        assert_eq!(deleted, 1);

        let state_after_delete = ms.get_state().expect("state after delete");
        assert_ne!(
            state_before, state_after_delete,
            "state must advance when messages are deleted"
        );

        // Now call again — nothing to delete.
        let deleted_again = ms.delete_expired(1000).expect("delete_expired again");
        assert_eq!(deleted_again, 0);

        let state_after_noop = ms.get_state().expect("state after noop");
        assert_eq!(
            state_after_delete, state_after_noop,
            "state must NOT advance when no messages were deleted"
        );
    }

    #[test]
    fn messages_without_expiry_never_expired() {
        // Oracle: messages with sender_expires_at = NULL must never be removed
        // by delete_expired, regardless of the now_unix value.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-nxp");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-nxp",
            "chat-nxp",
            "user-a",
            "permanent",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-nxp",
        )
        .expect("insert");

        // Use a very large now_unix — far in the future.
        let count = ms.delete_expired(i64::MAX).expect("delete_expired");
        assert_eq!(count, 0, "message without expiry must not be deleted");
        assert!(
            ms.get("msg-nxp").expect("get").is_some(),
            "permanent message must still exist"
        );
    }

    #[test]
    fn burn_on_read_persists_through_list() {
        // Oracle: burn_on_read set via insert_message_with_attachments must be
        // visible in list_by_chat results, not just get().
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-borl");

        store
            .insert_message_with_attachments(
                "msg-borl",
                "chat-borl",
                "user-a",
                "burn me",
                "text/plain",
                None,
                1000,
                &DeliveryState::Received,
                None,
                "msg-borl",
                &[],
                &[],
                None,
                None,
                true,
                &[],
            )
            .expect("insert");

        let ms = MessageStore::new(&store.conn, None);
        let msgs = ms.list_by_chat("chat-borl", 10).expect("list");
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].burn_on_read,
            Some(true),
            "burn_on_read must persist through list_by_chat"
        );
    }

    // -----------------------------------------------------------------------
    // Deletion + edit history tests
    // -----------------------------------------------------------------------

    #[test]
    fn soft_delete_clears_body() {
        // Oracle: after soft_delete, the message body must be empty string
        // and deleted_at must be set.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-sd1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-sd1",
            "chat-sd1",
            "user-a",
            "original body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-sd1",
        )
        .expect("insert");

        ms.soft_delete("msg-sd1", false, 2000).expect("soft_delete");

        let msg = ms.get("msg-sd1").expect("get").expect("must exist");
        assert_eq!(msg.body, "", "body must be empty after soft_delete");
    }

    #[test]
    fn soft_delete_sets_deleted_at() {
        // Oracle: soft_delete must set deleted_at to the provided timestamp.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-sd2");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-sd2",
            "chat-sd2",
            "user-a",
            "will be deleted",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-sd2",
        )
        .expect("insert");

        let delete_ts: i64 = 2000;
        ms.soft_delete("msg-sd2", false, delete_ts)
            .expect("soft_delete");

        let msg = ms.get("msg-sd2").expect("get").expect("must exist");
        assert!(msg.deleted_at.is_some(), "deleted_at must be set");
        let expected_rfc3339 = crate::util::unix_secs_to_rfc3339(delete_ts as u64);
        assert_eq!(
            msg.deleted_at.as_ref().unwrap().as_ref(),
            &expected_rfc3339,
            "deleted_at must match the provided timestamp"
        );
    }

    #[test]
    fn soft_delete_with_deleted_for_all() {
        // Oracle: soft_delete with deleted_for_all=true must set the flag.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-sd3");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-sd3",
            "chat-sd3",
            "user-a",
            "delete for all",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-sd3",
        )
        .expect("insert");

        ms.soft_delete("msg-sd3", true, 2000).expect("soft_delete");

        let msg = ms.get("msg-sd3").expect("get").expect("must exist");
        assert_eq!(
            msg.deleted_for_all,
            Some(true),
            "deleted_for_all must be true"
        );
    }

    #[test]
    fn soft_delete_idempotent_no_re_advance() {
        // Oracle: calling soft_delete twice must be idempotent. The second call
        // must return Ok but must NOT advance the state counter.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-sdi");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-sdi",
            "chat-sdi",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-sdi",
        )
        .expect("insert");

        ms.soft_delete("msg-sdi", false, 2000)
            .expect("first soft_delete");
        let state_after_first = ms.get_state().expect("state after first");

        ms.soft_delete("msg-sdi", false, 3000)
            .expect("second soft_delete");
        let state_after_second = ms.get_state().expect("state after second");

        assert_eq!(
            state_after_first, state_after_second,
            "second soft_delete must not advance state counter (idempotent)"
        );
    }

    #[test]
    fn soft_delete_cascade_removes_attachments() {
        // Oracle: soft_delete must DELETE FROM attachments for the message.
        // After soft_delete, get() must return empty attachments.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-sdca");

        let att = kith_core::make_attachment(
            "a".repeat(64),
            "file.txt",
            "text/plain",
            42,
            "b".repeat(64),
        );
        store
            .insert_message_with_attachments(
                "msg-sdca",
                "chat-sdca",
                "user-a",
                "has attachment",
                "text/plain",
                None,
                1000,
                &DeliveryState::Received,
                None,
                "msg-sdca",
                &[att],
                &[],
                None,
                None,
                false,
                &[],
            )
            .expect("insert with attachment");

        // Verify attachment exists.
        let before = MessageStore::new(&store.conn, None)
            .get("msg-sdca")
            .expect("get")
            .expect("exists");
        assert_eq!(before.attachments.len(), 1, "attachment must exist before delete");

        let ms = MessageStore::new(&store.conn, None);
        ms.soft_delete("msg-sdca", false, 2000)
            .expect("soft_delete");

        // Verify attachment row is actually gone from the table.
        let att_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM attachments WHERE message_id = 'msg-sdca'",
                [],
                |row| row.get(0),
            )
            .expect("count attachments");
        assert_eq!(
            att_count, 0,
            "attachment rows must be deleted by soft_delete"
        );
    }

    #[test]
    fn update_body_pushes_revision() {
        // Oracle: update_body must push the old body as a revision. After one edit,
        // edit_history must contain exactly one revision with the original body.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ub1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ub1",
            "chat-ub1",
            "user-a",
            "original body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ub1",
        )
        .expect("insert");

        ms.update_body("msg-ub1", "edited body", "text/plain", 2000)
            .expect("update_body");

        let msg = ms.get("msg-ub1").expect("get").expect("must exist");
        assert_eq!(msg.body, "edited body", "body must be updated");

        let history = msg.edit_history.expect("edit_history must be Some");
        assert_eq!(history.len(), 1, "one revision after one edit");
        // The revision stores the OLD body.
        let rev_json = serde_json::to_value(&history[0]).expect("serialize revision");
        assert_eq!(
            rev_json["body"], "original body",
            "revision must contain the old body"
        );
    }

    #[test]
    fn update_body_twice_creates_two_ordered_revisions() {
        // Oracle: two edits must produce two revisions in chronological order.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ub2");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ub2",
            "chat-ub2",
            "user-a",
            "version 1",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ub2",
        )
        .expect("insert");

        ms.update_body("msg-ub2", "version 2", "text/plain", 2000)
            .expect("first edit");
        ms.update_body("msg-ub2", "version 3", "text/plain", 3000)
            .expect("second edit");

        let msg = ms.get("msg-ub2").expect("get").expect("must exist");
        assert_eq!(msg.body, "version 3", "body must be latest version");

        let history = msg.edit_history.expect("edit_history must be Some");
        assert_eq!(history.len(), 2, "two revisions after two edits");

        // Revisions ordered by revision_index ASC: first revision = "version 1",
        // second revision = "version 2".
        let rev0 = serde_json::to_value(&history[0]).expect("serialize");
        let rev1 = serde_json::to_value(&history[1]).expect("serialize");
        assert_eq!(rev0["body"], "version 1", "first revision = original body");
        assert_eq!(rev1["body"], "version 2", "second revision = first edit");
    }

    #[test]
    fn update_body_sets_edited_at() {
        // Oracle: after update_body, the message's edited_at must be set to the
        // provided timestamp (as RFC3339).
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ubea");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ubea",
            "chat-ubea",
            "user-a",
            "original",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ubea",
        )
        .expect("insert");

        let edit_ts: i64 = 2000;
        ms.update_body("msg-ubea", "edited", "text/plain", edit_ts)
            .expect("update_body");

        let msg = ms.get("msg-ubea").expect("get").expect("must exist");
        assert!(msg.edited_at.is_some(), "edited_at must be set");
        let expected_rfc3339 = crate::util::unix_secs_to_rfc3339(edit_ts as u64);
        assert_eq!(
            msg.edited_at.as_ref().unwrap().as_ref(),
            &expected_rfc3339,
            "edited_at must match the edit timestamp"
        );
    }

    #[test]
    fn update_body_on_deleted_message_returns_error() {
        // Oracle: editing a soft-deleted message must return an error.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ubdel");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ubdel",
            "chat-ubdel",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ubdel",
        )
        .expect("insert");

        ms.soft_delete("msg-ubdel", false, 2000)
            .expect("soft_delete");

        let result = ms.update_body("msg-ubdel", "new body", "text/plain", 3000);
        assert!(
            result.is_err(),
            "update_body on deleted message must return Err"
        );
    }

    #[test]
    fn edit_history_loaded_in_list_by_chat() {
        // Oracle: list_by_chat must populate edit_history via batch loader.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ehlbc");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ehlbc",
            "chat-ehlbc",
            "user-a",
            "original",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ehlbc",
        )
        .expect("insert");

        ms.update_body("msg-ehlbc", "edited", "text/plain", 2000)
            .expect("update_body");

        let msgs = ms.list_by_chat("chat-ehlbc", 10).expect("list");
        assert_eq!(msgs.len(), 1);
        let history = msgs[0]
            .edit_history
            .as_ref()
            .expect("edit_history must be Some in list_by_chat");
        assert_eq!(history.len(), 1, "one revision in list_by_chat result");
    }

    #[test]
    fn soft_delete_advances_state_counter() {
        // Oracle: soft_delete must advance the state counter (first call only).
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-sdsc");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-sdsc",
            "chat-sdsc",
            "user-a",
            "body",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-sdsc",
        )
        .expect("insert");

        let state_before = ms.get_state().expect("state before");
        ms.soft_delete("msg-sdsc", false, 2000)
            .expect("soft_delete");
        let state_after = ms.get_state().expect("state after");

        assert_ne!(
            state_before, state_after,
            "soft_delete must advance the state counter"
        );
    }
    // -----------------------------------------------------------------------
    // Edge case tests (store layer)
    // -----------------------------------------------------------------------

    #[test]
    fn insert_duplicate_id_fails_with_constraint_violation() {
        // Oracle: SQLite PRIMARY KEY constraint rejects duplicate message IDs.
        // The error maps to KithError::Validation (constraint violation).
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-dup");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-dup",
            "chat-dup",
            "user-a",
            "first",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-dup",
        )
        .expect("first insert");

        let result = ms.insert(
            "msg-dup",
            "chat-dup",
            "user-a",
            "second",
            "text/plain",
            None,
            2000,
            &DeliveryState::Received,
            None,
            "msg-dup-2",
        );
        assert!(
            result.is_err(),
            "duplicate message ID must fail with constraint violation"
        );
        match result.unwrap_err() {
            KithError::Validation(msg) => {
                assert!(
                    msg.contains("constraint"),
                    "error must mention constraint; got: {msg}"
                );
            }
            other => panic!("expected KithError::Validation, got: {other:?}"),
        }
    }

    #[test]
    fn insert_with_nonexistent_chat_id_fails_fk_violation() {
        // Oracle: SQLite FK constraint rejects a message referencing a chat_id
        // not present in the chats table.
        let store = Store::open_in_memory().expect("open");

        let ms = MessageStore::new(&store.conn, None);
        let result = ms.insert(
            "msg-fk1",
            "no-such-chat",
            "user-a",
            "hello",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-fk1",
        );
        assert!(
            result.is_err(),
            "insert with nonexistent chat_id must fail (FK violation)"
        );
    }

    #[test]
    fn get_nonexistent_message_returns_none() {
        // Oracle: get() on a missing ID returns Ok(None), not an error.
        let store = Store::open_in_memory().expect("open");
        let ms = MessageStore::new(&store.conn, None);
        let result = ms.get("no-such-msg").expect("get must not error");
        assert!(result.is_none(), "nonexistent message must return None");
    }

    #[test]
    fn list_messages_for_empty_chat_returns_empty_vec() {
        // Oracle: a chat with no messages must return an empty Vec, not an error.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-empty");

        let ms = MessageStore::new(&store.conn, None);
        let msgs = ms
            .list_by_chat("chat-empty", 100)
            .expect("list_by_chat must not error");
        assert!(msgs.is_empty(), "empty chat must return empty vec");
    }

    #[test]
    fn list_by_chat_paged_offset_beyond_total_returns_empty() {
        // Oracle: SQL OFFSET beyond the total row count returns zero rows.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-pg1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-pg1",
            "chat-pg1",
            "user-a",
            "hello",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-pg1",
        )
        .expect("insert");

        let result = ms
            .list_by_chat_paged("chat-pg1", 10, 999)
            .expect("paged query must not error");
        assert!(
            result.is_empty(),
            "offset beyond total count must return empty vec"
        );
    }

    #[test]
    fn list_by_chat_paged_limit_zero_returns_empty() {
        // Oracle: SQL LIMIT 0 always returns zero rows regardless of data.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-pg2");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-pg2",
            "chat-pg2",
            "user-a",
            "hello",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-pg2",
        )
        .expect("insert");

        let result = ms
            .list_by_chat_paged("chat-pg2", 0, 0)
            .expect("paged query must not error");
        assert!(result.is_empty(), "limit=0 must return empty vec");
    }

    #[test]
    fn update_read_at_earlier_timestamp_does_not_regress() {
        // Oracle: the monotonicity guard `AND (read_at IS NULL OR read_at < ?1)`
        // prevents overwriting a later read_at with an earlier one.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-ra1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-ra1",
            "chat-ra1",
            "user-a",
            "hello",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-ra1",
        )
        .expect("insert");

        // First read_at = 5000
        ms.update_read_at("msg-ra1", 5000).expect("first read_at");

        // Attempt to set an earlier read_at = 3000 — must not regress.
        ms.update_read_at("msg-ra1", 3000)
            .expect("earlier read_at must succeed (idempotent)");

        let msg = ms.get("msg-ra1").expect("get").expect("must exist");
        // Oracle: read_at must still be 5000 (the later timestamp).
        // unix 5000 = 1970-01-01T01:23:20Z
        assert_eq!(
            msg.read_at.as_ref().map(|d| d.as_ref()),
            Some("1970-01-01T01:23:20Z"),
            "read_at must not regress to earlier timestamp"
        );
    }

    #[test]
    fn update_read_at_on_nonexistent_message_returns_error() {
        // Oracle: update_read_at on a missing message must return Err.
        let store = Store::open_in_memory().expect("open");
        let ms = MessageStore::new(&store.conn, None);
        let result = ms.update_read_at("no-such-msg", 1000);
        assert!(
            result.is_err(),
            "update_read_at on nonexistent message must return Err"
        );
    }

    #[test]
    fn get_changes_since_s0_returns_all_messages() {
        // Oracle: sinceState "s-0" means "return everything created or updated
        // after counter=0". Since all messages are inserted at counter>=1,
        // all must appear in the result.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-cs1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-cs1",
            "chat-cs1",
            "user-a",
            "first",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-cs1",
        )
        .expect("insert 1");
        ms.insert(
            "msg-cs2",
            "chat-cs1",
            "user-a",
            "second",
            "text/plain",
            None,
            2000,
            &DeliveryState::Received,
            None,
            "msg-cs2",
        )
        .expect("insert 2");

        let changes = ms.get_changes_since("s-0").expect("get_changes_since");
        assert_eq!(
            changes.added.len(),
            2,
            "sinceState s-0 must return all messages in added; got {:?}",
            changes.added
        );
        assert!(changes.added.contains(&"msg-cs1".to_string()));
        assert!(changes.added.contains(&"msg-cs2".to_string()));
        assert!(changes.updated.is_empty());
    }

    #[test]
    fn get_changes_since_current_state_returns_empty() {
        // Oracle: when sinceState equals the current state, no changes exist.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-cs3");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-cs3",
            "chat-cs3",
            "user-a",
            "hello",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-cs3",
        )
        .expect("insert");

        let current = ms.get_state().expect("get_state");
        let changes = ms.get_changes_since(&current).expect("get_changes_since");
        assert!(changes.added.is_empty(), "no new messages since current state");
        assert!(
            changes.updated.is_empty(),
            "no updated messages since current state"
        );
    }

    #[test]
    fn find_by_sender_msg_id_nonexistent_returns_none() {
        // Oracle: find_by_sender_msg_id with a non-matching ID returns Ok(None).
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-fs1");

        let ms = MessageStore::new(&store.conn, None);
        let result = ms
            .find_by_sender_msg_id("chat-fs1", "no-such-sender-id")
            .expect("must not error");
        assert!(result.is_none(), "nonexistent sender_msg_id must return None");
    }

    #[test]
    fn find_by_sender_msg_id_dedup_returns_existing() {
        // Oracle: after inserting a message with a given sender_msg_id,
        // find_by_sender_msg_id returns that message. This is the idempotency
        // check used by Peer/deliver — same sender_msg_id means duplicate delivery.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-fs2");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-fs2",
            "chat-fs2",
            "user-a",
            "original",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "sender-ulid-abc",
        )
        .expect("insert");

        let found = ms
            .find_by_sender_msg_id("chat-fs2", "sender-ulid-abc")
            .expect("must not error")
            .expect("must find existing");
        assert_eq!(found.id, "msg-fs2");
        assert_eq!(found.body, "original");
    }

    #[test]
    fn message_with_empty_body_accepted_by_store() {
        // Oracle: the store layer has body TEXT NOT NULL but no CHECK(body != '').
        // An empty string is a valid TEXT value in SQLite. The application layer
        // (kith-chat) enforces non-empty bodies; the store does not.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-eb1");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-eb1",
            "chat-eb1",
            "user-a",
            "",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-eb1",
        )
        .expect("empty body must be accepted by the store layer");

        let msg = ms.get("msg-eb1").expect("get").expect("must exist");
        assert_eq!(msg.body, "", "empty body must round-trip");
    }

    #[test]
    fn message_with_max_body_size_accepted() {
        // Oracle: MAX_BODY_BYTES = 65536 (kith_core::MAX_BODY_BYTES).
        // The store must accept a body of exactly this length without error.
        // SQLite TEXT has no built-in length limit.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-mb1");

        let large_body = "x".repeat(65536);
        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-mb1",
            "chat-mb1",
            "user-a",
            &large_body,
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-mb1",
        )
        .expect("65536-byte body must be accepted");

        let msg = ms.get("msg-mb1").expect("get").expect("must exist");
        assert_eq!(msg.body.len(), 65536, "body must round-trip at max size");
    }

    #[test]
    fn soft_delete_cascades_pinned_messages() {
        // Oracle: the pinned_messages table has FK on message_id with ON DELETE CASCADE.
        // When a message is hard-deleted (DELETE FROM messages), pinned_messages rows
        // referencing that message must be automatically removed.
        let store = Store::open_in_memory().expect("open");
        insert_chat(&store.conn, "chat-pnc");

        let ms = MessageStore::new(&store.conn, None);
        ms.insert(
            "msg-pnc",
            "chat-pnc",
            "user-a",
            "pinnable",
            "text/plain",
            None,
            1000,
            &DeliveryState::Received,
            None,
            "msg-pnc",
        )
        .expect("insert");

        // Pin the message.
        store
            .conn
            .execute(
                "INSERT INTO pinned_messages (chat_id, message_id) VALUES ('chat-pnc', 'msg-pnc')",
                [],
            )
            .expect("pin message");

        // Verify the pin exists.
        let pin_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pinned_messages WHERE message_id = 'msg-pnc'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pin_count, 1, "pin must exist before delete");

        // Hard-delete the message.
        store
            .conn
            .execute("DELETE FROM messages WHERE id = 'msg-pnc'", [])
            .unwrap();

        // Oracle: ON DELETE CASCADE must have removed the pinned_messages row.
        let pin_count_after: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pinned_messages WHERE message_id = 'msg-pnc'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            pin_count_after, 0,
            "pinned_messages must be cascade-deleted when message is hard-deleted"
        );
    }
}
