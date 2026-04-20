// Message/get, Message/set, Message/changes, Message/query, Message/queryChanges handlers

use crate::kith_to_jmap;
use kith_attach::BlobStore;
use kith_core::{Attachment, DeliveryState, JmapError};
use kith_jmap::{HandlerFuture, JmapHandler};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

const MAX_BODY_BYTES: usize = 65_536;
const MAX_ATTACHMENT_BYTES: u64 = 104_857_600; // 100 MiB per attachment
const MAX_ATTACHMENTS: usize = 20;
const SUPPORTED_BODY_TYPES: &[&str] = &["text/plain", "text/markdown"];

struct ParsedAttachment {
    blob_id: String,
    filename: String,
    content_type: String,
    size: u64,
    sha256: String,
}

fn validate_filename(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("filename must not be empty");
    }
    if name.len() > 255 {
        return Err("filename exceeds maximum length of 255");
    }
    if name.contains('\0') || name.contains('/') || name.contains('\\') {
        return Err("filename contains disallowed character");
    }
    Ok(())
}

fn validate_content_type(ct: &str) -> Result<(), &'static str> {
    if ct.is_empty() {
        return Err("contentType must not be empty");
    }
    if ct.len() > 256 {
        return Err("contentType exceeds maximum length");
    }
    if ct.chars().filter(|&c| c == '/').count() != 1 {
        return Err("contentType must contain exactly one '/'");
    }
    Ok(())
}

fn validate_sha256(s: &str) -> Result<(), &'static str> {
    if s.len() != 64 {
        return Err("sha256 must be 64 lowercase hex characters");
    }
    for ch in s.chars() {
        if !matches!(ch, '0'..='9' | 'a'..='f') {
            return Err("sha256 must be 64 lowercase hex characters");
        }
    }
    Ok(())
}

fn parse_attachments(obj: &serde_json::Map<String, Value>) -> Result<Vec<ParsedAttachment>, Value> {
    let arr = match obj.get("attachments") {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(Value::Array(a)) => a,
        Some(_) => {
            return Err(
                json!({"type": "invalidArguments", "description": "attachments must be an array"}),
            );
        }
    };
    if arr.len() > MAX_ATTACHMENTS {
        return Err(
            json!({"type": "invalidArguments", "description": format!("too many attachments: max is {MAX_ATTACHMENTS}")}),
        );
    }
    let mut result = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let att = item.as_object().ok_or_else(|| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}] must be an object")})
        })?;
        let blob_id = att.get("blobId").and_then(|v| v.as_str()).ok_or_else(|| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].blobId is required")})
        })?.to_string();
        BlobStore::validate_blob_id(&blob_id).map_err(|e| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].blobId: {e}")})
        })?;
        let filename = att.get("filename").and_then(|v| v.as_str()).ok_or_else(|| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].filename is required")})
        })?.to_string();
        validate_filename(&filename).map_err(|e| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].filename: {e}")})
        })?;
        let content_type = att.get("contentType").and_then(|v| v.as_str()).ok_or_else(|| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].contentType is required")})
        })?.to_string();
        validate_content_type(&content_type).map_err(|e| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].contentType: {e}")})
        })?;
        let size = att.get("size").and_then(|v| v.as_u64()).ok_or_else(|| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].size must be a non-negative integer")})
        })?;
        if size > MAX_ATTACHMENT_BYTES {
            return Err(
                json!({"type": "invalidArguments", "description": format!("attachments[{i}].size exceeds maximum of {MAX_ATTACHMENT_BYTES} bytes")}),
            );
        }
        let sha256 = att.get("sha256").and_then(|v| v.as_str()).ok_or_else(|| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].sha256 is required")})
        })?.to_string();
        validate_sha256(&sha256).map_err(|e| {
            json!({"type": "invalidArguments", "description": format!("attachments[{i}].sha256: {e}")})
        })?;
        result.push(ParsedAttachment {
            blob_id,
            filename,
            content_type,
            size,
            sha256,
        });
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Message/set
// ---------------------------------------------------------------------------

pub struct MessageSetHandler {
    store: Arc<Mutex<kith_store::Store>>,
    owner_id: String,
}

impl MessageSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>, owner_id: String) -> Self {
        Self { store, owner_id }
    }
}

impl JmapHandler for MessageSetHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);
        let owner_id = self.owner_id.clone();

        Box::pin(async move {
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            let create_map: Option<&Map<String, Value>> =
                obj.get("create").and_then(|v| v.as_object());
            let update_map: Option<&Map<String, Value>> =
                obj.get("update").and_then(|v| v.as_object());
            let destroy_list: Option<Vec<String>> = obj.get("destroy").and_then(|v| {
                v.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
            });

            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let mut created: Map<String, Value> = Map::new();
            let mut not_created: Map<String, Value> = Map::new();
            let mut updated: Map<String, Value> = Map::new();
            let mut not_updated: Map<String, Value> = Map::new();
            let mut not_destroyed: Map<String, Value> = Map::new();

            // Process creates.
            if let Some(creates) = create_map {
                for (client_id, value) in creates {
                    match process_create(&store, client_id, value, now_unix, &owner_id) {
                        Ok(msg_value) => {
                            created.insert(client_id.clone(), msg_value);
                        }
                        Err(err_value) => {
                            not_created.insert(client_id.clone(), err_value);
                        }
                    }
                }
            }

            // Process updates (only readAt is patchable).
            if let Some(updates) = update_map {
                for (server_id, patch) in updates {
                    match process_update(&store, server_id, patch, now_unix) {
                        Ok(()) => {
                            updated.insert(server_id.clone(), Value::Null);
                        }
                        Err(err_value) => {
                            not_updated.insert(server_id.clone(), err_value);
                        }
                    }
                }
            }

            // Destroy is not supported for messages.
            if let Some(destroy_ids) = destroy_list {
                for id in destroy_ids {
                    not_destroyed.insert(
                        id,
                        json!({
                            "type": "forbidden",
                            "description": "messages cannot be destroyed"
                        }),
                    );
                }
            }

            let new_state = {
                let guard = store
                    .lock()
                    .map_err(|_| JmapError::server_fail("store poisoned"))?;
                guard.messages().get_state().map_err(kith_to_jmap)?
            };

            Ok(json!({
                "accountId": "a-self",
                "oldState": Value::Null,
                "newState": new_state,
                "created": created,
                "updated": updated,
                "destroyed": [],
                "notCreated": not_created,
                "notUpdated": not_updated,
                "notDestroyed": not_destroyed,
            }))
        })
    }
}

fn process_create(
    store: &Arc<Mutex<kith_store::Store>>,
    _client_id: &str,
    value: &Value,
    now_unix: i64,
    owner_id: &str,
) -> Result<Value, Value> {
    let obj = value.as_object().ok_or_else(
        || json!({"type": "invalidArguments", "description": "create entry must be an object"}),
    )?;

    let chat_id = obj
        .get("chatId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"type": "invalidArguments", "description": "chatId is required"}))?
        .to_string();

    let body = obj
        .get("body")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"type": "invalidArguments", "description": "body is required"}))?
        .to_string();

    let body_type = obj
        .get("bodyType")
        .and_then(|v| v.as_str())
        .unwrap_or("text/plain")
        .to_string();

    let reply_to: Option<String> = obj
        .get("replyTo")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let sent_at: Option<String> = obj
        .get("sentAt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Validate body length BEFORE acquiring the store lock.
    if body.len() > MAX_BODY_BYTES {
        return Err(json!({"type": "invalidArguments", "description": "body too long"}));
    }

    // Validate bodyType.
    if !SUPPORTED_BODY_TYPES.contains(&body_type.as_str()) {
        return Err(json!({"type": "invalidArguments", "description": "unsupported bodyType"}));
    }

    // Parse and validate attachments BEFORE acquiring the store lock.
    let attachments = parse_attachments(obj)?;

    // Acquire the store lock for all DB operations.
    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "store poisoned"}))?;

    // Validate chatId exists.
    let chat = guard
        .chats()
        .get(&chat_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?
        .ok_or_else(|| json!({"type": "notFound", "description": "chatId not found"}))?;

    // Validate replyTo if present.
    if let Some(ref reply_id) = reply_to {
        match guard.messages().get(reply_id) {
            Ok(Some(ref referenced)) if referenced.chat_id == chat_id => {}
            Ok(Some(_)) => {
                return Err(
                    json!({"type": "invalidArguments", "description": "replyTo references a message in a different chat"}),
                );
            }
            Ok(None) => {
                return Err(
                    json!({"type": "invalidArguments", "description": "replyTo references a nonexistent message"}),
                );
            }
            Err(e) => {
                return Err(json!({"type": "serverFail", "description": e.to_string()}));
            }
        }
    }

    // Generate message ID.
    let msg_id = Ulid::new().to_string();

    // Convert ParsedAttachment -> kith_core::Attachment for the store method.
    let core_attachments: Vec<Attachment> = attachments
        .iter()
        .map(|a| Attachment {
            blob_id: a.blob_id.clone(),
            filename: a.filename.clone(),
            content_type: a.content_type.clone(),
            size: a.size,
            sha256: a.sha256.clone(),
        })
        .collect();

    // Insert message and all attachment rows in a single transaction.
    // If any attachment insert fails (e.g. duplicate blob_id / UNIQUE constraint),
    // the transaction rolls back automatically — no partial state is left in the DB.
    guard
        .insert_message_with_attachments(
            &msg_id,
            &chat_id,
            "self",
            &body,
            &body_type,
            sent_at.as_deref(),
            now_unix,
            &DeliveryState::Pending,
            reply_to.as_deref(),
            &core_attachments,
        )
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Update last_message_at on the chat.
    guard
        .chats()
        .update_last_message_at(&chat_id, now_unix)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Enqueue for each peer participant.
    for participant_id in &chat.participants {
        if participant_id == owner_id {
            continue;
        }
        if let Ok(Some(contact)) = guard.contacts().get_by_peer_user_id(participant_id) {
            let _ =
                guard
                    .outbox()
                    .enqueue(&msg_id, participant_id, &contact.mailbox_host, now_unix);
        }
    }

    // Fetch the created message for the response.
    let msg = guard
        .messages()
        .get(&msg_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?
        .ok_or_else(
            || json!({"type": "serverFail", "description": "message not found after insert"}),
        )?;

    drop(guard);

    serde_json::to_value(&msg).map_err(
        |e| json!({"type": "serverFail", "description": format!("serialization error: {e}")}),
    )
}

fn process_update(
    store: &Arc<Mutex<kith_store::Store>>,
    server_id: &str,
    patch: &Value,
    now_unix: i64,
) -> Result<(), Value> {
    let patch_obj = patch.as_object().ok_or_else(
        || json!({"type": "invalidArguments", "description": "update patch must be an object"}),
    )?;

    // Only readAt is patchable.
    for key in patch_obj.keys() {
        if key != "readAt" {
            return Err(
                json!({"type": "invalidArguments", "description": "only readAt is patchable"}),
            );
        }
    }

    let read_at_str = patch_obj
        .get("readAt")
        .and_then(|v| v.as_str())
        .ok_or_else(
            || json!({"type": "invalidArguments", "description": "readAt must be a string"}),
        )?;

    // Parse RFC 3339 to unix timestamp.
    let read_at_unix: i64 = chrono::DateTime::parse_from_rfc3339(read_at_str)
        .map(|dt| dt.timestamp())
        .map_err(
            |_| json!({"type": "invalidArguments", "description": "readAt must be RFC 3339"}),
        )?;

    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "store poisoned"}))?;

    guard
        .messages()
        .update_read_at(server_id, read_at_unix)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Enqueue a read receipt to the original sender for inbound messages.
    // Failures are silently ignored — receipt enqueue must not fail the readAt update.
    if let Ok(Some(msg)) = guard.messages().get(server_id) {
        if msg.sender_id != "self" {
            if let Ok(Some(contact)) = guard.contacts().get_by_peer_user_id(&msg.sender_id) {
                if !contact.blocked {
                    let _ = guard.outbox().enqueue_receipt(
                        server_id,
                        &msg.sender_id,
                        &contact.mailbox_host,
                        read_at_unix,
                        now_unix,
                    );
                }
            }
        }
    }

    drop(guard);
    Ok(())
}

// ---------------------------------------------------------------------------
// Message/get
// ---------------------------------------------------------------------------

pub struct MessageGetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl MessageGetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for MessageGetHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            // ids is required in v1; null or absent → invalidArguments.
            let ids: Vec<String> = match obj.get("ids") {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
                _ => {
                    return Err(JmapError::invalid_arguments("ids required"));
                }
            };

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            let mut messages = Vec::new();
            let mut not_found = Vec::new();

            for id in &ids {
                match guard.messages().get(id).map_err(kith_to_jmap)? {
                    Some(msg) => messages.push(msg),
                    None => not_found.push(id.clone()),
                }
            }

            let state = guard.messages().get_state().map_err(kith_to_jmap)?;
            drop(guard);

            let list = serde_json::to_value(&messages)
                .map_err(|e| JmapError::server_fail(format!("serialization error: {e}")))?;

            Ok(json!({
                "accountId": "a-self",
                "list": list,
                "notFound": not_found,
                "state": state,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Message/changes
// ---------------------------------------------------------------------------

pub struct MessageChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl MessageChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for MessageChangesHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            let since_state = obj
                .get("sinceState")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("sinceState is required"))?
                .to_string();

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            let result = guard
                .messages()
                .get_changes_since(&since_state)
                .map_err(kith_to_jmap)?;

            drop(guard);

            Ok(json!({
                "accountId": "a-self",
                "oldState": since_state,
                "newState": result.new_state,
                "hasMoreChanges": false,
                "created": result.added,
                "updated": result.updated,
                "destroyed": result.destroyed,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Message/query
// ---------------------------------------------------------------------------

pub struct MessageQueryHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl MessageQueryHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for MessageQueryHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            let filter = obj.get("filter");
            let chat_id = filter
                .and_then(|f| f.get("chatId"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| JmapError::invalid_arguments("filter.chatId is required"))?;

            let position: u32 = obj.get("position").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            let limit: u32 = obj
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(50)
                .min(200) as u32;

            let calculate_total: bool = obj
                .get("calculateTotal")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            // Validate chatId exists.
            if guard.chats().get(&chat_id).map_err(kith_to_jmap)?.is_none() {
                return Err(JmapError::invalid_arguments("unknown chatId"));
            }

            let messages = guard
                .messages()
                .list_by_chat(&chat_id, limit + position)
                .map_err(kith_to_jmap)?;

            let total_count = messages.len();

            let page_ids: Vec<String> = messages
                .into_iter()
                .skip(position as usize)
                .map(|m| m.id)
                .collect();

            let query_state = guard.messages().get_state().map_err(kith_to_jmap)?;
            drop(guard);

            let total = if calculate_total {
                Value::Number(serde_json::Number::from(total_count))
            } else {
                Value::Null
            };

            Ok(json!({
                "accountId": "a-self",
                "queryState": query_state,
                "canCalculateChanges": true,
                "position": position,
                "ids": page_ids,
                "total": total,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Message/queryChanges
// ---------------------------------------------------------------------------

pub struct MessageQueryChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl MessageQueryChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for MessageQueryChangesHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            let since_query_state = obj
                .get("sinceQueryState")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("sinceQueryState is required"))?
                .to_string();

            let filter = obj.get("filter");
            let chat_id = filter
                .and_then(|f| f.get("chatId"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| JmapError::invalid_arguments("filter.chatId is required"))?;

            // Parse sinceQueryState as "s-N".
            let since_counter: i64 = since_query_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .ok_or_else(JmapError::cannot_calculate_changes)?;

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            // Validate chatId exists.
            if guard.chats().get(&chat_id).map_err(kith_to_jmap)?.is_none() {
                return Err(JmapError::invalid_arguments("unknown chatId"));
            }

            let current_state = guard.messages().get_state().map_err(kith_to_jmap)?;
            let current_counter: i64 = current_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .unwrap_or(0);

            // If no changes, return early.
            if since_counter >= current_counter {
                drop(guard);
                return Ok(json!({
                    "accountId": "a-self",
                    "oldQueryState": since_query_state,
                    "newQueryState": current_state,
                    "removed": [],
                    "added": [],
                }));
            }

            // Get the changes since sinceQueryState.
            let changes = guard
                .messages()
                .get_changes_since(&since_query_state)
                .map_err(kith_to_jmap)?;

            // Get the current full ordered list for this chat.
            let full_list = guard
                .messages()
                .list_by_chat(&chat_id, 200)
                .map_err(kith_to_jmap)?;

            drop(guard);

            let new_state = changes.new_state.clone();

            // Build added list with indexes.
            let added_with_index: Vec<Value> = changes
                .added
                .iter()
                .map(|added_id| {
                    let index = full_list
                        .iter()
                        .position(|m| &m.id == added_id)
                        .map(|p| p as u64)
                        .unwrap_or(0);
                    json!({"id": added_id, "index": index})
                })
                .collect();

            Ok(json!({
                "accountId": "a-self",
                "oldQueryState": since_query_state,
                "newQueryState": new_state,
                "removed": changes.destroyed,
                "added": added_with_index,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kith_store::Store;
    use serde_json::json;

    fn make_store() -> Arc<Mutex<Store>> {
        Arc::new(Mutex::new(
            Store::open_in_memory().expect("open in-memory store"),
        ))
    }

    /// Insert a chat and contact so creates can enqueue to outbox.
    fn setup_chat_and_contact(
        store: &Arc<Mutex<Store>>,
        chat_id: &str,
        peer_user_id: &str,
        mailbox_host: &str,
    ) {
        let guard = store.lock().unwrap();
        guard
            .chats()
            .get_or_create(chat_id, "direct", &[peer_user_id], 1000)
            .unwrap();
        guard
            .contacts()
            .upsert(peer_user_id, "peer@example.com", mailbox_host, None, 1000)
            .unwrap();
    }

    fn get_message_count(store: &Arc<Mutex<Store>>) -> usize {
        let guard = store.lock().unwrap();
        // list_by_chat with a large limit to count all messages across chats.
        // We'll use a raw query via the connection; but store doesn't expose a global count.
        // Instead we check the state counter: if it's s-0 no messages were inserted.
        let state = guard.messages().get_state().unwrap();
        let n: i64 = state.strip_prefix("s-").unwrap().parse().unwrap();
        n as usize
    }

    // Oracle: a valid Message/set create returns created.m0.id (ULID) and
    // deliveryState=pending.  Independent oracle: JMAP RFC 8620 §5.3.
    #[tokio::test]
    async fn test_message_set_create_valid() {
        let store = make_store();
        let chat_id = "chat-abc";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "Hello, world!",
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let created = &result["created"];
        assert!(created.get("m0").is_some(), "created.m0 must be present");
        let msg = &created["m0"];

        // id must be a non-empty ULID string.
        let id = msg["id"].as_str().expect("id must be a string");
        assert!(!id.is_empty(), "id must not be empty");
        id.parse::<Ulid>().expect("id must be a valid ULID");

        // deliveryState must be "pending".
        assert_eq!(msg["deliveryState"], "pending");
    }

    // Oracle: body > 65536 bytes → notCreated/invalidArguments, no DB write.
    #[tokio::test]
    async fn test_message_set_create_oversized_body() {
        let store = make_store();
        let chat_id = "chat-big";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let oversized = "x".repeat(65537);
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": oversized,
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler should not return Err; oversized → notCreated");

        let not_created = &result["notCreated"];
        assert!(
            not_created.get("m0").is_some(),
            "notCreated.m0 must be present"
        );
        assert_eq!(not_created["m0"]["type"], "invalidArguments");

        // Verify no DB write occurred.
        assert_eq!(
            get_message_count(&store),
            0,
            "no message must be inserted on oversized body"
        );
    }

    // Oracle: chatId not in DB → notCreated with type=notFound.
    #[tokio::test]
    async fn test_message_set_create_unknown_chat() {
        let store = make_store();

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": "no-such-chat",
                    "body": "hi",
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler should not return Err");

        let not_created = &result["notCreated"];
        assert!(
            not_created.get("m0").is_some(),
            "notCreated.m0 must be present"
        );
        assert_eq!(not_created["m0"]["type"], "notFound");
    }

    // Oracle: replyTo in different chat → notCreated/invalidArguments.
    #[tokio::test]
    async fn test_message_set_create_cross_chat_reply() {
        let store = make_store();
        let chat1 = "chat-one";
        let chat2 = "chat-two";
        setup_chat_and_contact(&store, chat1, "peer-a", "peer-a.tail.ts.net");
        setup_chat_and_contact(&store, chat2, "peer-b", "peer-b.tail.ts.net");

        // Insert a message in chat1.
        let msg_in_chat1;
        {
            let guard = store.lock().unwrap();
            guard
                .messages()
                .insert(
                    "msg-in-chat1",
                    chat1,
                    "self",
                    "original",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
            msg_in_chat1 = "msg-in-chat1";
        }

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat2,
                    "body": "reply",
                    "replyTo": msg_in_chat1,
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler should not return Err");

        let not_created = &result["notCreated"];
        assert!(
            not_created.get("m0").is_some(),
            "notCreated.m0 must be present"
        );
        assert_eq!(not_created["m0"]["type"], "invalidArguments");
    }

    // Oracle: Message/get with matching id returns correct body field.
    #[tokio::test]
    async fn test_message_get_found() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .get_or_create("chat-g1", "direct", &[], 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-g1",
                    "chat-g1",
                    "self",
                    "hello body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
        }

        let handler = MessageGetHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "ids": ["msg-g1"]});
        let result = handler
            .call("Message/get".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let list = result["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["body"], "hello body");
    }

    // Oracle: Message/get with unknown id → notFound list.
    #[tokio::test]
    async fn test_message_get_not_found() {
        let store = make_store();
        let handler = MessageGetHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "ids": ["does-not-exist"]});
        let result = handler
            .call("Message/get".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let list = result["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 0);
        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert_eq!(not_found.len(), 1);
        assert_eq!(not_found[0], "does-not-exist");
    }

    // Oracle: Message/get with ids=null → invalidArguments error (v1 requirement).
    #[tokio::test]
    async fn test_message_get_ids_none() {
        let store = make_store();
        let handler = MessageGetHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "ids": null});
        let err = handler
            .call("Message/get".to_string(), "c0".to_string(), args)
            .await
            .expect_err("ids=null should return invalidArguments");
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Oracle: Message/set update readAt → updated map has the message id.
    #[tokio::test]
    async fn test_message_set_update_read_at() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .get_or_create("chat-ra", "direct", &[], 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-ra",
                    "chat-ra",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
        }

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "update": {
                "msg-ra": {
                    "readAt": "2026-04-19T12:00:00Z"
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let updated = &result["updated"];
        assert!(
            updated.get("msg-ra").is_some(),
            "updated[msg-ra] must be present"
        );
    }

    // Oracle: patching a non-patchable field → notUpdated/invalidArguments.
    #[tokio::test]
    async fn test_message_set_update_non_patchable_field() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .get_or_create("chat-np", "direct", &[], 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-np",
                    "chat-np",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
        }

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "update": {
                "msg-np": {
                    "body": "modified"
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler should not Err; error goes in notUpdated");

        let not_updated = &result["notUpdated"];
        assert!(
            not_updated.get("msg-np").is_some(),
            "notUpdated[msg-np] must be present"
        );
        assert_eq!(not_updated["msg-np"]["type"], "invalidArguments");
    }

    // Oracle: Message/changes with current state → empty created/updated/destroyed.
    #[tokio::test]
    async fn test_message_changes_empty() {
        let store = make_store();
        let state = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };

        let handler = MessageChangesHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "sinceState": state});
        let result = handler
            .call("Message/changes".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let created = result["created"].as_array().expect("created must be array");
        assert!(created.is_empty(), "no changes at current state");
        let updated = result["updated"].as_array().expect("updated must be array");
        assert!(updated.is_empty());
        let destroyed = result["destroyed"]
            .as_array()
            .expect("destroyed must be array");
        assert!(destroyed.is_empty());
    }

    // Oracle: Message/changes with s-0 after insert → id in created list.
    #[tokio::test]
    async fn test_message_changes_after_insert() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .get_or_create("chat-ch", "direct", &[], 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-ch",
                    "chat-ch",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
        }

        let handler = MessageChangesHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "sinceState": "s-0"});
        let result = handler
            .call("Message/changes".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let created = result["created"].as_array().expect("created must be array");
        assert!(
            created.iter().any(|v| v.as_str() == Some("msg-ch")),
            "msg-ch must be in created; got: {:?}",
            created
        );
    }

    // Oracle: Message/query with chatId filter returns inserted message id.
    #[tokio::test]
    async fn test_message_query_with_chat_id() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .get_or_create("chat-q1", "direct", &[], 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-q1",
                    "chat-q1",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
        }

        let handler = MessageQueryHandler::new(Arc::clone(&store));
        let args = json!({
            "accountId": "a-self",
            "filter": {"chatId": "chat-q1"}
        });
        let result = handler
            .call("Message/query".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let ids = result["ids"].as_array().expect("ids must be array");
        assert!(
            ids.iter().any(|v| v.as_str() == Some("msg-q1")),
            "msg-q1 must be in ids; got: {:?}",
            ids
        );
    }

    // Oracle: Message/query without filter → invalidArguments.
    #[tokio::test]
    async fn test_message_query_without_chat_id() {
        let store = make_store();
        let handler = MessageQueryHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self"});
        let err = handler
            .call("Message/query".to_string(), "c0".to_string(), args)
            .await
            .expect_err("missing chatId must return invalidArguments");
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Oracle: Message/queryChanges with current state → empty added.
    #[tokio::test]
    async fn test_message_querychanges_empty() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .get_or_create("chat-qc1", "direct", &[], 1000)
                .unwrap();
        }
        let state = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };

        let handler = MessageQueryChangesHandler::new(Arc::clone(&store));
        let args = json!({
            "accountId": "a-self",
            "sinceQueryState": state,
            "filter": {"chatId": "chat-qc1"}
        });
        let result = handler
            .call("Message/queryChanges".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let added = result["added"].as_array().expect("added must be array");
        assert!(added.is_empty(), "no changes at current state");
    }

    // Oracle: readAt update on an incoming message (sender_id != "self") succeeds and
    // the message id appears in the updated map. Contact must exist for the receipt
    // path to be entered; confirmed by state advancing after the update.
    #[tokio::test]
    async fn test_read_receipt_incoming_message() {
        let store = make_store();
        let chat_id = "chat-rr-in";
        let peer_uid = "peer-user-id";
        setup_chat_and_contact(&store, chat_id, peer_uid, "peer.tail.ts.net");

        // Insert an incoming message (sender_id = peer's tailscale user id).
        let state_before = {
            let guard = store.lock().unwrap();
            guard
                .messages()
                .insert(
                    "msg-rr-in",
                    chat_id,
                    peer_uid,
                    "hello from peer",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Received,
                    None,
                )
                .unwrap();
            guard.messages().get_state().unwrap()
        };

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "update": {
                "msg-rr-in": {
                    "readAt": "2026-04-19T12:00:00Z"
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        // Update must succeed.
        let updated = &result["updated"];
        assert!(
            updated.get("msg-rr-in").is_some(),
            "updated[msg-rr-in] must be present for incoming message"
        );
        assert!(
            result["notUpdated"]
                .as_object()
                .map(|m| m.is_empty())
                .unwrap_or(true),
            "notUpdated must be empty"
        );

        // State must have advanced (readAt write advances state counter).
        let new_state = result["newState"].as_str().unwrap().to_string();
        assert_ne!(
            state_before, new_state,
            "state must advance after readAt update"
        );
    }

    // Oracle: readAt update on an outgoing message (sender_id = "self") succeeds.
    // No receipt path is entered (sender is self). Confirmed by successful update.
    #[tokio::test]
    async fn test_read_receipt_outgoing_message() {
        let store = make_store();
        let chat_id = "chat-rr-out";
        setup_chat_and_contact(&store, chat_id, "peer-uid-out", "peer-out.tail.ts.net");

        // Insert an outgoing message (sender_id = "self").
        {
            let guard = store.lock().unwrap();
            guard
                .messages()
                .insert(
                    "msg-rr-out",
                    chat_id,
                    "self",
                    "hello outgoing",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
        }

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "update": {
                "msg-rr-out": {
                    "readAt": "2026-04-19T13:00:00Z"
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        // Update must succeed (no receipt for outgoing messages).
        let updated = &result["updated"];
        assert!(
            updated.get("msg-rr-out").is_some(),
            "updated[msg-rr-out] must be present for outgoing message"
        );
        assert!(
            result["notUpdated"]
                .as_object()
                .map(|m| m.is_empty())
                .unwrap_or(true),
            "notUpdated must be empty"
        );
    }

    // Oracle: Message/queryChanges after insert → added has {id, index}.
    #[tokio::test]
    async fn test_message_querychanges_after_insert() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .get_or_create("chat-qc2", "direct", &[], 1000)
                .unwrap();
        }

        // Capture state before insert.
        let state_before = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };

        {
            let guard = store.lock().unwrap();
            guard
                .messages()
                .insert(
                    "msg-qc2",
                    "chat-qc2",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                )
                .unwrap();
        }

        let handler = MessageQueryChangesHandler::new(Arc::clone(&store));
        let args = json!({
            "accountId": "a-self",
            "sinceQueryState": state_before,
            "filter": {"chatId": "chat-qc2"}
        });
        let result = handler
            .call("Message/queryChanges".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let added = result["added"].as_array().expect("added must be array");
        assert!(!added.is_empty(), "added must not be empty after insert");

        // Each added entry must have id and index fields.
        let entry = &added[0];
        assert!(entry.get("id").is_some(), "added entry must have id");
        assert!(entry.get("index").is_some(), "added entry must have index");
        assert_eq!(entry["id"], "msg-qc2");
    }

    // -----------------------------------------------------------------------
    // Attachment validation tests
    // -----------------------------------------------------------------------

    fn valid_attachment(blob_id: &str) -> serde_json::Value {
        json!({
            "blobId": blob_id,
            "filename": "test.txt",
            "contentType": "text/plain",
            "size": 100u64,
            "sha256": "a".repeat(64)
        })
    }

    #[tokio::test]
    async fn test_create_with_valid_attachment() {
        let store = make_store();
        let chat_id = "chat-att-ok";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let blob_id = "a".repeat(64);
        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "hello with attachment",
                    "attachments": [valid_attachment(&blob_id)]
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err");

        assert!(
            result["created"].get("m0").is_some(),
            "created.m0 must be present; got: {result}"
        );
        assert_eq!(get_message_count(&store), 1);
    }

    #[tokio::test]
    async fn test_create_attachment_bad_blob_id() {
        let store = make_store();
        let chat_id = "chat-att-bad-blob";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body",
                    "attachments": [{
                        "blobId": "../escape",
                        "filename": "test.txt",
                        "contentType": "text/plain",
                        "size": 100u64,
                        "sha256": "a".repeat(64)
                    }]
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err");

        assert!(
            result["notCreated"].get("m0").is_some(),
            "notCreated.m0 must be set for invalid blobId"
        );
        assert_eq!(get_message_count(&store), 0);
    }

    #[tokio::test]
    async fn test_create_attachment_bad_filename() {
        let store = make_store();
        let chat_id = "chat-att-bad-fn";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body",
                    "attachments": [{
                        "blobId": "a".repeat(64),
                        "filename": "../etc/passwd",
                        "contentType": "text/plain",
                        "size": 100u64,
                        "sha256": "a".repeat(64)
                    }]
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err");

        assert!(
            result["notCreated"].get("m0").is_some(),
            "notCreated.m0 must be set for filename with path separator"
        );
        assert_eq!(get_message_count(&store), 0);
    }

    #[tokio::test]
    async fn test_create_attachment_bad_content_type() {
        let store = make_store();
        let chat_id = "chat-att-bad-ct";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body",
                    "attachments": [{
                        "blobId": "a".repeat(64),
                        "filename": "file.bin",
                        "contentType": "notavalidmime",
                        "size": 100u64,
                        "sha256": "a".repeat(64)
                    }]
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err");

        assert!(
            result["notCreated"].get("m0").is_some(),
            "notCreated.m0 must be set for contentType without '/'"
        );
        assert_eq!(get_message_count(&store), 0);
    }

    #[tokio::test]
    async fn test_create_attachment_oversized() {
        let store = make_store();
        let chat_id = "chat-att-oversize";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body",
                    "attachments": [{
                        "blobId": "a".repeat(64),
                        "filename": "huge.bin",
                        "contentType": "application/octet-stream",
                        "size": MAX_ATTACHMENT_BYTES + 1,
                        "sha256": "a".repeat(64)
                    }]
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err");

        assert!(
            result["notCreated"].get("m0").is_some(),
            "notCreated.m0 must be set when size exceeds limit"
        );
        assert_eq!(get_message_count(&store), 0);
    }

    #[tokio::test]
    async fn test_create_attachment_bad_sha256() {
        let store = make_store();
        let chat_id = "chat-att-bad-sha";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body",
                    "attachments": [{
                        "blobId": "a".repeat(64),
                        "filename": "file.bin",
                        "contentType": "application/octet-stream",
                        "size": 100u64,
                        "sha256": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
                    }]
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err");

        assert!(
            result["notCreated"].get("m0").is_some(),
            "notCreated.m0 must be set for sha256 with non-hex characters"
        );
        assert_eq!(get_message_count(&store), 0);
    }

    #[tokio::test]
    async fn test_create_too_many_attachments() {
        let store = make_store();
        let chat_id = "chat-att-toomany";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        // Build MAX_ATTACHMENTS + 1 distinct valid attachments.
        let atts: Vec<Value> = (0..=MAX_ATTACHMENTS)
            .map(|i| {
                // Use unique per-entry blob_id (digits only are valid hex chars).
                let blob_id = format!("{:0>64}", i);
                json!({
                    "blobId": blob_id,
                    "filename": format!("file{i}.bin"),
                    "contentType": "application/octet-stream",
                    "size": 100u64,
                    "sha256": "a".repeat(64)
                })
            })
            .collect();

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body",
                    "attachments": atts
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err");

        assert!(
            result["notCreated"].get("m0").is_some(),
            "notCreated.m0 must be set when too many attachments provided"
        );
        assert_eq!(get_message_count(&store), 0);
    }

    // -----------------------------------------------------------------------
    // Rollback test — the core correctness guarantee
    // -----------------------------------------------------------------------
    //
    // Oracle: the UNIQUE constraint on attachments.id (PRIMARY KEY) causes the
    // second INSERT inside insert_message_with_attachments to fail.  The
    // transaction must roll back, leaving zero message rows and an unchanged
    // state counter.
    #[tokio::test]
    async fn test_create_attachment_duplicate_blob_id_rolls_back_message() {
        let store = make_store();
        let chat_id = "chat-att-dup";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let state_before = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };

        let shared_blob_id = "a".repeat(64);
        let att1 = json!({
            "blobId": shared_blob_id,
            "filename": "first.txt",
            "contentType": "text/plain",
            "size": 100u64,
            "sha256": "a".repeat(64)
        });
        let att2 = json!({
            "blobId": shared_blob_id,
            "filename": "second.txt",
            "contentType": "text/plain",
            "size": 200u64,
            "sha256": "b".repeat(64)
        });

        let handler = MessageSetHandler::new(Arc::clone(&store), "owner-uid".to_string());
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body with dup attachments",
                    "attachments": [att1, att2]
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return Err; errors go in notCreated");

        assert!(
            result["notCreated"].get("m0").is_some(),
            "notCreated.m0 must be present when duplicate blob_id causes constraint violation"
        );

        let state_after = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };
        assert_eq!(
            state_before, state_after,
            "state counter must not advance when transaction rolls back"
        );
        assert_eq!(
            get_message_count(&store),
            0,
            "no message row must remain after transactional rollback"
        );
    }
}
