// Message/get, Message/set, Message/changes, Message/query, Message/queryChanges handlers

use crate::kith_to_jmap;
use kith_attach::BlobStore;
use kith_core::{Attachment, JmapError, MAX_ATTACHMENT_BYTES, MAX_BODY_BYTES};
use kith_jmap::{HandlerFuture, JmapHandler};
use kith_store::OutboundMessageParams;
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

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

fn parse_attachments(
    obj: &serde_json::Map<String, Value>,
    blob_store: &BlobStore,
) -> Result<Vec<ParsedAttachment>, Value> {
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
        if !blob_store.blob_exists(&blob_id) {
            return Err(
                json!({"type": "invalidArguments", "description": format!("attachments[{i}].blobId: blob not found")}),
            );
        }
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
        if size == 0 || size > MAX_ATTACHMENT_BYTES as u64 {
            return Err(
                json!({"type": "invalidArguments", "description": format!("attachments[{i}].size must be between 1 and {MAX_ATTACHMENT_BYTES} bytes")}),
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
    blob_store: Arc<BlobStore>,
}

impl MessageSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>, blob_store: Arc<BlobStore>) -> Self {
        Self { store, blob_store }
    }
}

impl JmapHandler for MessageSetHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);
        let blob_store = Arc::clone(&self.blob_store);

        Box::pin(async move {
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
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

            // old_state is captured lazily: the first process_create or process_update
            // call captures it inside its own lock scope, before any DB write in that
            // call.  This prevents a concurrent Peer/deliver from slipping in between
            // a separate pre-loop lock scope and the first create, which would make
            // oldState describe a state before that concurrent write (RFC 8620 §5.3).
            let mut old_state_cell: Option<String> = None;

            // Process creates.
            if let Some(creates) = create_map {
                for (client_id, value) in creates {
                    match process_create(
                        &store,
                        &blob_store,
                        client_id,
                        value,
                        now_unix,
                        &mut old_state_cell,
                    ) {
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
                    match process_update(&store, server_id, patch, now_unix, &mut old_state_cell) {
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

            // Resolve old_state: if at least one create/update ran, it was captured
            // inside the first lock scope.  If no creates or updates ran, capture now.
            let old_state = match old_state_cell {
                Some(s) => s,
                None => {
                    let guard = store
                        .lock()
                        .map_err(|_| JmapError::server_fail("internal error"))?;
                    guard.messages().get_state().map_err(kith_to_jmap)?
                }
            };

            let new_state = {
                let guard = store
                    .lock()
                    .map_err(|_| JmapError::server_fail("internal error"))?;
                guard.messages().get_state().map_err(kith_to_jmap)?
            };

            Ok(json!({
                "accountId": "a-self",
                "oldState": old_state,
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
    blob_store: &BlobStore,
    _client_id: &str,
    value: &Value,
    now_unix: i64,
    old_state_out: &mut Option<String>,
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
    if body.is_empty() {
        return Err(json!({
            "type": "invalidProperties",
            "description": "body must not be empty",
            "properties": ["body"]
        }));
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(json!({"type": "invalidArguments", "description": "body too long"}));
    }

    // Validate bodyType.
    if !SUPPORTED_BODY_TYPES.contains(&body_type.as_str()) {
        return Err(json!({"type": "invalidArguments", "description": "unsupported bodyType"}));
    }

    // Parse and validate attachments BEFORE acquiring the store lock.
    let attachments = parse_attachments(obj, blob_store)?;

    // Acquire the store lock for all DB operations.
    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "internal error"}))?;

    // Capture old_state on the first call, inside the lock, before any DB write.
    if old_state_out.is_none() {
        *old_state_out = Some(
            guard
                .messages()
                .get_state()
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?,
        );
    }

    // Validate chatId exists.
    let chat = guard
        .chats()
        .get(&chat_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?
        .ok_or_else(|| json!({"type": "notFound", "description": "chatId not found"}))?;

    // Validate replyTo if present.
    if let Some(ref reply_id) = reply_to {
        // Validates existence and same-chat membership but does NOT walk the
        // chain to detect cycles (A→B→A).  SQLite has no referential-cycle
        // constraint, so a pair of colluding clients could construct one.
        // Phase 1 clients must cap reply-chain traversal depth to avoid an
        // infinite loop on malformed data.  Cycle detection is deferred to
        // Phase 2 when a recursive UI is introduced.
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

    // Build the outbox peer list BEFORE inserting the message so we can fail
    // early on missing hosts without leaving a Pending message with no outbox
    // entry.  The message insert and all outbox inserts are then committed
    // atomically inside insert_outbound_message.
    let mut outbox_peers: Vec<(String, String)> = Vec::new();
    if let Some(peer_id) = &chat.contact_id {
        // Direct chat: single peer via contact_id.
        let host = guard
            .contacts()
            .get_mailbox_host(peer_id)
            .map_err(|e| json!({"type": "serverFail", "description": format!("could not look up mailbox host: {e}")}))?
            .ok_or_else(|| json!({"type": "serverFail", "description": "contact has no mailbox host — add the contact before sending"}))?;
        outbox_peers.push((peer_id.clone(), host));
    } else if chat.kind == "group" {
        // Group chat: fan out to all members in chat_members.
        // Policy: all-or-nothing.  If any member has no mailbox host the
        // entire send fails with serverFail.  Best-effort fan-out (silently
        // skipping members with no host) is worse: the sender believes the
        // message reached everyone when some members never see it.  A hard
        // failure with a specific peer_id in the error tells the sender
        // exactly which contact record needs fixing.
        let members = guard
            .chats()
            .get_members(&chat_id)
            .map_err(|e| json!({"type": "serverFail", "description": format!("could not fetch group members: {e}")}))?;
        for peer_id in members {
            let host = guard
                .contacts()
                .get_mailbox_host(&peer_id)
                .map_err(|e| json!({"type": "serverFail", "description": format!("could not look up mailbox host for {peer_id}: {e}")}))?
                .ok_or_else(|| json!({"type": "serverFail", "description": format!("group member {peer_id} has no mailbox host — update the contact before sending")}))?;
            outbox_peers.push((peer_id, host));
        }
    }

    // Reject sends with no delivery target.  An empty outbox_peers would
    // store the message as 'pending' forever with no outbox row — the retry
    // loop never fires and the caller gets no error.  The only way to reach
    // this for a direct chat is if the host lookup above already failed (and
    // returned an error), so in practice this guard fires only for a group
    // chat that has no members in chat_members yet.
    if outbox_peers.is_empty() {
        return Err(json!({
            "type": "serverFail",
            "description": "no delivery targets — add members to the group before sending"
        }));
    }

    // Insert message, attachments, and outbox entries atomically.
    // A failure in any of these rolls back the whole transaction — no Pending
    // message with missing outbox entries is ever left in the database.
    let peer_refs: Vec<(&str, &str)> = outbox_peers
        .iter()
        .map(|(p, h)| (p.as_str(), h.as_str()))
        .collect();
    guard
        .insert_outbound_message(&OutboundMessageParams {
            id: &msg_id,
            chat_id: &chat_id,
            body: &body,
            body_type: &body_type,
            sent_at_peer: sent_at.as_deref(),
            created_at_unix: now_unix,
            reply_to: reply_to.as_deref(),
            attachments: &core_attachments,
            outbox_peers: &peer_refs,
        })
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Update last_message_at on the chat (best-effort cache; not part of the
    // delivery transaction — a failure here does not un-deliver the message,
    // and must not cause notCreated when the message was already committed).
    if let Err(e) = guard.chats().update_last_message_at(&chat_id, now_unix) {
        tracing::warn!("update_last_message_at failed: {e}");
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
    old_state_out: &mut Option<String>,
) -> Result<(), Value> {
    let patch_obj = patch.as_object().ok_or_else(
        || json!({"type": "invalidArguments", "description": "update patch must be an object"}),
    )?;

    // Only readAt is patchable.
    for key in patch_obj.keys() {
        if key != "readAt" {
            return Err(
                json!({"type": "invalidProperties", "description": "only readAt is patchable", "properties": [key]}),
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
    let read_at_unix_raw: i64 = chrono::DateTime::parse_from_rfc3339(read_at_str)
        .map(|dt| dt.timestamp())
        .map_err(
            |_| json!({"type": "invalidArguments", "description": "readAt must be RFC 3339"}),
        )?;

    // Reject epoch-0 or negative timestamps — these cannot represent a real
    // read event and would corrupt unread-message display.
    if read_at_unix_raw <= 0 {
        return Err(
            json!({"type": "invalidArguments", "description": "readAt must be after epoch"}),
        );
    }

    // Clamp readAt to the current time as an upper bound.  A far-future value
    // (e.g. 2099-01-01) cannot represent a real read event and would corrupt
    // UI sort order.  We allow up to 60 seconds in the future to tolerate minor
    // clock skew between the client and the server.
    let read_at_unix = read_at_unix_raw.min(now_unix + 60);

    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "internal error"}))?;

    // Capture old_state on the first call, inside the lock, before any DB write.
    if old_state_out.is_none() {
        *old_state_out = Some(
            guard
                .messages()
                .get_state()
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?,
        );
    }

    // Check the message exists before writing (RFC 8620 §5.3: notFound).
    match guard.messages().get(server_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(
                json!({"type": "notFound", "description": format!("message {server_id} not found")}),
            );
        }
        Err(e) => return Err(json!({"type": "serverFail", "description": e.to_string()})),
    }

    guard
        .messages()
        .update_read_at(server_id, read_at_unix)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Enqueue a read receipt to the original sender for inbound messages.
    // Failures are silently ignored — receipt enqueue must not fail the readAt update.
    if let Ok(Some(msg)) = guard.messages().get(server_id) {
        if msg.sender_id != "self" {
            // Intentional: receipts are not sent to blocked senders. Marking a blocked
            // contact's message as read is a local-only operation.
            if let Ok(true) = guard.contacts().is_permitted(&msg.sender_id) {
                if let Ok(Some(host)) = guard.contacts().get_mailbox_host(&msg.sender_id) {
                    let _ = guard.outbox().enqueue_receipt(
                        server_id,
                        &msg.sender_id,
                        &host,
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
                return Err(JmapError::account_not_found());
            }

            // ids is required in v1; null or absent → invalidArguments.
            let ids: Vec<String> = match obj.get("ids") {
                Some(Value::Array(arr)) => {
                    let mut v = Vec::with_capacity(arr.len());
                    for item in arr {
                        match item.as_str() {
                            Some(s) => v.push(s.to_string()),
                            None => {
                                return Err(JmapError::invalid_arguments(
                                    "ids must be an array of strings",
                                ))
                            }
                        }
                    }
                    v
                }
                _ => {
                    return Err(JmapError::invalid_arguments("ids required"));
                }
            };

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

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
                return Err(JmapError::account_not_found());
            }

            let since_state = obj
                .get("sinceState")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("sinceState is required"))?
                .to_string();

            // RFC 8620 §5.6: maxChanges=0 must return invalidArguments.
            let max_changes: Option<usize> = match obj.get("maxChanges") {
                None => None,
                Some(v) => {
                    let n = v.as_u64().ok_or_else(|| {
                        JmapError::invalid_arguments("maxChanges must be a positive integer")
                    })?;
                    if n == 0 {
                        return Err(JmapError::invalid_arguments(
                            "maxChanges must not be 0 (RFC 8620 §5.6)",
                        ));
                    }
                    Some(n as usize)
                }
            };

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            let (rows, current_state) = guard
                .messages()
                .get_changes_since_ordered(&since_state)
                .map_err(kith_to_jmap)?;

            drop(guard);

            let total = rows.len();
            let (items, has_more, new_state) = if let Some(max) = max_changes {
                if total > max {
                    let truncated = &rows[..max];
                    let new_state = truncated.last().map(|(_, v, _)| format!("s-{v}")).expect(
                        "truncated slice is non-empty: max>=1 invariant established at parse time",
                    );
                    (truncated.to_vec(), true, new_state)
                } else {
                    (rows, false, current_state)
                }
            } else {
                (rows, false, current_state)
            };

            // RFC 8620 §5.2: separate created IDs from updated IDs.
            // is_create=true  → message was inserted after sinceState → "created" list
            // is_create=false → message existed before sinceState → "updated" map (null patch)
            let mut created: Vec<Value> = Vec::new();
            let mut updated: Vec<Value> = Vec::new();
            for (id, _, is_create) in items {
                if is_create {
                    created.push(Value::String(id));
                } else {
                    updated.push(Value::String(id));
                }
            }

            Ok(json!({
                "accountId": "a-self",
                "oldState": since_state,
                "newState": new_state,
                "hasMoreChanges": has_more,
                "created": created,
                "updated": updated,
                "destroyed": [],
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
                return Err(JmapError::account_not_found());
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
                .min(500) as u32;

            let calculate_total: bool = obj
                .get("calculateTotal")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            // Validate chatId exists.
            if guard.chats().get(&chat_id).map_err(kith_to_jmap)?.is_none() {
                return Err(JmapError::invalid_arguments("unknown chatId"));
            }

            let page_messages = guard
                .messages()
                .list_by_chat_paged(&chat_id, limit, position)
                .map_err(kith_to_jmap)?;

            let page_ids: Vec<String> = page_messages.into_iter().map(|m| m.id).collect();

            let total_count = if calculate_total {
                guard
                    .messages()
                    .count_by_chat(&chat_id)
                    .map_err(kith_to_jmap)?
            } else {
                0
            };

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
                return Err(JmapError::account_not_found());
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

            // RFC 8620 §5.6: maxChanges=0 must return invalidArguments.
            let max_changes: Option<usize> = match obj.get("maxChanges") {
                None => None,
                Some(v) => {
                    let n = v.as_u64().ok_or_else(|| {
                        JmapError::invalid_arguments("maxChanges must be a positive integer")
                    })?;
                    if n == 0 {
                        return Err(JmapError::invalid_arguments(
                            "maxChanges must not be 0 (RFC 8620 §5.6)",
                        ));
                    }
                    Some(n as usize)
                }
            };

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            if guard.chats().get(&chat_id).map_err(kith_to_jmap)?.is_none() {
                return Err(JmapError::invalid_arguments("unknown chatId"));
            }

            // Single query: bulk-fetch new messages with pre-computed position indices.
            // Avoids N+1 round trips to get_position_in_chat.
            let (added_pairs, has_more, new_query_state) = guard
                .messages()
                .get_querychanges_since_for_chat(&since_query_state, &chat_id, max_changes)
                .map_err(kith_to_jmap)?;

            drop(guard);

            let added_with_index: Vec<Value> = added_pairs
                .into_iter()
                .map(|(id, index)| json!({"id": id, "index": index}))
                .collect();

            Ok(json!({
                "accountId": "a-self",
                "oldQueryState": since_query_state,
                "newQueryState": new_query_state,
                "hasMoreChanges": has_more,
                "removed": [],
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
    use kith_core::DeliveryState;
    use kith_store::Store;
    use serde_json::json;

    fn make_store() -> Arc<Mutex<Store>> {
        Arc::new(Mutex::new(
            Store::open_in_memory().expect("open in-memory store"),
        ))
    }

    /// Return a BlobStore backed by a unique temporary directory.
    ///
    /// Returns `(Arc<BlobStore>, tempfile::TempDir)`.  The caller must hold the
    /// `TempDir` guard for the duration of the test; dropping it removes the
    /// directory from disk.
    fn make_blob_store() -> (Arc<BlobStore>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("TempDir::new must succeed");
        let bs = BlobStore::new(dir.path());
        bs.init().expect("blob store init must succeed");
        (Arc::new(bs), dir)
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
            .create(chat_id, "direct", Some(peer_user_id), 1000)
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

    // Oracle: RFC 8620 §5.3 — empty body is rejected before any DB write.
    // The error type is invalidProperties (per-object SetError) with properties=["body"].
    #[tokio::test]
    async fn test_message_set_create_empty_body() {
        let store = make_store();
        let chat_id = "chat-empty-body";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "",
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler should not Err; empty body → notCreated");

        let not_created = &result["notCreated"];
        assert!(
            not_created.get("m0").is_some(),
            "notCreated.m0 must be present; got: {result}"
        );
        // Oracle: error type must be invalidProperties (per-object SetError).
        assert_eq!(
            not_created["m0"]["type"], "invalidProperties",
            "empty body must yield invalidProperties; got: {not_created}"
        );
        // Oracle: properties list must call out "body".
        let props = not_created["m0"]["properties"]
            .as_array()
            .expect("properties must be an array");
        assert!(
            props.iter().any(|v| v == "body"),
            "properties must include \"body\"; got: {props:?}"
        );
        // Oracle: no DB write occurred.
        assert_eq!(
            get_message_count(&store),
            0,
            "no message must be inserted on empty body"
        );
    }

    // Oracle: chatId not in DB → notCreated with type=notFound.
    #[tokio::test]
    async fn test_message_set_create_unknown_chat() {
        let store = make_store();

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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
                    "msg-in-chat1",
                )
                .unwrap();
            msg_in_chat1 = "msg-in-chat1";
        }

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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
                .create("chat-g1", "direct", None, 1000)
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
                    "msg-g1",
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
                .create("chat-ra", "direct", None, 1000)
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
                    "msg-ra",
                )
                .unwrap();
        }

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

    // Oracle: readAt far in the future (2099-01-01) is clamped to approximately now.
    // The oracle value "2099-01-01T00:00:00Z" is known a priori (independent of the
    // code under test). After the update the stored readAt must be in the current year,
    // not 2099 — confirming the `min(now_unix + 60)` clamp is applied.
    #[tokio::test]
    async fn test_message_set_update_read_at_far_future_clamped() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-clamp", "direct", None, 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-clamp",
                    "chat-clamp",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                    "msg-clamp",
                )
                .unwrap();
        }

        // Submit a readAt that is clearly in the far future (year 2099).
        let (blob_store, _blob_dir) = make_blob_store();
        let set_handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
        let set_args = json!({
            "accountId": "a-self",
            "update": {
                "msg-clamp": {
                    "readAt": "2099-01-01T00:00:00Z"
                }
            }
        });
        let set_result = set_handler
            .call("Message/set".to_string(), "c0".to_string(), set_args)
            .await
            .expect("should succeed");

        // Update must succeed — clamping is silent, not an error.
        assert!(
            set_result["updated"].get("msg-clamp").is_some(),
            "updated[msg-clamp] must be present: {set_result:?}"
        );

        // Retrieve the stored readAt via Message/get.
        let get_handler = MessageGetHandler::new(Arc::clone(&store));
        let get_args = json!({
            "accountId": "a-self",
            "ids": ["msg-clamp"]
        });
        let get_result = get_handler
            .call("Message/get".to_string(), "c1".to_string(), get_args)
            .await
            .expect("get should succeed");

        let msg = &get_result["list"][0];
        let stored_read_at = msg["readAt"]
            .as_str()
            .expect("readAt must be a string after update");

        // Oracle: the stored readAt must not be in year 2099.  The clamp caps it at
        // now+60 s; the current year when this test runs is at most a few years past
        // 2026, so the year prefix "2099" is a reliable sentinel.
        assert!(
            !stored_read_at.starts_with("2099"),
            "far-future readAt must be clamped: got {stored_read_at}"
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
                .create("chat-np", "direct", None, 1000)
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
                    "msg-np",
                )
                .unwrap();
        }

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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
        assert_eq!(not_updated["msg-np"]["type"], "invalidProperties");
    }

    // Oracle: Message/set update targeting a nonexistent message ID → notUpdated/notFound.
    // RFC 8620 §5.3: unknown ID in update must yield notFound, not serverFail.
    #[tokio::test]
    async fn test_message_set_update_nonexistent_id_returns_not_found() {
        let store = make_store();

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
        let args = json!({
            "accountId": "a-self",
            "update": {
                "no-such-message": {
                    "readAt": "2026-04-19T12:00:00Z"
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler should not Err; error goes in notUpdated");

        let not_updated = &result["notUpdated"];
        assert!(
            not_updated.get("no-such-message").is_some(),
            "notUpdated[no-such-message] must be present; got: {result:?}"
        );
        assert_eq!(
            not_updated["no-such-message"]["type"], "notFound",
            "nonexistent message must yield notFound; got: {result:?}"
        );
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
        // updated is RFC 8620 §5.2 Id[] array.
        let updated = result["updated"].as_array().expect("updated must be array");
        assert!(updated.is_empty(), "no updates at current state");
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
                .create("chat-ch", "direct", None, 1000)
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
                    "msg-ch",
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

    // Oracle: RFC 8620 §5.2 — an updated message (readAt set after creation) must appear
    // in "updated" (not "created") when sinceState is before the update but after creation.
    #[tokio::test]
    async fn test_message_changes_updated_not_created_on_read_at_change() {
        let store = make_store();
        let state_after_insert = {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-rfc52", "direct", None, 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-rfc52",
                    "chat-rfc52",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                    "msg-rfc52",
                )
                .unwrap();
            guard.messages().get_state().unwrap()
        };

        // Now update the message's readAt.
        {
            let guard = store.lock().unwrap();
            guard.messages().update_read_at("msg-rfc52", 2000).unwrap();
        }

        // Message/changes from the state AFTER insert but BEFORE update:
        // the message was created before sinceState, so it must be in "updated".
        let handler = MessageChangesHandler::new(Arc::clone(&store));
        let args = json!({
            "accountId": "a-self",
            "sinceState": state_after_insert,
        });
        let result = handler
            .call("Message/changes".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let created = result["created"].as_array().expect("created must be array");
        assert!(
            !created.iter().any(|v| v.as_str() == Some("msg-rfc52")),
            "msg-rfc52 must NOT be in created (it existed before sinceState); got: {result:?}"
        );
        let updated = result["updated"].as_array().expect("updated must be array");
        assert!(
            updated.iter().any(|v| v.as_str() == Some("msg-rfc52")),
            "msg-rfc52 must be in updated (it was modified after sinceState); got: {result:?}"
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
                .create("chat-q1", "direct", None, 1000)
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
                    "msg-q1",
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

    // Oracle: RFC 8620 §5.6 — maxChanges=0 must return invalidArguments.
    #[tokio::test]
    async fn test_message_changes_max_changes_zero_returns_invalid_arguments() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-mc0", "direct", None, 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-mc0",
                    "chat-mc0",
                    "self",
                    "body",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                    "msg-mc0",
                )
                .unwrap();
        }
        let handler = MessageChangesHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "sinceState": "s-0", "maxChanges": 0});
        let result = handler
            .call("Message/changes".to_string(), "c0".to_string(), args)
            .await;
        assert!(
            result.is_err(),
            "maxChanges=0 must return Err(invalidArguments); got Ok: {:?}",
            result
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.error_type, "invalidArguments",
            "error type must be invalidArguments; got: {:?}",
            err
        );
    }

    // Oracle: RFC 8620 §5.6 — maxChanges truncation: newState must be the last returned
    // item's state_version, not the current store state, so the client can page forward.
    #[tokio::test]
    async fn test_message_changes_max_changes_truncation() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-mct", "direct", None, 1000)
                .unwrap();
            for i in 0..3u32 {
                guard
                    .messages()
                    .insert(
                        &format!("msg-mct-{i}"),
                        "chat-mct",
                        "self",
                        "body",
                        "text/plain",
                        None,
                        1000,
                        &DeliveryState::Pending,
                        None,
                        &format!("msg-mct-{i}"),
                    )
                    .unwrap();
            }
        }
        let handler = MessageChangesHandler::new(Arc::clone(&store));
        // Page 1: maxChanges=1 from s-0 → 1 message, hasMoreChanges=true.
        let args1 = json!({"accountId": "a-self", "sinceState": "s-0", "maxChanges": 1});
        let r1 = handler
            .call("Message/changes".to_string(), "c0".to_string(), args1)
            .await
            .expect("page 1 must succeed");
        assert_eq!(
            r1["hasMoreChanges"], true,
            "hasMoreChanges must be true; got: {r1}"
        );
        let c1 = r1["created"].as_array().expect("created must be array");
        assert_eq!(c1.len(), 1, "must return exactly 1 item; got: {r1}");
        let state1 = r1["newState"]
            .as_str()
            .expect("newState must be string")
            .to_string();

        // Page 2: from state1 → 1 more, hasMoreChanges=true.
        let args2 = json!({"accountId": "a-self", "sinceState": state1, "maxChanges": 1});
        let r2 = handler
            .call("Message/changes".to_string(), "c1".to_string(), args2)
            .await
            .expect("page 2 must succeed");
        assert_eq!(
            r2["hasMoreChanges"], true,
            "page 2 hasMoreChanges must be true; got: {r2}"
        );
        let c2 = r2["created"].as_array().expect("created must be array");
        assert_eq!(c2.len(), 1, "page 2 must return exactly 1 item; got: {r2}");
        let state2 = r2["newState"]
            .as_str()
            .expect("newState must be string")
            .to_string();

        // Page 3: from state2 → last item, hasMoreChanges=false.
        let args3 = json!({"accountId": "a-self", "sinceState": state2, "maxChanges": 1});
        let r3 = handler
            .call("Message/changes".to_string(), "c2".to_string(), args3)
            .await
            .expect("page 3 must succeed");
        assert_eq!(
            r3["hasMoreChanges"], false,
            "page 3 hasMoreChanges must be false; got: {r3}"
        );
        let c3 = r3["created"].as_array().expect("created must be array");
        assert_eq!(c3.len(), 1, "page 3 must return exactly 1 item; got: {r3}");

        // All 3 messages must be covered across the 3 pages.
        let all_ids: Vec<String> = [&c1[..], &c2[..], &c3[..]]
            .concat()
            .iter()
            .map(|v| v.as_str().expect("id must be string").to_string())
            .collect();
        let mut sorted = all_ids.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            ["msg-mct-0", "msg-mct-1", "msg-mct-2"],
            "all 3 messages must be returned across pages; got: {all_ids:?}"
        );
    }

    // Oracle: Message/queryChanges with current state → empty added.
    #[tokio::test]
    async fn test_message_querychanges_empty() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-qc1", "direct", None, 1000)
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

    // Oracle: Message/queryChanges maxChanges=0 → invalidArguments (RFC 8620 §5.6).
    #[tokio::test]
    async fn test_querychanges_max_changes_zero_returns_invalid_arguments() {
        let store = make_store();
        let handler = MessageQueryChangesHandler::new(Arc::clone(&store));
        let args = json!({
            "accountId": "a-self",
            "sinceQueryState": "s-0",
            "filter": {"chatId": "chat-any"},
            "maxChanges": 0,
        });
        let err = handler
            .call("Message/queryChanges".to_string(), "c0".to_string(), args)
            .await
            .expect_err("maxChanges=0 must return error");
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Oracle: Message/queryChanges with maxChanges=1 and 3 new messages →
    // hasMoreChanges=true, 1 entry returned; subsequent page returns remaining.
    #[tokio::test]
    async fn test_querychanges_max_changes_truncation() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-qct", "direct", None, 1000)
                .unwrap();
            for i in 0..3u32 {
                guard
                    .messages()
                    .insert(
                        &format!("msg-qct-{i}"),
                        "chat-qct",
                        "self",
                        "body",
                        "text/plain",
                        None,
                        1000 + i as i64,
                        &DeliveryState::Pending,
                        None,
                        &format!("msg-qct-{i}"),
                    )
                    .unwrap();
            }
        }
        let handler = MessageQueryChangesHandler::new(Arc::clone(&store));

        // Page 1: maxChanges=1 from s-0 → 1 entry, hasMoreChanges=true.
        let r1 = handler
            .call(
                "Message/queryChanges".to_string(),
                "c0".to_string(),
                json!({"accountId":"a-self","sinceQueryState":"s-0","filter":{"chatId":"chat-qct"},"maxChanges":1}),
            )
            .await
            .expect("page 1 must succeed");
        assert_eq!(
            r1["hasMoreChanges"], true,
            "page 1 hasMoreChanges; got {r1:?}"
        );
        assert_eq!(
            r1["added"].as_array().unwrap().len(),
            1,
            "page 1 must have 1 entry; got {r1:?}"
        );
        let state1 = r1["newQueryState"].as_str().unwrap().to_string();

        // Page 2: from state1 → 1 more entry.
        let r2 = handler
            .call(
                "Message/queryChanges".to_string(),
                "c1".to_string(),
                json!({"accountId":"a-self","sinceQueryState":state1,"filter":{"chatId":"chat-qct"},"maxChanges":1}),
            )
            .await
            .expect("page 2 must succeed");
        assert_eq!(
            r2["hasMoreChanges"], true,
            "page 2 hasMoreChanges; got {r2:?}"
        );
        let state2 = r2["newQueryState"].as_str().unwrap().to_string();

        // Page 3: last item, hasMoreChanges=false.
        let r3 = handler
            .call(
                "Message/queryChanges".to_string(),
                "c2".to_string(),
                json!({"accountId":"a-self","sinceQueryState":state2,"filter":{"chatId":"chat-qct"},"maxChanges":1}),
            )
            .await
            .expect("page 3 must succeed");
        assert_eq!(
            r3["hasMoreChanges"], false,
            "page 3 must have no more; got {r3:?}"
        );
        assert_eq!(r3["added"].as_array().unwrap().len(), 1);
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
                    "msg-rr-in",
                )
                .unwrap();
            guard.messages().get_state().unwrap()
        };

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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
                    "msg-rr-out",
                )
                .unwrap();
        }

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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
                .create("chat-qc2", "direct", None, 1000)
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
                    "msg-qc2",
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

        // Write the blob to the store so the existence check passes.
        let (blob_store, _blob_dir) = make_blob_store();
        let blob_id = "a".repeat(64);
        blob_store
            .write_blob(&blob_id, b"fake attachment content")
            .await
            .expect("write_blob must succeed");
        let handler = MessageSetHandler::new(Arc::clone(&store), Arc::clone(&blob_store));
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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
    async fn test_create_attachment_zero_size() {
        let store = make_store();
        let chat_id = "chat-att-zero-sz";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
        let args = json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "body",
                    "attachments": [{
                        "blobId": "a".repeat(64),
                        "filename": "empty.bin",
                        "contentType": "application/octet-stream",
                        "size": 0u64,
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
            "notCreated.m0 must be set when size is zero"
        );
        assert_eq!(get_message_count(&store), 0);
    }

    #[tokio::test]
    async fn test_create_attachment_oversized() {
        let store = make_store();
        let chat_id = "chat-att-oversize";
        setup_chat_and_contact(&store, chat_id, "peer-uid", "peer.tail.ts.net");

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
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

    // Oracle: Message/set create to a group chat where a member has no mailbox
    // host must return notCreated/serverFail AND leave no message row in the DB.
    //
    // The host lookup now happens BEFORE insert_outbound_message is called, so
    // the failure fires before any INSERT — no partial state is left.
    //
    // Independent oracle: the message state counter must be unchanged, proving
    // no message row was committed.
    //
    // The store-error path for get_members/enqueue cannot be injected via
    // in-memory SQLite without additional plumbing, so that path is left to
    // integration tests.
    #[tokio::test]
    async fn test_group_chat_member_missing_host_returns_server_fail() {
        let store = make_store();
        let chat_id = "group-chat-no-host";
        let member_with_host = "uid-alice";
        let member_without_host = "uid-bob";

        {
            let guard = store.lock().unwrap();
            // Group chat: contact_id = None, kind = "group".
            guard.chats().create(chat_id, "group", None, 1000).unwrap();
            guard.chats().add_member(chat_id, member_with_host).unwrap();
            guard
                .chats()
                .add_member(chat_id, member_without_host)
                .unwrap();
            // Alice has a mailbox host; Bob does not appear in contacts at all.
            guard
                .contacts()
                .upsert(
                    member_with_host,
                    "alice@example.com",
                    "alice.tail.ts.net",
                    None,
                    1000,
                )
                .unwrap();
            // Bob is in chat_members but NOT in contacts → get_mailbox_host returns Ok(None).
        }

        let state_before = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
        let result = handler
            .call(
                "Message/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "m0": {
                            "chatId": chat_id,
                            "body": "hello group",
                        }
                    }
                }),
            )
            .await
            .expect("handler must not return Err; errors go in notCreated");

        // Oracle: must appear in notCreated with serverFail.
        // This is the primary invariant: the CALLER must learn that delivery
        // failed, not silently believe the message was sent.
        let not_created = result["notCreated"]
            .as_object()
            .expect("notCreated must be an object");
        assert!(
            not_created.contains_key("m0"),
            "group message with member missing host must be notCreated; got: {result:?}"
        );
        assert_eq!(
            not_created["m0"]["type"], "serverFail",
            "error type must be serverFail; got: {:?}",
            not_created["m0"]
        );

        // Confirm created is empty — the message must not appear as a success.
        let created = result["created"]
            .as_object()
            .expect("created must be an object");
        assert!(
            !created.contains_key("m0"),
            "group message with member missing host must NOT appear in created; got: {result:?}"
        );

        // Oracle: state counter must be unchanged — the host-lookup failure fires
        // before insert_outbound_message is called, so no message row is committed.
        let state_after = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };
        assert_eq!(
            state_before, state_after,
            "state counter must not advance: failure must occur before any INSERT"
        );
    }

    // Oracle: queryChanges position indices are correct for chats with > 200
    // messages.  list_by_chat previously capped at 200 rows; messages with
    // created_at rank >= 200 (oldest messages in newest-first order) would not
    // appear in the reference list, so position() returned None and the index
    // fell back to 0 — wrong.
    //
    // Independent oracle: with 205 messages inserted with created_at=1..=205,
    // list_by_chat returns newest first: msg-205 at index 0, msg-1 at index 204.
    // The oldest message must therefore appear at index 204 in the queryChanges
    // added list.  If the cap were still 200, the oldest 5 messages would be
    // absent from the reference list and their index would be 0 (the None
    // fallback), not 204.
    #[tokio::test]
    async fn test_message_querychanges_index_beyond_200() {
        let store = make_store();

        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-pos205", "direct", None, 1000)
                .unwrap();
        }

        // Capture state before any inserts (sinceQueryState for the full scan).
        let state_before = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };
        assert_eq!(state_before, "s-0", "precondition: empty store");

        // Insert 205 messages with strictly increasing created_at timestamps
        // so oldest = created_at 1, newest = created_at 205.
        // Message ID encodes its position: msg-qc-pos-001 .. msg-qc-pos-205.
        {
            let guard = store.lock().unwrap();
            for i in 1u32..=205 {
                let id = format!("msg-qc-pos-{i:03}");
                guard
                    .messages()
                    .insert(
                        &id,
                        "chat-pos205",
                        "self",
                        "body",
                        "text/plain",
                        None,
                        i as i64,
                        &DeliveryState::Pending,
                        None,
                        &id,
                    )
                    .unwrap_or_else(|e| panic!("insert {id} failed: {e}"));
            }
        }

        let handler = MessageQueryChangesHandler::new(Arc::clone(&store));
        let args = serde_json::json!({
            "accountId": "a-self",
            "sinceQueryState": state_before,
            "filter": {"chatId": "chat-pos205"}
        });
        let result = handler
            .call("Message/queryChanges".to_string(), "c0".to_string(), args)
            .await
            .expect("queryChanges must succeed");

        let added = result["added"].as_array().expect("added must be array");
        assert_eq!(added.len(), 205, "all 205 messages must appear in added");

        // list_by_chat returns newest first.
        // msg-qc-pos-001 has created_at=1 (oldest) → must be at index 204.
        // msg-qc-pos-205 has created_at=205 (newest) → must be at index 0.
        // With the old 200-row cap the five oldest messages were absent from
        // the reference list and fell back to index 0; the fix removes the cap.
        let find_index = |target_id: &str| {
            added
                .iter()
                .find(|e| e["id"].as_str() == Some(target_id))
                .unwrap_or_else(|| panic!("{target_id} not found in added"))["index"]
                .as_u64()
                .unwrap_or_else(|| panic!("{target_id} index is not a u64"))
        };

        // Newest message → index 0.
        assert_eq!(
            find_index("msg-qc-pos-205"),
            0,
            "newest message must be at index 0"
        );

        // Oldest message → index 204 (the 205th slot, 0-based).
        // This is the regression check: with the old cap the oldest 5 messages
        // were not in the reference list and would return index 0.
        assert_eq!(
            find_index("msg-qc-pos-001"),
            204,
            "oldest message must be at index 204, not the None-fallback 0"
        );

        // Messages at the boundary: msg-qc-pos-006 (created_at=6) is the
        // 200th-newest message; it was always within the old 200-row cap.
        // msg-qc-pos-005 (created_at=5) was the first to fall outside the cap.
        assert_eq!(
            find_index("msg-qc-pos-006"),
            199,
            "200th-newest message must be at index 199"
        );
        assert_eq!(
            find_index("msg-qc-pos-005"),
            200,
            "201st-newest message must be at index 200 (would be wrong with old cap)"
        );
    }

    // Oracle: Message/set create to a group chat with zero members must return
    // notCreated/serverFail and leave no message row in the DB.
    //
    // The empty-outbox guard fires after get_members returns [] and before
    // insert_outbound_message is called — no INSERT occurs.
    //
    // Independent oracle: the message state counter must be unchanged, proving
    // no message row was committed.
    #[tokio::test]
    async fn test_group_chat_no_members_returns_server_fail() {
        let store = make_store();
        let chat_id = "group-chat-no-members";

        {
            let guard = store.lock().unwrap();
            // Group chat with no members at all.
            guard.chats().create(chat_id, "group", None, 1000).unwrap();
            // No add_member calls — chat_members is empty.
        }

        let state_before = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
        let result = handler
            .call(
                "Message/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "m0": {
                            "chatId": chat_id,
                            "body": "hello nobody",
                        }
                    }
                }),
            )
            .await
            .expect("handler must not return Err; errors go in notCreated");

        // Oracle: must appear in notCreated with serverFail.
        let not_created = result["notCreated"]
            .as_object()
            .expect("notCreated must be an object");
        assert!(
            not_created.contains_key("m0"),
            "send to memberless group must be notCreated; got: {result:?}"
        );
        assert_eq!(
            not_created["m0"]["type"], "serverFail",
            "error type must be serverFail; got: {:?}",
            not_created["m0"]
        );

        // Oracle: state counter must be unchanged — the empty-outbox guard fires
        // before insert_outbound_message is called, so no message row is committed.
        let state_after = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };
        assert_eq!(
            state_before, state_after,
            "state counter must not advance: empty-members guard must fire before any INSERT"
        );
    }

    // Oracle: readAt with epoch-0 timestamp ("1970-01-01T00:00:00Z") must be
    // rejected with invalidArguments.  Independent oracle: epoch 0 cannot
    // represent a real read event; accepting it corrupts unread-message display.
    #[tokio::test]
    async fn test_read_at_epoch_zero_rejected() {
        let store = make_store();
        let chat_id = "chat-epoch0";
        let peer_uid = "peer-epoch0";
        setup_chat_and_contact(&store, chat_id, peer_uid, "peer-epoch0.tail.ts.net");

        // Insert a message to update.
        {
            let guard = store.lock().unwrap();
            guard
                .messages()
                .insert(
                    "msg-epoch0",
                    chat_id,
                    peer_uid,
                    "hi",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Received,
                    None,
                    "msg-epoch0",
                )
                .unwrap();
        }

        let (blob_store, _blob_dir) = make_blob_store();
        let handler = MessageSetHandler::new(Arc::clone(&store), blob_store);
        let args = json!({
            "accountId": "a-self",
            "update": {
                "msg-epoch0": {
                    "readAt": "1970-01-01T00:00:00Z"
                }
            }
        });

        let result = handler
            .call("Message/set".to_string(), "c0".to_string(), args)
            .await
            .expect("handler must not return top-level Err; errors go in notUpdated");

        // Oracle: epoch-0 readAt must appear in notUpdated with invalidArguments.
        let not_updated = result["notUpdated"]
            .as_object()
            .expect("notUpdated must be an object");
        assert!(
            not_updated.contains_key("msg-epoch0"),
            "epoch-0 readAt must be notUpdated; got: {result:?}"
        );
        assert_eq!(
            not_updated["msg-epoch0"]["type"], "invalidArguments",
            "error type must be invalidArguments; got: {:?}",
            not_updated["msg-epoch0"]
        );
    }

    // Oracle: Message/queryChanges for chat A must not include messages that
    // belong to chat B.  Independent oracle: JMAP RFC 8620 §5.6 — queryChanges
    // must be scoped to the filter supplied by the caller.
    #[tokio::test]
    async fn test_querychanges_does_not_leak_cross_chat_messages() {
        let store = make_store();

        // Set up two independent direct chats.
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-xc-a", "direct", None, 1000)
                .unwrap();
            guard
                .chats()
                .create("chat-xc-b", "direct", None, 1000)
                .unwrap();
        }

        // Capture state before any messages are inserted.
        let state_before = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().unwrap()
        };

        // Insert one message into chat A and one into chat B.
        {
            let guard = store.lock().unwrap();
            guard
                .messages()
                .insert(
                    "msg-xc-a",
                    "chat-xc-a",
                    "self",
                    "in chat A",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Pending,
                    None,
                    "msg-xc-a",
                )
                .unwrap();
            guard
                .messages()
                .insert(
                    "msg-xc-b",
                    "chat-xc-b",
                    "self",
                    "in chat B",
                    "text/plain",
                    None,
                    1001,
                    &DeliveryState::Pending,
                    None,
                    "msg-xc-b",
                )
                .unwrap();
        }

        // Call queryChanges scoped to chat A only.
        let handler = MessageQueryChangesHandler::new(Arc::clone(&store));
        let args = json!({
            "accountId": "a-self",
            "sinceQueryState": state_before,
            "filter": {"chatId": "chat-xc-a"}
        });
        let result = handler
            .call("Message/queryChanges".to_string(), "c0".to_string(), args)
            .await
            .expect("queryChanges must succeed");

        let added = result["added"].as_array().expect("added must be array");

        // Oracle: only msg-xc-a must appear; msg-xc-b (chat B) must be absent.
        let added_ids: Vec<&str> = added
            .iter()
            .filter_map(|e| e.get("id").and_then(|v| v.as_str()))
            .collect();
        assert!(
            added_ids.contains(&"msg-xc-a"),
            "msg-xc-a must appear in chat A queryChanges; got: {added_ids:?}"
        );
        assert!(
            !added_ids.contains(&"msg-xc-b"),
            "msg-xc-b (chat B) must NOT appear in chat A queryChanges; got: {added_ids:?}"
        );
    }
}
