use kith_core::JmapError;
use kith_jmap::{HandlerFuture, JmapHandler};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

// ---------------------------------------------------------------------------
// Chat/get
// ---------------------------------------------------------------------------

/// Handler for the `Chat/get` JMAP method.
///
/// Returns all chats (or a specific list) for the owner's account.
pub struct ChatGetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatGetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatGetHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // Step 1: Extract accountId and ids from args.
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            // Step 2: Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            // ids is optional: None means "return all".
            let ids: Option<Vec<String>> = match args.get("ids") {
                None | Some(Value::Null) => None,
                Some(Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for v in arr {
                        out.push(
                            v.as_str()
                                .ok_or_else(|| JmapError::invalid_arguments("ids must be strings"))?
                                .to_string(),
                        );
                    }
                    Some(out)
                }
                _ => return Err(JmapError::invalid_arguments("ids must be an array or null")),
            };

            // Step 3: Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            // Step 4: Fetch chats.
            let (chats, not_found) = match ids {
                None => {
                    let list = guard
                        .chats()
                        .list()
                        .map_err(|e| JmapError::server_fail(e.to_string()))?;
                    (list, vec![])
                }
                Some(id_list) => {
                    let mut found = Vec::new();
                    let mut missing: Vec<Value> = Vec::new();
                    for id in id_list {
                        match guard
                            .chats()
                            .get(&id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?
                        {
                            Some(c) => found.push(c),
                            None => missing.push(Value::String(id)),
                        }
                    }
                    (found, missing)
                }
            };

            // Step 5: Get state.
            let state = guard
                .chats()
                .get_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            // Step 6: Drop lock (guard drops here).
            drop(guard);

            // Step 7: Build and return response.
            Ok(json!({
                "accountId": "a-self",
                "list": chats,
                "notFound": not_found,
                "state": state,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Chat/set
// ---------------------------------------------------------------------------

/// Handler for the `Chat/set` JMAP method.
///
/// Supports creating direct chats by referencing a known contact.
/// Update and destroy operations are rejected (chats are immutable records).
pub struct ChatSetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatSetHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // Step 1: Extract accountId, create, update, destroy.
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            // Step 2: Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            let create: Option<Map<String, Value>> = match args.get("create") {
                None | Some(Value::Null) => None,
                Some(Value::Object(m)) => Some(m.clone()),
                _ => {
                    return Err(JmapError::invalid_arguments(
                        "create must be an object or null",
                    ))
                }
            };

            let update: Option<Map<String, Value>> = match args.get("update") {
                None | Some(Value::Null) => None,
                Some(Value::Object(m)) => Some(m.clone()),
                _ => {
                    return Err(JmapError::invalid_arguments(
                        "update must be an object or null",
                    ))
                }
            };

            let destroy: Option<Vec<String>> = match args.get("destroy") {
                None | Some(Value::Null) => None,
                Some(Value::Array(arr)) => {
                    let mut ids = Vec::with_capacity(arr.len());
                    for v in arr {
                        ids.push(
                            v.as_str()
                                .ok_or_else(|| {
                                    JmapError::invalid_arguments("destroy ids must be strings")
                                })?
                                .to_string(),
                        );
                    }
                    Some(ids)
                }
                _ => {
                    return Err(JmapError::invalid_arguments(
                        "destroy must be an array or null",
                    ))
                }
            };

            // Step 4: Timestamp for created_at on new chats.
            let now_unix: i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                // System clock is always >= UNIX_EPOCH on any real deployment;
                // unwrap_or_default() guards against the impossible case without panic.
                .unwrap_or_default()
                .as_secs() as i64;

            // Step 3+5: Acquire the store lock once, capture old_state and new_state
            // atomically with the create batch.  Both state values are read inside the
            // same lock scope so no concurrent write can slip in between them — which
            // would cause newState to include changes not part of this Set call,
            // causing clients that update sinceState to silently miss those changes
            // (RFC 8620 §5.3).
            let mut created: Map<String, Value> = Map::new();
            let mut not_created: Map<String, Value> = Map::new();

            let (old_state, new_state) = {
                let guard = store
                    .lock()
                    .map_err(|_| JmapError::server_fail("internal error"))?;

                let old_state = guard
                    .chats()
                    .get_state()
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                if let Some(create_map) = create {
                    for (client_id, fields) in create_map {
                        // Extract contactId (required).
                        let contact_id = match fields.get("contactId").and_then(|v| v.as_str()) {
                            Some(id) => id.to_string(),
                            None => {
                                not_created.insert(
                                    client_id,
                                    json!({"type": "invalidArguments", "description": "contactId is required"}),
                                );
                                continue;
                            }
                        };

                        // Step 4c: Look up contact (needed for blocked check).
                        let _contact = match guard
                            .contacts()
                            .get_by_peer_user_id(&contact_id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?
                        {
                            None => {
                                not_created.insert(
                                    client_id,
                                    json!({"type": "notFound", "description": "contact not found"}),
                                );
                                continue;
                            }
                            Some(c) => c,
                        };

                        // Step 4d: Check not blocked.
                        let permitted = guard
                            .contacts()
                            .is_permitted(&contact_id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?;

                        if !permitted {
                            not_created.insert(
                                client_id,
                                json!({"type": "forbidden", "description": "contact is blocked"}),
                            );
                            continue;
                        }

                        // Step 4e: Dedup — return existing direct chat if one exists.
                        let existing = guard
                            .chats()
                            .find_direct_by_contact_id(&contact_id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?;

                        // Step 4f: Create or reuse.
                        let chat = if let Some(existing_chat) = existing {
                            // RFC 8620 §5.3: already exists → notCreated / alreadyExists.
                            not_created.insert(
                                client_id,
                                json!({"type": "alreadyExists", "existingId": existing_chat.id}),
                            );
                            continue;
                        } else {
                            let chat_id = Ulid::new().to_string();
                            guard
                                .chats()
                                .create(&chat_id, "direct", Some(&contact_id), now_unix)
                                .map_err(|e| JmapError::server_fail(e.to_string()))?
                        };

                        // Step 4h: Record as created.
                        let chat_value = serde_json::to_value(chat)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?;
                        created.insert(client_id, chat_value);
                    }
                }

                // Capture new_state after all creates, still inside the same lock scope,
                // so newState reflects exactly this Set's changes and nothing else.
                let new_state = guard
                    .chats()
                    .get_state()
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                (old_state, new_state)
            };

            // Step 6: All updates are forbidden.
            let mut not_updated: Map<String, Value> = Map::new();
            if let Some(update_map) = update {
                for (id, _) in update_map {
                    not_updated.insert(
                        id,
                        json!({"type": "forbidden", "description": "chats cannot be updated"}),
                    );
                }
            }

            // Step 7: All destroys are forbidden.
            let mut not_destroyed: Map<String, Value> = Map::new();
            if let Some(destroy_list) = destroy {
                for id in destroy_list {
                    not_destroyed.insert(
                        id,
                        json!({"type": "forbidden", "description": "chats persist"}),
                    );
                }
            }

            Ok(json!({
                "accountId": "a-self",
                "oldState": old_state,
                "newState": new_state,
                "created": created,
                "updated": {},
                "destroyed": [],
                "notCreated": not_created,
                "notUpdated": not_updated,
                "notDestroyed": not_destroyed,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Chat/changes
// ---------------------------------------------------------------------------

/// Handler for the `Chat/changes` JMAP method.
///
/// Returns the set of chat IDs that have changed since the given state token,
/// using per-row state tracking via `get_changes_since`.
pub struct ChatChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatChangesHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // Step 1: Deserialize args.
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            let since_state = args
                .get("sinceState")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("sinceState is required"))?
                .to_string();

            // Step 2: Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            // Step 3: Parse maxChanges — RFC 8620 §5.6: maxChanges=0 must be invalidArguments.
            let max_changes: Option<usize> = match args.get("maxChanges") {
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

            // Step 4: Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            // Step 5: Get changes since the given state.
            let (rows, current_state) = guard
                .chats()
                .get_changes_since_ordered(&since_state)
                .map_err(|e| {
                    use kith_core::KithError;
                    match e {
                        KithError::Jmap(je) => je,
                        _ => JmapError::server_fail("store error"),
                    }
                })?;

            // Step 6: Drop lock.
            drop(guard);

            // Step 7: Apply maxChanges limit (RFC 8620 §5.6).
            let total = rows.len();
            let (items, has_more, new_state) = if let Some(max) = max_changes {
                if total > max {
                    let truncated = &rows[..max];
                    let new_state = truncated.last().map(|(_, c, _)| format!("s-{c}")).expect(
                        "truncated slice is non-empty: max>=1 invariant established at parse time",
                    );
                    (truncated.to_vec(), true, new_state)
                } else {
                    (rows, false, current_state)
                }
            } else {
                (rows, false, current_state)
            };

            // Split into created[] and updated[] per RFC 8620 §5.6.
            let mut created: Vec<serde_json::Value> = Vec::new();
            let mut updated: Vec<serde_json::Value> = Vec::new();
            for (id, _, is_create) in items {
                if is_create {
                    created.push(serde_json::Value::String(id));
                } else {
                    updated.push(serde_json::Value::String(id));
                }
            }

            // Step 8: Return response.
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
// Chat/query
// ---------------------------------------------------------------------------

/// Handler for the `Chat/query` JMAP method.
///
/// Returns a page of chat IDs ordered by lastMessageAt DESC (nulls last), then createdAt DESC.
pub struct ChatQueryHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatQueryHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatQueryHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // Step 1: Deserialize args.
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            let position: Option<u32> = match args.get("position") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_u64()
                        .ok_or_else(|| JmapError::invalid_arguments("position must be a number"))?
                        as u32,
                ),
            };

            let limit: Option<u32> = match args.get("limit") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_u64()
                        .ok_or_else(|| JmapError::invalid_arguments("limit must be a number"))?
                        as u32,
                ),
            };

            let calculate_total: bool = args
                .get("calculateTotal")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Step 2: Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            // Step 3: Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            // Step 4: Fetch a page of chat IDs with SQL-level pagination
            // (ordered by lastMessageAt DESC NULLS LAST, createdAt DESC).
            let offset = position.unwrap_or(0);
            let sql_limit = limit.unwrap_or(u32::MAX);
            let page = guard
                .chats()
                .list_ids_paged(sql_limit, offset)
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            let total = if calculate_total {
                guard
                    .chats()
                    .count()
                    .map_err(|e| JmapError::server_fail(e.to_string()))?
            } else {
                0
            };

            // Step 8: Get query state.
            let query_state = guard
                .chats()
                .get_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            // Step 9: Drop lock.
            drop(guard);

            // Step 10: Return response.
            Ok(json!({
                "accountId": "a-self",
                "queryState": query_state,
                "canCalculateChanges": true,
                "position": position.unwrap_or(0),
                "ids": page,
                "total": if calculate_total { json!(total) } else { Value::Null },
            }))
        })
    }
}

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

    /// Upsert a contact so Chat/set create tests can reference it.
    fn upsert_contact(store: &Arc<Mutex<Store>>, peer_user_id: &str) {
        let guard = store.lock().unwrap();
        guard
            .contacts()
            .upsert(
                peer_user_id,
                &format!("{peer_user_id}@example.com"),
                &format!("{peer_user_id}-kith.tail.ts.net"),
                None,
                1_000_000,
            )
            .expect("upsert contact");
    }

    // Oracle: Chat/get with ids=None on an empty store must return an empty list
    // and state "s-0" (schema initializes chat counter to 0).
    #[tokio::test]
    async fn test_chat_get_empty() {
        let store = make_store();
        let handler = ChatGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("Chat/get must succeed");

        assert_eq!(result["accountId"], "a-self");
        assert_eq!(result["list"], json!([]));
        // Oracle: SCHEMA_V1 initializes chat counter to 0.
        assert_eq!(result["state"], "s-0");
    }

    // Oracle: Chat/get with an unknown id must report it in notFound.
    #[tokio::test]
    async fn test_chat_get_not_found() {
        let store = make_store();
        let handler = ChatGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "ids": ["unknown-chat-id"]}),
            )
            .await
            .expect("Chat/get must succeed");

        assert_eq!(result["list"], json!([]));
        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert!(
            not_found.contains(&json!("unknown-chat-id")),
            "unknown-chat-id must appear in notFound, got: {not_found:?}"
        );
    }

    // Oracle: Chat/set create with a known, unblocked contact must return the created chat.
    // The returned id must be a non-empty ULID string (server-assigned, not derived from participants).
    #[tokio::test]
    async fn test_chat_set_create_valid() {
        let store = make_store();
        let contact_peer_user_id = "uid-bob";

        upsert_contact(&store, contact_peer_user_id);

        let handler = ChatSetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "c0": {"contactId": contact_peer_user_id}
                    }
                }),
            )
            .await
            .expect("Chat/set must succeed");

        assert_eq!(result["accountId"], "a-self");

        let created = result["created"]
            .as_object()
            .expect("created must be object");
        assert!(
            created.contains_key("c0"),
            "c0 must be in created, got: {created:?}"
        );

        // Oracle: the returned chat id must be a non-empty string (server-assigned ULID).
        let actual_id = created["c0"]["id"]
            .as_str()
            .expect("created chat must have an id field");
        assert!(!actual_id.is_empty(), "created chat id must not be empty");

        // Verify the chat was actually written to the store.
        let guard = store.lock().unwrap();
        let chat = guard
            .chats()
            .get(actual_id)
            .unwrap()
            .expect("chat must exist in store after create");
        assert_eq!(chat.kind, "direct");
    }

    // Oracle: Chat/set create with an unknown contactId must return notCreated/notFound.
    #[tokio::test]
    async fn test_chat_set_create_unknown_contact() {
        let store = make_store();

        let handler = ChatSetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "c0": {"contactId": "uid-nobody"}
                    }
                }),
            )
            .await
            .expect("Chat/set must succeed even on notCreated");

        let not_created = result["notCreated"]
            .as_object()
            .expect("notCreated must be object");
        assert!(
            not_created.contains_key("c0"),
            "c0 must be in notCreated for unknown contact"
        );
        assert_eq!(
            not_created["c0"]["type"], "notFound",
            "error type must be notFound for unknown contact"
        );

        // Oracle: no chat must have been created in the store.
        let guard = store.lock().unwrap();
        let chats = guard.chats().list().unwrap();
        assert!(
            chats.is_empty(),
            "no chat must be created for unknown contact"
        );
    }

    // Oracle: Chat/set create with a blocked contact must return notCreated/forbidden.
    #[tokio::test]
    async fn test_chat_set_create_blocked_contact() {
        let store = make_store();
        let contact_peer_user_id = "uid-blocked";

        upsert_contact(&store, contact_peer_user_id);

        // Block the contact.
        {
            let guard = store.lock().unwrap();
            guard
                .contacts()
                .set_blocked(contact_peer_user_id, true)
                .expect("set_blocked must succeed");
        }

        let handler = ChatSetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "c0": {"contactId": contact_peer_user_id}
                    }
                }),
            )
            .await
            .expect("Chat/set must succeed even on notCreated");

        let not_created = result["notCreated"]
            .as_object()
            .expect("notCreated must be object");
        assert!(
            not_created.contains_key("c0"),
            "c0 must be in notCreated for blocked contact"
        );
        assert_eq!(
            not_created["c0"]["type"], "forbidden",
            "error type must be forbidden for blocked contact"
        );

        // Oracle: no chat must have been created in the store.
        let guard = store.lock().unwrap();
        let chats = guard.chats().list().unwrap();
        assert!(
            chats.is_empty(),
            "no chat must be created for blocked contact"
        );
    }

    // Oracle: Chat/changes with the current state must return empty lists.
    // The store initializes to s-0; calling changes with s-0 against an empty store
    // must yield no created, updated, or destroyed IDs (counter equality → no delta).
    #[tokio::test]
    async fn test_chat_changes_empty() {
        let store = make_store();
        let current_state = {
            let guard = store.lock().unwrap();
            guard.chats().get_state().unwrap()
        };
        let handler = ChatChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": current_state}),
            )
            .await
            .expect("Chat/changes must succeed");

        assert_eq!(result["accountId"], "a-self");
        assert_eq!(result["created"], json!([]));
        assert_eq!(result["updated"], json!([]));
        assert_eq!(result["destroyed"], json!([]));
        assert_eq!(result["hasMoreChanges"], false);
    }

    // Oracle: A chat created after s-0 must appear in Chat/changes created list.
    // State advances from s-0 to s-1 on first get_or_create; requesting changes
    // since s-0 must include the new chat's ID in the created field.
    #[tokio::test]
    async fn test_chat_changes_after_create() {
        let store = make_store();
        let now_unix: i64 = 1_000_000;
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-new-1", "direct", Some("uid:alice"), now_unix)
                .unwrap();
        }

        let handler = ChatChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": "s-0"}),
            )
            .await
            .expect("Chat/changes must succeed");

        let created = result["created"].as_array().expect("created must be array");
        assert!(
            created.contains(&json!("chat-new-1")),
            "chat-new-1 must appear in created; got: {created:?}"
        );
    }

    // Oracle: RFC 8620 §5.5 — a malformed state token must return cannotCalculateChanges.
    // (stateMismatch is for /set ifInState checks; /changes uses cannotCalculateChanges
    // so the client knows to fall back to a full re-sync.)
    #[tokio::test]
    async fn test_chat_changes_malformed_state() {
        let store = make_store();
        let handler = ChatChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": "not-a-state"}),
            )
            .await;

        assert!(result.is_err(), "expected Err for malformed state");
        let err = result.unwrap_err();
        assert_eq!(
            err.error_type, "cannotCalculateChanges",
            "error type must be cannotCalculateChanges for invalid state token"
        );
    }

    // Oracle: RFC 8620 §5.6 — maxChanges=0 must return invalidArguments.
    #[tokio::test]
    async fn test_chat_changes_max_changes_zero_returns_invalid_arguments() {
        let store = make_store();
        upsert_contact(&store, "uid-mc0");
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-mc0", "direct", Some("uid-mc0"), 1_000_000)
                .unwrap();
        }
        let handler = ChatChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": "s-0", "maxChanges": 0}),
            )
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
    // item's changed_at_counter, not the current store state.
    #[tokio::test]
    async fn test_chat_changes_max_changes_truncation() {
        let store = make_store();
        upsert_contact(&store, "uid-ct1");
        upsert_contact(&store, "uid-ct2");
        upsert_contact(&store, "uid-ct3");
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-ct1", "direct", Some("uid-ct1"), 1_000_000)
                .unwrap();
            guard
                .chats()
                .create("chat-ct2", "direct", Some("uid-ct2"), 1_000_000)
                .unwrap();
            guard
                .chats()
                .create("chat-ct3", "direct", Some("uid-ct3"), 1_000_000)
                .unwrap();
        }
        let handler = ChatChangesHandler::new(Arc::clone(&store));

        // Page 1: maxChanges=1 from s-0 → 1 chat, hasMoreChanges=true.
        let r1 = handler
            .call(
                "Chat/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": "s-0", "maxChanges": 1}),
            )
            .await
            .expect("page 1 must succeed");
        assert_eq!(
            r1["hasMoreChanges"], true,
            "page 1 hasMoreChanges must be true; got: {r1}"
        );
        let c1 = r1["created"].as_array().expect("created must be array");
        assert_eq!(c1.len(), 1, "page 1 must return exactly 1 chat; got: {r1}");
        let state1 = r1["newState"]
            .as_str()
            .expect("newState must be string")
            .to_string();

        // Page 2: from state1 → 1 more, hasMoreChanges=true.
        let r2 = handler
            .call(
                "Chat/changes".to_string(),
                "c1".to_string(),
                json!({"accountId": "a-self", "sinceState": state1, "maxChanges": 1}),
            )
            .await
            .expect("page 2 must succeed");
        assert_eq!(
            r2["hasMoreChanges"], true,
            "page 2 hasMoreChanges must be true; got: {r2}"
        );
        let c2 = r2["created"].as_array().expect("created must be array");
        assert_eq!(c2.len(), 1, "page 2 must return exactly 1 chat; got: {r2}");
        let state2 = r2["newState"]
            .as_str()
            .expect("newState must be string")
            .to_string();

        // Page 3: from state2 → last chat, hasMoreChanges=false.
        let r3 = handler
            .call(
                "Chat/changes".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "sinceState": state2, "maxChanges": 1}),
            )
            .await
            .expect("page 3 must succeed");
        assert_eq!(
            r3["hasMoreChanges"], false,
            "page 3 hasMoreChanges must be false; got: {r3}"
        );
        let c3 = r3["created"].as_array().expect("created must be array");
        assert_eq!(c3.len(), 1, "page 3 must return exactly 1 chat; got: {r3}");

        // All 3 chats must be covered across the 3 pages.
        let all_ids: Vec<String> = [&c1[..], &c2[..], &c3[..]]
            .concat()
            .iter()
            .map(|v| v.as_str().expect("id must be string").to_string())
            .collect();
        let mut sorted = all_ids.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            ["chat-ct1", "chat-ct2", "chat-ct3"],
            "all 3 chats must appear across pages; got: {all_ids:?}"
        );
    }

    // Oracle: Chat/query on a store with 2 chats must return both IDs.
    // The query handler lists all chats and returns their IDs; no pagination applied
    // when position/limit are absent.
    #[tokio::test]
    async fn test_chat_query_all() {
        let store = make_store();
        let now_unix: i64 = 1_000_000;

        upsert_contact(&store, "uid-bob");
        upsert_contact(&store, "uid-carol");

        let chat_id_1 = "chat-bob-test";
        let chat_id_2 = "chat-carol-test";

        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create(&chat_id_1, "direct", Some("uid-bob"), now_unix)
                .unwrap();
            guard
                .chats()
                .create(&chat_id_2, "direct", Some("uid-carol"), now_unix + 1)
                .unwrap();
        }

        let handler = ChatQueryHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/query".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("Chat/query must succeed");

        assert_eq!(result["accountId"], "a-self");
        let ids = result["ids"].as_array().expect("ids must be array");
        assert_eq!(ids.len(), 2, "must return both chats; got: {ids:?}");
        assert!(
            ids.contains(&json!(chat_id_1)),
            "chat_id_1 must be in ids; got: {ids:?}"
        );
        assert!(
            ids.contains(&json!(chat_id_2)),
            "chat_id_2 must be in ids; got: {ids:?}"
        );
    }

    // Oracle: Chat/query with position=1 limit=1 on 3 chats must return exactly 1 ID.
    // The chats are ordered by lastMessageAt DESC NULLS LAST then createdAt DESC.
    // With no messages, order is createdAt DESC: chat3 > chat2 > chat1.
    // position=1 skips chat3; limit=1 takes only chat2.
    #[tokio::test]
    async fn test_chat_query_pagination() {
        let store = make_store();

        upsert_contact(&store, "uid-p1");
        upsert_contact(&store, "uid-p2");
        upsert_contact(&store, "uid-p3");

        let chat_id_1 = "chat-p1-test";
        let chat_id_2 = "chat-p2-test";
        let chat_id_3 = "chat-p3-test";

        {
            let guard = store.lock().unwrap();
            // Insert in ascending time order so createdAt DESC puts chat3 first.
            guard
                .chats()
                .create(&chat_id_1, "direct", Some("uid-p1"), 1_000_001)
                .unwrap();
            guard
                .chats()
                .create(&chat_id_2, "direct", Some("uid-p2"), 1_000_002)
                .unwrap();
            guard
                .chats()
                .create(&chat_id_3, "direct", Some("uid-p3"), 1_000_003)
                .unwrap();
        }

        let handler = ChatQueryHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Chat/query".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "position": 1, "limit": 1}),
            )
            .await
            .expect("Chat/query must succeed");

        let ids = result["ids"].as_array().expect("ids must be array");
        assert_eq!(
            ids.len(),
            1,
            "pagination position=1 limit=1 must return exactly 1 id; got: {ids:?}"
        );
        // position=1 skips the first result (chat3, newest); limit=1 takes the second (chat2).
        assert_eq!(
            ids[0],
            json!(chat_id_2),
            "position=1 limit=1 must return chat_id_2; got: {}",
            ids[0]
        );
    }

    // Oracle: Chat/set create for a contact that already has a direct chat must return
    // notCreated/alreadyExists per RFC 8620 §5.3, not the existing chat in `created`.
    // The existingId field must contain the ID of the already-existing chat.
    #[tokio::test]
    async fn test_chat_set_create_duplicate_returns_not_created_already_exists() {
        let store = make_store();
        let contact_peer_user_id = "uid-bob";

        upsert_contact(&store, contact_peer_user_id);

        let handler = ChatSetHandler::new(Arc::clone(&store));

        // First create — must succeed.
        let first_result = handler
            .call(
                "Chat/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": { "c0": {"contactId": contact_peer_user_id} }
                }),
            )
            .await
            .expect("first Chat/set create must succeed");

        let existing_id = first_result["created"]["c0"]["id"]
            .as_str()
            .expect("first create must return an id")
            .to_string();
        assert!(!existing_id.is_empty());

        // Second create for the same contact — must be notCreated/alreadyExists.
        let second_result = handler
            .call(
                "Chat/set".to_string(),
                "c1".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": { "c1": {"contactId": contact_peer_user_id} }
                }),
            )
            .await
            .expect("second Chat/set must succeed (method-level, not HTTP-level error)");

        // Oracle: RFC 8620 §5.3 — duplicate must go to notCreated, not created.
        let created = second_result["created"]
            .as_object()
            .expect("created must be object");
        assert!(
            !created.contains_key("c1"),
            "duplicate create must NOT appear in created; got: {created:?}"
        );

        let not_created = second_result["notCreated"]
            .as_object()
            .expect("notCreated must be object");
        assert!(
            not_created.contains_key("c1"),
            "duplicate create must appear in notCreated; got: {not_created:?}"
        );
        assert_eq!(
            not_created["c1"]["type"], "alreadyExists",
            "error type must be alreadyExists; got: {:?}",
            not_created["c1"]
        );
        assert_eq!(
            not_created["c1"]["existingId"], existing_id,
            "existingId must point to the original chat; got: {:?}",
            not_created["c1"]
        );
    }
}
