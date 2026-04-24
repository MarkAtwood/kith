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
                return Err(JmapError::not_found());
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
                .map_err(|_| JmapError::server_fail("store lock poisoned"))?;

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
    /// The owner's Tailscale user ID, used to compute the deterministic chatId.
    owner_id: String,
}

impl ChatSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>, owner_id: String) -> Self {
        Self { store, owner_id }
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
        let _owner_id = self.owner_id.clone();

        Box::pin(async move {
            // Step 1: Extract accountId, create, update, destroy.
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            // Step 2: Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::not_found());
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

            // Step 3: Timestamp for created_at on new chats.
            let now_unix: i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                // System clock is always >= UNIX_EPOCH on any real deployment;
                // unwrap_or_default() guards against the impossible case without panic.
                .unwrap_or_default()
                .as_secs() as i64;

            // Step 4: Process each create entry.
            let mut created: Map<String, Value> = Map::new();
            let mut not_created: Map<String, Value> = Map::new();

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

                    // Acquire lock per entry.
                    let guard = store
                        .lock()
                        .map_err(|_| JmapError::server_fail("store lock poisoned"))?;

                    // Step 4c: Look up contact (needed for blocked check).
                    let _contact = match guard
                        .contacts()
                        .get_by_peer_user_id(&contact_id)
                        .map_err(|e| JmapError::server_fail(e.to_string()))?
                    {
                        None => {
                            drop(guard);
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
                        drop(guard);
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
                        drop(guard);
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

                    // Step 4h: Drop lock.
                    drop(guard);

                    // Step 4i: Record as created.
                    let chat_value = serde_json::to_value(chat)
                        .map_err(|e| JmapError::server_fail(e.to_string()))?;
                    created.insert(client_id, chat_value);
                }
            }

            // Step 5: All updates are forbidden.
            let mut not_updated: Map<String, Value> = Map::new();
            if let Some(update_map) = update {
                for (id, _) in update_map {
                    not_updated.insert(
                        id,
                        json!({"type": "forbidden", "description": "chats cannot be updated"}),
                    );
                }
            }

            // Step 6: All destroys are forbidden.
            let mut not_destroyed: Map<String, Value> = Map::new();
            if let Some(destroy_list) = destroy {
                for id in destroy_list {
                    not_destroyed.insert(
                        id,
                        json!({"type": "forbidden", "description": "chats persist"}),
                    );
                }
            }

            // Step 7: Get new state after all operations.
            let new_state = store
                .lock()
                .map_err(|_| JmapError::server_fail("store lock poisoned"))?
                .chats()
                .get_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            Ok(json!({
                "accountId": "a-self",
                "oldState": null,
                "newState": new_state,
                "created": created,
                "updated": null,
                "destroyed": null,
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
/// Returns the set of chat IDs that have changed since the given state token.
/// Phase 1: no per-row state tracking — any advance returns all chat IDs as added.
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
                return Err(JmapError::not_found());
            }

            // Step 3: Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store lock poisoned"))?;

            // Step 4: Get changes since the given state.
            let result = guard.chats().get_changes_since(&since_state).map_err(|e| {
                use kith_core::KithError;
                match e {
                    KithError::Validation(_) => JmapError::state_mismatch(),
                    _ => JmapError::server_fail("store error"),
                }
            })?;

            // Step 5: Drop lock.
            drop(guard);

            // Step 6: Return response.
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
                return Err(JmapError::not_found());
            }

            // Step 3: Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store lock poisoned"))?;

            // Step 4: Fetch all chats (ordered by lastMessageAt DESC NULLS LAST, createdAt DESC).
            let chats = guard
                .chats()
                .list()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            // Step 5: Extract IDs.
            let ids: Vec<String> = chats.into_iter().map(|c| c.id).collect();
            let total = ids.len();

            // Step 7: Apply pagination.
            let skip = position.unwrap_or(0) as usize;
            let page: Vec<String> = match limit {
                Some(n) => ids.into_iter().skip(skip).take(n as usize).collect(),
                None => ids.into_iter().skip(skip).collect(),
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
        let owner_id = "uid-owner";
        let contact_peer_user_id = "uid-bob";

        upsert_contact(&store, contact_peer_user_id);

        let handler = ChatSetHandler::new(Arc::clone(&store), owner_id.to_string());
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
        let owner_id = "uid-owner";

        let handler = ChatSetHandler::new(Arc::clone(&store), owner_id.to_string());
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
        let owner_id = "uid-owner";
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

        let handler = ChatSetHandler::new(Arc::clone(&store), owner_id.to_string());
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

    // Oracle: A malformed state token (no s- prefix) must return a stateMismatch error.
    // The store's get_changes_since returns KithError::Validation for invalid tokens,
    // which the handler must map to JmapError::state_mismatch().
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
            err.error_type, "stateMismatch",
            "error type must be stateMismatch for invalid state token"
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
        let owner_id = "uid-owner";
        let contact_peer_user_id = "uid-bob";

        upsert_contact(&store, contact_peer_user_id);

        let handler = ChatSetHandler::new(Arc::clone(&store), owner_id.to_string());

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
