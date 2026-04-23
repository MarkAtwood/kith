// Contact/get, Contact/set, Contact/changes, Contact/query handlers

use crate::kith_to_jmap;
use kith_core::{JmapError, KithError};
use kith_jmap::{HandlerFuture, JmapHandler};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Contact/get
// ---------------------------------------------------------------------------

pub struct ChatContactGetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatContactGetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatContactGetHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // 1. Extract fields from args object.
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            // 2. Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            // ids: null or absent means "all"; present array means specific IDs.
            let ids: Option<Vec<String>> = match obj.get("ids") {
                None | Some(Value::Null) => None,
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
                    Some(v)
                }
                Some(_) => {
                    return Err(JmapError::invalid_arguments("ids must be null or an array"))
                }
            };

            // 3. Acquire lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            // 4. Fetch contacts.
            let (contacts, not_found) = match ids {
                None => {
                    let list = guard.contacts().list().map_err(kith_to_jmap)?;
                    (list, vec![])
                }
                Some(id_list) => {
                    let mut found = Vec::new();
                    let mut missing = Vec::new();
                    for id in id_list {
                        match guard
                            .contacts()
                            .get_by_peer_user_id(&id)
                            .map_err(kith_to_jmap)?
                        {
                            Some(c) => found.push(c),
                            None => missing.push(id),
                        }
                    }
                    (found, missing)
                }
            };

            // 5. Get current state.
            let state = guard.contacts().get_state().map_err(kith_to_jmap)?;

            // 6. Drop lock (guard drops at end of scope; explicit drop for clarity).
            drop(guard);

            // 7. Return response.
            let list = serde_json::to_value(&contacts)
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
// Contact/set
// ---------------------------------------------------------------------------

pub struct ChatContactSetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatContactSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatContactSetHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // 1. Extract top-level fields.
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            // 2. Verify accountId.
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

            // 3. Compute now_unix outside the lock.
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let mut created: Map<String, Value> = Map::new();
            let mut not_created: Map<String, Value> = Map::new();
            let mut updated: Map<String, Value> = Map::new();
            let mut not_updated: Map<String, Value> = Map::new();
            let mut not_destroyed: Map<String, Value> = Map::new();

            // 4. Process create entries.
            if let Some(creates) = create_map {
                for (client_id, value) in creates {
                    match process_create(&store, client_id, value, now_unix) {
                        Ok(contact_value) => {
                            created.insert(client_id.clone(), contact_value);
                        }
                        Err(err_value) => {
                            not_created.insert(client_id.clone(), err_value);
                        }
                    }
                }
            }

            // 5. Process update entries.
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

            // 6. Process destroy entries — always forbidden.
            if let Some(destroy_ids) = destroy_list {
                for id in destroy_ids {
                    not_destroyed.insert(
                        id,
                        json!({
                            "type": "forbidden",
                            "description": "contacts are auto-managed"
                        }),
                    );
                }
            }

            // 7. Get new state.
            let new_state = {
                let guard = store
                    .lock()
                    .map_err(|_| JmapError::server_fail("store poisoned"))?;
                guard.contacts().get_state().map_err(kith_to_jmap)?
            };

            // 8. Return full set response.
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

// ---------------------------------------------------------------------------
// Create helper (returns Ok(contact_json) or Err(error_json))
// ---------------------------------------------------------------------------

fn process_create(
    store: &Arc<Mutex<kith_store::Store>>,
    _client_id: &str,
    value: &Value,
    now_unix: i64,
) -> Result<Value, Value> {
    let obj = value.as_object().ok_or_else(
        || json!({"type": "invalidArguments", "description": "create entry must be an object"}),
    )?;

    // Extract required fields.
    let user_id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"type": "invalidArguments", "description": "id is required"}))?;

    let login = obj
        .get("login")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"type": "invalidArguments", "description": "login is required"}))?;

    // mailboxHost is a DB-only delivery-routing field; not in the JMAP ChatContact type.
    // Accept it as an input-only create field so the owner can provision contacts in Phase 1.
    let mailbox_host = obj.get("mailboxHost").and_then(|v| v.as_str()).ok_or_else(
        || json!({"type": "invalidArguments", "description": "mailboxHost is required"}),
    )?;

    let display_name: Option<&str> = obj.get("displayName").and_then(|v| v.as_str());
    let blocked: bool = obj
        .get("blocked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Validate displayName length.
    if display_name.unwrap_or("").len() > 256 {
        return Err(json!({"type": "invalidArguments", "description": "displayName too long"}));
    }

    // Validate mailboxHost.
    if mailbox_host.is_empty() || mailbox_host.contains('\0') {
        return Err(json!({"type": "invalidArguments", "description": "mailboxHost is invalid"}));
    }

    // Acquire lock, upsert, optionally set_blocked, fetch back.
    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "store poisoned"}))?;

    guard
        .contacts()
        .upsert(user_id, login, mailbox_host, display_name, now_unix)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    if blocked {
        guard
            .contacts()
            .set_blocked(user_id, true)
            .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    }

    let contact = guard
        .contacts()
        .get_by_peer_user_id(user_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?
        .ok_or_else(
            || json!({"type": "serverFail", "description": "contact not found after upsert"}),
        )?;

    drop(guard);

    serde_json::to_value(&contact).map_err(
        |e| json!({"type": "serverFail", "description": format!("serialization error: {e}")}),
    )
}

// ---------------------------------------------------------------------------
// Update helper (returns Ok(()) or Err(error_json))
// ---------------------------------------------------------------------------

fn process_update(
    store: &Arc<Mutex<kith_store::Store>>,
    server_id: &str,
    patch: &Value,
    now_unix: i64,
) -> Result<(), Value> {
    let patch_obj = patch.as_object().ok_or_else(
        || json!({"type": "invalidArguments", "description": "update patch must be an object"}),
    )?;

    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "store poisoned"}))?;

    // Load existing contact.
    let existing = guard
        .contacts()
        .get_by_peer_user_id(server_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?
        .ok_or_else(|| json!({"type": "notFound", "description": "contact not found"}))?;

    // Apply patch fields onto existing values.
    let new_display_name: Option<String> = if let Some(v) = patch_obj.get("displayName") {
        if v.is_null() {
            None
        } else {
            Some(
                v.as_str()
                    .ok_or_else(|| {
                        json!({"type": "invalidArguments", "description": "displayName must be a string or null"})
                    })?
                    .to_string(),
            )
        }
    } else {
        existing.display_name.clone()
    };

    let new_blocked: Option<bool> = if let Some(v) = patch_obj.get("blocked") {
        Some(v.as_bool().ok_or_else(
            || json!({"type": "invalidArguments", "description": "blocked must be a bool"}),
        )?)
    } else {
        None
    };

    // Validate updated displayName length.
    if new_display_name.as_deref().unwrap_or("").len() > 256 {
        return Err(json!({"type": "invalidArguments", "description": "displayName too long"}));
    }

    // Get the stored mailbox host (DB-only routing field; not patchable via JMAP).
    let current_mailbox_host = guard
        .contacts()
        .get_mailbox_host(server_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?
        .ok_or_else(|| json!({"type": "notFound", "description": "contact not found"}))?;

    // Re-upsert with updated values (preserves first_seen_at, updates last_seen_at).
    guard
        .contacts()
        .upsert(
            server_id,
            &existing.login,
            &current_mailbox_host,
            new_display_name.as_deref(),
            now_unix,
        )
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Apply blocked change if requested.
    if let Some(blocked) = new_blocked {
        guard
            .contacts()
            .set_blocked(server_id, blocked)
            .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    }

    drop(guard);

    Ok(())
}

// ---------------------------------------------------------------------------
// Contact/changes
// ---------------------------------------------------------------------------

pub struct ChatContactChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatContactChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatContactChangesHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // 1. Deserialize args.
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            // 2. Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            let since_state = obj
                .get("sinceState")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("sinceState is required"))?
                .to_string();

            // maxChanges is accepted but ignored in v1.

            // 3. Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            // 4. Call get_changes_since.
            let result = guard
                .contacts()
                .get_changes_since(&since_state)
                .map_err(|e| match e {
                    KithError::Validation(_) => JmapError::state_mismatch(),
                    _ => JmapError::server_fail("store error"),
                })?;

            // 5. Drop lock.
            drop(guard);

            // 6. Return changes response.
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
// Contact/query
// ---------------------------------------------------------------------------

pub struct ChatContactQueryHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatContactQueryHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatContactQueryHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // 1. Deserialize args.
            let obj = args
                .as_object()
                .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;

            let account_id = obj
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?;

            // 2. Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::invalid_arguments("unknown accountId"));
            }

            // filter, sort are accepted but ignored in v1.
            let position: Option<u32> = obj
                .get("position")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32);
            let limit: Option<u32> = obj.get("limit").and_then(|v| v.as_u64()).map(|n| n as u32);
            let calculate_total: bool = obj
                .get("calculateTotal")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // 3. Acquire lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            // 4. List all contacts.
            let contacts = guard.contacts().list().map_err(kith_to_jmap)?;

            // 5. Extract ids.
            let ids: Vec<String> = contacts.into_iter().map(|c| c.id).collect();

            // 6. Total before pagination.
            let total = ids.len();

            // 7. Apply pagination.
            let page: Vec<String> = ids
                .into_iter()
                .skip(position.unwrap_or(0) as usize)
                .take(limit.unwrap_or(u32::MAX) as usize)
                .collect();

            // 8. Get current state for queryState.
            let query_state = guard.contacts().get_state().map_err(kith_to_jmap)?;

            // 9. Drop lock.
            drop(guard);

            // 10. Return query response.
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

// ---------------------------------------------------------------------------
// ChatContact/queryChanges
// ---------------------------------------------------------------------------

pub struct ChatContactQueryChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ChatContactQueryChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ChatContactQueryChangesHandler {
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

            // Parse sinceQueryState as "s-N".
            let since_counter: i64 = since_query_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .ok_or_else(JmapError::cannot_calculate_changes)?;

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store poisoned"))?;

            let current_state = guard.contacts().get_state().map_err(kith_to_jmap)?;
            let current_counter: i64 = current_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .unwrap_or(0);

            // If no changes since sinceQueryState, return early with empty delta.
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

            let changes = guard
                .contacts()
                .get_changes_since(&since_query_state)
                .map_err(kith_to_jmap)?;

            // Get the current full ordered list to compute insertion indices.
            let full_list = guard.contacts().list().map_err(kith_to_jmap)?;

            drop(guard);

            let new_state = changes.new_state.clone();

            // Build added list with indices (position in the current query result).
            let added_with_index: Vec<Value> = changes
                .added
                .iter()
                .map(|added_id| {
                    let index = full_list
                        .iter()
                        .position(|c| &c.id == added_id)
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

    // Oracle: RFC 8620 §5.1 — Contact/get with ids=null returns all contacts.
    // Empty store → list is empty, state is "s-0".
    #[tokio::test]
    async fn test_contact_get_empty() {
        let store = make_store();
        let handler = ChatContactGetHandler::new(Arc::clone(&store));

        let args = json!({"accountId": "a-self"});
        let result = handler
            .call("ChatContact/get".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        assert_eq!(result["accountId"], "a-self");
        assert_eq!(result["list"], json!([]));
        assert_eq!(result["notFound"], json!([]));
        // Oracle: initial state counter is 0 (per SCHEMA_V1 migration).
        assert_eq!(result["state"], "s-0");
    }

    // Oracle: RFC 8620 §5.1 — Contact/get ids=null after upsert returns the contact
    // with correct id field (I-D §ChatContact — id IS the userId from the auth layer).
    #[tokio::test]
    async fn test_contact_get_after_upsert() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .contacts()
                .upsert(
                    "uid-alice",
                    "alice@example.com",
                    "alice-kith.tail.ts.net",
                    Some("Alice"),
                    1000,
                )
                .unwrap();
        }

        let handler = ChatContactGetHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self"});
        let result = handler
            .call("ChatContact/get".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let list = result["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 1);
        // Oracle: I-D §ChatContact — id IS the userId from the auth layer.
        assert_eq!(list[0]["id"], "uid-alice");
        assert_eq!(list[0]["login"], "alice@example.com");
    }

    // Oracle: RFC 8620 §5.1 — ids=["nonexistent"] → notFound: ["nonexistent"], list: [].
    #[tokio::test]
    async fn test_contact_get_not_found() {
        let store = make_store();
        let handler = ChatContactGetHandler::new(Arc::clone(&store));

        let args = json!({"accountId": "a-self", "ids": ["nonexistent"]});
        let result = handler
            .call("ChatContact/get".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        assert_eq!(result["list"], json!([]));
        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert_eq!(not_found.len(), 1);
        assert_eq!(not_found[0], "nonexistent");
    }

    // Oracle: RFC 8620 §5.3 — Contact/set create with valid fields returns
    // created.c0 with an id field.
    #[tokio::test]
    async fn test_contact_set_create_valid() {
        let store = make_store();
        let handler = ChatContactSetHandler::new(Arc::clone(&store));

        let args = json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-bob",
                    "login": "bob@example.com",
                    "mailboxHost": "bob-kith.tail.ts.net"
                }
            }
        });

        let result = handler
            .call("ChatContact/set".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        // Oracle: RFC 8620 §5.3 — created map must have the client-id key.
        let created = &result["created"];
        assert!(
            created.get("c0").is_some(),
            "created.c0 must be present; got: {result}"
        );
        // Oracle: ChatContact has an id field (per kith-core Contact struct).
        assert!(
            created["c0"]["id"].as_str().is_some(),
            "created.c0 must have an id field"
        );
        // Oracle: id IS the userId from the auth layer (I-D §ChatContact).
        assert_eq!(created["c0"]["id"], "uid-bob");
    }

    // Oracle: RFC 8620 §5.3 — displayName > 256 bytes → notCreated.c0 with
    // type=invalidArguments.
    #[tokio::test]
    async fn test_contact_set_create_oversized_display_name() {
        let store = make_store();
        let handler = ChatContactSetHandler::new(Arc::clone(&store));

        let long_name = "x".repeat(257);
        let args = json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-carol",
                    "login": "carol@example.com",
                    "mailboxHost": "carol-kith.tail.ts.net",
                    "displayName": long_name
                }
            }
        });

        let result = handler
            .call("ChatContact/set".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed (errors go in notCreated, not as handler error)");

        let not_created = &result["notCreated"];
        assert!(
            not_created.get("c0").is_some(),
            "notCreated.c0 must be present; got: {result}"
        );
        // Oracle: error type must be invalidArguments.
        assert_eq!(not_created["c0"]["type"], "invalidArguments");
        // Oracle: created must be empty (validation failed before any store write).
        assert_eq!(result["created"], json!({}));
    }

    // Oracle: RFC 8620 §5.3 — destroy any id → notDestroyed with type=forbidden.
    #[tokio::test]
    async fn test_contact_set_destroy_forbidden() {
        let store = make_store();
        let handler = ChatContactSetHandler::new(Arc::clone(&store));

        let args = json!({
            "accountId": "a-self",
            "destroy": ["uid-alice"]
        });

        let result = handler
            .call("ChatContact/set".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let not_destroyed = &result["notDestroyed"];
        assert!(
            not_destroyed.get("uid-alice").is_some(),
            "notDestroyed[uid-alice] must be present; got: {result}"
        );
        // Oracle: error type is forbidden (contacts are auto-managed).
        assert_eq!(not_destroyed["uid-alice"]["type"], "forbidden");
    }

    // Oracle: RFC 8620 §5.6 — /changes with sinceState == currentState →
    // created/updated/destroyed all empty, newState == oldState.
    #[tokio::test]
    async fn test_contact_changes_empty() {
        let store = make_store();
        let current_state = {
            let guard = store.lock().unwrap();
            guard.contacts().get_state().unwrap()
        };

        let handler = ChatContactChangesHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "sinceState": current_state});
        let result = handler
            .call("ChatContact/changes".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        assert_eq!(result["accountId"], "a-self");
        assert_eq!(result["created"], json!([]));
        assert_eq!(result["updated"], json!([]));
        assert_eq!(result["destroyed"], json!([]));
        assert_eq!(result["hasMoreChanges"], false);
        assert_eq!(result["oldState"], current_state);
        assert_eq!(result["newState"], current_state);
    }

    // Oracle: RFC 8620 §5.6 — after upsert, /changes with sinceState="s-0" must
    // include the new contact's id in created.
    #[tokio::test]
    async fn test_contact_changes_after_upsert() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .contacts()
                .upsert(
                    "uid-zara",
                    "zara@example.com",
                    "zara-kith.tail.ts.net",
                    None,
                    7000,
                )
                .unwrap();
        }

        let handler = ChatContactChangesHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "sinceState": "s-0"});
        let result = handler
            .call("ChatContact/changes".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let created = result["created"].as_array().expect("created must be array");
        assert!(
            created.iter().any(|v| v == "uid-zara"),
            "uid-zara must appear in created; got: {created:?}"
        );
    }

    // Oracle: RFC 8620 §5.6 — sinceState that is not a valid state token (non-"s-N")
    // must return a method-level error with type "stateMismatch".
    #[tokio::test]
    async fn test_contact_changes_malformed_state() {
        let store = make_store();
        let handler = ChatContactChangesHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "sinceState": "garbage"});
        let err = handler
            .call("ChatContact/changes".to_string(), "c0".to_string(), args)
            .await
            .expect_err("should return Err for malformed state");

        assert_eq!(
            err.error_type, "stateMismatch",
            "expected stateMismatch error; got: {:?}",
            err
        );
    }

    // Oracle: RFC 8620 Contact/query — with no filter, all contact ids are returned
    // and queryState matches the current state.
    #[tokio::test]
    async fn test_contact_query_all() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .contacts()
                .upsert(
                    "uid-alpha",
                    "alpha@example.com",
                    "alpha-kith.tail.ts.net",
                    None,
                    1000,
                )
                .unwrap();
            guard
                .contacts()
                .upsert(
                    "uid-beta",
                    "beta@example.com",
                    "beta-kith.tail.ts.net",
                    None,
                    2000,
                )
                .unwrap();
        }

        let expected_state = {
            let guard = store.lock().unwrap();
            guard.contacts().get_state().unwrap()
        };

        let handler = ChatContactQueryHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self"});
        let result = handler
            .call("ChatContact/query".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let ids = result["ids"].as_array().expect("ids must be array");
        assert_eq!(ids.len(), 2, "both contacts must be returned; got: {ids:?}");
        let id_strs: Vec<&str> = ids.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            id_strs.contains(&"uid-alpha"),
            "uid-alpha must be in ids; got: {id_strs:?}"
        );
        assert!(
            id_strs.contains(&"uid-beta"),
            "uid-beta must be in ids; got: {id_strs:?}"
        );
        assert_eq!(result["queryState"], expected_state);
    }

    // Oracle: RFC 8620 Contact/query pagination — position=1, limit=2 on a 3-contact
    // store returns ids[1] and ids[2] (0-indexed).
    #[tokio::test]
    async fn test_contact_query_pagination() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            // Insert contacts with logins that sort predictably (a < b < c).
            for (uid, login) in [
                ("uid-p1", "aaa@example.com"),
                ("uid-p2", "bbb@example.com"),
                ("uid-p3", "ccc@example.com"),
            ] {
                guard
                    .contacts()
                    .upsert(uid, login, "host.tail.ts.net", None, 1000)
                    .unwrap();
            }
        }

        let handler = ChatContactQueryHandler::new(Arc::clone(&store));
        let args = json!({"accountId": "a-self", "position": 1, "limit": 2});
        let result = handler
            .call("ChatContact/query".to_string(), "c0".to_string(), args)
            .await
            .expect("should succeed");

        let ids = result["ids"].as_array().expect("ids must be array");
        // list() orders by peer_login ascending: uid-p1 (aaa), uid-p2 (bbb), uid-p3 (ccc).
        // position=1 skips uid-p1; limit=2 takes uid-p2 and uid-p3.
        assert_eq!(
            ids.len(),
            2,
            "pagination must return exactly 2 items; got: {ids:?}"
        );
        assert_eq!(ids[0], "uid-p2", "first paginated id must be uid-p2");
        assert_eq!(ids[1], "uid-p3", "second paginated id must be uid-p3");
        assert_eq!(result["position"], 1);
    }
}
