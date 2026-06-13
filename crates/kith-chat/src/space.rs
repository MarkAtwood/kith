use kith_core::{JmapError, MAX_OBJECTS_IN_GET};
use kith_jmap::{HandlerFuture, JmapHandler};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Space/get
// ---------------------------------------------------------------------------

/// Handler for the `Space/get` JMAP method.
///
/// Returns all spaces (or a specific list) for the owner's account.
pub struct SpaceGetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceGetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceGetHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // Step 1: Extract accountId.
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            // Step 2: Verify accountId.
            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            // Step 3: Parse ids (optional).
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

            // RFC 8620 §5.1: reject if more than maxObjectsInGet IDs are requested.
            if let Some(ref id_list) = ids {
                if id_list.len() > MAX_OBJECTS_IN_GET {
                    return Err(JmapError::too_large());
                }
            }

            // Step 4: Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            // Step 5: Fetch spaces.
            let (spaces, not_found) = match ids {
                None => {
                    let list = guard
                        .spaces()
                        .list_spaces()
                        .map_err(|e| JmapError::server_fail(e.to_string()))?;
                    (list, vec![])
                }
                Some(id_list) => {
                    let mut found = Vec::new();
                    let mut missing: Vec<Value> = Vec::new();
                    for id in id_list {
                        match guard
                            .spaces()
                            .get_space(&id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?
                        {
                            Some(s) => found.push(s),
                            None => missing.push(Value::String(id)),
                        }
                    }
                    (found, missing)
                }
            };

            // Step 6: Get state.
            let state = guard
                .spaces()
                .get_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            // Step 7: Drop lock.
            drop(guard);

            // Step 8: Build and return response.
            Ok(json!({
                "accountId": "a-self",
                "list": spaces,
                "notFound": not_found,
                "state": state,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Space/changes
// ---------------------------------------------------------------------------

/// Handler for the `Space/changes` JMAP method.
///
/// Returns the set of space IDs that have changed since the given state token.
pub struct SpaceChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceChangesHandler {
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

            // Step 3: Acquire store lock.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            // Step 4: Get changes since the given state.
            let (rows, new_state) = guard
                .spaces()
                .get_changes_since_ordered(&since_state)
                .map_err(|e| {
                    use kith_core::KithError;
                    match e {
                        KithError::Jmap(je) => je,
                        _ => JmapError::server_fail("store error"),
                    }
                })?;

            // Step 5: Drop lock.
            drop(guard);

            // Step 6: Split into created[] and updated[] per RFC 8620 §5.6.
            let mut created: Vec<serde_json::Value> = Vec::new();
            let mut updated: Vec<serde_json::Value> = Vec::new();
            for (id, _counter, is_create) in rows {
                if is_create {
                    created.push(serde_json::Value::String(id));
                } else {
                    updated.push(serde_json::Value::String(id));
                }
            }

            // Step 7: Return response.
            Ok(json!({
                "accountId": "a-self",
                "oldState": since_state,
                "newState": new_state,
                "hasMoreChanges": false,
                "created": created,
                "updated": updated,
                "destroyed": [],
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

    // Oracle: Space/get with ids=None on an empty store must return an empty list
    // and state "s-0" (schema initializes space counter to 0).
    #[tokio::test]
    async fn test_space_get_empty() {
        let store = make_store();
        let handler = SpaceGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("Space/get must succeed");

        assert_eq!(result["accountId"], "a-self");
        assert_eq!(result["list"], json!([]));
        assert_eq!(result["state"], "s-0");
    }

    // Oracle: Space/get after creating a space must return it in the list.
    #[tokio::test]
    async fn test_space_get_after_create() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("space-1", "Test Space", None, None, false, false, 1_000_000)
                .expect("create space");
        }

        let handler = SpaceGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("Space/get must succeed");

        let list = result["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 1, "must return 1 space; got: {list:?}");
        assert_eq!(
            list[0]["id"], "space-1",
            "space id must match; got: {:?}",
            list[0]
        );
        assert_eq!(
            list[0]["name"], "Test Space",
            "space name must match; got: {:?}",
            list[0]
        );
    }

    // Oracle: Space/get with specific IDs must return only the requested spaces.
    #[tokio::test]
    async fn test_space_get_by_ids() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("space-a", "Alpha", None, None, false, false, 1_000_000)
                .expect("create space a");
            guard
                .spaces()
                .create_space("space-b", "Beta", None, None, false, false, 1_000_001)
                .expect("create space b");
        }

        let handler = SpaceGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "ids": ["space-a"]}),
            )
            .await
            .expect("Space/get must succeed");

        let list = result["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 1, "must return 1 space; got: {list:?}");
        assert_eq!(list[0]["id"], "space-a");
        assert_eq!(result["notFound"], json!([]));
    }

    // Oracle: Space/get with an unknown ID must report it in notFound.
    #[tokio::test]
    async fn test_space_get_not_found() {
        let store = make_store();
        let handler = SpaceGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "ids": ["no-such-space"]}),
            )
            .await
            .expect("Space/get must succeed");

        assert_eq!(result["list"], json!([]));
        let not_found = result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert!(
            not_found.contains(&json!("no-such-space")),
            "no-such-space must appear in notFound, got: {not_found:?}"
        );
    }

    // Oracle: Space/get with invalid accountId must return accountNotFound.
    #[tokio::test]
    async fn test_space_get_wrong_account() {
        let store = make_store();
        let handler = SpaceGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-wrong"}),
            )
            .await;

        assert!(result.is_err(), "expected Err for wrong accountId");
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "accountNotFound");
    }

    // Oracle: Space/changes from "s-0" against an empty store must return empty lists.
    #[tokio::test]
    async fn test_space_changes_empty() {
        let store = make_store();
        let handler = SpaceChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": "s-0"}),
            )
            .await
            .expect("Space/changes must succeed");

        assert_eq!(result["accountId"], "a-self");
        assert_eq!(result["created"], json!([]));
        assert_eq!(result["updated"], json!([]));
        assert_eq!(result["destroyed"], json!([]));
        assert_eq!(result["hasMoreChanges"], false);
    }

    // Oracle: Space/changes from "s-0" after creating a space must include
    // the space ID in the created list.
    #[tokio::test]
    async fn test_space_changes_after_create() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("space-new", "New Space", None, None, false, false, 1_000_000)
                .expect("create space");
        }

        let handler = SpaceChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": "s-0"}),
            )
            .await
            .expect("Space/changes must succeed");

        let created = result["created"].as_array().expect("created must be array");
        assert!(
            created.contains(&json!("space-new")),
            "space-new must appear in created; got: {created:?}"
        );
    }

    // Oracle: Space/changes at the current state must return empty lists.
    #[tokio::test]
    async fn test_space_changes_at_current_state() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("space-x", "X", None, None, false, false, 1_000_000)
                .expect("create space");
        }

        let current_state = {
            let guard = store.lock().unwrap();
            guard.spaces().get_state().unwrap()
        };

        let handler = SpaceChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": current_state}),
            )
            .await
            .expect("Space/changes must succeed");

        assert_eq!(result["created"], json!([]));
        assert_eq!(result["updated"], json!([]));
        assert_eq!(result["destroyed"], json!([]));
    }

    // Oracle: Space/changes with a malformed sinceState must return
    // cannotCalculateChanges (RFC 8620 §5.5).
    #[tokio::test]
    async fn test_space_changes_malformed_state() {
        let store = make_store();
        let handler = SpaceChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/changes".to_string(),
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

    // Oracle: Space/changes correctly reports updated IDs in the updated list
    // (not created) when a space is modified after initial creation.
    #[tokio::test]
    async fn test_space_changes_distinguishes_created_and_updated() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("space-cu", "Original", None, None, false, false, 1_000_000)
                .expect("create space");
        }

        // Capture state after create.
        let mid_state = {
            let guard = store.lock().unwrap();
            guard.spaces().get_state().unwrap()
        };

        // Update the space name (advances state counter).
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .update_space_metadata("space-cu", Some("Updated"), None, None)
                .expect("update space");
        }

        let handler = SpaceChangesHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/changes".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "sinceState": mid_state}),
            )
            .await
            .expect("Space/changes must succeed");

        let created = result["created"].as_array().expect("created must be array");
        let updated = result["updated"].as_array().expect("updated must be array");

        assert!(
            created.is_empty(),
            "space-cu must not appear in created after update; got: {created:?}"
        );
        assert!(
            updated.contains(&json!("space-cu")),
            "space-cu must appear in updated; got: {updated:?}"
        );
    }

    // Oracle: Space/get response contains correct state field matching
    // the store's current state counter.
    #[tokio::test]
    async fn test_space_get_state_field_matches_store() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("space-st", "Stateful", None, None, false, false, 1_000_000)
                .expect("create space");
        }

        let expected_state = {
            let guard = store.lock().unwrap();
            guard.spaces().get_state().unwrap()
        };

        let handler = SpaceGetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("Space/get must succeed");

        assert_eq!(
            result["state"], expected_state,
            "state field must match store state"
        );
    }
}
