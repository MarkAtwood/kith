use crate::kith_to_jmap;
use kith_core::{JmapError, KithError, SPACE_PERMISSION_NAMES, MAX_OBJECTS_IN_GET};
use kith_jmap::{HandlerFuture, JmapHandler};
use rand::Rng;
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

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

// ---------------------------------------------------------------------------
// Space/set
// ---------------------------------------------------------------------------

/// Handler for the `Space/set` JMAP method.
///
/// Uses semantic mutations instead of RFC 8620 PatchObject paths.
/// Create requires `name`; update accepts named keys like `name`,
/// `description`, `addRoles`, `removeMembers`, etc.
pub struct SpaceSetHandler {
    store: Arc<Mutex<kith_store::Store>>,
    /// Verified Tailscale user ID of the mailbox owner, used as the
    /// creator/admin member when creating a new space.
    owner_user_id: String,
}

impl SpaceSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>, owner_user_id: String) -> Self {
        Self {
            store,
            owner_user_id,
        }
    }
}

impl JmapHandler for SpaceSetHandler {
    fn call(&self, _method_name: String, _call_id: String, args: Value) -> HandlerFuture {
        let store = Arc::clone(&self.store);
        let owner_user_id = self.owner_user_id.clone();

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

            // Parse create / update / destroy from args (same shape as RFC 8620 §5.3).
            let create_map: Option<&Map<String, Value>> = match obj.get("create") {
                None | Some(Value::Null) => None,
                Some(Value::Object(m)) => Some(m),
                Some(_) => {
                    return Err(JmapError::invalid_arguments(
                        "create must be an object or null",
                    ))
                }
            };
            let update_map: Option<&Map<String, Value>> = match obj.get("update") {
                None | Some(Value::Null) => None,
                Some(Value::Object(m)) => Some(m),
                Some(_) => {
                    return Err(JmapError::invalid_arguments(
                        "update must be an object or null",
                    ))
                }
            };
            let destroy_list: Option<Vec<String>> = match obj.get("destroy") {
                None | Some(Value::Null) => None,
                Some(Value::Array(arr)) => {
                    let mut ids = Vec::with_capacity(arr.len());
                    for x in arr {
                        match x.as_str() {
                            Some(s) => ids.push(s.to_string()),
                            None => {
                                return Err(JmapError::invalid_arguments(
                                    "destroy array must contain only strings",
                                ));
                            }
                        }
                    }
                    Some(ids)
                }
                _ => {
                    return Err(JmapError::invalid_arguments(
                        "destroy must be an array or null",
                    ));
                }
            };

            let mut created: Map<String, Value> = Map::new();
            let mut not_created: Map<String, Value> = Map::new();
            let mut updated: Map<String, Value> = Map::new();
            let mut not_updated: Map<String, Value> = Map::new();
            let mut destroyed: Vec<Value> = Vec::new();
            let mut not_destroyed: Map<String, Value> = Map::new();

            let mut old_state_cell: Option<String> = None;
            let mut new_state_cell: Option<String> = None;

            // --- Creates ---
            if let Some(creates) = create_map {
                for (client_id, value) in creates {
                    match space_set_create(
                        &store,
                        client_id,
                        value,
                        &owner_user_id,
                        &mut old_state_cell,
                        &mut new_state_cell,
                    ) {
                        Ok(space_value) => {
                            created.insert(client_id.clone(), space_value);
                        }
                        Err(err_value) => {
                            not_created.insert(client_id.clone(), err_value);
                        }
                    }
                }
            }

            // --- Updates (semantic mutations) ---
            if let Some(updates) = update_map {
                for (server_id, patch) in updates {
                    match space_set_update(
                        &store,
                        server_id,
                        patch,
                        &mut old_state_cell,
                        &mut new_state_cell,
                    ) {
                        Ok(()) => {
                            updated.insert(server_id.clone(), Value::Null);
                        }
                        Err(err_value) => {
                            not_updated.insert(server_id.clone(), err_value);
                        }
                    }
                }
            }

            // --- Destroys ---
            if let Some(destroy_ids) = destroy_list {
                for id in destroy_ids {
                    match space_set_destroy(
                        &store,
                        &id,
                        &mut old_state_cell,
                        &mut new_state_cell,
                    ) {
                        Ok(()) => {
                            destroyed.push(Value::String(id));
                        }
                        Err(err_value) => {
                            not_destroyed.insert(id, err_value);
                        }
                    }
                }
            }

            // Resolve old_state / new_state.
            let (old_state, new_state) = match (old_state_cell, new_state_cell) {
                (Some(old), Some(new)) => (old, new),
                _ => {
                    let guard = store
                        .lock()
                        .map_err(|_| JmapError::server_fail("internal error"))?;
                    let s = guard.spaces().get_state().map_err(kith_to_jmap)?;
                    (s.clone(), s)
                }
            };

            Ok(json!({
                "accountId": "a-self",
                "oldState": old_state,
                "newState": new_state,
                "created": created,
                "updated": updated,
                "destroyed": destroyed,
                "notCreated": not_created,
                "notUpdated": not_updated,
                "notDestroyed": not_destroyed,
            }))
        })
    }
}

/// Process a single Space/set create entry.
fn space_set_create(
    store: &Arc<Mutex<kith_store::Store>>,
    _client_id: &str,
    value: &Value,
    owner_user_id: &str,
    old_state_out: &mut Option<String>,
    new_state_out: &mut Option<String>,
) -> Result<Value, Value> {
    let obj = value.as_object().ok_or_else(
        || json!({"type": "invalidArguments", "description": "create entry must be an object"}),
    )?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"type": "invalidArguments", "description": "name is required"}))?;

    if name.is_empty() {
        return Err(json!({"type": "invalidArguments", "description": "name must not be empty"}));
    }

    let description = obj.get("description").and_then(|v| v.as_str());
    let icon_blob_id = obj.get("iconBlobId").and_then(|v| v.as_str());

    let space_id = Ulid::new().to_string().to_lowercase();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "internal error"}))?;

    // Capture old state before any writes.
    if old_state_out.is_none() {
        *old_state_out = Some(
            guard
                .spaces()
                .get_state()
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?,
        );
    }

    // Create the space.
    let space = guard
        .spaces()
        .create_space(
            &space_id,
            name,
            description,
            icon_blob_id,
            false,
            false,
            now_unix,
        )
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Create an admin role with all permissions and add the caller as a member.
    let admin_role_id = Ulid::new().to_string().to_lowercase();
    let all_perms: Vec<&str> = SPACE_PERMISSION_NAMES.to_vec();
    guard
        .spaces()
        .add_role(&space_id, &admin_role_id, "Admin", None, &all_perms, 1)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    guard
        .spaces()
        .add_member(
            &space_id,
            owner_user_id,
            None,
            now_unix,
            &[admin_role_id.as_str()],
        )
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    // Capture new state.
    let new_state = guard
        .spaces()
        .get_state()
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    *new_state_out = Some(new_state);

    drop(guard);

    // Re-fetch the space to include roles and members in the response.
    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "internal error"}))?;
    let full_space = guard
        .spaces()
        .get_space(&space_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?
        .ok_or_else(|| {
            json!({"type": "serverFail", "description": "space vanished after creation"})
        })?;
    drop(guard);

    // Serialize the space. Use the full Space object minus the initial
    // skeleton -- serde_json::to_value gives us the canonical form.
    let _ = space; // consumed by the re-fetch above
    Ok(serde_json::to_value(full_space)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?)
}

/// Process a single Space/set update entry using semantic mutation keys.
fn space_set_update(
    store: &Arc<Mutex<kith_store::Store>>,
    server_id: &str,
    patch: &Value,
    old_state_out: &mut Option<String>,
    new_state_out: &mut Option<String>,
) -> Result<(), Value> {
    let obj = patch.as_object().ok_or_else(
        || json!({"type": "invalidArguments", "description": "update entry must be an object"}),
    )?;

    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "internal error"}))?;

    // Verify the space exists.
    let existing = guard
        .spaces()
        .get_space(server_id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    if existing.is_none() {
        return Err(json!({"type": "notFound", "description": "space not found"}));
    }

    // Capture old state before any writes.
    if old_state_out.is_none() {
        *old_state_out = Some(
            guard
                .spaces()
                .get_state()
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?,
        );
    }

    // --- Metadata: name, description, iconBlobId ---
    let new_name = obj.get("name").and_then(|v| v.as_str());
    let new_description: Option<Option<&str>> = if obj.contains_key("description") {
        Some(obj["description"].as_str())
    } else {
        None
    };
    let new_icon: Option<Option<&str>> = if obj.contains_key("iconBlobId") {
        Some(obj["iconBlobId"].as_str())
    } else {
        None
    };

    if new_name.is_some() || new_description.is_some() || new_icon.is_some() {
        guard
            .spaces()
            .update_space_metadata(server_id, new_name, new_description, new_icon)
            .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    }

    // --- addRoles ---
    if let Some(Value::Array(roles)) = obj.get("addRoles") {
        for role_val in roles {
            let role_obj = role_val.as_object().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "addRoles entries must be objects"})
            })?;
            let role_name = role_obj
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    json!({"type": "invalidArguments", "description": "role name is required"})
                })?;
            let permissions: Vec<&str> = match role_obj.get("permissions") {
                Some(Value::Array(arr)) => {
                    let mut perms = Vec::with_capacity(arr.len());
                    for p in arr {
                        let s = p.as_str().ok_or_else(|| {
                            json!({"type": "invalidArguments", "description": "permissions must be strings"})
                        })?;
                        if !SPACE_PERMISSION_NAMES.contains(&s) {
                            return Err(json!({"type": "invalidArguments", "description": format!("unknown permission: {s}")}));
                        }
                        perms.push(s);
                    }
                    perms
                }
                None | Some(Value::Null) => vec![],
                _ => {
                    return Err(json!({"type": "invalidArguments", "description": "permissions must be an array"}));
                }
            };
            let position = role_obj
                .get("position")
                .and_then(|v| v.as_u64())
                .unwrap_or(1);
            let role_id = Ulid::new().to_string().to_lowercase();
            let color = role_obj.get("color").and_then(|v| v.as_str());
            guard
                .spaces()
                .add_role(
                    server_id,
                    &role_id,
                    role_name,
                    color,
                    &permissions,
                    position.max(1),
                )
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- removeRoles ---
    if let Some(Value::Array(role_ids)) = obj.get("removeRoles") {
        for rid_val in role_ids {
            let rid = rid_val.as_str().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "removeRoles entries must be strings"})
            })?;
            guard
                .spaces()
                .remove_role(rid)
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- updateRoles ---
    if let Some(Value::Array(roles)) = obj.get("updateRoles") {
        for role_val in roles {
            let role_obj = role_val.as_object().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "updateRoles entries must be objects"})
            })?;
            let role_id = role_obj
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    json!({"type": "invalidArguments", "description": "updateRoles entry requires id"})
                })?;
            let name = role_obj.get("name").and_then(|v| v.as_str());
            let color: Option<Option<&str>> = if role_obj.contains_key("color") {
                Some(role_obj["color"].as_str())
            } else {
                None
            };
            let permissions: Option<Vec<&str>> = match role_obj.get("permissions") {
                Some(Value::Array(arr)) => {
                    let mut perms = Vec::with_capacity(arr.len());
                    for p in arr {
                        let s = p.as_str().ok_or_else(|| {
                            json!({"type": "invalidArguments", "description": "permissions must be strings"})
                        })?;
                        perms.push(s);
                    }
                    Some(perms)
                }
                None | Some(Value::Null) => None,
                _ => {
                    return Err(json!({"type": "invalidArguments", "description": "permissions must be an array"}));
                }
            };
            let position = role_obj.get("position").and_then(|v| v.as_u64());
            guard
                .spaces()
                .update_role(
                    role_id,
                    name,
                    color,
                    permissions.as_deref(),
                    position,
                )
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- addMembers ---
    if let Some(Value::Array(members)) = obj.get("addMembers") {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        for member_val in members {
            let member_obj = member_val.as_object().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "addMembers entries must be objects"})
            })?;
            let user_id = member_obj
                .get("userId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    json!({"type": "invalidArguments", "description": "addMembers entry requires userId"})
                })?;
            let nick = member_obj.get("nick").and_then(|v| v.as_str());
            let role_ids: Vec<&str> = match member_obj.get("roleIds") {
                Some(Value::Array(arr)) => {
                    let mut rids = Vec::with_capacity(arr.len());
                    for r in arr {
                        rids.push(r.as_str().ok_or_else(|| {
                            json!({"type": "invalidArguments", "description": "roleIds must be strings"})
                        })?);
                    }
                    rids
                }
                None | Some(Value::Null) => vec![],
                _ => {
                    return Err(json!({"type": "invalidArguments", "description": "roleIds must be an array"}));
                }
            };
            guard
                .spaces()
                .add_member(server_id, user_id, nick, now_unix, &role_ids)
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- removeMembers ---
    if let Some(Value::Array(user_ids)) = obj.get("removeMembers") {
        for uid_val in user_ids {
            let uid = uid_val.as_str().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "removeMembers entries must be strings"})
            })?;
            guard
                .spaces()
                .remove_member(server_id, uid)
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- updateMembers ---
    if let Some(Value::Array(members)) = obj.get("updateMembers") {
        for member_val in members {
            let member_obj = member_val.as_object().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "updateMembers entries must be objects"})
            })?;
            let user_id = member_obj
                .get("userId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    json!({"type": "invalidArguments", "description": "updateMembers entry requires userId"})
                })?;
            let nick: Option<Option<&str>> = if member_obj.contains_key("nick") {
                Some(member_obj["nick"].as_str())
            } else {
                None
            };
            let role_ids: Option<Vec<&str>> = match member_obj.get("roleIds") {
                Some(Value::Array(arr)) => {
                    let mut rids = Vec::with_capacity(arr.len());
                    for r in arr {
                        rids.push(r.as_str().ok_or_else(|| {
                            json!({"type": "invalidArguments", "description": "roleIds must be strings"})
                        })?);
                    }
                    Some(rids)
                }
                None | Some(Value::Null) => None,
                _ => {
                    return Err(json!({"type": "invalidArguments", "description": "roleIds must be an array"}));
                }
            };
            guard
                .spaces()
                .update_member(
                    server_id,
                    user_id,
                    nick,
                    role_ids.as_deref(),
                )
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- addCategories ---
    if let Some(Value::Array(categories)) = obj.get("addCategories") {
        for cat_val in categories {
            let cat_obj = cat_val.as_object().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "addCategories entries must be objects"})
            })?;
            let cat_name = cat_obj
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    json!({"type": "invalidArguments", "description": "category name is required"})
                })?;
            let position = cat_obj
                .get("position")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let cat_id = Ulid::new().to_string().to_lowercase();
            guard
                .spaces()
                .add_category(server_id, &cat_id, cat_name, position)
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- removeCategories ---
    if let Some(Value::Array(cat_ids)) = obj.get("removeCategories") {
        for cid_val in cat_ids {
            let cid = cid_val.as_str().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "removeCategories entries must be strings"})
            })?;
            guard
                .spaces()
                .remove_category(cid)
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // --- updateCategories ---
    if let Some(Value::Array(categories)) = obj.get("updateCategories") {
        for cat_val in categories {
            let cat_obj = cat_val.as_object().ok_or_else(|| {
                json!({"type": "invalidArguments", "description": "updateCategories entries must be objects"})
            })?;
            let cat_id = cat_obj
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    json!({"type": "invalidArguments", "description": "updateCategories entry requires id"})
                })?;
            let cat_name = cat_obj
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    json!({"type": "invalidArguments", "description": "updateCategories entry requires name"})
                })?;
            let position = cat_obj
                .get("position")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            guard
                .spaces()
                .update_category(cat_id, cat_name, position)
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
        }
    }

    // Capture new state.
    let new_state = guard
        .spaces()
        .get_state()
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    *new_state_out = Some(new_state);

    Ok(())
}

/// Process a single Space/set destroy entry.
fn space_set_destroy(
    store: &Arc<Mutex<kith_store::Store>>,
    id: &str,
    old_state_out: &mut Option<String>,
    new_state_out: &mut Option<String>,
) -> Result<(), Value> {
    let guard = store
        .lock()
        .map_err(|_| json!({"type": "serverFail", "description": "internal error"}))?;

    // Capture old state before write.
    if old_state_out.is_none() {
        *old_state_out = Some(
            guard
                .spaces()
                .get_state()
                .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?,
        );
    }

    // Verify the space exists before attempting to delete.
    let existing = guard
        .spaces()
        .get_space(id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    if existing.is_none() {
        return Err(json!({"type": "notFound", "description": "space not found"}));
    }

    guard
        .spaces()
        .delete_space(id)
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;

    let new_state = guard
        .spaces()
        .get_state()
        .map_err(|e| json!({"type": "serverFail", "description": e.to_string()}))?;
    *new_state_out = Some(new_state);

    Ok(())
}

// ---------------------------------------------------------------------------
// Space/query
// ---------------------------------------------------------------------------

/// Handler for the `Space/query` JMAP method.
///
/// Standard JMAP /query per RFC 8620 §5.5.  Filters by `name` (substring)
/// and `isPublic` (boolean).  Default sort: name ascending.
pub struct SpaceQueryHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceQueryHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceQueryHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            // Parse filter.
            let filter = args.get("filter");
            let filter_name: Option<String> = filter
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let filter_public: Option<bool> = filter
                .and_then(|f| f.get("isPublic"))
                .and_then(|v| v.as_bool());

            // Parse pagination.
            let position: u32 = match args.get("position") {
                None | Some(Value::Null) => 0,
                Some(v) => v
                    .as_u64()
                    .ok_or_else(|| JmapError::invalid_arguments("position must be a number"))?
                    as u32,
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

            // Query store.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            let all_ids = guard
                .spaces()
                .query_spaces(filter_name.as_deref(), filter_public)
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            let total = all_ids.len() as u64;

            // Apply position + limit.
            let start = (position as usize).min(all_ids.len());
            let end = match limit {
                Some(l) => (start + l as usize).min(all_ids.len()),
                None => all_ids.len(),
            };
            let page: Vec<&str> = all_ids[start..end].iter().map(|s| s.as_str()).collect();

            let query_state = guard
                .spaces()
                .get_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            drop(guard);

            Ok(json!({
                "accountId": "a-self",
                "queryState": query_state,
                "canCalculateChanges": false,
                "position": position,
                "ids": page,
                "total": if calculate_total { json!(total) } else { Value::Null },
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Space/join
// ---------------------------------------------------------------------------

/// Handler for the `Space/join` JMAP method.
///
/// Accepts exactly one of `inviteCode` or `spaceId` (not both, not neither).
/// Via inviteCode: resolve invite, check validity/ban, add member, increment uses.
/// Via spaceId: check isPublic/ban, add member.
pub struct SpaceJoinHandler {
    store: Arc<Mutex<kith_store::Store>>,
    owner_user_id: String,
}

impl SpaceJoinHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>, owner_user_id: String) -> Self {
        Self {
            store,
            owner_user_id,
        }
    }
}

impl JmapHandler for SpaceJoinHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);
        let owner_user_id = self.owner_user_id.clone();

        Box::pin(async move {
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            let invite_code = args.get("inviteCode").and_then(|v| v.as_str());
            let space_id_arg = args.get("spaceId").and_then(|v| v.as_str());

            // Exactly one of inviteCode or spaceId must be provided.
            match (invite_code, space_id_arg) {
                (Some(_), Some(_)) => {
                    return Err(JmapError::invalid_arguments(
                        "exactly one of inviteCode or spaceId must be provided, not both",
                    ));
                }
                (None, None) => {
                    return Err(JmapError::invalid_arguments(
                        "exactly one of inviteCode or spaceId is required",
                    ));
                }
                _ => {}
            }

            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            let joined_space_id = if let Some(code) = invite_code {
                // --- Join via invite code ---
                let invite = guard
                    .spaces()
                    .resolve_invite_by_code(code)
                    .map_err(|e| JmapError::server_fail(e.to_string()))?
                    .ok_or_else(|| JmapError::not_found())?;

                if !kith_store::space::SpaceStore::is_invite_valid(&invite, now_unix) {
                    return Err(JmapError::invalid_arguments("invite is expired or exhausted"));
                }

                let sid: String = invite.space_id.as_ref().to_string();

                if guard
                    .spaces()
                    .is_banned(&sid, &owner_user_id, now_unix)
                    .map_err(|e| JmapError::server_fail(e.to_string()))?
                {
                    return Err(JmapError::forbidden());
                }

                guard
                    .spaces()
                    .add_member(&sid, &owner_user_id, None, now_unix, &[])
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                let invite_id: String = invite.id.as_ref().to_string();
                guard
                    .spaces()
                    .increment_invite_uses(&invite_id)
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                sid
            } else {
                // --- Join via spaceId ---
                let sid = space_id_arg.expect("spaceId guaranteed present");

                let space = guard
                    .spaces()
                    .get_space(sid)
                    .map_err(|e| JmapError::server_fail(e.to_string()))?
                    .ok_or_else(|| JmapError::not_found())?;

                if !space.is_public {
                    return Err(JmapError::forbidden());
                }

                if guard
                    .spaces()
                    .is_banned(sid, &owner_user_id, now_unix)
                    .map_err(|e| JmapError::server_fail(e.to_string()))?
                {
                    return Err(JmapError::forbidden());
                }

                guard
                    .spaces()
                    .add_member(sid, &owner_user_id, None, now_unix, &[])
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                sid.to_string()
            };

            drop(guard);

            Ok(json!({
                "accountId": "a-self",
                "joined": joined_space_id,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// SpaceInvite/get
// ---------------------------------------------------------------------------

/// Handler for the `SpaceInvite/get` JMAP method.
///
/// Returns all invites (or a specific list by IDs) for the owner's account.
pub struct SpaceInviteGetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceInviteGetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceInviteGetHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

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

            if let Some(ref id_list) = ids {
                if id_list.len() > MAX_OBJECTS_IN_GET {
                    return Err(JmapError::too_large());
                }
            }

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            let (invites, not_found) = match ids {
                None => {
                    let list = guard
                        .spaces()
                        .list_all_invites()
                        .map_err(|e| JmapError::server_fail(e.to_string()))?;
                    (list, vec![])
                }
                Some(id_list) => {
                    let mut found = Vec::new();
                    let mut missing: Vec<Value> = Vec::new();
                    for id in id_list {
                        match guard
                            .spaces()
                            .get_invite(&id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?
                        {
                            Some(inv) => found.push(inv),
                            None => missing.push(Value::String(id)),
                        }
                    }
                    (found, missing)
                }
            };

            let state = guard
                .spaces()
                .get_invite_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            drop(guard);

            Ok(json!({
                "accountId": "a-self",
                "list": invites,
                "notFound": not_found,
                "state": state,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// SpaceInvite/changes
// ---------------------------------------------------------------------------

/// Handler for the `SpaceInvite/changes` JMAP method.
///
/// Returns `cannotCalculateChanges` for any non-current sinceState because the
/// invite table does not have per-row change tracking columns. When sinceState
/// equals the current state, returns empty change lists.
pub struct SpaceInviteChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceInviteChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceInviteChangesHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
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

            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            // Validate sinceState format.
            let since_counter = since_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .ok_or_else(|| {
                    KithError::Jmap(kith_core::JmapError::cannot_calculate_changes())
                })
                .map_err(crate::kith_to_jmap)?;

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            let current_state = guard
                .spaces()
                .get_invite_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            let current_counter: i64 = current_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .expect("get_invite_state always returns s-<integer>");

            drop(guard);

            if since_counter > current_counter {
                return Err(JmapError::cannot_calculate_changes());
            }

            // No per-row tracking — if state matches, nothing changed; otherwise
            // we cannot enumerate individual changes.
            if since_counter < current_counter {
                return Err(JmapError::cannot_calculate_changes());
            }

            Ok(json!({
                "accountId": "a-self",
                "oldState": since_state,
                "newState": current_state,
                "hasMoreChanges": false,
                "created": [],
                "updated": [],
                "destroyed": [],
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// SpaceInvite/set
// ---------------------------------------------------------------------------

/// Handler for the `SpaceInvite/set` JMAP method.
///
/// Create: requires `spaceId`, optional `defaultChannelId`, `expiresAt`, `maxUses`.
/// Update: not supported — returns `forbidden`.
/// Destroy: deletes the invite.
pub struct SpaceInviteSetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceInviteSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceInviteSetHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

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

            let now_unix: i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let mut created_map: Map<String, Value> = Map::new();
            let mut not_created: Map<String, Value> = Map::new();
            let updated_map: Map<String, Value> = Map::new();
            let mut not_updated: Map<String, Value> = Map::new();
            let mut destroyed_ids: Vec<Value> = Vec::new();
            let mut not_destroyed: Map<String, Value> = Map::new();

            let (old_state, new_state) = {
                let guard = store
                    .lock()
                    .map_err(|_| JmapError::server_fail("internal error"))?;

                let old_state = guard
                    .spaces()
                    .get_invite_state()
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                // Process creates.
                if let Some(create_map) = create {
                    for (client_id, fields) in create_map {
                        let space_id = match fields.get("spaceId").and_then(|v| v.as_str()) {
                            Some(id) => id.to_string(),
                            None => {
                                not_created.insert(
                                    client_id,
                                    json!({"type": "invalidArguments", "description": "spaceId is required"}),
                                );
                                continue;
                            }
                        };

                        let default_channel_id =
                            fields.get("defaultChannelId").and_then(|v| v.as_str());

                        let expires_at: Option<i64> =
                            fields.get("expiresAt").and_then(|v| v.as_i64());

                        let max_uses: Option<i64> =
                            fields.get("maxUses").and_then(|v| v.as_i64());

                        let invite_id = Ulid::new().to_string();
                        let code: String = rand::rng()
                            .sample_iter(rand::distr::Alphanumeric)
                            .take(8)
                            .map(char::from)
                            .collect();

                        match guard.spaces().create_invite(
                            &invite_id,
                            &code,
                            &space_id,
                            "owner",
                            default_channel_id,
                            expires_at,
                            max_uses,
                            now_unix,
                        ) {
                            Ok(()) => {
                                let invite = guard
                                    .spaces()
                                    .get_invite(&invite_id)
                                    .map_err(|e| JmapError::server_fail(e.to_string()))?
                                    .ok_or_else(|| {
                                        JmapError::server_fail("invite not found after create")
                                    })?;
                                let invite_value = serde_json::to_value(invite)
                                    .map_err(|e| JmapError::server_fail(e.to_string()))?;
                                created_map.insert(client_id, invite_value);
                            }
                            Err(e) => {
                                not_created.insert(
                                    client_id,
                                    json!({"type": "serverFail", "description": e.to_string()}),
                                );
                            }
                        }
                    }
                }

                // Process updates — not supported, return forbidden.
                if let Some(update_map) = update {
                    for (invite_id, _patch) in update_map {
                        not_updated.insert(
                            invite_id,
                            json!({"type": "forbidden", "description": "SpaceInvite updates are not supported"}),
                        );
                    }
                }

                // Process destroys.
                if let Some(destroy_list) = destroy {
                    for invite_id in destroy_list {
                        match guard.spaces().delete_invite(&invite_id) {
                            Ok(()) => {
                                destroyed_ids.push(Value::String(invite_id));
                            }
                            Err(e) => {
                                not_destroyed.insert(
                                    invite_id,
                                    json!({"type": "serverFail", "description": e.to_string()}),
                                );
                            }
                        }
                    }
                }

                let new_state = guard
                    .spaces()
                    .get_invite_state()
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                (old_state, new_state)
            };

            Ok(json!({
                "accountId": "a-self",
                "oldState": old_state,
                "newState": new_state,
                "created": created_map,
                "notCreated": not_created,
                "updated": updated_map,
                "notUpdated": not_updated,
                "destroyed": destroyed_ids,
                "notDestroyed": not_destroyed,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// SpaceBan/get
// ---------------------------------------------------------------------------

/// Handler for the `SpaceBan/get` JMAP method.
///
/// Returns all bans (or a specific list by IDs) for the owner's account.
pub struct SpaceBanGetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceBanGetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceBanGetHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

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

            if let Some(ref id_list) = ids {
                if id_list.len() > MAX_OBJECTS_IN_GET {
                    return Err(JmapError::too_large());
                }
            }

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            let (bans, not_found) = match ids {
                None => {
                    let list = guard
                        .spaces()
                        .list_all_bans()
                        .map_err(|e| JmapError::server_fail(e.to_string()))?;
                    (list, vec![])
                }
                Some(id_list) => {
                    let mut found = Vec::new();
                    let mut missing: Vec<Value> = Vec::new();
                    for id in id_list {
                        match guard
                            .spaces()
                            .get_ban(&id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?
                        {
                            Some(ban) => found.push(ban),
                            None => missing.push(Value::String(id)),
                        }
                    }
                    (found, missing)
                }
            };

            let state = guard
                .spaces()
                .get_ban_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            drop(guard);

            Ok(json!({
                "accountId": "a-self",
                "list": bans,
                "notFound": not_found,
                "state": state,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// SpaceBan/changes
// ---------------------------------------------------------------------------

/// Handler for the `SpaceBan/changes` JMAP method.
///
/// Returns `cannotCalculateChanges` for any non-current sinceState because the
/// ban table does not have per-row change tracking columns. When sinceState
/// equals the current state, returns empty change lists.
pub struct SpaceBanChangesHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceBanChangesHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceBanChangesHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
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

            if account_id != "a-self" {
                return Err(JmapError::account_not_found());
            }

            // Validate sinceState format.
            let since_counter = since_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .ok_or_else(|| {
                    KithError::Jmap(kith_core::JmapError::cannot_calculate_changes())
                })
                .map_err(crate::kith_to_jmap)?;

            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("internal error"))?;

            let current_state = guard
                .spaces()
                .get_ban_state()
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            let current_counter: i64 = current_state
                .strip_prefix("s-")
                .and_then(|n| n.parse::<i64>().ok())
                .expect("get_ban_state always returns s-<integer>");

            drop(guard);

            if since_counter > current_counter {
                return Err(JmapError::cannot_calculate_changes());
            }

            if since_counter < current_counter {
                return Err(JmapError::cannot_calculate_changes());
            }

            Ok(json!({
                "accountId": "a-self",
                "oldState": since_state,
                "newState": current_state,
                "hasMoreChanges": false,
                "created": [],
                "updated": [],
                "destroyed": [],
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// SpaceBan/set
// ---------------------------------------------------------------------------

/// Handler for the `SpaceBan/set` JMAP method.
///
/// Create: requires `spaceId` and `userId`, optional `reason` and `expiresAt`.
/// Update: supports `reason` and `expiresAt` changes only.
/// Destroy: lifts the ban.
pub struct SpaceBanSetHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl SpaceBanSetHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for SpaceBanSetHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let account_id = args
                .get("accountId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JmapError::invalid_arguments("accountId is required"))?
                .to_string();

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

            let now_unix: i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let mut created_map: Map<String, Value> = Map::new();
            let mut not_created: Map<String, Value> = Map::new();
            let mut updated_map: Map<String, Value> = Map::new();
            let mut not_updated: Map<String, Value> = Map::new();
            let mut destroyed_ids: Vec<Value> = Vec::new();
            let mut not_destroyed: Map<String, Value> = Map::new();

            let (old_state, new_state) = {
                let guard = store
                    .lock()
                    .map_err(|_| JmapError::server_fail("internal error"))?;

                let old_state = guard
                    .spaces()
                    .get_ban_state()
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                // Process creates.
                if let Some(create_map) = create {
                    for (client_id, fields) in create_map {
                        let space_id = match fields.get("spaceId").and_then(|v| v.as_str()) {
                            Some(id) => id.to_string(),
                            None => {
                                not_created.insert(
                                    client_id,
                                    json!({"type": "invalidArguments", "description": "spaceId is required"}),
                                );
                                continue;
                            }
                        };

                        let user_id = match fields.get("userId").and_then(|v| v.as_str()) {
                            Some(id) => id.to_string(),
                            None => {
                                not_created.insert(
                                    client_id,
                                    json!({"type": "invalidArguments", "description": "userId is required"}),
                                );
                                continue;
                            }
                        };

                        let reason = fields.get("reason").and_then(|v| v.as_str());
                        let expires_at: Option<i64> =
                            fields.get("expiresAt").and_then(|v| v.as_i64());

                        let ban_id = Ulid::new().to_string();

                        match guard.spaces().create_ban(
                            &ban_id,
                            &space_id,
                            &user_id,
                            "owner",
                            reason,
                            now_unix,
                            expires_at,
                        ) {
                            Ok(()) => {
                                let ban = guard
                                    .spaces()
                                    .get_ban(&ban_id)
                                    .map_err(|e| JmapError::server_fail(e.to_string()))?
                                    .ok_or_else(|| {
                                        JmapError::server_fail("ban not found after create")
                                    })?;
                                let ban_value = serde_json::to_value(ban)
                                    .map_err(|e| JmapError::server_fail(e.to_string()))?;
                                created_map.insert(client_id, ban_value);
                            }
                            Err(e) => {
                                not_created.insert(
                                    client_id,
                                    json!({"type": "serverFail", "description": e.to_string()}),
                                );
                            }
                        }
                    }
                }

                // Process updates — only reason and expiresAt.
                if let Some(update_map) = update {
                    for (ban_id, patch) in update_map {
                        let patch_obj = match patch.as_object() {
                            Some(o) => o,
                            None => {
                                not_updated.insert(
                                    ban_id,
                                    json!({"type": "invalidArguments", "description": "update value must be an object"}),
                                );
                                continue;
                            }
                        };

                        // Verify the ban exists.
                        let existing = guard
                            .spaces()
                            .get_ban(&ban_id)
                            .map_err(|e| JmapError::server_fail(e.to_string()))?;
                        if existing.is_none() {
                            not_updated.insert(
                                ban_id,
                                json!({"type": "notFound", "description": "ban not found"}),
                            );
                            continue;
                        }
                        let existing = existing.unwrap();

                        let reason = if patch_obj.contains_key("reason") {
                            patch_obj
                                .get("reason")
                                .and_then(|v| if v.is_null() { None } else { v.as_str() })
                        } else {
                            existing.reason.as_deref()
                        };

                        let expires_at: Option<i64> = if patch_obj.contains_key("expiresAt") {
                            patch_obj.get("expiresAt").and_then(|v| v.as_i64())
                        } else {
                            // Preserve existing — but we only have UTCDate, not i64.
                            // For simplicity, pass None to clear if not re-specified.
                            None
                        };

                        match guard.spaces().update_ban(&ban_id, reason, expires_at) {
                            Ok(()) => {
                                updated_map.insert(ban_id, Value::Null);
                            }
                            Err(e) => {
                                not_updated.insert(
                                    ban_id,
                                    json!({"type": "serverFail", "description": e.to_string()}),
                                );
                            }
                        }
                    }
                }

                // Process destroys.
                if let Some(destroy_list) = destroy {
                    for ban_id in destroy_list {
                        match guard.spaces().delete_ban(&ban_id) {
                            Ok(()) => {
                                destroyed_ids.push(Value::String(ban_id));
                            }
                            Err(e) => {
                                not_destroyed.insert(
                                    ban_id,
                                    json!({"type": "serverFail", "description": e.to_string()}),
                                );
                            }
                        }
                    }
                }

                let new_state = guard
                    .spaces()
                    .get_ban_state()
                    .map_err(|e| JmapError::server_fail(e.to_string()))?;

                (old_state, new_state)
            };

            Ok(json!({
                "accountId": "a-self",
                "oldState": old_state,
                "newState": new_state,
                "created": created_map,
                "notCreated": not_created,
                "updated": updated_map,
                "notUpdated": not_updated,
                "destroyed": destroyed_ids,
                "notDestroyed": not_destroyed,
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

    // -----------------------------------------------------------------------
    // Space/set tests
    // -----------------------------------------------------------------------

    const OWNER_ID: &str = "user-owner-1";

    fn set_handler(store: &Arc<Mutex<Store>>) -> SpaceSetHandler {
        SpaceSetHandler::new(Arc::clone(store), OWNER_ID.to_string())
    }

    fn get_handler(store: &Arc<Mutex<Store>>) -> SpaceGetHandler {
        SpaceGetHandler::new(Arc::clone(store))
    }

    // Oracle: Space/set create with name returns created entry containing
    // a server-assigned id and the supplied name.
    #[tokio::test]
    async fn test_space_set_create_with_name() {
        let store = make_store();
        let handler = set_handler(&store);
        let result = handler
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "t0": {"name": "My Space"}
                    }
                }),
            )
            .await
            .expect("Space/set must succeed");

        let created = result["created"].as_object().expect("created must be object");
        assert!(created.contains_key("t0"), "t0 must be in created");
        let space = &created["t0"];
        assert_eq!(space["name"], "My Space");
        assert!(!space["id"].as_str().unwrap().is_empty(), "id must be assigned");
    }

    // Oracle: Space/set create auto-adds the caller as a member with an admin role
    // that has all permissions. Verified by Space/get after creation.
    #[tokio::test]
    async fn test_space_set_create_adds_creator_as_member() {
        let store = make_store();
        let handler = set_handler(&store);
        let result = handler
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "t0": {"name": "Member Test"}
                    }
                }),
            )
            .await
            .expect("Space/set must succeed");

        let space = &result["created"]["t0"];
        let members = space["members"].as_array().expect("members must be array");
        assert_eq!(members.len(), 1, "must have exactly 1 member");
        assert_eq!(members[0]["id"], OWNER_ID);

        let roles = space["roles"].as_array().expect("roles must be array");
        assert_eq!(roles.len(), 1, "must have exactly 1 role (Admin)");
        assert_eq!(roles[0]["name"], "Admin");

        // Verify the admin role has all permissions.
        let perms = roles[0]["permissions"]
            .as_array()
            .expect("permissions must be array");
        for p in kith_core::SPACE_PERMISSION_NAMES {
            assert!(
                perms.iter().any(|v| v.as_str() == Some(p)),
                "Admin role must include permission '{p}'; got: {perms:?}"
            );
        }

        // Verify the member has the admin role assigned.
        let member_role_ids = members[0]["roleIds"]
            .as_array()
            .expect("roleIds must be array");
        assert_eq!(member_role_ids.len(), 1);
        assert_eq!(member_role_ids[0], roles[0]["id"]);
    }

    // Oracle: Space/set update name changes the name visible via Space/get.
    #[tokio::test]
    async fn test_space_set_update_name() {
        let store = make_store();
        let sh = set_handler(&store);

        // Create a space first.
        let create_result = sh
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {"t0": {"name": "Original"}}
                }),
            )
            .await
            .expect("create must succeed");
        let space_id = create_result["created"]["t0"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        // Update the name.
        let mut update = serde_json::Map::new();
        update.insert(
            space_id.clone(),
            json!({"name": "Renamed"}),
        );
        let update_result = sh
            .call(
                "Space/set".to_string(),
                "c1".to_string(),
                json!({
                    "accountId": "a-self",
                    "update": update
                }),
            )
            .await
            .expect("update must succeed");

        assert!(
            update_result["updated"]
                .as_object()
                .unwrap()
                .contains_key(&space_id),
            "space must appear in updated"
        );

        // Verify via Space/get.
        let gh = get_handler(&store);
        let get_result = gh
            .call(
                "Space/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [space_id]}),
            )
            .await
            .expect("get must succeed");
        assert_eq!(get_result["list"][0]["name"], "Renamed");
    }

    // Oracle: Space/set update description changes the description visible via Space/get.
    #[tokio::test]
    async fn test_space_set_update_description() {
        let store = make_store();
        let sh = set_handler(&store);

        let create_result = sh
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {"t0": {"name": "Desc Test"}}
                }),
            )
            .await
            .expect("create must succeed");
        let space_id = create_result["created"]["t0"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let mut update = serde_json::Map::new();
        update.insert(
            space_id.clone(),
            json!({"description": "A fine space"}),
        );
        sh.call(
            "Space/set".to_string(),
            "c1".to_string(),
            json!({
                "accountId": "a-self",
                "update": update
            }),
        )
        .await
        .expect("update must succeed");

        let gh = get_handler(&store);
        let get_result = gh
            .call(
                "Space/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [space_id]}),
            )
            .await
            .expect("get must succeed");
        assert_eq!(get_result["list"][0]["description"], "A fine space");
    }

    // Oracle: Space/set destroy removes the space; Space/get returns it in notFound.
    #[tokio::test]
    async fn test_space_set_destroy() {
        let store = make_store();
        let sh = set_handler(&store);

        let create_result = sh
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {"t0": {"name": "Doomed"}}
                }),
            )
            .await
            .expect("create must succeed");
        let space_id = create_result["created"]["t0"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let destroy_result = sh
            .call(
                "Space/set".to_string(),
                "c1".to_string(),
                json!({
                    "accountId": "a-self",
                    "destroy": [space_id.clone()]
                }),
            )
            .await
            .expect("destroy must succeed");

        let destroyed = destroy_result["destroyed"]
            .as_array()
            .expect("destroyed must be array");
        assert!(
            destroyed.contains(&json!(space_id)),
            "space_id must be in destroyed; got: {destroyed:?}"
        );

        // Verify via Space/get.
        let gh = get_handler(&store);
        let get_result = gh
            .call(
                "Space/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [space_id.clone()]}),
            )
            .await
            .expect("get must succeed");
        let not_found = get_result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert!(
            not_found.contains(&json!(space_id)),
            "destroyed space must be in notFound; got: {not_found:?}"
        );
    }

    // Oracle: Space/set addRoles adds a role visible via Space/get.
    #[tokio::test]
    async fn test_space_set_add_roles() {
        let store = make_store();
        let sh = set_handler(&store);

        let create_result = sh
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {"t0": {"name": "Roles Test"}}
                }),
            )
            .await
            .expect("create must succeed");
        let space_id = create_result["created"]["t0"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let mut update = serde_json::Map::new();
        update.insert(
            space_id.clone(),
            json!({
                "addRoles": [
                    {"name": "Moderator", "permissions": ["send", "pin"], "position": 2}
                ]
            }),
        );
        sh.call(
            "Space/set".to_string(),
            "c1".to_string(),
            json!({
                "accountId": "a-self",
                "update": update
            }),
        )
        .await
        .expect("update must succeed");

        let gh = get_handler(&store);
        let get_result = gh
            .call(
                "Space/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [space_id]}),
            )
            .await
            .expect("get must succeed");
        let roles = get_result["list"][0]["roles"]
            .as_array()
            .expect("roles must be array");
        // Should have Admin (from create) + Moderator (from addRoles).
        assert_eq!(roles.len(), 2, "must have 2 roles; got: {roles:?}");
        let mod_role = roles
            .iter()
            .find(|r| r["name"] == "Moderator")
            .expect("Moderator role must exist");
        let mod_perms = mod_role["permissions"]
            .as_array()
            .expect("permissions must be array");
        assert!(
            mod_perms.contains(&json!("send")),
            "Moderator must have 'send' permission"
        );
        assert!(
            mod_perms.contains(&json!("pin")),
            "Moderator must have 'pin' permission"
        );
    }

    // Oracle: Space/set addMembers adds a member visible via Space/get.
    #[tokio::test]
    async fn test_space_set_add_members() {
        let store = make_store();
        let sh = set_handler(&store);

        let create_result = sh
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {"t0": {"name": "Members Test"}}
                }),
            )
            .await
            .expect("create must succeed");
        let space_id = create_result["created"]["t0"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let mut update = serde_json::Map::new();
        update.insert(
            space_id.clone(),
            json!({
                "addMembers": [
                    {"userId": "user-bob"}
                ]
            }),
        );
        sh.call(
            "Space/set".to_string(),
            "c1".to_string(),
            json!({
                "accountId": "a-self",
                "update": update
            }),
        )
        .await
        .expect("update must succeed");

        let gh = get_handler(&store);
        let get_result = gh
            .call(
                "Space/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [space_id]}),
            )
            .await
            .expect("get must succeed");
        let members = get_result["list"][0]["members"]
            .as_array()
            .expect("members must be array");
        // Owner + Bob.
        assert_eq!(members.len(), 2, "must have 2 members; got: {members:?}");
        assert!(
            members.iter().any(|m| m["id"] == "user-bob"),
            "user-bob must be a member; got: {members:?}"
        );
    }

    // Oracle: Space/set removeRoles removes a role; Space/get no longer lists it.
    #[tokio::test]
    async fn test_space_set_remove_roles() {
        let store = make_store();
        let sh = set_handler(&store);

        let create_result = sh
            .call(
                "Space/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {"t0": {"name": "Remove Role Test"}}
                }),
            )
            .await
            .expect("create must succeed");
        let space_id = create_result["created"]["t0"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        // Add a "Helper" role.
        let mut update1 = serde_json::Map::new();
        update1.insert(
            space_id.clone(),
            json!({
                "addRoles": [{"name": "Helper", "permissions": ["send"], "position": 2}]
            }),
        );
        sh.call(
            "Space/set".to_string(),
            "c1".to_string(),
            json!({"accountId": "a-self", "update": update1}),
        )
        .await
        .expect("addRoles must succeed");

        // Fetch the Helper role's id.
        let gh = get_handler(&store);
        let get1 = gh
            .call(
                "Space/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [space_id.clone()]}),
            )
            .await
            .expect("get must succeed");
        let roles = get1["list"][0]["roles"].as_array().unwrap();
        let helper_id = roles
            .iter()
            .find(|r| r["name"] == "Helper")
            .expect("Helper role must exist")["id"]
            .as_str()
            .expect("role id")
            .to_string();

        // Remove it.
        let mut update2 = serde_json::Map::new();
        update2.insert(
            space_id.clone(),
            json!({"removeRoles": [helper_id]}),
        );
        sh.call(
            "Space/set".to_string(),
            "c3".to_string(),
            json!({"accountId": "a-self", "update": update2}),
        )
        .await
        .expect("removeRoles must succeed");

        // Verify Helper is gone.
        let get2 = gh
            .call(
                "Space/get".to_string(),
                "c4".to_string(),
                json!({"accountId": "a-self", "ids": [space_id]}),
            )
            .await
            .expect("get must succeed");
        let roles_after = get2["list"][0]["roles"].as_array().unwrap();
        assert!(
            !roles_after.iter().any(|r| r["name"] == "Helper"),
            "Helper role must be removed; got: {roles_after:?}"
        );
        // Admin role should still exist.
        assert!(
            roles_after.iter().any(|r| r["name"] == "Admin"),
            "Admin role must still exist; got: {roles_after:?}"
        );
    }

    // -------------------------------------------------------------------
    // SpaceInvite handler tests
    // -------------------------------------------------------------------

    /// Helper: create a space in the store so FK constraints are satisfied.
    fn ensure_space(store: &Arc<Mutex<Store>>, space_id: &str) {
        let guard = store.lock().unwrap();
        guard
            .spaces()
            .create_space(space_id, "Test Space", None, None, false, false, 1_000_000)
            .expect("create test space");
    }

    // Oracle: SpaceInvite/set create must return an invite object with an
    // 8-character alphanumeric code and server-assigned id.
    #[tokio::test]
    async fn test_space_invite_set_create() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let handler = SpaceInviteSetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "SpaceInvite/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "inv-client-0": {"spaceId": "sp-1"}
                    }
                }),
            )
            .await
            .expect("SpaceInvite/set must succeed");

        let created = result["created"]["inv-client-0"]
            .as_object()
            .expect("created entry must be an object");
        assert!(created.contains_key("id"), "created invite must have id");
        let code = created
            .get("code")
            .and_then(|v| v.as_str())
            .expect("created invite must have code");
        assert_eq!(code.len(), 8, "code must be 8 characters; got: {code}");
        assert!(
            code.chars().all(|c| c.is_ascii_alphanumeric()),
            "code must be alphanumeric; got: {code}"
        );
        assert_eq!(created["spaceId"], "sp-1");
    }

    // Oracle: SpaceInvite/get must retrieve an invite created by SpaceInvite/set.
    #[tokio::test]
    async fn test_space_invite_get_retrieves_created() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        // Create an invite.
        let set_handler = SpaceInviteSetHandler::new(Arc::clone(&store));
        let set_result = set_handler
            .call(
                "SpaceInvite/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "inv0": {"spaceId": "sp-1"}
                    }
                }),
            )
            .await
            .expect("create must succeed");

        let invite_id = set_result["created"]["inv0"]["id"]
            .as_str()
            .expect("created invite must have string id");

        // Get the invite.
        let get_handler = SpaceInviteGetHandler::new(Arc::clone(&store));
        let get_result = get_handler
            .call(
                "SpaceInvite/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "ids": [invite_id]}),
            )
            .await
            .expect("SpaceInvite/get must succeed");

        let list = get_result["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 1, "must return 1 invite");
        assert_eq!(list[0]["id"], invite_id);
        assert_eq!(list[0]["spaceId"], "sp-1");
    }

    // Oracle: SpaceInvite/set update must return forbidden for all entries.
    #[tokio::test]
    async fn test_space_invite_set_update_forbidden() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        // Create an invite first.
        let set_handler = SpaceInviteSetHandler::new(Arc::clone(&store));
        let set_result = set_handler
            .call(
                "SpaceInvite/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "inv0": {"spaceId": "sp-1"}
                    }
                }),
            )
            .await
            .expect("create must succeed");

        let invite_id = set_result["created"]["inv0"]["id"]
            .as_str()
            .expect("must have id");

        // Attempt update.
        let update_result = set_handler
            .call(
                "SpaceInvite/set".to_string(),
                "c1".to_string(),
                json!({
                    "accountId": "a-self",
                    "update": {
                        invite_id: {"maxUses": 10}
                    }
                }),
            )
            .await
            .expect("SpaceInvite/set update must succeed (at method level)");

        let not_updated = update_result["notUpdated"]
            .as_object()
            .expect("notUpdated must be object");
        assert!(
            not_updated.contains_key(invite_id),
            "invite must appear in notUpdated; got: {not_updated:?}"
        );
        assert_eq!(not_updated[invite_id]["type"], "forbidden");
    }

    // Oracle: SpaceInvite/set destroy must remove the invite so that
    // SpaceInvite/get no longer returns it.
    #[tokio::test]
    async fn test_space_invite_set_destroy() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let handler = SpaceInviteSetHandler::new(Arc::clone(&store));
        let create_result = handler
            .call(
                "SpaceInvite/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "inv0": {"spaceId": "sp-1"}
                    }
                }),
            )
            .await
            .expect("create must succeed");

        let invite_id = create_result["created"]["inv0"]["id"]
            .as_str()
            .expect("must have id")
            .to_string();

        // Destroy.
        let destroy_result = handler
            .call(
                "SpaceInvite/set".to_string(),
                "c1".to_string(),
                json!({
                    "accountId": "a-self",
                    "destroy": [invite_id]
                }),
            )
            .await
            .expect("destroy must succeed");

        let destroyed = destroy_result["destroyed"]
            .as_array()
            .expect("destroyed must be array");
        assert!(destroyed.contains(&json!(invite_id)));

        // Verify it's gone.
        let get_handler = SpaceInviteGetHandler::new(Arc::clone(&store));
        let get_result = get_handler
            .call(
                "SpaceInvite/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [invite_id]}),
            )
            .await
            .expect("get must succeed");

        let not_found = get_result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert!(
            not_found.contains(&json!(invite_id)),
            "destroyed invite must appear in notFound"
        );
    }

    // Oracle: SpaceInvite/changes at current state returns empty lists;
    // after a create the state counter advances so old state produces
    // cannotCalculateChanges.
    #[tokio::test]
    async fn test_space_invite_changes_after_create() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let changes_handler = SpaceInviteChangesHandler::new(Arc::clone(&store));

        // Get current state.
        let get_handler = SpaceInviteGetHandler::new(Arc::clone(&store));
        let get_result = get_handler
            .call(
                "SpaceInvite/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("get must succeed");
        let state_before = get_result["state"].as_str().expect("state must be string");

        // Changes at current state is empty.
        let changes_result = changes_handler
            .call(
                "SpaceInvite/changes".to_string(),
                "c1".to_string(),
                json!({"accountId": "a-self", "sinceState": state_before}),
            )
            .await
            .expect("changes at current state must succeed");
        assert_eq!(changes_result["created"], json!([]));

        // Create an invite — advances state.
        let set_handler = SpaceInviteSetHandler::new(Arc::clone(&store));
        set_handler
            .call(
                "SpaceInvite/set".to_string(),
                "c2".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {"inv0": {"spaceId": "sp-1"}}
                }),
            )
            .await
            .expect("create must succeed");

        // Changes with old state returns cannotCalculateChanges.
        let changes_err = changes_handler
            .call(
                "SpaceInvite/changes".to_string(),
                "c3".to_string(),
                json!({"accountId": "a-self", "sinceState": state_before}),
            )
            .await;
        assert!(
            changes_err.is_err(),
            "changes with old sinceState must error"
        );
        assert_eq!(changes_err.unwrap_err().error_type, "cannotCalculateChanges");
    }

    // -------------------------------------------------------------------
    // SpaceBan handler tests
    // -------------------------------------------------------------------

    // Oracle: SpaceBan/set create must return a ban object with the specified
    // spaceId and userId.
    #[tokio::test]
    async fn test_space_ban_set_create() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let handler = SpaceBanSetHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "SpaceBan/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "ban0": {
                            "spaceId": "sp-1",
                            "userId": "user-bad",
                            "reason": "spam"
                        }
                    }
                }),
            )
            .await
            .expect("SpaceBan/set must succeed");

        let created = result["created"]["ban0"]
            .as_object()
            .expect("created entry must be object");
        assert!(created.contains_key("id"), "ban must have id");
        assert_eq!(created["spaceId"], "sp-1");
        assert_eq!(created["userId"], "user-bad");
        assert_eq!(created["reason"], "spam");
    }

    // Oracle: SpaceBan/get must retrieve a ban created by SpaceBan/set.
    #[tokio::test]
    async fn test_space_ban_get_retrieves_ban() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let set_handler = SpaceBanSetHandler::new(Arc::clone(&store));
        let set_result = set_handler
            .call(
                "SpaceBan/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "ban0": {"spaceId": "sp-1", "userId": "user-bad"}
                    }
                }),
            )
            .await
            .expect("create must succeed");

        let ban_id = set_result["created"]["ban0"]["id"]
            .as_str()
            .expect("must have id");

        let get_handler = SpaceBanGetHandler::new(Arc::clone(&store));
        let get_result = get_handler
            .call(
                "SpaceBan/get".to_string(),
                "c1".to_string(),
                json!({"accountId": "a-self", "ids": [ban_id]}),
            )
            .await
            .expect("SpaceBan/get must succeed");

        let list = get_result["list"].as_array().expect("list must be array");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], ban_id);
        assert_eq!(list[0]["spaceId"], "sp-1");
        assert_eq!(list[0]["userId"], "user-bad");
    }

    // Oracle: SpaceBan/set update must change reason.
    #[tokio::test]
    async fn test_space_ban_set_update_reason() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let handler = SpaceBanSetHandler::new(Arc::clone(&store));
        let create_result = handler
            .call(
                "SpaceBan/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "ban0": {"spaceId": "sp-1", "userId": "user-bad", "reason": "spam"}
                    }
                }),
            )
            .await
            .expect("create must succeed");

        let ban_id = create_result["created"]["ban0"]["id"]
            .as_str()
            .expect("must have id")
            .to_string();

        // Update reason.
        let update_result = handler
            .call(
                "SpaceBan/set".to_string(),
                "c1".to_string(),
                json!({
                    "accountId": "a-self",
                    "update": {
                        ban_id.clone(): {"reason": "harassment"}
                    }
                }),
            )
            .await
            .expect("update must succeed");

        // Updated entry must be null (success).
        assert_eq!(update_result["updated"][&ban_id], Value::Null);

        // Verify updated reason via get.
        let get_handler = SpaceBanGetHandler::new(Arc::clone(&store));
        let get_result = get_handler
            .call(
                "SpaceBan/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [ban_id]}),
            )
            .await
            .expect("get must succeed");

        assert_eq!(get_result["list"][0]["reason"], "harassment");
    }

    // Oracle: SpaceBan/set destroy must remove the ban.
    #[tokio::test]
    async fn test_space_ban_set_destroy() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let handler = SpaceBanSetHandler::new(Arc::clone(&store));
        let create_result = handler
            .call(
                "SpaceBan/set".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "ban0": {"spaceId": "sp-1", "userId": "user-bad"}
                    }
                }),
            )
            .await
            .expect("create must succeed");

        let ban_id = create_result["created"]["ban0"]["id"]
            .as_str()
            .expect("must have id")
            .to_string();

        // Destroy.
        let destroy_result = handler
            .call(
                "SpaceBan/set".to_string(),
                "c1".to_string(),
                json!({
                    "accountId": "a-self",
                    "destroy": [ban_id]
                }),
            )
            .await
            .expect("destroy must succeed");

        let destroyed = destroy_result["destroyed"]
            .as_array()
            .expect("destroyed must be array");
        assert!(destroyed.contains(&json!(ban_id)));

        // Verify it's gone.
        let get_handler = SpaceBanGetHandler::new(Arc::clone(&store));
        let get_result = get_handler
            .call(
                "SpaceBan/get".to_string(),
                "c2".to_string(),
                json!({"accountId": "a-self", "ids": [ban_id]}),
            )
            .await
            .expect("get must succeed");

        let not_found = get_result["notFound"]
            .as_array()
            .expect("notFound must be array");
        assert!(
            not_found.contains(&json!(ban_id)),
            "destroyed ban must appear in notFound"
        );
    }

    // Oracle: SpaceBan/changes at current state returns empty lists;
    // after a create the state advances so old state returns
    // cannotCalculateChanges.
    #[tokio::test]
    async fn test_space_ban_changes_after_create() {
        let store = make_store();
        ensure_space(&store, "sp-1");

        let changes_handler = SpaceBanChangesHandler::new(Arc::clone(&store));

        // Get current state.
        let get_handler = SpaceBanGetHandler::new(Arc::clone(&store));
        let get_result = get_handler
            .call(
                "SpaceBan/get".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("get must succeed");
        let state_before = get_result["state"].as_str().expect("state must be string");

        // Changes at current state is empty.
        let changes_result = changes_handler
            .call(
                "SpaceBan/changes".to_string(),
                "c1".to_string(),
                json!({"accountId": "a-self", "sinceState": state_before}),
            )
            .await
            .expect("changes at current state must succeed");
        assert_eq!(changes_result["created"], json!([]));

        // Create a ban — advances state.
        let set_handler = SpaceBanSetHandler::new(Arc::clone(&store));
        set_handler
            .call(
                "SpaceBan/set".to_string(),
                "c2".to_string(),
                json!({
                    "accountId": "a-self",
                    "create": {
                        "ban0": {"spaceId": "sp-1", "userId": "user-bad"}
                    }
                }),
            )
            .await
            .expect("create must succeed");

        // Changes with old state returns cannotCalculateChanges.
        let changes_err = changes_handler
            .call(
                "SpaceBan/changes".to_string(),
                "c3".to_string(),
                json!({"accountId": "a-self", "sinceState": state_before}),
            )
            .await;
        assert!(
            changes_err.is_err(),
            "changes with old sinceState must error"
        );
        assert_eq!(changes_err.unwrap_err().error_type, "cannotCalculateChanges");
    }

    // ── Space/query tests ─────────────────────────────────────────────

    // Oracle: Space/query with no filter returns all space IDs, sorted by name.
    #[tokio::test]
    async fn test_space_query_returns_all() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("sp-b", "Bravo", None, None, false, false, 1_000_000)
                .expect("create space b");
            guard
                .spaces()
                .create_space("sp-a", "Alpha", None, None, false, false, 1_000_001)
                .expect("create space a");
            guard
                .spaces()
                .create_space("sp-c", "Charlie", None, None, true, false, 1_000_002)
                .expect("create space c");
        }

        let handler = SpaceQueryHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/query".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self"}),
            )
            .await
            .expect("Space/query must succeed");

        let ids = result["ids"].as_array().expect("ids must be array");
        assert_eq!(ids.len(), 3, "must return all 3 spaces");
        // Sorted by name ascending: Alpha, Bravo, Charlie
        assert_eq!(ids[0], "sp-a");
        assert_eq!(ids[1], "sp-b");
        assert_eq!(ids[2], "sp-c");
        assert_eq!(result["canCalculateChanges"], false);
    }

    // Oracle: Space/query with name filter returns only matching spaces.
    #[tokio::test]
    async fn test_space_query_name_filter() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("sp-1", "Engineering", None, None, false, false, 1_000_000)
                .expect("create space 1");
            guard
                .spaces()
                .create_space("sp-2", "Marketing", None, None, false, false, 1_000_001)
                .expect("create space 2");
            guard
                .spaces()
                .create_space("sp-3", "Engineering Ops", None, None, false, false, 1_000_002)
                .expect("create space 3");
        }

        let handler = SpaceQueryHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/query".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "filter": {"name": "Engineering"}}),
            )
            .await
            .expect("Space/query must succeed");

        let ids = result["ids"].as_array().expect("ids must be array");
        assert_eq!(ids.len(), 2, "must return 2 matching spaces; got: {ids:?}");
        assert!(ids.contains(&json!("sp-1")));
        assert!(ids.contains(&json!("sp-3")));
    }

    // Oracle: Space/query with position+limit returns a page of IDs.
    #[tokio::test]
    async fn test_space_query_pagination() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("sp-a", "Alpha", None, None, false, false, 1_000_000)
                .expect("create space a");
            guard
                .spaces()
                .create_space("sp-b", "Bravo", None, None, false, false, 1_000_001)
                .expect("create space b");
            guard
                .spaces()
                .create_space("sp-c", "Charlie", None, None, false, false, 1_000_002)
                .expect("create space c");
            guard
                .spaces()
                .create_space("sp-d", "Delta", None, None, false, false, 1_000_003)
                .expect("create space d");
        }

        let handler = SpaceQueryHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Space/query".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "position": 1,
                    "limit": 2,
                    "calculateTotal": true,
                }),
            )
            .await
            .expect("Space/query must succeed");

        let ids = result["ids"].as_array().expect("ids must be array");
        assert_eq!(ids.len(), 2, "page must contain 2 IDs; got: {ids:?}");
        // Sorted by name: Alpha(0), Bravo(1), Charlie(2), Delta(3)
        assert_eq!(ids[0], "sp-b");
        assert_eq!(ids[1], "sp-c");
        assert_eq!(result["total"], 4);
    }

    // ── Space/join tests ──────────────────────────────────────────────

    /// Helper: create a space and an invite for it, returning the invite code.
    fn create_space_with_invite(
        store: &Arc<Mutex<kith_store::Store>>,
        space_id: &str,
        code: &str,
        expires_at: Option<i64>,
        max_uses: Option<i64>,
    ) {
        let guard = store.lock().unwrap();
        guard
            .spaces()
            .create_space(space_id, "Test Space", None, None, false, false, 1_000_000)
            .expect("create space");
        guard
            .spaces()
            .create_invite(
                &format!("inv-{space_id}"),
                code,
                space_id,
                "creator",
                None,
                expires_at,
                max_uses,
                1_000_000,
            )
            .expect("create invite");
    }

    // Oracle: Space/join via inviteCode with a valid invite adds the caller
    // as a member and returns the space ID.
    #[tokio::test]
    async fn test_space_join_via_invite_code() {
        let store = make_store();
        create_space_with_invite(&store, "sp-join1", "JOINCODE", None, None);

        let handler = SpaceJoinHandler::new(Arc::clone(&store), "user-joiner".to_string());
        let result = handler
            .call(
                "Space/join".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "inviteCode": "JOINCODE"}),
            )
            .await
            .expect("Space/join via inviteCode must succeed");

        assert_eq!(result["joined"], "sp-join1");

        // Verify the user was added as member.
        let guard = store.lock().unwrap();
        let space = guard.spaces().get_space("sp-join1").unwrap().unwrap();
        let member_ids: Vec<&str> = space.members.iter().map(|m| m.id.as_ref()).collect();
        assert!(
            member_ids.contains(&"user-joiner"),
            "user must be in members; got: {member_ids:?}"
        );
    }

    // Oracle: Space/join via expired inviteCode returns invalidArguments.
    #[tokio::test]
    async fn test_space_join_expired_invite() {
        let store = make_store();
        // Invite expired at Unix timestamp 100 (well in the past).
        create_space_with_invite(&store, "sp-expired", "EXPCODE", Some(100), None);

        let handler = SpaceJoinHandler::new(Arc::clone(&store), "user-late".to_string());
        let err = handler
            .call(
                "Space/join".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "inviteCode": "EXPCODE"}),
            )
            .await;

        assert!(err.is_err(), "expired invite must fail");
        assert_eq!(err.unwrap_err().error_type, "invalidArguments");
    }

    // Oracle: Space/join via spaceId for a public space succeeds.
    #[tokio::test]
    async fn test_space_join_public_space() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("sp-pub", "Public Space", None, None, true, false, 1_000_000)
                .expect("create public space");
        }

        let handler = SpaceJoinHandler::new(Arc::clone(&store), "user-pub".to_string());
        let result = handler
            .call(
                "Space/join".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "spaceId": "sp-pub"}),
            )
            .await
            .expect("Space/join via spaceId for public space must succeed");

        assert_eq!(result["joined"], "sp-pub");

        // Verify membership.
        let guard = store.lock().unwrap();
        let space = guard.spaces().get_space("sp-pub").unwrap().unwrap();
        let member_ids: Vec<&str> = space.members.iter().map(|m| m.id.as_ref()).collect();
        assert!(
            member_ids.contains(&"user-pub"),
            "user must be member after join"
        );
    }

    // Oracle: Space/join via spaceId for a non-public space returns forbidden.
    #[tokio::test]
    async fn test_space_join_nonpublic_space_forbidden() {
        let store = make_store();
        {
            let guard = store.lock().unwrap();
            guard
                .spaces()
                .create_space("sp-priv", "Private Space", None, None, false, false, 1_000_000)
                .expect("create private space");
        }

        let handler = SpaceJoinHandler::new(Arc::clone(&store), "user-intruder".to_string());
        let err = handler
            .call(
                "Space/join".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "spaceId": "sp-priv"}),
            )
            .await;

        assert!(err.is_err(), "non-public space join must fail");
        assert_eq!(err.unwrap_err().error_type, "forbidden");
    }

    // Oracle: Space/join with both inviteCode and spaceId returns invalidArguments.
    #[tokio::test]
    async fn test_space_join_both_args_invalid() {
        let store = make_store();

        let handler = SpaceJoinHandler::new(Arc::clone(&store), "user-x".to_string());
        let err = handler
            .call(
                "Space/join".to_string(),
                "c0".to_string(),
                json!({
                    "accountId": "a-self",
                    "inviteCode": "SOME",
                    "spaceId": "sp-1",
                }),
            )
            .await;

        assert!(err.is_err(), "both args must fail");
        assert_eq!(err.unwrap_err().error_type, "invalidArguments");
    }
}
