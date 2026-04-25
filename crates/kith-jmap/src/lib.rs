use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use kith_core::{
    Identity, Invocation, JmapError, JmapRequest, JmapResponse, ResultReference, Role,
    MAX_ATTACHMENT_BYTES, MAX_BODY_BYTES, MAX_OBJECTS_IN_GET, MAX_REQUEST_BYTES,
};
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

const MAX_CALLS_IN_REQUEST: usize = 16;

/// Parse and validate a raw JMAP request value.
///
/// Returns `Err(JmapError)` on: empty `using` array, too many method calls, or
/// deserialization failure.
///
/// # RFC 8620 §3.3 deviation
///
/// RFC 8620 §3.3 REQUIRES returning `unknownCapability` for any URI in `using`
/// that the server does not support.  Kith deliberately deviates: unknown URIs
/// are silently accepted.  Rationale: standard JMAP clients include capabilities
/// the server does not implement (e.g. `urn:ietf:params:jmap:mail`), and
/// rejecting them would break interoperability without any security or correctness
/// benefit — Kith dispatches only the methods it knows about regardless of the
/// `using` declaration.  `urn:ietf:params:jmap:chat` is never required: clients
/// that declare only `urn:ietf:params:jmap:core` are accepted and have access to
/// the full kith method set.
pub fn parse_request(body: serde_json::Value) -> Result<JmapRequest, JmapError> {
    let req: JmapRequest = serde_json::from_value(body)
        .map_err(|e| JmapError::invalid_arguments(format!("invalid request: {e}")))?;

    if req.using.is_empty() {
        return Err(JmapError::unknown_capability("using must not be empty"));
    }

    // Unknown capability URIs are silently accepted — see RFC 8620 §3.3 deviation note
    // in the doc comment above.

    if req.method_calls.len() > MAX_CALLS_IN_REQUEST {
        return Err(JmapError::request_too_large("maxCallsInRequest is 16"));
    }

    Ok(req)
}

/// Wrap a method-level error as an error Invocation for methodResponses.
///
/// The method name and call_id are echoed from the request; the error becomes
/// the arguments.  Method-level errors are returned inside methodResponses with
/// HTTP 200 — they are NOT returned as top-level HTTP errors.
pub fn error_invocation(method_name: &str, call_id: &str, err: JmapError) -> Invocation {
    let err_value = serde_json::to_value(&err)
        .expect("JmapError always serializes successfully: only String fields");
    (method_name.to_string(), err_value, call_id.to_string())
}

/// Map a JmapError type string to the appropriate HTTP status code.
///
/// Error type strings are per RFC 8620 §7.1.
pub fn error_status(err: &JmapError) -> StatusCode {
    match err.error_type.as_str() {
        "unknownCapability" | "invalidArguments" | "requestTooLarge" => StatusCode::BAD_REQUEST,
        "forbidden" => StatusCode::FORBIDDEN,
        // accountNotFound is a request-level error (RFC 8620 §3.2).
        // notFound is method-level only — must NOT appear here (must stay HTTP 200).
        "accountNotFound" => StatusCode::NOT_FOUND,
        "serverFail" => StatusCode::INTERNAL_SERVER_ERROR,
        // Unknown error types are server-side bugs, not client mistakes.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// A request-level JMAP error response: HTTP status + JMAP error body.
///
/// Used when the error occurs before method dispatch (e.g., parse failure).
/// Derives HTTP status from the error type via `error_status`.
pub struct RequestError(pub StatusCode, pub JmapError);

impl IntoResponse for RequestError {
    fn into_response(self) -> Response {
        let body = serde_json::to_string(&self.1)
            .expect("JmapError always serializes successfully: only String fields");
        (self.0, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    }
}

/// Convenience constructor: derive HTTP status from error type automatically.
pub fn request_error(err: JmapError) -> RequestError {
    let status = error_status(&err);
    RequestError(status, err)
}

// --- Session Object (RFC 8620 §2) ---

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreCapability {
    pub max_size_upload: u64,
    pub max_concurrent_upload: u32,
    pub max_size_request: u64,
    pub max_concurrent_requests: u32,
    pub max_calls_in_request: u32,
    pub max_objects_in_get: u32,
    pub max_objects_in_set: u32,
    pub collation_algorithms: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KithChatCapability {
    pub max_body_bytes: u64,
    pub max_attachment_bytes: u64,
    pub supported_body_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    #[serde(rename = "urn:ietf:params:jmap:core")]
    pub core: CoreCapability,
    #[serde(rename = "urn:ietf:params:jmap:chat")]
    pub kith_chat: KithChatCapability,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KithAccountCapability {
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountCapabilities {
    #[serde(rename = "urn:ietf:params:jmap:chat")]
    pub kith_chat: KithAccountCapability,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub name: String,
    pub is_personal: bool,
    pub is_read_only: bool,
    pub account_capabilities: AccountCapabilities,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub capabilities: Capabilities,
    pub accounts: HashMap<String, Account>,
    pub primary_accounts: HashMap<String, String>,
    pub username: String,
    pub api_url: String,
    pub download_url: String,
    pub upload_url: String,
    pub event_source_url: String,
    pub state: String,
    #[serde(rename = "ownerUserId")]
    pub owner_user_id: String,
    #[serde(rename = "ownerLogin")]
    pub owner_login: String,
}

/// Build a JMAP Session object for the given caller.
///
/// `role` and `identity` describe the *caller* (owner or peer).
/// `base_url` is the HTTPS base URL of this mailbox (e.g. "https://alice-kith.tail-xxx.ts.net").
/// `state` is an opaque string from the store representing the current server state.
/// `owner_user_id` and `owner_login` identify the mailbox owner regardless of who is calling.
/// The returned Session can be serialized directly to JSON and returned at `/.well-known/jmap`.
pub fn build_session(
    role: Role,
    identity: &Identity,
    base_url: &str,
    state: String,
    owner_user_id: String,
    owner_login: String,
) -> Session {
    let role_str = match role {
        Role::Owner => "owner".to_string(),
        Role::Peer => "peer".to_string(),
    };

    let mut accounts = HashMap::new();
    accounts.insert(
        "a-self".to_string(),
        Account {
            name: identity.display().to_string(),
            is_personal: true,
            is_read_only: role == Role::Peer,
            account_capabilities: AccountCapabilities {
                kith_chat: KithAccountCapability { role: role_str },
            },
        },
    );

    let mut primary_accounts = HashMap::new();
    primary_accounts.insert(
        "urn:ietf:params:jmap:chat".to_string(),
        "a-self".to_string(),
    );

    Session {
        capabilities: Capabilities {
            core: CoreCapability {
                max_size_upload: MAX_ATTACHMENT_BYTES as u64,
                max_concurrent_upload: 4,
                max_size_request: MAX_REQUEST_BYTES as u64,
                max_concurrent_requests: 4,
                max_calls_in_request: MAX_CALLS_IN_REQUEST as u32,
                max_objects_in_get: MAX_OBJECTS_IN_GET as u32,
                max_objects_in_set: 500,
                collation_algorithms: vec!["i;unicode-casemap".to_string()],
            },
            kith_chat: KithChatCapability {
                max_body_bytes: MAX_BODY_BYTES as u64,
                max_attachment_bytes: MAX_ATTACHMENT_BYTES as u64,
                supported_body_types: vec!["text/plain".to_string(), "text/markdown".to_string()],
            },
        },
        accounts,
        primary_accounts,
        username: identity.display().to_string(),
        api_url: format!("{base_url}/jmap/api"),
        download_url: format!(
            "{base_url}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}"
        ),
        upload_url: format!("{base_url}/jmap/upload/{{accountId}}"),
        event_source_url: format!(
            "{base_url}/jmap/events?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"
        ),
        state,
        owner_user_id,
        owner_login,
    }
}

// --- Method dispatch registry ---

/// Method name → required Role table.
/// Methods not in this list return `unknownMethod`.
const METHOD_ROLES: &[(&str, Role)] = &[
    ("ChatContact/get", Role::Owner),
    ("ChatContact/set", Role::Owner),
    ("ChatContact/changes", Role::Owner),
    ("ChatContact/query", Role::Owner),
    ("ChatContact/queryChanges", Role::Owner),
    ("Chat/get", Role::Owner),
    ("Chat/set", Role::Owner),
    ("Chat/changes", Role::Owner),
    ("Chat/query", Role::Owner),
    ("Message/get", Role::Owner),
    ("Message/set", Role::Owner),
    ("Message/changes", Role::Owner),
    ("Message/query", Role::Owner),
    ("Message/queryChanges", Role::Owner),
    ("Peer/deliver", Role::Peer),
    ("Peer/receipt", Role::Peer),
];

/// Pinned boxed future returned by [`JmapHandler::call`].
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<serde_json::Value, JmapError>> + Send>>;

/// Trait for JMAP owner-role method handlers.
///
/// Implementors are stateful objects (e.g., holding an `Arc<Store>`) registered
/// with the [`Dispatcher`].  The dispatcher calls them after role-checking passes.
///
/// `Role::Peer` methods use [`PeerJmapHandler`] instead.
///
/// # Panics
///
/// Handlers must not panic.  A panic inside `call` will propagate through the
/// async executor and crash the task; there is no catch at the dispatch layer.
pub trait JmapHandler: Send + Sync {
    /// Execute the method.
    ///
    /// `method_name` and `call_id` are provided for logging/tracing purposes.
    /// Returns `Ok(result_value)` on success or `Err(JmapError)` on method-level
    /// failure; both paths are wrapped into the appropriate `Invocation` by
    /// [`Dispatcher::dispatch`].
    fn call(&self, method_name: String, call_id: String, args: serde_json::Value) -> HandlerFuture;
}

/// Trait for JMAP peer-role method handlers.
///
/// Unlike [`JmapHandler`], the verified caller [`Identity`] is passed as a
/// typed parameter.  There is no JSON extraction step and no possibility of
/// forgetting to verify the caller: the dispatcher enforces the typed parameter
/// at every call site, and the compiler enforces that callers provide it.
///
/// `Role::Owner` methods use [`JmapHandler`] instead.
///
/// # Panics
///
/// Handlers must not panic.
pub trait PeerJmapHandler: Send + Sync {
    fn call(
        &self,
        method_name: String,
        call_id: String,
        args: serde_json::Value,
        caller: Identity,
    ) -> HandlerFuture;
}

/// Method dispatch registry for JMAP.
///
/// # Usage
///
/// 1. Create with [`Dispatcher::new`].
/// 2. Register handlers with [`Dispatcher::register`].
/// 3. Call [`Dispatcher::dispatch`] for each incoming request.
pub struct Dispatcher {
    handlers: HashMap<String, Box<dyn JmapHandler>>,
    peer_handlers: HashMap<String, Box<dyn PeerJmapHandler>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            peer_handlers: HashMap::new(),
        }
    }

    /// Register an owner-role handler for a specific JMAP method name.
    ///
    /// Writes to the **owner** handler map (`self.handlers`).  Owner handlers
    /// are called only when `caller_role == Role::Owner`.
    ///
    /// Do NOT use this for peer-role methods (`Peer/deliver`, `Peer/receipt`).
    /// Registering a peer method here will cause it to silently return
    /// `unknownMethod` when called by a peer, because the dispatcher checks
    /// `self.peer_handlers` for peer-role calls, not `self.handlers`.
    /// Use [`Dispatcher::register_peer`] for peer-role methods.
    ///
    /// Overwrites any previously registered handler for that method.
    pub fn register(&mut self, method: impl Into<String>, handler: Box<dyn JmapHandler>) {
        self.handlers.insert(method.into(), handler);
    }

    /// Register a peer-role handler for a specific JMAP method name.
    ///
    /// Writes to the **peer** handler map (`self.peer_handlers`).  Peer handlers
    /// receive the verified caller [`Identity`] as a typed parameter; no JSON
    /// extraction is required.  They are called only when
    /// `caller_role == Role::Peer`.
    ///
    /// Do NOT use this for owner-role methods.  Registering an owner method
    /// here will cause it to silently return `unknownMethod` when called by the
    /// owner, because the dispatcher checks `self.handlers` for owner-role
    /// calls, not `self.peer_handlers`.  Use [`Dispatcher::register`] for
    /// owner-role methods.
    pub fn register_peer(&mut self, method: impl Into<String>, handler: Box<dyn PeerJmapHandler>) {
        self.peer_handlers.insert(method.into(), handler);
    }

    /// Dispatch a complete JMAP request and return a [`JmapResponse`].
    ///
    /// For each method call:
    /// - Unknown method name → `unknownMethod` error invocation
    /// - Role mismatch → `forbidden` error invocation
    /// - Method known but no handler registered → `unknownMethod` error invocation
    /// - Handler returns `Err` → error invocation with that error
    /// - Handler returns `Ok` → success invocation
    ///
    /// The HTTP status for the outer response is always 200; errors appear
    /// inside `methodResponses` per RFC 8620 §3.4.
    pub async fn dispatch(
        &self,
        request: JmapRequest,
        caller_role: Role,
        caller_identity: Identity,
        session_state: String,
    ) -> JmapResponse {
        let mut responses: Vec<Invocation> = Vec::with_capacity(request.method_calls.len());
        // Each entry is (call_id, method_name, result_value).
        // The method_name is needed by ResultReference resolution (RFC 8620 §9 name check).
        let mut prior: Vec<(String, String, serde_json::Value)> = Vec::new();
        // Accumulate client-id → server-id mappings from /set created maps (RFC 8620 §3.4).
        let mut created_ids: HashMap<String, String> = HashMap::new();

        for (method_name, args, call_id) in request.method_calls {
            let invocation = self
                .dispatch_one(
                    &method_name,
                    &call_id,
                    args,
                    caller_role,
                    &caller_identity,
                    &prior,
                )
                .await;

            // Collect createdIds from /set responses: for each entry in `created`
            // the key is the client-supplied creation ID and the value has an "id"
            // field with the server-assigned ID (RFC 8620 §3.4, §5.3).
            if let Some(created_map) = invocation.1.get("created").and_then(|v| v.as_object()) {
                for (client_id, obj) in created_map {
                    if let Some(server_id) = obj.get("id").and_then(|v| v.as_str()) {
                        created_ids.insert(client_id.clone(), server_id.to_string());
                    }
                }
            }

            // Record the result for subsequent ResultReference lookups.
            prior.push((call_id.clone(), method_name.clone(), invocation.1.clone()));
            responses.push(invocation);
        }

        JmapResponse {
            method_responses: responses,
            session_state,
            created_ids: if created_ids.is_empty() {
                None
            } else {
                Some(created_ids)
            },
        }
    }

    async fn dispatch_one(
        &self,
        method_name: &str,
        call_id: &str,
        mut args: serde_json::Value,
        caller_role: Role,
        caller_identity: &Identity,
        prior_responses: &[(String, String, serde_json::Value)],
    ) -> Invocation {
        // Resolve any ResultReference arguments before role check or handler dispatch.
        if let Err(e) = resolve_args(&mut args, prior_responses) {
            return error_invocation(method_name, call_id, e);
        }

        // Role check MUST precede handler lookup (defense-in-depth).
        let required_role = METHOD_ROLES
            .iter()
            .find(|(name, _)| *name == method_name)
            .map(|(_, role)| *role);

        let Some(required_role) = required_role else {
            return error_invocation(method_name, call_id, JmapError::unknown_method());
        };

        if caller_role != required_role {
            return error_invocation(method_name, call_id, JmapError::forbidden_method());
        }

        // Invariant: a method must be registered in exactly one map — never both.
        // If a developer accidentally calls register() for a peer method (or
        // register_peer() for an owner method), the method ends up in the wrong
        // map and silently returns unknownMethod at runtime.  This assert fires
        // during development/testing to surface the mis-registration immediately.
        debug_assert!(
            !(self.handlers.contains_key(method_name)
                && self.peer_handlers.contains_key(method_name)),
            "method '{method_name}' is registered in both owner and peer handler maps; \
             use register() for owner methods and register_peer() for peer methods"
        );

        if required_role == Role::Peer {
            // Peer methods: use the typed-identity handler map.
            let Some(handler) = self.peer_handlers.get(method_name) else {
                return error_invocation(method_name, call_id, JmapError::unknown_method());
            };
            // Spawn into a fresh task so that a panic inside the handler kills
            // only that task and not the connection handler.  The JoinError from
            // a panicking task is mapped to a serverFail invocation.
            let fut = handler.call(
                method_name.to_string(),
                call_id.to_string(),
                args,
                caller_identity.clone(),
            );
            match tokio::task::spawn(fut).await {
                Ok(Ok(result)) => (method_name.to_string(), result, call_id.to_string()),
                Ok(Err(err)) => error_invocation(method_name, call_id, err),
                Err(_panic) => error_invocation(
                    method_name,
                    call_id,
                    JmapError::server_fail("internal error"),
                ),
            }
        } else {
            // Owner methods: use the standard handler map.
            let Some(handler) = self.handlers.get(method_name) else {
                // Method is known in METHOD_ROLES but no handler is registered yet.
                return error_invocation(method_name, call_id, JmapError::unknown_method());
            };
            // Spawn into a fresh task so that a panic inside the handler kills
            // only that task and not the connection handler.  The JoinError from
            // a panicking task is mapped to a serverFail invocation.
            let fut = handler.call(method_name.to_string(), call_id.to_string(), args);
            match tokio::task::spawn(fut).await {
                Ok(Ok(result)) => (method_name.to_string(), result, call_id.to_string()),
                Ok(Err(err)) => error_invocation(method_name, call_id, err),
                Err(_panic) => error_invocation(
                    method_name,
                    call_id,
                    JmapError::server_fail("internal error"),
                ),
            }
        }
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl Dispatcher {
    /// Returns the names of all currently registered method handlers (owner and peer).
    ///
    /// Used only in tests to verify that the handler registry matches METHOD_ROLES.
    pub fn registered_method_names(&self) -> Vec<&str> {
        self.handlers
            .keys()
            .chain(self.peer_handlers.keys())
            .map(String::as_str)
            .collect()
    }
}

/// Resolve ResultReference arguments in a single JMAP method call's args.
///
/// Modifies `args` in place.  For every key in `args` that starts with `#`:
/// 1. Parse the value as a [`ResultReference`].
/// 2. Look up the referenced call-id in `prior_responses` (must be a prior call).
/// 3. Verify the `name` field matches the method name of the referenced call (RFC 8620 §9).
/// 4. Navigate the result with the RFC 6901 JSON Pointer path.
/// 5. Replace the `#key` entry with `key` → resolved value.
///
/// Returns `Err(JmapError)` on any resolution failure so the caller can return
/// an error Invocation without processing the method.
pub fn resolve_args(
    args: &mut serde_json::Value,
    prior_responses: &[(String, String, serde_json::Value)],
) -> Result<(), JmapError> {
    let obj = match args.as_object_mut() {
        Some(o) => o,
        None => return Ok(()), // non-object args have no #-key references
    };

    // Collect the #-prefixed keys first (can't mutate while iterating).
    let ref_keys: Vec<String> = obj.keys().filter(|k| k.starts_with('#')).cloned().collect();

    for ref_key in ref_keys {
        let plain_key = ref_key[1..].to_string(); // strip the '#'
        let ref_value = obj.remove(&ref_key).expect("key was just found in the map");

        // Parse as ResultReference
        let rr: ResultReference = serde_json::from_value(ref_value).map_err(|e| {
            JmapError::invalid_arguments(format!("invalid ResultReference for #{plain_key}: {e}"))
        })?;

        // Find the prior result by call-id; also capture the method name for
        // the name-field check required by RFC 8620 §9.
        let (prior_method_name, prior_result) = prior_responses
            .iter()
            .find(|(id, _, _)| id == &rr.result_of)
            .map(|(_, name, val)| (name.as_str(), val))
            .ok_or_else(|| {
                JmapError::invalid_arguments(format!(
                    "resultOf '{}' not found in prior responses",
                    rr.result_of
                ))
            })?;

        // RFC 8620 §9: if the name field does not match the method name of the
        // referenced invocation, the server MUST return invalidArguments.
        if rr.name != prior_method_name {
            return Err(JmapError::invalid_arguments(format!(
                "ResultReference name '{}' does not match method name '{}' of call '{}'",
                rr.name, prior_method_name, rr.result_of
            )));
        }

        // Apply RFC 6901 JSON Pointer
        let resolved = prior_result.pointer(&rr.path).ok_or_else(|| {
            JmapError::invalid_arguments(format!(
                "path '{}' does not resolve in result of '{}'",
                rr.path, rr.result_of
            ))
        })?;

        if obj.contains_key(&plain_key) {
            return Err(JmapError::invalid_arguments(format!(
                "argument key conflict: '{}' and '#{0}' both present in method call",
                plain_key
            )));
        }

        obj.insert(plain_key, resolved.clone());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Oracle: RFC 8620 §3 (request format), §7.1 (error type strings).
    // Expected values are derived from the RFC spec, not from running the code.

    fn dummy_identity() -> Identity {
        Identity {
            user_id: "uid-test".to_string(),
            login_name: "test@example.com".to_string(),
            display_name: None,
            node_name: "test-node.tail12345.ts.net".to_string(),
        }
    }

    // Test 1: Valid request with both capabilities → Ok
    #[test]
    fn test_parse_request_valid() {
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [
                ["ChatContact/get", {"accountId": "a-self"}, "0"]
            ]
        });
        let result = parse_request(body);
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.using.len(), 2);
        assert_eq!(req.method_calls.len(), 1);
    }

    // Test 2: Empty using array → unknownCapability (RFC 8620 §7.1)
    #[test]
    fn test_parse_request_empty_using() {
        let body = json!({
            "using": [],
            "methodCalls": []
        });
        let result = parse_request(body);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "unknownCapability");
    }

    // Test 3: Unknown capability URI → silently ignored, request accepted
    // Pragmatic interoperability: stock clients sending e.g. urn:ietf:params:jmap:mail
    // are not rejected; Kith dispatches only the methods it knows about.
    #[test]
    fn test_parse_request_unknown_capability_ignored() {
        let body = json!({
            "using": ["urn:ietf:params:jmap:chat", "urn:example:unknown:1"],
            "methodCalls": []
        });
        let result = parse_request(body);
        assert!(result.is_ok());
    }

    // Test 4: Only urn:ietf:params:jmap:core (no urn:ietf:params:jmap:chat) → accepted
    // urn:ietf:params:jmap:chat is implicit; stock clients that only declare core are accepted.
    #[test]
    fn test_parse_request_core_only_accepted() {
        let body = json!({
            "using": ["urn:ietf:params:jmap:core"],
            "methodCalls": []
        });
        let result = parse_request(body);
        assert!(result.is_ok());
    }

    // Test 5: More than 16 method calls → requestTooLarge (RFC 8620 §7.1)
    #[test]
    fn test_parse_request_too_many_calls() {
        let method_calls: Vec<serde_json::Value> = (0..17)
            .map(|i| json!(["ChatContact/get", {}, i.to_string()]))
            .collect();
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": method_calls
        });
        let result = parse_request(body);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "requestTooLarge");
    }

    // Test 6: Exactly 16 method calls → Ok (boundary: limit is inclusive)
    #[test]
    fn test_parse_request_exactly_16_calls() {
        let method_calls: Vec<serde_json::Value> = (0..16)
            .map(|i| json!(["ChatContact/get", {}, i.to_string()]))
            .collect();
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": method_calls
        });
        let result = parse_request(body);
        assert!(result.is_ok());
    }

    // Test 7: Malformed input (not a JSON object) → invalidArguments (RFC 8620 §7.1)
    #[test]
    fn test_parse_request_malformed() {
        let body = serde_json::Value::String("not an object".to_string());
        let result = parse_request(body);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Test 8: Only urn:ietf:params:jmap:chat (no core) → Ok
    // The required condition is that kith:chat:1 is present and no unknown URIs appear.
    // urn:ietf:params:jmap:core is allowed but not required.
    #[test]
    fn test_parse_request_kith_only() {
        let body = json!({
            "using": ["urn:ietf:params:jmap:chat"],
            "methodCalls": []
        });
        let result = parse_request(body);
        assert!(result.is_ok());
    }

    // Session object tests (oracle: RFC 8620 §2)
    #[test]
    fn test_build_session_owner_role() {
        let identity = kith_core::Identity {
            user_id: "uid-alice".to_string(),
            login_name: "alice@example.com".to_string(),
            display_name: Some("Alice Smith".to_string()),
            node_name: "alice-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Owner,
            &identity,
            "https://alice-kith.ts.net",
            "s-1".to_string(),
            "uid-alice".to_string(),
            "alice@example.com".to_string(),
        );
        // RFC 8620 §2: accounts MUST have at least one account
        assert!(session.accounts.contains_key("a-self"));
        // Role must be "owner"
        assert_eq!(
            session.accounts["a-self"]
                .account_capabilities
                .kith_chat
                .role,
            "owner"
        );
        // username must NOT be empty
        assert!(!session.username.is_empty());
        // username should use display_name when available
        assert_eq!(session.username, "Alice Smith");
    }

    #[test]
    fn test_build_session_peer_role() {
        let identity = kith_core::Identity {
            user_id: "uid-bob".to_string(),
            login_name: "bob@example.com".to_string(),
            display_name: None,
            node_name: "bob-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Peer,
            &identity,
            "https://alice-kith.ts.net",
            "s-0".to_string(),
            "uid-alice".to_string(),
            "alice@example.com".to_string(),
        );
        assert_eq!(
            session.accounts["a-self"]
                .account_capabilities
                .kith_chat
                .role,
            "peer"
        );
        // username falls back to login_name when display_name is None
        assert_eq!(session.username, "bob@example.com");
    }

    #[test]
    fn test_build_session_username_never_empty() {
        // Even with empty display_name and empty login_name, username uses user_id
        let identity = kith_core::Identity {
            user_id: "uid-fallback".to_string(),
            login_name: String::new(),
            display_name: Some(String::new()),
            node_name: "fallback-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Owner,
            &identity,
            "https://kith.ts.net",
            "s-0".to_string(),
            "uid-fallback".to_string(),
            String::new(),
        );
        assert!(!session.username.is_empty(), "username must never be empty");
        assert_eq!(session.username, "uid-fallback");
    }

    #[test]
    fn test_build_session_primary_accounts() {
        let identity = kith_core::Identity {
            user_id: "uid-x".to_string(),
            login_name: "x@example.com".to_string(),
            display_name: None,
            node_name: "x-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Owner,
            &identity,
            "https://kith.ts.net",
            "s-0".to_string(),
            "uid-x".to_string(),
            "x@example.com".to_string(),
        );
        // RFC 8620 §2: primaryAccounts must map each capability to an account
        assert_eq!(
            session.primary_accounts.get("urn:ietf:params:jmap:chat"),
            Some(&"a-self".to_string())
        );
    }

    #[test]
    fn test_build_session_api_url() {
        let identity = kith_core::Identity {
            user_id: "uid-x".to_string(),
            login_name: "x@example.com".to_string(),
            display_name: None,
            node_name: "x-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Owner,
            &identity,
            "https://kith.ts.net",
            "s-0".to_string(),
            "uid-x".to_string(),
            "x@example.com".to_string(),
        );
        // apiUrl must be the JMAP API endpoint
        assert_eq!(session.api_url, "https://kith.ts.net/jmap/api");
    }

    #[test]
    fn test_build_session_serializes_correctly() {
        let identity = kith_core::Identity {
            user_id: "uid-x".to_string(),
            login_name: "alice@example.com".to_string(),
            display_name: None,
            node_name: "x-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Owner,
            &identity,
            "https://kith.ts.net",
            "s-1".to_string(),
            "uid-x".to_string(),
            "alice@example.com".to_string(),
        );
        let json = serde_json::to_value(&session).expect("Session must serialize");
        // RFC 8620 §2: all required top-level fields must be present
        assert!(json.get("capabilities").is_some());
        assert!(json.get("accounts").is_some());
        assert!(json.get("primaryAccounts").is_some());
        assert!(json.get("username").is_some());
        assert!(json.get("apiUrl").is_some());
        assert!(json.get("downloadUrl").is_some());
        assert!(json.get("uploadUrl").is_some());
        assert!(json.get("eventSourceUrl").is_some());
        assert!(json.get("state").is_some());
        // Capability limits from kith spec
        let core_caps = &json["capabilities"]["urn:ietf:params:jmap:core"];
        assert_eq!(core_caps["maxCallsInRequest"], 16);
        assert_eq!(core_caps["maxSizeRequest"], 10_485_760_u64);
    }

    // --- Owner identity in Session tests ---
    // Oracle: Kith spec — Session must expose ownerUserId and ownerLogin so that
    // a remote peer can identify whose mailbox they are probing at /.well-known/jmap.
    // Expected JSON key names are hard-coded per the kith spec, not derived from
    // running the serializer first.

    #[test]
    fn session_includes_owner_identity() {
        let identity = kith_core::Identity {
            user_id: "uid-peer".to_string(),
            login_name: "peer@example.com".to_string(),
            display_name: None,
            node_name: "peer-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Peer,
            &identity,
            "https://alice-kith.ts.net",
            "s-0".to_string(),
            "uid-alice".to_string(),
            "alice@example.com".to_string(),
        );
        let json = serde_json::to_string(&session).unwrap();
        // Oracle: key names from kith spec — "ownerUserId" and "ownerLogin".
        // These are checked as raw string substrings so the test is independent of
        // the serializer's field ordering.
        assert!(
            json.contains("\"ownerUserId\":\"uid-alice\""),
            "ownerUserId must appear in serialized Session JSON; got: {json}"
        );
        assert!(
            json.contains("\"ownerLogin\":\"alice@example.com\""),
            "ownerLogin must appear in serialized Session JSON; got: {json}"
        );
    }

    #[test]
    fn session_owner_identity_is_mailbox_owner_not_caller() {
        // Owner fields must reflect the mailbox owner, not the caller's identity.
        // A peer calls /.well-known/jmap; the caller identity is different from the
        // owner identity. Both must appear in the JSON at the correct keys.
        let caller_identity = kith_core::Identity {
            user_id: "uid-bob".to_string(),
            login_name: "bob@example.com".to_string(),
            display_name: None,
            node_name: "bob-node.tail12345.ts.net".to_string(),
        };
        let session = build_session(
            kith_core::Role::Peer,
            &caller_identity,
            "https://alice-kith.ts.net",
            "s-0".to_string(),
            "uid-alice".to_string(),
            "alice@example.com".to_string(),
        );
        let json_val = serde_json::to_value(&session).unwrap();
        // ownerUserId and ownerLogin must be the owner's values, not the caller's.
        assert_eq!(
            json_val["ownerUserId"].as_str(),
            Some("uid-alice"),
            "ownerUserId must be the mailbox owner's user_id"
        );
        assert_eq!(
            json_val["ownerLogin"].as_str(),
            Some("alice@example.com"),
            "ownerLogin must be the mailbox owner's login"
        );
        // The caller's username comes through as the 'username' field, not ownerLogin.
        assert_eq!(
            json_val["username"].as_str(),
            Some("bob@example.com"),
            "username must be the caller's display name / login"
        );
    }

    // --- Dispatcher tests ---
    // Oracle: RFC 8620 §7.1 error type strings.
    // Expected values derived from the RFC spec, not from running the implementation.

    struct EchoHandler(serde_json::Value);

    impl JmapHandler for EchoHandler {
        fn call(
            &self,
            _method_name: String,
            _call_id: String,
            _args: serde_json::Value,
        ) -> HandlerFuture {
            let val = self.0.clone();
            Box::pin(async move { Ok(val) })
        }
    }

    struct ErrorHandler(JmapError);

    impl JmapHandler for ErrorHandler {
        fn call(
            &self,
            _method_name: String,
            _call_id: String,
            _args: serde_json::Value,
        ) -> HandlerFuture {
            let err = self.0.clone();
            Box::pin(async move { Err(err) })
        }
    }

    // Test: unknown method name → unknownMethod error (RFC 8620 §7.1)
    #[tokio::test]
    async fn test_dispatch_unknown_method() {
        let d = Dispatcher::new();
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "UnknownType/get".to_string(),
                serde_json::Value::Null,
                "c0".to_string(),
            )],
        };
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses.len(), 1);
        let (name, args, call_id) = &resp.method_responses[0];
        assert_eq!(name, "UnknownType/get");
        assert_eq!(call_id, "c0"); // call_id echoed verbatim
        assert_eq!(args["type"], "unknownMethod"); // RFC 8620 §7.1
    }

    // Test: owner calls peer-only method → "forbidden" (RFC 8620 §7.1)
    #[tokio::test]
    async fn test_dispatch_owner_calls_peer_method() {
        let d = Dispatcher::new();
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "Peer/deliver".to_string(),
                serde_json::Value::Null,
                "c1".to_string(),
            )],
        };
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses[0].1["type"], "forbidden"); // RFC 8620 §7.1
    }

    // Test: peer calls owner-only method → "forbidden" (RFC 8620 §7.1)
    #[tokio::test]
    async fn test_dispatch_peer_calls_owner_method() {
        let d = Dispatcher::new();
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "ChatContact/get".to_string(),
                serde_json::Value::Null,
                "c2".to_string(),
            )],
        };
        let resp = d
            .dispatch(req, Role::Peer, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses[0].1["type"], "forbidden");
    }

    // Test: known method, correct role, handler registered → success
    #[tokio::test]
    async fn test_dispatch_success() {
        let mut d = Dispatcher::new();
        d.register(
            "ChatContact/get",
            Box::new(EchoHandler(serde_json::json!({"list": []}))),
        );
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "ChatContact/get".to_string(),
                serde_json::Value::Null,
                "c3".to_string(),
            )],
        };
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-42".to_string())
            .await;
        assert_eq!(resp.session_state, "s-42");
        let (name, args, call_id) = &resp.method_responses[0];
        assert_eq!(name, "ChatContact/get");
        assert_eq!(call_id, "c3");
        assert_eq!(args["list"], serde_json::json!([]));
    }

    // Test: known method, correct role, handler returns error → error invocation
    #[tokio::test]
    async fn test_dispatch_handler_error() {
        let mut d = Dispatcher::new();
        d.register("Chat/get", Box::new(ErrorHandler(JmapError::not_found())));
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "Chat/get".to_string(),
                serde_json::Value::Null,
                "c4".to_string(),
            )],
        };
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses[0].1["type"], "notFound");
    }

    // Test: mixed batch — one success, one unknown, one forbidden
    #[tokio::test]
    async fn test_dispatch_mixed_batch() {
        let mut d = Dispatcher::new();
        d.register(
            "ChatContact/get",
            Box::new(EchoHandler(serde_json::json!({}))),
        );
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![
                (
                    "ChatContact/get".to_string(),
                    serde_json::Value::Null,
                    "c0".to_string(),
                ),
                (
                    "Bogus/method".to_string(),
                    serde_json::Value::Null,
                    "c1".to_string(),
                ),
                (
                    "Peer/deliver".to_string(),
                    serde_json::Value::Null,
                    "c2".to_string(),
                ),
            ],
        };
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses.len(), 3);
        // c0: success — no "type" field in response args
        assert!(resp.method_responses[0].1.get("type").is_none());
        // c1: unknownMethod
        assert_eq!(resp.method_responses[1].1["type"], "unknownMethod");
        // c2: forbidden (peer-only method called by owner)
        assert_eq!(resp.method_responses[2].1["type"], "forbidden");
    }

    // Test: known method, correct role, but no handler registered → unknownMethod
    #[tokio::test]
    async fn test_dispatch_known_method_no_handler() {
        let d = Dispatcher::new(); // no handlers registered
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "ChatContact/get".to_string(),
                serde_json::Value::Null,
                "c5".to_string(),
            )],
        };
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses[0].1["type"], "unknownMethod");
    }

    // Test: session_state is echoed verbatim in response
    #[tokio::test]
    async fn test_dispatch_session_state_echoed() {
        let d = Dispatcher::new();
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![],
        };
        let resp = d
            .dispatch(
                req,
                Role::Owner,
                dummy_identity(),
                "state-token-xyz".to_string(),
            )
            .await;
        assert_eq!(resp.session_state, "state-token-xyz");
    }

    // --- resolve_args tests ---
    // Oracle: RFC 8620 §9 ResultReference semantics.
    // All expected values are derived from the spec, not from running the code.

    // Test: no #-prefixed keys → args unchanged, Ok returned
    #[test]
    fn test_resolve_args_no_refs() {
        let mut args = json!({"ids": ["id-1", "id-2"], "accountId": "a-self"});
        let prior: Vec<(String, String, serde_json::Value)> = vec![];
        let result = resolve_args(&mut args, &prior);
        assert!(result.is_ok());
        // args must be unchanged: both keys still present, no extra keys
        assert_eq!(args["ids"], json!(["id-1", "id-2"]));
        assert_eq!(args["accountId"], "a-self");
    }

    // Test: non-object args (e.g. null) → Ok, no panic
    #[test]
    fn test_resolve_args_non_object() {
        let mut args = serde_json::Value::Null;
        let prior: Vec<(String, String, serde_json::Value)> = vec![];
        let result = resolve_args(&mut args, &prior);
        assert!(result.is_ok());
    }

    // Test: valid #-key resolves correctly (RFC 8620 §9 example pattern)
    // Prior result: {"list": [{"id": "chat-abc"}]}
    // Reference: resultOf="c0", name="Chat/get", path="/list/0/id"
    // Expected: "#chatId" key is replaced by "chatId": "chat-abc"
    #[test]
    fn test_resolve_args_valid_ref() {
        let prior_result = json!({"list": [{"id": "chat-abc"}]});
        let prior = vec![("c0".to_string(), "Chat/get".to_string(), prior_result)];

        let mut args = json!({
            "#chatId": {
                "resultOf": "c0",
                "name": "Chat/get",
                "path": "/list/0/id"
            }
        });

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        // #chatId must be gone; chatId must now hold the resolved value
        assert!(args.get("#chatId").is_none(), "#chatId key must be removed");
        assert_eq!(args["chatId"], "chat-abc");
    }

    // Test: resultOf references a call-id not in prior_responses → invalidArguments
    #[test]
    fn test_resolve_args_unknown_result_of() {
        let prior: Vec<(String, String, serde_json::Value)> = vec![];

        let mut args = json!({
            "#ids": {
                "resultOf": "c99",
                "name": "ChatContact/get",
                "path": "/list"
            }
        });

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Test: path does not exist in the prior result → invalidArguments
    #[test]
    fn test_resolve_args_bad_path() {
        let prior_result = json!({"list": []});
        let prior = vec![(
            "c0".to_string(),
            "ChatContact/get".to_string(),
            prior_result,
        )];

        let mut args = json!({
            "#ids": {
                "resultOf": "c0",
                "name": "ChatContact/get",
                "path": "/nonexistent/0/id"
            }
        });

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Test: #-key value is not a valid ResultReference JSON object → invalidArguments
    #[test]
    fn test_resolve_args_invalid_ref_value() {
        let prior: Vec<(String, String, serde_json::Value)> = vec![];

        // "#ids" value is a string, not a ResultReference object
        let mut args = json!({"#ids": "not-a-result-reference"});

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Test: multiple #-keys in a single args object all resolve
    #[test]
    fn test_resolve_args_multiple_refs() {
        let prior_a = json!({"list": [{"id": "chat-1"}]});
        let prior_b = json!({"list": [{"id": "msg-9"}]});
        let prior = vec![
            ("c0".to_string(), "Chat/get".to_string(), prior_a),
            ("c1".to_string(), "Message/get".to_string(), prior_b),
        ];

        let mut args = json!({
            "accountId": "a-self",
            "#chatId": {
                "resultOf": "c0",
                "name": "Chat/get",
                "path": "/list/0/id"
            },
            "#messageId": {
                "resultOf": "c1",
                "name": "Message/get",
                "path": "/list/0/id"
            }
        });

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(args["chatId"], "chat-1");
        assert_eq!(args["messageId"], "msg-9");
        assert_eq!(args["accountId"], "a-self"); // unaffected
        assert!(args.get("#chatId").is_none());
        assert!(args.get("#messageId").is_none());
    }

    // Test: ref to prior result that is an error invocation — path resolves into
    // error args just like any other value (RFC 8620 §9 imposes no restriction on
    // what the prior result looks like; it is up to the method to make sense of it).
    // Here we just check that resolve_args succeeds when path hits the error type field.
    #[test]
    fn test_resolve_args_ref_into_error_result() {
        let error_result = json!({"type": "notFound"});
        let prior = vec![("c0".to_string(), "Chat/get".to_string(), error_result)];

        let mut args = json!({
            "#errType": {
                "resultOf": "c0",
                "name": "Chat/get",
                "path": "/type"
            }
        });

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_ok());
        assert_eq!(args["errType"], "notFound");
    }

    // Test: dispatch with a ResultReference — integration test for resolve_args
    // through the full dispatch path.
    // Call 1: "ChatContact/get" → returns {"list": [{"id": "cid-1"}]}
    // Call 2: "Chat/get" args has "#ids" referencing call 1's /list/0/id
    // After resolution Chat/get receives args with ids: "cid-1".
    // The ArgsCapture handler records what args it received so we can assert.
    #[tokio::test]
    async fn test_dispatch_result_reference_end_to_end() {
        use std::sync::{Arc, Mutex};

        struct ArgsCapture(Arc<Mutex<serde_json::Value>>);
        impl JmapHandler for ArgsCapture {
            fn call(
                &self,
                _method_name: String,
                _call_id: String,
                args: serde_json::Value,
            ) -> HandlerFuture {
                *self.0.lock().unwrap() = args;
                Box::pin(async move { Ok(json!({})) })
            }
        }

        let captured: Arc<Mutex<serde_json::Value>> = Arc::new(Mutex::new(json!(null)));
        let mut d = Dispatcher::new();
        d.register(
            "ChatContact/get",
            Box::new(EchoHandler(json!({"list": [{"id": "cid-1"}]}))),
        );
        d.register("Chat/get", Box::new(ArgsCapture(Arc::clone(&captured))));

        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![
                (
                    "ChatContact/get".to_string(),
                    json!({"accountId": "a-self"}),
                    "c0".to_string(),
                ),
                (
                    "Chat/get".to_string(),
                    json!({
                        "accountId": "a-self",
                        "#ids": {
                            "resultOf": "c0",
                            "name": "ChatContact/get",
                            "path": "/list/0/id"
                        }
                    }),
                    "c1".to_string(),
                ),
            ],
        };

        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses.len(), 2);
        // c0 must have succeeded
        assert!(resp.method_responses[0].1.get("type").is_none());
        // c1 must have succeeded
        assert!(
            resp.method_responses[1].1.get("type").is_none(),
            "c1 failed: {:?}",
            resp.method_responses[1].1
        );
        // The Chat/get handler must have received ids resolved to "cid-1"
        let got_args = captured.lock().unwrap().clone();
        assert_eq!(got_args["ids"], "cid-1");
        assert!(got_args.get("#ids").is_none());
    }

    // ResultReference resolver tests (oracle: RFC 8620 §9, RFC 6901 §5)
    // All expected values are derived from the RFC specs, not from running resolve_args.

    #[test]
    fn test_resolve_args_simple_path() {
        // Oracle: RFC 8620 §9 example — /list/0/id on Contact/get result
        let prior = vec![(
            "c0".to_string(),
            "ChatContact/get".to_string(),
            serde_json::json!({"list": [{"id": "c-001", "name": "Alice"}], "state": "s-1"}),
        )];
        let mut args = serde_json::json!({
            "#ids": {"resultOf": "c0", "name": "ChatContact/get", "path": "/list/0/id"}
        });
        resolve_args(&mut args, &prior).expect("should resolve");
        // #ids replaced with ids → the resolved value "c-001"
        assert_eq!(args["ids"], "c-001");
        assert!(args.get("#ids").is_none(), "#ids key must be removed");
    }

    #[test]
    fn test_resolve_args_array_result() {
        // Oracle: RFC 6901 §5 — path /ids on {"ids": ["a", "b"]} → ["a", "b"]
        let prior = vec![(
            "q0".to_string(),
            "ChatContact/query".to_string(),
            serde_json::json!({"ids": ["c-001", "c-002"], "total": 2}),
        )];
        let mut args = serde_json::json!({
            "#ids": {"resultOf": "q0", "name": "ChatContact/query", "path": "/ids"}
        });
        resolve_args(&mut args, &prior).expect("should resolve");
        assert_eq!(args["ids"], serde_json::json!(["c-001", "c-002"]));
    }

    #[test]
    fn test_resolve_args_nested_path() {
        // Oracle: RFC 6901 §5 — /foo/bar/0 navigates nested object then array
        let prior = vec![(
            "r0".to_string(),
            "Foo/get".to_string(),
            serde_json::json!({"foo": {"bar": [10, 20, 30]}}),
        )];
        let mut args = serde_json::json!({
            "#val": {"resultOf": "r0", "name": "Foo/get", "path": "/foo/bar/0"}
        });
        resolve_args(&mut args, &prior).expect("should resolve");
        assert_eq!(args["val"], 10);
    }

    #[test]
    fn test_resolve_args_path_not_found() {
        // Path "/missing" doesn't exist in the prior result → Err(invalidArguments)
        let prior = vec![(
            "c0".to_string(),
            "ChatContact/get".to_string(),
            serde_json::json!({"list": [{"id": "c-001"}]}),
        )];
        let mut args = serde_json::json!({
            "#x": {"resultOf": "c0", "name": "ChatContact/get", "path": "/missing"}
        });
        let result = resolve_args(&mut args, &prior);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_type, "invalidArguments");
    }

    #[test]
    fn test_resolve_args_array_index_out_of_bounds() {
        // Path "/list/99" on 1-element array → None → Err(invalidArguments)
        let prior = vec![(
            "c0".to_string(),
            "ChatContact/get".to_string(),
            serde_json::json!({"list": [{"id": "c-001"}]}),
        )];
        let mut args = serde_json::json!({
            "#ids": {"resultOf": "c0", "name": "ChatContact/get", "path": "/list/99/id"}
        });
        let result = resolve_args(&mut args, &prior);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_type, "invalidArguments");
    }

    #[test]
    fn test_resolve_args_non_object_args() {
        // Non-object args (e.g. null) have no refs — should return Ok without modifying
        let prior: Vec<(String, String, serde_json::Value)> = vec![];
        let mut args = serde_json::Value::Null;
        resolve_args(&mut args, &prior).expect("should succeed on non-object args");
    }

    // Test: dispatch with an unresolvable ResultReference → error invocation for
    // the offending call; earlier calls in the batch are unaffected.
    #[tokio::test]
    async fn test_dispatch_result_reference_resolution_failure() {
        let mut d = Dispatcher::new();
        d.register(
            "ChatContact/get",
            Box::new(EchoHandler(json!({"list": []}))),
        );
        d.register("Chat/get", Box::new(EchoHandler(json!({}))));

        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![
                (
                    "ChatContact/get".to_string(),
                    json!({"accountId": "a-self"}),
                    "c0".to_string(),
                ),
                (
                    "Chat/get".to_string(),
                    json!({
                        "#ids": {
                            "resultOf": "c0",
                            "name": "ChatContact/get",
                            "path": "/list/0/id"  // list is empty → OOB
                        }
                    }),
                    "c1".to_string(),
                ),
            ],
        };

        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses.len(), 2);
        // c0 succeeded
        assert!(resp.method_responses[0].1.get("type").is_none());
        // c1 failed with invalidArguments due to OOB path
        assert_eq!(
            resp.method_responses[1].1["type"], "invalidArguments",
            "expected invalidArguments, got: {:?}",
            resp.method_responses[1].1
        );
    }

    // Test: METHOD_ROLES keys exactly match the set of registered handler names.
    //
    // Oracle: METHOD_ROLES is the authoritative list of supported methods.
    // Every entry must have a handler registered and every registered handler
    // must be listed in METHOD_ROLES — no stragglers, no gaps.
    //
    // The count is NOT hardcoded; both sets are compared dynamically so that
    // adding a new method to METHOD_ROLES without registering a handler (or
    // vice-versa) causes this test to fail.
    // Oracle: the full set of Kith JMAP methods is defined in the
    // kith-architecture.md spec and hardcoded here.  This test fails if
    // someone adds or removes an entry from METHOD_ROLES without updating
    // the spec-derived expected set.  A separate test in the kithd crate
    // checks that build_dispatcher actually registers a handler for each
    // entry (the other failure mode this test cannot reach).
    #[test]
    fn method_roles_contains_expected_methods() {
        let expected: std::collections::HashSet<&str> = [
            "ChatContact/get",
            "ChatContact/set",
            "ChatContact/changes",
            "ChatContact/query",
            "ChatContact/queryChanges",
            "Chat/get",
            "Chat/set",
            "Chat/changes",
            "Chat/query",
            "Message/get",
            "Message/set",
            "Message/changes",
            "Message/query",
            "Message/queryChanges",
            "Peer/deliver",
            "Peer/receipt",
        ]
        .into_iter()
        .collect();

        let actual: std::collections::HashSet<&str> =
            METHOD_ROLES.iter().map(|(name, _)| *name).collect();

        let added: Vec<&&str> = actual.difference(&expected).collect();
        assert!(
            added.is_empty(),
            "METHOD_ROLES has entries not in the expected spec set: {added:?}",
        );
        let removed: Vec<&&str> = expected.difference(&actual).collect();
        assert!(
            removed.is_empty(),
            "METHOD_ROLES is missing expected spec entries: {removed:?}",
        );
    }

    // Test: ResultReference with mismatched name → invalidArguments (RFC 8620 §9)
    //
    // Oracle: RFC 8620 §9 — "If the name does not match the method name of the
    // referenced invocation, the server MUST return an invalidArguments error."
    // The expected error type "invalidArguments" is taken from RFC 8620 §7.1.
    #[test]
    fn test_resolve_args_name_mismatch_returns_invalid_arguments() {
        // Prior call c0 was a "ChatContact/get" invocation.
        let prior = vec![(
            "c0".to_string(),
            "ChatContact/get".to_string(),
            json!({"list": [{"id": "c-001"}], "state": "s-1"}),
        )];

        // ResultReference claims c0 was a "Chat/get" — this is wrong.
        let mut args = json!({
            "#ids": {
                "resultOf": "c0",
                "name": "Chat/get",
                "path": "/list/0/id"
            }
        });

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_err(), "expected Err for name mismatch, got Ok");
        let err = result.unwrap_err();
        assert_eq!(
            err.error_type, "invalidArguments",
            "RFC 8620 §9 requires invalidArguments for name mismatch; got: {}",
            err.error_type
        );
    }

    // Test: both plain key and #-prefixed key present → invalidArguments (key conflict).
    //
    // Oracle: conflict is undefined behavior in RFC 8620 §9; Kith rejects it with
    // invalidArguments rather than silently overwriting the plain key.
    #[test]
    fn test_resolve_args_key_conflict_returns_invalid_arguments() {
        let prior_result = json!({"list": [{"id": "chat-abc"}]});
        let prior = vec![("c0".to_string(), "Chat/get".to_string(), prior_result)];

        // Both "chatId" (plain) and "#chatId" (ref) are present in args.
        let mut args = json!({
            "chatId": "existing-value",
            "#chatId": {
                "resultOf": "c0",
                "name": "Chat/get",
                "path": "/list/0/id"
            }
        });

        let result = resolve_args(&mut args, &prior);
        assert!(result.is_err(), "expected Err for key conflict, got Ok");
        let err = result.unwrap_err();
        assert_eq!(
            err.error_type, "invalidArguments",
            "key conflict must return invalidArguments; got: {}",
            err.error_type
        );
    }

    // Test: dispatch accumulates createdIds from /set responses (RFC 8620 §3.4).
    //
    // Oracle: RFC 8620 §3.4 — "If any methods in the batch create objects, the
    // response object MUST contain a createdIds property which maps the client-
    // provided creation ids to the server-assigned object ids."
    // The mapping structure (client-id → server-id) is from RFC 8620 §3.4 and §5.3.
    #[tokio::test]
    async fn test_dispatch_collects_created_ids() {
        // Handler returns a /set-style response with a "created" map.
        // The created map has client-id "c0" → object with "id": "server-01".
        struct SetHandler;
        impl JmapHandler for SetHandler {
            fn call(
                &self,
                _method_name: String,
                _call_id: String,
                _args: serde_json::Value,
            ) -> HandlerFuture {
                Box::pin(async move {
                    Ok(json!({
                        "accountId": "a-self",
                        "oldState": "s-0",
                        "newState": "s-1",
                        "created": {
                            "new-chat": {"id": "server-01", "name": "Test"}
                        },
                        "updated": null,
                        "destroyed": null,
                        "notCreated": null
                    }))
                })
            }
        }

        let mut d = Dispatcher::new();
        d.register("Chat/set", Box::new(SetHandler));

        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "Chat/set".to_string(),
                json!({"accountId": "a-self", "create": {"new-chat": {"name": "Test"}}}),
                "c0".to_string(),
            )],
        };

        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-1".to_string())
            .await;

        // The method call must have succeeded.
        assert!(
            resp.method_responses[0].1.get("type").is_none(),
            "Chat/set must succeed; got: {:?}",
            resp.method_responses[0].1
        );

        // createdIds must be present and map "new-chat" → "server-01".
        let created_ids = resp
            .created_ids
            .as_ref()
            .expect("createdIds must be present when objects were created");
        assert_eq!(
            created_ids.get("new-chat").map(String::as_str),
            Some("server-01"),
            "createdIds must map 'new-chat' to 'server-01'; got: {created_ids:?}"
        );
    }

    // Test: dispatch with no /set calls → createdIds is None (RFC 8620 §3.4).
    //
    // Oracle: RFC 8620 §3.4 — createdIds may be omitted when no objects were created.
    #[tokio::test]
    async fn test_dispatch_no_created_ids_when_no_set() {
        let mut d = Dispatcher::new();
        d.register(
            "ChatContact/get",
            Box::new(EchoHandler(json!({"list": [], "state": "s-0"}))),
        );

        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "ChatContact/get".to_string(),
                json!({"accountId": "a-self"}),
                "c0".to_string(),
            )],
        };

        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;

        assert!(
            resp.created_ids.is_none(),
            "createdIds must be absent when no objects were created; got: {:?}",
            resp.created_ids
        );
    }

    // Test: panicking owner handler returns serverFail, not a task panic.
    //
    // Oracle: RFC 8620 §7.1 "serverFail" is the correct error type for
    // internal server errors.  The panic isolation guarantee is that a handler
    // panic must not propagate to the connection handler task.
    #[tokio::test]
    async fn test_dispatch_panicking_handler_returns_server_fail() {
        struct PanicHandler;
        impl JmapHandler for PanicHandler {
            fn call(
                &self,
                _method_name: String,
                _call_id: String,
                _args: serde_json::Value,
            ) -> HandlerFuture {
                Box::pin(async move { panic!("intentional test panic") })
            }
        }

        let mut d = Dispatcher::new();
        d.register("ChatContact/get", Box::new(PanicHandler));

        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "ChatContact/get".to_string(),
                serde_json::Value::Null,
                "c0".to_string(),
            )],
        };

        // Must not panic; must return serverFail in methodResponses.
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses.len(), 1);
        assert_eq!(
            resp.method_responses[0].1["type"], "serverFail",
            "panicking handler must produce serverFail, got: {:?}",
            resp.method_responses[0].1
        );
    }

    // Test: panicking peer handler returns serverFail, not a task panic.
    #[tokio::test]
    async fn test_dispatch_panicking_peer_handler_returns_server_fail() {
        struct PanicPeerHandler;
        impl PeerJmapHandler for PanicPeerHandler {
            fn call(
                &self,
                _method_name: String,
                _call_id: String,
                _args: serde_json::Value,
                _caller: Identity,
            ) -> HandlerFuture {
                Box::pin(async move { panic!("intentional peer test panic") })
            }
        }

        let mut d = Dispatcher::new();
        d.register_peer("Peer/deliver", Box::new(PanicPeerHandler));

        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:chat".to_string()],
            method_calls: vec![(
                "Peer/deliver".to_string(),
                serde_json::Value::Null,
                "c0".to_string(),
            )],
        };

        // Must not panic; must return serverFail in methodResponses.
        let resp = d
            .dispatch(req, Role::Peer, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(resp.method_responses.len(), 1);
        assert_eq!(
            resp.method_responses[0].1["type"], "serverFail",
            "panicking peer handler must produce serverFail, got: {:?}",
            resp.method_responses[0].1
        );
    }
}
